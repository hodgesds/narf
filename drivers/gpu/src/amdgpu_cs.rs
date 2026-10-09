//! `DRM_IOCTL_AMDGPU_CS` — `amdgpu_cs_ioctl` (`amdgpu_cs.c`).
//!
//! Command submission: the ioctl that hands the GPU work to do. This module
//! is the parser and validator; it stops short of queueing, for the reason in
//! "What this does not do" below.
//!
//! ## The trust boundary, stated plainly
//!
//! **The contents of an indirect buffer are not validated, here or in Linux.**
//! Modern amdgpu does not parse IBs for the graphics and compute rings —
//! `ring->funcs->parse_cs` is NULL for GFX11 — because the command processor
//! executes them through the submitting client's own GPU virtual address
//! space. The page tables ARE the boundary: an IB that names an address the
//! client has not mapped faults, and one that names an address it HAS mapped
//! reaches only its own memory. That is why `amdgpu_vm`'s correctness matters
//! more than anything in this file, and why the protection-fault-enable bits
//! in the VM context register are load-bearing rather than decorative.
//!
//! What this file must get right is narrower and still sharp: every pointer it
//! follows comes from userspace, it follows them two levels deep, and a count
//! it is told determines how much it reads.
//!
//! ## The two-level pointer walk
//!
//! `cs.in.chunks` is a user pointer to an array of `num_chunks` **user
//! pointers**, each naming a `drm_amdgpu_cs_chunk`, which in turn carries
//! `chunk_data` — a third user pointer to `length_dw` dwords. Three
//! dereferences, all attacker-controlled, with two attacker-controlled counts
//! bounding them. Every one is bounded here before it is followed.
//!
//! ## What this does not do
//!
//! LINUX-GAP: a validated submission is **not queued**. The pieces it would
//! need now all exist separately — the GFX11 and compute queue descriptors
//! (`amdgpu_mqd`), the ring with its doorbell and writeback slots
//! (`amdgpu_ring`), the MES `ADD_QUEUE` transport (`amdgpu_mes`), the CP's
//! clear-state preamble (`amdgpu_clearstate`), and materialised page tables
//! (`amdgpu_vm`) — but nothing assembles them: no bring-up path allocates a
//! ring and an MQD, registers the queue with the MES, and hands this module
//! somewhere to write. `gfx_mqd_init` and `compute_mqd_init` are called by
//! tests and by nothing else. So there is still no ring an engine is reading,
//! and a fence handle returned for work that will never run is worse than a
//! refusal, because a client waits on it forever. A well-formed request
//! therefore parses, validates, and then reports ENODEV.
//! `AMDGPU_INFO_ACCEL_WORKING` reports false for the same reason, so no Mesa
//! client reaches this ioctl at all; it is reachable only by something that
//! ignored that answer.
//!
//! LINUX-GAP: only `AMDGPU_CHUNK_ID_IB` is accepted. The dependency and
//! synchronisation chunks — `DEPENDENCIES`, `SYNCOBJ_IN`/`_OUT`,
//! `SYNCOBJ_TIMELINE_WAIT`/`_SIGNAL`, `SCHEDULED_DEPENDENCIES` — each express
//! an ordering constraint against other submissions, and there is no
//! scheduler to order against. They are REFUSED rather than ignored: a client
//! that asked for its work to wait on a fence and had that silently dropped
//! would get a race, not an error. `BO_HANDLES` and `FENCE` are refused for
//! the same reason.

use alloc::vec::Vec;

use narf_filesystem::FsError;

use crate::amdgpu_uapi as uapi;
use crate::amdgpu_vm::{self, VmState};
use crate::drm_ioctl_bridge::{copy_in, copy_out};
use crate::drm_uapi;

/// `AMDGPU_GFX_SDMA_IB_PACKET_SIZE_MAX_DW`.
const IB_PACKET_SIZE_MAX_DW: u64 = 0xF_FFFF;

/// `amdgpu_ring_max_ibs(AMDGPU_RING_TYPE_GFX)` — "need to keep at least 192
/// on GFX7+ for old radv".
const MAX_IBS_GFX: usize = 192;
/// `amdgpu_ring_max_ibs(AMDGPU_RING_TYPE_COMPUTE)`.
const MAX_IBS_COMPUTE: usize = 125;
/// Everything else.
const MAX_IBS_OTHER: usize = 49;

/// A bound on `num_chunks`, which userspace supplies and which sizes an
/// allocation. Linux bounds it by `memdup_array_user`'s own overflow check and
/// by the allocator failing; an explicit cap is cheaper and says what it means.
/// A submission with more than this many chunks is not a real client.
const MAX_CHUNKS: u32 = 64;

/// Every `AMDGPU_IB_FLAG_*` a client may set.
///
/// `CE` is refused separately below. The rest are accepted into the parsed
/// form so a future queueing path can act on them, and none of them change
/// what is validated here.
const IB_FLAGS_KNOWN: u32 = uapi::AMDGPU_IB_FLAG_CE
    | uapi::AMDGPU_IB_FLAG_PREAMBLE
    | uapi::AMDGPU_IB_FLAG_PREEMPT
    | uapi::AMDGPU_IB_FLAG_TC_WB_NOT_INVALIDATE
    | uapi::AMDGPU_IB_FLAG_RESET_GDS_MAX_WAVE_ID
    | uapi::AMDGPU_IB_FLAGS_SECURE
    | uapi::AMDGPU_IB_FLAG_EMIT_MEM_SYNC;

/// One indirect buffer, as validated.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ib {
    /// GPU virtual address, with the canonical hole already stripped.
    pub va_start: u64,
    pub length_dw: u32,
    pub ip_type: u32,
    pub ip_instance: u32,
    pub ring: u32,
    pub flags: u32,
}

/// A parsed, validated submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submission {
    pub ctx_id: u32,
    pub ibs: Vec<Ib>,
}

/// How many IBs one ring type accepts (`amdgpu_ring_max_ibs`).
fn max_ibs(ip_type: u32) -> usize {
    match ip_type {
        uapi::AMDGPU_HW_IP_GFX => MAX_IBS_GFX,
        uapi::AMDGPU_HW_IP_COMPUTE => MAX_IBS_COMPUTE,
        _ => MAX_IBS_OTHER,
    }
}

/// Read `count` dwords from a user array, with the count bounded first.
///
/// # Safety
/// `uptr` is a user pointer; `copy_in` bounds-checks and SMAP-brackets it.
unsafe fn read_dwords(uptr: u64, count: u32, max: u32) -> Result<Vec<u32>, FsError> {
    if count > max {
        return Err(FsError::InvalidData);
    }
    let bytes = (count as usize)
        .checked_mul(4)
        .ok_or(FsError::InvalidData)?;
    if uptr == 0 || bytes == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: delegated to the caller's contract; `copy_in` checks the length
    // against its own cap and brackets the read.
    let raw = unsafe { copy_in(uptr as usize, bytes)? };
    Ok(raw
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect())
}

/// Validate one `drm_amdgpu_cs_chunk_ib`, already copied in as dwords.
fn parse_ib(words: &[u32], vm: &VmState) -> Result<Ib, FsError> {
    // `size < sizeof(struct drm_amdgpu_cs_chunk_ib)` is EINVAL. The struct is
    // 32 bytes — 8 dwords.
    if words.len() < 8 {
        return Err(FsError::InvalidData);
    }
    // words[0] is `_pad`, which Linux does not check and neither does this.
    let flags = words[1];
    let va_start = u64::from(words[2]) | (u64::from(words[3]) << 32);
    let ib_bytes = words[4];
    let ip_type = words[5];
    let ip_instance = words[6];
    let ring = words[7];

    if flags & !IB_FLAGS_KNOWN != 0 {
        return Err(FsError::InvalidData);
    }
    // `!adev->debug_enable_ce_cs && flags & AMDGPU_IB_FLAG_CE` — the constant
    // engine is blocked on modern amdgpu behind a debug knob, and there is no
    // knob here.
    if flags & uapi::AMDGPU_IB_FLAG_CE != 0 {
        return Err(FsError::InvalidData);
    }
    // Only the engines that exist. Linux resolves `ip_type` to a ring and
    // fails if there is none; the effect is the same and the list is the
    // honest one for this driver.
    if !matches!(
        ip_type,
        uapi::AMDGPU_HW_IP_GFX | uapi::AMDGPU_HW_IP_COMPUTE | uapi::AMDGPU_HW_IP_DMA
    ) {
        return Err(FsError::InvalidData);
    }
    // An IB is a whole number of dwords, and a zero-length one names no work.
    if ib_bytes == 0 || ib_bytes % 4 != 0 {
        return Err(FsError::InvalidData);
    }
    let length_dw = u64::from(ib_bytes) / 4;
    if length_dw > IB_PACKET_SIZE_MAX_DW {
        return Err(FsError::InvalidData);
    }

    // The hole is stripped before the address is used, as `amdgpu_cs` strips
    // it (`ib->gpu_addr & AMDGPU_GMC_HOLE_MASK`).
    let va = amdgpu_vm::strip_hole(va_start);
    if va & 3 != 0 {
        return Err(FsError::InvalidData);
    }

    // Linux checks this only for rings that carry a CS parser, which GFX11
    // does not — there, an unmapped IB simply faults the GPU and the VM
    // fault handler reports it. NARF has no VM fault handler wired to this
    // path, so an unmapped IB would be a hang with no diagnosis rather than
    // an error. Checking at submit is strictly stronger than Linux and costs
    // a client nothing: an IB must live in a mapped buffer to be fetched at
    // all, so a request this refuses could never have run.
    let end = va.checked_add(length_dw * 4).ok_or(FsError::InvalidData)?;
    let mapping = vm.lookup(va).ok_or(FsError::InvalidData)?;
    if end > mapping.va.saturating_add(mapping.size) {
        return Err(FsError::InvalidData);
    }
    // And it must be readable by the shader core, or the fetch itself faults.
    if mapping.vm_flags & uapi::AMDGPU_VM_PAGE_READABLE == 0 {
        return Err(FsError::PermissionDenied);
    }

    Ok(Ib {
        va_start: va,
        length_dw: length_dw as u32,
        ip_type,
        ip_instance,
        ring,
        flags,
    })
}

/// Parse and validate the whole submission.
///
/// Separated from [`dispatch`] so the validation can be tested directly — it
/// is the part with a security argument attached, and a test that could only
/// reach it through a path that ends in ENODEV would be testing very little.
pub fn parse(
    ctx_id: u32,
    num_chunks: u32,
    chunks_ptr: u64,
    vm: &VmState,
    ctx: &crate::amdgpu_ctx::CtxState,
) -> Result<Submission, FsError> {
    // A submission names a context the client owns. Linux resolves it through
    // `amdgpu_ctx_get` and fails with -EINVAL when it does not exist.
    if ctx.get(ctx_id).is_none() {
        return Err(FsError::InvalidData);
    }
    if num_chunks == 0 || num_chunks > MAX_CHUNKS {
        return Err(FsError::InvalidData);
    }
    if chunks_ptr == 0 {
        return Err(FsError::BadAddress);
    }

    // Level one: the array of pointers.
    let bytes = (num_chunks as usize) * 8;
    // SAFETY: `chunks_ptr` is the user pointer the caller supplied; `copy_in`
    // bounds-checks `bytes` and SMAP-brackets the read.
    let raw = unsafe { copy_in(chunks_ptr as usize, bytes)? };
    let pointers: Vec<u64> = raw
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();

    let mut ibs: Vec<Ib> = Vec::new();
    for pointer in pointers {
        if pointer == 0 {
            return Err(FsError::BadAddress);
        }
        // Level two: the chunk header, 16 bytes.
        // SAFETY: as above.
        let header = unsafe { copy_in(pointer as usize, 16)? };
        let chunk_id = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let length_dw = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let chunk_data = u64::from_le_bytes(header[8..16].try_into().unwrap());

        match chunk_id {
            uapi::AMDGPU_CHUNK_ID_IB => {
                // Level three: the chunk body. `length_dw` is the client's
                // own count and is bounded before it sizes anything — a
                // generous cap, since an IB chunk is 8 dwords and nothing
                // legitimate is near it.
                // SAFETY: as above.
                let words = unsafe { read_dwords(chunk_data, length_dw, 64)? };
                let ib = parse_ib(&words, vm)?;
                if ibs.len() >= max_ibs(ib.ip_type) {
                    return Err(FsError::InvalidData);
                }
                ibs.push(ib);
            }
            // Refused rather than ignored — see the module LINUX-GAP. A
            // dropped ordering constraint is a race, not an error.
            uapi::AMDGPU_CHUNK_ID_FENCE
            | uapi::AMDGPU_CHUNK_ID_DEPENDENCIES
            | uapi::AMDGPU_CHUNK_ID_BO_HANDLES
            | uapi::AMDGPU_CHUNK_ID_SYNCOBJ_IN
            | uapi::AMDGPU_CHUNK_ID_SYNCOBJ_OUT
            | uapi::AMDGPU_CHUNK_ID_SCHEDULED_DEPENDENCIES
            | uapi::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT
            | uapi::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_SIGNAL => return Err(FsError::Unsupported),
            _ => return Err(FsError::InvalidData),
        }
    }

    // A submission with no IB asks for nothing.
    if ibs.is_empty() {
        return Err(FsError::InvalidData);
    }
    Ok(Submission { ctx_id, ibs })
}

/// `DRM_IOCTL_AMDGPU_CS` for one open.
pub fn dispatch(
    cmd: u32,
    arg: usize,
    vm: &VmState,
    ctx: &crate::amdgpu_ctx::CtxState,
) -> Result<u64, FsError> {
    if drm_uapi::ioc_nr(cmd) != drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_CS {
        return Err(FsError::Unsupported);
    }
    // `union drm_amdgpu_cs`: in { ctx_id, bo_list_handle, num_chunks, flags,
    // chunks } is 24 bytes and larger than out { handle }.
    // SAFETY: `arg` is the ioctl pointer the trap layer validated (or
    // kernel-owned on the test path).
    let bytes = unsafe { copy_in(arg, 24)? };
    let ctx_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let bo_list_handle = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let num_chunks = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let chunks_ptr = u64::from_le_bytes(bytes[16..24].try_into().unwrap());

    // No submission flags are defined, so any is a client expecting something
    // this does not do.
    if flags != 0 {
        return Err(FsError::InvalidData);
    }
    // A BO list is the pre-`BO_HANDLES` way of naming the buffers a submission
    // touches, used for residency. Nothing here manages residency, and
    // accepting the handle would imply it does.
    if bo_list_handle != 0 {
        return Err(FsError::Unsupported);
    }

    let submission = parse(ctx_id, num_chunks, chunks_ptr, vm, ctx)?;
    let _ = submission;

    // Parsed and valid — and refused, because there is no engine reading a
    // ring. Returning a fence handle here would have a client wait forever on
    // work that will never run. See the module LINUX-GAP.
    //
    // `out.handle` is deliberately NOT written: a client that ignores the
    // error must not find a plausible handle in its buffer.
    let _ = copy_out;
    Err(FsError::NotFound)
}
