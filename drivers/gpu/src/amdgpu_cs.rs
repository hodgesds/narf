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
//! A card whose queue can run client work registers a [`Submitter`]; on
//! such a card the `/dev/dri` ioctl route ([`dispatch_async`]) queues a
//! validated submission and returns its sequence as the fence handle, and
//! `AMDGPU_WAIT_CS` parks until that sequence completes or the client's
//! deadline passes. The Navi48 graphics queue is the first such engine.
//!
//! LINUX-GAP: on a card without one, a validated submission is **not queued**. The pieces it would
//! need now all exist separately — the GFX11 and compute queue descriptors
//! (`amdgpu_mqd`), the ring with its doorbell and writeback slots
//! (`amdgpu_ring`), the MES `ADD_QUEUE` transport in both its process and its
//! legacy-kernel-queue shapes (`amdgpu_mes`), the CP's clear-state preamble
//! (`amdgpu_clearstate`), and materialised page tables (`amdgpu_vm`).
//! `GfxContext` assembles the descriptions — it owns the ring, the writeback
//! page and the queue descriptor, and derives the register sequence's
//! arguments and the MES mapping from the same addresses — and
//! `apply_gfx11_sequence` executes the register half.
//!
//! What is missing is the MES itself. Registering the queue needs a live
//! `MesQueue`, which needs the MES microcode loaded and `SET_HW_RSRC` issued
//! against hardware, and no bring-up path does either: `build_set_hw_resources`
//! and `MesQueue::new` are called by tests and by nothing else. Until that
//! runs, nothing tells the firmware the queue exists, so there is still no ring
//! an engine is reading — and a fence handle returned for work that will never
//! run is worse than a refusal, because a client waits on it forever. A
//! well-formed request therefore parses, validates, and then reports ENODEV.
//! `AMDGPU_INFO_ACCEL_WORKING` reports false for the same reason, so no Mesa
//! client reaches this ioctl at all; it is reachable only by something that
//! ignored that answer.
//!
//! Besides IBs, `SYNCOBJ_IN`/`_OUT`, `SYNCOBJ_TIMELINE_WAIT`/`_SIGNAL`,
//! `BO_HANDLES` (or a `BO_LIST` handle), `FENCE` (see `UserFence`) and the
//! two dependency chunks are accepted, with `amdgpu_cs_pass1`/`pass2`'s
//! errnos: one post-dependency chunk per submission, an unknown out-syncobj
//! is -EINVAL, an unknown in-syncobj -ENOENT and one without a fence (or
//! point) -EINVAL unless the timeline entry asks WAIT_FOR_SUBMIT (then up to
//! 5 s, -ETIME), a dependency on a job its context's ring never emitted
//! -EINVAL.
//!
//! LINUX-GAP: Linux's scheduler holds the job until its dependencies signal
//! and the ioctl returns at once; here the ioctl waits before queueing.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use narf_lib::sync::IrqSafeSpinLock;

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
/// `AMDGPU_RING_TYPE_VCN_JPEG`.
const MAX_IBS_JPEG: usize = 16;
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
    /// Syncobj points the job waits for (`AMDGPU_CHUNK_ID_SYNCOBJ_IN`, point
    /// 0, and `SYNCOBJ_TIMELINE_WAIT`), in chunk order.
    pub in_syncobjs: Vec<SyncobjPoint>,
    /// Syncobj points that get the job's fence (`SYNCOBJ_OUT`, point 0, or
    /// `SYNCOBJ_TIMELINE_SIGNAL`; one such chunk per submission).
    pub out_syncobjs: Vec<SyncobjPoint>,
    /// The BO list (`AMDGPU_CHUNK_ID_BO_HANDLES`), at most one per job.
    pub bo_handles: Option<Vec<u32>>,
    /// Earlier submissions the job waits for (`AMDGPU_CHUNK_ID_DEPENDENCIES`),
    /// or only needs scheduled (`SCHEDULED_DEPENDENCIES`, `scheduled` set).
    pub dependencies: Vec<Dependency>,
    /// The user fence (`AMDGPU_CHUNK_ID_FENCE`): a GEM handle and the byte
    /// offset the job's handle is written at once it completes.
    pub user_fence: Option<(u32, u32)>,
}

/// One `drm_amdgpu_cs_chunk_syncobj { handle, flags, point }` (a binary
/// `drm_amdgpu_cs_chunk_sem` is point 0, flags 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncobjPoint {
    pub handle: u32,
    pub flags: u32,
    pub point: u64,
}

/// `drm_amdgpu_cs_chunk_dep`: a submission named by its context, ring and
/// handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dependency {
    pub ip_type: u32,
    pub ip_instance: u32,
    pub ring: u32,
    pub ctx_id: u32,
    pub handle: u64,
    pub scheduled: bool,
}

/// Bound on one chunk's syncobjs: far beyond what Mesa sends.
const MAX_SYNCOBJS: u32 = 1024;
/// `amdgpu_cs_p1_bo_handles`: a `drm_amdgpu_bo_list_in` { operation,
/// list_handle, bo_number, bo_info_size, bo_info_ptr } (shorter is EINVAL)
/// whose entries each begin with a GEM handle
/// (`amdgpu_bo_create_list_entry_array`).
fn parse_bo_handles(words: &[u32]) -> Result<Vec<u32>, FsError> {
    if words.len() < 6 {
        return Err(FsError::InvalidData);
    }
    let pointer = u64::from(words[4]) | u64::from(words[5]) << 32;
    Ok(
        crate::amdgpu_bo_list::read_entries(words[2], words[3], pointer)?
            .into_iter()
            .map(|(handle, _)| handle)
            .collect(),
    )
}

/// How many IBs one ring type accepts (`amdgpu_ring_max_ibs`).
fn max_ibs(ip_type: u32) -> usize {
    match ip_type {
        uapi::AMDGPU_HW_IP_GFX => MAX_IBS_GFX,
        uapi::AMDGPU_HW_IP_COMPUTE => MAX_IBS_COMPUTE,
        uapi::AMDGPU_HW_IP_VCN_JPEG => MAX_IBS_JPEG,
        _ => MAX_IBS_OTHER,
    }
}

/// A chunk body that may be empty (`vmemdup_array_user` of zero dwords is
/// no error): the syncobj and dependency chunks.
///
/// # Safety
/// As [`read_dwords`].
unsafe fn read_dwords_or_empty(uptr: u64, count: u32, max: u32) -> Result<Vec<u32>, FsError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: delegated.
    unsafe { read_dwords(uptr, count, max) }
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
    // amdgpu_ib_schedule refuses SECURE on a ring without secure
    // submission; there is no TMZ here, so no ring has it, and DEV_INFO
    // never offers it.
    if flags & uapi::AMDGPU_IB_FLAGS_SECURE != 0 {
        return Err(FsError::InvalidData);
    }
    // Only the engines that exist. Linux resolves `ip_type` to a ring and
    // fails if there is none; the effect is the same and the list is the
    // honest one for this driver.
    if !matches!(
        ip_type,
        uapi::AMDGPU_HW_IP_GFX
            | uapi::AMDGPU_HW_IP_COMPUTE
            | uapi::AMDGPU_HW_IP_DMA
            | uapi::AMDGPU_HW_IP_VCN_DEC
            | uapi::AMDGPU_HW_IP_VCN_ENC
            | uapi::AMDGPU_HW_IP_VCN_JPEG
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
    let mut in_syncobjs = Vec::new();
    let mut out_syncobjs = Vec::new();
    let mut bo_handles = None;
    let mut dependencies = Vec::new();
    let mut user_fence = None;
    let mut post_deps = false;
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
                if ibs
                    .iter()
                    .filter(|old| {
                        (old.ip_type, old.ip_instance, old.ring)
                            == (ib.ip_type, ib.ip_instance, ib.ring)
                    })
                    .count()
                    >= max_ibs(ib.ip_type)
                {
                    return Err(FsError::InvalidData);
                }
                ibs.push(ib);
            }
            // `drm_amdgpu_cs_chunk_sem`: one syncobj handle per dword.
            uapi::AMDGPU_CHUNK_ID_SYNCOBJ_IN | uapi::AMDGPU_CHUNK_ID_SYNCOBJ_OUT => {
                // SAFETY: as above.
                let handles = unsafe { read_dwords_or_empty(chunk_data, length_dw, MAX_SYNCOBJS)? };
                let points = handles.into_iter().map(|handle| SyncobjPoint {
                    handle,
                    flags: 0,
                    point: 0,
                });
                if chunk_id == uapi::AMDGPU_CHUNK_ID_SYNCOBJ_IN {
                    in_syncobjs.extend(points);
                } else {
                    // amdgpu_cs_p2_syncobj_out: `if (p->post_deps) -EINVAL`.
                    if post_deps {
                        return Err(FsError::InvalidData);
                    }
                    post_deps = true;
                    out_syncobjs.extend(points);
                }
            }
            // `drm_amdgpu_cs_chunk_syncobj { handle, flags, point }`: four
            // dwords each, a partial trailing entry ignored.
            uapi::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT
            | uapi::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_SIGNAL => {
                // SAFETY: as above.
                let words =
                    unsafe { read_dwords_or_empty(chunk_data, length_dw, MAX_SYNCOBJS * 4)? };
                let points = words.chunks_exact(4).map(|w| SyncobjPoint {
                    handle: w[0],
                    flags: w[1],
                    point: u64::from(w[2]) | u64::from(w[3]) << 32,
                });
                if chunk_id == uapi::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT {
                    in_syncobjs.extend(points);
                } else {
                    if post_deps {
                        return Err(FsError::InvalidData);
                    }
                    post_deps = true;
                    out_syncobjs.extend(points);
                }
            }
            uapi::AMDGPU_CHUNK_ID_BO_HANDLES => {
                // Only a single BO list is allowed, as in Linux.
                if bo_handles.is_some() {
                    return Err(FsError::InvalidData);
                }
                // SAFETY: as above.
                let words = unsafe { read_dwords(chunk_data, length_dw, 64)? };
                bo_handles = Some(parse_bo_handles(&words)?);
            }
            // amdgpu_cs_p2_dependencies: `length_dw * 4 / 24` entries.
            uapi::AMDGPU_CHUNK_ID_DEPENDENCIES | uapi::AMDGPU_CHUNK_ID_SCHEDULED_DEPENDENCIES => {
                // SAFETY: as above.
                let words =
                    unsafe { read_dwords_or_empty(chunk_data, length_dw, MAX_SYNCOBJS * 6)? };
                for d in words.chunks_exact(6) {
                    dependencies.push(Dependency {
                        ip_type: d[0],
                        ip_instance: d[1],
                        ring: d[2],
                        ctx_id: d[3],
                        handle: u64::from(d[4]) | u64::from(d[5]) << 32,
                        scheduled: chunk_id == uapi::AMDGPU_CHUNK_ID_SCHEDULED_DEPENDENCIES,
                    });
                }
            }
            // `drm_amdgpu_cs_chunk_fence { handle, offset }`; a later chunk
            // replaces an earlier one, as in Linux.
            uapi::AMDGPU_CHUNK_ID_FENCE => {
                // SAFETY: as above.
                let words = unsafe { read_dwords(chunk_data, length_dw, 64)? };
                let [handle, offset, ..] = words[..] else {
                    return Err(FsError::InvalidData);
                };
                user_fence = Some((handle, offset));
            }
            _ => return Err(FsError::InvalidData),
        }
    }

    // A submission with no IB asks for nothing.
    if ibs.is_empty() {
        return Err(FsError::InvalidData);
    }
    Ok(Submission {
        ctx_id,
        ibs,
        in_syncobjs,
        out_syncobjs,
        bo_handles,
        dependencies,
        user_fence,
    })
}

/// The engine behind a card's command submission. A card registers one
/// once a queue can run client work; until then CS stays refused.
///
/// Jobs are named by tickets: opaque to clients (the CS handle), with the
/// ring index in the high 32 bits, so tickets of different rings are never
/// compared.
pub trait Submitter: Send + Sync {
    /// Queue `submission` in the address space `vm`; returns its sequence,
    /// which `AMDGPU_CS` hands back as the fence handle.
    ///
    /// The job reports a hang or its cancellation to `health`, its
    /// context's.
    fn submit<'a>(
        &'a self,
        vm: &'a VmState,
        submission: &'a Submission,
        health: &'a Arc<crate::amdgpu_ctx::Health>,
    ) -> Pin<Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>>;
    /// Refuse unsupported entity combinations before dependency waits or BO
    /// placement changes; actual submission rechecks its live admission.
    fn validate_submission(&self, _submission: &Submission) -> Result<(), FsError> {
        Ok(())
    }
    /// Whether job `ticket` has ended — completed, or given up on with an
    /// [`error`](Self::error) — without waiting or blocking on an async
    /// owner (job fences in syncobjs ask this). Memory the job may reach is
    /// released by [`retire`] alone, on true completion.
    fn signalled(&self, ticket: u64) -> bool;
    /// Whether hardware completion (or an owned reset receipt) permits
    /// memory/PTE retirement. An API error signal alone is insufficient.
    /// Backends which acknowledge failed jobs before hardware stops must
    /// override this with their independent physical completion witness.
    fn retired(&self, ticket: u64) -> bool {
        self.signalled(ticket) && self.error(ticket).is_none()
    }
    /// How job `ticket` ended if not by completing: `TimedOut` when it hung
    /// its ring, `Canceled` when it was abandoned behind such a job.
    fn error(&self, _ticket: u64) -> Option<FsError> {
        None
    }
    /// The ring index (a ticket's high 32 bits) that runs `ip_type`
    /// instance `ip_instance`, ring `ring`, if this engine has one.
    fn ring_for(&self, ip_type: u32, ip_instance: u32, ring: u32) -> Option<u32>;
    /// How many IBs one submission on ring `ring` may carry
    /// (`AMDGPU_INFO_MAX_IBS`); more are refused.
    fn max_ibs(&self, _ring: u32) -> u32 {
        1
    }
    /// Whether sequence `seq` has completed, waiting until monotonic
    /// `deadline_ns` (0: don't wait).
    fn wait(
        &self,
        seq: u64,
        deadline_ns: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>>;
}

static SUBMITTERS: IrqSafeSpinLock<Vec<(u32, Arc<dyn Submitter>)>> =
    IrqSafeSpinLock::new(Vec::new());

/// Let DRM card `card`'s clients submit through `submitter`.
pub fn register_submitter(card: u32, submitter: Arc<dyn Submitter>) {
    let mut s = SUBMITTERS.lock();
    s.retain(|(c, _)| *c != card);
    s.push((card, submitter));
    // A new engine numbers its own jobs.
    ISSUED.lock().retain(|(c, _, _)| *c != card);
}

/// Stop accepting submissions for DRM card `card`.
pub fn unregister_submitter(card: u32) {
    SUBMITTERS.lock().retain(|(c, _)| *c != card);
    ISSUED.lock().retain(|(c, _, _)| *c != card);
}

pub(crate) fn submitter(card: u32) -> Option<Arc<dyn Submitter>> {
    SUBMITTERS
        .lock()
        .iter()
        .find(|(c, _)| *c == card)
        .map(|(_, s)| s.clone())
}

/// The last ticket each (card, ring) handed out — `centity->sequence - 1`,
/// kept per ring rather than per context entity (tickets are per ring).
static ISSUED: IrqSafeSpinLock<Vec<(u32, u32, u64)>> = IrqSafeSpinLock::new(Vec::new());

fn note_issued(card: u32, ticket: u64) {
    let ring = (ticket >> 32) as u32;
    let mut issued = ISSUED.lock();
    match issued.iter_mut().find(|(c, r, _)| *c == card && *r == ring) {
        Some(entry) => {
            // Submissions on one ring can return out of order; keep the newest.
            if (ticket as u32).wrapping_sub(entry.2 as u32) as i32 > 0 {
                entry.2 = ticket;
            }
        }
        None => issued.push((card, ring, ticket)),
    }
}

fn last_issued(card: u32, ring: u32) -> Option<u64> {
    ISSUED
        .lock()
        .iter()
        .find(|(c, r, _)| *c == card && *r == ring)
        .map(|(_, _, t)| *t)
}

/// `amdgpu_ctx_get_fence` for `drm_amdgpu_fence`-shaped requests (WAIT_CS,
/// WAIT_FENCES, FENCE_TO_HANDLE, DEPENDENCIES): the context must be this
/// open's and the IP/ring one the engine runs (else -EINVAL); handle 0 names
/// no job (`None`, signalled), `!0` the ring's last job; a handle of another
/// ring, or past the last job the ring emitted, is -EINVAL.
///
/// LINUX-GAP: `!0` resolves to the ring's last job of any context, not the
/// context's own last (tickets are per ring), which only waits longer.
fn resolve_job(
    card: u32,
    engine: Option<&Arc<dyn Submitter>>,
    ctx: &crate::amdgpu_ctx::CtxState,
    ctx_id: u32,
    ip: (u32, u32, u32),
    handle: u64,
) -> Result<Option<u64>, FsError> {
    if ctx.get(ctx_id).is_none() {
        return Err(FsError::InvalidData);
    }
    let Some(engine) = engine else {
        // No engine ever ran a job of this card's contexts.
        return if handle == 0 {
            Ok(None)
        } else {
            Err(FsError::InvalidData)
        };
    };
    let ring = engine
        .ring_for(ip.0, ip.1, ip.2)
        .ok_or(FsError::InvalidData)?;
    if handle == 0 {
        return Ok(None);
    }
    let last = last_issued(card, ring);
    if handle == u64::MAX {
        return Ok(last);
    }
    if handle >> 32 != u64::from(ring) {
        return Err(FsError::InvalidData);
    }
    match last {
        Some(last) if (handle as u32).wrapping_sub(last as u32) as i32 <= 0 => Ok(Some(handle)),
        _ => Err(FsError::InvalidData),
    }
}

/// A job's completion as a dma-fence, for the syncobjs a submission
/// signals (`AMDGPU_CHUNK_ID_SYNCOBJ_OUT`) and the buffers it lists.
pub struct JobFence {
    engine: Arc<dyn Submitter>,
    card: u32,
    seq: u64,
    /// The submitting address space (`VmState::owner`), Linux's scheduler
    /// fence owner (`amdgpu_sync_get_owner`).
    owner: u64,
}
impl core::fmt::Debug for JobFence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JobFence")
            .field("card", &self.card)
            .field("seq", &self.seq)
            .finish()
    }
}
impl crate::drm::syncobj::DmaFence for JobFence {
    fn is_signalled(&self) -> bool {
        self.engine.signalled(self.seq)
    }
    fn wait(&self, timeout_ns: u64) -> bool {
        let deadline = narf_time::monotonic_ns().saturating_add(timeout_ns);
        loop {
            if self.engine.signalled(self.seq) {
                return true;
            }
            if narf_time::monotonic_ns() >= deadline {
                return false;
            }
            narf_scheduler::block_on_spin(narf_time::SleepUntil::new(
                narf_time::Deadline::after_us(50).as_instant(),
            ));
        }
    }
    /// Only the engine signals a job; a CPU signal is ignored, as a
    /// dma-fence from a driver's ring is not CPU-signallable.
    fn signal(&self) {}
    fn context(&self) -> Option<u64> {
        Some(JobFence::context_of(self.card, (self.seq >> 32) as u32))
    }
    fn seqno(&self) -> u64 {
        self.seq
    }
    fn driver_name(&self) -> &str {
        "amdgpu"
    }
    /// A sync_file of a job holds the job itself.
    fn drm_leaves(self: Arc<Self>) -> Option<Vec<Arc<dyn narf_filesystem::DrmFence>>> {
        Some(alloc::vec![self as Arc<dyn narf_filesystem::DrmFence>])
    }
}
impl JobFence {
    /// A ring's fence context: its card and ring, as Linux gives each
    /// scheduler ring its own context. Tickets of one ring are ordered.
    fn context_of(card: u32, ring: u32) -> u64 {
        u64::from(card) << 32 | u64::from(ring)
    }
    fn new(engine: &Arc<dyn Submitter>, card: u32, seq: u64, owner: u64) -> Arc<Self> {
        Arc::new(JobFence {
            engine: engine.clone(),
            card,
            seq,
            owner,
        })
    }
}
/// A job as a reservation fence (implicit sync on shared buffers).
impl narf_filesystem::DrmFence for JobFence {
    fn is_signalled(&self) -> bool {
        self.engine.signalled(self.seq)
    }
    fn wait(&self, timeout_ms: u64) -> bool {
        crate::drm::syncobj::DmaFence::wait(self, timeout_ms.saturating_mul(1_000_000))
    }
    fn context(&self) -> Option<u64> {
        Some(JobFence::context_of(self.card, (self.seq >> 32) as u32))
    }
    fn seqno(&self) -> u64 {
        self.seq
    }
    fn driver_name(&self) -> &str {
        "amdgpu"
    }
    fn owner(&self) -> Option<u64> {
        Some(self.owner)
    }
}

/// A job's user fence: written with the job's handle when the job retires.
///
/// LINUX-GAP: Linux has the ring write it (amdgpu_ring_emit_fence after
/// the IBs); here the CPU stores it when a fence read retires the job, so
/// a client polling the buffer may see it late and falls back to WAIT_CS,
/// which retires it.
struct UserFence {
    object: Arc<crate::amdgpu_gem::GemMapping>,
    offset: u64,
    ticket: u64,
}
impl Drop for UserFence {
    fn drop(&mut self) {
        // Retirement order is not job order: never step a ring's fence
        // back to an older job.
        let current = self.object.load_u64(self.offset).unwrap_or(0);
        let older = current >> 32 == self.ticket >> 32
            && (self.ticket as u32).wrapping_sub(current as u32) as i32 <= 0;
        if !older {
            let _ = self.object.store_u64(self.offset, self.ticket);
        }
    }
}

/// Memory a running job may still reach, freed once its card's engine
/// completes every ticket it waits for.
type Held = Box<dyn core::any::Any + Send + Sync>;
static DEFERRED: IrqSafeSpinLock<Vec<(u32, Vec<u64>, Held)>> = IrqSafeSpinLock::new(Vec::new());

/// Keep `held` until DRM card `card`'s engine completes all of `tickets`.
pub fn defer_until(card: u32, tickets: Vec<u64>, held: Held) {
    DEFERRED.lock().push((card, tickets, held));
}

/// Free what card `card` deferred for jobs `done` reports complete. A card's
/// submitter calls this whenever it learns its engine's progress.
pub fn retire(card: u32, done: &dyn Fn(u64) -> bool) {
    // A completion query may itself reap a native ring and re-enter retire.
    // Sample it outside DEFERRED, then revalidate the immutable tickets under
    // the lock. Newly queued holds are released only for sampled completions.
    let mut tickets: Vec<u64> = DEFERRED
        .lock()
        .iter()
        .filter(|entry| entry.0 == card)
        .flat_map(|entry| entry.1.iter().copied())
        .collect();
    tickets.sort_unstable();
    tickets.dedup();
    let completed: Vec<_> = tickets.into_iter().filter(|&ticket| done(ticket)).collect();
    let freed: Vec<Held> = {
        let mut deferred = DEFERRED.lock();
        let mut freed = Vec::new();
        let mut i = 0;
        while i < deferred.len() {
            if deferred[i].0 == card
                && deferred[i]
                    .1
                    .iter()
                    .all(|t| completed.binary_search(t).is_ok())
            {
                freed.push(deferred.swap_remove(i).2);
            } else {
                i += 1;
            }
        }
        freed
    };
    // Dropped outside the lock: freeing memory can be slow.
    drop(freed);
}

/// How many deferred frees card `card` has outstanding.
pub fn deferred(card: u32) -> usize {
    DEFERRED.lock().iter().filter(|d| d.0 == card).count()
}

/// Whether `cmd` is one of the amdgpu ioctls [`dispatch_async`] answers
/// (they may park): CS, WAIT_CS, GEM_WAIT_IDLE, WAIT_FENCES,
/// FENCE_TO_HANDLE.
pub fn is_async_ioctl(cmd: u32) -> bool {
    let nr = drm_uapi::ioc_nr(cmd);
    [
        uapi::DRM_AMDGPU_CS,
        uapi::DRM_AMDGPU_WAIT_CS,
        uapi::DRM_AMDGPU_GEM_WAIT_IDLE,
        uapi::DRM_AMDGPU_WAIT_FENCES,
        uapi::DRM_AMDGPU_FENCE_TO_HANDLE,
    ]
    .iter()
    .any(|&n| nr == drm_uapi::DRM_COMMAND_BASE + n)
}

/// One open's state the asynchronous amdgpu ioctls act on.
#[allow(missing_debug_implementations)]
pub struct CsOpen<'a> {
    pub vm: &'a VmState,
    pub gem: &'a crate::amdgpu_gem::GemState,
    pub ctx: &'a crate::amdgpu_ctx::CtxState,
    pub syncobjs: &'a IrqSafeSpinLock<crate::drm::syncobj::SyncObjTable>,
    pub bo_lists: &'a crate::amdgpu_bo_list::BoListTable,
    /// The caller's descriptor table (FENCE_TO_HANDLE's fd forms); `None`
    /// for a kernel caller.
    pub files: Option<&'a dyn narf_filesystem::IoctlContext>,
}

/// `amdgpu_gem_timeout`: a negative (as s64) timeout waits forever,
/// otherwise it is an absolute monotonic deadline.
fn gem_deadline(timeout: u64) -> u64 {
    if (timeout as i64) < 0 {
        u64::MAX
    } else {
        timeout
    }
}

/// Sleep briefly inside an ioctl that waits.
async fn nap() {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
}

async fn wait_kernel(
    card: u32,
    fences: Vec<Arc<dyn narf_filesystem::DrmFence>>,
    started: u64,
) -> Result<(), FsError> {
    for fence in fences {
        while !fence.is_signalled() {
            crate::amdgpu_gem::ensure_placement_live(card)?;
            if narf_time::monotonic_ns() >= started.saturating_add(5_000_000_000) {
                return Err(FsError::TimedOut);
            }
            nap().await;
        }
    }
    Ok(())
}

/// `AMDGPU_CS`, `AMDGPU_WAIT_CS`, `AMDGPU_GEM_WAIT_IDLE`,
/// `AMDGPU_WAIT_FENCES` and `AMDGPU_FENCE_TO_HANDLE` on DRM card `card`.
/// CS, WAIT_CS and WAIT_IDLE need a registered submitter (`Unsupported`
/// without one sends them to the synchronous paths); WAIT_FENCES and
/// FENCE_TO_HANDLE answer either way, as a card with no engine has no jobs.
pub async fn dispatch_async(
    card: u32,
    cmd: u32,
    arg: usize,
    open: &CsOpen<'_>,
) -> Result<u64, FsError> {
    let nr = drm_uapi::ioc_nr(cmd);
    if nr == drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_CS {
        crate::amdgpu_gem::ensure_placement_live(card)?;
    }
    let engine = submitter(card);
    if nr == drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_WAIT_FENCES {
        return wait_fences(card, engine.as_ref(), arg, open).await;
    }
    if nr == drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_FENCE_TO_HANDLE {
        return fence_to_handle(card, engine.as_ref(), arg, open);
    }
    let Some(engine) = engine else {
        return Err(FsError::Unsupported);
    };
    let (vm, gem, ctx) = (open.vm, open.gem, open.ctx);
    if nr == drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_GEM_WAIT_IDLE {
        // `drm_amdgpu_gem_wait_idle_in { handle, flags, timeout }`.
        // SAFETY: `arg` is the ioctl pointer the trap layer validated.
        let bytes = unsafe { copy_in(arg, 16)? };
        let handle = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let timeout = gem_deadline(u64::from_le_bytes(bytes[8..16].try_into().unwrap()));
        let object = gem.lookup(handle).ok_or(FsError::NotFound)?;
        // Linux waits on the buffer's reservation (dma_resv_wait_timeout,
        // READ usage): every job that listed it, from any open sharing it
        // through PRIME. A VM_ALWAYS_VALID buffer shares the VM root's
        // reservation, which every job of this address space fences — its
        // last job per ring here.
        let mut idle = true;
        if object.flags & u64::from(uapi::AMDGPU_GEM_CREATE_VM_ALWAYS_VALID) != 0 {
            for ticket in vm.last_jobs() {
                idle &= engine.wait(ticket, timeout).await?;
            }
        }
        for fence in object
            .dma_buf()
            .resv
            .fences(narf_filesystem::dma_buf::DmaResvUsage::Read)
        {
            while idle && !fence.is_signalled() {
                if narf_time::monotonic_ns() >= timeout {
                    idle = false;
                    break;
                }
                nap().await;
            }
        }
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&u32::from(!idle).to_le_bytes());
        out[4..8].copy_from_slice(&(object.preferred_domains() as u32).to_le_bytes());
        // SAFETY: as above.
        unsafe { copy_out(arg, &out)? };
        return Ok(0);
    }
    if nr == drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_WAIT_CS {
        // `drm_amdgpu_wait_cs_in { handle, timeout, ip_type, ip_instance,
        // ring, ctx_id }`.
        // SAFETY: `arg` is the ioctl pointer the trap layer validated.
        let bytes = unsafe { copy_in(arg, 32)? };
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let handle = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let timeout = gem_deadline(u64::from_le_bytes(bytes[8..16].try_into().unwrap()));
        let job = resolve_job(
            card,
            Some(&engine),
            ctx,
            word(28),
            (word(16), word(20), word(24)),
            handle,
        )?;
        let done = match job {
            Some(ticket) => engine.wait(ticket, timeout).await?,
            None => true,
        };
        // amdgpu_cs_wait_ioctl: a job that ended with an error reports it.
        if let Some(error) = job.filter(|_| done).and_then(|t| engine.error(t)) {
            return Err(error);
        }
        // `drm_amdgpu_wait_cs_out.status`: 0 completed, 1 still busy.
        // SAFETY: as above; the out arm overlays the first 8 bytes.
        unsafe { copy_out(arg, &u64::from(!done).to_le_bytes())? };
        return Ok(0);
    }
    if nr != drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_CS {
        return Err(FsError::Unsupported);
    }
    // Terminal recovery can retain admission forever. Refuse before user
    // dependency waits as well, and recheck on each polling iteration.
    crate::amdgpu_gem::ensure_placement_live(card)?;
    let started = narf_time::monotonic_ns();
    let (submission, bo_list_handle) = validated(arg, vm, ctx)?;
    engine.validate_submission(&submission)?;
    // amdgpu_ctx_get_entity: a context whose job hung or was canceled
    // fails every later submission with that error.
    let health = ctx.health(submission.ctx_id).ok_or(FsError::InvalidData)?;
    if let Some(error) = health.error() {
        return Err(error);
    }
    // amdgpu_cs_parser_bos: a BO list handle, or the BO_HANDLES chunk, not
    // both (EINVAL); an unknown list is ENOENT. Every listed BO is one this
    // open holds (ENOENT). LINUX-GAP: the list sets no residency.
    let listed: Vec<Arc<crate::amdgpu_gem::GemObject>> =
        match (&submission.bo_handles, bo_list_handle) {
            (Some(_), h) if h != 0 => return Err(FsError::InvalidData),
            (Some(handles), _) => handles
                .iter()
                .map(|&h| gem.lookup(h).ok_or(FsError::NotFound))
                .collect::<Result<_, _>>()?,
            (None, 0) => Vec::new(),
            (None, h) => open.bo_lists.get(h)?.as_ref().clone(),
        };
    // amdgpu_cs_p2_syncobj_out / _timeline_signal: unknown handles EINVAL.
    let out: Vec<(Arc<crate::drm::syncobj::SyncObjCore>, u64)> = {
        let table = open.syncobjs.lock();
        submission
            .out_syncobjs
            .iter()
            .map(|p| {
                table
                    .get(p.handle)
                    .map(|o| (o.core().clone(), p.point))
                    .map_err(|_| FsError::InvalidData)
            })
            .collect::<Result<_, _>>()?
    };
    // amdgpu_cs_p2_syncobj_in / _timeline_wait: drm_syncobj_find_fence,
    // waiting up to 5 s for an unsubmitted point under WAIT_FOR_SUBMIT.
    let mut waits: Vec<Arc<dyn crate::drm::syncobj::DmaFence>> = Vec::new();
    for p in &submission.in_syncobjs {
        let core = open
            .syncobjs
            .lock()
            .get(p.handle)
            .map(|o| o.core().clone())
            .map_err(|_| FsError::NotFound)?;
        loop {
            match crate::drm::syncobj_ioctl::find_fence_step(
                &core,
                p.point,
                u64::from(p.flags),
                started,
            ) {
                Ok(Some(fence)) => {
                    waits.push(fence);
                    break;
                }
                Ok(None) => {
                    crate::amdgpu_gem::ensure_placement_live(card)?;
                    nap().await;
                }
                Err(result) => return result,
            }
        }
    }
    // amdgpu_cs_p2_dependencies: each names a context this open owns, a ring
    // the engine runs and a job that ring emitted (EINVAL otherwise). A
    // scheduled dependency is met by any earlier job of the in-order ring.
    let mut after = Vec::new();
    for d in &submission.dependencies {
        let job = resolve_job(
            card,
            Some(&engine),
            ctx,
            d.ctx_id,
            (d.ip_type, d.ip_instance, d.ring),
            d.handle,
        )?;
        if let (Some(ticket), false) = (job, d.scheduled) {
            after.push(ticket);
        }
    }
    // amdgpu_cs_p1_user_fence: a one-page buffer of this open, with the
    // 8-byte fence inside it.
    let user_fence = match submission.user_fence {
        Some((handle, offset)) => {
            let object = gem.lookup(handle).ok_or(FsError::InvalidData)?;
            if object.byte_len != 4096 || offset > 4096 - 8 {
                return Err(FsError::InvalidData);
            }
            Some((object.clone(), object.mapping(), u64::from(offset)))
        }
        None => None,
    };
    for handle in after {
        while !engine.signalled(handle) {
            crate::amdgpu_gem::ensure_placement_live(card)?;
            nap().await;
        }
    }
    for fence in waits {
        while !fence.is_signalled() {
            crate::amdgpu_gem::ensure_placement_live(card)?;
            nap().await;
        }
    }
    // amdgpu_cs_sync_rings: implicit sync on each locked buffer's
    // reservation — the listed BOs and the user fence BO — skipping fences
    // of this address space's own jobs (AMDGPU_SYNC_NE_OWNER) and every
    // fence on an EXPLICIT_SYNC buffer (AMDGPU_SYNC_EXPLICIT; there are no
    // move fences here) except its KERNEL ones. A buffer the job does not list is not synced and
    // gets no fence, as in Linux; VM_ALWAYS_VALID buffers share the root
    // reservation, which holds only this space's jobs.
    let own = vm.owner();
    let locked: Vec<&Arc<crate::amdgpu_gem::GemObject>> = listed
        .iter()
        .chain(user_fence.as_ref().map(|(o, _, _)| o))
        .collect();
    for object in &locked {
        // Kernel initialization must finish before user work can observe a
        // fresh allocation. A stopped clear queue is not a successful fence.
        for fence in object
            .dma_buf()
            .resv
            .fences(narf_filesystem::dma_buf::DmaResvUsage::Kernel)
        {
            while !fence.is_signalled() {
                if narf_time::monotonic_ns() >= started.saturating_add(5_000_000_000) {
                    return Err(FsError::TimedOut);
                }
                crate::amdgpu_gem::ensure_placement_live(card)?;
                nap().await;
            }
        }
        // An EXPLICIT_SYNC buffer still waits for kernel work on it.
        let usage = if object.flags & u64::from(uapi::AMDGPU_GEM_CREATE_EXPLICIT_SYNC) != 0 {
            narf_filesystem::dma_buf::DmaResvUsage::Kernel
        } else {
            narf_filesystem::dma_buf::DmaResvUsage::Bookkeep
        };
        let fences = object.dma_buf().resv.fences(usage);
        for fence in fences {
            if fence.owner() == Some(own) {
                continue;
            }
            while !fence.is_signalled() {
                crate::amdgpu_gem::ensure_placement_live(card)?;
                nap().await;
            }
        }
    }
    // Kernel work on buffers mapped in this space (a clear of fresh VRAM)
    // lands before any job here runs, listed or not.
    for fence in vm.kernel_fences() {
        while !fence.is_signalled() {
            if narf_time::monotonic_ns() >= started.saturating_add(5_000_000_000) {
                return Err(FsError::TimedOut);
            }
            crate::amdgpu_gem::ensure_placement_live(card)?;
            nap().await;
        }
    }
    // Includes queue publication, note_job and reservation-fence attachment;
    // a relocator must never miss a job between those operations. Dependencies
    // are awaited first so other submissions can satisfy them.
    let _placement = crate::amdgpu_gem::lock_placement_live(card).await?;
    // A cancelled relocation can leave kernel DMA alive after releasing the
    // card gate. Re-sample move fences after admission, including BOs omitted
    // from the list, before a new job can write their old backing.
    let mut kernel = vm.kernel_fences();
    for object in &locked {
        kernel.extend(
            object
                .dma_buf()
                .resv
                .fences(narf_filesystem::dma_buf::DmaResvUsage::Kernel),
        );
    }
    wait_kernel(card, kernel, started).await?;
    for object in &listed {
        let to_vram = object.preferred_domains() & u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM) != 0;
        if object.system() == to_vram && object.cpu_visible() {
            // Failed promotion preserves the current valid placement. A
            // successful move rewrites every affected VM before this job.
            match crate::amdgpu_vm::relocate(&_placement, object, to_vram).await {
                Ok(()) => {}
                // These refusals leave the source valid and any submitted
                // move still covered by the real KERNEL-fence wait below.
                Err(
                    FsError::Busy | FsError::NoSpace | FsError::OutOfMemory | FsError::Unsupported,
                ) => {}
                // Lost/uncertain hardware progress is not ordinary pressure
                // fallback, even if a later progress sample becomes readable.
                Err(error) => return Err(error),
            }
            // A failed copy can still own queued DMA. Falling back to the
            // old placement is safe only after that move fence settles.
            wait_kernel(
                card,
                object
                    .dma_buf()
                    .resv
                    .fences(narf_filesystem::dma_buf::DmaResvUsage::Kernel),
                started,
            )
            .await?;
        }
    }
    let seq = engine.submit(vm, &submission, &health).await?;
    note_issued(card, seq);
    // What this space drops from now on waits for this job.
    vm.note_job(seq);
    let job = JobFence::new(&engine, card, seq, own);
    // amdgpu_cs_submit: the job is each locked buffer's writer.
    for object in &locked {
        object.dma_buf().resv.add_fence(
            job.clone() as Arc<dyn narf_filesystem::DrmFence>,
            narf_filesystem::dma_buf::DmaResvUsage::Write,
        );
    }
    if let Some((_, object, offset)) = user_fence {
        defer_until(
            card,
            alloc::vec![seq],
            Box::new(UserFence {
                object,
                offset,
                ticket: seq,
            }),
        );
    }
    // amdgpu_cs_post_dependencies: a timeline point for a non-zero point,
    // the payload otherwise.
    for (core, point) in out {
        let fence = job.clone() as Arc<dyn crate::drm::syncobj::DmaFence>;
        if point != 0 {
            core.add_point(fence, point);
        } else {
            core.replace_fence(Some(fence));
        }
    }
    // `drm_amdgpu_cs_out.handle`.
    // SAFETY: as above.
    unsafe { copy_out(arg, &seq.to_le_bytes())? };
    Ok(0)
}

/// `drm_amdgpu_fence { ctx_id, ip_type, ip_instance, ring, seq_no }`.
const FENCE_SIZE: usize = 24;

fn fence_entry(b: &[u8]) -> (u32, (u32, u32, u32), u64) {
    let word = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    (
        word(0),
        (word(4), word(8), word(12)),
        u64::from_le_bytes(b[16..24].try_into().unwrap()),
    )
}

/// `amdgpu_cs_wait_fences_ioctl`: in { fences, fence_count, wait_all,
/// timeout_ns }; out { status, first_signaled }. A zero count is EINVAL;
/// WAIT_ALL resolves and waits in order, stopping at the first timeout
/// (status 0); WAIT_ANY resolves every fence first (an error fails the
/// call), an already-signalled one answers at once, a timeout leaves
/// `first_signaled` all-ones.
async fn wait_fences(
    card: u32,
    engine: Option<&Arc<dyn Submitter>>,
    arg: usize,
    open: &CsOpen<'_>,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the ioctl struct pointer; 24 bytes.
    let b = unsafe { copy_in(arg, 24)? };
    let fences_ptr = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let count = u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize;
    let wait_all = u32::from_le_bytes(b[12..16].try_into().unwrap()) != 0;
    let deadline = gem_deadline(u64::from_le_bytes(b[16..24].try_into().unwrap()));
    if count == 0 {
        return Err(FsError::InvalidData);
    }
    if count > 1 << 16 {
        return Err(FsError::OutOfMemory);
    }
    // SAFETY: the caller's fence array; copy_in bounds and brackets it.
    let raw = unsafe { copy_in(fences_ptr as usize, count * FENCE_SIZE)? };
    let resolve = |e: &[u8]| {
        let (ctx_id, ip, seq) = fence_entry(e);
        resolve_job(card, engine, open.ctx, ctx_id, ip, seq)
    };
    let reply = |status: bool, first: u32| {
        let mut out = [0u8; 24];
        out[0..4].copy_from_slice(&u32::from(status).to_le_bytes());
        out[4..8].copy_from_slice(&first.to_le_bytes());
        // SAFETY: as above.
        unsafe { copy_out(arg, &out) }.map(|()| 0)
    };
    if wait_all {
        let mut status = true;
        for e in raw.chunks_exact(FENCE_SIZE) {
            let Some(ticket) = resolve(e)? else {
                continue;
            };
            let engine = engine.ok_or(FsError::InvalidData)?;
            if !engine.wait(ticket, deadline).await? {
                status = false;
                break;
            }
        }
        return reply(status, 0);
    }
    let mut tickets = Vec::with_capacity(count);
    for (i, e) in raw.chunks_exact(FENCE_SIZE).enumerate() {
        match resolve(e)? {
            Some(ticket) => tickets.push(ticket),
            None => return reply(true, i as u32),
        }
    }
    let engine = engine.ok_or(FsError::InvalidData)?;
    loop {
        if let Some(i) = tickets.iter().position(|&t| engine.signalled(t)) {
            return reply(true, i as u32);
        }
        if narf_time::monotonic_ns() >= deadline {
            return reply(false, !0);
        }
        nap().await;
    }
}

/// `amdgpu_cs_fence_to_handle_ioctl`: in { drm_amdgpu_fence, what, pad };
/// out { handle }. The fence resolves first (its errors win); a job never
/// named (handle 0) is the signalled stub. `what`: a new syncobj handle, a
/// syncobj fd, or a sync_file fd (both O_CLOEXEC); anything else EINVAL.
fn fence_to_handle(
    card: u32,
    engine: Option<&Arc<dyn Submitter>>,
    arg: usize,
    open: &CsOpen<'_>,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the ioctl struct pointer; 32 bytes.
    let b = unsafe { copy_in(arg, 32)? };
    let (ctx_id, ip, seq) = fence_entry(&b[0..FENCE_SIZE]);
    let what = u32::from_le_bytes(b[24..28].try_into().unwrap());
    let fence: Arc<dyn crate::drm::syncobj::DmaFence> = match (
        resolve_job(card, engine, open.ctx, ctx_id, ip, seq)?,
        engine,
    ) {
        (Some(ticket), Some(engine)) => JobFence::new(engine, card, ticket, open.vm.owner()),
        _ => crate::drm::syncobj::stub(),
    };
    let report = |handle: u32| {
        // SAFETY: `out.handle` at offset 0.
        unsafe { copy_out(arg, &handle.to_le_bytes()) }
    };
    const EMFILE: i64 = 24;
    const EOPNOTSUPP: i64 = 95;
    match what {
        uapi::AMDGPU_FENCE_TO_HANDLE_GET_SYNCOBJ => {
            let handle = open
                .syncobjs
                .lock()
                .create_with_fence(fence)
                .map_err(|_| FsError::OutOfMemory)?;
            report(handle)?;
            Ok(0)
        }
        uapi::AMDGPU_FENCE_TO_HANDLE_GET_SYNCOBJ_FD => {
            let Some(files) = open.files else {
                return Ok((-EOPNOTSUPP) as u64);
            };
            let core = crate::drm::syncobj::SyncObjCore::new(Some(fence));
            let Ok(fd) = files.install_file(crate::drm::syncobj_ioctl::syncobj_file(core), true)
            else {
                return Ok((-EMFILE) as u64);
            };
            report(fd as u32)?;
            Ok(0)
        }
        uapi::AMDGPU_FENCE_TO_HANDLE_GET_SYNC_FILE_FD => {
            let Some(files) = open.files else {
                return Ok((-EOPNOTSUPP) as u64);
            };
            let mut report = |fd: i32| report(fd as u32);
            match files.install_sync_file(crate::drm::syncobj::to_drm_leaves(&fence), &mut report) {
                Ok(_) => Ok(0),
                Err(narf_filesystem::InstallFdError::NoDescriptor) => Ok((-EMFILE) as u64),
                Err(narf_filesystem::InstallFdError::Report(e)) => Err(e),
            }
        }
        _ => Err(FsError::InvalidData),
    }
}

/// The `drm_amdgpu_cs` request at `arg`, read and validated, with its
/// `bo_list_handle`.
fn validated(
    arg: usize,
    vm: &VmState,
    ctx: &crate::amdgpu_ctx::CtxState,
) -> Result<(Submission, u32), FsError> {
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
    Ok((
        parse(ctx_id, num_chunks, chunks_ptr, vm, ctx)?,
        bo_list_handle,
    ))
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
    let (submission, bo_list_handle) = validated(arg, vm, ctx)?;
    let _ = (submission, bo_list_handle);

    // Parsed and valid — and refused, because there is no engine reading a
    // ring. Returning a fence handle here would have a client wait forever on
    // work that will never run. See the module LINUX-GAP.
    //
    // `out.handle` is deliberately NOT written: a client that ignores the
    // error must not find a plausible handle in its buffer.
    let _ = copy_out;
    Err(FsError::NotFound)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_cs_liveness_tests.rs"]
mod liveness_tests;
