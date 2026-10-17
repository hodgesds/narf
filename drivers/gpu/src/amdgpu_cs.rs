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
//! LINUX-GAP: besides IBs, `SYNCOBJ_IN`/`_OUT`, `BO_HANDLES`, `FENCE` (the
//! user fence, written by the CPU once the job is seen complete — see
//! [`retire`]) and the two dependency chunks are accepted. Timeline syncobj
//! chunks express a constraint this does not honour yet, and are REFUSED
//! rather than ignored: a client that asked for its work to wait on a fence
//! and had that silently dropped would get a race, not an error.

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
    /// Syncobjs whose fences the job waits for (`AMDGPU_CHUNK_ID_SYNCOBJ_IN`).
    pub in_syncobjs: Vec<u32>,
    /// Syncobjs that get the job's fence (`AMDGPU_CHUNK_ID_SYNCOBJ_OUT`).
    pub out_syncobjs: Vec<u32>,
    /// The BO list (`AMDGPU_CHUNK_ID_BO_HANDLES`), at most one per job.
    pub bo_handles: Option<Vec<u32>>,
    /// Earlier submissions the job waits for (`AMDGPU_CHUNK_ID_DEPENDENCIES`),
    /// or only needs scheduled (`SCHEDULED_DEPENDENCIES`, `scheduled` set).
    pub dependencies: Vec<Dependency>,
    /// The user fence (`AMDGPU_CHUNK_ID_FENCE`): a GEM handle and byte
    /// offset that receive the job's sequence once it completes.
    pub user_fence: Option<(u32, u32)>,
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
/// Bound on a BO list's entries (`AMDGPU_BO_LIST_MAX_PRIORITY` aside, Linux
/// bounds it by `INT_MAX / info_size`; this caps the copy).
const MAX_BO_HANDLES: u32 = 1 << 16;

/// `amdgpu_cs_p1_bo_handles`: a `drm_amdgpu_bo_list_in` { operation,
/// list_handle, bo_number, bo_info_size, bo_info_ptr } whose entries each
/// begin with a GEM handle (`drm_amdgpu_bo_list_entry`).
fn parse_bo_handles(words: &[u32]) -> Result<Vec<u32>, FsError> {
    if words.len() < 6 {
        return Err(FsError::InvalidData);
    }
    let (count, size) = (words[2], words[3]);
    let pointer = u64::from(words[4]) | u64::from(words[5]) << 32;
    if count > MAX_BO_HANDLES || (count != 0 && size < 4) || size > 64 {
        return Err(FsError::InvalidData);
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    if pointer == 0 {
        return Err(FsError::BadAddress);
    }
    let bytes = count as usize * size as usize;
    // SAFETY: `pointer` is the client's entry array; `copy_in` bounds-checks
    // `bytes` (itself bounded above) and SMAP-brackets the read.
    let raw = unsafe { copy_in(pointer as usize, bytes)? };
    Ok(raw
        .chunks_exact(size as usize)
        .map(|e| u32::from_le_bytes(e[0..4].try_into().unwrap()))
        .collect())
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
    let mut in_syncobjs = Vec::new();
    let mut out_syncobjs = Vec::new();
    let mut bo_handles = None;
    let mut dependencies = Vec::new();
    let mut user_fence = None;
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
            // `drm_amdgpu_cs_chunk_sem`: one syncobj handle per dword.
            uapi::AMDGPU_CHUNK_ID_SYNCOBJ_IN | uapi::AMDGPU_CHUNK_ID_SYNCOBJ_OUT => {
                // SAFETY: as above.
                let handles = unsafe { read_dwords(chunk_data, length_dw, MAX_SYNCOBJS)? };
                if chunk_id == uapi::AMDGPU_CHUNK_ID_SYNCOBJ_IN {
                    in_syncobjs.extend(handles);
                } else {
                    out_syncobjs.extend(handles);
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
                let words = unsafe { read_dwords(chunk_data, length_dw, MAX_SYNCOBJS * 6)? };
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
            // amdgpu_cs_p1_user_fence: `drm_amdgpu_cs_chunk_fence
            // { handle, offset }`, one per submission.
            uapi::AMDGPU_CHUNK_ID_FENCE => {
                // SAFETY: as above.
                let words = unsafe { read_dwords(chunk_data, length_dw, 64)? };
                if words.len() < 2 || user_fence.is_some() {
                    return Err(FsError::InvalidData);
                }
                user_fence = Some((words[0], words[1]));
            }
            // Refused rather than ignored — see the module LINUX-GAP. A
            // dropped ordering constraint is a race, not an error.
            uapi::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT
            | uapi::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_SIGNAL => return Err(FsError::Unsupported),
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
    fn submit<'a>(
        &'a self,
        vm: &'a VmState,
        submission: &'a Submission,
    ) -> Pin<Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>>;
    /// Whether job `ticket` has completed, without waiting or blocking on
    /// an async owner (job fences in syncobjs ask this).
    fn signalled(&self, ticket: u64) -> bool;
    /// The ring index (a ticket's high 32 bits) that runs `ip_type`
    /// instance `ip_instance`, ring `ring`, if this engine has one.
    fn ring_for(&self, ip_type: u32, ip_instance: u32, ring: u32) -> Option<u32>;
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
}

/// Stop accepting submissions for DRM card `card`.
pub fn unregister_submitter(card: u32) {
    SUBMITTERS.lock().retain(|(c, _)| *c != card);
}

fn submitter(card: u32) -> Option<Arc<dyn Submitter>> {
    SUBMITTERS
        .lock()
        .iter()
        .find(|(c, _)| *c == card)
        .map(|(_, s)| s.clone())
}

/// A job's completion as a dma-fence, for the syncobjs a submission
/// signals (`AMDGPU_CHUNK_ID_SYNCOBJ_OUT`).
pub struct JobFence {
    engine: Arc<dyn Submitter>,
    card: u32,
    seq: u64,
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
        Some(u64::from(self.card))
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

/// User fences owed: (card, ticket, buffer, byte offset).
type UserFence = (u32, u64, Arc<crate::amdgpu_gem::GemObject>, u64);
static USER_FENCES: IrqSafeSpinLock<Vec<UserFence>> = IrqSafeSpinLock::new(Vec::new());

/// Free what card `card` deferred for jobs `done` reports complete, and
/// write the user fence of each such job. A card's submitter calls this
/// whenever it learns its engine's progress.
///
/// LINUX-GAP: Linux's ring writes the user fence with a second RELEASE_MEM
/// to the BO's GART address; here the CPU writes the job's sequence when
/// completion is observed. Mesa reads it only as a fast path before
/// waiting through the kernel, which observes completion.
pub fn retire(card: u32, done: &dyn Fn(u64) -> bool) {
    let owed: Vec<UserFence> = {
        let mut fences = USER_FENCES.lock();
        let mut owed = Vec::new();
        let mut i = 0;
        while i < fences.len() {
            if fences[i].0 == card && done(fences[i].1) {
                owed.push(fences.swap_remove(i));
            } else {
                i += 1;
            }
        }
        owed
    };
    for (_, ticket, object, offset) in owed {
        object.write_u64(offset, ticket);
    }
    let freed: Vec<Held> = {
        let mut deferred = DEFERRED.lock();
        let mut freed = Vec::new();
        let mut i = 0;
        while i < deferred.len() {
            if deferred[i].0 == card && deferred[i].1.iter().all(|&t| done(t)) {
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

/// Whether `cmd` is `AMDGPU_CS` or `AMDGPU_WAIT_CS`, which may park.
pub fn is_async_ioctl(cmd: u32) -> bool {
    let nr = drm_uapi::ioc_nr(cmd);
    nr == drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_CS
        || nr == drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_WAIT_CS
        || nr == drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_GEM_WAIT_IDLE
}

/// `AMDGPU_CS`, `AMDGPU_WAIT_CS` and `AMDGPU_GEM_WAIT_IDLE` on DRM card
/// `card`, for a card with a registered submitter; `Unsupported` sends
/// anything else (and a card without one) to the synchronous paths.
pub async fn dispatch_async(
    card: u32,
    cmd: u32,
    arg: usize,
    vm: &VmState,
    gem: &crate::amdgpu_gem::GemState,
    ctx: &crate::amdgpu_ctx::CtxState,
    syncobjs: &IrqSafeSpinLock<crate::drm::syncobj::SyncObjTable>,
) -> Result<u64, FsError> {
    let Some(engine) = submitter(card) else {
        return Err(FsError::Unsupported);
    };
    let nr = drm_uapi::ioc_nr(cmd);
    if nr == drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_GEM_WAIT_IDLE {
        // `drm_amdgpu_gem_wait_idle_in { handle, flags, timeout }`.
        // SAFETY: `arg` is the ioctl pointer the trap layer validated.
        let bytes = unsafe { copy_in(arg, 16)? };
        let handle = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let timeout = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let object = gem.lookup(handle).ok_or(FsError::InvalidData)?;
        // LINUX-GAP: Linux waits on the buffer's reservation fences; this
        // waits for the last job this open submitted, which covers every
        // use the open made of it but not a job another process (holding
        // it through PRIME) submitted.
        let mut idle = true;
        for ticket in vm.last_jobs() {
            idle &= engine.wait(ticket, timeout).await?;
        }
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&u32::from(!idle).to_le_bytes());
        out[4..8].copy_from_slice(&(object.preferred_domains as u32).to_le_bytes());
        // SAFETY: as above.
        unsafe { copy_out(arg, &out)? };
        return Ok(0);
    }
    if nr == drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_WAIT_CS {
        // SAFETY: `arg` is the ioctl pointer the trap layer validated.
        let bytes = unsafe { copy_in(arg, 32)? };
        let handle = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        // amdgpu_gem_timeout: an absolute monotonic deadline in ns.
        let timeout = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let ctx_id = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
        if ctx.get(ctx_id).is_none() {
            return Err(FsError::InvalidData);
        }
        let done = handle == 0 || engine.wait(handle, timeout).await?;
        // `drm_amdgpu_wait_cs_out.status`: 0 completed, 1 still busy.
        // SAFETY: as above; the out arm overlays the first 8 bytes.
        unsafe { copy_out(arg, &u64::from(!done).to_le_bytes())? };
        return Ok(0);
    }
    if nr != drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_CS {
        return Err(FsError::Unsupported);
    }
    let submission = validated(arg, vm, ctx)?;
    // amdgpu_bo_list_create: every listed BO is one this open holds.
    // LINUX-GAP: the list sets no residency (nothing is evicted) and no
    // implicit sync (no reservation fences are attached to the BOs).
    if let Some(handles) = &submission.bo_handles {
        if handles.iter().any(|&h| gem.lookup(h).is_none()) {
            return Err(FsError::NotFound);
        }
    }
    // amdgpu_cs_p2_syncobj_in: each named syncobj's fence, which must exist.
    let fences = if submission.in_syncobjs.is_empty() {
        Vec::new()
    } else {
        syncobjs
            .lock()
            .snapshot_fences(&submission.in_syncobjs)
            .map_err(|_| FsError::NotFound)?
    };
    let mut waits = Vec::new();
    for fence in fences {
        waits.push(fence.ok_or(FsError::InvalidData)?);
    }
    let out: Vec<u32> = submission.out_syncobjs.clone();
    if !out.is_empty() {
        let table = syncobjs.lock();
        if out.iter().any(|&h| table.get(h).is_err()) {
            return Err(FsError::NotFound);
        }
    }
    // Each dependency names a context this open owns and the engine's ring
    // (the only one here); handle 0 names nothing. A scheduled dependency
    // is met by any earlier job of this single in-order ring.
    let mut after = Vec::new();
    for d in &submission.dependencies {
        if ctx.get(d.ctx_id).is_none() {
            return Err(FsError::InvalidData);
        }
        let ring = engine
            .ring_for(d.ip_type, d.ip_instance, d.ring)
            .ok_or(FsError::Unsupported)?;
        // A handle names a job of the dependency's own ring.
        if d.handle != 0 && d.handle >> 32 != u64::from(ring) {
            return Err(FsError::InvalidData);
        }
        if d.handle != 0 && !d.scheduled {
            after.push(d.handle);
        }
    }
    for handle in after {
        while !engine.signalled(handle) {
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
        }
    }
    // LINUX-GAP: Linux's scheduler holds the job until these signal and
    // the ioctl returns at once; here the ioctl waits before queueing.
    for fence in waits {
        while !fence.is_signalled() {
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
        }
    }
    // The user fence BO: 8 bytes inside a buffer this open holds.
    let user_fence = match submission.user_fence {
        Some((handle, offset)) => {
            let object = gem.lookup(handle).ok_or(FsError::NotFound)?;
            if u64::from(offset) + 8 > object.byte_len || offset % 8 != 0 {
                return Err(FsError::InvalidData);
            }
            Some((object, u64::from(offset)))
        }
        None => None,
    };
    let seq = engine.submit(vm, &submission).await?;
    // What this space drops from now on waits for this job.
    vm.note_job(seq);
    if let Some((object, offset)) = user_fence {
        USER_FENCES.lock().push((card, seq, object, offset));
    }
    // amdgpu_cs_post_dependencies: the out syncobjs carry the job's fence.
    if !out.is_empty() {
        let fence: Arc<dyn crate::drm::syncobj::DmaFence> = Arc::new(JobFence {
            engine: engine.clone(),
            card,
            seq,
        });
        let mut table = syncobjs.lock();
        for h in out {
            if let Ok(obj) = table.get_mut(h) {
                obj.replace_fence(fence.clone());
            }
        }
    }
    // `drm_amdgpu_cs_out.handle`.
    // SAFETY: as above.
    unsafe { copy_out(arg, &seq.to_le_bytes())? };
    Ok(0)
}

/// The `drm_amdgpu_cs` request at `arg`, read and validated.
fn validated(
    arg: usize,
    vm: &VmState,
    ctx: &crate::amdgpu_ctx::CtxState,
) -> Result<Submission, FsError> {
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
    parse(ctx_id, num_chunks, chunks_ptr, vm, ctx)
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
    let submission = validated(arg, vm, ctx)?;
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
