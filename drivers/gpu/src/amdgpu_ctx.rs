//! `DRM_IOCTL_AMDGPU_CTX` — `amdgpu_ctx_ioctl` (`amdgpu_ctx.c`).
//!
//! A submission context. Mesa allocates one per GL/Vulkan context and names it
//! on every `AMDGPU_CS`, so this is the last ioctl between opening the device
//! and submitting work. A context carries a scheduling priority, a reset
//! history, and a stable-power-state request.
//!
//! Contexts are per-open, like GEM handles and the address space, because they
//! are per-`drm_file` in Linux — `fpriv->ctx_mgr`. A context id from one client
//! must not name another's.
//!
//! LINUX-GAP: there are no scheduler entities behind a context. Linux builds
//! one `drm_sched_entity` per ring per priority at `amdgpu_ctx_init` and that
//! is what a submission is queued on; here a context is bookkeeping, and the
//! priority is recorded and reported back rather than acted on. It becomes real
//! when there is a ring to queue against.
//!
//! `QUERY_STATE` / `QUERY_STATE2` report a GPU recovery completed since the
//! context was created (`amdgpu_navi22_recovery::recoveries`): QUERY_STATE
//! answers `UNKNOWN_RESET` once per reset, QUERY_STATE2 sets `RESET` and
//! `VRAMLOST` (the recovery is a mode1 reset).
//!
//! A context's [`Health`] records whether one of its jobs hung on a ring (it
//! is guilty) or was abandoned behind another's hang. Linux reads that from
//! its entities' last errors (`drm_sched_entity_error`): `AMDGPU_CS` on such
//! a context fails with the error, QUERY_STATE answers `UNKNOWN_RESET`, and
//! QUERY_STATE2 reports RESET, plus GUILTY for a hang of its own. A ring
//! reset loses no VRAM.
//!
//! LINUX-GAP: no hang count, no `RESET_IN_PROGRESS`, and no RAS CE/UE
//! counters; a ring reset does not count as a device recovery, so a context
//! with no job on the ring that hung sees no RESET.
//!
//! LINUX-GAP: `SET_STABLE_PSTATE` validates and records, but does not reach the
//! SMU. Pinning the shader clock is what `AMDGPU_CTX_STABLE_PSTATE_PEAK` asks
//! for and it needs an SMU message this driver does not send yet; a client
//! reading the state back sees what it set, which is what the GET op is for,
//! but the hardware clock does not change.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_uapi as uapi;
use crate::drm_ioctl_bridge::{copy_in, copy_out};
use crate::drm_uapi;

/// `CAP_SYS_NICE` — raising a context above NORMAL priority is the same
/// authority as raising a thread's scheduling priority, which is what Linux
/// asks for.
const CAP_SYS_NICE: u32 = 23;

/// One submission context.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Context {
    /// The priority it was created with, after the UNSET/garbage fixup.
    pub priority: i32,
    /// `AMDGPU_CTX_STABLE_PSTATE_*` as last set.
    pub stable_pstate: u32,
    /// GPU recoveries completed when the context was created
    /// (`ctx->reset_counter` / `vram_lost_counter`).
    pub reset_epoch: u64,
    /// Recoveries already reported by `QUERY_STATE` (`reset_counter_query`).
    pub reset_queried: u64,
}

/// GPU recoveries completed since boot (Navi22 and Navi48 owners).
/// LINUX-GAP: this historical counter is global, not per DRM card.
pub fn recoveries() -> u64 {
    crate::amdgpu_navi22_recovery::recoveries()
        .wrapping_add(crate::amdgpu_navi48_platform::recoveries())
}

/// What became of a context's jobs: the engine records a hang here, and
/// the context's later submissions and queries read it.
#[derive(Debug)]
pub struct Health(AtomicU8, u64);
impl Default for Health {
    fn default() -> Self {
        Self(AtomicU8::new(HEALTHY), recoveries())
    }
}

const HEALTHY: u8 = 0;
const CANCELED: u8 = 1;
const GUILTY: u8 = 2;

impl Health {
    /// Reset generation at context creation, checked again under the GPU
    /// owner lock so a submission waiting through reset cannot use lost VRAM.
    pub(crate) fn reset_epoch(&self) -> u64 {
        self.1
    }
    /// A job of this context hung (`-ETIME`): it is guilty.
    pub fn mark_guilty(&self) {
        self.0.store(GUILTY, Ordering::Release);
    }

    /// A job of this context was abandoned behind another's hang
    /// (`-ECANCELED`); guilt, once recorded, stays.
    pub fn mark_canceled(&self) {
        let _ = self
            .0
            .compare_exchange(HEALTHY, CANCELED, Ordering::AcqRel, Ordering::Acquire);
    }

    /// The error the context's jobs ended with, which its next
    /// submission fails with.
    pub fn error(&self) -> Option<FsError> {
        match self.0.load(Ordering::Acquire) {
            GUILTY => Some(FsError::TimedOut),
            CANCELED => Some(FsError::Canceled),
            _ => None,
        }
    }
}

/// Contexts by id, each with its health.
type Contexts = BTreeMap<u32, (Context, Arc<Health>)>;

/// Per-open context table (`fpriv->ctx_mgr`).
#[derive(Debug)]
pub struct CtxState {
    contexts: IrqSafeSpinLock<Option<Contexts>>,
    next_id: AtomicU32,
}

impl Default for CtxState {
    fn default() -> Self {
        Self::new()
    }
}

impl CtxState {
    pub const fn new() -> Self {
        CtxState {
            contexts: IrqSafeSpinLock::new(None),
            // Linux allocates from `xa_limit_32b`, which starts at 0. Start at
            // 1 so a zeroed `ctx_id` in a request cannot name a live context
            // by accident — a client that forgot to set it gets ENOENT rather
            // than someone's first context.
            next_id: AtomicU32::new(1),
        }
    }

    pub fn get(&self, id: u32) -> Option<Context> {
        self.contexts
            .lock()
            .as_ref()
            .and_then(|m| m.get(&id).map(|(c, _)| *c))
    }

    /// Context `id`'s health, which its jobs report to.
    pub fn health(&self, id: u32) -> Option<Arc<Health>> {
        self.contexts
            .lock()
            .as_ref()
            .and_then(|m| m.get(&id).map(|(_, h)| h.clone()))
    }

    pub fn count(&self) -> usize {
        self.contexts.lock().as_ref().map_or(0, |m| m.len())
    }

    fn alloc(&self, priority: i32) -> Result<u32, FsError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            return Err(FsError::NoSpace);
        }
        let mut g = self.contexts.lock();
        g.get_or_insert_with(BTreeMap::new).insert(
            id,
            (
                Context {
                    priority,
                    stable_pstate: uapi::AMDGPU_CTX_STABLE_PSTATE_NONE,
                    reset_epoch: recoveries(),
                    reset_queried: recoveries(),
                },
                Arc::new(Health::default()),
            ),
        );
        Ok(id)
    }

    fn free(&self, id: u32) -> Result<(), FsError> {
        let mut g = self.contexts.lock();
        match g.as_mut().and_then(|m| m.remove(&id)) {
            Some(_) => Ok(()),
            None => Err(FsError::NotFound),
        }
    }

    fn query_reset(&self, id: u32) -> Result<u32, FsError> {
        let mut g = self.contexts.lock();
        let (ctx, health) = g
            .as_mut()
            .and_then(|m| m.get_mut(&id))
            .ok_or(FsError::NotFound)?;
        let now = recoveries();
        if ctx.reset_queried == now {
            // A context whose job hung or was canceled stays reset.
            return Ok(match health.error() {
                Some(_) => uapi::AMDGPU_CTX_UNKNOWN_RESET,
                None => uapi::AMDGPU_CTX_NO_RESET,
            });
        }
        ctx.reset_queried = now;
        Ok(uapi::AMDGPU_CTX_UNKNOWN_RESET)
    }

    fn set_pstate(&self, id: u32, pstate: u32) -> Result<(), FsError> {
        let mut g = self.contexts.lock();
        let map = g.as_mut().ok_or(FsError::NotFound)?;
        let (ctx, _) = map.get_mut(&id).ok_or(FsError::NotFound)?;
        ctx.stable_pstate = pstate;
        Ok(())
    }
}

/// `amdgpu_ctx_priority_is_valid` — the five defined levels.
///
/// Anything else, `AMDGPU_CTX_PRIORITY_UNSET` included, is NOT an error.
/// Linux's comment says why: "For backwards compatibility, we need to accept
/// ioctls with garbage in the priority field", and such a request is treated as
/// NORMAL. Rejecting it would break clients that never initialised the field.
fn priority_is_valid(priority: i32) -> bool {
    matches!(
        priority,
        uapi::AMDGPU_CTX_PRIORITY_VERY_LOW
            | uapi::AMDGPU_CTX_PRIORITY_LOW
            | uapi::AMDGPU_CTX_PRIORITY_NORMAL
            | uapi::AMDGPU_CTX_PRIORITY_HIGH
            | uapi::AMDGPU_CTX_PRIORITY_VERY_HIGH
    )
}

/// `amdgpu_ctx_priority_permit`.
///
/// NORMAL and below are open to everyone. Above it needs CAP_SYS_NICE, or for
/// the caller to be the current DRM master — a compositor may prioritise its
/// own work without holding a capability, which is the case the master arm
/// exists for.
fn priority_permitted(priority: i32, is_master: bool) -> bool {
    if priority <= uapi::AMDGPU_CTX_PRIORITY_NORMAL {
        return true;
    }
    if narf_filesystem::caller_capable(CAP_SYS_NICE) {
        return true;
    }
    is_master
}

/// `DRM_IOCTL_AMDGPU_CTX` for one open.
///
/// `is_master` is `drm_is_current_master(filp)` — whether THIS open holds DRM
/// master, not whether the device has one.
pub fn dispatch(cmd: u32, arg: usize, state: &CtxState, is_master: bool) -> Result<u64, FsError> {
    if drm_uapi::ioc_nr(cmd) != drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_CTX {
        return Err(FsError::Unsupported);
    }
    // `union drm_amdgpu_ctx`: in { op u32, flags u32, ctx_id u32, priority i32 }
    // overlaying `union drm_amdgpu_ctx_out`, whose own three arms — alloc (8),
    // state (16), pstate (8) — likewise overlap, making it 16. Both the in and
    // out arms are therefore 16 bytes, and so is the whole union: a conforming
    // client allocates exactly that much.
    let size = core::mem::size_of::<uapi::DrmAmdgpuCtx>();
    // SAFETY: `arg` is the ioctl pointer the trap layer validated (or
    // kernel-owned on the test path); `copy_in` bounds-checks and brackets it.
    let bytes = unsafe { copy_in(arg, size)? };
    let op = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let ctx_id = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let raw_priority = i32::from_le_bytes(bytes[12..16].try_into().unwrap());

    // The fixup happens BEFORE the op dispatch, so a garbage priority on a
    // FREE or QUERY is equally harmless.
    let priority = if priority_is_valid(raw_priority) {
        raw_priority
    } else {
        uapi::AMDGPU_CTX_PRIORITY_NORMAL
    };

    // Every op but SET_STABLE_PSTATE requires `flags` to be zero. That is the
    // forward-compatibility rule: a client setting an unknown flag must be
    // refused, not silently served without the behaviour it asked for.
    let mut out = [0u8; core::mem::size_of::<uapi::DrmAmdgpuCtxOut>()];
    match op {
        uapi::AMDGPU_CTX_OP_ALLOC_CTX => {
            if flags != 0 {
                return Err(FsError::InvalidData);
            }
            if !priority_permitted(priority, is_master) {
                return Err(FsError::PermissionDenied);
            }
            let id = state.alloc(priority)?;
            // `out.alloc.ctx_id` is the first word of the out arm.
            out[0..4].copy_from_slice(&id.to_le_bytes());
        }
        uapi::AMDGPU_CTX_OP_FREE_CTX => {
            if flags != 0 {
                return Err(FsError::InvalidData);
            }
            state.free(ctx_id)?;
            return Ok(0);
        }
        uapi::AMDGPU_CTX_OP_QUERY_STATE => {
            if flags != 0 {
                return Err(FsError::InvalidData);
            }
            // amdgpu_ctx_query: UNKNOWN_RESET once per new reset, then NO_RESET
            // unless one of its jobs hung or was canceled.
            let status = state.query_reset(ctx_id)?;
            // `out.state { flags u64, hangs u32, reset_status u32 }`.
            out[12..16].copy_from_slice(&status.to_le_bytes());
        }
        uapi::AMDGPU_CTX_OP_QUERY_STATE2 => {
            if flags != 0 {
                return Err(FsError::InvalidData);
            }
            // The context must exist — a query naming nothing is ENOENT, not
            // a zeroed answer that reads as "healthy".
            let ctx = state.get(ctx_id).ok_or(FsError::NotFound)?;
            let error = state.health(ctx_id).and_then(|h| h.error());
            // amdgpu_ctx_query2: a recovery since creation reset the GPU and,
            // being a mode1 reset, lost VRAM; a hang of the context's own
            // job on a ring reset that ring, and made it guilty.
            let mut f = 0u64;
            if ctx.reset_epoch != recoveries() {
                f |= u64::from(
                    uapi::AMDGPU_CTX_QUERY2_FLAGS_RESET | uapi::AMDGPU_CTX_QUERY2_FLAGS_VRAMLOST,
                );
            }
            if error.is_some() {
                f |= u64::from(uapi::AMDGPU_CTX_QUERY2_FLAGS_RESET);
            }
            if error == Some(FsError::TimedOut) {
                f |= u64::from(uapi::AMDGPU_CTX_QUERY2_FLAGS_GUILTY);
            }
            out[0..8].copy_from_slice(&f.to_le_bytes());
        }
        uapi::AMDGPU_CTX_OP_GET_STABLE_PSTATE => {
            if flags != 0 {
                return Err(FsError::InvalidData);
            }
            let ctx = state.get(ctx_id).ok_or(FsError::NotFound)?;
            // `out.pstate.flags` is a u32 in the first word of the out arm.
            out[0..4].copy_from_slice(&ctx.stable_pstate.to_le_bytes());
        }
        uapi::AMDGPU_CTX_OP_SET_STABLE_PSTATE => {
            // This is the one op that takes flags, and it takes only the
            // pstate field of them.
            if flags & !uapi::AMDGPU_CTX_STABLE_PSTATE_FLAGS_MASK != 0 {
                return Err(FsError::InvalidData);
            }
            let pstate = flags & uapi::AMDGPU_CTX_STABLE_PSTATE_FLAGS_MASK;
            // The mask is 4 bits but only 0..=PEAK are defined, so the range
            // check is separate from the mask check.
            if pstate > uapi::AMDGPU_CTX_STABLE_PSTATE_PEAK {
                return Err(FsError::InvalidData);
            }
            state.set_pstate(ctx_id, pstate)?;
            return Ok(0);
        }
        _ => return Err(FsError::InvalidData),
    }
    // SAFETY: `arg` as above; the out arm overlays the in arm at offset zero
    // and is the same 16 bytes, so this writes within the buffer `copy_in`
    // already validated.
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}
