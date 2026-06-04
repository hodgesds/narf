//! syncobj — DRM sync objects wrapping a dma-fence.
//!
//! A **syncobj** is a kernel object owned by a per-fd handle table that
//! holds a single `dma-fence` (binary syncobj) or a timeline of fences
//! (timeline syncobj — not implemented here).  Userspace creates,
//! signals, waits on, and shares syncobjs across drivers and fd
//! boundaries.  GPU drivers attach the fence completion side to a
//! command-buffer job; the wait side is the consumer-side primitive
//! that blocks compositors / GL/Vulkan drivers until previous work
//! retires.
//!
//! Linux model:
//!
//! - `struct drm_syncobj` owns a `dma_fence *` and refcount.  See
//!   `include/drm/drm_syncobj.h` + `drivers/gpu/drm/drm_syncobj.c`.
//! - `struct dma_fence` is the underlying signal/wait primitive
//!   (`drivers/dma-buf/dma-fence.c`).  Each fence has an ops vtable
//!   (`enable_signaling`, `wait`, etc.) and a single-bit-or-no signal
//!   state.
//! - `drm_syncobj_create_ioctl` (handle table alloc), `..._destroy`
//!   (handle table free), `..._wait` (block on N handles), `..._signal`
//!   (mark a syncobj's current fence signalled).
//!
//! What is implemented:
//!
//! - [`DmaFence`] trait — `is_signalled` / `wait` / `signal`.
//! - [`BinaryFence`] — a software-only fence with an atomic signalled
//!   bit; serves as the default fence for syncobjs that don't yet have
//!   a hardware-backed fence attached.
//! - [`SyncObj`] — one drm_syncobj.
//! - [`SyncObjTable`] — per-fd handle → syncobj table.
//! - Helpers `wait_handles` / `signal_handles` match the array-wait /
//!   array-signal ioctls in Linux.
//!
//! ## Deferred
//!
//! - **Timeline syncobjs** — multi-point fences with monotonically
//!   increasing 64-bit timeline values.  Linux supports them via the
//!   `chain` field; we keep `fence` as a single Arc for now.
//! - **Cross-fd sharing via dma-fence fd handoff** — Linux uses
//!   `sync_file` to wrap a fence in an fd that another fd-table can
//!   pick up; lands when the kernel fd-table arrives.
//!
//! ## Linux references
//!
//! - `drivers/gpu/drm/drm_syncobj.c` — handle table + ioctls.
//! - `drivers/dma-buf/dma-fence.c` — fence ops + signalling.
//! - `include/uapi/drm/drm.h` — `DRM_SYNCOBJ_*` flags.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

// ── Errors ─────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SyncError {
    /// Handle not in the syncobj table — Linux returns -ENOENT.
    NotFound,
    /// Wait timed out — Linux returns -ETIME.
    Timeout,
    /// Per-fd handle table at capacity.
    Full,
    /// Zero-handle array passed to wait/signal.
    EmptyHandles,
}

// ── Flag bits (match include/uapi/drm/drm.h) ──────────────────────────

/// `DRM_SYNCOBJ_CREATE_SIGNALED` — syncobj starts already signalled.
pub const SYNCOBJ_CREATE_SIGNALED: u32 = 1 << 0;
/// `DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL` — wait for all (vs first) handles.
pub const SYNCOBJ_WAIT_FLAGS_WAIT_ALL: u32 = 1 << 0;
/// `DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT` — wait for fence to be set
/// (not just signalled).  Not yet honoured here.
pub const SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT: u32 = 1 << 1;

// ── DmaFence trait ─────────────────────────────────────────────────────

/// One-shot signal primitive — Linux's `struct dma_fence` collapsed to
/// the minimum operations a syncobj or job needs.
///
/// Linux equivalent: `include/linux/dma-fence.h::struct dma_fence` plus
/// its `ops` vtable.  We dropped seqno / timeline scaffolding because
/// timeline syncobjs are deferred; a binary fence + atomic bit suffices.
pub trait DmaFence: Send + Sync + core::fmt::Debug {
    /// Has this fence been signalled?
    ///
    /// Linux equivalent: `dma_fence_is_signaled`.
    fn is_signalled(&self) -> bool;

    /// Block (or busy-spin in no_std) until signalled or `timeout_ns`
    /// elapses.  Returns `true` if signalled, `false` on timeout.
    ///
    /// Linux equivalent: `dma_fence_wait_timeout` (returns jiffies
    /// remaining; we collapse to bool).
    fn wait(&self, timeout_ns: u64) -> bool;

    /// Mark this fence as signalled.  Idempotent.
    ///
    /// Linux equivalent: `dma_fence_signal`.
    fn signal(&self);
}

// ── BinaryFence ────────────────────────────────────────────────────────

/// Software-only one-shot fence.
///
/// Used as the default fence under a freshly-created syncobj.  Drivers
/// can replace it with a hardware-backed fence (e.g. a CP fence
/// generated when a command buffer retires).
///
/// Linux equivalent: a freshly-allocated `dma_fence` with the
/// stub-ops vtable from `dma_fence_get_stub`.
#[derive(Debug)]
pub struct BinaryFence {
    signalled: AtomicBool,
}

impl BinaryFence {
    /// New unsignalled fence.
    pub fn new() -> Arc<Self> {
        Arc::new(BinaryFence {
            signalled: AtomicBool::new(false),
        })
    }

    /// New already-signalled fence — for syncobjs created with
    /// `DRM_SYNCOBJ_CREATE_SIGNALED`.
    pub fn signalled() -> Arc<Self> {
        Arc::new(BinaryFence {
            signalled: AtomicBool::new(true),
        })
    }
}

impl DmaFence for BinaryFence {
    fn is_signalled(&self) -> bool {
        self.signalled.load(Ordering::Acquire)
    }

    fn wait(&self, timeout_ns: u64) -> bool {
        // No suspend infrastructure in no_std; if already signalled,
        // return immediately, else "tick" the timeout by spinning
        // (caller controls TSC-deadline elsewhere). Tests should call
        // signal() before wait() to avoid burning real time.
        if self.is_signalled() {
            return true;
        }
        // Bounded poll loop. A higher-level kernel pump would convert
        // this to a real wait_event_timeout against a wait queue.
        let mut spins: u64 = 0;
        let cap = timeout_ns.saturating_div(100).min(1_000_000);
        while spins < cap {
            if self.is_signalled() {
                return true;
            }
            core::hint::spin_loop();
            spins += 1;
        }
        self.is_signalled()
    }

    fn signal(&self) {
        self.signalled.store(true, Ordering::Release);
    }
}

// ── SyncObj ────────────────────────────────────────────────────────────

/// One DRM sync object — a handle that points at a `dma-fence`.
///
/// Linux equivalent: `struct drm_syncobj` in
/// `include/drm/drm_syncobj.h`.
#[derive(Debug)]
pub struct SyncObj {
    /// Per-fd handle assigned at create.
    pub id: u32,
    /// Underlying fence; `None` means "no fence attached yet"
    /// (Linux: `syncobj->fence == NULL` — wait blocks until set when
    /// `WAIT_FOR_SUBMIT`).
    pub fence: Option<Arc<dyn DmaFence>>,
}

impl SyncObj {
    /// Replace the current fence (Linux: `drm_syncobj_replace_fence`).
    pub fn replace_fence(&mut self, fence: Arc<dyn DmaFence>) {
        self.fence = Some(fence);
    }

    /// Is this syncobj's fence signalled?  No-fence → unsignalled.
    pub fn is_signalled(&self) -> bool {
        self.fence
            .as_ref()
            .map(|f| f.is_signalled())
            .unwrap_or(false)
    }
}

// ── SyncObjTable ───────────────────────────────────────────────────────

/// Maximum syncobj handles per fd.  Linux uses an xarray (unbounded);
/// we cap conservatively.
const SYNCOBJ_TABLE_MAX: usize = 4096;

/// Per-fd handle → syncobj table.
///
/// Linux equivalent: `file_priv->syncobj_xa`.
#[derive(Debug, Default)]
pub struct SyncObjTable {
    objs: Vec<SyncObj>,
    next: u32,
}

impl SyncObjTable {
    pub fn new() -> Self {
        SyncObjTable {
            objs: Vec::new(),
            next: 1,
        }
    }

    /// Create a new syncobj.  If `flags & SYNCOBJ_CREATE_SIGNALED`, the
    /// new syncobj starts with a signalled binary fence; otherwise no
    /// fence is attached and waiters block until one is bound.
    ///
    /// Linux equivalent: `drm_syncobj_create_ioctl` →
    /// `drm_syncobj_create_as_handle` → `drm_syncobj_create`.
    pub fn create(&mut self, flags: u32) -> Result<u32, SyncError> {
        if self.objs.len() >= SYNCOBJ_TABLE_MAX {
            return Err(SyncError::Full);
        }
        let id = self.alloc_id();
        let fence: Option<Arc<dyn DmaFence>> = if flags & SYNCOBJ_CREATE_SIGNALED != 0 {
            Some(BinaryFence::signalled() as Arc<dyn DmaFence>)
        } else {
            None
        };
        self.objs.push(SyncObj { id, fence });
        Ok(id)
    }

    /// Create a syncobj from an existing fence.  Used by the scheduler
    /// to publish a job's output fence to userspace.
    pub fn create_with_fence(&mut self, fence: Arc<dyn DmaFence>) -> Result<u32, SyncError> {
        if self.objs.len() >= SYNCOBJ_TABLE_MAX {
            return Err(SyncError::Full);
        }
        let id = self.alloc_id();
        self.objs.push(SyncObj {
            id,
            fence: Some(fence),
        });
        Ok(id)
    }

    /// Destroy a syncobj by handle.
    ///
    /// Linux equivalent: `drm_syncobj_destroy_ioctl`.
    pub fn destroy(&mut self, id: u32) -> Result<(), SyncError> {
        let pos = self
            .objs
            .iter()
            .position(|o| o.id == id)
            .ok_or(SyncError::NotFound)?;
        self.objs.swap_remove(pos);
        Ok(())
    }

    /// Look up a syncobj by handle (read-only).
    pub fn get(&self, id: u32) -> Result<&SyncObj, SyncError> {
        self.objs
            .iter()
            .find(|o| o.id == id)
            .ok_or(SyncError::NotFound)
    }

    /// Look up a syncobj by handle (mutable).
    pub fn get_mut(&mut self, id: u32) -> Result<&mut SyncObj, SyncError> {
        self.objs
            .iter_mut()
            .find(|o| o.id == id)
            .ok_or(SyncError::NotFound)
    }

    /// Wait on an array of syncobj handles.
    ///
    /// - With `SYNCOBJ_WAIT_FLAGS_WAIT_ALL`, returns Ok once *all* are
    ///   signalled or `timeout_ns` expires.
    /// - Without it, returns Ok on the *first* signalled handle.
    ///
    /// Returns `Err(Timeout)` if the deadline expires before the
    /// condition holds.  An empty handle array is an error per Linux's
    /// EINVAL on count_handles == 0.
    ///
    /// Linux equivalent: `drm_syncobj_array_wait`.
    pub fn wait_handles(&self, ids: &[u32], timeout_ns: u64, flags: u32) -> Result<u32, SyncError> {
        if ids.is_empty() {
            return Err(SyncError::EmptyHandles);
        }
        // Resolve handles up-front so an unknown handle errors out.
        let fences: Vec<Option<Arc<dyn DmaFence>>> = ids
            .iter()
            .map(|&id| self.get(id).map(|o| o.fence.clone()))
            .collect::<Result<_, _>>()?;

        let wait_all = (flags & SYNCOBJ_WAIT_FLAGS_WAIT_ALL) != 0;

        // First, fast path — check signalled state already.
        let first_signalled = || -> Option<u32> {
            for (i, f) in fences.iter().enumerate() {
                if let Some(f) = f {
                    if f.is_signalled() {
                        return Some(ids[i]);
                    }
                }
            }
            None
        };
        let all_signalled = || -> bool {
            fences
                .iter()
                .all(|f| f.as_ref().is_some_and(|f| f.is_signalled()))
        };

        if wait_all {
            if all_signalled() {
                return Ok(ids[ids.len() - 1]);
            }
        } else if let Some(id) = first_signalled() {
            return Ok(id);
        }

        // Slow path — bounded poll. Each fence's `wait` will spin up
        // to `timeout_ns / count`. This mirrors Linux's per-fence
        // wait_timeout split (which is jiffies-based).
        let per_fence = timeout_ns.saturating_div(ids.len() as u64).max(1);
        for (i, f) in fences.iter().enumerate() {
            if let Some(f) = f {
                if f.wait(per_fence) && !wait_all {
                    return Ok(ids[i]);
                }
            }
        }

        if wait_all && all_signalled() {
            return Ok(ids[ids.len() - 1]);
        }
        if !wait_all {
            if let Some(id) = first_signalled() {
                return Ok(id);
            }
        }
        Err(SyncError::Timeout)
    }

    /// Signal an array of syncobj handles.
    ///
    /// Linux equivalent: `drm_syncobj_signal_ioctl`.  Each syncobj's
    /// current fence is signalled; if it has no fence attached, a
    /// fresh already-signalled binary fence is bound.
    pub fn signal_handles(&mut self, ids: &[u32]) -> Result<(), SyncError> {
        if ids.is_empty() {
            return Err(SyncError::EmptyHandles);
        }
        // Pre-validate all handles before any side-effect (atomic).
        for &id in ids {
            self.get(id)?;
        }
        for &id in ids {
            let obj = self.get_mut(id).expect("validated above");
            match &obj.fence {
                Some(f) => f.signal(),
                None => obj.fence = Some(BinaryFence::signalled() as Arc<dyn DmaFence>),
            }
        }
        Ok(())
    }

    /// Reset (clear fence) on an array of handles — `DRM_SYNCOBJ_RESET`
    /// (`drm_syncobj_reset_ioctl`).
    pub fn reset_handles(&mut self, ids: &[u32]) -> Result<(), SyncError> {
        if ids.is_empty() {
            return Err(SyncError::EmptyHandles);
        }
        for &id in ids {
            self.get(id)?;
        }
        for &id in ids {
            let obj = self.get_mut(id).expect("validated above");
            obj.fence = None;
        }
        Ok(())
    }

    /// Live handle count.
    pub fn len(&self) -> usize {
        self.objs.len()
    }

    /// Empty when no handles are live.
    pub fn is_empty(&self) -> bool {
        self.objs.is_empty()
    }

    fn alloc_id(&mut self) -> u32 {
        let mut candidate = self.next;
        loop {
            if candidate == 0 {
                candidate = 1;
            }
            if !self.objs.iter().any(|o| o.id == candidate) {
                self.next = candidate.wrapping_add(1).max(1);
                return candidate;
            }
            candidate = candidate.wrapping_add(1).max(1);
        }
    }
}
