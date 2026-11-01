//! syncobj — DRM sync objects wrapping a dma-fence.
//!
//! A **syncobj** is a kernel object owned by a per-fd handle table that
//! holds a single `dma-fence` (binary syncobj) or a timeline of fences
//! (timeline syncobj, a `dma_fence_chain`). Userspace creates, signals,
//! waits on, and shares syncobjs across drivers and fd boundaries. GPU
//! drivers attach the fence completion side to a command-buffer job; the
//! wait side is the consumer-side primitive that blocks compositors /
//! GL/Vulkan drivers until previous work retires.
//!
//! Linux model:
//!
//! - `struct drm_syncobj` owns a `dma_fence *` and refcount. See
//!   `include/drm/drm_syncobj.h` + `drivers/gpu/drm/drm_syncobj.c`. A handle
//!   names a refcounted object, so a syncobj fd (`HANDLE_TO_FD`) imported
//!   into another table names the SAME object: [`SyncObjCore`] is that
//!   object, and the table holds `Arc`s of it.
//! - A timeline syncobj's payload is a `dma_fence_chain`
//!   (`drivers/dma-buf/dma-fence-chain.c`): each node holds one fence, its
//!   point (`seqno`), the previous node's point (`prev_seqno`) and a link to
//!   the previous payload. [`FenceChain`] mirrors it, including the
//!   garbage collection `dma_fence_chain_walk` performs (signalled nodes are
//!   unlinked) and the context rule for out-of-order points.
//!
//! What is implemented:
//!
//! - [`DmaFence`] trait — `is_signalled` / `wait` / `signal`.
//! - [`BinaryFence`] — a software-only fence with an atomic signalled bit
//!   (also Linux's signalled stub, `dma_fence_get_stub`).
//! - [`FenceChain`], [`find_seqno`], [`query_point`] — timeline points.
//! - [`FenceArray`] — a container fence (`dma_fence_array`), and the
//!   `narf_filesystem::DrmFence` adapters a sync_file needs both ways.
//! - [`SyncObjCore`] / [`SyncObj`] / [`SyncObjTable`] — the object, a handle
//!   to it, and the per-fd table.
//! - [`poll_wait`] — one evaluation of `drm_syncobj_array_wait_timeout`'s
//!   condition, which the ioctl layer drives to a deadline.
//!
//! ## Linux references
//!
//! - `drivers/gpu/drm/drm_syncobj.c` — handle table + ioctls.
//! - `drivers/dma-buf/dma-fence.c` — fence ops + signalling.
//! - `drivers/dma-buf/dma-fence-chain.c` — timeline nodes.
//! - `include/uapi/drm/drm.h` — `DRM_SYNCOBJ_*` flags.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

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
/// `DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT` — wait for a fence (or the
/// timeline point) to be attached, not only for it to signal.
pub const SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT: u32 = 1 << 1;
/// `DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE` — wait only for the point to be
/// attached; an attached point counts as signalled.
pub const SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE: u32 = 1 << 2;
/// `DRM_SYNCOBJ_WAIT_FLAGS_WAIT_DEADLINE` — a fence deadline hint.
pub const SYNCOBJ_WAIT_FLAGS_WAIT_DEADLINE: u32 = 1 << 3;
/// `DRM_SYNCOBJ_QUERY_FLAGS_LAST_SUBMITTED`.
pub const SYNCOBJ_QUERY_FLAGS_LAST_SUBMITTED: u32 = 1 << 0;

// ── DmaFence trait ─────────────────────────────────────────────────────

/// One-shot signal primitive — Linux's `struct dma_fence` collapsed to
/// the minimum operations a syncobj or job needs.
///
/// Linux equivalent: `include/linux/dma-fence.h::struct dma_fence` plus
/// its `ops` vtable.
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

    /// Driver-private ordered execution-context key. A later job on the same
    /// context already depends on this fence and need not synchronously wait
    /// before queueing (Linux's `dma_fence_match_context` optimization).
    fn context(&self) -> Option<u64> {
        None
    }

    /// `dma_fence.seqno` within [`DmaFence::context`].
    fn seqno(&self) -> u64 {
        0
    }

    /// `dma_fence_ops.get_driver_name`.
    fn driver_name(&self) -> &str {
        "narf"
    }

    /// `to_dma_fence_chain`: this fence as a timeline node, if it is one.
    fn as_chain(&self) -> Option<&FenceChain> {
        None
    }

    /// `dma_fence_unwrap` for fences that already are sync_file leaves (a
    /// driver fence that also implements `DrmFence`, or an imported
    /// sync_file): those leaves, so exporting keeps their identity. `None`
    /// wraps the fence in an adapter instead ([`to_drm_leaves`]).
    fn drm_leaves(self: Arc<Self>) -> Option<Vec<Arc<dyn narf_filesystem::DrmFence>>> {
        None
    }
}

/// Wait for every fence in `fences` until `timeout_ns` from now.
fn wait_all(fences: &[Arc<dyn DmaFence>], timeout_ns: u64) -> bool {
    let deadline = narf_time::monotonic_ns().saturating_add(timeout_ns);
    for f in fences {
        let remaining = deadline.saturating_sub(narf_time::monotonic_ns());
        if !f.is_signalled() && !f.wait(remaining) {
            return false;
        }
    }
    true
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
    /// `DRM_SYNCOBJ_CREATE_SIGNALED`, and Linux's `dma_fence_get_stub()`.
    pub fn signalled() -> Arc<Self> {
        Arc::new(BinaryFence {
            signalled: AtomicBool::new(true),
        })
    }
}

/// `dma_fence_get_stub()` as a trait object.
pub fn stub() -> Arc<dyn DmaFence> {
    BinaryFence::signalled()
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

// ── FenceArray ─────────────────────────────────────────────────────────

/// A container fence that signals once every member has: Linux's
/// `dma_fence_array` with `signal_on_any = false`, which
/// `dma_fence_unwrap_merge` and `sync_file` imports produce.
#[derive(Debug)]
pub struct FenceArray {
    fences: Vec<Arc<dyn DmaFence>>,
}

impl FenceArray {
    pub fn new(fences: Vec<Arc<dyn DmaFence>>) -> Arc<Self> {
        Arc::new(FenceArray { fences })
    }
}

impl DmaFence for FenceArray {
    fn is_signalled(&self) -> bool {
        self.fences.iter().all(|f| f.is_signalled())
    }
    fn wait(&self, timeout_ns: u64) -> bool {
        wait_all(&self.fences, timeout_ns)
    }
    /// Not CPU-signallable: its members are.
    fn signal(&self) {}
    fn drm_leaves(self: Arc<Self>) -> Option<Vec<Arc<dyn narf_filesystem::DrmFence>>> {
        let mut out = Vec::new();
        for f in &self.fences {
            out.extend(to_drm_leaves(f));
        }
        Some(out)
    }
}

// ── FenceChain ─────────────────────────────────────────────────────────

/// Chain contexts (`dma_fence_context_alloc(1)` for a new timeline run).
static CHAIN_CONTEXT: AtomicU64 = AtomicU64::new(1);

/// One timeline node — Linux's `struct dma_fence_chain`.
#[derive(Debug)]
pub struct FenceChain {
    /// This node's point (`base.seqno`).
    seqno: u64,
    /// The previous node's point when this node continues its run, else 0.
    prev_seqno: u64,
    /// The run this node belongs to (`base.context`).
    context: u64,
    /// The fence this point waits for.
    fence: Arc<dyn DmaFence>,
    /// The previous payload, unlinked once signalled (`chain->prev`).
    prev: IrqSafeSpinLock<Option<Arc<dyn DmaFence>>>,
}

impl FenceChain {
    /// `dma_fence_chain_init(chain, prev, fence, point)`: a later point
    /// continues `prev`'s run; an earlier or equal one (an unordered
    /// timeline) starts a new run whose point is `max(prev, point)`.
    pub fn new(prev: Option<Arc<dyn DmaFence>>, fence: Arc<dyn DmaFence>, point: u64) -> Arc<Self> {
        let prev_chain = prev
            .as_ref()
            .and_then(|p| p.as_chain().map(|c| (c.context, c.seqno)));
        let (context, prev_seqno, seqno) = match prev_chain {
            // __dma_fence_is_later on a 64-bit fence: point > prev->seqno.
            Some((context, prev_seqno)) if point > prev_seqno => (context, prev_seqno, point),
            Some((_, prev_seqno)) => (
                CHAIN_CONTEXT.fetch_add(1, Ordering::Relaxed),
                0,
                prev_seqno.max(point),
            ),
            None => (CHAIN_CONTEXT.fetch_add(1, Ordering::Relaxed), 0, point),
        };
        Arc::new(FenceChain {
            seqno,
            prev_seqno,
            context,
            fence,
            prev: IrqSafeSpinLock::new(prev),
        })
    }

    /// This node's point.
    pub fn seqno(&self) -> u64 {
        self.seqno
    }

    /// The previous node's point (0 when this node starts a run).
    pub fn prev_seqno(&self) -> u64 {
        self.prev_seqno
    }

    /// `dma_fence_chain_contained`: the fence this node holds.
    pub fn contained(&self) -> &Arc<dyn DmaFence> {
        &self.fence
    }

    fn prev(&self) -> Option<Arc<dyn DmaFence>> {
        self.prev.lock().clone()
    }

    /// `dma_fence_chain_walk` from this node: the first previous payload
    /// that is not yet signalled, unlinking the signalled ones on the way.
    pub fn walk(&self) -> Option<Arc<dyn DmaFence>> {
        loop {
            let prev = self.prev()?;
            let (signalled, replacement) = match prev.as_chain() {
                Some(c) => (c.fence.is_signalled(), c.prev()),
                None => (prev.is_signalled(), None),
            };
            if !signalled {
                return Some(prev);
            }
            // cmpxchg(&chain->prev, prev, replacement).
            let unlinked = {
                let mut slot = self.prev.lock();
                if slot.as_ref().is_some_and(|p| same(p, &prev)) {
                    core::mem::replace(&mut *slot, replacement)
                } else {
                    None
                }
            };
            // Dropped outside the lock; FenceChain's Drop unlinks iteratively.
            drop(unlinked);
        }
    }
}

/// Whether two fence handles name the same fence.
fn same(a: &Arc<dyn DmaFence>, b: &Arc<dyn DmaFence>) -> bool {
    core::ptr::eq(
        Arc::as_ptr(a) as *const () as *const u8,
        Arc::as_ptr(b) as *const () as *const u8,
    )
}

impl Drop for FenceChain {
    /// `dma_fence_chain_release`: unlink as much of the chain as this node
    /// holds the last reference to, iteratively, so a long timeline does not
    /// recurse once per node.
    fn drop(&mut self) {
        let mut next = self.prev.lock().take();
        while let Some(p) = next {
            if Arc::strong_count(&p) > 1 {
                break;
            }
            let taken = match p.as_chain() {
                Some(c) => c.prev.lock().take(),
                None => break,
            };
            drop(p);
            next = taken;
        }
    }
}

impl DmaFence for FenceChain {
    /// `dma_fence_chain_signaled`: this node's fence and every earlier one.
    fn is_signalled(&self) -> bool {
        self.fence.is_signalled() && self.walk().is_none()
    }
    fn wait(&self, timeout_ns: u64) -> bool {
        let deadline = narf_time::monotonic_ns().saturating_add(timeout_ns);
        loop {
            if self.is_signalled() {
                return true;
            }
            let remaining = deadline.saturating_sub(narf_time::monotonic_ns());
            if remaining == 0 {
                return false;
            }
            let pending = if !self.fence.is_signalled() {
                self.fence.clone()
            } else {
                match self.walk() {
                    Some(p) => p,
                    None => return true,
                }
            };
            if !pending.wait(remaining) {
                return self.is_signalled();
            }
        }
    }
    /// A chain is not CPU-signallable: its fences are.
    fn signal(&self) {}
    fn driver_name(&self) -> &str {
        "dma_fence_chain"
    }
    fn as_chain(&self) -> Option<&FenceChain> {
        Some(self)
    }
    /// `dma_fence_unwrap` of a chain: every contained fence still linked.
    fn drm_leaves(self: Arc<Self>) -> Option<Vec<Arc<dyn narf_filesystem::DrmFence>>> {
        let mut out = to_drm_leaves(&self.fence);
        let mut cur = self.walk();
        while let Some(node) = cur {
            match node.as_chain() {
                Some(c) => {
                    out.extend(to_drm_leaves(&c.fence));
                    cur = c.walk();
                }
                None => {
                    out.extend(to_drm_leaves(&node));
                    cur = None;
                }
            }
        }
        Some(out)
    }
}

/// `dma_fence_unwrap_merge` of one fence before it becomes a timeline
/// point: a chain is flattened to the array of its fences (Linux WARNs on
/// chaining a chain through the contained fence).
fn flatten(fence: Arc<dyn DmaFence>) -> Arc<dyn DmaFence> {
    let Some(chain) = fence.as_chain() else {
        return fence;
    };
    let mut leaves = alloc::vec![chain.fence.clone()];
    let mut cur = chain.walk();
    while let Some(node) = cur {
        match node.as_chain() {
            Some(c) => {
                leaves.push(c.fence.clone());
                cur = c.walk();
            }
            None => {
                leaves.push(node);
                cur = None;
            }
        }
    }
    leaves.retain(|f| !f.is_signalled());
    match leaves.len() {
        0 => stub(),
        1 => leaves.pop().unwrap(),
        _ => FenceArray::new(leaves),
    }
}

/// `dma_fence_chain_find_seqno` on a syncobj payload, as
/// `drm_syncobj_find_fence` uses it:
///
/// - no payload: `Err` (-EINVAL; WAIT_FOR_SUBMIT callers wait instead);
/// - point 0: the whole payload;
/// - a non-chain payload, or a timeline whose last point is below `point`:
///   `Err` (not submitted yet);
/// - otherwise the node whose run covers `point`, or `Ok(None)` when every
///   node up to it has signalled (the caller substitutes the stub).
pub fn find_seqno(
    payload: Option<Arc<dyn DmaFence>>,
    point: u64,
) -> Result<Option<Arc<dyn DmaFence>>, ()> {
    let fence = payload.ok_or(())?;
    if point == 0 {
        return Ok(Some(fence));
    }
    let Some(head) = fence.as_chain() else {
        return Err(());
    };
    if head.seqno < point {
        return Err(());
    }
    let context = head.context;
    let mut cur = Some(fence.clone());
    while let Some(node) = cur.clone() {
        match node.as_chain() {
            Some(c) if c.context == context && c.prev_seqno >= point => cur = c.walk(),
            _ => break,
        }
    }
    Ok(cur)
}

/// `drm_syncobj_query_ioctl` for one payload: 0 for a binary syncobj; the
/// last point attached with `last_submitted`; else the last signalled point
/// of the current run (an unordered timeline can make this 0).
pub fn query_point(payload: Option<Arc<dyn DmaFence>>, last_submitted: bool) -> u64 {
    let Some(fence) = payload else {
        return 0;
    };
    let Some(head) = fence.as_chain() else {
        return 0;
    };
    if last_submitted {
        return head.seqno;
    }
    let context = head.context;
    let mut last = fence.clone();
    let mut cur = Some(fence.clone());
    while let Some(node) = cur {
        match node.as_chain() {
            Some(c) if c.context == context => {
                cur = c.walk();
                last = node.clone();
            }
            _ => break,
        }
    }
    let node = last.as_chain().expect("same-context nodes are chains");
    if last.is_signalled() {
        node.seqno
    } else {
        node.prev_seqno
    }
}

// ── sync_file adapters ─────────────────────────────────────────────────

/// A syncobj fence exposed as a sync_file leaf (`sync_file_create(fence)`).
#[derive(Debug)]
struct AsDrmFence(Arc<dyn DmaFence>);

impl narf_filesystem::DrmFence for AsDrmFence {
    fn is_signalled(&self) -> bool {
        self.0.is_signalled()
    }
    fn wait(&self, timeout_ms: u64) -> bool {
        self.0.wait(timeout_ms.saturating_mul(1_000_000))
    }
    fn context(&self) -> Option<u64> {
        self.0.context()
    }
    fn seqno(&self) -> u64 {
        self.0.seqno()
    }
    fn driver_name(&self) -> &str {
        self.0.driver_name()
    }
}

/// `dma_fence_unwrap` of `fence` into sync_file leaves.
pub fn to_drm_leaves(fence: &Arc<dyn DmaFence>) -> Vec<Arc<dyn narf_filesystem::DrmFence>> {
    match fence.clone().drm_leaves() {
        Some(leaves) => leaves,
        None => {
            alloc::vec![Arc::new(AsDrmFence(fence.clone())) as Arc<dyn narf_filesystem::DrmFence>]
        }
    }
}

/// One sync_file leaf as a syncobj fence.
struct FromDrmFence(Arc<dyn narf_filesystem::DrmFence>);

impl core::fmt::Debug for FromDrmFence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FromDrmFence")
            .field("context", &self.0.context())
            .field("seqno", &self.0.seqno())
            .finish()
    }
}

impl DmaFence for FromDrmFence {
    fn is_signalled(&self) -> bool {
        self.0.is_signalled()
    }
    fn wait(&self, timeout_ns: u64) -> bool {
        self.0.wait(timeout_ns.div_ceil(1_000_000))
    }
    fn signal(&self) {}
    fn context(&self) -> Option<u64> {
        self.0.context()
    }
    fn seqno(&self) -> u64 {
        self.0.seqno()
    }
    fn drm_leaves(self: Arc<Self>) -> Option<Vec<Arc<dyn narf_filesystem::DrmFence>>> {
        Some(alloc::vec![self.0.clone()])
    }
}

/// `sync_file_get_fence`: the leaves of an imported sync_file as one
/// syncobj fence — the stub for none, the leaf for one, an array otherwise.
pub fn from_drm_leaves(leaves: Vec<Arc<dyn narf_filesystem::DrmFence>>) -> Arc<dyn DmaFence> {
    let mut fences: Vec<Arc<dyn DmaFence>> = leaves
        .into_iter()
        .map(|l| Arc::new(FromDrmFence(l)) as Arc<dyn DmaFence>)
        .collect();
    match fences.len() {
        0 => stub(),
        1 => fences.pop().unwrap(),
        _ => FenceArray::new(fences),
    }
}

// ── SyncObjCore / SyncObj ──────────────────────────────────────────────

/// The refcounted object a syncobj handle names (`struct drm_syncobj`).
/// Shared by every handle and syncobj fd that names it.
#[derive(Debug)]
pub struct SyncObjCore {
    fence: IrqSafeSpinLock<Option<Arc<dyn DmaFence>>>,
}

impl SyncObjCore {
    /// A new object with `fence` as its payload.
    pub fn new(fence: Option<Arc<dyn DmaFence>>) -> Arc<Self> {
        Arc::new(SyncObjCore {
            fence: IrqSafeSpinLock::new(fence),
        })
    }

    /// `drm_syncobj_fence_get`.
    pub fn fence(&self) -> Option<Arc<dyn DmaFence>> {
        self.fence.lock().clone()
    }

    /// `drm_syncobj_replace_fence` (`None` resets).
    pub fn replace_fence(&self, fence: Option<Arc<dyn DmaFence>>) {
        let old = core::mem::replace(&mut *self.fence.lock(), fence);
        drop(old);
    }

    /// `drm_syncobj_add_point`: `fence` becomes timeline point `point`.
    /// An unordered point is accepted, as Linux accepts it (with a debug
    /// message): it starts a new run (see [`FenceChain::new`]).
    pub fn add_point(&self, fence: Arc<dyn DmaFence>, point: u64) {
        let fence = flatten(fence);
        let prev = {
            let mut slot = self.fence.lock();
            let prev = slot.clone();
            *slot = Some(FenceChain::new(prev.clone(), fence, point) as Arc<dyn DmaFence>);
            prev
        };
        // "Walk the chain once to trigger garbage collection".
        let mut cur = prev;
        while let Some(node) = cur {
            cur = node.as_chain().and_then(FenceChain::walk);
        }
    }

    /// `drm_syncobj_find_fence(handle, point, 0)` once the object is found:
    /// the fence for `point`, with the stub for an already-signalled point;
    /// `Err` (-EINVAL) when there is no fence or the point is not submitted.
    pub fn find_fence(&self, point: u64) -> Result<Arc<dyn DmaFence>, ()> {
        find_seqno(self.fence(), point).map(|f| f.unwrap_or_else(stub))
    }

    /// Whether the payload (every point) is signalled; no payload is not.
    pub fn is_signalled(&self) -> bool {
        self.fence().is_some_and(|f| f.is_signalled())
    }
}

/// One live handle in a [`SyncObjTable`].
#[derive(Debug)]
pub struct SyncObj {
    /// Per-fd handle assigned at create.
    pub id: u32,
    core: Arc<SyncObjCore>,
}

impl SyncObj {
    /// The object behind the handle.
    pub fn core(&self) -> &Arc<SyncObjCore> {
        &self.core
    }

    /// The current payload (`None`: no fence attached).
    pub fn fence(&self) -> Option<Arc<dyn DmaFence>> {
        self.core.fence()
    }

    /// Replace the current fence (Linux: `drm_syncobj_replace_fence`).
    pub fn replace_fence(&self, fence: Arc<dyn DmaFence>) {
        self.core.replace_fence(Some(fence));
    }

    /// Detach the fence (`drm_syncobj_replace_fence(syncobj, NULL)`).
    pub fn reset(&self) {
        self.core.replace_fence(None);
    }

    /// Is this syncobj's fence signalled?  No-fence → unsignalled.
    pub fn is_signalled(&self) -> bool {
        self.core.is_signalled()
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
    pub const fn new() -> Self {
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
        let fence = (flags & SYNCOBJ_CREATE_SIGNALED != 0).then(stub);
        self.insert(SyncObjCore::new(fence))
    }

    /// Create a syncobj from an existing fence.  Used by the scheduler
    /// to publish a job's output fence to userspace.
    pub fn create_with_fence(&mut self, fence: Arc<dyn DmaFence>) -> Result<u32, SyncError> {
        self.insert(SyncObjCore::new(Some(fence)))
    }

    /// A new handle naming `core` (`drm_syncobj_get_handle`, and the
    /// `xa_alloc` of `drm_syncobj_fd_to_handle`).
    pub fn insert(&mut self, core: Arc<SyncObjCore>) -> Result<u32, SyncError> {
        if self.objs.len() >= SYNCOBJ_TABLE_MAX {
            return Err(SyncError::Full);
        }
        let id = self.alloc_id();
        self.objs.push(SyncObj { id, core });
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

    /// `drm_syncobj_array_find`: the objects behind `ids`, each referenced
    /// so the table lock can be dropped before a wait. Any unknown handle is
    /// `NotFound` (-ENOENT).
    pub fn find_all(&self, ids: &[u32]) -> Result<Vec<Arc<SyncObjCore>>, SyncError> {
        ids.iter()
            .map(|&id| self.get(id).map(|o| o.core.clone()))
            .collect()
    }

    /// Wait on an array of syncobj handles.
    ///
    /// - With `SYNCOBJ_WAIT_FLAGS_WAIT_ALL`, returns Ok once *all* are
    ///   signalled or `timeout_ns` expires.
    /// - Without it, returns Ok on the *first* signalled handle.
    ///
    /// Returns `Err(Timeout)` if the deadline expires before the
    /// condition holds.  An empty handle array is an error.
    pub fn wait_handles(&self, ids: &[u32], timeout_ns: u64, flags: u32) -> Result<u32, SyncError> {
        let fences = self.snapshot_fences(ids)?;
        Self::wait_fences(ids, &fences, timeout_ns, flags)
    }

    /// Clone the current fences for an array of handles. Callers that keep the
    /// table behind an IRQ-safe lock use this to drop that lock before a
    /// potentially long hardware wait.
    pub fn snapshot_fences(
        &self,
        ids: &[u32],
    ) -> Result<Vec<Option<Arc<dyn DmaFence>>>, SyncError> {
        if ids.is_empty() {
            return Err(SyncError::EmptyHandles);
        }
        ids.iter()
            .map(|&id| self.get(id).map(|o| o.fence()))
            .collect()
    }

    /// Wait on a snapshot returned by [`Self::snapshot_fences`]. The snapshot
    /// keeps each fence alive without retaining the per-fd handle-table lock.
    pub fn wait_fences(
        ids: &[u32],
        fences: &[Option<Arc<dyn DmaFence>>],
        timeout_ns: u64,
        flags: u32,
    ) -> Result<u32, SyncError> {
        if ids.is_empty() || ids.len() != fences.len() {
            return Err(SyncError::EmptyHandles);
        }

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
        if timeout_ns == 0 {
            return Err(SyncError::Timeout);
        }

        // Slow path — bounded poll. Each fence's `wait` will spin up
        // to `timeout_ns / count`.
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
    /// Linux equivalent: `drm_syncobj_signal_ioctl` via
    /// `drm_syncobj_assign_null_handle`. Each syncobj's current payload is
    /// replaced by a fresh already-signalled stub fence. The old payload must
    /// not itself be signalled because it may also back a BO reservation or
    /// sync-file owned by another caller.
    pub fn signal_handles(&mut self, ids: &[u32]) -> Result<(), SyncError> {
        if ids.is_empty() {
            return Err(SyncError::EmptyHandles);
        }
        for core in self.find_all(ids)? {
            core.replace_fence(Some(stub()));
        }
        Ok(())
    }

    /// `drm_syncobj_timeline_signal_ioctl`: a signalled stub becomes point
    /// `points[i]` of each object.
    pub fn timeline_signal(&mut self, ids: &[u32], points: &[u64]) -> Result<(), SyncError> {
        if ids.is_empty() || ids.len() != points.len() {
            return Err(SyncError::EmptyHandles);
        }
        for (core, &point) in self.find_all(ids)?.iter().zip(points) {
            core.add_point(stub(), point);
        }
        Ok(())
    }

    /// Reset (clear fence) on an array of handles — `DRM_SYNCOBJ_RESET`
    /// (`drm_syncobj_reset_ioctl`).
    pub fn reset_handles(&mut self, ids: &[u32]) -> Result<(), SyncError> {
        if ids.is_empty() {
            return Err(SyncError::EmptyHandles);
        }
        for core in self.find_all(ids)? {
            core.replace_fence(None);
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

// ── Array wait ─────────────────────────────────────────────────────────

/// One evaluation of `drm_syncobj_array_wait_timeout`'s condition.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WaitPoll {
    /// The wait is satisfied; the index of the first signalled entry
    /// (`first_signaled`).
    Ready(u32),
    /// Not yet; wait and evaluate again.
    Pending,
    /// An entry has no fence for its point and neither WAIT_FOR_SUBMIT nor
    /// WAIT_AVAILABLE was given: -EINVAL.
    Invalid,
}

/// Evaluate a syncobj array wait once: each object's fence for its point
/// (`dma_fence_chain_find_seqno`), an unsubmitted point counting as pending
/// under WAIT_FOR_SUBMIT / WAIT_AVAILABLE and invalid otherwise, an attached
/// point counting as signalled under WAIT_AVAILABLE.
///
/// LINUX-GAP: Linux resolves each entry's fence once and then waits on that
/// fence; this re-resolves on every evaluation (the ioctl re-executes from
/// its arguments), so a payload replaced during the wait is waited on
/// instead of the one present at entry, and a reset during a wait without
/// WAIT_FOR_SUBMIT reads -EINVAL rather than continuing on the old fence.
pub fn poll_wait(objs: &[Arc<SyncObjCore>], points: &[u64], flags: u32) -> WaitPoll {
    let lenient =
        flags & (SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT | SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE) != 0;
    let available_only = flags & SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE != 0;
    let wait_all = flags & SYNCOBJ_WAIT_FLAGS_WAIT_ALL != 0;
    let mut first = !0u32;
    let mut signalled = 0usize;
    for (i, obj) in objs.iter().enumerate() {
        let point = points.get(i).copied().unwrap_or(0);
        let fence = match find_seqno(obj.fence(), point) {
            Ok(f) => f.unwrap_or_else(stub),
            Err(()) if lenient => continue,
            Err(()) => return WaitPoll::Invalid,
        };
        if available_only || fence.is_signalled() {
            if signalled == 0 {
                first = i as u32;
            }
            signalled += 1;
        }
    }
    if signalled == objs.len() || (signalled > 0 && !wait_all) {
        WaitPoll::Ready(first)
    } else {
        WaitPoll::Pending
    }
}
