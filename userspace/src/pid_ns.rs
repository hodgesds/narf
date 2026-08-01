//! Wave-67 — minimum-viable PID namespaces.
//!
//! Linux semantics replicated here (only the load-bearing slice):
//!
//! - A `PidNamespace` is a translation table between an "outer" PID
//!   (globally unique, allocated from the root [`crate::PID_POOL`])
//!   and an "inner" PID (per-namespace, starts at 1 for the
//!   namespace's init task).
//! - A task that calls `unshare(CLONE_NEWPID)` (or, in the future, a
//!   `clone3` with `CLONE_NEWPID`) becomes pid 1 inside the freshly
//!   minted child namespace; its outer PID is unchanged.
//! - `getpid()` returns the in-namespace value (this is what the
//!   process sees of itself); `kill(pid, sig)` interprets `pid` as
//!   in-namespace and translates back to the outer PID before
//!   delivering the signal.
//! - A task without an entry in [`TASK_PID_NS`] is implicitly in the
//!   root namespace and observes outer == inner.
//!
//! Everything here is gated `#[cfg(feature = "container")]` — a
//! kernel built without containers pays zero runtime cost.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Per-namespace bounded inner-PID pool. Mirrors the root [`crate::PID_POOL`]
/// design (Wave-61): lowest-free allocation, lazy watermark, BTreeSet
/// of released ids.
#[derive(Debug)]
pub struct PidNamespace {
    /// Stable namespace id (nsfs inode in Linux). Shared monotonic
    /// counter across all namespace flavours.
    id: crate::namespaces::NsId,
    /// Lowest inner id not yet minted.
    watermark: AtomicU64,
    /// Inner → outer translation.
    inner_to_outer: IrqSafeSpinLock<BTreeMap<u64, u64>>,
    /// Outer → inner translation.
    outer_to_inner: IrqSafeSpinLock<BTreeMap<u64, u64>>,
    /// Released inner ids available for re-use.
    free: IrqSafeSpinLock<BTreeSet<u64>>,
}

impl PidNamespace {
    /// Build a fresh PID namespace. The first `bind_outer` call will
    /// allocate inner pid 1.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            id: crate::namespaces::alloc_ns_id(),
            watermark: AtomicU64::new(1),
            inner_to_outer: IrqSafeSpinLock::new(BTreeMap::new()),
            outer_to_inner: IrqSafeSpinLock::new(BTreeMap::new()),
            free: IrqSafeSpinLock::new(BTreeSet::new()),
        })
    }

    /// Stable namespace id (nsfs inode in Linux).
    pub fn id(&self) -> crate::namespaces::NsId {
        self.id
    }

    /// Register `outer` in this namespace, allocating the lowest free
    /// inner id (starting at 1). Returns the inner id. If the outer
    /// is already registered, returns its existing inner id —
    /// idempotent so an unshare followed by a fork doesn't double-
    /// bind the parent.
    pub fn bind_outer(&self, outer: u64) -> u64 {
        // Already bound?
        if let Some(&inner) = self.outer_to_inner.lock().get(&outer) {
            return inner;
        }
        // Allocate inner: prefer the lowest released id.
        let inner = {
            let mut f = self.free.lock();
            if let Some(&i) = f.iter().next() {
                f.remove(&i);
                i
            } else {
                self.watermark.fetch_add(1, Ordering::Relaxed)
            }
        };
        self.inner_to_outer.lock().insert(inner, outer);
        self.outer_to_inner.lock().insert(outer, inner);
        inner
    }

    /// Translate an inner pid to its outer pid. None if the inner
    /// pid is not bound in this namespace.
    pub fn inner_to_outer(&self, inner: u64) -> Option<u64> {
        self.inner_to_outer.lock().get(&inner).copied()
    }

    /// Translate an outer pid to its inner pid in this namespace.
    /// None if the outer pid was never registered here.
    pub fn outer_to_inner(&self, outer: u64) -> Option<u64> {
        self.outer_to_inner.lock().get(&outer).copied()
    }

    /// Release `outer` from this namespace, returning its inner pid
    /// to the free pool. Idempotent — releasing an unbound outer is
    /// a silent no-op. Called by the exit observer when a task in
    /// this namespace dies.
    pub fn release_outer(&self, outer: u64) {
        let inner = {
            let mut o2i = self.outer_to_inner.lock();
            match o2i.remove(&outer) {
                Some(i) => i,
                None => return,
            }
        };
        self.inner_to_outer.lock().remove(&inner);
        // pid 1 is "init" — don't recycle it.  The init slot stays
        // empty after init dies; namespace-level reaping is a
        // follow-on once we have a use case for it.
        if inner > 1 {
            self.free.lock().insert(inner);
        }
    }

    /// Number of currently-bound tasks in this namespace.
    pub fn live_count(&self) -> usize {
        self.outer_to_inner.lock().len()
    }
}

// ── Per-task pointer to the active PID namespace ───────────────────
//
// Tasks not present in TASK_PID_NS are implicitly in the root
// namespace (outer == inner). On unshare(CLONE_NEWPID), the calling
// task installs a fresh namespace here and is rebound as inner pid 1.
// On fork, the child inherits the parent's namespace pointer.

static TASK_PID_NS: IrqSafeSpinLock<Option<BTreeMap<u64, Arc<PidNamespace>>>> =
    IrqSafeSpinLock::new(None);

fn ns_table_init(g: &mut Option<BTreeMap<u64, Arc<PidNamespace>>>) {
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
}

static TASK_PID_NS_FOR_CHILDREN: IrqSafeSpinLock<Option<BTreeMap<u64, Arc<PidNamespace>>>> =
    IrqSafeSpinLock::new(None);

/// Look up the PID namespace the given task belongs to. None means
/// the task is in the root namespace and its outer == inner.
pub fn ns_of(task: u64) -> Option<Arc<PidNamespace>> {
    let g = TASK_PID_NS.lock();
    g.as_ref().and_then(|m| m.get(&task).cloned())
}

/// Install `ns` as the active PID namespace for `task`. Replaces any
/// existing entry. Used by `unshare(CLONE_NEWPID)`, `setns`, and the
/// fork-inheritance path.
pub fn set_ns(task: u64, ns: Arc<PidNamespace>) {
    let mut g = TASK_PID_NS.lock();
    ns_table_init(&mut g);
    if let Some(m) = g.as_mut() {
        m.insert(task, ns);
    }
}

/// Remove `task`'s namespace entry — falls back to the root
/// namespace. Called by the exit observer.
pub fn clear_ns(task: u64) {
    let mut g = TASK_PID_NS.lock();
    if let Some(m) = g.as_mut() {
        m.remove(&task);
    }
    let mut g_child = TASK_PID_NS_FOR_CHILDREN.lock();
    if let Some(m) = g_child.as_mut() {
        m.remove(&task);
    }
}

/// Inherit the parent's PID namespace into the child. If the parent called
/// `unshare(CLONE_NEWPID)`, the first child spawned by fork/clone becomes PID 1
/// in the new namespace per Linux semantics.
pub fn inherit_into_child(parent_task: u64, child_task: u64, child_outer_pid: u64) -> Option<u64> {
    let pending_ns = {
        let g = TASK_PID_NS_FOR_CHILDREN.lock();
        g.as_ref().and_then(|m| m.get(&parent_task).cloned())
    };

    let ns = match pending_ns {
        Some(ns) => ns,
        None => ns_of(parent_task)?,
    };

    let inner = ns.bind_outer(child_outer_pid);
    set_ns(child_task, ns);
    Some(inner)
}

/// Linux `unshare(CLONE_NEWPID)` semantics: creates a fresh PID namespace for
/// future children of `task`. The calling task itself remains in its current namespace.
pub fn unshare_pid_ns_for_children(task: u64) -> Arc<PidNamespace> {
    let ns = PidNamespace::new();
    let mut g = TASK_PID_NS_FOR_CHILDREN.lock();
    ns_table_init(&mut g);
    if let Some(m) = g.as_mut() {
        m.insert(task, ns.clone());
    }
    ns
}

/// `unshare(CLONE_NEWPID)` legacy/test helper — create a fresh PID namespace for `task`
/// and bind `task`'s outer pid into it as inner pid 1 immediately.
pub fn unshare_pid_ns(task: u64, outer_pid: u64) -> Arc<PidNamespace> {
    let ns = PidNamespace::new();
    let inner = ns.bind_outer(outer_pid);
    debug_assert_eq!(inner, 1, "first bind in fresh namespace must be pid 1");
    set_ns(task, ns.clone());
    ns
}

/// `setns(fd, CLONE_NEWPID)`-style attach: move `task` into an
/// existing namespace `ns`, binding its outer pid for translation.
/// Returns the inner pid `task`'s outer was assigned.
pub fn attach_to_ns(task: u64, outer_pid: u64, ns: Arc<PidNamespace>) -> u64 {
    let inner = ns.bind_outer(outer_pid);
    set_ns(task, ns);
    inner
}

/// Is `outer` visible to `task`, and if so, what inner pid does `task` see?
/// `Some(inner)` when the outer pid is bound in `task`'s namespace (or `task`
/// is in the root namespace — everything is visible as its outer pid);
/// `None` when `task` is namespaced and the outer pid is not a member of that
/// namespace (a process in a sibling/parent namespace it must not see). Drives
/// `/proc` enumeration so a namespaced reader lists only its own namespace.
pub fn ns_visible_inner(task: u64, outer: u64) -> Option<u64> {
    match ns_of(task) {
        Some(ns) => ns.outer_to_inner(outer),
        None => Some(outer),
    }
}

/// Translate `task`'s outer pid through whichever namespace it
/// belongs to, returning the inner pid the task sees of itself.
/// A PID that is not mapped into a non-root namespace reports as zero, as
/// Linux does for credential and peer-PID queries; only the root namespace
/// falls back to the outer PID.
pub fn self_inner_pid(task: u64, outer_pid: u64) -> u64 {
    match ns_of(task) {
        Some(ns) => {
            if let Some(inner) = ns.outer_to_inner(outer_pid) {
                inner
            } else {
                // Some callers pass the caller's own TaskId in the `outer_pid`
                // slot; accept a direct TaskId→inner binding too.
                // If that is not mapped either, Linux reports 0 for an
                // ancestor or un-nested peer rather than leaking a host pid.
                ns.outer_to_inner(task).unwrap_or_default()
            }
        }
        None => outer_pid,
    }
}

/// Translate an in-namespace pid (as observed by `task`) to its
/// outer pid for kernel-side delivery (e.g. signal routing). Returns
/// None if `inner_pid` is not bound in the calling task's namespace.
/// If the calling task is in the root namespace, returns `Some(inner_pid)`.
pub fn resolve_inner_pid(task: u64, inner_pid: u64) -> Option<u64> {
    match ns_of(task) {
        Some(ns) => ns.inner_to_outer(inner_pid),
        None => Some(inner_pid),
    }
}

/// Test/reset hook — wipe all namespace state.
#[doc(hidden)]
pub fn __test_reset() {
    *TASK_PID_NS.lock() = Some(BTreeMap::new());
    *TASK_PID_NS_FOR_CHILDREN.lock() = Some(BTreeMap::new());
}
