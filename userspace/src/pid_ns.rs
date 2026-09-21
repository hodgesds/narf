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
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::errno::*;

use narf_lib::sync::IrqSafeSpinLock;

/// Serializes allocation/release across a nested PID-namespace chain so a
/// partially prepared clone is never visible in only some ancestors.
static PID_NS_ALLOC: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

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
    /// The user namespace of the task that created this one — Linux's
    /// `pid_ns->user_ns`. `setns` into it is gated on CAP_SYS_ADMIN here as
    /// well as in the caller's own namespace. `None` is the initial user
    /// namespace.
    owner: IrqSafeSpinLock<Option<Arc<crate::namespaces::UserNamespace>>>,
    /// Immediate ancestor PID namespace. None means the implicit root
    /// namespace; every descendant maps the same root-namespace task id.
    parent: Option<Arc<PidNamespace>>,
    /// The INITIAL namespace translates identically: inner == outer, and
    /// every task is visible.
    ///
    /// Linux says the same thing differently — `init_pid_ns` is an ordinary
    /// namespace whose `struct pid` `numbers[0]` IS the global id — but the
    /// effect is what matters here: a lookup in the initial namespace can
    /// never miss, because there is nothing to have been bound.
    ///
    /// This is what lets the initial namespace be a real object instead of
    /// the absence of one. Without it a freshly built `PidNamespace` starts
    /// with EMPTY maps and mints inner ids from a watermark, which is the
    /// opposite of what the initial namespace does.
    identity: bool,
}

impl Drop for PidNamespace {
    fn drop(&mut self) {
        // Retire the tree entry: an entry outliving its namespace would
        // answer a lookup with an id nothing can be reached through.
        crate::namespaces::ns_tree_remove(self.id);
    }
}

impl PidNamespace {
    /// Build a fresh PID namespace. The first `bind_outer` call will
    /// allocate inner pid 1.
    pub fn new() -> Arc<Self> {
        Self::new_child(None, None)
    }

    /// [`Self::new`] recording the creating task's user namespace, per
    /// `copy_pid_ns`'s `ns->user_ns = get_user_ns(user_ns)`.
    pub fn new_in(owner: Option<Arc<crate::namespaces::UserNamespace>>) -> Arc<Self> {
        Self::new_child(None, owner)
    }

    /// Build a namespace below `parent`. Every task in the returned namespace
    /// also receives a PID in each ancestor, matching Linux's `struct pid`
    /// `numbers[]` array.
    pub fn new_child(
        parent: Option<Arc<Self>>,
        owner: Option<Arc<crate::namespaces::UserNamespace>>,
    ) -> Arc<Self> {
        let owner_id = owner.as_ref().map_or(0, |u| u.id());
        let ns = Arc::new(Self {
            id: crate::namespaces::alloc_ns_id(),
            identity: false,
            watermark: AtomicU64::new(1),
            inner_to_outer: IrqSafeSpinLock::new(BTreeMap::new()),
            outer_to_inner: IrqSafeSpinLock::new(BTreeMap::new()),
            free: IrqSafeSpinLock::new(BTreeSet::new()),
            owner: IrqSafeSpinLock::new(owner),
            parent,
        });
        register(&ns, owner_id);
        ns
    }

    /// Immediate ancestor, or `None` when the parent is the implicit root
    /// namespace.
    pub fn parent(&self) -> Option<Arc<Self>> {
        self.parent.clone()
    }

    /// Linux namespace level (the initial/root namespace is level zero).
    pub fn level(&self) -> usize {
        let mut level = 1usize;
        let mut cursor = self.parent.as_ref();
        while let Some(parent) = cursor {
            level += 1;
            cursor = parent.parent.as_ref();
        }
        level
    }

    /// The user namespace this one belongs to (`pid_ns->user_ns`).
    pub fn owner_user_ns(&self) -> Arc<crate::namespaces::UserNamespace> {
        self.owner
            .lock()
            .clone()
            .unwrap_or_else(crate::namespaces::global_user)
    }

    /// Stable namespace id (nsfs inode in Linux).
    pub fn id(&self) -> crate::namespaces::NsId {
        self.id
    }

    /// Whether `self` is `ancestor` or one of its descendants. Linux uses
    /// this relation in `pidns_install`: setns may select only the caller's
    /// active PID namespace or a child, never a parent or sibling.
    pub fn is_descendant_of(&self, ancestor: &Self) -> bool {
        if self.id == ancestor.id {
            return true;
        }
        let mut cursor = self.parent.as_ref();
        while let Some(ns) = cursor {
            if ns.id == ancestor.id {
                return true;
            }
            cursor = ns.parent.as_ref();
        }
        false
    }

    /// Register `outer` in this namespace, allocating the lowest free
    /// inner id (starting at 1). Returns the inner id. If the outer
    /// is already registered, returns its existing inner id —
    /// idempotent so an unshare followed by a fork doesn't double-
    /// bind the parent.
    pub fn bind_outer(&self, outer: u64) -> u64 {
        let _allocation = PID_NS_ALLOC.lock();
        self.bind_outer_locked(outer, None).unwrap_or_default()
    }

    fn bind_outer_locked(&self, outer: u64, requested: Option<u64>) -> Result<u64, u64> {
        if outer == 0 {
            return Err(EINVAL as u64);
        }
        // The initial namespace has nothing to bind: a task's id there IS
        // its outer id. Recording one would be a second, redundant copy of
        // the identity map that could then drift from it.
        if self.identity {
            return match requested {
                Some(want) if want != outer => Err(EEXIST as u64),
                _ => Ok(outer),
            };
        }
        if let Some(&inner) = self.outer_to_inner.lock().get(&outer) {
            return match requested {
                Some(want) if want != inner => Err(EEXIST as u64),
                _ => Ok(inner),
            };
        }

        let watermark = self.watermark.load(Ordering::Relaxed);
        let init_alive = self.inner_to_outer.lock().contains_key(&1);
        if watermark > 1 && !init_alive {
            return Err(ENOMEM as u64);
        }

        let inner = match requested {
            Some(want) => {
                if want == 0 || want > crate::PID_MAX {
                    return Err(EINVAL as u64);
                }
                if want != 1 && !init_alive {
                    return Err(EINVAL as u64);
                }
                let mut free = self.free.lock();
                if want < watermark {
                    if !free.remove(&want) {
                        return Err(EEXIST as u64);
                    }
                } else {
                    for skipped in watermark..want {
                        free.insert(skipped);
                    }
                    self.watermark.store(want + 1, Ordering::Relaxed);
                }
                want
            }
            None => {
                let mut free = self.free.lock();
                if let Some(&candidate) = free.iter().next() {
                    free.remove(&candidate);
                    candidate
                } else {
                    if watermark == 0 || watermark > crate::PID_MAX {
                        return Err(EAGAIN as u64);
                    }
                    self.watermark.store(watermark + 1, Ordering::Relaxed);
                    watermark
                }
            }
        };
        if self.inner_to_outer.lock().contains_key(&inner) {
            return Err(EEXIST as u64);
        }
        self.inner_to_outer.lock().insert(inner, outer);
        self.outer_to_inner.lock().insert(outer, inner);
        Ok(inner)
    }

    fn release_outer_local_locked(&self, outer: u64) {
        let inner = self.outer_to_inner.lock().remove(&outer);
        if let Some(inner) = inner {
            self.inner_to_outer.lock().remove(&inner);
            if inner > 1 {
                self.free.lock().insert(inner);
            }
        }
    }

    fn chain_from(active: Option<Arc<Self>>) -> Vec<Arc<Self>> {
        let mut chain = Vec::new();
        let mut cursor = active;
        while let Some(ns) = cursor {
            cursor = ns.parent();
            chain.push(ns);
        }
        chain
    }

    fn bind_chain_existing_outer(
        active: Arc<Self>,
        outer: u64,
        requested: &[i32],
    ) -> Result<(Vec<Arc<Self>>, u64), u64> {
        let chain = Self::chain_from(Some(active));
        let _allocation = PID_NS_ALLOC.lock();
        let mut bound = Vec::new();
        let mut child_inner = outer;
        for (index, ns) in chain.iter().enumerate() {
            let requested = requested.get(index).map(|tid| *tid as u64);
            match ns.bind_outer_locked(outer, requested) {
                Ok(inner) => {
                    if index == 0 {
                        child_inner = inner;
                    }
                    bound.push(ns.clone());
                }
                Err(errno) => {
                    for prior in bound.iter().rev() {
                        prior.release_outer_local_locked(outer);
                    }
                    return Err(errno);
                }
            }
        }
        Ok((bound, child_inner))
    }

    fn release_chain_locked(&self, outer: u64) {
        self.release_outer_local_locked(outer);
        if let Some(parent) = &self.parent {
            parent.release_chain_locked(outer);
        }
    }

    /// Translate an inner pid to its outer pid. None if the inner
    /// pid is not bound in this namespace.
    pub fn inner_to_outer(&self, inner: u64) -> Option<u64> {
        if self.identity {
            return Some(inner);
        }
        self.inner_to_outer.lock().get(&inner).copied()
    }

    /// Translate an outer pid to its inner pid in this namespace.
    /// None if the outer pid was never registered here.
    pub fn outer_to_inner(&self, outer: u64) -> Option<u64> {
        if self.identity {
            return Some(outer);
        }
        self.outer_to_inner.lock().get(&outer).copied()
    }

    /// Release `outer` from this namespace and every ancestor.
    pub fn release_outer(&self, outer: u64) {
        let _allocation = PID_NS_ALLOC.lock();
        self.release_chain_locked(outer);
    }

    /// Number of currently-bound tasks in this namespace.
    pub fn live_count(&self) -> usize {
        self.outer_to_inner.lock().len()
    }
}

/// The INITIAL pid namespace — a real object, as `init_pid_ns` is in Linux.
///
/// Every task that has not unshared is in THIS namespace, rather than in the
/// absence of one. That distinction is not cosmetic: `may_see_all_namespaces`
/// asks "is the caller in the initial pid namespace", and answering it by
/// testing for the absence of a namespace makes a permission check depend on
/// a representation detail — one that silently inverts the moment the
/// representation changes.
/// `OnceLock`, not a lock-guarded `Option`: this is read on EVERY pid
/// translation — `self_inner_pid` is on the `getpid` path — and a spinlock
/// acquire plus an `Arc` clone per call would be a real cost for something
/// that is written once at boot. `OnceLock::get` is an acquire load and
/// hands back a `&T`, so the hot path neither locks nor touches a refcount.
static INITIAL_PID_NS: narf_lib::sync::OnceLock<Arc<PidNamespace>> =
    narf_lib::sync::OnceLock::new();

/// The initial pid namespace, created on first use and never dropped.
///
/// Identity-translating: a task's id here IS its outer id, so a lookup can
/// never miss. `init_namespaces` materialises it at boot so the namespace
/// tree holds it from the start.
pub fn initial_pid_ns() -> &'static Arc<PidNamespace> {
    INITIAL_PID_NS.get_or_init(|| {
        let ns = Arc::new(PidNamespace {
            id: crate::namespaces::initial_pid_ns_id(),
            identity: true,
            watermark: AtomicU64::new(1),
            inner_to_outer: IrqSafeSpinLock::new(BTreeMap::new()),
            outer_to_inner: IrqSafeSpinLock::new(BTreeMap::new()),
            free: IrqSafeSpinLock::new(BTreeSet::new()),
            owner: IrqSafeSpinLock::new(None),
            parent: None,
        });
        register(&ns, 0);
        ns
    })
}

/// `NsObject` for the pid namespace — lives here rather than beside its
/// siblings in `namespaces.rs` because `PidNamespace::id` is private to
/// this module.
impl narf_filesystem::NsObject for PidNamespace {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn into_any_arc(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }
    fn ns_id(&self) -> u64 {
        self.id
    }
    fn ns_type(&self) -> u32 {
        crate::namespaces::ns_type::PID
    }
}

/// Publish a fully-constructed namespace into the tree.
///
/// Registration follows `Arc::new` because the tree stores a `Weak` handle
/// and there is nothing to downgrade before the `Arc` exists
/// (`userspace/specification/namespace-tree.md` R7).
/// Re-state the initial pid namespace in the tree.
///
/// `initial_pid_ns` memoises, so it registers only on the very first call;
/// `init_namespaces` needs a way to restore the entry after the tree has
/// been reset. The insert is idempotent.
pub(crate) fn register_initial() {
    register(initial_pid_ns(), 0);
}

fn register(ns: &Arc<PidNamespace>, owner_user_ns: crate::namespaces::NsId) {
    crate::namespaces::ns_tree_add(
        ns.id,
        crate::namespaces::ns_type::PID,
        owner_user_ns,
        Arc::downgrade(ns) as alloc::sync::Weak<dyn narf_filesystem::NsObject>,
    );
}

/// Borrow the pid namespace `task` is in, without cloning an `Arc`.
///
/// The translation helpers below call this on every lookup, so it takes the
/// borrow rather than a reference count: `ns_of` hands back an owned `Arc`
/// only when the task really has unshared, and the initial namespace is a
/// `&'static` that costs nothing to reach.
fn with_pid_ns<R>(task: u64, f: impl FnOnce(&PidNamespace) -> R) -> R {
    match ns_of(task) {
        Some(ns) => f(&ns),
        None => f(initial_pid_ns()),
    }
}

/// The pid namespace `task` is in — never `None`, because every task is in
/// one. Replaces the old `ns_of(task)` + "None means initial" idiom.
pub fn current_pid_ns(task: u64) -> Arc<PidNamespace> {
    ns_of(task).unwrap_or_else(|| initial_pid_ns().clone())
}

/// PID allocation prepared before the scheduler task becomes runnable.
#[derive(Debug)]
pub struct PreparedPidClone {
    active: Option<Arc<PidNamespace>>,
    bound: Vec<Arc<PidNamespace>>,
    outer: u64,
    child_inner: u64,
    parent_visible: u64,
}

impl PreparedPidClone {
    pub fn outer(&self) -> u64 {
        self.outer
    }

    pub fn child_inner(&self) -> u64 {
        self.child_inner
    }

    pub fn parent_visible(&self) -> u64 {
        self.parent_visible
    }

    pub fn install(&self, child_task: u64) {
        if let Some(active) = &self.active {
            set_ns(child_task, active.clone());
        }
    }

    pub fn rollback(self) {
        let _allocation = PID_NS_ALLOC.lock();
        for ns in self.bound.iter().rev() {
            ns.release_outer_local_locked(self.outer);
        }
        crate::release_pid(crate::ProcessId(self.outer));
    }
}

// ── Per-task pointer to the active PID namespace ───────────────────
//
// Tasks not present in TASK_PID_NS are implicitly in the root
// namespace (outer == inner). unshare/setns change only the namespace for
// future children; clone/fork installs that namespace on the new task.

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

fn ns_for_children(task: u64) -> Option<Arc<PidNamespace>> {
    let pending = {
        let g = TASK_PID_NS_FOR_CHILDREN.lock();
        g.as_ref().and_then(|m| m.get(&task).cloned())
    };
    pending.or_else(|| ns_of(task))
}

fn same_namespace(left: &Option<Arc<PidNamespace>>, right: &Option<Arc<PidNamespace>>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left.id() == right.id(),
        _ => false,
    }
}

/// Linux rejects CLONE_THREAD when an earlier unshare/setns changed
/// `pid_ns_for_children` away from the caller's active PID namespace.
pub fn active_matches_for_children(task: u64) -> bool {
    same_namespace(&ns_of(task), &ns_for_children(task))
}

/// Linux `pidns_install` descendant rule for setns(CLONE_NEWPID).
pub fn may_setns_for_children(task: u64, target: Option<&PidNamespace>) -> bool {
    match (ns_of(task), target) {
        // Root is an ancestor of every PID namespace.
        (None, _) => true,
        // A namespaced task cannot escape back to the root namespace.
        (Some(_), None) => false,
        (Some(active), Some(target)) => target.is_descendant_of(&active),
    }
}

/// Number of PID values allocated for the prospective child, including the
/// implicit root namespace.
pub fn clone_pid_levels(parent_task: u64, new_pid: bool) -> Result<usize, u64> {
    let base = ns_for_children(parent_task);
    let base_level = base.as_ref().map_or(0, |ns| ns.level());
    if new_pid && base_level >= 32 {
        return Err(ENOSPC as u64); // ENOSPC, matching create_pid_namespace().
    }
    Ok(base_level + usize::from(new_pid) + 1)
}

/// Allocate one Linux PID/TID at every namespace level, with clone3's
/// `set_tid[]` interpreted innermost-first. Nothing is installed in the
/// per-task table until `PreparedPidClone::install`.
pub fn prepare_clone(
    parent_task: u64,
    requested: &[i32],
    new_pid: bool,
    new_pid_owner: Option<Arc<crate::namespaces::UserNamespace>>,
) -> Result<PreparedPidClone, u64> {
    let base = ns_for_children(parent_task);
    let active = if new_pid {
        let base_level = base.as_ref().map_or(0, |ns| ns.level());
        if base_level >= 32 {
            return Err(ENOSPC as u64);
        }
        Some(PidNamespace::new_child(base, new_pid_owner))
    } else {
        base
    };
    let chain = PidNamespace::chain_from(active.clone());
    if requested.len() > chain.len() + 1 {
        return Err(EINVAL as u64);
    }
    if requested
        .iter()
        .any(|&tid| tid <= 0 || tid as u64 > crate::PID_MAX)
    {
        return Err(EINVAL as u64);
    }

    // Linux's checkpoint_restore_ns_capable() is evaluated separately for
    // every requested namespace, including the initial/root namespace.
    for (index, _) in requested.iter().enumerate() {
        let owner = if let Some(ns) = chain.get(index) {
            ns.owner_user_ns()
        } else {
            crate::namespaces::global_user()
        };
        if !crate::handlers::task_ns_capable(
            parent_task,
            &owner,
            crate::handlers::CAP_CHECKPOINT_RESTORE,
        ) && !crate::handlers::task_ns_capable(
            parent_task,
            &owner,
            crate::handlers::CAP_SYS_ADMIN,
        ) {
            return Err(EPERM as u64);
        }
    }

    let root_requested = requested.get(chain.len()).copied();
    let outer = match root_requested {
        Some(tid) => crate::alloc_pid_specific(tid as u64)?.raw(),
        None => {
            let pid = crate::alloc_pid().raw();
            if pid == 0 {
                return Err(EAGAIN as u64);
            }
            pid
        }
    };

    let (bound, child_inner) = match active.clone() {
        Some(active) => match PidNamespace::bind_chain_existing_outer(active, outer, requested) {
            Ok(result) => result,
            Err(errno) => {
                crate::release_pid(crate::ProcessId(outer));
                return Err(errno);
            }
        },
        None => (Vec::new(), outer),
    };
    let parent_visible = ns_of(parent_task)
        .and_then(|ns| ns.outer_to_inner(outer))
        .unwrap_or(outer);
    Ok(PreparedPidClone {
        active,
        bound,
        outer,
        child_inner,
        parent_visible,
    })
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
    let ns = ns_for_children(parent_task)?;
    let (_, inner) =
        PidNamespace::bind_chain_existing_outer(ns.clone(), child_outer_pid, &[]).ok()?;
    set_ns(child_task, ns);
    Some(inner)
}

/// The child's pid AS SEEN BY THE PARENT — the value fork(2)/clone(2) returns
/// to the parent. Linux resolves this with `pid_vnr(pid)` in the CALLER's
/// active pid namespace (`kernel/fork.c` `kernel_clone` → `nr = pid_vnr(pid)`),
/// which is NOT necessarily the pid the child reports for ITSELF.
///
/// `child_outer` is the child's outer ProcessId; `child_self_inner` is the pid
/// the child reports for itself (its inner pid in whatever namespace
/// `inherit_into_child` placed it in). The two DIVERGE across a
/// `CLONE_NEWPID` boundary:
///
///  * Parent in the ROOT namespace → the child's OUTER pid. This covers a
///    plain root fork (outer == the return) AND `unshare(CLONE_NEWPID)` from
///    the root (`unshare -fp`, runc/crun init): there the child is pid 1 in a
///    NEW child namespace the parent is not in, but the parent must still see —
///    and `waitpid` — the child by its pid in the PARENT's namespace. Returning
///    the child's new-ns `1` made the parent's `waitpid` look for a child it
///    has no record of (`PENDING_EXITS` is keyed by outer pid) → ECHILD.
///  * Parent SHARES the child's namespace (ordinary container fork) → the
///    child's inner pid there, which equals `child_self_inner` (its getpid()).
///
/// Nested children are bound in every ancestor, so a namespaced parent always
/// resolves its own view directly.
pub fn fork_return_to_parent(parent_task: u64, child_outer: u64, child_self_inner: u64) -> u64 {
    match ns_of(parent_task) {
        None => child_outer,
        Some(pns) => pns.outer_to_inner(child_outer).unwrap_or(child_self_inner),
    }
}

/// Linux `unshare(CLONE_NEWPID)` semantics: creates a fresh PID namespace for
/// future children of `task`. The calling task itself remains in its current namespace.
pub fn unshare_pid_ns_for_children(task: u64) -> Result<Arc<PidNamespace>, u64> {
    let parent = ns_for_children(task);
    if parent.as_ref().is_some_and(|ns| ns.level() >= 32) {
        return Err(ENOSPC as u64); // ENOSPC, create_pid_namespace(MAX_PID_NS_LEVEL)
    }
    let ns = PidNamespace::new_child(parent, Some(crate::namespaces::current_user_ns(task)));
    let mut g = TASK_PID_NS_FOR_CHILDREN.lock();
    ns_table_init(&mut g);
    if let Some(m) = g.as_mut() {
        m.insert(task, ns.clone());
    }
    Ok(ns)
}

/// `unshare(CLONE_NEWPID)` legacy/test helper — create a fresh PID namespace for `task`
/// and bind `task`'s outer pid into it as inner pid 1 immediately.
pub fn unshare_pid_ns(task: u64, outer_pid: u64) -> Arc<PidNamespace> {
    let ns = PidNamespace::new_child(ns_of(task), Some(crate::namespaces::current_user_ns(task)));
    let inner = ns.bind_outer(outer_pid);
    debug_assert_eq!(inner, 1, "first bind in fresh namespace must be pid 1");
    set_ns(task, ns.clone());
    ns
}

/// `setns(fd, CLONE_NEWPID)` changes only the namespace used for future
/// children. Linux never moves the calling task into another PID namespace.
pub fn attach_to_ns(task: u64, outer_pid: u64, ns: Arc<PidNamespace>) -> u64 {
    let _ = outer_pid;
    let mut g = TASK_PID_NS_FOR_CHILDREN.lock();
    ns_table_init(&mut g);
    if let Some(m) = g.as_mut() {
        m.insert(task, ns);
    }
    self_inner_pid(task, crate::handlers::task_to_pid_raw(task).unwrap_or(task))
}

/// Is `outer` visible to `task`, and if so, what inner pid does `task` see?
/// `Some(inner)` when the outer pid is bound in `task`'s namespace (or `task`
/// is in the root namespace — everything is visible as its outer pid);
/// `None` when `task` is namespaced and the outer pid is not a member of that
/// namespace (a process in a sibling/parent namespace it must not see). Drives
/// `/proc` enumeration so a namespaced reader lists only its own namespace.
pub fn ns_visible_inner(task: u64, outer: u64) -> Option<u64> {
    // No `None` arm: the initial namespace is an object that translates
    // identically, so `outer_to_inner` there returns `Some(outer)` on its
    // own. The special case moved into the namespace, which is where it
    // belongs — every caller had to remember it before.
    with_pid_ns(task, |ns| ns.outer_to_inner(outer))
}

/// Translate `task`'s outer pid through whichever namespace it
/// belongs to, returning the inner pid the task sees of itself.
/// A PID that is not mapped into a non-root namespace reports as zero, as
/// Linux does for credential and peer-PID queries; only the root namespace
/// falls back to the outer PID.
pub fn self_inner_pid(task: u64, outer_pid: u64) -> u64 {
    with_pid_ns(task, |ns| {
        {
            if let Some(inner) = ns.outer_to_inner(outer_pid) {
                inner
            } else {
                // The fallback exists for callers that pass the caller's own
                // TaskId (or its own outer pid, registered under a TaskId key)
                // in the `outer_pid` slot — SELF-queries like getpid.
                //
                // As a GENERAL miss-fallback it FABRICATED identities: it
                // retried the lookup with the OBSERVER'S TaskId as the key, and
                // TaskIds and outer pids share the same small integers in a real
                // boot. So whenever any process happened to be registered under
                // an outer pid numerically equal to the observer's TaskId, EVERY
                // unmapped pid translated to that process's inner pid. For udev
                // that makes `hashmap_get(manager->workers, &sender)` find a
                // valid-but-wrong worker, and `on_worker_notify` then detaches
                // or asserts on the wrong worker's event (the
                // `assert(worker->event)` abort at udev-manager.c:1199) — with
                // no warning anywhere, because the borrowed identity is a real
                // registered worker.
                //
                // Linux renders a pid that is not mapped into the observer's
                // namespace as 0 (credential/peer-pid queries); never as
                // someone else.
                let is_self_query =
                    outer_pid == task || crate::handlers::task_to_pid_raw(task) == Some(outer_pid);
                if is_self_query {
                    ns.outer_to_inner(task).unwrap_or_default()
                } else {
                    0
                }
            }
        }
    })
}

/// Translate an in-namespace pid (as observed by `task`) to its
/// outer pid for kernel-side delivery (e.g. signal routing). Returns
/// None if `inner_pid` is not bound in the calling task's namespace.
/// If the calling task is in the root namespace, returns `Some(inner_pid)`.
pub fn resolve_inner_pid(task: u64, inner_pid: u64) -> Option<u64> {
    with_pid_ns(task, |ns| ns.inner_to_outer(inner_pid))
}

/// Test/reset hook — wipe all namespace state.
#[doc(hidden)]
pub fn __test_reset() {
    *TASK_PID_NS.lock() = Some(BTreeMap::new());
    *TASK_PID_NS_FOR_CHILDREN.lock() = Some(BTreeMap::new());
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_nested_pid_namespace_set_tid_order() -> TestResult {
        const ROOT_PARENT: u64 = 0xF1_00;
        const CHILD1: u64 = 0xF1_01;
        const CHILD2: u64 = 0xF1_02;
        const CHILD3: u64 = 0xF1_03;

        __test_reset();
        crate::handlers::__test_caps_reset();
        let verdict = (|| {
            let level1 =
                unshare_pid_ns_for_children(ROOT_PARENT).map_err(|_| "level-1 unshare failed")?;
            let plan1 = prepare_clone(ROOT_PARENT, &[], false, None)
                .map_err(|_| "level-1 init allocation failed")?;
            if plan1.child_inner() != 1 || plan1.parent_visible() != plan1.outer() {
                return Err("root parent/new pid namespace visibility is wrong");
            }
            plan1.install(CHILD1);

            let level2 =
                unshare_pid_ns_for_children(CHILD1).map_err(|_| "level-2 unshare failed")?;
            let plan2 = prepare_clone(CHILD1, &[], false, None)
                .map_err(|_| "level-2 init allocation failed")?;
            if plan2.child_inner() != 1 || plan2.parent_visible() != 2 {
                return Err("nested namespace init did not report pid 1/parent pid 2");
            }
            plan2.install(CHILD2);

            let level3 =
                unshare_pid_ns_for_children(CHILD2).map_err(|_| "level-3 unshare failed")?;
            // clone3 set_tid[] is innermost first: level3=1, level2=7,
            // level1=11; the root PID remains automatically allocated.
            let plan3 = prepare_clone(CHILD2, &[1, 7, 11], false, None)
                .map_err(|_| "three-level set_tid allocation failed")?;
            let outer3 = plan3.outer();
            if plan3.child_inner() != 1 || plan3.parent_visible() != 7 {
                return Err("set_tid did not use innermost-first ordering");
            }
            if level3.outer_to_inner(outer3) != Some(1)
                || level2.outer_to_inner(outer3) != Some(7)
                || level1.outer_to_inner(outer3) != Some(11)
            {
                return Err("one struct-pid identity was not bound at every ancestor level");
            }
            plan3.install(CHILD3);

            clear_ns(CHILD3);
            plan3.rollback();
            clear_ns(CHILD2);
            plan2.rollback();
            clear_ns(CHILD1);
            plan1.rollback();
            Ok(())
        })();
        clear_ns(ROOT_PARENT);
        __test_reset();
        crate::handlers::__test_caps_reset();
        match verdict {
            Ok(()) => TestResult::Pass,
            Err(reason) => TestResult::Fail(reason),
        }
    }
    kernel_test_in!(
        "userspace/process",
        smoke_nested_pid_namespace_set_tid_order
    );

    fn smoke_nested_pid_namespace_ancestor_collision_rolls_back() -> TestResult {
        let level1 = PidNamespace::new();
        if level1.bind_outer(100) != 1 {
            return TestResult::Fail("could not seed level-1 init");
        }
        let level2 = PidNamespace::new_child(Some(level1.clone()), None);
        if PidNamespace::bind_chain_existing_outer(level2.clone(), 200, &[1, 7]).is_err() {
            return TestResult::Fail("could not seed level-2 init");
        }
        let level3 = PidNamespace::new_child(Some(level2.clone()), None);
        // Level 1 pid 7 is occupied. The failed ancestor bind must undo the
        // already-created level3 pid 1 and level2 pid 8 rows atomically.
        if !matches!(
            PidNamespace::bind_chain_existing_outer(level3.clone(), 300, &[1, 8, 7]),
            Err(17)
        ) {
            return TestResult::Fail("ancestor set_tid collision did not return EEXIST");
        }
        if level3.outer_to_inner(300).is_some() || level2.outer_to_inner(300).is_some() {
            return TestResult::Fail("failed nested allocation leaked partial namespace bindings");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/process",
        smoke_nested_pid_namespace_ancestor_collision_rolls_back
    );

    fn smoke_pid_namespace_depth_and_setns_direction() -> TestResult {
        const TASK: u64 = 0xF2_00;
        __test_reset();
        let mut chain = Vec::new();
        for _ in 0..32 {
            match unshare_pid_ns_for_children(TASK) {
                Ok(ns) => chain.push(ns),
                Err(_) => {
                    return TestResult::Fail("PID namespace nesting failed below Linux limit")
                }
            }
        }
        if !matches!(unshare_pid_ns_for_children(TASK), Err(e) if e == ENOSPC as u64) {
            return TestResult::Fail("PID namespace nesting beyond level 32 did not return ENOSPC");
        }

        let level1 = chain[0].clone();
        let level2 = chain[1].clone();
        let root_sibling = PidNamespace::new_child(None, None);
        set_ns(TASK, level1.clone());
        if !may_setns_for_children(TASK, Some(&level1))
            || !may_setns_for_children(TASK, Some(&level2))
            || may_setns_for_children(TASK, Some(&root_sibling))
            || may_setns_for_children(TASK, None)
        {
            return TestResult::Fail("PID setns did not enforce same-or-descendant direction");
        }
        clear_ns(TASK);
        __test_reset();
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/process",
        smoke_pid_namespace_depth_and_setns_direction
    );
}
