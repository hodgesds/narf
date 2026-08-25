//! `CgroupFs` — Linux cgroup-v2 unified hierarchy, mounted at
//! `/sys/fs/cgroup`.
//!
//! The hierarchy is a tree of cgroups, each tracking the processes that
//! belong to it and exposing the standard v2 control-file interface.
//! Resource *controllers* (pids, memory, cpu, io, cpuset, misc, …)
//! register themselves at boot ([`controller::register_controller`])
//! and attach per-cgroup state when enabled via `cgroup.subtree_control`
//! — see [`controller`] and the per-controller submodules.
//!
//! With no controllers registered this degrades to the bare
//! organizational hierarchy (empty `cgroup.controllers`), which is a
//! legal v2 configuration and is all an init system needs to track
//! units.
//!
//! Linux references (GPL, citable post-relicense):
//!   `kernel/cgroup/cgroup.c`                   — core hierarchy + control files
//!   `Documentation/admin-guide/cgroup-v2.rst`  — the v2 interface contract
//!
//! # Authority model
//!
//! The cgroup tree is global kernel state. `CGROUP_ROOT` holds the
//! root; every `CgroupDir` / `CgroupAttrFile` is a *view* onto an
//! `Arc<Cgroup>`, so a `mkdir` mutating the tree is immediately visible
//! to a later `lookup_dir`. Process membership is keyed by **pid** (a
//! process lives in exactly one cgroup in v2); the `TASK_CGROUP`
//! reverse index finds a process's cgroup in O(log n) without walking
//! the tree.

pub mod controller;

#[cfg(feature = "cgroup-cpu")]
pub mod cpu;
#[cfg(feature = "cgroup-cpuset")]
pub mod cpuset;
#[cfg(feature = "cgroup-io")]
pub mod io;
#[cfg(feature = "cgroup-memory")]
pub mod memory;
#[cfg(feature = "cgroup-misc")]
pub mod misc;
#[cfg(feature = "cgroup-pids")]
pub mod pids;
#[cfg(feature = "cgroup-psi")]
pub mod psi;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_lib::sync::{IrqSafeSpinLock, OnceLock};

use crate::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_IN, POLL_PRI,
};

pub use controller::{register_controller, Controller, ControllerState};

/// Register every compiled-in resource controller. Call once at boot,
/// before cgroupfs is mounted, so the root's `cgroup.controllers`
/// advertises them. No-op for controllers whose sub-feature is off.
pub fn register_builtin_controllers() {
    #[cfg(feature = "cgroup-pids")]
    register_controller(Arc::new(pids::PidsController));
    #[cfg(feature = "cgroup-misc")]
    register_controller(Arc::new(misc::MiscController));
    #[cfg(feature = "cgroup-memory")]
    register_controller(Arc::new(memory::MemoryController));
    #[cfg(feature = "cgroup-cpu")]
    register_controller(Arc::new(cpu::CpuController));
    #[cfg(feature = "cgroup-cpuset")]
    register_controller(Arc::new(cpuset::CpuSetController));
    #[cfg(feature = "cgroup-io")]
    register_controller(Arc::new(io::IoController));
}

// ── Cgroup type (v2 §"Threads") ─────────────────────────────────────

/// `cgroup.type` value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CgroupType {
    /// Normal process-granularity cgroup (the default).
    Domain,
    /// Threaded cgroup — members are individual threads.
    Threaded,
    /// Domain that anchors a threaded subtree.
    DomainThreaded,
    /// Invalid (inside a threaded subtree, not itself threaded).
    DomainInvalid,
}

impl CgroupType {
    fn as_str(self) -> &'static str {
        match self {
            CgroupType::Domain => "domain\n",
            CgroupType::Threaded => "threaded\n",
            CgroupType::DomainThreaded => "domain threaded\n",
            CgroupType::DomainInvalid => "domain invalid\n",
        }
    }
}

// ── The cgroup node ─────────────────────────────────────────────────

/// Monotonic inode allocator for cgroups. Each cgroup gets a unique,
/// stable id, surfaced as its `st_ino` and as the cgroup id an init reads
/// via `name_to_handle_at`. The base is high (and distinct from MemFs's)
/// so it never aliases another filesystem's inodes under NARF's single
/// `st_dev` space.
static NEXT_CGROUP_INO: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0x2000_0000);
static NEXT_CGROUP_ATTR_INO: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0x3000_0000);
static CGROUP_ATTR_INOS: IrqSafeSpinLock<BTreeMap<(u64, &'static str), u64>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// Runtime toggle for the `CGEVT` populated-transition trace (kernel cmdline
/// `cgevt_trace`, set by boot-init). Off by default. Diagnostic only: prints
/// each `cgroup.events` `populated` transition (`0->1` on the first member,
/// `1->0` when it empties), walking up ancestors, so a service whose start job
/// hangs waiting for its cgroup to settle can be pinned — did its cgroup ever
/// go `1->0`, and at which path.
static CGEVT_TRACE: AtomicBool = AtomicBool::new(false);

/// Enable the `CGEVT` populated-transition trace (see [`CGEVT_TRACE`]).
pub fn set_cgevt_trace(v: bool) {
    CGEVT_TRACE.store(v, Ordering::Relaxed);
}

/// Absolute cgroup path a pid currently belongs to (root `/` if unplaced).
/// Diagnostic helper for the USEREXIT probe so an exiting process can be
/// attributed to its service cgroup (e.g. `.../user@957.service`) regardless
/// of its comm.
pub fn cgroup_path_of(pid: u64) -> String {
    cgroup_of(pid).abs_path()
}

/// Whether the `CGEVT` trace is enabled. Reused as a lightweight runtime gate
/// for the paired userspace exit-detection diagnostics (`CGATTACH`,
/// `PIDFD-MINT`, `PIDFD-EXIT`) so they can be watched in a boot WITHOUT the
/// `syscall-trace` firehose — which is heavy enough to change the failure mode
/// of the very phase (systemd `--user` session bring-up) they diagnose.
pub fn cgevt_trace_enabled() -> bool {
    CGEVT_TRACE.load(Ordering::Relaxed)
}

fn alloc_cgroup_ino() -> u64 {
    NEXT_CGROUP_INO.fetch_add(1, Ordering::Relaxed)
}

/// Stable kernfs-style inode identity for one named attribute in one cgroup.
/// Lookup creates fresh `FileOps` objects, so the identity must live outside
/// the open object to remain stable across path walks.
pub(crate) fn cgroup_attr_ino(cgroup_ino: u64, name: &'static str) -> u64 {
    let mut inos = CGROUP_ATTR_INOS.lock();
    *inos
        .entry((cgroup_ino, name))
        .or_insert_with(|| NEXT_CGROUP_ATTR_INO.fetch_add(1, Ordering::Relaxed))
}

/// One node in the cgroup-v2 hierarchy. The root has an empty `name`
/// and no parent; children are created by userspace `mkdir`.
pub struct Cgroup {
    /// Unique, stable inode / cgroup id (see [`NEXT_CGROUP_INO`]).
    ino: u64,
    /// Directory name (`""` for the root).
    name: String,
    /// Parent cgroup; `None` only for the root. Strong `Arc` — the tree
    /// is rooted in `CGROUP_ROOT` and is a DAG kept alive from the root.
    parent: Option<Arc<Cgroup>>,
    /// Distance from the root (root = 0). For `cgroup.max.depth`.
    depth: u64,
    /// Child cgroups by name.
    children: IrqSafeSpinLock<BTreeMap<String, Arc<Cgroup>>>,
    /// Pids of member processes (v2: a process is in exactly one cgroup).
    members: IrqSafeSpinLock<BTreeSet<u64>>,
    /// Tids of member threads, for threaded cgroups.
    threads: IrqSafeSpinLock<BTreeSet<u64>>,
    /// `cgroup.type`.
    cg_type: IrqSafeSpinLock<CgroupType>,
    /// `cgroup.freeze` requested on this cgroup itself.
    frozen: AtomicBool,
    /// `cgroup.subtree_control`: controllers enabled for *children*.
    enabled: IrqSafeSpinLock<BTreeSet<&'static str>>,
    /// Per-controller state active on *this* cgroup (its name is in the
    /// parent's `enabled` set). Keyed by controller name.
    ctrl_state: IrqSafeSpinLock<BTreeMap<&'static str, Arc<dyn ControllerState>>>,
    /// `cgroup.max.depth` / `cgroup.max.descendants` (`None` = "max").
    max_depth: IrqSafeSpinLock<Option<u64>>,
    max_descendants: IrqSafeSpinLock<Option<u64>>,
    /// `cgroup.pressure`: PSI accounting enabled for this cgroup
    /// (Linux 6.1+; default on). NARF's PSI is scaffold-zeroes, so this
    /// is a stored toggle only — kept so systemd's
    /// `MemoryPressureWatch=` probe writes round-trip.
    #[cfg(feature = "cgroup-psi")]
    psi_enabled: AtomicBool,
    /// `cgroup.events` change generation. Bumped on every transition of
    /// a field reported by `cgroup.events` (`populated`, `frozen`). An
    /// open `cgroup.events` file (`CgroupAttrFile`) captures this value
    /// and reports `POLLPRI` from `poll_readiness` while the live gen is
    /// ahead of what that fd last read — the level-triggered, busy-poll
    /// equivalent of the edge `kernfs_notify` systemd waits on to detect
    /// an emptied (or frozen) cgroup. NARF's poll layer is poll-only
    /// (no waker registration), so a generation an fd compares against
    /// is the right shape rather than a parked `Waker` list.
    events_gen: AtomicU64,
    /// Last-published `populated` bit, to detect transitions.
    last_populated: AtomicBool,
    /// POSIX owner of this cgroup's DIRECTORY (`st_uid`/`st_gid`).
    ///
    /// Linux keeps ownership on the kernfs node: `cgroup_mkdir` stamps the
    /// creating process's ids and `cgroup_kn_set_ugid` applies later
    /// chowns. Ownership is load-bearing for DELEGATION — systemd's
    /// `cg_set_access()` chowns a user's subtree to that uid so the
    /// unprivileged `systemd --user` can manage its own cgroups. Without
    /// it `user@UID.service` dies with 219/EXIT_CGROUP and no user session
    /// exists at all.
    owner: IrqSafeSpinLock<(u32, u32)>,
    /// Per-attribute-file owners, keyed by the file's inode.
    ///
    /// Not folded into `owner`: `cg_set_access()` chowns the directory and
    /// then `cgroup.procs` / `cgroup.subtree_control` / `cgroup.threads`
    /// INDIVIDUALLY, and Linux tracks each kernfs node separately, so a
    /// per-file entry is required rather than one owner for the whole
    /// cgroup. Absent entry = root-owned, matching the kernfs default.
    file_owners: IrqSafeSpinLock<BTreeMap<u64, (u32, u32)>>,
    /// Directory permission bits (kernfs default 0755).
    mode: IrqSafeSpinLock<u16>,
    /// Per-attribute-file permission bits, keyed by the file's inode.
    ///
    /// Required for the same reason as `file_owners`, and for a subtler one:
    /// systemd adjusts a delegated subtree with `fchmod_and_chown()`, which
    /// CHMODS FIRST and reports any failure as "Failed to adjust ownership
    /// of '<path>': Operation not supported". With `FileOps::set_perms`
    /// left at its `Unsupported` default the chmod rejected, the chown was
    /// never even reached, and the message named ownership — which is why
    /// fixing `set_owners` alone did not clear it. Absent entry = the
    /// kind-derived default from `stat()`.
    file_modes: IrqSafeSpinLock<BTreeMap<u64, u16>>,
}

impl core::fmt::Debug for Cgroup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cgroup")
            .field("name", &self.name)
            .field("depth", &self.depth)
            .field("is_root", &self.is_root())
            .finish_non_exhaustive()
    }
}

impl Cgroup {
    fn new_root() -> Arc<Self> {
        Arc::new(Cgroup {
            ino: alloc_cgroup_ino(),
            name: String::new(),
            parent: None,
            depth: 0,
            children: IrqSafeSpinLock::new(BTreeMap::new()),
            members: IrqSafeSpinLock::new(BTreeSet::new()),
            threads: IrqSafeSpinLock::new(BTreeSet::new()),
            cg_type: IrqSafeSpinLock::new(CgroupType::Domain),
            frozen: AtomicBool::new(false),
            enabled: IrqSafeSpinLock::new(BTreeSet::new()),
            ctrl_state: IrqSafeSpinLock::new(BTreeMap::new()),
            max_depth: IrqSafeSpinLock::new(None),
            max_descendants: IrqSafeSpinLock::new(None),
            #[cfg(feature = "cgroup-psi")]
            psi_enabled: AtomicBool::new(true),
            events_gen: AtomicU64::new(0),
            last_populated: AtomicBool::new(false),
            owner: IrqSafeSpinLock::new((0, 0)),
            file_owners: IrqSafeSpinLock::new(BTreeMap::new()),
            mode: IrqSafeSpinLock::new(0o755),
            file_modes: IrqSafeSpinLock::new(BTreeMap::new()),
        })
    }

    fn new_child(name: String, parent: Arc<Cgroup>) -> Arc<Self> {
        let depth = parent.depth + 1;
        // The child's active controllers = the parent's enabled set.
        // Build each child state, linking to the parent cgroup's state
        // for the same controller (for value inheritance) when present.
        let mut state = BTreeMap::new();
        let enabled: Vec<_> = parent.enabled.lock().iter().copied().collect();
        for cname in enabled {
            if let Some(ctrl) = controller::find(cname) {
                let parent_cs = { parent.ctrl_state.lock().get(cname).cloned() };
                state.insert(cname, ctrl.new_state(parent_cs));
            }
        }
        Arc::new(Cgroup {
            ino: alloc_cgroup_ino(),
            name,
            parent: Some(parent),
            depth,
            children: IrqSafeSpinLock::new(BTreeMap::new()),
            members: IrqSafeSpinLock::new(BTreeSet::new()),
            threads: IrqSafeSpinLock::new(BTreeSet::new()),
            cg_type: IrqSafeSpinLock::new(CgroupType::Domain),
            frozen: AtomicBool::new(false),
            enabled: IrqSafeSpinLock::new(BTreeSet::new()),
            ctrl_state: IrqSafeSpinLock::new(state),
            max_depth: IrqSafeSpinLock::new(None),
            max_descendants: IrqSafeSpinLock::new(None),
            #[cfg(feature = "cgroup-psi")]
            psi_enabled: AtomicBool::new(true),
            events_gen: AtomicU64::new(0),
            last_populated: AtomicBool::new(false),
            owner: IrqSafeSpinLock::new((0, 0)),
            file_owners: IrqSafeSpinLock::new(BTreeMap::new()),
            mode: IrqSafeSpinLock::new(0o755),
            file_modes: IrqSafeSpinLock::new(BTreeMap::new()),
        })
    }

    #[inline]
    fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    /// Effective frozen state: a cgroup is frozen if it *or any
    /// ancestor* has `cgroup.freeze` set (v2: freezing propagates down
    /// the subtree). `cgroup.events` reports this; `cgroup.freeze`
    /// reads back only the self-requested bit.
    fn effective_frozen(&self) -> bool {
        if self.frozen.load(Ordering::Acquire) {
            return true;
        }
        self.parent.as_ref().is_some_and(|p| p.effective_frozen())
    }

    /// `true` if this cgroup or any descendant has a member process.
    fn populated(&self) -> bool {
        if !self.members.lock().is_empty() {
            return true;
        }
        self.children.lock().values().any(|c| c.populated())
    }

    /// Number of descendant cgroups (not counting self).
    fn nr_descendants(&self) -> u64 {
        let children = self.children.lock();
        let mut n = children.len() as u64;
        for c in children.values() {
            n += c.nr_descendants();
        }
        n
    }

    /// Controllers available to *this* cgroup (its `cgroup.controllers`):
    /// the root sees every registered controller; a child sees its
    /// parent's `subtree_control` set.
    fn available_controllers(&self) -> Vec<&'static str> {
        match &self.parent {
            None => {
                let mut v: Vec<&'static str> =
                    controller::registered().iter().map(|c| c.name()).collect();
                v.sort_unstable();
                v
            }
            Some(p) => {
                let mut v: Vec<&'static str> = p.enabled.lock().iter().copied().collect();
                v.sort_unstable();
                v
            }
        }
    }

    /// Bump this cgroup's `cgroup.events` change generation, signalling
    /// any fd polling its `cgroup.events` file (`POLLPRI`) that a
    /// reported field changed. Called on `frozen` transitions and from
    /// [`notify_events`] on `populated` transitions.
    fn bump_events(&self) {
        self.events_gen.fetch_add(1, Ordering::AcqRel);
    }

    /// Absolute path of this cgroup's directory under `/sys/fs/cgroup`.
    ///
    /// Built by walking to the root, since inotify watches are keyed by
    /// PATH and systemd registers one per cgroup directory.
    fn abs_path(&self) -> String {
        let mut parts: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
        let mut cur = Some(self);
        while let Some(c) = cur {
            if !c.name.is_empty() {
                parts.push(&c.name);
            }
            cur = c.parent.as_deref();
        }
        let mut path = String::from("/sys/fs/cgroup");
        for seg in parts.iter().rev() {
            path.push('/');
            path.push_str(seg);
        }
        path
    }

    /// Re-publish `populated` and signal `cgroup.events` watchers if it
    /// transitioned, then walk up so an ancestor watching `events` also
    /// signals when a descendant empties.
    fn notify_events(&self) {
        let now = self.populated();
        let was = self.last_populated.swap(now, Ordering::AcqRel);
        if now != was {
            self.bump_events();
            // POLLPRI (bump_events) is NOT enough: systemd never polls this
            // file. It registers
            //   inotify_add_watch(fd, "<cgroup>/cgroup.events", IN_MODIFY)
            // (systemd src/core/cgroup.c) and re-reads `populated` from
            // unit_check_cgroup_events() when that fires.
            //
            // Every other IN_MODIFY in NARF originates on a userspace write
            // path (sys_write/sys_truncate → notify_modify_*), but this
            // transition is kernel-side — a task entering or leaving the
            // cgroup — so nothing on the write path ever runs and systemd
            // was never told.
            //
            // Consequence, measured: a Type=forking service's start job
            // never completes, because systemd is waiting to observe the
            // cgroup settle. plasma-kcminit.service stuck in `start
            // running` with no process alive, holding 20 other Plasma jobs
            // in `waiting` — kwin composited an empty scene and KDE showed
            // a black screen. Affects ANY Type=forking unit, not just KDE.
            //
            // Fired for ancestors too (this walks up), because systemd
            // watches each cgroup directory it manages, not just the leaf.
            let mut path = self.abs_path();
            path.push_str("/cgroup.events");
            crate::notify_modify(&path);
            if CGEVT_TRACE.load(Ordering::Relaxed) {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "CGEVT {} populated {}->{}",
                    self.abs_path(),
                    was as u8,
                    now as u8
                );
            }
        }
        if let Some(p) = &self.parent {
            p.notify_events();
        }
    }
}

// ── Global tree + reverse index ─────────────────────────────────────

static CGROUP_ROOT: OnceLock<Arc<Cgroup>> = OnceLock::new();

/// pid → its cgroup. Absent ⇒ implicitly the root cgroup.
static TASK_CGROUP: IrqSafeSpinLock<BTreeMap<u64, Arc<Cgroup>>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// Mutate the reverse index without recursively charging allocations made by
/// the map itself. The charge hook resolves a pid through `TASK_CGROUP`, so a
/// BTreeMap node allocation/free while this lock is held must be treated as
/// kernel cgroup metadata rather than charged to the current task.
fn mutate_task_cgroup<R>(f: impl FnOnce(&mut BTreeMap<u64, Arc<Cgroup>>) -> R) -> R {
    let mut membership = TASK_CGROUP.lock();
    #[cfg(feature = "cgroup-memory")]
    let _charge_bypass = memory::bypass_charge();
    f(&mut membership)
}

/// Mutate a controller-state map without charging its own BTreeMap metadata.
/// The memory charge hook walks these maps, so an allocation or final `Arc`
/// drop while one is locked must not recursively enter that walk.
fn mutate_ctrl_state<R>(
    cg: &Cgroup,
    f: impl FnOnce(&mut BTreeMap<&'static str, Arc<dyn ControllerState>>) -> R,
) -> R {
    let mut states = cg.ctrl_state.lock();
    #[cfg(feature = "cgroup-memory")]
    let _charge_bypass = memory::bypass_charge();
    f(&mut states)
}

/// Clone the small controller-state set under its lock, then release the lock
/// before invoking controller callbacks or allocating caller-owned output.
fn snapshot_ctrl_states(cg: &Cgroup) -> Vec<(&'static str, Arc<dyn ControllerState>)> {
    let states = cg.ctrl_state.lock();
    #[cfg(feature = "cgroup-memory")]
    let _charge_bypass = memory::bypass_charge();
    states
        .iter()
        .map(|(&name, state)| (name, state.clone()))
        .collect()
}

/// Clone one controller state under the metadata lock. Controller callbacks
/// may allocate, and allocator charging walks this same map, so every caller
/// must invoke the returned state only after this helper has released the
/// lock.
fn snapshot_ctrl_state(cg: &Cgroup, name: &'static str) -> Option<Arc<dyn ControllerState>> {
    cg.ctrl_state.lock().get(name).cloned()
}

fn root() -> Arc<Cgroup> {
    let root = CGROUP_ROOT.get_or_init(Cgroup::new_root).clone();

    // Linux creates a css for every available controller on the root even
    // before that controller is delegated through cgroup.subtree_control.
    // Besides making root-only/statistical files truthful, this is what lets
    // accounting from a descendant continue all the way to the hierarchy
    // root.  Reconcile here as well as at boot because tests and optional
    // controller registrations may add a controller after the root exists.
    for controller in controller::registered() {
        let name = controller.name();
        let present = { root.ctrl_state.lock().contains_key(name) };
        if !present {
            // Controller construction can allocate and install hooks. Do it
            // without the ctrl_state lock, then use the narrow metadata
            // mutation helper for the insertion itself. A concurrent root()
            // may construct the same state, but entry insertion selects one.
            let state = controller.new_state(None);
            mutate_ctrl_state(&root, |states| {
                states.entry(name).or_insert(state);
            });
        }
    }

    root
}

/// Collect the member pids of `pid`'s cgroup and its entire subtree — the
/// candidate set for a cgroup-scoped OOM when that subtree breaches
/// `memory.max`. A v2 process is in exactly one cgroup, and the charging pid is
/// always a member of its own subtree, so scoping the OOM here keeps every
/// victim inside the offending hierarchy (rather than killing machine-wide).
///
/// Runs inside the charge hook's per-CPU re-entrancy guard, so its own `Vec`
/// growth is treated as cgroup metadata (not recursively charged). NOTE: when
/// an ANCESTOR's `memory.max` is what breached, the ideal victim set is that
/// ancestor's (wider) subtree; scoping to the charging pid's own subtree is a
/// sound subset (documented follow-up: map the breaching MemoryState back to
/// its cgroup for exact scoping).
#[cfg(feature = "cgroup-memory")]
pub(super) fn oom_candidate_pids(pid: u64) -> Vec<u64> {
    let start = TASK_CGROUP.lock().get(&pid).cloned().unwrap_or_else(root);
    let mut out: Vec<u64> = Vec::new();
    let mut stack: Vec<Arc<Cgroup>> = alloc::vec![start];
    while let Some(cg) = stack.pop() {
        out.extend(cg.members.lock().iter().copied());
        stack.extend(cg.children.lock().values().cloned());
    }
    out
}

/// Resolve the cgroup a pid currently belongs to (root if unplaced).
fn cgroup_of(pid: u64) -> Arc<Cgroup> {
    // Keep the guard's lifetime explicit: `root()` may reconcile controller
    // state and allocate. Running that fallback while TASK_CGROUP remained
    // locked would let allocator charging recurse through cgroup_of().
    let placed = { TASK_CGROUP.lock().get(&pid).cloned() };
    placed.unwrap_or_else(root)
}

/// Pid of the process performing the current cgroupfs write, for the
/// Linux "write 0 into cgroup.procs = move yourself" form. cgroup membership
/// is keyed by the OUTER ProcessId (every fork/attach path uses it), so this
/// resolves through procfs's OUTER-pid hook — not `current_pid()`, which now
/// returns the caller's namespace-local pid. `None` when the hook is absent
/// (pre-boot, or a build without linux-compat).
fn caller_pid() -> Option<u64> {
    #[cfg(feature = "linux-compat")]
    {
        let pid = crate::procfs::current_outer_pid();
        if pid != 0 {
            return Some(pid);
        }
    }
    None
}

/// Invoke `f` with each active `ControllerState` named `name` along the
/// cgroup chain of `pid` (its cgroup up to the root). For controllers
/// whose accounting is driven by an external subsystem — the memory
/// allocator charging pages, the block layer attributing I/O — rather
/// than by membership. The callee downcasts via
/// [`ControllerState::as_any`].
pub fn with_chain_states<F: FnMut(&Arc<dyn ControllerState>)>(
    pid: u64,
    name: &'static str,
    mut f: F,
) {
    let mut cur = Some(cgroup_of(pid));
    while let Some(c) = cur {
        let state = c.ctrl_state.lock().get(name).cloned();
        if let Some(s) = state {
            f(&s);
        }
        cur = c.parent.clone();
    }
}

/// Allocation-free variant for final-owner accounting paths. Unlike
/// [`with_chain_states`], an unplaced/exited pid is ignored instead of falling
/// back through `root()`, whose controller reconciliation may allocate. Map
/// lookups, `Arc` clones, parent traversal, and state downcasts do not allocate;
/// callers must keep `f` allocation-free as well.
pub(super) fn with_existing_chain_states<F: FnMut(&Arc<dyn ControllerState>)>(
    pid: u64,
    name: &'static str,
    mut f: F,
) {
    let mut cur = { TASK_CGROUP.lock().get(&pid).cloned() };
    while let Some(c) = cur {
        let state = c.ctrl_state.lock().get(name).cloned();
        if let Some(s) = state {
            f(&s);
        }
        cur = c.parent.clone();
    }
}

/// `cg` plus every ancestor up to the root, bottom-up — the levels that
/// membership charging walks.
fn charge_chain(cg: &Arc<Cgroup>) -> Vec<Arc<Cgroup>> {
    let mut chain = Vec::new();
    let mut cur = Some(cg.clone());
    while let Some(c) = cur {
        chain.push(c.clone());
        cur = c.parent.clone();
    }
    chain
}

/// Run `on_detach(pid)` for every active controller on every level of
/// `cg`'s chain.
fn detach_chain(cg: &Arc<Cgroup>, pid: u64) {
    for node in charge_chain(cg) {
        for (_, state) in snapshot_ctrl_states(&node) {
            state.on_detach(pid);
        }
    }
}

/// Two-phase attach over `cg`'s chain: pre-check every `can_attach`
/// (charging nothing), then commit with `on_attach`.
fn attach_chain(cg: &Arc<Cgroup>, pid: u64) -> Result<(), FsError> {
    let chain = charge_chain(cg);
    for node in &chain {
        for (_, state) in snapshot_ctrl_states(node) {
            state.can_attach(pid)?;
        }
    }
    for node in &chain {
        for (_, state) in snapshot_ctrl_states(node) {
            state.on_attach(pid);
        }
    }
    Ok(())
}

/// Move `pid` into `dst`, honouring controller vetoes (`can_attach`);
/// on rejection the process stays put. The `cgroup.procs`-write path.
fn place(pid: u64, dst: &Arc<Cgroup>) -> Result<(), FsError> {
    // No-internal-process constraint (v2 §"No Internal Process
    // Constraint"): a non-root cgroup that distributes resources to its
    // children (has a non-empty `subtree_control`) may not hold member
    // processes directly. The root is exempt.
    if !dst.is_root() && !dst.enabled.lock().is_empty() {
        return Err(FsError::Busy);
    }
    let prev = TASK_CGROUP.lock().get(&pid).cloned();
    if let Some(prev) = &prev {
        if Arc::ptr_eq(prev, dst) {
            return Ok(());
        }
        detach_chain(prev, pid);
    }
    if let Err(e) = attach_chain(dst, pid) {
        // Roll back: re-charge the previous cgroup so the failed move is
        // accounting-neutral.
        if let Some(prev) = &prev {
            let _ = attach_chain(prev, pid);
        }
        return Err(e);
    }
    if let Some(prev) = &prev {
        prev.members.lock().remove(&pid);
    }
    dst.members.lock().insert(pid);
    mutate_task_cgroup(|membership| membership.insert(pid, dst.clone()));
    if let Some(prev) = &prev {
        prev.notify_events();
    }
    dst.notify_events();
    Ok(())
}

/// Move `pid` into `dst` unconditionally (no veto) — fork inheritance
/// and boot placement, where the process already exists.
fn place_forced(pid: u64, dst: &Arc<Cgroup>) {
    let prev = TASK_CGROUP.lock().get(&pid).cloned();
    if let Some(prev) = &prev {
        if Arc::ptr_eq(prev, dst) {
            return;
        }
        detach_chain(prev, pid);
        prev.members.lock().remove(&pid);
    }
    for node in charge_chain(dst) {
        for (_, state) in snapshot_ctrl_states(&node) {
            state.on_attach(pid);
        }
    }
    dst.members.lock().insert(pid);
    mutate_task_cgroup(|membership| membership.insert(pid, dst.clone()));
    if let Some(prev) = &prev {
        prev.notify_events();
    }
    dst.notify_events();
}

// ── Lifecycle hooks called by the userspace crate ───────────────────

/// Place a boot-time process (e.g. init) into the root cgroup.
pub fn attach_to_root(pid: u64) {
    let r = root();
    place_forced(pid, &r);
}

/// Fork/clone inheritance: a child process joins its parent's cgroup.
pub fn fork_inherit(parent_pid: u64, child_pid: u64) {
    let dst = cgroup_of(parent_pid);
    place_forced(child_pid, &dst);
}

/// `CLONE_INTO_CGROUP` (clone3): place the freshly-cloned `pid` into the
/// cgroup at `path` (cgroupfs-relative, e.g. `/system.slice/foo.service`;
/// `""` or `"/"` = the root cgroup). Controller vetoes are honoured
/// (`place`), matching Linux's `cgroup_attach_task` on the clone path.
///
/// Linux ref: `kernel/cgroup/cgroup.c::cgroup_css_set_fork`.
pub fn attach_by_path(path: &str, pid: u64) -> Result<(), FsError> {
    let mut cur = root();
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        let next = cur.children.lock().get(comp).cloned();
        match next {
            Some(n) => cur = n,
            None => return Err(FsError::NotFound),
        }
    }
    place(pid, &cur)
}

/// A process exited: drop its membership and uncharge controllers.
pub fn task_exited(pid: u64) {
    let cg = mutate_task_cgroup(|membership| membership.remove(&pid));
    if let Some(cg) = cg {
        detach_chain(&cg, pid);
        cg.members.lock().remove(&pid);
        cg.notify_events();
    }
    TASK_NS_ROOT.lock().remove(&pid);
}

/// Test-only seam for the lock/allocator recursion that can occur when a
/// membership-map mutation needs a fresh BTreeMap node. The real allocator
/// reaches the same charge hook from inside `insert`/`remove`; invoking it
/// directly makes the regression deterministic instead of depending on slab
/// state. Without `mutate_task_cgroup`'s bypass this call self-deadlocks.
#[cfg(feature = "cgroup-memory")]
#[doc(hidden)]
pub fn membership_charge_reentry_for_test(pid: u64, delta_bytes: i64) -> bool {
    mutate_task_cgroup(|_| memory::charge_hook_for_test(pid, delta_bytes))
}

/// Deterministically exercise allocator charging while the current cgroup's
/// controller-state map is being mutated. Without the metadata bypass this
/// re-enters `with_chain_states` and self-deadlocks on `ctrl_state`.
#[cfg(feature = "cgroup-memory")]
#[doc(hidden)]
pub fn ctrl_state_charge_reentry_for_test(pid: u64, delta_bytes: i64) -> bool {
    let cg = cgroup_of(pid);
    mutate_ctrl_state(&cg, |_| memory::charge_hook_for_test(pid, delta_bytes))
}

/// Exercise a controller read callback that re-enters memory charging. This
/// is the deterministic form of a formatted cgroup attribute read refilling
/// the allocator while `ctrl_state` is held.
#[cfg(feature = "cgroup-memory")]
#[doc(hidden)]
pub fn ctrl_read_charge_reentry_for_test(pid: u64, delta_bytes: i64) -> bool {
    use core::any::Any;

    #[derive(Debug)]
    struct ChargeOnRead {
        pid: u64,
        delta_bytes: i64,
        allowed: Arc<AtomicBool>,
    }

    impl ControllerState for ChargeOnRead {
        fn files(&self) -> &'static [&'static str] {
            &["__test.charge_on_read"]
        }

        fn read(&self, _file: &str) -> String {
            self.allowed.store(
                memory::charge_hook_for_test(self.pid, self.delta_bytes),
                Ordering::Release,
            );
            String::new()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    let cg = cgroup_of(pid);
    let allowed = Arc::new(AtomicBool::new(false));
    mutate_ctrl_state(&cg, |states| {
        states.insert(
            "__test_charge_on_read",
            Arc::new(ChargeOnRead {
                pid,
                delta_bytes,
                allowed: allowed.clone(),
            }),
        );
    });
    let file = CgroupAttrFile {
        cg: cg.clone(),
        kind: FileKind::Ctrl("__test_charge_on_read", "__test.charge_on_read"),
        ino: 0,
        seen_gen: AtomicU64::new(0),
    };
    let _ = file.content();
    mutate_ctrl_state(&cg, |states| {
        states.remove("__test_charge_on_read");
    });
    allowed.load(Ordering::Acquire)
}

/// Inject memory charging after `memory.high`/`memory.max` has been copied
/// out of its field lock but before the line is formatted.
#[cfg(feature = "cgroup-memory")]
#[doc(hidden)]
pub fn memory_limit_read_charge_reentry_for_test(pid: u64, file: &str, delta_bytes: i64) -> bool {
    let cg = cgroup_of(pid);
    snapshot_ctrl_state(&cg, "memory")
        .map(|state| {
            state
                .as_any()
                .downcast_ref::<memory::MemoryState>()
                .map(|state| state.limit_read_charge_reentry_for_test(file, pid, delta_bytes))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

// ── cgroup namespace (CLONE_NEWCGROUP) ──────────────────────────────

/// A cgroup namespace has its own nsfs identity even when two namespaces
/// happen to use the same cgroup directory as their visible root.
#[derive(Debug)]
pub struct CgroupNamespace {
    id: u64,
    root: Arc<Cgroup>,
}

impl CgroupNamespace {
    fn new(root: Arc<Cgroup>) -> Arc<Self> {
        Arc::new(Self {
            id: crate::alloc_mount_ns_id(),
            root,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

static INITIAL_CGROUP_NS: OnceLock<Arc<CgroupNamespace>> = OnceLock::new();

fn initial_cgroup_namespace() -> Arc<CgroupNamespace> {
    INITIAL_CGROUP_NS
        .get_or_init(|| CgroupNamespace::new(root()))
        .clone()
}

/// pid → its cgroup namespace. A process appears here once it unshares or
/// joins a namespace; absent means the shared initial namespace.
static TASK_NS_ROOT: IrqSafeSpinLock<BTreeMap<u64, Arc<CgroupNamespace>>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// `CLONE_NEWCGROUP`: make `pid`'s *current* cgroup its
/// cgroup-namespace root, so subsequent `/proc/[pid]/cgroup` paths
/// render relative to it (the v2 cgroup-namespace contract).
pub fn unshare_cgroup_ns(pid: u64) {
    let cur = cgroup_of(pid);
    TASK_NS_ROOT.lock().insert(pid, CgroupNamespace::new(cur));
}

/// Namespace object named by `/proc/<pid>/ns/cgroup`.
pub fn cgroup_namespace_of(pid: u64) -> Arc<CgroupNamespace> {
    TASK_NS_ROOT
        .lock()
        .get(&pid)
        .cloned()
        .unwrap_or_else(initial_cgroup_namespace)
}

/// Join an existing cgroup namespace through `setns(2)`.
pub fn install_cgroup_namespace(pid: u64, ns: Arc<CgroupNamespace>) {
    TASK_NS_ROOT.lock().insert(pid, ns);
}

/// Inherit the cgroup-namespace root from parent to child at fork.
pub fn fork_inherit_ns(parent_pid: u64, child_pid: u64) {
    let r = TASK_NS_ROOT.lock().get(&parent_pid).cloned();
    if let Some(r) = r {
        TASK_NS_ROOT.lock().insert(child_pid, r);
    }
}

/// Path of `cg` relative to a cgroup-namespace root (`/` when `cg` is
/// the root). Linux preserves sibling visibility using `..` components rather
/// than leaking an absolute host-hierarchy path.
fn cgroup_path_relative(cg: &Arc<Cgroup>, nsroot: &Arc<Cgroup>) -> String {
    let target = cgroup_components(cg);
    let namespace = cgroup_components(nsroot);
    let common = target
        .iter()
        .zip(namespace.iter())
        .take_while(|(target, namespace)| target == namespace)
        .count();

    let mut relative = String::new();
    for _ in common..namespace.len() {
        relative.push_str("/..");
    }
    for component in &target[common..] {
        relative.push('/');
        relative.push_str(component);
    }
    if relative.is_empty() {
        relative.push('/');
    }
    relative
}

/// `/proc/[pid]/cgroup` content: the v2 single-line form `0::<path>\n`.
/// `/proc/<pid>/cgroup` for target process `pid`, rendered relative to the
/// cgroup namespace of the READER (`reader_pid`, an outer ProcessId) — NOT the
/// target's. This is the Linux contract: `/proc/<pid>/cgroup` shows the path
/// namespaced to the process that opened the file. A reader outside any cgroup
/// namespace (e.g. PID 1) therefore sees the ABSOLUTE path even for a target
/// that is itself in a cgroup namespace — which is exactly what lets PID 1
/// attribute a service's `sd_notify(READY=1)` to its unit via
/// `manager_get_unit_by_pidref_cgroup` (it reads `/proc/<service>/cgroup` and
/// matches `/system.slice/<unit>`). Keying the relativization on the TARGET's
/// namespace made a namespaced service (ProtectControlGroups= → CLONE_NEWCGROUP)
/// read back as `0::/` to PID 1, so the match failed and every such
/// `Type=notify` service timed out.
pub fn proc_pid_cgroup(pid: u64, reader_pid: u64) -> Vec<u8> {
    let cg = cgroup_of(pid);
    let path = match TASK_NS_ROOT.lock().get(&reader_pid).cloned() {
        Some(namespace) => cgroup_path_relative(&cg, &namespace.root),
        None => cgroup_path(&cg),
    };
    format!("0::{path}\n").into_bytes()
}

/// `/proc/cgroups` content. v2 has a single unified hierarchy; emit the
/// header plus one row per registered controller (hierarchy 0).
pub fn proc_cgroups() -> Vec<u8> {
    let mut s = String::from("#subsys_name\thierarchy\tnum_cgroups\tenabled\n");
    let total = 1 + root().nr_descendants();
    for c in controller::registered() {
        s.push_str(&format!("{}\t0\t{}\t1\n", c.name(), total));
    }
    s.into_bytes()
}

/// Absolute path of a cgroup within the hierarchy (`/` for root).
fn cgroup_path(cg: &Arc<Cgroup>) -> String {
    let parts = cgroup_components(cg);
    if parts.is_empty() {
        return "/".to_string();
    }
    let mut s = String::new();
    for part in parts {
        s.push('/');
        s.push_str(&part);
    }
    s
}

fn cgroup_components(cg: &Arc<Cgroup>) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = cg.clone();
    while let Some(p) = cur.parent.clone() {
        parts.push(cur.name.clone());
        cur = p;
    }
    parts.reverse();
    parts
}

// ── Core control files ──────────────────────────────────────────────

/// A fixed `cgroup.*` interface file (as opposed to a controller file).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CoreFile {
    Controllers,
    SubtreeControl,
    Procs,
    Threads,
    Events,
    Type,
    Stat,
    StatLocal,
    Freeze,
    Kill,
    MaxDepth,
    MaxDescendants,
    /// `cgroup.pressure` — per-cgroup PSI-accounting toggle (Linux
    /// 6.1+, present on every cgroup including the root). NARF stores
    /// the bit so probe writes round-trip; the pressure numbers
    /// themselves are the psi module's scaffold zeroes.
    #[cfg(feature = "cgroup-psi")]
    Pressure,
    CpuStatLocal,
}

impl CoreFile {
    fn file_name(self) -> &'static str {
        match self {
            CoreFile::Controllers => "cgroup.controllers",
            CoreFile::SubtreeControl => "cgroup.subtree_control",
            CoreFile::Procs => "cgroup.procs",
            CoreFile::Threads => "cgroup.threads",
            CoreFile::Events => "cgroup.events",
            CoreFile::Type => "cgroup.type",
            CoreFile::Stat => "cgroup.stat",
            CoreFile::StatLocal => "cgroup.stat.local",
            CoreFile::Freeze => "cgroup.freeze",
            CoreFile::Kill => "cgroup.kill",
            CoreFile::MaxDepth => "cgroup.max.depth",
            CoreFile::MaxDescendants => "cgroup.max.descendants",
            #[cfg(feature = "cgroup-psi")]
            CoreFile::Pressure => "cgroup.pressure",
            CoreFile::CpuStatLocal => "cpu.stat.local",
        }
    }

    fn from_name(name: &str) -> Option<CoreFile> {
        Some(match name {
            "cgroup.controllers" => CoreFile::Controllers,
            "cgroup.subtree_control" => CoreFile::SubtreeControl,
            "cgroup.procs" => CoreFile::Procs,
            "cgroup.threads" => CoreFile::Threads,
            "cgroup.events" => CoreFile::Events,
            "cgroup.type" => CoreFile::Type,
            "cgroup.stat" => CoreFile::Stat,
            "cgroup.stat.local" => CoreFile::StatLocal,
            "cgroup.freeze" => CoreFile::Freeze,
            "cgroup.kill" => CoreFile::Kill,
            "cgroup.max.depth" => CoreFile::MaxDepth,
            "cgroup.max.descendants" => CoreFile::MaxDescendants,
            #[cfg(feature = "cgroup-psi")]
            "cgroup.pressure" => CoreFile::Pressure,
            "cpu.stat.local" => CoreFile::CpuStatLocal,
            _ => return None,
        })
    }

    fn writable(self) -> bool {
        match self {
            CoreFile::SubtreeControl
            | CoreFile::Procs
            | CoreFile::Threads
            | CoreFile::Type
            | CoreFile::Freeze
            | CoreFile::Kill
            | CoreFile::MaxDepth
            | CoreFile::MaxDescendants => true,
            #[cfg(feature = "cgroup-psi")]
            CoreFile::Pressure => true,
            _ => false,
        }
    }
}

/// Core files present in a cgroup. The root omits the per-cgroup
/// affordances (`type`, `events`, `freeze`, `kill`) that v2 only
/// defines for non-root cgroups.
fn core_files_for(cg: &Cgroup) -> &'static [CoreFile] {
    if cg.is_root() {
        &[
            CoreFile::Controllers,
            CoreFile::SubtreeControl,
            CoreFile::Procs,
            CoreFile::Threads,
            CoreFile::Stat,
            CoreFile::MaxDepth,
            CoreFile::MaxDescendants,
            #[cfg(feature = "cgroup-psi")]
            CoreFile::Pressure,
            CoreFile::CpuStatLocal,
        ]
    } else {
        &[
            CoreFile::Type,
            CoreFile::Controllers,
            CoreFile::SubtreeControl,
            CoreFile::Procs,
            CoreFile::Threads,
            CoreFile::Events,
            CoreFile::Freeze,
            CoreFile::Kill,
            CoreFile::Stat,
            CoreFile::StatLocal,
            CoreFile::MaxDepth,
            CoreFile::MaxDescendants,
            #[cfg(feature = "cgroup-psi")]
            CoreFile::Pressure,
            CoreFile::CpuStatLocal,
        ]
    }
}

fn max_str(v: &Option<u64>) -> String {
    match v {
        None => "max\n".to_string(),
        Some(n) => format!("{n}\n"),
    }
}

fn parse_max(text: &str) -> Result<Option<u64>, FsError> {
    let t = text.trim();
    if t == "max" {
        Ok(None)
    } else {
        let value = t.parse::<u64>().map_err(|_| FsError::InvalidData)?;
        // Linux stores both limits as non-negative `int` values.
        if value > i32::MAX as u64 {
            return Err(FsError::InvalidData);
        }
        Ok(Some(value))
    }
}

#[cfg(feature = "linux-compat")]
fn report_pid(pid: u64) -> Option<u64> {
    crate::procfs::pid_report(pid)
}

#[cfg(not(feature = "linux-compat"))]
fn report_pid(pid: u64) -> Option<u64> {
    Some(pid)
}

#[cfg(feature = "linux-compat")]
fn resolve_pid(pid: u64) -> Option<u64> {
    crate::procfs::pid_resolve(pid)
}

#[cfg(not(feature = "linux-compat"))]
fn resolve_pid(pid: u64) -> Option<u64> {
    Some(pid)
}

fn render_core(cg: &Arc<Cgroup>, f: CoreFile) -> String {
    match f {
        CoreFile::Controllers => {
            let names = cg.available_controllers();
            if names.is_empty() {
                String::new()
            } else {
                let mut s = names.join(" ");
                s.push('\n');
                s
            }
        }
        CoreFile::SubtreeControl => {
            let g = cg.enabled.lock();
            if g.is_empty() {
                String::new()
            } else {
                let mut v: Vec<&str> = g.iter().copied().collect();
                v.sort_unstable();
                let mut s = v.join(" ");
                s.push('\n');
                s
            }
        }
        CoreFile::Procs => {
            let mut s = String::new();
            // Members are outer ProcessIds; report them in the READER's PID
            // namespace and drop any not visible there (namespace isolation).
            for pid in cg.members.lock().iter() {
                if let Some(v) = report_pid(*pid) {
                    s.push_str(&v.to_string());
                    s.push('\n');
                }
            }
            s
        }
        CoreFile::Threads => {
            let mut s = String::new();
            // Threaded cgroups track tids; otherwise mirror procs.
            let t = cg.threads.lock();
            if t.is_empty() {
                for pid in cg.members.lock().iter() {
                    if let Some(v) = report_pid(*pid) {
                        s.push_str(&v.to_string());
                        s.push('\n');
                    }
                }
            } else {
                for tid in t.iter() {
                    s.push_str(&tid.to_string());
                    s.push('\n');
                }
            }
            s
        }
        CoreFile::Events => {
            // `frozen` is the EFFECTIVE state (self or any ancestor
            // frozen) — what systemd's freezer watches for.
            let populated = u8::from(cg.populated());
            let frozen = u8::from(cg.effective_frozen());
            format!("populated {populated}\nfrozen {frozen}\n")
        }
        CoreFile::Type => cg.cg_type.lock().as_str().to_string(),
        CoreFile::Stat => format!(
            "nr_descendants {}\nnr_dying_descendants 0\n",
            cg.nr_descendants()
        ),
        // NARF does not yet retain freezer-duration accounting, so the
        // Linux 6.17 local-stat shape is present with an honest zero.
        CoreFile::StatLocal => "frozen_usec 0\n".to_string(),
        CoreFile::Freeze => {
            format!("{}\n", u8::from(cg.frozen.load(Ordering::Acquire)))
        }
        CoreFile::Kill => "0\n".to_string(),
        CoreFile::MaxDepth => max_str(&cg.max_depth.lock()),
        CoreFile::MaxDescendants => max_str(&cg.max_descendants.lock()),
        #[cfg(feature = "cgroup-psi")]
        CoreFile::Pressure => {
            format!("{}\n", u8::from(cg.psi_enabled.load(Ordering::Acquire)))
        }
        // Linux's cpu.stat.local currently reports the local (rather than
        // hierarchical) CFS throttle time. NARF does not enforce cpu.max,
        // therefore its only truthful value is zero.
        CoreFile::CpuStatLocal => "throttled_usec 0\n".to_string(),
    }
}

fn store_core(cg: &Arc<Cgroup>, f: CoreFile, buf: &[u8]) -> Result<usize, FsError> {
    let text = core::str::from_utf8(buf).map_err(|_| FsError::InvalidData)?;
    match f {
        CoreFile::Procs | CoreFile::Threads => {
            let mut pid: u64 = text.trim().parse().map_err(|_| FsError::InvalidData)?;
            // Linux: writing "0" moves the writing process itself —
            // the form systemd's cg_attach uses to place PID 1.
            if pid == 0 {
                pid = caller_pid().ok_or(FsError::InvalidData)?;
            } else {
                // An explicit pid is in the WRITER's PID namespace; translate to
                // the outer ProcessId cgroup membership keys on. Invisible in
                // the writer's namespace → reject (Linux ESRCH-ish).
                pid = resolve_pid(pid).ok_or(FsError::InvalidData)?;
            }
            place(pid, cg)?;
            Ok(buf.len())
        }
        CoreFile::SubtreeControl => {
            store_subtree_control(cg, text)?;
            Ok(buf.len())
        }
        CoreFile::Freeze => {
            let want = match text.trim() {
                "0" => false,
                "1" => true,
                _ => return Err(FsError::InvalidData),
            };
            set_frozen(cg, want);
            Ok(buf.len())
        }
        CoreFile::Kill => {
            if *cg.cg_type.lock() == CgroupType::Threaded {
                return Err(FsError::Unsupported);
            }
            if text.trim() == "1" {
                kill_subtree(cg);
                Ok(buf.len())
            } else {
                Err(FsError::InvalidData)
            }
        }
        CoreFile::Type => {
            if text.trim() == "threaded" {
                enable_threaded(cg)?;
                Ok(buf.len())
            } else {
                Err(FsError::InvalidData)
            }
        }
        CoreFile::MaxDepth => {
            *cg.max_depth.lock() = parse_max(text)?;
            Ok(buf.len())
        }
        CoreFile::MaxDescendants => {
            *cg.max_descendants.lock() = parse_max(text)?;
            Ok(buf.len())
        }
        #[cfg(feature = "cgroup-psi")]
        CoreFile::Pressure => {
            let want = match text.trim() {
                "0" => false,
                "1" => true,
                _ => return Err(FsError::InvalidData),
            };
            cg.psi_enabled.store(want, Ordering::Release);
            Ok(buf.len())
        }
        CoreFile::Controllers
        | CoreFile::Events
        | CoreFile::Stat
        | CoreFile::StatLocal
        | CoreFile::CpuStatLocal => Err(FsError::ReadOnly),
    }
}

/// Apply Linux's load-bearing checks for the one writable cgroup.type
/// transition. Full per-thread placement is not yet implemented, but NARF must
/// not enter a threaded state Linux would reject: a populated cgroup or one
/// distributing a domain-only controller cannot become threaded.
fn enable_threaded(cg: &Arc<Cgroup>) -> Result<(), FsError> {
    if *cg.cg_type.lock() == CgroupType::Threaded {
        return Ok(());
    }
    if cg.populated() {
        return Err(FsError::Unsupported);
    }
    if cg
        .enabled
        .lock()
        .iter()
        .any(|name| matches!(*name, "memory" | "io" | "misc"))
    {
        return Err(FsError::Unsupported);
    }

    let parent = cg.parent.as_ref().ok_or(FsError::Unsupported)?;
    let mut parent_type = parent.cg_type.lock();
    match *parent_type {
        CgroupType::Domain => *parent_type = CgroupType::DomainThreaded,
        CgroupType::DomainThreaded | CgroupType::Threaded => {}
        CgroupType::DomainInvalid => return Err(FsError::Unsupported),
    }
    drop(parent_type);
    *cg.cg_type.lock() = CgroupType::Threaded;
    Ok(())
}

/// Parse and apply a `cgroup.subtree_control` write: `+ctrl`/`-ctrl`
/// tokens. A controller can only be enabled if it is available to this
/// cgroup (in `cgroup.controllers`). Toggling propagates the controller
/// state onto/off existing children.
fn store_subtree_control(cg: &Arc<Cgroup>, text: &str) -> Result<(), FsError> {
    let available: BTreeSet<&'static str> = cg.available_controllers().into_iter().collect();
    // Validate the whole write first (atomic: reject without applying).
    // Linux resolves repeated operations in input order: the final token for
    // a controller wins ("-cpu +cpu" enables, "+cpu -cpu" disables).
    let mut changes: BTreeMap<&'static str, bool> = BTreeMap::new();
    for tok in text.split_whitespace() {
        let (sign, name) = tok.split_at(1.min(tok.len()));
        let canon = controller::find(name)
            .map(|controller| controller.name())
            .ok_or(FsError::InvalidData)?;
        match sign {
            "+" => {
                if !available.contains(canon) {
                    return Err(FsError::NotFound);
                }
                changes.insert(canon, true);
            }
            "-" => {
                // A known controller which is not enabled here is a no-op.
                changes.insert(canon, false);
            }
            _ => return Err(FsError::InvalidData),
        }
    }

    // No-internal-process constraint: can't start distributing
    // resources to children while this (non-root) cgroup still holds
    // member processes.
    if !cg.is_root()
        && changes.values().any(|enable| *enable)
        && (!cg.members.lock().is_empty() || !cg.threads.lock().is_empty())
    {
        return Err(FsError::Busy);
    }

    let mut enabled = cg.enabled.lock();
    let children = cg.children.lock();
    // Linux refuses to withdraw a controller while a child still delegates
    // it to its own descendants. Otherwise that child would advertise an
    // enabled controller which is no longer available from its parent.
    for (&name, &enable) in &changes {
        if !enable
            && enabled.contains(name)
            && children
                .values()
                .any(|child| child.enabled.lock().contains(name))
        {
            return Err(FsError::Busy);
        }
    }

    for (name, enable) in changes {
        if enable && enabled.insert(name) {
            if let Some(ctrl) = controller::find(name) {
                let parent_cs = cg.ctrl_state.lock().get(name).cloned();
                for child in children.values() {
                    let state = ctrl.new_state(parent_cs.clone());
                    mutate_ctrl_state(child, |states| {
                        states.entry(name).or_insert(state);
                    });
                }
            }
        } else if !enable && enabled.remove(name) {
            for child in children.values() {
                mutate_ctrl_state(child, |states| states.remove(name));
            }
        }
    }
    Ok(())
}

// ── Freeze / kill (delegated to the signal subsystem) ───────────────

/// Hooks the userspace crate installs at boot so cgroupfs can freeze /
/// thaw / kill processes through the signal subsystem. filesystem
/// cannot depend on userspace, so this is the standard NARF
/// fn-pointer indirection.
type FreezeHook = fn(pid: u64, freeze: bool);
type KillHook = fn(pid: u64);

static FREEZE_HOOK: IrqSafeSpinLock<Option<FreezeHook>> = IrqSafeSpinLock::new(None);
static KILL_HOOK: IrqSafeSpinLock<Option<KillHook>> = IrqSafeSpinLock::new(None);

/// Install the freeze hook (SIGSTOP/SIGCONT delivery).
pub fn install_freeze_hook(h: FreezeHook) {
    *FREEZE_HOOK.lock() = Some(h);
}

/// Install the kill hook (SIGKILL delivery).
pub fn install_kill_hook(h: KillHook) {
    *KILL_HOOK.lock() = Some(h);
}

/// Collect every member pid in `cg`'s subtree.
fn subtree_pids(cg: &Arc<Cgroup>, out: &mut Vec<u64>) {
    out.extend(cg.members.lock().iter().copied());
    for child in cg.children.lock().values() {
        subtree_pids(child, out);
    }
}

/// Bump `cgroup.events` generations across a whole subtree. Used when
/// a freeze/thaw changes the *effective* frozen state of every
/// descendant, each of which may have its own `cgroup.events` watcher.
fn bump_events_subtree(cg: &Arc<Cgroup>) {
    cg.bump_events();
    let children: Vec<Arc<Cgroup>> = cg.children.lock().values().cloned().collect();
    for child in children {
        bump_events_subtree(&child);
    }
}

/// `cgroup.freeze` — freeze or thaw every process in the subtree.
fn set_frozen(cg: &Arc<Cgroup>, freeze: bool) {
    let changed = cg.frozen.swap(freeze, Ordering::AcqRel) != freeze;
    let hook = *FREEZE_HOOK.lock();
    if let Some(h) = hook {
        let mut pids = Vec::new();
        subtree_pids(cg, &mut pids);
        for pid in pids {
            h(pid, freeze);
        }
    }
    // The `frozen` field of `cgroup.events` flipped — for this cgroup
    // AND every descendant (their effective state follows the
    // ancestor): signal all their pollers. `notify_events` covers
    // `populated`, which a freeze does not move.
    if changed {
        bump_events_subtree(cg);
    }
    cg.notify_events();
}

/// `cgroup.kill` — SIGKILL every process in the subtree.
fn kill_subtree(cg: &Arc<Cgroup>) {
    let hook = *KILL_HOOK.lock();
    if let Some(h) = hook {
        let mut pids = Vec::new();
        subtree_pids(cg, &mut pids);
        for pid in pids {
            h(pid);
        }
    }
}

// ── Attribute file ──────────────────────────────────────────────────

/// Identifies which file a `CgroupAttrFile` is: a fixed core file, or a
/// controller-owned file (`controller name`, `file name`).
#[derive(Clone, Debug)]
enum FileKind {
    Core(CoreFile),
    Ctrl(&'static str, &'static str),
    /// The base `cpu.stat` — a core v2 file present in EVERY cgroup
    /// (root included) even when the cpu controller is not enabled
    /// there (Linux `cgroup_base_files`). systemd reads it for
    /// `CPUUsageNSec=` on any unit cgroup. When the cpu controller IS
    /// active on the cgroup, its richer `cpu.stat` takes precedence
    /// (see `CgroupDir::lookup`).
    CpuStatBase,
}

/// Render the base `cpu.stat` (no cpu controller on this cgroup):
/// aggregate usage of every member process in the subtree. Without the
/// `cgroup-cpu` feature there is no scheduler accounting seam, so the
/// well-formed zero shape is reported.
fn render_cpu_stat_base(cg: &Arc<Cgroup>) -> String {
    let usage: u64;
    #[cfg(feature = "cgroup-cpu")]
    {
        let mut pids = Vec::new();
        subtree_pids(cg, &mut pids);
        usage = cpu::members_usage_usec(&pids);
    }
    #[cfg(not(feature = "cgroup-cpu"))]
    {
        let _ = cg;
        usage = 0;
    }
    format!("usage_usec {usage}\nuser_usec 0\nsystem_usec 0\n")
}

struct CgroupAttrFile {
    cg: Arc<Cgroup>,
    kind: FileKind,
    ino: u64,
    /// For `cgroup.events`: the change generation this fd has observed.
    /// Captured at open from `cg.events_gen` and re-synced on every
    /// read; `poll_readiness` reports `POLLPRI` while `cg.events_gen` is
    /// ahead of it. Unused (and untouched) for every other file.
    seen_gen: AtomicU64,
}

impl CgroupAttrFile {
    /// Open a fresh view, capturing the cgroup's current `cgroup.events`
    /// generation so this fd starts level with the live state (no
    /// spurious POLLPRI on the first poll after open).
    fn open(cg: Arc<Cgroup>, kind: FileKind) -> Arc<dyn FileOps> {
        let seen_gen = AtomicU64::new(cg.events_gen.load(Ordering::Acquire));
        let name = match &kind {
            FileKind::Core(file) => file.file_name(),
            FileKind::Ctrl(_, file) => file,
            FileKind::CpuStatBase => "cpu.stat",
        };
        let ino = cgroup_attr_ino(cg.ino, name);
        Arc::new(CgroupAttrFile {
            cg,
            kind,
            ino,
            seen_gen,
        })
    }

    /// True for the one file with edge-poll semantics (`cgroup.events`).
    fn is_events(&self) -> bool {
        matches!(self.kind, FileKind::Core(CoreFile::Events))
    }
}

impl CgroupAttrFile {
    fn content(&self) -> String {
        match &self.kind {
            FileKind::Core(f) => render_core(&self.cg, *f),
            FileKind::Ctrl(ctrl, file) => snapshot_ctrl_state(&self.cg, ctrl)
                .map(|s| s.read(file))
                .unwrap_or_default(),
            FileKind::CpuStatBase => render_cpu_stat_base(&self.cg),
        }
    }

    fn is_writable(&self) -> bool {
        match &self.kind {
            FileKind::Core(f) => f.writable(),
            FileKind::Ctrl(ctrl, file) => snapshot_ctrl_state(&self.cg, ctrl)
                .map(|s| s.writable(file))
                .unwrap_or(false),
            FileKind::CpuStatBase => false,
        }
    }
}

impl FileOps for CgroupAttrFile {
    // Per-file ownership. The FileOps default is `Unsupported`, which is
    // what made `cg_set_access()` fail: it chowns cgroup.procs /
    // cgroup.subtree_control / cgroup.threads one by one after the
    // directory, so a rejected file chown aborts delegation and
    // `systemd --user` exits 219/EXIT_CGROUP.
    fn owners(&self) -> (u32, u32) {
        // No explicit chown yet ⇒ inherit the CGROUP DIRECTORY's owner, not
        // a hardcoded root. Linux stamps a new cgroup's interface files with
        // the creating task's ids (`cgroup_mkdir` → `cgroup_kn_set_ugid`),
        // which is what lets an unprivileged `systemd --user` write its own
        // `cgroup.procs`. Reporting (0,0) with 0644 put uid 1000 in the
        // "other" triplet (read-only), so open(O_WRONLY) was refused and the
        // user manager's children died 219/EXIT_CGROUP.
        //
        // Bind the first lookup to a `let` so its lock guard is dropped at
        // the end of the statement — matching on the guard directly would
        // hold `file_owners` while taking `owner`.
        let explicit = self.cg.file_owners.lock().get(&self.ino).copied();
        match explicit {
            Some(owner) => owner,
            None => *self.cg.owner.lock(),
        }
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        self.cg.file_owners.lock().insert(self.ino, (uid, gid));
        Box::pin(async { Ok(()) })
    }

    // chmod on a cgroup attribute file. Linux backs these with kernfs, whose
    // `kernfs_iop_setattr` accepts mode changes; the `Unsupported` default
    // made systemd's `fchmod_and_chown()` fail before it ever chowned.
    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        self.cg.file_modes.lock().insert(self.ino, perms & 0o7777);
        Box::pin(async { Ok(()) })
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Reading `cgroup.events` consumes the pending edge: re-sync this
        // fd's observed generation to the live one so `poll_readiness`
        // stops reporting POLLPRI until the next transition. Snapshot the
        // gen before rendering so a transition racing the read leaves the
        // fd one generation behind (POLLPRI stays set) rather than
        // silently swallowing the edge.
        if self.is_events() {
            let gen = self.cg.events_gen.load(Ordering::Acquire);
            self.seen_gen.store(gen, Ordering::Release);
        }
        let content = self.content();
        Box::pin(async move {
            let bytes = content.as_bytes();
            let start = offset as usize;
            if start >= bytes.len() {
                return Ok(0);
            }
            let slice = &bytes[start..];
            let n = slice.len().min(buf.len());
            buf[..n].copy_from_slice(&slice[..n]);
            Ok(n)
        })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let r = match &self.kind {
            FileKind::Core(f) => store_core(&self.cg, *f, buf),
            FileKind::Ctrl(ctrl, file) => {
                let st = snapshot_ctrl_state(&self.cg, ctrl);
                match st {
                    Some(s) => s.write(file, buf).map(|()| buf.len()),
                    None => Err(FsError::NotFound),
                }
            }
            FileKind::CpuStatBase => Err(FsError::ReadOnly),
        };
        Box::pin(async move { r })
    }

    fn stat(&self) -> Stat {
        let perms = self.cg.file_modes.lock().get(&self.ino).copied();
        let perms = perms.unwrap_or_else(|| match &self.kind {
            // Linux exposes these command files as write-only.
            FileKind::Core(CoreFile::Kill) | FileKind::Ctrl(_, "memory.reclaim") => 0o200,
            _ if self.is_writable() => 0o644,
            _ => 0o444,
        });
        Stat {
            // cgroupfs is kernfs-backed on Linux; virtual attribute files
            // report st_size == 0 regardless of their current rendered text.
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::File,
                perms,
            },
            mtime_cycles: 0,
        }
    }

    /// `cgroup.events` is the one cgroupfs file with edge-poll
    /// semantics: it is always readable (POLLIN — like any regular
    /// file) and additionally reports POLLPRI while a reported field
    /// (`populated` / `frozen`) has changed since this fd last read it.
    /// systemd waits on POLLPRI here to learn a cgroup emptied. Every
    /// other cgroupfs file uses the always-ready default.
    fn poll_readiness(&self) -> u32 {
        if !self.is_events() {
            return POLL_IN | crate::POLL_OUT;
        }
        let live = self.cg.events_gen.load(Ordering::Acquire);
        let seen = self.seen_gen.load(Ordering::Acquire);
        if live != seen {
            POLL_IN | POLL_PRI
        } else {
            POLL_IN
        }
    }
}

// ── Directory view ──────────────────────────────────────────────────

/// A directory view onto a cgroup: its control files plus child cgroups.
#[derive(Debug)]
pub struct CgroupDir {
    cg: Arc<Cgroup>,
}

impl CgroupDir {
    fn child(&self, name: &str) -> Option<Arc<Cgroup>> {
        self.cg.children.lock().get(name).cloned()
    }

    /// Active controller file on this cgroup as `(controller, file)`.
    fn ctrl_file(&self, name: &str) -> Option<(&'static str, &'static str)> {
        let states = snapshot_ctrl_states(&self.cg);
        for (cname, state) in &states {
            if let Some(f) = state
                .files()
                .iter()
                .copied()
                .find(|f| *f == name && controller_file_visible(&self.cg, f))
            {
                return Some((*cname, f));
            }
        }
        None
    }
}

/// Linux controller cftypes can be root-only, non-root-only, or present at
/// every level. `ControllerState::files()` describes the controller's stable
/// superset, while this kernfs-shaped filter selects the files visible at the
/// current hierarchy level.
fn controller_file_visible(cg: &Cgroup, file: &str) -> bool {
    if cg.is_root() {
        return matches!(
            file,
            // Base/statistical files which Linux publishes on the root.
            "cpu.stat"
                | "memory.stat"
                | "memory.numa_stat"
                | "memory.reclaim"
                | "memory.zswap.writeback"
                | "io.stat"
                | "cpuset.cpus.effective"
                | "cpuset.mems.effective"
                | "cpuset.cpus.subpartitions"
                | "cpuset.cpus.isolated"
                | "misc.current"
                | "misc.peak"
                | "misc.capacity"
        );
    }

    // These two cpuset diagnostics are root-only in Linux. Every other file
    // in a state belongs to a non-root cgroup.
    !matches!(
        file,
        "cpuset.cpus.subpartitions" | "cpuset.cpus.isolated" | "misc.capacity"
    )
}

/// Reject cgroup directory names that would break the tree or collide
/// with a control-file name.
fn valid_cgroup_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && CoreFile::from_name(name).is_none()
        && !name.starts_with("cgroup.")
}

impl DirOps for CgroupDir {
    // Directory ownership. The DirOps default silently DISCARDS the chown
    // (`set_dir_owners` is an empty body returning Ok), so a delegated
    // subtree reported root-owned however many times it was chowned.
    fn dir_owners(&self) -> (u32, u32) {
        *self.cg.owner.lock()
    }

    fn set_dir_owners(&self, uid: u32, gid: u32) {
        *self.cg.owner.lock() = (uid, gid);
    }

    // Directory chmod. `cg_set_access()` adjusts the delegated cgroup
    // DIRECTORY with the same `fchmod_and_chown()` helper it uses on the
    // attribute files, so the directory needs a real mode too — the
    // `dir_mode` default is a fixed constant and `set_dir_mode_async`
    // would otherwise discard the change.
    fn dir_mode(&self) -> u16 {
        *self.cg.mode.lock()
    }

    fn set_dir_mode_async<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        *self.cg.mode.lock() = perms & 0o7777;
        Box::pin(async { Ok(()) })
    }

    fn ino(&self) -> u64 {
        self.cg.ino
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        if let Some(f) = CoreFile::from_name(name) {
            if core_files_for(&self.cg).contains(&f) {
                return Some(CgroupAttrFile::open(self.cg.clone(), FileKind::Core(f)));
            }
            return None;
        }
        // PSI pressure files are present in every cgroup — root
        // included (Linux mirrors /proc/pressure there) — independent
        // of subtree_control.
        #[cfg(feature = "cgroup-psi")]
        if let Some(f) = psi::pressure_file(name, &self.cg) {
            return Some(f);
        }
        if let Some((ctrl, file)) = self.ctrl_file(name) {
            return Some(CgroupAttrFile::open(
                self.cg.clone(),
                FileKind::Ctrl(ctrl, file),
            ));
        }
        // Base cpu.stat: present everywhere the cpu controller isn't
        // (when it is, `ctrl_file` above already matched its richer
        // rendering).
        if name == "cpu.stat" {
            return Some(CgroupAttrFile::open(self.cg.clone(), FileKind::CpuStatBase));
        }
        None
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let child = self.child(name)?;
        Some(Arc::new(CgroupDir { cg: child }))
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Names live in non-static storage; `enumerate` is the real
        // readdir surface (see DirOps docs).
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let mut out: Vec<(String, FileType)> = Vec::new();
        for f in core_files_for(&self.cg) {
            out.push((f.file_name().to_string(), FileType::File));
        }
        let states = snapshot_ctrl_states(&self.cg);
        for (_, state) in &states {
            for f in state.files() {
                if controller_file_visible(&self.cg, f) {
                    out.push((f.to_string(), FileType::File));
                }
            }
        }
        // Base cpu.stat when the cpu controller isn't active here.
        if !states.iter().any(|(name, _)| *name == "cpu") {
            out.push(("cpu.stat".to_string(), FileType::File));
        }
        #[cfg(feature = "cgroup-psi")]
        for f in psi::file_names() {
            out.push((f.to_string(), FileType::File));
        }
        for name in self.cg.children.lock().keys() {
            out.push((name.clone(), FileType::Dir));
        }
        out.into_iter().skip(cursor).take(max).collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        let entries = self.enumerate(cursor, max);
        Box::pin(async move { Ok(entries) })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            if !valid_cgroup_name(name) {
                return Err(FsError::InvalidPath);
            }
            // kernfs semantics: a directory can't shadow an existing
            // interface file (base cpu.stat, psi, controller files).
            if self.lookup(name).is_some() {
                return Err(FsError::Busy);
            }
            // Enforce cgroup.max.depth / cgroup.max.descendants up the
            // ancestor chain.
            check_limits_for_new_child(&self.cg)?;
            let mut children = self.cg.children.lock();
            if children.contains_key(name) {
                return Err(FsError::Busy);
            }
            let child = Cgroup::new_child(name.to_string(), self.cg.clone());
            children.insert(name.to_string(), child.clone());
            Ok(Arc::new(CgroupDir { cg: child }) as Arc<dyn DirOps>)
        })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let child = self.child(name).ok_or(FsError::NotFound)?;
            // v2: removable only when it has no child cgroups and no
            // member processes/threads.
            if !child.children.lock().is_empty()
                || !child.members.lock().is_empty()
                || !child.threads.lock().is_empty()
            {
                return Err(FsError::Busy);
            }
            self.cg.children.lock().remove(name);
            Ok(())
        })
    }
}

/// Reject `mkdir` that would exceed an ancestor's `cgroup.max.depth` or
/// `cgroup.max.descendants`.
fn check_limits_for_new_child(parent: &Arc<Cgroup>) -> Result<(), FsError> {
    let new_depth = parent.depth + 1;
    let mut cur = Some(parent.clone());
    while let Some(c) = cur {
        if let Some(maxd) = *c.max_depth.lock() {
            if new_depth - c.depth > maxd {
                return Err(FsError::NoSpace);
            }
        }
        if let Some(maxn) = *c.max_descendants.lock() {
            if c.nr_descendants() + 1 > maxn {
                return Err(FsError::NoSpace);
            }
        }
        cur = c.parent.clone();
    }
    Ok(())
}

// ── FsInstance ──────────────────────────────────────────────────────

/// The cgroup-v2 filesystem. Mount at `/sys/fs/cgroup`.
#[derive(Debug)]
pub struct CgroupFs;

impl CgroupFs {
    pub fn new() -> Self {
        CgroupFs
    }
}

impl Default for CgroupFs {
    fn default() -> Self {
        CgroupFs::new()
    }
}

impl crate::FsInstance for CgroupFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(CgroupDir { cg: root() })
    }

    fn name(&self) -> &str {
        "cgroup2"
    }
}
