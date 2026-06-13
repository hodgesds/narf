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

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;

use narf_lib::sync::{IrqSafeSpinLock, OnceLock};

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};

pub use controller::{register_controller, Controller, ControllerState};

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

/// One node in the cgroup-v2 hierarchy. The root has an empty `name`
/// and no parent; children are created by userspace `mkdir`.
pub struct Cgroup {
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
    /// Wakers parked on `cgroup.events` (poll), woken on a
    /// populated/frozen transition.
    events_waiters: IrqSafeSpinLock<Vec<Waker>>,
    /// Last-published `populated` bit, to detect transitions for wakeups.
    last_populated: AtomicBool,
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
            events_waiters: IrqSafeSpinLock::new(Vec::new()),
            last_populated: AtomicBool::new(false),
        })
    }

    fn new_child(name: String, parent: Arc<Cgroup>) -> Arc<Self> {
        let depth = parent.depth + 1;
        // The child's active controllers = the parent's enabled set.
        // Build each child state, linking to the parent cgroup's state
        // for the same controller (for value inheritance) when present.
        let mut state = BTreeMap::new();
        {
            let enabled = parent.enabled.lock();
            let parent_state = parent.ctrl_state.lock();
            for &cname in enabled.iter() {
                if let Some(ctrl) = controller::find(cname) {
                    let parent_cs = parent_state.get(cname).cloned();
                    state.insert(cname, ctrl.new_state(parent_cs));
                }
            }
        }
        Arc::new(Cgroup {
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
            events_waiters: IrqSafeSpinLock::new(Vec::new()),
            last_populated: AtomicBool::new(false),
        })
    }

    #[inline]
    fn is_root(&self) -> bool {
        self.parent.is_none()
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

    /// Re-publish `populated` and wake `cgroup.events` pollers if it
    /// transitioned, then walk up so an ancestor watching `events` also
    /// wakes when a descendant empties.
    fn notify_events(&self) {
        let now = self.populated();
        let was = self.last_populated.swap(now, Ordering::AcqRel);
        if now != was {
            let mut w = self.events_waiters.lock();
            for waker in w.drain(..) {
                waker.wake();
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

fn root() -> Arc<Cgroup> {
    CGROUP_ROOT.get_or_init(Cgroup::new_root).clone()
}

/// Resolve the cgroup a pid currently belongs to (root if unplaced).
fn cgroup_of(pid: u64) -> Arc<Cgroup> {
    TASK_CGROUP.lock().get(&pid).cloned().unwrap_or_else(root)
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
        for state in node.ctrl_state.lock().values() {
            state.on_detach(pid);
        }
    }
}

/// Two-phase attach over `cg`'s chain: pre-check every `can_attach`
/// (charging nothing), then commit with `on_attach`.
fn attach_chain(cg: &Arc<Cgroup>, pid: u64) -> Result<(), FsError> {
    let chain = charge_chain(cg);
    for node in &chain {
        for state in node.ctrl_state.lock().values() {
            state.can_attach(pid)?;
        }
    }
    for node in &chain {
        for state in node.ctrl_state.lock().values() {
            state.on_attach(pid);
        }
    }
    Ok(())
}

/// Move `pid` into `dst`, honouring controller vetoes (`can_attach`);
/// on rejection the process stays put. The `cgroup.procs`-write path.
fn place(pid: u64, dst: &Arc<Cgroup>) -> Result<(), FsError> {
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
    TASK_CGROUP.lock().insert(pid, dst.clone());
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
        for state in node.ctrl_state.lock().values() {
            state.on_attach(pid);
        }
    }
    dst.members.lock().insert(pid);
    TASK_CGROUP.lock().insert(pid, dst.clone());
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

/// A process exited: drop its membership and uncharge controllers.
pub fn task_exited(pid: u64) {
    let cg = TASK_CGROUP.lock().remove(&pid);
    if let Some(cg) = cg {
        detach_chain(&cg, pid);
        cg.members.lock().remove(&pid);
        cg.notify_events();
    }
}

/// `/proc/[pid]/cgroup` content: the v2 single-line form `0::<path>\n`.
pub fn proc_pid_cgroup(pid: u64) -> Vec<u8> {
    let cg = cgroup_of(pid);
    let path = cgroup_path(&cg);
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
    let mut parts: Vec<String> = Vec::new();
    let mut cur = cg.clone();
    while let Some(p) = cur.parent.clone() {
        parts.push(cur.name.clone());
        cur = p;
    }
    if parts.is_empty() {
        return "/".to_string();
    }
    parts.reverse();
    let mut s = String::new();
    for part in parts {
        s.push('/');
        s.push_str(&part);
    }
    s
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
    Freeze,
    Kill,
    MaxDepth,
    MaxDescendants,
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
            CoreFile::Freeze => "cgroup.freeze",
            CoreFile::Kill => "cgroup.kill",
            CoreFile::MaxDepth => "cgroup.max.depth",
            CoreFile::MaxDescendants => "cgroup.max.descendants",
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
            "cgroup.freeze" => CoreFile::Freeze,
            "cgroup.kill" => CoreFile::Kill,
            "cgroup.max.depth" => CoreFile::MaxDepth,
            "cgroup.max.descendants" => CoreFile::MaxDescendants,
            _ => return None,
        })
    }

    fn writable(self) -> bool {
        matches!(
            self,
            CoreFile::SubtreeControl
                | CoreFile::Procs
                | CoreFile::Threads
                | CoreFile::Type
                | CoreFile::Freeze
                | CoreFile::Kill
                | CoreFile::MaxDepth
                | CoreFile::MaxDescendants
        )
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
            CoreFile::MaxDepth,
            CoreFile::MaxDescendants,
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
        t.parse::<u64>().map(Some).map_err(|_| FsError::InvalidData)
    }
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
            for pid in cg.members.lock().iter() {
                s.push_str(&pid.to_string());
                s.push('\n');
            }
            s
        }
        CoreFile::Threads => {
            let mut s = String::new();
            // Threaded cgroups track tids; otherwise mirror procs.
            let t = cg.threads.lock();
            if t.is_empty() {
                for pid in cg.members.lock().iter() {
                    s.push_str(&pid.to_string());
                    s.push('\n');
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
            let populated = u8::from(cg.populated());
            let frozen = u8::from(cg.frozen.load(Ordering::Acquire));
            format!("populated {populated}\nfrozen {frozen}\n")
        }
        CoreFile::Type => cg.cg_type.lock().as_str().to_string(),
        CoreFile::Stat => format!(
            "nr_descendants {}\nnr_dying_descendants 0\n",
            cg.nr_descendants()
        ),
        CoreFile::Freeze => {
            format!("{}\n", u8::from(cg.frozen.load(Ordering::Acquire)))
        }
        CoreFile::Kill => "0\n".to_string(),
        CoreFile::MaxDepth => max_str(&cg.max_depth.lock()),
        CoreFile::MaxDescendants => max_str(&cg.max_descendants.lock()),
    }
}

fn store_core(cg: &Arc<Cgroup>, f: CoreFile, buf: &[u8]) -> Result<usize, FsError> {
    let text = core::str::from_utf8(buf).map_err(|_| FsError::InvalidData)?;
    match f {
        CoreFile::Procs | CoreFile::Threads => {
            let pid: u64 = text.trim().parse().map_err(|_| FsError::InvalidData)?;
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
            if text.trim() == "1" {
                kill_subtree(cg);
                Ok(buf.len())
            } else {
                Err(FsError::InvalidData)
            }
        }
        CoreFile::Type => {
            // Only the domain→threaded transition is accepted.
            if text.trim() == "threaded" {
                *cg.cg_type.lock() = CgroupType::Threaded;
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
        CoreFile::Controllers | CoreFile::Events | CoreFile::Stat => Err(FsError::ReadOnly),
    }
}

/// Parse and apply a `cgroup.subtree_control` write: `+ctrl`/`-ctrl`
/// tokens. A controller can only be enabled if it is available to this
/// cgroup (in `cgroup.controllers`). Toggling propagates the controller
/// state onto/off existing children.
fn store_subtree_control(cg: &Arc<Cgroup>, text: &str) -> Result<(), FsError> {
    let available: BTreeSet<&'static str> = cg.available_controllers().into_iter().collect();
    // Validate the whole write first (atomic: reject without applying).
    let mut adds: Vec<&'static str> = Vec::new();
    let mut dels: Vec<&'static str> = Vec::new();
    for tok in text.split_whitespace() {
        let (sign, name) = tok.split_at(1.min(tok.len()));
        match sign {
            "+" => {
                let canon = available
                    .iter()
                    .copied()
                    .find(|c| *c == name)
                    .ok_or(FsError::InvalidData)?;
                adds.push(canon);
            }
            "-" => {
                // Disabling a controller that isn't available is a no-op
                // rather than an error; only act on known names.
                if let Some(canon) = available.iter().copied().find(|c| *c == name) {
                    dels.push(canon);
                }
            }
            _ => return Err(FsError::InvalidData),
        }
    }

    let mut enabled = cg.enabled.lock();
    let children = cg.children.lock();
    for name in adds {
        if enabled.insert(name) {
            if let Some(ctrl) = controller::find(name) {
                let parent_cs = cg.ctrl_state.lock().get(name).cloned();
                for child in children.values() {
                    child
                        .ctrl_state
                        .lock()
                        .entry(name)
                        .or_insert_with(|| ctrl.new_state(parent_cs.clone()));
                }
            }
        }
    }
    for name in dels {
        if enabled.remove(name) {
            for child in children.values() {
                child.ctrl_state.lock().remove(name);
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

/// `cgroup.freeze` — freeze or thaw every process in the subtree.
fn set_frozen(cg: &Arc<Cgroup>, freeze: bool) {
    cg.frozen.store(freeze, Ordering::Release);
    let hook = *FREEZE_HOOK.lock();
    if let Some(h) = hook {
        let mut pids = Vec::new();
        subtree_pids(cg, &mut pids);
        for pid in pids {
            h(pid, freeze);
        }
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
}

struct CgroupAttrFile {
    cg: Arc<Cgroup>,
    kind: FileKind,
}

impl CgroupAttrFile {
    fn content(&self) -> String {
        match &self.kind {
            FileKind::Core(f) => render_core(&self.cg, *f),
            FileKind::Ctrl(ctrl, file) => self
                .cg
                .ctrl_state
                .lock()
                .get(*ctrl)
                .map(|s| s.read(file))
                .unwrap_or_default(),
        }
    }

    fn is_writable(&self) -> bool {
        match &self.kind {
            FileKind::Core(f) => f.writable(),
            FileKind::Ctrl(ctrl, file) => self
                .cg
                .ctrl_state
                .lock()
                .get(*ctrl)
                .map(|s| s.writable(file))
                .unwrap_or(false),
        }
    }
}

impl FileOps for CgroupAttrFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
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
                let st = self.cg.ctrl_state.lock().get(*ctrl).cloned();
                match st {
                    Some(s) => s.write(file, buf).map(|()| buf.len()),
                    None => Err(FsError::NotFound),
                }
            }
        };
        Box::pin(async move { r })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.content().len() as u64,
            blocks: 0,
            mode: if self.is_writable() {
                Mode::FILE_RW
            } else {
                Mode::FILE_RO
            },
            mtime_cycles: 0,
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
        let states = self.cg.ctrl_state.lock();
        for (cname, state) in states.iter() {
            if let Some(f) = state.files().iter().copied().find(|f| *f == name) {
                return Some((cname, f));
            }
        }
        None
    }
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
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        if let Some(f) = CoreFile::from_name(name) {
            if core_files_for(&self.cg).contains(&f) {
                return Some(Arc::new(CgroupAttrFile {
                    cg: self.cg.clone(),
                    kind: FileKind::Core(f),
                }));
            }
            return None;
        }
        let (ctrl, file) = self.ctrl_file(name)?;
        Some(Arc::new(CgroupAttrFile {
            cg: self.cg.clone(),
            kind: FileKind::Ctrl(ctrl, file),
        }))
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
        for state in self.cg.ctrl_state.lock().values() {
            for f in state.files() {
                out.push((f.to_string(), FileType::File));
            }
        }
        for name in self.cg.children.lock().keys() {
            out.push((name.clone(), FileType::Dir));
        }
        out.into_iter().skip(cursor).take(max).collect()
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            if !valid_cgroup_name(name) {
                return Err(FsError::InvalidPath);
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
