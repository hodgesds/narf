//! `CgroupFs` — Linux cgroup-v2 unified hierarchy, mounted at
//! `/sys/fs/cgroup`.
//!
//! This is the *organizational* substrate an init system needs to
//! reach PID 1: a tree of cgroups, each tracking which processes
//! belong to it, exposed through the standard v2 control-file
//! interface. It deliberately advertises an **empty controller set**
//! — `cgroup.controllers` is blank — so there is no resource
//! accounting or enforcement here. systemd boots fine against a
//! controller-less hierarchy: it uses the tree purely to track and
//! supervise units. Resource controllers (cpu / memory / io / pids)
//! land later as additive sub-features that fill `cgroup.controllers`
//! and add their own per-cgroup files.
//!
//! Linux references (GPL, citable post-relicense):
//!   `kernel/cgroup/cgroup.c`              — core hierarchy + control files
//!   `Documentation/admin-guide/cgroup-v2.rst` — the v2 interface contract
//!
//! # Layout
//!
//! ```text
//! /sys/fs/cgroup/                 ← root cgroup
//!   cgroup.controllers            ← "" (no controllers in base feature)
//!   cgroup.subtree_control        ← rw; "+x" for unavailable x → EINVAL
//!   cgroup.procs                  ← rw; read = member pids, write = move a pid in
//!   cgroup.threads                ← rw; thread-granularity membership (stub: mirrors procs)
//!   cgroup.stat                   ← "nr_descendants N\nnr_dying_descendants 0\n"
//!   cgroup.max.depth              ← rw; "max\n"
//!   cgroup.max.descendants        ← rw; "max\n"
//!   <child>/                      ← created by userspace `mkdir`
//!     cgroup.type                 ← "domain\n"
//!     cgroup.events               ← "populated N\nfrozen 0\n"
//!     cgroup.freeze               ← rw; "0\n" (no-op in base feature)
//!     ...same control files as root...
//! ```
//!
//! # Authority model
//!
//! The cgroup tree is global kernel state. `CGROUP_ROOT` holds the
//! root; every `CgroupDir` / `CgroupAttrFile` is just a *view* onto an
//! `Arc<Cgroup>` in that tree, so `mkdir` mutating the tree is
//! immediately visible to a later `lookup_dir`. Process membership is
//! keyed by **pid** (a process lives in exactly one cgroup in v2);
//! the `TASK_CGROUP` reverse index lets fork-inheritance and
//! exit-cleanup find a process's cgroup in O(log n) without walking
//! the tree.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::{IrqSafeSpinLock, OnceLock};

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};

// ── The cgroup node ─────────────────────────────────────────────────

/// One node in the cgroup-v2 hierarchy. The root has an empty `name`
/// and no parent; children are created by userspace `mkdir`.
///
/// All mutable state is behind per-field locks so concurrent
/// `cgroup.procs` writes from different CPUs don't tear the membership
/// set. `members` holds **pids** (process ids), matching what
/// `cgroup.procs` exposes.
pub struct Cgroup {
    /// Directory name of this cgroup (`""` for the root).
    name: String,
    /// Parent cgroup. `None` only for the root. Held as a strong
    /// `Arc` — the tree is rooted in `CGROUP_ROOT` and never forms a
    /// cycle (children point up, the root holds children down via
    /// `children`, so this is a DAG kept alive from the root).
    parent: Option<Arc<Cgroup>>,
    /// Child cgroups by name.
    children: IrqSafeSpinLock<BTreeMap<String, Arc<Cgroup>>>,
    /// Pids of processes that are members of *this* cgroup (not
    /// descendants). v2: a process is a member of exactly one cgroup.
    members: IrqSafeSpinLock<BTreeSet<u64>>,
    /// `cgroup.subtree_control` contents — controllers enabled for
    /// children. Empty in the base feature (no controllers exist).
    subtree_control: IrqSafeSpinLock<String>,
}

impl core::fmt::Debug for Cgroup {
    // Name + root flag only — never touch the locks from Debug.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cgroup")
            .field("name", &self.name)
            .field("is_root", &self.is_root())
            .finish_non_exhaustive()
    }
}

impl Cgroup {
    fn new_root() -> Arc<Self> {
        Arc::new(Cgroup {
            name: String::new(),
            parent: None,
            children: IrqSafeSpinLock::new(BTreeMap::new()),
            members: IrqSafeSpinLock::new(BTreeSet::new()),
            subtree_control: IrqSafeSpinLock::new(String::new()),
        })
    }

    fn new_child(name: String, parent: Arc<Cgroup>) -> Arc<Self> {
        Arc::new(Cgroup {
            name,
            parent: Some(parent),
            children: IrqSafeSpinLock::new(BTreeMap::new()),
            members: IrqSafeSpinLock::new(BTreeSet::new()),
            subtree_control: IrqSafeSpinLock::new(String::new()),
        })
    }

    #[inline]
    fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    /// `true` if this cgroup or any descendant has at least one member
    /// process. Drives `cgroup.events`'s `populated` field — the
    /// signal systemd watches to know a unit's cgroup has emptied.
    fn populated(&self) -> bool {
        if !self.members.lock().is_empty() {
            return true;
        }
        self.children.lock().values().any(|c| c.populated())
    }

    /// Total number of descendant cgroups (not counting self).
    fn nr_descendants(&self) -> u64 {
        let children = self.children.lock();
        let mut n = children.len() as u64;
        for c in children.values() {
            n += c.nr_descendants();
        }
        n
    }
}

// ── Global tree + reverse index ─────────────────────────────────────

static CGROUP_ROOT: OnceLock<Arc<Cgroup>> = OnceLock::new();

/// pid → its cgroup. A process appears here once it is placed into a
/// cgroup (at boot for the init process, via `cgroup.procs` writes, or
/// via fork-inheritance). Absent ⇒ implicitly the root cgroup.
static TASK_CGROUP: IrqSafeSpinLock<BTreeMap<u64, Arc<Cgroup>>> =
    IrqSafeSpinLock::new(BTreeMap::new());

fn root() -> Arc<Cgroup> {
    CGROUP_ROOT.get_or_init(Cgroup::new_root).clone()
}

/// Resolve the cgroup a pid currently belongs to (root if unplaced).
fn cgroup_of(pid: u64) -> Arc<Cgroup> {
    TASK_CGROUP.lock().get(&pid).cloned().unwrap_or_else(root)
}

/// Move `pid` into `dst`, removing it from whatever cgroup it was in.
/// This is the one membership-mutation primitive; `cgroup.procs`
/// writes, fork-inheritance, and boot-time placement all route here.
fn place(pid: u64, dst: &Arc<Cgroup>) {
    let mut idx = TASK_CGROUP.lock();
    if let Some(prev) = idx.get(&pid) {
        if Arc::ptr_eq(prev, dst) {
            return;
        }
        prev.members.lock().remove(&pid);
    }
    dst.members.lock().insert(pid);
    idx.insert(pid, dst.clone());
}

// ── Lifecycle hooks called by the userspace crate ───────────────────

/// Place the init process (and any boot-time process) into the root
/// cgroup. Idempotent.
pub fn attach_to_root(pid: u64) {
    let r = root();
    place(pid, &r);
}

/// Fork/clone inheritance: a child process joins its parent's cgroup.
/// Mirrors how the mount/PID namespaces are inherited at the spawn
/// site. No-op bookkeeping for threads is handled by the caller (only
/// process-leader pids are placed).
pub fn fork_inherit(parent_pid: u64, child_pid: u64) {
    let dst = cgroup_of(parent_pid);
    place(child_pid, &dst);
}

/// A process has exited: drop its membership. Called from the exit
/// observer with the process's pid. Removing the entry lets the
/// `populated` state of its (former) cgroup chain fall to 0 once the
/// last member leaves — the edge systemd's empty-cgroup notification
/// keys on.
pub fn task_exited(pid: u64) {
    let mut idx = TASK_CGROUP.lock();
    if let Some(cg) = idx.remove(&pid) {
        cg.members.lock().remove(&pid);
    }
}

/// `/proc/[pid]/cgroup` content for a process: the v2 single-line
/// form `0::<path>\n`. Path is `/` for the root, else the
/// slash-joined cgroup names.
pub fn proc_pid_cgroup(pid: u64) -> Vec<u8> {
    let cg = cgroup_of(pid);
    let path = cgroup_path(&cg);
    format!("0::{path}\n").into_bytes()
}

/// `/proc/cgroups` content. v2 has no per-controller hierarchies, so
/// with an empty controller set this is just the header line — same
/// shape Linux emits when no controllers are compiled in.
pub fn proc_cgroups() -> Vec<u8> {
    b"#subsys_name\thierarchy\tnum_cgroups\tenabled\n".to_vec()
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

// ── Attribute files ─────────────────────────────────────────────────

/// Which control file a `CgroupAttrFile` represents. Dispatch in
/// `read`/`write` keys off this rather than a closure map — the v2
/// file set is fixed and small.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Attr {
    Controllers,
    SubtreeControl,
    Procs,
    Threads,
    Events,
    Type,
    Stat,
    Freeze,
    MaxDepth,
    MaxDescendants,
}

impl Attr {
    fn file_name(self) -> &'static str {
        match self {
            Attr::Controllers => "cgroup.controllers",
            Attr::SubtreeControl => "cgroup.subtree_control",
            Attr::Procs => "cgroup.procs",
            Attr::Threads => "cgroup.threads",
            Attr::Events => "cgroup.events",
            Attr::Type => "cgroup.type",
            Attr::Stat => "cgroup.stat",
            Attr::Freeze => "cgroup.freeze",
            Attr::MaxDepth => "cgroup.max.depth",
            Attr::MaxDescendants => "cgroup.max.descendants",
        }
    }

    fn from_name(name: &str) -> Option<Attr> {
        Some(match name {
            "cgroup.controllers" => Attr::Controllers,
            "cgroup.subtree_control" => Attr::SubtreeControl,
            "cgroup.procs" => Attr::Procs,
            "cgroup.threads" => Attr::Threads,
            "cgroup.events" => Attr::Events,
            "cgroup.type" => Attr::Type,
            "cgroup.stat" => Attr::Stat,
            "cgroup.freeze" => Attr::Freeze,
            "cgroup.max.depth" => Attr::MaxDepth,
            "cgroup.max.descendants" => Attr::MaxDescendants,
            _ => return None,
        })
    }

    fn writable(self) -> bool {
        matches!(
            self,
            Attr::SubtreeControl
                | Attr::Procs
                | Attr::Threads
                | Attr::Freeze
                | Attr::MaxDepth
                | Attr::MaxDescendants
        )
    }
}

/// The set of control files present in a cgroup. The root omits
/// `cgroup.type`, `cgroup.events`, and `cgroup.freeze` (v2: those are
/// non-root only).
fn attrs_for(cg: &Cgroup) -> &'static [Attr] {
    if cg.is_root() {
        &[
            Attr::Controllers,
            Attr::SubtreeControl,
            Attr::Procs,
            Attr::Threads,
            Attr::Stat,
            Attr::MaxDepth,
            Attr::MaxDescendants,
        ]
    } else {
        &[
            Attr::Type,
            Attr::Controllers,
            Attr::SubtreeControl,
            Attr::Procs,
            Attr::Threads,
            Attr::Events,
            Attr::Freeze,
            Attr::Stat,
            Attr::MaxDepth,
            Attr::MaxDescendants,
        ]
    }
}

/// Compute the current textual content of a control file.
fn render(cg: &Arc<Cgroup>, attr: Attr) -> String {
    match attr {
        // No controllers available in the base feature.
        Attr::Controllers => String::new(),
        Attr::SubtreeControl => cg.subtree_control.lock().clone(),
        Attr::Procs | Attr::Threads => {
            let mut s = String::new();
            for pid in cg.members.lock().iter() {
                s.push_str(&pid.to_string());
                s.push('\n');
            }
            s
        }
        Attr::Events => {
            let populated = if cg.populated() { 1 } else { 0 };
            format!("populated {populated}\nfrozen 0\n")
        }
        Attr::Type => "domain\n".to_string(),
        Attr::Stat => {
            format!("nr_descendants {}\nnr_dying_descendants 0\n", cg.nr_descendants())
        }
        Attr::Freeze => "0\n".to_string(),
        Attr::MaxDepth | Attr::MaxDescendants => "max\n".to_string(),
    }
}

/// Apply a write to a control file. Returns the number of bytes
/// consumed (always the whole write on success — v2 control files are
/// replace-on-write, not positional).
fn store(cg: &Arc<Cgroup>, attr: Attr, buf: &[u8]) -> Result<usize, FsError> {
    let text = core::str::from_utf8(buf).map_err(|_| FsError::InvalidData)?;
    match attr {
        Attr::Procs | Attr::Threads => {
            // Move the named pid into this cgroup. v2 accepts one pid
            // per write.
            let pid: u64 = text.trim().parse().map_err(|_| FsError::InvalidData)?;
            place(pid, cg);
            Ok(buf.len())
        }
        Attr::SubtreeControl => {
            // "+ctrl"/"-ctrl" tokens. No controllers are available, so
            // any "+x" is EINVAL (matches Linux rejecting a controller
            // not in cgroup.controllers); "-x" and empty are no-ops.
            for tok in text.split_whitespace() {
                let (sign, name) = tok.split_at(1.min(tok.len()));
                match sign {
                    "+" => {
                        let _ = name;
                        return Err(FsError::InvalidData);
                    }
                    "-" => { /* disabling an absent controller: no-op */ }
                    _ => return Err(FsError::InvalidData),
                }
            }
            Ok(buf.len())
        }
        // Accepted but not enforced in the base feature.
        Attr::Freeze | Attr::MaxDepth | Attr::MaxDescendants => Ok(buf.len()),
        // Read-only files.
        Attr::Controllers | Attr::Events | Attr::Type | Attr::Stat => Err(FsError::ReadOnly),
    }
}

/// A single cgroup control file, e.g. `<cg>/cgroup.procs`.
struct CgroupAttrFile {
    cg: Arc<Cgroup>,
    attr: Attr,
}

impl FileOps for CgroupAttrFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let content = render(&self.cg, self.attr);
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
        let r = store(&self.cg, self.attr, buf);
        Box::pin(async move { r })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: render(&self.cg, self.attr).len() as u64,
            blocks: 0,
            mode: if self.attr.writable() {
                Mode::FILE_RW
            } else {
                Mode::FILE_RO
            },
            mtime_cycles: 0,
        }
    }
}

// ── Directory view ──────────────────────────────────────────────────

/// A directory view onto a cgroup: its control files plus its child
/// cgroups.
#[derive(Debug)]
pub struct CgroupDir {
    cg: Arc<Cgroup>,
}

impl CgroupDir {
    fn child(&self, name: &str) -> Option<Arc<Cgroup>> {
        self.cg.children.lock().get(name).cloned()
    }
}

/// Reject cgroup directory names that would break the tree or the
/// flat control-file namespace.
fn valid_cgroup_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && Attr::from_name(name).is_none()
}

impl DirOps for CgroupDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let attr = Attr::from_name(name)?;
        if !attrs_for(&self.cg).contains(&attr) {
            return None;
        }
        Some(Arc::new(CgroupAttrFile {
            cg: self.cg.clone(),
            attr,
        }))
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let child = self.child(name)?;
        Some(Arc::new(CgroupDir { cg: child }))
    }

    fn iter<'a>(&'a self) -> alloc::boxed::Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Names live in non-static storage; `enumerate` is the real
        // readdir surface (see DirOps docs). `iter` returns empty.
        alloc::boxed::Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let mut out: Vec<(String, FileType)> = Vec::new();
        for attr in attrs_for(&self.cg) {
            out.push((attr.file_name().to_string(), FileType::File));
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
            // v2: a cgroup can only be removed when it has no child
            // cgroups and no member processes.
            if !child.children.lock().is_empty() || !child.members.lock().is_empty() {
                return Err(FsError::Busy);
            }
            self.cg.children.lock().remove(name);
            Ok(())
        })
    }
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
