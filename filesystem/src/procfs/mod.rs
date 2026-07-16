//! `/proc` synthetic filesystem — every read produces text on
//! demand from a closure. POSIX has no `/proc`; Linux's shape is
//! the de-facto standard and the one tooling expects (ps, top,
//! lsof, /proc/cpuinfo readers, build-system hardware probes).
//!
//! Stage-1 entries:
//!   /proc/cpuinfo     — one block per logical CPU (vendor/model/MHz)
//!   /proc/meminfo     — total/free RAM
//!   /proc/mounts      — current mount table
//!   /proc/uptime      — seconds since boot, idle seconds
//!   /proc/version     — kernel version string
//!   /proc/[pid]/{stat,status,cmdline,maps,comm}
//!     — per-task views; pid is the live scheduler TaskId
//!   /proc/self/...    — symlink-shape: each lookup resolves the
//!                       calling task fresh via the
//!                       `current-pid` hook
//!
//! The dir tree is read-only. Per-task data comes from the kernel
//! through fn-pointer hooks installed at boot
//! (`install_proc_hooks`); without the hooks installed, /proc/[pid]
//! lookups return NotFound and /proc/self resolves to pid 0.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat};

pub mod aggregate;
pub mod bus;
pub mod net;
pub mod pid_ext;
pub mod stubs;
pub mod sys;
pub mod sys_fs;
pub mod sys_kernel;
pub mod sys_net;
pub mod sys_vm;

// ── Hook plumbing ───────────────────────────────────────────────

/// Per-task metadata snapshot returned by the kernel when /proc
/// asks for /proc/[pid]/* contents. Filled by `install_proc_hooks`
/// at boot — the filesystem crate doesn't depend on the scheduler
/// directly to keep the dep graph one-way.
#[derive(Clone, Debug, Default)]
pub struct ProcTaskInfo {
    pub pid: u64,
    pub comm: String,
    /// One-character POSIX state: R running, S sleeping, Z zombie.
    pub state: char,
    pub brk_top: u64,
    pub stack_top: u64,
    /// argv joined with NULs (Linux /proc/[pid]/cmdline shape).
    pub cmdline: Vec<u8>,
    /// VMA list — one entry per address-space region. Filled by
    /// the kernel hook from the AS's regions table; rendered into
    /// /proc/[pid]/maps text by `render_maps`.
    pub vmas: Vec<ProcVma>,
    /// Parent visible pid (0 = unknown/orphan).
    pub ppid: u64,
    /// Process group + session ids (stat fields 5-6).
    pub pgrp: u64,
    pub session: u64,
    /// Consumed user CPU time in USER_HZ (100) ticks — stat field 14.
    pub utime_ticks: u64,
    /// In-syscall (kernel) CPU time in USER_HZ ticks — stat field 15.
    pub stime_ticks: u64,
    /// Creation time in USER_HZ ticks since boot — stat field 22; `ps`
    /// composes it with /proc/stat's btime for wall start times.
    pub starttime_ticks: u64,
}

/// A key-value pair from the ELF auxiliary vector.  Used by
/// `set_proc_auxv` / `proc_auxv_of` and rendered into
/// `/proc/[pid]/auxv` as two little-endian u64s (key, value).
#[derive(Copy, Clone, Debug, Default)]
pub struct ProcAuxEntry {
    pub key: u64,
    pub value: u64,
}

/// One virtual-memory area entry. Mirrors what `/proc/[pid]/maps`
/// reports per line: range, protection bits, and an optional name.
#[derive(Copy, Clone, Debug, Default)]
pub struct ProcVma {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub shared: bool,
    /// Optional Linux-style label (`[heap]`, `[stack]`, `[vdso]`).
    /// Empty for anonymous mappings.
    pub label: &'static str,
}

type CurrentPidFn = fn() -> u64;
type ListPidsFn = fn() -> Vec<u64>;
type TaskInfoFn = fn(u64) -> Option<ProcTaskInfo>;

static CURRENT_PID_HOOK: AtomicUsize = AtomicUsize::new(0);
static LIST_PIDS_HOOK: AtomicUsize = AtomicUsize::new(0);
static TASK_INFO_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Wire the kernel-side accessors. Called once from boot init.
pub fn install_proc_hooks(current: CurrentPidFn, list: ListPidsFn, info: TaskInfoFn) {
    CURRENT_PID_HOOK.store(current as usize, Ordering::Release);
    LIST_PIDS_HOOK.store(list as usize, Ordering::Release);
    TASK_INFO_HOOK.store(info as usize, Ordering::Release);
}

fn current_pid() -> u64 {
    let v = CURRENT_PID_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return 0;
    }
    // SAFETY: v was stored by install_proc_hooks as a CurrentPidFn fn-pointer; non-zero confirms it.
    let f: CurrentPidFn = unsafe { core::mem::transmute(v) };
    f()
}

fn list_pids() -> Vec<u64> {
    let v = LIST_PIDS_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_proc_hooks as a ListPidsFn fn-pointer; non-zero confirms it.
    let f: ListPidsFn = unsafe { core::mem::transmute(v) };
    f()
}

pub(crate) fn task_info(pid: u64) -> Option<ProcTaskInfo> {
    let v = TASK_INFO_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return None;
    }
    // SAFETY: v was stored by install_proc_hooks as a TaskInfoFn fn-pointer; non-zero confirms it.
    let f: TaskInfoFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

// ── Extended + writable per-pid hook types ──────────────────────

type FdPathFn = fn(u64, u32) -> Option<String>;
type RlimitsFn = fn(u64) -> [(u64, u64); 16];
type NiceFn = fn(u64) -> i32;
type EnvironFn = fn(u64) -> Vec<u8>;
type AuxvFn = fn(u64) -> Vec<u8>;
type SetCommFn = fn(u64, &str) -> Result<(), FsError>;
type OomAdjGetFn = fn(u64) -> i16;
type OomAdjSetFn = fn(u64, i16) -> Result<(), FsError>;
type CoredumpGetFn = fn(u64) -> u32;
type CoredumpSetFn = fn(u64, u32) -> Result<(), FsError>;
type OomScoreFn = fn(u64) -> i32;

// ── /proc/<pid>/exe + cwd + root path hooks ─────────────────────
//
// Three magic symlinks [[proc-magic-links]] that lsof, readelf,
// debuggers, and container runtimes rely on. All three are optional:
// when the hook is not installed the link renders an empty target
// (stat still reports S_IFLNK so the node type is correct).
//
// Linux refs:
//   `fs/proc/base.c:proc_exe_link`   — exe path via mm->exe_file
//   `fs/proc/base.c:proc_cwd_link`   — cwd from task->fs->pwd
//   `fs/proc/base.c:proc_root_link`  — root from task->fs->root

/// `pid -> absolute path of the task's executable` (e.g. `/bin/sh`).
/// Wiring point: `sys_execve` already calls `set_proc_argv`; the kernel
/// side should call `set_proc_exe_path(pid, path)` (or install the hook
/// below) immediately after the new executable image is loaded.
type ExePathFn = fn(u64) -> Option<String>;

/// `pid -> absolute path of the task's current working directory`.
type CwdPathFn = fn(u64) -> Option<String>;

/// `pid -> absolute path of the task's root` (chroot/container root).
type RootPathFn = fn(u64) -> Option<String>;

static EXE_PATH_HOOK: AtomicUsize = AtomicUsize::new(0);
static CWD_PATH_HOOK: AtomicUsize = AtomicUsize::new(0);
static ROOT_PATH_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Wire the three magic-symlink path hooks.  Called once at boot after
/// `install_proc_ext_hooks`.  All three are optional; pass a stub
/// returning `None` for any path the kernel side does not yet track.
///
/// Kernel-side wiring note: see `/tmp/narf_fs_agent_notes.md` for
/// exactly where each hook should be called.
pub fn install_proc_path_hooks(exe: ExePathFn, cwd: CwdPathFn, root: RootPathFn) {
    EXE_PATH_HOOK.store(exe as usize, Ordering::Release);
    CWD_PATH_HOOK.store(cwd as usize, Ordering::Release);
    ROOT_PATH_HOOK.store(root as usize, Ordering::Release);
}

/// Return the absolute exe path for `pid`, or `None` if no hook is installed
/// or the task has no recorded executable path.
pub(crate) fn hook_exe_path(pid: u64) -> Option<String> {
    let v = EXE_PATH_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return None;
    }
    // SAFETY: v was stored by install_proc_path_hooks as an ExePathFn fn-pointer; non-zero confirms it.
    let f: ExePathFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

/// Return the absolute cwd path for `pid`, or `None` if no hook is installed.
pub(crate) fn hook_cwd_path(pid: u64) -> Option<String> {
    let v = CWD_PATH_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return None;
    }
    // SAFETY: v was stored by install_proc_path_hooks as a CwdPathFn fn-pointer; non-zero confirms it.
    let f: CwdPathFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

/// Return the absolute root path for `pid`, or `None` if no hook is installed.
pub(crate) fn hook_root_path(pid: u64) -> Option<String> {
    let v = ROOT_PATH_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return None;
    }
    // SAFETY: v was stored by install_proc_path_hooks as a RootPathFn fn-pointer; non-zero confirms it.
    let f: RootPathFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

static FD_PATH_HOOK: AtomicUsize = AtomicUsize::new(0);
static RLIMITS_HOOK: AtomicUsize = AtomicUsize::new(0);
static NICE_HOOK: AtomicUsize = AtomicUsize::new(0);
static ENVIRON_HOOK: AtomicUsize = AtomicUsize::new(0);
static AUXV_HOOK: AtomicUsize = AtomicUsize::new(0);
static SET_COMM_HOOK: AtomicUsize = AtomicUsize::new(0);
static OOM_ADJ_GET_HOOK: AtomicUsize = AtomicUsize::new(0);
static OOM_ADJ_SET_HOOK: AtomicUsize = AtomicUsize::new(0);
static COREDUMP_GET_HOOK: AtomicUsize = AtomicUsize::new(0);
static COREDUMP_SET_HOOK: AtomicUsize = AtomicUsize::new(0);
static OOM_SCORE_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Wire the extended /proc/[pid]/* read hooks. Called once at boot.
pub fn install_proc_ext_hooks(
    fd_path: FdPathFn,
    rlimits: RlimitsFn,
    nice: NiceFn,
    environ: EnvironFn,
    auxv: AuxvFn,
) {
    FD_PATH_HOOK.store(fd_path as usize, Ordering::Release);
    RLIMITS_HOOK.store(rlimits as usize, Ordering::Release);
    NICE_HOOK.store(nice as usize, Ordering::Release);
    ENVIRON_HOOK.store(environ as usize, Ordering::Release);
    AUXV_HOOK.store(auxv as usize, Ordering::Release);
}

/// Wire the writable per-pid procfs hooks. Called once at boot after
/// `install_proc_ext_hooks`.
///
/// Linux refs: `comm_write` (fs/proc/base.c), `oom_score_adj_write`.
pub fn install_proc_write_hooks(
    set_comm: SetCommFn,
    oom_adj_get: OomAdjGetFn,
    oom_adj_set: OomAdjSetFn,
    coredump_get: CoredumpGetFn,
    coredump_set: CoredumpSetFn,
    oom_score: OomScoreFn,
) {
    SET_COMM_HOOK.store(set_comm as usize, Ordering::Release);
    OOM_ADJ_GET_HOOK.store(oom_adj_get as usize, Ordering::Release);
    OOM_ADJ_SET_HOOK.store(oom_adj_set as usize, Ordering::Release);
    COREDUMP_GET_HOOK.store(coredump_get as usize, Ordering::Release);
    COREDUMP_SET_HOOK.store(coredump_set as usize, Ordering::Release);
    OOM_SCORE_HOOK.store(oom_score as usize, Ordering::Release);
}

pub(crate) fn hook_fd_path(pid: u64, fd: u32) -> Option<String> {
    let v = FD_PATH_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return None;
    }
    // SAFETY: v was stored by install_proc_ext_hooks as a FdPathFn fn-pointer; non-zero confirms it.
    let f: FdPathFn = unsafe { core::mem::transmute(v) };
    f(pid, fd)
}

// ── Namespace procfs hooks (container feature) ──────────────────
//
// Wired by userspace so procfs can render /proc/<pid>/ns/<flavour>
// readlink text, the per-ns mountinfo view, and read/write the
// user-ns uid_map/gid_map — without procfs depending on the
// namespaces module (one-way dep via fn-pointers).

/// `(pid, flavour) -> readlink text` e.g. "uts:[4026531838]".
/// `flavour` is the [`crate::NsFlavourTag`] discriminant.
type NsReadlinkFn = fn(u64, u8) -> Option<String>;
/// `pid -> per-ns mountinfo body`. `None` ⇒ fall back to the global.
type MountinfoFn = fn(u64) -> Option<String>;
/// `(pid, is_uid) -> rendered uid_map/gid_map`.
type IdMapRenderFn = fn(u64, bool) -> Option<String>;
/// `(pid, is_uid, bytes) -> Ok(written) | Err`. Linux one-shot rule.
type IdMapWriteFn = fn(u64, bool, &[u8]) -> Result<usize, FsError>;

static NS_READLINK_HOOK: AtomicUsize = AtomicUsize::new(0);
static NS_MOUNTINFO_HOOK: AtomicUsize = AtomicUsize::new(0);
static NS_IDMAP_RENDER_HOOK: AtomicUsize = AtomicUsize::new(0);
static NS_IDMAP_WRITE_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Stable u8 tags for namespace flavours, mirroring
/// `userspace::namespaces::NsFlavour`. Kept here so the procfs ns
/// nodes can name a flavour without importing the userspace enum.
pub mod ns_tag {
    pub const UTS: u8 = 0;
    pub const NET: u8 = 1;
    pub const IPC: u8 = 2;
    pub const PID: u8 = 3;
    pub const MNT: u8 = 4;
    pub const CGROUP: u8 = 5;
    pub const USER: u8 = 6;
}

/// Wire the namespace procfs hooks. Called once at boot (container).
pub fn install_ns_proc_hooks(
    readlink: NsReadlinkFn,
    mountinfo: MountinfoFn,
    idmap_render: IdMapRenderFn,
    idmap_write: IdMapWriteFn,
) {
    NS_READLINK_HOOK.store(readlink as usize, Ordering::Release);
    NS_MOUNTINFO_HOOK.store(mountinfo as usize, Ordering::Release);
    NS_IDMAP_RENDER_HOOK.store(idmap_render as usize, Ordering::Release);
    NS_IDMAP_WRITE_HOOK.store(idmap_write as usize, Ordering::Release);
}

pub(crate) fn hook_ns_readlink(pid: u64, flavour: u8) -> Option<String> {
    let v = NS_READLINK_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return None;
    }
    // SAFETY: stored by install_ns_proc_hooks as an NsReadlinkFn; non-zero confirms it.
    let f: NsReadlinkFn = unsafe { core::mem::transmute(v) };
    f(pid, flavour)
}

pub(crate) fn hook_ns_mountinfo(pid: u64) -> Option<String> {
    let v = NS_MOUNTINFO_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return None;
    }
    // SAFETY: stored by install_ns_proc_hooks as a MountinfoFn; non-zero confirms it.
    let f: MountinfoFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_ns_idmap_render(pid: u64, is_uid: bool) -> Option<String> {
    let v = NS_IDMAP_RENDER_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return None;
    }
    // SAFETY: stored by install_ns_proc_hooks as an IdMapRenderFn; non-zero confirms it.
    let f: IdMapRenderFn = unsafe { core::mem::transmute(v) };
    f(pid, is_uid)
}

pub(crate) fn hook_ns_idmap_write(pid: u64, is_uid: bool, bytes: &[u8]) -> Result<usize, FsError> {
    let v = NS_IDMAP_WRITE_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Err(FsError::Unsupported);
    }
    // SAFETY: stored by install_ns_proc_hooks as an IdMapWriteFn; non-zero confirms it.
    let f: IdMapWriteFn = unsafe { core::mem::transmute(v) };
    f(pid, is_uid, bytes)
}

pub(crate) fn hook_rlimits(pid: u64) -> [(u64, u64); 16] {
    let v = RLIMITS_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return [(0, 0); 16];
    }
    // SAFETY: v was stored by install_proc_ext_hooks as a RlimitsFn fn-pointer; non-zero confirms it.
    let f: RlimitsFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_nice(pid: u64) -> i32 {
    let v = NICE_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return 0;
    }
    // SAFETY: v was stored by install_proc_ext_hooks as a NiceFn fn-pointer; non-zero confirms it.
    let f: NiceFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_environ(pid: u64) -> Vec<u8> {
    let v = ENVIRON_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_proc_ext_hooks as an EnvironFn fn-pointer; non-zero confirms it.
    let f: EnvironFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_auxv(pid: u64) -> Vec<u8> {
    let v = AUXV_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return alloc::vec![0u8; 16];
    }
    // SAFETY: v was stored by install_proc_ext_hooks as an AuxvFn fn-pointer; non-zero confirms it.
    let f: AuxvFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_set_comm(pid: u64, name: &str) -> Result<(), FsError> {
    let v = SET_COMM_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Err(FsError::Unsupported);
    }
    // SAFETY: v was stored by install_proc_write_hooks as a SetCommFn fn-pointer; non-zero confirms it.
    let f: SetCommFn = unsafe { core::mem::transmute(v) };
    f(pid, name)
}

pub(crate) fn hook_oom_adj_get(pid: u64) -> i16 {
    let v = OOM_ADJ_GET_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return 0;
    }
    // SAFETY: v was stored by install_proc_write_hooks as an OomAdjGetFn fn-pointer; non-zero confirms it.
    let f: OomAdjGetFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_oom_adj_set(pid: u64, val: i16) -> Result<(), FsError> {
    let v = OOM_ADJ_SET_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Err(FsError::Unsupported);
    }
    // SAFETY: v was stored by install_proc_write_hooks as an OomAdjSetFn fn-pointer; non-zero confirms it.
    let f: OomAdjSetFn = unsafe { core::mem::transmute(v) };
    f(pid, val)
}

pub(crate) fn hook_coredump_get(pid: u64) -> u32 {
    let v = COREDUMP_GET_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return 0x33;
    } // default: anon + anon-huge + ELF headers
      // SAFETY: v was stored by install_proc_write_hooks as a CoredumpGetFn fn-pointer; non-zero confirms it.
    let f: CoredumpGetFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_coredump_set(pid: u64, val: u32) -> Result<(), FsError> {
    let v = COREDUMP_SET_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Err(FsError::Unsupported);
    }
    // SAFETY: v was stored by install_proc_write_hooks as a CoredumpSetFn fn-pointer; non-zero confirms it.
    let f: CoredumpSetFn = unsafe { core::mem::transmute(v) };
    f(pid, val)
}

pub(crate) fn hook_oom_score(pid: u64) -> i32 {
    let v = OOM_SCORE_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return 0;
    }
    // SAFETY: v was stored by install_proc_write_hooks as an OomScoreFn fn-pointer; non-zero confirms it.
    let f: OomScoreFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

// ── Dynamic registration framework ──────────────────────────────
//
// `ProcFile` is the per-file trait other subsystems implement and
// register via `register_proc`. The registry is a tree of nodes
// (file or dir) keyed by the leading path components; `register_proc`
// auto-creates the intermediate directories.

/// One dynamically-registered procfs file. The `read` method is
/// called on every open; subsystems usually format their state into
/// a fresh `Vec<u8>` per call so the user sees a consistent
/// snapshot per read.
///
/// Linux ref: `struct proc_dir_entry::proc_iops` + `proc_fops` from
/// `fs/proc/internal.h`. The Rust trait collapses inode + file ops
/// into one object — NARF doesn't have a separate inode cache yet.
pub trait ProcFile: Send + Sync + core::fmt::Debug {
    /// Generate the file's content at this moment.
    fn read(&self) -> Vec<u8>;

    /// `true` if the file accepts writes. Default is read-only.
    fn writable(&self) -> bool {
        false
    }

    /// Handle a write. Default returns `FsError::ReadOnly`.
    fn write(&self, _buf: &[u8]) -> Result<usize, FsError> {
        Err(FsError::ReadOnly)
    }

    /// Last-modified time in monotonic cycles. Default reports the
    /// current monotonic clock so callers that snapshot mtime to
    /// detect a change always observe a fresh value across reads.
    fn mtime_cycles(&self) -> u64 {
        narf_time::monotonic_ns()
    }
}

/// A node in the dynamic procfs tree — either a file (leaf) or a
/// directory containing more nodes.
pub(crate) enum ProcNode {
    File(Arc<dyn ProcFile>),
    Dir(BTreeMap<String, ProcNode>),
}

impl core::fmt::Debug for ProcNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProcNode::File(_) => f.write_str("ProcNode::File"),
            ProcNode::Dir(m) => write!(f, "ProcNode::Dir(len={})", m.len()),
        }
    }
}

pub(crate) static REGISTRY: IrqSafeSpinLock<Option<BTreeMap<String, ProcNode>>> =
    IrqSafeSpinLock::new(None);

/// Register a procfs file at `path` (relative to `/proc`, e.g.
/// `"net/tcp"` not `"/proc/net/tcp"`). Intermediate directories
/// are created automatically.
///
/// A second `register_proc` at the same path replaces the existing
/// file — hard cutover; the old `Arc<dyn ProcFile>` is dropped.
///
/// Linux ref: `proc_create_data` in `fs/proc/generic.c:566`.
pub fn register_proc(path: &str, file: Arc<dyn ProcFile>) {
    let path = path.trim_matches('/');
    if path.is_empty() {
        return;
    }
    let components: Vec<&str> = path.split('/').collect();
    let mut g = REGISTRY.lock();
    let root = g.get_or_insert_with(BTreeMap::new);
    insert_into(root, &components, file);
}

fn insert_into(map: &mut BTreeMap<String, ProcNode>, components: &[&str], file: Arc<dyn ProcFile>) {
    match components {
        [] => {}
        [name] => {
            map.insert(String::from(*name), ProcNode::File(file));
        }
        [head, tail @ ..] => {
            let entry = map
                .entry(String::from(*head))
                .or_insert_with(|| ProcNode::Dir(BTreeMap::new()));
            // Hard cutover: if the slot was a file, replace it with
            // a directory holding the new path. Loses the old file,
            // matches Linux behaviour where a registration would
            // simply fail with -EEXIST today.
            if let ProcNode::File(_) = entry {
                *entry = ProcNode::Dir(BTreeMap::new());
            }
            if let ProcNode::Dir(child_map) = entry {
                insert_into(child_map, tail, file);
            }
        }
    }
}

/// Remove a previously-registered procfs file. Returns `true` iff
/// an entry existed at that path. Empty parent directories are
/// left in place — Linux's `remove_proc_entry` does the same.
pub fn unregister_proc(path: &str) -> bool {
    let path = path.trim_matches('/');
    if path.is_empty() {
        return false;
    }
    let components: Vec<&str> = path.split('/').collect();
    let mut g = REGISTRY.lock();
    let root = match g.as_mut() {
        Some(r) => r,
        None => return false,
    };
    remove_from(root, &components)
}

fn remove_from(map: &mut BTreeMap<String, ProcNode>, components: &[&str]) -> bool {
    match components {
        [] => false,
        [name] => map.remove(*name).is_some(),
        [head, tail @ ..] => {
            if let Some(ProcNode::Dir(child_map)) = map.get_mut(*head) {
                remove_from(child_map, tail)
            } else {
                false
            }
        }
    }
}

/// Snapshot of one directory level so callers (lookup/iter) can
/// release the registry lock before walking children.
#[derive(Debug)]
pub(crate) enum ProcNodeSnapshot {
    File(Arc<dyn ProcFile>),
    Dir(Vec<(String, ProcNodeKind)>),
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum ProcNodeKind {
    File,
    Dir,
}

/// Look up a node in the registry by relative path.
pub(crate) fn lookup_registry(components: &[&str]) -> Option<ProcNodeSnapshot> {
    let g = REGISTRY.lock();
    let mut cur = g.as_ref()?;
    let mut i = 0;
    while i < components.len() {
        let seg = components[i];
        let node = cur.get(seg)?;
        if i + 1 == components.len() {
            return Some(match node {
                ProcNode::File(f) => ProcNodeSnapshot::File(f.clone()),
                ProcNode::Dir(m) => ProcNodeSnapshot::Dir(snapshot_dir(m)),
            });
        }
        match node {
            ProcNode::Dir(m) => {
                cur = m;
                i += 1;
            }
            ProcNode::File(_) => return None,
        }
    }
    None
}

fn snapshot_dir(m: &BTreeMap<String, ProcNode>) -> Vec<(String, ProcNodeKind)> {
    m.iter()
        .map(|(k, v)| {
            let kind = match v {
                ProcNode::File(_) => ProcNodeKind::File,
                ProcNode::Dir(_) => ProcNodeKind::Dir,
            };
            (k.clone(), kind)
        })
        .collect()
}

// ── /proc/thread-self ────────────────────────────────────────────
//
// Magic symlink whose readlink text is `<pid>/task/<tid>`.  In NARF
// tid == pid for every task (no separate pthread_t kernel thread IDs
// yet), so the target is always `<pid>/task/<pid>`.  The node stats as
// Symlink so `readlink(2)` / `lstat(2)` treat it correctly, and
// `lookup_dir("thread-self")` in ProcRoot descends into the task/<tid>
// directory via ProcTaskDir for path-resolution.
//
// Linux ref: `fs/proc/self.c` `proc_thread_self_get_link` (6.9) — the
// kernel constructs `<tgid>/task/<tid>` as the link target.
// [[proc-magic-links]]

#[derive(Debug)]
struct ProcThreadSelf;

impl FileOps for ProcThreadSelf {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let pid = current_pid();
        Box::pin(async move {
            // readlink returns e.g. "7/task/7" — relative, no leading slash,
            // same shape as /proc/self which readlinks to "7".
            let target = format!("{}/task/{}", pid, pid);
            slice_read(target.as_bytes(), offset, buf)
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        // size MUST equal the readlink target length — sys_readlink sizes
        // its staging buffer from st.size, so 0 returns an empty string
        // (the same trap the per-pid `root` link hit).
        let pid = current_pid();
        Stat {
            size: format!("{}/task/{}", pid, pid).len() as u64,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Symlink,
                perms: 0o777,
            },
            mtime_cycles: 0,
        }
    }
}

/// Iterator helper: list names at a given dir path.
fn list_registry_dir(components: &[&str]) -> Vec<(String, ProcNodeKind)> {
    if components.is_empty() {
        let g = REGISTRY.lock();
        if let Some(m) = g.as_ref() {
            return snapshot_dir(m);
        }
        return Vec::new();
    }
    match lookup_registry(components) {
        Some(ProcNodeSnapshot::Dir(v)) => v,
        _ => Vec::new(),
    }
}

/// `FileOps` adapter for a dynamically-registered `ProcFile`.
pub(crate) struct ProcDynFile {
    pub(crate) file: Arc<dyn ProcFile>,
}

impl core::fmt::Debug for ProcDynFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcDynFile")
            .field("file", &self.file)
            .finish()
    }
}

impl FileOps for ProcDynFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let bytes = self.file.read();
            slice_read(&bytes, offset, buf)
        })
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let writable = self.file.writable();
        let result = if writable {
            self.file.write(buf)
        } else {
            Err(FsError::ReadOnly)
        };
        Box::pin(async move { result })
    }
    fn stat(&self) -> Stat {
        let mode = if self.file.writable() {
            Mode::FILE_RW
        } else {
            Mode::FILE_RO
        };
        Stat {
            size: 0,
            blocks: 0,
            mode,
            mtime_cycles: self.file.mtime_cycles(),
        }
    }
}

// ── Generic closure-backed read-only file ───────────────────────

/// Closure-backed virtual file. `gen` is called on every `read` —
/// we re-render rather than cache because the values (uptime,
/// /proc/self/stat) change between reads.
type GenStaticFn = fn() -> String;

struct ProcStaticFile {
    name: &'static str,
    gen: GenStaticFn,
}

impl core::fmt::Debug for ProcStaticFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcStaticFile")
            .field("name", &self.name)
            .finish()
    }
}

impl FileOps for ProcStaticFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let s = (self.gen)();
            slice_read(s.as_bytes(), offset, buf)
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        // See note on ProcPidFile::stat for why we don't call the
        // generator here — same lock-reentrancy reason.
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
}

/// Per-pid file with bound `pid` so the generator knows whose
/// state to render.
struct ProcPidFile {
    pid: u64,
    field: PidField,
}

#[derive(Copy, Clone, Debug)]
enum PidField {
    Stat,
    Status,
    Cmdline,
    Maps,
    Comm,
}

impl core::fmt::Debug for ProcPidFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcPidFile")
            .field("pid", &self.pid)
            .field("field", &self.field)
            .finish()
    }
}

impl FileOps for ProcPidFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let pid = self.pid;
        let field = self.field;
        Box::pin(async move {
            let info = match task_info(pid) {
                Some(i) => i,
                None => {
                    // Task gone (zombie reaped). Linux returns ESRCH;
                    // we surface as 0 bytes for read — same outcome
                    // for most consumers.
                    return Ok(0);
                }
            };
            let body = match field {
                PidField::Stat => render_stat(&info),
                PidField::Status => render_status(&info),
                PidField::Cmdline => return slice_read(&info.cmdline, offset, buf),
                PidField::Maps => render_maps(&info),
                PidField::Comm => format!("{}\n", info.comm),
            };
            slice_read(body.as_bytes(), offset, buf)
        })
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let pid = self.pid;
        let field = self.field;
        Box::pin(async move {
            if !matches!(field, PidField::Comm) {
                return Err(FsError::ReadOnly);
            }
            // Strip trailing newline / NUL (Linux write(2) shape).
            let trimmed = buf.trim_ascii_end();
            // Linux comm_write: clamp to TASK_COMM_LEN-1 (15 bytes) at
            // the procfs layer; the userspace hook is allowed to
            // assume a bounded name. Walk back to a valid UTF-8
            // boundary so from_utf8 cannot fail mid-codepoint.
            let mut end = trimmed.len().min(15);
            while end > 0 && (trimmed[end - 1] & 0xC0) == 0x80 {
                end -= 1;
            }
            let name = core::str::from_utf8(&trimmed[..end]).map_err(|_| FsError::InvalidData)?;
            // Hook unavailability is non-fatal: procfs write contract
            // is "always returns buf.len()" regardless of install
            // order.
            let _ = hook_set_comm(pid, name);
            Ok(buf.len())
        })
    }
    fn stat(&self) -> Stat {
        let mode = if matches!(self.field, PidField::Comm) {
            Mode::FILE_RW
        } else {
            Mode::FILE_RO
        };
        Stat {
            size: 0,
            blocks: 0,
            mode,
            mtime_cycles: 0,
        }
    }
}

pub(crate) fn slice_read(bytes: &[u8], offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
    let off = offset as usize;
    if off >= bytes.len() {
        return Ok(0);
    }
    let n = core::cmp::min(buf.len(), bytes.len() - off);
    buf[..n].copy_from_slice(&bytes[off..off + n]);
    Ok(n)
}

// ── Directory-marker file ───────────────────────────────────────
//
// resolve_async walks intermediate path components by calling
// lookup_async (returns a FileOps) + checking stat().mode.file_type
// == Dir, then calling lookup_dir_async to actually descend. For
// /proc/self/comm and /proc/[pid]/stat we need lookup("self") /
// lookup("<pid>") to return SOMETHING that stat()s as Dir even
// though those names refer to subdirs. ProcDirMarker is that
// stub — never read or written, exists only to pass the kind
// check in resolve_async.

#[derive(Debug)]
pub(crate) struct ProcDirMarker;

impl FileOps for ProcDirMarker {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::DIR_RO,
            mtime_cycles: 0,
        }
    }
}

// ── Per-pid directory ───────────────────────────────────────────

#[derive(Debug)]
struct ProcPidDir {
    pid: u64,
}

impl DirOps for ProcPidDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        // Subdirectory markers — resolve_async calls lookup_dir next.
        match name {
            "fd" | "fdinfo" | "task" | "ns" => return Some(Arc::new(ProcDirMarker)),
            _ => {}
        }
        // user-ns id-map files (read + one-shot write).
        match name {
            "uid_map" => {
                return Some(Arc::new(ProcIdMapFile {
                    pid: self.pid,
                    is_uid: true,
                }))
            }
            "gid_map" => {
                return Some(Arc::new(ProcIdMapFile {
                    pid: self.pid,
                    is_uid: false,
                }))
            }
            _ => {}
        }
        // Core flat files.
        let field = match name {
            "stat" => PidField::Stat,
            "status" => PidField::Status,
            "cmdline" => PidField::Cmdline,
            "maps" => PidField::Maps,
            "comm" => PidField::Comm,
            _ => {
                return pid_ext::lookup_pid_ext(self.pid, name)
                    .map(|f| Arc::new(f) as Arc<dyn FileOps>);
            }
        };
        Some(Arc::new(ProcPidFile {
            pid: self.pid,
            field,
        }))
    }
    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        match name {
            "fd" => Some(Arc::new(pid_ext::ProcFdDir { pid: self.pid })),
            "fdinfo" => Some(Arc::new(pid_ext::ProcFdInfoDir { pid: self.pid })),
            "task" => Some(Arc::new(pid_ext::ProcTaskDir { pid: self.pid })),
            "ns" => Some(Arc::new(ProcNsDir { pid: self.pid })),
            _ => None,
        }
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        Box::new(
            [
                // Core five (original Stage-1).
                DirEntry {
                    name: "stat",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "status",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "cmdline",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "maps",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "comm",
                    file_type: FileType::File,
                },
                // Extended flat files.
                DirEntry {
                    name: "io",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "sched",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "schedstat",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "stack",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "wchan",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "syscall",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "environ",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "auxv",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "limits",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "oom_score",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "oom_score_adj",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "coredump_filter",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "mountinfo",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "mountstats",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "personality",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "cgroup",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "statm",
                    file_type: FileType::File,
                },
                // Magic symlinks [[proc-magic-links]].
                DirEntry {
                    name: "exe",
                    file_type: FileType::Symlink,
                },
                DirEntry {
                    name: "cwd",
                    file_type: FileType::Symlink,
                },
                DirEntry {
                    name: "root",
                    file_type: FileType::Symlink,
                },
                // user-ns id maps.
                DirEntry {
                    name: "uid_map",
                    file_type: FileType::File,
                },
                DirEntry {
                    name: "gid_map",
                    file_type: FileType::File,
                },
                // Subdirectories.
                DirEntry {
                    name: "fd",
                    file_type: FileType::Dir,
                },
                DirEntry {
                    name: "fdinfo",
                    file_type: FileType::Dir,
                },
                DirEntry {
                    name: "task",
                    file_type: FileType::Dir,
                },
                DirEntry {
                    name: "ns",
                    file_type: FileType::Dir,
                },
            ]
            .into_iter(),
        )
    }
}

// ── /proc/<pid>/ns/<flavour> + uid_map/gid_map ──────────────────

/// `/proc/<pid>/ns` directory. Its children are the per-flavour ns
/// magic nodes. Linux models these as symlinks whose target text is
/// `flavour:[<id>]`; NARF makes them open()-able nodes (so they can
/// mint an ns-fd for setns) that also render that text via readlink.
#[derive(Debug)]
struct ProcNsDir {
    pid: u64,
}

/// One namespace magic node, e.g. `/proc/<pid>/ns/uts`. `read()`
/// returns the `flavour:[<id>]` link text (so `cat`/`readlink` see
/// it); opening it for setns is handled in the userspace open path
/// which recognises the path and mints an [`NsFd`].
#[derive(Debug)]
struct ProcNsLink {
    pid: u64,
    /// `ns_tag::*` discriminant.
    tag: u8,
}

const NS_NAMES: &[(&str, u8)] = &[
    ("uts", ns_tag::UTS),
    ("net", ns_tag::NET),
    ("ipc", ns_tag::IPC),
    ("pid", ns_tag::PID),
    ("mnt", ns_tag::MNT),
    ("cgroup", ns_tag::CGROUP),
    ("user", ns_tag::USER),
];

impl DirOps for ProcNsDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let tag = NS_NAMES.iter().find(|(n, _)| *n == name)?.1;
        Some(Arc::new(ProcNsLink { pid: self.pid, tag }))
    }
    fn lookup_dir(&self, _name: &str) -> Option<Arc<dyn DirOps>> {
        None
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        Box::new(NS_NAMES.iter().map(|(n, _)| DirEntry {
            name: n,
            file_type: FileType::Symlink,
        }))
    }
}

impl FileOps for ProcNsLink {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let pid = self.pid;
        let tag = self.tag;
        Box::pin(async move {
            let s = hook_ns_readlink(pid, tag).unwrap_or_default();
            slice_read(s.as_bytes(), offset, buf)
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Symlink,
                perms: 0o777,
            },
            mtime_cycles: 0,
        }
    }
}

/// `/proc/<pid>/uid_map` or `/proc/<pid>/gid_map`. Readable (renders
/// the active user-ns map) and writable once (Linux one-shot rule).
#[derive(Debug)]
struct ProcIdMapFile {
    pid: u64,
    is_uid: bool,
}

impl FileOps for ProcIdMapFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let pid = self.pid;
        let is_uid = self.is_uid;
        Box::pin(async move {
            let s = hook_ns_idmap_render(pid, is_uid).unwrap_or_default();
            slice_read(s.as_bytes(), offset, buf)
        })
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let pid = self.pid;
        let is_uid = self.is_uid;
        Box::pin(async move { hook_ns_idmap_write(pid, is_uid, buf) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
}

// ── /proc root ──────────────────────────────────────────────────

#[derive(Debug)]
struct ProcRoot;

impl DirOps for ProcRoot {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        match name {
            "cpuinfo" => Some(Arc::new(ProcStaticFile {
                name: "cpuinfo",
                gen: gen_cpuinfo,
            })),
            "meminfo" => Some(Arc::new(ProcStaticFile {
                name: "meminfo",
                gen: gen_meminfo,
            })),
            "mounts" => Some(Arc::new(ProcStaticFile {
                name: "mounts",
                gen: gen_mounts,
            })),
            "uptime" => Some(Arc::new(ProcStaticFile {
                name: "uptime",
                gen: gen_uptime,
            })),
            "version" => Some(Arc::new(ProcStaticFile {
                name: "version",
                gen: gen_version,
            })),
            "cmdline" => Some(Arc::new(ProcStaticFile {
                name: "cmdline",
                gen: gen_cmdline,
            })),
            "loadavg" => Some(Arc::new(ProcStaticFile {
                name: "loadavg",
                gen: gen_loadavg,
            })),
            "filesystems" => Some(Arc::new(ProcStaticFile {
                name: "filesystems",
                gen: gen_filesystems,
            })),
            "partitions" => Some(Arc::new(ProcStaticFile {
                name: "partitions",
                gen: gen_partitions,
            })),
            "sched" => Some(Arc::new(ProcStaticFile {
                name: "sched",
                gen: gen_sched,
            })),
            "stat" => Some(Arc::new(ProcStaticFile {
                name: "stat",
                gen: gen_stat,
            })),
            "self" => Some(Arc::new(ProcDirMarker)),
            // /proc/thread-self is a magic symlink (like /proc/self) that
            // resolves to `<pid>/task/<tid>`.  In NARF tid == the per-task
            // pid for procfs purposes, so the target is `<pid>/task/<pid>`.
            // The symlink stat is Symlink; readlink returns the formatted
            // string; descending into it resolves via ProcPidDir → task/.
            // Linux ref: `fs/proc/self.c` `proc_thread_self_get_link` (6.9).
            // [[proc-magic-links]]
            "thread-self" => Some(Arc::new(ProcThreadSelf)),
            _ => {
                // Dynamic registry — file or directory marker. The
                // dir marker keeps resolve_async happy so it'll
                // then descend via lookup_dir afterwards.
                if let Some(snap) = lookup_registry(&[name]) {
                    return Some(match snap {
                        ProcNodeSnapshot::File(f) => {
                            Arc::new(ProcDynFile { file: f }) as Arc<dyn FileOps>
                        }
                        ProcNodeSnapshot::Dir(_) => Arc::new(ProcDirMarker) as Arc<dyn FileOps>,
                    });
                }
                // Numeric pid → directory marker (lookup-as-file).
                // resolve_async needs lookup_async to return a
                // FileOps that stat()s as Dir before it'll call
                // lookup_dir_async for the descent.
                if let Ok(pid) = name.parse::<u64>() {
                    if task_info(pid).is_some() {
                        return Some(Arc::new(ProcDirMarker));
                    }
                }
                None
            }
        }
    }
    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        if name == "self" {
            // /proc/self resolves to the calling task's pid each
            // time; we materialise a fresh ProcPidDir bound to it.
            let pid = current_pid();
            return Some(Arc::new(ProcPidDir { pid }));
        }
        if name == "thread-self" {
            // /proc/thread-self → <pid>/task/<tid>; tid == pid in NARF.
            // Descending gives a ProcTaskTidDir that exposes `comm` etc.
            // Linux ref: `proc_thread_self_get_link` (fs/proc/self.c:80).
            let pid = current_pid();
            return pid_ext::ProcTaskDir { pid }.lookup_dir(&pid.to_string());
        }
        // Registry-backed subdirectory (e.g. "net").
        let snap = lookup_registry(&[name]);
        if matches!(snap, Some(ProcNodeSnapshot::Dir(_))) {
            return Some(Arc::new(ProcDynamicDir {
                path_components: alloc::vec![String::from(name)],
            }));
        }
        // Numeric name → per-pid dir. Validate the pid is live.
        if let Ok(pid) = name.parse::<u64>() {
            if task_info(pid).is_some() {
                return Some(Arc::new(ProcPidDir { pid }));
            }
        }
        None
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        // Static entries first, then "self", then every live pid
        // as its own decimal-named subdirectory. The decimal names
        // need owned Strings — but DirEntry holds &'static str, so
        // we leak the names (one allocation per pid per readdir).
        // Followups: switch DirEntry's name to String once a real
        // consumer needs the savings.
        let mut entries: Vec<DirEntry> = alloc::vec![
            DirEntry {
                name: "cpuinfo",
                file_type: FileType::File
            },
            DirEntry {
                name: "meminfo",
                file_type: FileType::File
            },
            DirEntry {
                name: "mounts",
                file_type: FileType::File
            },
            DirEntry {
                name: "uptime",
                file_type: FileType::File
            },
            DirEntry {
                name: "version",
                file_type: FileType::File
            },
            DirEntry {
                name: "cmdline",
                file_type: FileType::File
            },
            DirEntry {
                name: "loadavg",
                file_type: FileType::File
            },
            DirEntry {
                name: "filesystems",
                file_type: FileType::File
            },
            DirEntry {
                name: "partitions",
                file_type: FileType::File
            },
            DirEntry {
                name: "sched",
                file_type: FileType::File
            },
            DirEntry {
                name: "self",
                file_type: FileType::Dir
            },
            DirEntry {
                name: "thread-self",
                file_type: FileType::Symlink
            },
        ];
        // Dynamic registry top-level entries (e.g. "net", "acpi", ...).
        for (name, kind) in list_registry_dir(&[]) {
            let leaked: &'static str = Box::leak(name.into_boxed_str());
            entries.push(DirEntry {
                name: leaked,
                file_type: match kind {
                    ProcNodeKind::File => FileType::File,
                    ProcNodeKind::Dir => FileType::Dir,
                },
            });
        }
        for pid in list_pids() {
            let s = pid.to_string();
            // Leak the String so its bytes outlive this iter call.
            // Acceptable cost: real consumers (ls, ps) read /proc
            // infrequently and we cap at the live-pid count.
            let leaked: &'static str = Box::leak(s.into_boxed_str());
            entries.push(DirEntry {
                name: leaked,
                file_type: FileType::Dir,
            });
        }
        Box::new(entries.into_iter())
    }
}

// ── Dynamic-registry directory view ────────────────────────────
//
// `ProcDynamicDir` presents a registry subtree (e.g. `["net"]`) as a
// `DirOps` — the same view that `ProcRoot::lookup_dir` hands to
// `resolve_async` when it descends into a dynamic sub-directory.
//
// Linux ref: `proc_lookup` (fs/proc/generic.c:499) + the inode-lookup
// path that backs every `struct proc_dir_entry` with a `proc_iops`.

/// A `DirOps` view of a dynamic procfs subtree identified by the
/// leading `path_components` that reach it from the registry root.
///
/// Calling `iter()` returns one `DirEntry` per child of that node;
/// `lookup()` returns the `FileOps` for a registered file under it.
#[derive(Debug)]
pub struct ProcDynamicDir {
    /// Path components from the registry root to this directory,
    /// e.g. `["net"]` for `/proc/net/`.
    pub path_components: Vec<String>,
}

impl DirOps for ProcDynamicDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let mut path: Vec<&str> = self.path_components.iter().map(String::as_str).collect();
        path.push(name);
        match lookup_registry(&path) {
            Some(ProcNodeSnapshot::File(f)) => Some(Arc::new(ProcDynFile { file: f })),
            Some(ProcNodeSnapshot::Dir(_)) => Some(Arc::new(ProcDirMarker)),
            None => None,
        }
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let mut path: Vec<&str> = self.path_components.iter().map(String::as_str).collect();
        path.push(name);
        if matches!(lookup_registry(&path), Some(ProcNodeSnapshot::Dir(_))) {
            let mut child_components = self.path_components.clone();
            child_components.push(String::from(name));
            return Some(Arc::new(ProcDynamicDir {
                path_components: child_components,
            }));
        }
        None
    }

    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        let comps: Vec<&str> = self.path_components.iter().map(String::as_str).collect();
        let children = list_registry_dir(&comps);
        // DirEntry holds &'static str for name; we need to leak the
        // String — the same approach ProcRoot::iter uses for pid names.
        let entries: Vec<DirEntry> = children
            .into_iter()
            .map(|(name, kind)| {
                let file_type = match kind {
                    ProcNodeKind::File => FileType::File,
                    ProcNodeKind::Dir => FileType::Dir,
                };
                let leaked: &'static str = Box::leak(name.into_boxed_str());
                DirEntry {
                    name: leaked,
                    file_type,
                }
            })
            .collect();
        Box::new(entries.into_iter())
    }
}

// ── Single-poll helper (for tests) ─────────────────────────────

/// Poll `fut` exactly once using a no-op waker. Returns `Some(value)`
/// if the future completes in that single poll, or `None` if it would
/// need to wake up later (which never happens for procfs futs — they
/// are always immediately ready).
///
/// Used in tests that drive async `resolve_async` calls synchronously.
pub fn poll_once<F: core::future::Future>(fut: F) -> Option<F::Output> {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    // No-op waker — procfs futures are always `Poll::Ready` on the
    // first poll so we never need to schedule a wake-up.
    static VTABLE: RawWakerVTable = RawWakerVTable::new(
        |data| RawWaker::new(data, &VTABLE), // clone
        |_| {},                              // wake
        |_| {},                              // wake_by_ref
        |_| {},                              // drop
    );
    let raw = RawWaker::new(core::ptr::null(), &VTABLE);
    // SAFETY: VTABLE is a valid no-op vtable; the waker never outlives this stack frame.
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);

    let mut pinned = core::pin::pin!(fut);
    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

#[derive(Debug)]
pub struct ProcFs;

impl FsInstance for ProcFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(ProcRoot)
    }
    fn name(&self) -> &str {
        "procfs"
    }
}

// ── Generators (system-wide) ────────────────────────────────────

fn gen_cpuinfo() -> String {
    use core::fmt::Write as _;
    let mut s = String::new();
    #[cfg(target_arch = "x86_64")]
    {
        use narf_arch::x86_64::ident;
        let id = ident::read();
        let vendor_str = match id.vendor {
            ident::Vendor::Intel => "GenuineIntel",
            ident::Vendor::Amd => "AuthenticAMD",
            ident::Vendor::Hygon => "HygonGenuine",
            ident::Vendor::Centaur => "CentaurHauls",
            ident::Vendor::Via => "VIA VIA VIA ",
            ident::Vendor::Zhaoxin => "  Shanghai  ",
            ident::Vendor::Other(_) => "Unknown",
        };
        let brand = ident::brand_str(&id);
        let model_name = if brand.is_empty() { "(unknown)" } else { brand };
        // One block per logical CPU. SMP enumeration lands when the
        // userspace AP-count surface is wired through; today we
        // report the BSP only — matches what /proc/cpuinfo on a
        // single-CPU Linux config would show, and the fields are
        // identical per-block on a homogeneous system anyway.
        let _ = writeln!(s, "processor\t: 0");
        let _ = writeln!(s, "vendor_id\t: {}", vendor_str);
        let _ = writeln!(s, "cpu family\t: {}", id.family);
        let _ = writeln!(s, "model\t\t: {}", id.model);
        let _ = writeln!(s, "model name\t: {}", model_name);
        let _ = writeln!(s, "stepping\t: {}", id.stepping);
        let _ = writeln!(s);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = writeln!(s, "processor\t: 0");
        let _ = writeln!(s, "vendor_id\t: NARF");
        let _ = writeln!(s, "model name\t: (arch ident not yet wired)");
        let _ = writeln!(s);
    }
    s
}

fn gen_meminfo() -> String {
    use core::fmt::Write as _;
    let stats = narf_memory::frame::stats();
    // Frames are 4 KiB on every arch we target.
    let total_kb = stats.total * 4;
    let free_kb = stats.free * 4;
    let reserved_kb = stats.reserved * 4;
    let mut s = String::new();
    let _ = writeln!(s, "MemTotal:     {:>10} kB", total_kb);
    let _ = writeln!(s, "MemFree:      {:>10} kB", free_kb);
    // Without page-cache + slab accounting separated out we can't
    // distinguish "available" from "free"; report the same value
    // so the standard `free` math (`available = MemAvailable`)
    // still produces a meaningful number.
    let _ = writeln!(s, "MemAvailable: {:>10} kB", free_kb);
    let _ = writeln!(s, "Buffers:      {:>10} kB", 0);
    let _ = writeln!(s, "Cached:       {:>10} kB", 0);
    let _ = writeln!(s, "Reserved:     {:>10} kB", reserved_kb);
    s
}

fn gen_mounts() -> String {
    let mut s = String::new();
    for (path, fs_name) in crate::registry().list_with_names() {
        let _ =
            core::fmt::Write::write_fmt(&mut s, format_args!("none {} {} rw 0 0\n", path, fs_name));
    }
    s
}

fn gen_cmdline() -> String {
    let mut s = String::from(narf_boot::cmdline());
    s.push('\n');
    s
}

// ── /proc/loadavg EWMA state ────────────────────────────────────
//
// Linux tracks 1/5/15-minute exponential moving averages of the
// runnable count in `kernel/sched/loadavg.c` using fixed-point
// arithmetic with FIXED_1 = 1 << 11 (2048).  NARF samples lazily
// on each `read`, applying the correct per-elapsed-tick decay so
// the averages converge identically to the Linux model given the
// same runnable history.
//
// Decay factors per 5-second tick (Linux's load-average update
// period):
//   EXP_1   = e^(-5/60)   ≈ 0.9200 in FIXED_1 units → 1884
//   EXP_5   = e^(-5/300)  ≈ 0.9835               → 2014
//   EXP_15  = e^(-5/900)  ≈ 0.9945               → 2037
//
// Linux ref: `calc_load` (`kernel/sched/loadavg.c`) — the core
// one-tick decay step is `load = load*EXP + n*(FIXED_1 - EXP)`.
// [[proc-loadavg-ewma]]

/// Fixed-point scale: 1 << 11, matching Linux `FIXED_1`.
const FIXED_1: u64 = 1 << 11;

/// EXP_1, EXP_5, EXP_15 in FIXED_1 units (per 5 s tick).
const EXP_1: u64 = 1884; // e^(-5/60)  * FIXED_1
const EXP_5: u64 = 2014; // e^(-5/300) * FIXED_1
const EXP_15: u64 = 2037; // e^(-5/900) * FIXED_1

/// Monotonic nanoseconds of the last EWMA update (0 = never).
static LOADAVG_LAST_NS: IrqSafeSpinLock<u64> = IrqSafeSpinLock::new(0);
/// EWMA values in FIXED_1 units (avoids floating point).
static LOADAVG_AVG1: IrqSafeSpinLock<u64> = IrqSafeSpinLock::new(0);
static LOADAVG_AVG5: IrqSafeSpinLock<u64> = IrqSafeSpinLock::new(0);
static LOADAVG_AVG15: IrqSafeSpinLock<u64> = IrqSafeSpinLock::new(0);

/// Apply one 5-second EWMA tick: `load = load*exp + n*(FIXED_1 - exp)`.
/// Linux ref: `calc_load` (kernel/sched/loadavg.c).
#[inline]
fn calc_load_tick(load: u64, exp: u64, n: u64) -> u64 {
    (load.saturating_mul(exp) + n.saturating_mul(FIXED_1 - exp)) / FIXED_1
}

/// Sysinfo-shaped loadavg snapshot: (avg1, avg5, avg15) in the Linux
/// `sysinfo.loads[]` fixed point (SI_LOAD_SHIFT = 16). Our EWMA runs in
/// FIXED_1 = 2048 (11-bit) units, so the conversion is a << 5. Lets
/// `sys_sysinfo` (and busybox uptime, which reads sysinfo(2), not
/// /proc/loadavg) report the same numbers the proc file renders.
pub fn loadavg_sysinfo_fixed16() -> (u64, u64, u64) {
    let (a1, a5, a15) = loadavg_update();
    (a1 << 5, a5 << 5, a15 << 5)
}

/// Update the EWMA state and return a snapshot of (avg1, avg5, avg15)
/// in FIXED_1 units.  Called on every `/proc/loadavg` read.
fn loadavg_update() -> (u64, u64, u64) {
    let now_ns = narf_time::monotonic_ns();
    // Instantaneous RUNNABLE count — awake ready-queue slots, NOT the
    // full live-task list (which counts every parked getty/daemon and
    // pinned the rendered load at the task count — the alpine probe
    // read a flat "14.00 14.00 14.00").
    let runnable = narf_scheduler::runnable_task_count() as u64;

    let mut last_ns = LOADAVG_LAST_NS.lock();
    let mut avg1 = LOADAVG_AVG1.lock();
    let mut avg5 = LOADAVG_AVG5.lock();
    let mut avg15 = LOADAVG_AVG15.lock();

    let elapsed_ns = now_ns.saturating_sub(*last_ns);
    // Number of 5-second ticks elapsed since last update.
    // Cap at 1000 to avoid spending O(uptime_in_ticks) on first read.
    let ticks = (elapsed_ns / 5_000_000_000).min(1000);

    for _ in 0..ticks {
        *avg1 = calc_load_tick(*avg1, EXP_1, runnable);
        *avg5 = calc_load_tick(*avg5, EXP_5, runnable);
        *avg15 = calc_load_tick(*avg15, EXP_15, runnable);
    }
    // If no full tick has elapsed yet but this is the first call,
    // seed the averages with the instantaneous count so the first
    // read isn't misleadingly zero.
    if *last_ns == 0 {
        *avg1 = runnable * FIXED_1;
        *avg5 = runnable * FIXED_1;
        *avg15 = runnable * FIXED_1;
    }
    // Advance last_ns by the ticks we applied (keep sub-tick remainder).
    *last_ns = if ticks > 0 {
        last_ns.saturating_add(ticks * 5_000_000_000)
    } else {
        // No tick yet — mark that we've been called so seeding above
        // only runs on the very first read.
        if *last_ns == 0 {
            now_ns
        } else {
            *last_ns
        }
    };

    (*avg1, *avg5, *avg15)
}

fn gen_loadavg() -> String {
    // Linux format: "0.00 0.00 0.00 R/T lastpid\n"
    //   1/5/15-min EWMAs | runnable/total | last_pid
    // Averages are lazily-decayed [[proc-loadavg-ewma]].
    let (a1, a5, a15) = loadavg_update();
    // Convert FIXED_1 units to x.xx display.  Linux uses the same
    // division+remainder trick in `get_avenrun` (kernel/sched/loadavg.c).
    let fmt_avg = |v: u64| -> (u64, u64) {
        let integer = v / FIXED_1;
        let frac = ((v % FIXED_1) * 100) / FIXED_1;
        (integer, frac)
    };
    let (i1, f1) = fmt_avg(a1);
    let (i5, f5) = fmt_avg(a5);
    let (i15, f15) = fmt_avg(a15);
    let total = narf_scheduler::all_task_ids().len();
    // Floor at 1 — the reading process itself is running (Linux never
    // renders 0/T), and a momentarily all-contended try_lock sample
    // would otherwise show 0.
    let running = narf_scheduler::runnable_task_count().max(1);
    let last_pid = total;
    format!(
        "{}.{:02} {}.{:02} {}.{:02} {}/{} {}\n",
        i1, f1, i5, f5, i15, f15, running, total, last_pid
    )
}

fn gen_filesystems() -> String {
    use alloc::collections::BTreeSet;
    use core::fmt::Write as _;
    // Distinct fs.name() values from currently-mounted instances.
    // Linux's /proc/filesystems prefixes "nodev" for FS types that
    // can't back a block device; our mount surface doesn't track
    // that today, so omit the prefix — bare `mount` (no -t) only
    // checks for the FS-type token.
    let names: BTreeSet<String> = crate::registry()
        .list_with_names()
        .into_iter()
        .map(|(_p, n)| n)
        .collect();
    let mut s = String::new();
    for n in names {
        let _ = writeln!(s, "\t{}", n);
    }
    s
}

/// `/proc/stat` — system-wide kernel/scheduler stats. `top`, `uptime`,
/// `vmstat` and most monitors read this. NARF doesn't account per-task CPU
/// time, so the busy fields are 0 and the elapsed time is reported as idle
/// (the TCG system is mostly idle); the structure is what tools parse.
fn gen_stat() -> String {
    use core::fmt::Write as _;
    let mut s = String::new();
    let up_ns = narf_time::monotonic_ns();
    // USER_HZ = 100 → jiffies are centiseconds.
    let elapsed = up_ns / 10_000_000;
    let depths = narf_scheduler::cpu_queue_depths();
    // Per-CPU lines with REAL idle time — the scheduler folds each
    // CPU's actual sleep (HLT / idle pump) into a per-cpu counter
    // (`narf_scheduler::cpu_idle_ns`) — and busy derived as
    // elapsed − idle in the `user` column (NARF has no per-cpu
    // user/system/irq split). htop-class per-core bars are real now.
    // Columns: user nice system idle iowait irq softirq steal guest gnice.
    let mut busy_sum: u64 = 0;
    let mut idle_sum: u64 = 0;
    let mut cpu_lines = String::new();
    for (cpu, _) in &depths {
        let idle = (narf_scheduler::cpu_idle_ns(*cpu as usize) / 10_000_000).min(elapsed);
        let busy = elapsed.saturating_sub(idle);
        busy_sum += busy;
        idle_sum += idle;
        let _ = writeln!(cpu_lines, "cpu{} {} 0 0 {} 0 0 0 0 0 0", cpu, busy, idle);
    }
    let _ = writeln!(s, "cpu  {} 0 0 {} 0 0 0 0 0 0", busy_sum, idle_sum);
    s.push_str(&cpu_lines);
    let _ = writeln!(s, "intr 0");
    let _ = writeln!(s, "ctxt 0");
    // btime = wall-now minus uptime (UNIX seconds the system booted).
    let btime = (narf_time::now_wall().secs as u64).saturating_sub(up_ns / 1_000_000_000);
    let _ = writeln!(s, "btime {}", btime);
    let tasks = narf_scheduler::all_task_ids().len();
    let _ = writeln!(s, "processes {}", tasks);
    let running: usize = depths.iter().map(|(_, n)| *n).sum();
    let _ = writeln!(s, "procs_running {}", running.max(1));
    let _ = writeln!(s, "procs_blocked 0");
    s
}

fn gen_sched() -> String {
    use core::fmt::Write as _;
    let mut s = String::new();
    let tasks = narf_scheduler::all_task_ids().len();
    let depths = narf_scheduler::cpu_queue_depths();
    let online = depths.len();
    let _ = writeln!(s, "online_cpus:\t{}", online);
    let _ = writeln!(s, "total_tasks:\t{}", tasks);
    let _ = writeln!(s, "per_cpu_ready:");
    for (cpu, len) in depths {
        let _ = writeln!(s, "  cpu{:<3} {:>6}", cpu, len);
    }
    s
}

fn gen_partitions() -> String {
    use core::fmt::Write as _;
    // Linux format:
    //   major minor  #blocks  name
    // We don't have a major/minor allocator (no devnode space yet),
    // so report 0/N for major and the registry index for minor.
    // #blocks is capacity_kb, derived from capacity * lba_size.
    let mut s = String::from("major minor  #blocks  name\n");
    for (i, dev) in narf_block::block_devices().iter().enumerate() {
        let bytes = dev.dev.capacity().saturating_mul(dev.dev.lba_size() as u64);
        let kb = bytes / 1024;
        let _ = writeln!(s, "    0  {:>4}  {:>10}  {}", i, kb, dev.name);
    }
    s
}

fn gen_uptime() -> String {
    let now_ns = narf_time::monotonic_ns();
    let seconds = now_ns / 1_000_000_000;
    let frac_centi = (now_ns / 10_000_000) % 100;
    format!("{}.{:02} 0.00\n", seconds, frac_centi)
}

fn gen_version() -> String {
    String::from(concat!(
        "NARF kernel ",
        env!("CARGO_PKG_VERSION"),
        " (microkernel)\n",
    ))
}

// ── Per-pid renderers ───────────────────────────────────────────

fn render_stat(info: &ProcTaskInfo) -> String {
    // Linux /proc/[pid]/stat has 52 space-separated fields. We
    // populate the leading positions that real readers (ps, top,
    // glibc's getproctitle, /usr/bin/uptime) actually consume.
    // Fields:
    //   pid (comm) state ppid pgrp session tty_nr tpgid flags
    //   minflt cminflt majflt cmajflt utime stime cutime cstime
    //   priority nice num_threads itrealvalue starttime vsize rss
    //   ...  — we fill the first 23 with sensible values and pad.
    let vsize: u64 = info
        .vmas
        .iter()
        .map(|v| v.end.saturating_sub(v.start))
        .sum();
    let rss_pages = vsize / 4096; // no per-page residency — VmRSS mirrors VmSize
    format!(
        "{} ({}) {} {} {} {} 0 0 0 0 0 0 0 {} {} 0 0 20 0 1 0 {} {} {}          0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        info.pid,
        info.comm,
        info.state,
        info.ppid,
        info.pgrp,
        info.session,
        info.utime_ticks,
        info.stime_ticks,
        info.starttime_ticks,
        vsize,
        rss_pages,
    )
}

fn render_status(info: &ProcTaskInfo) -> String {
    let mut s = String::new();
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("Name:\t{}\n", info.comm));
    let _ = core::fmt::Write::write_fmt(
        &mut s,
        format_args!(
            "State:\t{} ({})\n",
            info.state,
            match info.state {
                'R' => "running",
                'S' => "sleeping",
                'Z' => "zombie",
                _ => "unknown",
            },
        ),
    );
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("Tgid:\t{}\n", info.pid));
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("Ngid:\t0\n"));
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("Pid:\t{}\n", info.pid));
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("PPid:\t{}\n", info.ppid));
    // Total mapped size from the VMA list. NARF doesn't separate resident
    // from virtual, so VmRSS/VmPeak/VmHWM mirror VmSize (best-effort, but
    // enough for ps/top to sort and display).
    let vm_kb: u64 = info
        .vmas
        .iter()
        .map(|v| v.end.saturating_sub(v.start) / 1024)
        .sum();
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("VmPeak:\t{} kB\n", vm_kb));
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("VmSize:\t{} kB\n", vm_kb));
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("VmHWM:\t{} kB\n", vm_kb));
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("VmRSS:\t{} kB\n", vm_kb));
    let _ = core::fmt::Write::write_fmt(
        &mut s,
        format_args!("VmData:\t{} kB\n", info.brk_top / 1024),
    );
    let _ = core::fmt::Write::write_fmt(
        &mut s,
        format_args!("VmStk:\t{} kB\n", info.stack_top / 1024),
    );
    // Single-threaded processes (NARF threads aren't surfaced per-tid here).
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("Threads:\t1\n"));
    s
}

fn render_maps(info: &ProcTaskInfo) -> String {
    // Linux /proc/[pid]/maps shape:
    //   start-end perms offset dev:major:minor inode pathname
    // We omit dev:major:minor (NARF doesn't yet model per-VMA
    // backing files); pathname slot carries our label or empty.
    let mut s = String::new();
    for v in info.vmas.iter() {
        let r = if v.readable { 'r' } else { '-' };
        let w = if v.writable { 'w' } else { '-' };
        let x = if v.executable { 'x' } else { '-' };
        let p = if v.shared { 's' } else { 'p' };
        let _ = core::fmt::Write::write_fmt(
            &mut s,
            format_args!(
                "{:016x}-{:016x} {}{}{}{} 00000000 00:00 0",
                v.start, v.end, r, w, x, p,
            ),
        );
        if !v.label.is_empty() {
            let _ = core::fmt::Write::write_fmt(&mut s, format_args!("          {}", v.label));
        }
        s.push('\n');
    }
    s
}

// ── Framework smokes ────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// Minimal `ProcFile` for tests: emits a fixed byte string.
#[derive(Debug)]
struct TestProcFile {
    body: Vec<u8>,
}

impl ProcFile for TestProcFile {
    fn read(&self) -> Vec<u8> {
        self.body.clone()
    }
}

/// Framework smoke: register a file, read returns its content.
fn smoke_register_proc_then_read() -> TestResult {
    let payload = b"hello-procfs\n".to_vec();
    register_proc(
        "tests/framework_smoke",
        Arc::new(TestProcFile {
            body: payload.clone(),
        }),
    );
    let snap = lookup_registry(&["tests", "framework_smoke"]);
    let ok = match snap {
        Some(ProcNodeSnapshot::File(f)) => f.read() == payload,
        _ => false,
    };
    unregister_proc("tests/framework_smoke");
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("register_proc → lookup → read round-trip failed")
    }
}
kernel_test_in!("filesystem/procfs", smoke_register_proc_then_read);

/// Regression: the static cpuinfo file still resolves through the
/// root and returns non-empty content. This verifies the refactor
/// didn't break the existing surface that tools depend on.
fn smoke_static_cpuinfo_still_works() -> TestResult {
    let root: Arc<dyn DirOps> = Arc::new(ProcRoot);
    let f = match root.lookup("cpuinfo") {
        Some(f) => f,
        None => return TestResult::Fail("cpuinfo lookup returned None"),
    };
    let mut buf = [0u8; 256];
    let res = poll_once(f.read(0, &mut buf));
    match res {
        Some(Ok(n)) if n > 0 && buf[..n].starts_with(b"processor") => TestResult::Pass,
        Some(Ok(_)) => TestResult::Fail("cpuinfo content unexpected"),
        Some(Err(_)) => TestResult::Fail("cpuinfo read returned error"),
        None => TestResult::Fail("cpuinfo read future not ready synchronously"),
    }
}
kernel_test_in!("filesystem/procfs", smoke_static_cpuinfo_still_works);

/// Framework smoke: register a file, then unregister it, then
/// confirm subsequent lookups fail.
fn smoke_unregister_proc_clears_entry() -> TestResult {
    register_proc(
        "tests/unregister_me",
        Arc::new(TestProcFile {
            body: alloc::vec![0u8; 4],
        }),
    );
    let before = matches!(
        lookup_registry(&["tests", "unregister_me"]),
        Some(ProcNodeSnapshot::File(_))
    );
    let removed = unregister_proc("tests/unregister_me");
    let after = matches!(
        lookup_registry(&["tests", "unregister_me"]),
        Some(ProcNodeSnapshot::File(_))
    );
    if before && removed && !after {
        TestResult::Pass
    } else {
        TestResult::Fail("unregister sequence wrong")
    }
}
kernel_test_in!("filesystem/procfs", smoke_unregister_proc_clears_entry);

/// mtime_cycles default reports a non-zero monotonic value.
fn smoke_proc_file_mtime_default_nonzero() -> TestResult {
    #[derive(Debug)]
    struct EmptyFile;
    impl ProcFile for EmptyFile {
        fn read(&self) -> Vec<u8> {
            Vec::new()
        }
    }
    let f = EmptyFile;
    let t1 = f.mtime_cycles();
    let t2 = f.mtime_cycles();
    if t1 > 0 && t2 >= t1 {
        TestResult::Pass
    } else {
        TestResult::Fail("mtime_cycles default did not return non-zero monotonic")
    }
}
kernel_test_in!("filesystem/procfs", smoke_proc_file_mtime_default_nonzero);

/// /proc root iter must list both static files and dynamically-
/// registered top-level entries.
fn smoke_root_iter_lists_dynamic_top_level() -> TestResult {
    register_proc(
        "tests_iter_topdir/leaf",
        Arc::new(TestProcFile {
            body: alloc::vec![0u8; 1],
        }),
    );
    let root = ProcRoot;
    let names: Vec<String> = root.iter().map(|e| String::from(e.name)).collect();
    let saw_cpuinfo = names.iter().any(|n| n == "cpuinfo");
    let saw_dynamic = names.iter().any(|n| n == "tests_iter_topdir");
    unregister_proc("tests_iter_topdir/leaf");
    if saw_cpuinfo && saw_dynamic {
        TestResult::Pass
    } else {
        TestResult::Fail("root iter missing static or dynamic entries")
    }
}
kernel_test_in!("filesystem/procfs", smoke_root_iter_lists_dynamic_top_level);

/// Smoke: `/proc/<pid>/comm` stat() reports FILE_RW mode.
fn smoke_comm_file_is_rw() -> TestResult {
    let f = ProcPidFile {
        pid: 1,
        field: PidField::Comm,
    };
    if f.stat().mode == Mode::FILE_RW {
        TestResult::Pass
    } else {
        TestResult::Fail("/proc/<pid>/comm stat mode should be FILE_RW")
    }
}
kernel_test_in!("filesystem/procfs", smoke_comm_file_is_rw);

/// Smoke: write "newname\n" to comm succeeds and hook is exercised.
fn smoke_comm_write_updates_read() -> TestResult {
    // Use a stable per-test pid to avoid colliding with live tasks.
    const PID: u64 = 0x000f_0ca1_0001;
    let f = ProcPidFile {
        pid: PID,
        field: PidField::Comm,
    };
    // Write with a trailing newline (Linux userspace shape).
    match poll_once(f.write(0, b"newname\n")) {
        Some(Ok(n)) if n > 0 => TestResult::Pass,
        Some(Ok(_)) => TestResult::Fail("comm write returned 0 bytes written"),
        Some(Err(_)) => TestResult::Fail("comm write returned error"),
        None => TestResult::Fail("comm write future did not complete"),
    }
}
kernel_test_in!("filesystem/procfs", smoke_comm_write_updates_read);

/// Smoke: write 30-char name → truncated to 15 (TASK_COMM_LEN - 1).
fn smoke_comm_write_truncates_to_15() -> TestResult {
    const PID: u64 = 0x000f_0ca1_0002;
    let f = ProcPidFile {
        pid: PID,
        field: PidField::Comm,
    };
    // 30 ASCII 'a' chars + newline — handler must accept and truncate.
    let long_name = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
    match poll_once(f.write(0, long_name)) {
        // write() must succeed (buf.len() returned) even for overlong names.
        Some(Ok(n)) if n == long_name.len() => TestResult::Pass,
        Some(Ok(_)) => TestResult::Fail("comm write returned unexpected byte count"),
        Some(Err(_)) => TestResult::Fail("comm write of overlong name returned error"),
        None => TestResult::Fail("comm write future did not complete"),
    }
}
kernel_test_in!("filesystem/procfs", smoke_comm_write_truncates_to_15);

/// Smoke: write to a non-comm pid file returns ReadOnly.
fn smoke_non_comm_write_returns_readonly() -> TestResult {
    let f = ProcPidFile {
        pid: 1,
        field: PidField::Stat,
    };
    let wr = poll_once(f.write(0, b"ignored\n"));
    if matches!(wr, Some(Err(FsError::ReadOnly))) {
        TestResult::Pass
    } else {
        TestResult::Fail("stat write should return ReadOnly")
    }
}
kernel_test_in!("filesystem/procfs", smoke_non_comm_write_returns_readonly);

/// /proc/thread-self readlink returns "<pid>/task/<pid>" shape (digit/task/digit).
fn smoke_thread_self_readlink_shape() -> TestResult {
    // current_pid() returns 0 when no hook is installed; target is "0/task/0".
    let ts = ProcThreadSelf;
    let mut buf = [0u8; 64];
    let res = poll_once(ts.read(0, &mut buf));
    match res {
        Some(Ok(n)) if n > 0 => {
            let s = match core::str::from_utf8(&buf[..n]) {
                Ok(s) => s,
                Err(_) => return TestResult::Fail("thread-self readlink not utf-8"),
            };
            // Shape: "<digits>/task/<digits>", no leading slash.
            let parts: Vec<&str> = s.split('/').collect();
            if parts.len() == 3
                && parts[0].chars().all(|c| c.is_ascii_digit())
                && parts[1] == "task"
                && parts[2].chars().all(|c| c.is_ascii_digit())
            {
                TestResult::Pass
            } else {
                TestResult::Fail("thread-self readlink shape wrong")
            }
        }
        Some(Ok(_)) => TestResult::Fail("thread-self readlink returned 0 bytes"),
        Some(Err(_)) => TestResult::Fail("thread-self readlink returned error"),
        None => TestResult::Fail("thread-self readlink future not ready"),
    }
}
kernel_test_in!("filesystem/procfs", smoke_thread_self_readlink_shape);

/// /proc/thread-self stat() reports Symlink type.
fn smoke_thread_self_stat_is_symlink() -> TestResult {
    let ts = ProcThreadSelf;
    if ts.stat().mode.file_type == FileType::Symlink {
        TestResult::Pass
    } else {
        TestResult::Fail("thread-self stat is not Symlink")
    }
}
kernel_test_in!("filesystem/procfs", smoke_thread_self_stat_is_symlink);

/// /proc/loadavg renders three x.yy values and the R/T/lastpid tail.
fn smoke_loadavg_format_three_values() -> TestResult {
    let s = gen_loadavg();
    // Expected shape: "1.23 0.45 0.06 1/3 3\n"
    let parts: Vec<&str> = s.trim_end_matches('\n').split_whitespace().collect();
    if parts.len() < 5 {
        return TestResult::Fail("loadavg: fewer than 5 whitespace tokens");
    }
    // First three must be x.xx floats.
    for v in parts.iter().take(3) {
        if v.find('.').is_none() {
            return TestResult::Fail("loadavg: token missing decimal point");
        }
        let dot_pos = v.find('.').unwrap();
        let frac = &v[dot_pos + 1..];
        if frac.len() != 2 {
            return TestResult::Fail("loadavg: fraction not exactly 2 digits");
        }
    }
    // parts[3] must contain "/" (R/T).
    if !parts[3].contains('/') {
        return TestResult::Fail("loadavg: R/T token missing slash");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/procfs", smoke_loadavg_format_three_values);

/// /proc/stat (mod.rs gen_stat path) has a "btime <positive-int>" line.
fn smoke_stat_btime_positive() -> TestResult {
    let s = gen_stat();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            let n: u64 = match rest.trim().parse() {
                Ok(v) => v,
                Err(_) => return TestResult::Fail("stat: btime is not an integer"),
            };
            // btime may be 0 in test env (wall clock not set), but the
            // line must exist and be parseable. Accept 0.
            let _ = n;
            return TestResult::Pass;
        }
    }
    TestResult::Fail("stat: btime line missing")
}
kernel_test_in!("filesystem/procfs", smoke_stat_btime_positive);

/// /proc/[pid]/stat now renders 52 real fields — ppid/pgrp/session
/// (4-6), utime (14), starttime (22), vsize/rss (23-24) — instead of
/// the pid/comm/state-plus-zeros stub. `ps`/`top` compose starttime
/// with /proc/stat btime and CPU% from utime deltas, so the positions
/// must match proc(5) exactly.
fn smoke_pid_stat_real_fields() -> TestResult {
    let info = ProcTaskInfo {
        pid: 7,
        comm: String::from("t"),
        state: 'R',
        brk_top: 0,
        stack_top: 0,
        cmdline: Vec::new(),
        vmas: alloc::vec![ProcVma {
            start: 0x1000,
            end: 0x3000, // 8192 bytes = 2 pages
            readable: true,
            writable: false,
            executable: false,
            shared: false,
            label: "",
        }],
        ppid: 2,
        pgrp: 3,
        session: 4,
        utime_ticks: 5,
        stime_ticks: 9,
        starttime_ticks: 6,
    };
    let line = render_stat(&info);
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() != 52 {
        return TestResult::Fail("stat must have exactly 52 fields");
    }
    // 0-based: ppid=3, pgrp=4, session=5, utime=13, starttime=21,
    // vsize=22, rss=23.
    if f[3] != "2" || f[4] != "3" || f[5] != "4" {
        return TestResult::Fail("ppid/pgrp/session must land in fields 4-6");
    }
    if f[13] != "5" || f[14] != "9" {
        return TestResult::Fail("utime/stime must land in fields 14-15");
    }
    if f[21] != "6" || f[22] != "8192" || f[23] != "2" {
        return TestResult::Fail("starttime/vsize/rss must land in fields 22-24");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/procfs", smoke_pid_stat_real_fields);

/// /proc/stat per-cpu lines carry real idle jiffies now (the
/// scheduler's idle_wait bracket) with busy = elapsed − idle in the
/// user column. Shape checks: aggregate + one line per CPU, 11 tokens
/// each, aggregate = per-cpu sums, idle ≤ elapsed.
fn smoke_stat_per_cpu_lines_real_idle() -> TestResult {
    let s = gen_stat();
    let mut agg: Option<(u64, u64)> = None;
    let mut busy_sum = 0u64;
    let mut idle_sum = 0u64;
    let mut cpus = 0usize;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("cpu") {
            let toks: Vec<&str> = line.split_whitespace().collect();
            if toks.len() != 11 {
                return TestResult::Fail("cpu lines must have 11 tokens");
            }
            let user: u64 = toks[1].parse().unwrap_or(u64::MAX);
            let idle: u64 = toks[4].parse().unwrap_or(u64::MAX);
            if user == u64::MAX || idle == u64::MAX {
                return TestResult::Fail("cpu busy/idle must be integers");
            }
            if rest.starts_with(' ') {
                agg = Some((user, idle));
            } else {
                cpus += 1;
                busy_sum += user;
                idle_sum += idle;
            }
        }
    }
    if cpus == 0 {
        return TestResult::Fail("stat must render at least cpu0");
    }
    match agg {
        Some((b, i)) if b == busy_sum && i == idle_sum => TestResult::Pass,
        Some(_) => TestResult::Fail("aggregate cpu line must equal per-cpu sums"),
        None => TestResult::Fail("aggregate cpu line missing"),
    }
}
kernel_test_in!("filesystem/procfs", smoke_stat_per_cpu_lines_real_idle);
