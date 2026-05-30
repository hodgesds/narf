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

use crate::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat,
};

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
    let f: CurrentPidFn = unsafe { core::mem::transmute(v) };
    f()
}

fn list_pids() -> Vec<u64> {
    let v = LIST_PIDS_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    let f: ListPidsFn = unsafe { core::mem::transmute(v) };
    f()
}

pub(crate) fn task_info(pid: u64) -> Option<ProcTaskInfo> {
    let v = TASK_INFO_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return None;
    }
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
    if v == 0 { return None; }
    let f: FdPathFn = unsafe { core::mem::transmute(v) };
    f(pid, fd)
}

pub(crate) fn hook_rlimits(pid: u64) -> [(u64, u64); 16] {
    let v = RLIMITS_HOOK.load(Ordering::Acquire);
    if v == 0 { return [(0, 0); 16]; }
    let f: RlimitsFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_nice(pid: u64) -> i32 {
    let v = NICE_HOOK.load(Ordering::Acquire);
    if v == 0 { return 0; }
    let f: NiceFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_environ(pid: u64) -> Vec<u8> {
    let v = ENVIRON_HOOK.load(Ordering::Acquire);
    if v == 0 { return Vec::new(); }
    let f: EnvironFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_auxv(pid: u64) -> Vec<u8> {
    let v = AUXV_HOOK.load(Ordering::Acquire);
    if v == 0 { return alloc::vec![0u8; 16]; }
    let f: AuxvFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_set_comm(pid: u64, name: &str) -> Result<(), FsError> {
    let v = SET_COMM_HOOK.load(Ordering::Acquire);
    if v == 0 { return Err(FsError::Unsupported); }
    let f: SetCommFn = unsafe { core::mem::transmute(v) };
    f(pid, name)
}

pub(crate) fn hook_oom_adj_get(pid: u64) -> i16 {
    let v = OOM_ADJ_GET_HOOK.load(Ordering::Acquire);
    if v == 0 { return 0; }
    let f: OomAdjGetFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_oom_adj_set(pid: u64, val: i16) -> Result<(), FsError> {
    let v = OOM_ADJ_SET_HOOK.load(Ordering::Acquire);
    if v == 0 { return Err(FsError::Unsupported); }
    let f: OomAdjSetFn = unsafe { core::mem::transmute(v) };
    f(pid, val)
}

pub(crate) fn hook_coredump_get(pid: u64) -> u32 {
    let v = COREDUMP_GET_HOOK.load(Ordering::Acquire);
    if v == 0 { return 0x33; } // default: anon + anon-huge + ELF headers
    let f: CoredumpGetFn = unsafe { core::mem::transmute(v) };
    f(pid)
}

pub(crate) fn hook_coredump_set(pid: u64, val: u32) -> Result<(), FsError> {
    let v = COREDUMP_SET_HOOK.load(Ordering::Acquire);
    if v == 0 { return Err(FsError::Unsupported); }
    let f: CoredumpSetFn = unsafe { core::mem::transmute(v) };
    f(pid, val)
}

pub(crate) fn hook_oom_score(pid: u64) -> i32 {
    let v = OOM_SCORE_HOOK.load(Ordering::Acquire);
    if v == 0 { return 0; }
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

fn insert_into(
    map: &mut BTreeMap<String, ProcNode>,
    components: &[&str],
    file: Arc<dyn ProcFile>,
) {
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
        f.debug_struct("ProcDynFile").field("file", &self.file).finish()
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
        f.debug_struct("ProcStaticFile").field("name", &self.name).finish()
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
            let name = core::str::from_utf8(trimmed).map_err(|_| FsError::InvalidData)?;
            hook_set_comm(pid, name).map_err(|_| FsError::InvalidData)?;
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
            "fd" | "fdinfo" | "task" => return Some(Arc::new(ProcDirMarker)),
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
        Some(Arc::new(ProcPidFile { pid: self.pid, field }))
    }
    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        match name {
            "fd" => Some(Arc::new(pid_ext::ProcFdDir { pid: self.pid })),
            "fdinfo" => Some(Arc::new(pid_ext::ProcFdInfoDir { pid: self.pid })),
            "task" => Some(Arc::new(pid_ext::ProcTaskDir { pid: self.pid })),
            _ => None,
        }
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        Box::new(
            [
                // Core five (original Stage-1).
                DirEntry { name: "stat", file_type: FileType::File },
                DirEntry { name: "status", file_type: FileType::File },
                DirEntry { name: "cmdline", file_type: FileType::File },
                DirEntry { name: "maps", file_type: FileType::File },
                DirEntry { name: "comm", file_type: FileType::File },
                // Extended flat files.
                DirEntry { name: "io", file_type: FileType::File },
                DirEntry { name: "sched", file_type: FileType::File },
                DirEntry { name: "schedstat", file_type: FileType::File },
                DirEntry { name: "stack", file_type: FileType::File },
                DirEntry { name: "wchan", file_type: FileType::File },
                DirEntry { name: "syscall", file_type: FileType::File },
                DirEntry { name: "environ", file_type: FileType::File },
                DirEntry { name: "auxv", file_type: FileType::File },
                DirEntry { name: "limits", file_type: FileType::File },
                DirEntry { name: "oom_score", file_type: FileType::File },
                DirEntry { name: "oom_score_adj", file_type: FileType::File },
                DirEntry { name: "coredump_filter", file_type: FileType::File },
                DirEntry { name: "mountinfo", file_type: FileType::File },
                DirEntry { name: "mountstats", file_type: FileType::File },
                DirEntry { name: "personality", file_type: FileType::File },
                DirEntry { name: "cgroup", file_type: FileType::File },
                // Subdirectories.
                DirEntry { name: "fd", file_type: FileType::Dir },
                DirEntry { name: "fdinfo", file_type: FileType::Dir },
                DirEntry { name: "task", file_type: FileType::Dir },
            ]
            .into_iter(),
        )
    }
}

// ── /proc root ──────────────────────────────────────────────────

#[derive(Debug)]
struct ProcRoot;

impl DirOps for ProcRoot {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        match name {
            "cpuinfo" => Some(Arc::new(ProcStaticFile { name: "cpuinfo", gen: gen_cpuinfo })),
            "meminfo" => Some(Arc::new(ProcStaticFile { name: "meminfo", gen: gen_meminfo })),
            "mounts" => Some(Arc::new(ProcStaticFile { name: "mounts", gen: gen_mounts })),
            "uptime" => Some(Arc::new(ProcStaticFile { name: "uptime", gen: gen_uptime })),
            "version" => Some(Arc::new(ProcStaticFile { name: "version", gen: gen_version })),
            "cmdline" => Some(Arc::new(ProcStaticFile { name: "cmdline", gen: gen_cmdline })),
            "loadavg" => Some(Arc::new(ProcStaticFile { name: "loadavg", gen: gen_loadavg })),
            "filesystems" => Some(Arc::new(ProcStaticFile { name: "filesystems", gen: gen_filesystems })),
            "partitions" => Some(Arc::new(ProcStaticFile { name: "partitions", gen: gen_partitions })),
            "sched" => Some(Arc::new(ProcStaticFile { name: "sched", gen: gen_sched })),
            "self" => Some(Arc::new(ProcDirMarker)),
            _ => {
                // Dynamic registry — file or directory marker. The
                // dir marker keeps resolve_async happy so it'll
                // then descend via lookup_dir afterwards.
                if let Some(snap) = lookup_registry(&[name]) {
                    return Some(match snap {
                        ProcNodeSnapshot::File(f) => Arc::new(ProcDynFile { file: f }) as Arc<dyn FileOps>,
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
            DirEntry { name: "cpuinfo", file_type: FileType::File },
            DirEntry { name: "meminfo", file_type: FileType::File },
            DirEntry { name: "mounts", file_type: FileType::File },
            DirEntry { name: "uptime", file_type: FileType::File },
            DirEntry { name: "version", file_type: FileType::File },
            DirEntry { name: "cmdline", file_type: FileType::File },
            DirEntry { name: "loadavg", file_type: FileType::File },
            DirEntry { name: "filesystems", file_type: FileType::File },
            DirEntry { name: "partitions", file_type: FileType::File },
            DirEntry { name: "sched", file_type: FileType::File },
            DirEntry { name: "self", file_type: FileType::Dir },
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
            entries.push(DirEntry { name: leaked, file_type: FileType::Dir });
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
                DirEntry { name: leaked, file_type }
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
        let model_name = if brand.is_empty() {
            "(unknown)"
        } else {
            brand
        };
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
        let _ = writeln!(s, "");
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = writeln!(s, "processor\t: 0");
        let _ = writeln!(s, "vendor_id\t: NARF");
        let _ = writeln!(s, "model name\t: (arch ident not yet wired)");
        let _ = writeln!(s, "");
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
        let _ = core::fmt::Write::write_fmt(
            &mut s,
            format_args!("none {} {} rw 0 0\n", path, fs_name),
        );
    }
    s
}

fn gen_cmdline() -> String {
    let mut s = String::from(narf_boot::cmdline());
    s.push('\n');
    s
}

fn gen_loadavg() -> String {
    // Linux format: "0.00 0.00 0.00 1/1 1\n"
    //   1/5/15-min averages | runnable/total | last_pid
    // We don't track EWMA averages today; report the same
    // instantaneous total task count for all three slots so the
    // standard parsers (`uptime`, `top`, `glibc::getloadavg`)
    // produce a meaningful number rather than zeros. last_pid is
    // approximated by the number of live tasks.
    let n = narf_scheduler::all_task_ids().len();
    format!("{n}.00 {n}.00 {n}.00 {n}/{n} {n}\n")
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
    format!(
        "{} ({}) {} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0\n",
        info.pid, info.comm, info.state,
    )
}

fn render_status(info: &ProcTaskInfo) -> String {
    let mut s = String::new();
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("Name:\t{}\n", info.comm));
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("State:\t{} ({})\n",
        info.state,
        match info.state {
            'R' => "running",
            'S' => "sleeping",
            'Z' => "zombie",
            _ => "unknown",
        },
    ));
    let _ = core::fmt::Write::write_fmt(&mut s, format_args!("Pid:\t{}\n", info.pid));
    let _ = core::fmt::Write::write_fmt(
        &mut s,
        format_args!("VmStk:\t{} kB\n", info.stack_top / 1024),
    );
    let _ = core::fmt::Write::write_fmt(
        &mut s,
        format_args!("VmData:\t{} kB\n", info.brk_top / 1024),
    );
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
            let _ = core::fmt::Write::write_fmt(
                &mut s,
                format_args!("          {}", v.label),
            );
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
        Arc::new(TestProcFile { body: payload.clone() }),
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
        Arc::new(TestProcFile { body: alloc::vec![0u8; 4] }),
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
        Arc::new(TestProcFile { body: alloc::vec![0u8; 1] }),
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
