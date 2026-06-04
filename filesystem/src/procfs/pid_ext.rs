//! Extended per-pid `/proc/<pid>/*` files.
//!
//! Each file is a zero-allocation generator that pulls a snapshot
//! from the kernel via fn-pointer hooks wired in at boot.  If a
//! particular counter or datum isn't tracked yet, the file renders
//! the correct Linux shape filled with zeros and carries a
//! `# TODO:` comment in the source — tooling parses structure,
//! not non-zero values.
//!
//! Linux refs:
//!   `fs/proc/base.c`    — per-pid file dispatch table
//!   `fs/proc/array.c`   — stat/status/sched renderers
//!   `fs/proc/fd.c`      — fd + fdinfo directories
//!   `fs/proc/task_mmu.c`— maps/smaps helpers

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};

use super::{
    hook_auxv, hook_coredump_get, hook_coredump_set, hook_environ, hook_fd_path, hook_nice,
    hook_oom_adj_get, hook_oom_adj_set, hook_oom_score, hook_rlimits, slice_read, task_info,
    ProcDirMarker,
};

// ── Extended flat-file enum ─────────────────────────────────────────

/// Extended per-pid file variants (beyond the core five).
#[derive(Copy, Clone, Debug)]
pub enum PidExtField {
    Io,
    Sched,
    Schedstat,
    Stack,
    Wchan,
    Syscall,
    Environ,
    Auxv,
    Limits,
    OomScore,
    OomScoreAdj,
    CoredumpFilter,
    Mountinfo,
    Mountstats,
    Personality,
    Cgroup,
}

/// A single extended per-pid file with bound `pid`.
#[derive(Debug)]
pub struct PidExtFile {
    pub pid: u64,
    pub field: PidExtField,
}

impl FileOps for PidExtFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let pid = self.pid;
        let field = self.field;
        Box::pin(async move {
            let bytes = render_ext(pid, field);
            slice_read(&bytes, offset, buf)
        })
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let pid = self.pid;
        let field = self.field;
        Box::pin(async move {
            match field {
                PidExtField::OomScoreAdj => {
                    let s = core::str::from_utf8(buf.trim_ascii_end())
                        .map_err(|_| FsError::InvalidData)?;
                    let val: i32 = s.parse().map_err(|_| FsError::InvalidData)?;
                    // Linux: range -1000..=1000; reject out-of-range.
                    if !(-1000..=1000).contains(&val) {
                        return Err(FsError::InvalidData);
                    }
                    hook_oom_adj_set(pid, val as i16).map_err(|_| FsError::InvalidData)?;
                    Ok(buf.len())
                }
                PidExtField::CoredumpFilter => {
                    let s = core::str::from_utf8(buf.trim_ascii_end())
                        .map_err(|_| FsError::InvalidData)?;
                    let stripped = s
                        .strip_prefix("0x")
                        .or_else(|| s.strip_prefix("0X"))
                        .unwrap_or(s);
                    let bits =
                        u32::from_str_radix(stripped, 16).map_err(|_| FsError::InvalidData)?;
                    hook_coredump_set(pid, bits).map_err(|_| FsError::InvalidData)?;
                    Ok(buf.len())
                }
                _ => Err(FsError::ReadOnly),
            }
        })
    }
    fn stat(&self) -> Stat {
        let writable = matches!(
            self.field,
            PidExtField::OomScoreAdj | PidExtField::CoredumpFilter
        );
        Stat {
            size: 0,
            blocks: 0,
            mode: if writable {
                Mode::FILE_RW
            } else {
                Mode::FILE_RO
            },
            mtime_cycles: 0,
        }
    }
}

/// Look up an extended per-pid file by `name` for `pid`.  Returns
/// `None` when the name is unknown — the caller falls through or
/// returns an error.
pub fn lookup_pid_ext(pid: u64, name: &str) -> Option<PidExtFile> {
    let field = match name {
        "io" => PidExtField::Io,
        "sched" => PidExtField::Sched,
        "schedstat" => PidExtField::Schedstat,
        "stack" => PidExtField::Stack,
        "wchan" => PidExtField::Wchan,
        "syscall" => PidExtField::Syscall,
        "environ" => PidExtField::Environ,
        "auxv" => PidExtField::Auxv,
        "limits" => PidExtField::Limits,
        "oom_score" => PidExtField::OomScore,
        "oom_score_adj" => PidExtField::OomScoreAdj,
        "coredump_filter" => PidExtField::CoredumpFilter,
        "mountinfo" => PidExtField::Mountinfo,
        "mountstats" => PidExtField::Mountstats,
        "personality" => PidExtField::Personality,
        "cgroup" => PidExtField::Cgroup,
        _ => return None,
    };
    Some(PidExtFile { pid, field })
}

// ── Renderers ───────────────────────────────────────────────────────

fn render_ext(pid: u64, field: PidExtField) -> Vec<u8> {
    match field {
        PidExtField::Io => render_io(pid).into_bytes(),
        PidExtField::Sched => render_sched(pid).into_bytes(),
        PidExtField::Schedstat => render_schedstat(pid).into_bytes(),
        PidExtField::Stack => render_stack(pid).into_bytes(),
        PidExtField::Wchan => render_wchan(pid).into_bytes(),
        PidExtField::Syscall => render_syscall(pid).into_bytes(),
        PidExtField::Environ => hook_environ(pid),
        PidExtField::Auxv => hook_auxv(pid),
        PidExtField::Limits => render_limits(pid).into_bytes(),
        PidExtField::OomScore => {
            let score = hook_oom_score(pid);
            format!("{}\n", score).into_bytes()
        }
        PidExtField::OomScoreAdj => {
            let adj = hook_oom_adj_get(pid);
            format!("{}\n", adj).into_bytes()
        }
        PidExtField::CoredumpFilter => {
            let bits = hook_coredump_get(pid);
            format!("{:x}\n", bits).into_bytes()
        }
        PidExtField::Mountinfo => render_mountinfo(pid).into_bytes(),
        PidExtField::Mountstats => render_mountstats(pid).into_bytes(),
        PidExtField::Personality => b"00000000\n".to_vec(),
        PidExtField::Cgroup => {
            // Linux shape: "hierarchy_id:subsystems:path\n" per cgroup.
            // NARF has no cgroups; report the single default hierarchy.
            b"0::/\n".to_vec()
        }
    }
}

/// `/proc/<pid>/io` — per-process I/O accounting.
///
/// Linux ref: `fs/proc/base.c:proc_tid_io_accounting`.
/// TODO: Hook into the fd table's byte-transfer counters once those
/// are tracked per task; today all fields are zero.
fn render_io(_pid: u64) -> String {
    // TODO: wire rchar/wchar/syscr/syscw/read_bytes/write_bytes from
    // the per-task fd-table I/O counters once those land.
    let mut s = String::new();
    let _ = writeln!(s, "rchar: 0");
    let _ = writeln!(s, "wchar: 0");
    let _ = writeln!(s, "syscr: 0");
    let _ = writeln!(s, "syscw: 0");
    let _ = writeln!(s, "read_bytes: 0");
    let _ = writeln!(s, "write_bytes: 0");
    let _ = writeln!(s, "cancelled_write_bytes: 0");
    s
}

/// `/proc/<pid>/sched` — scheduler statistics for a task.
///
/// Linux ref: `fs/proc/array.c:sched_show_task`.
/// TODO: Pull real counters from the scheduler once per-task runtime
/// accounting lands in narf_scheduler.
fn render_sched(pid: u64) -> String {
    let comm = task_info(pid)
        .map(|i| i.comm)
        .unwrap_or_else(|| format!("task-{}", pid));
    let nice = hook_nice(pid);
    let mut s = String::new();
    let _ = writeln!(s, "{} ({}, #threads: 1)", comm, pid);
    let _ = writeln!(
        s,
        "-------------------------------------------------------------------"
    );
    // TODO: pull real ns-resolution runtime from narf_scheduler task stats.
    let _ = writeln!(s, "se.exec_start                      :          0.000000");
    let _ = writeln!(s, "se.sum_exec_runtime                :          0.000000");
    let _ = writeln!(s, "se.statistics.wait_start           :          0.000000");
    let _ = writeln!(s, "se.statistics.sleep_start          :          0.000000");
    let _ = writeln!(s, "se.statistics.block_start          :          0.000000");
    let _ = writeln!(s, "se.statistics.sleep_max            :          0.000000");
    let _ = writeln!(s, "se.statistics.block_max            :          0.000000");
    let _ = writeln!(s, "se.statistics.exec_max             :          0.000000");
    let _ = writeln!(s, "se.statistics.slice_max            :          0.000000");
    let _ = writeln!(s, "se.statistics.wait_max             :          0.000000");
    let _ = writeln!(s, "se.statistics.wait_sum             :          0.000000");
    let _ = writeln!(s, "se.statistics.wait_count           :                 0");
    let _ = writeln!(s, "se.statistics.iowait_sum           :          0.000000");
    let _ = writeln!(s, "se.statistics.iowait_count         :                 0");
    let _ = writeln!(s, "se.nr_migrations                   :                 0");
    // TODO: pull nr_voluntary_switches / nr_involuntary_switches from
    // the scheduler's task-switch accounting once that lands.
    let _ = writeln!(s, "nr_voluntary_switches              :                 0");
    let _ = writeln!(s, "nr_involuntary_switches            :                 0");
    let _ = writeln!(s, "se.load.weight                     :              1024");
    let _ = writeln!(s, "se.avg.load_sum                    :                 0");
    let _ = writeln!(s, "se.avg.util_sum                    :                 0");
    let _ = writeln!(s, "se.avg.load_avg                    :                 0");
    let _ = writeln!(s, "se.avg.util_avg                    :                 0");
    let _ = writeln!(s, "se.avg.last_update_time            :                 0");
    let _ = writeln!(s, "policy                             :                 0");
    let _ = writeln!(
        s,
        "prio                               :               {}",
        20 + nice
    );
    let _ = writeln!(s, "clock-delta                        :                 0");
    s
}

/// `/proc/<pid>/schedstat` — three integers on one line.
///
/// Linux shape: `run_time_ns wait_time_ns timeslices\n`
/// Linux ref: `kernel/sched/stats.c:proc_schedstat_show`.
/// TODO: wire real ns counters from narf_scheduler task stats.
fn render_schedstat(_pid: u64) -> String {
    // TODO: pull run_time_ns / wait_time_ns / timeslices from
    // narf_scheduler per-task accounting once that lands.
    format!("0 0 0\n")
}

/// `/proc/<pid>/stack` — kernel-stack backtrace (privileged).
///
/// Linux ref: `fs/proc/base.c:proc_pid_stack`.
/// NARF has no unwinder yet; return a stub line that won't confuse parsers.
fn render_stack(_pid: u64) -> String {
    // TODO: walk the kernel stack frame chain once an unwinder is
    // available in narf_arch.
    format!("[<0000000000000000>] 0x0\n")
}

/// `/proc/<pid>/wchan` — symbol where the task is currently sleeping.
///
/// Linux ref: `fs/proc/base.c:proc_wchan_operations`.
/// TODO: surface the actual sleep-site once the scheduler exposes a
/// per-task "parked in" symbol handle.
fn render_wchan(pid: u64) -> String {
    let state = task_info(pid).map(|i| i.state).unwrap_or('R');
    if state == 'S' {
        // TODO: return the real wait-channel symbol name once
        // narf_scheduler exposes per-task sleep-site info.
        format!("sys_sleep\n")
    } else {
        format!("0\n")
    }
}

/// `/proc/<pid>/syscall` — current syscall number + args.
///
/// Linux ref: `fs/proc/base.c:proc_pid_syscall`.
/// Format: `syscall_nr arg0 arg1 arg2 arg3 arg4 arg5 sp pc\n`
/// or `"running\n"` when the task is not blocked in a syscall.
/// TODO: expose the saved syscall-entry frame from the trap path.
fn render_syscall(pid: u64) -> String {
    let state = task_info(pid).map(|i| i.state).unwrap_or('R');
    if state == 'R' {
        format!("running\n")
    } else {
        // TODO: read the saved trap frame (syscall nr + args + rsp/rip)
        // from narf_userspace::handlers once it exposes a per-task
        // snapshot accessor for the saved int 0x80 frame.
        format!("-1 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0\n")
    }
}

/// `/proc/<pid>/limits` — resource limit table.
///
/// Linux shape: one line per RLIMIT_* resource:
///   `Limit  Soft Limit  Hard Limit  Units`
/// Linux ref: `fs/proc/base.c:proc_pid_limits`.
fn render_limits(pid: u64) -> String {
    const NAMES: [&str; 16] = [
        "Max cpu time",
        "Max file size",
        "Max data size",
        "Max stack size",
        "Max core file size",
        "Max resident set",
        "Max processes",
        "Max open files",
        "Max locked memory",
        "Max address space",
        "Max file locks",
        "Max pending signals",
        "Max msgqueue size",
        "Max nice priority",
        "Max realtime priority",
        "Max realtime timeout",
    ];
    const UNITS: [&str; 16] = [
        "seconds",
        "bytes",
        "bytes",
        "bytes",
        "bytes",
        "bytes",
        "processes",
        "files",
        "bytes",
        "bytes",
        "locks",
        "signals",
        "bytes",
        "",
        "",
        "us",
    ];
    let pairs = hook_rlimits(pid);
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:<25} {:<20} {:<20} {}",
        "Limit", "Soft Limit", "Hard Limit", "Units"
    );
    for i in 0..16 {
        let (cur, max) = pairs[i];
        const RLIM_INFINITY: u64 = !0u64;
        let soft = if cur == RLIM_INFINITY {
            "unlimited".to_string()
        } else {
            cur.to_string()
        };
        let hard = if max == RLIM_INFINITY {
            "unlimited".to_string()
        } else {
            max.to_string()
        };
        let _ = writeln!(s, "{:<25} {:<20} {:<20} {}", NAMES[i], soft, hard, UNITS[i]);
    }
    s
}

/// `/proc/<pid>/mountinfo` — per-task mount namespace view.
///
/// Linux ref: `fs/proc_namespace.c:show_mountinfo`.
/// NARF has no per-task mount namespaces yet; expose the global
/// VfsRegistry.  Format per line:
///   `mount_id parent_id major:minor root mount_point opts - fstype source opts`
fn render_mountinfo(_pid: u64) -> String {
    let mut s = String::new();
    let mut id = 1u32;
    for (path, fs_name) in crate::registry().list_with_names() {
        let _ = writeln!(s, "{} 0 0:1 / {} rw - {} {} rw", id, path, fs_name, fs_name);
        id += 1;
    }
    if s.is_empty() {
        // Guarantee at least one line so parsers don't fail.
        let _ = writeln!(s, "1 0 0:1 / / rw - rootfs rootfs rw");
    }
    s
}

/// `/proc/<pid>/mountstats` — per-task mount stats.
///
/// Linux ref: `fs/proc_namespace.c:show_mountstats`.
/// NARF doesn't track per-mount I/O stats yet; render the mounts
/// with zero counters so `mount -v` parsers see valid structure.
fn render_mountstats(_pid: u64) -> String {
    let mut s = String::new();
    for (path, fs_name) in crate::registry().list_with_names() {
        let _ = writeln!(
            s,
            "device {} mounted on {} with fstype {}",
            fs_name, path, fs_name
        );
    }
    if s.is_empty() {
        let _ = writeln!(s, "device rootfs mounted on / with fstype rootfs");
    }
    s
}

// ── /proc/<pid>/fd/<n> directory ────────────────────────────────────

/// Directory presenting the per-pid `fd/` subtree.  Each numeric
/// child returns the fd's backing name via the `FD_PATH_HOOK`.
///
/// Linux ref: `fs/proc/fd.c:proc_fd_instantiate`.
#[derive(Debug)]
pub struct ProcFdDir {
    pub pid: u64,
}

/// Single fd pseudo-symlink file — returns the fd backing path as
/// its read content.  Linux: these are actual symlinks; NARF models
/// them as readable files for now.
#[derive(Debug)]
struct ProcFdFile {
    pid: u64,
    fd: u32,
}

impl FileOps for ProcFdFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let pid = self.pid;
        let fd = self.fd;
        Box::pin(async move {
            let path = hook_fd_path(pid, fd).unwrap_or_else(|| format!("anon_inode:[unknown]"));
            let bytes = path.into_bytes();
            slice_read(&bytes, offset, buf)
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
}

impl DirOps for ProcFdDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let fd: u32 = name.parse().ok()?;
        // Validate the fd exists before returning a file node.
        hook_fd_path(self.pid, fd)?;
        Some(Arc::new(ProcFdFile { pid: self.pid, fd }))
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        // Walk up to 256 fds; emit a DirEntry for each valid fd.
        // TODO: expose a proper fd-table enumerator from narf_userspace::fd
        // once that crate has a snapshot-of-pid API.
        let mut entries: Vec<DirEntry> = Vec::new();
        for n in 0u32..256 {
            if hook_fd_path(self.pid, n).is_none() {
                if n > 0 {
                    break;
                }
                continue;
            }
            let s = n.to_string();
            let leaked: &'static str = Box::leak(s.into_boxed_str());
            entries.push(DirEntry {
                name: leaked,
                file_type: FileType::File,
            });
        }
        Box::new(entries.into_iter())
    }
}

// ── /proc/<pid>/fdinfo/<n> directory ────────────────────────────────

/// Directory presenting the per-pid `fdinfo/` subtree.
///
/// Linux ref: `fs/proc/fd.c:proc_fdinfo_instantiate`.
#[derive(Debug)]
pub struct ProcFdInfoDir {
    pub pid: u64,
}

/// Single fdinfo file.  Renders `pos`, `flags`, `mnt_id` fields.
///
/// Linux ref: `fs/proc/fd.c:seq_show_fdinfo`.
#[derive(Debug)]
struct ProcFdInfoFile {
    pid: u64,
    fd: u32,
}

impl FileOps for ProcFdInfoFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let pid = self.pid;
        let fd = self.fd;
        Box::pin(async move {
            let mut s = String::new();
            // pos: file position offset.
            // TODO: read offset from FdEntry once fd table exposes snapshot-of-pid.
            let _ = writeln!(s, "pos:\t0");
            // flags: open-file status flags.
            // TODO: map FdEntry::flags to the O_* bitfield.
            let _ = writeln!(s, "flags:\t0100002");
            // mnt_id: mount-table ID. Always 1 until per-mount id allocator lands.
            let _ = writeln!(s, "mnt_id:\t1");
            if let Some(path) = hook_fd_path(pid, fd) {
                let _ = writeln!(s, "# backing: {}", path);
            }
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
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
}

impl DirOps for ProcFdInfoDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let fd: u32 = name.parse().ok()?;
        hook_fd_path(self.pid, fd)?; // validate fd exists
        Some(Arc::new(ProcFdInfoFile { pid: self.pid, fd }))
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        let mut entries: Vec<DirEntry> = Vec::new();
        for n in 0u32..256 {
            if hook_fd_path(self.pid, n).is_none() {
                if n > 0 {
                    break;
                }
                continue;
            }
            let s = n.to_string();
            let leaked: &'static str = Box::leak(s.into_boxed_str());
            entries.push(DirEntry {
                name: leaked,
                file_type: FileType::File,
            });
        }
        Box::new(entries.into_iter())
    }
}

// ── /proc/<pid>/task/<tid> directory ────────────────────────────────

/// `/proc/<pid>/task/` directory.  NARF has no separate thread IDs
/// yet — each task is its own thread group.  One entry: tid == pid.
///
/// Linux ref: `fs/proc/base.c:proc_task_readdir`.
#[derive(Debug)]
pub struct ProcTaskDir {
    pub pid: u64,
}

/// `/proc/<pid>/task/<tid>/` — exposes `comm` for the thread.
#[derive(Debug)]
struct ProcTaskTidDir {
    pid: u64,
}

/// `/proc/<pid>/task/<tid>/comm`
#[derive(Debug)]
struct ProcTaskTidComm {
    pid: u64,
}

impl FileOps for ProcTaskTidComm {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let pid = self.pid;
        Box::pin(async move {
            let comm = task_info(pid)
                .map(|i| i.comm)
                .unwrap_or_else(|| format!("task-{}", pid));
            let s = format!("{}\n", comm);
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
            mode: Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
}

impl DirOps for ProcTaskTidDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        match name {
            "comm" => Some(Arc::new(ProcTaskTidComm { pid: self.pid })),
            _ => None,
        }
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        Box::new(
            [DirEntry {
                name: "comm",
                file_type: FileType::File,
            }]
            .into_iter(),
        )
    }
}

impl DirOps for ProcTaskDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let tid: u64 = name.parse().ok()?;
        if tid == self.pid {
            Some(Arc::new(ProcDirMarker))
        } else {
            None
        }
    }
    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let tid: u64 = name.parse().ok()?;
        if tid == self.pid {
            Some(Arc::new(ProcTaskTidDir { pid: self.pid }))
        } else {
            None
        }
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        let s = self.pid.to_string();
        let leaked: &'static str = Box::leak(s.into_boxed_str());
        Box::new(
            [DirEntry {
                name: leaked,
                file_type: FileType::Dir,
            }]
            .into_iter(),
        )
    }
}

// ── Smoke tests ─────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// Smoke: `render_io` produces an "rchar:" line.
fn smoke_io_has_rchar_line() -> TestResult {
    let out = render_io(1);
    if out.contains("rchar:") {
        TestResult::Pass
    } else {
        TestResult::Fail("render_io missing 'rchar:' line")
    }
}
kernel_test_in!("filesystem/procfs/pid_ext", smoke_io_has_rchar_line);

/// Smoke: `render_sched` contains "exec_runtime" substring.
fn smoke_sched_contains_exec_runtime() -> TestResult {
    let out = render_sched(1);
    if out.contains("exec_runtime") {
        TestResult::Pass
    } else {
        TestResult::Fail("render_sched missing exec_runtime field")
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_sched_contains_exec_runtime
);

/// Smoke: `render_schedstat` is exactly "0 0 0\n".
fn smoke_schedstat_shape() -> TestResult {
    let out = render_schedstat(1);
    if out == "0 0 0\n" {
        TestResult::Pass
    } else {
        TestResult::Fail("render_schedstat wrong shape")
    }
}
kernel_test_in!("filesystem/procfs/pid_ext", smoke_schedstat_shape);

/// Smoke: `render_limits` has exactly 17 lines (header + 16 resources).
fn smoke_limits_has_16_resource_lines() -> TestResult {
    let out = render_limits(1);
    let count = out.lines().count();
    if count == 17 {
        TestResult::Pass
    } else {
        TestResult::Fail("render_limits should have 17 lines (1 header + 16 resources)")
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_limits_has_16_resource_lines
);

/// Smoke: `render_mountinfo` produces at least 1 line.
fn smoke_mountinfo_at_least_one_line() -> TestResult {
    let out = render_mountinfo(1);
    if out.lines().count() >= 1 {
        TestResult::Pass
    } else {
        TestResult::Fail("render_mountinfo produced no lines")
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_mountinfo_at_least_one_line
);

/// Smoke: `render_wchan` for an unknown pid (no task-info hook)
/// returns "0\n" because the fallback state is 'R'.
fn smoke_wchan_unknown_pid_returns_zero() -> TestResult {
    let out = render_wchan(u64::MAX);
    if out == "0\n" {
        TestResult::Pass
    } else {
        TestResult::Fail("render_wchan for unknown pid should be '0\\n'")
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_wchan_unknown_pid_returns_zero
);

/// Smoke: AT_NULL (16 zero bytes) is always at the tail of the
/// auxv returned by `hook_auxv` when no AUXV hook is installed.
fn smoke_auxv_has_at_null_terminator() -> TestResult {
    let bytes = hook_auxv(1);
    if bytes.len() < 16 {
        return TestResult::Fail("auxv too short (< 16 bytes)");
    }
    let tail = &bytes[bytes.len() - 16..];
    if tail.iter().all(|&b| b == 0) {
        TestResult::Pass
    } else {
        TestResult::Fail("auxv missing AT_NULL (0,0) terminator at tail")
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_auxv_has_at_null_terminator
);

/// Smoke: `hook_environ` with no hook installed returns empty bytes.
fn smoke_environ_empty_without_hook() -> TestResult {
    let empty = hook_environ(u64::MAX);
    if empty.is_empty() {
        TestResult::Pass
    } else {
        TestResult::Fail("environ without hook should be empty")
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_environ_empty_without_hook
);

/// Smoke: `ProcFdDir::lookup` with no FD_PATH hook returns None.
fn smoke_fd_lookup_no_hook_returns_none() -> TestResult {
    let dir = ProcFdDir { pid: 1 };
    match dir.lookup("0") {
        None => TestResult::Pass,
        Some(_) => TestResult::Fail("fd lookup without hook should return None"),
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_fd_lookup_no_hook_returns_none
);

/// Smoke: `ProcTaskDir::lookup` returns Some for own tid, None otherwise.
fn smoke_task_dir_own_tid_only() -> TestResult {
    let dir = ProcTaskDir { pid: 42 };
    let own = dir.lookup("42");
    let other = dir.lookup("99");
    if own.is_some() && other.is_none() {
        TestResult::Pass
    } else {
        TestResult::Fail("task dir should expose only own tid")
    }
}
kernel_test_in!("filesystem/procfs/pid_ext", smoke_task_dir_own_tid_only);

/// Smoke: `oom_score_adj` + `coredump_filter` are writable; `oom_score` is read-only.
fn smoke_writable_files_have_rw_mode() -> TestResult {
    let adj = PidExtFile {
        pid: 1,
        field: PidExtField::OomScoreAdj,
    };
    let cd = PidExtFile {
        pid: 1,
        field: PidExtField::CoredumpFilter,
    };
    let score = PidExtFile {
        pid: 1,
        field: PidExtField::OomScore,
    };
    if adj.stat().mode == Mode::FILE_RW
        && cd.stat().mode == Mode::FILE_RW
        && score.stat().mode == Mode::FILE_RO
    {
        TestResult::Pass
    } else {
        TestResult::Fail("oom_score_adj/coredump_filter should be RW; oom_score RO")
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_writable_files_have_rw_mode
);

/// Smoke: oom_score reads back "0\n" (no hook installed → 0).
fn smoke_oom_score_reads_back_zero() -> TestResult {
    use super::poll_once;
    let f = PidExtFile {
        pid: 1,
        field: PidExtField::OomScore,
    };
    let mut buf = [0u8; 64];
    match poll_once(f.read(0, &mut buf)) {
        Some(Ok(n)) if n > 0 => {
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
            // Value must be a decimal integer in 0..=1000 + "\n".
            let trimmed = s.trim();
            match trimmed.parse::<i32>() {
                Ok(v) if (0..=1000).contains(&v) => TestResult::Pass,
                _ => TestResult::Fail("oom_score not in 0..=1000 range"),
            }
        }
        _ => TestResult::Fail("oom_score read failed"),
    }
}
kernel_test_in!("filesystem/procfs/pid_ext", smoke_oom_score_reads_back_zero);

/// Smoke: coredump_filter default returns "33\n" (no hook → 0x33).
fn smoke_coredump_filter_default() -> TestResult {
    use super::poll_once;
    let f = PidExtFile {
        pid: 1,
        field: PidExtField::CoredumpFilter,
    };
    let mut buf = [0u8; 64];
    match poll_once(f.read(0, &mut buf)) {
        Some(Ok(n)) if n > 0 => {
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
            if s.trim() == "33" {
                TestResult::Pass
            } else {
                TestResult::Fail("coredump_filter default should be '33'")
            }
        }
        _ => TestResult::Fail("coredump_filter read failed"),
    }
}
kernel_test_in!("filesystem/procfs/pid_ext", smoke_coredump_filter_default);

/// Stub hooks used by the procfs write-validation smokes so the
/// validation path runs without depending on `install_all_hooks`
/// from the frame crate (which isn't called in `cargo xtask test`).
fn _stub_set_comm(_pid: u64, _name: &str) -> Result<(), FsError> {
    Ok(())
}
fn _stub_oom_adj_get(_pid: u64) -> i16 {
    0
}
fn _stub_oom_adj_set(_pid: u64, _val: i16) -> Result<(), FsError> {
    Ok(())
}
fn _stub_coredump_get(_pid: u64) -> u32 {
    0
}
fn _stub_coredump_set(_pid: u64, _val: u32) -> Result<(), FsError> {
    Ok(())
}
fn _stub_oom_score(_pid: u64) -> i32 {
    0
}

fn _install_stub_proc_write_hooks() {
    super::install_proc_write_hooks(
        _stub_set_comm,
        _stub_oom_adj_get,
        _stub_oom_adj_set,
        _stub_coredump_get,
        _stub_coredump_set,
        _stub_oom_score,
    );
}

/// Smoke: oom_score_adj write "100" is accepted; "1500" is rejected.
fn smoke_oom_score_adj_write_validation() -> TestResult {
    use super::poll_once;
    _install_stub_proc_write_hooks();
    // Valid write: "100\n".
    let f = PidExtFile {
        pid: 1,
        field: PidExtField::OomScoreAdj,
    };
    let ok = poll_once(f.write(0, b"100\n"));
    let reject = poll_once(f.write(0, b"1500\n"));
    let reject_neg = poll_once(f.write(0, b"-1001\n"));
    match (ok, reject, reject_neg) {
        (Some(Ok(_)), Some(Err(FsError::InvalidData)), Some(Err(FsError::InvalidData))) => {
            TestResult::Pass
        }
        _ => TestResult::Fail("oom_score_adj write validation wrong"),
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_oom_score_adj_write_validation
);

/// Smoke: coredump_filter write "ff" roundtrips; invalid hex rejected.
fn smoke_coredump_filter_write_validation() -> TestResult {
    use super::poll_once;
    _install_stub_proc_write_hooks();
    let f = PidExtFile {
        pid: 1,
        field: PidExtField::CoredumpFilter,
    };
    let ok = poll_once(f.write(0, b"ff\n"));
    let bad = poll_once(f.write(0, b"zz\n"));
    match (ok, bad) {
        (Some(Ok(_)), Some(Err(FsError::InvalidData))) => TestResult::Pass,
        _ => TestResult::Fail("coredump_filter write validation wrong"),
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_coredump_filter_write_validation
);

/// Smoke: fdinfo file contains "pos:" and "flags:" lines.
fn smoke_fdinfo_has_pos_and_flags() -> TestResult {
    use super::poll_once;
    let f = ProcFdInfoFile { pid: 1, fd: 0 };
    let mut buf = [0u8; 256];
    match poll_once(f.read(0, &mut buf)) {
        Some(Ok(n)) if n > 0 => {
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
            if s.contains("pos:") && s.contains("flags:") {
                TestResult::Pass
            } else {
                TestResult::Fail("fdinfo missing 'pos:' or 'flags:'")
            }
        }
        _ => TestResult::Fail("fdinfo read failed"),
    }
}
kernel_test_in!("filesystem/procfs/pid_ext", smoke_fdinfo_has_pos_and_flags);
