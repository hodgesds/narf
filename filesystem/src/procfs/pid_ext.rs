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
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat};

use super::{
    hook_auxv, hook_coredump_get, hook_coredump_set, hook_cwd_path, hook_environ, hook_exe_path,
    hook_fd_info, hook_fd_list, hook_fd_path, hook_fd_pidfd_pid, hook_nice,
    hook_ns_mountinfo_generation, hook_oom_adj_get, hook_oom_adj_set, hook_oom_score, hook_rlimits,
    hook_root_path, slice_read, task_info, ProcDirMarker,
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
    /// `/proc/<pid>/mounts` — the per-pid mount table (same shape as
    /// /proc/mounts). systemd + util-linux read it to enumerate mounts.
    Mounts,
    Personality,
    Cgroup,
    /// `/proc/<pid>/loginuid` — the audit login uid. Writable:
    /// systemd-logind stamps it on session setup.
    /// Linux ref: `kernel/audit.c:audit_set_loginuid` via `fs/proc/base.c`.
    Loginuid,
    /// `/proc/<pid>/sessionid` — the audit session id (read-only).
    Sessionid,
    /// `/proc/<pid>/setgroups` — user-ns "allow"/"deny" for setgroups(2)
    /// inside the namespace. Writable one-shot; defaults to "allow".
    Setgroups,
    /// `/proc/<pid>/statm` — 7-field page-count memory summary.
    /// Linux ref: `fs/proc/array.c:proc_pid_statm`.
    Statm,
    /// `/proc/<pid>/exe` — magic symlink to the task's executable image.
    /// Linux ref: `fs/proc/base.c:proc_exe_link`.
    Exe,
    /// `/proc/<pid>/cwd` — magic symlink to the task's current working dir.
    /// Linux ref: `fs/proc/base.c:proc_cwd_link`.
    Cwd,
    /// `/proc/<pid>/root` — magic symlink to the task's root (chroot/ns root).
    /// Linux ref: `fs/proc/base.c:proc_root_link`.
    Root,
}

/// A single extended per-pid file with bound `pid`.
#[derive(Debug)]
pub struct PidExtFile {
    pub pid: u64,
    pub field: PidExtField,
    mountinfo_generation: AtomicU64,
}

impl PidExtFile {
    pub fn new(pid: u64, field: PidExtField) -> Self {
        Self {
            pid,
            field,
            mountinfo_generation: AtomicU64::new(hook_ns_mountinfo_generation(pid)),
        }
    }
}

impl FileOps for PidExtFile {
    fn poll_readiness(&self) -> u32 {
        if !matches!(self.field, PidExtField::Mountinfo) {
            return crate::POLL_IN | crate::POLL_OUT;
        }
        let current = hook_ns_mountinfo_generation(self.pid);
        let observed = self.mountinfo_generation.load(Ordering::Acquire);
        // mountinfo remains an ordinary readable proc file. Linux adds the
        // mount-namespace change edge to that normal readiness rather than
        // replacing it; libmount may read its initial table before it arms
        // the POLLPRI monitor.
        let mut ready = crate::POLL_IN | crate::POLL_OUT;
        if current != observed {
            // Linux's proc_mounts_poll() returns both EPOLLPRI and EPOLLERR
            // for a mount-namespace event (fs/proc_namespace.c). libmount
            // treats that pair as its rescan trigger before systemd reaps a
            // successful mount helper.
            ready |= crate::POLL_PRI | crate::POLL_ERR;
        }
        ready
    }

    fn poll_edge_token(&self) -> (u64, u64) {
        if matches!(self.field, PidExtField::Mountinfo) {
            (hook_ns_mountinfo_generation(self.pid), 0)
        } else {
            (0, 0)
        }
    }

    fn acknowledge_poll_readiness(&self, readiness: u32) {
        if matches!(self.field, PidExtField::Mountinfo)
            && readiness & (crate::POLL_PRI | crate::POLL_ERR) != 0
        {
            // `proc_mounts_poll()`'s namespace sequence is per open file.
            // Only the epoll instance that returned this event advances its
            // cursor; a parent epoll merely querying a nested monitor must
            // leave the edge available for the monitor to drain.
            self.mountinfo_generation
                .store(hook_ns_mountinfo_generation(self.pid), Ordering::Release);
        }
    }

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
                PidExtField::Loginuid => {
                    // systemd-logind writes the session's login uid. Accept and
                    // record it; u32::MAX clears it back to "unset".
                    let s = core::str::from_utf8(buf.trim_ascii_end())
                        .map_err(|_| FsError::InvalidData)?;
                    let uid: u32 = s.parse().map_err(|_| FsError::InvalidData)?;
                    loginuid_set(pid, uid);
                    Ok(buf.len())
                }
                PidExtField::Setgroups => {
                    // user-ns "allow"/"deny". NARF has no per-ns setgroups gate
                    // yet, so accept a well-formed value as a no-op rather than
                    // failing the write (systemd/newuidmap expect success).
                    let s = core::str::from_utf8(buf.trim_ascii_end())
                        .map_err(|_| FsError::InvalidData)?;
                    if s == "allow" || s == "deny" {
                        Ok(buf.len())
                    } else {
                        Err(FsError::InvalidData)
                    }
                }
                _ => Err(FsError::ReadOnly),
            }
        })
    }
    fn truncate<'a>(&'a self, _len: u64) -> FsFuture<'a, ()> {
        // These procfs pseudo-files hold a single small value, not sized
        // content. Linux ignores an `ftruncate(2)` on them (the write path
        // that matters is the value write). systemd/pam's audit loginuid
        // setter opens `/proc/self/loginuid` O_RDWR then `ftruncate(fd, 0)`
        // before writing the new uid; the default `FileOps::truncate`
        // returns `Unsupported` (→ EPERM), which aborted that write and made
        // `pam_loginuid` (session required) fail → the whole systemd-user PAM
        // session failed with EXIT_PAM. Accept truncate as a no-op success to
        // match Linux and let the loginuid write proceed. Only writable fields
        // are ever opened O_RDWR, so a no-op here cannot lose read-only data.
        Box::pin(async move { Ok(()) })
    }
    fn stat(&self) -> Stat {
        // Magic symlinks [[proc-magic-links]] must report S_IFLNK so that
        // sys_readlink and the VFS walker treat them correctly. Linux reports
        // st_size == 0 for procfs magic links; readlink uses the caller's
        // buffer length and does not depend on this hint.
        match self.field {
            PidExtField::Exe => {
                return Stat {
                    size: 0,
                    blocks: 0,
                    mode: Mode {
                        file_type: FileType::Symlink,
                        perms: 0o777,
                    },
                    mtime_cycles: 0,
                };
            }
            PidExtField::Cwd => {
                return Stat {
                    size: 0,
                    blocks: 0,
                    mode: Mode {
                        file_type: FileType::Symlink,
                        perms: 0o777,
                    },
                    mtime_cycles: 0,
                };
            }
            PidExtField::Root => {
                return Stat {
                    size: 0,
                    blocks: 0,
                    mode: Mode {
                        file_type: FileType::Symlink,
                        perms: 0o777,
                    },
                    mtime_cycles: 0,
                };
            }
            _ => {}
        }
        let writable = matches!(
            self.field,
            PidExtField::OomScoreAdj
                | PidExtField::CoredumpFilter
                | PidExtField::Loginuid
                | PidExtField::Setgroups
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
        "mounts" => PidExtField::Mounts,
        "personality" => PidExtField::Personality,
        "cgroup" => PidExtField::Cgroup,
        "statm" => PidExtField::Statm,
        "loginuid" => PidExtField::Loginuid,
        "sessionid" => PidExtField::Sessionid,
        "setgroups" => PidExtField::Setgroups,
        // Magic symlinks [[proc-magic-links]].
        "exe" => PidExtField::Exe,
        "cwd" => PidExtField::Cwd,
        "root" => PidExtField::Root,
        _ => return None,
    };
    Some(PidExtFile::new(pid, field))
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
        PidExtField::Mounts => render_mounts(pid).into_bytes(),
        PidExtField::Personality => b"00000000\n".to_vec(),
        PidExtField::Loginuid => {
            // Linux emits the raw uid, or the u32 sentinel (4294967295) when
            // unset. NARF stores per-pid; default = unset.
            let v = loginuid_get(pid);
            match v {
                Some(uid) => format!("{}\n", uid).into_bytes(),
                None => b"4294967295\n".to_vec(),
            }
        }
        PidExtField::Sessionid => {
            // Audit session id: the u32 sentinel means "no session", which is
            // the correct answer until systemd-logind assigns one.
            b"4294967295\n".to_vec()
        }
        PidExtField::Setgroups => {
            // user-ns setgroups policy. Default "allow" (matches a fresh ns
            // before anyone writes "deny").
            b"allow\n".to_vec()
        }
        PidExtField::Statm => render_statm(pid).into_bytes(),
        // Magic symlinks — read() returns the target path verbatim so
        // that sys_readlink (which calls file.read()) gets the string.
        // [[proc-magic-links]] stat() reports S_IFLNK (see PidExtFile::stat).
        PidExtField::Exe => hook_exe_path(pid).unwrap_or_default().into_bytes(),
        PidExtField::Cwd => hook_cwd_path(pid).unwrap_or_default().into_bytes(),
        PidExtField::Root => hook_root_path(pid)
            .unwrap_or_else(|| "/".to_string())
            .into_bytes(),
        PidExtField::Cgroup => {
            // Linux v2 shape: "0::<path>\n". With the cgroup feature
            // this reports the process's real cgroup; otherwise the
            // single default hierarchy (no cgroups present).
            #[cfg(feature = "cgroup")]
            {
                // Render relative to the READER's cgroup namespace (Linux
                // semantics), not the target's — see proc_pid_cgroup.
                crate::cgroupfs::proc_pid_cgroup(pid, crate::procfs::current_outer_pid())
            }
            #[cfg(not(feature = "cgroup"))]
            {
                b"0::/\n".to_vec()
            }
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
    let comm = task_info(pid, super::TaskInfoQuery::Basic)
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
    "0 0 0\n".to_string()
}

/// `/proc/<pid>/stack` — kernel-stack backtrace (privileged).
///
/// Linux ref: `fs/proc/base.c:proc_pid_stack`.
/// NARF has no unwinder yet; return a stub line that won't confuse parsers.
fn render_stack(_pid: u64) -> String {
    // TODO: walk the kernel stack frame chain once an unwinder is
    // available in narf_arch.
    "[<0000000000000000>] 0x0\n".to_string()
}

/// `/proc/<pid>/wchan` — symbol where the task is currently sleeping.
///
/// Linux ref: `fs/proc/base.c:proc_wchan_operations`.
/// TODO: surface the actual sleep-site once the scheduler exposes a
/// per-task "parked in" symbol handle.
fn render_wchan(pid: u64) -> String {
    let state = task_info(pid, super::TaskInfoQuery::Basic)
        .map(|i| i.state)
        .unwrap_or('R');
    if state == 'S' {
        // TODO: return the real wait-channel symbol name once
        // narf_scheduler exposes per-task sleep-site info.
        "sys_sleep\n".to_string()
    } else {
        "0\n".to_string()
    }
}

/// `/proc/<pid>/syscall` — current syscall number + args.
///
/// Linux ref: `fs/proc/base.c:proc_pid_syscall`.
/// Format: `syscall_nr arg0 arg1 arg2 arg3 arg4 arg5 sp pc\n`
/// or `"running\n"` when the task is not blocked in a syscall.
/// TODO: expose the saved syscall-entry frame from the trap path.
fn render_syscall(pid: u64) -> String {
    let state = task_info(pid, super::TaskInfoQuery::Basic)
        .map(|i| i.state)
        .unwrap_or('R');
    if state == 'R' {
        "running\n".to_string()
    } else {
        // TODO: read the saved trap frame (syscall nr + args + rsp/rip)
        // from narf_userspace::handlers once it exposes a per-task
        // snapshot accessor for the saved int 0x80 frame.
        "-1 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0\n".to_string()
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
        "{:<25} {:<20} {:<20} Units",
        "Limit", "Soft Limit", "Hard Limit"
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
/// If the task has unshared its mount namespace, render that NS's
/// view (via the `NS_MOUNTINFO_HOOK`); otherwise fall back to the
/// global VfsRegistry.  Format per line:
///   `mount_id parent_id major:minor root mount_point opts - fstype source opts`
fn render_mountinfo(pid: u64) -> String {
    // Per-ns view first. The hook returns the task's private mount-ns
    // mount list (one "id\tparent\tpath\tfsname" line per mount) when it has
    // unshared CLONE_NEWNS; None ⇒ fall back to the global registry.
    if let Some(rows) = super::hook_ns_mountinfo(pid) {
        let mut s = String::new();
        for line in rows.lines() {
            let mut it = line.splitn(4, '\t');
            let id = it.next().unwrap_or("1");
            let parent = it.next().unwrap_or("0");
            let path = it.next().unwrap_or("/");
            let fs_name = it.next().unwrap_or("rootfs");
            let _ = writeln!(
                s,
                "{} {} 0:1 / {} rw - {} {} rw",
                id, parent, path, fs_name, fs_name
            );
        }
        if s.is_empty() {
            let _ = writeln!(s, "1 0 0:1 / / rw - rootfs rootfs rw");
        }
        return s;
    }
    let mut s = String::new();
    for (id, parent, path, fs_name) in crate::registry().list_mountinfo() {
        let _ = writeln!(
            s,
            "{} {} 0:1 / {} rw - {} {} rw",
            id, parent, path, fs_name, fs_name
        );
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

/// `/proc/<pid>/mounts` — the task's mount table (fstab-style rows).
///
/// Linux ref: `fs/proc_namespace.c:show_vfsmnt`. Same content as the
/// global /proc/mounts; each row is
///   `device mountpoint fstype options 0 0`.
fn render_mounts(_pid: u64) -> String {
    let mut s = String::new();
    for (path, fs_name) in crate::registry().list_with_names() {
        let _ = writeln!(s, "{} {} {} rw,relatime 0 0", fs_name, path, fs_name);
    }
    if s.is_empty() {
        let _ = writeln!(s, "rootfs / rootfs rw,relatime 0 0");
    }
    s
}

/// Per-pid audit login uid store. `None` (absent) ⇒ the unset sentinel.
/// systemd-logind writes this on session setup; NARF records it so a
/// subsequent read round-trips.
static LOGINUID_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, u32>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn loginuid_get(pid: u64) -> Option<u32> {
    let g = LOGINUID_TABLE.lock();
    g.as_ref().and_then(|m| m.get(&pid).copied())
}

fn loginuid_set(pid: u64, uid: u32) {
    let mut g = LOGINUID_TABLE.lock();
    let m = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    // The u32 sentinel clears the stored value (Linux treats it as "unset").
    if uid == u32::MAX {
        m.remove(&pid);
    } else {
        m.insert(pid, uid);
    }
}

/// `/proc/<pid>/statm` — seven space-separated page-count fields.
///
/// Linux format (fs/proc/array.c:proc_pid_statm):
///   `size resident shared text lib data dt\n`
///
/// Field meanings (all in pages, page = 4 KiB):
///   size     — total virtual memory pages (VmSize / PAGE_SIZE)
///   resident — resident set pages (VmRSS / PAGE_SIZE)
///   shared   — shared pages (file-backed resident pages)
///   text     — text (code) pages
///   lib      — library pages (always 0 in Linux ≥2.6)
///   data     — data + stack pages
///   dt       — dirty pages (always 0 in Linux ≥2.6)
///
/// We derive `size` from the sum of all VMA spans and `resident` from
/// the anonymous + file-backed extents (same denominator — the kernel
/// tracks these separately only with a page-table walk, which NARF
/// doesn't have yet). Fields without a data source are zeroed with a
/// TODO comment, matching the style of `render_io` and other partial
/// files in this module.
///
/// Linux ref: `fs/proc/array.c:proc_pid_statm`.
fn render_statm(pid: u64) -> String {
    const PAGE_SIZE: u64 = 4096;
    let info = task_info(pid, super::TaskInfoQuery::Basic);
    let size_pages = info.as_ref().map_or(0, |i| i.vm_size_bytes / PAGE_SIZE);
    let resident_pages = info.as_ref().map_or(0, |i| i.resident_pages);
    // shared: MAP_SHARED VMA pages — the `shared` flag every VMA
    // already carries (same residency approximation as `resident`).
    let shared_pages = info
        .as_ref()
        .map(|i| {
            i.vmas
                .iter()
                .filter(|v| v.shared)
                .map(|v| (v.end.saturating_sub(v.start)) / PAGE_SIZE)
                .sum::<u64>()
        })
        .unwrap_or(0);
    // text: executable VMA pages.
    let text_pages = info
        .as_ref()
        .map(|i| {
            i.vmas
                .iter()
                .filter(|v| v.executable && !v.writable)
                .map(|v| (v.end.saturating_sub(v.start)) / PAGE_SIZE)
                .sum::<u64>()
        })
        .unwrap_or(0);
    // lib: always 0 on Linux ≥2.6.
    let lib_pages: u64 = 0;
    // data: writable non-executable VMA pages (heap + stack + data).
    let data_pages = info
        .as_ref()
        .map(|i| {
            i.vmas
                .iter()
                .filter(|v| v.writable && !v.executable)
                .map(|v| (v.end.saturating_sub(v.start)) / PAGE_SIZE)
                .sum::<u64>()
        })
        .unwrap_or(0);
    // dt: dirty pages — always 0 on Linux ≥2.6.
    let dt_pages: u64 = 0;
    format!(
        "{} {} {} {} {} {} {}\n",
        size_pages, resident_pages, shared_pages, text_pages, lib_pages, data_pages, dt_pages
    )
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
            let path = hook_fd_path(pid, fd).unwrap_or_else(|| "anon_inode:[unknown]".to_string());
            let bytes = path.into_bytes();
            slice_read(&bytes, offset, buf)
        })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        // Linux models /proc/<pid>/fd/<n> as a symlink to the backing path;
        // readlink() (used by musl realpath, lsof, …) requires the node to
        // report S_IFLNK or it returns EINVAL/EPERM. read() yields the target.
        Stat {
            // Linux procfs fd magic links report st_size == 0.
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

impl DirOps for ProcFdDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let fd: u32 = name.parse().ok()?;
        // Validate the fd exists before returning a file node.
        hook_fd_path(self.pid, fd)?;
        Some(Arc::new(ProcFdFile { pid: self.pid, fd }))
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        // Enumerate the exact open fd set from the fd-table snapshot hook, so
        // the listing covers every open fd regardless of count and skips
        // closed slots. The hook returns fd numbers ascending; each becomes a
        // symlink entry whose target is resolved on lookup via the fd-path
        // hook.
        let fds = hook_fd_list(self.pid).unwrap_or_default();
        let mut entries: Vec<DirEntry> = Vec::with_capacity(fds.len());
        for n in fds {
            let s = n.to_string();
            let leaked: &'static str = Box::leak(s.into_boxed_str());
            entries.push(DirEntry {
                name: leaked,
                file_type: FileType::Symlink,
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

/// Single fdinfo file. Renders Linux's baseline `pos`, `flags`, `mnt_id`,
/// and `ino` fields.
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
            let info = hook_fd_info(pid, fd).unwrap_or_default();
            let _ = writeln!(s, "pos:\t{}", info.pos);
            // Linux renders the open-file status flags in octal.
            let _ = writeln!(s, "flags:\t0{:o}", info.flags);
            let _ = writeln!(s, "mnt_id:\t{}", info.mnt_id);
            let _ = writeln!(s, "ino:\t{}", info.ino);
            // pidfd fds carry `Pid:`/`NSpid:` lines (Linux
            // `fs/pidfs.c::pidfd_show_fdinfo`). Pre-pidfs userspace resolves
            // a pidfd to its process by parsing exactly these — systemd 258's
            // `pidfd_get_pid()` falls back here after `pidfd_spawn` (glibc
            // posix_spawn → clone3 CLONE_PIDFD) when the PIDFD_GET_INFO
            // ioctl/pidfs probe is unsupported, and returns ENOTTY ("Failed
            // to spawn executor: Inappropriate ioctl for device", killing
            // every early service) if the `Pid:` line is missing.
            if let Some(target) = hook_fd_pidfd_pid(pid, fd) {
                let _ = writeln!(s, "Pid:\t{}", target);
                let _ = writeln!(s, "NSpid:\t{}", target);
            }
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
        // Exact open fd set from the snapshot hook (mirrors ProcFdDir::iter).
        let fds = hook_fd_list(self.pid).unwrap_or_default();
        let mut entries: Vec<DirEntry> = Vec::with_capacity(fds.len());
        for n in fds {
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
            let comm = task_info(pid, super::TaskInfoQuery::Basic)
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

impl ProcTaskDir {
    /// The single thread's tid AS SEEN BY THE READER. `self.pid` is the outer
    /// ProcessId; a namespaced reader must see its inner tid, not the host
    /// number (Linux `fs/proc/array.c` renders task/<tid> via the reader's ns).
    /// NARF is single-thread-per-process, so tid == the reader's view of pid.
    /// Identity in the root namespace / when no pid-ns hook is installed. (#16)
    pub(crate) fn visible_tid(&self) -> u64 {
        crate::procfs::pid_report(self.pid).unwrap_or(self.pid)
    }
}

impl DirOps for ProcTaskDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let tid: u64 = name.parse().ok()?;
        if tid == self.visible_tid() {
            Some(Arc::new(ProcDirMarker))
        } else {
            None
        }
    }
    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let tid: u64 = name.parse().ok()?;
        if tid == self.visible_tid() {
            Some(Arc::new(ProcTaskTidDir { pid: self.pid }))
        } else {
            None
        }
    }
    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        let s = self.visible_tid().to_string();
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

/// A mountinfo renderer installed independently of the optional container
/// namespace bundle must be consumed by the actual procfs file renderer.
/// This is the production path systemd uses after `CLONE_NEWNS` and a stacked
/// file bind, before its bind-remount pass.
fn mountinfo_hook_for_stacked_file_test(pid: u64) -> Option<String> {
    (pid == 0x4d49).then(|| String::from("41\t40\t/proc/sys/kernel/domainname\tproc"))
}

fn smoke_mountinfo_uses_installed_namespace_hook() -> TestResult {
    super::install_mountinfo_hook(mountinfo_hook_for_stacked_file_test);
    let out = render_mountinfo(0x4d49);
    if out.lines().any(|line| {
        line.split_whitespace().nth(4) == Some("/proc/sys/kernel/domainname")
            && line.contains(" - proc proc rw")
    }) {
        TestResult::Pass
    } else {
        TestResult::Fail("render_mountinfo did not use its installed namespace hook")
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_mountinfo_uses_installed_namespace_hook
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

/// #16: `/proc/<pid>/task/<tid>` renders the tid in the READER's namespace.
/// With a pid-ns hook mapping outer pid 0x5150 → inner tid 7, a namespaced
/// reader must see `task/7` and resolve it — never the host number 0x5150.
fn smoke_task_dir_renders_reader_ns_tid() -> TestResult {
    fn stub_current_outer() -> u64 {
        0x5150
    }
    fn stub_resolve(inner: u64) -> Option<u64> {
        // reader-inner → outer
        if inner == 7 {
            Some(0x5150)
        } else {
            Some(inner)
        }
    }
    fn stub_report(outer: u64) -> Option<u64> {
        // outer → reader-inner
        if outer == 0x5150 {
            Some(7)
        } else {
            Some(outer)
        }
    }

    let snap = crate::procfs::__test_pidns_hooks_snapshot();
    crate::procfs::install_proc_pidns_hooks(stub_current_outer, stub_resolve, stub_report);

    let dir = ProcTaskDir { pid: 0x5150 };
    let names: alloc::vec::Vec<alloc::string::String> =
        dir.iter().map(|e| e.name.to_string()).collect();
    let iter_ok = names.len() == 1 && names[0] == "7";
    let lookup_inner_ok = dir.lookup("7").is_some() && dir.lookup_dir("7").is_some();
    // The host outer number (0x5150 == 20816) must NOT resolve for the reader.
    let outer_hidden = dir.lookup("20816").is_none() && dir.lookup_dir("20816").is_none();

    crate::procfs::__test_pidns_hooks_restore(snap);

    if iter_ok && lookup_inner_ok && outer_hidden {
        TestResult::Pass
    } else {
        TestResult::Fail("task dir must render/resolve the reader-ns inner tid, not the outer pid")
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_task_dir_renders_reader_ns_tid
);

/// Smoke: `oom_score_adj` + `coredump_filter` are writable; `oom_score` is read-only.
fn smoke_writable_files_have_rw_mode() -> TestResult {
    let adj = PidExtFile::new(1, PidExtField::OomScoreAdj);
    let cd = PidExtFile::new(1, PidExtField::CoredumpFilter);
    let score = PidExtFile::new(1, PidExtField::OomScore);
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
    let f = PidExtFile::new(1, PidExtField::OomScore);
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
    let f = PidExtFile::new(1, PidExtField::CoredumpFilter);
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
    0x33
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
    let f = PidExtFile::new(1, PidExtField::OomScoreAdj);
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
    let f = PidExtFile::new(1, PidExtField::CoredumpFilter);
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

/// Smoke: fdinfo contains Linux's four baseline fields.
fn smoke_fdinfo_has_pos_and_flags() -> TestResult {
    use super::poll_once;
    let f = ProcFdInfoFile { pid: 1, fd: 0 };
    let mut buf = [0u8; 256];
    match poll_once(f.read(0, &mut buf)) {
        Some(Ok(n)) if n > 0 => {
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
            if s.contains("pos:")
                && s.contains("flags:")
                && s.contains("mnt_id:")
                && s.contains("ino:")
            {
                TestResult::Pass
            } else {
                TestResult::Fail("fdinfo missing a baseline Linux field")
            }
        }
        _ => TestResult::Fail("fdinfo read failed"),
    }
}
kernel_test_in!("filesystem/procfs/pid_ext", smoke_fdinfo_has_pos_and_flags);

/// Smoke: a pidfd fd renders `Pid:`/`NSpid:` lines in fdinfo (Linux
/// `pidfd_show_fdinfo` parity — systemd's `pidfd_get_pid()` fallback
/// parses `Pid:` and returns ENOTTY without it, failing every
/// `pidfd_spawn`-based service start); a non-pidfd fd must NOT carry
/// a `Pid:` line.
fn smoke_fdinfo_pidfd_renders_pid_line() -> TestResult {
    use super::poll_once;
    fn stub(_pid: u64, fd: u32) -> Option<u64> {
        (fd == 7).then_some(42)
    }
    super::set_fd_pidfd_pid_hook(stub);
    let read_fdinfo = |fd: u32| -> Option<alloc::string::String> {
        let f = ProcFdInfoFile { pid: 1, fd };
        let mut buf = [0u8; 256];
        match poll_once(f.read(0, &mut buf)) {
            Some(Ok(n)) if n > 0 => Some(core::str::from_utf8(&buf[..n]).unwrap_or("").to_string()),
            _ => None,
        }
    };
    let pidfd = match read_fdinfo(7) {
        Some(s) => s,
        None => return TestResult::Fail("pidfd fdinfo read failed"),
    };
    if !pidfd.contains("Pid:\t42\n") || !pidfd.contains("NSpid:\t42\n") {
        return TestResult::Fail("pidfd fdinfo missing 'Pid:'/'NSpid:' lines");
    }
    let plain = match read_fdinfo(0) {
        Some(s) => s,
        None => return TestResult::Fail("plain fdinfo read failed"),
    };
    if plain.contains("Pid:") {
        return TestResult::Fail("non-pidfd fdinfo must not carry a 'Pid:' line");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_fdinfo_pidfd_renders_pid_line
);

// ── statm + magic symlink smokes ────────────────────────────────────────

/// Smoke: `render_statm` produces exactly 7 space-separated fields + newline.
fn smoke_statm_has_seven_fields() -> TestResult {
    let out = render_statm(u64::MAX); // no task-info hook → all zeros
    let trimmed = out.trim_end_matches('\n');
    let fields: alloc::vec::Vec<&str> = trimmed.split(' ').collect();
    if fields.len() == 7 {
        TestResult::Pass
    } else {
        TestResult::Fail("render_statm must produce exactly 7 space-separated fields")
    }
}
kernel_test_in!("filesystem/procfs/pid_ext", smoke_statm_has_seven_fields);

/// Smoke: all statm fields are valid decimal integers ≥ 0.
fn smoke_statm_fields_are_decimal() -> TestResult {
    let out = render_statm(u64::MAX);
    let trimmed = out.trim_end_matches('\n');
    for field in trimmed.split(' ') {
        if field.parse::<u64>().is_err() {
            return TestResult::Fail("render_statm field is not a non-negative integer");
        }
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/procfs/pid_ext", smoke_statm_fields_are_decimal);

/// Smoke: pid dir listing contains exe, cwd, root, statm entries.
fn smoke_pid_ext_lookup_magic_entries() -> TestResult {
    // lookup_pid_ext must recognise all four new names.
    for name in &["exe", "cwd", "root", "statm"] {
        if lookup_pid_ext(1, name).is_none() {
            return TestResult::Fail("lookup_pid_ext missing magic entry");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_pid_ext_lookup_magic_entries
);

/// Smoke: exe/cwd/root stat() reports FileType::Symlink.
fn smoke_magic_links_stat_as_symlink() -> TestResult {
    for field in &[PidExtField::Exe, PidExtField::Cwd, PidExtField::Root] {
        let f = PidExtFile::new(1, *field);
        if f.stat().mode.file_type != FileType::Symlink {
            return TestResult::Fail("magic link must stat as S_IFLNK");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_magic_links_stat_as_symlink
);

/// Smoke: exe/cwd read() return empty bytes when no hook is installed
/// (hook_exe_path / hook_cwd_path return None → unwrap_or_default → "").
fn smoke_magic_links_empty_without_hook() -> TestResult {
    use super::poll_once;
    for field in &[PidExtField::Exe, PidExtField::Cwd] {
        let f = PidExtFile::new(1, *field);
        let mut buf = [0u8; 64];
        match poll_once(f.read(0, &mut buf)) {
            Some(Ok(0)) => {} // expected: empty target
            Some(Ok(_)) => return TestResult::Fail("magic link without hook should return empty"),
            _ => return TestResult::Fail("magic link read failed"),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_magic_links_empty_without_hook
);

/// Smoke: root read() returns "/" when no hook installed (default fallback).
fn smoke_root_link_defaults_to_slash() -> TestResult {
    use super::poll_once;
    let f = PidExtFile::new(1, PidExtField::Root);
    let mut buf = [0u8; 8];
    match poll_once(f.read(0, &mut buf)) {
        Some(Ok(n)) if n > 0 => {
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
            if s == "/" {
                TestResult::Pass
            } else {
                TestResult::Fail("root link without hook should default to '/'")
            }
        }
        _ => TestResult::Fail("root link read failed"),
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_root_link_defaults_to_slash
);

/// Smoke: /proc/<pid>/loginuid round-trips a written uid (systemd-logind
/// stamps it) and reports the unset sentinel before any write.
fn smoke_loginuid_write_round_trips() -> TestResult {
    use super::poll_once;
    // A stable per-test pid to avoid colliding with any live task.
    const PID: u64 = 0x000f_109a_1d01;
    let f = PidExtFile::new(PID, PidExtField::Loginuid);
    // The node must be writable per its stat().
    if f.stat().mode != Mode::FILE_RW {
        return TestResult::Fail("loginuid must be RW");
    }
    // Fresh pid → unset sentinel 4294967295.
    let mut buf = [0u8; 16];
    match poll_once(f.read(0, &mut buf)) {
        Some(Ok(n)) => {
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
            if s.trim() != "4294967295" {
                return TestResult::Fail("unset loginuid must read the u32 sentinel");
            }
        }
        _ => return TestResult::Fail("loginuid read failed"),
    }
    // Write a uid; a write must succeed (not EPERM).
    match poll_once(f.write(0, b"1000\n")) {
        Some(Ok(n)) if n > 0 => {}
        _ => return TestResult::Fail("loginuid write must succeed"),
    }
    // Read back the stored value.
    let mut buf2 = [0u8; 16];
    match poll_once(f.read(0, &mut buf2)) {
        Some(Ok(n)) => {
            let s = core::str::from_utf8(&buf2[..n]).unwrap_or("");
            if s.trim() == "1000" {
                TestResult::Pass
            } else {
                TestResult::Fail("loginuid did not round-trip the written uid")
            }
        }
        _ => TestResult::Fail("loginuid read-back failed"),
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_loginuid_write_round_trips
);

/// Smoke: /proc/<pid>/loginuid accepts `ftruncate(fd, 0)` as a no-op success,
/// then still round-trips a subsequent write. systemd/pam's audit loginuid
/// setter opens the file O_RDWR and `ftruncate(fd, 0)` BEFORE writing the new
/// uid; the default `FileOps::truncate` returns `Unsupported` (→ EPERM), which
/// aborted that write and failed `pam_loginuid` (session required) — the whole
/// systemd-user PAM session then died with EXIT_PAM. Linux ignores the
/// truncate on this single-value procfs file. Regression guard for that gate.
fn smoke_loginuid_ftruncate_is_noop_then_writes() -> TestResult {
    use super::poll_once;
    const PID: u64 = 0x000f_109a_1d02;
    let f = PidExtFile::new(PID, PidExtField::Loginuid);
    // ftruncate(0) must succeed (no-op), NOT return Unsupported/EPERM.
    match poll_once(f.truncate(0)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("loginuid ftruncate must succeed as a no-op"),
    }
    // The value write after the truncate must still land and round-trip —
    // exactly the O_RDWR + ftruncate + write sequence pam_loginuid performs.
    match poll_once(f.write(0, b"957\n")) {
        Some(Ok(n)) if n > 0 => {}
        _ => return TestResult::Fail("loginuid write after ftruncate must succeed"),
    }
    let mut buf = [0u8; 16];
    match poll_once(f.read(0, &mut buf)) {
        Some(Ok(n)) if core::str::from_utf8(&buf[..n]).unwrap_or("").trim() == "957" => {
            TestResult::Pass
        }
        _ => TestResult::Fail("loginuid did not round-trip the post-truncate write"),
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_loginuid_ftruncate_is_noop_then_writes
);

/// Smoke: /proc/<pid>/setgroups accepts "deny" (systemd/newuidmap write
/// it) and rejects garbage.
fn smoke_setgroups_accepts_allow_deny() -> TestResult {
    use super::poll_once;
    let f = PidExtFile::new(1, PidExtField::Setgroups);
    if f.stat().mode != Mode::FILE_RW {
        return TestResult::Fail("setgroups must be RW");
    }
    match poll_once(f.write(0, b"deny\n")) {
        Some(Ok(n)) if n > 0 => {}
        _ => return TestResult::Fail("setgroups 'deny' must succeed"),
    }
    match poll_once(f.write(0, b"garbage")) {
        Some(Err(_)) => TestResult::Pass,
        _ => TestResult::Fail("setgroups must reject a non allow/deny value"),
    }
}
kernel_test_in!(
    "filesystem/procfs/pid_ext",
    smoke_setgroups_accepts_allow_deny
);

/// Smoke: /proc/<pid>/mounts renders at least one fstab-style row with
/// the trailing "0 0" dump/pass columns.
fn smoke_mounts_has_fstab_row() -> TestResult {
    let out = render_mounts(1);
    let ok = out.lines().next().map(|l| {
        let toks: Vec<&str> = l.split_whitespace().collect();
        toks.len() == 6 && toks[4] == "0" && toks[5] == "0"
    });
    if ok == Some(true) {
        TestResult::Pass
    } else {
        TestResult::Fail("mounts row must be 6 space-separated fields ending '0 0'")
    }
}
kernel_test_in!("filesystem/procfs/pid_ext", smoke_mounts_has_fstab_row);

/// Smoke: /proc/<pid>/cgroup renders the v2 "0::<path>" unified line
/// (systemd reads this to place a process in its slice).
fn smoke_cgroup_v2_unified_line() -> TestResult {
    use super::poll_once;
    let f = PidExtFile::new(1, PidExtField::Cgroup);
    let mut buf = [0u8; 64];
    match poll_once(f.read(0, &mut buf)) {
        Some(Ok(n)) => {
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
            if s.starts_with("0::") {
                TestResult::Pass
            } else {
                TestResult::Fail("cgroup must start with the v2 '0::' prefix")
            }
        }
        _ => TestResult::Fail("cgroup read failed"),
    }
}
kernel_test_in!("filesystem/procfs/pid_ext", smoke_cgroup_v2_unified_line);
