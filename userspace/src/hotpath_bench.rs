//! Syscall-path and procfs-read microbenchmarks.
//!
//! A diagnostic harness, not a test: it asserts nothing about speed and
//! always passes. It emits raw samples, one line per benchmark,
//!
//! ```text
//! HOTPATH_BENCH <name> unit=ps_per_op iters=<M> samples=<s1>,...,<s30>
//! ```
//!
//! where each sample is the mean cost of one operation over `M` back-to-back
//! iterations, in picoseconds. The statistics belong on the host, as
//! `verification/specification/spec.md` §8 requires: N = 30 samples per
//! benchmark, median with a 95% bootstrap CI. Numbers from a QEMU/KVM guest
//! are comparisons on one host, never bare-metal figures.
//!
//! What is measured is the kernel side of each path, driven through the same
//! entry points the syscall return and context switch use:
//!
//! * the syscall-entry seccomp gate and the syscall-exit signal gate, from a
//!   stackful task that has a published `Task` (the production shape), with
//!   another task holding a seccomp filter and a blocked pending signal, as
//!   on a desktop where systemd services and Flatpak apps do;
//! * the perf context-switch hook with one per-CPU event per CPU, as
//!   `perf top` opens;
//! * whole syscalls through the dispatcher (getpid, clock_gettime,
//!   rt_sigprocmask, a pipe write+read, poll with a zero timeout, a pwrite
//!   with an inotify instance watching unrelated files);
//! * `/proc` reads: the per-pid files htop reads, for one process and as an
//!   htop-style scan over 150 synthetic processes, and the system files.
//!
//! Built only on request (`--features narf-userspace/hotpath-bench`), run
//! with `--subsystem userspace/hotpath_bench`.
#![cfg(all(feature = "kernel-test", feature = "hotpath-bench"))]

use crate::abi_test_support::*;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering};

const SAMPLES: usize = 30;

fn now_ns() -> u64 {
    narf_scheduler::narf_time::monotonic_ns()
}

/// Run `op` `iters` times per sample, `SAMPLES` samples after a warm-up,
/// and print the raw per-op costs.
fn bench(name: &str, iters: u64, mut op: impl FnMut()) {
    for _ in 0..iters.div_ceil(4) {
        op();
    }
    let mut line = String::new();
    let _ = write!(
        line,
        "HOTPATH_BENCH {name} unit=ps_per_op iters={iters} samples="
    );
    for i in 0..SAMPLES {
        let start = now_ns();
        for _ in 0..iters {
            op();
        }
        let elapsed = now_ns().saturating_sub(start);
        let _ = write!(
            line,
            "{}{}",
            if i == 0 { "" } else { "," },
            elapsed.saturating_mul(1000) / iters
        );
    }
    let _ = writeln!(narf_console::ConsoleOnlyWriter, "{line}");
}

fn note(msg: &str) {
    let _ = writeln!(narf_console::ConsoleOnlyWriter, "HOTPATH_NOTE {msg}");
}

/// A syscall frame that is returning to user mode, as the `syscall`
/// instruction's dispatcher builds it.
struct ReturnCtx {
    args: SyscallArgs,
    ret: SyscallReturn,
}

impl TrapContext for ReturnCtx {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, r: SyscallReturn) {
        self.ret = r;
    }
    fn user_rsp(&self) -> u64 {
        0x7fff_0000
    }
    fn rip(&self) -> u64 {
        0x40_1000
    }
    fn set_rip(&mut self, _rip: u64) {}
    fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
        false
    }
    fn returning_to_user(&self) -> bool {
        true
    }
}

// libseccomp-shaped allow-list: arch check, then one JEQ per allowed number,
// default ERRNO(EPERM). The measured getpid (39) sits near the end, as in a
// systemd `SystemCallFilter=@system-service` list sorted by number.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ERRNO_EPERM: u32 = 0x0005_0001;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

#[repr(C)]
#[derive(Clone, Copy)]
struct Insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct Fprog {
    len: u16,
    filter: *const Insn,
}

fn allow_list_filter(allowed: &[u32]) -> Vec<Insn> {
    let n = allowed.len();
    let mut prog = Vec::new();
    prog.push(Insn {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 4,
    });
    // arch matches -> skip the kill.
    prog.push(Insn {
        code: BPF_JEQ_K,
        jt: 1,
        jf: 0,
        k: AUDIT_ARCH,
    });
    prog.push(Insn {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: 0,
    });
    prog.push(Insn {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });
    for (i, &nr) in allowed.iter().enumerate() {
        // On a match jump to the ALLOW at the end: (n - 1 - i) more JEQs,
        // then the default ERRNO.
        prog.push(Insn {
            code: BPF_JEQ_K,
            jt: (n - i) as u8,
            jf: 0,
            k: nr,
        });
    }
    prog.push(Insn {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: RET_ERRNO_EPERM,
    });
    prog.push(Insn {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: RET_ALLOW,
    });
    prog
}

/// Install `prog` as task `task`'s filter through the real syscall.
fn install_filter(task: u64, prog: &[Insn]) -> bool {
    set_task(task);
    let fprog = Fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    let nnp = call(Syscall::Prctl.raw(), a3(38, 1, 0, 0)); // PR_SET_NO_NEW_PRIVS
    let installed = call(
        Syscall::Seccomp.raw(),
        a2(1, 0, &fprog as *const Fprog as u64), // SECCOMP_SET_MODE_FILTER
    );
    set_task(FAKE_TASK);
    nnp == Some(0) && installed == Some(0)
}

/// The syscall numbers a typical service allow-list admits (x86_64), sorted.
#[cfg(target_arch = "x86_64")]
const SERVICE_ALLOW: [u32; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 32, 33, 35, 39, 41, 42, 43, 44, 45, 46, 47, 49, 51, 52, 54, 55, 56, 57, 59, 60, 61,
    62, 63, 72, 79, 89, 96, 97, 102, 158, 202, 228, 230, 231, 257,
];
#[cfg(target_arch = "aarch64")]
const SERVICE_ALLOW: [u32; 64] = [
    17, 19, 20, 21, 22, 23, 24, 25, 29, 34, 35, 48, 56, 57, 59, 61, 62, 63, 64, 65, 66, 67, 68, 72,
    73, 78, 79, 80, 93, 94, 96, 98, 99, 101, 113, 115, 124, 129, 130, 131, 132, 133, 134, 135, 139,
    160, 165, 166, 167, 172, 173, 174, 178, 198, 200, 203, 204, 206, 207, 208, 214, 215, 222, 226,
];

/// Benchmarks that need the production shape of `current`: a stackful task
/// with a registered `Task` published as the scheduler's user context.
fn gate_benches() {
    const TID: u64 = 0x4C0_0000;
    const PID: u64 = 4_000_500;
    const OTHER: u64 = 0x4C0_0001;
    const OTHER_PID: u64 = 4_000_501;
    let task = crate::task::Task::new_registered(TID, PID);
    crate::handlers::register_pid_task_mapping(PID, TID);
    crate::handlers::register_task_to_pid(TID, PID);
    let other = crate::task::Task::new_registered(OTHER, OTHER_PID);
    crate::handlers::register_pid_task_mapping(OTHER_PID, OTHER);
    crate::handlers::register_task_to_pid(OTHER, OTHER_PID);

    // Another task's filter makes seccomp active system-wide; another task's
    // blocked pending signal makes the signal tables non-empty.
    let filtered_elsewhere = install_filter(OTHER, &allow_list_filter(&SERVICE_ALLOW));
    let usr1 = crate::handlers::sig_bit(10);
    crate::handlers::set_signal_mask_for_task(OTHER, usr1);
    crate::handlers::raise_signal_pending(OTHER, 10);
    if !filtered_elsewhere || crate::signal_pending_of(OTHER) & usr1 == 0 {
        note("gate fixture incomplete: other-task filter or blocked signal missing");
    }

    let own_stack_was = narf_scheduler::stackful::user_own_stack_enabled();
    narf_scheduler::stackful::enable_user_own_stack();
    set_task(TID);
    static PUBLISHED: AtomicBool = AtomicBool::new(false);
    PUBLISHED.store(false, Ordering::Release);
    let owner = task.clone();
    let ran = narf_scheduler::stackful::run_on_stackful_task(async move {
        let ptr = Arc::as_ptr(&owner) as *mut ();
        // SAFETY: `owner` is retained by this future for the whole body,
        // and the context is cleared before it is dropped.
        unsafe { narf_scheduler::stackful::set_current_user_context(ptr) };
        PUBLISHED.store(
            crate::user_task::current_user_task().is_some(),
            Ordering::Release,
        );
        let getpid = Syscall::GetPid.raw();
        let mut ctx = ReturnCtx {
            args: a0(0),
            ret: SyscallReturn::ok(0),
        };
        bench("seccomp_entry_unfiltered_task", 20_000, || {
            core::hint::black_box(crate::seccomp::secure_computing(&mut ctx, getpid));
        });
        bench("signal_exit_nothing_deliverable", 20_000, || {
            core::hint::black_box(crate::default_signal_delivery(
                &mut ctx,
                crate::handlers::SYSCALL_NUM_NONE,
            ));
        });
        // SAFETY: as above.
        unsafe { narf_scheduler::stackful::set_current_user_context(core::ptr::null_mut()) };
    });
    if !ran || !PUBLISHED.load(Ordering::Acquire) {
        note("gate benches did not run with a published current task");
    }

    // The filtered task's own allowed syscall: the BPF (or its cache).
    let filtered_self = install_filter(TID, &allow_list_filter(&SERVICE_ALLOW));
    set_task(TID);
    let owner = task.clone();
    let ran = narf_scheduler::stackful::run_on_stackful_task(async move {
        let ptr = Arc::as_ptr(&owner) as *mut ();
        // SAFETY: as in the first stackful body.
        unsafe { narf_scheduler::stackful::set_current_user_context(ptr) };
        let getpid = Syscall::GetPid.raw();
        let mut ctx = ReturnCtx {
            args: a0(0),
            ret: SyscallReturn::ok(0),
        };
        bench("seccomp_entry_filtered_allowed", 20_000, || {
            core::hint::black_box(crate::seccomp::secure_computing(&mut ctx, getpid));
        });
        // SAFETY: as above.
        unsafe { narf_scheduler::stackful::set_current_user_context(core::ptr::null_mut()) };
    });
    if !ran || !filtered_self {
        note("filtered-task bench fixture incomplete");
    }
    set_task(FAKE_TASK);
    if !own_stack_was {
        narf_scheduler::stackful::__reset_user_own_stack_for_test();
    }
    crate::seccomp::__test_reset_task(TID);
    crate::seccomp::__test_reset_task(OTHER);
    crate::handlers::set_signal_mask_for_task(OTHER, 0);
    crate::handlers::clear_signal_pending(OTHER, 10);
    for (tid, _) in [(TID, PID), (OTHER, OTHER_PID)] {
        crate::handlers::__test_forget_task_pid(tid);
        crate::task::release_task(tid);
    }
    drop(task);
    drop(other);
}

/// `perf top`: one per-CPU event on every CPU, and context switches of a
/// task no event follows.
fn perf_switch_bench() {
    use narf_linux_perf_uapi::PerfEventAttr;
    let attr = PerfEventAttr {
        size: core::mem::size_of::<PerfEventAttr>() as u32,
        type_: 1,  // PERF_TYPE_SOFTWARE
        config: 0, // PERF_COUNT_SW_CPU_CLOCK
        ..PerfEventAttr::default()
    };
    let cpus = narf_scheduler::online_cpu_set()
        .bits()
        .count_ones()
        .clamp(1, 12);
    let mut fds = Vec::new();
    for cpu in 0..cpus {
        if let Some(fd) = call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &attr as *const _ as u64,
                -1i32 as u64,
                u64::from(cpu),
                -1i32 as u64,
            ),
        )
        .filter(|&fd| fd >= 0)
        {
            fds.push(fd as u64);
        }
    }
    if fds.len() as u32 != cpus {
        note("perf bench opened fewer per-CPU events than CPUs");
    }
    const SWITCHED: u64 = 0x4C0_0002;
    bench("perf_switch_pair_percpu_events", 20_000, || {
        crate::perf_event::on_task_switch(SWITCHED, true);
        crate::perf_event::on_task_switch(SWITCHED, false);
    });
    for fd in fds {
        let _ = call(Syscall::Close.raw(), a0(fd));
    }
}

/// Whole syscalls through the dispatcher.
fn syscall_benches() {
    let getpid = Syscall::GetPid.raw();
    bench("syscall_getpid", 20_000, || {
        core::hint::black_box(call_raw(getpid, a0(0)));
    });
    let mut ts = [0u64; 2];
    let ts_ptr = ts.as_mut_ptr() as u64;
    bench("syscall_clock_gettime_monotonic", 20_000, || {
        core::hint::black_box(call_raw(Syscall::ClockGetTime.raw(), a1(1, ts_ptr)));
    });
    let mut old = 0u64;
    let old_ptr = &mut old as *mut u64 as u64;
    bench("syscall_rt_sigprocmask_query", 20_000, || {
        core::hint::black_box(call_raw(Syscall::Sigprocmask.raw(), a3(0, 0, old_ptr, 8)));
    });
    let empty = 0u64;
    let empty_ptr = &empty as *const u64 as u64;
    bench("syscall_rt_sigprocmask_setmask", 20_000, || {
        core::hint::black_box(call_raw(Syscall::Sigprocmask.raw(), a3(2, empty_ptr, 0, 8)));
    });

    let mut fds = [0i32; 2];
    const O_NONBLOCK: u64 = 0o4000;
    if call(
        Syscall::Pipe2.raw(),
        a1(fds.as_mut_ptr() as u64, O_NONBLOCK),
    ) == Some(0)
    {
        let (rd, wr) = (fds[0] as u64, fds[1] as u64);
        let byte = [0x5au8; 1];
        let mut sink = [0u8; 1];
        let (byte_ptr, sink_ptr) = (byte.as_ptr() as u64, sink.as_mut_ptr() as u64);
        bench("syscall_pipe_write_read_1", 10_000, || {
            core::hint::black_box(call_raw(Syscall::Write.raw(), a2(wr, byte_ptr, 1)));
            core::hint::black_box(call_raw(Syscall::Read.raw(), a2(rd, sink_ptr, 1)));
        });
        #[repr(C)]
        struct PollFd {
            fd: i32,
            events: i16,
            revents: i16,
        }
        let mut pfd = PollFd {
            fd: rd as i32,
            events: 1, // POLLIN, on an empty pipe
            revents: 0,
        };
        let pfd_ptr = &mut pfd as *mut PollFd as u64;
        bench("syscall_poll_zero_timeout_1fd", 10_000, || {
            core::hint::black_box(call_raw(Syscall::Poll.raw(), a2(pfd_ptr, 1, 0)));
        });
        let _ = call(Syscall::Close.raw(), a0(rd));
        let _ = call(Syscall::Close.raw(), a0(wr));
    } else {
        note("pipe2 failed; pipe benches skipped");
    }
}

/// A file write while an inotify instance watches 64 unrelated files.
fn fsnotify_write_bench() {
    const O_RDWR: u64 = 2;
    let fd = match call_open(c"/hpb/target".as_ptr() as u64, O_RDWR) {
        Some(fd) if fd >= 0 => fd as u64,
        _ => {
            note("fsnotify bench: target open failed");
            return;
        }
    };
    let byte = [0x41u8; 1];
    let byte_ptr = byte.as_ptr() as u64;
    let pwrite = Syscall::Pwrite64.raw();
    bench("syscall_pwrite_1_no_inotify", 10_000, || {
        core::hint::black_box(call_raw(pwrite, a3(fd, byte_ptr, 1, 0)));
    });
    let ifd = match call(Syscall::InotifyInit1.raw(), a0(0)) {
        Some(ifd) if ifd >= 0 => ifd as u64,
        _ => {
            note("fsnotify bench: inotify_init1 failed");
            let _ = call(Syscall::Close.raw(), a0(fd));
            return;
        }
    };
    let mut watched = 0;
    for i in 0..64 {
        let mut path = String::new();
        let _ = write!(path, "/hpb/w{i}\0");
        if call(
            Syscall::InotifyAddWatch.raw(),
            a2(ifd, path.as_ptr() as u64, 0xfff),
        )
        .is_some_and(|wd| wd >= 1)
        {
            watched += 1;
        }
    }
    if watched != 64 {
        note("fsnotify bench: fewer than 64 watches installed");
    }
    bench("syscall_pwrite_1_inotify_64_unrelated", 10_000, || {
        core::hint::black_box(call_raw(pwrite, a3(fd, byte_ptr, 1, 0)));
    });
    let _ = call(Syscall::Close.raw(), a0(ifd));
    let _ = call(Syscall::Close.raw(), a0(fd));
}

/// Read a procfs file the way a monitor does: a fresh offset-0 read into a
/// page-sized buffer.
fn proc_read(file: &Arc<dyn narf_filesystem::FileOps>, buf: &mut [u8]) -> usize {
    crate::handlers::poll_blocking(file.read(0, buf))
        .and_then(Result::ok)
        .unwrap_or(0)
}

/// `/proc/<pid>/{stat,status,statm,cmdline,io}` for one process, an
/// htop-style refresh over 150 processes, and the system-wide files.
fn procfs_benches() {
    use narf_filesystem::FsInstance as _;
    const SCAN: u64 = 150;
    const BASE_TID: u64 = 0x4C1_0000;
    const BASE_PID: u64 = 4_001_000;
    let mut tasks = Vec::new();
    for i in 0..SCAN {
        let (tid, pid) = (BASE_TID + i, BASE_PID + i);
        tasks.push(crate::task::Task::new_registered(tid, pid));
        crate::handlers::register_pid_task_mapping(pid, tid);
        crate::handlers::register_task_to_pid(tid, pid);
    }
    let root = narf_filesystem::procfs::ProcFs.root();
    let mut buf = alloc::vec![0u8; 4096];
    const PER_PID: [&str; 5] = ["stat", "status", "statm", "cmdline", "io"];
    let first = alloc::format!("{BASE_PID}");
    match root.lookup_dir(&first) {
        Some(dir) => {
            for name in PER_PID {
                let Some(file) = dir.lookup(name) else {
                    note("procfs bench: a per-pid file is missing");
                    continue;
                };
                if proc_read(&file, &mut buf) == 0 && name != "cmdline" {
                    note("procfs bench: a per-pid file read returned nothing");
                }
                let mut bench_name = String::new();
                let _ = write!(bench_name, "proc_pid_{name}_read");
                bench(&bench_name, 2_000, || {
                    core::hint::black_box(proc_read(&file, &mut buf));
                });
            }
        }
        None => note("procfs bench: /proc/<pid> did not resolve"),
    }
    // One htop refresh: open (lookup) and read every per-pid file of every
    // process.
    let names: Vec<String> = (0..SCAN)
        .map(|i| alloc::format!("{}", BASE_PID + i))
        .collect();
    bench("proc_htop_scan_150_pids", 10, || {
        for name in &names {
            if let Some(dir) = root.lookup_dir(name) {
                for file in PER_PID {
                    if let Some(f) = dir.lookup(file) {
                        core::hint::black_box(proc_read(&f, &mut buf));
                    }
                }
            }
        }
    });
    for name in ["stat", "meminfo", "loadavg", "uptime"] {
        let Some(file) = root.lookup(name) else {
            note("procfs bench: a system file is missing");
            continue;
        };
        let mut bench_name = String::new();
        let _ = write!(bench_name, "proc_{name}_read");
        bench(&bench_name, 2_000, || {
            core::hint::black_box(proc_read(&file, &mut buf));
        });
    }
    for i in 0..SCAN {
        crate::handlers::__test_forget_task_pid(BASE_TID + i);
        crate::task::release_task(BASE_TID + i);
    }
    drop(tasks);
}

fn smoke_bench_syscall_hot_paths() -> TestResult {
    let mut seeds: Vec<(String, &[u8])> = Vec::new();
    seeds.push((String::from("target"), b"x"));
    for i in 0..64 {
        seeds.push((alloc::format!("w{i}"), b"x"));
    }
    let seeds: Vec<(&str, &[u8])> = seeds.iter().map(|(n, b)| (n.as_str(), *b)).collect();
    with_memfs("/hpb", "hpb", &seeds, || {
        let start = now_ns();
        syscall_benches();
        fsnotify_write_bench();
        perf_switch_bench();
        gate_benches();
        procfs_benches();
        let mut line = String::new();
        let _ = write!(line, "suite wall_ms={}", (now_ns() - start) / 1_000_000);
        note(&line);
        Ok(())
    })
}
kernel_test_in!("userspace/hotpath_bench", smoke_bench_syscall_hot_paths);
