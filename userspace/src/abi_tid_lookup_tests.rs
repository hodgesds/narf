//! Linux syscall ABI conformance — pid arguments that name a THREAD.
//!
//! Linux resolves most pid arguments with `find_task_by_vpid()` (or
//! `find_vpid()` + `pid_task(PIDTYPE_PID)`), which finds ANY task in the
//! caller's PID namespace: a CLONE_THREAD sibling's tid as well as a
//! thread-group leader's pid. NARF's `pid_to_task_raw()` knows only leaders, so
//! a handler that went `accept_pid_from` → `pid_to_task_raw` failed every
//! non-leader tid with ESRCH (glibc's `pthread_getattr_np(pthread_self())`
//! → `sched_getaffinity(tid)` crashed Firefox that way).
//!
//! The fixture is a real-shaped thread group: a leader registered at
//! `GROUP_PID`, and a non-leader sibling whose Linux tid (`SIB_TID`) comes from
//! the shared pid allocator and is registered exactly as `clone(CLONE_THREAD)`
//! registers it. A second, unrelated process (`OTHER_*`) supplies a foreign
//! thread. Scheduler TaskIds are private: every test also checks that a raw
//! TaskId is NOT accepted where Linux would see an unused pid.

use crate::abi_test_support::*;

const LEADER_TASK: u64 = 0xF100;
const GROUP_PID: u64 = 0xF180;
const SIB_TASK: u64 = 0xF101;
const SIB_TID: u64 = 0xF183;
const OTHER_TASK: u64 = 0xF200;
const OTHER_PID: u64 = 0xF280;
const OTHER_SIB_TASK: u64 = 0xF201;
const OTHER_SIB_TID: u64 = 0xF283;
/// A pid that names nothing.
const ABSENT: u64 = 0xF3F0;

const SIGUSR1: u64 = 10;

fn register_leader(task: u64, pid: u64) {
    crate::task::release_task(task);
    let _ = crate::task::Task::new_registered(task, pid);
    crate::handlers::register_pid_task_mapping(pid, task);
}

/// Register `task` as a non-leader thread of `tgid` the way
/// `clone(CLONE_THREAD)` does: the refcounted Task plus the tid ↔ task and
/// task → tgid maps.
fn register_thread(task: u64, tid: u64, tgid: u64) {
    crate::task::release_task(task);
    let _ = crate::task::Task::new_registered(task, tgid);
    crate::handlers::__test_register_thread_mapping(tid, task, tgid);
}

const ALL_TASKS: [u64; 4] = [LEADER_TASK, SIB_TASK, OTHER_TASK, OTHER_SIB_TASK];

/// Build both thread groups, run `body`, then release every synthetic task.
fn with_groups(body: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    with_setup(|| {
        register_leader(LEADER_TASK, GROUP_PID);
        register_thread(SIB_TASK, SIB_TID, GROUP_PID);
        register_leader(OTHER_TASK, OTHER_PID);
        register_thread(OTHER_SIB_TASK, OTHER_SIB_TID, OTHER_PID);
        let result = body();
        set_task(FAKE_TASK);
        for t in ALL_TASKS {
            crate::task::release_task(t);
        }
        result
    })
}

fn expect(got: Option<i64>, want: i64, msg: &'static str) -> Result<(), &'static str> {
    if got == Some(want) {
        Ok(())
    } else {
        Err(msg)
    }
}

// ── getsid / getpgid — kernel/sys.c:1240 / :1198 `find_task_by_vpid` ──────
fn smoke_abi_tid_getsid_getpgid_non_leader() -> TestResult {
    with_groups(|| {
        for caller in [LEADER_TASK, SIB_TASK] {
            set_task(caller);
            let sid = call(Syscall::Getsid.raw(), a0(GROUP_PID));
            if sid.is_none_or(|v| v <= 0) {
                return Err("getsid(leader pid) failed");
            }
            if call(Syscall::Getsid.raw(), a0(SIB_TID)) != sid {
                return Err("getsid(non-leader tid) did not report the thread's process session");
            }
            // `task_session(current)`: the session of the caller's process,
            // whichever of its threads asks.
            if call(Syscall::Getsid.raw(), a0(0)) != sid {
                return Err("getsid(0) from a thread did not report its process session");
            }
            let pgid = call(Syscall::Getpgid.raw(), a0(GROUP_PID));
            if pgid.is_none_or(|v| v <= 0) {
                return Err("getpgid(leader pid) failed");
            }
            if call(Syscall::Getpgid.raw(), a0(SIB_TID)) != pgid {
                return Err("getpgid(non-leader tid) did not report the thread's process group");
            }
        }
        set_task(LEADER_TASK);
        expect(
            call(Syscall::Getsid.raw(), a0(ABSENT)),
            ESRCH,
            "getsid(unused pid) must be ESRCH",
        )?;
        expect(
            call(Syscall::Getpgid.raw(), a0(ABSENT)),
            ESRCH,
            "getpgid(unused pid) must be ESRCH",
        )?;
        // A scheduler TaskId is not a pid.
        expect(
            call(Syscall::Getsid.raw(), a0(SIB_TASK)),
            ESRCH,
            "getsid accepted a raw TaskId",
        )?;
        expect(
            call(Syscall::Getpgid.raw(), a0(SIB_TASK)),
            ESRCH,
            "getpgid accepted a raw TaskId",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_getsid_getpgid_non_leader);

// ── setpgid — kernel/sys.c:1124-1142: pgid<0 EINVAL, ESRCH, !leader EINVAL ─
fn smoke_abi_tid_setpgid_non_leader_einval() -> TestResult {
    with_groups(|| {
        set_task(LEADER_TASK);
        expect(
            call(Syscall::Setpgid.raw(), a1(SIB_TID, 0)),
            EINVAL,
            "setpgid(non-leader tid) must be EINVAL (thread_group_leader check)",
        )?;
        set_task(SIB_TASK);
        expect(
            call(Syscall::Setpgid.raw(), a1(SIB_TID, 0)),
            EINVAL,
            "setpgid(own non-leader tid) must be EINVAL",
        )?;
        // `if (!pgid) pgid = pid; if (pgid < 0) return -EINVAL;` precedes the
        // lookup, so a negative pid with pgid 0 is EINVAL, not ESRCH.
        expect(
            call(Syscall::Setpgid.raw(), a1((-5i64) as u64, 0)),
            EINVAL,
            "setpgid(-5, 0) must be EINVAL (pgid takes the negative pid)",
        )?;
        expect(
            call(Syscall::Setpgid.raw(), a1(ABSENT, 0)),
            ESRCH,
            "setpgid(unused pid) must be ESRCH",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_setpgid_non_leader_einval);

// ── kcmp — kernel/kcmp.c:146-149 lookups (ESRCH) precede the type switch ──
fn smoke_abi_tid_kcmp_non_leader() -> TestResult {
    const KCMP_VM: u64 = 1;
    with_groups(|| {
        set_task(LEADER_TASK);
        // Threads of one group share one mm.
        expect(
            call(Syscall::Kcmp.raw(), a2(SIB_TID, GROUP_PID, KCMP_VM)),
            0,
            "kcmp(non-leader tid, its leader, KCMP_VM) must resolve both and report the shared mm",
        )?;
        expect(
            call(Syscall::Kcmp.raw(), a2(ABSENT, GROUP_PID, 99)),
            ESRCH,
            "kcmp: ESRCH from the task lookup must precede the EINVAL type check",
        )?;
        expect(
            call(Syscall::Kcmp.raw(), a2(SIB_TASK, GROUP_PID, KCMP_VM)),
            ESRCH,
            "kcmp accepted a raw TaskId",
        )?;
        expect(
            call(Syscall::Kcmp.raw(), a2(GROUP_PID, GROUP_PID, 99)),
            EINVAL,
            "kcmp(valid, valid, bad type) must be EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_kcmp_non_leader);

// ── get_robust_list — kernel/futex/syscalls.c:59 `find_task_by_vpid` ──────
fn smoke_abi_tid_get_robust_list_non_leader() -> TestResult {
    const HEAD: u64 = 0x7000_1000;
    with_groups(|| {
        set_task(SIB_TASK);
        expect(
            call(Syscall::SetRobustList.raw(), a1(HEAD, 24)),
            0,
            "set_robust_list on the sibling failed",
        )?;
        set_task(LEADER_TASK);
        let mut head = 0u64;
        let mut len = 0u64;
        expect(
            call(
                Syscall::GetRobustList.raw(),
                a2(
                    SIB_TID,
                    &mut head as *mut u64 as u64,
                    &mut len as *mut u64 as u64,
                ),
            ),
            0,
            "get_robust_list(non-leader tid) failed",
        )?;
        if head != HEAD {
            return Err("get_robust_list(non-leader tid) read the wrong task's list head");
        }
        expect(
            call(
                Syscall::GetRobustList.raw(),
                a2(
                    ABSENT,
                    &mut head as *mut u64 as u64,
                    &mut len as *mut u64 as u64,
                ),
            ),
            ESRCH,
            "get_robust_list(unused pid) must be ESRCH",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_get_robust_list_non_leader);

// ── prlimit64 — kernel/sys.c:1751 `pid ? find_task_by_vpid(pid) : current` ─
fn smoke_abi_tid_prlimit64_non_leader() -> TestResult {
    const RLIMIT_NOFILE: u64 = 7;
    with_groups(|| {
        let mut old = [0u8; 16];
        let out = old.as_mut_ptr() as u64;
        set_task(LEADER_TASK);
        expect(
            call(Syscall::Prlimit64.raw(), a3(SIB_TID, RLIMIT_NOFILE, 0, out)),
            0,
            "prlimit64(non-leader tid) must find the thread",
        )?;
        set_task(SIB_TASK);
        expect(
            call(Syscall::Prlimit64.raw(), a3(SIB_TID, RLIMIT_NOFILE, 0, out)),
            0,
            "prlimit64(own non-leader tid) must find the caller",
        )?;
        set_task(LEADER_TASK);
        expect(
            call(
                Syscall::Prlimit64.raw(),
                a3(SIB_TASK, RLIMIT_NOFILE, 0, out),
            ),
            ESRCH,
            "prlimit64 accepted a raw TaskId",
        )?;
        expect(
            call(Syscall::Prlimit64.raw(), a3(ABSENT, RLIMIT_NOFILE, 0, out)),
            ESRCH,
            "prlimit64(unused pid) must be ESRCH",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_prlimit64_non_leader);

// ── capget / capset — kernel/capability.c:115 / :233 ──────────────────────
//
// capget: `pid && pid != task_pid_vnr(current)` → `find_task_by_vpid(pid)`.
// capset: only 0 or `task_pid_vnr(current)` — the caller's own TID — else EPERM.
fn smoke_abi_tid_capget_capset_non_leader() -> TestResult {
    const V3: u32 = 0x2008_0522;
    fn hdr(pid: u64) -> [u8; 8] {
        let mut h = [0u8; 8];
        h[..4].copy_from_slice(&V3.to_ne_bytes());
        h[4..].copy_from_slice(&(pid as i32).to_ne_bytes());
        h
    }
    with_groups(|| {
        set_task(LEADER_TASK);
        let mut own = [0u8; 24];
        let h = hdr(0);
        expect(
            call(
                Syscall::Capget.raw(),
                a1(h.as_ptr() as u64, own.as_mut_ptr() as u64),
            ),
            0,
            "capget(0) failed",
        )?;
        let mut sib = [0u8; 24];
        let h = hdr(SIB_TID);
        expect(
            call(
                Syscall::Capget.raw(),
                a1(h.as_ptr() as u64, sib.as_mut_ptr() as u64),
            ),
            0,
            "capget(non-leader tid) must find the thread",
        )?;
        if sib != own {
            return Err("capget(non-leader tid) read some other task's capabilities");
        }
        let h = hdr(ABSENT);
        expect(
            call(
                Syscall::Capget.raw(),
                a1(h.as_ptr() as u64, sib.as_mut_ptr() as u64),
            ),
            ESRCH,
            "capget(unused pid) must be ESRCH",
        )?;

        set_task(SIB_TASK);
        let h = hdr(SIB_TID);
        expect(
            call(
                Syscall::Capset.raw(),
                a1(h.as_ptr() as u64, own.as_ptr() as u64),
            ),
            0,
            "capset(own tid) from a non-leader must be accepted (task_pid_vnr is the tid)",
        )?;
        let h = hdr(GROUP_PID);
        expect(
            call(
                Syscall::Capset.raw(),
                a1(h.as_ptr() as u64, own.as_ptr() as u64),
            ),
            EPERM,
            "capset(leader pid) from a non-leader must be EPERM",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_capget_capset_non_leader);

// ── kill / rt_sigqueueinfo — kernel/signal.c:1480 find_vpid + :1457
// pid_task(PIDTYPE_PID): a thread tid is accepted and the signal is
// process-directed (group_send_sig_info(..., PIDTYPE_TGID)).
fn smoke_abi_tid_kill_rt_sigqueueinfo_non_leader() -> TestResult {
    with_groups(|| {
        set_task(LEADER_TASK);
        expect(
            call(Syscall::Kill.raw(), a1(SIB_TID, 0)),
            0,
            "kill(non-leader tid, 0) must succeed",
        )?;
        expect(
            call(Syscall::Kill.raw(), a1(SIB_TID, SIGUSR1)),
            0,
            "kill(non-leader tid, SIGUSR1) must signal the thread's process",
        )?;
        expect(
            call(Syscall::Kill.raw(), a1(SIB_TASK, 0)),
            ESRCH,
            "kill accepted a raw TaskId",
        )?;
        expect(
            call(Syscall::Kill.raw(), a1(ABSENT, 0)),
            ESRCH,
            "kill(unused pid) must be ESRCH",
        )?;

        let mut info = [0u8; 128];
        info[0..4].copy_from_slice(&(SIGUSR1 as i32).to_ne_bytes());
        info[8..12].copy_from_slice(&(-1i32).to_ne_bytes()); // SI_QUEUE
        let ip = info.as_ptr() as u64;
        expect(
            call(Syscall::RtSigqueueinfo.raw(), a2(SIB_TID, SIGUSR1, ip)),
            0,
            "rt_sigqueueinfo(non-leader tid) must queue to the thread's process",
        )?;
        expect(
            call(Syscall::RtSigqueueinfo.raw(), a2(SIB_TASK, SIGUSR1, ip)),
            ESRCH,
            "rt_sigqueueinfo accepted a raw TaskId",
        )?;
        expect(
            call(Syscall::RtSigqueueinfo.raw(), a2(ABSENT, SIGUSR1, ip)),
            ESRCH,
            "rt_sigqueueinfo(unused pid) must be ESRCH",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_kill_rt_sigqueueinfo_non_leader);

// ── migrate_pages / move_pages — mm/mempolicy.c:1882, mm/migrate.c:2541 ───
fn smoke_abi_tid_migrate_move_pages_non_leader() -> TestResult {
    with_groups(|| {
        install_test_address_space()?;
        let node0: u64 = 1;
        let mask = &node0 as *const u64 as u64;
        for (caller, target) in [
            (SIB_TASK, SIB_TID),
            (LEADER_TASK, SIB_TID),
            (SIB_TASK, GROUP_PID),
        ] {
            set_task(caller);
            expect(
                call(Syscall::MigratePages.raw(), a3(target, 64, mask, mask)),
                0,
                "migrate_pages(thread of the caller's own process) must act on the shared mm",
            )?;
            expect(
                call(Syscall::MovePages.raw(), a4(target, 0, 0, 0, 0)),
                0,
                "move_pages(thread of the caller's own process, count 0) must return 0",
            )?;
        }
        set_task(LEADER_TASK);
        expect(
            call(Syscall::MigratePages.raw(), a3(ABSENT, 64, mask, mask)),
            ESRCH,
            "migrate_pages(unused pid) must be ESRCH",
        )?;
        expect(
            call(Syscall::MovePages.raw(), a4(ABSENT, 0, 0, 0, 0)),
            ESRCH,
            "move_pages(unused pid) must be ESRCH",
        )?;
        expect(
            call(Syscall::MovePages.raw(), a4(SIB_TASK, 0, 0, 0, 0)),
            ESRCH,
            "move_pages accepted a raw TaskId",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_migrate_move_pages_non_leader);

/// Six-argument form (`process_vm_readv`).
fn a5(arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> SyscallArgs {
    SyscallArgs {
        arg0,
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
    }
}

// ── process_vm_readv — mm/process_vm_access.c:197 find_get_task_by_vpid,
// after the iovec imports (:273-283) ─────────────────────────────────────
fn smoke_abi_tid_process_vm_readv_non_leader() -> TestResult {
    with_groups(|| {
        install_test_address_space()?;
        let src = [0x5au8; 8];
        let mut dst = [0u8; 8];
        let liov = [dst.as_mut_ptr() as u64, 8u64];
        let riov = [src.as_ptr() as u64, 8u64];
        let l = liov.as_ptr() as u64;
        let r = riov.as_ptr() as u64;
        set_task(LEADER_TASK);
        expect(
            call(Syscall::ProcessVmReadv.raw(), a5(SIB_TID, l, 1, r, 1, 0)),
            8,
            "process_vm_readv(non-leader tid of the caller's process) must copy",
        )?;
        if dst != src {
            return Err("process_vm_readv reported 8 bytes but copied something else");
        }
        set_task(SIB_TASK);
        expect(
            call(Syscall::ProcessVmReadv.raw(), a5(SIB_TID, l, 1, r, 1, 0)),
            8,
            "process_vm_readv(own non-leader tid) must copy",
        )?;
        // An empty local iovec returns 0 before the task lookup (:276).
        expect(
            call(Syscall::ProcessVmReadv.raw(), a5(ABSENT, l, 0, r, 1, 0)),
            0,
            "process_vm_readv with an empty local iovec must return 0 before the lookup",
        )?;
        expect(
            call(Syscall::ProcessVmReadv.raw(), a5(ABSENT, l, 1, r, 1, 0)),
            ESRCH,
            "process_vm_readv(unused pid) must be ESRCH",
        )?;
        expect(
            call(Syscall::ProcessVmReadv.raw(), a5(SIB_TASK, l, 1, r, 1, 0)),
            ESRCH,
            "process_vm_readv accepted a raw TaskId",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_process_vm_readv_non_leader);

// ── pidfd_open — kernel/pid.c:699 ESRCH; kernel/fork.c:1890 ENOENT for a
// non-leader without PIDFD_THREAD ─────────────────────────────────────────
fn smoke_abi_tid_pidfd_open_rejects_non_leader() -> TestResult {
    with_groups(|| {
        set_task(LEADER_TASK);
        expect(
            call(Syscall::PidfdOpen.raw(), a1(SIB_TID, 0)),
            ENOENT,
            "pidfd_open(non-leader tid, 0) must be ENOENT",
        )?;
        expect(
            call(Syscall::PidfdOpen.raw(), a1(ABSENT, 0)),
            ESRCH,
            "pidfd_open(unused pid) must be ESRCH, not a dead pidfd",
        )?;
        match call(Syscall::PidfdOpen.raw(), a1(GROUP_PID, 0)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("pidfd_open(leader pid) must succeed"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_pidfd_open_rejects_non_leader);

// ── pidfd_open(PIDFD_THREAD) on a non-leader → a live, thread-scoped pidfd:
// pidfd_send_signal infers PIDTYPE_PID from it (kernel/signal.c:4101-4104).
fn smoke_abi_tid_pidfd_thread_non_leader() -> TestResult {
    const PIDFD_THREAD: u64 = 0o200;
    const POLLIN: i16 = 1;
    with_groups(|| {
        set_task(LEADER_TASK);
        let fd = match call(Syscall::PidfdOpen.raw(), a1(SIB_TID, PIDFD_THREAD)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("pidfd_open(non-leader tid, PIDFD_THREAD) must succeed"),
        };
        // The thread is alive: the pidfd must not poll readable.
        let mut pfd = [0u8; 8];
        pfd[..4].copy_from_slice(&(fd as i32).to_ne_bytes());
        pfd[4..6].copy_from_slice(&POLLIN.to_ne_bytes());
        let ts = [0u64; 2];
        expect(
            call(
                Syscall::Ppoll.raw(),
                a4(pfd.as_mut_ptr() as u64, 1, ts.as_ptr() as u64, 0, 8),
            ),
            0,
            "a PIDFD_THREAD pidfd on a live thread must not read as exited",
        )?;
        expect(
            call(Syscall::PidfdSendSignal.raw(), a3(fd, 0, 0, 0)),
            0,
            "pidfd_send_signal(thread pidfd, 0) must find the live thread",
        )?;
        let bit = 1u64 << (SIGUSR1 - 1);
        expect(
            call(Syscall::PidfdSendSignal.raw(), a3(fd, SIGUSR1, 0, 0)),
            0,
            "pidfd_send_signal(thread pidfd, SIGUSR1) failed",
        )?;
        if crate::handlers::signal_pending_of(SIB_TASK) & bit == 0 {
            return Err("a thread pidfd's signal must be pending on that thread (PIDTYPE_PID)");
        }
        // `pidfd_get_task` resolves PIDTYPE_TGID: a thread pidfd naming a
        // non-leader is -ESRCH (kernel/pid.c:640).
        expect(
            call(Syscall::ProcessMadvise.raw(), a4(fd, 0, 0, 4, 0)),
            ESRCH,
            "process_madvise(thread pidfd of a non-leader) must be ESRCH",
        )?;
        expect(
            call(Syscall::ProcessMrelease.raw(), a1(fd, 0)),
            ESRCH,
            "process_mrelease(thread pidfd of a non-leader) must be ESRCH",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_pidfd_thread_non_leader);

// ── tkill / tgkill / rt_tgsigqueueinfo — kernel/signal.c:4168, :4184, :4231:
// `pid <= 0 (|| tgid <= 0)` is EINVAL; then do_send_specific's
// find_task_by_vpid (ESRCH) precedes check_kill_permission (EINVAL sig).
fn smoke_abi_tid_tkill_tgkill_order_and_number_space() -> TestResult {
    with_groups(|| {
        set_task(LEADER_TASK);
        expect(
            call(Syscall::Tkill.raw(), a1(SIB_TID, 0)),
            0,
            "tkill(sibling tid, 0) failed",
        )?;
        expect(
            call(Syscall::Tgkill.raw(), a2(GROUP_PID, SIB_TID, 0)),
            0,
            "tgkill(own tgid, sibling tid, 0) failed",
        )?;
        expect(
            call(Syscall::Tgkill.raw(), a2(OTHER_PID, SIB_TID, 0)),
            ESRCH,
            "tgkill with a tgid the thread is not in must be ESRCH",
        )?;
        expect(
            call(Syscall::Tkill.raw(), a1(0, 0)),
            EINVAL,
            "tkill(0) must be EINVAL",
        )?;
        expect(
            call(Syscall::Tgkill.raw(), a2(0, SIB_TID, 0)),
            EINVAL,
            "tgkill(tgid 0) must be EINVAL",
        )?;
        expect(
            call(Syscall::Tgkill.raw(), a2(GROUP_PID, 0, 0)),
            EINVAL,
            "tgkill(tid 0) must be EINVAL",
        )?;
        expect(
            call(Syscall::Tkill.raw(), a1(ABSENT, 99)),
            ESRCH,
            "tkill(unused tid, bad signal): ESRCH must precede EINVAL",
        )?;
        expect(
            call(Syscall::Tkill.raw(), a1(SIB_TASK, 0)),
            ESRCH,
            "tkill accepted a raw TaskId",
        )?;
        expect(
            call(Syscall::Tgkill.raw(), a2(GROUP_PID, SIB_TASK, 0)),
            ESRCH,
            "tgkill accepted a raw TaskId",
        )?;
        let mut info = [0u8; 128];
        info[0..4].copy_from_slice(&(SIGUSR1 as i32).to_ne_bytes());
        info[8..12].copy_from_slice(&(-1i32).to_ne_bytes()); // SI_QUEUE
        let ip = info.as_ptr() as u64;
        expect(
            call(
                Syscall::RtTgsigqueueinfo.raw(),
                a3(GROUP_PID, SIB_TID, SIGUSR1, ip),
            ),
            0,
            "rt_tgsigqueueinfo(own tgid, sibling tid) failed",
        )?;
        expect(
            call(
                Syscall::RtTgsigqueueinfo.raw(),
                a3(GROUP_PID, SIB_TASK, SIGUSR1, ip),
            ),
            ESRCH,
            "rt_tgsigqueueinfo accepted a raw TaskId",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_tid_tkill_tgkill_order_and_number_space
);

// ── wait4 / waitid accept only a thread-group id — kernel/exit.c:1644
// `do_wait_pid`: `pid_task(wo_pid, PIDTYPE_TGID)`; a non-leader tid matches
// only for its ptracer, so it is -ECHILD (never ESRCH) ──────────────────
fn smoke_abi_tid_wait_rejects_non_leader() -> TestResult {
    const WNOHANG: u64 = 1;
    const WEXITED: u64 = 4;
    const P_PID: u64 = 1;
    with_groups(|| {
        // OTHER exited as LEADER's child and is waiting to be reaped.
        crate::handlers::__test_stage_pending_exit(LEADER_TASK, OTHER_PID, 0);
        set_task(LEADER_TASK);
        let r = (|| {
            expect(
                call(Syscall::Wait4.raw(), a3(OTHER_SIB_TID, 0, WNOHANG, 0)),
                ECHILD,
                "wait4(non-leader tid of a child) must be ECHILD",
            )?;
            let mut info = [0u8; 128];
            expect(
                call(
                    Syscall::Waitid.raw(),
                    a4(
                        P_PID,
                        OTHER_SIB_TID,
                        info.as_mut_ptr() as u64,
                        WEXITED | WNOHANG,
                        0,
                    ),
                ),
                ECHILD,
                "waitid(P_PID, non-leader tid of a child) must be ECHILD",
            )?;
            // The leader's pid still reaps it (regression guard).
            expect(
                call(Syscall::Wait4.raw(), a3(OTHER_PID, 0, WNOHANG, 0)),
                OTHER_PID as i64,
                "wait4(child pid) must still reap the child",
            )
        })();
        crate::handlers::__test_clear_pending_exits(LEADER_TASK);
        r
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_wait_rejects_non_leader);

// ── sched_* / {get,set}priority / ioprio_* — `find_process_by_pid` /
// `find_task_by_vpid` (kernel/sched/syscalls.c:215, kernel/sys.c:282,
// block/ioprio.c:195): a non-leader tid resolves, a raw TaskId does not ──
fn smoke_abi_tid_sched_priority_number_space() -> TestResult {
    const PRIO_PROCESS: u64 = 0;
    const IOPRIO_WHO_PROCESS: u64 = 1;
    with_groups(|| {
        set_task(LEADER_TASK);
        expect(
            call(Syscall::SchedGetScheduler.raw(), a0(SIB_TID)),
            0,
            "sched_getscheduler(non-leader tid) must report SCHED_OTHER",
        )?;
        expect(
            call(Syscall::SchedGetScheduler.raw(), a0(SIB_TASK)),
            ESRCH,
            "sched_getscheduler accepted a raw TaskId",
        )?;
        match call(Syscall::Getpriority.raw(), a1(PRIO_PROCESS, SIB_TID)) {
            Some(v) if v > 0 => {}
            _ => return Err("getpriority(PRIO_PROCESS, non-leader tid) failed"),
        }
        expect(
            call(Syscall::Getpriority.raw(), a1(PRIO_PROCESS, SIB_TASK)),
            ESRCH,
            "getpriority accepted a raw TaskId",
        )?;
        match call(Syscall::IoprioGet.raw(), a1(IOPRIO_WHO_PROCESS, SIB_TID)) {
            Some(v) if v >= 0 => {}
            _ => return Err("ioprio_get(IOPRIO_WHO_PROCESS, non-leader tid) failed"),
        }
        expect(
            call(Syscall::IoprioGet.raw(), a1(IOPRIO_WHO_PROCESS, SIB_TASK)),
            ESRCH,
            "ioprio_get accepted a raw TaskId",
        )?;
        let mut ts = [0u64; 2];
        expect(
            call(
                Syscall::SchedRrGetInterval.raw(),
                a1(SIB_TID, ts.as_mut_ptr() as u64),
            ),
            0,
            "sched_rr_get_interval(non-leader tid) failed",
        )?;
        expect(
            call(
                Syscall::SchedRrGetInterval.raw(),
                a1(SIB_TASK, ts.as_mut_ptr() as u64),
            ),
            ESRCH,
            "sched_rr_get_interval accepted a raw TaskId",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_sched_priority_number_space);

// ── fcntl F_SETOWN / F_SETOWN_EX — fs/fcntl.c:177 / :250 `find_vpid` ──────
//
// A thread's struct pid is accepted for the TGID owner types; F_GETOWN /
// F_GETOWN_EX then report 0 (`pid_task(pid, PIDTYPE_TGID)` is NULL, :206/:272).
fn smoke_abi_tid_fcntl_setown_non_leader() -> TestResult {
    const F_SETOWN: u64 = 8;
    const F_GETOWN: u64 = 9;
    const F_SETOWN_EX: u64 = 15;
    const F_GETOWN_EX: u64 = 16;
    const F_OWNER_TID: i32 = 0;
    const F_OWNER_PID: i32 = 1;
    fn owner_ex(kind: i32, pid: u64) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&kind.to_ne_bytes());
        b[4..].copy_from_slice(&(pid as i32).to_ne_bytes());
        b
    }
    with_groups(|| {
        set_task(LEADER_TASK);
        let mut fds = [0i32; 2];
        expect(
            call(Syscall::Pipe2.raw(), a1(fds.as_mut_ptr() as u64, 0)),
            0,
            "pipe2 failed",
        )?;
        let fd = fds[0] as u64;
        expect(
            call(Syscall::Fcntl.raw(), a2(fd, F_SETOWN, SIB_TID)),
            0,
            "F_SETOWN(non-leader tid) must be accepted",
        )?;
        expect(
            call(Syscall::Fcntl.raw(), a1(fd, F_GETOWN)),
            0,
            "F_GETOWN after F_SETOWN(non-leader tid) must report 0",
        )?;
        expect(
            call(Syscall::Fcntl.raw(), a2(fd, F_SETOWN, GROUP_PID)),
            0,
            "F_SETOWN(leader) failed",
        )?;
        expect(
            call(Syscall::Fcntl.raw(), a1(fd, F_GETOWN)),
            GROUP_PID as i64,
            "F_GETOWN after F_SETOWN(leader) must report the pid",
        )?;
        expect(
            call(Syscall::Fcntl.raw(), a2(fd, F_SETOWN, ABSENT)),
            ESRCH,
            "F_SETOWN(unused pid) must be ESRCH",
        )?;
        expect(
            call(Syscall::Fcntl.raw(), a2(fd, F_SETOWN, SIB_TASK)),
            ESRCH,
            "F_SETOWN accepted a raw TaskId",
        )?;

        let ex = owner_ex(F_OWNER_PID, SIB_TID);
        expect(
            call(
                Syscall::Fcntl.raw(),
                a2(fd, F_SETOWN_EX, ex.as_ptr() as u64),
            ),
            0,
            "F_SETOWN_EX(F_OWNER_PID, non-leader tid) must be accepted",
        )?;
        let mut got = [0xffu8; 8];
        expect(
            call(
                Syscall::Fcntl.raw(),
                a2(fd, F_GETOWN_EX, got.as_mut_ptr() as u64),
            ),
            0,
            "F_GETOWN_EX failed",
        )?;
        if got != owner_ex(F_OWNER_PID, 0) {
            return Err(
                "F_GETOWN_EX after F_OWNER_PID(non-leader tid) must report {F_OWNER_PID, 0}",
            );
        }
        let ex = owner_ex(F_OWNER_TID, SIB_TID);
        expect(
            call(
                Syscall::Fcntl.raw(),
                a2(fd, F_SETOWN_EX, ex.as_ptr() as u64),
            ),
            0,
            "F_SETOWN_EX(F_OWNER_TID, non-leader tid) failed",
        )?;
        expect(
            call(
                Syscall::Fcntl.raw(),
                a2(fd, F_GETOWN_EX, got.as_mut_ptr() as u64),
            ),
            0,
            "F_GETOWN_EX failed",
        )?;
        if got != owner_ex(F_OWNER_TID, SIB_TID) {
            return Err("F_GETOWN_EX after F_OWNER_TID must report the tid");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_fcntl_setown_non_leader);

// ── timer_create SIGEV_THREAD_ID — kernel/time/posix-timers.c:398-399
// find_vpid + pid_task(PIDTYPE_PID) + same_thread_group, else EINVAL ──────
fn smoke_abi_tid_timer_create_thread_id_non_leader() -> TestResult {
    const CLOCK_MONOTONIC: u64 = 1;
    const SIGEV_THREAD_ID: i32 = 4;
    fn sev(tid: u64) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[8..12].copy_from_slice(&(SIGUSR1 as i32).to_ne_bytes());
        b[12..16].copy_from_slice(&SIGEV_THREAD_ID.to_ne_bytes());
        b[16..20].copy_from_slice(&(tid as i32).to_ne_bytes());
        b
    }
    with_groups(|| {
        let mut id = 0u64;
        let out = &mut id as *mut u64 as u64;
        for (caller, tid) in [
            (LEADER_TASK, SIB_TID),
            (SIB_TASK, SIB_TID),
            (SIB_TASK, GROUP_PID),
        ] {
            set_task(caller);
            let s = sev(tid);
            expect(
                call(
                    Syscall::TimerCreate.raw(),
                    a2(CLOCK_MONOTONIC, s.as_ptr() as u64, out),
                ),
                0,
                "timer_create(SIGEV_THREAD_ID, thread of own group) must succeed",
            )?;
        }
        set_task(LEADER_TASK);
        for tid in [OTHER_SIB_TID, OTHER_PID, ABSENT, SIB_TASK] {
            let s = sev(tid);
            expect(
                call(
                    Syscall::TimerCreate.raw(),
                    a2(CLOCK_MONOTONIC, s.as_ptr() as u64, out),
                ),
                EINVAL,
                "timer_create(SIGEV_THREAD_ID, not a thread of own group) must be EINVAL",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_tid_timer_create_thread_id_non_leader
);

// ── perf_event_open — kernel/events/core.c:13911 find_lively_task_by_vpid ─
fn smoke_abi_tid_perf_event_open_non_leader() -> TestResult {
    use narf_linux_perf_uapi::PerfEventAttr;
    with_groups(|| {
        let attr = PerfEventAttr {
            type_: 1, // PERF_TYPE_SOFTWARE
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: 1, // PERF_COUNT_SW_TASK_CLOCK
            ..PerfEventAttr::default()
        };
        let ap = &attr as *const _ as u64;
        let minus1 = -1i32 as u64;
        set_task(LEADER_TASK);
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(ap, SIB_TID, minus1, minus1),
        ) {
            Some(fd) if fd >= 0 => {}
            _ => return Err("perf_event_open(non-leader tid) must open a per-thread event"),
        }
        expect(
            call(Syscall::PerfEventOpen.raw(), a3(ap, ABSENT, minus1, minus1)),
            ESRCH,
            "perf_event_open(unused pid) must be ESRCH",
        )?;
        expect(
            call(
                Syscall::PerfEventOpen.raw(),
                a3(ap, SIB_TASK, minus1, minus1),
            ),
            ESRCH,
            "perf_event_open accepted a raw TaskId",
        )?;
        // Only -1 means "no task"; any other negative pid is a failed lookup.
        expect(
            call(
                Syscall::PerfEventOpen.raw(),
                a3(ap, -2i32 as u64, 0, minus1),
            ),
            ESRCH,
            "perf_event_open(pid -2) must be ESRCH",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_perf_event_open_non_leader);

// ── ptrace — kernel/ptrace.c:1398 find_get_task_by_vpid; ptrace_attach
// `same_thread_group(task, current)` → EPERM ───────────────────────────────
fn smoke_abi_tid_ptrace_attach_same_group() -> TestResult {
    const PTRACE_ATTACH: u64 = 16;
    with_groups(|| {
        crate::ptrace::ptrace_init();
        let r = (|| {
            set_task(SIB_TASK);
            expect(
                call(Syscall::Ptrace.raw(), a2(PTRACE_ATTACH, GROUP_PID, 0)),
                EPERM,
                "PTRACE_ATTACH to the caller's own group leader must be EPERM",
            )?;
            set_task(LEADER_TASK);
            expect(
                call(Syscall::Ptrace.raw(), a2(PTRACE_ATTACH, SIB_TID, 0)),
                EPERM,
                "PTRACE_ATTACH to a sibling thread must be EPERM",
            )?;
            expect(
                call(Syscall::Ptrace.raw(), a2(PTRACE_ATTACH, OTHER_SIB_TASK, 0)),
                ESRCH,
                "PTRACE_ATTACH accepted a raw TaskId",
            )?;
            expect(
                call(Syscall::Ptrace.raw(), a2(PTRACE_ATTACH, ABSENT, 0)),
                ESRCH,
                "PTRACE_ATTACH(unused pid) must be ESRCH",
            )
        })();
        crate::ptrace::ptrace_init();
        r
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_ptrace_attach_same_group);

// ── CPU clocks — kernel/time/posix-cpu-timers.c:57 pid_for_clock ─────────
fn thread_cpuclock(tid: u64) -> u64 {
    // MAKE_THREAD_CPUCLOCK(tid, CPUCLOCK_SCHED)
    ((!(tid as i64)) << 3 | 4 | 2) as u64
}
fn process_cpuclock(pid: u64) -> u64 {
    // MAKE_PROCESS_CPUCLOCK(pid, CPUCLOCK_SCHED)
    ((!(pid as i64)) << 3 | 2) as u64
}

fn smoke_abi_tid_cpu_clocks_non_leader() -> TestResult {
    with_groups(|| {
        let mut ts = [0u64; 2];
        let t = ts.as_mut_ptr() as u64;
        set_task(LEADER_TASK);
        expect(
            call(Syscall::ClockGetTime.raw(), a1(thread_cpuclock(SIB_TID), t)),
            0,
            "thread CPU clock of a sibling must be readable",
        )?;
        expect(
            call(Syscall::ClockGetTime.raw(), a1(thread_cpuclock(0), t)),
            0,
            "thread CPU clock 0 (self) must be readable",
        )?;
        expect(
            call(
                Syscall::ClockGetTime.raw(),
                a1(process_cpuclock(GROUP_PID), t),
            ),
            0,
            "process CPU clock of own process must be readable",
        )?;
        expect(
            call(
                Syscall::ClockGetTime.raw(),
                a1(process_cpuclock(OTHER_PID), t),
            ),
            0,
            "process CPU clock of another process must be readable",
        )?;
        expect(
            call(Syscall::ClockGetTime.raw(), a1(process_cpuclock(0), t)),
            0,
            "process CPU clock 0 (self) must be readable",
        )?;
        expect(
            call(
                Syscall::ClockGetTime.raw(),
                a1(thread_cpuclock(OTHER_SIB_TID), t),
            ),
            EINVAL,
            "thread CPU clock of another process's thread must be EINVAL",
        )?;
        expect(
            call(
                Syscall::ClockGetTime.raw(),
                a1(process_cpuclock(SIB_TID), t),
            ),
            EINVAL,
            "process CPU clock named by a sibling's tid must be EINVAL",
        )?;
        expect(
            call(Syscall::ClockGetTime.raw(), a1(process_cpuclock(ABSENT), t)),
            EINVAL,
            "unused pid CPU clock must be EINVAL",
        )?;
        expect(
            call(
                Syscall::ClockGetTime.raw(),
                a1(thread_cpuclock(SIB_TASK), t),
            ),
            EINVAL,
            "CPU clock accepted a raw TaskId",
        )?;
        set_task(SIB_TASK);
        expect(
            call(Syscall::ClockGetTime.raw(), a1(process_cpuclock(SIB_TID), t)),
            0,
            "clock_gettime(process clock of own non-leader tid) is allowed (pid == task_pid(current))",
        )?;
        expect(
            call(Syscall::ClockGetres.raw(), a1(process_cpuclock(SIB_TID), t)),
            EINVAL,
            "clock_getres(process clock of own non-leader tid) must be EINVAL (gettime=false)",
        )?;
        expect(
            call(Syscall::ClockGetres.raw(), a1(thread_cpuclock(SIB_TID), t)),
            0,
            "clock_getres(own thread clock) must succeed",
        )?;
        // CPUCLOCK_WHICH >= CPUCLOCK_MAX (3) is EINVAL (the PERTHREAD bit keeps
        // this from being a CLOCKFD id).
        expect(
            call(
                Syscall::ClockGetTime.raw(),
                a1(((!(0i64)) << 3 | 4 | 3) as u64, t),
            ),
            EINVAL,
            "CPU clock with which == CPUCLOCK_MAX must be EINVAL",
        )?;
        // clock_settime: a valid CPU clock can never be set (-EPERM); an
        // invalid one is -EINVAL (posix-cpu-timers.c:180-188).
        let zero = [0u64; 2];
        let z = zero.as_ptr() as u64;
        expect(
            call(Syscall::ClockSetTime.raw(), a1(thread_cpuclock(SIB_TID), z)),
            EPERM,
            "clock_settime(own thread CPU clock) must be EPERM",
        )?;
        expect(
            call(
                Syscall::ClockSetTime.raw(),
                a1(thread_cpuclock(OTHER_SIB_TID), z),
            ),
            EINVAL,
            "clock_settime(foreign thread CPU clock) must be EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_tid_cpu_clocks_non_leader);
