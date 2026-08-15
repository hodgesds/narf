//! Linux syscall ABI conformance — proc group, audit pass 2.
//!
//! Additional process/thread-management coverage that drives handler
//! branches the first `abi_proc_tests.rs` file does not: the NULL-pointer
//! and round-trip arms of `prctl` (PR_SET/GET_NAME, PR_SET/GET_DUMPABLE),
//! the `arch_prctl` EFAULT + alternate-subcode arms, `capget`'s datap-NULL
//! version probe, `capset`'s datap-NULL / wrong-pid arms, the `kcmp`
//! distinct-task ordering arm, `pidfd_send_signal`'s real queue path, the
//! `waitid` P_PID + non-WNOHANG fallback arms, `getppid` with a real
//! injected parent, `getpgid` of a non-self pid, and the `unshare`
//! mount-namespace arm. Shares the harness in [`crate::abi_test_support`];
//! every test drives `kernel_syscall_entry` against a synthetic `AbiCtx`.
#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;

// ── getppid(2) — real (injected) parent is reported ──

fn smoke_abi_proc2_getppid_injected_parent() -> TestResult {
    with_setup(|| {
        // The base file only asserts getppid >= 0. Inject a real parent-of
        // mapping (keyed by the caller's VISIBLE pid, which setup() pins to
        // FAKE_TASK via register_task_to_pid) and assert getppid reads it
        // back exactly — exercising the non-default (`unwrap_or(0)` miss)
        // branch of sys_getppid.
        crate::handlers::__test_inject_parent_of(FAKE_TASK, 7);
        match call(Syscall::GetPpid.raw(), a0(0)) {
            Some(7) => Ok(()),
            _ => Err("getppid did not report the injected parent pid"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_getppid_injected_parent);

// ── getpgid(2) — non-self target (pid != 0 translation arm) ──

fn smoke_abi_proc2_getpgid_other_pid() -> TestResult {
    with_setup(|| {
        // The base file only does getpgid(0) (the self arm). Passing a
        // non-zero pid takes the `pgid_from_user(pid)` translation arm; the
        // value is unmapped so read_pgid defaults to the (translated) pid
        // itself and the call still reports Ok with a non-negative pgid.
        match call(Syscall::Getpgid.raw(), a0(200)) {
            Some(v) if v >= 0 => Ok(()),
            Some(_) => Err("getpgid(other) returned negative pgid"),
            None => Err("getpgid(other) returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_getpgid_other_pid);

// ── prctl(2) — PR_SET/GET_NAME round-trip + NULL-pointer arms ──

fn smoke_abi_proc2_prctl_name_roundtrip() -> TestResult {
    with_setup(|| {
        // PR_SET_NAME = 15 with a (kernel-stack) "user" buffer copies up to
        // TASK_COMM_LEN bytes and trims at NUL; PR_GET_NAME = 16 copies the
        // stored 16-byte name back. copy_{from,to}_user operate on real
        // addresses in the harness, so this exercises the NAME arms that the
        // base file (NO_NEW_PRIVS only) never touches.
        const PR_SET_NAME: u64 = 15;
        const PR_GET_NAME: u64 = 16;
        let mut name = [0u8; 16];
        name[..4].copy_from_slice(b"abi\0");
        match call(
            Syscall::Prctl.raw(),
            a1(PR_SET_NAME, name.as_mut_ptr() as u64),
        ) {
            Some(0) => {}
            _ => return Err("PR_SET_NAME did not return 0"),
        }
        let mut out = [0u8; 16];
        match call(
            Syscall::Prctl.raw(),
            a1(PR_GET_NAME, out.as_mut_ptr() as u64),
        ) {
            Some(0) => {}
            _ => return Err("PR_GET_NAME did not return 0"),
        }
        if &out[..3] == b"abi" && out[3] == 0 {
            Ok(())
        } else {
            Err("PR_GET_NAME did not read back the name set by PR_SET_NAME")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_prctl_name_roundtrip);

fn smoke_abi_proc2_prctl_set_name_null() -> TestResult {
    with_setup(|| {
        // PR_SET_NAME with a NULL arg pointer takes the `arg_a == 0 → fail`
        // arm, returning the -1 sentinel.
        // LINUX-GAP: Linux returns -EFAULT for a NULL name pointer; NARF
        // returns the bare -1 sentinel.
        const PR_SET_NAME: u64 = 15;
        match call(Syscall::Prctl.raw(), a1(PR_SET_NAME, 0)) {
            Some(-1) => Ok(()),
            _ => Err("PR_SET_NAME(NULL) did not return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_prctl_set_name_null);

fn smoke_abi_proc2_prctl_get_name_null() -> TestResult {
    with_setup(|| {
        // PR_GET_NAME with a NULL out pointer takes its own `arg_a == 0 →
        // fail` arm, returning the -1 sentinel.
        // LINUX-GAP: Linux returns -EFAULT for a NULL name buffer; NARF
        // returns the bare -1 sentinel.
        const PR_GET_NAME: u64 = 16;
        match call(Syscall::Prctl.raw(), a1(PR_GET_NAME, 0)) {
            Some(-1) => Ok(()),
            _ => Err("PR_GET_NAME(NULL) did not return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_prctl_get_name_null);

fn smoke_abi_proc2_prctl_dumpable_roundtrip() -> TestResult {
    with_setup(|| {
        // PR_SET_DUMPABLE = 4 (arg=1) then PR_GET_DUMPABLE = 3 must read back
        // 1 — a distinct round-trip pair from the NO_NEW_PRIVS one the base
        // file covers, and neither arm takes a user pointer.
        const PR_SET_DUMPABLE: u64 = 4;
        const PR_GET_DUMPABLE: u64 = 3;
        match call(Syscall::Prctl.raw(), a1(PR_SET_DUMPABLE, 1)) {
            Some(0) => {}
            _ => return Err("PR_SET_DUMPABLE did not return 0"),
        }
        match call(Syscall::Prctl.raw(), a0(PR_GET_DUMPABLE)) {
            Some(1) => Ok(()),
            _ => Err("PR_GET_DUMPABLE did not read back 1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_prctl_dumpable_roundtrip);

// ── arch_prctl(2) — EFAULT + alternate-subcode arms ──

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc2_arch_prctl_get_fs_efault() -> TestResult {
    with_setup(|| {
        // ARCH_GET_FS = 0x1003 with a NULL destination: the RDMSR succeeds
        // but copy_to_user(0, ..) fails, taking the EFAULT arm. The base
        // file only exercises the success (valid-buffer) GET_FS path.
        const ARCH_GET_FS: u64 = 0x1003;
        match call(Syscall::ArchPrctl.raw(), a1(ARCH_GET_FS, 0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("arch_prctl ARCH_GET_FS(NULL) did not return -EFAULT"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc2_arch_prctl_get_fs_efault);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc2_arch_prctl_get_gs_einval() -> TestResult {
    with_setup(|| {
        // ARCH_GET_GS = 0x1004 shares the not-yet-wired `ARCH_SET_GS |
        // ARCH_GET_GS` arm with SET_GS (which the base file covers); assert
        // the GET_GS subcode also returns -EINVAL.
        const ARCH_GET_GS: u64 = 0x1004;
        match call(Syscall::ArchPrctl.raw(), a1(ARCH_GET_GS, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("arch_prctl ARCH_GET_GS did not return -EINVAL"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc2_arch_prctl_get_gs_einval);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc2_arch_prctl_unknown_einval() -> TestResult {
    with_setup(|| {
        // An unrecognised sub-code (0x9999) falls to the `_ => EINVAL` arm —
        // the catch-all the base file's comment mentions but never tests.
        match call(Syscall::ArchPrctl.raw(), a1(0x9999, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("arch_prctl with an unknown subcode did not return -EINVAL"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc2_arch_prctl_unknown_einval);

// ── capget(2) — datap == NULL version probe ──

fn smoke_abi_proc2_capget_probe() -> TestResult {
    with_setup(|| {
        // A valid v3 header with datap == NULL is the version-probe form:
        // capget returns 0 without writing any cap data. The base file's
        // capget cases cover the round-trip and the hdrp==NULL EFAULT, not
        // this datap==NULL success arm.
        const CAP_VERSION_3: u32 = 0x2008_0522;
        let mut hdr = [0u8; 8];
        hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
        match call(Syscall::Capget.raw(), a1(hdr.as_mut_ptr() as u64, 0)) {
            Some(0) => Ok(()),
            _ => Err("capget(hdr, NULL) version probe did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_capget_probe);

// ── capset(2) — datap == NULL EFAULT + visible-self / wrong-pid arms ──

fn smoke_abi_proc2_capset_null_data() -> TestResult {
    with_setup(|| {
        // capset rejects a NULL datap up-front via the `hdrp == 0 || datap
        // == 0 → EFAULT` arm, before any version parsing. The base file's
        // capset_neg exercises the bad-version EINVAL arm instead.
        let mut hdr = [0u8; 8];
        const CAP_VERSION_3: u32 = 0x2008_0522;
        hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
        match call(Syscall::Capset.raw(), a1(hdr.as_mut_ptr() as u64, 0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("capset(hdr, NULL) did not return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_capset_null_data);

/// Linux accepts the caller's visible PID in `cap_user_header_t.pid`, not
/// only its internal scheduler task ID.  `dbus-broker-launch` follows the
/// standard capget→capset sequence with `getpid_cached()` here while it drops
/// privileges before exec; rejecting that PID made the launcher exit 1 before
/// the broker could serve the system bus.
fn smoke_abi_proc2_capset_visible_self_pid() -> TestResult {
    with_setup(|| {
        const TASK: u64 = 0xBEEF;
        const PID: u64 = 0xCAFE;
        const CAP_VERSION_3: u32 = 0x2008_0522;

        set_task(TASK);
        crate::handlers::register_pid_task_mapping(PID, TASK);

        let mut hdr = [0u8; 8];
        hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
        hdr[4..].copy_from_slice(&(PID as i32).to_le_bytes());
        let mut data = [0u8; 24];

        let result = call(
            Syscall::Capset.raw(),
            a1(hdr.as_mut_ptr() as u64, data.as_mut_ptr() as u64),
        );
        set_task(FAKE_TASK);

        match result {
            Some(0) => Ok(()),
            _ => Err("capset rejected the caller's visible self PID"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_capset_visible_self_pid);

fn smoke_abi_proc2_capset_other_pid() -> TestResult {
    with_setup(|| {
        // capset only operates on the calling thread; a header naming a pid
        // that is neither 0 nor the caller's visible PID takes the
        // `pid != self → -EPERM` arm. The base file never sets a non-self
        // pid.
        const CAP_VERSION_3: u32 = 0x2008_0522;
        let mut hdr = [0u8; 8];
        hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
        // header pid field (offset 4) = some other pid (123456).
        hdr[4..].copy_from_slice(&123456i32.to_le_bytes());
        let mut data = [0u8; 24];
        match call(
            Syscall::Capset.raw(),
            a1(hdr.as_mut_ptr() as u64, data.as_mut_ptr() as u64),
        ) {
            Some(EPERM) => Ok(()),
            _ => Err("capset for a non-self pid did not return -EPERM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_capset_other_pid);

// ── kcmp(2) — distinct-task ordering arm (returns 1 or 2) ──

fn smoke_abi_proc2_kcmp_distinct_order() -> TestResult {
    with_setup(|| {
        // Register a second resolvable pid, then kcmp(self, other, KCMP_FILE,
        // ..) with two *distinct* tasks. KCMP_FILE == 0 (a non-VM type) so the
        // handler returns the pointer-ordering 1 or 2 — the distinct-task arm
        // the base file (which only checks the equal-self → 0 path) misses.
        const KCMP_FILE: u64 = 0;
        crate::handlers::register_pid_task_mapping(200, 200);
        match call(Syscall::Kcmp.raw(), a3(FAKE_TASK, 200, KCMP_FILE, 0)) {
            Some(1) | Some(2) => Ok(()),
            _ => Err("kcmp on distinct tasks did not return an ordering (1/2)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_kcmp_distinct_order);

// ── pidfd_send_signal(2) — real queue path (non-probe signum) ──

fn smoke_abi_proc2_pidfd_send_signal_queue() -> TestResult {
    with_setup(|| {
        // Mint a pidfd for self, then deliver a real signal (SIGKILL == 9).
        // Unlike the base file's sig-0 probe, this falls past the probe
        // short-circuit, queues the bit into SIGNAL_PENDING (boot-inited by
        // setup) and returns 0 — the actual delivery arm.
        let pidfd = match call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("pidfd_open setup failed"),
        };
        match call(Syscall::PidfdSendSignal.raw(), a3(pidfd, 9, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("pidfd_send_signal(SIGKILL) did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_pidfd_send_signal_queue);

// ── waitid(2) — P_PID + non-WNOHANG fallback arms ──

fn smoke_abi_proc2_waitid_ppid_no_child() -> TestResult {
    with_setup(|| {
        // waitid(P_PID, <pid>, infop, WNOHANG) with no matching child takes
        // the P_PID translation arm (want_pid = id, not -1) and then the
        // no-eligible-child gate → -ECHILD. The base file only drives P_ALL.
        // Linux: kernel/exit.c __do_wait leaves notask_error at -ECHILD when
        // the requested pid has no task; WNOHANG does not turn that into 0.
        const P_PID: u64 = 1;
        const WNOHANG: u64 = 1;
        let mut si = [0u8; 128];
        match call(
            Syscall::Waitid.raw(),
            a3(P_PID, 4242, si.as_mut_ptr() as u64, WNOHANG),
        ) {
            Some(v) if v == ECHILD => Ok(()),
            _ => Err("waitid(P_PID, WNOHANG) with no child must return -ECHILD"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_waitid_ppid_no_child);

fn smoke_abi_proc2_waitid_blocking_without_executor_echild() -> TestResult {
    with_setup(|| {
        // waitid with NO WNOHANG and no child must not claim a successful
        // reap: that would leave a zeroed siginfo_t which userspace reads as
        // an unknown child state. Linux returns ECHILD when no eligible child
        // exists; the kernel-test harness has no executor on which to park.
        const P_ALL: u64 = 0;
        let mut si = [0u8; 128];
        match call(
            Syscall::Waitid.raw(),
            a3(P_ALL, 0, si.as_mut_ptr() as u64, 0),
        ) {
            Some(v) if v == ECHILD => Ok(()),
            _ => Err("waitid without a child/executor did not return -ECHILD"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc2_waitid_blocking_without_executor_echild
);

// ── waitid(2) — WNOWAIT peek leaves the zombie reapable ──

fn smoke_abi_proc2_waitid_wnowait_peek_keeps_zombie() -> TestResult {
    with_setup(|| {
        // systemd PID 1's SIGCHLD dispatch: waitid(P_ALL, WEXITED|WNOHANG|
        // WNOWAIT) peeks the dead child, then reads /proc/<pid>/stat (PPid
        // — the "is this my child" check), and only afterwards reaps with
        // waitid(P_PID, ..., WEXITED). The peek must NOT consume the exit
        // or drop the /proc entry — a consuming peek turns the PPid check
        // into ESRCH ("Can't determine if process N is our child").
        const P_PID: u64 = 1;
        const WNOHANG: u64 = 1;
        const WEXITED: u64 = 4;
        const WNOWAIT: u64 = 0x0100_0000;
        const CHILD: u64 = 4243;
        // Synthetic exited child: registered zombie task + parent-of row +
        // a staged pending-exit entry (wstatus: exited, code 3).
        crate::handlers::register_task_to_pid(CHILD, CHILD);
        crate::handlers::register_pid_task_mapping(CHILD, CHILD);
        if crate::task::task_get(CHILD).is_none() {
            let _ = crate::task::Task::new_registered(CHILD, CHILD);
        }
        crate::task::mark_zombie(CHILD);
        crate::handlers::__test_inject_parent_of(CHILD, FAKE_TASK);
        crate::handlers::__test_stage_pending_exit(FAKE_TASK, CHILD, 3 << 8);
        // Peek: reports the child without reaping.
        let mut si = [0u8; 128];
        let args = a3(
            P_PID,
            CHILD,
            si.as_mut_ptr() as u64,
            WNOHANG | WEXITED | WNOWAIT,
        );
        match call(Syscall::Waitid.raw(), args) {
            Some(0) => {}
            _ => return Err("waitid(WNOWAIT) did not return 0"),
        }
        let si_pid = i32::from_ne_bytes(si[16..20].try_into().unwrap());
        let si_status = i32::from_ne_bytes(si[24..28].try_into().unwrap());
        if si_pid != CHILD as i32 {
            return Err("waitid(WNOWAIT) did not report the zombie child");
        }
        if si_status != 3 {
            return Err("waitid(WNOWAIT) si_status is not the exit code");
        }
        // Between peek and reap the zombie stays /proc-visible with
        // state Z and its real parent (what systemd's PPid check reads).
        let info =
            crate::handlers::proc_task_info(CHILD, narf_filesystem::procfs::TaskInfoQuery::Basic)
                .ok_or("zombie /proc entry vanished after the WNOWAIT peek")?;
        if info.state != 'Z' {
            return Err("unreaped zombie must report /proc state Z");
        }
        if info.ppid != FAKE_TASK {
            return Err("zombie /proc PPid is not the real parent");
        }
        // The real reap still finds the child — the peek consumed nothing.
        let mut si2 = [0u8; 128];
        let args = a3(P_PID, CHILD, si2.as_mut_ptr() as u64, WNOHANG | WEXITED);
        match call(Syscall::Waitid.raw(), args) {
            Some(0) => {}
            _ => return Err("post-peek reap waitid did not return 0"),
        }
        if i32::from_ne_bytes(si2[16..20].try_into().unwrap()) != CHILD as i32 {
            return Err("WNOWAIT peek consumed the exit — child not reapable");
        }
        // Fully reaped now: the child no longer exists, so another peek is
        // -ECHILD and must leave infop untouched. (Linux: the reaped pid has
        // no task, so notask_error stays -ECHILD.) This asserted 0 before
        // waitid grew wait4's no-eligible-child gate.
        let mut si3 = [0u8; 128];
        let args = a3(
            P_PID,
            CHILD,
            si3.as_mut_ptr() as u64,
            WNOHANG | WEXITED | WNOWAIT,
        );
        match call(Syscall::Waitid.raw(), args) {
            Some(v) if v == ECHILD => {}
            _ => return Err("post-reap waitid must return -ECHILD"),
        }
        if i32::from_ne_bytes(si3[16..20].try_into().unwrap()) != 0 {
            return Err("post-reap peek still reported the reaped child");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc2_waitid_wnowait_peek_keeps_zombie
);

// ── /proc/<pid> visibility across the whole fork→exit→reap lifecycle ──

fn smoke_abi_proc2_proc_visible_running_and_zombie_child() -> TestResult {
    with_setup(|| {
        // systemd PID 1's post-fork child check: right after fork returns
        // pid N, service_set_main_pidref reads /proc/<N>/stat's PPid
        // (pid_get_ppid) — while the child is actively RUNNING on another
        // CPU. A currently-polled task is popped off its per-CPU ready
        // queue, so proc_task_info must resolve it through the task
        // registry (spawn→reap window), not the queue scans; a miss maps
        // to ESRCH ("Can't determine if process N is our child").
        //
        // Model the exact shape: a registered RUNNING Task with a real
        // pid→tid binding (tid != pid, like every forked child) that is
        // on NO ready queue and is NOT the caller.
        const P_PID: u64 = 1;
        const WNOHANG: u64 = 1;
        const WEXITED: u64 = 4;
        const CHILD_PID: u64 = 4245;
        const CHILD_TID: u64 = 4501;
        crate::handlers::register_pid_task_mapping(CHILD_PID, CHILD_TID);
        if crate::task::task_get(CHILD_TID).is_none() {
            let _ = crate::task::Task::new_registered(CHILD_TID, CHILD_PID);
        }
        crate::handlers::__test_inject_parent_of(CHILD_PID, FAKE_TASK);
        // (1) Running child (off-queue, off-CPU-locally): /proc resolves
        // with state R and the real parent in PPid.
        let info = crate::handlers::proc_task_info(
            CHILD_PID,
            narf_filesystem::procfs::TaskInfoQuery::Basic,
        )
        .ok_or("/proc entry missing for a registered RUNNING child (off-queue)")?;
        if info.state != 'R' {
            return Err("running child must report /proc state R");
        }
        if info.ppid != FAKE_TASK {
            return Err("running child /proc PPid is not the real parent");
        }
        // (2) Instant exit (the modprobe@ shape): the zombie stays
        // /proc-visible with state Z + PPid until the parent reaps.
        crate::task::mark_zombie(CHILD_TID);
        crate::handlers::__test_stage_pending_exit(FAKE_TASK, CHILD_PID, 0);
        let info = crate::handlers::proc_task_info(
            CHILD_PID,
            narf_filesystem::procfs::TaskInfoQuery::Basic,
        )
        .ok_or("/proc entry vanished for an unreaped zombie child")?;
        if info.state != 'Z' {
            return Err("unreaped zombie must report /proc state Z");
        }
        if info.ppid != FAKE_TASK {
            return Err("zombie child /proc PPid is not the real parent");
        }
        // (3) Reap: waitid(P_PID, WEXITED) consumes the zombie; the pid
        // drops out of /proc (no stale visibility after release).
        let mut si = [0u8; 128];
        let args = a3(P_PID, CHILD_PID, si.as_mut_ptr() as u64, WNOHANG | WEXITED);
        match call(Syscall::Waitid.raw(), args) {
            Some(0) => {}
            _ => return Err("waitid reap of the zombie child did not return 0"),
        }
        if i32::from_ne_bytes(si[16..20].try_into().unwrap()) != CHILD_PID as i32 {
            return Err("waitid did not reap the zombie child");
        }
        if crate::handlers::proc_task_info(CHILD_PID, narf_filesystem::procfs::TaskInfoQuery::Basic)
            .is_some()
        {
            return Err("reaped pid must not stay /proc-visible");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc2_proc_visible_running_and_zombie_child
);

// ── unshare(2) — mount-namespace arm (CLONE_NEWNS) ──

fn smoke_abi_proc2_unshare_newns() -> TestResult {
    with_setup(|| {
        // unshare(CLONE_NEWNS) takes the feature-independent mount-namespace
        // arm: it inits the per-task mount-ns table, snapshots the global
        // mounts, records the entry (any = true) and returns 0. The base file
        // only covers the flags == 0 no-op success.
        const CLONE_NEWNS: u64 = 0x0002_0000;
        let result = match call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) {
            Some(0) => Ok(()),
            _ => Err("unshare(CLONE_NEWNS) did not return 0"),
        };
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_unshare_newns);

fn smoke_abi_proc2_unshare_newns_copies_current_namespace() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        let result = (|| {
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("first unshare(CLONE_NEWNS) failed");
            }
            let first = match crate::handlers::current_mount_namespace() {
                Some(ns) => ns,
                None => return Err("first unshare did not install a namespace"),
            };
            let auth = narf_filesystem::bootstrap_mount_authority();
            let private: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
                alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("nested-private"));
            if first.mount_arc(&auth, "/nested-private", private).is_err() {
                return Err("private mount setup failed");
            }
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("second unshare(CLONE_NEWNS) failed");
            }
            let second = match crate::handlers::current_mount_namespace() {
                Some(ns) => ns,
                None => return Err("second unshare did not install a namespace"),
            };
            if alloc::sync::Arc::ptr_eq(&first, &second) {
                return Err("unshare must create an independent mount table");
            }
            match second.resolve_absolute("/nested-private", |fs, rel| {
                rel.is_empty() && fs.name() == "nested-private"
            }) {
                Some(true) => Ok(()),
                _ => Err("nested unshare must copy mounts from the current namespace"),
            }
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc2_unshare_newns_copies_current_namespace
);

// ── prctl PR_SET/GET_PDEATHSIG + PR_SET/GET_CHILD_SUBREAPER ──

fn smoke_abi_proc2_prctl_pdeathsig_roundtrip() -> TestResult {
    with_setup(|| {
        // set(SIGUSR1=10) → get reads 10 back through the int pointer.
        if call(Syscall::Prctl.raw(), a1(1, 10)) != Some(0) {
            return Err("PR_SET_PDEATHSIG(10) should return 0");
        }
        let mut out: i32 = -1;
        if call(Syscall::Prctl.raw(), a1(2, &mut out as *mut i32 as u64)) != Some(0) || out != 10 {
            return Err("PR_GET_PDEATHSIG must read back 10");
        }
        // 0 clears. 64 (SIGRTMAX) is a VALID signal now (bit-N-1 fits
        // 1..=64); 65 is the out-of-range probe.
        if call(Syscall::Prctl.raw(), a1(1, 0)) != Some(0) {
            return Err("PR_SET_PDEATHSIG(0) should clear and return 0");
        }
        if call(Syscall::Prctl.raw(), a1(1, 64)) != Some(0) {
            return Err("PR_SET_PDEATHSIG(64=SIGRTMAX) should return 0");
        }
        if call(Syscall::Prctl.raw(), a1(1, 65)) != Some(-22) {
            return Err("PR_SET_PDEATHSIG(65) should return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_prctl_pdeathsig_roundtrip);

fn smoke_abi_proc2_prctl_subreaper_roundtrip() -> TestResult {
    with_setup(|| {
        if call(Syscall::Prctl.raw(), a1(36, 1)) != Some(0) {
            return Err("PR_SET_CHILD_SUBREAPER(1) should return 0");
        }
        let mut out: i32 = 0;
        if call(Syscall::Prctl.raw(), a1(37, &mut out as *mut i32 as u64)) != Some(0) || out != 1 {
            return Err("PR_GET_CHILD_SUBREAPER must read back 1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_prctl_subreaper_roundtrip);

// ── pdeathsig delivery + subreaper reparenting on parent exit ──
//
// Three synthetic tasks: SUB (subreaper) ← MID ← KID(pdeathsig=10).
// Orphanizing MID must (a) deliver KID's death signal and (b) retarget
// KID's parent row to SUB instead of dropping it.
fn smoke_abi_proc2_pdeathsig_and_subreaper_on_exit() -> TestResult {
    with_setup(|| {
        const SUB: u64 = 0x7A00;
        const MID: u64 = 0x7A01;
        const KID: u64 = 0x7A02;
        for t in [SUB, MID, KID] {
            crate::handlers::register_task_to_pid(t, t);
            crate::handlers::register_pid_task_mapping(t, t);
            if crate::task::task_get(t).is_none() {
                let _ = crate::task::Task::new_registered(t, t);
            }
        }
        crate::handlers::__test_inject_parent_of(KID, MID);
        crate::handlers::__test_inject_parent_of(MID, SUB);
        // Switch identity to configure per-task prctl state through the
        // real syscall: SUB volunteers as subreaper, KID arms pdeathsig.
        set_task(SUB);
        if call(Syscall::Prctl.raw(), a1(36, 1)) != Some(0) {
            return Err("subreaper prctl on SUB failed");
        }
        set_task(KID);
        if call(Syscall::Prctl.raw(), a1(1, 10)) != Some(0) {
            return Err("pdeathsig prctl on KID failed");
        }
        set_task(FAKE_TASK);
        // MID dies.
        crate::handlers::__test_orphanize_children_of(MID);
        if crate::handlers::signal_pending_of(KID) & crate::handlers::sig_bit(10) == 0 {
            return Err("KID must receive its pdeathsig when MID exits");
        }
        let reparented = crate::handlers::parent_of_get(KID);
        // Release the synthetic tasks — the refcounted TASKS registry is
        // NOT swept by setup()/teardown(), and stale entries are exactly
        // the persistent-state class behind the pause_neg ordering saga
        // (see the kernel-test-suite pitfalls note).
        for t in [SUB, MID, KID] {
            crate::handlers::release_reaped_task(t);
        }
        if reparented != Some(SUB) {
            return Err("KID must be reparented to the subreaper SUB");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc2_pdeathsig_and_subreaper_on_exit
);

// ── /proc/<pid>/* end-to-end renderer coverage ──────────────────────
//
// The per-pid procfs renderers (stat/status/statm/comm/cmdline, the fd/
// directory and the root magic symlink) live behind private structs in
// `narf_filesystem::procfs`; the only public seam that drives the FULL
// stack (path resolver → the kernel task_info hook → renderer) is a real
// `open("<base>/<pid>/<file>")` + `read()` against a mounted `ProcFs`.
// `with_procfs` mounts ProcFs at a pid-unique base (so a boot-mounted
// `/proc` never makes the mount `Busy`), wires only the hooks the
// renderers need (TASK_INFO/CURRENT_PID/LIST_PIDS + FD_PATH via the
// snapshot/restore seam), registers a synthetic task with a KNOWN comm /
// argv / parent, and asserts the rendered output matches that known state
// — field counts + key fields, never brittle full strings. pid == tid
// identity (like FAKE_TASK) so the TaskId-keyed comm/argv/fd tables and
// the pid-keyed PARENT_OF row agree. Every hook this helper installs is
// undone on exit so the filesystem crate's un-hooked-slot assertions
// (`smoke_fd_lookup_no_hook_returns_none` etc.) still hold.

/// Wire the procfs per-pid hooks to the real handlers, mount `ProcFs` at a
/// UNIQUE per-pid path, run `body` (passed that mount base, e.g.
/// `/proc_test_22343`), then unmount + release the synthetic task and undo
/// every hook this helper installs.
///
/// Two properties this helper must preserve for the full kernel-test run:
///
///   * **Mount is Busy-proof.** In the full boot `/proc` is already
///     mounted, so `registry().mount("/proc", ..)` returns `Busy`. Mounting
///     at a pid-unique base (`/proc_test_<pid>`) always succeeds and still
///     drives the identical resolver → task_info hook → renderer stack,
///     because ProcFs resolves paths relative to its mount point.
///
///   * **No leaked global hook state.** The procfs hook slots are
///     process-global `AtomicUsize` fn-pointer stores with no boot-time
///     install in a `kernel-test` build (the harness runs before
///     `install_all_hooks`). `install_proc_ext_hooks` / `install_proc_path_hooks`
///     would leave FD_PATH / EXE_PATH / CWD_PATH / ENVIRON installed, which
///     the filesystem crate's `smoke_fd_lookup_no_hook_returns_none`,
///     `smoke_magic_links_empty_without_hook`, and `smoke_environ_empty_without_hook`
///     tests assert are ABSENT. So this helper installs only what the
///     renderers under test need and what it can undo:
///       - `install_proc_hooks` (TASK_INFO / CURRENT_PID / LIST_PIDS) — no
///         test asserts these absent, and `pid_resolve`/`current_outer_pid`
///         fall back to identity when the pidns hooks are unset, so numeric
///         `/proc/<pid>/*` and `/proc/self/*` both resolve without them.
///       - FD_PATH — the only ext/path hook needed here (the fd-symlink
///         test). It is the one hook with a snapshot/restore seam, so it is
///         saved before and restored after every call.
///
/// The exe/cwd/root magic links and the ext (rlimits/nice/environ/auxv)
/// hooks are deliberately NOT installed: root defaults to "/" un-hooked and
/// no test here reads exe/cwd/environ/rlimits.
fn with_procfs(
    pid: u64,
    comm: &str,
    argv: &[&str],
    parent: u64,
    body: impl FnOnce(&str) -> Result<(), &'static str>,
) -> TestResult {
    setup();
    // Kernel-test fixture: hands the syscall entry point kernel `.rodata` /
    // stack pointers as stand-in user buffers. See
    // `handlers::kernel_buffers_guard` and `with_setup`, which does the same
    // for the tests that use the closure form of this harness.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // TASK_INFO / CURRENT_PID / LIST_PIDS — needed by every renderer and by
    // `/proc/self` resolution; none has a hook-absent assertion elsewhere.
    narf_filesystem::procfs::install_proc_hooks(
        crate::handlers::proc_current_pid,
        crate::handlers::proc_list_pids,
        crate::handlers::proc_task_info,
    );
    // FD_PATH: snapshot so we can restore the exact prior slot (0 in a
    // kernel-test build) after the test, keeping the un-hooked fd-lookup
    // assertion valid. Install by re-pointing through the restore seam.
    let fd_path_prev = narf_filesystem::procfs::__test_fd_path_hook_snapshot();
    narf_filesystem::procfs::__test_fd_path_hook_restore(crate::handlers::fd_path_of as usize);
    // Synthetic task with pid == tid identity + a real registry entry so
    // proc_task_info's liveness gate resolves it in every state.
    if pid != FAKE_TASK {
        crate::handlers::register_task_to_pid(pid, pid);
        crate::handlers::register_pid_task_mapping(pid, pid);
        if crate::task::task_get(pid).is_none() {
            let _ = crate::task::Task::new_registered(pid, pid);
        }
    }
    crate::handlers::set_proc_comm(pid, comm);
    crate::handlers::set_proc_argv(pid, argv);
    crate::handlers::__test_inject_parent_of(pid, parent);

    // Pid-unique mount base so a boot-mounted (or prior-test) `/proc` never
    // makes this `Busy`.
    let base = alloc::format!("/proc_test_{}", pid);
    let auth = bootstrap_mount_authority();
    let handle = match registry().mount(&auth, &base, narf_filesystem::procfs::ProcFs) {
        Ok(h) => h,
        Err(_) => {
            narf_filesystem::procfs::__test_fd_path_hook_restore(fd_path_prev);
            teardown();
            return TestResult::Fail("procfs mount failed");
        }
    };
    let outcome = body(&base);
    let _ = registry().unmount(&handle, &base);
    // Undo the FD_PATH install so `smoke_fd_lookup_no_hook_returns_none`
    // still sees the slot unhooked.
    narf_filesystem::procfs::__test_fd_path_hook_restore(fd_path_prev);
    if pid != FAKE_TASK {
        crate::handlers::release_reaped_task(pid);
    }
    teardown();
    match outcome {
        Ok(()) => TestResult::Pass,
        Err(msg) => TestResult::Fail(msg),
    }
}

/// Read a whole small `/proc` file into `out`, returning the byte count.
/// `path` is the NUL-terminated absolute path bytes. The per-pid renderers
/// are all well under 4 KiB, so a single read at offset 0 captures the
/// entire file.
fn read_proc_file(path: &[u8], out: &mut [u8]) -> Result<usize, &'static str> {
    let fd = match call_open(path.as_ptr() as u64, 0) {
        Some(fd) if fd >= 0 => fd as u64,
        _ => return Err("open of /proc file failed"),
    };
    let n = match call(
        Syscall::Read.raw(),
        a2(fd, out.as_mut_ptr() as u64, out.len() as u64),
    ) {
        Some(n) if n >= 0 => n as usize,
        _ => return Err("read of /proc file failed"),
    };
    Ok(n)
}

// ── /proc/<pid>/stat — field count + leading fields match known state ──

fn smoke_abi_proc2_pid_stat_fields() -> TestResult {
    const PID: u64 = 0x5747;
    const PARENT: u64 = 0x5740;
    with_procfs(PID, "statproc", &["statproc"], PARENT, |base| {
        let mut buf = [0u8; 512];
        let path = alloc::format!("{}/{}/stat\0", base, PID);
        let n = read_proc_file(path.as_bytes(), &mut buf)?;
        let s = core::str::from_utf8(&buf[..n]).map_err(|_| "stat not utf-8")?;
        let line = s.trim_end_matches('\n');
        // The comm field is parenthesised and may contain spaces; Linux
        // parsers split on the LAST ')'. pid before '(', the rest after.
        let open = line.find('(').ok_or("stat missing '(' around comm")?;
        let close = line.rfind(')').ok_or("stat missing ')' around comm")?;
        let pid_field = line[..open].trim();
        let comm_field = &line[open + 1..close];
        let rest: alloc::vec::Vec<&str> = line[close + 1..].split_whitespace().collect();
        // Field 1: pid echoes /proc/<N>.
        if pid_field != "22343" {
            return Err("stat field 1 (pid) does not echo /proc/<N>");
        }
        // Field 2: comm without the parens.
        if comm_field != "statproc" {
            return Err("stat comm field does not match the known comm");
        }
        // After the comm there are 50 more fields (Linux has 52 total; we
        // render the full 52-column line). rest[0]=state, [1]=ppid,
        // [2]=pgrp, [3]=session.
        if rest.len() != 50 {
            return Err("stat must render 50 fields after (comm)");
        }
        if rest[0] != "R" {
            return Err("stat state field (3) is not R for a running task");
        }
        if rest[1] != "22336" {
            return Err("stat ppid field (4) does not match the injected parent");
        }
        // pgrp + session are non-negative integers.
        if rest[2].parse::<u64>().is_err() || rest[3].parse::<u64>().is_err() {
            return Err("stat pgrp/session fields (5/6) are not integers");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_pid_stat_fields);

// ── /proc/<pid>/status — key lines present + consistent with stat ──

fn smoke_abi_proc2_pid_status_lines() -> TestResult {
    const PID: u64 = 0x5748;
    const PARENT: u64 = 0x5741;
    with_procfs(PID, "statusproc", &["statusproc"], PARENT, |base| {
        let mut buf = [0u8; 2048];
        let path = alloc::format!("{}/{}/status\0", base, PID);
        let n = read_proc_file(path.as_bytes(), &mut buf)?;
        let s = core::str::from_utf8(&buf[..n]).map_err(|_| "status not utf-8")?;
        // Name: matches comm.
        let name = s
            .lines()
            .find_map(|l| l.strip_prefix("Name:\t"))
            .ok_or("status missing Name: line")?;
        if name != "statusproc" {
            return Err("status Name: does not match the known comm");
        }
        // State: leading char R (running).
        let state = s
            .lines()
            .find_map(|l| l.strip_prefix("State:\t"))
            .ok_or("status missing State: line")?;
        if !state.starts_with('R') {
            return Err("status State: is not R for a running task");
        }
        // Pid: echoes /proc/<N>.
        let pidl = s
            .lines()
            .find_map(|l| l.strip_prefix("Pid:\t"))
            .ok_or("status missing Pid: line")?;
        if pidl.trim() != "22344" {
            return Err("status Pid: does not echo /proc/<N>");
        }
        // PPid: matches the injected parent (0x5741 = 22337).
        let ppidl = s
            .lines()
            .find_map(|l| l.strip_prefix("PPid:\t"))
            .ok_or("status missing PPid: line")?;
        if ppidl.trim() != "22337" {
            return Err("status PPid: does not match the injected parent");
        }
        // Uid:/Gid: are 4-column tab-separated quads of integers.
        for key in ["Uid:\t", "Gid:\t"] {
            let l = s
                .lines()
                .find_map(|l| l.strip_prefix(key))
                .ok_or("status missing Uid:/Gid: line")?;
            let cols: alloc::vec::Vec<&str> = l.split('\t').collect();
            if cols.len() != 4 || cols.iter().any(|c| c.parse::<u32>().is_err()) {
                return Err("status Uid:/Gid: is not a 4-column integer quad");
            }
        }
        // VmSize:/VmRSS: present and " kB"-suffixed.
        for key in ["VmSize:", "VmRSS:"] {
            let l = s
                .lines()
                .find(|l| l.starts_with(key))
                .ok_or("status missing VmSize:/VmRSS: line")?;
            if !l.trim_end().ends_with("kB") {
                return Err("status VmSize:/VmRSS: is not kB-suffixed");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_pid_status_lines);

// ── /proc/<pid>/statm — exactly 7 integer fields ──

fn smoke_abi_proc2_pid_statm_seven_ints() -> TestResult {
    const PID: u64 = 0x5749;
    with_procfs(PID, "statmproc", &["statmproc"], 0, |base| {
        let mut buf = [0u8; 256];
        let path = alloc::format!("{}/{}/statm\0", base, PID);
        let n = read_proc_file(path.as_bytes(), &mut buf)?;
        let s = core::str::from_utf8(&buf[..n]).map_err(|_| "statm not utf-8")?;
        let line = s.trim_end_matches('\n');
        let fields: alloc::vec::Vec<&str> = line.split(' ').collect();
        if fields.len() != 7 {
            return Err("statm must render exactly 7 space-separated fields");
        }
        if fields.iter().any(|f| f.parse::<u64>().is_err()) {
            return Err("statm fields must all be non-negative integers");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_pid_statm_seven_ints);

// ── /proc/<pid>/comm — matches the process comm (+ 15-byte truncation) ──

fn smoke_abi_proc2_pid_comm_matches() -> TestResult {
    const PID: u64 = 0x574a;
    with_procfs(PID, "commproc", &["commproc"], 0, |base| {
        let mut buf = [0u8; 64];
        let path = alloc::format!("{}/{}/comm\0", base, PID);
        let n = read_proc_file(path.as_bytes(), &mut buf)?;
        let s = core::str::from_utf8(&buf[..n]).map_err(|_| "comm not utf-8")?;
        if s.trim_end_matches('\n') == "commproc" {
            Ok(())
        } else {
            Err("/proc/<pid>/comm did not match the known comm")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_pid_comm_matches);

fn smoke_abi_proc2_pid_comm_truncated_to_15() -> TestResult {
    const PID: u64 = 0x574b;
    // 20 chars in; TASK_COMM_LEN-1 = 15 kept (set_proc_comm truncates).
    with_procfs(PID, "abcdefghijklmnopqrst", &["x"], 0, |base| {
        let mut buf = [0u8; 64];
        let path = alloc::format!("{}/{}/comm\0", base, PID);
        let n = read_proc_file(path.as_bytes(), &mut buf)?;
        let s = core::str::from_utf8(&buf[..n]).map_err(|_| "comm not utf-8")?;
        let name = s.trim_end_matches('\n');
        if name == "abcdefghijklmno" {
            Ok(())
        } else {
            Err("/proc/<pid>/comm was not truncated to 15 bytes")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_pid_comm_truncated_to_15);

// ── /proc/<pid>/cmdline — NUL-separated argv ──

fn smoke_abi_proc2_pid_cmdline_nul_separated() -> TestResult {
    const PID: u64 = 0x574c;
    with_procfs(PID, "cmdproc", &["/bin/cmdproc", "-x", "arg"], 0, |base| {
        let mut buf = [0u8; 256];
        let path = alloc::format!("{}/{}/cmdline\0", base, PID);
        let n = read_proc_file(path.as_bytes(), &mut buf)?;
        let raw = &buf[..n];
        // Linux /proc/<pid>/cmdline: argv joined by NULs (trailing NUL after
        // the last arg). Split on NUL and drop the empty tail.
        let mut parts: alloc::vec::Vec<&[u8]> = raw.split(|&b| b == 0).collect();
        while parts.last() == Some(&&b""[..]) {
            parts.pop();
        }
        if parts.len() != 3 {
            return Err("cmdline did not split into 3 NUL-separated argv entries");
        }
        if parts[0] != b"/bin/cmdproc" || parts[1] != b"-x" || parts[2] != b"arg" {
            return Err("cmdline argv entries do not match the known argv");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_pid_cmdline_nul_separated);

// ── /proc/<pid>/fd/ — lists open fds; fd/N symlinks to its backing path ──

fn smoke_abi_proc2_pid_fd_lists_and_symlinks() -> TestResult {
    // Use FAKE_TASK (pid == tid) so the fd table the harness opens into is
    // the same TaskId proc_fd_list / fd_path_of resolve.
    with_procfs(FAKE_TASK, "fdproc", &["fdproc"], 0, |base| {
        // Seed a real backing file and open it in the caller's fd table.
        let auth = bootstrap_mount_authority();
        let fs = narf_filesystem::MemFs::with_seeds("fdm", &[("f", b"hi")]);
        let mh = registry()
            .mount(&auth, "/fdm", fs)
            .map_err(|_| "backing memfs mount failed")?;
        let result = (|| {
            let backing = b"/fdm/f\0";
            let srcfd = match call_open(backing.as_ptr() as u64, 0) {
                Some(fd) if fd >= 0 => fd as u32,
                _ => return Err("open of backing file failed"),
            };
            // /proc/<pid>/fd/<srcfd> readlinks to the recorded backing path.
            let link_path = alloc::format!("{}/{}/fd/{}\0", base, FAKE_TASK, srcfd);
            let mut tbuf = [0u8; 128];
            let tn = call_readlink(
                link_path.as_ptr() as u64,
                tbuf.as_mut_ptr() as u64,
                tbuf.len() as u64,
            );
            let tn = match tn {
                Some(v) if v > 0 => v as usize,
                _ => return Err("readlink of /proc/<pid>/fd/<n> failed"),
            };
            let target =
                core::str::from_utf8(&tbuf[..tn]).map_err(|_| "fd link target not utf-8")?;
            if !target.ends_with("/fdm/f") {
                return Err("/proc/<pid>/fd/<n> did not symlink to the backing path");
            }
            // The fd-list hook reports srcfd as an open fd for this task.
            let fds = crate::handlers::proc_fd_list(FAKE_TASK);
            if !fds.contains(&srcfd) {
                return Err("proc_fd_list did not list the freshly opened fd");
            }
            Ok(())
        })();
        let _ = registry().unmount(&mh, "/fdm");
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_pid_fd_lists_and_symlinks);

fn smoke_abi_proc2_fdinfo_uses_live_fd_metadata() -> TestResult {
    with_procfs(FAKE_TASK, "fdinfoproc", &["fdinfoproc"], 0, |base| {
        let auth = bootstrap_mount_authority();
        let fs = narf_filesystem::MemFs::with_seeds("fdinfo-mem", &[("f", b"hello")]);
        let mh = registry()
            .mount(&auth, "/fdinfo-mem", fs)
            .map_err(|_| "fdinfo backing mount failed")?;
        let result = (|| {
            let path = b"/fdinfo-mem/f\0";
            let fd = match call_open(path.as_ptr() as u64, 0o2) {
                Some(fd) if fd >= 0 => fd as u32,
                _ => return Err("fdinfo backing open failed"),
            };
            let ino = crate::fd::with_table(FAKE_TASK, |table| {
                let entry = table.get_mut(fd)?;
                entry.offset = 37;
                entry.status_flags = 0o2002;
                Some(entry.ops.ino())
            })
            .flatten()
            .ok_or("fdinfo entry disappeared")?;
            let mnt_id = crate::mqueue::fd_mount_id(FAKE_TASK, fd)
                .ok_or("fdinfo mount identity was not recorded")?;

            let fdinfo_path = alloc::format!("{}/{}/fdinfo/{}\0", base, FAKE_TASK, fd);
            let mut buf = [0u8; 512];
            let n = read_proc_file(fdinfo_path.as_bytes(), &mut buf)?;
            let text = core::str::from_utf8(&buf[..n]).map_err(|_| "fdinfo not utf-8")?;
            if !text.contains("pos:\t37\n") || !text.contains("flags:\t02002\n") {
                return Err("fdinfo did not expose live offset/status flags");
            }
            if !text.contains(&alloc::format!("mnt_id:\t{}\n", mnt_id))
                || !text.contains(&alloc::format!("ino:\t{}\n", ino))
            {
                return Err("fdinfo did not expose live mount/inode identity");
            }
            Ok(())
        })();
        let _ = registry().unmount(&mh, "/fdinfo-mem");
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_fdinfo_uses_live_fd_metadata);

// ── /proc/self resolves to the calling pid ──

fn smoke_abi_proc2_proc_self_is_caller() -> TestResult {
    with_procfs(FAKE_TASK, "selfproc", &["selfproc"], 0, |base| {
        // <base>/self/comm must render THIS task's comm — proving /proc/self
        // resolved to the caller's pid (FAKE_TASK).
        let mut buf = [0u8; 64];
        let comm_path = alloc::format!("{}/self/comm\0", base);
        let n = read_proc_file(comm_path.as_bytes(), &mut buf)?;
        let s = core::str::from_utf8(&buf[..n]).map_err(|_| "self/comm not utf-8")?;
        if s.trim_end_matches('\n') != "selfproc" {
            return Err("/proc/self/comm did not render the caller's comm");
        }
        // And <base>/self/stat's pid field 1 equals FAKE_TASK.
        let mut sbuf = [0u8; 512];
        let stat_path = alloc::format!("{}/self/stat\0", base);
        let sn = read_proc_file(stat_path.as_bytes(), &mut sbuf)?;
        let st = core::str::from_utf8(&sbuf[..sn]).map_err(|_| "self/stat not utf-8")?;
        let pid_field = st.split(' ').next().unwrap_or("");
        if pid_field != alloc::format!("{}", FAKE_TASK) {
            return Err("/proc/self/stat pid field is not the caller's pid");
        }
        // Linux procfs magic links report st_size == 0. readlink must still
        // use the caller's buffer and return the complete target.
        let self_path = alloc::format!("{}/self\0", base);
        let mut link_buf = [0u8; 32];
        let link_len = call_readlink(
            self_path.as_ptr() as u64,
            link_buf.as_mut_ptr() as u64,
            link_buf.len() as u64,
        );
        let link_len = match link_len {
            Some(n) if n > 0 => n as usize,
            _ => return Err("readlink of zero-size /proc/self failed"),
        };
        if &link_buf[..link_len] != alloc::format!("{}", FAKE_TASK).as_bytes() {
            return Err("/proc/self readlink target is not the caller's pid");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_proc_self_is_caller);

// ── /proc/<pid>/root symlink defaults to "/" (exe/cwd unimplemented here) ──
//
// exe/cwd render empty when no exec/cwd is recorded for the synthetic task
// (hook_exe_path / hook_cwd_path return None → empty target), so only the
// root magic link — which defaults to "/" — is asserted end-to-end.
fn smoke_abi_proc2_pid_root_symlink_default() -> TestResult {
    const PID: u64 = 0x574d;
    with_procfs(PID, "rootproc", &["rootproc"], 0, |base| {
        let mut buf = [0u8; 64];
        let path = alloc::format!("{}/{}/root\0", base, PID);
        let n = call_readlink(
            path.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        );
        let n = match n {
            Some(v) if v > 0 => v as usize,
            _ => return Err("readlink of /proc/<pid>/root failed"),
        };
        let target = core::str::from_utf8(&buf[..n]).map_err(|_| "root link not utf-8")?;
        if target == "/" {
            Ok(())
        } else {
            Err("/proc/<pid>/root did not default to '/'")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_pid_root_symlink_default);

// setpgid/getpgid interpret their pid AND pgid arguments in the CALLER's pid
// namespace (Linux find_task_by_vpid). `pgid_from_user` translates them to
// the TaskId the PGID_TABLE keys on; the container variant skipped the
// inner->outer hop and did `pid_to_task_raw(inner)` directly, so an
// in-namespace pgid resolved to whatever ROOT-namespace process owns the same
// small number. Job control (bash, `kill -TERM -$pgid`, systemd
// KillMode=control-group) all route through here.
//
// Exposed with a collision victim: a root-ns process registered at OUTER pid 2
// == the worker's INNER pid. The bug resolves the worker's inner pgid 2 to the
// victim; the fix resolves it to the worker.
#[cfg(feature = "container")]
fn smoke_abi_proc2_setpgid_resolves_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xB100;
        const MANAGER_PID: u64 = 0xB000;
        const WORKER_TASK: u64 = 0xB101;
        const WORKER_PID: u64 = 0xB001;
        const VICTIM_TASK: u64 = 0xB102;
        const VICTIM_PID: u64 = 2; // collides with the worker's INNER pid

        crate::pid_ns::__test_reset();
        let register = |task: u64, pid: u64| {
            crate::task::release_task(task);
            let _ = crate::task::Task::new_registered(task, pid);
            crate::handlers::register_task_to_pid(task, pid);
            crate::handlers::register_pid_task_mapping(pid, task);
        };
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            register(VICTIM_TASK, VICTIM_PID);
            crate::pid_ns::unshare_pid_ns(MANAGER_TASK, MANAGER_PID);
            if crate::pid_ns::inherit_into_child(MANAGER_TASK, WORKER_TASK, WORKER_PID) != Some(2) {
                return Err("worker was not assigned inner pid 2");
            }

            set_task(MANAGER_TASK);
            // setpgid(inner worker 2, inner pgid 2): make the worker its own
            // group leader, addressed entirely in the manager's namespace.
            if call(Syscall::Setpgid.raw(), a1(2, 2)) != Some(0) {
                return Err("setpgid(2, 2) did not succeed");
            }
            // getpgid(inner 2) must read back the worker's group as inner 2 —
            // NOT the victim's, and not 0.
            match call(Syscall::Getpgid.raw(), a0(2)) {
                Some(2) => Ok(()),
                Some(0) => Err(
                    "getpgid resolved the in-namespace pgid to a ROOT-namespace collision victim (setpgid keyed the wrong task) — inner->outer translation missing",
                ),
                Some(_) => Err("getpgid returned an unexpected pgid after setpgid"),
                None => Err("getpgid returned a non-Ok status"),
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        for t in [MANAGER_TASK, WORKER_TASK, VICTIM_TASK] {
            crate::task::release_task(t);
        }
        result
    })
}
#[cfg(feature = "container")]
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc2_setpgid_resolves_in_caller_pid_ns
);

// kill(-pgid) resolves the process group in the CALLER's pid namespace
// (Linux find_vpid(-pid)). The kill(2) handler's pid < -1 arm passed the raw
// in-namespace pgid straight to deliver_signal_to_pgrp, which compares
// against TaskId-space group ids — so a container's `kill -TERM -$pgid`
// (bash job control, systemd KillMode=control-group) signalled whatever
// ROOT-namespace group owned the same number, or nobody.
#[cfg(feature = "container")]
fn smoke_abi_proc2_kill_pgrp_resolves_in_caller_pid_ns() -> TestResult {
    const SIGUSR1: u64 = 10;
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xB200;
        const MANAGER_PID: u64 = 0xB000;
        const WORKER_TASK: u64 = 0xB201;
        const WORKER_PID: u64 = 0xB001;
        const VICTIM_TASK: u64 = 0xB202;
        const VICTIM_PID: u64 = 2; // collides with the worker's INNER pid

        crate::pid_ns::__test_reset();
        let register = |task: u64, pid: u64| {
            crate::task::release_task(task);
            let _ = crate::task::Task::new_registered(task, pid);
            crate::handlers::register_task_to_pid(task, pid);
            crate::handlers::register_pid_task_mapping(pid, task);
        };
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            register(VICTIM_TASK, VICTIM_PID);
            crate::pid_ns::unshare_pid_ns(MANAGER_TASK, MANAGER_PID);
            if crate::pid_ns::inherit_into_child(MANAGER_TASK, WORKER_TASK, WORKER_PID) != Some(2) {
                return Err("worker was not assigned inner pid 2");
            }
            set_task(MANAGER_TASK);
            // Put the worker in its own group (inner pgid 2).
            if call(Syscall::Setpgid.raw(), a1(2, 2)) != Some(0) {
                return Err("setpgid(2, 2) failed");
            }
            // Signal that group by its IN-NAMESPACE pgid.
            if call(Syscall::Kill.raw(), a1((-2i64) as u64, SIGUSR1)) != Some(0) {
                return Err("kill(-2, SIGUSR1) did not report success");
            }
            let worker_pending =
                crate::handlers::signal_pending_of(WORKER_TASK) & (1u64 << (SIGUSR1 - 1)) != 0;
            let victim_pending =
                crate::handlers::signal_pending_of(VICTIM_TASK) & (1u64 << (SIGUSR1 - 1)) != 0;
            if victim_pending {
                return Err("kill(-2) signalled the ROOT-namespace collision victim");
            }
            if !worker_pending {
                return Err(
                    "kill(-2) did not reach the worker's group — the in-namespace pgid was not translated",
                );
            }
            Ok(())
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        for t in [MANAGER_TASK, WORKER_TASK, VICTIM_TASK] {
            crate::task::release_task(t);
        }
        result
    })
}
#[cfg(feature = "container")]
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc2_kill_pgrp_resolves_in_caller_pid_ns
);
