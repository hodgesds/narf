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

// ── capset(2) — datap == NULL EFAULT + wrong-pid arm ──

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

fn smoke_abi_proc2_capset_other_pid() -> TestResult {
    with_setup(|| {
        // capset only operates on the calling thread; a header naming a pid
        // that is neither 0 nor the caller takes the `pid != self → -1`
        // (EPERM-ish) arm. The base file never sets a non-self pid.
        // LINUX-GAP: Linux returns -EPERM for cross-thread capset; NARF
        // returns the bare -1 sentinel.
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
            Some(-1) => Ok(()),
            _ => Err("capset for a non-self pid did not return -1"),
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
        // WNOHANG no-child success → 0. The base file only drives P_ALL.
        const P_PID: u64 = 1;
        const WNOHANG: u64 = 1;
        let mut si = [0u8; 128];
        match call(
            Syscall::Waitid.raw(),
            a3(P_PID, 4242, si.as_mut_ptr() as u64, WNOHANG),
        ) {
            Some(0) => Ok(()),
            _ => Err("waitid(P_PID, WNOHANG) with no child did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_waitid_ppid_no_child);

fn smoke_abi_proc2_waitid_blocking_fallback() -> TestResult {
    with_setup(|| {
        // waitid with NO WNOHANG and no child: there is no UserTaskCtx / yield
        // hook in the harness, so the blocking arm falls through to the
        // "report no child" fallback (ok(0)) rather than parking. This pins
        // the no-future fallback the base file's WNOHANG-only case skips.
        const P_ALL: u64 = 0;
        let mut si = [0u8; 128];
        match call(
            Syscall::Waitid.raw(),
            a3(P_ALL, 0, si.as_mut_ptr() as u64, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("waitid blocking fallback (no future) did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_waitid_blocking_fallback);

// ── unshare(2) — mount-namespace arm (CLONE_NEWNS) ──

fn smoke_abi_proc2_unshare_newns() -> TestResult {
    with_setup(|| {
        // unshare(CLONE_NEWNS) takes the feature-independent mount-namespace
        // arm: it inits the per-task mount-ns table, snapshots the global
        // mounts, records the entry (any = true) and returns 0. The base file
        // only covers the flags == 0 no-op success.
        const CLONE_NEWNS: u64 = 0x0002_0000;
        match call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) {
            Some(0) => Ok(()),
            _ => Err("unshare(CLONE_NEWNS) did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc2_unshare_newns);

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
        // 0 clears; out-of-range (64: no bit in the u64 signal maps) → EINVAL.
        if call(Syscall::Prctl.raw(), a1(1, 0)) != Some(0) {
            return Err("PR_SET_PDEATHSIG(0) should clear and return 0");
        }
        if call(Syscall::Prctl.raw(), a1(1, 64)) != Some(-22) {
            return Err("PR_SET_PDEATHSIG(64) should return -EINVAL");
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
        if crate::handlers::signal_pending_of(KID) & (1u64 << 10) == 0 {
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
