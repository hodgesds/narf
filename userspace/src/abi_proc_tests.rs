//! Linux syscall ABI conformance — proc group.
//!
//! Process/thread-management syscalls. Shares the harness in
//! [`crate::abi_test_support`]. Every test drives `kernel_syscall_entry`
//! against a synthetic `AbiCtx` (no user mode, no scheduler, no live
//! address space), so the reachable surface for the fork/clone/exec
//! family is the immediate argument-validation + table-bookkeeping path;
//! the success path that spawns a real child task is unreachable here and
//! is exercised only with its error/stub return.
#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;

// ── getppid(2) — infallible, returns parent visible pid (0 if none) ──

fn smoke_abi_proc_getppid_pos() -> TestResult {
    with_setup(|| {
        // getppid is infallible: it always reports Ok with the parent's
        // visible pid, defaulting to 0 when no parent-of mapping exists
        // for the fake task. Assert the Ok status + a non-negative value.
        match call(Syscall::GetPpid.raw(), a0(0)) {
            Some(v) if v >= 0 => Ok(()),
            Some(_) => Err("getppid returned negative"),
            None => Err("getppid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_getppid_pos);

fn smoke_abi_proc_getppid_ignores_args() -> TestResult {
    with_setup(|| {
        // getppid takes no arguments; garbage in arg0 must not change the
        // result (regression pin against an args-shape drift).
        let clean = call(Syscall::GetPpid.raw(), a0(0));
        let garbage = call(Syscall::GetPpid.raw(), a0(0xdead_beef));
        if clean == garbage {
            Ok(())
        } else {
            Err("getppid result changed with garbage in arg0")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_getppid_ignores_args);

// ── gettid(2) — infallible; a group leader's tid equals its pid ──

fn smoke_abi_proc_gettid_pos() -> TestResult {
    with_setup(|| {
        // The harness reports FAKE_TASK as the current task id; gettid
        // returns exactly that.
        match call(Syscall::Gettid.raw(), a0(0)) {
            Some(v) if v as u64 == FAKE_TASK => Ok(()),
            Some(_) => Err("gettid did not return the current task id"),
            None => Err("gettid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_gettid_pos);

fn smoke_abi_proc_gettid_tracks_set_task() -> TestResult {
    with_setup(|| {
        set_task(4242);
        let r = call(Syscall::Gettid.raw(), a0(0));
        set_task(FAKE_TASK);
        match r {
            Some(4242) => Ok(()),
            _ => Err("gettid did not follow the overridden task id"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_gettid_tracks_set_task);

fn smoke_abi_proc_gettid_group_leader_equals_pid() -> TestResult {
    with_setup(|| {
        const TASK: u64 = 0xBEEF;
        const PID: u64 = 0xCAFE;
        set_task(TASK);
        crate::handlers::register_pid_task_mapping(PID, TASK);
        let result = call(Syscall::Gettid.raw(), a0(0));
        set_task(FAKE_TASK);
        match result {
            Some(value) if value == PID as i64 => Ok(()),
            _ => Err("gettid did not equal getpid for group leader"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_gettid_group_leader_equals_pid);

// ── getpgid(2) / setpgid(2) — process-group bookkeeping ──

fn smoke_abi_proc_setpgid_pos() -> TestResult {
    with_setup(|| {
        // setpgid(0, 0): make the caller its own group leader. PGID_TABLE
        // is boot-initialised, so this records the entry and returns 0.
        match call(Syscall::Setpgid.raw(), a1(0, 0)) {
            Some(0) => Ok(()),
            Some(_) => Err("setpgid(0,0) should return 0"),
            None => Err("setpgid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setpgid_pos);

fn smoke_abi_proc_getpgid_pos() -> TestResult {
    with_setup(|| {
        // After setpgid(0,0) the caller's pgid is itself; getpgid(0) must
        // then report a non-negative group id (the exact value depends on
        // pid-space translation under the container feature, so we only
        // assert Ok + non-negative).
        let _ = call(Syscall::Setpgid.raw(), a1(0, 0));
        match call(Syscall::Getpgid.raw(), a0(0)) {
            Some(v) if v >= 0 => Ok(()),
            Some(_) => Err("getpgid returned negative pgid"),
            None => Err("getpgid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_getpgid_pos);

fn smoke_abi_proc_setpgid_neg() -> TestResult {
    with_setup(|| {
        // NARF's setpgid never validates the target's existence/session;
        // it inserts unconditionally and returns 0. The only failure path
        // is an uninitialised table, which can't happen post-boot — so the
        // negative case here is the absence of an error: a setpgid against
        // an arbitrary (unknown) target pid still returns 0, not an errno.
        // LINUX-GAP: Linux returns -ESRCH for a non-existent target pid and
        // -EPERM across session boundaries; NARF accepts any pid with ok(0).
        match call(Syscall::Setpgid.raw(), a1(123456, 0)) {
            Some(0) => Ok(()),
            other => {
                let _ = other;
                Err("setpgid on an unknown pid changed from ok(0)")
            }
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setpgid_neg);

// ── getpgrp(2) — caller's pgid, no args ──

fn smoke_abi_proc_getpgrp_pos() -> TestResult {
    with_setup(|| match call_getpgrp() {
        Some(v) if v >= 0 => Ok(()),
        Some(_) => Err("getpgrp returned negative"),
        None => Err("getpgrp returned non-Ok status"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_getpgrp_pos);

// ── getsid(2) / setsid(2) — session bookkeeping ──

fn smoke_abi_proc_setsid_pos() -> TestResult {
    with_setup(|| {
        // setsid makes the caller a session leader: sid = pgid = pid. The
        // handler records both tables and returns the new sid. SID_TABLE is
        // boot-initialised so this succeeds.
        match call(Syscall::Setsid.raw(), a0(0)) {
            Some(v) if v >= 0 => Ok(()),
            Some(_) => Err("setsid returned negative sid"),
            None => Err("setsid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setsid_pos);

fn smoke_abi_proc_getsid_pos() -> TestResult {
    with_setup(|| {
        // getsid(0) reads the caller's session id, defaulting to its own
        // task id when no setsid mapping exists. Infallible → Ok + >= 0.
        match call(Syscall::Getsid.raw(), a0(0)) {
            Some(v) if v >= 0 => Ok(()),
            Some(_) => Err("getsid returned negative"),
            None => Err("getsid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_getsid_pos);

fn smoke_abi_proc_getsid_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: Linux returns -ESRCH for getsid of a non-existent pid;
        // NARF's getsid has no error path — an unknown pid resolves to the
        // pid itself (default sid == pid) and returns Ok.
        match call(Syscall::Getsid.raw(), a0(987654)) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("getsid on an unknown pid changed from the ok-default path"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_getsid_neg);

// getsid(2) must return the session id in the caller's VISIBLE-pid space —
// the ProcessId, never the raw scheduler TaskId. `setsid` records the sid in
// TaskId space (SID_TABLE[tid] = tid), so getsid has to translate TaskId →
// ProcessId on the way out, exactly as `getpgid`/`getpgrp` do via
// `pgid_to_user`. The handler instead wrapped the raw sid in
// `report_pid_to`, which is the IDENTITY in a non-container build and expects
// an outer pid (not a TaskId) in a container build — so the mandatory
// `task_to_pid_raw` hop was missing and a raw TaskId leaked to userspace in
// EVERY build.
//
// agetty/login compare `getsid(0)` against `tcgetsid(fd)` (which goes through
// `current_task_sid_user` → `pgid_to_user`, the CORRECT idiom) to confirm
// they own the tty's session after TIOCSCTTY; when the two come from
// different number spaces the check can only pass by coincidence.
//
// Exposed only when TaskId != ProcessId, which the default FAKE_TASK
// (tid == pid == 99) hides — so drive a task whose registered pid differs.
fn smoke_abi_proc_getsid_reports_visible_pid_space() -> TestResult {
    with_setup(|| {
        const LEADER_TID: u64 = 0x5501;
        const LEADER_PID: u64 = 0x5502; // deliberately != LEADER_TID
        set_task(LEADER_TID);
        crate::handlers::register_task_to_pid(LEADER_TID, LEADER_PID);
        crate::handlers::register_pid_task_mapping(LEADER_PID, LEADER_TID);

        // Become a session leader: sid == pid, recorded in TaskId space.
        if call(Syscall::Setsid.raw(), a0(0))
            .filter(|&v| v >= 0)
            .is_none()
        {
            set_task(FAKE_TASK);
            return Err("setsid setup failed");
        }
        let sid = call(Syscall::Getsid.raw(), a0(0));
        set_task(FAKE_TASK);
        match sid {
            Some(v) if v as u64 == LEADER_PID => Ok(()),
            Some(v) if v as u64 == LEADER_TID => Err(
                "getsid returned the raw scheduler TaskId instead of the visible ProcessId — the TaskId->pid translation is missing",
            ),
            Some(_) => Err("getsid returned an unexpected value"),
            None => Err("getsid returned a non-Ok status"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc_getsid_reports_visible_pid_space
);

// ── prctl(2) — PR_SET/GET_NO_NEW_PRIVS round-trip + bad op ──

fn smoke_abi_proc_prctl_pos() -> TestResult {
    with_setup(|| {
        // PR_SET_NO_NEW_PRIVS = 38, arg = 1. Then PR_GET_NO_NEW_PRIVS = 39
        // must read back 1. PRCTL_TABLE is boot-initialised; this round-trips
        // deterministically regardless of any prior boot-time state for the
        // fake task (we set then immediately get).
        const PR_SET_NO_NEW_PRIVS: u64 = 38;
        const PR_GET_NO_NEW_PRIVS: u64 = 39;
        match call(Syscall::Prctl.raw(), a1(PR_SET_NO_NEW_PRIVS, 1)) {
            Some(0) => {}
            _ => return Err("PR_SET_NO_NEW_PRIVS did not return 0"),
        }
        match call(Syscall::Prctl.raw(), a0(PR_GET_NO_NEW_PRIVS)) {
            Some(1) => Ok(()),
            _ => Err("PR_GET_NO_NEW_PRIVS did not read back 1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_prctl_pos);

fn smoke_abi_proc_prctl_neg() -> TestResult {
    with_setup(|| {
        // An unrecognised prctl option returns -EINVAL, matching Linux (NOT the
        // -1/EPERM sentinel — that made systemd treat a PR_SET_MDWE feature
        // probe as a fatal 228/EXIT_SECCOMP instead of degrading to seccomp).
        match call(Syscall::Prctl.raw(), a0(0xFFFF)) {
            Some(-22) => Ok(()),
            other => {
                let _ = other;
                Err("prctl with an unknown op must return -EINVAL")
            }
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_prctl_neg);

// prctl feature-probe / no-op options systemd and glibc exercise during
// service setup. PR_SET_MDWE must report EINVAL (unsupported, pre-6.3-style) so
// systemd's MemoryDenyWriteExecute= falls back to seccomp instead of failing
// 228/EXIT_SECCOMP; the rest are accepted no-ops with Linux-shaped returns.
fn smoke_abi_proc_prctl_feature_probes() -> TestResult {
    with_setup(|| {
        const PR_GET_TSC: u64 = 25;
        const PR_SET_TSC: u64 = 26;
        const PR_SET_TIMERSLACK: u64 = 29;
        const PR_GET_TIMERSLACK: u64 = 30;
        const PR_SET_THP_DISABLE: u64 = 41;
        const PR_SET_MDWE: u64 = 65;
        const PR_MDWE_REFUSE_EXEC_GAIN: u64 = 1;

        // MDWE is unsupported → EINVAL (drives systemd's seccomp fallback).
        match call(
            Syscall::Prctl.raw(),
            a1(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN),
        ) {
            Some(-22) => {}
            _ => return Err("PR_SET_MDWE must return -EINVAL (unsupported)"),
        }
        // Timer slack: SET accepted, GET returns the default slack (ns).
        match call(Syscall::Prctl.raw(), a1(PR_SET_TIMERSLACK, 1000)) {
            Some(0) => {}
            _ => return Err("PR_SET_TIMERSLACK must return 0"),
        }
        match call(Syscall::Prctl.raw(), a0(PR_GET_TIMERSLACK)) {
            Some(v) if v > 0 => {}
            _ => return Err("PR_GET_TIMERSLACK must return a positive slack"),
        }
        // TSC stays enabled: SET_TSC(ENABLE) and GET_TSC both succeed.
        let mut tsc = [0u8; 4];
        match call(Syscall::Prctl.raw(), a1(PR_SET_TSC, 1)) {
            Some(0) => {}
            _ => return Err("PR_SET_TSC must return 0"),
        }
        match call(
            Syscall::Prctl.raw(),
            a1(PR_GET_TSC, tsc.as_mut_ptr() as u64),
        ) {
            Some(0) => {}
            _ => return Err("PR_GET_TSC must return 0"),
        }
        if i32::from_ne_bytes(tsc) != 1 {
            return Err("PR_GET_TSC must report rdtsc enabled (1)");
        }
        // THP toggle is a no-op success (NARF has no transparent huge pages).
        match call(Syscall::Prctl.raw(), a1(PR_SET_THP_DISABLE, 1)) {
            Some(0) => Ok(()),
            _ => Err("PR_SET_THP_DISABLE must return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_prctl_feature_probes);

fn smoke_abi_proc_prctl_keepcaps_roundtrip() -> TestResult {
    with_setup(|| {
        const PR_GET_KEEPCAPS: u64 = 7;
        const PR_SET_KEEPCAPS: u64 = 8;

        match call(Syscall::Prctl.raw(), a1(PR_SET_KEEPCAPS, 1)) {
            Some(0) => {}
            _ => return Err("PR_SET_KEEPCAPS(1) did not return 0"),
        }
        match call(Syscall::Prctl.raw(), a0(PR_GET_KEEPCAPS)) {
            Some(1) => {}
            _ => return Err("PR_GET_KEEPCAPS did not read back 1"),
        }
        match call(Syscall::Prctl.raw(), a1(PR_SET_KEEPCAPS, 2)) {
            Some(-22) => Ok(()),
            _ => Err("PR_SET_KEEPCAPS accepted a non-boolean value"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_prctl_keepcaps_roundtrip);

// ── prctl(PR_CAP_AMBIENT) — ambient capability set round-trip ──

fn smoke_abi_proc_prctl_cap_ambient() -> TestResult {
    with_setup(|| {
        // systemd's early init drives CLEAR_ALL, then RAISE/LOWER/IS_SET.
        const PR_CAP_AMBIENT: u64 = 47;
        const PR_CAP_AMBIENT_IS_SET: u64 = 1;
        const PR_CAP_AMBIENT_RAISE: u64 = 2;
        const PR_CAP_AMBIENT_LOWER: u64 = 3;
        const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;
        const CAP_NET_ADMIN: u64 = 12;

        // CLEAR_ALL succeeds and empties the set.
        match call(
            Syscall::Prctl.raw(),
            a2(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0),
        ) {
            Some(0) => {}
            _ => return Err("PR_CAP_AMBIENT_CLEAR_ALL did not return 0"),
        }
        // IS_SET on the just-cleared cap reads back 0.
        match call(
            Syscall::Prctl.raw(),
            a2(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_NET_ADMIN),
        ) {
            Some(0) => {}
            _ => return Err("PR_CAP_AMBIENT_IS_SET after clear did not read 0"),
        }
        // RAISE then IS_SET reads back 1.
        match call(
            Syscall::Prctl.raw(),
            a2(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN),
        ) {
            Some(0) => {}
            _ => return Err("PR_CAP_AMBIENT_RAISE did not return 0"),
        }
        match call(
            Syscall::Prctl.raw(),
            a2(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_NET_ADMIN),
        ) {
            Some(1) => {}
            _ => return Err("PR_CAP_AMBIENT_IS_SET after raise did not read 1"),
        }
        // LOWER then IS_SET reads back 0 again.
        match call(
            Syscall::Prctl.raw(),
            a2(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_NET_ADMIN),
        ) {
            Some(0) => {}
            _ => return Err("PR_CAP_AMBIENT_LOWER did not return 0"),
        }
        match call(
            Syscall::Prctl.raw(),
            a2(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_NET_ADMIN),
        ) {
            Some(0) => Ok(()),
            _ => Err("PR_CAP_AMBIENT_IS_SET after lower did not read 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_prctl_cap_ambient);

// ── arch_prctl(2) — x86_64 thread-pointer install ──

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_arch_prctl_pos() -> TestResult {
    with_setup(|| {
        // ARCH_GET_FS = 0x1003: read the live IA32_FS_BASE and copy it as a
        // u64 to a (kernel-stack) buffer the harness passes as the "user"
        // pointer. copy_to_user operates on real addresses here, so the
        // write succeeds and the handler returns 0.
        const ARCH_GET_FS: u64 = 0x1003;
        let mut out = [0u8; 8];
        match call(
            Syscall::ArchPrctl.raw(),
            a1(ARCH_GET_FS, out.as_mut_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("arch_prctl ARCH_GET_FS did not return 0"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_arch_prctl_pos);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_arch_prctl_neg() -> TestResult {
    with_setup(|| {
        // ARCH_SET_GS = 0x1001 is not yet wired; the handler returns
        // -EINVAL. An unknown sub-code (0x9999) likewise returns -EINVAL.
        const ARCH_SET_GS: u64 = 0x1001;
        match call(Syscall::ArchPrctl.raw(), a1(ARCH_SET_GS, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("arch_prctl ARCH_SET_GS did not return -EINVAL"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_arch_prctl_neg);

// ── set_tid_address(2) — records clear_child_tid, returns caller TID ──

fn smoke_abi_proc_set_tid_address_pos() -> TestResult {
    with_setup(|| {
        // set_tid_address records the pointer regardless of value and
        // returns the caller's TID (FAKE_TASK). A NULL pointer is the
        // legal "disable clear_child_tid" case and still returns the TID.
        match call(Syscall::SetTidAddress.raw(), a0(0)) {
            Some(v) if v as u64 == FAKE_TASK => Ok(()),
            Some(_) => Err("set_tid_address did not return the caller TID"),
            None => Err("set_tid_address returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_set_tid_address_pos);

fn smoke_abi_proc_set_tid_address_nonzero() -> TestResult {
    with_setup(|| {
        // A non-zero (kernel-stack) pointer is recorded the same way; the
        // return is invariant to the pointer value (it's always the TID).
        let mut slot = [0u8; 8];
        match call(Syscall::SetTidAddress.raw(), a0(slot.as_mut_ptr() as u64)) {
            Some(v) if v as u64 == FAKE_TASK => Ok(()),
            _ => Err("set_tid_address with a pointer did not return the TID"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_set_tid_address_nonzero);

// ── capget(2) / capset(2) — capability-set round-trip ──

fn smoke_abi_proc_capset_capget_pos() -> TestResult {
    with_setup(|| {
        // capset then capget with the v3 header round-trips a cap mask.
        // The harness passes kernel-stack buffers as the user hdr/data
        // pointers; copy_{from,to}_user operate on real addresses.
        const CAP_VERSION_3: u32 = 0x2008_0522;
        // header: { u32 version; i32 pid } — pid 0 = self.
        let mut hdr = [0u8; 8];
        hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
        // data: 2 * cap_user_data_t, each { u32 effective; u32 permitted;
        // u32 inheritable }. For ndata=2 the layout is field-major: 3 lo
        // words then 3 hi words. Plant a low-word effective bit.
        let mut data = [0u8; 24];
        data[0..4].copy_from_slice(&0x0000_0001u32.to_le_bytes()); // effective lo
        match call(
            Syscall::Capset.raw(),
            a1(hdr.as_mut_ptr() as u64, data.as_mut_ptr() as u64),
        ) {
            Some(0) => {}
            _ => return Err("capset with a v3 header did not return 0"),
        }
        // Read it back.
        let mut out = [0u8; 24];
        match call(
            Syscall::Capget.raw(),
            a1(hdr.as_mut_ptr() as u64, out.as_mut_ptr() as u64),
        ) {
            Some(0) => {}
            _ => return Err("capget with a v3 header did not return 0"),
        }
        if out[0..4] == 0x0000_0001u32.to_le_bytes() {
            Ok(())
        } else {
            Err("capget did not read back the effective bit set by capset")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_capset_capget_pos);

fn smoke_abi_proc_capget_neg() -> TestResult {
    with_setup(|| {
        // hdrp == NULL → EFAULT (Linux-shaped error in the value).
        match call(Syscall::Capget.raw(), a1(0, 0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("capget(NULL,..) did not return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_capget_neg);

fn smoke_abi_proc_capset_neg() -> TestResult {
    with_setup(|| {
        // An unknown capability version makes capset rewrite the header to
        // the preferred version and return EINVAL (Linux retry protocol).
        let mut hdr = [0u8; 8];
        hdr[..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let mut data = [0u8; 24];
        match call(
            Syscall::Capset.raw(),
            a1(hdr.as_mut_ptr() as u64, data.as_mut_ptr() as u64),
        ) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("capset with a bad version did not return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_capset_neg);

// ── personality(2) — always-accept stub ──

fn smoke_abi_proc_personality_pos() -> TestResult {
    with_setup(|| {
        // NARF's personality is a stub that returns 0 (the prior
        // personality, conventionally PER_LINUX == 0) for any argument.
        match call(Syscall::Personality.raw(), a0(0xffff_ffff)) {
            Some(0) => Ok(()),
            _ => Err("personality stub did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_personality_pos);

// ── kcmp(2) — resource comparison ──

fn smoke_abi_proc_kcmp_pos() -> TestResult {
    with_setup(|| {
        // kcmp(self, self, KCMP_VM, 0, 0): a task shares every resource
        // with itself → 0. KCMP_VM == 1.
        const KCMP_VM: u64 = 1;
        match call(Syscall::Kcmp.raw(), a3(FAKE_TASK, FAKE_TASK, KCMP_VM, 0)) {
            Some(0) => Ok(()),
            _ => Err("kcmp(self,self) did not return 0 (equal)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_kcmp_pos);

fn smoke_abi_proc_kcmp_neg() -> TestResult {
    with_setup(|| {
        // type >= KCMP_TYPES (8) → EINVAL.
        match call(Syscall::Kcmp.raw(), a3(FAKE_TASK, FAKE_TASK, 99, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("kcmp with an out-of-range type did not return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_kcmp_neg);

fn smoke_abi_proc_kcmp_esrch() -> TestResult {
    with_setup(|| {
        // An unknown pid (no PID→TaskId mapping, and != self) → ESRCH.
        const KCMP_VM: u64 = 1;
        match call(Syscall::Kcmp.raw(), a3(FAKE_TASK, 7_654_321, KCMP_VM, 0)) {
            Some(v) if v == ESRCH => Ok(()),
            _ => Err("kcmp with an unknown pid did not return -ESRCH"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_kcmp_esrch);

// ── pidfd_open(2) — mint a pidfd ──

fn smoke_abi_proc_pidfd_open_pos() -> TestResult {
    with_setup(|| {
        // A non-zero pid with no live mapping is treated as a zombie and a
        // pidfd is minted + installed in the caller's fd table, returning a
        // small non-negative fd.
        match call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, 0)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("pidfd_open did not return a valid fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_open_pos);

fn smoke_abi_proc_pidfd_open_neg() -> TestResult {
    with_setup(|| {
        // pid == 0 is rejected with the -1 sentinel.
        // LINUX-GAP: Linux returns -EINVAL for pid 0; NARF returns -1.
        match call(Syscall::PidfdOpen.raw(), a1(0, 0)) {
            Some(-1) => Ok(()),
            _ => Err("pidfd_open(0) did not return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_open_neg);

#[cfg(feature = "container")]
fn smoke_abi_proc_pidfd_open_translates_inner_pid() -> TestResult {
    with_setup(|| {
        const CALLER_OUTER: u64 = 10_000;
        const CHILD_TASK: u64 = 20_001;
        const CHILD_OUTER: u64 = 10_001;

        crate::pid_ns::__test_reset();
        crate::pid_ns::unshare_pid_ns(FAKE_TASK, CALLER_OUTER);
        let inner =
            crate::pid_ns::inherit_into_child(FAKE_TASK, CHILD_TASK, CHILD_OUTER).unwrap_or(0);
        crate::handlers::register_pid_task_mapping(CHILD_OUTER, CHILD_TASK);

        let fd = match call(Syscall::PidfdOpen.raw(), a1(inner, 0)) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => {
                crate::pid_ns::__test_reset();
                return Err("pidfd_open(inner pid) did not return a valid fd");
            }
        };
        let target = crate::fd::with_table(FAKE_TASK, |t| {
            t.get(fd).and_then(|entry| entry.ops.pidfd_target_pid())
        })
        .flatten();
        crate::pid_ns::__test_reset();

        if target == Some(CHILD_OUTER) {
            Ok(())
        } else {
            Err("pidfd_open did not translate inner pid to outer ProcessId")
        }
    })
}
#[cfg(feature = "container")]
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc_pidfd_open_translates_inner_pid
);

// ── pidfd_send_signal(2) — deliver via a pidfd ──

fn smoke_abi_proc_pidfd_send_signal_pos() -> TestResult {
    with_setup(|| {
        // Mint a pidfd for self, then pidfd_send_signal(pidfd, 0, ...): sig
        // 0 is the existence/permission probe — it resolves the target and
        // returns 0 without queuing anything.
        let pidfd = match call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("pidfd_open setup failed"),
        };
        match call(Syscall::PidfdSendSignal.raw(), a3(pidfd, 0, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("pidfd_send_signal(sig 0) did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_send_signal_pos);

fn smoke_abi_proc_pidfd_send_signal_neg() -> TestResult {
    with_setup(|| {
        // signum > 64 → EINVAL (checked before any fd resolution). 64 is
        // valid now (SIGRTMAX), so 65 is the out-of-range probe.
        match call(Syscall::PidfdSendSignal.raw(), a3(3, 65, 0, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("pidfd_send_signal with sig 65 did not return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_send_signal_neg);

fn smoke_abi_proc_pidfd_send_signal_badfd() -> TestResult {
    with_setup(|| {
        // A valid signum but an fd that isn't a pidfd → EBADF.
        match call(Syscall::PidfdSendSignal.raw(), a3(4242, 9, 0, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("pidfd_send_signal on a non-pidfd did not return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_send_signal_badfd);

// ── pidfd_getfd(2) — clone an fd out of a pidfd's target ──

fn smoke_abi_proc_pidfd_getfd_neg() -> TestResult {
    with_setup(|| {
        // flags != 0 → EINVAL (validated first).
        match call(Syscall::PidfdGetfd.raw(), a3(0, 0, 1, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("pidfd_getfd with non-zero flags did not return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_getfd_neg);

fn smoke_abi_proc_pidfd_getfd_badfd() -> TestResult {
    with_setup(|| {
        // flags == 0 but arg0 is not a pidfd → EBADF.
        match call(Syscall::PidfdGetfd.raw(), a3(4242, 0, 0, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("pidfd_getfd on a non-pidfd did not return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_getfd_badfd);

fn smoke_abi_proc_pidfd_getfd_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        // Open a real fd in the (single) task's fd table, mint a pidfd for
        // self, then pidfd_getfd should duplicate that fd into a new slot.
        // target_pid == self short-circuits the pid→task resolution so the
        // source table is the caller's own.
        let path = b"/abi/f\0";
        let srcfd = match call_open(path.as_ptr() as u64, 0) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open setup failed"),
        };
        let pidfd = match call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("pidfd_open setup failed"),
        };
        match call(Syscall::PidfdGetfd.raw(), a3(pidfd, srcfd, 0, 0)) {
            Some(newfd) if newfd >= 0 && newfd as u64 != srcfd => Ok(()),
            Some(_) => Err("pidfd_getfd returned an unexpected fd"),
            None => Err("pidfd_getfd returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_getfd_pos);

// ── wait4(2) — non-blocking reap paths ──

fn smoke_abi_proc_wait4_wnohang_no_child() -> TestResult {
    with_setup(|| {
        // wait4(-1, NULL, WNOHANG, NULL) with NO children at all → -ECHILD.
        // Linux (kernel/exit.c __do_wait): notask_error stays -ECHILD and
        // WNOHANG only turns it into 0 when an *eligible* (living, unreaped)
        // child exists. FAKE_TASK has no children, so the handler's
        // has_living_child gate returns -ECHILD before the WNOHANG
        // short-circuit. WNOHANG == 1.
        const WNOHANG: u64 = 1;
        match call(Syscall::Wait4.raw(), a3((-1i64) as u64, 0, WNOHANG, 0)) {
            Some(v) if v == ECHILD => Ok(()),
            _ => Err("wait4 WNOHANG with no child must return -ECHILD"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_wait4_wnohang_no_child);

// The blocking (non-WNOHANG, no-child) wait4 path is only exercised via the
// polling future, so the immediate-return WNOHANG path above is the
// reachable surface here. Both now return -ECHILD, matching Linux.

// ── waitid(2) — non-blocking + validation paths ──

fn smoke_abi_proc_waitid_wnohang_no_child() -> TestResult {
    with_setup(|| {
        // waitid(P_ALL, 0, infop, WNOHANG) with NO child at all → -ECHILD,
        // exactly as the wait4 case above and for the same reason: Linux
        // (kernel/exit.c __do_wait) leaves notask_error at -ECHILD and
        // WNOHANG only turns it into 0 when an *eligible* child exists.
        // This previously expected 0, which was NARF's pre-guard behaviour;
        // a blocking waitid in that state parked forever with no backstop.
        const P_ALL: u64 = 0;
        const WNOHANG: u64 = 1;
        let mut si = [0u8; 128];
        match call(
            Syscall::Waitid.raw(),
            a3(P_ALL, 0, si.as_mut_ptr() as u64, WNOHANG),
        ) {
            Some(v) if v == ECHILD => Ok(()),
            _ => Err("waitid WNOHANG with no child must return -ECHILD"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_waitid_wnohang_no_child);

fn smoke_abi_proc_waitid_neg() -> TestResult {
    with_setup(|| {
        // An unrecognised idtype → EINVAL. idtype 3 is P_PIDFD (a *valid*
        // idtype since Linux 5.4), so 4 is the first genuinely-unknown value.
        match call(Syscall::Waitid.raw(), a3(4, 0, 0, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("waitid with a bad idtype did not return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_waitid_neg);

fn smoke_abi_proc_waitid_pidfd_badfd() -> TestResult {
    with_setup(|| {
        // idtype 3 = P_PIDFD is a *valid* idtype; `id` is a pidfd. A pidfd
        // that names no open fd → EBADF (not EINVAL). glibc's
        // __clone_pidfd_supported() probes exactly this and requires EBADF
        // to enable pidfd_spawn (systemd 258's only service-exec path).
        match call(Syscall::Waitid.raw(), a3(3, 0x7fff_ffff, 0, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("waitid(P_PIDFD, bad fd) did not return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_waitid_pidfd_badfd);

// ── #29 pgid-filtered wait: wait4(pid<-1), wait4(0), waitid(P_PGID) ──
//
// A process-group-scoped wait must reap only children in the target group,
// not "any child" (the old collapse). Each test stages two zombies in
// DIFFERENT process groups under the caller and asserts the group-scoped wait
// picks the matching one — never the first-queued one, which is what the
// any-child collapse returned.

/// Register `task`↔`pid` (both directions) and put `task` in process group
/// `pgid` (a task-space pgid). Mirrors `abi_pidns_tests::register` locally.
fn wt_register(task: u64, pid: u64, pgid: u64) {
    crate::task::release_task(task);
    let _ = crate::task::Task::new_registered(task, pid);
    crate::handlers::register_task_to_pid(task, pid);
    crate::handlers::register_pid_task_mapping(pid, task);
    crate::handlers::__test_set_pgid(task, pgid);
}

// wait4(-pgid): reap the zombie in group -pid, not the first-queued sibling.
fn smoke_abi_proc_wait4_pgid_selects_group() -> TestResult {
    with_setup(|| {
        const PARENT: u64 = 0x7000_0000;
        const PARENT_PID: u64 = 0x7000_1000;
        const GA_LEADER: u64 = 0x7000_0101; // group A leader task (pgid value)
        const GB_LEADER: u64 = 0x7000_0102; // group B leader task
        const GB_LEADER_PID: u64 = 0x7000_2102;
        const C1_TASK: u64 = 0x7000_0201;
        const C1_PID: u64 = 0x7000_1201; // in group A, queued FIRST
        const C2_TASK: u64 = 0x7000_0202;
        const C2_PID: u64 = 0x7000_1202; // in group B, queued SECOND

        let result = {
            wt_register(PARENT, PARENT_PID, PARENT);
            wt_register(C1_TASK, C1_PID, GA_LEADER);
            wt_register(C2_TASK, C2_PID, GB_LEADER);
            // The group-B leader must be pid→task resolvable so pgid_from_user
            // maps its pid back to GB_LEADER.
            crate::handlers::register_task_to_pid(GB_LEADER, GB_LEADER_PID);
            crate::handlers::register_pid_task_mapping(GB_LEADER_PID, GB_LEADER);

            // Two zombies queued under PARENT: A first, B second.
            crate::handlers::__test_stage_pending_exit(PARENT, C1_PID, 0);
            crate::handlers::__test_stage_pending_exit(PARENT, C2_PID, 0);

            set_task(PARENT);
            // wait4(-(GB_LEADER_PID)) must reap C2 (group B), not C1.
            let neg = (-(GB_LEADER_PID as i64)) as u64;
            match call(Syscall::Wait4.raw(), a3(neg, 0, 0, 0)) {
                Some(v) if v as u64 == C2_PID => Ok(()),
                Some(v) if v as u64 == C1_PID => Err("wait4(-pgid) reaped the first-queued child in the WRONG group — pgid filter missing (collapsed to any child)"),
                _ => Err("wait4(-pgid) returned an unexpected result"),
            }
        };
        set_task(FAKE_TASK);
        crate::handlers::__test_clear_pending_exits(PARENT);
        for t in [PARENT, C1_TASK, C2_TASK, GB_LEADER] {
            crate::task::release_task(t);
        }
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_wait4_pgid_selects_group);

// waitid(P_PGID, g): reap the zombie in group g, not the first-queued sibling.
fn smoke_abi_proc_waitid_pgid_selects_group() -> TestResult {
    with_setup(|| {
        const PARENT: u64 = 0x7100_0000;
        const PARENT_PID: u64 = 0x7100_1000;
        const GA_LEADER: u64 = 0x7100_0101;
        const GB_LEADER: u64 = 0x7100_0102;
        const GB_LEADER_PID: u64 = 0x7100_2102;
        const C1_TASK: u64 = 0x7100_0201;
        const C1_PID: u64 = 0x7100_1201; // group A, queued FIRST
        const C2_TASK: u64 = 0x7100_0202;
        const C2_PID: u64 = 0x7100_1202; // group B, queued SECOND
        const P_PGID: u64 = 2;
        const WEXITED: u64 = 4;

        let result = (|| {
            wt_register(PARENT, PARENT_PID, PARENT);
            wt_register(C1_TASK, C1_PID, GA_LEADER);
            wt_register(C2_TASK, C2_PID, GB_LEADER);
            crate::handlers::register_task_to_pid(GB_LEADER, GB_LEADER_PID);
            crate::handlers::register_pid_task_mapping(GB_LEADER_PID, GB_LEADER);
            crate::handlers::__test_stage_pending_exit(PARENT, C1_PID, 0);
            crate::handlers::__test_stage_pending_exit(PARENT, C2_PID, 0);

            set_task(PARENT);
            // waitid(P_PGID, GB_LEADER_PID, NULL, WEXITED) → 0, reaps C2. Verify
            // by confirming C1 (group A) is STILL queued afterward: a following
            // waitid(P_PGID, GA_LEADER_PID) reaps C1.
            match call(Syscall::Waitid.raw(), a3(P_PGID, GB_LEADER_PID, 0, WEXITED)) {
                Some(0) => {}
                _ => return Err("waitid(P_PGID, group B) did not succeed"),
            }
            // C2 consumed; C1 (group A) must remain. wait4(-1) now reaps C1.
            match call(Syscall::Wait4.raw(), a3((-1i64) as u64, 0, 0, 0)) {
                Some(v) if v as u64 == C1_PID => Ok(()),
                Some(v) if v as u64 == C2_PID => Err("waitid(P_PGID, group B) reaped the WRONG (group A) child — pgid filter missing"),
                _ => Err("follow-up wait4 returned an unexpected result"),
            }
        })();
        set_task(FAKE_TASK);
        crate::handlers::__test_clear_pending_exits(PARENT);
        for t in [PARENT, C1_TASK, C2_TASK, GB_LEADER] {
            crate::task::release_task(t);
        }
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_waitid_pgid_selects_group);

// has_living_child pgid branch: WNOHANG returns ECHILD when no LIVING child is
// in the target group, 0 when one is — the old code answered "any child".
fn smoke_abi_proc_wait4_pgid_echild_when_group_empty() -> TestResult {
    with_setup(|| {
        const PARENT: u64 = 0x7200_0000;
        const PARENT_PID: u64 = 0x7200_1000;
        const GA_LEADER: u64 = 0x7200_0101; // the child's group
        const GA_LEADER_PID: u64 = 0x7200_2101;
        const GB_LEADER: u64 = 0x7200_0102; // an EMPTY group (no child)
        const GB_LEADER_PID: u64 = 0x7200_2102;
        const CHILD_TASK: u64 = 0x7200_0201;
        const CHILD_PID: u64 = 0x7200_1201; // living child in group A
        const WNOHANG: u64 = 1;
        const ECHILD: i64 = -10;

        let result = (|| {
            wt_register(PARENT, PARENT_PID, PARENT);
            wt_register(CHILD_TASK, CHILD_PID, GA_LEADER);
            crate::handlers::register_task_to_pid(GA_LEADER, GA_LEADER_PID);
            crate::handlers::register_pid_task_mapping(GA_LEADER_PID, GA_LEADER);
            crate::handlers::register_task_to_pid(GB_LEADER, GB_LEADER_PID);
            crate::handlers::register_pid_task_mapping(GB_LEADER_PID, GB_LEADER);
            // A LIVING child of PARENT in group A (no queued exit).
            crate::handlers::__test_inject_parent_of(CHILD_PID, PARENT);

            set_task(PARENT);
            // Group A has a living child → WNOHANG returns 0 (not ECHILD).
            let neg_a = (-(GA_LEADER_PID as i64)) as u64;
            match call(Syscall::Wait4.raw(), a3(neg_a, 0, WNOHANG, 0)) {
                Some(0) => {}
                _ => return Err("wait4(-pgidA, WNOHANG) with a living group-A child should return 0"),
            }
            // Group B has NO child of PARENT → ECHILD (the old any-child check
            // wrongly saw the group-A child and returned 0 here).
            let neg_b = (-(GB_LEADER_PID as i64)) as u64;
            match call(Syscall::Wait4.raw(), a3(neg_b, 0, WNOHANG, 0)) {
                Some(v) if v == ECHILD => Ok(()),
                Some(0) => Err("wait4(-pgidB, WNOHANG) returned 0 despite no child in group B — has_living_child ignored the pgid"),
                _ => Err("wait4(-pgidB, WNOHANG) returned an unexpected result"),
            }
        })();
        set_task(FAKE_TASK);
        for t in [PARENT, CHILD_TASK, GA_LEADER, GB_LEADER] {
            crate::task::release_task(t);
        }
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc_wait4_pgid_echild_when_group_empty
);

// ── fork(2) / vfork(2) — no live address space in the harness ──

fn smoke_abi_proc_fork_neg() -> TestResult {
    with_setup(|| {
        // No user address space is installed in the harness, so sys_fork's
        // `current_address_space()` lookup returns None and the handler
        // reports a non-Ok NARF status (InvalidOp). The success path (spawn
        // a child) is unreachable without a live AS + scheduler.
        let r = call_raw(Syscall::Fork.raw(), a0(0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("fork without an address space did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_fork_neg);

fn smoke_abi_proc_vfork_neg() -> TestResult {
    with_setup(|| {
        // Vfork maps to sys_fork; same no-AS InvalidOp path.
        let r = call_raw(Syscall::Vfork.raw(), a0(0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("vfork without an address space did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_vfork_neg);

// ── clone(2) — no live address space ──

fn smoke_abi_proc_clone_neg() -> TestResult {
    with_setup(|| {
        // clone routes through do_clone3, whose first step is the
        // `current_address_space()` lookup — None in the harness → InvalidOp.
        let r = call_raw(Syscall::Clone.raw(), a0(0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("clone without an address space did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_clone_neg);

fn smoke_abi_proc_legacy_clone_pidfd_pointer() -> TestResult {
    const CLONE_PIDFD: u64 = 0x1000;
    const OUT_PTR: u64 = 0x1234_5678;
    if crate::handlers::legacy_clone_pidfd_ptr(CLONE_PIDFD | 17, OUT_PTR) != OUT_PTR {
        return TestResult::Fail("legacy clone dropped the CLONE_PIDFD output pointer");
    }
    if crate::handlers::legacy_clone_pidfd_ptr(17, OUT_PTR) != 0 {
        return TestResult::Fail("legacy clone treated parent_tid as pidfd without CLONE_PIDFD");
    }
    TestResult::Pass
}
kernel_test_in!("syscall_abi", smoke_abi_proc_legacy_clone_pidfd_pointer);

// ── clone3(2) — struct validation + no live address space ──

fn smoke_abi_proc_clone3_badarg() -> TestResult {
    with_setup(|| {
        // clone3(NULL, ...) and clone3(ptr, size<8) are rejected with
        // InvalidOp before any address-space work.
        let r = call_raw(Syscall::Clone3.raw(), a1(0, 64));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("clone3(NULL,..) did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_clone3_badarg);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_clone3_no_as() -> TestResult {
    with_setup(|| {
        // A well-formed clone_args (size >= 8, non-NULL) passes the prefix
        // validation, then hits the no-AS InvalidOp path in do_clone3.
        let mut ca = [0u8; 88]; // CLONE_ARGS_MIN-ish; flags=0, all zero.
        let r = call_raw(
            Syscall::Clone3.raw(),
            a1(ca.as_mut_ptr() as u64, ca.len() as u64),
        );
        let _ = &mut ca;
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("clone3 without an address space did not report InvalidOp")
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_clone3_no_as);

// ── execve(2) / execveat(2) — NULL path rejection ──

fn smoke_abi_proc_execve_neg() -> TestResult {
    with_setup(|| {
        // execve(NULL, ...) is rejected with InvalidOp (path_uptr == 0).
        let r = call_raw(Syscall::Execve.raw(), a2(0, 0, 0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("execve(NULL,..) did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_execve_neg);

fn smoke_abi_proc_execve_missing_path() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        // A non-NULL path that doesn't resolve (or that can't be loaded
        // without a live AS) fails: the handler reports a non-Ok NARF
        // status rather than success. The full success path needs a real
        // user address space to load the image into, unreachable here.
        let path = b"/abi/nope\0";
        let r = call_raw(Syscall::Execve.raw(), a3(path.as_ptr() as u64, 0, 0, 0));
        if r.status != SyscallReturn::OK || (r.value as i64) < 0 {
            Ok(())
        } else {
            Err("execve of a missing path reported success")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_execve_missing_path);

fn smoke_abi_proc_execve_missing_path_enoent() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        // LINUX ABI: execve of a non-existent path must return -ENOENT, NOT
        // -EINVAL. execvp(3) PATH-searches by execve'ing each candidate and only
        // retries the next dir on ENOENT — returning EINVAL aborts the search, so
        // a binary not in the first PATH entry (e.g. weston in /usr/bin while PATH
        // starts with /bin) became "can't execute: Invalid argument" despite
        // existing. Guards that regression.
        let path = b"/abi/does-not-exist\0";
        let r = call_raw(Syscall::Execve.raw(), a3(path.as_ptr() as u64, 0, 0, 0));
        const ENOENT: i64 = -2;
        if r.status == SyscallReturn::OK && (r.value as i64) == ENOENT {
            Ok(())
        } else {
            Err("execve of a missing path must return -ENOENT (not -EINVAL)")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_execve_missing_path_enoent);

fn smoke_abi_proc_execveat_neg() -> TestResult {
    with_setup(|| {
        // execveat reshapes (dirfd, path, argv, envp, flags) → execve(path,
        // argv, envp); a NULL path (arg1) forwards as execve(NULL) → InvalidOp.
        let r = call_raw(Syscall::Execveat.raw(), a3(0, 0, 0, 0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("execveat with a NULL path did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_execveat_neg);

// ── exit_task — landing path not installed in the harness ──

fn smoke_abi_proc_exit_task_neg() -> TestResult {
    with_setup(|| {
        // With no UserTaskCtx exit hook and no EXIT_LANDING_RIP installed,
        // sys_exit_task can neither longjmp nor redirect, so it reports a
        // non-Ok NARF status (InvalidOp). The real "process exits" path is
        // unreachable without the polling future / landing trampoline.
        let r = call_raw(Syscall::ExitTask.raw(), a0(0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("exit_task without a landing path did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_exit_task_neg);

// ── unshare(2) — no-op flags succeed ──

fn smoke_abi_proc_unshare_pos() -> TestResult {
    with_setup(|| {
        // unshare(0): no namespace bits set → Linux returns 0, and so does
        // NARF (the no-op success path).
        match call(Syscall::Unshare.raw(), a0(0)) {
            Some(0) => Ok(()),
            _ => Err("unshare(0) did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_unshare_pos);

// ── setns(2) — no resolvable target ──

fn smoke_abi_proc_setns_neg() -> TestResult {
    with_setup(|| {
        // setns with an fd that isn't an NsFd and a target that resolves to
        // no namespace yields the -1 sentinel: under `container`, no
        // supported nstype bits / no namespace → ok(!0); without `container`
        // the whole syscall is a !0 stub. Either way the value is -1.
        // LINUX-GAP: Linux returns -EBADF / -EINVAL here; NARF returns the
        // bare -1 sentinel.
        match call(Syscall::Setns.raw(), a1(4242, 0)) {
            Some(-1) => Ok(()),
            other => {
                let _ = other;
                Err("setns with an unresolvable target did not return -1")
            }
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setns_neg);

#[cfg(feature = "container")]
fn smoke_abi_proc_namespace_open_mints_setns_fd() -> TestResult {
    with_setup(|| {
        // TASK_INFO / CURRENT_PID / LIST_PIDS. `procfs`'s hooks start at 0 and
        // are wired for a real boot by `cross_crate_init::install_all_hooks`,
        // which a kernel-test image never reaches — so in this build they are
        // installed only as a side effect of whichever *other* smoke happened
        // to run first (there are five such donors, in `abi_fsx2_tests.rs` and
        // `abi_proc2_tests.rs`, none of which restores them).
        //
        // Without them `task_info()` returns `None`, so `ProcRootDir::
        // lookup_dir`'s liveness gate rejects `/proc/<pid>` and the O_PATH open
        // below is ENOENT. That made this test's verdict a function of
        // `kernel_test_in!` registration order — which is *link* order, so
        // linking any unrelated module could flip it. It did: adding a BPF test
        // module turned this red on aarch64 with the body untouched.
        //
        // Installing them here puts the fix on the causal path instead of
        // relying on a donor. Idempotent, and safe against the hook-absence
        // assertions elsewhere, which cover FD_PATH / EXE_PATH / CWD_PATH /
        // ENVIRON only — never these three.
        narf_filesystem::procfs::install_proc_hooks(
            crate::handlers::proc_current_pid,
            crate::handlers::proc_list_pids,
            crate::handlers::proc_task_info,
        );
        let path = b"/proc/self/ns/uts\0";
        let fd = match call_open(path.as_ptr() as u64, 0) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("open of /proc/self/ns/uts failed"),
        };
        let task = crate::handlers::current_task_id();
        let is_nsfd = crate::fd::with_table(task, |table| {
            table.get(fd).is_some_and(|entry| {
                entry
                    .ops
                    .as_any()
                    .and_then(|any| any.downcast_ref::<crate::namespaces::NsFd>())
                    .is_some()
            })
        })
        .unwrap_or(false);
        if !is_nsfd {
            return Err("proc namespace open installed a symlink file, not an NsFd");
        }
        match call(
            Syscall::Setns.raw(),
            a1(fd as u64, crate::namespaces::CLONE_NEWUTS),
        ) {
            Some(0) => Ok(()),
            _ => Err("setns rejected the fd opened from /proc/self/ns/uts"),
        }?;

        // Use the numeric proc path here: the generic nofollow resolver must
        // preserve only the final namespace link, whereas `/proc/self` is an
        // intermediate magic link that this focused test need not exercise.
        let visible_pid = crate::handlers::proc_current_pid();
        if visible_pid != FAKE_TASK {
            return Err("proc current pid did not match the ABI harness task");
        }
        let basic_info = crate::handlers::proc_task_info(
            visible_pid,
            narf_filesystem::procfs::TaskInfoQuery::Basic,
        )
        .ok_or("proc task provider could not see the ABI harness task")?;
        if !basic_info.vmas.is_empty() {
            return Err("basic proc task snapshot eagerly materialised VMAs");
        }
        let link_path = alloc::format!("/proc/{visible_pid}/ns/uts\0");
        let mounted_proc =
            crate::handlers::current_resolve_absolute(link_path.trim_end_matches('\0'), |fs, _| {
                fs.name() == "proc"
            });
        if mounted_proc != Some(true) {
            return Err("ABI harness path did not resolve through the proc mount");
        }
        let link_fd = match call_open(link_path.as_ptr() as u64, 0o10000000 | 0o400000) {
            Some(fd) if fd >= 0 => fd as u32,
            Some(-1) => return Err("O_PATH|O_NOFOLLOW namespace open returned generic failure"),
            Some(-2) => return Err("O_PATH|O_NOFOLLOW namespace open returned ENOENT"),
            Some(-40) => return Err("O_PATH|O_NOFOLLOW namespace open returned ELOOP"),
            Some(_) => return Err("O_PATH|O_NOFOLLOW namespace open returned another errno"),
            None => return Err("O_PATH|O_NOFOLLOW namespace open returned invalid-op"),
        };
        let preserved_link = crate::fd::with_table(task, |table| {
            table.get(link_fd).is_some_and(|entry| {
                entry.ops.stat().mode.file_type == narf_filesystem::FileType::Symlink
                    && entry
                        .ops
                        .as_any()
                        .and_then(|any| any.downcast_ref::<crate::namespaces::NsFd>())
                        .is_none()
            })
        })
        .unwrap_or(false);
        if preserved_link {
            Ok(())
        } else {
            Err("O_PATH|O_NOFOLLOW followed the namespace magic link")
        }
    })
}
#[cfg(feature = "container")]
kernel_test_in!("syscall_abi", smoke_abi_proc_namespace_open_mints_setns_fd);

// ── read(2) must not hold the fd-table lock across FileOps ────────
//
// `sys_read` used to call `FileOps::read` while holding the caller's
// fd-table lock. Any file whose read consults the fd table then
// re-entered that lock — and it is a non-reentrant IrqSafeSpinLock, so
// the CPU spun forever with interrupts masked.
//
// procfs is the real-world instance: `/proc/<pid>/fdinfo/<n>` and
// `/proc/<pid>/fd/<n>` render via `fd_path_of`, which calls
// `fd::with_table`. dbus-daemon reads `/proc/self/fdinfo/<n>` right
// after `pidfd_open`, so this one deadlock hung the session bus and with
// it every KDE Plasma startup.
//
// This pins the RULE rather than the procfs instance: a FileOps whose
// `read` touches the fd table must not wedge `read(2)`. (Driving it
// through a real /proc path is not possible here — the ABI harness's
// synthetic pid has no procfs directory.)
//
// A regression HANGS rather than fails, which is the honest shape for a
// deadlock pin; the harness's QEMU timeout turns it into a failure.
#[derive(Debug)]
struct ReentrantFdTableFile;

impl narf_filesystem::FileOps for ReentrantFdTableFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async move {
            // The re-entry under test: consult the caller's fd table from
            // inside a FileOps::read.
            let task = crate::handlers::current_task_id();
            let n_open = crate::fd::with_table(task, |t| t.open_fd_numbers().len()).unwrap_or(0);
            let msg = b"reentered";
            let n = core::cmp::min(buf.len(), msg.len());
            buf[..n].copy_from_slice(&msg[..n]);
            let _ = n_open;
            Ok(n)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async move { Err(narf_filesystem::FsError::ReadOnly) })
    }

    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
}

fn smoke_abi_proc_fdinfo_read_no_deadlock() -> TestResult {
    with_setup(|| {
        let task = crate::handlers::current_task_id();
        let fd = crate::fd::with_table(task, |t| {
            t.open(crate::fd::FdEntry {
                ops: alloc::sync::Arc::new(ReentrantFdTableFile),
                offset: 0,
                flags: 0,
                status_flags: 0,
            })
        });
        let fd = match fd {
            Some(f) => f,
            None => return Err("installing the probe fd failed"),
        };
        let mut buf = [0u8; 32];
        // THE point of the test: this must return, not spin.
        match call(
            Syscall::Read.raw(),
            a3(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0),
        ) {
            Some(n) if n > 0 => {
                if &buf[..n as usize] == b"reentered" {
                    Ok(())
                } else {
                    Err("re-entrant FileOps::read returned the wrong bytes")
                }
            }
            _ => Err("read() on a fd-table-touching FileOps returned no data"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_fdinfo_read_no_deadlock);

// ── seccomp(2): compatibility query/error subset ───────────────────
//
// NARF does not implement a BPF VM or enforce seccomp filters. It does
// expose the Linux feature-query subset used during runtime probing and
// rejects NEW_LISTENER, whose notification fd semantics are unavailable.
// Linux reference: kernel/seccomp.c::do_seccomp and
// seccomp_get_action_avail.

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_seccomp_query_subset() -> TestResult {
    with_setup(|| {
        const SECCOMP_GET_ACTION_AVAIL: u64 = 2;
        const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
        const UNKNOWN_ACTION: u32 = 0x1234_0000;

        let allow = SECCOMP_RET_ALLOW;
        if call(
            Syscall::Seccomp.raw(),
            a2(SECCOMP_GET_ACTION_AVAIL, 0, (&allow as *const u32) as u64),
        ) != Some(0)
        {
            return Err("seccomp GET_ACTION_AVAIL must accept SECCOMP_RET_ALLOW");
        }

        let unknown = UNKNOWN_ACTION;
        if call(
            Syscall::Seccomp.raw(),
            a2(SECCOMP_GET_ACTION_AVAIL, 0, (&unknown as *const u32) as u64),
        ) != Some(-95)
        {
            return Err("seccomp GET_ACTION_AVAIL must reject an unknown action with EOPNOTSUPP");
        }
        Ok(())
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_seccomp_query_subset);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_seccomp_new_listener_is_einval() -> TestResult {
    with_setup(|| {
        const SECCOMP_SET_MODE_FILTER: u64 = 1;
        const SECCOMP_FILTER_FLAG_NEW_LISTENER: u64 = 1 << 3;
        match call(
            Syscall::Seccomp.raw(),
            a2(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, 0),
        ) {
            Some(EINVAL) => Ok(()),
            _ => Err("seccomp NEW_LISTENER must return -EINVAL when notifications are unsupported"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_seccomp_new_listener_is_einval);
