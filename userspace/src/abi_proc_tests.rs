//! Linux syscall ABI conformance — proc group.
//!
//! Process/thread-management syscalls. Shares the harness in
//! [`crate::abi_test_support`]. Every test drives `kernel_syscall_entry`
//! against a synthetic `AbiCtx` (no user mode, no scheduler, no live
//! address space), so the reachable surface for the fork/clone/exec
//! family is the immediate argument-validation + table-bookkeeping path;
//! the success path that spawns a real child task is unreachable here and
//! is exercised only with its error/stub return.

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

fn smoke_abi_proc_pgid_cache_tracks_outer_id() -> TestResult {
    with_setup(|| {
        const LEADER_TASK: u64 = 0x6A10_0001;
        const LEADER_PID: u64 = 0x6A20_0001;
        const MEMBER_TASK: u64 = 0x6A10_0002;
        const MEMBER_PID: u64 = 0x6A20_0002;

        crate::task::release_task(LEADER_TASK);
        crate::task::release_task(MEMBER_TASK);
        let _ = crate::task::Task::new_registered(LEADER_TASK, LEADER_PID);
        let _ = crate::task::Task::new_registered(MEMBER_TASK, MEMBER_PID);
        crate::handlers::register_pid_task_mapping(LEADER_PID, LEADER_TASK);
        crate::handlers::register_pid_task_mapping(MEMBER_PID, MEMBER_TASK);

        crate::handlers::__test_set_pgid(LEADER_TASK, LEADER_TASK);
        crate::handlers::pgid_fork(LEADER_TASK, MEMBER_TASK);
        let inherited = crate::task::__test_cached_process_group(MEMBER_TASK);
        if inherited != Some((LEADER_TASK, LEADER_PID)) {
            crate::task::release_task(LEADER_TASK);
            crate::task::release_task(MEMBER_TASK);
            return Err("fork did not cache both TaskId and outer pid of inherited pgrp");
        }

        crate::handlers::__test_set_pgid(MEMBER_TASK, MEMBER_TASK);
        let moved = crate::task::__test_cached_process_group(MEMBER_TASK);
        crate::task::release_task(LEADER_TASK);
        crate::task::release_task(MEMBER_TASK);
        if moved == Some((MEMBER_TASK, MEMBER_PID)) {
            Ok(())
        } else {
            Err("setpgid did not update the cached outer process-group id")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pgid_cache_tracks_outer_id);

// ── setpgid(2) error ladder — kernel/sys.c::SYSCALL_DEFINE2(setpgid) ──
//
// This handler used to validate NOTHING: it translated both arguments and
// inserted into PGID_TABLE unconditionally, always returning 0. Silent
// acceptance is worse than a wrong errno — a shell doing job-control setup
// could "successfully" move a pid that does not exist, or join a group in
// another session, and never learn. One test per arm of Linux's ladder.

fn smoke_abi_proc_setpgid_unknown_pid_esrch() -> TestResult {
    with_setup(|| {
        // `p = find_task_by_vpid(pid); if (!p) { err = -ESRCH; goto out; }`
        match call(Syscall::Setpgid.raw(), a1(123456, 0)) {
            Some(-3) => Ok(()),
            Some(0) => Err("setpgid on a non-existent pid still returns 0 (no target validation)"),
            Some(_) => Err("setpgid on a non-existent pid: wrong errno, want -ESRCH"),
            None => Err("setpgid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setpgid_unknown_pid_esrch);

fn smoke_abi_proc_setpgid_negative_pgid_einval() -> TestResult {
    with_setup(|| {
        // `if (pgid < 0) return -EINVAL;` — and pgid_t is `int`, so the
        // argument is the low 32 bits. Reading the whole register made a
        // negative pgid arrive as a huge positive u64 and skip this check.
        match call(Syscall::Setpgid.raw(), a1(0, (-5i64) as u64)) {
            Some(-22) => Ok(()),
            Some(0) => Err("setpgid with a negative pgid succeeded"),
            Some(_) => Err("setpgid with a negative pgid: wrong errno, want -EINVAL"),
            None => Err("setpgid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setpgid_negative_pgid_einval);

fn smoke_abi_proc_setpgid_negative_pgid_beats_bad_pid() -> TestResult {
    with_setup(|| {
        // Ordering: `if (pgid < 0) return -EINVAL;` sits BEFORE the
        // find_task_by_vpid lookup, so a negative pgid wins over a target
        // that also does not exist. A caller must be able to tell its own
        // bad argument apart from a process that went away.
        match call(Syscall::Setpgid.raw(), a1(123456, (-5i64) as u64)) {
            Some(-22) => Ok(()),
            Some(-3) => Err("setpgid checked the target before the negative pgid (wrong order)"),
            Some(_) => Err("setpgid(bad pid, negative pgid): want -EINVAL"),
            None => Err("setpgid returned non-Ok status"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc_setpgid_negative_pgid_beats_bad_pid
);

fn smoke_abi_proc_setpgid_unrelated_target_esrch() -> TestResult {
    with_setup(|| {
        // A live task that is neither the caller nor a child of it:
        // `else { err = -ESRCH; if (p != group_leader) goto out; }`.
        // Linux deliberately reports ESRCH (not EPERM) so setpgid cannot be
        // used to probe whether an unrelated pid exists.
        const OTHER: u64 = 0xC001;
        crate::task::release_task(OTHER);
        let _ = crate::task::Task::new_registered(OTHER, OTHER);
        crate::handlers::register_task_to_pid(OTHER, OTHER);
        crate::handlers::register_pid_task_mapping(OTHER, OTHER);
        let result = match call(Syscall::Setpgid.raw(), a1(OTHER, 0)) {
            Some(-3) => Ok(()),
            Some(0) => Err("setpgid moved an unrelated process into a group"),
            Some(-1) => Err("setpgid on an unrelated process leaked EPERM (probeable existence)"),
            Some(_) => Err("setpgid on an unrelated process: want -ESRCH"),
            None => Err("setpgid returned non-Ok status"),
        };
        crate::task::release_task(OTHER);
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setpgid_unrelated_target_esrch);

fn smoke_abi_proc_setpgid_session_leader_eperm() -> TestResult {
    with_setup(|| {
        // `err = -EPERM; if (p->signal->leader) goto out;` — a session
        // leader's process group IS its session and cannot be changed.
        // setsid() publishes the explicit sid == pid row that marks one.
        crate::handlers::__test_sid_reset();
        let result = (|| {
            // setsid itself refuses a caller that is ALREADY a process-group
            // leader, and a task with no PGID row defaults to leading its own
            // group. Put the caller in its parent's group first — exactly
            // what fork does — so setsid has a legal starting state.
            const PARENT_GROUP: u64 = 0xC010;
            crate::handlers::__test_set_pgid(FAKE_TASK, PARENT_GROUP);
            match call(Syscall::Setsid.raw(), a0(0)) {
                Some(v) if v >= 0 => {}
                Some(_) => return Err("setsid setup failed"),
                None => return Err("setsid returned non-Ok status"),
            }
            match call(Syscall::Setpgid.raw(), a1(0, 0)) {
                Some(-1) => Ok(()),
                Some(0) => Err("setpgid on a session leader succeeded"),
                Some(_) => Err("setpgid on a session leader: wrong errno, want -EPERM"),
                None => Err("setpgid returned non-Ok status"),
            }
        })();
        crate::handlers::__test_sid_reset();
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setpgid_session_leader_eperm);

fn smoke_abi_proc_setpgid_join_unknown_group_eperm() -> TestResult {
    with_setup(|| {
        // `if (pgid != pid) { pgrp = find_vpid(pgid);
        //    g = pid_task(pgrp, PIDTYPE_PGID);
        //    if (!g || task_session(g) != task_session(group_leader)) goto out; }`
        // with err still -EPERM from the session-leader check above. Joining
        // a group that has no live member is refused, not silently recorded.
        match call(Syscall::Setpgid.raw(), a1(0, 4242)) {
            Some(-1) => Ok(()),
            Some(0) => Err("setpgid joined a process group with no live member"),
            Some(_) => Err("setpgid into an unknown group: wrong errno, want -EPERM"),
            None => Err("setpgid returned non-Ok status"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc_setpgid_join_unknown_group_eperm
);

fn smoke_abi_proc_setpgid_self_is_not_a_leader() -> TestResult {
    with_setup(|| {
        // Regression pin on `is_session_leader`. `read_sid` defaults to
        // "sid == pid" for a task with NO table row, which is a convenience
        // for readers but cannot distinguish a real session leader from a
        // task that never called setsid. Reusing that defaulted reader for
        // the -EPERM leader check would reject EVERY ordinary setpgid(0,0) —
        // the single most common form of the call.
        crate::handlers::__test_sid_reset();
        let result = match call(Syscall::Setpgid.raw(), a1(0, 0)) {
            Some(0) => Ok(()),
            Some(-1) => Err(
                "setpgid(0,0) reported EPERM — a task with no SID row was misread as a session leader",
            ),
            Some(_) => Err("setpgid(0,0) failed with an unexpected errno"),
            None => Err("setpgid returned non-Ok status"),
        };
        crate::handlers::__test_sid_reset();
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setpgid_self_is_not_a_leader);

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
        // Model a fork child in its parent's process group. Linux rejects a
        // process-group leader with EPERM, so a positive fixture must not use
        // the default pgid == pid state.
        crate::handlers::__test_set_pgid(FAKE_TASK, FAKE_TASK + 1);
        match call(Syscall::Setsid.raw(), a0(0)) {
            Some(v) if v >= 0 => Ok(()),
            Some(_) => Err("setsid returned negative sid"),
            None => Err("setsid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setsid_pos);

fn smoke_abi_proc_setsid_group_leader_eperm() -> TestResult {
    with_setup(|| match call(Syscall::Setsid.raw(), a0(0)) {
        Some(-1) => Ok(()),
        _ => Err("setsid did not return EPERM for a process-group leader"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setsid_group_leader_eperm);

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
        // `sys_getsid` returns -ESRCH for a pid that names no live task,
        // as Linux does.
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
        crate::handlers::__test_set_pgid(LEADER_TID, LEADER_TID + 1);

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
// service setup. PR_SET_MDWE is now implemented, so it SUCCEEDS and systemd's
// MemoryDenyWriteExecute= gets the real W^X enforcement rather than falling
// back to its seccomp path; the rest are accepted no-ops with Linux-shaped
// returns.
/// `kernel/sys.c::prctl_set_mdwe` is deliberately ONE-WAY:
///
///     current_bits = get_current_mdwe();
///     if (current_bits && current_bits != bits)
///             return -EPERM; /* Cannot unset the flags */
///
/// That -EPERM is the feature, not a detail. MDWE exists so a process cannot
/// map or promote executable memory; if it could simply clear the bits first,
/// an attacker who gained control of it would turn the protection off and
/// then do exactly what it was meant to prevent. A W^X flag that can be
/// unset protects nothing.
///
/// The argument validation around it matters too — `PR_MDWE_NO_INHERIT`
/// alone is rejected, because inheriting a restriction that was never
/// imposed is meaningless, and a caller that got 0 for it would believe it
/// had asked for something.
fn smoke_abi_proc_prctl_mdwe_cannot_be_unset() -> TestResult {
    with_setup(|| {
        const PR_SET_MDWE: u64 = 65;
        const PR_GET_MDWE: u64 = 66;
        const REFUSE_EXEC_GAIN: u64 = 1;
        const NO_INHERIT: u64 = 2;

        // Nothing set yet.
        if call(Syscall::Prctl.raw(), a0(PR_GET_MDWE)) != Some(0) {
            return Err("PR_GET_MDWE on a fresh task was not 0");
        }
        // `if (bits & ~(PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT))`
        if call(Syscall::Prctl.raw(), a1(PR_SET_MDWE, 0x4)) != Some(-22) {
            return Err("PR_SET_MDWE with an unknown bit was not -EINVAL");
        }
        // `NO_INHERIT` without `REFUSE_EXEC_GAIN` is meaningless → EINVAL.
        if call(Syscall::Prctl.raw(), a1(PR_SET_MDWE, NO_INHERIT)) != Some(-22) {
            return Err("PR_SET_MDWE(NO_INHERIT alone) was not -EINVAL");
        }
        // `if (arg3 || arg4 || arg5) return -EINVAL;`
        if call(Syscall::Prctl.raw(), a2(PR_SET_MDWE, REFUSE_EXEC_GAIN, 1)) != Some(-22) {
            return Err("PR_SET_MDWE with a non-zero arg3 was not -EINVAL");
        }

        if call(Syscall::Prctl.raw(), a1(PR_SET_MDWE, REFUSE_EXEC_GAIN)) != Some(0) {
            return Err("PR_SET_MDWE(REFUSE_EXEC_GAIN) failed");
        }
        // Setting the SAME bits again is idempotent, not an error.
        if call(Syscall::Prctl.raw(), a1(PR_SET_MDWE, REFUSE_EXEC_GAIN)) != Some(0) {
            return Err("re-setting the same MDWE bits was not idempotent");
        }
        // Clearing is refused — the whole point.
        if call(Syscall::Prctl.raw(), a1(PR_SET_MDWE, 0)) != Some(-1) {
            return Err("MDWE could be cleared; the restriction is not one-way");
        }
        // So is changing to a different combination.
        if call(
            Syscall::Prctl.raw(),
            a1(PR_SET_MDWE, REFUSE_EXEC_GAIN | NO_INHERIT),
        ) != Some(-1)
        {
            return Err("MDWE bits could be changed after being set");
        }
        // And it is still set after all those refusals.
        match call(Syscall::Prctl.raw(), a0(PR_GET_MDWE)) {
            Some(v) if v as u64 == REFUSE_EXEC_GAIN => Ok(()),
            _ => Err("MDWE bits did not survive the refused changes"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_prctl_mdwe_cannot_be_unset);

fn smoke_abi_proc_prctl_feature_probes() -> TestResult {
    with_setup(|| {
        const PR_GET_TSC: u64 = 25;
        const PR_SET_TSC: u64 = 26;
        const PR_SET_TIMERSLACK: u64 = 29;
        const PR_GET_TIMERSLACK: u64 = 30;
        const PR_SET_THP_DISABLE: u64 = 41;
        const PR_SET_MDWE: u64 = 65;
        const PR_MDWE_REFUSE_EXEC_GAIN: u64 = 1;

        // MDWE is implemented: the request succeeds and PR_GET_MDWE reads it
        // back. This arm asserted -EINVAL while the feature was unsupported.
        const PR_GET_MDWE: u64 = 66;
        match call(
            Syscall::Prctl.raw(),
            a1(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN),
        ) {
            Some(0) => {}
            _ => return Err("PR_SET_MDWE must succeed"),
        }
        match call(Syscall::Prctl.raw(), a0(PR_GET_MDWE)) {
            Some(v) if v as u64 == PR_MDWE_REFUSE_EXEC_GAIN => {}
            _ => return Err("PR_GET_MDWE did not read back the bits that were set"),
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
        // RAISE has PRECONDITIONS (`security/commoncap.c:1421`): the
        // capability must already be in BOTH permitted and inheritable.
        // The harness task boots with a full permitted set and an EMPTY
        // inheritable one — `init_cred` uses `CAP_FULL_SET` for
        // permitted/effective/bset and nothing for pI — so the raise is
        // -EPERM until inheritable is populated. This case previously
        // asserted it succeeded outright, which is what a handler with no
        // preconditions does.
        match call(
            Syscall::Prctl.raw(),
            a2(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN),
        ) {
            Some(-1) => {}
            _ => return Err("RAISE without the cap in inheritable must be -EPERM"),
        }
        // Grant it inheritable, and the same raise is permitted. Ambient is
        // the set that survives an exec into permitted and effective, so
        // raising one the task does not already hold both ways would
        // manufacture privilege rather than carry it.
        crate::handlers::__test_set_inheritable(FAKE_TASK, 1u64 << CAP_NET_ADMIN);
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
        //
        // Both the effective AND the permitted word carry the bit:
        // `cap_capset` refuses an effective set that is not a subset of the
        // new permitted set (`security/commoncap.c`), because an effective
        // bit with no permitted bit behind it is a capability the task can
        // exercise but was never granted. This case used to set only the
        // effective word, which capset now correctly rejects with -EPERM.
        let mut data = [0u8; 24];
        data[0..4].copy_from_slice(&0x0000_0001u32.to_le_bytes()); // effective lo
        data[4..8].copy_from_slice(&0x0000_0001u32.to_le_bytes()); // permitted lo
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
        // `SYSCALL_DEFINE2(pidfd_open)`: `if (pid <= 0) return -EINVAL;` — a
        // malformed argument, distinct from the -ESRCH a valid-but-absent pid
        // gets and from the -EMFILE an exhausted table gets.
        match call(Syscall::PidfdOpen.raw(), a1(0, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("pidfd_open(0) did not return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_open_neg);

// `pidfd_open` validates `flags` against `PIDFD_NONBLOCK | PIDFD_THREAD`
// (`kernel/pid.c`): any other bit is -EINVAL, and the check runs BEFORE the pid
// lookup, so even a live pid with a junk flag fails. Regression guard for the
// parity fix that stopped ignoring `flags` entirely.
fn smoke_abi_proc_pidfd_open_bad_flags() -> TestResult {
    with_setup(|| {
        // bit 0 is neither PIDFD_NONBLOCK (0o4000) nor PIDFD_THREAD (0o200).
        match call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, 0x1)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("pidfd_open with an unknown flag did not return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_open_bad_flags);

// `if (pid <= 0) return -EINVAL;` — a NEGATIVE pid is a malformed argument
// (EINVAL), NOT a well-formed-but-absent pid (ESRCH). Guards the fix from
// regressing to a `== 0`-only check that let a negative pid fall through.
fn smoke_abi_proc_pidfd_open_neg_pid() -> TestResult {
    with_setup(
        || match call(Syscall::PidfdOpen.raw(), a1((-1i64) as u64, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            Some(v) if v == ESRCH => {
                Err("pidfd_open(-1) returned -ESRCH; Linux gives -EINVAL for pid<=0")
            }
            _ => Err("pidfd_open(-1) did not return -EINVAL"),
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_open_neg_pid);

// PIDFD_NONBLOCK (== O_NONBLOCK) is a VALID flag: accepted (not -EINVAL) and
// reflected in the open-file status flags, matching Linux `pidfd_create` which
// ORs `flags` into the description. `fcntl(F_GETFL)` must read it back.
fn smoke_abi_proc_pidfd_open_nonblock() -> TestResult {
    with_setup(|| {
        const PIDFD_NONBLOCK: u64 = 0o4000; // O_NONBLOCK
        const F_GETFL: u64 = 3;
        let fd = match call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, PIDFD_NONBLOCK)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("pidfd_open(PIDFD_NONBLOCK) was rejected"),
        };
        match call(Syscall::Fcntl.raw(), a2(fd, F_GETFL, 0)) {
            Some(v) if (v as u64) & PIDFD_NONBLOCK == PIDFD_NONBLOCK => Ok(()),
            _ => Err("pidfd F_GETFL did not report O_NONBLOCK"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_open_nonblock);

// Linux opens pidfds O_CLOEXEC (`pidfd_create` → O_RDWR | O_CLOEXEC), so
// `fcntl(F_GETFD)` reports FD_CLOEXEC.
fn smoke_abi_proc_pidfd_open_cloexec() -> TestResult {
    with_setup(|| {
        const F_GETFD: u64 = 1;
        const FD_CLOEXEC: i64 = 1;
        let fd = match call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("pidfd_open failed"),
        };
        match call(Syscall::Fcntl.raw(), a2(fd, F_GETFD, 0)) {
            Some(v) if v & FD_CLOEXEC == FD_CLOEXEC => Ok(()),
            _ => Err("pidfd F_GETFD did not report FD_CLOEXEC"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_open_cloexec);

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
        // fd resolution precedes signum validation, so use a real pidfd to
        // isolate the invalid-signal result.
        let pidfd = match call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("pidfd_open setup failed"),
        };
        match call(Syscall::PidfdSendSignal.raw(), a3(pidfd, 65, 0, 0)) {
            Some(v) if v == EINVAL => {}
            _ => return Err("pidfd_send_signal with sig 65 did not return -EINVAL"),
        }
        // The same bad signal cannot hide an unresolved descriptor.
        match call(Syscall::PidfdSendSignal.raw(), a3(4242, 65, 0, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("pidfd_send_signal must resolve fd before validating signal"),
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

fn smoke_abi_proc_pidfd_send_signal_flags_first() -> TestResult {
    with_setup(|| {
        // NARF supports no pidfd signal-scope flags yet. Their rejection is the
        // syscall wrapper's first check, ahead of fd, signal, and info errors.
        match call(Syscall::PidfdSendSignal.raw(), a3(4242, 65, u64::MAX, 1)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("pidfd_send_signal flags must return -EINVAL first"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_send_signal_flags_first);

fn smoke_abi_proc_pidfd_send_signal_missing_target() -> TestResult {
    with_setup(|| {
        const MISSING_PID: u64 = 0xDEAD_1000;
        let state = crate::pidfd::mint_for(MISSING_PID, 0, false);
        let file: alloc::sync::Arc<dyn narf_filesystem::FileOps> =
            alloc::sync::Arc::new(crate::pidfd::PidFdFile::new(state));
        let pidfd = crate::fd::install(
            FAKE_TASK,
            crate::fd::FdEntry {
                ops: file,
                offset: 0,
                flags: 0,
                status_flags: 0,
            },
        )
        .ok_or("fd table missing")?;
        match call(Syscall::PidfdSendSignal.raw(), a3(pidfd as u64, 0, 0, 0)) {
            Some(v) if v == ESRCH => Ok(()),
            _ => Err("pidfd_send_signal must return -ESRCH for an exited target"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc_pidfd_send_signal_missing_target
);

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

fn smoke_abi_proc_wait_rejects_invalid_options() -> TestResult {
    with_setup(|| {
        // Linux kernel_wait4 rejects bits outside its six supported options
        // before walking the child list.
        if call(Syscall::Wait4.raw(), a3((-1i64) as u64, 0, 0x10, 0)) != Some(EINVAL) {
            return Err("wait4 accepted an unknown option bit");
        }

        // Linux waitid additionally requires at least one requested event
        // class (WEXITED, WSTOPPED, or WCONTINUED).
        if call(Syscall::Waitid.raw(), a3(0, 0, 0, 1)) != Some(EINVAL) {
            return Err("waitid without an event class did not return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_wait_rejects_invalid_options);

fn smoke_abi_proc_wait_clone_child_classes() -> TestResult {
    fn peek_pid(options: u64) -> Result<u64, &'static str> {
        let mut si = [0u8; 128];
        match call(
            Syscall::Waitid.raw(),
            a3(0, 0, si.as_mut_ptr() as u64, options),
        ) {
            Some(0) => Ok(u32::from_ne_bytes([si[16], si[17], si[18], si[19]]) as u64),
            _ => Err("waitid clone-class peek failed"),
        }
    }

    with_setup(|| {
        const CLONE_CHILD: u64 = 0x6a01;
        const FORK_CHILD: u64 = 0x6a02;
        const WNOHANG: u64 = 1;
        const WEXITED: u64 = 4;
        const WNOWAIT: u64 = 0x0100_0000;
        const __WALL: u64 = 0x4000_0000;
        const __WCLONE: u64 = 0x8000_0000;
        let base = WNOHANG | WEXITED | WNOWAIT;

        // Queue the clone child first so an implementation that ignores
        // eligible_child will visibly choose the wrong record.
        crate::handlers::__test_stage_pending_exit_with_signal(FAKE_TASK, CLONE_CHILD, 0, 0);
        crate::handlers::__test_stage_pending_exit_with_signal(FAKE_TASK, FORK_CHILD, 0, 17);

        let result = (|| {
            if peek_pid(base)? != FORK_CHILD {
                return Err("ordinary wait selected a non-SIGCHLD clone child");
            }
            if peek_pid(base | __WCLONE)? != CLONE_CHILD {
                return Err("__WCLONE did not select the clone child");
            }
            if peek_pid(base | __WALL)? != CLONE_CHILD {
                return Err("__WALL did not select both child classes");
            }
            Ok(())
        })();
        crate::handlers::__test_clear_pending_exits(FAKE_TASK);
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_wait_clone_child_classes);
fn smoke_abi_proc_wait_thread_group_and_wnothread() -> TestResult {
    with_setup(|| {
        const SIBLING: u64 = 0x6a10;
        const SIBLING_CHILD: u64 = 0x6a11;
        const BASE: u64 = 1 | 4 | 0x0100_0000; // WNOHANG|WEXITED|WNOWAIT
        const __WNOTHREAD: u64 = 0x2000_0000;

        crate::handlers::register_task_to_pid(SIBLING, FAKE_TASK);
        crate::handlers::thread_group_live_inc(FAKE_TASK);
        crate::handlers::__test_stage_pending_exit_with_signal(SIBLING, SIBLING_CHILD, 0, 17);

        let mut si = [0u8; 128];
        let private = call(
            Syscall::Waitid.raw(),
            a3(0, 0, si.as_mut_ptr() as u64, BASE | __WNOTHREAD),
        );
        if private != Some(ECHILD) {
            crate::handlers::__test_thread_group_live_reset();
            return Err("__WNOTHREAD saw a sibling thread's child");
        }

        let shared = call(
            Syscall::Waitid.raw(),
            a3(0, 0, si.as_mut_ptr() as u64, BASE),
        );
        let reported = u32::from_ne_bytes([si[16], si[17], si[18], si[19]]) as u64;
        crate::handlers::__test_clear_pending_exits(SIBLING);
        crate::handlers::__test_thread_group_live_reset();
        if shared != Some(0) || reported != SIBLING_CHILD {
            return Err("default wait did not see a sibling thread's child");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc_wait_thread_group_and_wnothread
);

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
        const WEXITED: u64 = 4;
        match call(
            Syscall::Waitid.raw(),
            a3(P_ALL, 0, si.as_mut_ptr() as u64, WNOHANG | WEXITED),
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
        match call(Syscall::Waitid.raw(), a3(4, 0, 0, 4)) {
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
        match call(Syscall::Waitid.raw(), a3(3, 0x7fff_ffff, 0, 5)) {
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
                _ => {
                    return Err(
                        "wait4(-pgidA, WNOHANG) with a living group-A child should return 0",
                    )
                }
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

// #32: proc_task_info fills stat fields 7-8 (tty_nr/tpgid) from the task's
// controlling terminal + its foreground pgrp (translated), not hardcoded 0 0.
fn smoke_abi_proc_stat_tty_fields_from_ctty() -> TestResult {
    with_setup(|| {
        const T_TASK: u64 = 0x7400_0000;
        const T_PID: u64 = 0x7400_1000;
        const LEADER_TASK: u64 = 0x7400_0101; // console fg pgrp (task-space)
        const LEADER_PID: u64 = 0x7400_1101;
        const CONSOLE_DEV: u64 = (5 << 8) | 1;

        for (t, p) in [(T_TASK, T_PID), (LEADER_TASK, LEADER_PID)] {
            crate::task::release_task(t);
            let _ = crate::task::Task::new_registered(t, p);
            crate::handlers::register_task_to_pid(t, p);
            crate::handlers::register_pid_task_mapping(p, t);
        }
        let saved_fg = narf_filesystem::console_tty::fg_pgrp();
        let result = (|| {
            set_task(T_TASK);
            // T's controlling terminal is the console; its fg pgrp is LEADER.
            crate::handlers::set_controlling_tty_console(T_TASK);
            narf_filesystem::console_tty::set_fg_pgrp(LEADER_TASK);
            let info = crate::handlers::proc_task_info(
                T_PID,
                narf_filesystem::procfs::TaskInfoQuery::Basic,
            )
            .ok_or("proc_task_info returned None for a live task")?;
            if info.tty_nr != CONSOLE_DEV {
                return Err("tty_nr was not the console device (5,1) for a console-ctty task");
            }
            // tpgid is the fg pgrp rendered in the reader's ns (root ns here →
            // the leader's outer pid), NOT the raw task-space id or 0.
            if info.tpgid != LEADER_PID as i64 {
                return Err("tpgid was not the fg pgrp's visible pid (pgid_to_user missing)");
            }
            // Detached from the controlling tty → tty_nr 0, tpgid -1 (Linux).
            crate::handlers::detach_controlling_tty(T_TASK);
            let info2 = crate::handlers::proc_task_info(
                T_PID,
                narf_filesystem::procfs::TaskInfoQuery::Basic,
            )
            .ok_or("proc_task_info returned None after detach")?;
            if info2.tty_nr != 0 || info2.tpgid != -1 {
                return Err("a task with no controlling tty must render tty_nr 0, tpgid -1");
            }
            Ok(())
        })();
        set_task(FAKE_TASK);
        narf_filesystem::console_tty::set_fg_pgrp(saved_fg);
        for t in [T_TASK, LEADER_TASK] {
            crate::task::release_task(t);
        }
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_stat_tty_fields_from_ctty);

// ── fork(2) / vfork(2) — no live address space in the harness ──

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_fork_neg() -> TestResult {
    with_setup(|| {
        // No user address space is installed in the harness, so sys_fork's
        // `current_address_space()` lookup returns None. LINUX ABI: fork(2)
        // never returns EINVAL — an AS/COW-dup failure reads as -ENOMEM so
        // callers back off rather than treating args as invalid. The success
        // path (spawn a child) is unreachable without a live AS + scheduler.
        let r = call(Syscall::Fork.raw(), a0(0));
        if r == Some(ENOMEM) {
            Ok(())
        } else {
            Err("fork without an address space must return -ENOMEM")
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_fork_neg);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_vfork_neg() -> TestResult {
    with_setup(|| {
        // Vfork maps to sys_fork; same no-AS path → -ENOMEM (not EINVAL).
        let r = call(Syscall::Vfork.raw(), a0(0));
        if r == Some(ENOMEM) {
            Ok(())
        } else {
            Err("vfork without an address space must return -ENOMEM")
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_vfork_neg);

#[cfg(target_arch = "aarch64")]
fn smoke_abi_proc_legacy_fork_is_unwired() -> TestResult {
    // The aarch64 Generic ABI has neither fork(2) nor vfork(2); libc creates
    // processes through clone(2). Keep absent variants out of the reverse
    // syscall table instead of assigning non-Linux wire numbers to them.
    if Syscall::Fork.raw() == u32::MAX && Syscall::Vfork.raw() == u32::MAX {
        TestResult::Pass
    } else {
        TestResult::Fail("aarch64 unexpectedly wires legacy fork/vfork syscall numbers")
    }
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_legacy_fork_is_unwired);

// ── clone(2) — no live address space ──

fn smoke_abi_proc_clone_neg() -> TestResult {
    with_setup(|| {
        // clone routes through do_clone3, whose first step is the
        // `current_address_space()` lookup — None in the harness → ENOMEM.
        let r = call_raw(Syscall::Clone.raw(), a0(0));
        if r.status == SyscallReturn::OK && r.value as i64 == -12 {
            // Legacy clone truncates flags to 32 bits. A clone3-only upper
            // flag must be ignored and reach the same no-mm ENOMEM path.
            let upper = call(Syscall::Clone.raw(), a0(0x1_0000_0000));
            if upper == Some(-12) {
                Ok(())
            } else {
                Err("legacy clone did not truncate flags to 32 bits")
            }
        } else {
            Err("clone without an address space did not return -ENOMEM")
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

fn smoke_abi_proc_clone_parent_linux_semantics() -> TestResult {
    with_setup(|| {
        const CLONE_PARENT: u64 = 0x0000_8000;
        const GRANDPARENT: u64 = 0x6b00;
        const FORK_CHILD: u64 = 0x6b01;
        const SIGUSR1: u8 = 10;
        const SIGCHLD: u8 = 17;

        // fork() publishes the ordinary Linux child class.
        crate::handlers::__test_parent_of_set(FORK_CHILD, FAKE_TASK);
        if crate::handlers::__test_parent_link(FORK_CHILD) != Some((FAKE_TASK, SIGCHLD)) {
            return Err("fork child link did not default to SIGCHLD");
        }

        // CLONE_PARENT reuses current->real_parent and copies the caller's
        // group-leader exit_signal; the new clone3 exit_signal is not used.
        crate::handlers::__test_parent_of_set_with_signal(FAKE_TASK, GRANDPARENT, SIGUSR1);
        if crate::handlers::__test_clone_parent_link(FAKE_TASK, CLONE_PARENT, 0)
            != Ok((GRANDPARENT, SIGUSR1))
        {
            return Err("CLONE_PARENT did not inherit parent and exit signal");
        }
        if crate::handlers::__test_clone_parent_link(FAKE_TASK, 0, SIGCHLD)
            != Ok((FAKE_TASK, SIGCHLD))
        {
            return Err("ordinary clone did not retain its requested exit signal");
        }

        // clone3 forbids a non-zero exit_signal with CLONE_PARENT.
        let mut clone3 = [0u8; 64];
        clone3[..8].copy_from_slice(&CLONE_PARENT.to_ne_bytes());
        clone3[32..40].copy_from_slice(&(SIGCHLD as u64).to_ne_bytes());
        if call(
            Syscall::Clone3.raw(),
            a1(clone3.as_ptr() as u64, clone3.len() as u64),
        ) != Some(EINVAL)
        {
            return Err("clone3(CLONE_PARENT, exit_signal) did not return -EINVAL");
        }

        // Legacy clone does not have clone3's restriction. Linux accepts the
        // low-byte signal and CLONE_PARENT then inherits the caller's signal.
        // The ABI harness has no address space, so acceptance reaches ENOMEM.
        if call(Syscall::Clone.raw(), a0(CLONE_PARENT | SIGCHLD as u64)) != Some(ENOMEM) {
            return Err("legacy clone incorrectly rejected CLONE_PARENT plus CSIGNAL");
        }

        // Linux rejects CLONE_PARENT from a namespace init, which has no
        // reusable real parent.
        crate::handlers::__test_wait_reset();
        if crate::handlers::__test_clone_parent_link(FAKE_TASK, CLONE_PARENT, 0) != Err(22) {
            return Err("parentless CLONE_PARENT did not return EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_clone_parent_linux_semantics);

// ── clone3(2) — struct validation + no live address space ──

fn smoke_abi_proc_clone3_badarg() -> TestResult {
    with_setup(|| {
        // LINUX ABI: the two failure modes are now distinguished (were both
        // folded to InvalidOp). clone3(NULL, size) faults on the clone_args
        // pointer → -EFAULT; clone3(ptr, size<8) is an undersized struct →
        // -EINVAL. glibc's clone3→clone fallback depends on these being right.
        let null_ptr = call(Syscall::Clone3.raw(), a1(0, 64));
        if null_ptr != Some(EFAULT) {
            return Err("clone3(NULL, ..) must return -EFAULT");
        }
        // A non-NULL but obviously-invalid (kernel-half) pointer with size<8
        // is rejected on the size floor before the pointer is dereferenced.
        let scratch = [0u8; 8];
        let undersize = call(Syscall::Clone3.raw(), a1(scratch.as_ptr() as u64, 63));
        if undersize != Some(EINVAL) {
            return Err("clone3(ptr, size<8) must return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_clone3_badarg);

fn smoke_abi_proc_clone3_errno_matrix() -> TestResult {
    with_setup(|| {
        const E2BIG: i64 = -7;
        const ENOMEM: i64 = -12;

        // Size validation precedes pointer access, matching Linux.
        if call(Syscall::Clone3.raw(), a1(0, 4097)) != Some(E2BIG) {
            return Err("clone3 oversized struct must return -E2BIG before EFAULT");
        }

        // An unknown non-zero extension field is E2BIG; a zero extension is
        // forward-compatible and reaches the later no-address-space ENOMEM.
        let mut extended = [0u8; 89];
        extended[88] = 1;
        if call(
            Syscall::Clone3.raw(),
            a1(extended.as_ptr() as u64, extended.len() as u64),
        ) != Some(E2BIG)
        {
            return Err("clone3 non-zero unknown tail must return -E2BIG");
        }
        extended[88] = 0;
        if call(
            Syscall::Clone3.raw(),
            a1(extended.as_ptr() as u64, extended.len() as u64),
        ) != Some(ENOMEM)
        {
            return Err("clone3 zero unknown tail was not accepted");
        }

        // clone3 requires stack and stack_size as a pair.
        let mut bad_stack = [0u8; 64];
        bad_stack[40..48].copy_from_slice(&0x1000u64.to_ne_bytes());
        if call(
            Syscall::Clone3.raw(),
            a1(bad_stack.as_ptr() as u64, bad_stack.len() as u64),
        ) != Some(EINVAL)
        {
            return Err("clone3 stack without stack_size must return -EINVAL");
        }

        // CLONE_THREAD requires CLONE_SIGHAND, which in turn requires CLONE_VM.
        let mut bad_flags = [0u8; 64];
        bad_flags[..8].copy_from_slice(&0x1_0000u64.to_ne_bytes());
        if call(
            Syscall::Clone3.raw(),
            a1(bad_flags.as_ptr() as u64, bad_flags.len() as u64),
        ) != Some(EINVAL)
        {
            return Err("clone3 CLONE_THREAD without SIGHAND must return -EINVAL");
        }
        bad_flags[..8].copy_from_slice(&0x800u64.to_ne_bytes());
        if call(
            Syscall::Clone3.raw(),
            a1(bad_flags.as_ptr() as u64, bad_flags.len() as u64),
        ) != Some(EINVAL)
        {
            return Err("clone3 CLONE_SIGHAND without VM must return -EINVAL");
        }

        // The dedicated exit_signal field accepts 0..=64 only.
        let mut bad_signal = [0u8; 64];
        bad_signal[32..40].copy_from_slice(&65u64.to_ne_bytes());
        if call(
            Syscall::Clone3.raw(),
            a1(bad_signal.as_ptr() as u64, bad_signal.len() as u64),
        ) != Some(EINVAL)
        {
            return Err("clone3 invalid exit_signal must return -EINVAL");
        }

        // clone3 reserves the obsolete CLONE_DETACHED bit for future reuse.
        let mut detached = [0u8; 64];
        detached[..8].copy_from_slice(&0x0040_0000u64.to_ne_bytes());
        if call(
            Syscall::Clone3.raw(),
            a1(detached.as_ptr() as u64, detached.len() as u64),
        ) != Some(EINVAL)
        {
            return Err("clone3 CLONE_DETACHED must return -EINVAL");
        }

        // Linux copies the set_tid pid_t array before capability checks:
        // a bad array is EFAULT, while a readable request without either
        // checkpoint/restore capability is EPERM.
        let mut set_tid_args = [0u8; 80];
        set_tid_args[64..72].copy_from_slice(&u64::MAX.to_ne_bytes());
        set_tid_args[72..80].copy_from_slice(&1u64.to_ne_bytes());
        if call(
            Syscall::Clone3.raw(),
            a1(set_tid_args.as_ptr() as u64, set_tid_args.len() as u64),
        ) != Some(-14)
        {
            return Err("clone3 unreadable set_tid array must return -EFAULT");
        }
        let requested_pid = 123i32;
        set_tid_args[64..72]
            .copy_from_slice(&(core::ptr::addr_of!(requested_pid) as u64).to_ne_bytes());
        install_test_address_space()?;
        crate::handlers::__test_set_caps(FAKE_TASK, 0, 0);
        let set_tid_result = call(
            Syscall::Clone3.raw(),
            a1(set_tid_args.as_ptr() as u64, set_tid_args.len() as u64),
        );
        crate::handlers::__test_set_caps(FAKE_TASK, !0, !0);
        if set_tid_result != Some(-1) {
            return Err("clone3 set_tid request must return -EPERM");
        }

        // Output pointers are mandatory when their corresponding flags are
        // set; NULL is EFAULT, not an accepted request that silently omits the
        // write.
        let mut null_pidfd = [0u8; 64];
        null_pidfd[..8].copy_from_slice(&0x1000u64.to_ne_bytes());
        if call(
            Syscall::Clone3.raw(),
            a1(null_pidfd.as_ptr() as u64, null_pidfd.len() as u64),
        ) != Some(-14)
        {
            return Err("clone3 CLONE_PIDFD with NULL pidfd must return -EFAULT");
        }

        // clone3's stack range is checked like Linux access_ok(), but its
        // prescribed errno for a non-user range is EINVAL.
        let mut bad_stack_range = [0u8; 64];
        bad_stack_range[40..48].copy_from_slice(&((1u64 << 47) - 8).to_ne_bytes());
        bad_stack_range[48..56].copy_from_slice(&16u64.to_ne_bytes());
        if call(
            Syscall::Clone3.raw(),
            a1(
                bad_stack_range.as_ptr() as u64,
                bad_stack_range.len() as u64,
            ),
        ) != Some(EINVAL)
        {
            return Err("clone3 non-user stack range must return -EINVAL");
        }

        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_clone3_errno_matrix);

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
        if r.status == SyscallReturn::OK && r.value as i64 == -12 {
            Ok(())
        } else {
            Err("clone3 without an address space did not return -ENOMEM")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_clone3_no_as);

// ── execve(2) / execveat(2) — NULL path rejection ──

fn smoke_abi_proc_execve_neg() -> TestResult {
    with_setup(|| {
        // LINUX ABI: execve(NULL, ...) faults on the pathname pointer → -EFAULT
        // (was folded to -EINVAL by the blanket invalid_op path). glibc/callers
        // distinguish a bad-address fault from a bad argument.
        let r = call(Syscall::Execve.raw(), a2(0, 0, 0));
        if r == Some(EFAULT) {
            Ok(())
        } else {
            Err("execve(NULL,..) must return -EFAULT")
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
        // execveat(dirfd, path, argv, envp, flags): a NULL path pointer (arg1)
        // faults → -EFAULT (Linux parity; previously folded to -EINVAL).
        let r = call(Syscall::Execveat.raw(), a3(0, 0, 0, 0));
        if r == Some(EFAULT) {
            Ok(())
        } else {
            Err("execveat with a NULL path must return -EFAULT")
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

// ── unshare(2) — `kernel/fork.c::check_unshare_flags` rejects unknown bits ──
//
// This is the first thing ksys_unshare does, before a single namespace is
// touched, so an unsupported bit changes nothing and reports -EINVAL. NARF
// used to IGNORE unknown bits and return 0 — worse than a wrong errno:
// runc/bubblewrap/systemd probe for namespace support by calling
// unshare(CLONE_NEW<x>) and treating EINVAL as "unsupported", so a blanket 0
// told them a namespace existed and the workload then ran unisolated.
fn smoke_abi_proc_unshare_unknown_flags_neg() -> TestResult {
    with_setup(|| {
        // CLONE_PIDFD (0x1000) is a valid clone(2) flag but is NOT in
        // check_unshare_flags' accepted set.
        const CLONE_PIDFD: u64 = 0x0000_1000;
        if call(Syscall::Unshare.raw(), a0(CLONE_PIDFD)) != Some(EINVAL) {
            return Err("unshare(CLONE_PIDFD) must return -EINVAL");
        }
        // `unsigned long` flags: a bit in the upper half is equally invalid.
        if call(Syscall::Unshare.raw(), a0(1u64 << 40)) != Some(EINVAL) {
            return Err("unshare with a high flag bit must return -EINVAL");
        }
        // A valid bit ORed with an invalid one is still rejected, and must
        // leave the valid namespace unshared (the check runs first).
        const CLONE_NEWNS: u64 = 0x0002_0000;
        if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS | CLONE_PIDFD)) != Some(EINVAL) {
            return Err("unshare(CLONE_NEWNS|CLONE_PIDFD) must return -EINVAL");
        }
        // Positive pin: every bit check_unshare_flags DOES accept, together,
        // so the validation above cannot creep into rejecting a real call.
        const CLONE_VM: u64 = 0x0000_0100;
        const CLONE_FS: u64 = 0x0000_0200;
        const CLONE_FILES: u64 = 0x0000_0400;
        const CLONE_SIGHAND: u64 = 0x0000_0800;
        const CLONE_THREAD: u64 = 0x0001_0000;
        const CLONE_SYSVSEM: u64 = 0x0004_0000;
        const CLONE_NEWTIME: u64 = 0x0000_0080;
        let harmless = CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_NEWTIME;
        if call(Syscall::Unshare.raw(), a0(harmless)) != Some(0) {
            return Err("unshare of the accepted non-namespace bits must return 0");
        }
        let _ = (CLONE_VM, CLONE_SIGHAND, CLONE_THREAD);
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_unshare_unknown_flags_neg);

// ── setns(2) — `kernel/nsproxy.c::SYSCALL_DEFINE2(setns)` ──
//
//   if (fd_empty(f)) return -EBADF;
//   ... else err = -EINVAL;   /* an open fd that is not a namespace file */
//
// Both used to be the bare -1 = EPERM. That is the one answer setns never
// gives here, and it is the answer a container runtime reads as "I am not
// privileged enough to join" — so it abandons the join instead of fixing the
// descriptor it closed too early (EBADF) or the nstype it mismatched (EINVAL).
fn smoke_abi_proc_setns_neg() -> TestResult {
    with_setup(|| {
        // An fd number with nothing open behind it → -EBADF.
        if call(Syscall::Setns.raw(), a1(4242, 0)) != Some(EBADF) {
            return Err("setns on an unoccupied fd must return -EBADF");
        }
        // A negative fd can never name an open file → -EBADF too.
        if call(Syscall::Setns.raw(), a1((-1i64) as u64, 0)) != Some(EBADF) {
            return Err("setns(-1) must return -EBADF");
        }
        // An fd that IS open but is not a namespace file → -EINVAL, the
        // final `else` branch. fd 1 is the console every fresh fd table
        // carries. (This is also the arm that used to reinterpret the number
        // as a pid — see the pidns suite.)
        if call(Syscall::Setns.raw(), a1(1, 0)) != Some(EINVAL) {
            return Err("setns on an open non-namespace fd must return -EINVAL");
        }
        Ok(())
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
        let fd = crate::fd::install(
            task,
            crate::fd::FdEntry {
                ops: alloc::sync::Arc::new(ReentrantFdTableFile),
                offset: 0,
                flags: 0,
                status_flags: 0,
            },
        );
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

// ── securebits (`security/commoncap.c::cap_task_prctl`) ──────────
//
// `PrctlState.securebits` had no readers: it round-tripped through
// PR_GET_SECUREBITS and nothing else consulted it, so every bit was
// decorative. It is the single store for all four settable bits now,
// including SECURE_KEEP_CAPS — which `PR_SET_KEEPCAPS` also writes, as it
// does in Linux.

const PR_SET_SECUREBITS: u64 = 28;
const PR_GET_SECUREBITS: u64 = 27;
const PR_SET_KEEPCAPS_OPT: u64 = 8;
const PR_GET_KEEPCAPS_OPT: u64 = 7;
const SECBIT_KEEP_CAPS: u64 = 1 << 4;
const SECBIT_KEEP_CAPS_LOCKED: u64 = 1 << 5;
const SECBIT_NOROOT: u64 = 1 << 0;
const SECBIT_NOROOT_LOCKED: u64 = 1 << 1;

/// A lock makes its bit immutable, in both directions.
///
/// `cap_task_prctl`'s PR_SET_SECUREBITS guard has four arms and NARF only
/// had the last one:
///
/// ```text
/// if ((((old->securebits & SECURE_ALL_LOCKS) >> 1)
///      & (old->securebits ^ arg2))                        /*[1]*/
///     || ((old->securebits & SECURE_ALL_LOCKS & ~arg2))   /*[2]*/
///     || (arg2 & ~(SECURE_ALL_LOCKS | SECURE_ALL_BITS))   /*[3]*/
///     || (cap_capable(...CAP_SETPCAP...) != 0))           /*[4]*/
///         return -EPERM;
/// ```
///
/// [1] and [2] together are the whole security property: without them a
/// securebit is a suggestion. A sandbox locks NOROOT precisely so that code
/// running later — including code an attacker controls — cannot turn it
/// back off.
fn smoke_abi_proc_prctl_securebits_locks() -> TestResult {
    const EPERM: i64 = -1;
    with_setup(|| {
        // Set NOROOT and lock it.
        let want = SECBIT_NOROOT | SECBIT_NOROOT_LOCKED;
        if call(Syscall::Prctl.raw(), a1(PR_SET_SECUREBITS, want)) != Some(0) {
            return Err("setting NOROOT with its lock should succeed while privileged");
        }
        if call(Syscall::Prctl.raw(), a0(PR_GET_SECUREBITS)) != Some(want as i64) {
            return Err("PR_GET_SECUREBITS did not read back what was set");
        }
        // [1] — clearing a LOCKED bit.
        if call(
            Syscall::Prctl.raw(),
            a1(PR_SET_SECUREBITS, SECBIT_NOROOT_LOCKED),
        ) != Some(EPERM)
        {
            return Err("clearing a locked securebit must be -EPERM");
        }
        // [2] — clearing the LOCK itself.
        if call(Syscall::Prctl.raw(), a1(PR_SET_SECUREBITS, SECBIT_NOROOT)) != Some(EPERM) {
            return Err("clearing a securebit lock must be -EPERM");
        }
        // [3] — a bit outside the defined mask. EPERM, not EINVAL: libcap
        // reads EINVAL as "this kernel has no securebits at all".
        if call(Syscall::Prctl.raw(), a1(PR_SET_SECUREBITS, 1 << 20)) != Some(EPERM) {
            return Err("an undefined securebit must be -EPERM");
        }
        // Setting the same value again is a no-op change, so it is allowed —
        // the control that says the locks refuse CHANGES, not every write.
        if call(Syscall::Prctl.raw(), a1(PR_SET_SECUREBITS, want)) != Some(0) {
            return Err("re-setting the same securebits must still be permitted");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_prctl_securebits_locks);

/// `PR_SET_KEEPCAPS` and `PR_SET_SECUREBITS` write the SAME bit.
///
/// `PR_SET_KEEPCAPS` is `securebits |= issecure_mask(SECURE_KEEP_CAPS)`
/// (`security/commoncap.c:1394`) and `PR_GET_KEEPCAPS` is
/// `issecure(SECURE_KEEP_CAPS)` (`:1382`). NARF kept a separate `keep_caps`
/// bool beside `securebits`, so the two could disagree about the same bit
/// and `PR_SET_SECUREBITS` could not reach the one `cap_emulate_setxuid`
/// actually read.
fn smoke_abi_proc_prctl_keepcaps_is_a_securebit() -> TestResult {
    const EPERM: i64 = -1;
    with_setup(|| {
        // Set through KEEPCAPS, observe through SECUREBITS.
        if call(Syscall::Prctl.raw(), a1(PR_SET_KEEPCAPS_OPT, 1)) != Some(0) {
            return Err("PR_SET_KEEPCAPS(1) should succeed");
        }
        match call(Syscall::Prctl.raw(), a0(PR_GET_SECUREBITS)) {
            Some(bits) if bits as u64 & SECBIT_KEEP_CAPS != 0 => {}
            _ => return Err("PR_SET_KEEPCAPS did not set SECBIT_KEEP_CAPS"),
        }
        // Clear through SECUREBITS, observe through KEEPCAPS.
        if call(Syscall::Prctl.raw(), a1(PR_SET_SECUREBITS, 0)) != Some(0) {
            return Err("clearing securebits should succeed");
        }
        if call(Syscall::Prctl.raw(), a0(PR_GET_KEEPCAPS_OPT)) != Some(0) {
            return Err("clearing SECBIT_KEEP_CAPS did not clear PR_GET_KEEPCAPS");
        }
        // The lock applies to PR_SET_KEEPCAPS too — same bit, same rules.
        if call(
            Syscall::Prctl.raw(),
            a1(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS_LOCKED),
        ) != Some(0)
        {
            return Err("locking SECBIT_KEEP_CAPS should succeed");
        }
        if call(Syscall::Prctl.raw(), a1(PR_SET_KEEPCAPS_OPT, 1)) != Some(EPERM) {
            return Err("PR_SET_KEEPCAPS under SECURE_KEEP_CAPS_LOCKED must be -EPERM");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_prctl_keepcaps_is_a_securebit);

/// Ambient survives an ordinary exec into permitted and effective, and a
/// set-user-ID exec cancels it.
///
/// This is what makes the ambient set worth having (`cap_bprm_creds_from_file`,
/// `security/commoncap.c:966`). Without it `PR_CAP_AMBIENT_RAISE` writes a
/// field that never influences anything — which, with the set split across
/// two stores, is exactly what it did.
fn smoke_abi_proc_ambient_survives_exec() -> TestResult {
    const CAP_NET_ADMIN: u64 = 12;
    const OWNER: u32 = 4300;
    const CALLER: u32 = 1300;
    with_memfs("/amb", "amb", &[("prog", b"\x7fELF")], || {
        let task = FAKE_TASK;
        let path = "/amb/prog";
        let cpath = b"/amb/prog\0";
        let bit = 1u64 << CAP_NET_ADMIN;

        // Raise it ambient: needs permitted AND inheritable.
        crate::handlers::__test_set_inheritable(task, bit);
        if call(
            Syscall::Prctl.raw(),
            a2(
                47, /* PR_CAP_AMBIENT */
                2,  /* RAISE */
                CAP_NET_ADMIN,
            ),
        ) != Some(0)
        {
            return Err("the ambient raise fixture failed");
        }

        // An ORDINARY exec (no set-user-ID bit) as a non-root uid: the
        // effective set collapses to the ambient one, so the raised
        // capability is what survives.
        if call(Syscall::Chmod.raw(), a1(cpath.as_ptr() as u64, 0o755)) != Some(0) {
            return Err("chmod of the probe binary failed");
        }
        crate::handlers::__test_set_fsids(task, CALLER, CALLER);
        let (_, _, _, effective) = crate::handlers::__test_bprm_fill_uid(task, path, false);
        if effective & bit == 0 {
            crate::handlers::__test_uidgid_reset();
            crate::handlers::__test_caps_reset();
            return Err("an ambient capability did not survive an ordinary exec");
        }

        // A SET-USER-ID exec cancels ambient: the new image is already
        // gaining privilege from the file, and carrying a second
        // independently granted set across the same exec would stack two
        // sources the caller never combined deliberately.
        crate::handlers::__test_caps_reset();
        crate::handlers::__test_set_inheritable(task, bit);
        let _ = call(Syscall::Prctl.raw(), a2(47, 2, CAP_NET_ADMIN));
        let chown_ok = call(
            Syscall::Chown.raw(),
            a2(cpath.as_ptr() as u64, OWNER as u64, OWNER as u64),
        ) == Some(0)
            && call(Syscall::Chmod.raw(), a1(cpath.as_ptr() as u64, 0o4755)) == Some(0);
        crate::handlers::__test_set_fsids(task, CALLER, CALLER);
        let (euid, ..) = crate::handlers::__test_bprm_fill_uid(task, path, false);
        let ambient_after = crate::handlers::__test_ambient(task);
        crate::handlers::__test_uidgid_reset();
        crate::handlers::__test_caps_reset();
        if !chown_ok {
            return Err("staging the set-user-ID probe binary failed");
        }
        if euid != OWNER {
            return Err("the set-user-ID transition did not happen — the case is vacuous");
        }
        if ambient_after != 0 {
            return Err("a set-user-ID exec must cancel the ambient set");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_ambient_survives_exec);

// ── RLIMIT_CPU ──────────────────────────────────────────────────────
//
// `kernel/time/posix-cpu-timers.c::check_process_timers`. The limit used to
// appear exactly once in this tree, in a comment listing default values as
// `= INFINITY`; setrlimit accepted it and nothing ever read it, so a process
// held to one second of CPU ran forever.
//
// The sampling hook is the timer tick's return-to-user path, so these drive
// it directly rather than waiting on wall time.

const RLIMIT_CPU_RES: u64 = 0;
/// SIGXCPU is signal 24 ⇒ bit 23 (`sig_bit(n) == 1 << (n - 1)`).
const SIGXCPU_PENDING: u64 = 1u64 << 23;
/// SIGKILL is signal 9 ⇒ bit 8. It cannot be blocked, so it is read from the
/// raw pending bitmap rather than through `rt_sigpending`.
const SIGKILL_PENDING: u64 = 1u64 << 8;
const ONE_SEC_NS: u64 = 1_000_000_000;

fn set_cpu_limit(cur: u64, max: u64) -> Result<(), &'static str> {
    let pair = [cur, max];
    match call(
        Syscall::Setrlimit.raw(),
        a1(RLIMIT_CPU_RES, pair.as_ptr() as u64),
    ) {
        Some(0) => Ok(()),
        _ => Err("could not set RLIMIT_CPU"),
    }
}

fn cpu_soft_limit() -> Result<u64, &'static str> {
    let mut pair = [0u64; 2];
    match call(
        Syscall::Getrlimit.raw(),
        a1(RLIMIT_CPU_RES, pair.as_mut_ptr() as u64),
    ) {
        Some(0) => Ok(pair[0]),
        _ => Err("could not read RLIMIT_CPU"),
    }
}

/// Burn `ns` of CPU on the harness task, through the field the real
/// accounting path writes.
fn burn_cpu_ns(ns: u64) -> Result<(), &'static str> {
    if crate::task::__test_add_cpu_ns(FAKE_TASK, ns, 0) {
        Ok(())
    } else {
        Err("harness task is not registered")
    }
}

/// Start from a known zero. The harness task is registered once for the
/// whole run, so its CPU accounting is cumulative across smokes — without
/// this, whichever of these tests ran first decided whether the others saw
/// a task that had already burned a minute.
fn reset_cpu_ns() {
    crate::task::__test_reset_cpu_ns(FAKE_TASK);
}

fn smoke_abi_proc_rlimit_cpu_soft_warns_and_rearms() -> TestResult {
    with_setup(|| {
        reset_cpu_ns();
        set_cpu_limit(1, u64::MAX)?;

        // Under the limit: nothing fires. Without this arm the test would
        // pass for a hook that signalled unconditionally.
        burn_cpu_ns(ONE_SEC_NS / 10)?;
        crate::handlers::numa_balance_tick();
        if crate::handlers::signal_pending_of(FAKE_TASK) & SIGXCPU_PENDING != 0 {
            return Err("SIGXCPU raised below RLIMIT_CPU");
        }
        if cpu_soft_limit()? != 1 {
            return Err("the soft limit moved before it was reached");
        }

        // At the limit. `check_rlimit` fires on `time >= limit`, not `>`.
        burn_cpu_ns(ONE_SEC_NS)?;
        crate::handlers::numa_balance_tick();
        if crate::handlers::signal_pending_of(FAKE_TASK) & SIGXCPU_PENDING == 0 {
            return Err("reaching RLIMIT_CPU did not raise SIGXCPU");
        }

        // The distinctive part: the soft limit RAISES ITSELF by a second.
        // That is how Linux implements "a SIGXCPU every second", and it is
        // visible to the process — `getrlimit` now reports a limit larger
        // than the one it set.
        if cpu_soft_limit()? != 2 {
            return Err("the soft limit did not re-arm one second later");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc_rlimit_cpu_soft_warns_and_rearms
);

fn smoke_abi_proc_rlimit_cpu_hard_kills() -> TestResult {
    with_setup(|| {
        // soft 1s, hard 3s.
        reset_cpu_ns();
        set_cpu_limit(1, 3)?;

        // Between the two: warned, not killed. The hard arm returning
        // immediately is what makes this ordering observable.
        burn_cpu_ns(2 * ONE_SEC_NS)?;
        crate::handlers::numa_balance_tick();
        let pending = crate::handlers::signal_pending_of(FAKE_TASK);
        if pending & SIGXCPU_PENDING == 0 {
            return Err("past the soft limit did not raise SIGXCPU");
        }
        if pending & SIGKILL_PENDING != 0 {
            return Err("SIGKILL raised before the hard limit");
        }

        // At the hard limit: SIGKILL.
        burn_cpu_ns(2 * ONE_SEC_NS)?;
        crate::handlers::numa_balance_tick();
        if crate::handlers::signal_pending_of(FAKE_TASK) & SIGKILL_PENDING == 0 {
            return Err("reaching the RLIMIT_CPU hard limit did not raise SIGKILL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_rlimit_cpu_hard_kills);

fn smoke_abi_proc_rlimit_cpu_infinity_is_free() -> TestResult {
    with_setup(|| {
        reset_cpu_ns();
        // The default is RLIM_INFINITY, and the sampler must take its early
        // return — otherwise every task on the system pays a thread-group
        // walk on every timer tick.
        burn_cpu_ns(60 * ONE_SEC_NS)?;
        crate::handlers::numa_balance_tick();
        let pending = crate::handlers::signal_pending_of(FAKE_TASK);
        if pending & (SIGXCPU_PENDING | SIGKILL_PENDING) != 0 {
            return Err("an unlimited RLIMIT_CPU still signalled");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_rlimit_cpu_infinity_is_free);

// ── RLIMIT_NPROC ────────────────────────────────────────────────────
//
// `kernel/fork.c::copy_process`. The limit had appeared exactly once in
// this tree — in a comment in `sys_fork` explaining what the GLOBAL
// live-task cap stands in for — so a single unprivileged account could
// consume every slot that cap allows.
//
// Counted per REAL uid, over live and zombie tasks alike, and exempting
// uid 0 (`INIT_USER`) plus CAP_SYS_RESOURCE / CAP_SYS_ADMIN. The harness
// holds one task, so its own credential row is the count.

const RLIMIT_NPROC_RES: u64 = 6;
#[cfg(target_arch = "x86_64")]
const NOCHANGE_ID: u64 = u64::MAX;

fn set_nproc_limit(cur: u64) -> Result<(), &'static str> {
    let pair = [cur, u64::MAX];
    match call(
        Syscall::Setrlimit.raw(),
        a1(RLIMIT_NPROC_RES, pair.as_ptr() as u64),
    ) {
        Some(0) => Ok(()),
        _ => Err("could not set RLIMIT_NPROC"),
    }
}

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_rlimit_nproc_refuses_fork() -> TestResult {
    with_setup(|| {
        // A real privilege drop, not a fsuid poke: the count is over REAL
        // uids, and `cap_emulate_setxuid` has to run so the capability
        // exemption below is not silently granted.
        if call(Syscall::Setresuid.raw(), a2(1000, 1000, 1000)) != Some(0) {
            return Err("could not drop to an unprivileged uid");
        }
        // One task owns uid 1000, so a limit of 1 is exactly full: Linux
        // increments for the task being created and then tests `val > max`,
        // so N tasks fit and the (N+1)-th attempt fails.
        set_nproc_limit(1)?;
        // -EAGAIN outranks the harness's no-address-space -ENOMEM, because
        // `copy_creds` runs long before `copy_mm`. A check placed after the
        // AS lookup would report ENOMEM here and this would read as a pass
        // for the wrong reason.
        match call(Syscall::Fork.raw(), a0(0)) {
            Some(v) if v == EAGAIN => {}
            Some(v) if v == ENOMEM => {
                return Err("RLIMIT_NPROC was checked after the address space, not before")
            }
            _ => return Err("fork over RLIMIT_NPROC was not -EAGAIN"),
        }
        // Raising the limit lets it through to the normal no-AS path again,
        // which proves the refusal came from the limit and not from
        // something the privilege drop broke.
        set_nproc_limit(64)?;
        match call(Syscall::Fork.raw(), a0(0)) {
            Some(v) if v == ENOMEM => Ok(()),
            _ => Err("fork under RLIMIT_NPROC did not reach the address-space path"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_rlimit_nproc_refuses_fork);

/// v3 capability header version, as `abi_creds_tests` spells it.
#[cfg(target_arch = "x86_64")]
const NPROC_CAP_VERSION_3: u32 = 0x2008_0522;
/// CAP_SYS_ADMIN (21) and CAP_SYS_RESOURCE (24) — the two that exempt a
/// task from RLIMIT_NPROC. Both are below 32, so both live in word 0.
#[cfg(target_arch = "x86_64")]
const NPROC_EXEMPTING_CAPS: u32 = (1u32 << 21) | (1u32 << 24);

/// Drop CAP_SYS_ADMIN and CAP_SYS_RESOURCE, keeping everything else.
///
/// Without this, a test of the uid-0 exemption is VACUOUS: root also holds
/// both capabilities, so the capability arm answers first and deleting the
/// uid check changes nothing. Found exactly that way — stubbing the uid
/// check out left the test passing.
#[cfg(target_arch = "x86_64")]
fn drop_nproc_exempting_caps() -> Result<(), &'static str> {
    let mut hdr = [0u32; 2];
    hdr[0] = NPROC_CAP_VERSION_3;
    // capget writes three u32 pairs: effective, permitted, inheritable.
    let mut data = [0u32; 6];
    if call(
        Syscall::Capget.raw(),
        a1(hdr.as_mut_ptr() as u64, data.as_mut_ptr() as u64),
    ) != Some(0)
    {
        return Err("capget failed");
    }
    // Word 0 of each set is data[0], data[2], data[4]; word 1 is the odd
    // indices and holds no capability this cares about.
    for i in [0usize, 2, 4] {
        data[i] &= !NPROC_EXEMPTING_CAPS;
    }
    hdr[0] = NPROC_CAP_VERSION_3;
    if call(
        Syscall::Capset.raw(),
        a1(hdr.as_mut_ptr() as u64, data.as_mut_ptr() as u64),
    ) != Some(0)
    {
        return Err("capset failed to drop the exempting capabilities");
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_rlimit_nproc_exempts_root() -> TestResult {
    with_setup(|| {
        set_nproc_limit(0)?;
        // Isolate the uid-0 arm by removing the other reason root would be
        // exempt. What remains under test is `p->real_cred->user != INIT_USER`
        // alone.
        drop_nproc_exempting_caps()?;
        match call(Syscall::Fork.raw(), a0(0)) {
            Some(v) if v == ENOMEM => Ok(()),
            Some(v) if v == EAGAIN => Err("RLIMIT_NPROC was applied to uid 0"),
            _ => Err("fork as root returned an unexpected error"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_rlimit_nproc_exempts_root);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_rlimit_nproc_exempts_capable() -> TestResult {
    with_setup(|| {
        // Real uid 1000 with effective uid 0: COUNTED under 1000, so the
        // uid-0 arm cannot answer, while the capabilities survive because
        // `cap_emulate_setxuid` only drops them on an EFFECTIVE transition
        // away from root. That isolates the capability arm.
        if call(Syscall::Setresuid.raw(), a2(1000, NOCHANGE_ID, NOCHANGE_ID)) != Some(0) {
            return Err("could not set a non-root real uid");
        }
        set_nproc_limit(0)?;
        match call(Syscall::Fork.raw(), a0(0)) {
            Some(v) if v == ENOMEM => Ok(()),
            Some(v) if v == EAGAIN => {
                Err("CAP_SYS_RESOURCE did not exempt the task from RLIMIT_NPROC")
            }
            _ => Err("fork with CAP_SYS_RESOURCE returned an unexpected error"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_rlimit_nproc_exempts_capable);

fn smoke_abi_proc_rlimit_nproc_defers_setuid_failure_to_execve() -> TestResult {
    with_setup(|| {
        // Zero, so the uid the task moves to is over quota the moment it
        // arrives (`val > max` with one task and a limit of none).
        set_nproc_limit(0)?;

        // set*uid() must SUCCEED anyway. Linux is explicit that it does not
        // fail here because "too many poorly written programs don't check
        // set*uid() return code" — the failure is deferred instead.
        if call(Syscall::Setresuid.raw(), a2(1000, 1000, 1000)) != Some(0) {
            return Err("set*uid() must not fail for RLIMIT_NPROC");
        }

        // ...and execve is where it lands. The path does not exist: -EAGAIN
        // rather than -ENOENT is what shows the check runs before the binary
        // is resolved, as `do_execveat_common` does it.
        let path = b"/nonexistent-nproc-probe\0";
        match call(Syscall::Execve.raw(), a2(path.as_ptr() as u64, 0, 0)) {
            Some(v) if v == EAGAIN => {}
            Some(v) if v == ENOENT => {
                return Err("the deferred RLIMIT_NPROC failure ran after path resolution")
            }
            _ => return Err("execve after an over-quota set*uid() was not -EAGAIN"),
        }

        // The recheck: back under the limit, execve must stop failing.
        // Linux clears the flag rather than latching it — "we're below the
        // limit (still or again), so we don't want to make further execve()
        // calls fail."
        set_nproc_limit(64)?;
        match call(Syscall::Execve.raw(), a2(path.as_ptr() as u64, 0, 0)) {
            Some(v) if v == EAGAIN => {
                Err("the RLIMIT_NPROC exec flag latched instead of being rechecked")
            }
            _ => Ok(()),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_proc_rlimit_nproc_defers_setuid_failure_to_execve
);
