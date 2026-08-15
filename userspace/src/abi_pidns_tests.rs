//! Linux syscall ABI conformance — PID-namespace argument translation.
//!
//! Every syscall that takes a pid ARRIVING from userspace must resolve it in
//! the CALLER's pid namespace (Linux `find_task_by_vpid`), i.e. through
//! `accept_pid_from(current_task_id(), pid)` before it is used as an outer
//! ProcessId / scheduler TaskId / table key. These tests pin the fixes for the
//! `docs/pidns_translation_audit.md` findings whose handlers keyed on the RAW
//! caller-namespace pid.
//!
//! Each test builds a fresh PID namespace: a MANAGER task (`unshare(CLONE_NEWPID)`
//! → inner pid 1) and a WORKER inherited into it (inner pid 2). It then drives
//! the syscall with the WORKER's IN-NAMESPACE pid (2) and asserts the handler
//! acted on the WORKER (outer WORKER_PID / WORKER_TASK), not on whatever
//! ROOT-namespace entity a raw lookup of the number 2 would land on.
//!
//! Gated on `container` (the pid-namespace tables only exist there) AND
//! `linux-compat` (the ABI harness).
#![cfg(all(feature = "linux-compat", feature = "container"))]

use crate::abi_test_support::*;

/// Register a task in every table a real spawned task appears in: the
/// refcounted scheduler registry and the outer-pid ↔ TaskId maps. Only ever
/// called with LARGE, synthetic TaskIds — never a small number that could
/// alias a live boot/kernel task.
fn register(task: u64, pid: u64) {
    crate::task::release_task(task);
    let _ = crate::task::Task::new_registered(task, pid);
    crate::handlers::register_task_to_pid(task, pid);
    crate::handlers::register_pid_task_mapping(pid, task);
}

/// Release each synthetic task from the refcounted registry (teardown).
fn release_all(tasks: &[u64]) {
    for &t in tasks {
        crate::task::release_task(t);
    }
}

/// unshare a fresh PID namespace for `manager` (→ inner pid 1) and inherit
/// `worker` into it (→ inner pid 2). Returns Err on any binding surprise.
fn build_manager_worker(
    manager_task: u64,
    manager_pid: u64,
    worker_task: u64,
    worker_pid: u64,
) -> Result<(), &'static str> {
    crate::pid_ns::unshare_pid_ns(manager_task, manager_pid);
    if crate::pid_ns::inherit_into_child(manager_task, worker_task, worker_pid) != Some(2) {
        return Err("worker was not assigned inner pid 2");
    }
    Ok(())
}

// ── #11 prlimit64(pid) — Linux kernel/sys.c:1751 `find_task_by_vpid` ──
//
// The handler did `let task = if pid == 0 { current } else { pid };`, using the
// caller-namespace pid DIRECTLY as the TaskId the rlimit table keys on. The fix
// translates inner → outer → TaskId. Observed by seeding only the WORKER's
// RLIMIT_NOFILE and reading it back by the worker's inner pid: the fix reads the
// worker's soft limit, the bug reads the (empty) TaskId `2` slot → the default.
fn smoke_abi_pidns_prlimit64_resolves_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xD100;
        const MANAGER_PID: u64 = 0xD000;
        const WORKER_TASK: u64 = 0xD101;
        const WORKER_PID: u64 = 0xD001;
        const RLIMIT_NOFILE: u64 = 7;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            // Seed only the worker's soft NOFILE (111) via its self arm.
            let mut wbuf = [0u8; 16];
            wbuf[..8].copy_from_slice(&111u64.to_ne_bytes());
            wbuf[8..].copy_from_slice(&222u64.to_ne_bytes());
            set_task(WORKER_TASK);
            if call(
                Syscall::Prlimit64.raw(),
                a3(0, RLIMIT_NOFILE, wbuf.as_ptr() as u64, 0),
            ) != Some(0)
            {
                return Err("seeding the worker rlimit failed");
            }

            // Manager reads inner pid 2's prior soft limit into oldbuf.
            set_task(MANAGER_TASK);
            let mut oldbuf = [0u8; 16];
            if call(
                Syscall::Prlimit64.raw(),
                a3(2, RLIMIT_NOFILE, 0, oldbuf.as_mut_ptr() as u64),
            ) != Some(0)
            {
                return Err("prlimit64 read of inner pid 2 did not succeed");
            }
            let cur = u64::from_ne_bytes(oldbuf[..8].try_into().unwrap());
            if cur == 111 {
                Ok(())
            } else {
                Err("prlimit64 used the inner pid directly as a TaskId (read the wrong / default rlimit) — accept_pid_from -> pid_to_task_raw missing")
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, WORKER_TASK]);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pidns_prlimit64_resolves_in_caller_pid_ns
);

// ── #12 kcmp(pid1, pid2) — Linux kernel/kcmp.c:146 `find_task_by_vpid` ──
//
// `resolve()` did `pid_to_task_raw(pid)` on the raw inner pids, so an
// in-namespace pid resolved to whatever ROOT-namespace process owned the same
// number. Two workers (inner 2 / inner 3) plus two collision victims registered
// at OUTER pids 2 / 3. TaskIds are chosen so the CORRECT comparison (worker2 vs
// worker3) orders `2` while the BUGGY comparison (victim@2 vs victim@3) orders
// `1` — a clean 2-vs-1 discriminator that also proves BOTH args are translated.
fn smoke_abi_pidns_kcmp_resolves_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xC100;
        const MANAGER_PID: u64 = 0xC000;
        const W1_TASK: u64 = 0xC201; // inner 2; LARGER than W2_TASK
        const W1_PID: u64 = 0xC001;
        const W2_TASK: u64 = 0xC102; // inner 3; SMALLER than W1_TASK
        const W2_PID: u64 = 0xC002;
        const V1_TASK: u64 = 0xC300; // registered at OUTER pid 2; SMALLER than V2
        const V1_PID: u64 = 2;
        const V2_TASK: u64 = 0xC400; // registered at OUTER pid 3; LARGER than V1
        const V2_PID: u64 = 3;
        const KCMP_FILE: u64 = 0;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(W1_TASK, W1_PID);
            register(W2_TASK, W2_PID);
            register(V1_TASK, V1_PID);
            register(V2_TASK, V2_PID);
            crate::pid_ns::unshare_pid_ns(MANAGER_TASK, MANAGER_PID);
            if crate::pid_ns::inherit_into_child(MANAGER_TASK, W1_TASK, W1_PID) != Some(2) {
                return Err("worker1 was not assigned inner pid 2");
            }
            if crate::pid_ns::inherit_into_child(MANAGER_TASK, W2_TASK, W2_PID) != Some(3) {
                return Err("worker2 was not assigned inner pid 3");
            }
            set_task(MANAGER_TASK);
            // Correct: cmp(W1_TASK=0xC201, W2_TASK=0xC102) -> t1>t2 -> 2.
            // Buggy:   cmp(V1_TASK=0xC300, V2_TASK=0xC400) -> t1<t2 -> 1.
            match call(Syscall::Kcmp.raw(), a3(2, 3, KCMP_FILE, 0)) {
                Some(2) => Ok(()),
                Some(1) => Err("kcmp compared ROOT-namespace collision victims — raw pid_to_task_raw on the inner pids instead of accept_pid_from"),
                Some(-3) => Err("kcmp returned ESRCH for resolvable in-namespace pids"),
                _ => Err("kcmp returned an unexpected result"),
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, W1_TASK, W2_TASK, V1_TASK, V2_TASK]);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pidns_kcmp_resolves_in_caller_pid_ns
);

// ── #18 sched_setparam(pid) — Linux kernel/sched/syscalls.c ──
//
// `let task = if pid == 0 { current } else { pid };` used the caller-namespace
// pid directly as the SCHED_PARAM_TABLE key. The fix mirrors sched_setaffinity.
// The manager sets the worker's param by inner pid 2, then the worker reads its
// OWN param (self arm): the fix routed the write to the worker (99), the bug
// wrote the raw-`2` slot, leaving the worker's entry at the default (0).
fn smoke_abi_pidns_sched_setparam_resolves_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xE100;
        const MANAGER_PID: u64 = 0xE000;
        const WORKER_TASK: u64 = 0xE101;
        const WORKER_PID: u64 = 0xE001;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            let prio = 99i32;
            set_task(MANAGER_TASK);
            if call(
                Syscall::SchedSetparam.raw(),
                a1(2, &prio as *const i32 as u64),
            ) != Some(0)
            {
                return Err("sched_setparam(inner 2) did not succeed");
            }
            // Worker reads its own param (self arm — unaffected by the bug).
            set_task(WORKER_TASK);
            let mut out = 0i32;
            if call(
                Syscall::SchedGetparam.raw(),
                a1(0, &mut out as *mut i32 as u64),
            ) != Some(0)
            {
                return Err("reading the worker's sched param failed");
            }
            if out == 99 {
                Ok(())
            } else {
                Err("sched_setparam wrote the raw inner pid's TaskId slot, not the worker's — accept_pid_from -> pid_to_task_raw missing")
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, WORKER_TASK]);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pidns_sched_setparam_resolves_in_caller_pid_ns
);

// ── #18 sched_getparam(pid) — Linux kernel/sched/syscalls.c ──
//
// Same raw-pid-as-key bug on the read side. Seed only the worker's param (77)
// via its self arm, then have the manager read it by inner pid 2: the fix reads
// the worker (77), the bug reads the empty raw-`2` slot (default 0).
fn smoke_abi_pidns_sched_getparam_resolves_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xE110;
        const MANAGER_PID: u64 = 0xE010;
        const WORKER_TASK: u64 = 0xE111;
        const WORKER_PID: u64 = 0xE011;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            let prio = 77i32;
            set_task(WORKER_TASK);
            if call(
                Syscall::SchedSetparam.raw(),
                a1(0, &prio as *const i32 as u64),
            ) != Some(0)
            {
                return Err("seeding the worker's sched param failed");
            }
            set_task(MANAGER_TASK);
            let mut out = 0i32;
            if call(
                Syscall::SchedGetparam.raw(),
                a1(2, &mut out as *mut i32 as u64),
            ) != Some(0)
            {
                return Err("sched_getparam(inner 2) did not succeed");
            }
            if out == 77 {
                Ok(())
            } else {
                Err("sched_getparam read the raw inner pid's TaskId slot, not the worker's — accept_pid_from -> pid_to_task_raw missing")
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, WORKER_TASK]);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pidns_sched_getparam_resolves_in_caller_pid_ns
);

// ── #19 capset(hdr.pid) — Linux kernel/capability.c:115 `task_pid_vnr` ──
//
// The self-check compared the caller-supplied (inner) pid against the caller's
// OUTER self pid, so a container task passing its own getpid() (an inner value)
// hit a spurious EPERM. The fix translates the incoming pid first. The worker
// runs the standard capget→capset privilege-drop with its OWN in-namespace pid.
fn smoke_abi_pidns_capset_self_pid_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xF100;
        const MANAGER_PID: u64 = 0xF000;
        const WORKER_TASK: u64 = 0xF101;
        const WORKER_PID: u64 = 0xF001;
        const CAP_VERSION_3: u32 = 0x2008_0522;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            let mut hdr = [0u8; 8];
            hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
            hdr[4..].copy_from_slice(&2i32.to_le_bytes()); // caller's getpid() == inner 2
            let mut data = [0u8; 24];
            set_task(WORKER_TASK);
            match call(
                Syscall::Capset.raw(),
                a1(hdr.as_mut_ptr() as u64, data.as_mut_ptr() as u64),
            ) {
                Some(0) => Ok(()),
                Some(-1) => Err("capset rejected the caller's OWN in-namespace pid with EPERM — the inner pid was compared against the outer self pid without accept_pid_from"),
                _ => Err("capset returned an unexpected result"),
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, WORKER_TASK]);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pidns_capset_self_pid_in_caller_pid_ns
);

// ── #20 migrate_pages(pid) — Linux mm/migrate.c:2541 `find_task_by_vpid` ──
//
// The self-check `arg0 != task && arg0 != visible_pid` compared the inner pid
// against the outer self pid → spurious EPERM in a container. The fix translates
// arg0 first. With arg0 = the worker's own inner pid and maxnode = 0, a PASSING
// self-check falls through to the next validation (EINVAL); a FAILING one
// returns EPERM.
fn smoke_abi_pidns_migrate_pages_self_pid_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xF200;
        const MANAGER_PID: u64 = 0xF010;
        const WORKER_TASK: u64 = 0xF201;
        const WORKER_PID: u64 = 0xF011;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            set_task(WORKER_TASK);
            match call(Syscall::MigratePages.raw(), a3(2, 0, 0, 0)) {
                Some(-22) => Ok(()),
                Some(-1) => Err("migrate_pages rejected the caller's OWN in-namespace pid with EPERM — arg0 compared untranslated against the outer self pid"),
                _ => Err("migrate_pages returned an unexpected result"),
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, WORKER_TASK]);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pidns_migrate_pages_self_pid_in_caller_pid_ns
);

// ── #20 move_pages(pid) — Linux mm/migrate.c `find_task_by_vpid` ──
//
// Same untranslated self-comparison. With arg0 = the worker's own inner pid and
// valid page/status pointers, a PASSING self-check falls through to
// current_address_space() (absent in the ABI harness → InvalidOp, so `call`
// yields None); a FAILING one returns EPERM.
fn smoke_abi_pidns_move_pages_self_pid_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xF210;
        const MANAGER_PID: u64 = 0xF020;
        const WORKER_TASK: u64 = 0xF211;
        const WORKER_PID: u64 = 0xF021;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            set_task(WORKER_TASK);
            let pages = [0u64; 1];
            let mut status = [0i32; 1];
            let args = SyscallArgs {
                arg0: 2, // caller's own inner pid
                arg1: 1, // count
                arg2: pages.as_ptr() as u64,
                arg3: 0, // nodes == NULL (query mode)
                arg4: status.as_mut_ptr() as u64,
                arg5: 0, // flags
                ..Default::default()
            };
            match call(Syscall::MovePages.raw(), args) {
                None => Ok(()),
                Some(-1) => Err("move_pages rejected the caller's OWN in-namespace pid with EPERM — arg0 compared untranslated against the outer self pid"),
                Some(_) => Err("move_pages returned an unexpected result"),
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, WORKER_TASK]);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pidns_move_pages_self_pid_in_caller_pid_ns
);

// ── #22 get_robust_list(pid) — Linux kernel/futex/syscalls.c:59 ──
//
// `let task = if arg0 == 0 { current } else { arg0 };` used the caller-namespace
// pid directly as the ROBUST_LIST_TABLE key. Seed only the worker's list head,
// then read it by inner pid 2: the fix returns the worker's head, the bug reads
// the raw-`2` slot (a different key) → not the worker's head.
fn smoke_abi_pidns_get_robust_list_resolves_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xA100;
        const MANAGER_PID: u64 = 0xA000;
        const WORKER_TASK: u64 = 0xA101;
        const WORKER_PID: u64 = 0xA001;
        const WORKER_HEAD: u64 = 0xAAAA_0000;
        const ROBUST_LEN: u64 = 24;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            set_task(WORKER_TASK);
            if call(Syscall::SetRobustList.raw(), a1(WORKER_HEAD, ROBUST_LEN)) != Some(0) {
                return Err("seeding the worker robust list failed");
            }
            set_task(MANAGER_TASK);
            let mut head_out = 0u64;
            let mut len_out = 0u64;
            if call(
                Syscall::GetRobustList.raw(),
                a2(
                    2,
                    &mut head_out as *mut u64 as u64,
                    &mut len_out as *mut u64 as u64,
                ),
            ) != Some(0)
            {
                return Err("get_robust_list(inner 2) did not succeed");
            }
            if head_out == WORKER_HEAD {
                Ok(())
            } else {
                Err("get_robust_list used the inner pid directly as a TaskId key (read the wrong head) — accept_pid_from -> pid_to_task_raw missing")
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, WORKER_TASK]);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pidns_get_robust_list_resolves_in_caller_pid_ns
);

// ── #23 ioprio_set(WHO_PROCESS, who) — Linux block/ioprio.c ──
//
// `who` was used raw as the IOPRIO_TABLE key `(which, who)`, so two namespaces
// with the same inner pid share one entry. For IOPRIO_WHO_PROCESS the fix
// translates `who`. The manager sets the worker's ioprio by inner pid 2; a
// root-ns reader then queries the worker's OUTER pid: the fix stored it there,
// the bug stored it under the raw-`2` key (leaving the outer key at default).
fn smoke_abi_pidns_ioprio_set_resolves_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xA200;
        const MANAGER_PID: u64 = 0xA010;
        const WORKER_TASK: u64 = 0xA201;
        const WORKER_PID: u64 = 0xA011;
        const IOPRIO_WHO_PROCESS: u64 = 1;
        const IOPRIO_DEFAULT: u64 = (2u64 << 13) | 4;
        const WORKER_PRIO: u64 = 0x0AAA;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            set_task(MANAGER_TASK);
            if call(
                Syscall::IoprioSet.raw(),
                a2(IOPRIO_WHO_PROCESS, 2, WORKER_PRIO),
            ) != Some(0)
            {
                return Err("ioprio_set(WHO_PROCESS, inner 2) did not succeed");
            }
            // Root-ns reader queries the worker by its OUTER pid.
            set_task(FAKE_TASK);
            match call(Syscall::IoprioGet.raw(), a1(IOPRIO_WHO_PROCESS, WORKER_PID)) {
                Some(v) if v as u64 == WORKER_PRIO => Ok(()),
                Some(v) if v as u64 == IOPRIO_DEFAULT => Err("ioprio_set keyed the ioprio under the raw inner pid, not the worker's outer pid — accept_pid_from missing"),
                _ => Err("ioprio entry for the worker has an unexpected value"),
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, WORKER_TASK]);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pidns_ioprio_set_resolves_in_caller_pid_ns
);

// ── #23 ioprio_get(WHO_PROCESS, who) — Linux block/ioprio.c ──
//
// Same raw-`who` bug on the read side. A root-ns task records the worker's
// ioprio under its OUTER pid; the manager then reads it by inner pid 2: the fix
// resolves to the worker (found), the bug reads the raw-`2` key (default).
fn smoke_abi_pidns_ioprio_get_resolves_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xA210;
        const MANAGER_PID: u64 = 0xA020;
        const WORKER_TASK: u64 = 0xA211;
        const WORKER_PID: u64 = 0xA021;
        const IOPRIO_WHO_PROCESS: u64 = 1;
        const IOPRIO_DEFAULT: u64 = (2u64 << 13) | 4;
        const WORKER_PRIO: u64 = 0x0246;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            // Root-ns task records the worker's real (outer-pid) ioprio.
            set_task(FAKE_TASK);
            if call(
                Syscall::IoprioSet.raw(),
                a2(IOPRIO_WHO_PROCESS, WORKER_PID, WORKER_PRIO),
            ) != Some(0)
            {
                return Err("seeding the worker ioprio failed");
            }
            set_task(MANAGER_TASK);
            match call(Syscall::IoprioGet.raw(), a1(IOPRIO_WHO_PROCESS, 2)) {
                Some(v) if v as u64 == WORKER_PRIO => Ok(()),
                Some(v) if v as u64 == IOPRIO_DEFAULT => Err("ioprio_get read the raw inner pid key, not the worker's outer pid — accept_pid_from missing"),
                _ => Err("ioprio_get returned an unexpected value"),
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, WORKER_TASK]);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pidns_ioprio_get_resolves_in_caller_pid_ns
);
