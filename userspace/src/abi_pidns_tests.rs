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
#![cfg(feature = "container")]

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

            // Seed the worker's slot with a sentinel, then have the manager
            // write 0 to it by INNER pid. If the translation resolves, the
            // sentinel is overwritten; if setparam keyed the raw inner pid
            // instead, the sentinel survives.
            //
            // The value written has to be 0 — `sched_setparam` accepts only
            // 0 for a SCHED_OTHER task — so the discriminator is the
            // sentinel's disappearance rather than a distinctive value
            // arriving. (This test used to write 99, which Linux rejects
            // outright on SCHED_OTHER.)
            const SENTINEL: i32 = 0x5A5A;
            crate::handlers::__test_set_sched_param(WORKER_TASK, SENTINEL);
            let prio = 0i32;
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
            let mut out = -1i32;
            if call(
                Syscall::SchedGetparam.raw(),
                a1(0, &mut out as *mut i32 as u64),
            ) != Some(0)
            {
                return Err("reading the worker's sched param failed");
            }
            if out == 0 {
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

            // Seed the worker's slot DIRECTLY with a distinguishable value.
            // `sched_setparam` accepts only 0 on a SCHED_OTHER task, so it
            // cannot produce one — and a value of 0 would be
            // indistinguishable from the unset default, leaving this test
            // passing without proving the lookup resolved anything.
            const SEEDED: i32 = 77;
            crate::handlers::__test_set_sched_param(WORKER_TASK, SEEDED);
            set_task(MANAGER_TASK);
            let mut out = 0i32;
            if call(
                Syscall::SchedGetparam.raw(),
                a1(2, &mut out as *mut i32 as u64),
            ) != Some(0)
            {
                return Err("sched_getparam(inner 2) did not succeed");
            }
            if out == SEEDED {
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
            };
            // Reaching the address-space lookup is what proves the pid
            // check let the caller through. That arm used to answer
            // `invalid_op()` and this case read its `None` as the signal;
            // `invalid_op` leaves `value` at 0 though, so the signal was
            // indistinguishable from move_pages reporting success. It is
            // now -ENOMEM, a specific value, which says the same thing
            // without the ambiguity.
            match call(Syscall::MovePages.raw(), args) {
                Some(v) if v == ENOMEM => Ok(()),
                Some(-1) => Err("move_pages rejected the caller's OWN in-namespace pid with EPERM — arg0 compared untranslated against the outer self pid"),
                Some(_) => Err("move_pages returned an unexpected result"),
                None => Err("move_pages did not reach the address-space lookup"),
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

// ── #27 bpf(BPF_TASK_FD_QUERY).pid — Linux kernel/bpf/syscall.c ──
//
// The self-check `if pid != 0 && pid != me` compared the caller-namespace pid
// against the OUTER self pid, so a container querying its own fds with its own
// getpid() was rejected (ENOTSUP). The fix translates the pid first. The worker
// loads an atomic program, attaches it to a tracepoint perf event via
// PERF_EVENT_IOC_SET_BPF, then queries that fd by its OWN inner pid: the fix
// reports the program (0), the bug rejects the inner pid with ENOTSUP.
fn smoke_abi_pidns_bpf_task_fd_query_self_pid_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xB300;
        const MANAGER_PID: u64 = 0xB030;
        const WORKER_TASK: u64 = 0xB301;
        const WORKER_PID: u64 = 0xB031;
        const BPF_PROG_LOAD: u64 = 5;
        const BPF_TASK_FD_QUERY: u64 = 20;
        const BPF_PROG_TYPE_RAW_TRACEPOINT: u32 = 17;
        const PERF_TYPE_TRACEPOINT: u32 = 2;
        const PERF_EVENT_IOC_SET_BPF: u64 = 0x4004_2408;
        const ENOTSUP: i64 = -95;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            set_task(WORKER_TASK);
            // Trivial atomic program: r0 = 0; exit.
            let mut insns = [0u8; 16];
            insns[0] = 0xB7; // BPF_ALU64|BPF_MOV|BPF_K, dst r0, imm 0
            insns[8] = 0x95; // BPF_JMP|BPF_EXIT
            let license = b"GPL\0";
            let mut load_attr = [0u8; 160];
            load_attr[0..4].copy_from_slice(&BPF_PROG_TYPE_RAW_TRACEPOINT.to_le_bytes());
            load_attr[4..8].copy_from_slice(&2u32.to_le_bytes()); // insn_cnt
            load_attr[8..16].copy_from_slice(&(insns.as_ptr() as u64).to_le_bytes());
            load_attr[16..24].copy_from_slice(&(license.as_ptr() as u64).to_le_bytes());
            let prog_fd = match call(
                Syscall::Bpf.raw(),
                a2(BPF_PROG_LOAD, load_attr.as_ptr() as u64, 160),
            ) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("BPF_PROG_LOAD of a trivial atomic program failed"),
            };

            // Tracepoint perf event for self (pid 0, any config != 0).
            let mut pattr = [0u8; 144];
            pattr[0..4].copy_from_slice(&PERF_TYPE_TRACEPOINT.to_le_bytes());
            pattr[4..8].copy_from_slice(&144u32.to_le_bytes()); // size
            pattr[8..16].copy_from_slice(&1u64.to_le_bytes()); // config != 0
            let event_fd = match call(
                Syscall::PerfEventOpen.raw(),
                a3(pattr.as_ptr() as u64, 0, -1i64 as u64, -1i64 as u64),
            ) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("perf_event_open(TRACEPOINT) failed"),
            };
            if call(
                Syscall::Ioctl.raw(),
                a2(event_fd, PERF_EVENT_IOC_SET_BPF, prog_fd),
            ) != Some(0)
            {
                return Err("PERF_EVENT_IOC_SET_BPF failed");
            }

            // Query that fd by the caller's OWN in-namespace pid (2).
            let mut q = [0u8; 48];
            q[0..4].copy_from_slice(&2u32.to_le_bytes()); // task_fd_query.pid
            q[4..8].copy_from_slice(&(event_fd as u32).to_le_bytes()); // .fd
            match call(
                Syscall::Bpf.raw(),
                a2(BPF_TASK_FD_QUERY, q.as_mut_ptr() as u64, 48),
            ) {
                Some(0) => Ok(()),
                Some(v) if v == ENOTSUP => Err("BPF_TASK_FD_QUERY rejected the caller's OWN in-namespace pid with ENOTSUP — the inner pid was compared against the outer self pid without accept_pid_from"),
                _ => Err("BPF_TASK_FD_QUERY returned an unexpected result"),
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
    smoke_abi_pidns_bpf_task_fd_query_self_pid_in_caller_pid_ns
);

// ── #34 setns rejects a pid reinterpreted as an fd — Linux nsproxy.c (fd-only) ─
//
// The removed "legacy TaskId path" resolved setns's arg0 — an fd number — as an
// outer pid when it wasn't a namespace fd, and joined that process's namespaces
// with no ns translation. A caller passing a stray integer equal to a
// namespaced task's outer pid could jump into that task's pid namespace. Linux
// setns(2) takes only an fd. The fix rejects any non-NsFd target. Discriminator:
// setns(<victim outer pid>, CLONE_NEWPID) fails and leaves the caller in its
// own namespace, rather than returning 0 and attaching it to the victim's.
// The errno is `kernel/nsproxy.c`'s -EBADF: the number is an fd, and nothing
// is open on it. (It used to be the bare -1 = EPERM, which a runtime reads as
// "unprivileged" and retries after dropping into a user namespace.)
fn smoke_abi_pidns_setns_rejects_pid_as_fd() -> TestResult {
    with_setup(|| {
        const CALLER_TASK: u64 = 0xED00;
        const CALLER_PID: u64 = 0xED80;
        const VICT_TASK: u64 = 0xED01;
        const VICT_PID: u64 = 0xED81;
        const CLONE_NEWPID: u64 = 0x2000_0000;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(CALLER_TASK, CALLER_PID);
            register(VICT_TASK, VICT_PID);
            // The victim lives in its own pid namespace.
            crate::pid_ns::unshare_pid_ns(VICT_TASK, VICT_PID);

            set_task(CALLER_TASK);
            // target == the victim's OUTER pid, passed where an fd is expected.
            match call(Syscall::Setns.raw(), a1(VICT_PID, CLONE_NEWPID)) {
                Some(v) if v == EBADF => {}
                Some(0) => {
                    return Err("setns joined a namespace by reinterpreting the fd number as a pid — legacy TaskId path not removed")
                }
                _ => return Err("setns(pid-as-fd) must return -EBADF"),
            }
            // The caller must NOT have been attached to the victim's pid ns.
            if crate::pid_ns::ns_of(CALLER_TASK).is_some() {
                return Err(
                    "setns attached the caller to the victim's pid ns despite returning -1",
                );
            }
            Ok(())
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[CALLER_TASK, VICT_TASK]);
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pidns_setns_rejects_pid_as_fd);

// ── #26 tkill/tgkill non-leader raw-tid arm — Linux signal.c find_task_by_vpid ─
//
// A CLONE_THREAD sibling's gettid() is its raw TaskId, so signal_tid_from_user
// accepts a raw non-leader tid directly. The old code did so WITHOUT any
// namespace check, letting a container signal a HOST thread whose raw TaskId it
// happened to name. The fix gates the raw arm on the sibling's thread group
// being visible in the caller's ns. Discriminator: a root-ns process (leader +
// one sibling thread) is invisible to a namespaced manager; the manager's
// tkill of the sibling's raw tid returns ESRCH (fix) rather than delivering
// (bug). A root-ns caller can still reach the sibling (regression guard).
fn smoke_abi_pidns_tkill_non_leader_ns_gated() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xEB00;
        const MANAGER_PID: u64 = 0xEB80;
        const WORKER_TASK: u64 = 0xEB01;
        const WORKER_PID: u64 = 0xEB81;
        const LEADER_TASK: u64 = 0xEC00; // thread-group leader in the ROOT ns
        const GROUP_PID: u64 = 0xEC80;
        const SIBLING_TID: u64 = 0xEC01; // non-leader sibling thread of GROUP_PID
        const SIGTERM: u64 = 15;
        const ESRCH: i64 = -3;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;
            // Root-ns process: leader at GROUP_PID …
            register(LEADER_TASK, GROUP_PID);
            // … plus a sibling thread: task_to_pid_raw(SIBLING_TID) == GROUP_PID,
            // but pid_to_task_raw(GROUP_PID) stays LEADER_TASK (so SIBLING_TID
            // reads as a non-leader). Only the task→pid direction is registered.
            crate::task::release_task(SIBLING_TID);
            let _ = crate::task::Task::new_registered(SIBLING_TID, GROUP_PID);
            crate::handlers::register_task_to_pid(SIBLING_TID, GROUP_PID);

            // Namespaced manager: the sibling's group is invisible in its ns.
            set_task(MANAGER_TASK);
            match call(Syscall::Tkill.raw(), a1(SIBLING_TID, SIGTERM)) {
                Some(v) if v == ESRCH => {}
                Some(0) => {
                    return Err("tkill delivered to a ROOT-ns sibling thread from a namespaced caller — raw non-leader arm not ns-gated")
                }
                _ => return Err("tkill(non-leader sibling) returned an unexpected result"),
            }

            // Regression guard: a root-ns caller still reaches the sibling
            // (null signal existence probe → 0, not ESRCH).
            set_task(FAKE_TASK);
            match call(Syscall::Tkill.raw(), a1(SIBLING_TID, 0)) {
                Some(0) => Ok(()),
                _ => Err("ns gate wrongly rejected a root-ns caller signalling the sibling thread"),
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, WORKER_TASK, LEADER_TASK, SIBLING_TID]);
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pidns_tkill_non_leader_ns_gated);

// ── #30 wait4/waitid(P_PID) unbound inner pid → ECHILD — Linux exit.c do_wait ─
//
// A specific `want_pid` arriving from a namespaced caller was translated
// inner→outer, but on a MISS (an inner pid not bound in the caller's ns) the
// old code kept the RAW inner and let PENDING_EXITS matching proceed. A
// ROOT-namespace child queued at that same OUTER number was then reaped by the
// container. The fix returns ECHILD on the miss instead. Discriminator: stage a
// pending exit for the manager at OUTER pid 3 (a root-ns collision victim) while
// inner 3 is NOT bound in the manager's ns, then wait for inner 3 — the fix
// returns ECHILD, the bug reaps the victim (a non-ECHILD result).
fn smoke_abi_pidns_wait_unbound_inner_echild() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xE900;
        const MANAGER_PID: u64 = 0xE090;
        const WORKER_TASK: u64 = 0xE901;
        const WORKER_PID: u64 = 0xE091;
        const VICTIM_TASK: u64 = 0xEA00; // root-ns child registered at OUTER pid 3
        const VICTIM_PID: u64 = 3;
        const P_PID: u64 = 1;
        const ECHILD: i64 = -10;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            register(VICTIM_TASK, VICTIM_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;
            // The victim has exited and is queued for reaping under the manager.
            crate::handlers::__test_stage_pending_exit(MANAGER_TASK, VICTIM_PID, 0);

            set_task(MANAGER_TASK);
            // wait4(inner 3): inner 3 is unbound in the manager's ns. The bug
            // reaps the victim and returns report_pid_to(manager, 3) == 0 (the
            // outer pid 3 is invisible in the manager's ns); the fix ECHILDs.
            match call(Syscall::Wait4.raw(), a3(3, 0, 0, 0)) {
                Some(v) if v == ECHILD => {}
                Some(0) => {
                    return Err("wait4 reaped a ROOT-ns collision victim for an unbound inner pid — kept the raw inner instead of returning ECHILD")
                }
                _ => return Err("wait4(unbound inner) returned an unexpected result"),
            }

            // waitid(P_PID, inner 3): same miss must be ECHILD before any reap.
            match call(Syscall::Waitid.raw(), a3(P_PID, 3, 0, 4)) {
                Some(v) if v == ECHILD => Ok(()),
                Some(0) => Err("waitid(P_PID, unbound inner) reaped a ROOT-ns collision victim instead of returning ECHILD"),
                _ => Err("waitid(P_PID, unbound inner) returned an unexpected result"),
            }
        })();
        set_task(FAKE_TASK);
        crate::handlers::__test_clear_pending_exits(MANAGER_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, WORKER_TASK, VICTIM_TASK]);
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pidns_wait_unbound_inner_echild);

// ── #13 fork/clone return after CLONE_NEWPID — Linux kernel/fork.c pid_vnr ──
//
// fork(2) returns the child's pid IN THE PARENT's namespace (Linux resolves it
// with `pid_vnr(pid)` in the caller's active ns), which is NOT always the pid
// the child reports for itself. The old handler returned `child_ns_pid` — the
// child's SELF view — directly, so a parent that did `unshare(CLONE_NEWPID)`
// from the root got the child's new-ns pid 1 instead of the child's outer pid;
// its `waitpid` then looked for a child it had no record of (PENDING_EXITS is
// keyed by outer pid) → ECHILD. The fix routes the return through
// `pid_ns::fork_return_to_parent`. This drives the SAME pid-ns primitives
// sys_fork does (the harness cannot reach fork's spawn path — no live AS) and
// pins the contract that function encodes across all three namespace shapes.
fn smoke_abi_pidns_fork_return_resolves_in_parent_pid_ns() -> TestResult {
    with_setup(|| {
        use crate::pid_ns::{fork_return_to_parent, inherit_into_child};
        // Root parent (no namespace at all).
        const P_ROOT_TASK: u64 = 0xB700;
        const P_ROOT_PID: u64 = 0xB070;
        const C_ROOT_TASK: u64 = 0xB701;
        const C_ROOT_PID: u64 = 0xB071;
        // Container parent sharing its child's namespace.
        const P_CT_TASK: u64 = 0xB710;
        const P_CT_PID: u64 = 0xB080;
        const C_CT_TASK: u64 = 0xB711;
        const C_CT_PID: u64 = 0xB081;
        // Root parent that did unshare(CLONE_NEWPID) — child lands in a NEW ns.
        const P_UN_TASK: u64 = 0xB720;
        const P_UN_PID: u64 = 0xB090;
        const C_UN_TASK: u64 = 0xB721;
        const C_UN_PID: u64 = 0xB091;

        crate::pid_ns::__test_reset();
        let result = (|| {
            for &(t, p) in &[
                (P_ROOT_TASK, P_ROOT_PID),
                (C_ROOT_TASK, C_ROOT_PID),
                (P_CT_TASK, P_CT_PID),
                (C_CT_TASK, C_CT_PID),
                (P_UN_TASK, P_UN_PID),
                (C_UN_TASK, C_UN_PID),
            ] {
                register(t, p);
            }

            // 1) Plain root fork: parent in the root ns, child in the root ns.
            // inherit_into_child returns None (no namespace), so sys_fork keeps
            // child_ns_pid == the child's outer pid; the parent must see it too.
            if inherit_into_child(P_ROOT_TASK, C_ROOT_TASK, C_ROOT_PID).is_some() {
                return Err("root parent unexpectedly namespaced its child");
            }
            if fork_return_to_parent(P_ROOT_TASK, C_ROOT_PID, C_ROOT_PID) != C_ROOT_PID {
                return Err("plain root fork did not return the child's outer pid");
            }

            // 2) Ordinary container fork: parent already IN namespace N (inner
            // pid 1); the child shares N (inner pid 2). The parent must see the
            // child's IN-namespace pid, and it must equal the child's getpid().
            crate::pid_ns::unshare_pid_ns(P_CT_TASK, P_CT_PID);
            let child_self = match inherit_into_child(P_CT_TASK, C_CT_TASK, C_CT_PID) {
                Some(2) => 2u64,
                _ => return Err("container child was not bound as inner pid 2 in the shared ns"),
            };
            if fork_return_to_parent(P_CT_TASK, C_CT_PID, child_self) != child_self {
                return Err("container fork return diverged from the child's in-namespace pid — over-translated a shared-namespace fork");
            }

            // 3) unshare(CLONE_NEWPID) from the root: the parent stays in the
            // root ns; the child becomes pid 1 in a NEW child namespace. The
            // parent must see the child's OUTER pid (so its waitpid matches),
            // NOT the child's new-ns pid 1.
            crate::pid_ns::unshare_pid_ns_for_children(P_UN_TASK).unwrap();
            let child_self = match inherit_into_child(P_UN_TASK, C_UN_TASK, C_UN_PID) {
                Some(1) => 1u64,
                _ => return Err("unshared child was not pid 1 in the new namespace"),
            };
            let ret = fork_return_to_parent(P_UN_TASK, C_UN_PID, child_self);
            if ret == child_self {
                return Err("fork returned the child's NEW-ns pid 1 to a root parent — parent waitpid would ECHILD (fork_return_to_parent not applied)");
            }
            if ret != C_UN_PID {
                return Err("fork return after unshare(CLONE_NEWPID) was neither the child's outer pid nor its new-ns pid");
            }
            Ok(())
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[
            P_ROOT_TASK,
            C_ROOT_TASK,
            P_CT_TASK,
            C_CT_TASK,
            P_UN_TASK,
            C_UN_TASK,
        ]);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pidns_fork_return_resolves_in_parent_pid_ns
);

// ── #10 perf_event_open(pid) — Linux kernel/events/core.c find_task_by_vpid ──
//
// The pid target resolution did `pid_to_task_raw(pid)` on the RAW caller-ns pid,
// so `perf record -p <inner>` in a container profiled whatever ROOT-namespace
// task owned the same small number. The fix translates inner → outer via
// accept_pid_from first, and an inner pid NOT bound in the caller's namespace is
// ESRCH (not a silent hit on a collision victim).
//
// Discriminator: a WORKER is inherited at inner 2, but a VICTIM is registered at
// OUTER pid 3 with NO inner-3 binding in the manager's ns. The manager opens a
// software CPU-clock event twice:
//   * pid 2 (the worker's real inner pid)  → resolvable → fd (guards the fix
//     against over-rejecting a legitimately bound inner pid), and
//   * pid 3 (unbound inner; collides with the victim's OUTER pid) → the fix
//     returns ESRCH, the bug returns a live fd targeting the ROOT-ns victim.
fn smoke_abi_pidns_perf_event_open_resolves_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xB500;
        const MANAGER_PID: u64 = 0xB060;
        const WORKER_TASK: u64 = 0xB501;
        const WORKER_PID: u64 = 0xB061;
        const VICTIM_TASK: u64 = 0xB600; // registered at OUTER pid 3
        const VICTIM_PID: u64 = 3;
        const ESRCH: i64 = -3;

        // Software CPU-clock event: type_=PERF_TYPE_SOFTWARE(1), size=144,
        // config=PERF_COUNT_SW_CPU_CLOCK(0). cpu=-1 follows the task.
        let mut pattr = [0u8; 144];
        pattr[0..4].copy_from_slice(&1u32.to_le_bytes());
        pattr[4..8].copy_from_slice(&144u32.to_le_bytes());

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            register(VICTIM_TASK, VICTIM_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            set_task(MANAGER_TASK);
            // Resolvable inner pid 2 → the worker: must still be admitted.
            match call(
                Syscall::PerfEventOpen.raw(),
                a3(pattr.as_ptr() as u64, 2, -1i64 as u64, -1i64 as u64),
            ) {
                Some(fd) if fd >= 0 => {
                    let _ = call(Syscall::Close.raw(), a1(fd as u64, 0));
                }
                Some(v) if v == ESRCH => {
                    return Err("perf_event_open rejected the worker's resolvable inner pid 2 with ESRCH — accept_pid_from → pid_to_task_raw over-rejects a bound inner pid")
                }
                _ => return Err("perf_event_open(inner 2) returned an unexpected result"),
            }

            // Unbound inner pid 3 that collides with the victim's OUTER pid.
            match call(
                Syscall::PerfEventOpen.raw(),
                a3(pattr.as_ptr() as u64, 3, -1i64 as u64, -1i64 as u64),
            ) {
                Some(v) if v == ESRCH => Ok(()),
                Some(fd) if fd >= 0 => {
                    let _ = call(Syscall::Close.raw(), a1(fd as u64, 0));
                    Err("perf_event_open targeted a ROOT-namespace collision victim for an inner pid unbound in the caller's ns — raw pid_to_task_raw instead of accept_pid_from")
                }
                _ => Err("perf_event_open(unbound inner 3) returned an unexpected result"),
            }
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        release_all(&[MANAGER_TASK, WORKER_TASK, VICTIM_TASK]);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pidns_perf_event_open_resolves_in_caller_pid_ns
);

// ── #28 setpriority(PRIO_PROCESS, who) — Linux kernel/sys.c:282 ──
//
// The `who` argument was DISCARDED, so setpriority always renamed the caller
// (renice -p N reniced the caller). The fix resolves `who` via accept_pid_from.
// The manager renices the worker by inner pid 2; the worker then reads its OWN
// nice: the fix routed the change to the worker (5 → getpriority 25), the
// discard left the worker at the default (0 → 20).
fn smoke_abi_pidns_setpriority_resolves_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xB400;
        const MANAGER_PID: u64 = 0xB040;
        const WORKER_TASK: u64 = 0xB401;
        const WORKER_PID: u64 = 0xB041;
        const PRIO_PROCESS: u64 = 0;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            set_task(MANAGER_TASK);
            if call(Syscall::Setpriority.raw(), a2(PRIO_PROCESS, 2, 5)) != Some(0) {
                return Err("setpriority(PRIO_PROCESS, inner 2, 5) did not succeed");
            }
            // Worker reads its own nice (self arm, who == 0). nice 5 →
            // getpriority 20 - 5 == 15; the caller's default nice 0 → 20.
            set_task(WORKER_TASK);
            match call(Syscall::Getpriority.raw(), a1(PRIO_PROCESS, 0)) {
                Some(15) => Ok(()),
                Some(20) => Err("setpriority ignored `who` and reniced the caller, not the worker — accept_pid_from resolution missing"),
                _ => Err("getpriority returned an unexpected value for the worker"),
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
    smoke_abi_pidns_setpriority_resolves_in_caller_pid_ns
);

// ── #28 getpriority(PRIO_PROCESS, who) — Linux kernel/sys.c:282 ──
//
// Same discarded `who` on the read side. Seed the worker's own nice (7), then
// have the manager read it by inner pid 2: the fix resolves to the worker
// (getpriority 20 - 7 == 13), the discard reads the caller's own nice
// (default 0 → 20).
fn smoke_abi_pidns_getpriority_resolves_in_caller_pid_ns() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xB410;
        const MANAGER_PID: u64 = 0xB050;
        const WORKER_TASK: u64 = 0xB411;
        const WORKER_PID: u64 = 0xB051;
        const PRIO_PROCESS: u64 = 0;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register(MANAGER_TASK, MANAGER_PID);
            register(WORKER_TASK, WORKER_PID);
            build_manager_worker(MANAGER_TASK, MANAGER_PID, WORKER_TASK, WORKER_PID)?;

            set_task(WORKER_TASK);
            if call(Syscall::Setpriority.raw(), a2(PRIO_PROCESS, 0, 7)) != Some(0) {
                return Err("seeding the worker's nice failed");
            }
            set_task(MANAGER_TASK);
            match call(Syscall::Getpriority.raw(), a1(PRIO_PROCESS, 2)) {
                Some(13) => Ok(()),
                Some(20) => Err("getpriority ignored `who` and read the caller's own nice, not the worker's — accept_pid_from resolution missing"),
                _ => Err("getpriority returned an unexpected value"),
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
    smoke_abi_pidns_getpriority_resolves_in_caller_pid_ns
);

// ── the namespace tree ────────────────────────────────────────────────
//
// Linux 6.17's `kernel/nstree.c` registers every namespace, of every
// flavour, in one structure keyed by id — so a namespace can be found or
// enumerated WITHOUT holding a task that happens to be in it. Before it, the
// only way to reach a namespace was through something already using it,
// which meant there was no way to ask what namespaces exist at all.

/// A namespace appears in the tree when created and is gone when dropped.
///
/// The drop half is the one that matters: an entry outliving its namespace
/// would answer a lookup with an id nothing can be reached through, and
/// since ids are never reused, it would accumulate forever.
fn smoke_abi_nstree_tracks_lifetime() -> TestResult {
    use crate::namespaces::{ns_tree_lookup, ns_type, UtsNamespace};
    with_setup(|| {
        let before = crate::namespaces::ns_tree_len();
        let id = {
            let ns = UtsNamespace::new_default();
            let id = ns.id();
            let entry = ns_tree_lookup(id).ok_or("a fresh namespace should be in the tree")?;
            if entry.ns_type != ns_type::UTS {
                return Err("the tree recorded the wrong flavour");
            }
            if entry.id != id {
                return Err("the tree recorded the wrong id");
            }
            if crate::namespaces::ns_tree_len() != before + 1 {
                return Err("creating a namespace did not grow the tree by one");
            }
            id
        };
        // The Arc is gone, so the entry must be too.
        if ns_tree_lookup(id).is_some() {
            return Err("a dropped namespace is still in the tree");
        }
        if crate::namespaces::ns_tree_len() != before {
            return Err("dropping a namespace did not shrink the tree");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nstree_tracks_lifetime);

/// Every flavour lands in ONE tree.
///
/// That is the whole point of a unified tree rather than a per-type list:
/// ids are drawn from a single counter, so a lookup needs no type argument,
/// and `listns` with no filter must see all of them.
fn smoke_abi_nstree_spans_every_flavour() -> TestResult {
    use crate::namespaces::{ns_tree_lookup, ns_type, IpcNamespace, NetNamespace, UtsNamespace};
    with_setup(|| {
        let uts = UtsNamespace::new_default();
        let net = NetNamespace::new_with_loopback();
        let ipc = IpcNamespace::new();
        let pid = crate::pid_ns::PidNamespace::new();
        for (id, want, what) in [
            (uts.id(), ns_type::UTS, "uts"),
            (net.id(), ns_type::NET, "net"),
            (ipc.id(), ns_type::IPC, "ipc"),
            (pid.id(), ns_type::PID, "pid"),
        ] {
            let entry = ns_tree_lookup(id).ok_or("a flavour is missing from the tree")?;
            if entry.ns_type != want {
                let _ = what;
                return Err("a flavour was recorded with the wrong type bit");
            }
        }
        // Ids come from one counter, so no two flavours can collide.
        let ids = [uts.id(), net.id(), ipc.id(), pid.id()];
        for (i, a) in ids.iter().enumerate() {
            if ids[i + 1..].contains(a) {
                return Err("two namespaces of different flavours share an id");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nstree_spans_every_flavour);

/// Enumeration is ordered and resumes from a cursor.
///
/// The cursor is what `listns(2)` needs: a caller with more namespaces than
/// buffer resumes instead of restarting, which is what makes the call safe
/// against a tree that is changing underneath it. Paging one at a time must
/// reach exactly the same set as one call.
fn smoke_abi_nstree_enumeration_pages() -> TestResult {
    use crate::namespaces::{ns_tree_list, ns_type, UtsNamespace};
    with_setup(|| {
        crate::namespaces::__test_ns_tree_reset();
        let a = UtsNamespace::new_default();
        let b = UtsNamespace::new_default();
        let c = UtsNamespace::new_default();
        let all = ns_tree_list(0, 0, None, 64);
        if all.len() != 3 {
            return Err("the tree did not list every namespace");
        }
        // Ascending id order — the counter is monotonic, so creation order.
        if all != [a.id(), b.id(), c.id()] {
            return Err("enumeration is not in id order");
        }
        // Page one at a time, carrying the cursor.
        let mut paged = alloc::vec::Vec::new();
        let mut cursor = 0u64;
        loop {
            let one = ns_tree_list(cursor, 0, None, 1);
            match one.first() {
                Some(&id) => {
                    paged.push(id);
                    cursor = id;
                }
                None => break,
            }
            if paged.len() > 3 {
                return Err("the cursor did not advance — paging would not terminate");
            }
        }
        if paged != all {
            return Err("paging with the cursor reached a different set than one call");
        }
        // A type filter selects, and a flavour with no instances is empty
        // rather than an error.
        if ns_tree_list(0, ns_type::UTS, None, 64).len() != 3 {
            return Err("the UTS filter did not select the UTS namespaces");
        }
        if !ns_tree_list(0, ns_type::NET, None, 64).is_empty() {
            return Err("the NET filter selected namespaces of another flavour");
        }
        crate::namespaces::__test_ns_tree_reset();
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nstree_enumeration_pages);

/// The owning user namespace is recorded, and filters on it.
///
/// `listns`'s `user_ns_id` selects the namespaces one user namespace owns,
/// which is how a container runtime asks "what did this sandbox create".
fn smoke_abi_nstree_owner_filter() -> TestResult {
    use crate::namespaces::{ns_tree_list, ns_tree_lookup, IpcNamespace, UserNamespace};
    with_setup(|| {
        crate::namespaces::__test_ns_tree_reset();
        let parent = UserNamespace::new_initial();
        let child = UserNamespace::new_child(parent.clone(), 0);
        // An IPC namespace owned by the child user namespace.
        let owned = IpcNamespace::new_in(Some(child.clone()));
        let entry = ns_tree_lookup(owned.id()).ok_or("the owned namespace is missing")?;
        if entry.owner_user_ns != child.id() {
            return Err("the tree recorded the wrong owning user namespace");
        }
        // One owned by nobody in particular — the initial user namespace.
        let unowned = IpcNamespace::new();
        let unowned_entry =
            ns_tree_lookup(unowned.id()).ok_or("the unowned namespace is missing")?;
        if unowned_entry.owner_user_ns != 0 {
            return Err("a namespace with no explicit owner should record 0");
        }
        // The filter selects only what the child owns.
        let mine = ns_tree_list(0, 0, Some(child.id()), 64);
        if mine != [owned.id()] {
            return Err("the owner filter did not select exactly the owned namespace");
        }
        // And the child user namespace itself is owned by its PARENT, which
        // is what makes the ownership chain walkable.
        let child_entry = ns_tree_lookup(child.id()).ok_or("the child user ns is missing")?;
        if child_entry.owner_user_ns != parent.id() {
            return Err("a user namespace should be owned by its parent");
        }
        crate::namespaces::__test_ns_tree_reset();
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nstree_owner_filter);

/// The two flavours that live BELOW this crate reach the same tree.
///
/// `MountNamespace` and `CgroupNamespace` are in `narf-filesystem`, which
/// sits under userspace and cannot call up — they register through a hook
/// installed at init. A tree missing them would report a partial system,
/// and nothing else would notice, because every other flavour is right.
fn smoke_abi_nstree_includes_cross_crate_flavours() -> TestResult {
    use crate::namespaces::{ns_tree_lookup, ns_type};
    with_setup(|| {
        let mnt = narf_filesystem::MountNamespace::snapshot_global_owned_by(None);
        let entry = ns_tree_lookup(mnt.id())
            .ok_or("a mount namespace minted below this crate is missing from the tree")?;
        if entry.ns_type != ns_type::MNT {
            return Err("the mount namespace was recorded with the wrong type bit");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_nstree_includes_cross_crate_flavours
);

// ── listns(2) ─────────────────────────────────────────────────────────

/// `struct ns_id_req { u32 size, spare; u64 ns_id; u32 ns_type, spare2; u64 user_ns_id; }`.
fn ns_id_req(size: u32, cursor: u64, ns_type: u32, user_ns_id: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&size.to_ne_bytes());
    b[8..16].copy_from_slice(&cursor.to_ne_bytes());
    b[16..20].copy_from_slice(&ns_type.to_ne_bytes());
    b[24..32].copy_from_slice(&user_ns_id.to_ne_bytes());
    b
}

/// `listns` enumerates the tree, filters by type, and pages with a cursor.
///
/// Paging is the load-bearing part: `req.ns_id` is the last id already seen,
/// so a caller with more namespaces than buffer resumes instead of
/// restarting. One id at a time must reach the same set as one call.
fn smoke_abi_listns_enumerates_and_pages() -> TestResult {
    use crate::namespaces::{ns_type, UtsNamespace};
    with_setup(|| {
        crate::namespaces::__test_ns_tree_reset();
        let a = UtsNamespace::new_default();
        let b = UtsNamespace::new_default();
        let c = UtsNamespace::new_default();
        let mut out = [0u64; 16];
        let list = |cursor: u64, ty: u32, nr: u64, out: &mut [u64; 16]| {
            let req = ns_id_req(32, cursor, ty, 0);
            call(
                Syscall::Listns.raw(),
                a3(req.as_ptr() as u64, out.as_mut_ptr() as u64, nr, 0),
            )
        };
        let n = match list(0, 0, 16, &mut out) {
            Some(n) if n >= 3 => n as usize,
            _ => return Err("listns should enumerate the namespaces in the tree"),
        };
        let all = out[..n].to_vec();
        for id in [a.id(), b.id(), c.id()] {
            if !all.contains(&id) {
                return Err("listns omitted a namespace that is in the tree");
            }
        }
        // Ascending id order — what makes the cursor work at all.
        if all.windows(2).any(|w| w[0] >= w[1]) {
            return Err("listns did not return ids in ascending order");
        }
        // Page one at a time. Bounded by a generous constant rather than by
        // `n`, so a cursor that fails to advance is caught as a runaway
        // rather than by an equality that a one-off tree growth would break.
        let mut paged = alloc::vec::Vec::new();
        let mut cursor = 0u64;
        loop {
            let mut one = [0u64; 16];
            match list(cursor, 0, 1, &mut one) {
                Some(1) => {
                    if one[0] <= cursor {
                        return Err("the cursor did not advance — paging would not terminate");
                    }
                    paged.push(one[0]);
                    cursor = one[0];
                }
                // A cursor with nothing after it is -ENOENT, not an empty
                // success: that is how a paging caller learns it is done.
                Some(-2) => break,
                Some(0) => return Err("listns ended with 0 rather than -ENOENT"),
                _ => return Err("paging with a cursor should keep returning ids"),
            }
            if paged.len() > 256 {
                return Err("paging did not terminate");
            }
        }
        if paged != all {
            return Err("paging with the cursor reached a different set than one call");
        }
        // Listing must not CREATE a namespace. It used to: the first
        // `capable()` inside the handler materialised the lazily-built
        // initial user namespace, which then joined the tree, so the first
        // call grew it by one. The initial namespaces are registered at boot
        // now — as Linux registers `init_user_ns` and friends — and this is
        // the assertion that keeps it that way.
        let before = crate::namespaces::ns_tree_len();
        let _ = list(0, 0, 16, &mut out);
        if crate::namespaces::ns_tree_len() != before {
            return Err("listns created a namespace while enumerating");
        }
        // A type filter selects.
        let mut uts_out = [0u64; 16];
        let uts_n = match list(0, ns_type::UTS, 16, &mut uts_out) {
            Some(n) if n >= 3 => n as usize,
            _ => return Err("the UTS filter should select the UTS namespaces"),
        };
        if uts_out[..uts_n].iter().any(|id| !all.contains(id)) {
            return Err("the type filter returned something outside the tree");
        }
        crate::namespaces::__test_ns_tree_reset();
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_listns_enumerates_and_pages);

/// `listns`'s argument rules.
///
/// The one that is easy to get wrong is the type filter: a bit outside
/// `NS_ALL` is -EOPNOTSUPP and NOT -EINVAL, and not an empty result either.
/// "No such namespace type" and "no namespaces of that type" are different
/// answers, and a caller probing for a flavour this kernel does not know
/// needs to tell them apart.
fn smoke_abi_listns_argument_rules() -> TestResult {
    use crate::namespaces::ns_type;
    with_setup(|| {
        const E2BIG: i64 = -7;
        const EOPNOTSUPP: i64 = -95;
        const EOVERFLOW: i64 = -75;
        let mut out = [0u64; 8];
        let mut call_with = |req: &[u8], nr: u64, flags: u64| {
            call(
                Syscall::Listns.raw(),
                a3(req.as_ptr() as u64, out.as_mut_ptr() as u64, nr, flags),
            )
        };
        // An unknown flag.
        let ok = ns_id_req(32, 0, 0, 0);
        if call_with(&ok, 8, 1) != Some(EINVAL) {
            return Err("an unknown listns flag must be -EINVAL");
        }
        // Past the one-million cap.
        if call_with(&ok, 1_000_001, 0) != Some(EOVERFLOW) {
            return Err("nr_ns_ids above the cap must be -EOVERFLOW");
        }
        // Below VER0, and past PAGE_SIZE — E2BIG decided first.
        let small = ns_id_req(31, 0, 0, 0);
        if call_with(&small, 8, 0) != Some(EINVAL) {
            return Err("a size below NS_ID_REQ_SIZE_VER0 must be -EINVAL");
        }
        let huge = ns_id_req(4097, 0, 0, 0);
        if call_with(&huge, 8, 0) != Some(E2BIG) {
            return Err("a size above PAGE_SIZE must be -E2BIG");
        }
        // A reserved field the caller set.
        let mut spare = ns_id_req(32, 0, 0, 0);
        spare[4..8].copy_from_slice(&1u32.to_ne_bytes());
        if call_with(&spare, 8, 0) != Some(EINVAL) {
            return Err("a nonzero spare must be -EINVAL");
        }
        // A type bit outside NS_ALL.
        let bad_type = ns_id_req(32, 0, 1 << 3, 0);
        if call_with(&bad_type, 8, 0) != Some(EOPNOTSUPP) {
            return Err("a type outside NS_ALL must be -EOPNOTSUPP, not -EINVAL");
        }
        // A type bit INSIDE NS_ALL with no instances is an empty success,
        // not an error — the other half of that distinction.
        crate::namespaces::__test_ns_tree_reset();
        let time_ns = ns_id_req(32, 0, ns_type::TIME, 0);
        if call_with(&time_ns, 8, 0) != Some(0) {
            return Err("a known type with no instances must be an empty success");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_listns_argument_rules);

/// The `user_ns_id` filter, including `LISTNS_CURRENT_USER`.
///
/// This is how a container runtime asks "what did this sandbox create".
fn smoke_abi_listns_owner_filter() -> TestResult {
    use crate::namespaces::{IpcNamespace, UserNamespace};
    const LISTNS_CURRENT_USER: u64 = u64::MAX;
    with_setup(|| {
        crate::namespaces::__test_ns_tree_reset();
        let parent = UserNamespace::new_initial();
        let child = UserNamespace::new_child(parent.clone(), 0);
        let owned = IpcNamespace::new_in(Some(child.clone()));
        let _other = IpcNamespace::new();

        let mut out = [0u64; 16];
        let req = ns_id_req(32, 0, 0, child.id());
        let n = match call(
            Syscall::Listns.raw(),
            a3(req.as_ptr() as u64, out.as_mut_ptr() as u64, 16, 0),
        ) {
            Some(n) if n >= 0 => n as usize,
            _ => return Err("listns with an owner filter should succeed"),
        };
        if out[..n] != [owned.id()] {
            return Err("the owner filter did not select exactly the owned namespace");
        }
        // An owner id that names nothing is -EINVAL, NOT an empty result.
        // `do_listns_userns` resolves the id to a user namespace first:
        // `if (!ns) return -EINVAL;`. The two answers mean different things
        // — "the user namespace you asked about is gone" versus "it exists
        // and owns nothing" — and a supervisor polling a sandbox it created
        // needs to tell them apart.
        let gone = ns_id_req(32, 0, 0, 0x7FFF_FFFF_FFFF);
        if call(
            Syscall::Listns.raw(),
            a3(gone.as_ptr() as u64, out.as_mut_ptr() as u64, 16, 0),
        ) != Some(EINVAL)
        {
            return Err("an owner id that names no namespace must be -EINVAL");
        }
        // And an id that names a namespace of the WRONG flavour: the lookup
        // is `lookup_ns_id(id, CLONE_NEWUSER)`, so an IPC id is not a valid
        // owner either.
        let wrong = ns_id_req(32, 0, 0, owned.id());
        if call(
            Syscall::Listns.raw(),
            a3(wrong.as_ptr() as u64, out.as_mut_ptr() as u64, 16, 0),
        ) != Some(EINVAL)
        {
            return Err("an owner id naming a non-user namespace must be -EINVAL");
        }
        // LISTNS_CURRENT_USER resolves to the caller's own user namespace,
        // so it must not be treated as the literal id u64::MAX.
        let cur = ns_id_req(32, 0, 0, LISTNS_CURRENT_USER);
        match call(
            Syscall::Listns.raw(),
            a3(cur.as_ptr() as u64, out.as_mut_ptr() as u64, 16, 0),
        ) {
            Some(n) if n >= 0 => {}
            _ => return Err("LISTNS_CURRENT_USER should resolve, not be used literally"),
        }
        crate::namespaces::__test_ns_tree_reset();
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_listns_owner_filter);

// ── Reserved initial-namespace ids ───────────────────────────────
//
// `enum init_ns_id` (`include/uapi/linux/nsfs.h:71`) fixes the id of each
// flavour's INITIAL namespace, and `is_ns_init_id()` is spelled
// `ns->ns_id <= NS_LAST_INIT_ID` — so the values must be exactly those and
// exactly contiguous. See `userspace/specification/namespace-tree.md` R2.

/// The initial namespace of every flavour carries its reserved UAPI id.
///
/// These were previously drawn from the shared counter, which made an
/// initial namespace's id depend on boot ordering and match the UAPI
/// constants only by coincidence. The negative half is what makes this a
/// real check: a *non*-initial namespace must never land in the reserved
/// block, or `is_ns_init_id` would call it initial and the refcount rules
/// that hang off that predicate would apply to the wrong object.
fn smoke_abi_ns_initial_ids_are_reserved() -> TestResult {
    use crate::namespaces::{init_ns_id, is_init_ns_id, ns_tree_lookup, ns_type};
    with_setup(|| {
        crate::namespaces::init_namespaces();
        for (id, want, what) in [
            (init_ns_id::IPC, ns_type::IPC, "ipc"),
            (init_ns_id::UTS, ns_type::UTS, "uts"),
            (init_ns_id::USER, ns_type::USER, "user"),
            (init_ns_id::PID, ns_type::PID, "pid"),
            (init_ns_id::NET, ns_type::NET, "net"),
            (init_ns_id::MNT, ns_type::MNT, "mnt"),
        ] {
            let entry = ns_tree_lookup(id)
                .ok_or("an initial namespace is missing from the tree at its reserved id")?;
            if entry.ns_type != want {
                let _ = what;
                return Err("a reserved id is held by the wrong flavour");
            }
            if !is_init_ns_id(id) {
                return Err("a reserved id did not read as an initial-namespace id");
            }
        }
        // The UAPI block is 1..=8 and NOTHING else may fall in it.
        if is_init_ns_id(0) || is_init_ns_id(init_ns_id::LAST + 1) {
            return Err("the reserved id range does not match NS_LAST_INIT_ID");
        }
        // Negative control: a freshly minted namespace must land ABOVE the
        // block. Without the counter starting at NS_LAST_INIT_ID + 1 this is
        // the assertion that fails.
        let fresh = crate::namespaces::UtsNamespace::new_default();
        if is_init_ns_id(fresh.id()) {
            return Err("a newly created namespace was minted inside the reserved id block");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ns_initial_ids_are_reserved);

/// `narf-filesystem` spells the reserved MNT id itself, because the
/// reserved block lives in the crate ABOVE it. The two must agree.
///
/// Without this, a rename or a renumber on one side would silently give the
/// initial mount namespace two different identities depending on which
/// crate you asked.
fn smoke_abi_ns_init_ids_agree_across_crates() -> TestResult {
    if narf_filesystem::NS_INIT_ID_MNT != crate::namespaces::init_ns_id::MNT {
        return TestResult::Fail("narf-filesystem's NS_INIT_ID_MNT disagrees with init_ns_id::MNT");
    }
    TestResult::Pass
}
kernel_test_in!("syscall_abi", smoke_abi_ns_init_ids_agree_across_crates);

/// The initial mount namespace IS the global registry, not a snapshot.
///
/// A snapshot would fork the table at boot: a later `mount(2)` through the
/// registry would be invisible through the namespace object, and the two
/// would drift apart with nothing reporting it. A private namespace must
/// still diverge — that is the negative control, and it is what says this
/// test is measuring sharing rather than measuring nothing.
fn smoke_abi_initial_mount_ns_shares_the_registry() -> TestResult {
    with_setup(|| {
        let init = narf_filesystem::initial_mount_ns();
        let private = narf_filesystem::MountNamespace::snapshot_global();
        let before_init = init.list().len();
        let before_private = private.list().len();

        // Mount through the REGISTRY, not through either namespace object —
        // that is the path the initial namespace has to observe.
        let auth = narf_filesystem::bootstrap_mount_authority();
        let fs: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
            alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("nstree-probe"));
        let handle = match narf_filesystem::registry().mount_arc(&auth, "/abi-nstree-probe", fs) {
            Ok(h) => h,
            Err(_) => return Err("could not mount the probe filesystem in the registry"),
        };

        let grew_init = init.list().len() > before_init;
        let grew_private = private.list().len() > before_private;
        let _ = narf_filesystem::registry().unmount(&handle, "/abi-nstree-probe");

        if !grew_init {
            return Err("a mount through the registry was invisible to the initial namespace");
        }
        if grew_private {
            return Err("a mount through the registry leaked into a private namespace");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_initial_mount_ns_shares_the_registry
);

/// Namespace churn retires trees, and every retired tree is reclaimed.
///
/// Each add and remove publishes a fresh map and retires the previous one,
/// so a few hundred namespaces retire a few hundred trees — well past the
/// 64-entry ceiling the collector's per-CPU queue used to have, when an
/// over-capacity enqueue was silently discarded. The leak itself is fixed
/// in `narf-rcu` and pinned there by
/// `smoke_rcu_retire_far_past_old_bucket_cap_reclaims_all`; this asserts
/// the tree is a well-behaved consumer of the fixed collector — the queue
/// drains to empty, and the tree is still correct after churning through it.
fn smoke_abi_nstree_churn_reclaims_retired_trees() -> TestResult {
    use crate::namespaces::UtsNamespace;
    with_setup(|| {
        const N: usize = 256;
        narf_rcu::report_quiescent();
        for _ in 0..N {
            let ns = UtsNamespace::new_default();
            if crate::namespaces::ns_tree_lookup(ns.id()).is_none() {
                return Err("a namespace created during churn was not in the tree");
            }
        }
        // Every one of those maps must be reclaimABLE, not discarded.
        if narf_rcu::qsbr::overflow_count_this_cpu() != 0 {
            return Err("the collector discarded a retired tree");
        }
        narf_rcu::sync();
        if narf_rcu::qsbr::deferred_len_this_cpu() != 0 {
            return Err("retired trees were still queued after a grace period");
        }
        // And the tree itself survived the churn: those namespaces are gone
        // (each `Arc` dropped at its iteration's end), so what remains must
        // still be a whole map and not a half-published intermediate.
        crate::namespaces::init_namespaces();
        if crate::namespaces::ns_tree_lookup(crate::namespaces::init_ns_id::USER).is_none() {
            return Err("the tree lost an initial namespace across the churn");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nstree_churn_reclaims_retired_trees);

/// A reader holding a tree snapshot survives a concurrent removal.
///
/// This is the property the copy-on-write cell exists for: `ns_tree_entries_from`
/// hands back owned entries taken under a pin, and a namespace dropped
/// afterwards cannot invalidate them. Under the old spinlock the same
/// sequence was safe only because no caller held a borrow across a drop —
/// a rule maintained by hand at every call site.
fn smoke_abi_nstree_snapshot_survives_removal() -> TestResult {
    use crate::namespaces::UtsNamespace;
    with_setup(|| {
        let ns = UtsNamespace::new_default();
        let id = ns.id();
        let snapshot = crate::namespaces::ns_tree_entries_from(0, 0, None);
        if !snapshot.iter().any(|e| e.id == id) {
            return Err("the snapshot did not contain the namespace that was live when taken");
        }
        drop(ns);
        // The snapshot is owned, so it still names the id; the TREE must not.
        if !snapshot.iter().any(|e| e.id == id) {
            return Err("a snapshot taken before the drop lost its entry");
        }
        if crate::namespaces::ns_tree_lookup(id).is_some() {
            return Err("a dropped namespace is still reachable through the tree");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nstree_snapshot_survives_removal);

/// The cursor's end-of-list answer comes from the SELECTED tree.
///
/// `do_listns` decides it with `lookup_ns_id_at(last + 1, ns_type)`, where
/// `ns_type` is non-zero only when the caller named EXACTLY ONE type bit
/// (`hweight32(kls->ns_type) == 1`). The two halves pull in opposite
/// directions, which is why both are pinned:
///
/// - One type bit walks that flavour's tree, so running out of THAT flavour
///   is genuinely the end of the list — `-ENOENT` — even with higher-id
///   namespaces of other flavours present.
/// - Zero bits, or two or more, walk the unified tree, so the same
///   situation is an empty success. That half is
///   `smoke_abi_listns_multi_bit_filter_uses_the_unified_tree`.
///
/// An implementation that always consulted the unified tree gets the first
/// wrong and a paging loop never terminates; one that always applied the
/// caller's full mask gets the second wrong and a supervisor reads the tree
/// as exhausted while it is not.
fn smoke_abi_listns_cursor_enoent_uses_the_selected_tree() -> TestResult {
    use crate::namespaces::{ns_type, IpcNamespace, UtsNamespace};
    with_setup(|| {
        crate::namespaces::__test_ns_tree_reset();
        // One UTS, then an IPC with a HIGHER id. Ids come from one counter,
        // so creation order is id order.
        let uts = UtsNamespace::new_default();
        let ipc = IpcNamespace::new();
        if ipc.id() <= uts.id() {
            return Err("the fixture needs the IPC namespace to sort after the UTS one");
        }
        let mut out = [0u64; 8];
        let list = |cursor: u64, ty: u32, out: &mut [u64; 8]| {
            let req = ns_id_req(32, cursor, ty, 0);
            call(
                Syscall::Listns.raw(),
                a3(req.as_ptr() as u64, out.as_mut_ptr() as u64, 8, 0),
            )
        };
        // Single-bit: the UTS tree is exhausted, so end-of-list. The IPC
        // namespace above the cursor lives in a different tree and does not
        // count.
        if list(uts.id(), ns_type::UTS, &mut out) != Some(-2) {
            return Err("a single-type cursor past its flavour's last namespace must be -ENOENT");
        }
        // Unfiltered, past every id: also end-of-list. This is what keeps
        // the rule from degenerating into "a type filter always means
        // ENOENT".
        if list(ipc.id(), 0, &mut out) != Some(-2) {
            return Err("an unfiltered cursor past every namespace must be -ENOENT");
        }
        // Unfiltered, with the IPC namespace still above the cursor: not the
        // end, so it enumerates rather than erroring.
        if list(uts.id(), 0, &mut out) != Some(1) {
            return Err("an unfiltered cursor with more namespaces above it must not be -ENOENT");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_listns_cursor_enoent_uses_the_selected_tree
);

/// A multi-bit type filter selects the UNIFIED tree, not a per-type one.
///
/// `hweight32(kls->ns_type) == 1` is the test, so two bits fall through to
/// `ns_type = 0`. The mask still filters per element via `ns_requested`, so
/// the RESULT set is unchanged — what changes is the cursor lookup, which
/// then consults the unified tree and applies no type constraint at all.
fn smoke_abi_listns_multi_bit_filter_uses_the_unified_tree() -> TestResult {
    use crate::namespaces::{ns_type, IpcNamespace, NetNamespace, UtsNamespace};
    with_setup(|| {
        crate::namespaces::__test_ns_tree_reset();
        let uts = UtsNamespace::new_default();
        let ipc = IpcNamespace::new();
        let net = NetNamespace::new_with_loopback();
        let mut out = [0u64; 8];
        let list = |cursor: u64, ty: u32, out: &mut [u64; 8]| {
            let req = ns_id_req(32, cursor, ty, 0);
            call(
                Syscall::Listns.raw(),
                a3(req.as_ptr() as u64, out.as_mut_ptr() as u64, 8, 0),
            )
        };
        // Two bits: both flavours come back, neither is dropped.
        let both = ns_type::UTS | ns_type::IPC;
        let n = match list(0, both, &mut out) {
            Some(n) if n >= 2 => n as usize,
            _ => return Err("a two-bit filter should enumerate both flavours"),
        };
        let got = out[..n].to_vec();
        if !got.contains(&uts.id()) || !got.contains(&ipc.id()) {
            return Err("a two-bit filter omitted one of the flavours it named");
        }
        if got.contains(&net.id()) {
            return Err("a two-bit filter returned a flavour it did not name");
        }
        // Cursor past the last MATCH of the two-bit filter, with the net
        // namespace still above it: the unified tree has more, so 0.
        let last_match = core::cmp::max(uts.id(), ipc.id());
        if last_match < net.id() && list(last_match, both, &mut out) != Some(0) {
            return Err("a multi-bit cursor consulted a per-type tree instead of the unified one");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_listns_multi_bit_filter_uses_the_unified_tree
);

/// Ordered next/previous traversal over one flavour.
///
/// `__ns_tree_adjoined_rcu` walks the per-type list forward or backward and
/// reports `-ENOENT` at either end. It is what `NS_MNT_GET_NEXT`/`PREV` ride
/// on, and the property that makes it usable is that stepping forward then
/// back returns where you started — a traversal that skipped or repeated
/// would silently give an enumerating caller the wrong set.
fn smoke_abi_nstree_adjoined_walks_one_flavour() -> TestResult {
    use crate::namespaces::{ns_tree_adjoined, ns_type, IpcNamespace, UtsNamespace};
    with_setup(|| {
        crate::namespaces::__test_ns_tree_reset();
        let a = UtsNamespace::new_default();
        // An IPC namespace BETWEEN the two UTS ones: traversal must step
        // over it, which is what says the flavour constraint is real.
        let mid = IpcNamespace::new();
        let b = UtsNamespace::new_default();

        let next = ns_tree_adjoined(a.id(), ns_type::UTS, false)
            .ok_or("next from the first UTS namespace should find the second")?;
        if next.id != b.id() {
            return Err("traversal did not step over a namespace of another flavour");
        }
        let prev = ns_tree_adjoined(b.id(), ns_type::UTS, true)
            .ok_or("previous from the second UTS namespace should find the first")?;
        if prev.id != a.id() {
            return Err("stepping forward then back did not return to the start");
        }
        // Both ends report nothing rather than wrapping.
        if ns_tree_adjoined(b.id(), ns_type::UTS, false).is_some() {
            return Err("traversal past the last namespace of a flavour should find nothing");
        }
        if ns_tree_adjoined(a.id(), ns_type::UTS, true).is_some() {
            return Err("traversal before the first namespace of a flavour should find nothing");
        }
        // Unfiltered, the in-between namespace IS the next one — the
        // negative control for the flavour filter above.
        let any = ns_tree_adjoined(a.id(), 0, false)
            .ok_or("unfiltered traversal should find the next namespace of any flavour")?;
        if any.id != mid.id() {
            return Err("unfiltered traversal skipped a namespace");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nstree_adjoined_walks_one_flavour);

// ── nsfs: `fs/nsfs.c` ────────────────────────────────────────────
//
// An ns-fd was opaque: a caller could hold one and `setns` to it, but not
// ask what it WAS. These are the ioctls `nsenter`, `lsns` and systemd's
// `pidref_namespace_open_by_type` use to interrogate one.

/// Install `held` as an fd in the harness task's table.
#[cfg(feature = "container")]
fn install_ns_fd(held: crate::namespaces::HeldNs) -> Result<u32, &'static str> {
    let ops: alloc::sync::Arc<dyn narf_filesystem::FileOps> = crate::namespaces::NsFd::new(held);
    crate::fd::install(
        FAKE_TASK,
        crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: 0,
        },
    )
    .ok_or("could not install an ns-fd")
}

/// `_IO(NSIO, nr)` / `_IOR(NSIO, nr, size)` — the exact encodings, computed
/// against `<linux/ioctl.h>` with gcc rather than assembled by hand.
#[cfg(feature = "container")]
const fn nsio(nr: u32) -> u64 {
    (0xb7u32 << 8 | nr) as u64
}
#[cfg(feature = "container")]
const fn nsio_r(nr: u32, size: u32) -> u64 {
    ((2u32 << 30) | (size << 16) | (0xb7u32 << 8) | nr) as u64
}

/// The identity ioctls: what flavour is this, and which namespace.
///
/// `NS_GET_NSTYPE` is the odd one — it returns the `CLONE_NEW*` value AS
/// THE RETURN VALUE rather than writing through the argument, so a caller
/// reading it out of a buffer would read uninitialised memory and a kernel
/// writing it there would corrupt the caller's stack.
fn smoke_abi_nsfs_identity_ioctls() -> TestResult {
    use crate::namespaces::{ns_type, HeldNs, UtsNamespace};
    with_setup(|| {
        let ns = UtsNamespace::new_default();
        let id = ns.id();
        let fd = install_ns_fd(HeldNs::Uts(ns))?;

        // NS_GET_NSTYPE -> CLONE_NEWUTS, as the return value.
        let got = call(Syscall::Ioctl.raw(), a2(fd as u64, nsio(3), 0));
        if got != Some(i64::from(ns_type::UTS)) {
            return Err("NS_GET_NSTYPE must return the CLONE_NEW* value itself");
        }

        // NS_GET_ID -> the namespace id, written through the argument.
        let mut out = [0u64; 1];
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, nsio_r(13, 8), out.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("NS_GET_ID should succeed on an ns-fd");
        }
        if out[0] != id {
            return Err("NS_GET_ID reported the wrong namespace id");
        }

        // NS_GET_MNTNS_ID is the mount-only spelling of the same question,
        // so it must refuse a UTS namespace rather than answer it.
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, nsio_r(5, 8), out.as_mut_ptr() as u64),
        ) != Some(EINVAL)
        {
            return Err("NS_GET_MNTNS_ID on a non-mount namespace must be -EINVAL");
        }

        // A command in nsfs's ioctl range that nsfs does not define is
        // -ENOTTY, and so is one with the right number but the wrong
        // argument size — that is what `nsfs_ioctl_valid` is for, and
        // without it a caller's mis-sized buffer would be written anyway.
        const ENOTTY: i64 = -25;
        if call(Syscall::Ioctl.raw(), a2(fd as u64, nsio(0x7e), 0)) != Some(ENOTTY) {
            return Err("an undefined nsfs ioctl must be -ENOTTY");
        }
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, nsio_r(13, 4), out.as_mut_ptr() as u64),
        ) != Some(ENOTTY)
        {
            return Err("NS_GET_ID with the wrong argument size must be -ENOTTY");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nsfs_identity_ioctls);

/// `NS_GET_USERNS` / `NS_GET_PARENT` mint a real fd, and refuse to hand out
/// a namespace above the caller.
///
/// `ns_get_owner` walks from the owner up through `->parent` looking for
/// the CALLER's user namespace, and `-EPERM`s if it never meets it. That
/// walk is the whole permission model: without it an ns-fd held inside a
/// container would hand out a route to the host's user namespace.
/// `NS_GET_PARENT` on the initial user namespace hits the same wall from
/// the other side — it has no parent, which is `!p -> -EPERM`.
fn smoke_abi_nsfs_get_userns_and_parent() -> TestResult {
    use crate::namespaces::{ns_type, HeldNs, UserNamespace, UtsNamespace};
    with_setup(|| {
        // A UTS namespace owned by the initial user namespace: the caller
        // IS in that user namespace, so the walk meets it immediately.
        let host = crate::namespaces::global_user();
        let uts = UtsNamespace::clone_from_in(&UtsNamespace::new_default(), Some(host.clone()));
        let fd = install_ns_fd(HeldNs::Uts(uts))?;
        let owner_fd = match call(Syscall::Ioctl.raw(), a2(fd as u64, nsio(1), 0)) {
            Some(f) if f >= 0 => f as u64,
            _ => return Err("NS_GET_USERNS should return an fd for an owner in reach"),
        };
        // The fd it returns is a real ns-fd — it answers the identity
        // ioctls — rather than a placeholder.
        if call(Syscall::Ioctl.raw(), a2(owner_fd, nsio(3), 0)) != Some(i64::from(ns_type::USER)) {
            return Err("NS_GET_USERNS did not return a user-namespace fd");
        }
        let mut out = [0u64; 1];
        let _ = call(
            Syscall::Ioctl.raw(),
            a2(owner_fd, nsio_r(13, 8), out.as_mut_ptr() as u64),
        );
        if out[0] != host.id() {
            return Err("NS_GET_USERNS named the wrong user namespace");
        }

        // The initial user namespace has no parent, so asking for one is
        // -EPERM. This is the negative control for the walk above: without
        // it, every NS_GET_PARENT would look like it worked.
        let host_fd = install_ns_fd(HeldNs::User(host))?;
        if call(Syscall::Ioctl.raw(), a2(host_fd as u64, nsio(2), 0)) != Some(-1) {
            return Err("NS_GET_PARENT on the initial user namespace must be -EPERM");
        }
        // A child user namespace's parent IS reachable — it is the
        // caller's own — so that direction must still work.
        let child = UserNamespace::new_child(crate::namespaces::global_user(), 0);
        let child_fd = install_ns_fd(HeldNs::User(child))?;
        match call(Syscall::Ioctl.raw(), a2(child_fd as u64, nsio(2), 0)) {
            Some(f) if f >= 0 => {}
            _ => return Err("NS_GET_PARENT on a child user namespace should return an fd"),
        }
        // A flavour with no parent at all is -EINVAL, not -EPERM: the
        // question does not apply, rather than being refused.
        if call(Syscall::Ioctl.raw(), a2(fd as u64, nsio(2), 0)) != Some(EINVAL) {
            return Err("NS_GET_PARENT on a flavour without parents must be -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nsfs_get_userns_and_parent);

/// `NS_GET_OWNER_UID` reports the owner uid THROUGH the caller's id map.
///
/// `from_kuid_munged` is what makes this safe to expose: a caller in a
/// namespace that does not map the owner sees the overflow id rather than
/// the host uid, so the ioctl cannot be used to read host identity from
/// inside a container. It is -EINVAL for every flavour but user.
fn smoke_abi_nsfs_owner_uid() -> TestResult {
    use crate::namespaces::{HeldNs, UserNamespace, UtsNamespace};
    with_setup(|| {
        let child = UserNamespace::new_child(crate::namespaces::global_user(), 4242);
        let fd = install_ns_fd(HeldNs::User(child))?;
        let mut out = [0u32; 1];
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, nsio(4), out.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("NS_GET_OWNER_UID should succeed on a user namespace");
        }
        // The caller is in the initial user namespace, whose map is the
        // identity, so the owner uid comes back unchanged.
        if out[0] != 4242 {
            return Err("NS_GET_OWNER_UID reported the wrong owner uid");
        }
        let uts_fd = install_ns_fd(HeldNs::Uts(UtsNamespace::new_default()))?;
        if call(
            Syscall::Ioctl.raw(),
            a2(uts_fd as u64, nsio(4), out.as_mut_ptr() as u64),
        ) != Some(EINVAL)
        {
            return Err("NS_GET_OWNER_UID on a non-user namespace must be -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nsfs_owner_uid);

/// `NS_MNT_GET_INFO` reports the mount count and id; traversal needs
/// system-wide visibility.
///
/// The `size` field is what a caller compiled against a later struct reads
/// to know how much of its buffer this kernel filled — without it, a larger
/// struct's trailing zeroes would be indistinguishable from real data.
fn smoke_abi_nsfs_mnt_info_and_traversal() -> TestResult {
    use crate::namespaces::HeldNs;
    with_setup(|| {
        let ns = narf_filesystem::MountNamespace::snapshot_global();
        let want_id = ns.id();
        let want_mounts = ns.list().len() as u32;
        let fd = install_ns_fd(HeldNs::Mnt(ns))?;
        let mut info = [0u8; 16];
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, nsio_r(10, 16), info.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("NS_MNT_GET_INFO should succeed on a mount-namespace fd");
        }
        if u32::from_ne_bytes(info[0..4].try_into().unwrap()) != 16 {
            return Err("NS_MNT_GET_INFO must report the struct size it filled in");
        }
        if u32::from_ne_bytes(info[4..8].try_into().unwrap()) != want_mounts {
            return Err("NS_MNT_GET_INFO reported the wrong mount count");
        }
        if u64::from_ne_bytes(info[8..16].try_into().unwrap()) != want_id {
            return Err("NS_MNT_GET_INFO reported the wrong namespace id");
        }
        // A buffer smaller than the first published struct is -EINVAL, and
        // a NULL one is too: reporting into it is the command's whole job.
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, nsio_r(10, 8), info.as_mut_ptr() as u64),
        ) != Some(-25)
        {
            return Err("an undersized NS_MNT_GET_INFO must not be accepted");
        }
        if call(Syscall::Ioctl.raw(), a2(fd as u64, nsio_r(10, 16), 0)) != Some(EINVAL) {
            return Err("NS_MNT_GET_INFO with a NULL buffer must be -EINVAL");
        }
        // Traversal is privileged even though INFO is not — `may_use_nsfs_ioctl`
        // gates only NEXT/PREV. The harness task is in the initial pid
        // namespace WITH CAP_SYS_ADMIN, so here it is allowed;
        // `smoke_abi_nsfs_traversal_is_privileged` is the refusal half.
        match call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, nsio_r(11, 16), info.as_mut_ptr() as u64),
        ) {
            // Either a further mount namespace, or the end of the list.
            Some(f) if f >= 0 => {}
            Some(-2) => {}
            _ => return Err("NS_MNT_GET_NEXT should return an fd or -ENOENT"),
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nsfs_mnt_info_and_traversal);

/// An nsfs file handle round-trips, and the cross-checks reject a forged one.
///
/// `nsfs_encode_fh` carries id, type and inode. The id alone would locate
/// the namespace; the other two are what let the decoder notice a handle
/// that no longer names what it did — ids are unique within a boot but
/// minted afresh on the next one, so a persisted handle would otherwise
/// resolve silently to some unrelated namespace.
fn smoke_abi_nsfs_file_handle_round_trip() -> TestResult {
    use crate::namespaces::{ns_type, HeldNs, UtsNamespace};
    const AT_EMPTY_PATH: u64 = 0x1000;
    const ESTALE: i64 = -116;
    with_setup(|| {
        let ns = UtsNamespace::new_default();
        let id = ns.id();
        let fd = install_ns_fd(HeldNs::Uts(ns))?;

        // name_to_handle_at(fd, "", &handle, &mnt_id, AT_EMPTY_PATH).
        let mut handle = [0u8; 24];
        handle[0..4].copy_from_slice(&16u32.to_ne_bytes());
        let empty = b"\0";
        if call(
            Syscall::NameToHandleAt.raw(),
            a4(
                fd as u64,
                empty.as_ptr() as u64,
                handle.as_mut_ptr() as u64,
                0,
                AT_EMPTY_PATH,
            ),
        ) != Some(0)
        {
            return Err("name_to_handle_at on an ns-fd should succeed");
        }
        if i32::from_ne_bytes(handle[4..8].try_into().unwrap()) != 0xf1 {
            return Err("an ns-fd must encode to a FILEID_NSFS handle");
        }
        if u64::from_ne_bytes(handle[8..16].try_into().unwrap()) != id {
            return Err("the handle carried the wrong namespace id");
        }
        if u32::from_ne_bytes(handle[16..20].try_into().unwrap()) != ns_type::UTS {
            return Err("the handle carried the wrong namespace type");
        }

        // open_by_handle_at gives back an fd naming the same namespace.
        let reopened = match call(
            Syscall::OpenByHandleAt.raw(),
            a2(0, handle.as_ptr() as u64, 0),
        ) {
            Some(f) if f >= 0 => f as u64,
            _ => return Err("open_by_handle_at should reopen an nsfs handle"),
        };
        let mut out = [0u64; 1];
        let _ = call(
            Syscall::Ioctl.raw(),
            a2(reopened, nsio_r(13, 8), out.as_mut_ptr() as u64),
        );
        if out[0] != id {
            return Err("the reopened handle named a different namespace");
        }

        // A handle whose TYPE disagrees with the namespace the id names is
        // stale, not silently accepted. This is the check that catches a
        // handle kept across a reboot.
        let mut forged = handle;
        forged[16..20].copy_from_slice(&ns_type::NET.to_ne_bytes());
        if call(
            Syscall::OpenByHandleAt.raw(),
            a2(0, forged.as_ptr() as u64, 0),
        ) != Some(ESTALE)
        {
            return Err("a handle whose type contradicts its id must be -ESTALE");
        }
        // So is one whose INODE disagrees.
        let mut forged = handle;
        forged[20..24].copy_from_slice(&0xdead_beefu32.to_ne_bytes());
        if call(
            Syscall::OpenByHandleAt.raw(),
            a2(0, forged.as_ptr() as u64, 0),
        ) != Some(ESTALE)
        {
            return Err("a handle whose inode contradicts its id must be -ESTALE");
        }
        // `!fid->ns_inum != !fid->ns_type` — both set or neither.
        let mut forged = handle;
        forged[20..24].copy_from_slice(&0u32.to_ne_bytes());
        if call(
            Syscall::OpenByHandleAt.raw(),
            a2(0, forged.as_ptr() as u64, 0),
        ) != Some(ESTALE)
        {
            return Err("a handle with a type but no inode must be -ESTALE");
        }
        // And an id that names nothing.
        let mut forged = handle;
        forged[8..16].copy_from_slice(&u64::MAX.to_ne_bytes());
        if call(
            Syscall::OpenByHandleAt.raw(),
            a2(0, forged.as_ptr() as u64, 0),
        ) != Some(ESTALE)
        {
            return Err("a handle naming no namespace must be -ESTALE");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nsfs_file_handle_round_trip);

/// Mount-namespace traversal needs system-wide visibility; the other nsfs
/// ioctls do not.
///
/// `may_use_nsfs_ioctl` returns `may_see_all_namespaces()` for NEXT/PREV
/// and `true` for everything else, and the refusal is `-EPERM` rather than
/// `-ENOTTY`: the command exists, this caller may not use it. Enumerating
/// the system's mount namespaces is exactly the capability a container must
/// not have, so the gate is the whole point of the command.
///
/// The INFO half is the control. Without it a broken implementation that
/// refused EVERY nsfs ioctl would pass the interesting assertion.
fn smoke_abi_nsfs_traversal_is_privileged() -> TestResult {
    use crate::namespaces::HeldNs;
    with_setup(|| {
        let ns = narf_filesystem::MountNamespace::snapshot_global();
        let fd = install_ns_fd(HeldNs::Mnt(ns))?;
        let mut info = [0u8; 16];
        drop_to_unprivileged_uid()?;

        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, nsio_r(11, 16), info.as_mut_ptr() as u64),
        ) != Some(-1)
        {
            return Err("NS_MNT_GET_NEXT without CAP_SYS_ADMIN must be -EPERM");
        }
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, nsio_r(12, 16), info.as_mut_ptr() as u64),
        ) != Some(-1)
        {
            return Err("NS_MNT_GET_PREV without CAP_SYS_ADMIN must be -EPERM");
        }
        // Unprivileged callers may still ask what their OWN namespace is —
        // the gate gates traversal, not the whole file.
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, nsio_r(10, 16), info.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("NS_MNT_GET_INFO must not require CAP_SYS_ADMIN");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_nsfs_traversal_is_privileged);
