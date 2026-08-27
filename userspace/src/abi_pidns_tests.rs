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
            match call(Syscall::Waitid.raw(), a3(P_PID, 3, 0, 0)) {
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
            crate::pid_ns::unshare_pid_ns_for_children(P_UN_TASK);
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
