//! Linux syscall ABI conformance — sched group.
//!
//! Shares the harness in [`crate::abi_test_support`]; see that module for
//! the rationale. Scheduler / rlimit / priority surface.
//!
//! Tests pin the implemented Linux-compatible wire behavior. Where a
//! cooperative-scheduler limit makes an arm unreachable, the case says so at
//! the assertion rather than relying on a file-level note.

use crate::abi_test_support::*;

/// A non-canonical x86_64 address (bit 48 set, 49..63 clear). Any
/// `copy_to_user` / `validate_user_range` against it returns EFAULT, so it's
/// a deterministic "bad user pointer" for the negative buffer paths.
const BAD_PTR: u64 = 0x0001_0000_0000_0000;

// Linux sched policy numbers.
const SCHED_OTHER: u64 = 0;
const SCHED_FIFO: u64 = 1;
const SCHED_RR: u64 = 2;
const SCHED_IDLE: u64 = 5;
const SCHED_DEADLINE: u64 = 6;

// ── getcpu(cpu*, node*, tcache) ─────────────────────────────────────
// Reports the live logical CPU and its SRAT NUMA node. The ABI harness runs
// on the BSP, which belongs to node 0 in the default QEMU topology.

fn smoke_abi_sched_getcpu_pos() -> TestResult {
    with_setup(|| {
        let mut cpu = [0xFFu8; 4];
        let mut node = [0xFFu8; 4];
        let args = a2(cpu.as_mut_ptr() as u64, node.as_mut_ptr() as u64, 0);
        match call(Syscall::Getcpu.raw(), args) {
            Some(0) => {
                if u32::from_ne_bytes(cpu) == 0 && u32::from_ne_bytes(node) == 0 {
                    Ok(())
                } else {
                    Err("getcpu must report CPU 0 / node 0")
                }
            }
            _ => Err("getcpu should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getcpu_pos);

fn smoke_abi_sched_getcpu_null_ptrs_ok() -> TestResult {
    with_setup(|| {
        // Both out-pointers null: handler skips the writes and still ok(0).
        // (Linux would EFAULT a *bad* non-null pointer; null is a no-op here.)
        match call(Syscall::Getcpu.raw(), a2(0, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("getcpu with null pointers should still return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getcpu_null_ptrs_ok);

fn smoke_abi_sched_getcpu_bad_cpu_ptr_neg() -> TestResult {
    with_setup(|| match call(Syscall::Getcpu.raw(), a2(BAD_PTR, 0, 0)) {
        Some(v) if v == EFAULT => Ok(()),
        _ => Err("getcpu with a bad CPU pointer should return -EFAULT"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getcpu_bad_cpu_ptr_neg);

// ── getpriority(which, who) ─────────────────────────────────────────
// PRIO_PROCESS(0) only; returns 20 - nice (default nice 0 ⇒ 20).

fn smoke_abi_sched_getpriority_pos() -> TestResult {
    with_setup(|| {
        // PRIO_PROCESS, self. Default nice 0 ⇒ wire value 20 - nice == 20.
        match call(Syscall::Getpriority.raw(), a1(0, 0)) {
            Some(20) => Ok(()),
            other => {
                let _ = other;
                Err("getpriority(PRIO_PROCESS) should return 20 - nice == 20")
            }
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getpriority_pos);

fn smoke_abi_sched_getpriority_bad_which_neg() -> TestResult {
    with_setup(|| {
        // `which` outside [PRIO_PROCESS, PRIO_USER] → -EINVAL
        // (kernel/sys.c). PRIO_PGRP(1) and PRIO_USER(2) are now
        // implemented, so the out-of-range probe is 3 — using 1 here would
        // be asserting that a supported scope is rejected.
        if call(Syscall::Getpriority.raw(), a1(3, 0)) != Some(EINVAL) {
            return Err("getpriority with an out-of-range which should return -EINVAL");
        }
        if call(Syscall::Getpriority.raw(), a1((-1i64) as u64, 0)) != Some(EINVAL) {
            return Err("getpriority with a negative which should return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getpriority_bad_which_neg);

// ── setpriority(which, who, prio) ───────────────────────────────────

fn smoke_abi_sched_setpriority_pos() -> TestResult {
    with_setup(|| {
        // Set nice 10 then read it back: getpriority returns 20 - 10 == 10.
        match call(Syscall::Setpriority.raw(), a2(0, 0, 10)) {
            Some(0) => {}
            _ => return Err("smoke_abi_sched_setpriority_pos: unexpected syscall return"),
        }
        match call(Syscall::Getpriority.raw(), a1(0, 0)) {
            Some(10) => Ok(()),
            _ => Err("getpriority after setpriority(nice 10) should be 20 - 10 == 10"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setpriority_pos);

fn smoke_abi_sched_setpriority_out_of_range_neg() -> TestResult {
    with_setup(|| {
        // Linux CLAMPS niceval to [MIN_NICE(-20), MAX_NICE(19)] instead of
        // rejecting it, so an out-of-range value succeeds (returns 0) rather
        // than the old -1. Both ends clamp; getpriority then reads back the
        // clamped nice (via NARF's own nice→priority mapping), which must
        // differ between the two clamps to prove the clamp actually applied.
        if call(Syscall::Setpriority.raw(), a2(0, 0, 100)) != Some(0) {
            return Err("setpriority with an out-of-range nice should clamp and return 0");
        }
        let high = call(Syscall::Getpriority.raw(), a1(0, 0));
        if call(Syscall::Setpriority.raw(), a2(0, 0, (-100i64) as u64)) != Some(0) {
            return Err("setpriority(-100) should clamp and return 0");
        }
        let low = call(Syscall::Getpriority.raw(), a1(0, 0));
        if high == low {
            return Err("out-of-range setpriority did not clamp to distinct nice bounds");
        }
        // `if (which > PRIO_USER || which < PRIO_PROCESS) goto out;` —
        // only a value OUTSIDE [0, 2] is -EINVAL. PRIO_USER(2) used to be
        // rejected here because the scope was unimplemented; it is now a
        // supported selection, so the probe moved to 3.
        if call(Syscall::Setpriority.raw(), a2(3, 0, 0)) != Some(EINVAL) {
            return Err("setpriority with an unsupported which should return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setpriority_out_of_range_neg);

// ── getrlimit(resource, rlimit*) ────────────────────────────────────
// rlimit* is a 16-byte {cur, max} pair. RLIMIT_NOFILE == 7.

fn smoke_abi_sched_getrlimit_pos() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 16];
        // RLIMIT_NOFILE (7): default {cur=1024, max=4096}.
        let args = a1(7, buf.as_mut_ptr() as u64);
        match call(Syscall::Getrlimit.raw(), args) {
            Some(0) => {
                let cur = u64::from_ne_bytes(buf[..8].try_into().unwrap());
                let max = u64::from_ne_bytes(buf[8..].try_into().unwrap());
                if cur == 1024 && max == 4096 {
                    Ok(())
                } else {
                    Err("getrlimit RLIMIT_NOFILE not the default {1024,4096}")
                }
            }
            _ => Err("getrlimit(RLIMIT_NOFILE) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getrlimit_pos);

fn smoke_abi_sched_getrlimit_null_buf_neg() -> TestResult {
    with_setup(|| match call(Syscall::Getrlimit.raw(), a1(7, 0)) {
        Some(v) if v == EFAULT => Ok(()),
        _ => Err("getrlimit with null buffer should return -EFAULT"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getrlimit_null_buf_neg);

fn smoke_abi_sched_getrlimit_bad_resource_neg() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 16];
        let args = a1(999, buf.as_mut_ptr() as u64);
        match call(Syscall::Getrlimit.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("getrlimit with bad resource should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getrlimit_bad_resource_neg);

fn smoke_abi_sched_getrlimit_bad_resource_precedes_bad_pointer() -> TestResult {
    with_setup(|| match call(Syscall::Getrlimit.raw(), a1(999, 0)) {
        Some(v) if v == EINVAL => Ok(()),
        _ => Err("getrlimit must validate resource before copying output"),
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_getrlimit_bad_resource_precedes_bad_pointer
);

// ── setrlimit(resource, rlimit*) ────────────────────────────────────

fn smoke_abi_sched_setrlimit_pos() -> TestResult {
    with_setup(|| {
        // Write a new RLIMIT_NOFILE {cur=128, max=512}, read it back.
        let mut wbuf = [0u8; 16];
        wbuf[..8].copy_from_slice(&128u64.to_ne_bytes());
        wbuf[8..].copy_from_slice(&512u64.to_ne_bytes());
        match call(Syscall::Setrlimit.raw(), a1(7, wbuf.as_ptr() as u64)) {
            Some(0) => {}
            _ => return Err("smoke_abi_sched_setrlimit_pos: unexpected syscall return"),
        }
        let mut rbuf = [0u8; 16];
        match call(Syscall::Getrlimit.raw(), a1(7, rbuf.as_mut_ptr() as u64)) {
            Some(0) => {
                let cur = u64::from_ne_bytes(rbuf[..8].try_into().unwrap());
                let max = u64::from_ne_bytes(rbuf[8..].try_into().unwrap());
                if cur == 128 && max == 512 {
                    Ok(())
                } else {
                    Err("setrlimit didn't persist {128,512}")
                }
            }
            _ => Err("getrlimit after setrlimit should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setrlimit_pos);

fn smoke_abi_sched_setrlimit_null_buf_neg() -> TestResult {
    with_setup(|| match call(Syscall::Setrlimit.raw(), a1(7, 0)) {
        Some(v) if v == EFAULT => Ok(()),
        _ => Err("setrlimit with null buffer should return -EFAULT"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setrlimit_null_buf_neg);

// ── prlimit64(pid, resource, new*, old*) ────────────────────────────

fn smoke_abi_sched_prlimit64_pos() -> TestResult {
    with_setup(|| {
        // Set new RLIMIT_NOFILE {cur=64, max=200} for self (pid 0),
        // capturing the prior value into old*.
        let mut newbuf = [0u8; 16];
        newbuf[..8].copy_from_slice(&64u64.to_ne_bytes());
        newbuf[8..].copy_from_slice(&200u64.to_ne_bytes());
        let mut oldbuf = [0u8; 16];
        let args = a3(0, 7, newbuf.as_ptr() as u64, oldbuf.as_mut_ptr() as u64);
        match call(Syscall::Prlimit64.raw(), args) {
            Some(0) => {
                // old* must hold the prior default {1024, 4096}.
                let ocur = u64::from_ne_bytes(oldbuf[..8].try_into().unwrap());
                let omax = u64::from_ne_bytes(oldbuf[8..].try_into().unwrap());
                if ocur == 1024 && omax == 4096 {
                    Ok(())
                } else {
                    Err("prlimit64 old value not the prior default {1024,4096}")
                }
            }
            _ => Err("prlimit64 set+get should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_prlimit64_pos);

fn smoke_abi_sched_prlimit64_bad_resource_neg() -> TestResult {
    with_setup(|| match call(Syscall::Prlimit64.raw(), a3(0, 999, 0, 0)) {
        Some(v) if v == EINVAL => Ok(()),
        _ => Err("prlimit64 with bad resource should return -EINVAL"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_prlimit64_bad_resource_neg);

fn smoke_abi_sched_setrlimit_validates_pair_and_hard_raise() -> TestResult {
    with_setup(|| {
        let invalid_pair = [513u64, 512u64];
        if call(
            Syscall::Setrlimit.raw(),
            a1(7, invalid_pair.as_ptr() as u64),
        ) != Some(EINVAL)
        {
            return Err("setrlimit(cur > max) should return -EINVAL");
        }
        let hard_raise = [1024u64, 4097u64];
        // Drop caps so this exercises the *unauthorized* path: raising a hard
        // limit without CAP_SYS_RESOURCE must still be -EPERM. (The harness
        // otherwise starts as the boot credential with every capability.)
        crate::handlers::__test_set_caps(FAKE_TASK, 0, 0);
        if call(Syscall::Setrlimit.raw(), a1(7, hard_raise.as_ptr() as u64)) != Some(EPERM) {
            return Err("unauthorized hard-limit raise should return -EPERM");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setrlimit_validates_pair_and_hard_raise
);

fn smoke_abi_sched_setrlimit_cap_sys_resource_raises_hard_limit() -> TestResult {
    with_setup(|| {
        // The harness starts as the boot credential with every Linux
        // capability effective. `do_prlimit` specifically permits this hard
        // raise with CAP_SYS_RESOURCE. PAM's `pam_limits` relies on that when
        // a root systemd executor applies an `@audio nice -11` policy before
        // entering the user's session.
        let raised = [31u64, 31u64];
        if call(Syscall::Setrlimit.raw(), a1(13, raised.as_ptr() as u64)) != Some(0) {
            return Err("CAP_SYS_RESOURCE should permit raising RLIMIT_NICE");
        }
        let mut observed = [0u8; 16];
        if call(
            Syscall::Getrlimit.raw(),
            a1(13, observed.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("getrlimit(RLIMIT_NICE) failed after privileged raise");
        }
        let cur = u64::from_ne_bytes(observed[..8].try_into().unwrap());
        let max = u64::from_ne_bytes(observed[8..].try_into().unwrap());
        if (cur, max) != (31, 31) {
            return Err("privileged RLIMIT_NICE raise did not persist");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setrlimit_cap_sys_resource_raises_hard_limit
);

fn smoke_abi_sched_prlimit64_error_order_and_missing_pid() -> TestResult {
    with_setup(|| {
        const MISSING_PID: u64 = 0x7fff_ffff;
        if call(Syscall::Prlimit64.raw(), a3(MISSING_PID, 7, BAD_PTR, 0)) != Some(EFAULT) {
            return Err("prlimit64 must copy new before missing-PID lookup");
        }
        if call(Syscall::Prlimit64.raw(), a3(MISSING_PID, 7, 0, 0)) != Some(ESRCH) {
            return Err("prlimit64 of a nonexistent PID should return -ESRCH");
        }
        if call(Syscall::Prlimit64.raw(), a3((-1i64) as u64, 7, 0, 0)) != Some(ESRCH) {
            return Err("prlimit64 of a negative pid_t should return -ESRCH");
        }

        // SYSCALL_DEFINE4's generated wrapper narrows pid to pid_t and
        // resource to unsigned int. High register bits therefore cannot turn
        // self/resource-7 into a missing PID or invalid resource.
        let raw_self = 1u64 << 32;
        let raw_resource_7 = (1u64 << 32) | 7;
        if call(Syscall::Prlimit64.raw(), a3(raw_self, raw_resource_7, 0, 0)) != Some(0) {
            return Err("prlimit64 did not apply Linux 32-bit argument narrowing");
        }

        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_prlimit64_error_order_and_missing_pid
);

fn smoke_abi_sched_reap_retires_rlimit_storage() -> TestResult {
    with_setup(|| {
        const TARGET_TID: u64 = 0xA7_100;
        const TARGET_PID: u64 = 0xA7_200;
        let owner = crate::task::Task::new_registered(TARGET_TID, TARGET_PID);
        crate::handlers::register_pid_task_mapping(TARGET_PID, TARGET_TID);

        let limits = [64u64, 200u64];
        let set_result = call(
            Syscall::Prlimit64.raw(),
            a3(TARGET_PID, 7, limits.as_ptr() as u64, 0),
        );
        let populated = crate::handlers::__test_rlimit_storage_len();

        crate::task::mark_zombie(TARGET_TID);
        crate::handlers::release_reaped_task(TARGET_PID);
        let retained = crate::handlers::__test_rlimit_storage_len();
        drop(owner);

        if set_result != Some(0) || populated != 1 {
            return Err("prlimit64 did not populate exactly one target row");
        }
        if retained != 0 {
            return Err("reap retained rlimit lifetime state for a dead TaskId");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_reap_retires_rlimit_storage);

// ── sched_getaffinity(pid, cpusetsize, mask*) ───────────────────────
// Reports the task's allowed mask intersected with online CPUs.

fn smoke_abi_sched_getaffinity_pos() -> TestResult {
    with_setup(|| {
        narf_scheduler::__reset_queues_for_test();
        let spec = narf_scheduler::TaskSpec {
            affinity: narf_scheduler::Affinity::any(),
            ..narf_scheduler::TaskSpec::unthrottled()
        };
        let target = narf_scheduler::spawn_with_spec(core::future::pending::<()>(), spec);
        let mut mask = [0xFFu8; 128];
        let args = a2(target.raw(), 128, mask.as_mut_ptr() as u64);
        let result = match call(Syscall::SchedGetaffinity.raw(), args) {
            Some(8) => {
                if u64::from_ne_bytes(mask[..8].try_into().unwrap())
                    == narf_lib::smp::online_bitmap()
                    && mask[8..].iter().all(|byte| *byte == 0xFF)
                {
                    Ok(())
                } else {
                    Err("sched_getaffinity returned the wrong live mask")
                }
            }
            _ => Err("sched_getaffinity should return kernel mask width (8)"),
        };
        narf_scheduler::__reset_queues_for_test();
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getaffinity_pos);

fn smoke_abi_sched_getaffinity_tiny_size_neg() -> TestResult {
    with_setup(|| {
        let mut mask = [0u8; 8];
        // cpusetsize 4 (< sizeof(unsigned long)) ⇒ -EINVAL.
        let args = a2(0, 4, mask.as_mut_ptr() as u64);
        match call(Syscall::SchedGetaffinity.raw(), args) {
            Some(-22) => Ok(()),
            _ => Err("sched_getaffinity with size < 8 should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getaffinity_tiny_size_neg);

// ── sched_setaffinity(pid, cpusetsize, mask*) ───────────────────────

fn smoke_abi_sched_setaffinity_pos() -> TestResult {
    with_setup(|| {
        narf_scheduler::__reset_queues_for_test();
        let spec = narf_scheduler::TaskSpec {
            affinity: narf_scheduler::Affinity::any(),
            ..narf_scheduler::TaskSpec::unthrottled()
        };
        let target = narf_scheduler::spawn_with_spec(core::future::pending::<()>(), spec);
        let mut mask = [0u8; 8];
        mask[0] = 1;
        let args = a2(target.raw(), 8, mask.as_ptr() as u64);
        let result = match call(Syscall::SchedSetaffinity.raw(), args) {
            Some(0)
                if narf_scheduler::task_affinity(target)
                    == Some(narf_scheduler::CpuSet::single(narf_scheduler::CpuId::BOOT)) =>
            {
                Ok(())
            }
            _ => Err("sched_setaffinity should return 0"),
        };
        narf_scheduler::__reset_queues_for_test();
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setaffinity_pos);

fn smoke_abi_sched_setaffinity_null_mask_neg() -> TestResult {
    with_setup(|| {
        // Null mask pointer ⇒ -EFAULT.
        match call(Syscall::SchedSetaffinity.raw(), a2(0, 8, 0)) {
            Some(-14) => Ok(()),
            _ => Err("sched_setaffinity with null mask should return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setaffinity_null_mask_neg);

// ── sched_get_priority_max(policy) ──────────────────────────────────

fn smoke_abi_sched_get_priority_max_pos() -> TestResult {
    with_setup(|| {
        // SCHED_RR ⇒ 99; SCHED_OTHER ⇒ 0.
        match call(Syscall::SchedGetPriorityMax.raw(), a0(SCHED_RR)) {
            Some(99) => {}
            _ => return Err("sched_get_priority_max(SCHED_RR) should be 99"),
        }
        match call(Syscall::SchedGetPriorityMax.raw(), a0(SCHED_OTHER)) {
            Some(0) => Ok(()),
            _ => Err("sched_get_priority_max(SCHED_OTHER) should be 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_get_priority_max_pos);

fn smoke_abi_sched_get_priority_max_bad_policy_neg() -> TestResult {
    with_setup(|| {
        // `kernel/sched/syscalls.c`: the switch opens `int ret = -EINVAL;`
        // and an unrecognised policy falls straight through to it. A bare -1
        // reaches the caller as errno 1 (EPERM), which glibc's pthread
        // attribute code — it probes this range before validating a
        // priority — reads as "not allowed to ask" rather than "no such
        // policy".
        match call(Syscall::SchedGetPriorityMax.raw(), a0(42)) {
            Some(-22) => Ok(()),
            Some(-1) => {
                Err("sched_get_priority_max bad policy still returns the -1/EPERM sentinel")
            }
            _ => Err("sched_get_priority_max bad policy should return -EINVAL"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_get_priority_max_bad_policy_neg
);

fn smoke_abi_sched_get_priority_max_known_but_unadmittable() -> TestResult {
    with_setup(|| {
        // SCHED_DEADLINE (6) and SCHED_EXT (7) are recognised policy numbers
        // in `include/uapi/linux/sched.h`, and sched_get_priority_max is a
        // bare switch with no admission check — both report 0 even though
        // neither is accepted by sched_setscheduler. Reporting EINVAL made a
        // libc probing the range conclude the kernel predates the constant.
        for policy in [6u64, 7u64] {
            match call(Syscall::SchedGetPriorityMax.raw(), a0(policy)) {
                Some(0) => {}
                Some(-22) => return Err("sched_get_priority_max rejected a recognised policy"),
                _ => return Err("sched_get_priority_max(SCHED_DEADLINE/EXT) should be 0"),
            }
            match call(Syscall::SchedGetPriorityMin.raw(), a0(policy)) {
                Some(0) => {}
                Some(-22) => return Err("sched_get_priority_min rejected a recognised policy"),
                _ => return Err("sched_get_priority_min(SCHED_DEADLINE/EXT) should be 0"),
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_get_priority_max_known_but_unadmittable
);

fn smoke_abi_sched_get_priority_policy_is_int_wide() -> TestResult {
    with_setup(|| {
        // `SYSCALL_DEFINE1(sched_get_priority_max, int, policy)` — only the
        // low 32 bits are the argument. Matching the full 64-bit register
        // sent a caller that left garbage in the upper half (legal for a
        // libc stub; the psABI only promises the low half of an `int`) to
        // the error arm for a perfectly valid policy.
        let dirty = 0xdead_beef_0000_0002u64; // upper garbage + SCHED_RR
        match call(Syscall::SchedGetPriorityMax.raw(), a0(dirty)) {
            Some(99) => {}
            Some(-22) => {
                return Err("sched_get_priority_max matched the full register, not the low int")
            }
            _ => return Err("sched_get_priority_max(dirty SCHED_RR) should be 99"),
        }
        match call(Syscall::SchedGetPriorityMin.raw(), a0(dirty)) {
            Some(1) => Ok(()),
            Some(-22) => Err("sched_get_priority_min matched the full register, not the low int"),
            _ => Err("sched_get_priority_min(dirty SCHED_RR) should be 1"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_get_priority_policy_is_int_wide
);

// ── sched_get_priority_min(policy) ──────────────────────────────────

fn smoke_abi_sched_get_priority_min_pos() -> TestResult {
    with_setup(|| {
        // SCHED_RR ⇒ 1; SCHED_OTHER ⇒ 0.
        match call(Syscall::SchedGetPriorityMin.raw(), a0(SCHED_RR)) {
            Some(1) => {}
            _ => return Err("sched_get_priority_min(SCHED_RR) should be 1"),
        }
        match call(Syscall::SchedGetPriorityMin.raw(), a0(SCHED_OTHER)) {
            Some(0) => Ok(()),
            _ => Err("sched_get_priority_min(SCHED_OTHER) should be 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_get_priority_min_pos);

fn smoke_abi_sched_get_priority_min_bad_policy_neg() -> TestResult {
    with_setup(|| {
        // Same bare `int ret = -EINVAL;` fall-through as the max variant.
        match call(Syscall::SchedGetPriorityMin.raw(), a0(42)) {
            Some(-22) => Ok(()),
            Some(-1) => {
                Err("sched_get_priority_min bad policy still returns the -1/EPERM sentinel")
            }
            _ => Err("sched_get_priority_min bad policy should return -EINVAL"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_get_priority_min_bad_policy_neg
);

// ── sched_getparam(pid, param*) ─────────────────────────────────────
// param* is a single i32 (sched_priority). Default 0.

fn smoke_abi_sched_getparam_pos() -> TestResult {
    with_setup(|| {
        let mut buf = [0xFFu8; 4];
        let args = a1(0, buf.as_mut_ptr() as u64);
        match call(Syscall::SchedGetparam.raw(), args) {
            Some(0) => {
                if i32::from_ne_bytes(buf) == 0 {
                    Ok(())
                } else {
                    Err("sched_getparam default sched_priority should be 0")
                }
            }
            _ => Err("sched_getparam should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getparam_pos);

fn smoke_abi_sched_getparam_null_buf_neg() -> TestResult {
    with_setup(|| {
        // `if (unlikely(!param || pid < 0)) return -EINVAL;` — a NULL param
        // is EINVAL, not EFAULT: Linux rejects it by inspection before any
        // access is attempted.
        match call(Syscall::SchedGetparam.raw(), a1(0, 0)) {
            Some(-22) => Ok(()),
            Some(-1) => Err("sched_getparam null param still returns the -1/EPERM sentinel"),
            Some(-14) => Err("sched_getparam null param returned EFAULT; Linux rejects it EINVAL"),
            _ => Err("sched_getparam with null buffer should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getparam_null_buf_neg);

fn smoke_abi_sched_getparam_negative_pid_einval() -> TestResult {
    with_setup(|| {
        // The same guard covers `pid < 0`, and pid_t is `int` — reading the
        // full register let a negative pid arrive as a huge positive u64 and
        // miss the check entirely.
        let mut buf = [0u8; 4];
        let args = a1((-1i64) as u64, buf.as_mut_ptr() as u64);
        match call(Syscall::SchedGetparam.raw(), args) {
            Some(-22) => Ok(()),
            Some(-3) => Err("sched_getparam(negative pid) returned ESRCH; Linux rejects it EINVAL"),
            Some(0) => Err("sched_getparam accepted a negative pid"),
            _ => Err("sched_getparam with a negative pid should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getparam_negative_pid_einval);

fn smoke_abi_sched_getparam_null_beats_bad_pid() -> TestResult {
    with_setup(|| {
        // Ordering: `!param || pid < 0` is ONE guard evaluated before the
        // find_process_by_pid lookup, so a null param wins over a pid that
        // names no task. A caller must be able to tell its own null pointer
        // apart from "that process went away".
        match call(Syscall::SchedGetparam.raw(), a1(123456, 0)) {
            Some(-22) => Ok(()),
            Some(-3) => Err("sched_getparam looked up the pid before checking param (wrong order)"),
            _ => Err("sched_getparam(bad pid, null param) should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getparam_null_beats_bad_pid);

fn smoke_abi_sched_getparam_unknown_pid_esrch() -> TestResult {
    with_setup(|| {
        // Past the argument guard: `p = find_process_by_pid(pid);
        // if (!p) return -ESRCH;`.
        let mut buf = [0u8; 4];
        let args = a1(123456, buf.as_mut_ptr() as u64);
        match call(Syscall::SchedGetparam.raw(), args) {
            Some(-3) => Ok(()),
            Some(0) => Err("sched_getparam reported a priority for a non-existent pid"),
            _ => Err("sched_getparam on an unknown pid should return -ESRCH"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getparam_unknown_pid_esrch);

fn smoke_abi_sched_getparam_bad_ptr_efault() -> TestResult {
    with_setup(|| {
        // `return copy_to_user(param, &lp, sizeof(*param)) ? -EFAULT : 0;`
        // — a non-null but unmapped pointer is EFAULT, distinct from the
        // EINVAL a null one gets.
        match call(Syscall::SchedGetparam.raw(), a1(0, BAD_PTR)) {
            Some(-14) => Ok(()),
            Some(-1) => Err("sched_getparam copy fault still returns the -1/EPERM sentinel"),
            _ => Err("sched_getparam with an unmapped param should return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getparam_bad_ptr_efault);

// ── sched_setparam(pid, param*) ─────────────────────────────────────

fn smoke_abi_sched_setparam_pos() -> TestResult {
    with_setup(|| {
        // `__sched_setscheduler`:
        //
        //     if (attr->sched_priority > MAX_RT_PRIO-1)  return -EINVAL;
        //     if (rt_policy(policy) != (attr->sched_priority != 0))
        //                                                return -EINVAL;
        //
        // with Linux's own comment above it: "valid priority for
        // SCHED_NORMAL, SCHED_BATCH and SCHED_IDLE is 0". Every NARF task
        // is SCHED_OTHER, so 0 is the ONLY value that agrees with the
        // policy.
        //
        // This used to set 50 and read it back, and its own final arm
        // returned Ok either way — so it asserted nothing while documenting
        // behaviour Linux rejects. A caller that got 0 back from setparam
        // believed it held a real-time priority on a policy that has none.
        let zero = 0i32.to_ne_bytes();
        match call(Syscall::SchedSetparam.raw(), a1(0, zero.as_ptr() as u64)) {
            Some(0) => {}
            _ => return Err("sched_setparam(0) on a SCHED_OTHER task should succeed"),
        }
        let mut rbuf = [0xFFu8; 4];
        match call(
            Syscall::SchedGetparam.raw(),
            a1(0, rbuf.as_mut_ptr() as u64),
        ) {
            Some(0) if i32::from_ne_bytes(rbuf) == 0 => {}
            Some(0) => return Err("sched_getparam did not read back the stored priority"),
            _ => return Err("sched_getparam should succeed"),
        }
        // A non-zero priority disagrees with SCHED_OTHER.
        let fifty = 50i32.to_ne_bytes();
        match call(Syscall::SchedSetparam.raw(), a1(0, fifty.as_ptr() as u64)) {
            Some(-22) => {}
            Some(0) => return Err("sched_setparam accepted an RT priority on SCHED_OTHER"),
            _ => return Err("sched_setparam(50) on SCHED_OTHER should be -EINVAL"),
        }
        // And one past MAX_RT_PRIO-1 is rejected by the range check that
        // precedes it, so it is -EINVAL for a second, independent reason.
        let huge = 100i32.to_ne_bytes();
        match call(Syscall::SchedSetparam.raw(), a1(0, huge.as_ptr() as u64)) {
            Some(-22) => Ok(()),
            _ => Err("sched_setparam(100) should be -EINVAL (> MAX_RT_PRIO-1)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setparam_pos);

fn smoke_abi_sched_setparam_null_buf_neg() -> TestResult {
    with_setup(|| {
        // do_sched_setscheduler: `!param` → -EINVAL (before the copy).
        if call(Syscall::SchedSetparam.raw(), a1(0, 0)) != Some(EINVAL) {
            return Err("sched_setparam with a null param should return -EINVAL");
        }
        // A non-NULL but faulting param → -EFAULT (copy_from_user).
        if call(Syscall::SchedSetparam.raw(), a1(0, BAD_PTR)) != Some(EFAULT) {
            return Err("sched_setparam with a faulting param should return -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setparam_null_buf_neg);

// ── sched_getscheduler(pid) ─────────────────────────────────────────

fn smoke_abi_sched_getscheduler_pos() -> TestResult {
    with_setup(|| {
        // A fresh task is SCHED_OTHER (0).
        match call(Syscall::SchedGetScheduler.raw(), a0(0)) {
            Some(0) => Ok(()),
            _ => Err("sched_getscheduler should report SCHED_OTHER (0)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getscheduler_pos);

// ── sched_setscheduler(pid, policy, param*) ─────────────────────────

fn smoke_abi_sched_setscheduler_pos() -> TestResult {
    with_setup(|| {
        // SCHED_RR at priority 1 (the harness task holds CAP_SYS_NICE),
        // then read it back — the policy is no longer hard-coded.
        let one = 1i32.to_ne_bytes();
        match call(
            Syscall::SchedSetScheduler.raw(),
            a3(0, SCHED_RR, one.as_ptr() as u64, 0),
        ) {
            Some(0) => {}
            _ => return Err("sched_setscheduler(SCHED_RR, 1) should return 0"),
        }
        match call(Syscall::SchedGetScheduler.raw(), a0(0)) {
            Some(v) if v == SCHED_RR as i64 => Ok(()),
            Some(0) => Err("sched_getscheduler still reports SCHED_OTHER after SCHED_RR"),
            _ => Err("sched_getscheduler should report SCHED_RR"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setscheduler_pos);

fn smoke_abi_sched_setscheduler_reset_on_fork_pos() -> TestResult {
    with_setup(|| {
        const SCHED_RESET_ON_FORK: u64 = 0x4000_0000;
        let zero = 0i32.to_ne_bytes();
        match call(
            Syscall::SchedSetScheduler.raw(),
            a3(
                0,
                SCHED_OTHER | SCHED_RESET_ON_FORK,
                zero.as_ptr() as u64,
                0,
            ),
        ) {
            Some(0) => {}
            _ => return Err("sched_setscheduler must accept SCHED_RESET_ON_FORK"),
        }
        // `if (p->sched_reset_on_fork) retval |= SCHED_RESET_ON_FORK;`
        match call(Syscall::SchedGetScheduler.raw(), a0(0)) {
            Some(v) if v as u64 == SCHED_OTHER | SCHED_RESET_ON_FORK => Ok(()),
            _ => Err("sched_getscheduler must OR SCHED_RESET_ON_FORK back in"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setscheduler_reset_on_fork_pos
);

fn smoke_abi_sched_setscheduler_bad_policy_neg() -> TestResult {
    with_setup(|| {
        // Policy 42 is unknown ⇒ EINVAL — with a VALID param, so the
        // answer is about the policy and not the NULL-param guard.
        let zero = 0i32.to_ne_bytes();
        match call(
            Syscall::SchedSetScheduler.raw(),
            a3(0, 42, zero.as_ptr() as u64, 0),
        ) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("sched_setscheduler bad policy should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setscheduler_bad_policy_neg);

// ── sched_rr_get_interval(pid, timespec*) ───────────────────────────
// A SCHED_OTHER task's default slice is under one jiffy ⇒ {0, 0}.

fn smoke_abi_sched_rr_get_interval_pos() -> TestResult {
    with_setup(|| {
        let mut ts = [0xFFu8; 16];
        let args = a1(0, ts.as_mut_ptr() as u64);
        match call(Syscall::SchedRrGetInterval.raw(), args) {
            Some(0) => {
                let sec = u64::from_ne_bytes(ts[..8].try_into().unwrap());
                let nsec = u64::from_ne_bytes(ts[8..].try_into().unwrap());
                if sec == 0 && nsec == 0 {
                    Ok(())
                } else {
                    Err("sched_rr_get_interval should write {0, 0}")
                }
            }
            _ => Err("sched_rr_get_interval should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_rr_get_interval_pos);

fn smoke_abi_sched_rr_get_interval_bad_ptr_neg() -> TestResult {
    with_setup(|| {
        // Non-canonical timespec pointer ⇒ put_timespec64's copy_to_user
        // faults ⇒ -EFAULT.
        match call(Syscall::SchedRrGetInterval.raw(), a1(0, BAD_PTR)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("sched_rr_get_interval with a bad pointer should return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_rr_get_interval_bad_ptr_neg);

// ── sched_setattr(pid, attr*, flags) ────────────────────────────────
// attr* is a struct whose first u32 is the declared size (>= 48).

fn smoke_abi_sched_setattr_pos() -> TestResult {
    with_setup(|| {
        let mut attr = [0u8; 48];
        // First u32 = declared size (48).
        attr[..4].copy_from_slice(&48u32.to_le_bytes());
        let args = a3(0, attr.as_ptr() as u64, 0, 0);
        match call(Syscall::SchedSetattr.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("sched_setattr with valid attr should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setattr_pos);

fn smoke_abi_sched_setattr_nonzero_flags_neg() -> TestResult {
    with_setup(|| {
        let mut attr = [0u8; 48];
        attr[..4].copy_from_slice(&48u32.to_le_bytes());
        // flags must be 0; arg2 = 1 ⇒ EINVAL.
        let args = a3(0, attr.as_ptr() as u64, 1, 0);
        match call(Syscall::SchedSetattr.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("sched_setattr with non-zero flags should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setattr_nonzero_flags_neg);

/// `-E2BIG` for an unusable size, not `-EINVAL` — and the required size is
/// written BACK into the caller's `size` field.
///
/// `sched_copy_attr`'s `err_size` label:
///
/// ```text
/// err_size:
///         put_user(sizeof(*attr), &uattr->size);
///         return -E2BIG;
/// ```
///
/// This case previously asserted -EINVAL, which is what `mnt_id_req` and
/// `ns_id_req` answer — `sched_attr` is the odd one out. The write-back is
/// the half that matters in practice: it is the only way a caller compiled
/// against a different struct version learns what this kernel wants, and
/// without it a too-small caller can only guess.
fn smoke_abi_sched_setattr_short_size_neg() -> TestResult {
    with_setup(|| {
        let mut attr = [0u8; 48];
        attr[..4].copy_from_slice(&16u32.to_le_bytes());
        let args = a3(0, attr.as_ptr() as u64, 0, 0);
        if call(Syscall::SchedSetattr.raw(), args) != Some(E2BIG) {
            return Err("sched_setattr with an undersized struct must be -E2BIG");
        }
        if u32::from_ne_bytes(attr[..4].try_into().unwrap()) != 48 {
            return Err("sched_setattr must write the required size back on -E2BIG");
        }
        // Above PAGE_SIZE takes the same label, so the same two answers.
        attr[..4].copy_from_slice(&5000u32.to_le_bytes());
        if call(Syscall::SchedSetattr.raw(), args) != Some(E2BIG) {
            return Err("sched_setattr past PAGE_SIZE must be -E2BIG");
        }
        if u32::from_ne_bytes(attr[..4].try_into().unwrap()) != 48 {
            return Err("the oversize path must write the required size back too");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setattr_short_size_neg);

/// A size of ZERO means `SCHED_ATTR_SIZE_VER0` — the documented quirk.
///
/// `/* ABI compatibility quirk: */ if (!size) size = SCHED_ATTR_SIZE_VER0;`
/// A caller that zeroes the whole struct and fills in only the fields it
/// cares about never sets `size`, and Linux accepts that. Treating it as
/// "too small" refuses exactly those callers.
fn smoke_abi_sched_setattr_zero_size_means_ver0() -> TestResult {
    with_setup(|| {
        let attr = [0u8; 48];
        let args = a3(0, attr.as_ptr() as u64, 0, 0);
        if call(Syscall::SchedSetattr.raw(), args) != Some(0) {
            return Err("sched_setattr with size 0 must be accepted as VER0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setattr_zero_size_means_ver0);

/// A struct larger than this kernel knows is accepted only if its tail is
/// ZERO; a field set beyond VER0 is `-E2BIG`.
///
/// This is the whole point of the extensible-struct rule, and the failure it
/// prevents is silent: truncating instead would discard a field the caller
/// set and believes is in effect. A VER1 caller asking for util clamping
/// would think it got it.
fn smoke_abi_sched_setattr_rejects_set_fields_past_ver0() -> TestResult {
    with_setup(|| {
        // VER1-sized, tail all zero: accepted, because nothing was asked for.
        let mut attr = [0u8; 56];
        attr[..4].copy_from_slice(&56u32.to_le_bytes());
        let args = a3(0, attr.as_ptr() as u64, 0, 0);
        if call(Syscall::SchedSetattr.raw(), args) != Some(0) {
            return Err("a larger struct with a zero tail must be accepted");
        }
        // Same size, but a byte set past VER0: refused rather than dropped.
        attr[48] = 1;
        if call(Syscall::SchedSetattr.raw(), args) != Some(E2BIG) {
            return Err("a field set past the known struct must be -E2BIG, not truncated");
        }
        if u32::from_ne_bytes(attr[..4].try_into().unwrap()) != 48 {
            return Err("the tail-check path must write the required size back");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setattr_rejects_set_fields_past_ver0
);

/// Target and flag validation: a negative pid, a pid that names nothing,
/// an out-of-range policy, and flags no kernel defines.
///
/// The ESRCH half matters beyond tidiness: without it, attributes are
/// recorded against a pid nobody can see, and `sched_getattr` then answers
/// for a process that does not exist.
fn smoke_abi_sched_setattr_target_and_flags_neg() -> TestResult {
    with_setup(|| {
        let mut attr = [0u8; 48];
        attr[..4].copy_from_slice(&48u32.to_le_bytes());
        let p = attr.as_ptr() as u64;

        // `if (unlikely(!uattr || pid < 0 || flags)) return -EINVAL;`
        if call(Syscall::SchedSetattr.raw(), a3((-1i64) as u64, p, 0, 0)) != Some(EINVAL) {
            return Err("a negative pid must be -EINVAL");
        }
        // A pid that names no task.
        if call(Syscall::SchedSetattr.raw(), a3(0x7f00_0001, p, 0, 0)) != Some(ESRCH) {
            return Err("a pid that names no task must be -ESRCH");
        }
        // `if ((int)attr.sched_policy < 0) return -EINVAL;` — the cast is
        // load-bearing: sched_policy is a __u32.
        attr[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        if call(Syscall::SchedSetattr.raw(), a3(0, p, 0, 0)) != Some(EINVAL) {
            return Err("a policy that is negative as a signed int must be -EINVAL");
        }
        attr[4..8].copy_from_slice(&0u32.to_le_bytes());
        // A flag outside SCHED_FLAG_ALL.
        attr[8..16].copy_from_slice(&0x8000u64.to_le_bytes());
        if call(Syscall::SchedSetattr.raw(), a3(0, p, 0, 0)) != Some(EINVAL) {
            return Err("a flag no kernel defines must be -EINVAL");
        }
        // SCHED_FLAG_UTIL_CLAMP needs VER1, which this kernel does not
        // publish — -EINVAL, not the -E2BIG the size checks give, because
        // the size was fine and the combination was not.
        attr[8..16].copy_from_slice(&0x20u64.to_le_bytes());
        if call(Syscall::SchedSetattr.raw(), a3(0, p, 0, 0)) != Some(EINVAL) {
            return Err("SCHED_FLAG_UTIL_CLAMP below VER1 must be -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setattr_target_and_flags_neg);

// ── sched_getattr(pid, attr*, size, flags) ──────────────────────────

fn smoke_abi_sched_getattr_pos() -> TestResult {
    with_setup(|| {
        let mut attr = [0u8; 48];
        // arg2 = buffer size (48), arg3 = flags (0).
        let args = a3(0, attr.as_mut_ptr() as u64, 48, 0);
        match call(Syscall::SchedGetattr.raw(), args) {
            Some(0) => {
                // The kernel reports the real struct size in the first word.
                if u32::from_le_bytes(attr[..4].try_into().unwrap()) == 48 {
                    Ok(())
                } else {
                    Err("sched_getattr should report size 48 in first word")
                }
            }
            _ => Err("sched_getattr should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getattr_pos);

fn smoke_abi_sched_getattr_short_size_neg() -> TestResult {
    with_setup(|| {
        let mut attr = [0u8; 48];
        let p = attr.as_mut_ptr() as u64;
        // `usize < SCHED_ATTR_SIZE_VER0` — -EINVAL here, where the SETTER
        // answers -E2BIG. The setter negotiates about a struct the caller
        // wrote and can rewrite; the getter is handed a buffer, and one too
        // small for the first published version is just a bad argument.
        if call(Syscall::SchedGetattr.raw(), a3(0, p, 16, 0)) != Some(EINVAL) {
            return Err("sched_getattr with an undersized buffer must be -EINVAL");
        }
        if call(Syscall::SchedGetattr.raw(), a3(0, p, 5000, 0)) != Some(EINVAL) {
            return Err("sched_getattr past PAGE_SIZE must be -EINVAL");
        }
        if call(Syscall::SchedGetattr.raw(), a3((-1i64) as u64, p, 48, 0)) != Some(EINVAL) {
            return Err("sched_getattr with a negative pid must be -EINVAL");
        }
        if call(Syscall::SchedGetattr.raw(), a3(0x7f00_0001, p, 48, 0)) != Some(ESRCH) {
            return Err("sched_getattr for a pid that names no task must be -ESRCH");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getattr_short_size_neg);

/// A buffer larger than the struct must have its TAIL ZEROED.
///
/// `copy_struct_to_user`: `if (usize > ksize) clear_user(dst + size, rest);`
/// Leaving it alone hands the caller back whatever was already in its own
/// buffer as though the kernel had written it — a VER1 caller reads its own
/// stack garbage as `sched_util_min`/`sched_util_max` and cannot tell.
/// `size` reports what was actually filled in, which is how it knows where
/// the real data stops.
fn smoke_abi_sched_getattr_zeroes_the_tail() -> TestResult {
    with_setup(|| {
        // Poison the whole buffer first: zeroing it here would make the
        // assertion below vacuous.
        let mut attr = [0xAAu8; 64];
        let p = attr.as_mut_ptr() as u64;
        if call(Syscall::SchedGetattr.raw(), a3(0, p, 64, 0)) != Some(0) {
            return Err("sched_getattr with a larger buffer should succeed");
        }
        if u32::from_ne_bytes(attr[..4].try_into().unwrap()) != 48 {
            return Err("sched_getattr must report how much of the buffer it filled");
        }
        if attr[48..64].iter().any(|&b| b != 0) {
            return Err("sched_getattr left the caller's tail holding its own stale bytes");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getattr_zeroes_the_tail);

// ── membarrier(cmd, flags, cpu_id) ──────────────────────────────────
//
// `kernel/sched/membarrier.c`. The expedited commands are a rendezvous, so
// the interesting assertions are the ones a no-op handler fails: that
// `flags` is read at all, that an unregistered address space is refused,
// and that registration is visible afterwards.
//
// Every command below except QUERY / GLOBAL reads `current->mm`, and the
// ABI harness deliberately starts each test with none — hence the explicit
// `install_test_address_space()`. It hands out a FRESH address space per
// test, which is what keeps the "unregistered ⇒ EPERM" case independent of
// registry order.

const MB_QUERY: u64 = 0;
const MB_GLOBAL: u64 = 1 << 0;
const MB_GLOBAL_EXPEDITED: u64 = 1 << 1;
const MB_REGISTER_GLOBAL_EXPEDITED: u64 = 1 << 2;
const MB_PRIVATE_EXPEDITED: u64 = 1 << 3;
const MB_REGISTER_PRIVATE_EXPEDITED: u64 = 1 << 4;
const MB_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 1 << 5;
const MB_PRIVATE_EXPEDITED_RSEQ: u64 = 1 << 7;
const MB_GET_REGISTRATIONS: u64 = 1 << 9;
const MB_FLAG_CPU: u64 = 1 << 0;

/// The mask this configuration must report: every command except QUERY,
/// minus the SYNC_CORE and RSEQ pairs (no `sync_core_before_usermode`, and
/// `rseq(2)` is -ENOSYS). Matches Linux's `MEMBARRIER_CMD_BITMASK` with
/// both CONFIGs off.
const MB_SUPPORTED: u64 = MB_GLOBAL
    | MB_GLOBAL_EXPEDITED
    | MB_REGISTER_GLOBAL_EXPEDITED
    | MB_PRIVATE_EXPEDITED
    | MB_REGISTER_PRIVATE_EXPEDITED
    | MB_GET_REGISTRATIONS;

fn membarrier(cmd: u64, flags: u64) -> Option<i64> {
    call(Syscall::Membarrier.raw(), a1(cmd, flags))
}

fn smoke_abi_sched_membarrier_query_pos() -> TestResult {
    with_setup(|| {
        // QUERY answers the supported-command bitmask — and answers 0 when
        // the cross-CPU rendezvous is unavailable, rather than advertising
        // barriers this kernel cannot deliver.
        let expect = if narf_lib::smp::remote_barrier_available() {
            MB_SUPPORTED as i64
        } else {
            0
        };
        match membarrier(MB_QUERY, 0) {
            Some(v) if v == expect => {}
            _ => return Err("membarrier QUERY reported the wrong supported mask"),
        }
        // The two unsupported pairs must be absent from the mask AND
        // rejected when issued — Linux's CONFIG-off shape. A mask that
        // advertised them would send a JIT down a path that never
        // serializes.
        if expect as u64 & (MB_PRIVATE_EXPEDITED_SYNC_CORE | MB_PRIVATE_EXPEDITED_RSEQ) != 0 {
            return Err("QUERY advertised SYNC_CORE/RSEQ, which are not implemented");
        }
        for cmd in [MB_PRIVATE_EXPEDITED_SYNC_CORE, MB_PRIVATE_EXPEDITED_RSEQ] {
            match membarrier(cmd, 0) {
                Some(v) if v == EINVAL => {}
                _ => return Err("an unadvertised membarrier command must be -EINVAL"),
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_membarrier_query_pos);

fn smoke_abi_sched_membarrier_bad_cmd_neg() -> TestResult {
    with_setup(|| {
        // Not a defined command bit at all.
        match membarrier(0x4000, 0) {
            Some(v) if v == EINVAL => {}
            _ => return Err("membarrier with unsupported cmd should return -EINVAL"),
        }
        // Two supported bits OR'd together is still not a command: Linux
        // switches on the value, it does not test bits, so this lands in
        // `default:`. A handler that masked instead would accept it.
        match membarrier(MB_GLOBAL | MB_PRIVATE_EXPEDITED, 0) {
            Some(v) if v == EINVAL => {}
            _ => return Err("a combination of two command bits must be -EINVAL"),
        }
        // Negative cmd — `int cmd` is signed and nothing below QUERY exists.
        match membarrier((-1i64) as u64, 0) {
            Some(v) if v == EINVAL => {}
            _ => return Err("a negative membarrier cmd must be -EINVAL"),
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_membarrier_bad_cmd_neg);

fn smoke_abi_sched_membarrier_rejects_flags() -> TestResult {
    with_setup(|| {
        if !narf_lib::smp::remote_barrier_available() {
            return Ok(());
        }
        // `flags` used to be read by nothing: every one of these was a
        // success. Linux validates per-command BEFORE dispatching, and only
        // PRIVATE_EXPEDITED_RSEQ tolerates a non-zero value.
        for cmd in [
            MB_GLOBAL,
            MB_GLOBAL_EXPEDITED,
            MB_REGISTER_GLOBAL_EXPEDITED,
            MB_PRIVATE_EXPEDITED,
            MB_REGISTER_PRIVATE_EXPEDITED,
            MB_GET_REGISTRATIONS,
        ] {
            for flags in [MB_FLAG_CPU, 0xDEAD_BEEF] {
                match membarrier(cmd, flags) {
                    Some(v) if v == EINVAL => {}
                    _ => return Err("membarrier with non-zero flags must be -EINVAL"),
                }
            }
        }
        // QUERY is not exempt from the flags rule either.
        match membarrier(MB_QUERY, 1) {
            Some(v) if v == EINVAL => {}
            _ => return Err("membarrier QUERY with flags set must be -EINVAL"),
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_membarrier_rejects_flags);

fn smoke_abi_sched_membarrier_registration_gates_expedited() -> TestResult {
    with_setup(|| {
        if !narf_lib::smp::remote_barrier_available() {
            return Ok(());
        }
        install_test_address_space()?;

        // Fresh address space: nothing registered, so GET_REGISTRATIONS is
        // empty and PRIVATE_EXPEDITED is refused. Linux returns -EPERM for
        // an mm without MEMBARRIER_STATE_PRIVATE_EXPEDITED_READY; returning
        // 0 here is the failure mode this whole test exists to catch.
        match membarrier(MB_GET_REGISTRATIONS, 0) {
            Some(0) => {}
            _ => return Err("a fresh address space must report no registrations"),
        }
        match membarrier(MB_PRIVATE_EXPEDITED, 0) {
            Some(v) if v == EPERM => {}
            _ => return Err("PRIVATE_EXPEDITED without registration must be -EPERM"),
        }

        // Register, and the same call must now succeed. Together with the
        // -EPERM above this pins BOTH directions: a registration that did
        // nothing would leave this -EPERM, and a missing gate would have
        // made the -EPERM above a 0.
        match membarrier(MB_REGISTER_PRIVATE_EXPEDITED, 0) {
            Some(0) => {}
            _ => return Err("REGISTER_PRIVATE_EXPEDITED should succeed"),
        }
        match membarrier(MB_PRIVATE_EXPEDITED, 0) {
            Some(0) => {}
            _ => return Err("PRIVATE_EXPEDITED after registration should succeed"),
        }
        match membarrier(MB_GET_REGISTRATIONS, 0) {
            Some(v) if v == MB_REGISTER_PRIVATE_EXPEDITED as i64 => {}
            _ => return Err("GET_REGISTRATIONS should report the private registration"),
        }

        // Registration is idempotent, and the global one is tracked
        // separately — GET_REGISTRATIONS reports the OR of both.
        match membarrier(MB_REGISTER_PRIVATE_EXPEDITED, 0) {
            Some(0) => {}
            _ => return Err("re-registering should be a no-op success"),
        }
        match membarrier(MB_REGISTER_GLOBAL_EXPEDITED, 0) {
            Some(0) => {}
            _ => return Err("REGISTER_GLOBAL_EXPEDITED should succeed"),
        }
        let both = (MB_REGISTER_PRIVATE_EXPEDITED | MB_REGISTER_GLOBAL_EXPEDITED) as i64;
        match membarrier(MB_GET_REGISTRATIONS, 0) {
            Some(v) if v == both => {}
            _ => return Err("GET_REGISTRATIONS should report both registrations"),
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_membarrier_registration_gates_expedited
);

fn smoke_abi_sched_membarrier_global_needs_no_mm() -> TestResult {
    with_setup(|| {
        if !narf_lib::smp::remote_barrier_available() {
            return Ok(());
        }
        // GLOBAL and GLOBAL_EXPEDITED never read `current->mm` in Linux, and
        // GLOBAL needs no registration — that is the property distinguishing
        // it from GLOBAL_EXPEDITED. The harness installs no address space,
        // so this also proves the handler does not demand one.
        for cmd in [MB_GLOBAL, MB_GLOBAL_EXPEDITED] {
            match membarrier(cmd, 0) {
                Some(0) => {}
                _ => return Err("GLOBAL/GLOBAL_EXPEDITED should succeed without an mm"),
            }
        }
        // The mm-backed commands, by contrast, must report the missing
        // address space rather than quietly succeeding.
        for cmd in [
            MB_PRIVATE_EXPEDITED,
            MB_REGISTER_PRIVATE_EXPEDITED,
            MB_GET_REGISTRATIONS,
        ] {
            match membarrier(cmd, 0) {
                Some(-12) => {}
                _ => return Err("an mm-backed membarrier command needs an address space"),
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_membarrier_global_needs_no_mm);

fn smoke_abi_sched_membarrier_rendezvous_reaches_peers() -> TestResult {
    with_setup(|| {
        // The barrier itself. On a uniprocessor there is no peer and
        // `remote_barrier` is vacuously true; on SMP it must interrupt every
        // online peer and collect an acknowledgement from each, so the
        // handler-side counter has to move. A no-op barrier — the bug this
        // replaces — leaves it exactly where it was.
        let targets = narf_lib::smp::online_bitmap();
        let peers = targets & !(1u64 << narf_lib::percpu::current_cpu());
        let before = narf_lib::smp::barrier_serviced_count();
        if !narf_lib::smp::remote_barrier(targets) {
            if narf_lib::smp::remote_barrier_available() {
                return Err("remote_barrier failed while reporting itself available");
            }
            return Ok(());
        }
        if peers != 0 && narf_lib::smp::barrier_serviced_count() == before {
            return Err("remote_barrier returned without any peer servicing it");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_membarrier_rendezvous_reaches_peers
);

// ── set_robust_list(head*, len) / get_robust_list(pid, head**, len*) ─
// Round-trip: set_robust_list stores (head, len); get_robust_list reads
// them back. set_robust_list has no reachable error (always ok(0)).

fn smoke_abi_sched_set_robust_list_pos() -> TestResult {
    with_setup(|| {
        // Register an arbitrary head pointer + len; always ok(0).
        match call(Syscall::SetRobustList.raw(), a1(0xCAFE_0000, 24)) {
            Some(0) => Ok(()),
            _ => Err("set_robust_list should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_set_robust_list_pos);

fn smoke_abi_sched_get_robust_list_pos() -> TestResult {
    with_setup(|| {
        // First register a head/len, then read it back.
        match call(Syscall::SetRobustList.raw(), a1(0xCAFE_0000, 24)) {
            Some(0) => {}
            _ => return Err("set_robust_list precondition should return 0"),
        }
        let mut head = [0u8; 8];
        let mut len = [0u8; 8];
        let args = a3(0, head.as_mut_ptr() as u64, len.as_mut_ptr() as u64, 0);
        match call(Syscall::GetRobustList.raw(), args) {
            Some(0) => {
                let h = u64::from_ne_bytes(head);
                let l = u64::from_ne_bytes(len);
                if h == 0xCAFE_0000 && l == 24 {
                    Ok(())
                } else {
                    Err("get_robust_list should read back the registered head/len")
                }
            }
            _ => Err("get_robust_list should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_get_robust_list_pos);

fn smoke_abi_sched_get_robust_list_bad_head_neg() -> TestResult {
    with_setup(|| {
        // Non-canonical head out-pointer ⇒ copy_to_user EFAULT.
        let args = a3(0, BAD_PTR, 0, 0);
        match call(Syscall::GetRobustList.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("get_robust_list with bad head pointer should return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_get_robust_list_bad_head_neg);

// ── rseq(rseq*, len, flags, sig) ────────────────────────────────────
// NARF does not implement restartable-sequence registration or migration
// aborts. Report ENOSYS so libc uses its non-rseq fallback instead of trusting
// an ABI area the kernel never maintains.

fn smoke_abi_sched_rseq_unimplemented() -> TestResult {
    with_setup(
        || match call(Syscall::Rseq.raw(), a3(0xBEEF_0000, 32, 0, 0x53053053)) {
            Some(ENOSYS) => Ok(()),
            _ => Err("unimplemented rseq must return -ENOSYS"),
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_sched_rseq_unimplemented);

// ── sched_yield() ───────────────────────────────────────────────────
// Returns ok(0) whether or not another runnable task exists; no error path (no
// signal pending for FAKE_TASK in the harness). The sole-runnable fast path is
// observable only as avoided scheduling work, never as a different return.

fn smoke_abi_sched_yield_pos() -> TestResult {
    with_setup(|| match call(Syscall::Yield.raw(), a0(0)) {
        Some(0) => Ok(()),
        _ => Err("sched_yield should return 0"),
    })
}
kernel_test_in!("syscall_abi/sched_yield", smoke_abi_sched_yield_pos);

// A pending signal does not interrupt sched_yield. Linux completes the yield
// with return value 0, then delivers the signal from the common return-to-user
// path. In particular, SA_RESTART must not replay an already-completed yield.
// This exercises the real `syscall`-instruction entry with a UserState snapshot
// so the completion hook can build the signal frame.
#[cfg(target_arch = "x86_64")]
fn smoke_abi_sched_yield_pending_signal_still_returns_zero() -> TestResult {
    with_setup(|| {
        let task = FAKE_TASK;
        crate::handlers::__test_set_sigaction_flags(
            task,
            10,
            0xDEAD_BEEF,
            crate::handlers::SA_RESTART | crate::handlers::SA_NODEFER,
        );
        crate::handlers::raise_signal_pending(task, 10);

        let mut user_stack = [0u8; 512];
        let mut state = narf_scheduler::UserState {
            rax: Syscall::Yield.raw() as u64,
            rip: 0x4000,
            rflags: 0x202,
            rsp: user_stack.as_mut_ptr() as u64 + user_stack.len() as u64,
            valid: 1,
            ..Default::default()
        };
        let ret = crate::kernel_syscall_entry_plain_with_state(
            Syscall::Yield.raw(),
            &SyscallArgs::default(),
            &mut state as *mut _ as *mut u8,
        );

        if ret.status != SyscallReturn::OK || ret.value != 0 {
            return Err("pending signal interrupted sched_yield instead of returning 0");
        }
        if state.rip != 0xDEAD_BEEF {
            return Err("pending signal was not delivered after sched_yield completed");
        }
        Ok(())
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "syscall_abi/sched_yield",
    smoke_abi_sched_yield_pending_signal_still_returns_zero
);

// ─────────────────────────────────────────────────────────────────────
// PRIO_PGRP / PRIO_USER and IOPRIO_WHO_PGRP / IOPRIO_WHO_USER
//
// All four syscalls take a (which, who) pair and all four had the group
// and user scopes unimplemented, taking -EINVAL. They differ only in the
// numbers they use for the three cases, so the selection is one shared
// resolver — the same root-cause shape as the rest of this audit.
// ─────────────────────────────────────────────────────────────────────

const WHO_ESRCH: i64 = -3;
const WHO_EINVAL: i64 = -22;
const PRIO_PROCESS_W: u64 = 0;
const PRIO_PGRP_W: u64 = 1;
const PRIO_USER_W: u64 = 2;
const IOPRIO_WHO_PROCESS_W: u64 = 1;
const IOPRIO_WHO_PGRP_W: u64 = 2;
const IOPRIO_WHO_USER_W: u64 = 3;

fn smoke_abi_sched_getpriority_scopes_are_implemented() -> TestResult {
    with_setup(|| {
        // All three scopes must resolve; only a `which` outside
        // [PRIO_PROCESS, PRIO_USER] is -EINVAL. `who == 0` means the
        // caller's own process / group / real uid.
        for which in [PRIO_PROCESS_W, PRIO_PGRP_W, PRIO_USER_W] {
            match call(Syscall::Getpriority.raw(), a1(which, 0)) {
                // nice_to_rlimit(0) == 20 for the default nice.
                Some(20) => {}
                Some(v) if v == WHO_EINVAL => {
                    return Err("a PRIO_* scope is still unimplemented (-EINVAL)")
                }
                _ => return Err("getpriority(scope, 0) should report the caller's nice"),
            }
        }
        match call(Syscall::Getpriority.raw(), a1(9, 0)) {
            Some(v) if v == WHO_EINVAL => Ok(()),
            _ => Err("getpriority with an out-of-range which should be -EINVAL"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_getpriority_scopes_are_implemented
);

fn smoke_abi_sched_getpriority_group_reports_the_most_favoured() -> TestResult {
    with_setup(|| {
        // `if (niceval > retval) retval = niceval;` over the group, where
        // niceval is `20 - nice`. So the answer is the MAXIMUM wire value,
        // i.e. the numerically LOWEST nice — the most favoured member.
        // Taking the minimum would describe the group as less favoured
        // than it actually is.
        //
        // Renice the caller to 5, then check the group answer tracks the
        // best member rather than the last one visited.
        if call(Syscall::Setpriority.raw(), a2(PRIO_PROCESS_W, 0, 5)) != Some(0) {
            return Err("setpriority setup failed");
        }
        match call(Syscall::Getpriority.raw(), a1(PRIO_PGRP_W, 0)) {
            Some(15) => Ok(()), // 20 - 5
            Some(v) if v == WHO_ESRCH => Err("PRIO_PGRP found no tasks in the caller's own group"),
            _ => Err("getpriority(PRIO_PGRP) did not report the group's best nice"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_getpriority_group_reports_the_most_favoured
);

fn smoke_abi_sched_setpriority_group_applies_to_the_caller() -> TestResult {
    with_setup(|| {
        // A group renice must actually reach its members. The caller is in
        // its own group, so PRIO_PGRP with who == 0 includes it.
        if call(Syscall::Setpriority.raw(), a2(PRIO_PGRP_W, 0, 7)) != Some(0) {
            return Err("setpriority(PRIO_PGRP, 0) failed");
        }
        match call(Syscall::Getpriority.raw(), a1(PRIO_PROCESS_W, 0)) {
            Some(13) => Ok(()), // 20 - 7
            _ => Err("a PRIO_PGRP renice did not reach the caller"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setpriority_group_applies_to_the_caller
);

fn smoke_abi_sched_setpriority_unmatched_user_is_esrch() -> TestResult {
    with_setup(|| {
        // `error = -ESRCH` and only a visited task clears it. A uid that
        // owns no task leaves it, which is how a caller learns nothing was
        // renamed rather than believing it succeeded.
        match call(Syscall::Setpriority.raw(), a2(PRIO_USER_W, 4242, 5)) {
            Some(v) if v == WHO_ESRCH => Ok(()),
            Some(0) => Err("setpriority(PRIO_USER, unowned uid) reported success"),
            _ => Err("setpriority for a uid owning no task should be -ESRCH"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setpriority_unmatched_user_is_esrch
);

fn smoke_abi_sched_ioprio_scopes_share_one_per_task_value() -> TestResult {
    with_setup(|| {
        // The table used to be keyed by the `(which, who)` tuple, so the
        // three scopes were disjoint stores rather than three views of one
        // value: a WHO_PROCESS set was invisible to a WHO_PGRP get over
        // the same process. Linux keeps ioprio in the task, and `which`
        // only selects which tasks to visit.
        const PRIO: u64 = (1u64 << 13) | 3; // IOPRIO_CLASS_RT, level 3
        if call(Syscall::IoprioSet.raw(), a2(IOPRIO_WHO_PROCESS_W, 0, PRIO)) != Some(0) {
            return Err("ioprio_set(WHO_PROCESS, 0) failed");
        }
        // Read it back through a DIFFERENT scope covering the same task.
        match call(Syscall::IoprioGet.raw(), a1(IOPRIO_WHO_PGRP_W, 0)) {
            Some(v) if v as u64 == PRIO => {}
            Some(v) if v as u64 == (2u64 << 13) | 4 => {
                return Err("WHO_PGRP read the default — the scopes are still separate stores")
            }
            _ => return Err("ioprio_get(WHO_PGRP) did not see the per-task value"),
        }
        match call(Syscall::IoprioGet.raw(), a1(IOPRIO_WHO_USER_W, 0)) {
            Some(v) if v as u64 == PRIO => Ok(()),
            _ => Err("ioprio_get(WHO_USER) did not see the per-task value"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_ioprio_scopes_share_one_per_task_value
);

fn smoke_abi_sched_clone_io_shares_context_fork_copies() -> TestResult {
    with_setup(|| {
        const PARENT: u64 = 0xC1_10;
        const SHARED: u64 = 0xC1_11;
        const COPIED: u64 = 0xC1_12;
        const INITIAL: u32 = (2 << 13) | 3;
        const UPDATED: u32 = (3 << 13) | 7;

        crate::handlers::ioprio_init();
        crate::handlers::__test_ioprio_set_task(PARENT, INITIAL);
        crate::handlers::__test_ioprio_fork(PARENT, SHARED, true);
        crate::handlers::__test_ioprio_fork(PARENT, COPIED, false);
        crate::handlers::__test_ioprio_set_task(SHARED, UPDATED);

        if crate::handlers::__test_ioprio_of_task(PARENT) != UPDATED {
            return Err("CLONE_IO child did not share the parent's io_context");
        }
        if crate::handlers::__test_ioprio_of_task(COPIED) != INITIAL {
            return Err("ordinary fork did not retain an independent io_context copy");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_clone_io_shares_context_fork_copies
);

fn smoke_abi_sched_ioprio_set_rejects_a_bad_class() -> TestResult {
    with_setup(|| {
        // `ioprio_check_cap(ioprio)` runs FIRST, before the `which`
        // switch, so a bad class beats a `who` that names nothing.
        let bad_class = 9u64 << 13;
        match call(
            Syscall::IoprioSet.raw(),
            a2(IOPRIO_WHO_USER_W, 4242, bad_class),
        ) {
            Some(v) if v == WHO_EINVAL => Ok(()),
            Some(v) if v == WHO_ESRCH => {
                Err("ioprio_set selected tasks before validating the class")
            }
            _ => Err("ioprio_set with an undefined class should be -EINVAL"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_ioprio_set_rejects_a_bad_class
);

fn smoke_abi_sched_setparam_arg_errors() -> TestResult {
    with_setup(|| {
        // `if (!param || pid < 0) return -EINVAL;` — one guard, before the
        // copy and before the pid lookup, so a null param outranks a pid
        // that names nothing.
        if call(Syscall::SchedSetparam.raw(), a1(0, 0)) != Some(EINVAL) {
            return Err("sched_setparam(null param) should be -EINVAL");
        }
        let zero = 0i32.to_ne_bytes();
        if call(
            Syscall::SchedSetparam.raw(),
            a1((-1i64) as u64, zero.as_ptr() as u64),
        ) != Some(EINVAL)
        {
            return Err("sched_setparam(negative pid) should be -EINVAL");
        }
        if call(Syscall::SchedSetparam.raw(), a1(123456, 0)) != Some(EINVAL) {
            return Err("a null param must outrank a pid that names nothing");
        }
        // Past the guard: a pid naming no task is -ESRCH.
        if call(
            Syscall::SchedSetparam.raw(),
            a1(123456, zero.as_ptr() as u64),
        ) != Some(-3)
        {
            return Err("sched_setparam on an unknown pid should be -ESRCH");
        }
        // And a faulting param is -EFAULT, after the null/pid guard.
        match call(Syscall::SchedSetparam.raw(), a1(0, BAD_PTR)) {
            Some(-14) => Ok(()),
            _ => Err("sched_setparam with an unmapped param should be -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setparam_arg_errors);

// ─────────────────────────────────────────────────────────────────────
// Scheduling-policy parity (`kernel/sched/syscalls.c`)
//
// Every setter funnels into `__sched_setscheduler`, and every case below
// is one of its arms, taken in Linux's order. Before this block
// `sched_getscheduler` hard-coded SCHED_OTHER, `sched_setscheduler`
// accepted a NULL param and never read a priority, and `sched_getattr`
// replayed stored bytes — so none of these answers were reachable.
// ─────────────────────────────────────────────────────────────────────

const SCHED_RESET_ON_FORK_W: u64 = 0x4000_0000;
const SCHED_FLAG_RESET_ON_FORK_W: u64 = 0x01;
const SCHED_FLAG_KEEP_POLICY_W: u64 = 0x08;
const SCHED_FLAG_KEEP_PARAMS_W: u64 = 0x10;
const SCHED_FLAG_UTIL_CLAMP_MIN_W: u64 = 0x20;
const SCHED_FLAG_SUGOV_W: u64 = 0x1000_0000;
const RLIMIT_RTPRIO_W: u64 = 14;

/// A VER0 `struct sched_attr`.
#[allow(clippy::too_many_arguments)]
fn sched_attr(
    policy: u32,
    flags: u64,
    nice: i32,
    priority: u32,
    runtime: u64,
    deadline: u64,
    period: u64,
) -> [u8; 48] {
    let mut b = [0u8; 48];
    b[0..4].copy_from_slice(&48u32.to_ne_bytes());
    b[4..8].copy_from_slice(&policy.to_ne_bytes());
    b[8..16].copy_from_slice(&flags.to_ne_bytes());
    b[16..20].copy_from_slice(&nice.to_ne_bytes());
    b[20..24].copy_from_slice(&priority.to_ne_bytes());
    b[24..32].copy_from_slice(&runtime.to_ne_bytes());
    b[32..40].copy_from_slice(&deadline.to_ne_bytes());
    b[40..48].copy_from_slice(&period.to_ne_bytes());
    b
}

fn setattr(pid: u64, attr: &[u8]) -> Option<i64> {
    call(
        Syscall::SchedSetattr.raw(),
        a3(pid, attr.as_ptr() as u64, 0, 0),
    )
}

fn getattr(pid: u64) -> Result<[u8; 48], &'static str> {
    let mut out = [0xAAu8; 48];
    match call(
        Syscall::SchedGetattr.raw(),
        a3(pid, out.as_mut_ptr() as u64, 48, 0),
    ) {
        Some(0) => Ok(out),
        _ => Err("sched_getattr should succeed"),
    }
}

fn attr_u32(b: &[u8; 48], off: usize) -> u32 {
    u32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
}

fn attr_u64(b: &[u8; 48], off: usize) -> u64 {
    u64::from_ne_bytes(b[off..off + 8].try_into().unwrap())
}

fn setscheduler(pid: u64, policy: u64, prio: i32) -> Option<i64> {
    let p = prio.to_ne_bytes();
    call(
        Syscall::SchedSetScheduler.raw(),
        a3(pid, policy, p.as_ptr() as u64, 0),
    )
}

fn getscheduler(pid: u64) -> Option<i64> {
    call(Syscall::SchedGetScheduler.raw(), a0(pid))
}

fn getparam(pid: u64) -> Option<i32> {
    let mut out = [0xFFu8; 4];
    match call(
        Syscall::SchedGetparam.raw(),
        a1(pid, out.as_mut_ptr() as u64),
    ) {
        Some(0) => Some(i32::from_ne_bytes(out)),
        _ => None,
    }
}

fn rr_interval_ns(pid: u64) -> Option<u64> {
    let mut ts = [0xFFu8; 16];
    match call(
        Syscall::SchedRrGetInterval.raw(),
        a1(pid, ts.as_mut_ptr() as u64),
    ) {
        Some(0) => {
            let sec = u64::from_ne_bytes(ts[..8].try_into().unwrap());
            let nsec = u64::from_ne_bytes(ts[8..].try_into().unwrap());
            Some(sec * 1_000_000_000 + nsec)
        }
        _ => None,
    }
}

fn set_rlimit(resource: u64, cur: u64, max: u64) -> Option<i64> {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&cur.to_ne_bytes());
    buf[8..].copy_from_slice(&max.to_ne_bytes());
    call(Syscall::Setrlimit.raw(), a1(resource, buf.as_ptr() as u64))
}

/// Register a live task owned by root (uid 0) — a "someone else's process"
/// once the harness task drops to an unprivileged uid.
fn register_foreign(task: u64) {
    crate::task::release_task(task);
    let _ = crate::task::Task::new_registered(task, task);
    crate::handlers::register_task_to_pid(task, task);
    crate::handlers::register_pid_task_mapping(task, task);
}

fn online_cpus() -> u32 {
    narf_scheduler::online_cpu_set().bits().count_ones().max(1)
}

// ── sched_setscheduler / sched_setparam argument guards ─────────────

fn smoke_abi_sched_setscheduler_arg_errors_in_linux_order() -> TestResult {
    with_setup(|| {
        let zero = 0i32.to_ne_bytes();
        let p = zero.as_ptr() as u64;
        let ss = |pid: u64, policy: u64, param: u64| {
            call(Syscall::SchedSetScheduler.raw(), a3(pid, policy, param, 0))
        };
        // `if (policy < 0) return -EINVAL;` — before the param is looked at.
        if ss(0, (-1i64) as u64, 0) != Some(EINVAL) {
            return Err("a negative policy must be -EINVAL");
        }
        // `if (!param || pid < 0) return -EINVAL;` — the case that used to
        // return 0 without reading anything.
        if ss(0, SCHED_OTHER, 0) != Some(EINVAL) {
            return Err("a NULL param must be -EINVAL, not success");
        }
        if ss((-1i64) as u64, SCHED_OTHER, p) != Some(EINVAL) {
            return Err("a negative pid must be -EINVAL");
        }
        // Then the copy: -EFAULT outranks a pid that names nothing.
        if ss(123456, SCHED_OTHER, BAD_PTR) != Some(EFAULT) {
            return Err("an unmapped param must be -EFAULT before the pid lookup");
        }
        if ss(123456, SCHED_OTHER, p) != Some(ESRCH) {
            return Err("a pid that names no task must be -ESRCH");
        }
        // `pid_t` / `int` are the low 32 bits of each register.
        if ss(
            0xFFFF_FFFF_0000_0000,
            0xdead_0000_0000_0000 | SCHED_OTHER,
            p,
        ) != Some(0)
        {
            return Err("sched_setscheduler must read pid/policy as 32-bit ints");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setscheduler_arg_errors_in_linux_order
);

fn smoke_abi_sched_setscheduler_policy_priority_agreement() -> TestResult {
    with_setup(|| {
        // "Valid priorities for SCHED_FIFO and SCHED_RR are 1..MAX_RT_PRIO-1,
        // valid priority for SCHED_NORMAL, SCHED_BATCH and SCHED_IDLE is 0."
        let cases: [(u64, i32, &str); 7] = [
            (SCHED_FIFO, 0, "SCHED_FIFO at priority 0 must be -EINVAL"),
            (SCHED_RR, 0, "SCHED_RR at priority 0 must be -EINVAL"),
            (SCHED_FIFO, 100, "an RT priority above 99 must be -EINVAL"),
            (SCHED_FIFO, -1, "a negative priority must be -EINVAL"),
            (
                SCHED_OTHER,
                1,
                "SCHED_OTHER with a non-zero priority must be -EINVAL",
            ),
            (
                SCHED_IDLE,
                5,
                "SCHED_IDLE with a non-zero priority must be -EINVAL",
            ),
            // A `sched_param` cannot carry runtime/deadline/period, so
            // SCHED_DEADLINE always fails `__checkparam_dl` here.
            (
                SCHED_DEADLINE,
                0,
                "SCHED_DEADLINE via sched_setscheduler must be -EINVAL",
            ),
        ];
        for (policy, prio, why) in cases {
            if setscheduler(0, policy, prio) != Some(EINVAL) {
                return Err(why);
            }
        }
        // Policies no kernel defines, and SCHED_EXT without
        // CONFIG_SCHED_CLASS_EXT — even though get_priority_max knows it.
        for policy in [4u64, 7, 8, 42] {
            if setscheduler(0, policy, 0) != Some(EINVAL) {
                return Err("an unsettable policy number must be -EINVAL");
            }
        }
        // None of the refusals changed anything.
        if getscheduler(0) != Some(0) {
            return Err("a refused sched_setscheduler changed the policy");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setscheduler_policy_priority_agreement
);

fn smoke_abi_sched_policy_round_trip_through_every_reader() -> TestResult {
    with_setup(|| {
        // SCHED_FIFO 10: every reader must agree.
        if setscheduler(0, SCHED_FIFO, 10) != Some(0) {
            return Err("privileged sched_setscheduler(SCHED_FIFO, 10) should succeed");
        }
        if getscheduler(0) != Some(SCHED_FIFO as i64) {
            return Err("sched_getscheduler did not report SCHED_FIFO");
        }
        if getparam(0) != Some(10) {
            return Err("sched_getparam did not report the RT priority");
        }
        let a = getattr(0)?;
        if attr_u32(&a, 4) != SCHED_FIFO as u32 || attr_u32(&a, 20) != 10 {
            return Err("sched_getattr did not report SCHED_FIFO / 10");
        }
        // `get_rr_interval_rt`: 0 for FIFO.
        if rr_interval_ns(0) != Some(0) {
            return Err("SCHED_FIFO has no round-robin quantum");
        }
        // sched_setparam now judges against FIFO: 0 is refused, 1..99 not.
        let zero = 0i32.to_ne_bytes();
        if call(Syscall::SchedSetparam.raw(), a1(0, zero.as_ptr() as u64)) != Some(EINVAL) {
            return Err("sched_setparam(0) on a SCHED_FIFO task must be -EINVAL");
        }
        let fifty = 50i32.to_ne_bytes();
        if call(Syscall::SchedSetparam.raw(), a1(0, fifty.as_ptr() as u64)) != Some(0) {
            return Err("sched_setparam(50) on a SCHED_FIFO task should succeed");
        }
        if getparam(0) != Some(50) || getscheduler(0) != Some(SCHED_FIFO as i64) {
            return Err("sched_setparam must keep the policy and set the priority");
        }
        // SCHED_RR: `sched_rr_timeslice` = RR_TIMESLICE = 100 ms.
        if setscheduler(0, SCHED_RR, 5) != Some(0) {
            return Err("sched_setscheduler(SCHED_RR, 5) should succeed");
        }
        if rr_interval_ns(0) != Some(100_000_000) {
            return Err("SCHED_RR must report the 100 ms round-robin timeslice");
        }
        // Back to SCHED_OTHER: priority reads 0 again (the RT value is not
        // reported for a non-RT task).
        if setscheduler(0, SCHED_OTHER, 0) != Some(0) {
            return Err("returning to SCHED_OTHER should succeed");
        }
        if getparam(0) != Some(0) || getscheduler(0) != Some(0) {
            return Err("SCHED_OTHER must report policy 0 / priority 0");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_policy_round_trip_through_every_reader
);

fn smoke_abi_sched_getscheduler_arg_errors() -> TestResult {
    with_setup(|| {
        // `if (pid < 0) return -EINVAL;` then `if (!p) return -ESRCH;`.
        if getscheduler((-1i64) as u64) != Some(EINVAL) {
            return Err("sched_getscheduler(-1) must be -EINVAL");
        }
        if getscheduler(123456) != Some(ESRCH) {
            return Err("sched_getscheduler on a pid naming no task must be -ESRCH");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getscheduler_arg_errors);

// ── user_check_sched_setscheduler: the -EPERM arms ──────────────────

fn smoke_abi_sched_unprivileged_rt_needs_rlimit_rtprio() -> TestResult {
    with_setup(|| {
        // RLIMIT_RTPRIO defaults to 0 (INIT_RLIMITS), so an unprivileged
        // task may not enter an RT policy at all.
        let mut buf = [0u8; 16];
        if call(
            Syscall::Getrlimit.raw(),
            a1(RLIMIT_RTPRIO_W, buf.as_mut_ptr() as u64),
        ) != Some(0)
            || buf != [0u8; 16]
        {
            return Err("RLIMIT_RTPRIO must default to {0, 0} like Linux");
        }
        drop_to_unprivileged_uid()?;
        if setscheduler(0, SCHED_FIFO, 1) != Some(EPERM) {
            return Err("an unprivileged task entered SCHED_FIFO with RLIMIT_RTPRIO 0");
        }
        if getscheduler(0) != Some(0) {
            return Err("the refused call changed the policy anyway");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_unprivileged_rt_needs_rlimit_rtprio
);

fn smoke_abi_sched_rlimit_rtprio_is_the_unprivileged_ceiling() -> TestResult {
    with_setup(|| {
        // Grant headroom while still privileged, then drop.
        if set_rlimit(RLIMIT_RTPRIO_W, 20, 20) != Some(0) {
            return Err("setrlimit(RLIMIT_RTPRIO, 20) should succeed while privileged");
        }
        drop_to_unprivileged_uid()?;
        if setscheduler(0, SCHED_FIFO, 10) != Some(0) {
            return Err("SCHED_FIFO 10 is within RLIMIT_RTPRIO 20 and must succeed");
        }
        // "Can't increase priority" past the rlimit.
        if setscheduler(0, SCHED_FIFO, 30) != Some(EPERM) {
            return Err("raising an RT priority past RLIMIT_RTPRIO must be -EPERM");
        }
        // Lowering is always allowed; raising back within the limit too.
        let five = 5i32.to_ne_bytes();
        if call(Syscall::SchedSetparam.raw(), a1(0, five.as_ptr() as u64)) != Some(0) {
            return Err("lowering an RT priority must not need privilege");
        }
        let fifteen = 15i32.to_ne_bytes();
        if call(Syscall::SchedSetparam.raw(), a1(0, fifteen.as_ptr() as u64)) != Some(0) {
            return Err("raising an RT priority within RLIMIT_RTPRIO must succeed");
        }
        if getparam(0) != Some(15) {
            return Err("the RT priority did not follow the permitted changes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_rlimit_rtprio_is_the_unprivileged_ceiling
);

fn smoke_abi_sched_reset_on_fork_cannot_be_cleared_unprivileged() -> TestResult {
    with_setup(|| {
        if setscheduler(0, SCHED_OTHER | SCHED_RESET_ON_FORK_W, 0) != Some(0) {
            return Err("setting SCHED_RESET_ON_FORK should succeed");
        }
        drop_to_unprivileged_uid()?;
        // "Normal users shall not reset the sched_reset_on_fork flag".
        if setscheduler(0, SCHED_OTHER, 0) != Some(EPERM) {
            return Err("clearing reset_on_fork without CAP_SYS_NICE must be -EPERM");
        }
        // Keeping it is fine, and sched_setparam (SETPARAM_POLICY) keeps it
        // implicitly.
        if setscheduler(0, SCHED_OTHER | SCHED_RESET_ON_FORK_W, 0) != Some(0) {
            return Err("re-asserting reset_on_fork must succeed");
        }
        let zero = 0i32.to_ne_bytes();
        if call(Syscall::SchedSetparam.raw(), a1(0, zero.as_ptr() as u64)) != Some(0) {
            return Err("sched_setparam keeps reset_on_fork and must succeed");
        }
        if getscheduler(0) != Some((SCHED_OTHER | SCHED_RESET_ON_FORK_W) as i64) {
            return Err("reset_on_fork did not survive");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_reset_on_fork_cannot_be_cleared_unprivileged
);

fn smoke_abi_sched_leaving_sched_idle_needs_rlimit_nice() -> TestResult {
    with_setup(|| {
        drop_to_unprivileged_uid()?;
        // Entering SCHED_IDLE is never privileged...
        if setscheduler(0, SCHED_IDLE, 0) != Some(0) {
            return Err("an unprivileged task may always enter SCHED_IDLE");
        }
        // ...but "Treat SCHED_IDLE as nice 20": leaving it is a nice
        // reduction to the task's nice (0), which RLIMIT_NICE 0 forbids.
        if setscheduler(0, SCHED_OTHER, 0) != Some(EPERM) {
            return Err("leaving SCHED_IDLE without RLIMIT_NICE headroom must be -EPERM");
        }
        if getscheduler(0) != Some(SCHED_IDLE as i64) {
            return Err("the refused call left SCHED_IDLE anyway");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_leaving_sched_idle_needs_rlimit_nice
);

fn smoke_abi_sched_setters_refuse_another_users_task() -> TestResult {
    with_setup(|| {
        const OTHER: u64 = 0x5C_4ED0;
        register_foreign(OTHER);
        let result = (|| {
            drop_to_unprivileged_uid()?;
            // `check_same_owner` fails ⇒ req_priv ⇒ -EPERM, for every setter.
            if setscheduler(OTHER, SCHED_OTHER, 0) != Some(EPERM) {
                return Err("sched_setscheduler on another user's task must be -EPERM");
            }
            let zero = 0i32.to_ne_bytes();
            if call(
                Syscall::SchedSetparam.raw(),
                a1(OTHER, zero.as_ptr() as u64),
            ) != Some(EPERM)
            {
                return Err("sched_setparam on another user's task must be -EPERM");
            }
            let attr = sched_attr(0, 0, 0, 0, 0, 0, 0);
            if setattr(OTHER, &attr) != Some(EPERM) {
                return Err("sched_setattr on another user's task must be -EPERM");
            }
            // Reading is not privileged.
            if getscheduler(OTHER) != Some(0) || getparam(OTHER) != Some(0) {
                return Err("reading another task's policy must succeed");
            }
            Ok(())
        })();
        crate::task::release_task(OTHER);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setters_refuse_another_users_task
);

// ── sched_setattr ───────────────────────────────────────────────────

fn smoke_abi_sched_setattr_error_order() -> TestResult {
    with_setup(|| {
        // The flag mask is checked in `__sched_setscheduler`, i.e. AFTER the
        // task lookup: an unknown flag against a pid naming nothing is
        // -ESRCH, not -EINVAL.
        let bad_flag = sched_attr(0, 0x8000, 0, 0, 0, 0, 0);
        if setattr(0x7f00_0001, &bad_flag) != Some(ESRCH) {
            return Err("sched_setattr must look the task up before checking flags");
        }
        if setattr(0, &bad_flag) != Some(EINVAL) {
            return Err("an undefined sched_flag must be -EINVAL");
        }
        // SCHED_FLAG_SUGOV is kernel-internal: past the mask, refused after
        // the permission check.
        let sugov = sched_attr(0, SCHED_FLAG_SUGOV_W, 0, 0, 0, 0, 0);
        if setattr(0, &sugov) != Some(EINVAL) {
            return Err("SCHED_FLAG_SUGOV from userspace must be -EINVAL");
        }
        // Util clamping with a VER1-sized struct: the size is fine, but
        // without CONFIG_UCLAMP_TASK `uclamp_validate` is -EOPNOTSUPP.
        let mut v1 = [0u8; 56];
        v1[..48].copy_from_slice(&sched_attr(0, SCHED_FLAG_UTIL_CLAMP_MIN_W, 0, 0, 0, 0, 0));
        v1[..4].copy_from_slice(&56u32.to_ne_bytes());
        if setattr(0, &v1) != Some(EOPNOTSUPP) {
            return Err("util clamping without uclamp support must be -EOPNOTSUPP");
        }
        // `unsigned int flags` — upper register bits are not the argument.
        let ok = sched_attr(0, 0, 0, 0, 0, 0, 0);
        if call(
            Syscall::SchedSetattr.raw(),
            a3(0, ok.as_ptr() as u64, 1u64 << 32, 0),
        ) != Some(0)
        {
            return Err("sched_setattr must read its flags argument as 32 bits");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setattr_error_order);

fn smoke_abi_sched_setattr_nice_reaches_getpriority() -> TestResult {
    with_setup(|| {
        // `__setscheduler_params` writes `static_prio` for a fair policy:
        // the nice asked for is THE nice, visible to getpriority.
        if setattr(0, &sched_attr(0, 0, 5, 0, 0, 0, 0)) != Some(0) {
            return Err("sched_setattr(SCHED_OTHER, nice 5) should succeed");
        }
        if call(Syscall::Getpriority.raw(), a1(0, 0)) != Some(15) {
            return Err("the nice set via sched_setattr did not reach getpriority");
        }
        // And the reverse: setpriority shows up in sched_getattr.
        if call(Syscall::Setpriority.raw(), a2(0, 0, 7)) != Some(0) {
            return Err("setpriority setup failed");
        }
        if attr_u32(&getattr(0)?, 16) as i32 != 7 {
            return Err("sched_getattr did not report the setpriority nice");
        }
        // `sched_copy_attr` clamps an out-of-range nice rather than failing.
        if setattr(0, &sched_attr(0, 0, 100, 0, 0, 0, 0)) != Some(0) {
            return Err("an out-of-range sched_nice must be clamped, not refused");
        }
        if call(Syscall::Getpriority.raw(), a1(0, 0)) != Some(1) {
            return Err("sched_nice 100 must clamp to 19");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setattr_nice_reaches_getpriority
);

fn smoke_abi_sched_setattr_nice_reduction_is_eperm() -> TestResult {
    with_setup(|| {
        drop_to_unprivileged_uid()?;
        // Raising nice needs nothing...
        if setattr(0, &sched_attr(0, 0, 5, 0, 0, 0, 0)) != Some(0) {
            return Err("raising nice via sched_setattr must not need privilege");
        }
        // ...lowering it past RLIMIT_NICE is `goto req_priv` — -EPERM here,
        // where setpriority's `can_nice` failure is -EACCES.
        if setattr(0, &sched_attr(0, 0, -5, 0, 0, 0, 0)) != Some(EPERM) {
            return Err("an unprivileged nice reduction via sched_setattr must be -EPERM");
        }
        if call(Syscall::Getpriority.raw(), a1(0, 0)) != Some(15) {
            return Err("the refused nice reduction changed the nice anyway");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setattr_nice_reduction_is_eperm
);

fn smoke_abi_sched_setattr_keep_policy_and_params() -> TestResult {
    with_setup(|| {
        if setscheduler(0, SCHED_RR, 30) != Some(0) {
            return Err("setup: SCHED_RR 30");
        }
        // KEEP_POLICY: the struct's policy (SCHED_OTHER here) is ignored and
        // the priority applies to the current RR policy.
        let keep_policy = sched_attr(0, SCHED_FLAG_KEEP_POLICY_W, 0, 40, 0, 0, 0);
        if setattr(0, &keep_policy) != Some(0) {
            return Err("SCHED_FLAG_KEEP_POLICY should keep SCHED_RR");
        }
        if getscheduler(0) != Some(SCHED_RR as i64) || getparam(0) != Some(40) {
            return Err("KEEP_POLICY did not keep the policy / apply the priority");
        }
        // KEEP_PARAMS: the struct's priority (0) is replaced by the task's
        // own, so switching to FIFO keeps 40 instead of failing prio 0.
        let keep_params = sched_attr(SCHED_FIFO as u32, SCHED_FLAG_KEEP_PARAMS_W, 0, 0, 0, 0, 0);
        if setattr(0, &keep_params) != Some(0) {
            return Err("SCHED_FLAG_KEEP_PARAMS should carry the priority over");
        }
        if getscheduler(0) != Some(SCHED_FIFO as i64) || getparam(0) != Some(40) {
            return Err("KEEP_PARAMS did not keep the priority");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setattr_keep_policy_and_params
);

fn smoke_abi_sched_setattr_fair_slice_round_trips() -> TestResult {
    with_setup(|| {
        // Linux ≥ 6.12 reports `se.slice` as a fair task's sched_runtime.
        // Default: 0.75 ms × (1 + ilog2(min(cpus, 8))).
        let cpus = online_cpus().min(8);
        let base = 750_000u64 * (1 + u64::from(cpus.ilog2()));
        if attr_u64(&getattr(0)?, 24) != base {
            return Err("a fair task's sched_runtime must be the base slice");
        }
        // A custom slice is clamped to [0.1 ms, 100 ms] and reported back,
        // and `get_rr_interval_fair` rounds it to whole jiffies.
        if setattr(0, &sched_attr(0, 0, 0, 0, 50_000_000, 0, 0)) != Some(0) {
            return Err("sched_setattr with a 50 ms custom slice should succeed");
        }
        if attr_u64(&getattr(0)?, 24) != 50_000_000 {
            return Err("the custom slice did not round-trip");
        }
        if rr_interval_ns(0) != Some(50_000_000) {
            return Err("sched_rr_get_interval must report the fair slice in whole jiffies");
        }
        if setattr(0, &sched_attr(0, 0, 0, 0, 10, 0, 0)) != Some(0)
            || attr_u64(&getattr(0)?, 24) != 100_000
        {
            return Err("a custom slice below 0.1 ms must clamp up to 0.1 ms");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setattr_fair_slice_round_trips
);

// ── SCHED_DEADLINE ──────────────────────────────────────────────────

const DL_RUNTIME: u64 = 10_000_000; // 10 ms
const DL_DEADLINE: u64 = 30_000_000; // 30 ms
const DL_PERIOD: u64 = 100_000_000; // 100 ms

fn smoke_abi_sched_deadline_checkparam() -> TestResult {
    with_setup(|| {
        let dl = SCHED_DEADLINE as u32;
        // `__checkparam_dl` refusals, each -EINVAL.
        let bad: [([u8; 48], &str); 7] = [
            (
                sched_attr(dl, 0, 0, 0, DL_RUNTIME, 0, DL_PERIOD),
                "deadline 0",
            ),
            (
                sched_attr(dl, 0, 0, 0, 1000, DL_DEADLINE, DL_PERIOD),
                "runtime < 1 << DL_SCALE",
            ),
            (
                sched_attr(dl, 0, 0, 0, DL_DEADLINE + 1, DL_DEADLINE, DL_PERIOD),
                "runtime > deadline",
            ),
            (
                sched_attr(dl, 0, 0, 0, DL_RUNTIME, DL_PERIOD + 1, DL_PERIOD),
                "deadline > period",
            ),
            (
                sched_attr(dl, 0, 0, 0, 2048, 50_000, 0),
                "period below 100 us",
            ),
            (
                sched_attr(dl, 0, 0, 0, DL_RUNTIME, DL_DEADLINE, 5_000_000_000),
                "period above 2^22 us",
            ),
            (
                sched_attr(dl, 0, 0, 1, DL_RUNTIME, DL_DEADLINE, DL_PERIOD),
                "non-zero sched_priority",
            ),
        ];
        for (attr, _why) in bad.iter() {
            if setattr(0, attr) != Some(EINVAL) {
                return Err("a SCHED_DEADLINE triple failing __checkparam_dl must be -EINVAL");
            }
        }
        if getscheduler(0) != Some(0) {
            return Err("a refused SCHED_DEADLINE request changed the policy");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_deadline_checkparam);

fn smoke_abi_sched_deadline_admitted_and_reported() -> TestResult {
    with_setup(|| {
        let attr = sched_attr(
            SCHED_DEADLINE as u32,
            0,
            0,
            0,
            DL_RUNTIME,
            DL_DEADLINE,
            DL_PERIOD,
        );
        if setattr(0, &attr) != Some(0) {
            return Err("a valid privileged SCHED_DEADLINE request should be admitted");
        }
        if getscheduler(0) != Some(SCHED_DEADLINE as i64) {
            return Err("sched_getscheduler did not report SCHED_DEADLINE");
        }
        let a = getattr(0)?;
        if attr_u32(&a, 4) != SCHED_DEADLINE as u32
            || attr_u64(&a, 24) != DL_RUNTIME
            || attr_u64(&a, 32) != DL_DEADLINE
            || attr_u64(&a, 40) != DL_PERIOD
        {
            return Err("sched_getattr did not report the deadline reservation");
        }
        // A deadline task has no RT priority and no RR quantum.
        if getparam(0) != Some(0) || rr_interval_ns(0) != Some(0) {
            return Err("SCHED_DEADLINE must report priority 0 and a 0 interval");
        }
        // sched_fork: `if (dl_prio(p->prio)) return -EAGAIN;`.
        if !crate::handlers::__test_sched_fork_denied(FAKE_TASK) {
            return Err("fork of a SCHED_DEADLINE task must be refused");
        }
        #[cfg(target_arch = "x86_64")]
        if call(Syscall::Fork.raw(), a0(0)) != Some(EAGAIN) {
            return Err("fork(2) from a SCHED_DEADLINE task must be -EAGAIN");
        }
        // With reset_on_fork the child restarts as SCHED_NORMAL, so fork is
        // allowed again.
        let with_reset = sched_attr(
            SCHED_DEADLINE as u32,
            SCHED_FLAG_RESET_ON_FORK_W,
            0,
            0,
            DL_RUNTIME,
            DL_DEADLINE,
            DL_PERIOD,
        );
        if setattr(0, &with_reset) != Some(0) {
            return Err("adding reset_on_fork to a DL task should succeed");
        }
        if crate::handlers::__test_sched_fork_denied(FAKE_TASK) {
            return Err("a reset_on_fork DL task must be allowed to fork");
        }
        // Leaving SCHED_DEADLINE always succeeds.
        if setscheduler(0, SCHED_OTHER | SCHED_RESET_ON_FORK_W, 0) != Some(0) {
            return Err("leaving SCHED_DEADLINE should succeed");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_deadline_admitted_and_reported
);

fn smoke_abi_sched_deadline_is_always_privileged() -> TestResult {
    with_setup(|| {
        drop_to_unprivileged_uid()?;
        // "Can't set/change SCHED_DEADLINE policy at all for now".
        let attr = sched_attr(
            SCHED_DEADLINE as u32,
            0,
            0,
            0,
            DL_RUNTIME,
            DL_DEADLINE,
            DL_PERIOD,
        );
        if setattr(0, &attr) != Some(EPERM) {
            return Err("an unprivileged SCHED_DEADLINE request must be -EPERM");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_deadline_is_always_privileged);

fn smoke_abi_sched_deadline_bandwidth_admission_is_ebusy() -> TestResult {
    with_setup(|| {
        // Fill the root domain to 90% per CPU with seeded reservations, then
        // ask for 99% more: `__dl_overflow` against the default 95% cap.
        let cpus = u64::from(online_cpus());
        let dl = SCHED_DEADLINE as u32;
        const SEED_BASE: u64 = 0xD1_0000;
        let fill = sched_attr(dl, 0, 0, 0, 90_000_000, 100_000_000, 100_000_000);
        let mut seeded = alloc::vec::Vec::new();
        for i in 0..cpus {
            let t = SEED_BASE + i;
            register_foreign(t);
            seeded.push(t);
            if setattr(t, &fill) != Some(0) {
                for t in seeded {
                    crate::task::release_task(t);
                }
                return Err("seeding a 90% reservation should be admitted");
            }
        }
        let big = sched_attr(dl, 0, 0, 0, 99_000_000, 100_000_000, 100_000_000);
        let got = setattr(0, &big);
        // A small request still fits in the remaining 5% per CPU.
        let small = sched_attr(dl, 0, 0, 0, 1_000_000, 100_000_000, 100_000_000);
        let got_small = setattr(0, &small);
        for t in seeded {
            crate::task::release_task(t);
        }
        if got != Some(EBUSY) {
            return Err("a reservation past the root domain's bandwidth must be -EBUSY");
        }
        if got_small != Some(0) {
            return Err("a reservation within the remaining bandwidth must be admitted");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_deadline_bandwidth_admission_is_ebusy
);

fn smoke_abi_sched_deadline_pins_affinity() -> TestResult {
    with_setup(|| {
        let attr = sched_attr(
            SCHED_DEADLINE as u32,
            0,
            0,
            0,
            DL_RUNTIME,
            DL_DEADLINE,
            DL_PERIOD,
        );
        if setattr(0, &attr) != Some(0) {
            return Err("setup: SCHED_DEADLINE");
        }
        // `dl_task_check_affinity`: a DL task may not narrow below its root
        // domain — -EBUSY, ahead of the empty-mask -EINVAL.
        let empty = [0u8; 8];
        match call(
            Syscall::SchedSetaffinity.raw(),
            a2(0, 8, empty.as_ptr() as u64),
        ) {
            Some(v) if v == EBUSY => Ok(()),
            Some(v) if v == EINVAL => {
                Err("a DL task's affinity check ran after the empty-mask check")
            }
            _ => Err("narrowing a SCHED_DEADLINE task's affinity must be -EBUSY"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_deadline_pins_affinity);

// ── fork inheritance (sched_fork) ───────────────────────────────────

fn smoke_abi_sched_fork_inherits_and_resets() -> TestResult {
    with_setup(|| {
        const CHILD_A: u64 = 0xF0_4C_01;
        const CHILD_B: u64 = 0xF0_4C_02;
        const CHILD_C: u64 = 0xF0_4C_03;
        // Plain inheritance: policy, priority and nice are copied.
        if setscheduler(0, SCHED_FIFO, 10) != Some(0)
            || call(Syscall::Setpriority.raw(), a2(0, 0, 5)) != Some(0)
        {
            return Err("setup: SCHED_FIFO 10 / nice 5");
        }
        crate::handlers::__test_sched_fork(FAKE_TASK, CHILD_A);
        if crate::handlers::__test_sched_policy_of(CHILD_A) != SCHED_FIFO as i32 {
            return Err("a forked child must inherit SCHED_FIFO");
        }
        if crate::handlers::nice_of(CHILD_A) != 5 {
            return Err("a forked child must inherit its parent's nice");
        }
        // reset_on_fork on an RT parent: child is SCHED_NORMAL at nice 0,
        // and the flag is consumed.
        if setscheduler(0, SCHED_FIFO | SCHED_RESET_ON_FORK_W, 10) != Some(0) {
            return Err("setup: SCHED_FIFO | RESET_ON_FORK");
        }
        crate::handlers::__test_sched_fork(FAKE_TASK, CHILD_B);
        if crate::handlers::__test_sched_policy_of(CHILD_B) != SCHED_OTHER as i32
            || crate::handlers::nice_of(CHILD_B) != 0
        {
            return Err("reset_on_fork must restart an RT parent's child as SCHED_NORMAL nice 0");
        }
        // reset_on_fork on a fair parent keeps a POSITIVE nice (only a
        // negative one is reset).
        if setscheduler(0, SCHED_OTHER | SCHED_RESET_ON_FORK_W, 0) != Some(0) {
            return Err("setup: SCHED_OTHER | RESET_ON_FORK");
        }
        crate::handlers::__test_sched_fork(FAKE_TASK, CHILD_C);
        if crate::handlers::__test_sched_policy_of(CHILD_C) != SCHED_OTHER as i32
            || crate::handlers::nice_of(CHILD_C) != 5
        {
            return Err("reset_on_fork must leave a fair parent's non-negative nice alone");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_fork_inherits_and_resets);

// ── sched_getattr ───────────────────────────────────────────────────

fn smoke_abi_sched_getattr_faults_are_efault() -> TestResult {
    with_setup(|| {
        // Both halves of `copy_struct_to_user` report -EFAULT. The tail
        // half used to return a POSITIVE 14 as though it had succeeded.
        match call(Syscall::SchedGetattr.raw(), a3(0, BAD_PTR, 64, 0)) {
            Some(v) if v == EFAULT => {}
            Some(14) => return Err("sched_getattr reported EFAULT as a positive success value"),
            _ => return Err("sched_getattr into an unmapped buffer must be -EFAULT"),
        }
        match call(Syscall::SchedGetattr.raw(), a3(0, BAD_PTR, 48, 0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("sched_getattr into an unmapped buffer must be -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getattr_faults_are_efault);

// ── sched_{get,set}affinity ordering ────────────────────────────────

fn smoke_abi_sched_setaffinity_empty_mask_is_checked_last() -> TestResult {
    with_setup(|| {
        let mask = [0u8; 8];
        // `len == 0` is not refused up front: `get_user_cpu_mask` copies
        // nothing (so even NULL does not fault), and the empty mask is only
        // -EINVAL after the pid lookup.
        if call(Syscall::SchedSetaffinity.raw(), a2(123456, 0, 0)) != Some(ESRCH) {
            return Err("sched_setaffinity(len 0) must look the pid up first (-ESRCH)");
        }
        if call(Syscall::SchedSetaffinity.raw(), a2(0, 0, 0)) != Some(EINVAL) {
            return Err("sched_setaffinity(len 0, NULL) must be -EINVAL, not -EFAULT");
        }
        if call(
            Syscall::SchedSetaffinity.raw(),
            a2(0, 8, mask.as_ptr() as u64),
        ) != Some(EINVAL)
        {
            return Err("an all-zero mask must be -EINVAL");
        }
        // pid_t: a negative pid names nothing (-ESRCH, not -EINVAL, here).
        let one = [1u8, 0, 0, 0, 0, 0, 0, 0];
        if call(
            Syscall::SchedSetaffinity.raw(),
            a2((-1i64) as u64, 8, one.as_ptr() as u64),
        ) != Some(ESRCH)
        {
            return Err("sched_setaffinity(-1) must be -ESRCH");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setaffinity_empty_mask_is_checked_last
);

fn smoke_abi_sched_setaffinity_foreign_task_is_eperm() -> TestResult {
    with_setup(|| {
        narf_scheduler::__reset_queues_for_test();
        let spec = narf_scheduler::TaskSpec {
            affinity: narf_scheduler::Affinity::any(),
            ..narf_scheduler::TaskSpec::unthrottled()
        };
        let target = narf_scheduler::spawn_with_spec(core::future::pending::<()>(), spec);
        let result = (|| {
            drop_to_unprivileged_uid()?;
            let one = [1u8, 0, 0, 0, 0, 0, 0, 0];
            match call(
                Syscall::SchedSetaffinity.raw(),
                a2(target.raw(), 8, one.as_ptr() as u64),
            ) {
                Some(v) if v == EPERM => Ok(()),
                _ => Err("pinning another user's task without CAP_SYS_NICE must be -EPERM"),
            }
        })();
        narf_scheduler::__reset_queues_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setaffinity_foreign_task_is_eperm
);

fn smoke_abi_sched_getaffinity_len_and_order() -> TestResult {
    with_setup(|| {
        let mut mask = [0u8; 8];
        let p = mask.as_mut_ptr() as u64;
        // `(len * BITS_PER_BYTE) < nr_cpu_ids` in `unsigned int`: 0, and a
        // length whose ×8 wraps to 0, are both -EINVAL.
        for len in [0u64, 0x2000_0000, 12] {
            if call(Syscall::SchedGetaffinity.raw(), a2(0, len, p)) != Some(EINVAL) {
                return Err("sched_getaffinity must refuse a short, wrapping or unaligned len");
            }
        }
        // No up-front NULL check: the pid lookup answers first.
        if call(Syscall::SchedGetaffinity.raw(), a2(123456, 8, 0)) != Some(ESRCH) {
            return Err("sched_getaffinity(bad pid, NULL) must be -ESRCH, not -EFAULT");
        }
        if call(Syscall::SchedGetaffinity.raw(), a2((-1i64) as u64, 8, p)) != Some(ESRCH) {
            return Err("sched_getaffinity(-1) must be -ESRCH");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getaffinity_len_and_order);

// ── getcpu ──────────────────────────────────────────────────────────

fn smoke_abi_sched_getcpu_attempts_both_writes() -> TestResult {
    with_setup(|| {
        // `err |= put_user(cpu, cpup); err |= put_user(node, nodep);` — a
        // bad cpup does not stop nodep being written.
        let mut node = [0xFFu8; 4];
        match call(
            Syscall::Getcpu.raw(),
            a2(BAD_PTR, node.as_mut_ptr() as u64, 0),
        ) {
            Some(v) if v == EFAULT => {}
            _ => return Err("getcpu with a bad cpu pointer must be -EFAULT"),
        }
        if u32::from_ne_bytes(node) != 0 {
            return Err("getcpu skipped the node write after the cpu write faulted");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getcpu_attempts_both_writes);

// ── setpriority: error threading across a set ───────────────────────

fn smoke_abi_sched_setpriority_success_never_clears_a_failure() -> TestResult {
    with_setup(|| {
        // Group: caller (uid 1000), A (uid 0, not ours), B (uid 1000).
        // Visited caller → A → B. `if (error == -ESRCH) error = 0;` means
        // B's success must NOT erase A's -EPERM.
        const PGRP: u64 = 0x6A_6A00;
        const A: u64 = 0x6A_6A01;
        const B: u64 = 0x6A_6A02;
        register_foreign(A);
        register_foreign(B);
        let result = (|| {
            for t in [FAKE_TASK, A, B] {
                crate::handlers::__test_set_pgid(t, PGRP);
            }
            crate::handlers::__test_set_uidgid_euid(B, 1000);
            drop_to_unprivileged_uid()?;
            match call(Syscall::Setpriority.raw(), a2(PRIO_PGRP_W, 0, 5)) {
                Some(v) if v == EPERM => {}
                Some(0) => return Err("a later success cleared an earlier -EPERM in the group"),
                _ => return Err("setpriority over a partly-foreign group must be -EPERM"),
            }
            // Every permitted member was still reniced.
            if crate::handlers::nice_of(B) != 5 {
                return Err("the permitted member after the refusal was not reniced");
            }
            if call(Syscall::Getpriority.raw(), a1(0, 0)) != Some(15) {
                return Err("the caller was not reniced");
            }
            Ok(())
        })();
        crate::task::release_task(A);
        crate::task::release_task(B);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setpriority_success_never_clears_a_failure
);

// ── ioprio_set: ioprio_check_cap + set_task_ioprio ──────────────────

fn smoke_abi_sched_ioprio_set_class_and_level_checks() -> TestResult {
    with_setup(|| {
        // Only IOPRIO_CLASS_NONE/RT/BE/IDLE (0..=3) exist; 4..=7 fall to
        // `default: return -EINVAL;` (7 is IOPRIO_CLASS_INVALID).
        for class in 4u64..=7 {
            if call(
                Syscall::IoprioSet.raw(),
                a2(IOPRIO_WHO_PROCESS_W, 0, class << 13),
            ) != Some(EINVAL)
            {
                return Err("an undefined I/O priority class must be -EINVAL");
            }
        }
        // `case IOPRIO_CLASS_NONE: if (level) return -EINVAL;`
        if call(Syscall::IoprioSet.raw(), a2(IOPRIO_WHO_PROCESS_W, 0, 3)) != Some(EINVAL) {
            return Err("IOPRIO_CLASS_NONE with a level must be -EINVAL");
        }
        if call(Syscall::IoprioSet.raw(), a2(IOPRIO_WHO_PROCESS_W, 0, 0)) != Some(0) {
            return Err("IOPRIO_CLASS_NONE level 0 must be accepted");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_ioprio_set_class_and_level_checks
);

fn smoke_abi_sched_ioprio_set_foreign_task_is_eperm() -> TestResult {
    with_setup(|| {
        const OTHER: u64 = 0x10_F00D;
        register_foreign(OTHER);
        let result = (|| {
            drop_to_unprivileged_uid()?;
            const BE_3: u64 = (2 << 13) | 3;
            // `set_task_ioprio`: the target's uid must be the caller's uid
            // or euid, else CAP_SYS_NICE, else -EPERM. It used to be absent.
            match call(
                Syscall::IoprioSet.raw(),
                a2(IOPRIO_WHO_PROCESS_W, OTHER, BE_3),
            ) {
                Some(v) if v == EPERM => {}
                Some(0) => return Err("an unprivileged task reprioritised another user's I/O"),
                _ => return Err("ioprio_set on another user's task must be -EPERM"),
            }
            // Its own I/O is fine.
            if call(Syscall::IoprioSet.raw(), a2(IOPRIO_WHO_PROCESS_W, 0, BE_3)) != Some(0) {
                return Err("ioprio_set on the caller's own task must succeed");
            }
            Ok(())
        })();
        crate::task::release_task(OTHER);
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_ioprio_set_foreign_task_is_eperm
);
