//! Linux syscall ABI conformance — sched group.
//!
//! Shares the harness in [`crate::abi_test_support`]; see that module for
//! the rationale. Scheduler / rlimit / priority surface.
//!
//! Tests pin the implemented Linux-compatible wire behavior. Remaining
//! cooperative-scheduler gaps are called out locally with LINUX-GAP comments.

use crate::abi_test_support::*;

/// A non-canonical x86_64 address (bit 48 set, 49..63 clear). Any
/// `copy_to_user` / `validate_user_range` against it returns EFAULT, so it's
/// a deterministic "bad user pointer" for the negative buffer paths.
const BAD_PTR: u64 = 0x0001_0000_0000_0000;

// Linux sched policy numbers.
const SCHED_OTHER: u64 = 0;
const SCHED_RR: u64 = 2;

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

fn smoke_abi_sched_prlimit64_error_order_and_missing_pid() -> TestResult {
    with_setup(|| {
        const MISSING_PID: u64 = 0x7fff_ffff;
        if call(Syscall::Prlimit64.raw(), a3(MISSING_PID, 7, BAD_PTR, 0)) != Some(EFAULT) {
            return Err("prlimit64 must copy new before missing-PID lookup");
        }
        if call(Syscall::Prlimit64.raw(), a3(MISSING_PID, 7, 0, 0)) != Some(ESRCH) {
            return Err("prlimit64 of a nonexistent PID should return -ESRCH");
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
// Cooperative single policy: always SCHED_OTHER (0). No reachable error.

fn smoke_abi_sched_getscheduler_pos() -> TestResult {
    with_setup(|| {
        // Always reports SCHED_OTHER (0) regardless of pid.
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
        // SCHED_RR (policy 2) is a recognised policy ⇒ ok(0).
        match call(Syscall::SchedSetScheduler.raw(), a3(0, SCHED_RR, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("sched_setscheduler(SCHED_RR) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setscheduler_pos);

fn smoke_abi_sched_setscheduler_reset_on_fork_pos() -> TestResult {
    with_setup(|| {
        const SCHED_RESET_ON_FORK: u64 = 0x4000_0000;
        match call(
            Syscall::SchedSetScheduler.raw(),
            a3(0, SCHED_OTHER | SCHED_RESET_ON_FORK, 0, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("sched_setscheduler must accept SCHED_RESET_ON_FORK"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_setscheduler_reset_on_fork_pos
);

fn smoke_abi_sched_setscheduler_bad_policy_neg() -> TestResult {
    with_setup(|| {
        // Policy 42 is unknown ⇒ EINVAL.
        match call(Syscall::SchedSetScheduler.raw(), a3(0, 42, 0, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("sched_setscheduler bad policy should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setscheduler_bad_policy_neg);

// ── sched_rr_get_interval(pid, timespec*) ───────────────────────────
// Cooperative policy has no quantum ⇒ writes {0, 0} and returns ok(0).

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

fn smoke_abi_sched_setattr_short_size_neg() -> TestResult {
    with_setup(|| {
        let mut attr = [0u8; 48];
        // Declared size 16 < SCHED_ATTR_SIZE (48) ⇒ EINVAL.
        attr[..4].copy_from_slice(&16u32.to_le_bytes());
        let args = a3(0, attr.as_ptr() as u64, 0, 0);
        match call(Syscall::SchedSetattr.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("sched_setattr with short size should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setattr_short_size_neg);

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
        // Buffer size 16 < SCHED_ATTR_SIZE (48) ⇒ EINVAL.
        let args = a3(0, attr.as_mut_ptr() as u64, 16, 0);
        match call(Syscall::SchedGetattr.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("sched_getattr with short size should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getattr_short_size_neg);

// ── membarrier(cmd, flags) ──────────────────────────────────────────

fn smoke_abi_sched_membarrier_query_pos() -> TestResult {
    with_setup(|| {
        // cmd 0 (MEMBARRIER_CMD_QUERY) returns the supported-command bitmask.
        // Supported = GLOBAL|GLOBAL_EXPEDITED|REGISTER_GLOBAL_EXPEDITED|
        //             PRIVATE_EXPEDITED|REGISTER_PRIVATE_EXPEDITED
        //           = bits 0..=4 = 0b11111 = 31.
        match call(Syscall::Membarrier.raw(), a1(0, 0)) {
            Some(31) => Ok(()),
            _ => Err("membarrier QUERY should report supported mask (31)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_membarrier_query_pos);

fn smoke_abi_sched_membarrier_bad_cmd_neg() -> TestResult {
    with_setup(|| {
        // cmd 0x4000 is not a supported single-bit command ⇒ EINVAL.
        match call(Syscall::Membarrier.raw(), a1(0x4000, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("membarrier with unsupported cmd should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_membarrier_bad_cmd_neg);

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
// Stub: accepts everything and returns ok(0); no reachable error path.

fn smoke_abi_sched_rseq_pos() -> TestResult {
    with_setup(|| {
        // Registration is a no-op stub ⇒ always ok(0).
        match call(Syscall::Rseq.raw(), a3(0xBEEF_0000, 32, 0, 0x53053053)) {
            Some(0) => Ok(()),
            _ => Err("rseq should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_rseq_pos);

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
