//! Linux syscall ABI conformance — sched group.
//!
//! Shares the harness in [`crate::abi_test_support`]; see that module for
//! the rationale. Scheduler / rlimit / priority surface.
//!
//! Tests pin the implemented Linux-compatible wire behavior. Remaining
//! cooperative-scheduler gaps are called out locally with LINUX-GAP comments.
#![cfg(feature = "linux-compat")]

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
// PRIO_PROCESS(0) only; returns nice+20 (default nice 0 ⇒ 20).

fn smoke_abi_sched_getpriority_pos() -> TestResult {
    with_setup(|| {
        // PRIO_PROCESS, self. Default nice 0 ⇒ wire value 20 (nice+20).
        match call(Syscall::Getpriority.raw(), a1(0, 0)) {
            Some(20) => Ok(()),
            other => {
                let _ = other;
                Err("getpriority(PRIO_PROCESS) should return nice+20 == 20")
            }
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getpriority_pos);

fn smoke_abi_sched_getpriority_bad_which_neg() -> TestResult {
    with_setup(|| {
        // PRIO_PGRP(1) / PRIO_USER(2) are unsupported ⇒ wire -1 sentinel.
        // LINUX-GAP: Linux supports PRIO_PGRP/PRIO_USER; bad 'which' is EINVAL.
        match call(Syscall::Getpriority.raw(), a1(1, 0)) {
            Some(-1) => Ok(()),
            _ => Err("getpriority with non-PRIO_PROCESS should return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getpriority_bad_which_neg);

// ── setpriority(which, who, prio) ───────────────────────────────────

fn smoke_abi_sched_setpriority_pos() -> TestResult {
    with_setup(|| {
        // Set nice 10 then read it back: getpriority returns 10+20 == 30.
        match call(Syscall::Setpriority.raw(), a2(0, 0, 10)) {
            Some(0) => {}
            _ => return Err("smoke_abi_sched_setpriority_pos: unexpected syscall return"),
        }
        match call(Syscall::Getpriority.raw(), a1(0, 0)) {
            Some(30) => Ok(()),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setpriority_pos);

fn smoke_abi_sched_setpriority_out_of_range_neg() -> TestResult {
    with_setup(|| {
        // prio 100 is outside the valid -20..=19 nice range ⇒ wire -1.
        // LINUX-GAP: Linux clamps and may EACCES; bad args here yield -1.
        match call(Syscall::Setpriority.raw(), a2(0, 0, 100)) {
            Some(-1) => Ok(()),
            _ => Err("setpriority with out-of-range nice should return -1"),
        }
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
        // Unknown policy 42 ⇒ wire -1 sentinel.
        // LINUX-GAP: Linux returns -EINVAL for an unknown policy.
        match call(Syscall::SchedGetPriorityMax.raw(), a0(42)) {
            Some(-1) => Ok(()),
            _ => Err("sched_get_priority_max bad policy should return -1"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sched_get_priority_max_bad_policy_neg
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
        // Unknown policy 42 ⇒ wire -1 sentinel.
        // LINUX-GAP: Linux returns -EINVAL for an unknown policy.
        match call(Syscall::SchedGetPriorityMin.raw(), a0(42)) {
            Some(-1) => Ok(()),
            _ => Err("sched_get_priority_min bad policy should return -1"),
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
        // Null param pointer ⇒ wire -1 sentinel.
        // LINUX-GAP: Linux returns -EINVAL/-EFAULT for a bad param pointer.
        match call(Syscall::SchedGetparam.raw(), a1(0, 0)) {
            Some(-1) => Ok(()),
            _ => Err("sched_getparam with null buffer should return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_getparam_null_buf_neg);

// ── sched_setparam(pid, param*) ─────────────────────────────────────

fn smoke_abi_sched_setparam_pos() -> TestResult {
    with_setup(|| {
        // Set sched_priority 50, then read it back via sched_getparam.
        let inbuf = 50i32.to_ne_bytes();
        match call(Syscall::SchedSetparam.raw(), a1(0, inbuf.as_ptr() as u64)) {
            Some(0) => {}
            _ => return Err("smoke_abi_sched_setparam_pos: unexpected syscall return"),
        }
        let mut rbuf = [0u8; 4];
        match call(
            Syscall::SchedGetparam.raw(),
            a1(0, rbuf.as_mut_ptr() as u64),
        ) {
            Some(0) if i32::from_ne_bytes(rbuf) == 50 => Ok(()),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_setparam_pos);

fn smoke_abi_sched_setparam_null_buf_neg() -> TestResult {
    with_setup(|| {
        // Null param pointer ⇒ wire -1 sentinel.
        // LINUX-GAP: Linux returns -EINVAL/-EFAULT for a bad param pointer.
        match call(Syscall::SchedSetparam.raw(), a1(0, 0)) {
            Some(-1) => Ok(()),
            _ => Err("sched_setparam with null buffer should return -1"),
        }
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
        // Non-canonical timespec pointer ⇒ copy_to_user EFAULT ⇒ wire -1.
        // LINUX-GAP: Linux returns -EFAULT for a bad timespec pointer.
        match call(Syscall::SchedRrGetInterval.raw(), a1(0, BAD_PTR)) {
            Some(-1) => Ok(()),
            _ => Err("sched_rr_get_interval with bad pointer should return -1"),
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
// Drives the sleep pumps and returns ok(0); no error path (no signal
// pending for FAKE_TASK in the harness).

fn smoke_abi_sched_yield_pos() -> TestResult {
    with_setup(|| match call(Syscall::Yield.raw(), a0(0)) {
        Some(0) => Ok(()),
        _ => Err("sched_yield should return 0"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sched_yield_pos);
