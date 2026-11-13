//! Exercise runtime policy replacement through real futex dequeue paths.
use super::*;
use crate::futex_policy::{self as policy, FutexPolicyError, FutexWaiterInfo, FutexWakePolicy};
use narf_capabilities::{Cap, CapError, Grant};
use narf_scheduler::SchedPolicy;

struct PreferOdd;

struct NamedPolicy(&'static str);

impl FutexWakePolicy for NamedPolicy {
    fn name(&self) -> &'static str {
        self.0
    }
    fn rank(&self, _waiter: FutexWaiterInfo) -> i64 {
        0
    }
}

impl FutexWakePolicy for PreferOdd {
    fn name(&self) -> &'static str {
        "test-odd"
    }

    fn rank(&self, waiter: FutexWaiterInfo) -> i64 {
        assert_ne!(waiter.task_id, 0x7e_06ff, "ranked an ineligible key");
        if waiter.task_id & 1 != 0 {
            i64::MAX
        } else {
            i64::MIN
        }
    }
}

struct RestoreFifo(Cap<SchedPolicy, Grant>);

impl Drop for RestoreFifo {
    fn drop(&mut self) {
        policy::select_policy(&self.0, "fifo").expect("restore FIFO policy");
    }
}

fn prepare() -> Result<RestoreFifo, &'static str> {
    let cap = Cap::bootstrap();
    match policy::register_policy(&cap, PreferOdd) {
        Ok(()) | Err(FutexPolicyError::AlreadyRegistered) => {}
        _ => return Err("register test futex policy"),
    }
    policy::select_policy(&cap, "fifo").map_err(|_| "select initial FIFO")?;
    Ok(RestoreFifo(cap))
}

fn smoke_abi_futex_policy_switch_queued_filter_and_ties() -> TestResult {
    with_setup(|| {
        let restore = prepare()?;
        let words = [0u32; 256];
        let p = words.as_ptr() as u64;
        let bucket = crate::handlers::__test_futex_current_bucket_index(true, p)
            .map_err(|_| "private futex key")?;
        let collision = (1..words.len())
            .map(|i| p + 4 * i as u64)
            .find(|&a| crate::handlers::__test_futex_current_bucket_index(true, a) == Ok(bucket))
            .ok_or("no colliding private futex key")?;
        let tids = [0x7e_0600, 0x7e_0603, 0x7e_0601, 0x7e_0605];
        let result = (|| {
            let ineligible = queue(true, collision, MATCH_ANY, 0x7e_06ff)?;
            let first = queue(true, p, 1, tids[0])?;
            let skipped = queue(true, p, 2, tids[1])?;
            let old = queue(true, p, 1, tids[2])?;
            let last = queue(true, p, 1, tids[3])?;
            policy::select_policy(&restore.0, "test-odd").map_err(|_| "select custom policy")?;
            let refreshed = queue(true, p, 1, tids[2])?;
            if futex(p, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, 1) != Some(1)
                || refreshed.load(Ordering::Acquire) != 1
                || old.load(Ordering::Acquire) != 0
                || skipped.load(Ordering::Acquire) != 0
                || first.load(Ordering::Acquire) != 0
                || last.load(Ordering::Acquire) != 0
            {
                return Err("policy ignored filter, FIFO tie or refreshed registration");
            }
            crate::handlers::__test_futex_drop_current(true, p, tids[1]);
            policy::select_policy(&restore.0, "fifo").map_err(|_| "restore FIFO while queued")?;
            if futex(p, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0) != Some(1)
                || first.load(Ordering::Acquire) != 1
                || last.load(Ordering::Acquire) != 0
                || futex(p, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 8, 0) != Some(1)
                || last.load(Ordering::Acquire) != 1
                || skipped.load(Ordering::Acquire) != 0
                || ineligible.load(Ordering::Acquire) != 0
            {
                return Err("switch/cancel changed the remaining FIFO positions");
            }
            Ok(())
        })();
        for tid in tids {
            crate::handlers::__test_futex_drop_current(true, p, tid);
        }
        crate::handlers::__test_futex_drop_current(true, collision, 0x7e_06ff);
        result
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_abi_futex_policy_switch_queued_filter_and_ties
);

struct SwitchOnWake {
    cap: Cap<SchedPolicy, Grant>,
    hits: Arc<AtomicU32>,
}

impl alloc::task::Wake for SwitchOnWake {
    fn wake(self: Arc<Self>) {
        // This also catches calling a waker while holding a bucket/config lock.
        policy::select_policy(&self.cap, "fifo").expect("switch from waker");
        self.hits.fetch_add(1, Ordering::AcqRel);
    }
}

fn smoke_abi_futex_policy_batch_snapshot_and_requeue_handles() -> TestResult {
    with_setup(|| {
        use crate::handlers::{
            __test_futex_bucket_index, __test_futex_q_new, __test_futex_q_queue,
            __test_futex_q_unqueue, __test_futex_requeue, __test_futex_waiter_count,
            futex_wake_waiters_for_test,
        };
        let restore = prepare()?;
        const SRC: u64 = 0x7e_6100;
        let dst = (1..4096)
            .map(|i| SRC + 4 * i)
            .find(|&a| __test_futex_bucket_index(0, a) != __test_futex_bucket_index(0, SRC))
            .ok_or("no different bucket")?;
        let tids = [0x7e_0610, 0x7e_0613, 0x7e_0611, 0x7e_0612];
        let waits: alloc::vec::Vec<_> = tids
            .iter()
            .map(|_| (__test_futex_q_new(&[SRC]), Arc::new(AtomicU32::new(0))))
            .collect();
        for (i, (q, hits)) in waits.iter().enumerate() {
            let waker = if i == 1 {
                Waker::from(Arc::new(SwitchOnWake {
                    cap: restore.0,
                    hits: hits.clone(),
                }))
            } else {
                counting_waker(hits.clone())
            };
            __test_futex_q_queue(q, 0, tids[i], waker);
        }
        let result = (|| {
            policy::select_policy(&restore.0, "test-odd").map_err(|_| "select custom policy")?;
            if __test_futex_requeue(SRC, dst, 0, 4) != (0, 4)
                || futex_wake_waiters_for_test(dst, 2) != 2
                || waits[1].1.load(Ordering::Acquire) != 1
                || waits[2].1.load(Ordering::Acquire) != 1
                || waits[0].1.load(Ordering::Acquire) != 0
                || waits[3].1.load(Ordering::Acquire) != 0
                || policy::current_policy_name() != "fifo"
            {
                return Err("batch mixed policies or requeue lost ordering");
            }
            // Cancel a requeued live handle after replacement, then reuse a
            // freed slot before the already-woken registration unqueues.
            if __test_futex_q_unqueue(&waits[3].0, 1, tids[3]).is_some() {
                return Err("cancel of requeued waiter reported a wake");
            }
            let reused = __test_futex_q_new(&[dst]);
            __test_futex_q_queue(&reused, 0, 0x7e_0615, counting_waker(waits[3].1.clone()));
            let body = (|| {
                if __test_futex_q_unqueue(&waits[1].0, 1, tids[1]) != Some(0)
                    || __test_futex_waiter_count(dst) != 2
                    || futex_wake_waiters_for_test(dst, 1) != 1
                    || waits[0].1.load(Ordering::Acquire) != 1
                    || waits[3].1.load(Ordering::Acquire) != 0
                    || futex_wake_waiters_for_test(dst, 8) != 1
                    || waits[3].1.load(Ordering::Acquire) != 1
                {
                    return Err("policy replacement invalidated cancellation handles or FIFO");
                }
                Ok(())
            })();
            let _ = __test_futex_q_unqueue(&reused, 1, 0x7e_0615);
            body
        })();
        for (i, (q, _)) in waits.iter().enumerate() {
            let _ = __test_futex_q_unqueue(q, 1, tids[i]);
        }
        result
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_abi_futex_policy_batch_snapshot_and_requeue_handles
);

struct SysctlFd(u64);

impl Drop for SysctlFd {
    fn drop(&mut self) {
        let _ = call(Syscall::Close.raw(), a0(self.0));
    }
}

impl SysctlFd {
    fn open(path: &[u8], flags: u64) -> Result<Self, &'static str> {
        call_open(path.as_ptr() as u64, flags)
            .filter(|fd| *fd >= 0)
            .map(|fd| Self(fd as u64))
            .ok_or("open policy sysctl")
    }

    fn write(&self, value: &[u8]) -> Option<i64> {
        call(
            Syscall::Write.raw(),
            a2(self.0, value.as_ptr() as u64, value.len() as u64),
        )
    }
}

fn read_sysctl(path: &[u8]) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let fd = SysctlFd::open(path, 0)?;
    let mut buf = [0u8; 128];
    let n = call(
        Syscall::Read.raw(),
        a2(fd.0, buf.as_mut_ptr() as u64, buf.len() as u64),
    )
    .filter(|n| *n >= 0)
    .ok_or("read policy sysctl")?;
    Ok(buf[..n as usize].to_vec())
}

fn smoke_abi_futex_policy_authority_and_sysctl() -> TestResult {
    with_setup(|| {
        const PATH: &[u8] = b"/proc/sys/kernel/futex_wake_policy\0";
        const NAMES: &[u8] = b"/proc/sys/kernel/futex_wake_policies\0";
        let restore = prepare()?;
        let revoked: Cap<SchedPolicy, Grant> = Cap::bootstrap();
        revoked.revoke();
        if policy::select_policy(&revoked, "test-odd")
            != Err(FutexPolicyError::Capability(CapError::Revoked))
            || policy::register_policy(&revoked, PreferOdd)
                != Err(FutexPolicyError::Capability(CapError::Revoked))
            || policy::select_policy(&restore.0, "missing") != Err(FutexPolicyError::UnknownPolicy)
            || policy::current_policy_name() != "fifo"
        {
            return Err("invalid policy/capability changed active policy");
        }
        for name in [
            "",
            "UPPER",
            "two words",
            "abcdefghijklmnopqrstuvwxyz0123456",
        ] {
            if policy::register_policy(&restore.0, NamedPolicy(name))
                != Err(FutexPolicyError::InvalidName)
            {
                return Err("invalid policy name was registered");
            }
        }
        for name in ["fifo", "test-odd"] {
            if policy::register_policy(&restore.0, NamedPolicy(name))
                != Err(FutexPolicyError::AlreadyRegistered)
            {
                return Err("registration replaced a reserved or existing policy");
            }
        }
        let file = SysctlFd::open(PATH, 1)?;
        if read_sysctl(PATH)? != b"fifo\n"
            || !read_sysctl(NAMES)?.windows(8).any(|w| w == b"test-odd")
        {
            return Err("policy sysctls do not describe the registry");
        }
        crate::handlers::__test_set_caps(FAKE_TASK, 0, 0);
        if file.write(b"test-odd\n") != Some(-1) || policy::current_policy_name() != "fifo" {
            return Err("unprivileged sysctl write changed ordering");
        }
        crate::handlers::__test_set_caps(FAKE_TASK, 1 << 23, 1 << 23);
        if file.write(b"test-odd\n") != Some(9)
            || read_sysctl(PATH)? != b"test-odd\n"
            || file.write(b"missing\n") != Some(-22)
            || policy::current_policy_name() != "test-odd"
        {
            return Err("authorized runtime selector or invalid-name handling failed");
        }
        // Permission is rechecked at write time, including on an open file.
        crate::handlers::__test_set_caps(FAKE_TASK, 0, 0);
        if file.write(b"fifo\n") != Some(-1) || policy::current_policy_name() != "test-odd" {
            return Err("open sysctl retained revoked authority");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_abi_futex_policy_authority_and_sysctl
);
