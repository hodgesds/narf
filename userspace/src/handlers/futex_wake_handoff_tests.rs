//! Handler-driven futex wake routing (benchmark variant B4).
//!
//! `FutexWaiter::wake` must route an urgent wake of a handler-driven
//! waiter (`q: Some`, the live `futex_block` path) through
//! `narf_scheduler::wake_preempt_task`, so a local, direct-eligible
//! waiter gets the exact-cell direct handoff instead of full executor
//! placement. These tests prove the routing against the scheduler's
//! documented handoff contract (`scheduler/src/lib.rs`):
//!
//! - `wake_preempt_task`: a scheduler waker whose task id matches, homed
//!   on the waker's CPU, not the runner, and `direct_eligible` publishes
//!   the exact cell on that CPU's urgent hint; every other case falls
//!   back to ordinary placement (`wake_place_and_kick`), and
//!   foreign/mismatched wakers fall back to a plain wake. The wake itself
//!   is published first (`publish_owned_wake`) on every arm, so a
//!   declined handoff can never lose the wake.
//! - `direct_eligible` is set at spawn and requires Default class +
//!   NORMAL priority + unthrottled budget + no budget cap: RT, budgeted,
//!   or pinned tasks never get the direct path.
//!
//! Fixtures are synthetic scheduler wakers built with the scheduler's
//! test-only hook (`__make_waker_for_test`): a parked waiter's awake flag
//! starts clear, the home CPU and direct-eligibility are chosen per
//! case, and the task id is the waiter's `tid`, so `wake_preempt_task`
//! sees exactly what a real `futex_block` waiter would present. The
//! assertions observe only public scheduler postconditions — the awake
//! flag (wake published) and the exact urgent hint (handoff taken) —
//! never the new code's own branches.
//!
//! No benchmark numbers live here: selection among futex variants is by
//! hardware measurement only (`perf bench futex` on the cube).
use super::*;
use crate::abi_test_support::{kernel_test_in, with_setup, TestResult};

/// Enqueue one handler-driven waiter (`q: Some`) for `tid` on `key`,
/// woken by `waker`, then dequeue it the way
/// `futex_wake_waiters_key_bitset` does: select the first matching waiter
/// and remove it, which `mark_woken()`s it. Returns the waiter ready for
/// `wake()`.
fn dequeue_handler_waiter(
    key: FutexKey,
    tid: u64,
    waker: Waker,
) -> Result<FutexWaiter, &'static str> {
    let wait = Arc::new(FutexQ::new(core::iter::once(key)));
    futex_queue(key, tid, 0, waker, FUTEX_BITSET_MATCH_ANY, &wait);
    let mut bucket = futex_wait_bucket(key).values.lock();
    let handle =
        futex_select_waiter(&bucket, key, FUTEX_BITSET_MATCH_ANY).ok_or("waiter missing")?;
    futex_remove_woken(&mut bucket, handle).ok_or("dequeue failed")
}

fn smoke_futex_handler_urgent_wake_takes_direct_handoff_when_eligible() -> TestResult {
    with_setup(|| {
        narf_scheduler::__reset_queues_for_test();
        let cpu = narf_lib::percpu::current_cpu();
        const TID: u64 = 0x7e_7301;
        let key = futex_key(0, 0x7e_7300);
        let waker =
            narf_scheduler::__make_waker_for_test(narf_scheduler::TaskId(TID), cpu as u32, true);
        let probe = waker.clone();
        if narf_scheduler::__waker_flag_for_test(&probe) != Some(false) {
            return Err("fixture waker did not start asleep");
        }
        let waiter = dequeue_handler_waiter(key, TID, waker)?;
        waiter.wake(true);
        if narf_scheduler::__waker_flag_for_test(&probe) != Some(true) {
            return Err("urgent handler wake did not publish the wake");
        }
        let hint = narf_scheduler::__take_urgent_wake_waker_for_test(cpu)
            .ok_or("urgent handler wake published no exact handoff")?;
        if !hint.will_wake(&probe) {
            return Err("urgent hint names a different waiter");
        }
        if narf_scheduler::__take_urgent_wake_waker_for_test(cpu).is_some() {
            return Err("urgent hint was not one-shot");
        }
        narf_scheduler::__reset_queues_for_test();
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_futex_handler_urgent_wake_takes_direct_handoff_when_eligible
);

fn smoke_futex_handler_urgent_wake_falls_back_when_not_direct_eligible() -> TestResult {
    with_setup(|| {
        narf_scheduler::__reset_queues_for_test();
        let cpu = narf_lib::percpu::current_cpu();
        const TID: u64 = 0x7e_7311;
        let key = futex_key(0, 0x7e_7310);
        let waker =
            narf_scheduler::__make_waker_for_test(narf_scheduler::TaskId(TID), cpu as u32, false);
        let probe = waker.clone();
        let waiter = dequeue_handler_waiter(key, TID, waker)?;
        waiter.wake(true);
        if narf_scheduler::__waker_flag_for_test(&probe) != Some(true) {
            return Err("fallback handler wake did not publish the wake");
        }
        if narf_scheduler::__take_urgent_wake_waker_for_test(cpu).is_some() {
            return Err("ineligible handler wake published an exact handoff");
        }
        narf_scheduler::__reset_queues_for_test();
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_futex_handler_urgent_wake_falls_back_when_not_direct_eligible
);

fn smoke_futex_handler_urgent_wake_falls_back_when_wakee_remote() -> TestResult {
    with_setup(|| {
        narf_scheduler::__reset_queues_for_test();
        let cpu = narf_lib::percpu::current_cpu();
        let remote = cpu + 1;
        const TID: u64 = 0x7e_7321;
        let key = futex_key(0, 0x7e_7320);
        let waker =
            narf_scheduler::__make_waker_for_test(narf_scheduler::TaskId(TID), remote as u32, true);
        let probe = waker.clone();
        let waiter = dequeue_handler_waiter(key, TID, waker)?;
        waiter.wake(true);
        if narf_scheduler::__waker_flag_for_test(&probe) != Some(true) {
            return Err("remote handler wake did not publish the wake");
        }
        if narf_scheduler::__take_urgent_wake_waker_for_test(cpu).is_some() {
            return Err("remote handler wake published a local exact handoff");
        }
        narf_scheduler::__reset_queues_for_test();
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_futex_handler_urgent_wake_falls_back_when_wakee_remote
);

fn smoke_futex_handler_nonurgent_wake_keeps_plain_wake() -> TestResult {
    with_setup(|| {
        narf_scheduler::__reset_queues_for_test();
        let cpu = narf_lib::percpu::current_cpu();
        const TID: u64 = 0x7e_7331;
        let key = futex_key(0, 0x7e_7330);
        let waker =
            narf_scheduler::__make_waker_for_test(narf_scheduler::TaskId(TID), cpu as u32, true);
        let probe = waker.clone();
        let waiter = dequeue_handler_waiter(key, TID, waker)?;
        waiter.wake(false);
        if narf_scheduler::__waker_flag_for_test(&probe) != Some(true) {
            return Err("non-urgent handler wake did not publish the wake");
        }
        if narf_scheduler::__take_urgent_wake_waker_for_test(cpu).is_some() {
            return Err("non-urgent handler wake published an exact handoff");
        }
        narf_scheduler::__reset_queues_for_test();
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_futex_handler_nonurgent_wake_keeps_plain_wake
);
