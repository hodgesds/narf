//! Smokes for workqueues (`scheduler/workqueue`).
//!
//! The kernel-test runner owns its CPU's executor: these drive it with
//! executor rounds and use bound workqueues, so every work runs on the
//! test CPU's pools.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::workqueue::{
    self, alloc_ordered_workqueue, alloc_workqueue, cancel_delayed_work_sync,
    cancel_work_sync_blocking, flush_work_blocking, mod_delayed_work_on, queue_delayed_work_on,
    queue_work_on, DelayedWork, WorkFn, WorkFuture, WorkRef, WorkStruct, WQ_MEM_RECLAIM,
};

fn me() -> usize {
    narf_lib::percpu::current_cpu()
}

/// Run executor rounds until `done` or `ms` pass.
fn rounds_until(ms: u64, mut done: impl FnMut() -> bool) -> bool {
    let end = narf_time::monotonic_ns() + ms * 1_000_000;
    while narf_time::monotonic_ns() < end {
        let _ = crate::poll_one_round();
        if done() {
            return true;
        }
        core::hint::spin_loop();
    }
    done()
}

/// A work that counts its runs and records their order.
#[repr(C)]
struct Counted {
    work: WorkStruct,
    runs: AtomicUsize,
    stamp: AtomicU64,
}

static ORDER: AtomicU64 = AtomicU64::new(0);

fn counted_fn(r: WorkRef) {
    // SAFETY: only `Counted` uses this function; `work` is its first field;
    // the test keeps it alive.
    let c = unsafe { &*(r.as_ptr() as *const Counted) };
    c.stamp
        .store(ORDER.fetch_add(1, Ordering::AcqRel), Ordering::Release);
    c.runs.fetch_add(1, Ordering::AcqRel);
}

fn counted() -> Box<Counted> {
    Box::new(Counted {
        work: WorkStruct::new(WorkFn::Sync(counted_fn)),
        runs: AtomicUsize::new(0),
        stamp: AtomicU64::new(0),
    })
}

/// `queue_work` runs a work once in task context; queueing it again while
/// pending is refused; after it ran it can be queued again.
fn smoke_workqueue_queue_runs_once() -> TestResult {
    let wq = workqueue::system_wq();
    let c = counted();
    // SAFETY: the Box outlives the work; it is flushed below.
    let (first, second) = unsafe {
        (
            queue_work_on(me(), wq, &c.work),
            queue_work_on(me(), wq, &c.work),
        )
    };
    let ran = rounds_until(1000, || c.runs.load(Ordering::Acquire) == 1);
    // SAFETY: as above.
    let again = unsafe { queue_work_on(me(), wq, &c.work) };
    let ran2 = rounds_until(1000, || c.runs.load(Ordering::Acquire) == 2);
    flush_work_blocking(&c.work);
    if !first || second {
        return TestResult::Fail("queueing a pending work was not refused");
    }
    if !ran || !again || !ran2 {
        return TestResult::Fail("a queued work did not run exactly once per queueing");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler/workqueue", smoke_workqueue_queue_runs_once);

static GATE: AtomicBool = AtomicBool::new(false);
static ASYNC_DONE: AtomicUsize = AtomicUsize::new(0);

/// Resolves when `GATE` opens (polled by executor rounds).
struct Gate;
impl Future for Gate {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if GATE.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn sleeper_fn(_: WorkRef) -> WorkFuture {
    Box::pin(async {
        Gate.await;
        ASYNC_DONE.fetch_add(1, Ordering::AcqRel);
    })
}

/// Concurrency management: while an async work sleeps, the pool runs the
/// next work on another worker instead of waiting for it.
fn smoke_workqueue_sleeping_work_does_not_stall_pool() -> TestResult {
    let wq = workqueue::system_wq();
    GATE.store(false, Ordering::Release);
    ASYNC_DONE.store(0, Ordering::Release);
    let sleeper = Box::new(WorkStruct::new(WorkFn::Async(sleeper_fn)));
    let c = counted();
    // SAFETY: the Boxes outlive the works; both finish below.
    unsafe {
        queue_work_on(me(), wq, &sleeper);
        queue_work_on(me(), wq, &c.work);
    }
    let other_ran = rounds_until(1000, || c.runs.load(Ordering::Acquire) == 1);
    let still_asleep = ASYNC_DONE.load(Ordering::Acquire) == 0;
    GATE.store(true, Ordering::Release);
    let woke = rounds_until(1000, || ASYNC_DONE.load(Ordering::Acquire) == 1);
    flush_work_blocking(&sleeper);
    if !other_ran || !still_asleep {
        return TestResult::Fail("a sleeping work stalled the next work on its pool");
    }
    if !woke {
        return TestResult::Fail("the sleeping work did not finish once woken");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/workqueue",
    smoke_workqueue_sleeping_work_does_not_stall_pool
);

/// An ordered workqueue (`max_active = 1`) runs its works one at a time in
/// queue order.
fn smoke_workqueue_ordered_runs_in_order() -> TestResult {
    let wq = alloc_ordered_workqueue("wq-test-ordered", 0);
    let works: Vec<Box<Counted>> = (0..8).map(|_| counted()).collect();
    for w in &works {
        // SAFETY: the Boxes outlive the works; all finish below.
        unsafe { queue_work_on(me(), wq, &w.work) };
    }
    let all = rounds_until(2000, || {
        works.iter().all(|w| w.runs.load(Ordering::Acquire) == 1)
    });
    for w in &works {
        flush_work_blocking(&w.work);
    }
    if !all {
        return TestResult::Fail("an ordered workqueue's work did not run");
    }
    let stamps: Vec<u64> = works
        .iter()
        .map(|w| w.stamp.load(Ordering::Acquire))
        .collect();
    if stamps.windows(2).any(|s| s[0] > s[1]) {
        return TestResult::Fail("an ordered workqueue ran works out of queue order");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler/workqueue", smoke_workqueue_ordered_runs_in_order);

#[repr(C)]
struct DCounted {
    dw: DelayedWork,
    runs: AtomicUsize,
    at: AtomicU64,
}

fn dcounted_fn(r: WorkRef) {
    // SAFETY: only `DCounted` uses this function; the `DelayedWork` (and
    // its `work`) is its first field; the test keeps it alive.
    let c = unsafe { &*(r.as_ptr() as *const DCounted) };
    c.at.store(narf_time::timer::jiffies(), Ordering::Release);
    c.runs.fetch_add(1, Ordering::AcqRel);
}

/// Delayed work: not before its delay, then once; `mod_delayed_work`
/// moves a pending one; `cancel_delayed_work_sync` stops one for good.
fn smoke_workqueue_delayed_work_and_mod() -> TestResult {
    let wq = workqueue::system_wq();
    let d = Box::new(DCounted {
        dw: DelayedWork::new(WorkFn::Sync(dcounted_fn), false),
        runs: AtomicUsize::new(0),
        at: AtomicU64::new(0),
    });
    let start = narf_time::timer::jiffies();
    // SAFETY: the Box outlives the work; cancelled below.
    let queued = unsafe { queue_delayed_work_on(me(), wq, &d.dw, 20) };
    // Pushed out before it fired: `mod_delayed_work` reports it pending.
    // SAFETY: as above.
    let modded = unsafe { mod_delayed_work_on(me(), wq, &d.dw, 40) };
    let early = rounds_until(25, || d.runs.load(Ordering::Acquire) != 0);
    let ran = rounds_until(2000, || d.runs.load(Ordering::Acquire) == 1);
    let at = d.at.load(Ordering::Acquire);
    // SAFETY: as above.
    unsafe { queue_delayed_work_on(me(), wq, &d.dw, 10) };
    let cancelled = crate::workqueue::cancel_delayed_work_sync_blocking(&d.dw);
    let after = rounds_until(50, || d.runs.load(Ordering::Acquire) != 1);
    let _ = cancel_delayed_work_sync;
    if !queued || !modded {
        return TestResult::Fail("queue / mod_delayed_work return values");
    }
    if early || !ran || at < start + 40 {
        return TestResult::Fail("a delayed work ran before its (modified) delay");
    }
    if !cancelled || after {
        return TestResult::Fail("cancel_delayed_work_sync did not stop a pending work");
    }
    TestResult::Pass
}
kernel_test_in!("scheduler/workqueue", smoke_workqueue_delayed_work_and_mod);

/// `cancel_work_sync` on a running (sleeping) work waits for it to finish
/// and leaves it idle; `flush_work` on an idle work returns at once.
fn smoke_workqueue_cancel_waits_for_running() -> TestResult {
    let wq = workqueue::system_wq();
    GATE.store(false, Ordering::Release);
    ASYNC_DONE.store(0, Ordering::Release);
    let s = Box::new(WorkStruct::new(WorkFn::Async(sleeper_fn)));
    // SAFETY: the Box outlives the work; cancelled below.
    unsafe { queue_work_on(me(), wq, &s) };
    let started = rounds_until(1000, || !s.is_pending());
    // Open the gate a little later from a timer-free path: the cancel drives
    // executor rounds, during which the gate opens.
    static OPEN_AT: AtomicU64 = AtomicU64::new(0);
    OPEN_AT.store(narf_time::monotonic_ns() + 20_000_000, Ordering::Release);
    #[repr(C)]
    struct Opener {
        work: WorkStruct,
    }
    fn opener_fn(_: WorkRef) -> WorkFuture {
        Box::pin(async {
            while narf_time::monotonic_ns() < OPEN_AT.load(Ordering::Acquire) {
                crate::yield_now().await;
            }
            GATE.store(true, Ordering::Release);
        })
    }
    let o = Box::new(Opener {
        work: WorkStruct::new(WorkFn::Async(opener_fn)),
    });
    // SAFETY: as above; flushed below.
    unsafe { queue_work_on(me(), wq, &o.work) };
    let was = cancel_work_sync_blocking(&s);
    let done = ASYNC_DONE.load(Ordering::Acquire);
    flush_work_blocking(&o.work);
    let idle_flush = flush_work_blocking(&s);
    if !started {
        return TestResult::Fail("the work never started");
    }
    if was || done != 1 {
        return TestResult::Fail("cancel_work_sync returned before the running work finished");
    }
    if idle_flush || s.is_pending() {
        return TestResult::Fail("a cancelled work was left pending");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/workqueue",
    smoke_workqueue_cancel_waits_for_running
);

/// `WQ_MEM_RECLAIM`: when a pool is out of workers (every one asleep in a
/// work, at its limit), its queued works of a reclaim workqueue go to that
/// workqueue's rescuer, which runs them.
fn smoke_workqueue_rescuer_runs_when_pool_is_full() -> TestResult {
    let wq = alloc_workqueue("wq-test-reclaim", WQ_MEM_RECLAIM, 0);
    let plain = alloc_workqueue("wq-test-plain", 0, 0);
    GATE.store(false, Ordering::Release);
    ASYNC_DONE.store(0, Ordering::Release);
    let n = workqueue::MAX_WORKERS_PER_POOL + 1;
    let sleepers: Vec<Box<WorkStruct>> = (0..n)
        .map(|_| Box::new(WorkStruct::new(WorkFn::Async(sleeper_fn))))
        .collect();
    for s in &sleepers {
        // SAFETY: the Boxes outlive the works; all finish below.
        unsafe { queue_work_on(me(), plain, s) };
    }
    // Every worker of the pool is now asleep or about to be.
    let full = rounds_until(2000, || {
        workqueue::__pool_workers(Some(me())) >= workqueue::MAX_WORKERS_PER_POOL
    });
    let maydays = workqueue::maydays();
    let c = counted();
    // SAFETY: as above.
    unsafe { queue_work_on(me(), wq, &c.work) };
    let rescued = rounds_until(2000, || c.runs.load(Ordering::Acquire) == 1);
    GATE.store(true, Ordering::Release);
    let drained = rounds_until(5000, || ASYNC_DONE.load(Ordering::Acquire) == n);
    for s in &sleepers {
        flush_work_blocking(s);
    }
    if !full {
        return TestResult::Skip("the pool did not reach its worker limit");
    }
    if !rescued || workqueue::maydays() == maydays {
        return TestResult::Fail("a reclaim workqueue's work waited on a full pool");
    }
    if !drained {
        return TestResult::Fail("sleeping works did not finish after waking");
    }
    TestResult::Pass
}
kernel_test_in!(
    "scheduler/workqueue",
    smoke_workqueue_rescuer_runs_when_pool_is_full
);
