//! Host tests. The KABI is replaced by `abi::host` stand-ins: a per-thread
//! console transcript, the host heap and a per-thread clock moved by hand.

extern crate std;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::abi::{advance_ns, take_transcript};
use crate::console::{print_fmt, LINE};
use crate::exec::{block_on, Executor, Run, Stopped, MAX_PASSES};
use crate::heap::KernelHeap;
use crate::sync::{Mutex, SpinLock};
use crate::time::{now_ns, sleep_ms, yield_now, Deadline};

fn leak_executor() -> &'static Executor {
    Box::leak(Box::new(Executor::new()))
}

// ── console ─────────────────────────────────────────────────────────

#[test]
fn short_line_is_one_console_write() {
    take_transcript();
    crate::printkln!("probe {} at {:#x}", "ath11k", 0x1103);
    assert_eq!(take_transcript(), ["probe ath11k at 0x1103\n"]);
}

#[test]
fn long_line_splits_without_losing_bytes() {
    take_transcript();
    let long: String = core::iter::repeat_n('x', LINE * 2 + 10).collect();
    print_fmt(format_args!("{long}"));
    let writes = take_transcript();
    assert!(writes.len() >= 3);
    assert!(writes.iter().all(|w| w.len() <= LINE));
    assert_eq!(writes.concat(), long);
}

#[test]
fn split_never_lands_inside_a_utf8_sequence() {
    take_transcript();
    // 'é' is two bytes; an odd prefix puts a boundary mid-character at LINE.
    let mut s = String::from("a");
    while s.len() < LINE * 3 {
        s.push('é');
    }
    print_fmt(format_args!("{s}"));
    let writes = take_transcript();
    // Every write reached the console (a non-UTF-8 write would be dropped
    // with -EINVAL and missing from the transcript).
    assert_eq!(writes.concat(), s);
}

#[test]
fn empty_output_writes_nothing() {
    take_transcript();
    print_fmt(format_args!(""));
    assert!(take_transcript().is_empty());
}

// ── heap ────────────────────────────────────────────────────────────

#[test]
fn heap_round_trips_through_the_kernel_allocator() {
    let heap = KernelHeap;
    let layout = Layout::from_size_align(4096, 64).unwrap();
    // SAFETY: valid non-zero layout; freed with the same layout below.
    let p = unsafe { heap.alloc(layout) };
    assert!(!p.is_null());
    assert_eq!(p as usize % 64, 0);
    // SAFETY: `p` names 4096 writable bytes.
    unsafe {
        p.write_bytes(0xa5, 4096);
        heap.dealloc(p, layout);
    }
}

// ── locks ───────────────────────────────────────────────────────────

#[test]
fn spinlock_try_lock_fails_while_held() {
    let lock = SpinLock::new(1u32);
    let guard = lock.lock();
    assert!(lock.is_locked());
    assert!(lock.try_lock().is_none());
    drop(guard);
    *lock.try_lock().unwrap() += 1;
    assert_eq!(lock.into_inner(), 2);
}

#[test]
fn spinlock_serialises_threads() {
    let lock = Arc::new(SpinLock::new(0u64));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let lock = lock.clone();
            std::thread::spawn(move || {
                for _ in 0..10_000 {
                    *lock.lock() += 1;
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(*lock.lock(), 40_000);
}

#[test]
fn mutex_waiter_is_woken_by_the_release() {
    let exec = leak_executor();
    let mutex: &'static Mutex<Vec<u32>> = Box::leak(Box::new(Mutex::new(Vec::new())));
    // The holder keeps the lock across two yields; the waiter must not get
    // in until it lets go, and must then run without a fresh spawn.
    exec.spawn(async move {
        let mut g = mutex.lock().await;
        g.push(1);
        yield_now().await;
        yield_now().await;
        g.push(2);
    })
    .unwrap();
    exec.spawn(async move {
        mutex.lock().await.push(3);
    })
    .unwrap();
    let mut runs = 0;
    while exec.run() != Run::Idle {
        runs += 1;
        assert!(runs < 10, "mutex waiter never completed");
    }
    assert_eq!(*mutex.try_lock().unwrap(), [1, 2, 3]);
}

#[test]
fn releasing_the_mutex_wakes_the_parked_waiter_exactly_once() {
    use alloc::task::Wake;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);

    let mutex = Mutex::new(7u32);
    let held = mutex.try_lock().unwrap();
    let mut waiter = pin!(mutex.lock());
    assert!(waiter.as_mut().poll(&mut cx).is_pending());
    // A second poll while still held must not park a duplicate waker.
    assert!(waiter.as_mut().poll(&mut cx).is_pending());
    assert_eq!(count.0.load(Ordering::Acquire), 0);
    drop(held);
    assert_eq!(count.0.load(Ordering::Acquire), 1);
    match waiter.as_mut().poll(&mut cx) {
        Poll::Ready(guard) => assert_eq!(*guard, 7),
        Poll::Pending => panic!("woken waiter could not take the free mutex"),
    };
}

// ── time ────────────────────────────────────────────────────────────

#[test]
fn sleep_is_pending_until_the_clock_passes_the_deadline() {
    let exec = leak_executor();
    let done: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    exec.spawn(async move {
        sleep_ms(5).await;
        done.store(1, Ordering::Release);
    })
    .unwrap();
    assert_eq!(exec.run(), Run::Pending(1));
    advance_ns(4_999_999);
    assert_eq!(exec.run(), Run::Pending(1));
    assert_eq!(done.load(Ordering::Acquire), 0);
    advance_ns(1);
    assert_eq!(exec.run(), Run::Idle);
    assert_eq!(done.load(Ordering::Acquire), 1);
}

#[test]
fn deadline_saturates_and_reports_remaining() {
    let start = now_ns();
    let d = Deadline::after_ns(1_000);
    assert_eq!(d.remaining_ns(), 1_000);
    assert!(!d.expired());
    advance_ns(1_000);
    assert!(d.expired());
    assert_eq!(d.remaining_ns(), 0);
    assert_eq!(Deadline::after_ns(u64::MAX).as_ns(), u64::MAX);
    assert!(now_ns() >= start);
}

// ── executor ────────────────────────────────────────────────────────

#[test]
fn spawned_tasks_complete_and_leave_the_executor_idle() {
    let exec = leak_executor();
    let hits: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    for _ in 0..3 {
        exec.spawn(async move {
            hits.fetch_add(1, Ordering::AcqRel);
        })
        .unwrap();
    }
    assert_eq!(exec.live(), 3);
    assert_eq!(exec.run(), Run::Idle);
    assert_eq!(hits.load(Ordering::Acquire), 3);
    assert_eq!(exec.live(), 0);
}

#[test]
fn a_wake_during_the_pass_gets_another_pass_in_the_same_run() {
    let exec = leak_executor();
    exec.spawn(async {
        // Two yields complete within one `run`: each wakes the executor.
        yield_now().await;
        yield_now().await;
    })
    .unwrap();
    assert_eq!(exec.run(), Run::Idle);
}

#[test]
fn a_self_waking_task_cannot_pin_the_upcall() {
    let exec = leak_executor();
    let polls: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    exec.spawn(async move {
        loop {
            polls.fetch_add(1, Ordering::AcqRel);
            yield_now().await;
        }
    })
    .unwrap();
    assert_eq!(exec.run(), Run::Pending(1));
    assert_eq!(polls.load(Ordering::Acquire), MAX_PASSES);
}

#[test]
fn a_task_spawned_by_a_task_runs_in_the_same_call() {
    let exec = leak_executor();
    let hits: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    exec.spawn(async move {
        exec.spawn(async move {
            hits.fetch_add(1, Ordering::AcqRel);
        })
        .unwrap();
    })
    .unwrap();
    assert_eq!(exec.run(), Run::Idle);
    assert_eq!(hits.load(Ordering::Acquire), 1);
}

#[test]
fn a_reentrant_run_reports_busy_instead_of_deadlocking() {
    let exec = leak_executor();
    let inner: &'static SpinLock<Option<Run>> = Box::leak(Box::new(SpinLock::new(None)));
    exec.spawn(async move {
        *inner.lock() = Some(exec.run());
    })
    .unwrap();
    assert_eq!(exec.run(), Run::Idle);
    assert_eq!(*inner.lock(), Some(Run::Busy));
}

#[test]
fn stop_refuses_new_tasks_and_drops_pending_ones() {
    struct DropFlag(&'static AtomicUsize);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }
    let exec = leak_executor();
    let dropped: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    exec.spawn(async move {
        let _flag = DropFlag(dropped);
        sleep_ms(1_000_000).await;
    })
    .unwrap();
    assert_eq!(exec.run(), Run::Pending(1));
    exec.stop();
    assert_eq!(exec.spawn(async {}), Err(Stopped));
    assert_eq!(exec.run(), Run::Idle);
    assert_eq!(dropped.load(Ordering::Acquire), 1);
    assert_eq!(exec.live(), 0);
}

#[test]
fn concurrent_runs_from_two_cpus_poll_each_task_exclusively() {
    // Two "upcalls" hammer `run` while tasks count their own polls under a
    // non-atomic counter guarded by a flag: overlapping polls would trip it.
    let exec = leak_executor();
    let in_poll: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    let finished: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    for _ in 0..16 {
        exec.spawn(async move {
            for _ in 0..50 {
                assert_eq!(in_poll.fetch_add(1, Ordering::AcqRel), 0);
                in_poll.fetch_sub(1, Ordering::AcqRel);
                yield_now().await;
            }
            finished.fetch_add(1, Ordering::AcqRel);
        })
        .unwrap();
    }
    let threads: Vec<_> = (0..2)
        .map(|_| {
            std::thread::spawn(move || {
                // Bounded, so a broken executor fails the test instead of
                // hanging it.
                for _ in 0..1_000_000 {
                    if finished.load(Ordering::Acquire) == 16 {
                        break;
                    }
                    let _ = exec.run();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(finished.load(Ordering::Acquire), 16);
    assert_eq!(exec.live(), 0);
}

#[test]
fn block_on_drives_a_self_advancing_future() {
    let out = block_on(async {
        yield_now().await;
        41 + 1
    });
    assert_eq!(out, 42);
}
