//! Completion publication, cancellation and delayed-delivery races.
use super::*;
use crate::abi_test_support::{kernel_test_in, with_setup, TestResult};
use alloc::task::Wake;
use core::sync::atomic::AtomicBool;

struct TaskRegistration(u64);
impl Drop for TaskRegistration {
    fn drop(&mut self) {
        crate::task::release_task(self.0);
    }
}

struct CheckCompletion {
    wait: Arc<FutexQ>,
    seen: Arc<AtomicBool>,
}

impl Wake for CheckCompletion {
    fn wake(self: Arc<Self>) {
        self.seen.store(self.wait.has_woken(), Ordering::Release);
    }
}

fn queue(key: FutexKey, tid: u64) -> (Arc<FutexQ>, Arc<AtomicBool>) {
    let wait = Arc::new(FutexQ::new(core::iter::once(key)));
    let seen = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(CheckCompletion {
        wait: wait.clone(),
        seen: seen.clone(),
    }));
    futex_queue(key, tid, 0, waker, FUTEX_BITSET_MATCH_ANY, &wait);
    (wait, seen)
}

fn smoke_futex_completion_precedes_delivery_and_skips_bucket() -> TestResult {
    with_setup(|| {
        let key = futex_key(0, 0x7e_7100);
        let (wait, seen) = queue(key, 0x7e_7101);
        let waiter = {
            let mut bucket = futex_wait_bucket(key).values.lock();
            let handle = futex_select_waiter(&bucket, key, FUTEX_BITSET_MATCH_ANY)
                .ok_or("waiter missing")?;
            let waiter = futex_remove_woken(&mut bucket, handle).ok_or("dequeue failed")?;
            // A timeout/signal resume can run before delivery. Successful
            // unqueue must not acquire this still-held bucket lock.
            if !wait.has_woken() || futex_unqueue(&wait, 0, 0x7e_7101) {
                return Err("wake completion was not published at dequeue");
            }
            waiter
        };
        waiter.wake(true);
        if !seen.load(Ordering::Acquire) {
            return Err("notification preceded completion publication");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_futex_completion_precedes_delivery_and_skips_bucket
);

fn smoke_futex_completion_delayed_wake_preserves_new_park() -> TestResult {
    with_setup(|| {
        const TID: u64 = 0x7e_7201;
        let _registration = TaskRegistration(TID);
        let owner = crate::task::Task::new_registered(TID, TID);
        let key = futex_key(0, 0x7e_7200);
        let (wait, seen) = queue(key, TID);
        let delayed = {
            let mut bucket = futex_wait_bucket(key).values.lock();
            let handle = futex_select_waiter(&bucket, key, FUTEX_BITSET_MATCH_ANY)
                .ok_or("waiter missing")?;
            futex_remove_woken(&mut bucket, handle).ok_or("dequeue failed")?
        };
        if futex_unqueue(&wait, 0, TID) {
            return Err("dequeued wait did not complete");
        }
        // The task can observe completion via another wake and start a new
        // syscall before the original waker delivers its notification.
        owner
            .uctx
            .sleep_deadline_ns
            .store(123456789, Ordering::Release);
        let (next, next_seen) = queue(key, TID);
        delayed.wake(true);
        let unchanged = owner.uctx.sleep_deadline_ns.load(Ordering::Acquire) == 123456789
            && !next.has_woken()
            && !next_seen.load(Ordering::Acquire)
            && seen.load(Ordering::Acquire);
        let cancelled = futex_unqueue(&next, 0, TID);
        if !unchanged || !cancelled || next.has_woken() {
            return Err("old delivery completed or cleared a newer park");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_futex_completion_delayed_wake_preserves_new_park
);

fn smoke_futex_completion_requeue_and_cancel_are_not_wakes() -> TestResult {
    with_setup(|| {
        let key = futex_key(0, 0x7e_7300);
        let destination = (1..4096)
            .map(|i| futex_key(0, key.uaddr + 4 * i))
            .find(|k| futex_bucket_index(*k) != futex_bucket_index(key))
            .ok_or("no distinct bucket")?;
        let (wait, seen) = queue(key, 0x7e_7301);
        let moved = futex_requeue_waiters_keyed(key, destination, destination.uaddr, 0, 1, 0);
        let pending = moved == (0, 1) && !wait.has_woken() && !seen.load(Ordering::Acquire);
        let cancelled = futex_unqueue(&wait, 0, 0x7e_7301);
        if !pending || !cancelled || wait.has_woken() || futex_wake_waiters_key(destination, 1) != 0
        {
            return Err("requeue or cancellation reported a successful wait");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_futex_completion_requeue_and_cancel_are_not_wakes
);

fn smoke_futex_completion_vector_keeps_highest_woken_index() -> TestResult {
    with_setup(|| {
        let key = futex_key(0, 0x7e_7350);
        let wait = Arc::new(FutexQ::new([key; 3].into_iter()));
        let hits = Arc::new(AtomicUsize::new(0));
        for idx in 0..3 {
            futex_queue(
                key,
                0x7e_7351,
                idx,
                Waker::from(Arc::new(CountWake(hits.clone()))),
                1 << idx,
                &wait,
            );
        }
        let woken = futex_wake_waiters_key_bitset(key, 3, 0b101);
        let middle_pending = !wait.entry(1).woken.load(Ordering::Acquire);
        let result = futex_unqueue_multiple(&wait, 3, 0x7e_7351);
        if woken != 2
            || hits.load(Ordering::Acquire) != 2
            || !wait.has_woken()
            || !middle_pending
            || result != Some(2)
            || futex_waiter_count_key(key) != 0
        {
            return Err("vector completion lost bitset filtering or highest-index semantics");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_futex_completion_vector_keeps_highest_woken_index
);

fn smoke_futex_cached_wait_excludes_delayed_delivery() -> TestResult {
    with_setup(|| {
        let cache = narf_lib::sync::IrqSafeSpinLock::new(None);
        let key = futex_key(0, 0x7e_7400);
        let first = FutexQ::single_cached(&cache, key);
        let address = Arc::as_ptr(&first);
        drop(first);
        let old = FutexQ::single_cached(&cache, key);
        if Arc::as_ptr(&old) != address {
            return Err("quiescent single-wait storage was not reused");
        }
        let seen = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(CheckCompletion {
            wait: old.clone(),
            seen: seen.clone(),
        }));
        futex_queue(key, 0x7e_7401, 0, waker, FUTEX_BITSET_MATCH_ANY, &old);
        let delayed = {
            let mut bucket = futex_wait_bucket(key).values.lock();
            let handle = futex_select_waiter(&bucket, key, FUTEX_BITSET_MATCH_ANY)
                .ok_or("waiter missing")?;
            futex_remove_woken(&mut bucket, handle).ok_or("dequeue failed")?
        };
        if futex_unqueue(&old, 0, 0x7e_7401) {
            return Err("old wait did not complete");
        }
        drop(old);
        let next = FutexQ::single_cached(&cache, key);
        if Arc::as_ptr(&next) == address {
            return Err("reused a completion record still owned by delayed delivery");
        }
        delayed.wake(true);
        if next.has_woken() || !seen.load(Ordering::Acquire) {
            return Err("old completion leaked into the new wait");
        }
        let address = Arc::as_ptr(&next);
        drop(next);
        let reused = FutexQ::single_cached(&cache, key);
        if Arc::as_ptr(&reused) != address || reused.has_woken() {
            return Err("quiescent replacement was not reset and reused");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/futex",
    smoke_futex_cached_wait_excludes_delayed_delivery
);

struct CountWake(Arc<AtomicUsize>);
impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

fn smoke_signal_wait_handle_stays_with_task() -> TestResult {
    with_setup(|| {
        const TID: u64 = 0x7e_7501;
        let _registration = TaskRegistration(TID);
        let task = crate::task::Task::new_registered(TID, TID);
        let hits = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountWake(hits.clone())));
        register_signal_waker(TID, waker.clone());
        if !dbg_has_signal_waker(TID)
            || SIGNAL_WAKERS[signal_waker_shard(TID)]
                .values
                .lock()
                .as_ref()
                .is_some_and(|m| m.contains_key(&TID))
        {
            return Err("registered task used the fallback signal map");
        }
        task.uctx
            .sleep_deadline_ns
            .store(u64::MAX, Ordering::Release);
        signal_wake_up(TID, true);
        if hits.load(Ordering::Acquire) != 1
            || dbg_has_signal_waker(TID)
            || task.uctx.sleep_deadline_ns.load(Ordering::Acquire) != 0
        {
            return Err("signal did not consume the precise task-owned wait handle");
        }
        register_signal_waker(TID, waker.clone());
        drop_signal_waker(TID);
        if dbg_has_signal_waker(TID) {
            return Err("signal wait cancellation left a handle");
        }
        task.uctx.install_scheduler_waker(&waker);
        signal_wake_up(TID, true);
        if hits.load(Ordering::Acquire) != 2 {
            return Err("signal lost the lifetime-waker fallback between parks");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/signal",
    smoke_signal_wait_handle_stays_with_task
);
