//! Keep a PM operation alive when its caller cancels. Normal callers poll
//! inline, including boot-time sync/async bridges; only cancellation hands
//! the unfinished operation to the executor for rollback/completion.
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

pub(super) type Cleanup = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// One owner of the presentation gate, acquired before the first await.
pub(super) struct Gate {
    flag: &'static AtomicBool,
    release: fn(),
    held: bool,
}
impl Gate {
    pub(super) fn claim(flag: &'static AtomicBool, release: fn()) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(Self {
            flag,
            release,
            held: true,
        })
    }
    /// Transfer exclusion to the parked suspend, until its resume finishes.
    pub(super) fn park(mut self) {
        self.held = false;
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        if self.held {
            self.flag.store(false, Ordering::Release);
            (self.release)();
        }
    }
}

/// Pin the operation independently of its waiter. Cancellation never drops
/// a partially completed hardware transaction or a retained owner. The
/// operation checks `cancelled` before starting, and before parking a
/// successful suspend; a cancelled suspend rolls back through resume.
pub(super) struct Retained<F: Future + Send + 'static, C: FnOnce(Cleanup)> {
    future: Option<Pin<Box<F>>>,
    cancelled: Arc<AtomicBool>,
    continue_cancelled: Option<C>,
}
impl<F: Future + Send + 'static, C: FnOnce(Cleanup)> Retained<F, C> {
    pub(super) fn new(future: F, cancelled: Arc<AtomicBool>, continue_cancelled: C) -> Self {
        Self {
            future: Some(Box::pin(future)),
            cancelled,
            continue_cancelled: Some(continue_cancelled),
        }
    }
}
// The only structurally pinned field is already pinned in its own Box.
impl<F: Future + Send + 'static, C: FnOnce(Cleanup)> Unpin for Retained<F, C> {}
impl<F: Future + Send + 'static, C: FnOnce(Cleanup)> Future for Retained<F, C> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let result = this
            .future
            .as_mut()
            .expect("PM operation polled after completion")
            .as_mut()
            .poll(cx);
        if result.is_ready() {
            this.future = None;
        }
        result
    }
}
impl<F: Future + Send + 'static, C: FnOnce(Cleanup)> Drop for Retained<F, C> {
    fn drop(&mut self) {
        if let Some(future) = self.future.take() {
            self.cancelled.store(true, Ordering::Release);
            self.continue_cancelled.take().unwrap()(Box::pin(async move {
                let _ = future.await;
            }));
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::sync::atomic::AtomicUsize;
    use core::task::Waker;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::mutex::Mutex;
    use narf_lib::sync::IrqSafeSpinLock;

    fn poll<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }
    async fn phase() {
        let mut once = false;
        core::future::poll_fn(|cx| {
            if core::mem::replace(&mut once, true) {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await
    }
    fn navi48_pm_cancel_retains_each_phase_until_rollback() -> TestResult {
        // The boundaries represent display retirement, eviction, quiesce,
        // PCI save and BACO entry. Their retained futures cannot be dropped.
        for stop in 0..=5 {
            let cancelled = Arc::new(AtomicBool::new(false));
            let observe = cancelled.clone();
            let finished = Arc::new(AtomicUsize::new(0));
            let counts = finished.clone();
            let tasks = Arc::new(IrqSafeSpinLock::new(Vec::<Cleanup>::new()));
            let pending = tasks.clone();
            let mut operation = Box::pin(Retained::new(
                async move {
                    if observe.load(Ordering::Acquire) {
                        return;
                    }
                    for _ in 0..5 {
                        phase().await;
                    }
                    counts.fetch_add(1, Ordering::AcqRel);
                    if observe.load(Ordering::Acquire) {
                        phase().await; // retained resume/rollback
                        counts.fetch_add(1, Ordering::AcqRel);
                    }
                },
                cancelled.clone(),
                move |task| pending.lock().push(task),
            ));
            for _ in 0..stop {
                assert!(poll(operation.as_mut()).is_pending());
            }
            drop(operation);
            assert!(cancelled.load(Ordering::Acquire));
            let mut task = tasks.lock().pop().unwrap();
            while poll(task.as_mut()).is_pending() {}
            assert_eq!(
                finished.load(Ordering::Acquire),
                if stop == 0 { 0 } else { 2 }
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi48-pm",
        navi48_pm_cancel_retains_each_phase_until_rollback
    );

    fn navi48_pm_completion_runs_inline_without_executor() -> TestResult {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut operation = Box::pin(Retained::new(
            async {
                phase().await;
                17
            },
            cancelled.clone(),
            |_| panic!("completed operation spawned"),
        ));
        assert!(poll(operation.as_mut()).is_pending());
        assert_eq!(poll(operation.as_mut()), Poll::Ready(17));
        drop(operation);
        assert!(!cancelled.load(Ordering::Acquire));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi48-pm",
        navi48_pm_completion_runs_inline_without_executor
    );

    fn navi48_pm_cancelled_resume_keeps_its_owner_until_complete() -> TestResult {
        struct Owner(Arc<AtomicUsize>);
        impl Drop for Owner {
            fn drop(&mut self) {
                assert_eq!(self.0.load(Ordering::Acquire), 5);
                self.0.store(6, Ordering::Release);
            }
        }
        for stop in 1..=5 {
            let progress = Arc::new(AtomicUsize::new(0));
            let counts = progress.clone();
            let tasks = Arc::new(IrqSafeSpinLock::new(Vec::<Cleanup>::new()));
            let pending = tasks.clone();
            let mut resume = Box::pin(Retained::new(
                async move {
                    let _owner = Owner(counts.clone());
                    for k in 1..=5 {
                        phase().await;
                        counts.store(k, Ordering::Release);
                    }
                },
                Arc::new(AtomicBool::new(false)),
                move |task| pending.lock().push(task),
            ));
            for _ in 0..stop {
                assert!(poll(resume.as_mut()).is_pending());
            }
            drop(resume);
            assert!(progress.load(Ordering::Acquire) < 5);
            let mut task = tasks.lock().pop().unwrap();
            while poll(task.as_mut()).is_pending() {}
            assert_eq!(progress.load(Ordering::Acquire), 6);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi48-pm",
        navi48_pm_cancelled_resume_keeps_its_owner_until_complete
    );

    fn navi48_pm_cancelled_transition_serializes_resume_and_new_suspend() -> TestResult {
        let mutex = Arc::new(Mutex::new(()));
        let counts = Arc::new(AtomicUsize::new(0));
        let tasks = Arc::new(IrqSafeSpinLock::new(Vec::<Cleanup>::new()));
        let pending = tasks.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let first_mutex = mutex.clone();
        let first_counts = counts.clone();
        let observe = cancelled.clone();
        let mut first = Box::pin(Retained::new(
            async move {
                let _transition = first_mutex.lock().await;
                phase().await;
                assert!(observe.load(Ordering::Acquire));
                // Complete the first suspend and its rollback under the same
                // mutex, before any competing resume/new suspend can enter.
                first_counts.store(1, Ordering::Release);
                phase().await;
                first_counts.store(2, Ordering::Release);
            },
            cancelled,
            move |task| pending.lock().push(task),
        ));
        assert!(poll(first.as_mut()).is_pending());
        let mut second = Box::pin(async {
            let _transition = mutex.lock().await;
            assert_eq!(counts.load(Ordering::Acquire), 2);
        });
        assert!(poll(second.as_mut()).is_pending());
        drop(first);
        assert!(poll(second.as_mut()).is_pending());
        let mut task = tasks.lock().pop().unwrap();
        assert!(poll(task.as_mut()).is_pending());
        assert!(poll(second.as_mut()).is_pending());
        assert!(poll(task.as_mut()).is_ready());
        assert!(poll(second.as_mut()).is_ready());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi48-pm",
        navi48_pm_cancelled_transition_serializes_resume_and_new_suspend
    );

    fn navi48_pm_gate_has_one_owner_and_releases_on_drop() -> TestResult {
        static FLAG: AtomicBool = AtomicBool::new(false);
        let gate = Gate::claim(&FLAG, || {}).unwrap();
        assert!(Gate::claim(&FLAG, || {}).is_none());
        drop(gate);
        assert!(!FLAG.load(Ordering::Acquire));
        Gate::claim(&FLAG, || {}).unwrap().park();
        assert!(FLAG.load(Ordering::Acquire));
        assert!(Gate::claim(&FLAG, || {}).is_none());
        FLAG.store(false, Ordering::Release);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/navi48-pm",
        navi48_pm_gate_has_one_owner_and_releases_on_drop
    );
}
