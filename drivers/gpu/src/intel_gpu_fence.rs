//! Terminal job completion. Cancelling a wait never cancels GPU ownership.

use alloc::collections::BTreeMap;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JobError {
    Reset,
}

#[derive(Debug)]
struct State {
    result: Option<Result<(), JobError>>,
    waiters: BTreeMap<u64, Waker>,
    next_waiter: u64,
}

#[derive(Debug)]
pub struct CompletionFence {
    state: IrqSafeSpinLock<State>,
}

impl Default for CompletionFence {
    fn default() -> Self {
        Self::new()
    }
}

impl CompletionFence {
    pub fn new() -> Self {
        Self {
            state: IrqSafeSpinLock::new(State {
                result: None,
                waiters: BTreeMap::new(),
                next_waiter: 0,
            }),
        }
    }

    pub fn result(&self) -> Option<Result<(), JobError>> {
        self.state.lock().result
    }

    /// Only the hardware request owner may establish a terminal result.
    pub(crate) fn signal(&self, result: Result<(), JobError>) {
        let waiters = {
            let mut state = self.state.lock();
            if state.result.is_some() {
                return;
            }
            state.result = Some(result);
            core::mem::take(&mut state.waiters)
        };
        for (_, waker) in waiters {
            waker.wake();
        }
    }

    pub fn wait(&self) -> FenceWait<'_> {
        FenceWait {
            fence: self,
            waiter: None,
        }
    }
}

#[derive(Debug)]
pub struct FenceWait<'a> {
    fence: &'a CompletionFence,
    waiter: Option<u64>,
}

impl Future for FenceWait<'_> {
    type Output = Result<(), JobError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut state = this.fence.state.lock();
        if let Some(result) = state.result {
            return Poll::Ready(result);
        }
        let key = *this.waiter.get_or_insert_with(|| {
            let key = state.next_waiter;
            state.next_waiter = key.checked_add(1).expect("Intel fence waiter id exhausted");
            key
        });
        if !state
            .waiters
            .get(&key)
            .is_some_and(|w| w.will_wake(cx.waker()))
        {
            state.waiters.insert(key, cx.waker().clone());
        }
        Poll::Pending
    }
}

impl Drop for FenceWait<'_> {
    fn drop(&mut self) {
        if let Some(key) = self.waiter {
            self.fence.state.lock().waiters.remove(&key);
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn smoke_wait_ownership() -> TestResult {
        let fence = CompletionFence::new();
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let mut cancelled = fence.wait();
        let mut retained = fence.wait();
        if Pin::new(&mut cancelled).poll(&mut cx).is_ready()
            || Pin::new(&mut retained).poll(&mut cx).is_ready()
        {
            return TestResult::Fail("uncompleted job signalled");
        }
        drop(cancelled);
        if fence.result().is_some() || fence.state.lock().waiters.len() != 1 {
            return TestResult::Fail("wait cancellation changed job ownership");
        }
        fence.signal(Err(JobError::Reset));
        fence.signal(Ok(()));
        if counter.0.load(Ordering::Relaxed) != 1
            || Pin::new(&mut retained).poll(&mut cx) != Poll::Ready(Err(JobError::Reset))
        {
            return TestResult::Fail("terminal error or wake lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_fence", smoke_wait_ownership);
}
