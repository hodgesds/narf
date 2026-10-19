//! Cancellation-safe FIFO admission for native GPU ring submissions.
use alloc::collections::VecDeque;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Debug)]
struct Entry {
    id: u64,
    waker: Waker,
}
#[derive(Debug)]
struct State {
    next: u64,
    waiters: VecDeque<Entry>,
}
#[derive(Debug)]
pub(crate) struct Queue {
    state: IrqSafeSpinLock<State>,
}
impl Queue {
    pub(crate) const fn new() -> Self {
        Self {
            state: IrqSafeSpinLock::new(State {
                next: 0,
                waiters: VecDeque::new(),
            }),
        }
    }
    pub(crate) fn enter(&self) -> Enter<'_> {
        Enter {
            queue: self,
            id: None,
        }
    }
    fn remove(&self, id: u64) {
        let wake = {
            let mut state = self.state.lock();
            let head = state.waiters.front().is_some_and(|e| e.id == id);
            state.waiters.retain(|e| e.id != id);
            head.then(|| state.waiters.front().map(|e| e.waker.clone()))
                .flatten()
        };
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}
#[derive(Debug)]
pub(crate) struct Enter<'a> {
    queue: &'a Queue,
    id: Option<u64>,
}
#[derive(Debug)]
pub(crate) struct Permit<'a> {
    queue: &'a Queue,
    id: u64,
}
impl<'a> Future for Enter<'a> {
    type Output = Permit<'a>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let queue = self.queue;
        let mut state = queue.state.lock();
        let id = match self.id {
            Some(id) => id,
            None => {
                let id = state.next;
                state.next = id.wrapping_add(1);
                state.waiters.push_back(Entry {
                    id,
                    waker: cx.waker().clone(),
                });
                self.id = Some(id);
                id
            }
        };
        if state.waiters.front().is_some_and(|e| e.id == id) {
            self.id = None;
            Poll::Ready(Permit { queue, id })
        } else {
            if let Some(entry) = state.waiters.iter_mut().find(|e| e.id == id) {
                if !entry.waker.will_wake(cx.waker()) {
                    entry.waker = cx.waker().clone();
                }
            }
            Poll::Pending
        }
    }
}
impl Drop for Enter<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.queue.remove(id);
        }
    }
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.queue.remove(self.id);
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn rdna2_admission_fifo_cancel_and_no_barging() -> TestResult {
        let queue = Queue::new();
        let mut cx = Context::from_waker(Waker::noop());
        let mut first = core::pin::pin!(queue.enter());
        let Poll::Ready(held) = first.as_mut().poll(&mut cx) else {
            return TestResult::Fail("first admission blocked");
        };
        let mut second = alloc::boxed::Box::pin(queue.enter());
        let mut third = core::pin::pin!(queue.enter());
        let mut fourth = core::pin::pin!(queue.enter());
        if second.as_mut().poll(&mut cx).is_ready() || third.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("queue bypassed held permit");
        }
        drop(held);
        if fourth.as_mut().poll(&mut cx).is_ready() || third.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("new arrival bypassed queued waiter");
        }
        drop(second);
        let Poll::Ready(held) = third.as_mut().poll(&mut cx) else {
            return TestResult::Fail("cancelled head wedged queue");
        };
        if fourth.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("permit released before enqueue");
        }
        drop(held);
        if fourth.as_mut().poll(&mut cx).is_pending() {
            return TestResult::Fail("FIFO queue failed to advance");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/rdna2",
        rdna2_admission_fifo_cancel_and_no_barging
    );
}
