//! Driver-owned work shared by executor polls and synchronous network drains.

use alloc::boxed::Box;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use narf_lib::mutex::Mutex;

/// A short, nonblocking lock serializes polls; the operation itself retains
/// logical device ownership across Pending. Both entry paths use this helper.
pub(super) fn poll_work(slot: &Mutex<Option<Work>>, cx: &mut Context<'_>) -> Poll<()> {
    let Some(mut slot) = slot.try_lock() else {
        cx.waker().wake_by_ref();
        return Poll::Pending;
    };
    let Some(work) = slot.as_mut() else {
        return Poll::Ready(());
    };
    if work.poll(cx).is_pending() {
        return Poll::Pending;
    }
    *slot = None;
    Poll::Ready(())
}

/// Dropping a waiter never drops the in-flight firmware/key operation. The
/// device retains this slot until a terminal poll releases its state guard.
pub(super) struct Work {
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
}
impl Work {
    pub(super) fn new(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self {
            future: Box::pin(future),
        }
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.future.as_mut().poll(cx)
    }
}

pub(super) struct PendingTx<T> {
    frame: T,
    deadline: narf_time::Deadline,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Transmit {
    Sent,
    Busy,
    Expired,
}

impl<T> PendingTx<T> {
    pub(super) fn new(frame: T) -> Self {
        Self {
            frame,
            deadline: narf_time::Deadline::after_ms(2000),
        }
    }

    /// Try once. A lack of credit preserves the exact original packet and
    /// its deadline; success alone permits the caller to retire this slot.
    pub(super) fn progress<E>(
        &self,
        submit: impl FnOnce(&T) -> Result<bool, E>,
    ) -> Result<Transmit, E> {
        if self.deadline.expired() {
            Ok(Transmit::Expired)
        } else {
            submit(&self.frame).map(|sent| if sent { Transmit::Sent } else { Transmit::Busy })
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "progress_tests.rs"]
mod tests;
