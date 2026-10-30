// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained hardware transitions. Public cancellation drops only a waiter;
//! the persistent device continues polling the exact card transition.
use super::{recovery::Rebuild, *};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Recover,
    Suspend,
    Resume,
    Idle,
}
struct Completion {
    result: Option<Result<bool, Error>>,
    waiters: Vec<Waker>,
}
type ResultSlot = Arc<IrqSafeSpinLock<Completion>>;
pub(super) struct Work {
    operation: Operation,
    result: ResultSlot,
    future: Pin<Box<dyn Future<Output = Result<bool, Error>> + Send>>,
}

impl<I, M, E> Device<I, M, E>
where
    I: Port<Buffer = M> + 'static,
    M: Memory + 'static,
    E: Rebuild<I, M> + 'static,
{
    pub(crate) fn schedule(
        self: &Arc<Self>,
        operation: Operation,
    ) -> Result<impl Future<Output = Result<(), Error>> + Send + 'static, Error> {
        let result = {
            let mut slot = self.work.try_lock().ok_or(Error::Busy)?;
            if let Some(work) = slot.as_ref() {
                if work.operation != operation {
                    return Err(Error::Busy);
                }
                work.result.clone()
            } else {
                let device = self.clone();
                let activity = self.lifecycle.activity_ms.load(Ordering::Acquire);
                let result = Arc::new(IrqSafeSpinLock::new(Completion {
                    result: None,
                    waiters: Vec::new(),
                }));
                *slot = Some(Work {
                    operation,
                    result: result.clone(),
                    future: Box::pin(async move {
                        match operation {
                            Operation::Recover => device.recover_once().await,
                            Operation::Suspend => device.sleep_once(true, None).await,
                            Operation::Idle => device.sleep_once(false, Some(activity)).await,
                            Operation::Resume => {
                                device.lifecycle.suspended.store(false, Ordering::Release);
                                device.recover_once().await
                            }
                        }
                    }),
                });
                result
            }
        };
        if let Some(signal) = self.environment.interrupt() {
            signal.raise();
        }
        let device = self.clone();
        Ok(core::future::poll_fn(move |cx| {
            {
                let mut completion = result.lock();
                if let Some(result) = completion.result {
                    return Poll::Ready(result.map(|_| ()));
                }
                if !completion.waiters.iter().any(|w| w.will_wake(cx.waker())) {
                    if completion.waiters.len() == 16 {
                        return Poll::Ready(Err(Error::Busy));
                    }
                    completion.waiters.push(cx.waker().clone());
                }
            }
            device.poll_transition(cx);
            match result.lock().result {
                Some(result) => Poll::Ready(result.map(|_| ())),
                None => Poll::Pending,
            }
        }))
    }
}

impl<I, M, E> Device<I, M, E>
where
    I: Port<Buffer = M> + 'static,
    M: Memory + 'static,
    E: Environment + 'static,
{
    /// Both a public waiter and the worker can drive progress. Poll ownership
    /// uses a regular mutex; no interrupt-disabling guard crosses a poll.
    pub(crate) fn poll_transition(&self, cx: &mut Context<'_>) {
        let Some(mut slot) = self.work.try_lock() else {
            cx.waker().wake_by_ref();
            return;
        };
        let Some(work) = slot.as_mut() else { return };
        if let Poll::Ready(result) = work.future.as_mut().poll(cx) {
            let wake = {
                let mut completion = work.result.lock();
                completion.result = Some(result);
                core::mem::take(&mut completion.waiters)
            };
            *slot = None;
            drop(slot);
            for wake in wake {
                wake.wake();
            }
        }
    }
}
