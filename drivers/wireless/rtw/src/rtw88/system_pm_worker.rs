// SPDX-License-Identifier: GPL-2.0-or-later
//! Retain the real parked hardware receipt in a background owner. Cancelling
//! the foreground PM waiter requests rollback; it cannot drop DMA retirement.
use alloc::{boxed::Box, sync::Arc};
use core::{
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    task::{Poll, Waker},
};
use narf_lib::sync::IrqSafeSpinLock;
use narf_power::device_pm::DevicePmError;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Planned,
    Preparing,
    Suspended,
    Resuming,
    Resumed,
    Failed,
}
pub(super) struct Control {
    phase: AtomicU8,
    resume: AtomicBool,
    waiter: IrqSafeSpinLock<Option<Waker>>,
    error: IrqSafeSpinLock<Option<DevicePmError>>,
}
impl Control {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            phase: AtomicU8::new(Phase::Planned as u8),
            resume: AtomicBool::new(false),
            waiter: IrqSafeSpinLock::new(None),
            error: IrqSafeSpinLock::new(None),
        })
    }
    pub(super) fn phase(&self) -> Phase {
        match self.phase.load(Ordering::Acquire) {
            0 => Phase::Planned,
            1 => Phase::Preparing,
            2 => Phase::Suspended,
            3 => Phase::Resuming,
            4 => Phase::Resumed,
            _ => Phase::Failed,
        }
    }
    pub(super) fn error(&self) -> DevicePmError {
        (*self.error.lock()).unwrap_or(DevicePmError::DriverError)
    }
    pub(super) fn request_resume(&self) {
        self.resume.store(true, Ordering::Release);
        let waiter = self.waiter.lock().take();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
    fn failed(&self, error: DevicePmError) {
        *self.error.lock() = Some(error);
        self.phase.store(Phase::Failed as u8, Ordering::Release);
    }
    async fn resume_requested(&self) {
        core::future::poll_fn(|cx| {
            if self.resume.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            let old = self.waiter.lock().replace(cx.waker().clone());
            drop(old);
            if self.resume.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}
/// Native Parked retains the exact original function claim, DMA-retirement
/// token, actual card-off/PCI D3 receipts and parked config. Phase is status
/// only; it never constructs any of those proofs or enables another owner.
#[async_trait::async_trait]
pub(super) trait Backend: Send + 'static {
    type Parked: Send;
    async fn prepare(&mut self) -> Result<Self::Parked, DevicePmError>;
    async fn resume(&mut self, parked: Self::Parked) -> Result<(), DevicePmError>;
}
pub(super) async fn run<B: Backend>(mut backend: B, control: Arc<Control>) {
    control
        .phase
        .store(Phase::Preparing as u8, Ordering::Release);
    let parked = match backend.prepare().await {
        Ok(parked) => parked,
        Err(error) => {
            control.failed(error);
            return;
        }
    };
    control
        .phase
        .store(Phase::Suspended as u8, Ordering::Release);
    control.resume_requested().await;
    control
        .phase
        .store(Phase::Resuming as u8, Ordering::Release);
    match backend.resume(parked).await {
        Ok(()) => control.phase.store(Phase::Resumed as u8, Ordering::Release),
        Err(error) => control.failed(error),
    }
}
