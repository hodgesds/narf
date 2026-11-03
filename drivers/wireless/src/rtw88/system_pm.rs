// SPDX-License-Identifier: GPL-2.0-or-later
//! Async family suspend fan-out. Durable workers own retirement/rollback;
//! cancellation of a foreground waiter never drops an in-flight native owner.
use super::{
    functions::Barrier,
    system_pm_worker::{self, Control, Phase},
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;
use narf_power::{
    device_pm::DevicePmError,
    system_pm::{AsyncSystemPm, SystemPmFuture},
};
use narf_time::Deadline;
const PREPARE_MS: u64 = 10_000;
const RESUME_MS: u64 = 30_000;
struct Session {
    controls: Vec<Arc<Control>>,
    _barrier: Arc<Barrier>,
}
static SESSION: IrqSafeSpinLock<Option<Arc<Session>>> = IrqSafeSpinLock::new(None);
fn clear(session: &Arc<Session>) {
    let removed = {
        let mut current = SESSION.lock();
        if current
            .as_ref()
            .is_some_and(|value| Arc::ptr_eq(value, session))
        {
            current.take()
        } else {
            None
        }
    };
    drop(removed);
}
async fn pause() {
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
}
async fn settled(session: &Session) -> Result<(), DevicePmError> {
    let deadline = Deadline::after_ms(RESUME_MS);
    loop {
        if session
            .controls
            .iter()
            .all(|control| matches!(control.phase(), Phase::Resumed | Phase::Failed))
        {
            return session
                .controls
                .iter()
                .find(|control| control.phase() == Phase::Failed)
                .map_or(Ok(()), |control| Err(control.error()));
        }
        if deadline.expired() {
            return Err(DevicePmError::Busy);
        }
        pause().await;
    }
}
fn request_resume(session: &Session) {
    for control in &session.controls {
        control.request_resume();
    }
}
struct Attempt {
    session: Arc<Session>,
    armed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        request_resume(&self.session);
        let session = self.session.clone();
        // This observer owns no device, PCI, DMA or reset operation. Each
        // worker retains its original hardware proofs until rollback ends.
        narf_scheduler::spawn(async move {
            loop {
                if settled(&session).await.is_ok()
                    || session
                        .controls
                        .iter()
                        .all(|control| matches!(control.phase(), Phase::Resumed | Phase::Failed))
                {
                    clear(&session);
                    return;
                }
            }
        });
    }
}
pub(super) struct SystemPm;
impl SystemPm {
    async fn prepare() -> Result<(), DevicePmError> {
        if SESSION.lock().is_some() {
            return Err(DevicePmError::Busy);
        }
        let barrier = Barrier::begin().map_err(|_| DevicePmError::Busy)?;
        let controls: Vec<_> = barrier.owners().iter().map(|_| Control::new()).collect();
        let session = Arc::new(Session {
            controls,
            _barrier: barrier.clone(),
        });
        {
            let mut slot = SESSION.lock();
            if slot.is_some() {
                return Err(DevicePmError::Busy);
            }
            *slot = Some(session.clone());
        }
        for (owner, control) in barrier.owners().iter().zip(&session.controls) {
            let backend = super::system_pm_native::Native::new(owner.clone(), barrier.clone());
            narf_scheduler::spawn(system_pm_worker::run(backend, control.clone()));
        }
        let mut attempt = Attempt {
            session: session.clone(),
            armed: true,
        };
        let deadline = Deadline::after_ms(PREPARE_MS);
        loop {
            let failed = session
                .controls
                .iter()
                .find(|control| control.phase() == Phase::Failed)
                .map(|control| control.error());
            if let Some(error) = failed {
                request_resume(&session);
                let _ = settled(&session).await;
                if session
                    .controls
                    .iter()
                    .all(|control| matches!(control.phase(), Phase::Resumed | Phase::Failed))
                {
                    clear(&session);
                    attempt.armed = false;
                }
                return Err(error);
            }
            if session
                .controls
                .iter()
                .all(|control| control.phase() == Phase::Suspended)
            {
                attempt.armed = false;
                return Ok(());
            }
            if deadline.expired() {
                return Err(DevicePmError::Busy);
            }
            pause().await;
        }
    }
    async fn resume() -> Result<(), DevicePmError> {
        let session = SESSION.lock().clone();
        let Some(session) = session else {
            return Ok(());
        };
        request_resume(&session);
        let mut attempt = Attempt {
            session: session.clone(),
            armed: true,
        };
        let result = settled(&session).await;
        if session
            .controls
            .iter()
            .all(|control| matches!(control.phase(), Phase::Resumed | Phase::Failed))
        {
            clear(&session);
            attempt.armed = false;
        }
        result
    }
}
impl AsyncSystemPm for SystemPm {
    fn prepare_suspend<'a>(&'a self) -> SystemPmFuture<'a> {
        Box::pin(Self::prepare())
    }
    fn resume_from_suspend<'a>(&'a self) -> SystemPmFuture<'a> {
        Box::pin(Self::resume())
    }
}
