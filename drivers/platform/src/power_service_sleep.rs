//! Owned asynchronous sleep requests. Every completion belongs to its own
//! Arc, so an older task cannot overwrite a newer request's observed result.

use alloc::sync::Arc;
use core::fmt::Write as _;
use narf_capabilities::{Cap, Invoke, NoopOp};
use narf_lib::sync::IrqSafeSpinLock;
use narf_power::{service::PowerAction, suspend::SuspendError, Power};

#[derive(Debug)]
pub struct SleepRequest {
    action: PowerAction,
    result: IrqSafeSpinLock<Option<Result<(), SuspendError>>>,
}

impl SleepRequest {
    pub fn action(&self) -> PowerAction {
        self.action
    }

    /// None means queued/running, not a completed successful transition.
    pub fn result(&self) -> Option<Result<(), SuspendError>> {
        *self.result.lock()
    }
}

static LAST: IrqSafeSpinLock<Option<Arc<SleepRequest>>> = IrqSafeSpinLock::new(None);

pub fn last_sleep_request() -> Option<Arc<SleepRequest>> {
    LAST.lock().clone()
}

fn complete(request: &SleepRequest, result: Result<(), SuspendError>) {
    *request.result.lock() = Some(result);
    match result {
        Ok(()) => {
            let _ = writeln!(narf_console::Writer, "  power-service: resumed");
        }
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "  power-service: {:?} request not carried out: {error:?}",
                request.action
            );
        }
    }
}

pub(crate) fn schedule_sleep(action: PowerAction, cap: Cap<Power, Invoke>) -> Arc<SleepRequest> {
    let request = Arc::new(SleepRequest {
        action,
        result: IrqSafeSpinLock::new(None),
    });
    *LAST.lock() = Some(request.clone());
    if cap.invoke(NoopOp).is_err() {
        complete(&request, Err(SuspendError::AuthorityRevoked));
        return request;
    }
    let supported = match action {
        PowerAction::Suspend => narf_power::suspend::s3_supported(),
        PowerAction::Freeze => narf_power::s2idle::s2idle_supported(),
        PowerAction::Hibernate => narf_power::hibernate::available(),
        PowerAction::PowerOff => false,
    };
    if !supported {
        complete(&request, Err(SuspendError::NotImplemented));
        return request;
    }
    let owned = request.clone();
    // This exact current Invoke capability survives every Pending poll. The
    // coordinator rechecks it before preparation and after preparation.
    // A hibernation runs on the boot CPU, which its restore resumes on.
    let mut spec = narf_scheduler::TaskSpec::unthrottled();
    if action == PowerAction::Hibernate {
        spec.affinity = narf_scheduler::Affinity::pinned(narf_scheduler::CpuId(0));
    }
    narf_scheduler::spawn_with_spec(
        async move {
            let result = match action {
                PowerAction::Suspend => narf_power::suspend::suspend_async(&cap).await,
                PowerAction::Freeze => narf_power::s2idle::suspend_to_idle_async(&cap).await,
                PowerAction::Hibernate => {
                    narf_power::hibernate::hibernate(&cap).await.map_err(|e| {
                        let _ = writeln!(
                            narf_console::Writer,
                            "  power-service: hibernation failed: {e:?}"
                        );
                        match e {
                            narf_power::hibernate::HibernateError::AuthorityRevoked => {
                                SuspendError::AuthorityRevoked
                            }
                            narf_power::hibernate::HibernateError::Busy => {
                                SuspendError::AlreadySuspending
                            }
                            _ => SuspendError::Aborted,
                        }
                    })
                }
                PowerAction::PowerOff => Err(SuspendError::NotImplemented),
            };
            complete(&owned, result);
        },
        spec,
    );
    request
}
