use super::*;
use crate::amdgpu_navi22_boot::Error as BootError;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Check,
    Quiesce,
    Reinitialize,
    Restart,
    Lose,
}
#[derive(Default)]
struct Model {
    refuse: bool,
    fail: Option<Step>,
    stall: Option<Step>,
    calls: Vec<Call>,
}
fn report() -> crate::amdgpu_navi22_boot::Report {
    crate::amdgpu_navi22_boot::tests::report()
}
impl Backend for Model {
    fn check(&mut self) -> Result<(), Error> {
        self.calls.push(Call::Check);
        if self.refuse {
            Err(Error::Unsupported)
        } else {
            Ok(())
        }
    }
    async fn quiesce(&mut self) -> Result<(), BootError> {
        self.calls.push(Call::Quiesce);
        if self.stall == Some(Step::Quiesce) {
            core::future::pending::<()>().await;
        }
        if self.fail == Some(Step::Quiesce) {
            return Err(BootError::Invalid);
        }
        Ok(())
    }
    async fn reinitialize(&mut self) -> Result<crate::amdgpu_navi22_boot::Report, BootError> {
        self.calls.push(Call::Reinitialize);
        if self.stall == Some(Step::Reinitialize) {
            core::future::pending::<()>().await;
        }
        if self.fail == Some(Step::Reinitialize) {
            return Err(BootError::Reset(
                crate::amdgpu_reset_navi22::Error::DeviceGone,
            ));
        }
        Ok(report())
    }
    async fn restart(&mut self) {
        self.calls.push(Call::Restart);
    }
    fn lose(&mut self) {
        self.calls.push(Call::Lose);
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn navi22_recovery_sequences_quiesce_reset_restart() -> TestResult {
    let mut recovery = Recovery::new();
    let mut model = Model::default();
    let before = recoveries();
    if run(recovery.run(&mut model)) != Ok(report())
        || model.calls
            != [
                Call::Check,
                Call::Quiesce,
                Call::Reinitialize,
                Call::Restart,
            ]
        || recovery.state() != State::Recovered(report())
        || recoveries() != before + 1
    {
        return TestResult::Fail("amdgpu_device_gpu_recover order");
    }
    // A recovered device can be recovered again.
    model.calls.clear();
    if run(recovery.run(&mut model)).is_err() || model.calls.len() != 4 {
        return TestResult::Fail("second recovery refused");
    }
    // A refused recovery has no side effects and keeps the device usable.
    let mut recovery = Recovery::new();
    let mut model = Model {
        refuse: true,
        ..Model::default()
    };
    if run(recovery.run(&mut model)) != Err(Error::Unsupported)
        || model.calls != [Call::Check]
        || recovery.state() != State::Idle
    {
        return TestResult::Fail("refusal touched the device");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-recovery",
    navi22_recovery_sequences_quiesce_reset_restart
);

fn navi22_recovery_failure_is_terminal_device_loss() -> TestResult {
    for (step, error) in [
        (Step::Quiesce, BootError::Invalid),
        (
            Step::Reinitialize,
            BootError::Reset(crate::amdgpu_reset_navi22::Error::DeviceGone),
        ),
    ] {
        let mut recovery = Recovery::new();
        let mut model = Model {
            fail: Some(step),
            ..Model::default()
        };
        let lost = Error::Failed(step, error);
        if run(recovery.run(&mut model)) != Err(lost)
            || recovery.state() != State::Lost(lost)
            || model.calls.last() != Some(&Call::Lose)
            || model.calls.iter().filter(|c| **c == Call::Lose).count() != 1
            || model.calls.contains(&Call::Restart)
        {
            return TestResult::Fail("failed step must report device loss once");
        }
        model.calls.clear();
        if run(recovery.run(&mut model)) != Err(Error::Busy) || !model.calls.is_empty() {
            return TestResult::Fail("lost device recovered again");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-recovery",
    navi22_recovery_failure_is_terminal_device_loss
);

fn navi22_recovery_cancellation_reaches_every_waiter() -> TestResult {
    for step in [Step::Quiesce, Step::Reinitialize] {
        let mut recovery = Recovery::new();
        let mut model = Model {
            stall: Some(step),
            ..Model::default()
        };
        {
            let mut future = core::pin::pin!(recovery.run(&mut model));
            let mut cx = Context::from_waker(Waker::noop());
            if future.as_mut().poll(&mut cx).is_ready() {
                return TestResult::Fail("stalled step completed");
            }
        }
        let expected = if step == Step::Quiesce {
            vec![Call::Check, Call::Quiesce, Call::Lose]
        } else {
            vec![Call::Check, Call::Quiesce, Call::Reinitialize, Call::Lose]
        };
        if model.calls != expected || recovery.state() != State::Lost(Error::Cancelled(step)) {
            return TestResult::Fail("cancellation did not report device loss");
        }
        if run(recovery.run(&mut model)) != Err(Error::Busy) {
            return TestResult::Fail("cancelled recovery replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-recovery",
    navi22_recovery_cancellation_reaches_every_waiter
);
