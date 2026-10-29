use super::*;
use crate::ath10k::bmi::BmiError;
use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    cell::RefCell,
    future::{ready, Future},
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

fn run<F: Future>(f: F) -> Option<F::Output> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn scripted(
    script: Vec<Result<RecoveryScheduled, RecoveryError>>,
    retries: u32,
) -> (Option<Outcome>, usize, usize) {
    let script = RefCell::new(VecDeque::from(script));
    let calls = RefCell::new(0usize);
    let delays = RefCell::new(0usize);
    let outcome = run(supervise(
        || {
            *calls.borrow_mut() += 1;
            ready(
                script
                    .borrow_mut()
                    .pop_front()
                    .unwrap_or(Err(RecoveryError::Busy)),
            )
        },
        || {
            *delays.borrow_mut() += 1;
            ready(())
        },
        retries,
    ));
    (outcome, calls.into_inner(), delays.into_inner())
}

fn smoke_ath10k_restart_supervisor_schedules_fresh_generation() -> TestResult {
    let ok = Ok(RecoveryScheduled { attempt: 1 });
    if scripted(vec![ok], 5) != (Some(Outcome::Scheduled { attempt: 1 }), 1, 0) {
        return TestResult::Fail("first recover() success must be reported once");
    }
    // A crash seen by a boot stage: its owner is stored only after it returns.
    let two = Ok(RecoveryScheduled { attempt: 2 });
    let script = vec![Err(RecoveryError::Busy), Err(RecoveryError::Busy), two];
    if scripted(script, 5) != (Some(Outcome::Scheduled { attempt: 2 }), 3, 2) {
        return TestResult::Fail("Busy must back off and retry until the owner appears");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/restart",
    smoke_ath10k_restart_supervisor_schedules_fresh_generation
);

fn smoke_ath10k_restart_supervisor_terminal_failures() -> TestResult {
    if scripted(vec![Err(RecoveryError::Exhausted)], 5) != (Some(Outcome::Wedged), 1, 0) {
        return TestResult::Fail("spent attempt budget must be WEDGED without retry");
    }
    let failed = Err(RecoveryError::Transport(BmiError::Pci));
    if scripted(vec![failed], 5) != (Some(Outcome::Failed(BmiError::Pci)), 1, 0) {
        return TestResult::Fail("failed retirement must not be retried");
    }
    if scripted(vec![], 4) != (Some(Outcome::Abandoned), 4, 4) {
        return TestResult::Fail("absent owner must be abandoned after the bounded wait");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/restart",
    smoke_ath10k_restart_supervisor_terminal_failures
);

fn smoke_ath10k_restart_gate_deduplicates_and_reopens() -> TestResult {
    let gate = Gate::new();
    if !gate.request() || !gate.restarting() {
        return TestResult::Fail("first crash must start one supervisor");
    }
    // Crash storms while restarting only count (ATH10K_FLAG_RESTARTING).
    if gate.request() || gate.request() || gate.crashes() != 3 {
        return TestResult::Fail("concurrent crash requests must not spawn again");
    }
    gate.complete();
    if gate.restarting() || !gate.request() || gate.crashes() != 4 {
        return TestResult::Fail("a successor generation's crash must recover again");
    }
    gate.complete();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/restart",
    smoke_ath10k_restart_gate_deduplicates_and_reopens
);
