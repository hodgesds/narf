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

fn smoke_ath10k_non_crash_recovery_gate_preserves_firmware_counter() -> TestResult {
    let gate = Gate::new();
    if !gate.request_non_crash() || gate.request_non_crash() || gate.crashes() != 0 {
        return TestResult::Fail("scan cleanup inflated crash counter or duplicated supervisor");
    }
    if gate.request() || gate.crashes() != 1 {
        return TestResult::Fail("real crash while cleanup runs was not counted exactly once");
    }
    gate.complete();
    if !gate.request_non_crash() || gate.crashes() != 1 {
        return TestResult::Fail("non-crash successor changed firmware crash statistics");
    }
    gate.complete();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/restart",
    smoke_ath10k_non_crash_recovery_gate_preserves_firmware_counter
);

fn smoke_ath10k_recovery_scope_rejects_successor_epoch_and_other_owner() -> TestResult {
    let old = Arc::new(17u32);
    let successor = Arc::new(17u32); // same contents never mean the same owner
    let request = Scope {
        generation: 23,
        owner: Some(old.clone()),
    };
    if !request.matches(23, Some(&old))
        || request.matches(24, Some(&old))
        || request.matches(23, Some(&successor))
        || request.matches(23, None)
    {
        return TestResult::Fail("retired scan callback could select another physical generation");
    }
    let crash: Scope<u32> = Scope {
        generation: 23,
        owner: None,
    };
    if !crash.matches(23, None) || crash.matches(24, Some(&successor)) {
        return TestResult::Fail("boot-stage crash escaped its reporting generation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/restart",
    smoke_ath10k_recovery_scope_rejects_successor_epoch_and_other_owner
);

fn smoke_ath10k_pending_recovery_keeps_current_owner_after_stale_callback() -> TestResult {
    let old = Arc::new(17u32);
    let current = Arc::new(17u32);
    let scope = |owner: &Arc<u32>| Scope {
        generation: 24,
        owner: Some(owner.clone()),
    };
    let mut requests = Requests::new();
    drop(requests.enqueue(scope(&old))); // late callback sampled the new epoch
    drop(requests.enqueue(scope(&current)));
    if requests
        .take()
        .is_none_or(|r| r.matches(24, Some(&current)))
        || requests
            .take()
            .is_none_or(|r| !r.matches(24, Some(&current)))
        || requests.take().is_some()
    {
        return TestResult::Fail("stale exact owner suppressed the current cleanup request");
    }
    drop(requests.enqueue(scope(&old)));
    drop(requests.enqueue(scope(&current)));
    let (rejected, superseded) = requests.enqueue(Scope {
        generation: 24,
        owner: None,
    });
    if rejected.is_some() || superseded.len() != 2 {
        return TestResult::Fail("genuine current crash did not supersede exact-owner requests");
    }
    drop(superseded);
    if requests.enqueue(scope(&current)).0.is_none()
        || requests
            .enqueue(Scope {
                generation: 23,
                owner: Some(old),
            })
            .0
            .is_none()
        || requests
            .take()
            .is_none_or(|r| r.owner.is_some() || !r.matches(24, None))
        || requests.take().is_some()
    {
        return TestResult::Fail("recovery queue lost crash scope or admitted obsolete epoch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/restart",
    smoke_ath10k_pending_recovery_keeps_current_owner_after_stale_callback
);

fn smoke_ath10k_scoped_supervisor_abandons_stale_without_busy_retry() -> TestResult {
    let calls = RefCell::new(0usize);
    let delays = RefCell::new(0usize);
    let outcome = run(supervise_scoped(
        || {
            *calls.borrow_mut() += 1;
            ready(Ok(None))
        },
        || {
            *delays.borrow_mut() += 1;
            ready(())
        },
        100,
    ));
    if outcome != Some(Outcome::Abandoned) || *calls.borrow() != 1 || *delays.borrow() != 0 {
        return TestResult::Fail("stale recovery retried against a successor owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/restart",
    smoke_ath10k_scoped_supervisor_abandons_stale_without_busy_retry
);
