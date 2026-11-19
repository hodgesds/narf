use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn facts(device: bool, session: bool, restarting: bool, pinned: u8) -> Facts {
    Facts {
        device,
        session,
        restarting,
        pinned,
    }
}

fn smoke_ath10k_pm_suspend_plan_retires_live_generation() -> TestResult {
    if plan(facts(false, false, false, 0)) != Ok(Plan::Nothing) {
        return TestResult::Fail("no bound function must suspend trivially");
    }
    if plan(facts(true, true, false, 0)) != Ok(Plan::Retire)
        || plan(facts(true, true, false, PINNED_LIMIT - 1)) != Ok(Plan::Retire)
    {
        return TestResult::Fail("a retained session must be retired for power-down");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/pm",
    smoke_ath10k_pm_suspend_plan_retires_live_generation
);

fn smoke_ath10k_pm_suspend_refusals_keep_generation() -> TestResult {
    if plan(facts(true, false, false, 0)) != Err(SuspendError::Busy) {
        return TestResult::Fail("boot in progress must abort suspend as Busy");
    }
    if plan(facts(true, true, true, 0)) != Err(SuspendError::Busy) {
        return TestResult::Fail("automatic recovery in progress must abort suspend");
    }
    if plan(facts(true, true, false, PINNED_LIMIT)) != Err(SuspendError::Pinned) {
        return TestResult::Fail("pinned-generation budget must bound power-downs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/pm",
    smoke_ath10k_pm_suspend_refusals_keep_generation
);

fn smoke_ath10k_pm_resume_clears_retry_timeout() -> TestResult {
    if retry_timeout(0x1234_8056) != Some(0x1234_0056) || retry_timeout(0x1234_0056).is_some() {
        return TestResult::Fail("config 0x41 RETRY_TIMEOUT handling differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/pm",
    smoke_ath10k_pm_resume_clears_retry_timeout
);
