use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A dispatch vector no in-tree owner arms during kernel tests.
const VECTOR: u8 = 0xe7;

fn smoke_irq_wake_depth_is_balanced() -> TestResult {
    if enable_irq_wake(31) != Err(WakeError::InvalidVector) {
        return TestResult::Fail("an exception vector was armed for wake");
    }
    if disable_irq_wake(VECTOR) != Err(WakeError::Unbalanced) || wake_armed(VECTOR) {
        return TestResult::Fail("unbalanced disable was accepted");
    }
    if enable_irq_wake(VECTOR).is_err() || enable_irq_wake(VECTOR).is_err() {
        return TestResult::Fail("wake arming refused on a SKIP_SET_WAKE controller");
    }
    if !armed_vectors().contains(&VECTOR) {
        return TestResult::Fail("armed vector missing from the suspend allowlist");
    }
    // Depth 2: one disable keeps the line armed (Linux wake_depth).
    if disable_irq_wake(VECTOR).is_err() || !wake_armed(VECTOR) {
        return TestResult::Fail("nested wake users were not counted");
    }
    if disable_irq_wake(VECTOR).is_err() || wake_armed(VECTOR) {
        return TestResult::Fail("last wake user did not disarm");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts/wake", smoke_irq_wake_depth_is_balanced);

fn smoke_irq_wake_latches_only_inside_suspend_window() -> TestResult {
    if enable_irq_wake(VECTOR).is_err() {
        return TestResult::Fail("arm failed");
    }
    // Ordinary runtime delivery is not a system wakeup.
    set_suspend_window(false);
    note_delivery(VECTOR);
    let outside = wakeup_pending();
    set_suspend_window(true);
    // An unarmed vector inside the window is not a wakeup either.
    note_delivery(VECTOR.wrapping_add(1));
    let unarmed = wakeup_pending();
    note_delivery(VECTOR);
    let latched = wakeup_pending() && last_wakeup() == Some(VECTOR);
    set_suspend_window(false);
    // Resuming consumes the latch but keeps the reason.
    let consumed = !wakeup_pending() && last_wakeup() == Some(VECTOR);
    // Opening a new window clears the stale reason.
    set_suspend_window(true);
    let cleared = !wakeup_pending() && last_wakeup().is_none();
    set_suspend_window(false);
    let _ = disable_irq_wake(VECTOR);
    if outside || unarmed {
        return TestResult::Fail("delivery outside the armed window latched a wakeup");
    }
    if !latched {
        return TestResult::Fail("armed delivery inside the window did not latch");
    }
    if !consumed {
        return TestResult::Fail("resume did not consume the latch or lost the reason");
    }
    if !cleared {
        return TestResult::Fail("a new suspend window kept the stale wakeup");
    }
    TestResult::Pass
}
kernel_test_in!(
    "interrupts/wake",
    smoke_irq_wake_latches_only_inside_suspend_window
);
