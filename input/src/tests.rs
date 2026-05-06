//! Per-crate smoke tests for `narf-input`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under the `"input"` subsystem.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_input_ring_push_pop_round_trip() -> TestResult {
    use crate::{EventRing, InputEvent, KeyCode, KeyEvent, Modifiers};
    let r = EventRing::new(4);
    if !r.push(InputEvent::Key(KeyEvent {
        code: KeyCode::A,
        pressed: true,
        modifiers: Modifiers::EMPTY,
    })) {
        return TestResult::Fail("push reported drop on empty ring");
    }
    let popped = match r.pop() {
        Some(e) => e,
        None => return TestResult::Fail("pop empty"),
    };
    if let InputEvent::Key(k) = popped {
        if k.code != KeyCode::A || !k.pressed {
            return TestResult::Fail("popped event mismatch");
        }
    } else {
        return TestResult::Fail("wrong variant");
    }
    if r.pop().is_some() {
        return TestResult::Fail("pop should now be empty");
    }
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_ring_push_pop_round_trip);

fn smoke_input_ring_overflow_drops_oldest() -> TestResult {
    use crate::{EventRing, InputEvent, KeyCode, KeyEvent, Modifiers};
    let r = EventRing::new(2);
    let ev = |c: KeyCode| {
        InputEvent::Key(KeyEvent {
            code: c,
            pressed: true,
            modifiers: Modifiers::EMPTY,
        })
    };
    let _ = r.push(ev(KeyCode::A));
    let _ = r.push(ev(KeyCode::B));
    // Capacity reached; this push drops A.
    let clean = r.push(ev(KeyCode::C));
    if clean {
        return TestResult::Fail("third push reported clean on full ring");
    }
    if r.dropped() != 1 {
        return TestResult::Fail("dropped counter not bumped");
    }
    // Remaining events must be B, C in order.
    if let Some(InputEvent::Key(k)) = r.pop() {
        if k.code != KeyCode::B {
            return TestResult::Fail("expected B first after drop");
        }
    } else {
        return TestResult::Fail("ring unexpectedly empty");
    }
    if let Some(InputEvent::Key(k)) = r.pop() {
        if k.code != KeyCode::C {
            return TestResult::Fail("expected C second");
        }
    } else {
        return TestResult::Fail("ring unexpectedly empty");
    }
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_ring_overflow_drops_oldest);

fn smoke_input_kind_default_domain() -> TestResult {
    use narf_drivers::BoundKind;
    if BoundKind::Input.default_domain() != 6 {
        return TestResult::Fail("Input domain != 6");
    }
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_kind_default_domain);
