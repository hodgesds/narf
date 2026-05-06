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

// ── RMI4 codec smokes ──────────────────────────────────────────────

fn smoke_rmi4_pdt_entry_round_trip() -> TestResult {
    use crate::rmi4::{PdtEntry, F11_2D_TOUCHPAD};
    // PDT entry: query/cmd/ctl/data bases at 0x40/0x41/0x42/0x43,
    // interrupt source count = 1, version = 0, function number = 0x11.
    let buf = [0x40, 0x41, 0x42, 0x43, 0x01, F11_2D_TOUCHPAD];
    let entry = PdtEntry::decode(&buf).expect("decode").expect("non-terminal");
    if entry.function_number != F11_2D_TOUCHPAD {
        return TestResult::Fail("function number mismatch");
    }
    if entry.interrupt_source_count != 1 {
        return TestResult::Fail("IRQ source count lives in low 3 bits");
    }
    if entry.query_base != 0x40 || entry.data_base != 0x43 {
        return TestResult::Fail("base register layout lost");
    }
    TestResult::Pass
}
kernel_test_in!("input/rmi4", smoke_rmi4_pdt_entry_round_trip);

fn smoke_rmi4_pdt_terminator_short_circuits() -> TestResult {
    use crate::rmi4::PdtEntry;
    // Function number 0x00 = end-of-table.
    let buf = [0u8; 6];
    match PdtEntry::decode(&buf).expect("decode") {
        None => TestResult::Pass,
        Some(_) => TestResult::Fail("function-number 0x00 must terminate the walk"),
    }
}
kernel_test_in!("input/rmi4", smoke_rmi4_pdt_terminator_short_circuits);

fn smoke_rmi4_f01_device_status_decode() -> TestResult {
    use crate::rmi4::F01DeviceStatus;
    // Unconfigured (bit 7) + status code 0x05 (Configuration CRC Failure).
    let s = F01DeviceStatus::decode(0x80 | 0x05);
    if s.status_code != 0x05 {
        return TestResult::Fail("status code lives in low nibble");
    }
    if !s.unconfigured {
        return TestResult::Fail("unconfigured bit lost");
    }
    if s.flash_programming_mode {
        return TestResult::Fail("flash-programming bit shouldn't be set");
    }
    TestResult::Pass
}
kernel_test_in!("input/rmi4", smoke_rmi4_f01_device_status_decode);

fn smoke_rmi4_f01_device_control_byte_pack() -> TestResult {
    use crate::rmi4::{f01_device_control_byte, F01_CONFIGURED, F01_REPORT_RATE_HIGH, F01_SLEEP_NORMAL};
    let b = f01_device_control_byte(F01_SLEEP_NORMAL, true, true);
    if b & F01_CONFIGURED == 0 {
        return TestResult::Fail("configured bit not set");
    }
    if b & F01_REPORT_RATE_HIGH == 0 {
        return TestResult::Fail("report-rate-high bit not set");
    }
    if (b & 0x03) != F01_SLEEP_NORMAL {
        return TestResult::Fail("sleep-mode field lost");
    }
    TestResult::Pass
}
kernel_test_in!("input/rmi4", smoke_rmi4_f01_device_control_byte_pack);

fn smoke_rmi4_finger_position_packing() -> TestResult {
    use crate::rmi4::Finger;
    // X = 0xABC (12 bits), Y = 0x123, w_x = 0x07, w_y = 0x05.
    // X high byte = 0xAB; X low nibble = 0xC -> goes into byte2[7..4].
    // Y high byte = 0x12; Y low nibble = 0x3 -> goes into byte2[3..0].
    let buf = [0xAB, 0x12, 0xC3, 0x07, 0x05];
    let f = Finger::parse(&buf);
    if f.x != 0xABC {
        return TestResult::Fail("X 12-bit packing wrong");
    }
    if f.y != 0x123 {
        return TestResult::Fail("Y 12-bit packing wrong");
    }
    if f.w_x != 0x07 || f.w_y != 0x05 {
        return TestResult::Fail("touch widths lost");
    }
    if !f.present {
        return TestResult::Fail("non-zero report should mark finger present");
    }
    TestResult::Pass
}
kernel_test_in!("input/rmi4", smoke_rmi4_finger_position_packing);

fn smoke_rmi4_touchpad_report_two_fingers() -> TestResult {
    use crate::rmi4::{Finger, TouchpadReport};
    // 2 fingers, each takes 2 bits. So state_bytes = 1.
    // States: finger0 = 01 (present), finger1 = 00 (no finger) ⇒ byte 0 = 0x01.
    // Finger 0 report: x=0x100, y=0x200, w_x=4, w_y=4
    //   byte 0 = 0x10 (X high)
    //   byte 1 = 0x20 (Y high)
    //   byte 2 = 0x00 (low nibbles)
    //   byte 3 = 0x04 (Wx)
    //   byte 4 = 0x04 (Wy)
    // Finger 1 report: all zeros
    let buf = [
        0x01, // state byte
        0x10, 0x20, 0x00, 0x04, 0x04, // finger 0
        0, 0, 0, 0, 0, // finger 1 (all zero)
    ];
    let r = TouchpadReport::parse(&buf, 2).expect("parse");
    if r.fingers.len() != 2 {
        return TestResult::Fail("expected 2 finger slots");
    }
    if !r.fingers[0].present {
        return TestResult::Fail("finger 0 should be present");
    }
    if r.fingers[1].present {
        return TestResult::Fail("finger 1 should be absent");
    }
    if r.fingers[0].x != 0x100 || r.fingers[0].y != 0x200 {
        return TestResult::Fail("finger 0 position decode wrong");
    }
    let _f: Finger = r.fingers[0]; // Copy compile-check
    TestResult::Pass
}
kernel_test_in!("input/rmi4", smoke_rmi4_touchpad_report_two_fingers);

fn smoke_rmi4_touchpad_report_rejects_short_buffer() -> TestResult {
    use crate::rmi4::{Rmi4Error, TouchpadReport};
    // 5 fingers requires 2 state bytes + 5*5 = 27 bytes total.
    let buf = [0u8; 5];
    match TouchpadReport::parse(&buf, 5) {
        Err(Rmi4Error::Short) => TestResult::Pass,
        _ => TestResult::Fail("under-sized buffer must be rejected"),
    }
}
kernel_test_in!("input/rmi4", smoke_rmi4_touchpad_report_rejects_short_buffer);
