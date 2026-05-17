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

fn smoke_input_from_evdev_covers_standard_codes() -> TestResult {
    use crate::KeyCode;
    // Spot-check the boundary cases that hand-coded ranges trip on:
    // 0/1 (Reserved/Escape), 70/71 (last contiguous / first keypad
    // gap), 84..=86 (Linux gap → must be Unknown not UB), 87/88 (F11/
    // F12), 100/101 (RightAlt yes, 101=KEY_LINEFEED no), 127 (Menu),
    // 0x110 (BTN_LEFT, not a KeyCode → Unknown).
    let cases: &[(u16, KeyCode)] = &[
        (0, KeyCode::Reserved),
        (1, KeyCode::Escape),
        (30, KeyCode::A),
        (42, KeyCode::LeftShift),
        (70, KeyCode::ScrollLock),
        (71, KeyCode::Kp7),
        (83, KeyCode::KpDot),
        (84, KeyCode::Unknown),
        (86, KeyCode::Unknown),
        (87, KeyCode::F11),
        (88, KeyCode::F12),
        (100, KeyCode::RightAlt),
        (101, KeyCode::Unknown),
        (102, KeyCode::Home),
        (111, KeyCode::Delete),
        (125, KeyCode::LeftMeta),
        (127, KeyCode::Menu),
        (0x110, KeyCode::Unknown),
        (0xFFFF, KeyCode::Unknown),
    ];
    for &(code, expected) in cases {
        let got = KeyCode::from_evdev(code);
        if got != expected {
            return TestResult::Fail("from_evdev mapping mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_from_evdev_covers_standard_codes);

fn smoke_input_apply_modifiers_shift_press_release() -> TestResult {
    use crate::{apply_modifiers, KeyCode, Modifiers};
    let empty = Modifiers::EMPTY;
    let after_press = apply_modifiers(KeyCode::LeftShift, true, empty);
    if !after_press.contains(Modifiers::SHIFT) {
        return TestResult::Fail("shift press should set SHIFT");
    }
    let after_release = apply_modifiers(KeyCode::LeftShift, false, after_press);
    if after_release.contains(Modifiers::SHIFT) {
        return TestResult::Fail("shift release should clear SHIFT");
    }
    // CapsLock: toggles on press, no-op on release.
    let after_caps_press = apply_modifiers(KeyCode::CapsLock, true, empty);
    if !after_caps_press.contains(Modifiers::CAPS_LOCK) {
        return TestResult::Fail("capslock press should set CAPS_LOCK");
    }
    let after_caps_release = apply_modifiers(KeyCode::CapsLock, false, after_caps_press);
    if !after_caps_release.contains(Modifiers::CAPS_LOCK) {
        return TestResult::Fail("capslock release must not clear CAPS_LOCK");
    }
    // Non-modifier passes through unchanged.
    let after_letter = apply_modifiers(KeyCode::A, true, after_caps_press);
    if after_letter != after_caps_press {
        return TestResult::Fail("non-modifier press shouldn't alter modifier state");
    }
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_apply_modifiers_shift_press_release);

fn smoke_input_push_key_stamps_live_modifiers() -> TestResult {
    use crate::{
        __reset_modifiers_for_test, init_global_ring, pop_key, push_key, KeyCode, Modifiers,
    };
    init_global_ring(8);
    __reset_modifiers_for_test();
    // Drain anything stale.
    while pop_key().is_some() {}
    // Press LeftShift, then press A. The A event must carry SHIFT.
    let _ = push_key(KeyCode::LeftShift, true);
    let _ = push_key(KeyCode::A, true);
    let _ = push_key(KeyCode::A, false);
    let _ = push_key(KeyCode::LeftShift, false);
    let _shift_press = pop_key();
    let a_press = match pop_key() {
        Some(k) => k,
        None => return TestResult::Fail("A press not in ring"),
    };
    if a_press.code != KeyCode::A || !a_press.pressed {
        return TestResult::Fail("A press shape wrong");
    }
    if !a_press.modifiers.contains(Modifiers::SHIFT) {
        return TestResult::Fail("A press should carry SHIFT modifier");
    }
    let _a_release = pop_key();
    let shift_release = match pop_key() {
        Some(k) => k,
        None => return TestResult::Fail("Shift release not in ring"),
    };
    if shift_release.modifiers.contains(Modifiers::SHIFT) {
        return TestResult::Fail("Shift release should not carry SHIFT");
    }
    __reset_modifiers_for_test();
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_push_key_stamps_live_modifiers);

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

// ── Goodix GT911 smokes ────────────────────────────────────────────

extern crate alloc;

fn smoke_goodix_addresses_and_constants() -> TestResult {
    use crate::goodix::{
        I2C_ADDR_PRIMARY, I2C_ADDR_SECONDARY, MAX_TOUCH_POINTS, REG_POINT_BASE, REG_STATUS,
    };
    if I2C_ADDR_PRIMARY != 0x5D {
        return TestResult::Fail("primary I²C addr = 0x5D");
    }
    if I2C_ADDR_SECONDARY != 0x14 {
        return TestResult::Fail("secondary I²C addr = 0x14");
    }
    if MAX_TOUCH_POINTS != 5 {
        return TestResult::Fail("GT911 reports up to 5 simultaneous touches");
    }
    if REG_STATUS != 0x814E {
        return TestResult::Fail("status register = 0x814E");
    }
    if REG_POINT_BASE != 0x814F {
        return TestResult::Fail("first point register = 0x814F");
    }
    TestResult::Pass
}
kernel_test_in!("input/goodix", smoke_goodix_addresses_and_constants);

fn smoke_goodix_coord_report_decodes_two_fingers() -> TestResult {
    use crate::goodix::{CoordReport, STATUS_BUFFER_READY};
    // Status byte: buffer-ready + 2 touches.
    // Finger 0: track 0, x=400, y=240, size=10
    // Finger 1: track 1, x=600, y=300, size=12
    let mut buf = alloc::vec![STATUS_BUFFER_READY | 2];
    buf.push(0); // track id
    buf.extend_from_slice(&400u16.to_le_bytes());
    buf.extend_from_slice(&240u16.to_le_bytes());
    buf.extend_from_slice(&10u16.to_le_bytes());
    buf.push(0); // reserved
    buf.push(1); // track id
    buf.extend_from_slice(&600u16.to_le_bytes());
    buf.extend_from_slice(&300u16.to_le_bytes());
    buf.extend_from_slice(&12u16.to_le_bytes());
    buf.push(0);
    let r = CoordReport::parse(&buf).expect("parse");
    if !r.buffer_ready {
        return TestResult::Fail("buffer-ready bit lost");
    }
    if r.points.len() != 2 {
        return TestResult::Fail("expected 2 touch points");
    }
    if r.points[0].track_id != 0 || r.points[0].x != 400 || r.points[0].y != 240 {
        return TestResult::Fail("finger 0 decode wrong");
    }
    if r.points[1].x != 600 {
        return TestResult::Fail("finger 1 X decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("input/goodix", smoke_goodix_coord_report_decodes_two_fingers);

fn smoke_goodix_coord_report_rejects_overflow() -> TestResult {
    use crate::goodix::{CoordReport, GoodixError};
    let buf = [0xFFu8; 64]; // status byte low nibble = 0xF (15) > 5
    match CoordReport::parse(&buf) {
        Err(GoodixError::BadCount) => TestResult::Pass,
        _ => TestResult::Fail("touch count > 5 must be rejected"),
    }
}
kernel_test_in!("input/goodix", smoke_goodix_coord_report_rejects_overflow);

fn smoke_goodix_coord_report_zero_touches_buffer_ready() -> TestResult {
    use crate::goodix::{CoordReport, STATUS_BUFFER_READY};
    let buf = [STATUS_BUFFER_READY];
    let r = CoordReport::parse(&buf).expect("parse");
    if !r.buffer_ready {
        return TestResult::Fail("buffer-ready flag lost");
    }
    if !r.points.is_empty() {
        return TestResult::Fail("zero touches → empty point list");
    }
    TestResult::Pass
}
kernel_test_in!("input/goodix", smoke_goodix_coord_report_zero_touches_buffer_ready);

fn smoke_goodix_config_checksum_round_trip() -> TestResult {
    use crate::goodix::{config_checksum_byte, verify_config};
    let body = alloc::vec![0x42u8; 184];
    let cs = config_checksum_byte(&body);
    let mut full = body.clone();
    full.push(cs);
    if verify_config(&full).is_err() {
        return TestResult::Fail("freshly-checksummed block must verify");
    }
    full[100] ^= 0xFF;
    if verify_config(&full).is_ok() {
        return TestResult::Fail("tampered block should fail to verify");
    }
    TestResult::Pass
}
kernel_test_in!("input/goodix", smoke_goodix_config_checksum_round_trip);

fn smoke_goodix_command_constants() -> TestResult {
    use crate::goodix::{CMD_CALIBRATION, CMD_READ_COORD, CMD_SOFT_RESET};
    if CMD_READ_COORD != 0 || CMD_SOFT_RESET != 0x02 || CMD_CALIBRATION != 0x04 {
        return TestResult::Fail("command-register byte values per §4.1");
    }
    TestResult::Pass
}
kernel_test_in!("input/goodix", smoke_goodix_command_constants);
