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

/// `dispatch_pointer_to_node` must emit relative motion AND button
/// transitions in a single evdev frame (one `SYN_REPORT`). Regression for
/// the PS/2 mouse only forwarding motion to evdev — clicks never reached
/// the compositor because the button `EV_KEY` events were dropped.
fn smoke_input_evdev_pointer_frame_carries_button() -> TestResult {
    use crate::evdev::{dispatch_pointer_to_node, key, rel, DeviceCaps, EventType, ROUTER};

    let mut caps = DeviceCaps::new();
    caps.add_rel(rel::REL_X);
    caps.add_rel(rel::REL_Y);
    caps.add_key(key::BTN_LEFT);
    let (id, node) = ROUTER.register_device(caps);
    let reader = match ROUTER.open_reader(id) {
        Some(r) => r,
        None => return TestResult::Fail("open_reader failed"),
    };

    // One packet: move (5, -3) with the left button going down.
    dispatch_pointer_to_node(&node, 5, -3, &[(key::BTN_LEFT, true)]);

    // Expect: REL_X=5, REL_Y=-3, KEY BTN_LEFT=1, then SYN_REPORT.
    let mut saw_relx = false;
    let mut saw_rely = false;
    let mut saw_btn = false;
    let mut saw_syn = false;
    while let Some(ev) = reader.poll_event() {
        match ev.type_ {
            EventType::Rel if ev.code == rel::REL_X && ev.value == 5 => saw_relx = true,
            EventType::Rel if ev.code == rel::REL_Y && ev.value == -3 => saw_rely = true,
            EventType::Key if ev.code == key::BTN_LEFT && ev.value == 1 => saw_btn = true,
            EventType::Syn => saw_syn = true,
            _ => {}
        }
    }
    ROUTER.unregister_device(id);

    if !saw_relx || !saw_rely {
        return TestResult::Fail("motion REL_X/REL_Y missing from pointer frame");
    }
    if !saw_btn {
        return TestResult::Fail("button BTN_LEFT press missing from pointer frame");
    }
    if !saw_syn {
        return TestResult::Fail("SYN_REPORT frame terminator missing");
    }
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_evdev_pointer_frame_carries_button);

fn smoke_input_evdev_abs_pointer_frame_is_absolute() -> TestResult {
    use crate::evdev::{dispatch_abs_pointer_to_node, key, DeviceCaps, EventType, ROUTER};
    use crate::{abs, AxisInfo};

    // An absolute pointer (virtio-tablet): ABS_X/ABS_Y with a range + buttons,
    // and crucially NO relative axes.
    let range = AxisInfo {
        min: 0,
        max: 0x7FFF,
        fuzz: 0,
        flat: 0,
        res: 0,
    };
    let mut caps = DeviceCaps::new();
    caps.add_abs_info(abs::ABS_X, range);
    caps.add_abs_info(abs::ABS_Y, range);
    caps.add_key(key::BTN_LEFT);
    // The range must round-trip so EVIOCGABS can report it (libinput drops an
    // absolute axis with an empty range).
    if caps.abs_info(abs::ABS_X).map(|a| a.max) != Some(0x7FFF) {
        return TestResult::Fail("abs_info range did not round-trip through DeviceCaps");
    }
    if caps.relbit.get(crate::evdev::rel::REL_X) {
        return TestResult::Fail("absolute pointer must not advertise REL_X");
    }

    let (id, node) = ROUTER.register_device(caps);
    let reader = match ROUTER.open_reader(id) {
        Some(r) => r,
        None => return TestResult::Fail("open_reader failed"),
    };

    // One frame: absolute position (16000, 12000) with the left button down.
    dispatch_abs_pointer_to_node(&node, 16000, 12000, true, &[(key::BTN_LEFT, true)]);

    let mut saw_absx = false;
    let mut saw_absy = false;
    let mut saw_btn = false;
    let mut saw_syn = false;
    let mut saw_rel = false;
    while let Some(ev) = reader.poll_event() {
        match ev.type_ {
            EventType::Abs if ev.code == abs::ABS_X && ev.value == 16000 => saw_absx = true,
            EventType::Abs if ev.code == abs::ABS_Y && ev.value == 12000 => saw_absy = true,
            EventType::Key if ev.code == key::BTN_LEFT && ev.value == 1 => saw_btn = true,
            EventType::Rel => saw_rel = true,
            EventType::Syn => saw_syn = true,
            _ => {}
        }
    }
    ROUTER.unregister_device(id);

    if saw_rel {
        return TestResult::Fail("absolute pointer frame must not emit EV_REL");
    }
    if !saw_absx || !saw_absy {
        return TestResult::Fail("absolute ABS_X/ABS_Y position missing from frame");
    }
    if !saw_btn {
        return TestResult::Fail("button BTN_LEFT press missing from absolute frame");
    }
    if !saw_syn {
        return TestResult::Fail("SYN_REPORT frame terminator missing");
    }
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_evdev_abs_pointer_frame_is_absolute);

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
    let entry = PdtEntry::decode(&buf)
        .expect("decode")
        .expect("non-terminal");
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
    use crate::rmi4::{
        f01_device_control_byte, F01_CONFIGURED, F01_REPORT_RATE_HIGH, F01_SLEEP_NORMAL,
    };
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
kernel_test_in!(
    "input/rmi4",
    smoke_rmi4_touchpad_report_rejects_short_buffer
);

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
kernel_test_in!(
    "input/goodix",
    smoke_goodix_coord_report_decodes_two_fingers
);

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
kernel_test_in!(
    "input/goodix",
    smoke_goodix_coord_report_zero_touches_buffer_ready
);

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

// ═══════════════════════════════════════════════════════════════════════════════
// evdev layer smokes (10 required)
// ═══════════════════════════════════════════════════════════════════════════════

// ── 1. EvdevEvent wire-size matches Linux struct input_event (16 bytes) ───────

fn smoke_evdev_event_size_matches_linux() -> TestResult {
    use crate::evdev::EvdevEvent;
    // Linux 64-bit kernel struct input_event:
    //   time = 8 + 8 bytes, type u16 + code u16 + value i32 = 16 bytes.
    // Ref: include/uapi/linux/input.h struct input_event.
    if core::mem::size_of::<EvdevEvent>() != 16 {
        return TestResult::Fail("EvdevEvent must be 16 bytes to match Linux struct input_event");
    }
    TestResult::Pass
}
kernel_test_in!("input/evdev", smoke_evdev_event_size_matches_linux);

// ── 2. Key + button + axis code constants match Linux ─────────────────────────

fn smoke_evdev_code_constants_pinned() -> TestResult {
    use crate::evdev::key;
    // Ref: include/uapi/linux/input-event-codes.h
    if key::KEY_A != 30 {
        return TestResult::Fail("KEY_A must be 30");
    }
    if key::BTN_LEFT != 0x110 {
        return TestResult::Fail("BTN_LEFT must be 0x110");
    }
    use crate::evdev::rel;
    if rel::REL_X != 0 {
        return TestResult::Fail("REL_X must be 0");
    }
    use crate::evdev::abs;
    if abs::ABS_X != 0 {
        return TestResult::Fail("ABS_X must be 0");
    }
    TestResult::Pass
}
kernel_test_in!("input/evdev", smoke_evdev_code_constants_pinned);

// ── 3. Queue overflow → SYN_DROPPED emitted ───────────────────────────────────

fn smoke_evdev_queue_overflow_syn_dropped() -> TestResult {
    use crate::evdev::key::KEY_A;
    use crate::evdev::syn::SYN_DROPPED;
    use crate::evdev::{DeviceCaps, EvdevEvent, EventType, ROUTER};

    let mut caps = DeviceCaps::new();
    caps.add_key(KEY_A);
    let (id, node) = ROUTER.register_device(caps);

    // Fill ring to capacity (256 slots).
    for i in 0u32..256 {
        node.dispatch(EvdevEvent {
            time: i as u64,
            type_: EventType::Key,
            code: KEY_A,
            value: 1,
        });
    }
    // One more push causes overflow + SYN_DROPPED insertion.
    node.dispatch(EvdevEvent {
        time: 256,
        type_: EventType::Key,
        code: KEY_A,
        value: 0,
    });

    let reader = ROUTER.open_reader(id).expect("reader");
    let mut found_dropped = false;
    let mut limit = 300usize;
    while let Some(ev) = reader.poll_event() {
        if ev.type_ == EventType::Syn && ev.code == SYN_DROPPED {
            found_dropped = true;
            break;
        }
        limit -= 1;
        if limit == 0 {
            break;
        }
    }
    ROUTER.unregister_device(id);
    if !found_dropped {
        return TestResult::Fail("overflow did not produce SYN_DROPPED");
    }
    TestResult::Pass
}
kernel_test_in!("input/evdev", smoke_evdev_queue_overflow_syn_dropped);

// ── 4. Capability bitmap: KEY_A + KEY_B reported, not KEY_C ───────────────────

fn smoke_evdev_capability_bitmap() -> TestResult {
    use crate::evdev::key::{KEY_A, KEY_B, KEY_C};
    use crate::evdev::{DeviceCaps, EventType};

    let mut caps = DeviceCaps::new();
    caps.add_key(KEY_A);
    caps.add_key(KEY_B);

    if !caps.has(EventType::Key, KEY_A) {
        return TestResult::Fail("KEY_A should be in caps");
    }
    if !caps.has(EventType::Key, KEY_B) {
        return TestResult::Fail("KEY_B should be in caps");
    }
    if caps.has(EventType::Key, KEY_C) {
        return TestResult::Fail("KEY_C should NOT be in caps");
    }
    TestResult::Pass
}
kernel_test_in!("input/evdev", smoke_evdev_capability_bitmap);

// ── 4b. Identity + properties round-trip through the router ──────────────────

fn smoke_evdev_identity_round_trips_through_router() -> TestResult {
    use crate::evdev::{bus, prop, DeviceCaps, InputId, ROUTER};

    let mut caps = DeviceCaps::new();
    // The synthetic default every unplumbed producer still reports.
    if caps.name != "narf-input" || caps.id.bustype != bus::VIRTUAL {
        return TestResult::Fail("default caps must keep the virtual narf-input identity");
    }
    caps.set_identity(
        "ELAN09BD I2C-HID Touchpad",
        "i2c-ELAN0001/input0",
        "",
        InputId::new(bus::I2C, 0x04F3, 0x3045, 0x0001),
    );
    caps.add_prop(prop::POINTER);
    caps.add_prop(prop::BUTTONPAD);
    let (id, _node) = ROUTER.register_device(caps);
    let got = ROUTER.caps(id).expect("caps");
    ROUTER.unregister_device(id);
    if got.name != "ELAN09BD I2C-HID Touchpad"
        || got.phys != "i2c-ELAN0001/input0"
        || got.id != InputId::new(bus::I2C, 0x04F3, 0x3045, 0x0001)
        || !got.has_prop(prop::BUTTONPAD)
        || !got.has_prop(prop::POINTER)
        || got.has_prop(prop::DIRECT)
    {
        return TestResult::Fail("registered identity/properties did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!(
    "input/evdev",
    smoke_evdev_identity_round_trips_through_router
);

// ── 4c. MT slot-protocol-B frame: two contacts, move, primary hand-off ───────

fn smoke_evdev_mt_frame_two_contacts_and_release() -> TestResult {
    use crate::abs;
    use crate::evdev::{DeviceCaps, EventType, MtContactUpdate, MtEvdevState, ROUTER};

    let (id, node) = ROUTER.register_device(DeviceCaps::new());
    let reader = ROUTER.open_reader(id).expect("reader");
    let mut state = MtEvdevState::new(2);
    let upd = |slot, active, tracking_id, x, y| MtContactUpdate {
        slot,
        active,
        tracking_id,
        x,
        y,
        pressure: None,
    };

    // Frame 1: two contacts down — the frame the old I2C-HID path
    // collapsed to a single relative pointer.
    let n = state.dispatch_frame(
        &node,
        &[upd(0, true, 7, 100, 200), upd(1, true, 9, 300, 400)],
        false,
        false,
    );
    if n == 0 || state.active_contacts() != 2 {
        return TestResult::Fail("two-contact frame emitted nothing");
    }
    let mut events = alloc::vec::Vec::new();
    while let Some(ev) = reader.poll_event() {
        events.push(ev);
    }
    let has = |type_: EventType, code: u16, value: i32| {
        events
            .iter()
            .any(|e| e.type_ == type_ && e.code == code && e.value == value)
    };
    if !has(EventType::Abs, abs::ABS_MT_SLOT, 1)
        || !has(EventType::Abs, abs::ABS_MT_TRACKING_ID, 9)
        || !has(EventType::Abs, abs::ABS_MT_POSITION_X, 300)
        || !has(EventType::Abs, abs::ABS_X, 100)
        || !has(EventType::Key, crate::evdev::key::BTN_TOUCH, 1)
    {
        return TestResult::Fail("two-contact frame missing MT/ST events");
    }
    if events.iter().filter(|e| e.type_ == EventType::Syn).count() != 1 {
        return TestResult::Fail("frame must carry exactly one SYN_REPORT");
    }

    // Frame 2: release slot 0 — tracking id -1, ABS_X/Y hand off to the
    // surviving slot-1 contact, BTN_TOUCH stays down.
    let n = state.dispatch_frame(&node, &[upd(0, false, 7, 100, 200)], true, false);
    if n == 0 || state.active_contacts() != 1 {
        return TestResult::Fail("release frame emitted nothing");
    }
    let mut events = alloc::vec::Vec::new();
    while let Some(ev) = reader.poll_event() {
        events.push(ev);
    }
    let has = |type_: EventType, code: u16, value: i32| {
        events
            .iter()
            .any(|e| e.type_ == type_ && e.code == code && e.value == value)
    };
    if !has(EventType::Abs, abs::ABS_MT_TRACKING_ID, -1)
        || !has(EventType::Abs, abs::ABS_X, 300)
        || !has(EventType::Key, crate::evdev::key::BTN_LEFT, 1)
        || has(EventType::Key, crate::evdev::key::BTN_TOUCH, 0)
    {
        return TestResult::Fail("release frame must hand off primary and keep BTN_TOUCH");
    }
    ROUTER.unregister_device(id);
    TestResult::Pass
}
kernel_test_in!("input/evdev", smoke_evdev_mt_frame_two_contacts_and_release);

// ── 5. Reader blocking-wait future yields when an event arrives ────────────────

fn smoke_evdev_reader_wait_future_resolves() -> TestResult {
    use crate::evdev::{DeviceCaps, EvdevEvent, EventType, ROUTER};
    use core::future::Future;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    let (id, node) = ROUTER.register_device(DeviceCaps::new());
    let reader = ROUTER.open_reader(id).expect("reader");

    // Poll the future before any event arrives — should be Pending.
    let mut fut = reader.wait_event_async();
    // SAFETY: we don't move `fut` after this pin.
    let mut fut = unsafe { core::pin::Pin::new_unchecked(&mut fut) };

    static VTABLE: RawWakerVTable = {
        unsafe fn clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTABLE)
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop_waker(_: *const ()) {}
        RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker)
    };
    let raw = RawWaker::new(core::ptr::null(), &VTABLE);
    // SAFETY: `raw` pairs a null data pointer with `VTABLE`, whose clone returns a
    // fresh RawWaker over the same null pointer and the same `'static` VTABLE, while
    // wake/wake_by_ref/drop are no-ops that never dereference the (unused) pointer.
    // This satisfies the RawWaker contract, so `Waker::from_raw` is sound.
    // SAFETY: Valid memory or trusted environment
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);

    match fut.as_mut().poll(&mut cx) {
        Poll::Pending => {}
        Poll::Ready(_) => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("future should be Pending before event pushed");
        }
    }

    // Push an event — future should now resolve.
    node.dispatch(EvdevEvent {
        time: 0,
        type_: EventType::Key,
        code: crate::evdev::key::KEY_A,
        value: 1,
    });

    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(Some(ev)) => {
            ROUTER.unregister_device(id);
            if ev.type_ != EventType::Key {
                return TestResult::Fail("wrong event type from future");
            }
        }
        Poll::Ready(None) => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("future resolved to None before device removal");
        }
        Poll::Pending => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("future still Pending after event pushed");
        }
    }
    TestResult::Pass
}
kernel_test_in!("input/evdev", smoke_evdev_reader_wait_future_resolves);

// ── 6. Many-readers fan-out (multiple readers can attach) ─────────────────────

fn smoke_evdev_many_readers_fanout() -> TestResult {
    use crate::evdev::{DeviceCaps, EvdevEvent, EventType, ROUTER};

    let (id, node) = ROUTER.register_device(DeviceCaps::new());
    let r1 = ROUTER.open_reader(id).expect("reader1");
    let r2 = ROUTER.open_reader(id).expect("reader2");
    let r3 = ROUTER.open_reader(id).expect("reader3");

    node.dispatch(EvdevEvent {
        time: 1,
        type_: EventType::Key,
        code: crate::evdev::key::KEY_A,
        value: 1,
    });
    node.dispatch(EvdevEvent {
        time: 2,
        type_: EventType::Key,
        code: crate::evdev::key::KEY_B,
        value: 1,
    });
    node.dispatch(EvdevEvent {
        time: 3,
        type_: EventType::Key,
        code: crate::evdev::key::KEY_A,
        value: 0,
    });

    let ev1 = r1.poll_event();
    let ev2 = r2.poll_event();
    let ev3 = r3.poll_event();

    ROUTER.unregister_device(id);

    // At least one reader must have seen an event (shared ring).
    let saw_event = ev1.is_some() || ev2.is_some() || ev3.is_some();
    drop((r1, r2, r3));
    if !saw_event {
        return TestResult::Fail("no reader received any event");
    }
    TestResult::Pass
}
kernel_test_in!("input/evdev", smoke_evdev_many_readers_fanout);

// ── 7. uinput: create device with KEY_A cap, inject press, reader sees it ─────

fn smoke_uinput_inject_key_press() -> TestResult {
    use crate::evdev::key::KEY_A;
    use crate::evdev::DeviceCaps;
    use crate::evdev::{EventType, ROUTER};
    use crate::uinput::UserDevice;

    let mut caps = DeviceCaps::new();
    caps.add_key(KEY_A);
    let dev = UserDevice::create(caps);
    let id = dev.id();

    let reader = ROUTER.open_reader(id).expect("reader");
    dev.inject_key(KEY_A, true);

    let mut found = false;
    let mut limit = 10usize;
    while let Some(ev) = reader.poll_event() {
        if ev.type_ == EventType::Key && ev.code == KEY_A && ev.value == 1 {
            found = true;
        }
        limit -= 1;
        if limit == 0 {
            break;
        }
    }
    drop(dev); // unregisters device
    if !found {
        return TestResult::Fail("reader did not see KEY_A press from uinput");
    }
    TestResult::Pass
}
kernel_test_in!("input/evdev", smoke_uinput_inject_key_press);

// ── 8. i8042 key dispatch helper → reader sees EV_KEY with correct code ───────

fn smoke_evdev_i8042_key_routes_to_evdev() -> TestResult {
    use crate::evdev::key::KEY_A;
    use crate::evdev::{DeviceCaps, EventType, ROUTER};

    let mut caps = DeviceCaps::new();
    caps.add_key(KEY_A);
    let (id, node) = ROUTER.register_device(caps);
    let reader = ROUTER.open_reader(id).expect("reader");

    // Use the i8042 driver helper directly.
    crate::evdev::dispatch_key_to_node(&node, KEY_A, true);

    let ev = reader.poll_event();
    ROUTER.unregister_device(id);
    match ev {
        Some(e) if e.type_ == EventType::Key && e.code == KEY_A && e.value == 1 => TestResult::Pass,
        Some(_) => TestResult::Fail("wrong event from i8042 key dispatch"),
        None => TestResult::Fail("no event from i8042 key dispatch"),
    }
}
kernel_test_in!("input/evdev", smoke_evdev_i8042_key_routes_to_evdev);

// ── 9. i8042 mouse motion helper → reader sees EV_REL/REL_X ──────────────────

fn smoke_evdev_i8042_mouse_routes_to_evdev() -> TestResult {
    use crate::evdev::{rel, DeviceCaps, EventType, ROUTER};

    let mut caps = DeviceCaps::new();
    caps.add_rel(rel::REL_X);
    caps.add_rel(rel::REL_Y);
    let (id, node) = ROUTER.register_device(caps);
    let reader = ROUTER.open_reader(id).expect("reader");

    crate::evdev::dispatch_rel_to_node(&node, 5, -3);

    let mut found_x = false;
    let mut limit = 10usize;
    while let Some(ev) = reader.poll_event() {
        if ev.type_ == EventType::Rel && ev.code == rel::REL_X && ev.value == 5 {
            found_x = true;
        }
        limit -= 1;
        if limit == 0 {
            break;
        }
    }
    ROUTER.unregister_device(id);
    if !found_x {
        return TestResult::Fail("REL_X event not seen from mouse dispatch");
    }
    TestResult::Pass
}
kernel_test_in!("input/evdev", smoke_evdev_i8042_mouse_routes_to_evdev);

// ── 10. Drop device → SYN_DROPPED + reader handle invalidates ─────────────────

fn smoke_evdev_device_drop_invalidates_reader() -> TestResult {
    use crate::evdev::syn::SYN_DROPPED;
    use crate::evdev::{DeviceCaps, EventType, ROUTER};

    let (id, _node) = ROUTER.register_device(DeviceCaps::new());
    let reader = ROUTER.open_reader(id).expect("reader");

    ROUTER.unregister_device(id);

    let ev = reader.poll_event();
    match ev {
        Some(e) if e.type_ == EventType::Syn && e.code == SYN_DROPPED => {}
        Some(_) => return TestResult::Fail("expected SYN_DROPPED, got different event"),
        None => return TestResult::Fail("expected SYN_DROPPED, got None"),
    }
    if reader.is_valid() {
        return TestResult::Fail("reader should be invalid after device removal");
    }
    TestResult::Pass
}
kernel_test_in!("input/evdev", smoke_evdev_device_drop_invalidates_reader);

// Linux drivers/tty/sysrq.c: with Alt and SysRq held, the next key press is a
// SysRq command, is recorded, and is NOT delivered to readers; a plain key, or
// the letter with only Alt or only SysRq held, is delivered normally.
fn smoke_input_sysrq_alt_sysrq_t_is_a_command() -> TestResult {
    use crate::evdev::{dispatch_key_to_node, take_sysrq_request, DeviceCaps, EventType, ROUTER};
    const KEY_LEFTALT: u16 = 56;
    const KEY_SYSRQ: u16 = 99;
    const KEY_T: u16 = 20;

    let mut caps = DeviceCaps::new();
    for k in [KEY_LEFTALT, KEY_SYSRQ, KEY_T] {
        caps.add_key(k);
    }
    let (id, node) = ROUTER.register_device(caps);
    let reader = match ROUTER.open_reader(id) {
        Some(r) => r,
        None => return TestResult::Fail("open_reader failed"),
    };
    let _ = take_sysrq_request();
    let t_events = |reader: &crate::evdev::Reader| {
        let mut n = 0;
        while let Some(ev) = reader.poll_event() {
            if ev.type_ == EventType::Key && ev.code == KEY_T {
                n += 1;
            }
        }
        n
    };

    // A plain T is an ordinary key.
    dispatch_key_to_node(&node, KEY_T, true);
    dispatch_key_to_node(&node, KEY_T, false);
    if take_sysrq_request().is_some() || t_events(&reader) != 2 {
        return TestResult::Fail("a plain T was treated as a SysRq command");
    }
    // Alt alone, then SysRq alone: still ordinary.
    dispatch_key_to_node(&node, KEY_LEFTALT, true);
    dispatch_key_to_node(&node, KEY_T, true);
    dispatch_key_to_node(&node, KEY_T, false);
    dispatch_key_to_node(&node, KEY_LEFTALT, false);
    dispatch_key_to_node(&node, KEY_SYSRQ, true);
    dispatch_key_to_node(&node, KEY_T, true);
    dispatch_key_to_node(&node, KEY_T, false);
    dispatch_key_to_node(&node, KEY_SYSRQ, false);
    if take_sysrq_request().is_some() || t_events(&reader) != 4 {
        return TestResult::Fail("T with only Alt or only SysRq held was a SysRq command");
    }
    // Alt+SysRq+T: recorded, and the T press/release is swallowed.
    dispatch_key_to_node(&node, KEY_LEFTALT, true);
    dispatch_key_to_node(&node, KEY_SYSRQ, true);
    dispatch_key_to_node(&node, KEY_T, true);
    dispatch_key_to_node(&node, KEY_T, false);
    dispatch_key_to_node(&node, KEY_SYSRQ, false);
    dispatch_key_to_node(&node, KEY_LEFTALT, false);
    let req = take_sysrq_request();
    let delivered = t_events(&reader);
    ROUTER.unregister_device(id);
    if req != Some(KEY_T) {
        return TestResult::Fail("Alt+SysRq+T did not record a SysRq T command");
    }
    if delivered != 0 {
        return TestResult::Fail("the SysRq command key reached the reader");
    }
    if take_sysrq_request().is_some() {
        return TestResult::Fail("a SysRq request was taken twice");
    }
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_sysrq_alt_sysrq_t_is_a_command);

// Linux `drivers/tty/sysrq.c` keeps the Alt/SysRq state per input handle
// (`struct sysrq_state`, one per connected keyboard in `sysrq_connect`), so a
// modifier held on one keyboard never arms another. A device whose Alt is
// stuck down (or was unplugged mid-press) must not turn SysRq+T on a second
// keyboard into a command, and must not swallow that keyboard's T.
fn smoke_input_sysrq_state_is_per_device() -> TestResult {
    use crate::evdev::{dispatch_key_to_node, take_sysrq_request, DeviceCaps, EventType, ROUTER};
    const KEY_LEFTALT: u16 = 56;
    const KEY_SYSRQ: u16 = 99;
    const KEY_T: u16 = 20;

    let keyboard = || {
        let mut caps = DeviceCaps::new();
        for k in [KEY_LEFTALT, KEY_SYSRQ, KEY_T] {
            caps.add_key(k);
        }
        ROUTER.register_device(caps)
    };
    let (id_a, node_a) = keyboard();
    let (id_b, node_b) = keyboard();
    let reader_b = match ROUTER.open_reader(id_b) {
        Some(r) => r,
        None => return TestResult::Fail("open_reader failed"),
    };
    let _ = take_sysrq_request();

    // Alt held on keyboard A; SysRq+T on keyboard B.
    dispatch_key_to_node(&node_a, KEY_LEFTALT, true);
    dispatch_key_to_node(&node_b, KEY_SYSRQ, true);
    dispatch_key_to_node(&node_b, KEY_T, true);
    dispatch_key_to_node(&node_b, KEY_T, false);
    dispatch_key_to_node(&node_b, KEY_SYSRQ, false);
    dispatch_key_to_node(&node_a, KEY_LEFTALT, false);
    let req = take_sysrq_request();
    let mut t = 0;
    while let Some(ev) = reader_b.poll_event() {
        if ev.type_ == EventType::Key && ev.code == KEY_T {
            t += 1;
        }
    }
    ROUTER.unregister_device(id_a);
    ROUTER.unregister_device(id_b);
    if req.is_some() {
        return TestResult::Fail("Alt on one keyboard armed SysRq on another");
    }
    if t != 2 {
        return TestResult::Fail("the second keyboard's T was swallowed");
    }
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_sysrq_state_is_per_device);

/// The serial producers' fill never overfills the byte ring: it stops at
/// capacity and throttles, leaving the rest in the device, instead of letting
/// `EventRing::push` evict the oldest queued byte. Without the atomic room
/// check two producers (the UART IRQ and the reader's refill) could both push
/// into the last slot and cut a character out of the middle of the input.
fn smoke_input_fill_byte_ring_never_evicts() -> TestResult {
    crate::init_global_ring(64);
    crate::__reset_global_ring_for_test();
    while crate::pop_ascii_byte().is_some() {}
    let cap = crate::BYTE_RING_CAPACITY;
    let mut next = 0usize;
    let queued = crate::fill_byte_ring(
        || {
            next += 1;
            Some((next % 251) as u8)
        },
        usize::MAX,
    );
    let pulled = next;
    // A second producer finds no room and pulls nothing from its device.
    let mut second = 0usize;
    let queued2 = crate::fill_byte_ring(
        || {
            second += 1;
            Some(0xff)
        },
        usize::MAX,
    );
    let first = crate::pop_ascii_byte();
    let mut rest = 1usize;
    while crate::pop_ascii_byte().is_some() {
        rest += 1;
    }
    if queued != cap || pulled != cap {
        return TestResult::Fail("fill_byte_ring did not stop at the ring's capacity");
    }
    if queued2 != 0 || second != 0 {
        return TestResult::Fail("a fill of a full ring pulled a byte it could not queue");
    }
    if first != Some(1) || rest != cap {
        return TestResult::Fail("a queued serial byte was evicted");
    }
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_fill_byte_ring_never_evicts);

/// Every parked console reader is woken by serial input, not just the last
/// one to park. With `ttyS0` and the VTs separate ttys, a serial shell and the
/// getty on tty1 park at the same time; a single waker slot let the VT reader
/// overwrite the shell's waker, and the shell slept through its own input.
fn smoke_input_console_input_wakes_every_reader() -> TestResult {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{RawWaker, RawWakerVTable, Waker};

    fn counter_waker(c: &Arc<AtomicUsize>) -> Waker {
        unsafe fn clone(p: *const ()) -> RawWaker {
            // SAFETY: `p` came from `Arc::into_raw` below.
            unsafe { Arc::increment_strong_count(p as *const AtomicUsize) };
            RawWaker::new(p, &VTABLE)
        }
        unsafe fn wake(p: *const ()) {
            // SAFETY: consumes the reference `clone`/`into_raw` handed out.
            let c = unsafe { Arc::from_raw(p as *const AtomicUsize) };
            c.fetch_add(1, Ordering::SeqCst);
        }
        unsafe fn wake_by_ref(p: *const ()) {
            // SAFETY: `p` is a live `Arc<AtomicUsize>` pointer.
            unsafe { &*(p as *const AtomicUsize) }.fetch_add(1, Ordering::SeqCst);
        }
        unsafe fn drop(p: *const ()) {
            // SAFETY: releases the reference this waker owned.
            unsafe { Arc::decrement_strong_count(p as *const AtomicUsize) };
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        let p = Arc::into_raw(c.clone()) as *const ();
        // SAFETY: the vtable upholds the RawWaker contract for an Arc.
        unsafe { Waker::from_raw(RawWaker::new(p, &VTABLE)) }
    }

    crate::init_global_ring(64);
    crate::__reset_global_ring_for_test();
    let serial_reader = Arc::new(AtomicUsize::new(0));
    let vt_reader = Arc::new(AtomicUsize::new(0));
    crate::register_byte_waker(&counter_waker(&serial_reader));
    crate::register_byte_waker(&counter_waker(&vt_reader));
    let _ = crate::push_global(crate::InputEvent::AsciiByte(b'x'));
    narf_lib::deferred_wake::drain_and_wake();
    while crate::pop_ascii_byte().is_some() {}
    if serial_reader.load(Ordering::SeqCst) != 1 || vt_reader.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("console input did not wake every parked reader");
    }
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_console_input_wakes_every_reader);

// ── LED state (issue #768) ────────────────────────────────────────
// The input core owns the per-device LED bitmap; producers either
// register a sink (i8042) or poll `led_state` (I2C-HID pump).

static LED_SINK_LAST: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);
static LED_SINK_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn recording_led_sink(bitmap: u16) {
    LED_SINK_LAST.store(bitmap, core::sync::atomic::Ordering::SeqCst);
    LED_SINK_CALLS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}

fn smoke_input_evdev_led_caps_and_ev_led_state() -> TestResult {
    use crate::evdev::{led, DeviceCaps, EvdevEvent, EventType, ROUTER};
    use core::sync::atomic::Ordering;

    // Caps: add_led publishes the ledbit + EV_LED in EVIOCGBIT terms.
    let mut caps = DeviceCaps::new();
    if caps.has(EventType::Led, led::LED_CAPSL) {
        return TestResult::Fail("LED_CAPSL advertised before add_led");
    }
    caps.add_led(led::LED_NUML);
    caps.add_led(led::LED_CAPSL);
    caps.add_led(led::LED_SCROLLL);
    if !caps.has(EventType::Led, led::LED_NUML)
        || !caps.has(EventType::Led, led::LED_CAPSL)
        || !caps.has(EventType::Led, led::LED_SCROLLL)
    {
        return TestResult::Fail("add_led did not set the ledbit bits");
    }
    if caps.has(EventType::Led, led::LED_MAIL) {
        return TestResult::Fail("undeclared LED_MAIL advertised");
    }
    if caps.evbit & (1 << (EventType::Led as u16)) == 0 {
        return TestResult::Fail("EV_LED missing from evbit after add_led");
    }

    LED_SINK_LAST.store(0, Ordering::SeqCst);
    LED_SINK_CALLS.store(0, Ordering::SeqCst);
    let (id, node) = ROUTER.register_device(caps);
    node.set_led_sink(recording_led_sink);
    let ev = |code: u16, value: i32| EvdevEvent {
        time: 0,
        type_: EventType::Led,
        code,
        value,
    };

    // EV_LED set: state bit lands, sink fires once with the bitmap.
    node.dispatch(ev(led::LED_CAPSL, 1));
    if node.led_state() != (1 << led::LED_CAPSL) {
        return TestResult::Fail("EV_LED CAPSL=1 did not set the state bit");
    }
    if ROUTER.led_state(id) != Some(1 << led::LED_CAPSL) {
        return TestResult::Fail("ROUTER.led_state disagrees with the node");
    }
    if LED_SINK_CALLS.load(Ordering::SeqCst) != 1
        || LED_SINK_LAST.load(Ordering::SeqCst) != (1 << led::LED_CAPSL)
    {
        return TestResult::Fail("sink not fired exactly once with the new bitmap");
    }
    // Re-dispatching the same state is a no-op: no second sink call.
    node.dispatch(ev(led::LED_CAPSL, 1));
    if LED_SINK_CALLS.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("idempotent EV_LED re-set fired the sink again");
    }
    // Clear, then an out-of-range code is ignored entirely.
    node.dispatch(ev(led::LED_CAPSL, 0));
    if node.led_state() != 0 || LED_SINK_CALLS.load(Ordering::SeqCst) != 2 {
        return TestResult::Fail("EV_LED CAPSL=0 did not clear + fire");
    }
    node.dispatch(ev(led::LED_MAX + 1, 1));
    if node.led_state() != 0 || LED_SINK_CALLS.load(Ordering::SeqCst) != 2 {
        return TestResult::Fail("out-of-range EV_LED code changed state");
    }
    ROUTER.unregister_device(id);
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_evdev_led_caps_and_ev_led_state);

fn smoke_input_evdev_lock_keys_toggle_leds() -> TestResult {
    use crate::evdev::{key, led, DeviceCaps, EvdevEvent, EventType, ROUTER};
    use core::sync::atomic::Ordering;

    LED_SINK_LAST.store(0, Ordering::SeqCst);
    LED_SINK_CALLS.store(0, Ordering::SeqCst);
    let mut caps = DeviceCaps::new();
    caps.add_key(key::KEY_CAPSLOCK);
    caps.add_key(key::KEY_NUMLOCK);
    caps.add_key(key::KEY_SCROLLLOCK);
    caps.add_led(led::LED_NUML);
    caps.add_led(led::LED_CAPSL);
    caps.add_led(led::LED_SCROLLL);
    let (id, node) = ROUTER.register_device(caps);
    node.set_led_sink(recording_led_sink);
    let key_ev = |code: u16, value: i32| EvdevEvent {
        time: 0,
        type_: EventType::Key,
        code,
        value,
    };

    // Press toggles on; release does not; autorepeat does not;
    // a second press toggles off.
    node.dispatch(key_ev(key::KEY_CAPSLOCK, 1));
    if node.led_state() != (1 << led::LED_CAPSL) {
        return TestResult::Fail("CapsLock press did not light LED_CAPSL");
    }
    node.dispatch(key_ev(key::KEY_CAPSLOCK, 0));
    node.dispatch(key_ev(key::KEY_CAPSLOCK, 2));
    if node.led_state() != (1 << led::LED_CAPSL) {
        return TestResult::Fail("CapsLock release/repeat changed the LED state");
    }
    if LED_SINK_CALLS.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("sink fired for a release/repeat");
    }
    node.dispatch(key_ev(key::KEY_CAPSLOCK, 1));
    if node.led_state() != 0 {
        return TestResult::Fail("second CapsLock press did not toggle off");
    }
    // NumLock and ScrollLock map to their own bits (Linux LED-code
    // order: Num=bit0, Scroll=bit2).
    node.dispatch(key_ev(key::KEY_NUMLOCK, 1));
    node.dispatch(key_ev(key::KEY_SCROLLLOCK, 1));
    if node.led_state() != ((1 << led::LED_NUML) | (1 << led::LED_SCROLLL)) {
        return TestResult::Fail("Num/Scroll lock presses mapped to wrong LED bits");
    }
    if LED_SINK_LAST.load(Ordering::SeqCst) != node.led_state() {
        return TestResult::Fail("sink bitmap disagrees with node state");
    }
    ROUTER.unregister_device(id);
    TestResult::Pass
}
kernel_test_in!("input", smoke_input_evdev_lock_keys_toggle_leds);
