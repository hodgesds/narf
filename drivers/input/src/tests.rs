//! Per-crate smoke tests for `narf-input-driver`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under the `"drivers/input"` subsystem.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_i8042_decode_a_keystroke() -> TestResult {
    // Synthetic scancode-set-1 byte stream for: press 'A', release 'A'.
    // Make code for KEY_A in set 1 = 0x1E. Release sets the 0x80 bit.
    use crate::i8042;
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, KeyCode,
    };

    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042::__reset_for_test();

    i8042::feed_bytes_for_test(&[0x1E, 0x9E]);

    // Two events should now be in the global ring.
    let press = pop_global();
    let release = pop_global();
    let press_ok = matches!(
        press,
        Some(InputEvent::Key(k)) if k.code == KeyCode::A && k.pressed
    );
    let release_ok = matches!(
        release,
        Some(InputEvent::Key(k)) if k.code == KeyCode::A && !k.pressed
    );
    if !press_ok {
        return TestResult::Fail("A press event missing or wrong");
    }
    if !release_ok {
        return TestResult::Fail("A release event missing or wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_decode_a_keystroke);

// ── Issue #771: PS/2 re-probe bookkeeping ────────────────────────
//
// `reprobe()` itself drives the 8042 ports, so no fixture can
// run it in the test harness — but its unregister half (the part
// that used to leak: `init()` discarded the evdev id) runs
// through the same `drop_stale_registration` the hook calls, via
// the `__drop_stale_*_registration_for_test` hooks. These
// fixtures prove a seeded registration is fully removed from
// the router and the driver's cached node — the exact state a
// re-probe must leave behind before the fresh probe runs.

fn smoke_i8042_reprobe_drops_stale_registration() -> TestResult {
    use crate::i8042;
    use narf_input::evdev::{DeviceCaps, ROUTER};
    i8042::__reset_for_test();
    let mut caps = DeviceCaps::new();
    caps.set_identity(
        "test AT keyboard",
        "isa0060/serio0/input0",
        "",
        narf_input::evdev::InputId::new(narf_input::evdev::bus::I8042, 0x0001, 0x0001, 0),
    );
    caps.add_key(30);
    let (id, node) = ROUTER.register_device(caps);
    i8042::__seed_kbd_registration_for_test(id, node.clone());
    if i8042::kbd_evdev_node().is_none() || ROUTER.caps(id).is_none() {
        return TestResult::Fail("seeded keyboard registration missing");
    }
    i8042::__drop_stale_kbd_registration_for_test();
    if i8042::kbd_evdev_node().is_some()
        || ROUTER.caps(id).is_some()
        || ROUTER.device_ids().contains(&id)
        || node.is_alive()
    {
        return TestResult::Fail("stale keyboard node still visible after re-probe drop");
    }
    // Defensive: the drop already unregistered; a no-op if so.
    ROUTER.unregister_device(id);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_reprobe_drops_stale_registration
);

fn smoke_i8042_mouse_reprobe_drops_stale_registration() -> TestResult {
    use crate::i8042_mouse;
    use narf_input::evdev::{DeviceCaps, ROUTER};
    i8042_mouse::__reset_for_test();
    let mut caps = DeviceCaps::new();
    caps.set_identity(
        "test PS/2 mouse",
        "isa0060/serio1/input0",
        "",
        narf_input::evdev::InputId::new(narf_input::evdev::bus::I8042, 0x0002, 0x0001, 0),
    );
    caps.add_key(narf_input::evdev::key::BTN_LEFT);
    let (id, node) = ROUTER.register_device(caps);
    i8042_mouse::__seed_mouse_registration_for_test(id, node.clone());
    if i8042_mouse::mouse_evdev_node().is_none() || ROUTER.caps(id).is_none() {
        return TestResult::Fail("seeded mouse registration missing");
    }
    i8042_mouse::__drop_stale_mouse_registration_for_test();
    if i8042_mouse::mouse_evdev_node().is_some()
        || ROUTER.caps(id).is_some()
        || ROUTER.device_ids().contains(&id)
        || node.is_alive()
    {
        return TestResult::Fail("stale mouse node still visible after re-probe drop");
    }
    // Defensive: the drop already unregistered; a no-op if so.
    ROUTER.unregister_device(id);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_mouse_reprobe_drops_stale_registration
);

fn smoke_i8042_modifier_tracking() -> TestResult {
    // Press LeftShift (make 0x2A), press 'A' (make 0x1E), release both.
    // The 'A' press event should carry SHIFT in its modifier bitset.
    use crate::i8042;
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, KeyCode, Modifiers,
    };

    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042::__reset_for_test();

    i8042::feed_bytes_for_test(&[0x2A, 0x1E, 0x9E, 0xAA]);

    // Skip shift press, inspect 'A' press.
    let _ = pop_global();
    match pop_global() {
        Some(InputEvent::Key(k)) => {
            if k.code != KeyCode::A || !k.pressed {
                return TestResult::Fail("expected A press second");
            }
            if !k.modifiers.contains(Modifiers::SHIFT) {
                return TestResult::Fail("SHIFT modifier not carried on A");
            }
        }
        _ => return TestResult::Fail("missing A event"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_modifier_tracking);

/// Pop the next global-ring event, expecting a key event for
/// `want` with pressed state `pressed`. Shared by the i8042 E0/E1
/// smokes below.
fn i8042_expect_key(want: narf_input::KeyCode, pressed: bool) -> bool {
    use narf_input::{pop_global, InputEvent};
    matches!(
        pop_global(),
        Some(InputEvent::Key(k)) if k.code == want && k.pressed == pressed
    )
}

fn smoke_i8042_e0_navigation_cluster() -> TestResult {
    // E0-prefixed navigation cluster, scancode set 1 (IBM PS/2
    // set-1 table): Home E0 47, Insert E0 52, Delete E0 53,
    // End E0 4F, PageUp E0 49, PageDown E0 51. Break = the make
    // code | 0x80 behind a fresh E0 prefix. All of these decoded
    // to Unknown before the E0 table was completed.
    use crate::i8042;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, KeyCode};

    init_global_ring(32);
    __reset_global_ring_for_test();
    i8042::__reset_for_test();

    let cases: [(u8, KeyCode); 6] = [
        (0x47, KeyCode::Home),
        (0x52, KeyCode::Insert),
        (0x53, KeyCode::Delete),
        (0x4F, KeyCode::End),
        (0x49, KeyCode::PageUp),
        (0x51, KeyCode::PageDown),
    ];
    for (make, want) in cases {
        i8042::feed_bytes_for_test(&[0xE0, make, 0xE0, make | 0x80]);
        if !i8042_expect_key(want, true) {
            return TestResult::Fail("E0 navigation press decoded wrong");
        }
        if !i8042_expect_key(want, false) {
            return TestResult::Fail("E0 navigation release decoded wrong");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_e0_navigation_cluster);

fn smoke_i8042_e0_original_six_regression() -> TestResult {
    // The six E0 keys that already decoded before the table was
    // completed must not regress: RightCtrl E0 1D, RightAlt E0 38,
    // Up E0 48, Left E0 4B, Right E0 4D, Down E0 50.
    use crate::i8042;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, KeyCode};

    init_global_ring(32);
    __reset_global_ring_for_test();
    i8042::__reset_for_test();

    let cases: [(u8, KeyCode); 6] = [
        (0x1D, KeyCode::RightCtrl),
        (0x38, KeyCode::RightAlt),
        (0x48, KeyCode::Up),
        (0x4B, KeyCode::Left),
        (0x4D, KeyCode::Right),
        (0x50, KeyCode::Down),
    ];
    for (make, want) in cases {
        i8042::feed_bytes_for_test(&[0xE0, make, 0xE0, make | 0x80]);
        if !i8042_expect_key(want, true) {
            return TestResult::Fail("original E0 press regressed");
        }
        if !i8042_expect_key(want, false) {
            return TestResult::Fail("original E0 release regressed");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_e0_original_six_regression);

fn smoke_i8042_e0_keypad_and_meta_keys() -> TestResult {
    // Remaining set-1 E0 keys: keypad Enter E0 1C, keypad Divide
    // E0 35, LeftMeta E0 5B, RightMeta E0 5C, Menu E0 5D.
    use crate::i8042;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, KeyCode};

    init_global_ring(32);
    __reset_global_ring_for_test();
    i8042::__reset_for_test();

    let cases: [(u8, KeyCode); 5] = [
        (0x1C, KeyCode::KpEnter),
        (0x35, KeyCode::KpSlash),
        (0x5B, KeyCode::LeftMeta),
        (0x5C, KeyCode::RightMeta),
        (0x5D, KeyCode::Menu),
    ];
    for (make, want) in cases {
        i8042::feed_bytes_for_test(&[0xE0, make, 0xE0, make | 0x80]);
        if !i8042_expect_key(want, true) {
            return TestResult::Fail("E0 keypad/meta press decoded wrong");
        }
        if !i8042_expect_key(want, false) {
            return TestResult::Fail("E0 keypad/meta release decoded wrong");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_e0_keypad_and_meta_keys);

fn smoke_i8042_print_screen_wire_frame() -> TestResult {
    // Print Screen's set-1 wire frame, byte-for-byte per the IBM
    // set-1 table: make = E0 2A E0 37, break = E0 B7 E0 AA. The
    // 2A/AA pair is the keyboard's "fake shift" wrapper, NOT a
    // LeftShift keystroke: the whole frame must yield exactly one
    // SysRq press and one SysRq release, nothing else.
    use crate::i8042;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_global, KeyCode};

    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042::__reset_for_test();

    i8042::feed_bytes_for_test(&[0xE0, 0x2A, 0xE0, 0x37]);
    if !i8042_expect_key(KeyCode::SysRq, true) {
        return TestResult::Fail("Print Screen make did not yield SysRq press");
    }
    if pop_global().is_some() {
        return TestResult::Fail("Print Screen make leaked extra events (fake shift)");
    }
    i8042::feed_bytes_for_test(&[0xE0, 0xB7, 0xE0, 0xAA]);
    if !i8042_expect_key(KeyCode::SysRq, false) {
        return TestResult::Fail("Print Screen break did not yield SysRq release");
    }
    if pop_global().is_some() {
        return TestResult::Fail("Print Screen break leaked extra events (fake shift)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_print_screen_wire_frame);

fn smoke_i8042_e0_prefix_changes_meaning() -> TestResult {
    // Masking-defeating: these make codes mean one key plain and a
    // different key behind E0. A decoder that consumes the prefix
    // but then decodes the byte through the plain table (or masks
    // the prefix away) fails every pair:
    //   0x47 = Kp7        vs E0 47 = Home
    //   0x52 = Kp0        vs E0 52 = Insert
    //   0x37 = KpAsterisk vs E0 37 = Print Screen (SysRq)
    //   0x1C = Enter      vs E0 1C = keypad Enter
    //   0x35 = Slash      vs E0 35 = keypad Slash
    use crate::i8042;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, KeyCode};

    init_global_ring(64);
    __reset_global_ring_for_test();
    i8042::__reset_for_test();

    let cases: [(u8, KeyCode, KeyCode); 5] = [
        (0x47, KeyCode::Kp7, KeyCode::Home),
        (0x52, KeyCode::Kp0, KeyCode::Insert),
        (0x37, KeyCode::KpAsterisk, KeyCode::SysRq),
        (0x1C, KeyCode::Enter, KeyCode::KpEnter),
        (0x35, KeyCode::Slash, KeyCode::KpSlash),
    ];
    for (make, plain, extended) in cases {
        i8042::feed_bytes_for_test(&[make, make | 0x80, 0xE0, make, 0xE0, make | 0x80]);
        if !i8042_expect_key(plain, true) || !i8042_expect_key(plain, false) {
            return TestResult::Fail("plain keypad decode changed by E0 work");
        }
        if !i8042_expect_key(extended, true) || !i8042_expect_key(extended, false) {
            return TestResult::Fail("E0 decode fell through to the plain table");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_e0_prefix_changes_meaning);

fn smoke_i8042_e1_pause_frame() -> TestResult {
    // Pause's set-1 frame is a single six-byte sequence with no
    // separate break code: E1 1D 45 E1 9D C5 (IBM set-1 table).
    // Expect exactly a Pause press (when the 45 lands) and a Pause
    // release (when the C5 lands) — and in particular no RightCtrl
    // event from the frame's 1D byte, which is what the old
    // E1-unaware path emitted.
    use crate::i8042;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_global, KeyCode};

    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042::__reset_for_test();

    i8042::feed_bytes_for_test(&[0xE1, 0x1D, 0x45, 0xE1, 0x9D, 0xC5]);
    if !i8042_expect_key(KeyCode::Pause, true) {
        return TestResult::Fail("Pause frame did not yield Pause press");
    }
    if !i8042_expect_key(KeyCode::Pause, false) {
        return TestResult::Fail("Pause frame did not yield Pause release");
    }
    if pop_global().is_some() {
        return TestResult::Fail("Pause frame leaked extra events");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_e1_pause_frame);

fn smoke_i8042_e1_resynchronizes_without_stuck_keys() -> TestResult {
    use crate::i8042;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_global, KeyCode};

    init_global_ring(16);
    // An aborted prefix must not swallow the following A make/break.
    __reset_global_ring_for_test();
    i8042::__reset_for_test();
    i8042::feed_bytes_for_test(&[0xE1, 0x1D, 0x1E, 0x9E]);
    if !i8042_expect_key(KeyCode::A, true)
        || !i8042_expect_key(KeyCode::A, false)
        || pop_global().is_some()
    {
        return TestResult::Fail("aborted E1 prefix swallowed or contaminated the next key");
    }

    // If Pause was already reported, a malformed tail must release it
    // before retrying the mismatching byte as an ordinary key.
    __reset_global_ring_for_test();
    i8042::__reset_for_test();
    i8042::feed_bytes_for_test(&[0xE1, 0x1D, 0x45, 0x1E, 0x9E]);
    if !i8042_expect_key(KeyCode::Pause, true)
        || !i8042_expect_key(KeyCode::Pause, false)
        || !i8042_expect_key(KeyCode::A, true)
        || !i8042_expect_key(KeyCode::A, false)
        || pop_global().is_some()
    {
        return TestResult::Fail("aborted E1 tail left Pause pressed or swallowed the next key");
    }

    // A prior incomplete E0 prefix must not survive a complete E1 frame.
    __reset_global_ring_for_test();
    i8042::__reset_for_test();
    i8042::feed_bytes_for_test(&[0xE0, 0xE1, 0x1D, 0x45, 0xE1, 0x9D, 0xC5, 0x1E, 0x9E]);
    if !i8042_expect_key(KeyCode::Pause, true)
        || !i8042_expect_key(KeyCode::Pause, false)
        || !i8042_expect_key(KeyCode::A, true)
        || !i8042_expect_key(KeyCode::A, false)
        || pop_global().is_some()
    {
        return TestResult::Fail("E0 latch leaked across an E1 Pause frame");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_e1_resynchronizes_without_stuck_keys
);

fn smoke_i8042_mouse_packet_decode() -> TestResult {
    use crate::i8042_mouse;
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, PointerButtons,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042_mouse::__reset_for_test();

    // Packet: status=0x09 (left button + sync), dx=+5, dy=+3.
    // PS/2 reports +Y as up; our convention is +Y down → expect dy=-3.
    i8042_mouse::feed_byte_for_test(0x09);
    i8042_mouse::feed_byte_for_test(5);
    i8042_mouse::feed_byte_for_test(3);

    match pop_global() {
        Some(InputEvent::Pointer(p)) => {
            if p.dx != 5 || p.dy != -3 {
                return TestResult::Fail("dx/dy decode wrong");
            }
            if !p.buttons.contains(PointerButtons::LEFT) {
                return TestResult::Fail("LEFT button bit missing");
            }
        }
        _ => return TestResult::Fail("no PointerEvent emitted"),
    }
    let (dx, dy) = i8042_mouse::take_rel_delta();
    if dx != 5 || dy != -3 {
        return TestResult::Fail("rel accumulator wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_mouse_packet_decode);

fn smoke_i8042_mouse_signed_dx_decodes() -> TestResult {
    use crate::i8042_mouse;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_global, InputEvent};
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042_mouse::__reset_for_test();

    // Status with X-sign bit set (bit 4): dx is negative.
    // 0x18 = sync (bit 3) + X-sign (bit 4); dx byte=0xFB (251) →
    // signed = 251 - 256 = -5; dy byte=0, no Y-sign → +0 → dy=-0=0.
    i8042_mouse::feed_byte_for_test(0x18);
    i8042_mouse::feed_byte_for_test(0xFB);
    i8042_mouse::feed_byte_for_test(0x00);
    match pop_global() {
        Some(InputEvent::Pointer(p)) => {
            if p.dx != -5 || p.dy != 0 {
                return TestResult::Fail("signed dx decode wrong");
            }
        }
        _ => return TestResult::Fail("no PointerEvent"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_mouse_signed_dx_decodes);

fn smoke_i8042_mouse_drops_unsynced_byte() -> TestResult {
    use crate::i8042_mouse;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_global};
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042_mouse::__reset_for_test();

    // First byte without the sync bit (0x08) clear — should drop.
    i8042_mouse::feed_byte_for_test(0x00);
    if pop_global().is_some() {
        return TestResult::Fail("non-sync byte produced an event");
    }
    // Then a proper packet — should produce one event.
    i8042_mouse::feed_byte_for_test(0x08);
    i8042_mouse::feed_byte_for_test(0x01);
    i8042_mouse::feed_byte_for_test(0x02);
    if pop_global().is_none() {
        return TestResult::Fail("packet after re-sync didn't produce event");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_mouse_drops_unsynced_byte);

fn smoke_i8042_mouse_intellimouse_wheel_reports_scroll() -> TestResult {
    use crate::i8042_mouse;
    use crate::psmouse::PsmouseProtocol;
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, PointerButtons,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042_mouse::__reset_for_test();
    i8042_mouse::set_protocol_for_test(PsmouseProtocol::IntelliMouse);

    // 4-byte packet, no motion, wheel byte 0x01. Linux reports
    // REL_WHEEL = -(signed char)packet[3] = -1 (one click up).
    i8042_mouse::feed_byte_for_test(0x08);
    i8042_mouse::feed_byte_for_test(0x00);
    i8042_mouse::feed_byte_for_test(0x00);
    i8042_mouse::feed_byte_for_test(0x01);

    // The motion half still rides the Pointer channel (dx=dy=0).
    match pop_global() {
        Some(InputEvent::Pointer(p)) => {
            if p.dx != 0 || p.dy != 0 {
                return TestResult::Fail("wheel packet motion should be zero");
            }
            if p.buttons != PointerButtons::EMPTY {
                return TestResult::Fail("wheel packet should carry no buttons");
            }
        }
        _ => return TestResult::Fail("no PointerEvent for wheel packet"),
    }
    match pop_global() {
        Some(InputEvent::Scroll(s)) => {
            if s.dx != 0 || s.dy != -1 {
                return TestResult::Fail("wheel 0x01 should scroll dy=-1");
            }
        }
        _ => return TestResult::Fail("no ScrollEvent for wheel packet"),
    }
    // Wheel byte 0xFF = -1 signed -> REL_WHEEL = +1 (one click down).
    i8042_mouse::feed_byte_for_test(0x08);
    i8042_mouse::feed_byte_for_test(0x00);
    i8042_mouse::feed_byte_for_test(0x00);
    i8042_mouse::feed_byte_for_test(0xFF);
    let _ = pop_global(); // Pointer half
    match pop_global() {
        Some(InputEvent::Scroll(s)) => {
            if s.dx != 0 || s.dy != 1 {
                return TestResult::Fail("wheel 0xFF should scroll dy=+1");
            }
        }
        _ => return TestResult::Fail("no ScrollEvent for wheel 0xFF"),
    }
    let (wheel, hwheel) = i8042_mouse::take_wheel_delta();
    if wheel != 0 || hwheel != 0 {
        return TestResult::Fail("wheel accumulator should read (-1+1, 0) = (0, 0)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_mouse_intellimouse_wheel_reports_scroll
);

fn smoke_i8042_mouse_explorer_side_extra_buttons() -> TestResult {
    use crate::i8042_mouse;
    use crate::psmouse::PsmouseProtocol;
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, PointerButtons,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042_mouse::__reset_for_test();
    i8042_mouse::set_protocol_for_test(PsmouseProtocol::Explorer);

    // 4th byte 0x10: 4th button (bit 4) pressed, wheel nibble 0.
    // 0x30: 4th + 5th. 0x00: both released. No wheel motion anywhere.
    for b3 in [0x10u8, 0x30, 0x00] {
        i8042_mouse::feed_byte_for_test(0x08);
        i8042_mouse::feed_byte_for_test(0x00);
        i8042_mouse::feed_byte_for_test(0x00);
        i8042_mouse::feed_byte_for_test(b3);
    }
    let want: [PointerButtons; 3] = [
        PointerButtons::SIDE,
        PointerButtons::SIDE | PointerButtons::EXTRA,
        PointerButtons::EMPTY,
    ];
    for (i, w) in want.iter().enumerate() {
        match pop_global() {
            Some(InputEvent::Pointer(p)) => {
                if p.buttons != *w {
                    return TestResult::Fail("Explorer side/extra button state wrong");
                }
            }
            _ => return TestResult::Fail("missing PointerEvent in Explorer button sequence"),
        }
        // Wheel is zero in all three packets: no ScrollEvent follows.
        if pop_global().is_some() {
            return TestResult::Fail("wheel-zero Explorer packet leaked a ScrollEvent");
        }
        let _ = i;
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_mouse_explorer_side_extra_buttons
);

fn smoke_i8042_mouse_explorer_tilt_hwheel() -> TestResult {
    use crate::i8042_mouse;
    use crate::psmouse::PsmouseProtocol;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_global, InputEvent};
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042_mouse::__reset_for_test();
    i8042_mouse::set_protocol_for_test(PsmouseProtocol::ExplorerTilt);

    // 4th byte 0x41: top bits 0x40 = Explorer 4.0 horizontal scroll,
    // value (0x41 & 32) - (0x41 & 31) = 31 on REL_HWHEEL.
    i8042_mouse::feed_byte_for_test(0x08);
    i8042_mouse::feed_byte_for_test(0x00);
    i8042_mouse::feed_byte_for_test(0x00);
    i8042_mouse::feed_byte_for_test(0x41);
    let _ = pop_global(); // Pointer half
    match pop_global() {
        Some(InputEvent::Scroll(s)) => {
            if s.dx != 31 || s.dy != 0 {
                return TestResult::Fail("tilt 0x41 should scroll dx=+31");
            }
        }
        _ => return TestResult::Fail("no ScrollEvent for tilt packet"),
    }
    // 0x81: top bits 0x80 = vertical tilt scroll, value -1 on REL_WHEEL.
    i8042_mouse::feed_byte_for_test(0x08);
    i8042_mouse::feed_byte_for_test(0x00);
    i8042_mouse::feed_byte_for_test(0x00);
    i8042_mouse::feed_byte_for_test(0x81);
    let _ = pop_global(); // Pointer half
    match pop_global() {
        Some(InputEvent::Scroll(s)) => {
            if s.dx != 0 || s.dy != -1 {
                return TestResult::Fail("tilt 0x81 should scroll dy=-1");
            }
        }
        _ => return TestResult::Fail("no ScrollEvent for vertical tilt packet"),
    }
    let (wheel, hwheel) = i8042_mouse::take_wheel_delta();
    if wheel != -1 || hwheel != 31 {
        return TestResult::Fail("wheel accumulator should read (-1, 31)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_mouse_explorer_tilt_hwheel);

/// Elantech v2 info for the IRQ-path fixtures: firmware 02.08.00
/// (known-fw ranges 1152x768, pressure reporting on).
fn elantech_v2_info_for_test() -> crate::psmouse::ElantechInfo {
    crate::psmouse::ElantechInfo {
        hw_version: 2,
        fw_version: 0x020800,
        ic_version: 2,
        x_max: 1152,
        y_max: 768,
        width: 0,
        reports_pressure: true,
        crc_enabled: false,
        buttonpad: false,
        has_trackpoint: false,
        samples_1: 0,
        jumpy_cursor: false,
    }
}

fn smoke_i8042_mouse_elantech_v2_absolute_reports_touch() -> TestResult {
    use crate::i8042_mouse;
    use crate::psmouse::PsmouseProtocol;
    use narf_input::{
        __reset_global_ring_for_test, abs, init_global_ring, pop_global, InputEvent, TouchState,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042_mouse::__reset_for_test();
    i8042_mouse::set_elantech_for_test(PsmouseProtocol::Elantech, &elantech_v2_info_for_test());

    // v2 1-finger packet (verified vector): x=1000, y=500,
    // pressure 0xAB, width 5, left pressed.
    for b in [0x55u8, 0xA3, 0xE8, 0x12, 0xB1, 0x0C] {
        i8042_mouse::feed_byte_for_test(b);
    }
    match pop_global() {
        Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_X && a.value == 1000 => {}
        _ => return TestResult::Fail("no ABS_X=1000 for Elantech v2 packet"),
    }
    match pop_global() {
        Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_Y && a.value == 500 => {}
        _ => return TestResult::Fail("no ABS_Y=500 for Elantech v2 packet"),
    }
    match pop_global() {
        Some(InputEvent::Touch(t))
            if t.slot == 0
                && t.state == TouchState::Down
                && t.x == 1000
                && t.y == 500
                && t.pressure == 0xAB => {}
        _ => return TestResult::Fail("no Touch Down slot 0 (1000, 500, pres 0xAB)"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_mouse_elantech_v2_absolute_reports_touch
);

fn smoke_i8042_mouse_elantech_bad_packet_drops_and_resyncs() -> TestResult {
    use crate::i8042_mouse;
    use crate::psmouse::PsmouseProtocol;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_global, InputEvent};
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042_mouse::__reset_for_test();
    i8042_mouse::set_elantech_for_test(PsmouseProtocol::Elantech, &elantech_v2_info_for_test());

    // A packet failing the v2 constant-bit check (byte 0 0x00),
    // then the exact v2 debounce packet — neither may report
    // anything, and neither may desync the stream.
    for b in [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00] {
        i8042_mouse::feed_byte_for_test(b);
    }
    for b in [0x84u8, 0xFF, 0xFF, 0x02, 0xFF, 0xFF] {
        i8042_mouse::feed_byte_for_test(b);
    }
    if pop_global().is_some() {
        return TestResult::Fail("bad / debounce Elantech packets must not report");
    }
    // The good packet after them still decodes: the stream is
    // back in sync.
    for b in [0x55u8, 0xA3, 0xE8, 0x12, 0xB1, 0x0C] {
        i8042_mouse::feed_byte_for_test(b);
    }
    match pop_global() {
        Some(InputEvent::Absolute(a)) if a.value == 1000 => {}
        _ => return TestResult::Fail("good packet after bad ones must still report ABS_X=1000"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_mouse_elantech_bad_packet_drops_and_resyncs
);

fn smoke_i8042_mouse_elantech_v1_jumpy_discards_first_two() -> TestResult {
    use crate::i8042_mouse;
    use crate::psmouse::{ElantechInfo, PsmouseProtocol};
    use narf_input::{
        __reset_global_ring_for_test, abs, init_global_ring, pop_global, InputEvent, TouchState,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042_mouse::__reset_for_test();
    // Firmware 02.00.22: jumpy-cursor workaround is on.
    let info = ElantechInfo {
        hw_version: 1,
        fw_version: 0x020022,
        ic_version: 2,
        x_max: 544,
        y_max: 352,
        width: 0,
        reports_pressure: false,
        crc_enabled: false,
        buttonpad: false,
        has_trackpoint: false,
        samples_1: 0,
        jumpy_cursor: true,
    };
    i8042_mouse::set_elantech_for_test(PsmouseProtocol::ElantechV1, &info);

    // v1 1-finger packet (verified vector): x=300, y=200, left.
    // The first two single-finger reports are discarded as bogus.
    for _ in 0..2 {
        for b in [0x49u8, 0x04, 0x2C, 0x98] {
            i8042_mouse::feed_byte_for_test(b);
        }
        if pop_global().is_some() {
            return TestResult::Fail("jumpy v1 pad must discard its first two reports");
        }
    }
    for b in [0x49u8, 0x04, 0x2C, 0x98] {
        i8042_mouse::feed_byte_for_test(b);
    }
    match pop_global() {
        Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_X && a.value == 300 => {}
        _ => return TestResult::Fail("third v1 report must deliver ABS_X=300"),
    }
    match pop_global() {
        Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_Y && a.value == 200 => {}
        _ => return TestResult::Fail("third v1 report must deliver ABS_Y=200"),
    }
    match pop_global() {
        Some(InputEvent::Touch(t))
            if t.slot == 0 && t.state == TouchState::Down && t.x == 300 && t.y == 200 => {}
        _ => return TestResult::Fail("third v1 report must deliver Touch Down (300, 200)"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_mouse_elantech_v1_jumpy_discards_first_two
);

fn smoke_i8042_mouse_elantech_v4_head_motion_status() -> TestResult {
    use crate::i8042_mouse;
    use crate::psmouse::{ElantechInfo, PsmouseProtocol};
    use narf_input::{
        __reset_global_ring_for_test, abs, init_global_ring, pop_global, InputEvent, TouchState,
    };
    init_global_ring(16);
    __reset_global_ring_for_test();
    i8042_mouse::__reset_for_test();
    // Firmware 46.0F.02 (v4, ranges 1200x800, width scale 52).
    let info = ElantechInfo {
        hw_version: 4,
        fw_version: 0x460f02,
        ic_version: 6,
        x_max: 1200,
        y_max: 800,
        width: 52,
        reports_pressure: true,
        crc_enabled: false,
        buttonpad: false,
        has_trackpoint: false,
        samples_1: 0,
        jumpy_cursor: false,
    };
    i8042_mouse::set_elantech_for_test(PsmouseProtocol::Elantech, &info);

    // Head packet: slot 0 at (1000, 200), pressure 0x9A.
    for b in [0x30u8, 0x93, 0xE8, 0x31, 0xA2, 0x58] {
        i8042_mouse::feed_byte_for_test(b);
    }
    match pop_global() {
        Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_X && a.value == 1000 => {}
        _ => return TestResult::Fail("v4 head must deliver ABS_X=1000"),
    }
    match pop_global() {
        Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_Y && a.value == 200 => {}
        _ => return TestResult::Fail("v4 head must deliver ABS_Y=200"),
    }
    match pop_global() {
        Some(InputEvent::Touch(t))
            if t.slot == 0
                && t.state == TouchState::Down
                && t.x == 1000
                && t.y == 200
                && t.pressure == 0x9A => {}
        _ => return TestResult::Fail("v4 head must deliver Touch Down slot 0 (1000, 200)"),
    }
    // Motion packet: slot 0 dx=+10, dy=-5 -> (1010, 205).
    for b in [0x20u8, 0x0A, 0xFB, 0x32, 0x00, 0x00] {
        i8042_mouse::feed_byte_for_test(b);
    }
    match pop_global() {
        Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_X && a.value == 1010 => {}
        _ => return TestResult::Fail("v4 motion must deliver ABS_X=1010"),
    }
    match pop_global() {
        Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_Y && a.value == 205 => {}
        _ => return TestResult::Fail("v4 motion must deliver ABS_Y=205"),
    }
    match pop_global() {
        Some(InputEvent::Touch(t))
            if t.slot == 0 && t.state == TouchState::Move && t.x == 1010 && t.y == 205 => {}
        _ => return TestResult::Fail("v4 motion must deliver Touch Move slot 0 (1010, 205)"),
    }
    // Status packet: no fingers down — release at the last position.
    for b in [0x00u8, 0x00, 0x00, 0x10, 0x00, 0x00] {
        i8042_mouse::feed_byte_for_test(b);
    }
    match pop_global() {
        Some(InputEvent::Touch(t))
            if t.slot == 0
                && t.state == TouchState::Up
                && t.tracking_id.is_none()
                && t.x == 1010
                && t.y == 205 => {}
        _ => return TestResult::Fail("v4 status must deliver Touch Up slot 0 at (1010, 205)"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_mouse_elantech_v4_head_motion_status
);

fn smoke_i8042_mouse_elantech_v3_head_tail_pair() -> TestResult {
    use crate::i8042_mouse;
    use crate::psmouse::{ElantechInfo, PsmouseProtocol};
    use narf_input::{
        __reset_global_ring_for_test, abs, init_global_ring, pop_global, InputEvent, TouchState,
    };
    init_global_ring(16);
    __reset_global_ring_for_test();
    i8042_mouse::__reset_for_test();
    let info = ElantechInfo {
        hw_version: 3,
        fw_version: 0x050000,
        ic_version: 5,
        x_max: 1200,
        y_max: 800,
        width: 0,
        reports_pressure: true,
        crc_enabled: false,
        buttonpad: false,
        has_trackpoint: false,
        samples_1: 0,
        jumpy_cursor: false,
    };
    i8042_mouse::set_elantech_for_test(PsmouseProtocol::Elantech, &info);

    // Two-finger head packet only stashes finger A: no events.
    for b in [0x85u8, 0x52, 0x58, 0x02, 0x60, 0x64] {
        i8042_mouse::feed_byte_for_test(b);
    }
    if pop_global().is_some() {
        return TestResult::Fail("v3 head packet must not report on its own");
    }
    // Tail packet completes the pair: (600, 700) + (900, 400).
    for b in [0x8Du8, 0x73, 0x84, 0x0C, 0x81, 0x90] {
        i8042_mouse::feed_byte_for_test(b);
    }
    match pop_global() {
        Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_X && a.value == 600 => {}
        _ => return TestResult::Fail("v3 tail must deliver ABS_X=600"),
    }
    match pop_global() {
        Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_Y && a.value == 700 => {}
        _ => return TestResult::Fail("v3 tail must deliver ABS_Y=700"),
    }
    match pop_global() {
        Some(InputEvent::Touch(t))
            if t.slot == 0 && t.state == TouchState::Down && t.x == 600 && t.y == 700 => {}
        _ => return TestResult::Fail("v3 tail must deliver Touch Down slot 0 (600, 700)"),
    }
    match pop_global() {
        Some(InputEvent::Touch(t))
            if t.slot == 1 && t.state == TouchState::Down && t.x == 900 && t.y == 400 => {}
        _ => return TestResult::Fail("v3 tail must deliver Touch Down slot 1 (900, 400)"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_mouse_elantech_v3_head_tail_pair
);

fn smoke_i8042_mouse_3byte_fallback_stream_stays_in_sync() -> TestResult {
    use crate::i8042_mouse;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_global, InputEvent};
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042_mouse::__reset_for_test();
    // Protocol stays Standard (failed knock): 3-byte packets.

    // Packet 1, then a stray 0x01 (a wheel byte from a 4-byte
    // stream) — no sync bit, so it must drop, not shift the
    // stream — then packet 2.
    for b in [0x08u8, 5, 3, 0x01, 0x08, 1, 1] {
        i8042_mouse::feed_byte_for_test(b);
    }
    match pop_global() {
        Some(InputEvent::Pointer(p)) => {
            if p.dx != 5 || p.dy != -3 {
                return TestResult::Fail("first 3-byte packet decoded wrong");
            }
        }
        _ => return TestResult::Fail("first packet missing"),
    }
    match pop_global() {
        Some(InputEvent::Pointer(p)) => {
            if p.dx != 1 || p.dy != -1 {
                return TestResult::Fail("stray wheel byte desynced the 3-byte stream");
            }
        }
        _ => return TestResult::Fail("second packet missing after stray byte"),
    }
    if pop_global().is_some() {
        return TestResult::Fail("no ScrollEvent may appear in 3-byte mode");
    }
    let (dx, dy) = i8042_mouse::take_rel_delta();
    if dx != 6 || dy != -4 {
        return TestResult::Fail("rel accumulator wrong after fallback stream");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_mouse_3byte_fallback_stream_stays_in_sync
);

fn smoke_virtio_input_decode_synthetic() -> TestResult {
    use narf_drivers_virtio::input_pci::feed_synthetic_events_for_test;
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, KeyCode,
    };

    init_global_ring(8);
    __reset_global_ring_for_test();

    // EV_KEY type=1, code=KEY_A=30, value=1 (press)
    // EV_KEY type=1, code=KEY_A=30, value=0 (release)
    let n = feed_synthetic_events_for_test(&[(1, 30, 1), (1, 30, 0)]);
    if n != 2 {
        return TestResult::Fail("expected 2 synthetic events");
    }
    let press = matches!(
        pop_global(),
        Some(InputEvent::Key(k)) if k.code == KeyCode::A && k.pressed
    );
    let release = matches!(
        pop_global(),
        Some(InputEvent::Key(k)) if k.code == KeyCode::A && !k.pressed
    );
    if !press {
        return TestResult::Fail("A press missing");
    }
    if !release {
        return TestResult::Fail("A release missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_virtio_input_decode_synthetic);

fn smoke_virtio_input_btn_left_emits_pointer() -> TestResult {
    use narf_drivers_virtio::input_pci::feed_synthetic_events_for_test;
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, PointerButtons,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    // EV_REL REL_X=+5, EV_REL REL_Y=-3, EV_KEY BTN_LEFT=0x110 press,
    // EV_SYN → expect one PointerEvent(dx=5, dy=-3, LEFT).
    let _ = feed_synthetic_events_for_test(&[
        (2, 0, 5u32),           // EV_REL REL_X +5
        (2, 1, (-3i32) as u32), // EV_REL REL_Y -3
        (1, 0x110, 1),          // EV_KEY BTN_LEFT press
        (0, 0, 0),              // EV_SYN
    ]);
    // After SYN, exactly one Pointer event sits in the global ring.
    match pop_global() {
        Some(InputEvent::Pointer(p)) => {
            if p.dx != 5 || p.dy != -3 {
                return TestResult::Fail("pointer delta mismatch");
            }
            if !p.buttons.contains(PointerButtons::LEFT) {
                return TestResult::Fail("LEFT button bit not set");
            }
        }
        _ => return TestResult::Fail("expected one PointerEvent after SYN"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_virtio_input_btn_left_emits_pointer);

fn smoke_virtio_input_shift_a_stamps_modifier() -> TestResult {
    use narf_drivers_virtio::input_pci::feed_synthetic_events_for_test;
    use narf_input::{
        __reset_global_ring_for_test, __reset_modifiers_for_test, init_global_ring, pop_key,
        KeyCode, Modifiers,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    __reset_modifiers_for_test();
    // LeftShift=42 press, A=30 press, A release, LeftShift release.
    let _ = feed_synthetic_events_for_test(&[(1, 42, 1), (1, 30, 1), (1, 30, 0), (1, 42, 0)]);
    let _shift_press = pop_key();
    let a_press = match pop_key() {
        Some(k) => k,
        None => return TestResult::Fail("A press missing"),
    };
    if a_press.code != KeyCode::A {
        return TestResult::Fail("A press code wrong");
    }
    if !a_press.modifiers.contains(Modifiers::SHIFT) {
        return TestResult::Fail("A press should carry SHIFT through virtio-input");
    }
    __reset_modifiers_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_virtio_input_shift_a_stamps_modifier);

fn smoke_virtio_input_tablet_abs_xy_emits_absolute() -> TestResult {
    use narf_drivers_virtio::input_pci::feed_synthetic_events_for_test;
    use narf_input::{__reset_global_ring_for_test, abs, init_global_ring, pop_absolute};
    init_global_ring(8);
    __reset_global_ring_for_test();
    // Tablet frame: ABS_X=1000, ABS_Y=2000, SYN.
    let _ = feed_synthetic_events_for_test(&[
        (3, abs::ABS_X, 1000),
        (3, abs::ABS_Y, 2000),
        (0, 0, 0), // EV_SYN
    ]);
    let x = match pop_absolute() {
        Some(a) => a,
        None => return TestResult::Fail("expected first Absolute event"),
    };
    if x.axis != abs::ABS_X || x.value != 1000 {
        return TestResult::Fail("ABS_X event shape wrong");
    }
    let y = match pop_absolute() {
        Some(a) => a,
        None => return TestResult::Fail("expected second Absolute event"),
    };
    if y.axis != abs::ABS_Y || y.value != 2000 {
        return TestResult::Fail("ABS_Y event shape wrong");
    }
    if pop_absolute().is_some() {
        return TestResult::Fail("only two Absolute events expected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_virtio_input_tablet_abs_xy_emits_absolute
);

fn smoke_virtio_input_multitouch_slot_protocol_b() -> TestResult {
    use narf_drivers_virtio::input_pci::feed_synthetic_events_for_test;
    use narf_input::{__reset_global_ring_for_test, abs, init_global_ring, pop_touch};
    init_global_ring(16);
    __reset_global_ring_for_test();
    // Two fingers down at once:
    //   slot 0: tracking_id 100 at (50, 60)
    //   slot 1: tracking_id 101 at (200, 210)
    //   SYN — expect two Touch events
    // Then lift slot 0 (tracking_id -1) at next SYN.
    let _ = feed_synthetic_events_for_test(&[
        (3, abs::ABS_MT_SLOT, 0),
        (3, abs::ABS_MT_TRACKING_ID, 100),
        (3, abs::ABS_MT_POSITION_X, 50),
        (3, abs::ABS_MT_POSITION_Y, 60),
        (3, abs::ABS_MT_SLOT, 1),
        (3, abs::ABS_MT_TRACKING_ID, 101),
        (3, abs::ABS_MT_POSITION_X, 200),
        (3, abs::ABS_MT_POSITION_Y, 210),
        (0, 0, 0), // EV_SYN
        (3, abs::ABS_MT_SLOT, 0),
        (3, abs::ABS_MT_TRACKING_ID, (-1i32) as u32),
        (0, 0, 0), // EV_SYN
    ]);
    let t0 = match pop_touch() {
        Some(t) => t,
        None => return TestResult::Fail("expected slot 0 down"),
    };
    if t0.slot != 0 || t0.tracking_id != Some(100) || t0.x != 50 || t0.y != 60 {
        return TestResult::Fail("slot 0 contact shape wrong");
    }
    let t1 = match pop_touch() {
        Some(t) => t,
        None => return TestResult::Fail("expected slot 1 down"),
    };
    if t1.slot != 1 || t1.tracking_id != Some(101) || t1.x != 200 || t1.y != 210 {
        return TestResult::Fail("slot 1 contact shape wrong");
    }
    let t_lift = match pop_touch() {
        Some(t) => t,
        None => return TestResult::Fail("expected slot 0 release"),
    };
    if t_lift.slot != 0 || t_lift.tracking_id.is_some() {
        return TestResult::Fail("slot 0 release shape wrong");
    }
    if pop_touch().is_some() {
        return TestResult::Fail("only three Touch events expected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_virtio_input_multitouch_slot_protocol_b
);

fn smoke_virtio_input_btn_touch_drives_slot_zero() -> TestResult {
    use narf_drivers_virtio::input_pci::feed_synthetic_events_for_test;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_touch};
    init_global_ring(8);
    __reset_global_ring_for_test();
    // BTN_TOUCH = 0x14a. Press, SYN, release, SYN.
    let _ = feed_synthetic_events_for_test(&[(1, 0x14a, 1), (0, 0, 0), (1, 0x14a, 0), (0, 0, 0)]);
    let down = match pop_touch() {
        Some(t) => t,
        None => return TestResult::Fail("expected BTN_TOUCH down event"),
    };
    if down.slot != 0 || down.tracking_id.is_none() {
        return TestResult::Fail("BTN_TOUCH down should mark slot 0 active");
    }
    let up = match pop_touch() {
        Some(t) => t,
        None => return TestResult::Fail("expected BTN_TOUCH up event"),
    };
    if up.slot != 0 || up.tracking_id.is_some() {
        return TestResult::Fail("BTN_TOUCH up should release slot 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_virtio_input_btn_touch_drives_slot_zero
);

fn smoke_virtio_input_extra_mouse_buttons() -> TestResult {
    use narf_drivers_virtio::input_pci::feed_synthetic_events_for_test;
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, PointerButtons,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    // BTN_SIDE=0x113 press, BTN_BACK=0x116 press, SYN; then both
    // release, SYN. Expect a PointerEvent with SIDE+BACK set, then
    // one with neither.
    let _ = feed_synthetic_events_for_test(&[
        (1, 0x113, 1),
        (1, 0x116, 1),
        (0, 0, 0),
        (1, 0x113, 0),
        (1, 0x116, 0),
        (0, 0, 0),
    ]);
    match pop_global() {
        Some(InputEvent::Pointer(p)) => {
            if !p.buttons.contains(PointerButtons::SIDE) {
                return TestResult::Fail("SIDE button bit not set");
            }
            if !p.buttons.contains(PointerButtons::BACK) {
                return TestResult::Fail("BACK button bit not set");
            }
        }
        _ => return TestResult::Fail("expected PointerEvent with SIDE+BACK"),
    }
    // Second SYN emits Pointer only when buttons or delta are
    // non-empty — both buttons cleared yields no event.
    if pop_global().is_some() {
        return TestResult::Fail("post-release SYN should not emit PointerEvent");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_virtio_input_extra_mouse_buttons);

fn smoke_axis_info_decodes_virtio_absinfo() -> TestResult {
    use narf_input::AxisInfo;
    // virtio_input_absinfo: min=10, max=32767, fuzz=2, flat=3, res=11
    // packed as five little-endian i32s.
    let mut buf = [0u8; 20];
    buf[0..4].copy_from_slice(&10i32.to_le_bytes());
    buf[4..8].copy_from_slice(&32767i32.to_le_bytes());
    buf[8..12].copy_from_slice(&2i32.to_le_bytes());
    buf[12..16].copy_from_slice(&3i32.to_le_bytes());
    buf[16..20].copy_from_slice(&11i32.to_le_bytes());
    let a = match AxisInfo::from_virtio_absinfo(&buf) {
        Some(a) => a,
        None => return TestResult::Fail("expected Some for 20-byte input"),
    };
    if a.min != 10 || a.max != 32767 || a.fuzz != 2 || a.flat != 3 || a.res != 11 {
        return TestResult::Fail("AxisInfo field decode wrong");
    }
    if AxisInfo::from_virtio_absinfo(&buf[..10]).is_some() {
        return TestResult::Fail("short buffer should return None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_axis_info_decodes_virtio_absinfo);

fn smoke_virtio_input_device_name_populated() -> TestResult {
    use narf_drivers_virtio::input_pci;
    if !input_pci::is_probed() {
        return TestResult::Skip("virtio-input not probed in this QEMU config");
    }
    // The default xtask test profile doesn't attach virtio-tablet
    // (which is what carries a meaningful CFG_ID_NAME); just verify
    // the accessor doesn't panic and that absence is reported as
    // an empty string rather than UB-via-uninit.
    let len = input_pci::with_controller(|c| c.device_name().len()).unwrap_or(0);
    if len > 128 {
        return TestResult::Fail("device_name() returned more than the 128-byte cap");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_virtio_input_device_name_populated);

fn smoke_virtio_input_hwheel_emits_horizontal_scroll() -> TestResult {
    use narf_drivers_virtio::input_pci::feed_synthetic_events_for_test;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_global, InputEvent};
    init_global_ring(8);
    __reset_global_ring_for_test();
    // EV_REL REL_HWHEEL=6 value=+1 → ScrollEvent{dx:+1,dy:0}.
    // EV_REL REL_HWHEEL value=-2 → ScrollEvent{dx:-2,dy:0}.
    let _ = feed_synthetic_events_for_test(&[(2, 6, 1u32), (2, 6, (-2i32) as u32)]);
    match pop_global() {
        Some(InputEvent::Scroll(s)) => {
            if s.dx != 1 || s.dy != 0 {
                return TestResult::Fail("first HWHEEL should emit dx=+1");
            }
        }
        _ => return TestResult::Fail("expected first Scroll event"),
    }
    match pop_global() {
        Some(InputEvent::Scroll(s)) => {
            if s.dx != -2 || s.dy != 0 {
                return TestResult::Fail("second HWHEEL should emit dx=-2");
            }
        }
        _ => return TestResult::Fail("expected second Scroll event"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_virtio_input_hwheel_emits_horizontal_scroll
);

fn smoke_virtio_input_count_matches_probe() -> TestResult {
    use narf_drivers_virtio::input_pci;
    // count() and is_probed() must agree — empty <=> count == 0.
    let n = input_pci::count();
    if input_pci::is_probed() {
        if n == 0 {
            return TestResult::Fail("is_probed() true but count() == 0");
        }
    } else if n != 0 {
        return TestResult::Fail("is_probed() false but count() > 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_virtio_input_count_matches_probe);

fn smoke_virtio_input_gamepad_buttons_routed_to_button_ring() -> TestResult {
    use narf_drivers_virtio::input_pci::feed_synthetic_events_for_test;
    use narf_input::{__reset_global_ring_for_test, btn, init_global_ring, pop_button, pop_key};
    init_global_ring(8);
    __reset_global_ring_for_test();
    // BTN_SOUTH press + release, BTN_TL2 press, BTN_DPAD_UP press.
    // None of these should land in the key ring; all in the button ring.
    let _ = feed_synthetic_events_for_test(&[
        (1, btn::BTN_SOUTH, 1),
        (1, btn::BTN_SOUTH, 0),
        (1, btn::BTN_TL2, 1),
        (1, btn::BTN_DPAD_UP, 1),
    ]);
    if pop_key().is_some() {
        return TestResult::Fail("gamepad buttons must not appear in the key ring");
    }
    let cases: &[(u16, bool)] = &[
        (btn::BTN_SOUTH, true),
        (btn::BTN_SOUTH, false),
        (btn::BTN_TL2, true),
        (btn::BTN_DPAD_UP, true),
    ];
    for &(want_code, want_pressed) in cases {
        match pop_button() {
            Some(b) => {
                if b.code != want_code || b.pressed != want_pressed {
                    return TestResult::Fail("button event shape wrong");
                }
            }
            None => return TestResult::Fail("expected button event missing"),
        }
    }
    if pop_button().is_some() {
        return TestResult::Fail("only four button events expected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_virtio_input_gamepad_buttons_routed_to_button_ring
);

fn smoke_virtio_input_sync_leds_no_panic_when_unprobed() -> TestResult {
    // sync_leds() must be idempotent + side-effect-free for
    // devices without LEDs. We don't synthetically construct a
    // controller; just verify that the function exists at the
    // narf_drivers_virtio path and behaves when called via
    // with_each. When no controller is probed this iterates zero
    // times — that's the assertion.
    let mut hits = 0u32;
    narf_drivers_virtio::input_pci::with_each(|c| {
        c.sync_leds();
        hits = hits.saturating_add(1);
    });
    let probed = narf_drivers_virtio::input_pci::is_probed();
    if probed && hits == 0 {
        return TestResult::Fail("with_each should iterate when probed");
    }
    if !probed && hits != 0 {
        return TestResult::Fail("with_each should be empty when no devices");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_virtio_input_sync_leds_no_panic_when_unprobed
);

fn smoke_virtio_input_probed_at_boot() -> TestResult {
    use narf_drivers_virtio::input_pci;
    if input_pci::is_probed() {
        TestResult::Pass
    } else {
        TestResult::Skip("virtio-keyboard-pci not present in this QEMU config")
    }
}
kernel_test_in!("drivers/input", smoke_virtio_input_probed_at_boot);

fn smoke_virtio_input_rel_delta_accumulates() -> TestResult {
    // Synthetic EV_REL events: REL_X=0 +5, REL_Y=1 -3, REL_X +2.
    // After feeding, take_rel_delta should report (7, -3) and reset.
    // Note: our feed_synthetic_events_for_test only handles EV_KEY;
    // we still verify the API on the controller side for pre-init.
    use narf_drivers_virtio::input_pci;
    if !input_pci::is_probed() {
        return TestResult::Skip("virtio-input not probed");
    }
    let (_, _) = input_pci::with_controller(|c| c.take_rel_delta()).unwrap_or((0, 0));
    // Drain (no events under -display none) and verify the
    // accumulator stays zero.
    let _drained = input_pci::with_controller(|c| c.drain_events()).unwrap_or(0);
    let (dx, dy) = input_pci::with_controller(|c| c.take_rel_delta()).unwrap_or((1, 1));
    if dx != 0 || dy != 0 {
        return TestResult::Fail("rel delta unexpected non-zero with no input");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_virtio_input_rel_delta_accumulates);

// ── WBDI / MS OS 2.0 Descriptor recogniser ────────────────────────

fn smoke_wbdi_set_header_decode() -> TestResult {
    use crate::wbdi::{desc_type, SetHeader};

    let mut buf = [0u8; 10];

    buf[0..2].copy_from_slice(&10u16.to_le_bytes());

    buf[2..4].copy_from_slice(&desc_type::SET_HEADER_DESCRIPTOR.to_le_bytes());

    buf[4..8].copy_from_slice(&0x0603_0000u32.to_le_bytes()); // NTDDI_WIN8_1

    buf[8..10].copy_from_slice(&30u16.to_le_bytes()); // total = 10 + 20 (one CompatibleID)

    let h = SetHeader::decode(&buf).expect("hdr");

    if h.total_length != 30 || h.windows_version != 0x0603_0000 {
        return TestResult::Fail("header decode");
    }

    TestResult::Pass
}

kernel_test_in!("drivers/input/wbdi", smoke_wbdi_set_header_decode);

fn smoke_wbdi_recogniser_accepts_winusb_wbdi() -> TestResult {
    use crate::wbdi::{desc_type, is_wbdi, COMPATIBLE_ID_WINUSB, SUB_COMPATIBLE_ID_WBDI};

    let mut blob = alloc::vec::Vec::new();

    // SetHeader (10 bytes)

    blob.extend_from_slice(&10u16.to_le_bytes());

    blob.extend_from_slice(&desc_type::SET_HEADER_DESCRIPTOR.to_le_bytes());

    blob.extend_from_slice(&0x0603_0000u32.to_le_bytes());

    blob.extend_from_slice(&30u16.to_le_bytes());

    // CompatibleID feature (20 bytes)

    blob.extend_from_slice(&20u16.to_le_bytes());

    blob.extend_from_slice(&desc_type::FEATURE_COMPATIBLE_ID.to_le_bytes());

    blob.extend_from_slice(COMPATIBLE_ID_WINUSB);

    blob.extend_from_slice(SUB_COMPATIBLE_ID_WBDI);

    if !is_wbdi(&blob) {
        return TestResult::Fail("WBDI compatible-id should match");
    }

    TestResult::Pass
}

kernel_test_in!(
    "drivers/input/wbdi",
    smoke_wbdi_recogniser_accepts_winusb_wbdi
);

fn smoke_wbdi_find_interface_in_vendor_class_config() -> TestResult {
    use crate::wbdi::{
        desc_type, find_wbdi_interface, COMPATIBLE_ID_WINUSB, SUB_COMPATIBLE_ID_WBDI,
    };

    // OS desc set: WBDI.

    let mut ms = alloc::vec::Vec::new();

    ms.extend_from_slice(&10u16.to_le_bytes());

    ms.extend_from_slice(&desc_type::SET_HEADER_DESCRIPTOR.to_le_bytes());

    ms.extend_from_slice(&0x0603_0000u32.to_le_bytes());

    ms.extend_from_slice(&30u16.to_le_bytes());

    ms.extend_from_slice(&20u16.to_le_bytes());

    ms.extend_from_slice(&desc_type::FEATURE_COMPATIBLE_ID.to_le_bytes());

    ms.extend_from_slice(COMPATIBLE_ID_WINUSB);

    ms.extend_from_slice(SUB_COMPATIBLE_ID_WBDI);

    // USB cfg: vendor-class iface 5.

    let cfg: [u8; 18] = [
        9, 2, 18, 0, 1, 1, 0, 0xA0, 0, 9, 4, 5, 0, 1, 0xFF, 0xFF, 0xFF,
        0, // 9-byte interface descriptor
    ];

    match find_wbdi_interface(&cfg, &ms) {
        Some(5) => TestResult::Pass,

        _ => TestResult::Fail("interface number wrong"),
    }
}

kernel_test_in!(
    "drivers/input/wbdi",
    smoke_wbdi_find_interface_in_vendor_class_config
);

fn smoke_wbdi_recogniser_rejects_non_wbdi() -> TestResult {
    use crate::wbdi::{desc_type, is_wbdi};

    let mut blob = alloc::vec::Vec::new();

    blob.extend_from_slice(&10u16.to_le_bytes());

    blob.extend_from_slice(&desc_type::SET_HEADER_DESCRIPTOR.to_le_bytes());

    blob.extend_from_slice(&0x0603_0000u32.to_le_bytes());

    blob.extend_from_slice(&30u16.to_le_bytes());

    blob.extend_from_slice(&20u16.to_le_bytes());

    blob.extend_from_slice(&desc_type::FEATURE_COMPATIBLE_ID.to_le_bytes());

    blob.extend_from_slice(b"WINUSB\0\0");

    blob.extend_from_slice(b"OTHER\0\0\0");

    if is_wbdi(&blob) {
        return TestResult::Fail("sub-id mismatch must reject");
    }

    TestResult::Pass
}

kernel_test_in!("drivers/input/wbdi", smoke_wbdi_recogniser_rejects_non_wbdi);

/// The target Goodix MOC reader uses a vendor-class interface without
/// requiring an MS OS WBDI compatible-ID descriptor, so its VID/PID
/// must remain in the explicit fingerprint table.
fn smoke_wbdi_known_goodix_6594() -> TestResult {
    if crate::wbdi::is_known_fingerprint_vid_pid(0x27C6, 0x6594) {
        TestResult::Pass
    } else {
        TestResult::Fail("Goodix 27c6:6594 missing from fingerprint table")
    }
}
kernel_test_in!("drivers/input/wbdi", smoke_wbdi_known_goodix_6594);

// ── I2C-HID ────────────────────────────────────────────────────────
//
// Mock I2cBus implementation that records every transfer and lets
// each test stage canned reads. Lets us verify the protocol framing
// without needing a real touchpad on a real I2C bus.

mod i2c_hid_smokes {
    use alloc::boxed::Box;
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use async_trait::async_trait;
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use narf_drivers_i2c::{I2cBus, I2cError, I2cOp};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    use crate::i2c_hid::{HidDescriptor, I2cHidDriver, I2cHidError, RetryPolicy, HID_DESC_LENGTH};

    #[derive(Debug)]
    pub(super) struct MockBus {
        /// Pre-staged bytes the bus returns in order, one Vec per
        /// I2cOp::Read in the order they're encountered.
        canned_reads: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
        /// Captured Write payloads, one per I2cOp::Write.
        captured_writes: IrqSafeSpinLock<Vec<Vec<u8>>>,
        /// Fail the next N transfers with `I2cError::Timeout`
        /// (issue #771 fixtures: a wedging device). A failed
        /// transfer records no writes — the command never reached
        /// the device.
        fail_next: AtomicUsize,
        /// Total transfers attempted (failed + successful).
        transfer_count: AtomicUsize,
    }

    impl MockBus {
        pub(super) fn new() -> Self {
            Self {
                canned_reads: IrqSafeSpinLock::new(VecDeque::new()),
                captured_writes: IrqSafeSpinLock::new(Vec::new()),
                fail_next: AtomicUsize::new(0),
                transfer_count: AtomicUsize::new(0),
            }
        }
        pub(super) fn stage_read(&self, data: Vec<u8>) {
            self.canned_reads.lock().push_back(data);
        }
        pub(super) fn writes(&self) -> Vec<Vec<u8>> {
            self.captured_writes.lock().clone()
        }
        /// Fail the next `n` transfers with a bus timeout.
        pub(super) fn fail_next(&self, n: usize) {
            self.fail_next.store(n, Ordering::SeqCst);
        }
        pub(super) fn transfers(&self) -> usize {
            self.transfer_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl I2cBus for MockBus {
        async fn transfer(&self, _addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
            self.transfer_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_next.load(Ordering::SeqCst) > 0 {
                self.fail_next.fetch_sub(1, Ordering::SeqCst);
                return Err(I2cError::Timeout);
            }
            for op in ops.iter_mut() {
                match op {
                    I2cOp::Write(data) => {
                        self.captured_writes.lock().push((*data).to_vec());
                    }
                    I2cOp::Read(buf) => {
                        let canned = self
                            .canned_reads
                            .lock()
                            .pop_front()
                            .unwrap_or_else(|| alloc::vec![0u8; buf.len()]);
                        let n = canned.len().min(buf.len());
                        buf[..n].copy_from_slice(&canned[..n]);
                        for byte in buf.iter_mut().skip(n) {
                            *byte = 0;
                        }
                    }
                }
            }
            Ok(())
        }
        fn name(&self) -> &str {
            "mock-i2c"
        }
    }

    pub(super) fn make_descriptor_bytes() -> Vec<u8> {
        let mut buf = alloc::vec![0u8; HID_DESC_LENGTH];
        let put16 = |buf: &mut [u8], off: usize, v: u16| {
            buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
        };
        put16(&mut buf, 0, HID_DESC_LENGTH as u16); // wHIDDescLength
        put16(&mut buf, 2, 0x0100); // bcdVersion
        put16(&mut buf, 4, 100); // wReportDescLength
        put16(&mut buf, 6, 0x0002); // wReportDescRegister
        put16(&mut buf, 8, 0x0003); // wInputRegister
        put16(&mut buf, 10, 32); // wMaxInputLength
        put16(&mut buf, 12, 0x0004); // wOutputRegister
        put16(&mut buf, 14, 32); // wMaxOutputLength
        put16(&mut buf, 16, 0x0005); // wCommandRegister
        put16(&mut buf, 18, 0x0006); // wDataRegister
        put16(&mut buf, 20, 0x04F3); // wVendorID (Elan)
        put16(&mut buf, 22, 0x3045); // wProductID
        put16(&mut buf, 24, 0x0001); // wVersionID
        buf
    }

    fn smoke_i2c_hid_descriptor_round_trip() -> TestResult {
        let bytes = make_descriptor_bytes();
        let d = match HidDescriptor::parse(&bytes) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("parse failed on valid descriptor"),
        };
        if d.w_hid_desc_length != 30 {
            return TestResult::Fail("wHIDDescLength mismatch");
        }
        if d.bcd_version != 0x0100 {
            return TestResult::Fail("bcdVersion mismatch");
        }
        if d.w_input_register != 0x0003 || d.w_command_register != 0x0005 {
            return TestResult::Fail("operating registers mismatch");
        }
        if d.w_vendor_id != 0x04F3 {
            return TestResult::Fail("VID mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/i2c-hid", smoke_i2c_hid_descriptor_round_trip);

    fn smoke_i2c_hid_descriptor_rejects_short_buf() -> TestResult {
        match HidDescriptor::parse(&[0u8; 10]) {
            Err(I2cHidError::BadDescriptor) => TestResult::Pass,
            _ => TestResult::Fail("short buffer should have been rejected"),
        }
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_descriptor_rejects_short_buf
    );

    fn smoke_i2c_hid_descriptor_rejects_wrong_length_field() -> TestResult {
        let mut bytes = make_descriptor_bytes();
        bytes[0] = 0x10; // length field claims 0x0010 instead of 0x001E
        match HidDescriptor::parse(&bytes) {
            Err(I2cHidError::BadDescriptor) => TestResult::Pass,
            _ => TestResult::Fail("wrong length field should have been rejected"),
        }
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_descriptor_rejects_wrong_length_field
    );

    fn smoke_i2c_hid_descriptor_rejects_wrong_major_version() -> TestResult {
        let mut bytes = make_descriptor_bytes();
        bytes[3] = 0x02; // bcdVersion = 0x0200 (major 2, we expect major 1)
        match HidDescriptor::parse(&bytes) {
            Err(I2cHidError::BadDescriptor) => TestResult::Pass,
            _ => TestResult::Fail("major-version mismatch should have been rejected"),
        }
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_descriptor_rejects_wrong_major_version
    );

    pub(super) fn run_async<F>(fut: F) -> TestResult
    where
        F: core::future::Future<Output = TestResult> + Send + 'static,
    {
        narf_scheduler::__reset_queues_for_test();
        let result = Arc::new(AtomicI32::new(-1));
        let r = result.clone();
        narf_scheduler::spawn(async move {
            let outcome = fut.await;
            let code = match outcome {
                TestResult::Pass => 0,
                TestResult::Fail(_) => 1,
                TestResult::Skip(_) => 2,
            };
            r.store(code, Ordering::SeqCst);
        });
        narf_scheduler::run_until_empty();
        match result.load(Ordering::SeqCst) {
            0 => TestResult::Pass,
            1 => TestResult::Fail("inner fut failed"),
            2 => TestResult::Skip("inner fut skipped"),
            _ => TestResult::Fail("async task didn't complete"),
        }
    }

    fn smoke_i2c_hid_read_descriptor_emits_register_then_read() -> TestResult {
        let bus = Arc::new(MockBus::new());
        bus.stage_read(make_descriptor_bytes());
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        let bus_for_check = bus.clone();
        run_async(async move {
            match drv.read_descriptor().await {
                Ok(d) => {
                    if d.w_command_register != 0x0005 {
                        return TestResult::Fail("descriptor command-reg wrong after read");
                    }
                }
                Err(_) => return TestResult::Fail("read_descriptor errored"),
            }
            // Bus should have seen exactly one Write of [reg_lo, reg_hi]
            let writes = bus_for_check.writes();
            if writes.len() != 1 {
                return TestResult::Fail("expected exactly 1 write before the read");
            }
            if writes[0] != alloc::vec![0x01, 0x00] {
                return TestResult::Fail("descriptor register address bytes wrong");
            }
            TestResult::Pass
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_read_descriptor_emits_register_then_read
    );

    fn smoke_i2c_hid_set_output_report_framing() -> TestResult {
        let bus = Arc::new(MockBus::new());
        bus.stage_read(make_descriptor_bytes());
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        let bus_for_check = bus.clone();
        run_async(async move {
            if drv.read_descriptor().await.is_err() {
                return TestResult::Fail("descriptor read failed");
            }
            // Keyboard LED body: Num+Scroll lit = 0x05 (HID usage
            // order), report ID 0.
            if drv.set_output_report(0, &[0x05]).await.is_err() {
                return TestResult::Fail("set_output_report errored");
            }
            // The Feature form shares the framing (refactor guard).
            if drv.set_feature_report(0, &[0x05]).await.is_err() {
                return TestResult::Fail("set_feature_report errored");
            }
            let writes = bus_for_check.writes();
            if writes.len() != 3 {
                return TestResult::Fail("expected desc-pointer + 2 report writes");
            }
            // SET_REPORT framing (Microsoft HID-over-I2C §7.2):
            // [cmd reg 0x0005 LE][(type<<4)|report id][opcode 0x03]
            // [data reg 0x0006 LE][total len = 2+1+1 = 4 LE]
            // [report id][payload]. Output type = 0x02, Feature = 0x03.
            let expect_output: Vec<u8> =
                alloc::vec![0x05, 0x00, 0x20, 0x03, 0x06, 0x00, 0x04, 0x00, 0x00, 0x05];
            let expect_feature: Vec<u8> =
                alloc::vec![0x05, 0x00, 0x30, 0x03, 0x06, 0x00, 0x04, 0x00, 0x00, 0x05];
            if writes[1] != expect_output {
                return TestResult::Fail("SET_REPORT (Output) frame bytes wrong");
            }
            if writes[2] != expect_feature {
                return TestResult::Fail("SET_REPORT (Feature) frame bytes wrong");
            }
            TestResult::Pass
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_set_output_report_framing
    );

    fn smoke_i2c_hid_reset_writes_command_then_polls_input() -> TestResult {
        let bus = Arc::new(MockBus::new());
        // Stage descriptor read, then a 0-length post-RESET sentinel.
        bus.stage_read(make_descriptor_bytes());
        bus.stage_read(alloc::vec![0u8, 0u8]);
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        let bus_for_check = bus.clone();
        run_async(async move {
            if drv.read_descriptor().await.is_err() {
                return TestResult::Fail("descriptor read failed");
            }
            if drv.reset().await.is_err() {
                return TestResult::Fail("reset failed");
            }
            let writes = bus_for_check.writes();
            // Expect: [desc_reg], [cmd_addr_lo, cmd_addr_hi, 0, 0x01],
            // [input_reg_lo, input_reg_hi]
            if writes.len() != 3 {
                return TestResult::Fail("expected 3 writes (desc, cmd, input)");
            }
            // RESET command bytes: cmd_addr=0x0005, data=0, opcode=0x01
            if writes[1] != alloc::vec![0x05, 0x00, 0x00, 0x01] {
                return TestResult::Fail("RESET command framing wrong");
            }
            // Input register address (0x0003)
            if writes[2] != alloc::vec![0x03, 0x00] {
                return TestResult::Fail("input register address wrong");
            }
            TestResult::Pass
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_reset_writes_command_then_polls_input
    );

    // ── Issue #771: bounded retry / backoff / give-up ─────────────
    //
    // The bounds are NOT invented here: the policy defaults come
    // from the tree itself (CCID `MAX_RETRIES = 3`, i40e
    // start-100 ms / double / cap-30 000 ms). These fixtures prove
    // the driver honours them — a RESET failure retries with
    // backoff then re-binds, and a permanently wedged device gives
    // up after exactly the bounded number of attempts.

    fn smoke_i2c_hid_retry_backoff_doubles_and_caps() -> TestResult {
        let policy = RetryPolicy::default();
        // i40e shape: 100, 200, 400, 800, ... capped at 30 000.
        if policy.backoff_ms(0) != 100
            || policy.backoff_ms(1) != 200
            || policy.backoff_ms(2) != 400
            || policy.backoff_ms(3) != 800
            || policy.backoff_ms(8) != 25_600
            || policy.backoff_ms(9) != 30_000
            || policy.backoff_ms(30) != 30_000
        {
            return TestResult::Fail(
                "default backoff sequence wrong (want 100/200/400/.../30000 cap)",
            );
        }
        let small = RetryPolicy {
            max_attempts: 2,
            base_backoff_ms: 10,
            max_backoff_ms: 25,
        };
        if small.backoff_ms(0) != 10 || small.backoff_ms(1) != 20 || small.backoff_ms(2) != 25 {
            return TestResult::Fail("custom backoff cap wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_retry_backoff_doubles_and_caps
    );

    fn smoke_i2c_hid_reset_retries_then_rebinds() -> TestResult {
        let bus = Arc::new(MockBus::new());
        bus.stage_read(make_descriptor_bytes());
        // 0-length post-RESET sentinel for the successful attempt.
        bus.stage_read(alloc::vec![0u8, 0u8]);
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        let bus_for_check = bus.clone();
        // Zero-backoff test policy: the backoff *values* are proven
        // by the pure test above; here only the attempt counting
        // matters, and sleeps must not slow the suite.
        let policy = RetryPolicy {
            max_attempts: 3,
            base_backoff_ms: 0,
            max_backoff_ms: 0,
        };
        run_async(async move {
            if drv.read_descriptor().await.is_err() {
                return TestResult::Fail("descriptor read failed");
            }
            // Fail the next two transfers (two RESET attempts),
            // then let the third through. Set here — after the
            // descriptor read — so the failures land on RESET.
            bus_for_check.fail_next(2);
            if drv.reset_with_retry(&policy).await.is_err() {
                return TestResult::Fail("reset should have succeeded on attempt 3");
            }
            // Transfers: 1 descriptor read + 2 failed RESET writes
            // + 1 successful RESET write + 1 sentinel poll.
            if bus_for_check.transfers() != 5 {
                return TestResult::Fail(
                    "expected exactly 5 transfers (1 desc + 3 RESET attempts + 1 poll)",
                );
            }
            let writes = bus_for_check.writes();
            if writes.len() != 3 {
                return TestResult::Fail("expected desc + RESET + input-poll writes");
            }
            if writes[1] != alloc::vec![0x05, 0x00, 0x00, 0x01] {
                return TestResult::Fail("RESET command framing wrong on the retry that landed");
            }
            TestResult::Pass
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_reset_retries_then_rebinds
    );

    fn smoke_i2c_hid_reset_gives_up_boundedly() -> TestResult {
        let bus = Arc::new(MockBus::new());
        bus.stage_read(make_descriptor_bytes());
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        let bus_for_check = bus.clone();
        let policy = RetryPolicy {
            max_attempts: 3,
            base_backoff_ms: 0,
            max_backoff_ms: 0,
        };
        run_async(async move {
            if drv.read_descriptor().await.is_err() {
                return TestResult::Fail("descriptor read failed");
            }
            // Wedged device: every transfer fails.
            bus_for_check.fail_next(100);
            match drv.reset_with_retry(&policy).await {
                Err(I2cHidError::Bus(I2cError::Timeout)) => {}
                _ => return TestResult::Fail("wedged device should have failed with Timeout"),
            }
            // Exactly max_attempts RESET attempts, then stop —
            // no fourth attempt, no infinite spin.
            if bus_for_check.transfers() != 4 {
                return TestResult::Fail(
                    "expected exactly 4 transfers (1 desc + 3 RESET attempts)",
                );
            }
            // No RESET command ever landed on the bus.
            let writes = bus_for_check.writes();
            if writes.len() != 1 {
                return TestResult::Fail("wedged device should have seen no RESET write land");
            }
            TestResult::Pass
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_reset_gives_up_boundedly
    );

    fn smoke_i2c_hid_bring_up_returns_descriptor() -> TestResult {
        let bus = Arc::new(MockBus::new());
        bus.stage_read(make_descriptor_bytes());
        bus.stage_read(alloc::vec![0u8, 0u8]);
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        let bus_for_check = bus.clone();
        run_async(async move {
            let policy = RetryPolicy {
                max_attempts: 3,
                base_backoff_ms: 0,
                max_backoff_ms: 0,
            };
            match drv.bring_up(&policy).await {
                Ok(d) => {
                    if d.w_vendor_id != 0x04F3 {
                        return TestResult::Fail("bring_up descriptor VID wrong");
                    }
                }
                Err(_) => return TestResult::Fail("bring_up failed on a healthy bus"),
            }
            // Descriptor read + RESET write + sentinel poll +
            // SET_POWER(ON) write.
            let writes = bus_for_check.writes();
            if writes.len() != 4 {
                return TestResult::Fail("expected desc + RESET + poll + SET_POWER writes");
            }
            if writes[3] != alloc::vec![0x05, 0x00, 0x00, 0x08] {
                return TestResult::Fail("SET_POWER(ON) command framing wrong");
            }
            TestResult::Pass
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_bring_up_returns_descriptor
    );

    fn smoke_i2c_hid_bring_up_fails_on_bad_descriptor() -> TestResult {
        let bus = Arc::new(MockBus::new());
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        let bus_for_check = bus.clone();
        run_async(async move {
            let policy = RetryPolicy {
                max_attempts: 3,
                base_backoff_ms: 0,
                max_backoff_ms: 0,
            };
            // Fail the descriptor read itself: bring-up must fail
            // fast (no RESET attempts against an unidentified
            // device).
            bus_for_check.fail_next(1);
            match drv.bring_up(&policy).await {
                Err(I2cHidError::Bus(I2cError::Timeout)) => {}
                _ => return TestResult::Fail("bring_up should have failed on descriptor read"),
            }
            if bus_for_check.transfers() != 1 {
                return TestResult::Fail("failed descriptor read must not trigger RESET attempts");
            }
            TestResult::Pass
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_bring_up_fails_on_bad_descriptor
    );

    fn smoke_i2c_hid_set_power_validates_state() -> TestResult {
        let bus = Arc::new(MockBus::new());
        bus.stage_read(make_descriptor_bytes());
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        run_async(async move {
            drv.read_descriptor().await.unwrap();
            // 2 = invalid power state
            match drv.set_power(2).await {
                Err(I2cHidError::BadPowerState) => TestResult::Pass,
                _ => TestResult::Fail("invalid power state should have been rejected"),
            }
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_set_power_validates_state
    );

    fn smoke_i2c_hid_set_power_sleep_writes_correct_command() -> TestResult {
        let bus = Arc::new(MockBus::new());
        bus.stage_read(make_descriptor_bytes());
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        let bus_for_check = bus.clone();
        run_async(async move {
            drv.read_descriptor().await.unwrap();
            if drv.set_power(crate::i2c_hid::POWER_SLEEP).await.is_err() {
                return TestResult::Fail("set_power(SLEEP) errored");
            }
            let writes = bus_for_check.writes();
            // writes[0] is the descriptor register read.
            // writes[1] is the SET_POWER cmd: cmd_addr=0x0005, data=0x01, opcode=0x08
            if writes[1] != alloc::vec![0x05, 0x00, 0x01, 0x08] {
                return TestResult::Fail("SET_POWER(SLEEP) command framing wrong");
            }
            TestResult::Pass
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_set_power_sleep_writes_correct_command
    );

    fn smoke_i2c_hid_input_report_decode() -> TestResult {
        // First 2 bytes = total length (8) LSB; next 6 bytes = payload.
        let bus = Arc::new(MockBus::new());
        bus.stage_read(make_descriptor_bytes());
        // Input report: length=8, payload=[1,2,3,4,5,6]; pad to
        // wMaxInputLength (32 bytes) with zeros.
        let mut report = alloc::vec![0u8; 32];
        report[0..2].copy_from_slice(&8u16.to_le_bytes());
        report[2..8].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        bus.stage_read(report);
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        run_async(async move {
            drv.read_descriptor().await.unwrap();
            let mut buf = [0u8; 16];
            match drv.read_input_report(&mut buf).await {
                Ok(6) => {
                    if buf[..6] != [1, 2, 3, 4, 5, 6] {
                        TestResult::Fail("payload bytes wrong")
                    } else {
                        TestResult::Pass
                    }
                }
                Ok(other) => {
                    let _ = other;
                    TestResult::Fail("payload length wrong")
                }
                Err(_) => TestResult::Fail("read_input_report errored"),
            }
        })
    }
    kernel_test_in!("drivers/input/i2c-hid", smoke_i2c_hid_input_report_decode);

    fn smoke_i2c_hid_input_report_zero_means_no_data() -> TestResult {
        let bus = Arc::new(MockBus::new());
        bus.stage_read(make_descriptor_bytes());
        // Length=0 → device has nothing to report.
        bus.stage_read(alloc::vec![0u8; 32]);
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        run_async(async move {
            drv.read_descriptor().await.unwrap();
            let mut buf = [0u8; 16];
            match drv.read_input_report(&mut buf).await {
                Ok(0) => TestResult::Pass,
                _ => TestResult::Fail("len=0 should have returned 0 bytes"),
            }
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_input_report_zero_means_no_data
    );

    fn smoke_i2c_hid_uninitialised_rejects_ops() -> TestResult {
        // No descriptor read first → reset/set_power/read_input
        // should all return NotInitialised.
        let bus: Arc<dyn I2cBus> = Arc::new(MockBus::new());
        let drv = I2cHidDriver::new(bus, 0x2c, 0x0001);
        run_async(async move {
            match drv.reset().await {
                Err(I2cHidError::NotInitialised) => {}
                _ => return TestResult::Fail("reset should require descriptor"),
            }
            match drv.set_power(0).await {
                Err(I2cHidError::NotInitialised) => {}
                _ => return TestResult::Fail("set_power should require descriptor"),
            }
            let mut buf = [0u8; 4];
            match drv.read_input_report(&mut buf).await {
                Err(I2cHidError::NotInitialised) => {}
                _ => return TestResult::Fail("read_input_report should require descriptor"),
            }
            TestResult::Pass
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_i2c_hid_uninitialised_rejects_ops
    );
}

// ── i2c-hid auto-binding ──────────────────────────────────────────
//
// Smokes for the bind helper + PTP→PointerEvent translator. The
// bind helper itself depends on AML namespace + I2C registry state
// that's not trivially fakeable in a smoke, so we cover the pure
// translation path here and rely on real-HW bring-up to exercise
// the discovery pass end-to-end.

mod i2c_hid_bind_smokes {
    use alloc::vec::Vec;
    use narf_hid::ptp::{DecodedContact, DecodedReport};
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, PointerButtons,
    };
    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::i2c_hid_bind::__push_ptp_pointer_for_test as push_ptp_pointer;

    fn one_contact(x: i32, y: i32, tip: bool) -> DecodedReport {
        DecodedReport {
            contacts: alloc::vec![DecodedContact {
                tip_switch: tip,
                contact_id: 0,
                x,
                y,
                pressure: None,
                in_range: tip,
                confidence: true,
            }],
            contact_count: 1,
            scan_time: 0,
            button1: false,
        }
    }

    fn smoke_ptp_pointer_emits_relative_motion() -> TestResult {
        init_global_ring(8);
        __reset_global_ring_for_test();
        let mut lx: Option<i32> = None;
        let mut ly: Option<i32> = None;
        let mut lb = false;

        // First touch: no last position → dx/dy=0, suppressed.
        push_ptp_pointer(&one_contact(100, 200, true), &mut lx, &mut ly, &mut lb);
        if pop_global().is_some() {
            return TestResult::Fail("first touch should produce zero-delta and be suppressed");
        }

        // Second touch: deltas = (5, 7).
        push_ptp_pointer(&one_contact(105, 207, true), &mut lx, &mut ly, &mut lb);
        match pop_global() {
            Some(InputEvent::Pointer(p)) => {
                if p.dx != 5 || p.dy != 7 {
                    return TestResult::Fail("dx/dy mismatch on motion");
                }
                if p.buttons != PointerButtons::EMPTY {
                    return TestResult::Fail("no button should be set");
                }
            }
            _ => return TestResult::Fail("expected PointerEvent on motion"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_ptp_pointer_emits_relative_motion
    );

    fn smoke_ptp_pointer_button_change_emits_event() -> TestResult {
        init_global_ring(8);
        __reset_global_ring_for_test();
        let mut lx: Option<i32> = None;
        let mut ly: Option<i32> = None;
        let mut lb = false;

        let mut r = one_contact(50, 50, true);
        // First sample primes the deltas; suppressed (no motion).
        push_ptp_pointer(&r, &mut lx, &mut ly, &mut lb);
        let _ = pop_global();

        // Same coordinates, button1 transitions false→true. Should
        // emit a PointerEvent carrying the button bit even with
        // zero motion.
        r.button1 = true;
        push_ptp_pointer(&r, &mut lx, &mut ly, &mut lb);
        match pop_global() {
            Some(InputEvent::Pointer(p)) => {
                if p.dx != 0 || p.dy != 0 {
                    return TestResult::Fail("dx/dy should be zero on button-only");
                }
                if !p.buttons.contains(PointerButtons::LEFT) {
                    return TestResult::Fail("LEFT button should be set");
                }
            }
            _ => return TestResult::Fail("expected PointerEvent on button transition"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_ptp_pointer_button_change_emits_event
    );

    fn smoke_ptp_pointer_no_active_contact_resets_origin() -> TestResult {
        init_global_ring(8);
        __reset_global_ring_for_test();
        let mut lx: Option<i32> = None;
        let mut ly: Option<i32> = None;
        let mut lb = false;

        push_ptp_pointer(&one_contact(10, 20, true), &mut lx, &mut ly, &mut lb);
        push_ptp_pointer(&one_contact(15, 25, true), &mut lx, &mut ly, &mut lb);
        let _: Vec<_> = (0..2).filter_map(|_| pop_global()).collect();

        // Lift: no active contact. Should reset last_x/y so the next
        // touch doesn't emit a huge fake delta.
        push_ptp_pointer(&one_contact(0, 0, false), &mut lx, &mut ly, &mut lb);
        let _ = pop_global();
        if lx.is_some() || ly.is_some() {
            return TestResult::Fail("lift should clear last position");
        }

        // New touch far away: first sample after lift must be
        // suppressed (would be a huge delta against stale prev).
        push_ptp_pointer(&one_contact(500, 500, true), &mut lx, &mut ly, &mut lb);
        if pop_global().is_some() {
            return TestResult::Fail("first touch after lift should be suppressed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_ptp_pointer_no_active_contact_resets_origin
    );

    // Publication: a two-contact PTP report must reach the evdev node
    // as slot-protocol-B — the second contact is exactly what the
    // first-contact relative-pointer path above drops (issue #764).
    fn smoke_ptp_reports_reach_evdev_node() -> TestResult {
        use crate::i2c_hid_touch::{
            __new_ptp_state_for_test, __pump_ptp_to_evdev_for_test, build_ptp_caps,
        };
        use narf_input::abs;
        use narf_input::evdev::{bus, key, prop, DeviceCaps, EventType, InputId, ROUTER};

        let blob = narf_hid::ptp::__ptp_descriptor_blob();
        let parsed = match narf_hid::parse(blob) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("parse(PTP_DESCRIPTOR) failed"),
        };
        let profile = match narf_hid::ptp::detect(&parsed) {
            Some(p) => p,
            None => return TestResult::Fail("PTP detect rejected the descriptor"),
        };

        let mut identity = DeviceCaps::new();
        identity.set_identity(
            "ELAN09BD I2C-HID Touchpad",
            "i2c-ELAN0001/input0",
            "",
            InputId::new(bus::I2C, 0x04F3, 0x3045, 0x0001),
        );
        let caps = build_ptp_caps(&profile, &identity);
        if !caps.has_prop(prop::BUTTONPAD) || !caps.has_prop(prop::POINTER) {
            return TestResult::Fail("PTP caps must carry POINTER+BUTTONPAD props");
        }
        if caps.abs_info(abs::ABS_MT_POSITION_X).map(|i| i.max) != Some(0x7FFF) {
            return TestResult::Fail("PTP MT X range must come from the profile");
        }
        let (id, node) = ROUTER.register_device(caps);
        let reader = ROUTER.open_reader(id).expect("reader");
        let mut state = __new_ptp_state_for_test(profile.contacts_max);

        let contact = |cid: u8, tip: bool, x: i32, y: i32| DecodedContact {
            tip_switch: tip,
            contact_id: cid,
            x,
            y,
            pressure: None,
            in_range: tip,
            confidence: true,
        };
        let down = DecodedReport {
            contacts: alloc::vec![contact(7, true, 100, 200), contact(9, true, 300, 400)],
            contact_count: 2,
            scan_time: 0,
            button1: true,
        };
        let n = __pump_ptp_to_evdev_for_test(&profile, &mut state, &node, &down);
        if n == 0 {
            ROUTER.unregister_device(id);
            return TestResult::Fail("PTP down frame emitted no evdev events");
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
        let ok = has(EventType::Abs, abs::ABS_MT_TRACKING_ID, 9)
            && has(EventType::Abs, abs::ABS_MT_POSITION_X, 300)
            && has(EventType::Abs, abs::ABS_X, 100)
            && has(EventType::Key, key::BTN_TOUCH, 1)
            && has(EventType::Key, key::BTN_LEFT, 1)
            && events.iter().filter(|e| e.type_ == EventType::Syn).count() == 1;
        if !ok {
            ROUTER.unregister_device(id);
            return TestResult::Fail("PTP evdev frame missing second contact / click / SYN");
        }

        // Release both contacts + the clickpad button in one frame.
        let up = DecodedReport {
            contacts: alloc::vec![contact(7, false, 100, 200), contact(9, false, 300, 400)],
            contact_count: 2,
            scan_time: 0,
            button1: false,
        };
        let _ = __pump_ptp_to_evdev_for_test(&profile, &mut state, &node, &up);
        let mut events = alloc::vec::Vec::new();
        while let Some(ev) = reader.poll_event() {
            events.push(ev);
        }
        let has = |type_: EventType, code: u16, value: i32| {
            events
                .iter()
                .any(|e| e.type_ == type_ && e.code == code && e.value == value)
        };
        let ok = has(EventType::Abs, abs::ABS_MT_TRACKING_ID, -1)
            && has(EventType::Key, key::BTN_TOUCH, 0)
            && has(EventType::Key, key::BTN_LEFT, 0);
        ROUTER.unregister_device(id);
        if !ok {
            return TestResult::Fail("PTP release frame missing tracking -1 / releases");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/i2c-hid", smoke_ptp_reports_reach_evdev_node);

    // End-to-end test of the SET_FEATURE(Device Mode = MULTI_TOUCH)
    // wiring added to the bind layer. Parses a real PTP report
    // descriptor, builds a PtpProfile from it, hands it to
    // `set_ptp_multi_touch_mode` against a MockBus, and checks
    // both the return value and the captured wire bytes.
    fn smoke_set_ptp_multi_touch_mode_writes_set_feature() -> TestResult {
        use alloc::sync::Arc;
        use narf_drivers_i2c::I2cBus;

        use super::i2c_hid_smokes::{make_descriptor_bytes, run_async, MockBus};
        use crate::i2c_hid::I2cHidDriver;
        use crate::i2c_hid_bind::{set_ptp_multi_touch_mode, PtpModeSetResult};

        // Parse the shared PTP descriptor blob → ReportDescriptor →
        // PtpProfile. The blob is the synthetic 2-finger fixture
        // narf-hid uses for its own smokes.
        let blob = narf_hid::ptp::__ptp_descriptor_blob();
        let parsed = match narf_hid::parse(blob) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("parse(PTP_DESCRIPTOR) failed"),
        };
        let profile = match narf_hid::ptp::detect(&parsed) {
            Some(p) => p,
            None => return TestResult::Fail("PTP detect rejected the descriptor"),
        };

        // Bring up an I2cHidDriver wrapped around a MockBus. We
        // pre-stage the descriptor read so `read_descriptor` finds
        // the operating registers it needs.
        let bus = Arc::new(MockBus::new());
        bus.stage_read(make_descriptor_bytes());
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        let bus_for_check = bus.clone();
        run_async(async move {
            if drv.read_descriptor().await.is_err() {
                return TestResult::Fail("descriptor read failed");
            }
            let result = set_ptp_multi_touch_mode(&drv, &profile).await;
            if result != PtpModeSetResult::Set {
                return TestResult::Fail("set_ptp_multi_touch_mode returned non-Set");
            }
            // Captured writes: [0] = descriptor read, [1] = the
            // SET_FEATURE we just issued. The SET_FEATURE wire form
            // (per Microsoft HID-over-I2C spec §7.2.3.1) is:
            //   [cmd_addr_lo, cmd_addr_hi,
            //    (report_type<<4) | report_id,
            //    SET_REPORT opcode,
            //    data_addr_lo, data_addr_hi,
            //    total_len_lo, total_len_hi,
            //    report_id,
            //    body...]
            let writes = bus_for_check.writes();
            if writes.len() < 2 {
                return TestResult::Fail("expected at least 2 bus writes");
            }
            let w = &writes[1];
            // From make_descriptor_bytes:
            //   wCommandRegister = 0x0005, wDataRegister = 0x0006.
            // From the synthetic PTP descriptor:
            //   Device Mode feature report id = 0x03.
            if w.len() < 10 {
                return TestResult::Fail("SET_FEATURE wire write too short");
            }
            if w[0] != 0x05 || w[1] != 0x00 {
                return TestResult::Fail("cmd_register low/high bytes wrong");
            }
            // report_type (FEATURE=0x03) in high nibble, report_id
            // (0x03) in low nibble → 0x33.
            if w[2] != 0x33 {
                return TestResult::Fail("report type+id byte wrong");
            }
            // SET_REPORT opcode = 0x03.
            if w[3] != 0x03 {
                return TestResult::Fail("SET_REPORT opcode byte wrong");
            }
            if w[4] != 0x06 || w[5] != 0x00 {
                return TestResult::Fail("data_register low/high bytes wrong");
            }
            // Total length: 2 (prefix) + 1 (report_id) + 1 (mode body) = 4.
            if w[6] != 0x04 || w[7] != 0x00 {
                return TestResult::Fail("total length field wrong");
            }
            // The echoed report id.
            if w[8] != 0x03 {
                return TestResult::Fail("echoed report id wrong");
            }
            // The mode byte — MULTI_TOUCH = 0x03.
            if w[9] != narf_hid::ptp::mode::MULTI_TOUCH {
                return TestResult::Fail("mode byte != MULTI_TOUCH");
            }
            TestResult::Pass
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_set_ptp_multi_touch_mode_writes_set_feature
    );
}

// ── i2c-hid touchscreen pump ──────────────────────────────────────
//
// Smokes for the touchscreen decode → TouchEvent translation path.
// The descriptor + report decode itself is covered in narf-hid;
// here we exercise the slot-allocation + Down/Move/Up state
// transitions + coordinate normalisation that the bind layer adds
// on top of the decoder.

mod i2c_hid_touch_smokes {
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_touch, TouchState};
    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::i2c_hid_touch::{
        __build_decoded_for_test, __new_state_for_test, __pump_report_for_test,
    };

    /// Manufacture a TouchscreenProfile from the canonical HID
    /// touchscreen descriptor in narf-hid. Keeps the smokes tiny.
    fn make_profile() -> narf_hid::touchscreen::TouchscreenProfile {
        let blob = narf_hid::touchscreen::__touchscreen_descriptor_blob();
        let parsed = narf_hid::parse(blob).expect("parse");
        narf_hid::touchscreen::detect(&parsed).expect("detect")
    }

    fn smoke_touchscreen_down_move_up_lifecycle() -> TestResult {
        init_global_ring(16);
        __reset_global_ring_for_test();
        let profile = make_profile();
        let mut state = __new_state_for_test();

        // First report: contact id 5 down at (0x1000, 0x2000).
        let n = __pump_report_for_test(
            &profile,
            &mut state,
            &__build_decoded_for_test(&[(5, true, 0x1000, 0x2000)]),
        );
        if n != 1 {
            return TestResult::Fail("first report should push one event");
        }
        let down = match pop_touch() {
            Some(t) => t,
            None => return TestResult::Fail("expected Touch Down event"),
        };
        if down.state != TouchState::Down {
            return TestResult::Fail("first contact must be Down");
        }
        if down.id != 5 || down.slot != 0 {
            return TestResult::Fail("contact id 5 should bind to slot 0");
        }

        // Second report: same contact, moved. Expect Move.
        let _ = __pump_report_for_test(
            &profile,
            &mut state,
            &__build_decoded_for_test(&[(5, true, 0x2000, 0x3000)]),
        );
        let mv = match pop_touch() {
            Some(t) => t,
            None => return TestResult::Fail("expected Touch Move event"),
        };
        if mv.state != TouchState::Move {
            return TestResult::Fail("second contact must be Move");
        }
        if mv.id != 5 || mv.slot != 0 {
            return TestResult::Fail("Move must reuse slot 0 for contact id 5");
        }

        // Third report: tip switch released. Expect Up.
        let _ = __pump_report_for_test(
            &profile,
            &mut state,
            &__build_decoded_for_test(&[(5, false, 0x2000, 0x3000)]),
        );
        let up = match pop_touch() {
            Some(t) => t,
            None => return TestResult::Fail("expected Touch Up event"),
        };
        if up.state != TouchState::Up {
            return TestResult::Fail("released contact must be Up");
        }
        if up.id != 5 {
            return TestResult::Fail("Up must carry id 5");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_touchscreen_down_move_up_lifecycle
    );

    fn smoke_touchscreen_two_fingers_get_distinct_slots() -> TestResult {
        init_global_ring(16);
        __reset_global_ring_for_test();
        let profile = make_profile();
        let mut state = __new_state_for_test();

        // Two fingers down at once, contact ids 3 and 7.
        let n = __pump_report_for_test(
            &profile,
            &mut state,
            &__build_decoded_for_test(&[(3, true, 0x0100, 0x0100), (7, true, 0x6000, 0x6000)]),
        );
        if n != 2 {
            return TestResult::Fail("two contacts down should push 2 events");
        }
        let t0 = pop_touch().expect("first event");
        let t1 = pop_touch().expect("second event");
        if t0.slot == t1.slot {
            return TestResult::Fail("two simultaneous contacts must hold distinct slots");
        }
        if t0.state != TouchState::Down || t1.state != TouchState::Down {
            return TestResult::Fail("both initial contacts must be Down");
        }
        let ids: alloc::vec::Vec<u16> = alloc::vec![t0.id, t1.id];
        if !ids.contains(&3) || !ids.contains(&7) {
            return TestResult::Fail("contact ids should be 3 and 7");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_touchscreen_two_fingers_get_distinct_slots
    );

    fn smoke_touchscreen_normalises_coordinates_to_u16() -> TestResult {
        use narf_input::TouchEvent;
        let max = TouchEvent::normalise_axis(0x7FFF, 0, 0x7FFF);
        if max != u16::MAX {
            return TestResult::Fail("max value should map to 0xFFFF");
        }
        let min = TouchEvent::normalise_axis(0, 0, 0x7FFF);
        if min != 0 {
            return TestResult::Fail("min value should map to 0");
        }
        let mid = TouchEvent::normalise_axis(0x4000, 0, 0x7FFF);
        if !(0x7FF0..=0x8010).contains(&mid) {
            return TestResult::Fail("midpoint should normalise to ~0x8000");
        }
        let high = TouchEvent::normalise_axis(0x10000, 0, 0x7FFF);
        if high != u16::MAX {
            return TestResult::Fail("over-range value should clamp to MAX");
        }
        let low = TouchEvent::normalise_axis(-100, 0, 0x7FFF);
        if low != 0 {
            return TestResult::Fail("under-range value should clamp to 0");
        }
        let degen = TouchEvent::normalise_axis(42, 100, 100);
        if degen != 42 {
            return TestResult::Fail("degenerate range should pass value through");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_touchscreen_normalises_coordinates_to_u16
    );

    fn smoke_touchscreen_slot_reused_after_release() -> TestResult {
        init_global_ring(16);
        __reset_global_ring_for_test();
        let profile = make_profile();
        let mut state = __new_state_for_test();

        let _ = __pump_report_for_test(
            &profile,
            &mut state,
            &__build_decoded_for_test(&[(42, true, 0, 0)]),
        );
        let _ = __pump_report_for_test(
            &profile,
            &mut state,
            &__build_decoded_for_test(&[(42, false, 0, 0)]),
        );
        let _ = pop_touch();
        let _ = pop_touch();

        let _ = __pump_report_for_test(
            &profile,
            &mut state,
            &__build_decoded_for_test(&[(99, true, 0, 0)]),
        );
        let new_touch = match pop_touch() {
            Some(t) => t,
            None => return TestResult::Fail("expected Touch Down for id 99"),
        };
        if new_touch.id != 99 || new_touch.slot != 0 {
            return TestResult::Fail("freed slot 0 should be reused by next Down");
        }
        if new_touch.state != TouchState::Down {
            return TestResult::Fail("new contact must be Down");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_touchscreen_slot_reused_after_release
    );

    fn smoke_touchscreen_event_lands_on_touch_ring() -> TestResult {
        init_global_ring(8);
        __reset_global_ring_for_test();
        let profile = make_profile();
        let mut state = __new_state_for_test();
        let _ = __pump_report_for_test(
            &profile,
            &mut state,
            &__build_decoded_for_test(&[(1, true, 0x100, 0x200)]),
        );
        match pop_touch() {
            Some(_) => TestResult::Pass,
            None => TestResult::Fail("touch event missing from Touch ring"),
        }
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_touchscreen_event_lands_on_touch_ring
    );

    fn smoke_touchscreen_no_event_on_unknown_release() -> TestResult {
        // A "tip_switch=0" report for a contact id we never saw
        // Down should NOT emit anything — there's no slot to
        // release.
        init_global_ring(8);
        __reset_global_ring_for_test();
        let profile = make_profile();
        let mut state = __new_state_for_test();
        let n = __pump_report_for_test(
            &profile,
            &mut state,
            &__build_decoded_for_test(&[(123, false, 0, 0)]),
        );
        if n != 0 {
            return TestResult::Fail("phantom release should not produce an event");
        }
        if pop_touch().is_some() {
            return TestResult::Fail("phantom release pushed an event");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_touchscreen_no_event_on_unknown_release
    );

    // ── Pen / stylus pump ─────────────────────────────────────────
    //
    // Exercises `pump_pen_report` — the bridge between
    // `narf_hid::pen::DecodedPen` and the Button + Absolute rings.

    fn smoke_pen_in_range_emits_btn_tool_pen_and_abs_xy() -> TestResult {
        use crate::i2c_hid_touch::{
            __build_pen_for_test, __new_pen_state_for_test, __pump_pen_for_test,
        };
        use narf_input::{
            __reset_global_ring_for_test, abs, btn, init_global_ring, pop_absolute, pop_button,
        };
        init_global_ring(16);
        __reset_global_ring_for_test();
        let mut state = __new_pen_state_for_test();

        // Hover (in_range=true, tip=false). Expect BTN_TOOL_PEN=1
        // and an ABS_X + ABS_Y.
        let pen = __build_pen_for_test(true, false, false, false, 0x1000, 0x2000, None);
        let n = __pump_pen_for_test(&mut state, &pen);
        if n < 3 {
            return TestResult::Fail("hover should emit at least 3 events");
        }
        match pop_button() {
            Some(b) => {
                if b.code != btn::BTN_TOOL_PEN || !b.pressed {
                    return TestResult::Fail("expected BTN_TOOL_PEN pressed");
                }
            }
            None => return TestResult::Fail("no button event for hover"),
        }
        let ax = match pop_absolute() {
            Some(a) => a,
            None => return TestResult::Fail("no ABS_X event for hover"),
        };
        if ax.axis != abs::ABS_X || ax.value != 0x1000 {
            return TestResult::Fail("ABS_X shape wrong");
        }
        let ay = match pop_absolute() {
            Some(a) => a,
            None => return TestResult::Fail("no ABS_Y event for hover"),
        };
        if ay.axis != abs::ABS_Y || ay.value != 0x2000 {
            return TestResult::Fail("ABS_Y shape wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_pen_in_range_emits_btn_tool_pen_and_abs_xy
    );

    fn smoke_pen_tip_down_emits_btn_stylus_and_pressure() -> TestResult {
        use crate::i2c_hid_touch::{
            __build_pen_for_test, __new_pen_state_for_test, __pump_pen_for_test,
        };
        use narf_input::{
            __reset_global_ring_for_test, abs, btn, init_global_ring, pop_absolute, pop_button,
        };
        init_global_ring(16);
        __reset_global_ring_for_test();
        let mut state = __new_pen_state_for_test();

        // Hover first so in_range state is set.
        let hover = __build_pen_for_test(true, false, false, false, 0, 0, None);
        let _ = __pump_pen_for_test(&mut state, &hover);
        // Drain the hover events.
        while pop_button().is_some() {}
        while pop_absolute().is_some() {}

        // Tip down with pressure 512.
        let tip_down = __build_pen_for_test(true, true, false, false, 100, 200, Some(512));
        let _ = __pump_pen_for_test(&mut state, &tip_down);

        // Expect BTN_STYLUS=true (tip), then ABS_X, ABS_Y, ABS_PRESSURE.
        match pop_button() {
            Some(b) if b.code == btn::BTN_STYLUS && b.pressed => {}
            _ => return TestResult::Fail("expected BTN_STYLUS pressed"),
        }
        let found_pressure = {
            let mut found = false;
            for _ in 0..4 {
                if let Some(a) = pop_absolute() {
                    if a.axis == abs::ABS_PRESSURE && a.value == 512 {
                        found = true;
                    }
                }
            }
            found
        };
        if !found_pressure {
            return TestResult::Fail("ABS_PRESSURE(512) not emitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_pen_tip_down_emits_btn_stylus_and_pressure
    );

    fn smoke_pen_eraser_emits_btn_tool_rubber() -> TestResult {
        use crate::i2c_hid_touch::{
            __build_pen_for_test, __new_pen_state_for_test, __pump_pen_for_test,
        };
        use narf_input::{__reset_global_ring_for_test, btn, init_global_ring, pop_button};
        init_global_ring(16);
        __reset_global_ring_for_test();
        let mut state = __new_pen_state_for_test();

        // Eraser end (eraser=true, in_range=true).
        let eraser = __build_pen_for_test(true, false, true, false, 0, 0, None);
        let _ = __pump_pen_for_test(&mut state, &eraser);

        // First button event must be BTN_TOOL_RUBBER pressed.
        match pop_button() {
            Some(b) => {
                if b.code != btn::BTN_TOOL_RUBBER || !b.pressed {
                    return TestResult::Fail("expected BTN_TOOL_RUBBER pressed");
                }
            }
            None => return TestResult::Fail("no button event for eraser hover"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_pen_eraser_emits_btn_tool_rubber
    );

    fn smoke_pen_leave_range_releases_tool() -> TestResult {
        use crate::i2c_hid_touch::{
            __build_pen_for_test, __new_pen_state_for_test, __pump_pen_for_test,
        };
        use narf_input::{__reset_global_ring_for_test, btn, init_global_ring, pop_button};
        init_global_ring(16);
        __reset_global_ring_for_test();
        let mut state = __new_pen_state_for_test();

        // Hover in.
        let hover = __build_pen_for_test(true, false, false, false, 0, 0, None);
        let _ = __pump_pen_for_test(&mut state, &hover);
        while pop_button().is_some() {}

        // Hover out: BTN_TOOL_PEN released.
        let out = __build_pen_for_test(false, false, false, false, 0, 0, None);
        let _ = __pump_pen_for_test(&mut state, &out);
        match pop_button() {
            Some(b) => {
                if b.code != btn::BTN_TOOL_PEN || b.pressed {
                    return TestResult::Fail("expected BTN_TOOL_PEN released");
                }
            }
            None => return TestResult::Fail("no button event for pen-out"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/i2c-hid", smoke_pen_leave_range_releases_tool);

    // Publication: touchscreen contacts must reach the evdev node as
    // MT frames with the device's identity (issue #764), not only the
    // global ring.
    fn smoke_touchscreen_reports_reach_evdev_node() -> TestResult {
        use crate::i2c_hid_touch::{__pump_report_to_evdev_for_test, build_touchscreen_caps};
        use narf_input::abs;
        use narf_input::evdev::{bus, key, prop, DeviceCaps, EventType, InputId, ROUTER};

        let profile = make_profile();
        let mut identity = DeviceCaps::new();
        identity.set_identity(
            "GDIX I2C-HID Touchscreen",
            "i2c-GDIX0001/input0",
            "",
            InputId::new(bus::I2C, 0x27C6, 0x0117, 0x0001),
        );
        let caps = build_touchscreen_caps(&profile, &identity);
        if !caps.has_prop(prop::DIRECT) || caps.has_prop(prop::BUTTONPAD) {
            return TestResult::Fail("touchscreen caps must be DIRECT, not BUTTONPAD");
        }
        let (id, node) = ROUTER.register_device(caps);
        if ROUTER.caps(id).expect("caps").name != "GDIX I2C-HID Touchscreen" {
            ROUTER.unregister_device(id);
            return TestResult::Fail("touchscreen node lost its identity");
        }
        let reader = ROUTER.open_reader(id).expect("reader");
        let mut state = __new_state_for_test();
        let _ = __pump_report_to_evdev_for_test(
            &profile,
            &mut state,
            &__build_decoded_for_test(&[(3, true, 0x0100, 0x0200), (7, true, 0x6000, 0x6000)]),
            &node,
        );
        let mut events = alloc::vec::Vec::new();
        while let Some(ev) = reader.poll_event() {
            events.push(ev);
        }
        let has = |type_: EventType, code: u16, value: i32| {
            events
                .iter()
                .any(|e| e.type_ == type_ && e.code == code && e.value == value)
        };
        let ok = has(EventType::Abs, abs::ABS_MT_TRACKING_ID, 7)
            && has(EventType::Abs, abs::ABS_MT_POSITION_X, 0x6000)
            && has(EventType::Key, key::BTN_TOUCH, 1)
            && events.iter().filter(|e| e.type_ == EventType::Syn).count() == 1;
        ROUTER.unregister_device(id);
        if !ok {
            return TestResult::Fail("touchscreen evdev frame missing second contact");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_touchscreen_reports_reach_evdev_node
    );

    // Publication: pen reports must reach the evdev node with tablet
    // semantics (BTN_TOOL_PEN + BTN_TOUCH + ABS_PRESSURE), not the
    // global ring's BTN_STYLUS-for-tip mapping.
    fn smoke_pen_reports_reach_evdev_node() -> TestResult {
        use crate::i2c_hid_touch::{
            __build_pen_for_test, __new_pen_state_for_test, __pump_pen_to_evdev_for_test,
            build_pen_caps,
        };
        use narf_hid::pen::{PenFields, PenProfile, UsagePick};
        use narf_input::abs;
        use narf_input::evdev::{bus, key, prop, DeviceCaps, EventType, InputId, ROUTER};

        // Pen profile manufactured from a parsed descriptor field so
        // the caps constructor sees real logical ranges.
        let blob = narf_hid::touchscreen::__touchscreen_descriptor_blob();
        let parsed = narf_hid::parse(blob).expect("parse");
        let base = parsed.fields[0].clone();
        let pick = |min: i32, max: i32| {
            let mut f = base.clone();
            f.logical_min = min;
            f.logical_max = max;
            UsagePick { field: f, index: 0 }
        };
        let profile = PenProfile {
            input_report_id: 1,
            fields: PenFields {
                tip_switch: pick(0, 1),
                in_range: Some(pick(0, 1)),
                eraser: Some(pick(0, 1)),
                invert: None,
                barrel_switch: Some(pick(0, 1)),
                secondary_barrel_switch: None,
                x: pick(0, 0x7FFF),
                y: pick(0, 0x7FFF),
                tip_pressure: Some(pick(0, 1023)),
                x_tilt: None,
                y_tilt: None,
                twist: None,
            },
        };
        let mut identity = DeviceCaps::new();
        identity.set_identity(
            "WCOM I2C-HID Pen",
            "i2c-WCOM0001/input0",
            "",
            InputId::new(bus::I2C, 0x056A, 0x0001, 0x0001),
        );
        let caps = build_pen_caps(&profile, &identity);
        if !caps.has_prop(prop::DIRECT)
            || caps.abs_info(abs::ABS_PRESSURE).map(|i| i.max) != Some(1023)
        {
            return TestResult::Fail("pen caps must be DIRECT with the pressure range");
        }
        let (id, node) = ROUTER.register_device(caps);
        let reader = ROUTER.open_reader(id).expect("reader");
        let mut state = __new_pen_state_for_test();

        // Tip down with pressure + barrel held.
        let pen = __build_pen_for_test(true, true, false, true, 100, 200, Some(512));
        let _ = __pump_pen_to_evdev_for_test(&mut state, &pen, &node);
        let mut events = alloc::vec::Vec::new();
        while let Some(ev) = reader.poll_event() {
            events.push(ev);
        }
        let has = |type_: EventType, code: u16, value: i32| {
            events
                .iter()
                .any(|e| e.type_ == type_ && e.code == code && e.value == value)
        };
        let ok = has(EventType::Key, key::BTN_TOOL_PEN, 1)
            && has(EventType::Key, key::BTN_TOUCH, 1)
            && has(EventType::Key, key::BTN_STYLUS, 1)
            && has(EventType::Abs, abs::ABS_X, 100)
            && has(EventType::Abs, abs::ABS_PRESSURE, 512);
        if !ok {
            ROUTER.unregister_device(id);
            return TestResult::Fail("pen evdev frame missing tool/touch/stylus/pressure");
        }

        // Leave range: the tool must be released exactly once.
        let out = __build_pen_for_test(false, false, false, false, 0, 0, None);
        let _ = __pump_pen_to_evdev_for_test(&mut state, &out, &node);
        let mut events = alloc::vec::Vec::new();
        while let Some(ev) = reader.poll_event() {
            events.push(ev);
        }
        let releases = events
            .iter()
            .filter(|e| e.type_ == EventType::Key && e.code == key::BTN_TOOL_PEN && e.value == 0)
            .count();
        ROUTER.unregister_device(id);
        if releases != 1 {
            return TestResult::Fail("pen leave-range must release the tool once");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/i2c-hid", smoke_pen_reports_reach_evdev_node);

    // ── End-to-end FakeI2cHid bind ───────────────────────────────
    //
    // Builds a MockBus, stages a full HID descriptor + touchscreen
    // report-descriptor read, plus one synthetic 2-finger touchscreen
    // input report, and verifies that TouchEvents land on the ring.
    // This exercises the entire decode chain without real hardware.

    fn smoke_fake_i2c_hid_touchscreen_end_to_end() -> TestResult {
        use super::i2c_hid_smokes::{make_descriptor_bytes, run_async, MockBus};
        use crate::i2c_hid::{I2cHidDriver, POWER_ON};
        use alloc::sync::Arc;
        use narf_drivers_i2c::I2cBus;
        use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_touch, TouchState};

        // ── Build the report-descriptor blob ─────────────────────
        // Re-use the canonical 2-finger touchscreen blob from narf-hid.
        let report_desc_blob = narf_hid::touchscreen::__touchscreen_descriptor_blob();

        // ── Build a synthetic 2-finger input report ───────────────
        // Report structure (from the blob):
        //   Byte 0: Report ID (1)
        //   Per finger 0:
        //     Byte 1 bits[0..1]: tip_switch (1 bit) + in_range (1 bit)
        //     Byte 1 bits[2..7]: padding (6 bits)
        //     Byte 2: contact_id (8 bits)
        //     Bytes 3-4: X (16-bit LE)
        //     Bytes 5-6: Y (16-bit LE)
        //   Per finger 1:
        //     Byte 7 bits[0..1]: tip_switch + in_range
        //     Byte 7 bits[2..7]: padding
        //     Byte 8: contact_id
        //     Bytes 9-10: X
        //     Bytes 11-12: Y
        //   Byte 13: contact_count (8 bits)
        //
        // Finger 0: tip+in_range=0b11, id=1, X=0x1000, Y=0x2000
        // Finger 1: tip+in_range=0b11, id=2, X=0x5000, Y=0x6000
        // contact_count=2
        let input_report: alloc::vec::Vec<u8> = alloc::vec![
            0x01,        // Report ID
            0b0000_0011, // F0: tip=1, in_range=1, pad=000000
            0x01,        // F0: contact_id = 1
            0x00,
            0x10, // F0: X = 0x1000
            0x00,
            0x20,        // F0: Y = 0x2000
            0b0000_0011, // F1: tip=1, in_range=1, pad=000000
            0x02,        // F1: contact_id = 2
            0x00,
            0x50, // F1: X = 0x5000
            0x00,
            0x60, // F1: Y = 0x6000
            0x02, // contact_count = 2
        ];

        // ── Wire up the MockBus ───────────────────────────────────
        // Reads staged in order:
        //  1. HID descriptor (for read_descriptor)
        //  2. Report descriptor blob (for read_report_descriptor)
        //  3. Input report (for read_input_report in the pump loop)
        let bus = Arc::new(MockBus::new());

        // HID descriptor: set wReportDescLength to actual blob length,
        // wMaxInputLength large enough to hold input_report + 2-byte len prefix.
        let mut hid_desc = make_descriptor_bytes();
        let put16 = |buf: &mut [u8], off: usize, v: u16| {
            buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
        };
        put16(&mut hid_desc, 4, report_desc_blob.len() as u16); // wReportDescLength
        put16(&mut hid_desc, 10, input_report.len() as u16 + 2); // wMaxInputLength
                                                                 // Call sequence in the test:
                                                                 //   read_descriptor() → reads HID descriptor
                                                                 //   reset()           → WRITE cmd, then polls input register (reads 2-byte len)
                                                                 //   set_power(ON)     → WRITE only, no read
                                                                 //   read_report_descriptor() → reads report descriptor bytes
                                                                 //   read_input_report() → reads length-prefixed input report

        // (1) HID descriptor — 30 bytes, no prefix.
        bus.stage_read(hid_desc);

        // (2) RESET sentinel — driver polls input register for len==0 or 2.
        bus.stage_read(alloc::vec![0u8; 2]);

        // (3) Report descriptor — driver reads exactly wReportDescLength bytes directly.
        bus.stage_read(report_desc_blob.to_vec());

        // (4) Input report — length-prefixed; first 2 bytes = total length.
        let total_len = input_report.len() as u16 + 2;
        let max_len = total_len as usize;
        let mut framed = alloc::vec![0u8; max_len];
        framed[0..2].copy_from_slice(&total_len.to_le_bytes());
        framed[2..2 + input_report.len()].copy_from_slice(&input_report);
        bus.stage_read(framed);

        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x10, 0x0001);

        init_global_ring(16);
        __reset_global_ring_for_test();

        run_async(async move {
            if drv.read_descriptor().await.is_err() {
                return TestResult::Fail("HID descriptor read failed");
            }
            if drv.reset().await.is_err() {
                return TestResult::Fail("RESET failed");
            }
            if drv.set_power(POWER_ON).await.is_err() {
                return TestResult::Fail("SET_POWER(ON) failed");
            }
            let rd_blob = match drv.read_report_descriptor().await {
                Ok(b) => b,
                Err(_) => return TestResult::Fail("read_report_descriptor failed"),
            };
            let parsed = match narf_hid::parse(&rd_blob) {
                Ok(p) => p,
                Err(_) => return TestResult::Fail("narf_hid::parse failed"),
            };
            let ts_profile = match narf_hid::touchscreen::detect(&parsed) {
                Some(p) => p,
                None => return TestResult::Fail("touchscreen detect rejected descriptor"),
            };
            // Read the one staged input report.
            let mut buf = alloc::vec![0u8; 64];
            let n = match drv.read_input_report(&mut buf).await {
                Ok(n) => n,
                Err(_) => return TestResult::Fail("read_input_report failed"),
            };
            if n == 0 {
                return TestResult::Fail("input report returned 0 bytes");
            }
            // Decode and pump.
            let payload = &buf[..n];
            let decoded = match narf_hid::touchscreen::decode_input(&ts_profile, payload) {
                Ok(d) => d,
                Err(_) => return TestResult::Fail("decode_input failed"),
            };
            let mut touch_state = crate::i2c_hid_touch::TouchPumpState::new();
            let pushed = crate::i2c_hid_touch::pump_report(&ts_profile, &mut touch_state, &decoded);
            if pushed < 1 {
                return TestResult::Fail("pump_report pushed 0 events");
            }
            // Verify at least one TouchEvent landed with Down state.
            match pop_touch() {
                Some(t) if t.state == TouchState::Down => {}
                Some(_) => return TestResult::Fail("expected Down on first contact"),
                None => return TestResult::Fail("no TouchEvent in ring after pump"),
            }
            TestResult::Pass
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_fake_i2c_hid_touchscreen_end_to_end
    );

    // ── End-to-end FakeI2cHid Elan bind ──────────────────────────
    //
    // Stages an Elan HID descriptor (VID 0x04F3, as
    // `make_descriptor_bytes` builds), the absolute-mode +
    // parameter-query exchange, and one synthetic 0x5D i2c-HID
    // multi-finger report; verifies an Elan device decodes and
    // binds through the HID path (classify → probe → decode →
    // pump) and a TouchEvent lands on the ring.

    fn smoke_fake_i2c_hid_elan_end_to_end() -> TestResult {
        use super::i2c_hid_smokes::{make_descriptor_bytes, run_async, MockBus};
        use crate::hid_elan::{classify_device, ElanReport};
        use crate::i2c_hid::{I2cHidDriver, POWER_ON};
        use alloc::sync::Arc;
        use narf_drivers_i2c::I2cBus;
        use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_touch, TouchState};

        let bus = Arc::new(MockBus::new());
        let mut hid_desc = make_descriptor_bytes();
        let put16 = |buf: &mut [u8], off: usize, v: u16| {
            buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
        };
        put16(&mut hid_desc, 10, 64); // wMaxInputLength
        put16(&mut hid_desc, 14, 32); // wMaxOutputLength
                                      // (1) HID descriptor. (2) RESET sentinel.
        bus.stage_read(hid_desc);
        bus.stage_read(alloc::vec![0u8; 2]);
        // (3)-(5) Parameter GET responses: [len=7][5-byte report].
        // MAX_X = 0x1234, MAX_Y = 0x0500, RES x/y = 0x10/0x10.
        for resp in [
            [0x0D, 0x05, 0x03, 0x34, 0x12],
            [0x0D, 0x05, 0x03, 0x00, 0x05],
            [0x0D, 0x05, 0x03, 0x10, 0x10],
        ] {
            bus.stage_read(alloc::vec![0x07, 0x00]);
            bus.stage_read(resp.to_vec());
        }
        // (6) One 0x5D i2c-HID report: finger 0 present, no click.
        // Finger record mirrors the ElanFinger unit fixture:
        // X = 0x1AB, raw Y = 0x234 → y = 0x500 - 0x234 = 0x2CC.
        let mut report = [0u8; 32];
        report[0] = 0x5D;
        report[1] = 0x08; // finger 0 present (bit 3), btn released
        report[2..7].copy_from_slice(&[0x12, 0xAB, 0x34, 0x45, 0x80]);
        let total_len = report.len() as u16 + 2;
        let mut framed = alloc::vec![0u8; total_len as usize];
        framed[0..2].copy_from_slice(&total_len.to_le_bytes());
        framed[2..].copy_from_slice(&report);
        bus.stage_read(framed);

        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x10, 0x0001);

        init_global_ring(16);
        __reset_global_ring_for_test();

        run_async(async move {
            if drv.read_descriptor().await.is_err() {
                return TestResult::Fail("HID descriptor read failed");
            }
            if drv.reset().await.is_err() {
                return TestResult::Fail("RESET failed");
            }
            if drv.set_power(POWER_ON).await.is_err() {
                return TestResult::Fail("SET_POWER(ON) failed");
            }
            let desc = match drv.descriptor() {
                Some(d) => d,
                None => return TestResult::Fail("no descriptor after read"),
            };
            // Classify: Elan VID under a generic PNP0C50 _HID.
            if classify_device("PNP0C50", desc.w_vendor_id, desc.w_product_id).is_none() {
                return TestResult::Fail("Elan device did not classify");
            }
            if classify_device("PNP0C50", 0x1234, 0x5678).is_some() {
                return TestResult::Fail("non-Elan device classified as Elan");
            }
            let params = match crate::i2c_hid_bind::elan_probe(&drv).await {
                Ok(p) => p,
                Err(_) => return TestResult::Fail("Elan probe failed"),
            };
            if params.max_x != 0x1234 || params.max_y != 0x0500 {
                return TestResult::Fail("Elan params wrong");
            }
            let mut buf = alloc::vec![0u8; 64];
            let n = match drv.read_input_report(&mut buf).await {
                Ok(n) => n,
                Err(_) => return TestResult::Fail("read_input_report failed"),
            };
            if n == 0 {
                return TestResult::Fail("input report returned 0 bytes");
            }
            let payload = &buf[..n];
            let decoded = match ElanReport::decode_i2c(payload, params.max_y) {
                Some(r) => r,
                None => return TestResult::Fail("decode_i2c rejected the 0x5D report"),
            };
            if decoded.fingers.is_empty() || !decoded.fingers[0].present {
                return TestResult::Fail("finger 0 missing after decode");
            }
            if decoded.fingers[0].x != 0x1AB || decoded.fingers[0].y != 0x2CC {
                return TestResult::Fail("finger coordinates wrong after decode");
            }
            let contacts: alloc::vec::Vec<crate::rmi4_core::Rmi4Contact> = decoded
                .fingers
                .iter()
                .map(|f| crate::rmi4_core::Rmi4Contact {
                    present: f.present,
                    x: f.x as i32,
                    y: f.y as i32,
                    pressure: f.pressure as i32,
                })
                .collect();
            let mut state = crate::rmi4_core::Rmi4PumpState::new();
            let pushed = state.pump_contacts(
                None,
                &contacts,
                Some(decoded.btn_left),
                0,
                params.max_x as i32,
                0,
                params.max_y as i32,
            );
            if pushed < 1 {
                return TestResult::Fail("pump pushed 0 events");
            }
            match pop_touch() {
                Some(t) if t.state == TouchState::Down => {}
                Some(_) => return TestResult::Fail("expected Down on first contact"),
                None => return TestResult::Fail("no TouchEvent in ring after pump"),
            }
            TestResult::Pass
        })
    }
    kernel_test_in!("drivers/input/i2c-hid", smoke_fake_i2c_hid_elan_end_to_end);

    // ── End-to-end FakeI2cHid RMI4-over-HID bind ─────────────────
    //
    // Stages a Synaptics HID descriptor (VID 0x06CB), the RMI
    // mode-set + PDT walk + F$01/F$30 queries a real device
    // answers, and F$12 ATTN reports; verifies an RMI4 F$12
    // device decodes and binds through the HID path (classify →
    // session probe → ATTN pump) and TouchEvents land on the ring.
    // Phase 1 is the single-source fast path (F$12 data decoded
    // in place from the ATTN); phase 2 carries both the F$12 and
    // F$30 sources, exercising the register-read fallback and
    // the F$30 clickpad button (observed as a LEFT PointerEvent).

    fn smoke_fake_i2c_hid_rmi4_f12_end_to_end() -> TestResult {
        use super::i2c_hid_smokes::{make_descriptor_bytes, run_async, MockBus};
        use crate::hid_rmi::{classify_device, AttnReport, HidRmiSession};
        use crate::i2c_hid::{I2cHidDriver, POWER_ON};
        use alloc::sync::Arc;
        use narf_drivers_i2c::I2cBus;
        use narf_input::{
            __reset_global_ring_for_test, init_global_ring, pop_pointer, pop_touch, PointerButtons,
            TouchState,
        };

        // Fake PDT, page 0, in scan order (offsets 0xE9 down):
        //   0xE9 F$12 (query 0x00, data 0x03, 1 source)
        //   0xE3 F$01 (query 0x10, 1 source)
        //   0xDD F$30 (query 0x20, data 0x23, 1 source)
        //   0xD7 terminator (function 0x00)
        // Interrupt map: F$12 → bit 0, F$01 → bit 1, F$30 → bit 2.
        fn pdt_entry(query: u8, cmd: u8, ctrl: u8, data: u8, sources: u8, func: u8) -> [u8; 6] {
            [query, cmd, ctrl, data, sources, func]
        }
        // One length-prefixed RMI_READ_DATA_REPORT (0x0B) carrying
        // `body` bytes: [len][0x0B][count][body...].
        fn read_data_report(body: &[u8]) -> alloc::vec::Vec<u8> {
            let mut framed = alloc::vec![0u8; body.len() + 4];
            framed[0..2].copy_from_slice(&((body.len() + 4) as u16).to_le_bytes());
            framed[2] = 0x0B;
            framed[3] = body.len() as u8;
            framed[4..].copy_from_slice(body);
            framed
        }

        let bus = Arc::new(MockBus::new());
        let mut hid_desc = make_descriptor_bytes();
        let put16 = |buf: &mut [u8], off: usize, v: u16| {
            buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
        };
        put16(&mut hid_desc, 10, 64); // wMaxInputLength
        put16(&mut hid_desc, 14, 32); // wMaxOutputLength
        put16(&mut hid_desc, 20, 0x06CB); // wVendorID (Synaptics)
        put16(&mut hid_desc, 22, 0x0000); // wProductID
                                          // (1) HID descriptor. (2) RESET sentinel.
        bus.stage_read(hid_desc);
        bus.stage_read(alloc::vec![0u8; 2]);
        // (3)-(6) Probe reads, in the session's order: three PDT
        // entries, the terminator, the F$01 query, the F$30 query.
        bus.stage_read(read_data_report(&pdt_entry(
            0x00, 0x01, 0x02, 0x03, 0x01, 0x12,
        )));
        bus.stage_read(read_data_report(&pdt_entry(
            0x10, 0x11, 0x12, 0x13, 0x01, 0x01,
        )));
        bus.stage_read(read_data_report(&pdt_entry(
            0x20, 0x21, 0x22, 0x23, 0x01, 0x30,
        )));
        bus.stage_read(read_data_report(&[0u8; 6]));
        bus.stage_read(read_data_report(&[
            0x01, 0x00, 0x02, 0x01, 0x20, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01,
        ]));
        bus.stage_read(read_data_report(&[0x48, 0x08]));
        // (7)-(8) Phase-2 fallback reads, consumed by the
        // multi-source ATTN below — in the order the pump issues
        // them (F$30 button read first, then the F$12 Data 1
        // read): the F$30 data byte (0xFE: GPIO 0 low = clickpad
        // pressed), then F$12 Data 1 (40 bytes = 5 objects,
        // first a finger at 0x1000/0x2000).
        bus.stage_read(read_data_report(&[0xFE]));
        let mut f12_data = [0u8; 40];
        f12_data[0] = 0x01; // FINGER
        f12_data[1..3].copy_from_slice(&0x1000u16.to_le_bytes());
        f12_data[3..5].copy_from_slice(&0x2000u16.to_le_bytes());
        f12_data[5] = 0x80;
        bus.stage_read(read_data_report(&f12_data));

        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut drv = I2cHidDriver::new(bus_dyn, 0x10, 0x0001);

        init_global_ring(16);
        __reset_global_ring_for_test();

        run_async(async move {
            if drv.read_descriptor().await.is_err() {
                return TestResult::Fail("HID descriptor read failed");
            }
            if drv.reset().await.is_err() {
                return TestResult::Fail("RESET failed");
            }
            if drv.set_power(POWER_ON).await.is_err() {
                return TestResult::Fail("SET_POWER(ON) failed");
            }
            let desc = match drv.descriptor() {
                Some(d) => d,
                None => return TestResult::Fail("no descriptor after read"),
            };
            let quirks = match classify_device("SYNA8002", desc.w_vendor_id, desc.w_product_id) {
                Some(q) => q,
                None => return TestResult::Fail("Synaptics device did not classify as RMI4"),
            };
            if classify_device("PNP0C50", 0x1234, 0x5678).is_some() {
                return TestResult::Fail("non-Synaptics device classified as RMI4");
            }
            let mut session = HidRmiSession::new(&drv, 32, quirks);
            let probe = match session.probe().await {
                Ok(p) => p,
                Err(_) => return TestResult::Fail("RMI4 probe failed"),
            };
            if !probe.product.is_synaptics() {
                return TestResult::Fail("probe product is not Synaptics");
            }
            if probe.f12.is_none() || probe.f30.is_none() {
                return TestResult::Fail("probe missed F$12 or F$30");
            }
            if probe.source_mask_for(0x12) != 0x01 || probe.source_mask_for(0x30) != 0x04 {
                return TestResult::Fail("interrupt map wrong");
            }
            // The probe issued one read-addr output report per
            // register read (4 PDT + F$01 query + F$30 query)
            // plus one set-page output report.
            let writes = bus.writes();
            let is_out =
                |w: &alloc::vec::Vec<u8>, id: u8| w.len() >= 9 && (w[2] >> 4) == 0x02 && w[8] == id;
            if writes.iter().filter(|w| is_out(w, 0x0A)).count() != 6 {
                return TestResult::Fail("probe must issue 6 read-addr output reports");
            }
            if writes.iter().filter(|w| is_out(w, 0x09)).count() != 1 {
                return TestResult::Fail("probe must issue 1 set-page output report");
            }
            let caps =
                crate::i2c_hid_touch::build_rmi_caps(&probe, &narf_input::evdev::DeviceCaps::new());
            let (evdev_id, node) = narf_input::evdev::ROUTER.register_device(caps);
            let mut state = crate::rmi4_core::Rmi4PumpState::new();
            // Phase 1: single-source ATTN (F$12 only) — fast path.
            let mut attn1 = [0u8; 10];
            attn1[0] = 0x0C;
            attn1[1] = 0x01;
            attn1[2] = 0x01; // FINGER
            attn1[3..5].copy_from_slice(&0x1000u16.to_le_bytes());
            attn1[5..7].copy_from_slice(&0x2000u16.to_le_bytes());
            attn1[7] = 0x80;
            let attn1 = match AttnReport::decode(&attn1) {
                Some(a) => a,
                None => return TestResult::Fail("ATTN decode failed"),
            };
            crate::i2c_hid_bind::pump_rmi_attn(&mut session, &probe, &attn1, &mut state, &node)
                .await;
            match pop_touch() {
                Some(t) if t.state == TouchState::Down && t.x == 0x1000 && t.y == 0x2000 => {}
                Some(_) => return TestResult::Fail("phase 1: expected Down at 0x1000/0x2000"),
                None => return TestResult::Fail("phase 1: no TouchEvent in ring"),
            }
            // Phase 2: multi-source ATTN (F$12 + F$30) — the
            // register-read fallback + clickpad button.
            let mut attn2 = [0u8; 10];
            attn2[0] = 0x0C;
            attn2[1] = 0x05; // F$12 bit 0 + F$30 bit 2
            attn2[2] = 0x01;
            attn2[3..5].copy_from_slice(&0x1000u16.to_le_bytes());
            attn2[5..7].copy_from_slice(&0x2000u16.to_le_bytes());
            attn2[7] = 0x80;
            let attn2 = match AttnReport::decode(&attn2) {
                Some(a) => a,
                None => return TestResult::Fail("ATTN decode failed (phase 2)"),
            };
            crate::i2c_hid_bind::pump_rmi_attn(&mut session, &probe, &attn2, &mut state, &node)
                .await;
            match pop_touch() {
                Some(t) if t.state == TouchState::Move => {}
                Some(_) => return TestResult::Fail("phase 2: expected Move on held contact"),
                None => return TestResult::Fail("phase 2: no TouchEvent in ring"),
            }
            match pop_pointer() {
                Some(p) if p.buttons == PointerButtons::LEFT => {}
                Some(_) => return TestResult::Fail("phase 2: expected LEFT button"),
                None => return TestResult::Fail("phase 2: no PointerEvent in ring"),
            }
            narf_input::evdev::ROUTER.unregister_device(evdev_id);
            TestResult::Pass
        })
    }
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_fake_i2c_hid_rmi4_f12_end_to_end
    );
}

// ─── RMI4 core protocol smoke tests ────────────────────────────────
//
// Cover the function decoders our hid-rmi / future smbus-rmi
// drivers chain through. Each smoke uses synthetic byte streams
// modelled on the public Synaptics RMI4 application notes; no
// real silicon required.

fn smoke_rmi4_pdt_three_function_walk() -> TestResult {
    use crate::rmi4_core::{
        find_function, walk_pdt_page, Rmi4Transport, TransportError, F01_DEVICE_CONTROL,
        F11_2D_TOUCHPAD, F30_GPIO_LED, PDT_ENTRY_SIZE, PDT_LAST_SLOT_OFFSET,
    };

    // Fake transport: a 256-byte page with three PDT entries laid
    // out at offsets PDT_LAST_SLOT_OFFSET, -6, -12 respectively
    // (F01, F11, F30) and a 0x00 terminator at -18.
    struct FakePage {
        bytes: [u8; 256],
    }
    impl Rmi4Transport for FakePage {
        fn read_block(&mut self, addr: u16, dst: &mut [u8]) -> Result<(), TransportError> {
            let lo = (addr & 0xFF) as usize;
            if lo + dst.len() > self.bytes.len() {
                return Err(TransportError::Short);
            }
            dst.copy_from_slice(&self.bytes[lo..lo + dst.len()]);
            Ok(())
        }
        fn write_block(&mut self, _addr: u16, _src: &[u8]) -> Result<(), TransportError> {
            Ok(())
        }
    }

    let mut page = FakePage { bytes: [0u8; 256] };
    let last = PDT_LAST_SLOT_OFFSET as usize;
    // F01 entry at PDT_LAST_SLOT_OFFSET.
    page.bytes[last] = 0x10; // query base
    page.bytes[last + 1] = 0x20; // command base
    page.bytes[last + 2] = 0x30; // control base
    page.bytes[last + 3] = 0x40; // data base
    page.bytes[last + 4] = 0x01; // 1 IRQ source, version 0
    page.bytes[last + 5] = F01_DEVICE_CONTROL;
    // F11 entry at PDT_LAST_SLOT_OFFSET - 6.
    let s2 = last - PDT_ENTRY_SIZE;
    page.bytes[s2] = 0x50;
    page.bytes[s2 + 1] = 0x60;
    page.bytes[s2 + 2] = 0x70;
    page.bytes[s2 + 3] = 0x80;
    page.bytes[s2 + 4] = 0x02;
    page.bytes[s2 + 5] = F11_2D_TOUCHPAD;
    // F30 entry at PDT_LAST_SLOT_OFFSET - 12.
    let s3 = last - 2 * PDT_ENTRY_SIZE;
    page.bytes[s3] = 0x90;
    page.bytes[s3 + 1] = 0xA0;
    page.bytes[s3 + 2] = 0xB0;
    page.bytes[s3 + 3] = 0xC0;
    page.bytes[s3 + 4] = 0x01;
    page.bytes[s3 + 5] = F30_GPIO_LED;
    // Terminator (function_number = 0) at the next slot.
    page.bytes[s3 - PDT_ENTRY_SIZE + 5] = 0x00;

    let table = match walk_pdt_page(&mut page, 0) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("walk_pdt_page returned Err"),
    };
    if table.len() != 3 {
        return TestResult::Fail("expected exactly three PDT entries");
    }
    let f01 = match find_function(&table, F01_DEVICE_CONTROL) {
        Some(e) => e,
        None => return TestResult::Fail("F01 missing from walk"),
    };
    if f01.query_base != 0x10 || f01.data_base != 0x40 {
        return TestResult::Fail("F01 base register decode wrong");
    }
    if find_function(&table, F11_2D_TOUCHPAD).is_none() {
        return TestResult::Fail("F11 missing from walk");
    }
    if find_function(&table, F30_GPIO_LED).is_none() {
        return TestResult::Fail("F30 missing from walk");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input/rmi4", smoke_rmi4_pdt_three_function_walk);

fn smoke_rmi4_f01_product_info_decode() -> TestResult {
    use crate::rmi4_core::{F01ProductInfo, RMI_MANUFACTURER_SYNAPTICS};
    // 11 query bytes: manuf=1, props=0x10, firmware=0x1234 (LE), date 24/05/29,
    // tester=0x4242, serial=0xCAFE.
    let buf = [
        RMI_MANUFACTURER_SYNAPTICS,
        0x10,
        0x34,
        0x12,
        24,
        5,
        29,
        0x42,
        0x42,
        0xCA,
        0xFE,
    ];
    let p = match F01ProductInfo::decode(&buf) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("decode short"),
    };
    if !p.is_synaptics() {
        return TestResult::Fail("expected Synaptics manuf");
    }
    if p.firmware_id != 0x1234 {
        return TestResult::Fail("firmware id");
    }
    if p.year != 24 || p.month != 5 || p.day != 29 {
        return TestResult::Fail("date");
    }
    if p.tester_id != 0x4242 || p.serial != 0xCAFE {
        return TestResult::Fail("tester/serial");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input/rmi4", smoke_rmi4_f01_product_info_decode);

fn smoke_rmi4_f11_finger_decode() -> TestResult {
    use narf_input::rmi4::{Finger, TouchpadReport};
    // One finger active. state-byte 0b01 → state=01 (present accurate)
    // for finger 0. Finger record: x_hi=0x12, y_hi=0x34, packed_lo=0x56
    // (x_lo=5, y_lo=6), w_x=7, w_y=8 → x = (0x12<<4)|5 = 0x125,
    // y = (0x34<<4)|6 = 0x346.
    let mut buf = [0u8; 1 + Finger::REPORT_SIZE];
    buf[0] = 0b01;
    buf[1] = 0x12;
    buf[2] = 0x34;
    buf[3] = 0x56;
    buf[4] = 7;
    buf[5] = 8;
    let rep = match TouchpadReport::parse(&buf, 1) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("parse"),
    };
    let f = rep.fingers[0];
    if !f.present {
        return TestResult::Fail("expected present");
    }
    if f.x != 0x125 || f.y != 0x346 {
        return TestResult::Fail("position decode");
    }
    if f.w_x != 7 || f.w_y != 8 {
        return TestResult::Fail("width decode");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input/rmi4", smoke_rmi4_f11_finger_decode);

fn smoke_rmi4_f12_object_decode() -> TestResult {
    use crate::rmi4_core::{decode_f12_data1, f12_object, F12_OBJECT_SIZE};
    // Two objects: one FINGER, one PALM. Each 8 bytes.
    let mut buf = [0u8; 2 * F12_OBJECT_SIZE];
    // Finger at x=0x0123, y=0x0456, z=0x80, wx=4, wy=5
    buf[0] = f12_object::FINGER;
    buf[1] = 0x23;
    buf[2] = 0x01;
    buf[3] = 0x56;
    buf[4] = 0x04;
    buf[5] = 0x80;
    buf[6] = 4;
    buf[7] = 5;
    // Palm at slot 1
    buf[8] = f12_object::PALM;
    buf[9] = 0xAA;
    buf[10] = 0x0A;
    buf[11] = 0xBB;
    buf[12] = 0x0B;
    buf[13] = 0xFF;
    buf[14] = 30;
    buf[15] = 30;

    let objs = match decode_f12_data1(&buf, 2) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("decode_f12_data1"),
    };
    if objs.len() != 2 {
        return TestResult::Fail("expected 2 objects");
    }
    if !objs[0].is_touching_finger() {
        return TestResult::Fail("first object must be touching finger");
    }
    if objs[0].x != 0x0123 || objs[0].y != 0x0456 {
        return TestResult::Fail("finger pos wrong");
    }
    if objs[1].object_type != f12_object::PALM {
        return TestResult::Fail("second object must be palm");
    }
    if objs[1].is_touching_finger() {
        return TestResult::Fail("palm must not be a touching finger");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input/rmi4", smoke_rmi4_f12_object_decode);

fn smoke_rmi4_f30_button_bitmap_to_btn_codes() -> TestResult {
    use crate::rmi4_core::{classic_clickpad_buttons, decode_f30_buttons};
    // 3 GPIOs, lines 0 and 2 low (left + middle pressed). Active-low
    // polarity → bitmap = 0b101.
    let data = [0b1111_1010];
    let bm = match decode_f30_buttons(&data, 3) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("decode_f30_buttons"),
    };
    if bm != 0b101 {
        return TestResult::Fail("bitmap polarity inversion wrong");
    }
    let (l, r, m) = classic_clickpad_buttons(bm);
    if !l || r || !m {
        return TestResult::Fail("classic mapping wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/rmi4",
    smoke_rmi4_f30_button_bitmap_to_btn_codes
);

// ── HID multi-touch class driver smokes ──────────────────────────
//
// Lives in drivers/input/{hid_multitouch.rs,hid_mt_features.rs}.
// Covers report-descriptor shape match, slot-B emission, PTP
// feature mode encode + max-contact decode, button state, 4
// per-device classes (Default/Win8/Apple/Nsmu), and the
// touchscreen variant. References:
//   - linux/drivers/hid/hid-multitouch.c
//   - HID Usage Tables 1.4 §16
//   - Microsoft PTP Implementation Guide

fn smoke_mt_descriptor_matches_touchpad_collection() -> TestResult {
    use crate::hid_multitouch::MtShape;
    use narf_hid::descriptor::parse;
    let blob = narf_hid::ptp::__ptp_descriptor_blob();
    let parsed = match parse(blob) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("PTP blob fails to parse"),
    };
    match MtShape::detect(&parsed) {
        Some(MtShape::TouchPad) => TestResult::Pass,
        Some(other) => {
            let _ = other;
            TestResult::Fail("expected TouchPad shape on PTP blob")
        }
        None => TestResult::Fail("PTP blob not matched as MT"),
    }
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_descriptor_matches_touchpad_collection
);

fn smoke_mt_descriptor_matches_touchscreen_collection() -> TestResult {
    use crate::hid_multitouch::{MtClass, MtShape, __attach_synth_screen_for_test};
    let dev = __attach_synth_screen_for_test(MtClass::Default, 0);
    if dev.shape != MtShape::TouchScreen {
        return TestResult::Fail("expected TouchScreen shape on synth descriptor");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_descriptor_matches_touchscreen_collection
);

fn smoke_mt_contact_id_and_tip_switch_fields_resolved() -> TestResult {
    // Reuses the in-tree PTP profile probe — confirms that on the
    // canonical PTP blob, every per-contact ContactFields entry has
    // a non-None contact_id field AND that tip_switch is populated.
    use narf_hid::descriptor::parse;
    use narf_hid::ptp;
    let blob = ptp::__ptp_descriptor_blob();
    let parsed = match parse(blob) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("PTP blob parse"),
    };
    let profile = match ptp::detect(&parsed) {
        Some(p) => p,
        None => return TestResult::Fail("PTP blob not matched"),
    };
    for (i, c) in profile.contacts.iter().enumerate() {
        if c.contact_id.is_none() {
            let _ = i;
            return TestResult::Fail("contact missing contact_id field");
        }
        // tip_switch is non-Option in ContactFields — its presence
        // is implicit. Sanity-check the report_size is at least 1
        // bit per HID spec.
        if c.tip_switch.report_size == 0 {
            return TestResult::Fail("tip_switch field has zero report_size");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_contact_id_and_tip_switch_fields_resolved
);

fn smoke_mt_ptp_mode_feature_encode_round_trip() -> TestResult {
    use crate::hid_mt_features::{encode_mode_feature, mode};
    use narf_hid::descriptor::parse;
    use narf_hid::ptp;
    let blob = ptp::__ptp_descriptor_blob();
    let parsed = match parse(blob) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("parse"),
    };
    let p = match ptp::detect(&parsed) {
        Some(p) => p,
        None => return TestResult::Fail("PTP detect"),
    };
    let bytes = match encode_mode_feature(&p, mode::TOUCHPAD) {
        Some(b) => b,
        None => return TestResult::Fail("encode_mode_feature returned None"),
    };
    // First byte = report-id (Configuration TLC = 3 in the canonical
    // blob). Body[0] should carry the mode = 0x03.
    if bytes.is_empty() {
        return TestResult::Fail("empty mode feature");
    }
    if bytes[0] != 3 {
        return TestResult::Fail("mode report id wrong");
    }
    if bytes.len() < 2 || bytes[1] != mode::TOUCHPAD {
        return TestResult::Fail("mode byte not placed at body[0]");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_ptp_mode_feature_encode_round_trip
);

fn smoke_mt_max_contact_count_decode_defaults() -> TestResult {
    use crate::hid_mt_features::{decode_max_contact_count, find_contact_count_max_feature};
    use narf_hid::descriptor::parse;
    use narf_hid::ptp;
    let blob = ptp::__ptp_descriptor_blob();
    let parsed = match parse(blob) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("parse"),
    };
    // The canonical blob doesn't expose a Contact Count Max field;
    // find_contact_count_max_feature should return None.
    if find_contact_count_max_feature(&parsed).is_some() {
        // Blob updated — recompute against a real field.
        let f = find_contact_count_max_feature(&parsed).unwrap().clone();
        let body = alloc::vec![0u8; 8];
        let v = decode_max_contact_count(&f, &body);
        if v == 0 {
            return TestResult::Fail("decoded zero, expected fallback ≥1");
        }
    }
    // Resolve path: with no class override and no Feature field,
    // we should fall back to profile.contacts_max (2) per the
    // canonical blob.
    let p = match ptp::detect(&parsed) {
        Some(p) => p,
        None => return TestResult::Fail("PTP detect"),
    };
    let n = crate::hid_mt_features::resolve_max_contacts(&p, &parsed, None);
    if n != 2 {
        return TestResult::Fail("expected resolve_max_contacts == 2 for canonical blob");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_max_contact_count_decode_defaults
);

fn smoke_mt_five_finger_contacts_emit_five_slot_events() -> TestResult {
    use crate::hid_multitouch::{
        MtClass, __attach_synth_pad_for_test, __build_ptp_decoded_for_test,
        __reset_registry_for_test,
    };
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_touch};
    init_global_ring(64);
    __reset_global_ring_for_test();
    __reset_registry_for_test();
    let dev = __attach_synth_pad_for_test(MtClass::Win8, 5);
    // Five contacts, all tip=true.
    let decoded = __build_ptp_decoded_for_test(
        &[
            (10, true, 100, 200),
            (11, true, 110, 210),
            (12, true, 120, 220),
            (13, true, 130, 230),
            (14, true, 140, 240),
        ],
        false,
    );
    let emitted = dev.pump_ptp(&decoded);
    if emitted < 5 {
        return TestResult::Fail("expected ≥5 events");
    }
    let mut seen_slots = 0u32;
    for _ in 0..5 {
        let t = match pop_touch() {
            Some(t) => t,
            None => return TestResult::Fail("expected 5 Touch events"),
        };
        if t.tracking_id.is_none() {
            return TestResult::Fail("tracking_id should be Some on Down");
        }
        seen_slots |= 1 << t.slot;
    }
    if seen_slots.count_ones() != 5 {
        return TestResult::Fail("expected 5 distinct slots");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_five_finger_contacts_emit_five_slot_events
);

fn smoke_mt_contact_release_emits_tracking_id_none() -> TestResult {
    use crate::hid_multitouch::{
        MtClass, __attach_synth_pad_for_test, __build_ptp_decoded_for_test,
        __reset_registry_for_test,
    };
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_touch};
    init_global_ring(16);
    __reset_global_ring_for_test();
    __reset_registry_for_test();
    let dev = __attach_synth_pad_for_test(MtClass::Win8, 5);
    // Frame 1: contact down.
    let down = __build_ptp_decoded_for_test(&[(7, true, 100, 200)], false);
    let _ = dev.pump_ptp(&down);
    // Drain Down event.
    let t_down = match pop_touch() {
        Some(t) => t,
        None => return TestResult::Fail("expected Down event"),
    };
    if t_down.tracking_id != Some(7) {
        return TestResult::Fail("Down tracking_id mismatch");
    }
    // Frame 2: same contact_id, tip=false → release.
    let up = __build_ptp_decoded_for_test(&[(7, false, 100, 200)], false);
    let _ = dev.pump_ptp(&up);
    let t_up = match pop_touch() {
        Some(t) => t,
        None => return TestResult::Fail("expected Up event"),
    };
    if t_up.tracking_id.is_some() {
        return TestResult::Fail("Up event tracking_id should be None");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_contact_release_emits_tracking_id_none
);

fn smoke_mt_button1_press_emits_pointer_left() -> TestResult {
    use crate::hid_multitouch::{
        MtClass, __attach_synth_pad_for_test, __build_ptp_decoded_for_test,
        __reset_registry_for_test,
    };
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_pointer, PointerButtons};
    init_global_ring(16);
    __reset_global_ring_for_test();
    __reset_registry_for_test();
    let dev = __attach_synth_pad_for_test(MtClass::Default, 5);
    // Frame 1: button up.
    let f1 = __build_ptp_decoded_for_test(&[(1, false, 0, 0)], false);
    let _ = dev.pump_ptp(&f1);
    // Drain any noise.
    let _ = pop_pointer();
    // Frame 2: button1 press.
    let f2 = __build_ptp_decoded_for_test(&[(1, false, 0, 0)], true);
    let _ = dev.pump_ptp(&f2);
    let p = match pop_pointer() {
        Some(p) => p,
        None => return TestResult::Fail("expected PointerEvent on button1 press"),
    };
    if !p.buttons.contains(PointerButtons::LEFT) {
        return TestResult::Fail("LEFT button bit missing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_button1_press_emits_pointer_left
);

fn smoke_mt_apple_class_lookup_carries_apple_quirks() -> TestResult {
    use crate::hid_multitouch::{lookup_class, MtClass, MtQuirks};
    let e = lookup_class(MtClass::Apple);
    if !e.quirks.contains(MtQuirks::APPLE_TOUCHBAR) {
        return TestResult::Fail("Apple class missing APPLE_TOUCHBAR");
    }
    if !e.quirks.contains(MtQuirks::SLOT_IS_CONTACTID_MINUS_ONE) {
        return TestResult::Fail("Apple class missing SLOT_IS_CONTACTID_MINUS_ONE");
    }
    if e.max_contacts != 11 {
        return TestResult::Fail("Apple max_contacts should be 11");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_apple_class_lookup_carries_apple_quirks
);

fn smoke_mt_win8_class_defaults_to_five_contacts() -> TestResult {
    use crate::hid_mt_features::DEFAULT_MAX_CONTACTS;
    use crate::hid_multitouch::{MtClass, __attach_synth_pad_for_test};
    let dev = __attach_synth_pad_for_test(MtClass::Win8, 0);
    if dev.max_contacts != DEFAULT_MAX_CONTACTS {
        return TestResult::Fail("Win8 attach should default max_contacts to 5");
    }
    Ok::<(), ()>(()).err().ok_or(()).err();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_win8_class_defaults_to_five_contacts
);

fn smoke_mt_touchscreen_emits_abs_x_y_without_slot_first() -> TestResult {
    use crate::hid_multitouch::{
        MtClass, __attach_synth_screen_for_test, __build_screen_decoded_for_test,
        __reset_registry_for_test,
    };
    use narf_input::{__reset_global_ring_for_test, abs, init_global_ring, pop_absolute};
    init_global_ring(16);
    __reset_global_ring_for_test();
    __reset_registry_for_test();
    let dev = __attach_synth_screen_for_test(MtClass::Default, 0);
    // One contact, tip down.
    let decoded = __build_screen_decoded_for_test(&[(1, true, 5000, 8000)]);
    let _ = dev.pump_screen(&decoded);
    // First two events should be ABS_X then ABS_Y (touchscreens
    // emit absolute for the first in-range contact).
    let x = match pop_absolute() {
        Some(a) => a,
        None => return TestResult::Fail("expected ABS_X event"),
    };
    if x.axis != abs::ABS_X || x.value != 5000 {
        return TestResult::Fail("ABS_X shape wrong");
    }
    let y = match pop_absolute() {
        Some(a) => a,
        None => return TestResult::Fail("expected ABS_Y event"),
    };
    if y.axis != abs::ABS_Y || y.value != 8000 {
        return TestResult::Fail("ABS_Y shape wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_touchscreen_emits_abs_x_y_without_slot_first
);

fn smoke_mt_frame_emits_touch_events_per_slot() -> TestResult {
    // Functional analog of "Frame SYN_REPORT termination" — verify
    // that across two consecutive frames, slot reuse for the same
    // contact_id stays stable (no spurious release/re-acquire) and
    // that a fresh contact_id allocates a new slot.
    use crate::hid_multitouch::{
        MtClass, __attach_synth_pad_for_test, __build_ptp_decoded_for_test,
        __reset_registry_for_test,
    };
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_touch, TouchState};
    init_global_ring(16);
    __reset_global_ring_for_test();
    __reset_registry_for_test();
    let dev = __attach_synth_pad_for_test(MtClass::Win8, 5);
    // Frame 1: contact 42 down.
    let f1 = __build_ptp_decoded_for_test(&[(42, true, 100, 200)], false);
    let _ = dev.pump_ptp(&f1);
    let t1 = match pop_touch() {
        Some(t) => t,
        None => return TestResult::Fail("expected Down event frame 1"),
    };
    if t1.state != TouchState::Down {
        return TestResult::Fail("frame 1 should be Down");
    }
    let first_slot = t1.slot;
    // Frame 2: same contact 42 stays down, new contact 43 added.
    let f2 = __build_ptp_decoded_for_test(&[(42, true, 110, 210), (43, true, 300, 400)], false);
    let _ = dev.pump_ptp(&f2);
    // Drain — expect Move for slot 0, Down for slot 1.
    let mut got_move_42 = false;
    let mut got_down_43 = false;
    for _ in 0..2 {
        let t = match pop_touch() {
            Some(t) => t,
            None => return TestResult::Fail("expected two events frame 2"),
        };
        if t.slot == first_slot && t.state == TouchState::Move && t.tracking_id == Some(42) {
            got_move_42 = true;
        } else if t.slot != first_slot && t.state == TouchState::Down && t.tracking_id == Some(43) {
            got_down_43 = true;
        }
    }
    if !got_move_42 {
        return TestResult::Fail("contact 42 should emit Move on frame 2");
    }
    if !got_down_43 {
        return TestResult::Fail("contact 43 should emit Down on frame 2");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_frame_emits_touch_events_per_slot
);

fn smoke_mt_nsmu_quirk_synthesises_release_for_unseen_contact() -> TestResult {
    use crate::hid_multitouch::{
        __attach_synth_pad_for_test, __build_ptp_decoded_for_test, __reset_registry_for_test,
        lookup_class, MtClass, MtQuirks,
    };
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_touch, TouchState};
    init_global_ring(16);
    __reset_global_ring_for_test();
    __reset_registry_for_test();
    // Confirm Nsmu carries NOT_SEEN_MEANS_UP.
    let entry = lookup_class(MtClass::Nsmu);
    if !entry.quirks.contains(MtQuirks::NOT_SEEN_MEANS_UP) {
        return TestResult::Fail("Nsmu class missing NOT_SEEN_MEANS_UP");
    }
    let dev = __attach_synth_pad_for_test(MtClass::Nsmu, 5);
    // Frame 1: contact 99 down.
    let f1 = __build_ptp_decoded_for_test(&[(99, true, 50, 60)], false);
    let _ = dev.pump_ptp(&f1);
    // Drain Down.
    let _ = pop_touch();
    // Frame 2: empty report (contact_count = 0) — Nsmu should emit
    // an Up for the stale contact.
    let f2 = __build_ptp_decoded_for_test(&[], false);
    let _ = dev.pump_ptp(&f2);
    let t = match pop_touch() {
        Some(t) => t,
        None => return TestResult::Fail("expected synthesised Up"),
    };
    if t.state != TouchState::Up {
        return TestResult::Fail("expected TouchState::Up");
    }
    if t.tracking_id.is_some() {
        return TestResult::Fail("Up tracking_id should be None");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_nsmu_quirk_synthesises_release_for_unseen_contact
);

fn smoke_mt_apple_synth_descriptor_carries_scan_time() -> TestResult {
    // Per the task spec: "Apple Magic Trackpad 2 quirk: scan time
    // field present". The PTP canonical blob includes a Scan Time
    // field; verify the Apple class attach exposes it via the PTP
    // profile (the profile holds the parsed Field).
    use crate::hid_multitouch::{MtClass, MtProfile, __attach_synth_pad_for_test};
    let dev = __attach_synth_pad_for_test(MtClass::Apple, 0);
    match &dev.profile {
        MtProfile::Pad(p) => {
            if p.scan_time.is_none() {
                return TestResult::Fail("Apple PTP profile missing scan_time field");
            }
        }
        MtProfile::Screen(_) => return TestResult::Fail("expected Pad profile"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-multitouch",
    smoke_mt_apple_synth_descriptor_carries_scan_time
);

// ─── hid-rmi (RMI4 over HID transport) smoke tests ─────────────────

fn smoke_hid_rmi_set_rmi_mode_feature_encode() -> TestResult {
    use crate::hid_rmi::{encode_set_rmi_mode, RMI_MODE_ATTN_REPORTS, RMI_SET_RMI_MODE_REPORT_ID};
    let buf = encode_set_rmi_mode(RMI_MODE_ATTN_REPORTS);
    if buf.len() != 2 {
        return TestResult::Fail("Set_RMI_Mode body must be exactly 2 bytes");
    }
    if buf[0] != RMI_SET_RMI_MODE_REPORT_ID {
        return TestResult::Fail("leading byte must be Set_RMI_Mode report id (0x0F)");
    }
    if buf[1] != RMI_MODE_ATTN_REPORTS {
        return TestResult::Fail("mode byte not propagated");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-rmi",
    smoke_hid_rmi_set_rmi_mode_feature_encode
);

fn smoke_hid_rmi_transport_write_register_via_output_report() -> TestResult {
    use crate::hid_rmi::{encode_write_block, RMI_WRITE_REPORT_ID};
    // Write 3 bytes [0xDE, 0xAD, 0xBE] to RMI register 0x0142
    // (page 1, offset 0x42). 19-byte output report (typical
    // Synaptics touchpad reports 1 byte report id + 18 byte body).
    let payload = [0xDEu8, 0xAD, 0xBE];
    let buf = encode_write_block(0x0142, &payload, 19);
    if buf.len() != 19 {
        return TestResult::Fail("output report not padded to declared size");
    }
    if buf[0] != RMI_WRITE_REPORT_ID {
        return TestResult::Fail("leading byte not WRITE_REPORT_ID (0x09)");
    }
    if buf[1] != 3 {
        return TestResult::Fail("write-count field wrong");
    }
    if buf[2] != 0x42 || buf[3] != 0x01 {
        return TestResult::Fail("addr LE encoding wrong");
    }
    if buf[4] != 0xDE || buf[5] != 0xAD || buf[6] != 0xBE {
        return TestResult::Fail("payload bytes not copied at offset 4");
    }
    // Trailing bytes must be zero-padded.
    for &b in &buf[7..] {
        if b != 0 {
            return TestResult::Fail("trailing pad bytes must be 0");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-rmi",
    smoke_hid_rmi_transport_write_register_via_output_report
);

fn smoke_hid_rmi_clickpad_quirk_path() -> TestResult {
    use crate::hid_rmi::{clickpad_btn_left, is_clickpad, DeviceQuirks};
    // Synaptics ThinkPad-class touchpad: no HAS_PHYS_BUTTONS,
    // 0 mech_mouse_btns → clickpad.
    if !is_clickpad(false, 0) {
        return TestResult::Fail("default Synaptics touchpad should classify as clickpad");
    }
    // Razer Blade 14: HAS_PHYS_BUTTONS → NOT a clickpad.
    let razer_quirks = DeviceQuirks::HAS_PHYS_BUTTONS;
    if is_clickpad(razer_quirks.contains(DeviceQuirks::HAS_PHYS_BUTTONS), 2) {
        return TestResult::Fail("phys-buttons quirk + 2 mech_mouse_btns must NOT be clickpad");
    }
    // F$30 bitmap 0b001 → BTN_LEFT pressed on clickpad.
    if !clickpad_btn_left(0b001) {
        return TestResult::Fail("clickpad_btn_left should fire on bit 0");
    }
    if clickpad_btn_left(0b010) {
        return TestResult::Fail("clickpad_btn_left must ignore bit 1");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input/hid-rmi", smoke_hid_rmi_clickpad_quirk_path);

fn smoke_hid_rmi_device_id_table_covers_canonical_vids() -> TestResult {
    use crate::hid_rmi::{
        match_device, DeviceQuirks, RMI_DEVICE_TABLE, USB_DEVICE_ID_RAZER_BLADE_14,
        USB_DEVICE_ID_SYNAPTICS_ACER_SWITCH5, USB_VENDOR_ID_LENOVO, USB_VENDOR_ID_PRIMAX,
        USB_VENDOR_ID_RAZER, USB_VENDOR_ID_SYNAPTICS,
    };
    if RMI_DEVICE_TABLE.len() < 4 {
        return TestResult::Fail("expected ≥4 entries in RMI_DEVICE_TABLE");
    }
    // Razer Blade 14 must carry HAS_PHYS_BUTTONS.
    match match_device(USB_VENDOR_ID_RAZER, USB_DEVICE_ID_RAZER_BLADE_14) {
        Some(m) => {
            if !m.quirks.contains(DeviceQuirks::HAS_PHYS_BUTTONS) {
                return TestResult::Fail("Razer Blade 14 missing HAS_PHYS_BUTTONS");
            }
        }
        None => return TestResult::Fail("Razer Blade 14 not in table"),
    }
    // Synaptics Acer Switch 5 must carry OUTPUT_SET_REPORT.
    match match_device(
        USB_VENDOR_ID_SYNAPTICS,
        USB_DEVICE_ID_SYNAPTICS_ACER_SWITCH5,
    ) {
        Some(m) => {
            if !m.quirks.contains(DeviceQuirks::OUTPUT_SET_REPORT) {
                return TestResult::Fail("Synaptics Acer Switch 5 missing OUTPUT_SET_REPORT");
            }
        }
        None => return TestResult::Fail("Synaptics Acer Switch 5 not in table"),
    }
    // Lenovo X1 Cover present without quirks.
    if match_device(USB_VENDOR_ID_LENOVO, 0x6085).is_none() {
        return TestResult::Fail("Lenovo X1 Cover not in table");
    }
    // Primax Rezel present.
    if match_device(USB_VENDOR_ID_PRIMAX, 0x4E72).is_none() {
        return TestResult::Fail("Primax Rezel not in table");
    }
    // Unmatched VID returns None.
    if match_device(0xFFFF, 0xFFFF).is_some() {
        return TestResult::Fail("unknown VID/PID should not match");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-rmi",
    smoke_hid_rmi_device_id_table_covers_canonical_vids
);

fn smoke_hid_rmi_classify_synaptics_prefix_and_reject() -> TestResult {
    use crate::hid_rmi::{classify_device, USB_VENDOR_ID_SYNAPTICS};
    // Table hit (Acer Switch 5) classifies with its quirks.
    match classify_device("PNP0C50", USB_VENDOR_ID_SYNAPTICS, 0x81A7) {
        Some(q) => {
            use crate::hid_rmi::DeviceQuirks;
            if !q.contains(DeviceQuirks::OUTPUT_SET_REPORT) {
                return TestResult::Fail("table-hit quirks lost in classify");
            }
        }
        None => return TestResult::Fail("table hit must classify"),
    }
    // SYNA ACPI prefix classifies even with an unlisted PID.
    if classify_device("SYNA8002", USB_VENDOR_ID_SYNAPTICS, 0x8002).is_none() {
        return TestResult::Fail("SYNA prefix must classify as RMI4");
    }
    // Synaptics VID classifies even under a generic PNP0C50 _HID.
    if classify_device("PNP0C50", USB_VENDOR_ID_SYNAPTICS, 0x0000).is_none() {
        return TestResult::Fail("Synaptics VID must classify as RMI4");
    }
    // Anything else is rejected — an Elan device must never be
    // claimed as RMI4, and neither must an unknown VID/PID.
    if classify_device("ELAN09BD", 0x04F3, 0x09BD).is_some() {
        return TestResult::Fail("Elan device must not classify as RMI4");
    }
    if classify_device("PNP0C50", 0x1234, 0x5678).is_some() {
        return TestResult::Fail("unknown device must not classify as RMI4");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-rmi",
    smoke_hid_rmi_classify_synaptics_prefix_and_reject
);

fn smoke_hid_rmi_set_page_output_report_layout() -> TestResult {
    use crate::hid_rmi::{encode_set_page, rmi_page, RMI_WRITE_REPORT_ID};
    if rmi_page(0x0142) != 1 {
        return TestResult::Fail("rmi_page must return high byte of addr");
    }
    if rmi_page(0xFFFF) != 0xFF {
        return TestResult::Fail("rmi_page edge case");
    }
    let buf = encode_set_page(2, 19);
    if buf[0] != RMI_WRITE_REPORT_ID {
        return TestResult::Fail("set_page must use WRITE_REPORT_ID");
    }
    if buf[1] != 1 {
        return TestResult::Fail("set_page write-count must be 1");
    }
    if buf[2] != 0xFF || buf[3] != 0 {
        return TestResult::Fail("set_page must target register 0x00FF");
    }
    if buf[4] != 2 {
        return TestResult::Fail("set_page must carry the page byte at offset 4");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-rmi",
    smoke_hid_rmi_set_page_output_report_layout
);

fn smoke_hid_rmi_attn_report_decode() -> TestResult {
    use crate::hid_rmi::{AttnReport, RMI_ATTN_REPORT_ID};
    // ATTN report: [0x0C, 0x04 (int=F12), F12 data block...]
    let buf = [RMI_ATTN_REPORT_ID, 0x04, 0xAA, 0xBB, 0xCC];
    let attn = match AttnReport::decode(&buf) {
        Some(a) => a,
        None => return TestResult::Fail("AttnReport::decode rejected valid ATTN"),
    };
    if attn.interrupt_sources != 0x04 {
        return TestResult::Fail("interrupt source byte mis-decoded");
    }
    if attn.data != [0xAA, 0xBB, 0xCC] {
        return TestResult::Fail("ATTN data slice wrong");
    }
    // Non-ATTN report returns None.
    let other = [0x0B, 0x01, 0x00];
    if AttnReport::decode(&other).is_some() {
        return TestResult::Fail("AttnReport::decode must reject non-ATTN reports");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input/hid-rmi", smoke_hid_rmi_attn_report_decode);

// ─── hid-elan touchpad smoke tests ─────────────────────────────────

fn smoke_hid_elan_absolute_mode_feature_encode() -> TestResult {
    use crate::hid_elan::{encode_absolute_mode_feature, ELAN_FEATURE_REPORT};
    let buf = encode_absolute_mode_feature();
    // Linux `elan_start_multitouch` writes:
    //   [0x0D, 0x00, 0x03, 0x21, 0x00]
    if buf != [0x0D, 0x00, 0x03, 0x21, 0x00] {
        return TestResult::Fail("absolute mode magic bytes wrong");
    }
    if buf[0] != ELAN_FEATURE_REPORT {
        return TestResult::Fail("leading byte must be ELAN_FEATURE_REPORT (0x0D)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-elan",
    smoke_hid_elan_absolute_mode_feature_encode
);

fn smoke_hid_elan_device_id_table_at_least_five() -> TestResult {
    use crate::hid_elan::{
        match_device, ElanBus, ElanQuirks, ELAN_DEVICE_TABLE, USB_DEVICE_ID_HP_X2,
        USB_DEVICE_ID_HP_X2_10_COVER, USB_DEVICE_ID_TOSHIBA_CLICK_L9W, USB_VENDOR_ID_ELAN,
    };
    if ELAN_DEVICE_TABLE.len() < 5 {
        return TestResult::Fail("expected ≥5 entries in ELAN_DEVICE_TABLE");
    }
    // HP Pavilion X2 must carry HAS_LED + USB bus.
    match match_device(USB_VENDOR_ID_ELAN, USB_DEVICE_ID_HP_X2) {
        Some(m) => {
            if !m.quirks.contains(ElanQuirks::HAS_LED) {
                return TestResult::Fail("HP X2 missing HAS_LED");
            }
            if m.bus != ElanBus::Usb {
                return TestResult::Fail("HP X2 must be on Usb bus");
            }
        }
        None => return TestResult::Fail("HP X2 not in table"),
    }
    match match_device(USB_VENDOR_ID_ELAN, USB_DEVICE_ID_HP_X2_10_COVER) {
        Some(m) => {
            if !m.quirks.contains(ElanQuirks::HAS_LED) {
                return TestResult::Fail("HP X2 cover missing HAS_LED");
            }
        }
        None => return TestResult::Fail("HP X2 cover not in table"),
    }
    // Toshiba Click L9W must be I2cHid (Linux marks it
    // HID_I2C_DEVICE explicitly).
    match match_device(USB_VENDOR_ID_ELAN, USB_DEVICE_ID_TOSHIBA_CLICK_L9W) {
        Some(m) => {
            if m.bus != ElanBus::I2cHid {
                return TestResult::Fail("Toshiba Click L9W must be on I2cHid bus");
            }
        }
        None => return TestResult::Fail("Toshiba Click L9W not in table"),
    }
    // Unknown VID returns None.
    if match_device(0xDEAD, 0xBEEF).is_some() {
        return TestResult::Fail("unknown vid/pid must not match");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-elan",
    smoke_hid_elan_device_id_table_at_least_five
);

fn smoke_hid_elan_classify_prefix_and_reject() -> TestResult {
    use crate::hid_elan::{classify_device, ElanBus, USB_VENDOR_ID_ELAN};
    // Table hit (Toshiba Click L9W) keeps its I2cHid bus.
    match classify_device("PNP0C50", USB_VENDOR_ID_ELAN, 0x0401) {
        Some(m) => {
            if m.bus != ElanBus::I2cHid {
                return TestResult::Fail("table-hit bus lost in classify");
            }
        }
        None => return TestResult::Fail("table hit must classify"),
    }
    // ELAN ACPI prefix classifies even with an unlisted PID.
    match classify_device("ELAN09BD", USB_VENDOR_ID_ELAN, 0x09BD) {
        Some(m) => {
            if m.bus != ElanBus::I2cHid {
                return TestResult::Fail("prefix-classified device must be I2cHid");
            }
        }
        None => return TestResult::Fail("ELAN prefix must classify"),
    }
    // Elan VID classifies even under a generic PNP0C50 _HID.
    if classify_device("PNP0C50", USB_VENDOR_ID_ELAN, 0x0000).is_none() {
        return TestResult::Fail("Elan VID must classify");
    }
    // Anything else is rejected — a Synaptics device must never
    // be claimed as Elan, and neither must an unknown VID/PID.
    if classify_device("SYNA8002", 0x06CB, 0x8002).is_some() {
        return TestResult::Fail("Synaptics device must not classify as Elan");
    }
    if classify_device("PNP0C50", 0x1234, 0x5678).is_some() {
        return TestResult::Fail("unknown device must not classify as Elan");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-elan",
    smoke_hid_elan_classify_prefix_and_reject
);

fn smoke_hid_elan_param_query_round_trip() -> TestResult {
    use crate::hid_elan::{
        decode_param_response_le16, encode_param_query, param, ELAN_FEATURE_REPORT,
    };
    // SET phase encodes the param code at byte 3.
    let q = encode_param_query(param::MAX_X);
    if q != [ELAN_FEATURE_REPORT, 0x05, 0x03, param::MAX_X, 0x01] {
        return TestResult::Fail("param query body wrong");
    }
    // GET response simulates max_x = 0x1234.
    let resp = [ELAN_FEATURE_REPORT, 0x05, 0x03, 0x34, 0x12];
    let v = match decode_param_response_le16(&resp) {
        Some(v) => v,
        None => return TestResult::Fail("decode_param_response_le16 returned None"),
    };
    if v != 0x1234 {
        return TestResult::Fail("LE16 decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-elan",
    smoke_hid_elan_param_query_round_trip
);

fn smoke_hid_elan_finger_decode_inverts_y() -> TestResult {
    use crate::hid_elan::ElanFinger;
    // data layout for one finger record (Linux `elan_report_mt_slot`):
    //   byte 0: X[12..9] in bits 7..4, Y[12..10] in bits 2..0
    //   byte 1: X[8..1]
    //   byte 2: Y[8..1]
    //   byte 3: width nibble pair (sx low / sy high)
    //   byte 4: pressure
    //
    // Choose X = (0x1<<8)|0xAB = 0x1AB, Y_raw = (0x2<<8)|0x34 = 0x234,
    // max_y = 0x500 → reported y = 0x500 - 0x234 = 0x2CC.
    let data = [
        0x12, // X hi nibble 1, Y high 2 bits = 010
        0xAB, // X lo
        0x34, // Y lo
        0x45, // wx=5 wy=4
        0x80, // pressure 128
    ];
    let f = match ElanFinger::decode(&data, 0x500) {
        Some(f) => f,
        None => return TestResult::Fail("decode None on valid 5-byte slice"),
    };
    if !f.present {
        return TestResult::Fail("present should be true");
    }
    if f.x != 0x1AB {
        return TestResult::Fail("X decode wrong");
    }
    if f.y != 0x2CC {
        return TestResult::Fail("Y inversion wrong");
    }
    if f.pressure != 0x80 {
        return TestResult::Fail("pressure");
    }
    if f.w_x != 5 || f.w_y != 4 {
        return TestResult::Fail("width nibbles");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-elan",
    smoke_hid_elan_finger_decode_inverts_y
);

fn smoke_hid_elan_mute_led_feature_encode() -> TestResult {
    use crate::hid_elan::{encode_mute_led, ELAN_LED_REPORT_SIZE, ELAN_MUTE_LED_REPORT};
    let on = encode_mute_led(true);
    let off = encode_mute_led(false);
    if on.len() != ELAN_LED_REPORT_SIZE || off.len() != ELAN_LED_REPORT_SIZE {
        return TestResult::Fail("LED body must be ELAN_LED_REPORT_SIZE");
    }
    if on[0] != ELAN_MUTE_LED_REPORT || off[0] != ELAN_MUTE_LED_REPORT {
        return TestResult::Fail("leading byte must be 0xBC");
    }
    if on[1] != 0x02 || off[1] != 0x02 {
        return TestResult::Fail("byte 1 must be 0x02");
    }
    if on[2] != 1 {
        return TestResult::Fail("ON state must set byte 2 = 1");
    }
    if off[2] != 0 {
        return TestResult::Fail("OFF state must clear byte 2");
    }
    // Trailing bytes zero.
    for &b in &on[3..] {
        if b != 0 {
            return TestResult::Fail("trailing pad must be 0");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-elan",
    smoke_hid_elan_mute_led_feature_encode
);

fn smoke_hid_elan_resolution_convert() -> TestResult {
    use crate::hid_elan::convert_resolution;
    // Linux: (val * 10 + 790) * 10 / 254.
    // val=0 → 790 * 10 / 254 = 7900 / 254 = 31.
    if convert_resolution(0) != 31 {
        return TestResult::Fail("resolution(0) must be 31 dots/mm");
    }
    // val=10 → (100+790)*10/254 = 8900/254 = 35.
    if convert_resolution(10) != 35 {
        return TestResult::Fail("resolution(10) must be 35");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input/hid-elan", smoke_hid_elan_resolution_convert);

fn smoke_hid_elan_usb_single_finger_report() -> TestResult {
    use crate::hid_elan::{ElanReport, ELAN_INPUT_REPORT_SIZE, ELAN_SINGLE_FINGER};
    // 8-byte single-finger USB report with finger 0 active + clickpad
    // button pressed.
    let mut buf = [0u8; ELAN_INPUT_REPORT_SIZE];
    buf[0] = ELAN_SINGLE_FINGER;
    buf[1] = 0;
    // bit 3 → finger 0 active, bit 0 → BTN_LEFT
    buf[2] = (1 << 3) | 0x01;
    // Finger payload starts at buf[3].
    buf[3] = 0x12;
    buf[4] = 0xAB;
    buf[5] = 0x34;
    buf[6] = 0x00;
    buf[7] = 0x80;
    let r = match ElanReport::decode_usb_single_finger(&buf, 0x500) {
        Some(r) => r,
        None => return TestResult::Fail("decode_usb_single_finger rejected"),
    };
    if !r.btn_left {
        return TestResult::Fail("BTN_LEFT bit not set");
    }
    if r.fingers.len() != 5 {
        return TestResult::Fail("expected 5 finger slots");
    }
    if !r.fingers[0].present {
        return TestResult::Fail("finger 0 should be present");
    }
    for i in 1..5 {
        if r.fingers[i].present {
            return TestResult::Fail("higher-slot fingers must be absent");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input/hid-elan",
    smoke_hid_elan_usb_single_finger_report
);

// ── i2c-hid keyboard pump ─────────────────────────────────────────
//
// Smokes for the HID keyboard decode → EV_KEY translation path. The
// descriptor parse + usage→KEY_* mapping is covered in narf-hid; here
// we exercise the report-diff (press/release/autorepeat + modifier
// state) and the EV_KEY dispatch onto an evdev DeviceNode that the
// bind layer adds on top of the decoder.

mod i2c_hid_keyboard_smokes {
    use narf_hid::keyboard::modbit;
    use narf_input::evdev::{EventType, ROUTER};
    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::i2c_hid_keyboard::{
        __build_boot_report, __new_consumer_state_for_test, __new_state_for_test,
        build_keyboard_caps, diff_consumer, diff_report, pump_report, KeyEmit,
    };

    fn make_profile() -> narf_hid::keyboard::KeyboardProfile {
        let blob = narf_hid::keyboard::__boot_keyboard_descriptor_blob();
        let parsed = narf_hid::parse(blob).expect("parse");
        narf_hid::keyboard::detect(&parsed).expect("detect")
    }

    fn decode(
        p: &narf_hid::keyboard::KeyboardProfile,
        modifiers: u8,
        keys: &[u16],
    ) -> narf_hid::keyboard::DecodedKeyboardReport {
        let report = __build_boot_report(modifiers, keys);
        narf_hid::keyboard::decode_input(p, &report).expect("decode")
    }

    // Press a, add b, release a, release all — assert the exact EV_KEY
    // stream incl. modifiers and autorepeat.
    fn smoke_keyboard_press_add_release_stream() -> TestResult {
        let p = make_profile();
        let mut st = __new_state_for_test();

        // Frame 1: press 'a' (usage 0x04 → KEY_A 30).
        let e = diff_report(&mut st, &decode(&p, 0, &[0x04]));
        if e != alloc::vec![KeyEmit { code: 30, value: 1 }] {
            return TestResult::Fail("frame1: expected KEY_A press");
        }

        // Frame 2: add 'b' (0x05 → KEY_B 48). 'a' still held → repeat.
        let e = diff_report(&mut st, &decode(&p, 0, &[0x04, 0x05]));
        if e != alloc::vec![
            KeyEmit { code: 30, value: 2 }, // a autorepeat
            KeyEmit { code: 48, value: 1 }, // b press
        ] {
            return TestResult::Fail("frame2: expected KEY_A repeat + KEY_B press");
        }

        // Frame 3: release 'a', 'b' still held → b repeat.
        let e = diff_report(&mut st, &decode(&p, 0, &[0x05]));
        if e != alloc::vec![
            KeyEmit { code: 30, value: 0 }, // a release
            KeyEmit { code: 48, value: 2 }, // b autorepeat
        ] {
            return TestResult::Fail("frame3: expected KEY_A release + KEY_B repeat");
        }

        // Frame 4: release all.
        let e = diff_report(&mut st, &decode(&p, 0, &[]));
        if e != alloc::vec![KeyEmit { code: 48, value: 0 }] {
            return TestResult::Fail("frame4: expected KEY_B release");
        }

        // Frame 5: nothing held, nothing changed → empty.
        let e = diff_report(&mut st, &decode(&p, 0, &[]));
        if !e.is_empty() {
            return TestResult::Fail("idle frame must emit nothing");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-kbd",
        smoke_keyboard_press_add_release_stream
    );

    // Modifier press/release emits its own EV_KEY (KEY_LEFTSHIFT 42),
    // and the shift state rides alongside the key press.
    fn smoke_keyboard_modifier_transitions() -> TestResult {
        let p = make_profile();
        let mut st = __new_state_for_test();

        // Press shift + 'a' in one frame: shift modifier (bit1→KEY_LEFTSHIFT 42)
        // then the 'a' press.
        let e = diff_report(&mut st, &decode(&p, modbit::LEFT_SHIFT, &[0x04]));
        if e != alloc::vec![
            KeyEmit { code: 42, value: 1 }, // LeftShift press
            KeyEmit { code: 30, value: 1 }, // A press
        ] {
            return TestResult::Fail("expected LeftShift + A press");
        }

        // Release shift, keep 'a' → shift release + A repeat.
        let e = diff_report(&mut st, &decode(&p, 0, &[0x04]));
        if e != alloc::vec![
            KeyEmit { code: 42, value: 0 }, // LeftShift release
            KeyEmit { code: 30, value: 2 }, // A repeat
        ] {
            return TestResult::Fail("expected LeftShift release + A repeat");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-kbd",
        smoke_keyboard_modifier_transitions
    );

    // EV_KEY events + a closing EV_SYN land on an evdev DeviceNode ring.
    fn smoke_keyboard_events_reach_evdev_node() -> TestResult {
        let p = make_profile();
        let mut st = __new_state_for_test();
        let (id, node) = ROUTER.register_device(build_keyboard_caps());
        let reader = ROUTER.open_reader(id).expect("reader");

        // Press 'a' → expect one EV_KEY(30,1) then EV_SYN.
        let n = pump_report(&node, &mut st, &decode(&p, 0, &[0x04]));
        if n != 1 {
            return TestResult::Fail("expected one key event dispatched");
        }
        let key = match reader.poll_event() {
            Some(ev) => ev,
            None => return TestResult::Fail("no EV_KEY on ring"),
        };
        if key.type_ != EventType::Key || key.code != 30 || key.value != 1 {
            return TestResult::Fail("first event must be KEY_A press");
        }
        let syn = match reader.poll_event() {
            Some(ev) => ev,
            None => return TestResult::Fail("no EV_SYN after key"),
        };
        if syn.type_ != EventType::Syn {
            return TestResult::Fail("frame must end with SYN_REPORT");
        }
        // Device caps must advertise KEY_A.
        if !ROUTER.caps(id).expect("caps").has(EventType::Key, 30) {
            return TestResult::Fail("keyboard caps must advertise KEY_A");
        }
        ROUTER.unregister_device(id);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-kbd",
        smoke_keyboard_events_reach_evdev_node
    );

    // Consumer (Fn/media) press/release diff → KEY_VOLUMEUP etc.
    fn smoke_keyboard_consumer_diff() -> TestResult {
        use narf_hid::usage::consumer;
        let mut st = __new_consumer_state_for_test();
        // Press Volume Up.
        let e = diff_consumer(&mut st, &[consumer::VOLUME_UP]);
        if e != alloc::vec![KeyEmit {
            code: 115,
            value: 1
        }] {
            return TestResult::Fail("expected KEY_VOLUMEUP press");
        }
        // Release (empty report).
        let e = diff_consumer(&mut st, &[]);
        if e != alloc::vec![KeyEmit {
            code: 115,
            value: 0
        }] {
            return TestResult::Fail("expected KEY_VOLUMEUP release");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/i2c-hid-kbd", smoke_keyboard_consumer_diff);
}

// ── i8042 keyboard LED output (issue #768) ────────────────────────
// The Set-LEDs exchange (0xED + data byte, ACK after each) is
// driven through `feed_bytes_for_test`, the same byte path the IRQ
// handler uses; `__led_tx_log_for_test` records every byte the
// driver wrote, so the wire conversation is pinned byte-for-byte
// with no port I/O (init() never runs in the harness, so
// `led_write_byte` records without touching 0x60).

fn smoke_i8042_ps2_led_byte_mapping() -> TestResult {
    use crate::i8042::ps2_led_byte;
    use narf_input::evdev::led;
    // Core bitmap is Linux EV_LED order (Num=bit0, Caps=bit1,
    // Scroll=bit2); the PS/2 data byte is Scroll=bit0, Num=bit1,
    // Caps=bit2 (IBM PS/2 Tech Ref; Linux atkbd_set_leds).
    if ps2_led_byte(0) != 0x00 {
        return TestResult::Fail("no LEDs must encode as 0x00");
    }
    if ps2_led_byte(1 << led::LED_NUML) != 0x02 {
        return TestResult::Fail("Num Lock must map to PS/2 bit1 (0x02)");
    }
    if ps2_led_byte(1 << led::LED_CAPSL) != 0x04 {
        return TestResult::Fail("Caps Lock must map to PS/2 bit2 (0x04)");
    }
    if ps2_led_byte(1 << led::LED_SCROLLL) != 0x01 {
        return TestResult::Fail("Scroll Lock must map to PS/2 bit0 (0x01)");
    }
    if ps2_led_byte(0b111) != 0x07 {
        return TestResult::Fail("all three locks must encode as 0x07");
    }
    // Masking-defeating: LEDs with no PS/2 representation (and every
    // other core bit) must not leak into the data byte.
    if ps2_led_byte(u16::MAX) != 0x07 {
        return TestResult::Fail("unrelated core bits leaked into the PS/2 byte");
    }
    if ps2_led_byte((1 << led::LED_MAIL) | (1 << led::LED_CAPSL)) != 0x04 {
        return TestResult::Fail("LED_MAIL must be masked out, CAPSL kept");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_ps2_led_byte_mapping);

fn smoke_i8042_led_exchange_ack_flow() -> TestResult {
    use crate::i8042;
    use narf_input::evdev::led;
    i8042::__reset_for_test();

    // Sink fires (core state: Caps Lock on) → command byte only.
    i8042::on_led_state(1 << led::LED_CAPSL);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED] {
        return TestResult::Fail("exchange must start with exactly [0xED]");
    }
    if i8042::__led_tx_idle_for_test() {
        return TestResult::Fail("exchange must be in flight after 0xED");
    }
    // Keyboard ACKs the command → data byte for CAPSL (PS/2 bit2).
    i8042::feed_bytes_for_test(&[0xFA]);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0x04] {
        return TestResult::Fail("ACK of 0xED must produce data byte 0x04");
    }
    // Keyboard ACKs the data byte → exchange complete, no more writes.
    i8042::feed_bytes_for_test(&[0xFA]);
    if !i8042::__led_tx_idle_for_test() {
        return TestResult::Fail("exchange must be idle after the data ACK");
    }
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0x04] {
        return TestResult::Fail("no further bytes may be written after completion");
    }
    i8042::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_led_exchange_ack_flow);

fn smoke_i8042_led_exchange_resend_paths() -> TestResult {
    use crate::i8042;
    use narf_input::evdev::led;
    i8042::__reset_for_test();

    // RESEND of the command byte: 0xED is retransmitted.
    i8042::on_led_state(1 << led::LED_NUML);
    i8042::feed_bytes_for_test(&[0xFE]);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0xED] {
        return TestResult::Fail("RESEND of 0xED must retransmit 0xED");
    }
    i8042::feed_bytes_for_test(&[0xFA]);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0xED, 0x02] {
        return TestResult::Fail("ACK after RESEND must produce the data byte 0x02");
    }
    // RESEND of the data byte: the data byte is retransmitted.
    i8042::feed_bytes_for_test(&[0xFE]);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0xED, 0x02, 0x02] {
        return TestResult::Fail("RESEND of the data byte must retransmit it");
    }
    i8042::feed_bytes_for_test(&[0xFA]);
    if !i8042::__led_tx_idle_for_test() {
        return TestResult::Fail("exchange must complete after the final ACK");
    }

    // RESEND exhaustion: after 3 retransmissions the next RESEND
    // aborts the exchange (no fourth retransmit, machine idle).
    i8042::__reset_for_test();
    i8042::on_led_state(1 << led::LED_CAPSL);
    i8042::feed_bytes_for_test(&[0xFE, 0xFE, 0xFE]);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0xED, 0xED, 0xED] {
        return TestResult::Fail("expected 1 + 3 retransmissions of 0xED");
    }
    i8042::feed_bytes_for_test(&[0xFE]);
    if !i8042::__led_tx_idle_for_test() {
        return TestResult::Fail("exhausted RESEND budget must abort the exchange");
    }
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0xED, 0xED, 0xED] {
        return TestResult::Fail("no byte may be written after the abort");
    }
    i8042::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_led_exchange_resend_paths);

fn smoke_i8042_led_exchange_aborts_on_scancode() -> TestResult {
    use crate::i8042;
    use narf_input::evdev::led;
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, KeyCode,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042::__reset_for_test();

    // Mid-exchange, a real scancode arrives (keyboard never ACKed).
    // The byte must NOT be consumed by the LED protocol: it decodes
    // as a key, and the exchange aborts.
    i8042::on_led_state(1 << led::LED_CAPSL);
    i8042::feed_bytes_for_test(&[0x1E]); // 'A' make
    if !i8042::__led_tx_idle_for_test() {
        return TestResult::Fail("a scancode mid-exchange must abort the exchange");
    }
    match pop_global() {
        Some(InputEvent::Key(k)) if k.code == KeyCode::A && k.pressed => {}
        _ => return TestResult::Fail("the scancode byte was swallowed by the LED exchange"),
    }
    // A fresh state change starts a clean new exchange afterwards.
    i8042::on_led_state(1 << led::LED_NUML);
    i8042::feed_bytes_for_test(&[0xFA, 0xFA]);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0xED, 0x02] {
        return TestResult::Fail("post-abort exchange must run cleanly");
    }
    if !i8042::__led_tx_idle_for_test() {
        return TestResult::Fail("post-abort exchange must complete");
    }
    i8042::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_led_exchange_aborts_on_scancode);

fn smoke_i8042_led_exchange_tracks_midflight_change() -> TestResult {
    use crate::i8042;
    use narf_input::evdev::led;
    i8042::__reset_for_test();

    let caps_only = 1 << led::LED_CAPSL;
    let caps_num = caps_only | (1 << led::LED_NUML);
    let num_only = 1 << led::LED_NUML;

    i8042::on_led_state(caps_only);
    // State moves before the command is even ACKed: the data byte
    // must carry the NEWEST bitmap (Num+Caps → PS/2 0x06).
    i8042::on_led_state(caps_num);
    i8042::feed_bytes_for_test(&[0xFA]);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0x06] {
        return TestResult::Fail("data byte must encode the newest bitmap (0x06)");
    }
    // State moves again while the data byte is in flight: on
    // completion a follow-up exchange starts automatically and
    // delivers Num-only (PS/2 0x02).
    i8042::on_led_state(num_only);
    i8042::feed_bytes_for_test(&[0xFA]);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0x06, 0xED] {
        return TestResult::Fail("mid-flight change must queue a follow-up exchange");
    }
    i8042::feed_bytes_for_test(&[0xFA, 0xFA]);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0x06, 0xED, 0x02] {
        return TestResult::Fail("follow-up exchange must deliver 0x02");
    }
    if !i8042::__led_tx_idle_for_test() {
        return TestResult::Fail("all exchanges must be complete at the end");
    }
    i8042::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_led_exchange_tracks_midflight_change
);

// ── i8042 device power management (issue #770) ───────────────────
// The PM hooks touch real ports only when the controller
// initialised (init() never runs in the harness), so these
// fixtures pin the port-free contract: registration in the
// device-PM registry, suspend/resume as a no-op Ok when
// uninitialised, and the decode/LED/mouse state resume resets.
// The shared port sequences themselves are the same helpers
// `init()` already exercises on real hardware.

fn smoke_i8042_pm_registers_in_device_pm() -> TestResult {
    use crate::i8042;
    // Isolate the global registry so other suites' entries can't
    // leak into the count (restored on guard drop).
    let _guard = narf_power::device_pm::__test_isolate_registry();
    i8042::register_device_pm();
    let names: alloc::vec::Vec<alloc::string::String> = narf_power::device_pm::registered_devices()
        .iter()
        .map(|e| e.name.clone())
        .collect();
    if names.iter().filter(|n| n.as_str() == "i8042").count() != 1 {
        return TestResult::Fail("\"i8042\" must be registered exactly once");
    }
    // Re-registration is idempotent on the name.
    i8042::register_device_pm();
    if narf_power::device_pm::device_count() != 1 {
        return TestResult::Fail("re-registering \"i8042\" must not duplicate the entry");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_pm_registers_in_device_pm);

fn smoke_i8042_pm_suspend_resume_noop_when_uninitialised() -> TestResult {
    use crate::i8042;
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, KeyCode,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042::__reset_for_test();
    crate::i8042_mouse::__reset_for_test();

    // Suspend + resume must succeed with no port I/O when the
    // controller never initialised.
    if i8042::pm_suspend().is_err() {
        return TestResult::Fail("suspend must be Ok when uninitialised");
    }
    if i8042::pm_resume().is_err() {
        return TestResult::Fail("resume must be Ok when uninitialised");
    }

    // Resume drops a stale E0 latch: 0xE0 fed pre-resume, then
    // 0x47 post-resume must decode as plain keypad 7, not Home
    // (E0 0x47).
    i8042::feed_bytes_for_test(&[0xE0]);
    if i8042::pm_resume().is_err() {
        return TestResult::Fail("second resume must be Ok when uninitialised");
    }
    i8042::feed_bytes_for_test(&[0x47]);
    match pop_global() {
        Some(InputEvent::Key(k)) if k.code == KeyCode::Kp7 && k.pressed => {}
        _ => return TestResult::Fail("0x47 after resume must decode as Kp7, not Home"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_pm_suspend_resume_noop_when_uninitialised
);

fn smoke_i8042_pm_resume_parks_inflight_led_exchange() -> TestResult {
    use crate::i8042;
    use narf_input::evdev::led;
    use narf_input::{__reset_global_ring_for_test, init_global_ring};
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042::__reset_for_test();

    // Start an exchange (Caps Lock on): 0xED written, machine
    // awaiting its ACK.
    i8042::on_led_state(1 << led::LED_CAPSL);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED] {
        return TestResult::Fail("exchange must start with exactly [0xED]");
    }
    if i8042::__led_tx_idle_for_test() {
        return TestResult::Fail("exchange must be in flight before resume");
    }
    // Clear the desired bitmap before resume: on an initialised
    // controller `pm_resume` re-drives a non-zero desired bitmap
    // (the keyboard reset cleared its LEDs), which starts a fresh
    // exchange and would mask the park. With nothing to re-drive,
    // the park at Idle is observable on either path; the re-drive
    // itself is pinned by
    // `smoke_i8042_pm_resume_redrives_desired_leds` below.
    // Turning the LED off mid-exchange only records intent — no
    // second byte is written while the exchange is in flight.
    i8042::on_led_state(0);
    // Resume parks it: the keyboard was reset, so the ACK will
    // never arrive — the machine must return to Idle instead of
    // blocking every later LED update.
    if i8042::pm_resume().is_err() {
        return TestResult::Fail("resume must be Ok");
    }
    if !i8042::__led_tx_idle_for_test() {
        return TestResult::Fail("resume must park the LED exchange at Idle");
    }
    // A late ACK byte must NOT be consumed as an LED response
    // (no data byte written); it falls through to scancode
    // decode instead.
    i8042::feed_bytes_for_test(&[0xFA]);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED] {
        return TestResult::Fail("late ACK must not resume the parked exchange");
    }
    // The machine is ready for a fresh exchange: a new sink call
    // starts a clean one for the requested bitmap.
    i8042::on_led_state(1 << led::LED_CAPSL);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0xED] {
        return TestResult::Fail("fresh exchange must start after the park");
    }
    i8042::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_pm_resume_parks_inflight_led_exchange
);

fn smoke_i8042_pm_resume_redrives_desired_leds() -> TestResult {
    use crate::i8042;
    use narf_input::evdev::led;
    use narf_input::{__reset_global_ring_for_test, init_global_ring};
    init_global_ring(8);
    __reset_global_ring_for_test();
    i8042::__reset_for_test();

    // Start an exchange (Caps Lock on) and leave the LED lit: on
    // an initialised controller resume re-drives the desired
    // bitmap, because the keyboard reset cleared its LEDs.
    i8042::on_led_state(1 << led::LED_CAPSL);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED] {
        return TestResult::Fail("exchange must start with exactly [0xED]");
    }
    if i8042::pm_resume().is_err() {
        return TestResult::Fail("resume must be Ok");
    }
    // The stale exchange was parked and a fresh one started for
    // the preserved desired bitmap: a second 0xED, still in flight.
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0xED] {
        return TestResult::Fail("resume must re-drive the desired LEDs with a fresh 0xED");
    }
    if i8042::__led_tx_idle_for_test() {
        return TestResult::Fail("re-driven exchange must be in flight after resume");
    }
    // The fresh exchange completes normally: its ACK writes the
    // Caps data byte, and the data ACK returns it to Idle.
    i8042::feed_bytes_for_test(&[0xFA]);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0xED, 0x04] {
        return TestResult::Fail("ACK of the re-driven exchange must write the LED data byte");
    }
    i8042::feed_bytes_for_test(&[0xFA]);
    if !i8042::__led_tx_idle_for_test() {
        return TestResult::Fail("re-driven exchange must complete at Idle");
    }
    i8042::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers/input", smoke_i8042_pm_resume_redrives_desired_leds);

fn smoke_i8042_pm_resume_drops_partial_mouse_packet() -> TestResult {
    use crate::i8042;
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_global, InputEvent, PointerButtons,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    crate::i8042_mouse::__reset_for_test();

    // A complete packet first, to prove the accumulator works.
    crate::i8042_mouse::feed_byte_for_test(0x09);
    crate::i8042_mouse::feed_byte_for_test(5);
    crate::i8042_mouse::feed_byte_for_test(3);
    if crate::i8042_mouse::take_rel_delta() != (5, -3) {
        return TestResult::Fail("baseline packet must decode to (5, -3)");
    }
    // Split packet: first byte only, then suspend/resume.
    crate::i8042_mouse::feed_byte_for_test(0x09);
    if i8042::pm_resume().is_err() {
        return TestResult::Fail("resume must be Ok when uninitialised");
    }
    // Stale deltas are zero and the phase machine is reset: a
    // fresh full packet decodes cleanly instead of completing
    // the split one with garbage bytes.
    if crate::i8042_mouse::take_rel_delta() != (0, 0) {
        return TestResult::Fail("resume must zero the stale relative deltas");
    }
    crate::i8042_mouse::feed_byte_for_test(0x09);
    crate::i8042_mouse::feed_byte_for_test(5);
    crate::i8042_mouse::feed_byte_for_test(3);
    match pop_global() {
        Some(InputEvent::Pointer(p)) => {
            if p.dx != 5 || p.dy != -3 {
                return TestResult::Fail("post-resume packet must decode to (5, -3)");
            }
            if !p.buttons.contains(PointerButtons::LEFT) {
                return TestResult::Fail("post-resume packet lost the LEFT button bit");
            }
        }
        _ => return TestResult::Fail("post-resume packet produced no PointerEvent"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_pm_resume_drops_partial_mouse_packet
);

fn smoke_i8042_led_sink_wired_from_core_dispatch() -> TestResult {
    use crate::i8042;
    use narf_input::evdev::{key, led, DeviceCaps, EvdevEvent, EventType, ROUTER};
    i8042::__reset_for_test();

    // A node wired exactly as init() wires the real keyboard:
    // LED caps + the i8042 sink. A CapsLock press dispatched at the
    // node must start the wire exchange end-to-end.
    let mut caps = DeviceCaps::new();
    caps.add_key(key::KEY_CAPSLOCK);
    caps.add_led(led::LED_NUML);
    caps.add_led(led::LED_CAPSL);
    caps.add_led(led::LED_SCROLLL);
    let (id, node) = ROUTER.register_device(caps);
    node.set_led_sink(i8042::on_led_state);
    node.dispatch(EvdevEvent {
        time: 0,
        type_: EventType::Key,
        code: key::KEY_CAPSLOCK,
        value: 1,
    });
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED] {
        return TestResult::Fail("core dispatch did not start the LED exchange");
    }
    i8042::feed_bytes_for_test(&[0xFA, 0xFA]);
    if i8042::__led_tx_log_for_test() != alloc::vec![0xED, 0x04] {
        return TestResult::Fail("end-to-end exchange must deliver CAPSL byte 0x04");
    }
    if !i8042::__led_tx_idle_for_test() {
        return TestResult::Fail("end-to-end exchange must complete");
    }
    ROUTER.unregister_device(id);
    i8042::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/input",
    smoke_i8042_led_sink_wired_from_core_dispatch
);

// ── psmouse protocol negotiation + Synaptics decoders ──────────────────────
//
// Fixtures are built from the cited specs, never from the impl:
// knock byte sequences from Linux `psmouse-base.c` / Chapweske,
// Synaptics packet layouts from Linux `synaptics_parse_hw_state`.
// The fake transport records every byte the driver sends and replays
// canned replies, so the negotiation fixtures pin the exact wire
// order of the whole probe sequence.

mod psmouse_smokes {
    use alloc::collections::VecDeque;
    use alloc::vec;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::psmouse::{
        decode_elantech_v1, decode_elantech_v2, decode_elantech_v3, decode_elantech_v4,
        decode_synaptics_newabs, decode_synaptics_oldabs, elantech_hw_version, elantech_info,
        elantech_is_debounce_v2, elantech_is_signature_valid, elantech_packet_check_v1,
        elantech_packet_check_v2, elantech_packet_check_v3, elantech_packet_check_v4,
        negotiate_protocol, synaptics_invert_y, synaptics_validate_byte, ElantechPacket,
        ElantechState, Ps2Transport, PsmouseHardware, PsmouseProtocol, SynapticsPktType,
    };

    /// Fake PS/2 device: records every byte sent, replays canned
    /// reply bytes in order. `send` always ACKs (the real ACK wait
    /// is a transport detail); `recv` pops the next canned byte.
    struct FakePs2 {
        sent: Vec<u8>,
        replies: VecDeque<u8>,
    }

    impl FakePs2 {
        fn new(replies: &[u8]) -> Self {
            Self {
                sent: Vec::new(),
                replies: replies.iter().copied().collect(),
            }
        }
    }

    impl Ps2Transport for FakePs2 {
        fn send(&mut self, byte: u8) -> bool {
            self.sent.push(byte);
            true
        }

        fn recv(&mut self) -> Option<u8> {
            self.replies.pop_front()
        }
    }

    /// SETRATE(rate) wire bytes: [0xF3, rate].
    fn set_rate(rate: u8) -> [u8; 2] {
        [0xF3, rate]
    }

    /// The shared probe prefix every negotiation runs: Synaptics
    /// detect (4x SETRES(0) + GETINFO, answered "not Synaptics"),
    /// ALPS E6 report (answered "not ALPS"), Elantech magic knock
    /// (answered "not Elantech"), then reset (BAT + ID).
    /// Returns the bytes the driver must have sent, and consumes
    /// the matching replies from the fake.
    fn probe_prefix_sent() -> Vec<u8> {
        let mut sent = Vec::new();
        // Synaptics: SETRES(0) x4, GETINFO.
        for _ in 0..4 {
            sent.extend_from_slice(&[0xE8, 0x00]);
        }
        sent.push(0xE9);
        // ALPS E6: SETRES(0xE6), SETSCALE11, SETSCALE11, GETINFO.
        sent.extend_from_slice(&[0xE8, 0xE6, 0xE6, 0xE6, 0xE9]);
        // Elantech magic knock: SETDEFAULTS, DISABLE, 3x
        // SETSCALE11, GETINFO.
        sent.extend_from_slice(&[0xF6, 0xF5, 0xE6, 0xE6, 0xE6, 0xE9]);
        // Reset.
        sent.push(0xFF);
        sent
    }

    /// Sliced command wire bytes (Linux `ps2_sliced_command`):
    /// `0xE6`, then `0xE8` + each 2-bit slice of `command`, most
    /// significant first. Built from the wire format, not from
    /// the implementation.
    fn sliced_cmd(cmd: u8) -> Vec<u8> {
        let mut sent = vec![0xE6];
        for shift in [6, 4, 2, 0] {
            sent.extend_from_slice(&[0xE8, (cmd >> shift) & 0x03]);
        }
        sent
    }

    fn smoke_psmouse_intellimouse_knock_sequence() -> TestResult {
        // Replies, in order: Synaptics GETINFO [0,0,0] (not Synaptics),
        // ALPS E6 GETINFO [0,0,0] (not ALPS), Elantech magic-knock
        // GETINFO [0,0,0] (not Elantech), reset BAT+ID, Intelli
        // prefix GETID=0x03, Explorer GETID=0x00 (not Explorer),
        // standalone Intelli GETID=0x03.
        let replies = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0x00, 0x03, 0x00, 0x03,
        ];
        let mut fake = FakePs2::new(&replies);
        let (hw, proto) = negotiate_protocol(&mut fake);
        if hw != PsmouseHardware::Generic {
            return TestResult::Fail("plain mouse must not detect vendor hardware");
        }
        if proto != PsmouseProtocol::IntelliMouse {
            return TestResult::Fail("ID 0x03 after 200/100/80 must negotiate IntelliMouse");
        }
        // Exact wire order: probe prefix, Intelli knock + GETID,
        // Explorer knock + GETID, Intelli knock + GETID again
        // (Linux tries Explorer first, then IntelliMouse standalone).
        let mut want = probe_prefix_sent();
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(100));
        want.extend_from_slice(&set_rate(80));
        want.push(0xF2);
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(80));
        want.push(0xF2);
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(100));
        want.extend_from_slice(&set_rate(80));
        want.push(0xF2);
        if fake.sent != want {
            return TestResult::Fail("IntelliMouse knock wire sequence wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/psmouse",
        smoke_psmouse_intellimouse_knock_sequence
    );

    fn smoke_psmouse_explorer_knock_sequence() -> TestResult {
        // Replies: Synaptics no, ALPS no, Elantech magic knock no,
        // reset BAT+ID, Intelli prefix GETID=0x03, Explorer GETID=0x04,
        // then the 4.0 tilt knock (200/80/40) with no further replies.
        let replies = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0x00, 0x03, 0x04,
        ];
        let mut fake = FakePs2::new(&replies);
        let (hw, proto) = negotiate_protocol(&mut fake);
        if hw != PsmouseHardware::Generic || proto != PsmouseProtocol::ExplorerTilt {
            return TestResult::Fail("ID 0x04 after 200/200/80 must negotiate ExplorerTilt");
        }
        let mut want = probe_prefix_sent();
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(100));
        want.extend_from_slice(&set_rate(80));
        want.push(0xF2);
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(80));
        want.push(0xF2);
        // Tilt enable: 200, 80, 40 — and no standalone Intelli knock
        // afterwards (Explorer already won).
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(80));
        want.extend_from_slice(&set_rate(40));
        if fake.sent != want {
            return TestResult::Fail("Explorer knock wire sequence wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/psmouse",
        smoke_psmouse_explorer_knock_sequence
    );

    fn smoke_psmouse_standard_fallback_knock() -> TestResult {
        // Plain mouse: every GETID answers 0x00.
        let replies = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut fake = FakePs2::new(&replies);
        let (hw, proto) = negotiate_protocol(&mut fake);
        if hw != PsmouseHardware::Generic || proto != PsmouseProtocol::Standard {
            return TestResult::Fail("ID 0x00 everywhere must fall back to Standard");
        }
        // No tilt knock may appear after a failed Explorer attempt.
        if fake.sent.windows(2).any(|w| w[0] == 0xF3 && w[1] == 40) {
            return TestResult::Fail("tilt knock must not run without ID 0x04");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/psmouse",
        smoke_psmouse_standard_fallback_knock
    );

    fn smoke_psmouse_synaptics_detect_knock() -> TestResult {
        // Synaptics pad in relative mode: GETINFO answers [?, 0x47, ?],
        // then it also answers the IntelliMouse knock (pads emulate
        // IMPS in relative mode — Linux records Synaptics hardware
        // AND negotiates the wheel protocol).
        let replies = [
            0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0xAA, 0x00, 0x03, 0x00, 0x03,
        ];
        let mut fake = FakePs2::new(&replies);
        let (hw, proto) = negotiate_protocol(&mut fake);
        if hw != PsmouseHardware::Synaptics {
            return TestResult::Fail("GETINFO byte 0x47 must detect Synaptics");
        }
        if proto != PsmouseProtocol::IntelliMouse {
            return TestResult::Fail("Synaptics pad must still negotiate IntelliMouse wheel");
        }
        // ALPS must NOT be probed once Synaptics matched (the ALPS
        // E6 knock would confuse the pad — Linux skips it too).
        // Elantech IS still probed after a Synaptics match (Linux
        // keeps probing vendor protocols until one claims the
        // device); the pad fails its magic knock.
        let mut want: Vec<u8> = Vec::new();
        for _ in 0..4 {
            want.extend_from_slice(&[0xE8, 0x00]);
        }
        want.push(0xE9);
        want.extend_from_slice(&[0xF6, 0xF5, 0xE6, 0xE6, 0xE6, 0xE9]);
        want.push(0xFF);
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(100));
        want.extend_from_slice(&set_rate(80));
        want.push(0xF2);
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(80));
        want.push(0xF2);
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(100));
        want.extend_from_slice(&set_rate(80));
        want.push(0xF2);
        if fake.sent != want {
            return TestResult::Fail("Synaptics wire sequence wrong (ALPS must be skipped)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/psmouse",
        smoke_psmouse_synaptics_detect_knock
    );

    fn smoke_psmouse_alps_detect_knock() -> TestResult {
        // ALPS pad: Synaptics GETINFO no, E6 report 00-00-0A, E7
        // report 73-02-64 (v3 signature), Elantech magic knock no,
        // then plain-mouse IDs.
        let replies = [
            0x00, 0x00, 0x00, // Synaptics GETINFO
            0x00, 0x00, 0x0A, // ALPS E6 report
            0x73, 0x02, 0x64, // ALPS E7 report
            0x00, 0x00, 0x00, // Elantech magic knock (fails)
            0xAA, 0x00, // reset BAT+ID
            0x00, 0x00, 0x00, // GETIDs
        ];
        let mut fake = FakePs2::new(&replies);
        let (hw, proto) = negotiate_protocol(&mut fake);
        if hw != PsmouseHardware::Alps {
            return TestResult::Fail("E6/E7 reports must detect ALPS");
        }
        if proto != PsmouseProtocol::Standard {
            return TestResult::Fail("ALPS pad answering ID 0x00 must stay Standard");
        }
        // Wire order: Synaptics knock, ALPS E6 (E8-E6-E6-E6-E9),
        // ALPS E7 (E8-E7-E7-E7-E9), Elantech magic knock
        // (F6-F5-E6-E6-E6-E9), reset, then the wheel knocks.
        let mut want: Vec<u8> = Vec::new();
        for _ in 0..4 {
            want.extend_from_slice(&[0xE8, 0x00]);
        }
        want.push(0xE9);
        want.extend_from_slice(&[0xE8, 0xE6, 0xE6, 0xE6, 0xE9]);
        want.extend_from_slice(&[0xE8, 0xE7, 0xE7, 0xE7, 0xE9]);
        want.extend_from_slice(&[0xF6, 0xF5, 0xE6, 0xE6, 0xE6, 0xE9]);
        want.push(0xFF);
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(100));
        want.extend_from_slice(&set_rate(80));
        want.push(0xF2);
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(80));
        want.push(0xF2);
        want.extend_from_slice(&set_rate(200));
        want.extend_from_slice(&set_rate(100));
        want.extend_from_slice(&set_rate(80));
        want.push(0xF2);
        if fake.sent != want {
            return TestResult::Fail("ALPS wire sequence wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/psmouse", smoke_psmouse_alps_detect_knock);

    fn smoke_synaptics_newabs_decode() -> TestResult {
        // NEWABS packet built from the Linux layout for x=1000,
        // y=2000, z=50, w=1, left pressed:
        //   b0 = 0x81 (sync + left), b1 = 0x73 (x hi 0x3, y hi 0x7),
        //   b2 = 50 (z), b3 = 0xC4 (sync + w bit), b4 = 0xE8 (x lo),
        //   b5 = 0xD0 (y lo).
        let buf: [u8; 6] = [0x81, 0x73, 50, 0xC4, 0xE8, 0xD0];
        for idx in 0..5 {
            if !synaptics_validate_byte(&buf, idx, SynapticsPktType::NewAbsStrict) {
                return TestResult::Fail("NEWABS strict validation must pass this packet");
            }
        }
        let hw = decode_synaptics_newabs(&buf);
        if hw.x != 1000 || hw.y != 2000 || hw.z != 50 || hw.w != 1 {
            return TestResult::Fail("NEWABS x/y/z/w decode wrong");
        }
        if !hw.left || hw.right {
            return TestResult::Fail("NEWABS button bits wrong");
        }
        if synaptics_invert_y(hw.y) != 5856 - 2000 {
            return TestResult::Fail("Y inversion must be 5856 - y");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/psmouse", smoke_synaptics_newabs_decode);

    fn smoke_synaptics_oldabs_decode() -> TestResult {
        // OLDABS packet for x=1000, y=2000, z=50, w=2, left pressed:
        //   b0 = 0xC5 (sync + w bit + left), b1 = 0x03 (x hi),
        //   b2 = 0xE8 (x lo), b3 = 0xB2 (sync + z lo 0x32),
        //   b4 = 0x07 (y hi), b5 = 0xD0 (y lo).
        let buf: [u8; 6] = [0xC5, 0x03, 0xE8, 0xB2, 0x07, 0xD0];
        for idx in 0..5 {
            if !synaptics_validate_byte(&buf, idx, SynapticsPktType::OldAbs) {
                return TestResult::Fail("OLDABS validation must pass this packet");
            }
        }
        let hw = decode_synaptics_oldabs(&buf);
        if hw.x != 1000 || hw.y != 2000 || hw.z != 50 || hw.w != 2 {
            return TestResult::Fail("OLDABS x/y/z/w decode wrong");
        }
        if !hw.left || hw.right {
            return TestResult::Fail("OLDABS button bits wrong");
        }
        // A NEWABS-strict check must reject an OLDABS packet
        // (byte 0 fails the NEWABS mask), so the two flavours can
        // never be confused by the packet-type probe.
        if synaptics_validate_byte(&buf, 0, SynapticsPktType::NewAbsStrict) {
            return TestResult::Fail("NEWABS validation must reject OLDABS byte 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/psmouse", smoke_synaptics_oldabs_decode);

    fn smoke_elantech_signature_and_hw_version() -> TestResult {
        // Signature: a zero major is never Elantech (this is the
        // standard mouse 00.02.64 false positive); a zero minor is
        // a real firmware; a sample rate in param[2] is a mouse
        // echoing rates, not a version; the hw>=4 carve-out accepts
        // revisions above 20 that are not rates.
        if elantech_is_signature_valid(&[0x00, 0x02, 0x64]) {
            return TestResult::Fail("00.02.64 must fail the signature (zero major)");
        }
        if !elantech_is_signature_valid(&[0x02, 0x00, 0x22]) {
            return TestResult::Fail("02.00.22 must pass the signature");
        }
        if elantech_is_signature_valid(&[0x02, 0x08, 0x64]) {
            return TestResult::Fail("02.08.64 must fail the signature (100 is a rate)");
        }
        if !elantech_is_signature_valid(&[0x02, 0x08, 0x00]) {
            return TestResult::Fail("02.08.00 must pass the signature");
        }
        if !elantech_is_signature_valid(&[0x46, 0x0F, 0x02]) {
            return TestResult::Fail("46.0F.02 must pass the signature (hw>=4 carve-out)");
        }
        if elantech_is_signature_valid(&[0x16, 0x0F, 0x28]) {
            return TestResult::Fail("16.0F.28 must fail (revision 40, and 40 is a rate)");
        }
        // Hardware version table (elantech_set_properties).
        if elantech_hw_version(0x020022) != Some(1) {
            return TestResult::Fail("fw 0x020022 must be hw v1");
        }
        if elantech_hw_version(0x020600) != Some(1) {
            return TestResult::Fail("fw 0x020600 must be hw v1");
        }
        if elantech_hw_version(0x020030) != Some(2) {
            return TestResult::Fail("fw 0x020030 must be hw v2");
        }
        if elantech_hw_version(0x020800) != Some(2) {
            return TestResult::Fail("fw 0x020800 must be hw v2");
        }
        if elantech_hw_version(0x040216) != Some(2) {
            return TestResult::Fail("fw 0x040216 must be hw v2");
        }
        if elantech_hw_version(0x050000) != Some(3) {
            return TestResult::Fail("fw 0x050000 must be hw v3");
        }
        if elantech_hw_version(0x460f02) != Some(4) {
            return TestResult::Fail("fw 0x460f02 must be hw v4");
        }
        if elantech_hw_version(0x030000).is_some() {
            return TestResult::Fail("fw 0x030000 (IC 3) must be unknown hardware");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/psmouse",
        smoke_elantech_signature_and_hw_version
    );

    fn smoke_psmouse_elantech_detect_v2_knock() -> TestResult {
        // Elantech v2 pad, firmware 02.08.00 (elantech.rst EF023):
        // Synaptics no, ALPS E6 no, magic knock 3C-03-C8, firmware
        // version 02.08.00, capabilities 00-16-0C, samples 00-00-00,
        // then the v2 absolute-mode register writes + reg 0x10
        // read-back. No reset and no wheel knock may follow.
        let replies = [
            0x00, 0x00, 0x00, // Synaptics GETINFO
            0x00, 0x00, 0x00, // ALPS E6 GETINFO
            0x3C, 0x03, 0xC8, // Elantech magic knock
            0x02, 0x08, 0x00, // FW version query
            0x00, 0x16, 0x0C, // Capabilities query
            0x00, 0x00, 0x00, // Sample query
            0x54, 0x00, 0x00, // Reg 0x10 read-back
        ];
        let mut fake = FakePs2::new(&replies);
        let (hw, proto) = negotiate_protocol(&mut fake);
        if hw != PsmouseHardware::Elantech || proto != PsmouseProtocol::Elantech {
            return TestResult::Fail("Elantech v2 pad must negotiate Elantech");
        }
        let Some(info) = elantech_info() else {
            return TestResult::Fail("Elantech info must be recorded after detection");
        };
        if info.hw_version != 2
            || info.fw_version != 0x020800
            || info.x_max != 1152
            || info.y_max != 768
            || !info.reports_pressure
            || info.crc_enabled
            || info.buttonpad
            || info.has_trackpoint
        {
            return TestResult::Fail("Elantech v2 info (ranges/flags) wrong");
        }
        let mut want = probe_prefix_sent();
        // The probe prefix ends with the magic knock + reset; the
        // Elantech path returns before the reset, so drop it.
        want.pop();
        // FW version / capabilities / samples: sliced queries.
        want.extend_from_slice(&sliced_cmd(0x01));
        want.push(0xE9);
        want.extend_from_slice(&sliced_cmd(0x02));
        want.push(0xE9);
        want.extend_from_slice(&sliced_cmd(0x03));
        want.push(0xE9);
        // Absolute mode, v2: write reg 0x10=0x54, 0x11=0x88,
        // 0x21=0x60 (F8 11 F8 reg F8 val E6 each), then read back
        // reg 0x10 (F8 10 F8 10 E9).
        want.extend_from_slice(&[0xF8, 0x11, 0xF8, 0x10, 0xF8, 0x54, 0xE6]);
        want.extend_from_slice(&[0xF8, 0x11, 0xF8, 0x11, 0xF8, 0x88, 0xE6]);
        want.extend_from_slice(&[0xF8, 0x11, 0xF8, 0x21, 0xF8, 0x60, 0xE6]);
        want.extend_from_slice(&[0xF8, 0x10, 0xF8, 0x10, 0xE9]);
        if fake.sent != want {
            return TestResult::Fail("Elantech v2 detect wire sequence wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/psmouse",
        smoke_psmouse_elantech_detect_v2_knock
    );

    fn smoke_psmouse_elantech_rejects_standard_mouse() -> TestResult {
        // The #1676 false positive, nailed shut: a standard mouse
        // answers the Elantech magic knock's GETINFO with
        // 00-02-64, which parses as version triple 00.02.64 — but
        // the magic bytes are 3C-03-C8, so detection fails before
        // the firmware query ever runs.
        let replies = [
            0x00, 0x00, 0x00, // Synaptics GETINFO
            0x00, 0x00, 0x00, // ALPS E6 GETINFO
            0x00, 0x02, 0x64, // Elantech magic knock (fails)
            0xAA, 0x00, // reset BAT+ID
            0x00, 0x00, 0x00, // GETIDs
        ];
        let mut fake = FakePs2::new(&replies);
        let (hw, proto) = negotiate_protocol(&mut fake);
        if hw != PsmouseHardware::Generic || proto != PsmouseProtocol::Standard {
            return TestResult::Fail("standard mouse must fall back to Standard, not Elantech");
        }
        if elantech_info().is_some() {
            return TestResult::Fail("no Elantech info may be recorded for a standard mouse");
        }
        // The firmware query is a sliced command; it must never
        // appear — the knock alone decides.
        if fake.sent.windows(2).any(|w| w[0] == 0xE8 && w[1] == 0x01) {
            return TestResult::Fail("firmware query must not run after a failed magic knock");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/psmouse",
        smoke_psmouse_elantech_rejects_standard_mouse
    );

    fn smoke_psmouse_elantech_rejects_zero_major_signature() -> TestResult {
        // Magic knock passes, but the firmware version is
        // 00.02.64: param[0] == 0 fails the signature (Linux:
        // "Probably not a real Elantech touchpad").
        let replies = [
            0x00, 0x00, 0x00, // Synaptics GETINFO
            0x00, 0x00, 0x00, // ALPS E6 GETINFO
            0x3C, 0x03, 0xC8, // Elantech magic knock
            0x00, 0x02, 0x64, // FW version query (invalid)
            0xAA, 0x00, // reset BAT+ID
            0x00, 0x00, 0x00, // GETIDs
        ];
        let mut fake = FakePs2::new(&replies);
        let (hw, proto) = negotiate_protocol(&mut fake);
        if hw != PsmouseHardware::Generic || proto != PsmouseProtocol::Standard {
            return TestResult::Fail("zero-major firmware must fall back to Standard");
        }
        if elantech_info().is_some() {
            return TestResult::Fail("no Elantech info may be recorded on signature failure");
        }
        // No register writes (0xF8) may appear: absolute mode
        // must never be attempted for a rejected pad.
        if fake.sent.contains(&0xF8) {
            return TestResult::Fail("register writes must not run after a signature failure");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/psmouse",
        smoke_psmouse_elantech_rejects_zero_major_signature
    );

    fn smoke_psmouse_elantech_rejects_rate_version_signature() -> TestResult {
        // Magic knock passes, but the firmware version is
        // 02.08.64: param[2] == 100 is a sample rate, so the
        // signature fails (Logitech mice answer the knock this way).
        let replies = [
            0x00, 0x00, 0x00, // Synaptics GETINFO
            0x00, 0x00, 0x00, // ALPS E6 GETINFO
            0x3C, 0x03, 0xC8, // Elantech magic knock
            0x02, 0x08, 0x64, // FW version query (invalid)
            0xAA, 0x00, // reset BAT+ID
            0x00, 0x00, 0x00, // GETIDs
        ];
        let mut fake = FakePs2::new(&replies);
        let (hw, proto) = negotiate_protocol(&mut fake);
        if hw != PsmouseHardware::Generic || proto != PsmouseProtocol::Standard {
            return TestResult::Fail("rate-valued firmware must fall back to Standard");
        }
        if elantech_info().is_some() {
            return TestResult::Fail("no Elantech info may be recorded on signature failure");
        }
        if fake.sent.contains(&0xF8) {
            return TestResult::Fail("register writes must not run after a signature failure");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/psmouse",
        smoke_psmouse_elantech_rejects_rate_version_signature
    );

    fn smoke_psmouse_elantech_detect_v4_knock() -> TestResult {
        // Elantech v4 pad, firmware 46.0F.02: the hw>=4 carve-out
        // accepts the signature, and hw v3+ uses the fast (0xF8)
        // query commands. FW_ID 34-B0-20 gives ranges 1200x800
        // with 24 traces, so width is 1200/23 = 52. No reg 0x10
        // read-back exists on v4.
        let replies = [
            0x00, 0x00, 0x00, // Synaptics GETINFO
            0x00, 0x00, 0x00, // ALPS E6 GETINFO
            0x3C, 0x03, 0xC8, // Elantech magic knock
            0x46, 0x0F, 0x02, // FW version query
            0x00, 0x18, 0x0C, // Capabilities query (24 traces)
            0x00, 0x00, 0x00, // Sample query
            0x34, 0xB0, 0x20, // FW ID query (1200x800)
        ];
        let mut fake = FakePs2::new(&replies);
        let (hw, proto) = negotiate_protocol(&mut fake);
        if hw != PsmouseHardware::Elantech || proto != PsmouseProtocol::Elantech {
            return TestResult::Fail("Elantech v4 pad must negotiate Elantech");
        }
        let Some(info) = elantech_info() else {
            return TestResult::Fail("Elantech info must be recorded after detection");
        };
        if info.hw_version != 4
            || info.fw_version != 0x460f02
            || info.x_max != 1200
            || info.y_max != 800
            || info.width != 52
            || !info.reports_pressure
            || info.crc_enabled
        {
            return TestResult::Fail("Elantech v4 info (ranges/width/flags) wrong");
        }
        let mut want = probe_prefix_sent();
        want.pop(); // Elantech returns before the reset.
        want.extend_from_slice(&sliced_cmd(0x01));
        want.push(0xE9);
        // Fast queries (hw v3+): F8, cmd, GETINFO.
        want.extend_from_slice(&[0xF8, 0x02, 0xE9]);
        want.extend_from_slice(&[0xF8, 0x03, 0xE9]);
        want.extend_from_slice(&[0xF8, 0x00, 0xE9]);
        // Absolute mode, v4: write reg 0x07=0x01
        // (F8 00 F8 07 F8 00 F8 01 E6), no read-back.
        want.extend_from_slice(&[0xF8, 0x00, 0xF8, 0x07, 0xF8, 0x00, 0xF8, 0x01, 0xE6]);
        if fake.sent != want {
            return TestResult::Fail("Elantech v4 detect wire sequence wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/psmouse",
        smoke_psmouse_elantech_detect_v4_knock
    );

    fn smoke_psmouse_elantech_detect_v1_knock() -> TestResult {
        // Elantech v1 pad, firmware 02.00.22 (elantech.rst EF013):
        // sliced register writes (0x10=0x16, 0x11=0x8F) plus a
        // sliced read-back of reg 0x10 showing the absolute-mode
        // bit. Ranges are the v1 constants (544x352).
        let replies = [
            0x00, 0x00, 0x00, // Synaptics GETINFO
            0x00, 0x00, 0x00, // ALPS E6 GETINFO
            0x3C, 0x03, 0xC8, // Elantech magic knock
            0x02, 0x00, 0x22, // FW version query
            0x00, 0x00, 0x00, // Capabilities query
            0x16, 0x00, 0x00, // Reg 0x10 read-back (absolute bit set)
        ];
        let mut fake = FakePs2::new(&replies);
        let (hw, proto) = negotiate_protocol(&mut fake);
        if hw != PsmouseHardware::Elantech || proto != PsmouseProtocol::ElantechV1 {
            return TestResult::Fail("Elantech v1 pad must negotiate ElantechV1");
        }
        let Some(info) = elantech_info() else {
            return TestResult::Fail("Elantech info must be recorded after detection");
        };
        if info.hw_version != 1
            || info.fw_version != 0x020022
            || info.x_max != 544
            || info.y_max != 352
            || info.reports_pressure
            || !info.jumpy_cursor
        {
            return TestResult::Fail("Elantech v1 info (ranges/jumpy) wrong");
        }
        let mut want = probe_prefix_sent();
        want.pop(); // Elantech returns before the reset.
        want.extend_from_slice(&sliced_cmd(0x01));
        want.push(0xE9);
        want.extend_from_slice(&sliced_cmd(0x02));
        want.push(0xE9);
        // Absolute mode, v1: write reg 0x10=0x16 then 0x11=0x8F
        // (sliced WRITE, sliced reg, sliced val, SETSCALE11 each),
        // then read back reg 0x10 (sliced READ, sliced reg, GETINFO).
        for (reg, val) in [(0x10u8, 0x16u8), (0x11u8, 0x8fu8)] {
            want.extend_from_slice(&sliced_cmd(0x11));
            want.extend_from_slice(&sliced_cmd(reg));
            want.extend_from_slice(&sliced_cmd(val));
            want.push(0xE6);
        }
        want.extend_from_slice(&sliced_cmd(0x10));
        want.extend_from_slice(&sliced_cmd(0x10));
        want.push(0xE9);
        if fake.sent != want {
            return TestResult::Fail("Elantech v1 detect wire sequence wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/psmouse",
        smoke_psmouse_elantech_detect_v1_knock
    );

    fn smoke_elantech_v1_decode() -> TestResult {
        // v1 packets, both firmware layouts (verified vectors):
        // new-fw (02.00.22): 1 finger at (300, 200), left pressed.
        let pkt: [u8; 4] = [0x49, 0x04, 0x2C, 0x98];
        if !elantech_packet_check_v1(&pkt, 0x020022) {
            return TestResult::Fail("v1 parity check must pass this packet");
        }
        let mut state = ElantechState::default();
        let Some(frame) = decode_elantech_v1(&mut state, &pkt, 0x020022, 352, false) else {
            return TestResult::Fail("v1 decode must produce a frame");
        };
        if frame.fingers != 1
            || !frame.slots[0].active
            || frame.slots[0].x != 300
            || frame.slots[0].y != 200
            || !frame.left
            || frame.right
        {
            return TestResult::Fail("v1 new-fw decode (fingers/x/y/buttons) wrong");
        }
        // Old-fw (01.00.00): 2 fingers at (100, 50), left pressed.
        let pkt: [u8; 4] = [0x0D, 0x91, 0x64, 0x2E];
        if !elantech_packet_check_v1(&pkt, 0x010000) {
            return TestResult::Fail("v1 old-fw parity check must pass this packet");
        }
        let mut state = ElantechState::default();
        let Some(frame) = decode_elantech_v1(&mut state, &pkt, 0x010000, 352, false) else {
            return TestResult::Fail("v1 old-fw decode must produce a frame");
        };
        if frame.fingers != 2 || frame.slots[0].x != 100 || frame.slots[0].y != 50 {
            return TestResult::Fail("v1 old-fw decode (fingers/x/y) wrong");
        }
        // One flipped parity bit fails the check.
        if elantech_packet_check_v1(&[0x49, 0x04, 0x2C, 0x99], 0x020022) {
            return TestResult::Fail("v1 parity check must fail a corrupted packet");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/psmouse", smoke_elantech_v1_decode);

    fn smoke_elantech_v2_decode() -> TestResult {
        // 1 finger at (1000, 500), pressure 0xAB, width 5, left.
        let pkt: [u8; 6] = [0x55, 0xA3, 0xE8, 0x12, 0xB1, 0x0C];
        if !elantech_packet_check_v2(&pkt, true) {
            return TestResult::Fail("v2 pressure check must pass this packet");
        }
        let mut state = ElantechState::default();
        let frame = decode_elantech_v2(&mut state, &pkt, 768);
        if frame.fingers != 1
            || frame.slots[0].x != 1000
            || frame.slots[0].y != 500
            || frame.pressure != 0xAB
            || frame.width != 5
            || !frame.left
        {
            return TestResult::Fail("v2 1-finger decode (x/y/pres/width/buttons) wrong");
        }
        // 2 fingers at (400, 600) and (800, 300); fixed pres/width.
        let pkt: [u8; 6] = [0x85, 0x64, 0x2A, 0x02, 0xC8, 0x75];
        if !elantech_packet_check_v2(&pkt, true) {
            return TestResult::Fail("v2 2-finger check must pass this packet");
        }
        let mut state = ElantechState::default();
        let frame = decode_elantech_v2(&mut state, &pkt, 768);
        if frame.fingers != 2
            || frame.slots[0].x != 400
            || frame.slots[0].y != 600
            || frame.slots[1].x != 800
            || frame.slots[1].y != 300
            || frame.pressure != 127
            || frame.width != 7
        {
            return TestResult::Fail("v2 2-finger decode wrong");
        }
        // 4 fingers: fingers field 3 with byte 3 bit 7 set.
        let pkt: [u8; 6] = [0xD5, 0xA3, 0xE8, 0x92, 0xB1, 0x0C];
        if !elantech_packet_check_v2(&pkt, true) {
            return TestResult::Fail("v2 4-finger check must pass this packet");
        }
        let mut state = ElantechState::default();
        let frame = decode_elantech_v2(&mut state, &pkt, 768);
        if frame.fingers != 4 || frame.slots[0].x != 1000 || frame.slots[0].y != 500 {
            return TestResult::Fail("v2 4-finger decode wrong");
        }
        // Old non-pressure firmware layout (fw 02.00.30, EF113).
        let pkt: [u8; 6] = [0x7D, 0x03, 0xE8, 0x38, 0x01, 0x0C];
        if !elantech_packet_check_v2(&pkt, false) {
            return TestResult::Fail("v2 old-fw check must pass this packet");
        }
        let mut state = ElantechState::default();
        let frame = decode_elantech_v2(&mut state, &pkt, 768);
        if frame.fingers != 1 || frame.slots[0].x != 1000 || frame.slots[0].y != 500 {
            return TestResult::Fail("v2 old-fw decode wrong");
        }
        // The exact debounce packet is recognised as such.
        if !elantech_is_debounce_v2(&[0x84, 0xFF, 0xFF, 0x02, 0xFF, 0xFF]) {
            return TestResult::Fail("v2 debounce packet must be recognised");
        }
        if elantech_is_debounce_v2(&[0x55, 0xA3, 0xE8, 0x12, 0xB1, 0x0C]) {
            return TestResult::Fail("a live v2 packet must not be debounce");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/psmouse", smoke_elantech_v2_decode);

    fn smoke_elantech_v3_decode() -> TestResult {
        // Two-finger head packet only stashes finger A (600, 700).
        let head: [u8; 6] = [0x85, 0x52, 0x58, 0x02, 0x60, 0x64];
        if elantech_packet_check_v3(&head, false) != ElantechPacket::V3Head {
            return TestResult::Fail("v3 head packet must classify as V3Head");
        }
        let mut state = ElantechState::default();
        if decode_elantech_v3(&mut state, &head, ElantechPacket::V3Head, 800, false).is_some() {
            return TestResult::Fail("v3 head packet must not produce a frame");
        }
        if !state.v3_head_pending {
            return TestResult::Fail("v3 head packet must stash its finger");
        }
        // Tail packet completes the pair: (600, 700) + (900, 400).
        let tail: [u8; 6] = [0x8D, 0x73, 0x84, 0x0C, 0x81, 0x90];
        if elantech_packet_check_v3(&tail, false) != ElantechPacket::V3Tail {
            return TestResult::Fail("v3 tail packet must classify as V3Tail");
        }
        let Some(frame) = decode_elantech_v3(&mut state, &tail, ElantechPacket::V3Tail, 800, false)
        else {
            return TestResult::Fail("v3 tail packet must produce a frame");
        };
        if frame.fingers != 2
            || frame.slots[0].x != 600
            || frame.slots[0].y != 700
            || frame.slots[1].x != 900
            || frame.slots[1].y != 400
        {
            return TestResult::Fail("v3 head/tail decode wrong");
        }
        // One finger rides a single head-type packet.
        let pkt: [u8; 6] = [0x45, 0x53, 0xE8, 0x02, 0x02, 0x58];
        if elantech_packet_check_v3(&pkt, false) != ElantechPacket::V3Head {
            return TestResult::Fail("v3 1-finger packet must classify as V3Head");
        }
        let mut state = ElantechState::default();
        let Some(frame) = decode_elantech_v3(&mut state, &pkt, ElantechPacket::V3Head, 800, false)
        else {
            return TestResult::Fail("v3 1-finger packet must produce a frame");
        };
        if frame.fingers != 1 || frame.slots[0].x != 1000 || frame.slots[0].y != 200 {
            return TestResult::Fail("v3 1-finger decode wrong");
        }
        // Debounce, CRC signatures, and the trackpoint signature.
        if elantech_packet_check_v3(&[0xC4, 0xFF, 0xFF, 0x02, 0xFF, 0xFF], false)
            != ElantechPacket::Debounce
        {
            return TestResult::Fail("v3 debounce packet must classify as Debounce");
        }
        if elantech_packet_check_v3(&[0x45, 0x53, 0xE8, 0x08, 0x02, 0x58], true)
            != ElantechPacket::V3Head
        {
            return TestResult::Fail("v3 CRC head signature must classify as V3Head");
        }
        if elantech_packet_check_v3(&[0x45, 0x53, 0xE8, 0x09, 0x02, 0x58], true)
            != ElantechPacket::V3Tail
        {
            return TestResult::Fail("v3 CRC tail signature must classify as V3Tail");
        }
        if elantech_packet_check_v3(&[0x45, 0x53, 0xE8, 0x06, 0x02, 0x58], false)
            != ElantechPacket::Trackpoint
        {
            return TestResult::Fail("v3 trackpoint signature must classify as Trackpoint");
        }
        if elantech_packet_check_v3(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00], false)
            != ElantechPacket::Unknown
        {
            return TestResult::Fail("garbage must classify as Unknown");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/psmouse", smoke_elantech_v3_decode);

    fn smoke_elantech_v4_decode() -> TestResult {
        // Head: slot 0 at (1000, 200), pressure 0x9A, 3 traces.
        let head: [u8; 6] = [0x30, 0x93, 0xE8, 0x31, 0xA2, 0x58];
        if elantech_packet_check_v4(&head, false, 0x460f02, 0, false) != ElantechPacket::V4Head {
            return TestResult::Fail("v4 head packet must classify as V4Head");
        }
        let mut state = ElantechState::default();
        let Some(frame) =
            decode_elantech_v4(&mut state, &head, ElantechPacket::V4Head, 800, 52, false)
        else {
            return TestResult::Fail("v4 head packet must produce a frame");
        };
        if frame.fingers != 1
            || frame.slots[0].x != 1000
            || frame.slots[0].y != 200
            || frame.slots[0].pressure != 0x9A
            || frame.slots[0].width != 156
        {
            return TestResult::Fail("v4 head decode (x/y/pres/width) wrong");
        }
        // Motion: slot 0 dx=+10, dy=-5 -> (1010, 205).
        let motion: [u8; 6] = [0x20, 0x0A, 0xFB, 0x32, 0x00, 0x00];
        if elantech_packet_check_v4(&motion, false, 0x460f02, 0, false) != ElantechPacket::V4Motion
        {
            return TestResult::Fail("v4 motion packet must classify as V4Motion");
        }
        let Some(frame) = decode_elantech_v4(
            &mut state,
            &motion,
            ElantechPacket::V4Motion,
            800,
            52,
            false,
        ) else {
            return TestResult::Fail("v4 motion packet must produce a frame");
        };
        if frame.slots[0].x != 1010 || frame.slots[0].y != 205 {
            return TestResult::Fail("v4 motion decode wrong");
        }
        // Status: no fingers down — slot 0 releases.
        let status: [u8; 6] = [0x00, 0x00, 0x00, 0x10, 0x00, 0x00];
        if elantech_packet_check_v4(&status, false, 0x460f02, 0, false) != ElantechPacket::V4Status
        {
            return TestResult::Fail("v4 status packet must classify as V4Status");
        }
        let Some(frame) = decode_elantech_v4(
            &mut state,
            &status,
            ElantechPacket::V4Status,
            800,
            52,
            false,
        ) else {
            return TestResult::Fail("v4 status packet must produce a frame");
        };
        if frame.fingers != 0 || frame.slots[0].active {
            return TestResult::Fail("v4 status decode must release slot 0");
        }
        // A packet type of 3 is unknown, and a head packet naming
        // slot 5 (id bits 110) decodes to nothing.
        if elantech_packet_check_v4(
            &[0x30, 0x93, 0xE8, 0x33, 0xA2, 0x58],
            false,
            0x460f02,
            0,
            false,
        ) != ElantechPacket::Unknown
        {
            return TestResult::Fail("v4 type 3 must classify as Unknown");
        }
        let bad_head: [u8; 6] = [0x30, 0x93, 0xE8, 0xD1, 0xA2, 0x58];
        if elantech_packet_check_v4(&bad_head, false, 0x460f02, 0, false) != ElantechPacket::V4Head
        {
            return TestResult::Fail("v4 slot-5 head must still classify as V4Head");
        }
        if decode_elantech_v4(
            &mut state,
            &bad_head,
            ElantechPacket::V4Head,
            800,
            52,
            false,
        )
        .is_some()
        {
            return TestResult::Fail("v4 head naming slot 5 must decode to nothing");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/psmouse", smoke_elantech_v4_decode);
}

// ─── RMI4-over-SMBus transport smoke tests ──────────────────────────
//
// The fake below is a miniature RMI4-over-SMBus device: a 256-byte
// page-0 register image, a protocol-version byte, and a v2 mapping
// table it maintains from the host's mapping writes — so the
// transport's framing is validated against device behaviour, not
// against its own constants.

mod smbus_rmi_smokes {
    use alloc::vec::Vec;
    use narf_drivers_platform::smbus::SmbusError;
    use narf_input::{
        __reset_global_ring_for_test, init_global_ring, pop_pointer, pop_touch, PointerButtons,
        TouchState,
    };
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    use crate::rmi4_core::{decode_f12_data1, probe_device, Rmi4PumpState, Rmi4Transport};
    use crate::smbus_rmi::{
        probe_at, probe_at_with_state, SmbusIo, SmbusRmiTransport, SmbusRmiVersion,
        SMBUS_RMI_DEFAULT_ADDR,
    };
    use crate::smbus_rmi_attn::{f01_bringup, service_attn};

    /// Operation codes for the fake's read/write logs.
    const OP_READ_BYTE: u8 = 0;
    const OP_WRITE_BYTE: u8 = 1;
    const OP_READ_WORD: u8 = 2;
    const OP_WRITE_WORD: u8 = 3;
    const OP_READ_BLOCK: u8 = 4;
    const OP_WRITE_BLOCK: u8 = 5;

    /// Faithful miniature RMI4-over-SMBus device (see the module
    /// docs). Page-0 only; reads on any other page return zero.
    #[derive(Debug)]
    struct FakeSmbus {
        mem: IrqSafeSpinLock<[u8; 256]>,
        page: IrqSafeSpinLock<u8>,
        version: u8,
        map: IrqSafeSpinLock<[(u16, u8); 8]>,
        writes: IrqSafeSpinLock<Vec<(u8, u8, Vec<u8>)>>,
        reads: IrqSafeSpinLock<Vec<(u8, u8)>>,
    }

    impl FakeSmbus {
        fn new(mem: [u8; 256], version: u8) -> Self {
            Self {
                mem: IrqSafeSpinLock::new(mem),
                page: IrqSafeSpinLock::new(0),
                version,
                map: IrqSafeSpinLock::new([(0, 0); 8]),
                writes: IrqSafeSpinLock::new(Vec::new()),
                reads: IrqSafeSpinLock::new(Vec::new()),
            }
        }

        fn read_mem(&self, addr: u16) -> u8 {
            if *self.page.lock() != 0 || addr >= 256 {
                return 0;
            }
            self.mem.lock()[addr as usize]
        }

        fn write_mem(&self, addr: u16, value: u8) {
            if *self.page.lock() != 0 || addr >= 256 {
                return;
            }
            self.mem.lock()[addr as usize] = value;
        }
    }

    impl SmbusIo for FakeSmbus {
        fn read_byte_data(&self, _addr: u8, cmd: u8) -> Result<u8, SmbusError> {
            self.reads.lock().push((OP_READ_BYTE, cmd));
            if cmd == 0xFD {
                return Ok(self.version);
            }
            Ok(self.read_mem(cmd as u16))
        }
        fn write_byte_data(&self, _addr: u8, cmd: u8, value: u8) -> Result<(), SmbusError> {
            self.writes
                .lock()
                .push((OP_WRITE_BYTE, cmd, alloc::vec![value]));
            if cmd == 0xFF {
                *self.page.lock() = value;
                return Ok(());
            }
            self.write_mem(cmd as u16, value);
            Ok(())
        }
        fn read_word_data(&self, _addr: u8, cmd: u8) -> Result<u16, SmbusError> {
            self.reads.lock().push((OP_READ_WORD, cmd));
            let lo = self.read_mem(cmd as u16);
            let hi = self.read_mem(cmd.wrapping_add(1) as u16);
            Ok(u16::from_le_bytes([lo, hi]))
        }
        fn write_word_data(&self, _addr: u8, cmd: u8, value: u16) -> Result<(), SmbusError> {
            self.writes
                .lock()
                .push((OP_WRITE_WORD, cmd, value.to_le_bytes().to_vec()));
            let [lo, hi] = value.to_le_bytes();
            self.write_mem(cmd as u16, lo);
            self.write_mem(cmd.wrapping_add(1) as u16, hi);
            Ok(())
        }
        fn read_block_data(&self, _addr: u8, cmd: u8, buf: &mut [u8]) -> Result<usize, SmbusError> {
            self.reads.lock().push((OP_READ_BLOCK, cmd));
            if cmd >= 8 {
                return Err(SmbusError::Failed);
            }
            let (rmiaddr, count) = self.map.lock()[cmd as usize];
            if count as usize > buf.len() {
                return Err(SmbusError::Failed);
            }
            for i in 0..count as usize {
                buf[i] = self.read_mem(rmiaddr.wrapping_add(i as u16));
            }
            Ok(count as usize)
        }
        fn write_block_data(&self, _addr: u8, cmd: u8, data: &[u8]) -> Result<(), SmbusError> {
            self.writes
                .lock()
                .push((OP_WRITE_BLOCK, cmd, data.to_vec()));
            if cmd >= 0x80 {
                // Mapping-table write: [cmd, rmiaddr_lo,
                // rmiaddr_hi, readcount, flags].
                if data.len() != 5 || data[0] != cmd {
                    return Err(SmbusError::Failed);
                }
                let rmiaddr = u16::from_le_bytes([data[1], data[2]]);
                self.map.lock()[(cmd - 0x80) as usize] = (rmiaddr, data[3]);
                return Ok(());
            }
            // Data write: data[0] echoes the command code.
            if cmd >= 8 || data.is_empty() || data[0] != cmd {
                return Err(SmbusError::Failed);
            }
            let (rmiaddr, _) = self.map.lock()[cmd as usize];
            for (i, b) in data.iter().skip(1).enumerate() {
                self.write_mem(rmiaddr.wrapping_add(i as u16), *b);
            }
            Ok(())
        }
    }

    /// Standard Synaptics page-0 image shared by the fixtures:
    /// PDT entries (F$12 @ 0xE9, F$01 @ 0xE3, F$30 @ 0xDD,
    /// terminator @ 0xD7), the F$01 query (manufacturer 1) at
    /// 0x10, the F$30 query (8 lines) at 0x20, and one F$12
    /// finger object at data base 0x03.
    fn synaptics_page0() -> [u8; 256] {
        let mut mem = [0u8; 256];
        // Entry layout: [query, cmd, ctrl, data, intr|ver, func].
        mem[0xE9..0xEF].copy_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x01, 0x12]);
        mem[0xE3..0xE9].copy_from_slice(&[0x10, 0x11, 0x12, 0x13, 0x01, 0x01]);
        mem[0xDD..0xE3].copy_from_slice(&[0x20, 0x21, 0x22, 0x23, 0x01, 0x30]);
        // Terminator at 0xD7 stays zero (function 0x00).
        mem[0x10..0x1B].copy_from_slice(&[
            0x01, 0x00, 0x02, 0x01, 0x20, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01,
        ]);
        mem[0x20..0x22].copy_from_slice(&[0x48, 0x08]);
        mem[0x03..0x0B].copy_from_slice(&[0x01, 0x00, 0x10, 0x00, 0x20, 0x80, 0x05, 0x06]);
        mem
    }

    /// ATTN-fixture page-0 image with non-overlapping register
    /// blocks. The shared [`synaptics_page0`] packs the F$12
    /// data block against the F$01 query, so a 5-object
    /// (40-byte) F$12 read would decode query bytes as phantom
    /// fingers; this image lays the blocks out separately:
    /// PDT entries (F$12 @ 0xE9, F$01 @ 0xE3, F$30 @ 0xDD,
    /// terminator @ 0xD7), the F$01 query (manufacturer 1) at
    /// 0x10, the F$30 query (8 lines) at 0x20, F$01 data
    /// (device status 0x13, interrupt status 0x14), F$12 Data 1
    /// (5 objects) at 0x40, F$30 data at 0x70. `status` is the
    /// F$01 interrupt-status byte; `f30_data` the F$30 button
    /// bitmap (active-low).
    fn attn_page0(status: u8, f30_data: u8) -> [u8; 256] {
        let mut mem = [0u8; 256];
        // Entry layout: [query, cmd, ctrl, data, intr|ver, func].
        mem[0xE9..0xEF].copy_from_slice(&[0x00, 0x01, 0x02, 0x40, 0x01, 0x12]);
        mem[0xE3..0xE9].copy_from_slice(&[0x10, 0x11, 0x12, 0x13, 0x01, 0x01]);
        mem[0xDD..0xE3].copy_from_slice(&[0x20, 0x21, 0x22, 0x70, 0x01, 0x30]);
        // Terminator at 0xD7 stays zero (function 0x00).
        mem[0x10..0x1B].copy_from_slice(&[
            0x01, 0x00, 0x02, 0x01, 0x20, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01,
        ]);
        mem[0x20..0x22].copy_from_slice(&[0x48, 0x08]);
        // One F$12 finger object at data base 0x40; the other
        // four object slots stay zero (no object).
        mem[0x40..0x48].copy_from_slice(&[0x01, 0x00, 0x10, 0x00, 0x20, 0x80, 0x05, 0x06]);
        mem[0x14] = status;
        mem[0x70] = f30_data;
        mem
    }

    fn smoke_smbus_rmi_v1_probe_and_pdt_walk() -> TestResult {
        let fake = FakeSmbus::new(synaptics_page0(), 0x00); // v1
        let (version, probe) = match probe_at(&fake, SMBUS_RMI_DEFAULT_ADDR) {
            Some(p) => p,
            None => return TestResult::Fail("v1 probe declined the Synaptics image"),
        };
        if version != SmbusRmiVersion::V1 {
            return TestResult::Fail("version byte 0x00 must negotiate v1");
        }
        if !probe.product.is_synaptics() {
            return TestResult::Fail("probe product is not Synaptics");
        }
        if probe.f12.is_none() || probe.f30.is_none() {
            return TestResult::Fail("probe missed F$12 or F$30");
        }
        if probe.f11.is_some() {
            return TestResult::Fail("image has no F$11");
        }
        // Page-select write ({0xFF, 0x00}) must precede the reads.
        let writes = fake.writes.lock();
        if !writes
            .iter()
            .any(|(op, cmd, data)| *op == OP_WRITE_BYTE && *cmd == 0xFF && data == &[0])
        {
            return TestResult::Fail("v1 probe must page-select to 0");
        }
        // The 6-byte PDT entry at 0xE9 is assembled from word
        // reads at 0xE9 / 0xEB / 0xED (no plain block-read op on
        // the ICH host — see the transport docs).
        let reads = fake.reads.lock();
        for cmd in [0xE9u8, 0xEB, 0xED] {
            if !reads.iter().any(|(op, c)| *op == OP_READ_WORD && *c == cmd) {
                return TestResult::Fail("PDT entry must be read as words at 0xE9/0xEB/0xED");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/smbus-rmi",
        smoke_smbus_rmi_v1_probe_and_pdt_walk
    );

    fn smoke_smbus_rmi_v1_read_write_round_trip() -> TestResult {
        let fake = FakeSmbus::new(synaptics_page0(), 0x00); // v1
        let mut t = SmbusRmiTransport::new(&fake, SMBUS_RMI_DEFAULT_ADDR);
        // Reads/writes before version negotiation are refused.
        let mut tmp = [0u8; 1];
        if t.read_block(0x40, &mut tmp).is_ok() {
            return TestResult::Fail("read before probe_version must fail");
        }
        if t.probe_version().is_err() {
            return TestResult::Fail("probe_version failed on the v1 image");
        }
        if t.write_block(0x40, &[0xAA, 0xBB, 0xCC]).is_err() {
            return TestResult::Fail("v1 write failed");
        }
        let mut back = [0u8; 3];
        if t.read_block(0x40, &mut back).is_err() {
            return TestResult::Fail("v1 read failed");
        }
        if back != [0xAA, 0xBB, 0xCC] {
            return TestResult::Fail("v1 write/read round trip mismatch");
        }
        // The 3-byte write is three byte-data writes to
        // incrementing addresses (no plain multi-byte write op).
        let writes = fake.writes.lock();
        let byte_writes: Vec<(u8, u8)> = writes
            .iter()
            .filter(|(op, cmd, _)| *op == OP_WRITE_BYTE && *cmd >= 0x40 && *cmd <= 0x42)
            .map(|(_, cmd, data)| (*cmd, data[0]))
            .collect();
        if byte_writes != alloc::vec![(0x40, 0xAA), (0x41, 0xBB), (0x42, 0xCC)] {
            return TestResult::Fail("v1 multi-byte write must be sequential byte writes");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/smbus-rmi",
        smoke_smbus_rmi_v1_read_write_round_trip
    );

    fn smoke_smbus_rmi_v2_mapping_table_and_block_read() -> TestResult {
        let fake = FakeSmbus::new(synaptics_page0(), 0x01); // v2
        let (version, probe) = match probe_at(&fake, SMBUS_RMI_DEFAULT_ADDR) {
            Some(p) => p,
            None => return TestResult::Fail("v2 probe declined the Synaptics image"),
        };
        if version != SmbusRmiVersion::V2 {
            return TestResult::Fail("version byte 0x01 must negotiate v2");
        }
        if probe.f12.is_none() {
            return TestResult::Fail("v2 probe missed F$12");
        }
        // First mapping write programs slot 0 for the PDT read
        // at 0xE9 (6 bytes): [0x80, 0xE9, 0x00, 0x06, 0x01].
        let writes = fake.writes.lock();
        if !writes.iter().any(|(op, cmd, data)| {
            *op == OP_WRITE_BLOCK && *cmd == 0x80 && data == &[0x80, 0xE9, 0x00, 0x06, 0x01]
        }) {
            return TestResult::Fail("first v2 mapping write wrong");
        }
        let n_slot0 = writes
            .iter()
            .filter(|(op, cmd, _)| *op == OP_WRITE_BLOCK && *cmd == 0x80)
            .count();
        drop(writes);
        // A repeat read of the same (address, length) through
        // one transport reuses slot 0 — no second mapping write
        // for it.
        let mut t = SmbusRmiTransport::new(&fake, SMBUS_RMI_DEFAULT_ADDR);
        if t.probe_version().is_err() {
            return TestResult::Fail("v2 probe_version failed on repeat");
        }
        let mut buf = [0u8; 6];
        if t.read_block(0xE9, &mut buf).is_err() {
            return TestResult::Fail("v2 repeat read failed");
        }
        if buf != [0x00, 0x01, 0x02, 0x03, 0x01, 0x12] {
            return TestResult::Fail("v2 repeat read returned the wrong PDT entry");
        }
        let writes = fake.writes.lock();
        let n_slot0_after = writes
            .iter()
            .filter(|(op, cmd, _)| *op == OP_WRITE_BLOCK && *cmd == 0x80)
            .count();
        if n_slot0_after != n_slot0 + 1 {
            return TestResult::Fail("first repeat read must program slot 0 once");
        }
        drop(writes);
        if t.read_block(0xE9, &mut buf).is_err() {
            return TestResult::Fail("v2 second repeat read failed");
        }
        let writes = fake.writes.lock();
        let n_slot0_final = writes
            .iter()
            .filter(|(op, cmd, _)| *op == OP_WRITE_BLOCK && *cmd == 0x80)
            .count();
        if n_slot0_final != n_slot0_after {
            return TestResult::Fail("second repeat read must reuse the mapping slot");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/smbus-rmi",
        smoke_smbus_rmi_v2_mapping_table_and_block_read
    );

    fn smoke_smbus_rmi_v2_write_chunks_at_31() -> TestResult {
        let fake = FakeSmbus::new(synaptics_page0(), 0x01); // v2
        let mut t = SmbusRmiTransport::new(&fake, SMBUS_RMI_DEFAULT_ADDR);
        if t.probe_version().is_err() {
            return TestResult::Fail("v2 probe_version failed");
        }
        // 40 bytes → chunks of 31 + 9 (the echoed command code
        // is the 32nd block byte).
        if t.write_block(0x03, &[0x55; 40]).is_err() {
            return TestResult::Fail("v2 write failed");
        }
        let writes = fake.writes.lock();
        let data_writes: Vec<&(u8, u8, Vec<u8>)> = writes
            .iter()
            .filter(|(op, cmd, _)| *op == OP_WRITE_BLOCK && *cmd < 8)
            .collect();
        if data_writes.len() != 2 {
            return TestResult::Fail("40-byte v2 write must be two block writes");
        }
        if data_writes[0].2.len() != 32 || data_writes[1].2.len() != 10 {
            return TestResult::Fail("v2 write chunks must be 32 and 10 bytes on the wire");
        }
        if data_writes[0].2[0] != data_writes[0].1 || data_writes[1].2[0] != data_writes[1].1 {
            return TestResult::Fail("v2 block writes must echo the command code first");
        }
        drop(writes);
        // The fake device applied both chunks to its image.
        let mem = fake.mem.lock();
        if mem[0x03..0x2B].iter().any(|b| *b != 0x55) {
            return TestResult::Fail("v2 write did not land in the device image");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/smbus-rmi",
        smoke_smbus_rmi_v2_write_chunks_at_31
    );

    fn smoke_smbus_rmi_rejects_unknown_version_and_vendor() -> TestResult {
        // Version byte 0x05 → version 6: unrecognised.
        let fake = FakeSmbus::new(synaptics_page0(), 0x05);
        if probe_at(&fake, SMBUS_RMI_DEFAULT_ADDR).is_some() {
            return TestResult::Fail("unknown SMBus version must be declined");
        }
        // Non-Synaptics manufacturer (0x42) is declined even
        // though the PDT walk succeeds.
        let mut mem = synaptics_page0();
        mem[0x10] = 0x42;
        let fake = FakeSmbus::new(mem, 0x00);
        if probe_at(&fake, SMBUS_RMI_DEFAULT_ADDR).is_some() {
            return TestResult::Fail("non-Synaptics device must be declined");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/smbus-rmi",
        smoke_smbus_rmi_rejects_unknown_version_and_vendor
    );

    fn smoke_smbus_rmi_f12_data_decode() -> TestResult {
        let fake = FakeSmbus::new(synaptics_page0(), 0x00); // v1
        let mut t = SmbusRmiTransport::new(&fake, SMBUS_RMI_DEFAULT_ADDR);
        if t.probe_version().is_err() {
            return TestResult::Fail("v1 probe_version failed");
        }
        let probe = match probe_device(&mut t) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("PDT walk failed on the v1 image"),
        };
        let f12 = match probe.f12 {
            Some(f) => f,
            None => return TestResult::Fail("probe missed F$12"),
        };
        let mut buf = [0u8; 8];
        if t.read_block(f12.data_base as u16, &mut buf).is_err() {
            return TestResult::Fail("F$12 data read failed");
        }
        let objs = match decode_f12_data1(&buf, 1) {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("F$12 decode failed"),
        };
        if objs.len() != 1 || !objs[0].present || !objs[0].is_touching_finger() {
            return TestResult::Fail("expected one touching finger");
        }
        if objs[0].x != 0x1000 || objs[0].y != 0x2000 || objs[0].z != 0x80 {
            return TestResult::Fail("F$12 object coordinates wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/smbus-rmi", smoke_smbus_rmi_f12_data_decode);

    // ── ATTN pump (issue #1682) ─────────────────────────────────
    //
    // The fake device is the attention source here: the F$01
    // interrupt-status byte at 0x14 plays the role of the ATTN
    // line (set bit = line asserted), and the F$12 / F$30 data
    // registers hold the report the pump must deliver. No GPIO
    // or IRQ hardware is involved — the routing layer is
    // exercised by the pump task on real firmware, while
    // `service_attn` (the unit under test) is transport-neutral
    // and runs end-to-end against the fake.

    fn smoke_smbus_rmi_attn_f12_finger_down_and_lift() -> TestResult {
        // F$12 source set (bit 0), no buttons (all lines high).
        let fake = FakeSmbus::new(attn_page0(0x01, 0xFF), 0x00); // v1
        let (_version, probe) = match probe_at(&fake, SMBUS_RMI_DEFAULT_ADDR) {
            Some(p) => p,
            None => return TestResult::Fail("v1 probe declined the Synaptics image"),
        };
        init_global_ring(16);
        __reset_global_ring_for_test();
        let mut t = SmbusRmiTransport::new(&fake, SMBUS_RMI_DEFAULT_ADDR);
        if t.probe_version().is_err() {
            return TestResult::Fail("v1 probe_version failed");
        }
        let mut state = Rmi4PumpState::new();
        let n_reads_before = fake.reads.lock().len();
        let pushed = match service_attn(&mut t, &probe, &mut state, None) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("ATTN service failed"),
        };
        if pushed < 1 {
            return TestResult::Fail("ATTN service pushed 0 events");
        }
        match pop_touch() {
            Some(t) if t.state == TouchState::Down && t.x == 0x1000 && t.y == 0x2000 => {}
            Some(_) => return TestResult::Fail("expected Down at 0x1000/0x2000"),
            None => return TestResult::Fail("no TouchEvent in ring after ATTN"),
        }
        // The service's first bus read after the probe must be
        // the F$01 interrupt-status byte at data_base + 1
        // (0x14) — not the device-status byte at 0x13.
        let reads = fake.reads.lock();
        let post_probe = &reads[n_reads_before..];
        if post_probe.first() != Some(&(OP_READ_BYTE, 0x14)) {
            return TestResult::Fail(
                "ATTN service must read the F$01 interrupt status at 0x14 first",
            );
        }
        drop(reads);
        // Lift: clear the finger object, keep the F$12 source
        // set — the next ATTN must surface an Up.
        fake.mem.lock()[0x40] = 0x00;
        if service_attn(&mut t, &probe, &mut state, None).is_err() {
            return TestResult::Fail("lift ATTN service failed");
        }
        match pop_touch() {
            Some(t) if t.state == TouchState::Up => {}
            Some(_) => return TestResult::Fail("expected Up after finger lift"),
            None => return TestResult::Fail("no TouchEvent in ring after lift ATTN"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/smbus-rmi",
        smoke_smbus_rmi_attn_f12_finger_down_and_lift
    );

    fn smoke_smbus_rmi_attn_f30_button_only() -> TestResult {
        // F$30 source set (bit 2), GPIO 0 low = clickpad pressed.
        let fake = FakeSmbus::new(attn_page0(0x04, 0xFE), 0x00); // v1
        let (_version, probe) = match probe_at(&fake, SMBUS_RMI_DEFAULT_ADDR) {
            Some(p) => p,
            None => return TestResult::Fail("v1 probe declined the Synaptics image"),
        };
        init_global_ring(16);
        __reset_global_ring_for_test();
        let mut t = SmbusRmiTransport::new(&fake, SMBUS_RMI_DEFAULT_ADDR);
        if t.probe_version().is_err() {
            return TestResult::Fail("v1 probe_version failed");
        }
        let mut state = Rmi4PumpState::new();
        if service_attn(&mut t, &probe, &mut state, None).is_err() {
            return TestResult::Fail("button ATTN service failed");
        }
        // Buttons-only ATTN: no touch events, but BTN_LEFT must
        // still reach the ring as a PointerEvent (the HID pump
        // drops this frame; the SMBus pump delivers it).
        if pop_touch().is_some() {
            return TestResult::Fail("button-only ATTN must not push TouchEvents");
        }
        match pop_pointer() {
            Some(p) if p.buttons == PointerButtons::LEFT => {}
            Some(_) => return TestResult::Fail("expected LEFT button"),
            None => return TestResult::Fail("no PointerEvent in ring after button ATTN"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/smbus-rmi",
        smoke_smbus_rmi_attn_f30_button_only
    );

    fn smoke_smbus_rmi_attn_no_sources_is_noop() -> TestResult {
        let fake = FakeSmbus::new(attn_page0(0x00, 0xFF), 0x00); // v1
        let (_version, probe) = match probe_at(&fake, SMBUS_RMI_DEFAULT_ADDR) {
            Some(p) => p,
            None => return TestResult::Fail("v1 probe declined the Synaptics image"),
        };
        init_global_ring(16);
        __reset_global_ring_for_test();
        let mut t = SmbusRmiTransport::new(&fake, SMBUS_RMI_DEFAULT_ADDR);
        if t.probe_version().is_err() {
            return TestResult::Fail("v1 probe_version failed");
        }
        let mut state = Rmi4PumpState::new();
        let n_reads_before = fake.reads.lock().len();
        let pushed = match service_attn(&mut t, &probe, &mut state, None) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("zero-source ATTN service failed"),
        };
        if pushed != 0 {
            return TestResult::Fail("zero-source ATTN must push nothing");
        }
        if pop_touch().is_some() || pop_pointer().is_some() {
            return TestResult::Fail("zero-source ATTN must leave the ring empty");
        }
        // Only the one status-byte read after the probe — no
        // F$12 / F$30 data reads on a spurious wake.
        let reads = fake.reads.lock();
        if reads[n_reads_before..] != [(OP_READ_BYTE, 0x14)] {
            return TestResult::Fail("zero-source ATTN must issue exactly one status read");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/smbus-rmi",
        smoke_smbus_rmi_attn_no_sources_is_noop
    );

    fn smoke_smbus_rmi_attn_v2_state_roundtrip() -> TestResult {
        let fake = FakeSmbus::new(attn_page0(0x00, 0xFF), 0x01); // v2
        let (version, _probe, state) = match probe_at_with_state(&fake, SMBUS_RMI_DEFAULT_ADDR) {
            Some(p) => p,
            None => return TestResult::Fail("v2 probe declined the Synaptics image"),
        };
        if version != SmbusRmiVersion::V2 {
            return TestResult::Fail("version byte 0x01 must negotiate v2");
        }
        // Mapping-table program writes (block writes to
        // 0x80..0x87) after the probe.
        let map_writes = || {
            fake.writes
                .lock()
                .iter()
                .filter(|(op, cmd, _)| *op == OP_WRITE_BLOCK && *cmd >= 0x80)
                .count()
        };
        let n0 = map_writes();
        // First F$12 read from the captured state programs the
        // slots for (0x40, 32) and (0x60, 8).
        let mut t = SmbusRmiTransport::from_state(&fake, SMBUS_RMI_DEFAULT_ADDR, state);
        let mut buf = [0u8; 40];
        if t.read_block(0x40, &mut buf).is_err() {
            return TestResult::Fail("v2 F$12 read failed");
        }
        if decode_f12_data1(&buf, 1).is_err() {
            return TestResult::Fail("v2 F$12 data did not decode");
        }
        let state2 = t.into_state();
        let n1 = map_writes();
        if n1 <= n0 {
            return TestResult::Fail("first F$12 read must program mapping slots");
        }
        // Second pass from the round-tripped state reuses both
        // slots — no further mapping-table programs.
        let mut t2 = SmbusRmiTransport::from_state(&fake, SMBUS_RMI_DEFAULT_ADDR, state2);
        if t2.read_block(0x40, &mut buf).is_err() {
            return TestResult::Fail("v2 repeat F$12 read failed");
        }
        if map_writes() != n1 {
            return TestResult::Fail("repeat F$12 read must reuse the mapping slots");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/smbus-rmi",
        smoke_smbus_rmi_attn_v2_state_roundtrip
    );

    fn smoke_smbus_rmi_attn_f01_bringup_writes_configured() -> TestResult {
        let fake = FakeSmbus::new(synaptics_page0(), 0x00); // v1
        let (_version, probe) = match probe_at(&fake, SMBUS_RMI_DEFAULT_ADDR) {
            Some(p) => p,
            None => return TestResult::Fail("v1 probe declined the Synaptics image"),
        };
        let mut t = SmbusRmiTransport::new(&fake, SMBUS_RMI_DEFAULT_ADDR);
        if t.probe_version().is_err() {
            return TestResult::Fail("v1 probe_version failed");
        }
        if f01_bringup(&mut t, &probe).is_err() {
            return TestResult::Fail("F$01 bring-up failed");
        }
        // F$01 control base is 0x12; the byte is SLEEP_NORMAL |
        // CONFIGURED = 0x80.
        if fake.mem.lock()[0x12] != 0x80 {
            return TestResult::Fail("F$01 control byte must be 0x80 (configured)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/smbus-rmi",
        smoke_smbus_rmi_attn_f01_bringup_writes_configured
    );
}

// ── ALPS absolute-mode smokes (#1674) ────────────────────────────────────────
//
// Fixture discipline (#746): every packet vector below was built
// from the Linux ALPS spec itself (`alps.txt` v3.19 for v1–v5,
// `drivers/input/mouse/alps.c` v6.6 for v6–v8) and checked
// against an independent Python transcription of the Linux
// formulas — never from the implementation's constants. Two
// vectors the first draft carried were wrong as *wire* packets
// and were corrected here (see the comments): a packet's first
// byte must satisfy the model's `(b0 & mask0) == byte0` check
// that Linux `alps_process_byte` applies to every packet, so
// bits the coordinate macros ignore still have to carry the
// sync pattern — the v3 bitmap packet is `0xCF` (not `0xC0`),
// the v7 TWO packet is `0xC8` (not `0x80`), the v7 IDLE packet
// is `0x48` (not `0x00`), and the v8 packets carry `0x18` in
// bits 3–4 of byte 0.
mod alps_smokes {
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::alps::*;
    use crate::i8042_mouse;
    use narf_input::{
        __reset_global_ring_for_test, abs, init_global_ring, pop_global, InputEvent,
        PointerButtons, TouchState,
    };

    /// Fake PS/2 transport: records every sent byte, serves
    /// canned reply bytes in order, auto-ACKs every send (like
    /// a real pad replying `0xFA`). The knock sequences are
    /// fixture-pinned byte-for-byte instead of trusted from the
    /// implementation.
    struct FakeAlpsTransport {
        sent: Vec<u8>,
        replies: Vec<u8>,
        next_reply: usize,
    }

    impl FakeAlpsTransport {
        fn new(replies: &[u8]) -> Self {
            FakeAlpsTransport {
                sent: Vec::new(),
                replies: replies.to_vec(),
                next_reply: 0,
            }
        }

        fn consumed_all(&self) -> bool {
            self.next_reply == self.replies.len()
        }
    }

    impl AlpsTransport for FakeAlpsTransport {
        fn send(&mut self, byte: u8) -> bool {
            self.sent.push(byte);
            true
        }

        fn recv(&mut self) -> Option<u8> {
            let b = self.replies.get(self.next_reply).copied();
            if b.is_some() {
                self.next_reply += 1;
            }
            b
        }
    }

    /// First Touchpad report in a decode, if any.
    fn touchpad_fields(d: AlpsDecode) -> Option<AlpsFields> {
        for ev in d.events.iter().flatten() {
            if let AlpsEvent::Touchpad(f) = *ev {
                return Some(f);
            }
        }
        None
    }

    fn decode(protocol: AlpsProtocol, packet: &[u8]) -> AlpsDecode {
        AlpsDecoder::new(protocol).decode(packet)
    }

    fn feed(packet: &[u8]) {
        for b in packet {
            i8042_mouse::feed_byte_for_test(*b);
        }
    }

    fn reset_ring_and_mouse() {
        init_global_ring(16);
        __reset_global_ring_for_test();
        i8042_mouse::__reset_for_test();
    }

    fn smoke_alps_model_table_lookup() -> TestResult {
        if ALPS_MODEL_TABLE.len() != 21 {
            return TestResult::Fail("model table must carry 21 Linux rows");
        }
        // V1: UMAX-530T.
        let m = match lookup_model(&[0x33, 0x02, 0x0a]) {
            Some(m) => m,
            None => return TestResult::Fail("V1 signature not in table"),
        };
        if m.version != AlpsVersion::V1 || m.byte0 != 0x88 || m.mask0 != 0xf8 {
            return TestResult::Fail("V1 row wrong");
        }
        // V6: Dell XT2.
        let m = match lookup_model(&[0x73, 0x00, 0x14]) {
            Some(m) => m,
            None => return TestResult::Fail("V6 signature not in table"),
        };
        if m.version != AlpsVersion::V6 || m.byte0 != 0xff || m.mask0 != 0xff {
            return TestResult::Fail("V6 row wrong");
        }
        // V2 + wheel: Toshiba Satellite S2400-103.
        let m = match lookup_model(&[0x63, 0x02, 0x3c]) {
            Some(m) => m,
            None => return TestResult::Fail("V2 wheel signature not in table"),
        };
        if m.version != AlpsVersion::V2 || m.flags & FLAG_WHEEL == 0 {
            return TestResult::Fail("V2 wheel row wrong");
        }
        // 73-02-64 is NOT a table row (it falls through to the
        // V4/V3 fallback chain in `identify`).
        if lookup_model(&[0x73, 0x02, 0x64]).is_some() {
            return TestResult::Fail("73-02-64 must not be a table row");
        }
        if lookup_model(&[0x00, 0x00, 0x00]).is_some() {
            return TestResult::Fail("unknown signature must miss");
        }
        // The suspicious first row is kept deliberately (Linux
        // "XXX" comment) — same signature, same flags.
        let m = match lookup_model(&[0x20, 0x02, 0x0e]) {
            Some(m) => m,
            None => return TestResult::Fail("suspicious first row missing"),
        };
        if m.version != AlpsVersion::V2 || m.flags & FLAG_PASS == 0 {
            return TestResult::Fail("suspicious first row wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_model_table_lookup);

    fn smoke_alps_identify_fallbacks() -> TestResult {
        // Table hit wins regardless of the EC report.
        let p = identify(&[0x33, 0x02, 0x0a], &[0x00, 0x00, 0x00]);
        if p.map(|p| p.version) != Some(AlpsVersion::V1) {
            return TestResult::Fail("table hit must win");
        }
        let cases: [([u8; 3], [u8; 3], Option<AlpsVersion>); 9] = [
            (
                [0x73, 0x02, 0x64],
                [0x73, 0x02, 0x8a],
                Some(AlpsVersion::V4),
            ),
            (
                [0x73, 0x03, 0x50],
                [0x73, 0x01, 0x00],
                Some(AlpsVersion::V5),
            ),
            (
                [0x00, 0x00, 0x00],
                [0x88, 0xb0, 0x00],
                Some(AlpsVersion::V7),
            ),
            (
                [0x00, 0x00, 0x00],
                [0x88, 0x08, 0x00],
                Some(AlpsVersion::V3Rushmore),
            ),
            (
                [0x73, 0x02, 0x64],
                [0x88, 0x07, 0x95],
                Some(AlpsVersion::V3),
            ),
            (
                [0x73, 0x03, 0x14],
                [0x73, 0x03, 0x14],
                Some(AlpsVersion::V8),
            ),
            (
                [0x73, 0x03, 0x28],
                [0x73, 0x03, 0x28],
                Some(AlpsVersion::V8),
            ),
            // V9 is identified only to be refused.
            ([0x73, 0x03, 0xc8], [0x73, 0x03, 0xc8], None),
            ([0x00, 0x00, 0x00], [0x00, 0x00, 0x00], None),
        ];
        for (e7, ec, want) in cases {
            let got = identify(&e7, &ec).map(|p| p.version);
            if got != want {
                return TestResult::Fail("identify fallback wrong");
            }
        }
        if !is_ss4plus_device(&[0x73, 0x03, 0x28]) {
            return TestResult::Fail("73-03-28 must be SS4-Plus");
        }
        if is_ss4plus_device(&[0x73, 0x03, 0x14]) {
            return TestResult::Fail("73-03-14 must not be SS4-Plus");
        }
        if !e6_report_valid(&[0x00, 0x00, 0x0a]) || !e6_report_valid(&[0x00, 0x00, 0x64]) {
            return TestResult::Fail("E6 valid replies rejected");
        }
        if e6_report_valid(&[0x00, 0x00, 0x00]) || e6_report_valid(&[0x08, 0x00, 0x0a]) {
            return TestResult::Fail("E6 invalid replies accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_identify_fallbacks);

    fn smoke_alps_probe_wire_v3() -> TestResult {
        // E6 `00-00-0A`, E7 `73-02-64`, EC `88-07-95` — a v3 pad.
        let mut t = FakeAlpsTransport::new(&[0x00, 0x00, 0x0a, 0x73, 0x02, 0x64, 0x88, 0x07, 0x95]);
        let proto = match probe_alps(&mut t) {
            Some(p) => p,
            None => return TestResult::Fail("v3 pad not identified"),
        };
        if proto != ALPS_V3_PROTOCOL {
            return TestResult::Fail("probe must return the v3 protocol");
        }
        // Wire: E6 report, E7 report, EC report, exit (EA).
        // Per alps.txt / #1676 the SETRES argument is the report
        // byte itself (E6/E7/EC), not Linux's literal 0x00.
        let want: [u8; 16] = [
            0xe8, 0xe6, 0xe6, 0xe6, 0xe9, 0xe8, 0xe7, 0xe7, 0xe7, 0xe9, 0xe8, 0xec, 0xec, 0xec,
            0xe9, 0xea,
        ];
        if t.sent != want {
            return TestResult::Fail("probe wire bytes wrong");
        }
        if !t.consumed_all() {
            return TestResult::Fail("probe did not consume all replies");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_probe_wire_v3);

    fn smoke_alps_probe_rejects_non_alps() -> TestResult {
        // Bad E6 reply: only the E6 report goes out.
        let mut t = FakeAlpsTransport::new(&[0x00, 0x00, 0x00]);
        if probe_alps(&mut t).is_some() {
            return TestResult::Fail("bad E6 must reject");
        }
        if t.sent != [0xe8, 0xe6, 0xe6, 0xe6, 0xe9] {
            return TestResult::Fail("bad-E6 probe wire wrong");
        }
        // Good E6 but unidentifiable E7/EC: still rejected.
        let mut t = FakeAlpsTransport::new(&[0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        if probe_alps(&mut t).is_some() {
            return TestResult::Fail("unidentifiable pad must reject");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_probe_rejects_non_alps);

    fn smoke_alps_decode_v1() -> TestResult {
        // x=1000 y=500 z=50, left. (p0 0x8F: (0x8F & 0xF8) == 0x88.)
        let proto = lookup_model(&[0x33, 0x02, 0x0a]).unwrap().protocol();
        let f = match touchpad_fields(decode(proto, &[0x8f, 0x68, 0x10, 0x03, 0x74, 0x32])) {
            Some(f) => f,
            None => return TestResult::Fail("v1 packet produced no report"),
        };
        if f.st.x != 1000 || f.st.y != 500 || f.pressure != 50 {
            return TestResult::Fail("v1 coordinates wrong");
        }
        if !f.left || f.right || f.fingers != 1 || !f.touch {
            return TestResult::Fail("v1 buttons/fingers/touch wrong");
        }
        if f.mt[0].x != 1000 || f.mt[0].y != 500 {
            return TestResult::Fail("v1 mt[0] must mirror st");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_decode_v1);

    fn smoke_alps_decode_v2() -> TestResult {
        let proto = lookup_model(&[0x63, 0x02, 0x0a]).unwrap().protocol();
        // x=1500 y=700 z=30, right+middle. z=30 does NOT set
        // BTN_TOUCH (hysteresis: set above 30).
        let f = match touchpad_fields(decode(proto, &[0xf8, 0x5c, 0x58, 0x56, 0x3c, 0x1e])) {
            Some(f) => f,
            None => return TestResult::Fail("v2 packet produced no report"),
        };
        if f.st.x != 1500 || f.st.y != 700 || f.pressure != 30 {
            return TestResult::Fail("v2 coordinates wrong");
        }
        if f.left || !f.right || !f.middle || f.fingers != 1 {
            return TestResult::Fail("v2 buttons/fingers wrong");
        }
        if f.touch {
            return TestResult::Fail("v2 z=30 must not set touch");
        }
        // Same packet with z=31 sets touch.
        let f = match touchpad_fields(decode(proto, &[0xf8, 0x5c, 0x58, 0x56, 0x3c, 0x1f])) {
            Some(f) => f,
            None => return TestResult::Fail("v2 z=31 packet produced no report"),
        };
        if !f.touch {
            return TestResult::Fail("v2 z=31 must set touch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_decode_v2);

    fn smoke_alps_decode_v3_pinnacle() -> TestResult {
        // Single touch: x=1000 y=800 z=60, left.
        let f = match touchpad_fields(decode(
            ALPS_V3_PROTOCOL,
            &[0x8f, 0x3e, 0x32, 0x01, 0x20, 0x3c],
        )) {
            Some(f) => f,
            None => return TestResult::Fail("v3 ST packet produced no report"),
        };
        if f.st.x != 1000 || f.st.y != 800 || f.pressure != 60 || !f.left {
            return TestResult::Fail("v3 ST coordinates/buttons wrong");
        }
        if f.fingers != 1 {
            return TestResult::Fail("v3 ST must report one finger");
        }
        // Bitmap sequence: the position packet (first_mp) is
        // stashed with no report; the bitmap packet completes it.
        let mut dec = AlpsDecoder::new(ALPS_V3_PROTOCOL);
        let d = dec.decode(&[0x8f, 0x3e, 0x32, 0x01, 0x60, 0x3c]);
        if !d.is_empty() {
            return TestResult::Fail("v3 first_mp packet must be stashed");
        }
        // Bitmap first byte is 0xCF, not 0xC0: bit 0x40 marks
        // the bitmap, and the first-byte check needs the 0x8F
        // sync bits too (0xCF & 0x8F == 0x8F).
        let f = match touchpad_fields(dec.decode(&[0xcf, 0x06, 0x0c, 0x00, 0x00, 0x01])) {
            Some(f) => f,
            None => return TestResult::Fail("v3 bitmap packet produced no report"),
        };
        if f.fingers != 2 {
            return TestResult::Fail("v3 bitmap must report two fingers");
        }
        if f.mt[0].x != 1000 || f.mt[0].y != 800 {
            return TestResult::Fail("v3 bitmap mt[0] wrong");
        }
        if f.mt[1].x != 428 || f.mt[1].y != 980 {
            return TestResult::Fail("v3 bitmap mt[1] wrong");
        }
        if f.x_map != 0x18 || f.y_map != 0x18 {
            return TestResult::Fail("v3 bitmap maps wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_decode_v3_pinnacle);

    fn smoke_alps_decode_v3_rushmore_bitmap() -> TestResult {
        let mut dec = AlpsDecoder::new(ALPS_V3_RUSHMORE_PROTOCOL);
        let d = dec.decode(&[0x8f, 0x3e, 0x32, 0x01, 0x60, 0x3c]);
        if !d.is_empty() {
            return TestResult::Fail("rushmore first_mp packet must be stashed");
        }
        let f = match touchpad_fields(dec.decode(&[0xcf, 0x06, 0x0c, 0x00, 0x00, 0x41])) {
            Some(f) => f,
            None => return TestResult::Fail("rushmore bitmap produced no report"),
        };
        if f.fingers != 2 || f.mt[0].x != 1000 || f.mt[0].y != 800 {
            return TestResult::Fail("rushmore bitmap mt[0]/fingers wrong");
        }
        if f.mt[1].x != 428 || f.mt[1].y != 980 {
            return TestResult::Fail("rushmore bitmap mt[1] wrong");
        }
        if f.x_map != 0x18 || f.y_map != 0x18 {
            return TestResult::Fail("rushmore bitmap maps wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_decode_v3_rushmore_bitmap);

    fn smoke_alps_decode_v3_trackstick() -> TestResult {
        // dx=-14 dy=-1 pressure=32, no buttons.
        let d = decode(ALPS_V3_PROTOCOL, &[0xef, 0x10, 0x08, 0x00, 0x20, 0x3f]);
        match d.events[0] {
            Some(AlpsEvent::Trackstick {
                dx,
                dy,
                pressure,
                left,
                right,
                middle,
            }) => {
                if dx != -14 || dy != -1 || pressure != 32 {
                    return TestResult::Fail("v3 stick dx/dy/pressure wrong");
                }
                if left || right || middle {
                    return TestResult::Fail("v3 stick must report no buttons");
                }
            }
            _ => return TestResult::Fail("v3 stick packet not decoded as trackstick"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_decode_v3_trackstick);

    fn smoke_alps_decode_v4() -> TestResult {
        let mut dec = AlpsDecoder::new(ALPS_V4_PROTOCOL);
        let p1 = [0x8f, 0x3e, 0x32, 0x20, 0x01, 0x3c, 0x46, 0x18];
        let p2 = [0x8f, 0x3e, 0x32, 0x20, 0x01, 0x3c, 0x00, 0x78];
        let p3 = [0x8f, 0x3e, 0x32, 0x20, 0x01, 0x3c, 0x00, 0x00];
        for p in [&p1, &p2] {
            let f = match touchpad_fields(dec.decode(p)) {
                Some(f) => f,
                None => return TestResult::Fail("v4 fragment produced no report"),
            };
            if f.fingers != 1 || f.st.x != 1000 || f.st.y != 800 {
                return TestResult::Fail("v4 fragment must report one finger at st");
            }
        }
        let f = match touchpad_fields(dec.decode(&p3)) {
            Some(f) => f,
            None => return TestResult::Fail("v4 third packet produced no report"),
        };
        if f.fingers != 2 {
            return TestResult::Fail("v4 third packet must report two fingers");
        }
        if f.mt[0].x != 1000 || f.mt[0].y != 800 {
            return TestResult::Fail("v4 mt[0] wrong");
        }
        if f.mt[1].x != 500 || f.mt[1].y != 210 {
            return TestResult::Fail("v4 mt[1] wrong");
        }
        if f.x_map != 0x318 || f.y_map != 0x318 {
            return TestResult::Fail("v4 bitmap maps wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_decode_v4);

    fn smoke_alps_decode_v5() -> TestResult {
        // Dolphin single touch: x=1000 y=800 z=60, left.
        let f = match touchpad_fields(decode(
            ALPS_V5_PROTOCOL,
            &[0xc8, 0x68, 0x20, 0x01, 0x67, 0x3c],
        )) {
            Some(f) => f,
            None => return TestResult::Fail("v5 packet produced no report"),
        };
        if f.st.x != 1000 || f.st.y != 800 || f.pressure != 60 {
            return TestResult::Fail("v5 coordinates wrong");
        }
        if !f.left || f.fingers != 1 || !f.touch {
            return TestResult::Fail("v5 buttons/fingers/touch wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_decode_v5);

    fn smoke_alps_decode_v6() -> TestResult {
        let proto = lookup_model(&[0x73, 0x00, 0x14]).unwrap().protocol();
        // Touchpad: x=1000 y=800 z=50, left.
        let f = match touchpad_fields(decode(proto, &[0xff, 0xe8, 0x20, 0x39, 0x30, 0x32])) {
            Some(f) => f,
            None => return TestResult::Fail("v6 packet produced no report"),
        };
        if f.st.x != 1000 || f.st.y != 800 || f.pressure != 50 {
            return TestResult::Fail("v6 coordinates wrong");
        }
        if !f.left || f.right || f.fingers != 1 || !f.touch {
            return TestResult::Fail("v6 buttons/fingers/touch wrong");
        }
        // Trackpoint: dx=4 dy=-2 pressure=32.
        let d = decode(proto, &[0xff, 0x10, 0x08, 0x00, 0x20, 0x7f]);
        match d.events[0] {
            Some(AlpsEvent::Trackstick {
                dx, dy, pressure, ..
            }) => {
                if dx != 4 || dy != -2 || pressure != 32 {
                    return TestResult::Fail("v6 stick dx/dy/pressure wrong");
                }
            }
            _ => return TestResult::Fail("v6 stick packet not decoded as trackstick"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_decode_v6);

    fn smoke_alps_decode_v7() -> TestResult {
        // TWO, single finger: mt[0]=(1000,1047), left. First
        // byte is 0xC8, not 0x80: the left bit (0x80) plus the
        // 0x48 sync bits the first-byte check requires.
        let f = match touchpad_fields(decode(
            ALPS_V7_PROTOCOL,
            &[0xc8, 0x7d, 0x5f, 0xd8, 0xff, 0xbf],
        )) {
            Some(f) => f,
            None => return TestResult::Fail("v7 TWO packet produced no report"),
        };
        if f.fingers != 1 || f.mt[0].x != 1000 || f.mt[0].y != 1047 {
            return TestResult::Fail("v7 TWO mt[0]/fingers wrong");
        }
        if f.mt[1].x != 0 || f.mt[1].y != 0 {
            return TestResult::Fail("v7 false-positive second touch must clear");
        }
        if !f.left || f.pressure != 0x30 {
            return TestResult::Fail("v7 TWO buttons/pressure wrong");
        }
        // IDLE: no fingers. First byte 0x48 — a 0x00 first byte
        // would be refused by the first-byte check, and the
        // real idle packet carries the 0x48 sync bits.
        let f = match touchpad_fields(decode(
            ALPS_V7_PROTOCOL,
            &[0x48, 0x00, 0x40, 0x48, 0x00, 0x00],
        )) {
            Some(f) => f,
            None => return TestResult::Fail("v7 IDLE packet produced no report"),
        };
        if f.fingers != 0 {
            return TestResult::Fail("v7 IDLE must report zero fingers");
        }
        // Trackstick: dx=16 dy=0 pressure=32, left.
        let d = decode(ALPS_V7_PROTOCOL, &[0x48, 0x01, 0x10, 0x00, 0x06, 0x20]);
        match d.events[0] {
            Some(AlpsEvent::Trackstick {
                dx,
                dy,
                pressure,
                left,
                ..
            }) => {
                if dx != 16 || dy != 0 || pressure != 32 || !left {
                    return TestResult::Fail("v7 stick dx/dy/pressure/buttons wrong");
                }
            }
            _ => return TestResult::Fail("v7 stick packet not decoded as trackstick"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_decode_v7);

    fn smoke_alps_decode_v8() -> TestResult {
        // ONE: mt[0]=(1000,800), pressure 96, left. Byte 0
        // carries 0x18 in bits 3–4 (the v8 sync pattern) plus
        // the left button in bit 5 — 0x38, not 0x20.
        let f = match touchpad_fields(decode(
            ALPS_V8_PROTOCOL,
            &[0x38, 0xed, 0x00, 0x88, 0x0c, 0x60],
        )) {
            Some(f) => f,
            None => return TestResult::Fail("v8 ONE packet produced no report"),
        };
        if f.fingers != 1 || f.mt[0].x != 1000 || f.mt[0].y != 800 {
            return TestResult::Fail("v8 ONE mt[0]/fingers wrong");
        }
        if f.pressure != 96 || !f.left {
            return TestResult::Fail("v8 ONE pressure/buttons wrong");
        }
        // STICK: dx=16 dy=-8 pressure=32.
        let d = decode(ALPS_V8_PROTOCOL, &[0x18, 0x10, 0x08, 0x28, 0x20, 0x00]);
        match d.events[0] {
            Some(AlpsEvent::Trackstick {
                dx, dy, pressure, ..
            }) => {
                if dx != 16 || dy != -8 || pressure != 32 {
                    return TestResult::Fail("v8 stick dx/dy/pressure wrong");
                }
            }
            _ => return TestResult::Fail("v8 stick packet not decoded as trackstick"),
        }
        // TWO (standard macros): mt[0]=(96,192), mt[1]=(320,384).
        let f = match touchpad_fields(decode(
            ALPS_V8_PROTOCOL,
            &[0x1b, 0x01, 0x06, 0x1a, 0x08, 0x0c],
        )) {
            Some(f) => f,
            None => return TestResult::Fail("v8 TWO packet produced no report"),
        };
        if f.fingers != 2 || f.mt[0].x != 96 || f.mt[0].y != 192 {
            return TestResult::Fail("v8 TWO mt[0]/fingers wrong");
        }
        if f.mt[1].x != 320 || f.mt[1].y != 384 {
            return TestResult::Fail("v8 TWO mt[1] wrong");
        }
        if f.pressure != 0x30 {
            return TestResult::Fail("v8 TWO pressure wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_decode_v8);

    fn smoke_alps_decode_v2_interleaved() -> TestResult {
        // 9-byte frame: ALPS head + bare PS/2 + ALPS tail.
        let proto = AlpsProtocol {
            version: AlpsVersion::V2,
            byte0: 0xf8,
            mask0: 0xf8,
            flags: FLAG_PS2_INTERLEAVED,
        };
        let mut dec = AlpsDecoder::new(proto);
        let frame: [u8; 9] = [0xf8, 0x5c, 0x58, 0x0f, 0x05, 0x03, 0x56, 0x3c, 0x1e];
        let d = dec.decode_interleaved_v2(&frame);
        match d.events[0] {
            Some(AlpsEvent::BarePs2 {
                dx,
                dy,
                left,
                right,
                middle,
            }) => {
                if dx != 5 || dy != -3 {
                    return TestResult::Fail("interleaved bare dx/dy wrong");
                }
                if left || right || middle {
                    return TestResult::Fail("interleaved bare buttons must be ignored");
                }
            }
            _ => return TestResult::Fail("interleaved frame must start with BarePs2"),
        }
        let f = match touchpad_fields(d) {
            Some(f) => f,
            None => return TestResult::Fail("interleaved frame must end with Touchpad"),
        };
        if f.st.x != 1500 || f.st.y != 700 || f.pressure != 30 || !f.right {
            return TestResult::Fail("interleaved touchpad report wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_decode_v2_interleaved);

    fn smoke_alps_rejects_non_alps_packet() -> TestResult {
        let proto = lookup_model(&[0x63, 0x02, 0x0a]).unwrap().protocol();
        let dec = AlpsDecoder::new(proto);
        // A standard PS/2 packet (sync bit, no ALPS first byte).
        if dec.is_valid_first_byte(0x08) {
            return TestResult::Fail("0x08 must fail the v2 first-byte check");
        }
        if !decode(proto, &[0x08, 0x00, 0x00, 0x00, 0x00, 0x00]).is_empty() {
            return TestResult::Fail("non-ALPS packet must decode to no events");
        }
        if !decode(proto, &[0xf8, 0x5c]).is_empty() {
            return TestResult::Fail("short packet must decode to no events");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_rejects_non_alps_packet);

    fn smoke_alps_enable_v1_v2_wire() -> TestResult {
        let mut t = FakeAlpsTransport::new(&[]);
        if !enter_absolute_mode(&mut t, AlpsVersion::V1) {
            return TestResult::Fail("v1 enable failed");
        }
        if t.sent != [0xf5, 0xf5, 0xf5, 0xf5, 0xf4, 0xf0] {
            return TestResult::Fail("v1/v2 enable wire wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_enable_v1_v2_wire);

    fn smoke_alps_enable_v5_wire() -> TestResult {
        let mut t = FakeAlpsTransport::new(&[]);
        if !enter_absolute_mode(&mut t, AlpsVersion::V5) {
            return TestResult::Fail("v5 enable failed");
        }
        if t.sent != [0xea, 0xf3, 0x64, 0xf3, 0x28] {
            return TestResult::Fail("v5 enable wire wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_enable_v5_wire);

    fn smoke_alps_enable_v6_wire() -> TestResult {
        // The GETID nibble inside the 0x181 word returns 2 bytes.
        let mut t = FakeAlpsTransport::new(&[0x00, 0x00]);
        if !enter_absolute_mode(&mut t, AlpsVersion::V6) {
            return TestResult::Fail("v6 enable failed");
        }
        let want: [u8; 23] = [
            0xec, 0xe9, 0xf5, 0xf5, 0xe7, 0xe6, 0xe7, 0xe9, 0xf4, 0xf4, 0xe8, 0x00, 0xf4, 0xf4,
            0xf4, 0xf4, 0xf3, 0x01, 0xf2, 0xf3, 0x01, 0xf5, 0xec,
        ];
        if t.sent != want {
            return TestResult::Fail("v6 monitor-mode wire wrong");
        }
        if !t.consumed_all() {
            return TestResult::Fail("v6 enable did not consume all replies");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_enable_v6_wire);

    fn smoke_alps_enable_v8_wire() -> TestResult {
        // Enter-command-mode replies: a valid firmware id.
        let mut t = FakeAlpsTransport::new(&[0x73, 0x03, 0x14]);
        if !enter_absolute_mode(&mut t, AlpsVersion::V8) {
            return TestResult::Fail("v8 enable failed");
        }
        let want: [u8; 21] = [
            0xea, 0xea, 0xf3, 0x64, 0xf3, 0x28, 0xea, 0xec, 0xec, 0xec, 0xe9, 0xec, 0xf0, 0xf0,
            0xf6, 0xe8, 0x02, 0xe7, 0xf0, 0xea, 0xf4,
        ];
        if t.sent != want {
            return TestResult::Fail("v8 enable wire wrong");
        }
        if !t.consumed_all() {
            return TestResult::Fail("v8 enable did not consume all replies");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_enable_v8_wire);

    fn smoke_alps_enable_v3_wire() -> TestResult {
        // Replies: command-mode entry (88-07-95), then the
        // GETINFO echo for each register read (0x0004, 0x0006,
        // 0x0007, 0x0144, 0x0159, 0x0162) with value 0x00.
        let mut t = FakeAlpsTransport::new(&[
            0x88, 0x07, 0x95, 0x00, 0x04, 0x00, 0x00, 0x06, 0x00, 0x00, 0x07, 0x00, 0x01, 0x44,
            0x00, 0x01, 0x59, 0x00, 0x01, 0x62, 0x00,
        ]);
        if !enter_absolute_mode(&mut t, AlpsVersion::V3) {
            return TestResult::Fail("v3 enable failed");
        }
        if t.sent.len() < 4 || t.sent[..4] != [0xec, 0xec, 0xec, 0xe9] {
            return TestResult::Fail("v3 enable must start with command-mode entry");
        }
        let n = t.sent.len();
        if t.sent[n - 4..] != [0xea, 0xf3, 0x64, 0xf4] {
            return TestResult::Fail("v3 enable must end with exit + SETRATE 0x64 + ENABLE");
        }
        if !t.consumed_all() {
            return TestResult::Fail("v3 enable did not consume all replies");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_alps_enable_v3_wire);

    fn smoke_i8042_alps_feed_v6_touchpad() -> TestResult {
        reset_ring_and_mouse();
        let proto = lookup_model(&[0x73, 0x00, 0x14]).unwrap().protocol();
        i8042_mouse::set_alps_protocol(proto, [0x73, 0x00, 0x14]);
        // Touch down: x=1000 y=800 z=50, left.
        feed(&[0xff, 0xe8, 0x20, 0x39, 0x30, 0x32]);
        match pop_global() {
            Some(InputEvent::Touch(t)) => {
                if t.slot != 0 || t.x != 1000 || t.y != 800 || t.pressure != 50 {
                    return TestResult::Fail("ALPS Touch down shape wrong");
                }
                if t.state != TouchState::Down {
                    return TestResult::Fail("first touch must be Down");
                }
            }
            _ => return TestResult::Fail("no Touch event for ALPS packet"),
        }
        match pop_global() {
            Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_X && a.value == 1000 => {}
            _ => return TestResult::Fail("ABS_X event wrong"),
        }
        match pop_global() {
            Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_Y && a.value == 800 => {}
            _ => return TestResult::Fail("ABS_Y event wrong"),
        }
        match pop_global() {
            Some(InputEvent::Absolute(a)) if a.axis == abs::ABS_PRESSURE && a.value == 50 => {}
            _ => return TestResult::Fail("ABS_PRESSURE event wrong"),
        }
        match pop_global() {
            Some(InputEvent::Pointer(p)) => {
                if p.dx != 0 || p.dy != 0 || !p.buttons.contains(PointerButtons::LEFT) {
                    return TestResult::Fail("ALPS Pointer button event wrong");
                }
            }
            _ => return TestResult::Fail("no Pointer event for ALPS button edge"),
        }
        if pop_global().is_some() {
            return TestResult::Fail("ALPS down packet emitted extra events");
        }
        // Touchpad packets never touch the relative accumulator.
        if i8042_mouse::take_rel_delta() != (0, 0) {
            return TestResult::Fail("touchpad must not accumulate rel delta");
        }
        // Lift (z=0): a single Touch Up reusing the last position.
        feed(&[0xff, 0xe8, 0x20, 0x39, 0x30, 0x00]);
        match pop_global() {
            Some(InputEvent::Touch(t)) => {
                if t.state != TouchState::Up || t.x != 1000 || t.y != 800 || t.pressure != 0 {
                    return TestResult::Fail("ALPS Touch up shape wrong");
                }
            }
            _ => return TestResult::Fail("no Touch Up for ALPS lift"),
        }
        if pop_global().is_some() {
            return TestResult::Fail("ALPS lift emitted extra events");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_i8042_alps_feed_v6_touchpad);

    fn smoke_i8042_alps_feed_rejects_standard_packet() -> TestResult {
        reset_ring_and_mouse();
        let proto = lookup_model(&[0x63, 0x02, 0x0a]).unwrap().protocol();
        i8042_mouse::set_alps_protocol(proto, [0x63, 0x02, 0x0a]);
        // A standard 3-byte PS/2 packet must be dropped whole.
        feed(&[0x08, 0x01, 0x02]);
        if pop_global().is_some() {
            return TestResult::Fail("ALPS-active feed must drop standard packets");
        }
        // …but a real v2 packet still decodes afterwards.
        feed(&[0xf8, 0x5c, 0x58, 0x56, 0x3c, 0x1e]);
        match pop_global() {
            Some(InputEvent::Touch(t)) => {
                if t.x != 1500 || t.y != 700 {
                    return TestResult::Fail("v2 packet after rejection decoded wrong");
                }
            }
            _ => return TestResult::Fail("v2 packet after rejection produced no Touch"),
        }
        // Clearing the protocol restores the 3-byte path.
        i8042_mouse::clear_alps_protocol();
        __reset_global_ring_for_test();
        feed(&[0x09, 0x05, 0x03]);
        match pop_global() {
            Some(InputEvent::Pointer(p)) => {
                if p.dx != 5 || p.dy != -3 || !p.buttons.contains(PointerButtons::LEFT) {
                    return TestResult::Fail("cleared feed did not restore 3-byte decode");
                }
            }
            _ => return TestResult::Fail("no Pointer after clearing ALPS protocol"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/alps",
        smoke_i8042_alps_feed_rejects_standard_packet
    );

    fn smoke_i8042_alps_feed_v2_interleaved() -> TestResult {
        reset_ring_and_mouse();
        // The table's interleaved row expects byte0 0xff; the
        // verified frame's ALPS part starts 0xF8, so the test
        // protocol mirrors the frame (same version + flag).
        let proto = AlpsProtocol {
            version: AlpsVersion::V2,
            byte0: 0xf8,
            mask0: 0xf8,
            flags: FLAG_PS2_INTERLEAVED,
        };
        i8042_mouse::set_alps_protocol(proto, [0x00, 0x00, 0x00]);
        // The 6-byte ALPS part alone emits nothing — it waits
        // for its 3 extension bytes.
        feed(&[0xf8, 0x5c, 0x58, 0x0f, 0x05, 0x03]);
        if pop_global().is_some() {
            return TestResult::Fail("stashed interleaved packet must not emit yet");
        }
        feed(&[0x56, 0x3c, 0x1e]);
        // Bare PS/2 part first: relative motion, no buttons.
        match pop_global() {
            Some(InputEvent::Pointer(p)) => {
                if p.dx != 5 || p.dy != -3 || p.buttons != PointerButtons::EMPTY {
                    return TestResult::Fail("interleaved bare motion wrong");
                }
            }
            _ => return TestResult::Fail("no Pointer for interleaved bare part"),
        }
        match pop_global() {
            Some(InputEvent::Touch(t)) => {
                if t.x != 1500 || t.y != 700 || t.state != TouchState::Down {
                    return TestResult::Fail("interleaved touchpad report wrong");
                }
            }
            _ => return TestResult::Fail("no Touch for interleaved ALPS part"),
        }
        if i8042_mouse::take_rel_delta() != (5, -3) {
            return TestResult::Fail("interleaved bare motion must accumulate rel delta");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input/alps", smoke_i8042_alps_feed_v2_interleaved);
}
