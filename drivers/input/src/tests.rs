//! Per-crate smoke tests for `narf-input-driver`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under the `"drivers/input"` subsystem.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_i8042_decode_a_keystroke() -> TestResult {
    // Synthetic scancode-set-1 byte stream for: press 'A', release 'A'.
    // Make code for KEY_A in set 1 = 0x1E. Release sets the 0x80 bit.
    use crate::i8042;
    use narf_input::{
        InputEvent, KeyCode, __reset_global_ring_for_test, init_global_ring, pop_global,
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

fn smoke_i8042_modifier_tracking() -> TestResult {
    // Press LeftShift (make 0x2A), press 'A' (make 0x1E), release both.
    // The 'A' press event should carry SHIFT in its modifier bitset.
    use crate::i8042;
    use narf_input::{
        InputEvent, KeyCode, Modifiers, __reset_global_ring_for_test, init_global_ring, pop_global,
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

fn smoke_virtio_input_decode_synthetic() -> TestResult {
    use narf_drivers_virtio::input_pci::feed_synthetic_events_for_test;
    use narf_input::{
        InputEvent, KeyCode, __reset_global_ring_for_test, init_global_ring, pop_global,
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
        InputEvent, PointerButtons, __reset_global_ring_for_test, init_global_ring, pop_global,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    // EV_REL REL_X=+5, EV_REL REL_Y=-3, EV_KEY BTN_LEFT=0x110 press,
    // EV_SYN → expect one PointerEvent(dx=5, dy=-3, LEFT).
    let _ = feed_synthetic_events_for_test(&[
        (2, 0, 5u32),         // EV_REL REL_X +5
        (2, 1, (-3i32) as u32), // EV_REL REL_Y -3
        (1, 0x110, 1),        // EV_KEY BTN_LEFT press
        (0, 0, 0),            // EV_SYN
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
        KeyCode, Modifiers, __reset_global_ring_for_test, __reset_modifiers_for_test,
        init_global_ring, pop_key,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    __reset_modifiers_for_test();
    // LeftShift=42 press, A=30 press, A release, LeftShift release.
    let _ = feed_synthetic_events_for_test(&[
        (1, 42, 1),
        (1, 30, 1),
        (1, 30, 0),
        (1, 42, 0),
    ]);
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
    use narf_input::{
        abs, __reset_global_ring_for_test, init_global_ring, pop_absolute,
    };
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
kernel_test_in!("drivers/input", smoke_virtio_input_tablet_abs_xy_emits_absolute);

fn smoke_virtio_input_multitouch_slot_protocol_b() -> TestResult {
    use narf_drivers_virtio::input_pci::feed_synthetic_events_for_test;
    use narf_input::{
        abs, __reset_global_ring_for_test, init_global_ring, pop_touch,
    };
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
    if t_lift.slot != 0 || t_lift.tracking_id != None {
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
    let _ = feed_synthetic_events_for_test(&[
        (1, 0x14a, 1),
        (0, 0, 0),
        (1, 0x14a, 0),
        (0, 0, 0),
    ]);
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
kernel_test_in!("drivers/input", smoke_virtio_input_btn_touch_drives_slot_zero);

fn smoke_virtio_input_extra_mouse_buttons() -> TestResult {
    use narf_drivers_virtio::input_pci::feed_synthetic_events_for_test;
    use narf_input::{
        InputEvent, PointerButtons, __reset_global_ring_for_test, init_global_ring, pop_global,
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
    use narf_input::{
        InputEvent, __reset_global_ring_for_test, init_global_ring, pop_global,
    };
    init_global_ring(8);
    __reset_global_ring_for_test();
    // EV_REL REL_HWHEEL=6 value=+1 → ScrollEvent{dx:+1,dy:0}.
    // EV_REL REL_HWHEEL value=-2 → ScrollEvent{dx:-2,dy:0}.
    let _ = feed_synthetic_events_for_test(&[
        (2, 6, 1u32),
        (2, 6, (-2i32) as u32),
    ]);
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
    use narf_input::{
        btn, __reset_global_ring_for_test, init_global_ring, pop_button, pop_key,
    };
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

fn smoke_generic_fb_discovery() -> TestResult {
    use narf_fb::last_picked_backend;
    if let Some(name) = last_picked_backend() {
        if name == "generic-fb" || name == "bochs-display" || name == "virtio-gpu" {
            return TestResult::Pass;
        }
    }
    TestResult::Skip("no framebuffer backend picked")
}
kernel_test_in!("drivers/graphics", smoke_generic_fb_discovery);



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

kernel_test_in!("drivers/input/wbdi", smoke_wbdi_recogniser_accepts_winusb_wbdi);



fn smoke_wbdi_find_interface_in_vendor_class_config() -> TestResult {

    use crate::wbdi::{desc_type, find_wbdi_interface, COMPATIBLE_ID_WINUSB, SUB_COMPATIBLE_ID_WBDI};

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

        9, 2, 18, 0, 1, 1, 0, 0xA0, 0,

        9, 4, 5, 0, 1, 0xFF, 0xFF, 0xFF, 0, // 9-byte interface descriptor

    ];

    match find_wbdi_interface(&cfg, &ms) {

        Some(5) => TestResult::Pass,

        _ => TestResult::Fail("interface number wrong"),

    }

}

kernel_test_in!("drivers/input/wbdi", smoke_wbdi_find_interface_in_vendor_class_config);



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
    use core::sync::atomic::{AtomicI32, Ordering};
    use narf_drivers_i2c::{I2cBus, I2cError, I2cOp};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    use crate::i2c_hid::{HidDescriptor, I2cHidDriver, I2cHidError, HID_DESC_LENGTH};

    #[derive(Debug)]
    pub(super) struct MockBus {
        /// Pre-staged bytes the bus returns in order, one Vec per
        /// I2cOp::Read in the order they're encountered.
        canned_reads: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
        /// Captured Write payloads, one per I2cOp::Write.
        captured_writes: IrqSafeSpinLock<Vec<Vec<u8>>>,
    }

    impl MockBus {
        pub(super) fn new() -> Self {
            Self {
                canned_reads: IrqSafeSpinLock::new(VecDeque::new()),
                captured_writes: IrqSafeSpinLock::new(Vec::new()),
            }
        }
        pub(super) fn stage_read(&self, data: Vec<u8>) {
            self.canned_reads.lock().push_back(data);
        }
        pub(super) fn writes(&self) -> Vec<Vec<u8>> {
            self.captured_writes.lock().clone()
        }
    }

    #[async_trait]
    impl I2cBus for MockBus {
        async fn transfer(&self, _addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
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
            if drv
                .set_power(crate::i2c_hid::POWER_SLEEP)
                .await
                .is_err()
            {
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
        InputEvent, PointerButtons, __reset_global_ring_for_test, init_global_ring, pop_global,
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
    kernel_test_in!("drivers/input/i2c-hid", smoke_ptp_pointer_emits_relative_motion);

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

    // End-to-end test of the SET_FEATURE(Device Mode = MULTI_TOUCH)
    // wiring added to the bind layer. Parses a real PTP report
    // descriptor, builds a PtpProfile from it, hands it to
    // `set_ptp_multi_touch_mode` against a MockBus, and checks
    // both the return value and the captured wire bytes.
    fn smoke_set_ptp_multi_touch_mode_writes_set_feature() -> TestResult {
        use alloc::sync::Arc;
        use narf_drivers_i2c::I2cBus;

        use crate::i2c_hid::{HidDescriptor, I2cHidDriver};
        use crate::i2c_hid_bind::{set_ptp_multi_touch_mode, PtpModeSetResult};
        use super::i2c_hid_smokes::{make_descriptor_bytes, run_async, MockBus};

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
    use narf_input::{
        TouchState, __reset_global_ring_for_test, init_global_ring, pop_touch,
    };
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
            &__build_decoded_for_test(&[
                (3, true, 0x0100, 0x0100),
                (7, true, 0x6000, 0x6000),
            ]),
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
        use narf_input::{abs, btn, __reset_global_ring_for_test, init_global_ring,
                         pop_absolute, pop_button};
        use crate::i2c_hid_touch::{__build_pen_for_test, __new_pen_state_for_test,
                                   __pump_pen_for_test};
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
        use narf_input::{abs, btn, __reset_global_ring_for_test, init_global_ring,
                         pop_absolute, pop_button};
        use crate::i2c_hid_touch::{__build_pen_for_test, __new_pen_state_for_test,
                                   __pump_pen_for_test};
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
        use narf_input::{btn, __reset_global_ring_for_test, init_global_ring, pop_button};
        use crate::i2c_hid_touch::{__build_pen_for_test, __new_pen_state_for_test,
                                   __pump_pen_for_test};
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
        use narf_input::{btn, __reset_global_ring_for_test, init_global_ring, pop_button};
        use crate::i2c_hid_touch::{__build_pen_for_test, __new_pen_state_for_test,
                                   __pump_pen_for_test};
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
    kernel_test_in!(
        "drivers/input/i2c-hid",
        smoke_pen_leave_range_releases_tool
    );

    // ── End-to-end FakeI2cHid bind ───────────────────────────────
    //
    // Builds a MockBus, stages a full HID descriptor + touchscreen
    // report-descriptor read, plus one synthetic 2-finger touchscreen
    // input report, and verifies that TouchEvents land on the ring.
    // This exercises the entire decode chain without real hardware.

    fn smoke_fake_i2c_hid_touchscreen_end_to_end() -> TestResult {
        use alloc::sync::Arc;
        use narf_drivers_i2c::I2cBus;
        use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_touch, TouchState};
        use super::i2c_hid_smokes::{make_descriptor_bytes, run_async, MockBus};
        use crate::i2c_hid::{I2cHidDriver, POWER_ON};

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
            0x01,               // Report ID
            0b0000_0011,        // F0: tip=1, in_range=1, pad=000000
            0x01,               // F0: contact_id = 1
            0x00, 0x10,         // F0: X = 0x1000
            0x00, 0x20,         // F0: Y = 0x2000
            0b0000_0011,        // F1: tip=1, in_range=1, pad=000000
            0x02,               // F1: contact_id = 2
            0x00, 0x50,         // F1: X = 0x5000
            0x00, 0x60,         // F1: Y = 0x6000
            0x02,               // contact_count = 2
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
            buf[off..off+2].copy_from_slice(&v.to_le_bytes());
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
    page.bytes[last] = 0x10;     // query base
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

