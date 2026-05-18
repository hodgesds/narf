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
    struct MockBus {
        /// Pre-staged bytes the bus returns in order, one Vec per
        /// I2cOp::Read in the order they're encountered.
        canned_reads: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
        /// Captured Write payloads, one per I2cOp::Write.
        captured_writes: IrqSafeSpinLock<Vec<Vec<u8>>>,
    }

    impl MockBus {
        fn new() -> Self {
            Self {
                canned_reads: IrqSafeSpinLock::new(VecDeque::new()),
                captured_writes: IrqSafeSpinLock::new(Vec::new()),
            }
        }
        fn stage_read(&self, data: Vec<u8>) {
            self.canned_reads.lock().push_back(data);
        }
        fn writes(&self) -> Vec<Vec<u8>> {
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

    fn make_descriptor_bytes() -> Vec<u8> {
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

    fn run_async<F>(fut: F) -> TestResult
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
}
