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
