//! Per-driver smoke tests for `narf-drivers-usb`. Tests register
//! via `narf_kernel_test::kernel_test_in!` so the runner groups
//! output under each driver's subsystem path.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

// ── xhci ───────────────────────────────────────────────────────────

fn smoke_xhci_bring_up() -> TestResult {
    use crate::xhci;
    if !xhci::is_probed() { return TestResult::Skip("xhci not probed"); }
    if !xhci::with_controller(|c| c.is_running()).unwrap_or(false) {
        return TestResult::Fail("xhci not running after bring_up");
    }
    let v = xhci::with_controller(|c| c.version()).unwrap_or(0);
    if v == 0 || v == 0xFFFF {
        return TestResult::Fail("xhci HCIVERSION reads garbage");
    }
    let slots = xhci::with_controller(|c| c.max_slots()).unwrap_or(0);
    if slots == 0 { return TestResult::Fail("xhci max_slots = 0"); }
    let ports = xhci::with_controller(|c| c.max_ports()).unwrap_or(0);
    if ports == 0 { return TestResult::Fail("xhci max_ports = 0"); }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_bring_up);

fn smoke_xhci_amd_phoenix_matches() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    use crate::xhci;
    __reset_for_test();
    xhci::register_pci_driver();
    let regs = registered_pci_drivers();
    let want: &[(u16, u16)] = &[
        (xhci::QEMU_XHCI_VENDOR, xhci::QEMU_XHCI_DEVICE),
        (xhci::AMD_VENDOR,       xhci::AMD_PHX_15B9),
        (xhci::AMD_VENDOR,       xhci::AMD_PHX_15BA),
        (xhci::AMD_VENDOR,       xhci::AMD_PHX_15C0),
        (xhci::AMD_VENDOR,       xhci::AMD_PHX_15C1),
    ];
    for (v, d) in want.iter().copied() {
        let found = regs.iter().any(|m|
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == v && device == d));
        if !found {
            return TestResult::Fail("missing xhci VID/DID match");
        }
    }
    let class_match = regs.iter().any(|m|
        matches!(m.kind, MatchKind::Class {
            class: 0x0C, mask: 0xFF,
        }));
    if !class_match {
        return TestResult::Fail("xhci class-match backstop missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_amd_phoenix_matches);

// ── xhci live (QEMU) ───────────────────────────────────────────────

fn smoke_xhci_enable_slot_command() -> TestResult {
    use crate::xhci;
    if !xhci::is_probed() { return TestResult::Skip("xhci not probed"); }
    let r = xhci::with_controller(|c| c.enable_slot());
    match r {
        Some(Ok(slot_id)) if slot_id >= 1 => TestResult::Pass,
        Some(Ok(_))   => TestResult::Fail("Enable Slot returned slot 0"),
        Some(Err(_))  => TestResult::Fail("Enable Slot command failed"),
        None          => TestResult::Skip("xhci controller missing"),
    }
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_enable_slot_command);

fn smoke_xhci_address_device_qemu() -> TestResult {
    use crate::xhci;
    if !xhci::is_probed() { return TestResult::Skip("xhci not probed"); }
    let port_speed = xhci::with_controller(|c| {
        let connected = c.connected_ports();
        connected.first().copied().map(|(p, _)| (p, c.port_speed(p)))
    }).flatten();
    let (port, speed) = match port_speed {
        Some((p, Some(s))) => (p, s),
        _ => return TestResult::Skip("no connected port / unknown speed"),
    };
    let _post = match xhci::with_controller(|c| c.port_reset(port)) {
        Some(Ok(v)) => v,
        _           => return TestResult::Fail("port_reset failed"),
    };
    let slot_id = match xhci::with_controller(|c| c.enable_slot()) {
        Some(Ok(s)) => s,
        _           => return TestResult::Fail("enable_slot failed"),
    };
    match xhci::with_controller(|c| c.address_device(slot_id, port, speed)) {
        Some(Ok(_)) => TestResult::Pass,
        _           => TestResult::Fail("address_device failed"),
    }
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_address_device_qemu);

// ── MSC class-driver descriptor parser ─────────────────────────────

fn smoke_msc_config_descriptor_parse() -> TestResult {
    use crate::msc;
    use crate::xhci::EndpointKind;

    // Synthesized blob: Configuration Descriptor (9 B) +
    // Interface Descriptor (9 B, MSC BOT 08:06:50) + 2 ×
    // Endpoint Descriptor (7 B each, bulk-IN @ ep1 / bulk-OUT @ ep2).
    let cfg: [u8; 32] = [
        9, 2, 32, 0, 1, 1, 0, 0xC0, 0,
        9, 4, 0, 0, 2, 0x08, 0x06, 0x50, 0,
        7, 5, 0x81, 0x02, 0x00, 0x02, 0,
        7, 5, 0x02, 0x02, 0x00, 0x02, 0,
    ];
    let (in_ep, out_ep) = match msc::find_bot_endpoints(&cfg) {
        Ok(p)  => p,
        Err(_) => return TestResult::Fail("find_bot_endpoints rejected MSC blob"),
    };
    if in_ep.kind != EndpointKind::BulkIn
        || in_ep.ep_addr != 0x81
        || in_ep.max_packet != 0x0200
    {
        return TestResult::Fail("bulk-IN endpoint mis-decoded");
    }
    if out_ep.kind != EndpointKind::BulkOut
        || out_ep.ep_addr != 0x02
        || out_ep.max_packet != 0x0200
    {
        return TestResult::Fail("bulk-OUT endpoint mis-decoded");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_config_descriptor_parse);

fn smoke_msc_attach_via_xhci_qemu() -> TestResult {
    use crate::{msc, xhci};
    if !xhci::is_probed() { return TestResult::Skip("xhci not probed"); }
    msc::__reset_msc_for_test();
    let attached = xhci::with_controller(|c|
        msc::enumerate_and_attach_msc(c)
    ).unwrap_or(0);
    if attached == 0 {
        return TestResult::Skip("no MSC device attached to xhci");
    }
    if msc::attached_msc_count() != attached {
        return TestResult::Fail("registry count diverged from return");
    }
    let cap_ok = msc::with_device(0, |d| d.lba_bytes != 0 && d.last_lba != 0)
        .unwrap_or(false);
    if !cap_ok {
        return TestResult::Fail("READ CAPACITY(10) didn't populate dev");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/msc", smoke_msc_attach_via_xhci_qemu);

// ── HID class-driver descriptor parser + report decode ─────────────

fn smoke_hid_boot_keyboard_parse() -> TestResult {
    use crate::hid;
    use crate::xhci::EndpointKind;

    let cfg: [u8; 25] = [
        9, 2, 25, 0, 1, 1, 0, 0xA0, 0,
        9, 4, 0, 0, 1, 0x03, 0x01, 0x01, 0,
        7, 5, 0x81, 0x03, 0x08, 0x00, 10,
    ];
    let (iface, ep) = match hid::find_boot_keyboard(&cfg) {
        Ok(v)  => v,
        Err(_) => return TestResult::Fail("find_boot_keyboard rejected HID blob"),
    };
    if iface != 0 || ep.kind != EndpointKind::InterruptIn
        || ep.ep_addr != 0x81 || ep.max_packet != 8
    {
        return TestResult::Fail("HID kbd endpoint mis-decoded");
    }
    let report = hid::KbdReport::from_bytes([
        hid::kbd_mod::LCTRL | hid::kbd_mod::LSHIFT,
        0,
        0x04, 0x05, 0, 0, 0, 0,
    ]);
    if !report.pressed(0x04) || !report.pressed(0x05) {
        return TestResult::Fail("KbdReport::pressed missed key");
    }
    if report.modifiers
        != (hid::kbd_mod::LCTRL | hid::kbd_mod::LSHIFT)
    {
        return TestResult::Fail("KbdReport modifier byte wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_boot_keyboard_parse);

// ── HID Usage → KeyCode coverage ───────────────────────────────────

fn smoke_hid_usage_to_keycode_table() -> TestResult {
    use crate::hid::usage_to_keycode;
    use narf_input::KeyCode;
    // Spot-check the rows people care most about: letters, digits,
    // navigation cluster, function-row, numpad, modifier escapes.
    let cases: &[(u8, KeyCode)] = &[
        (0x04, KeyCode::A),         (0x1D, KeyCode::Z),
        (0x1E, KeyCode::Key1),      (0x27, KeyCode::Key0),
        (0x28, KeyCode::Enter),     (0x29, KeyCode::Escape),
        (0x2A, KeyCode::Backspace), (0x2B, KeyCode::Tab),
        (0x2C, KeyCode::Space),     (0x39, KeyCode::CapsLock),
        (0x3A, KeyCode::F1),        (0x45, KeyCode::F12),
        (0x46, KeyCode::SysRq),     (0x48, KeyCode::Pause),
        (0x49, KeyCode::Insert),    (0x4C, KeyCode::Delete),
        (0x4A, KeyCode::Home),      (0x4D, KeyCode::End),
        (0x4B, KeyCode::PageUp),    (0x4E, KeyCode::PageDown),
        (0x4F, KeyCode::Right),     (0x50, KeyCode::Left),
        (0x51, KeyCode::Down),      (0x52, KeyCode::Up),
        (0x53, KeyCode::NumLock),   (0x54, KeyCode::KpSlash),
        (0x55, KeyCode::KpAsterisk),(0x56, KeyCode::KpMinus),
        (0x57, KeyCode::KpPlus),    (0x58, KeyCode::KpEnter),
        (0x59, KeyCode::Kp1),       (0x62, KeyCode::Kp0),
        (0x63, KeyCode::KpDot),     (0x65, KeyCode::Menu),
        (0xE0, KeyCode::LeftCtrl),  (0xE7, KeyCode::RightMeta),
    ];
    for &(u, want) in cases {
        let got = usage_to_keycode(u);
        if got != want {
            return TestResult::Fail("usage_to_keycode mismatch");
        }
    }
    if usage_to_keycode(0x00) != KeyCode::Unknown
        || usage_to_keycode(0xFF) != KeyCode::Unknown
    {
        return TestResult::Fail("Unknown sentinel mis-set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_usage_to_keycode_table);

fn smoke_hid_modifier_byte_to_modifiers() -> TestResult {
    use crate::hid;
    use narf_input::Modifiers;
    let m = hid::modifier_byte_to_modifiers(
        hid::kbd_mod::LCTRL | hid::kbd_mod::RSHIFT
        | hid::kbd_mod::LALT | hid::kbd_mod::RGUI);
    if !m.contains(Modifiers::CTRL)  { return TestResult::Fail("CTRL"); }
    if !m.contains(Modifiers::SHIFT) { return TestResult::Fail("SHIFT"); }
    if !m.contains(Modifiers::ALT)   { return TestResult::Fail("ALT"); }
    if !m.contains(Modifiers::META)  { return TestResult::Fail("META"); }
    let none = hid::modifier_byte_to_modifiers(0);
    if none.bits() != 0 { return TestResult::Fail("zero byte → non-zero mods"); }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_modifier_byte_to_modifiers);

fn smoke_hid_diff_press_release_repeat() -> TestResult {
    use crate::hid::{self, BootKeyboard, KbdReport};
    use narf_input::{InputEvent, KeyCode, __reset_global_ring_for_test,
                     init_global_ring, pop_global};

    init_global_ring(64);
    __reset_global_ring_for_test();
    hid::__reset_keyboards_for_test();

    // Fabricate a keyboard binding without going through the
    // controller — we only exercise translate_report here.
    let mut kbd = BootKeyboard {
        slot_id: 1,
        interrupt_in_ep: 3,
        interface_num: 0,
        last_report: KbdReport::default(),
    };

    // First report: A pressed (with LShift held) — should fire two
    // events: LeftShift press, then A press.
    let r1 = KbdReport::from_bytes([
        hid::kbd_mod::LSHIFT, 0,
        0x04, 0, 0, 0, 0, 0,
    ]);
    let n1 = kbd.translate_report(r1);
    if n1 != 2 { return TestResult::Fail("expected 2 events on first press"); }

    let e1 = pop_global();
    let e2 = pop_global();
    let (k1, p1) = match e1 { Some(InputEvent::Key(k)) => (k.code, k.pressed), _ => return TestResult::Fail("e1 missing") };
    let (k2, p2) = match e2 { Some(InputEvent::Key(k)) => (k.code, k.pressed), _ => return TestResult::Fail("e2 missing") };
    if !(p1 && k1 == KeyCode::LeftShift) {
        return TestResult::Fail("expected LShift press first");
    }
    if !(p2 && k2 == KeyCode::A) {
        return TestResult::Fail("expected A press second");
    }

    // Second report: same keys still held → no events.
    let n2 = kbd.translate_report(r1);
    if n2 != 0 { return TestResult::Fail("repeat report emitted events"); }
    if pop_global().is_some() { return TestResult::Fail("ring non-empty after repeat"); }

    // Third report: A released, B pressed (still LShift held) →
    // one release (A) + one press (B), no LShift transition.
    let r3 = KbdReport::from_bytes([
        hid::kbd_mod::LSHIFT, 0,
        0x05, 0, 0, 0, 0, 0,
    ]);
    let n3 = kbd.translate_report(r3);
    if n3 != 2 { return TestResult::Fail("expected 2 events on swap"); }

    let mut got_a_release = false;
    let mut got_b_press   = false;
    for _ in 0..2 {
        match pop_global() {
            Some(InputEvent::Key(k)) => {
                if k.code == KeyCode::A && !k.pressed { got_a_release = true; }
                if k.code == KeyCode::B &&  k.pressed { got_b_press   = true; }
            }
            _ => return TestResult::Fail("missing event after swap"),
        }
    }
    if !got_a_release { return TestResult::Fail("A release missing"); }
    if !got_b_press   { return TestResult::Fail("B press missing");   }

    // Fourth report: empty (everything released) → LShift release
    // and B release.
    let r4 = KbdReport::from_bytes([0; 8]);
    let n4 = kbd.translate_report(r4);
    if n4 != 2 { return TestResult::Fail("expected 2 releases on clear"); }

    let mut got_shift_release = false;
    let mut got_b_release     = false;
    for _ in 0..2 {
        match pop_global() {
            Some(InputEvent::Key(k)) => {
                if k.code == KeyCode::LeftShift && !k.pressed { got_shift_release = true; }
                if k.code == KeyCode::B         && !k.pressed { got_b_release     = true; }
            }
            _ => return TestResult::Fail("missing release event"),
        }
    }
    if !got_shift_release { return TestResult::Fail("LShift release missing"); }
    if !got_b_release     { return TestResult::Fail("B release missing");     }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_diff_press_release_repeat);

fn smoke_hid_rollover_suppressed() -> TestResult {
    use crate::hid::{self, BootKeyboard, KbdReport};
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_global};

    init_global_ring(64);
    __reset_global_ring_for_test();
    let mut kbd = BootKeyboard {
        slot_id: 1, interrupt_in_ep: 3, interface_num: 0,
        last_report: KbdReport::default(),
    };
    // The HID error roll-over: all six positions = 0x01 with no
    // modifier bits set. Should produce zero events.
    let roll = KbdReport::from_bytes([0, 0, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
    let n = kbd.translate_report(roll);
    if n != 0 { return TestResult::Fail("rollover emitted events"); }
    if pop_global().is_some() { return TestResult::Fail("rollover wrote to ring"); }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_rollover_suppressed);

fn smoke_hid_modifier_only_transition() -> TestResult {
    use crate::hid::{self, BootKeyboard, KbdReport};
    use narf_input::{InputEvent, KeyCode, Modifiers,
                     __reset_global_ring_for_test, init_global_ring, pop_global};

    init_global_ring(64);
    __reset_global_ring_for_test();
    let mut kbd = BootKeyboard {
        slot_id: 1, interrupt_in_ep: 3, interface_num: 0,
        last_report: KbdReport::default(),
    };
    // Press LCtrl alone → one event with CTRL set.
    let r1 = KbdReport::from_bytes([hid::kbd_mod::LCTRL, 0, 0, 0, 0, 0, 0, 0]);
    let n1 = kbd.translate_report(r1);
    if n1 != 1 { return TestResult::Fail("expected 1 event for ctrl press"); }
    match pop_global() {
        Some(InputEvent::Key(k)) => {
            if !(k.pressed && k.code == KeyCode::LeftCtrl
                && k.modifiers.contains(Modifiers::CTRL)) {
                return TestResult::Fail("ctrl press shape wrong");
            }
        }
        _ => return TestResult::Fail("ctrl press missing"),
    }
    // Add RAlt on top of LCtrl → one event (RAlt press) carrying
    // both CTRL and ALT.
    let r2 = KbdReport::from_bytes([
        hid::kbd_mod::LCTRL | hid::kbd_mod::RALT, 0, 0, 0, 0, 0, 0, 0]);
    let n2 = kbd.translate_report(r2);
    if n2 != 1 { return TestResult::Fail("expected 1 event for ralt add"); }
    match pop_global() {
        Some(InputEvent::Key(k)) => {
            if !(k.pressed && k.code == KeyCode::RightAlt
                && k.modifiers.contains(Modifiers::CTRL)
                && k.modifiers.contains(Modifiers::ALT)) {
                return TestResult::Fail("ralt-add shape wrong");
            }
        }
        _ => return TestResult::Fail("ralt-add missing"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid", smoke_hid_modifier_only_transition);
