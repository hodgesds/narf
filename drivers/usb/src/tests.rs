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
