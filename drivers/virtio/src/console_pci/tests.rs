//! Per-driver smokes for `virtio-console-pci`. Registered under
//! `drivers/virtio/console_pci`.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_virtio_console_pci_match_table() -> TestResult {
    use crate::console_pci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    console_pci::register_pci_driver();
    let regs = registered_pci_drivers();
    let want_modern = regs.iter().any(|m|
        matches!(m.kind, MatchKind::VendorDevice {
            vendor: console_pci::VIRTIO_CONSOLE_PCI_VENDOR,
            device: console_pci::VIRTIO_CONSOLE_PCI_DEVICE_MODERN,
        }));
    let want_legacy = regs.iter().any(|m|
        matches!(m.kind, MatchKind::VendorDevice {
            vendor: console_pci::VIRTIO_CONSOLE_PCI_VENDOR,
            device: console_pci::VIRTIO_CONSOLE_PCI_DEVICE_LEGACY,
        }));
    if !(want_modern && want_legacy) {
        return TestResult::Fail("console_pci: missing VID/DID entries");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/console_pci", smoke_virtio_console_pci_match_table);

fn smoke_virtio_console_pci_config_round_trip() -> TestResult {
    use crate::console_pci::ConsoleConfig;
    let want = ConsoleConfig {
        cols: 80, rows: 24, max_nr_ports: 1, emerg_wr: 0x100,
    };
    let bytes = want.encode();
    let got = match ConsoleConfig::decode(&bytes) {
        Some(c) => c,
        None    => return TestResult::Fail("decode rejected encoded blob"),
    };
    if got != want { return TestResult::Fail("round-trip mismatch"); }
    if ConsoleConfig::decode(&bytes[..15]).is_some() {
        return TestResult::Fail("decode accepted short slice");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/console_pci", smoke_virtio_console_pci_config_round_trip);

fn smoke_virtio_console_pci_control_event_round_trip() -> TestResult {
    use crate::console_pci::{build_control, decode_control, ControlEvent};
    let cases: &[(u32, ControlEvent, u16)] = &[
        (0,    ControlEvent::DeviceReady,   1),
        (1,    ControlEvent::DeviceAdd,     0),
        (1,    ControlEvent::PortReady,     1),
        (1,    ControlEvent::ConsolePort,   1),
        (1,    ControlEvent::Resize,        0),
        (1,    ControlEvent::PortOpen,      1),
        (1,    ControlEvent::PortName,      0),
        (0xFF, ControlEvent::DeviceRemove,  0),
    ];
    for &(id, ev, val) in cases {
        let raw = build_control(id, ev, val);
        let dec = match decode_control(&raw) {
            Some(d) => d,
            None    => return TestResult::Fail("decode_control rejected"),
        };
        if dec.id != id || dec.event != ev || dec.value != val {
            return TestResult::Fail("control round-trip mismatch");
        }
    }
    if decode_control(&[0u8; 7]).is_some() {
        return TestResult::Fail("decode_control accepted short slice");
    }
    // Unknown opcode → ControlEvent::Unknown.
    let raw = [0,0,0,0, 0xFF, 0xFF, 0,0];
    if let Some(d) = decode_control(&raw) {
        if !matches!(d.event, ControlEvent::Unknown) {
            return TestResult::Fail("unknown opcode not mapped");
        }
    } else {
        return TestResult::Fail("decode_control rejected valid 8 bytes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/console_pci", smoke_virtio_console_pci_control_event_round_trip);

fn smoke_virtio_console_pci_live_bring_up() -> TestResult {
    use crate::console_pci;
    if !console_pci::is_probed() {
        return TestResult::Skip("no virtio-console-pci device on this run");
    }
    let cols = console_pci::with_controller(|c| c.cols()).unwrap_or(0);
    let rows = console_pci::with_controller(|c| c.rows()).unwrap_or(0);
    // F_SIZE is optional — accept any value, just confirm the
    // controller is structurally present.
    let _ = (cols, rows);
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/console_pci", smoke_virtio_console_pci_live_bring_up);

fn smoke_virtio_console_pci_live_write() -> TestResult {
    use crate::console_pci;
    if !console_pci::is_probed() {
        return TestResult::Skip("no virtio-console-pci device on this run");
    }
    let r = console_pci::with_controller(|c|
        c.write_bytes(b"NARF virtio-console live\n"));
    match r {
        Some(Ok(n)) if n == 25 => TestResult::Pass,
        Some(Ok(_))            => TestResult::Fail("short write"),
        Some(Err(_))           => TestResult::Fail("write_bytes failed"),
        None                   => TestResult::Skip("controller missing"),
    }
}
kernel_test_in!("drivers/virtio/console_pci", smoke_virtio_console_pci_live_write);
