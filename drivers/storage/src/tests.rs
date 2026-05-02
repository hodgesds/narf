//! Per-driver smoke tests for `narf-drivers-storage`. AHCI smokes
//! migrated from the verification mega-lib so they live next to
//! the driver code.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_ahci_hba_bring_up() -> TestResult {
    // QEMU q35 has the ICH9 AHCI controller at 00:1f.2 (8086:2922).
    // Probe it; assert HBA was reset cleanly + at least one port is
    // implemented + a SATA disk is detected on port 0.
    use narf_bus::{bootstrap_registry_authority, devices, BusKind, probe_all_pci};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use crate::ahci;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d|
        matches!(&d.kind, BusKind::Pcie { .. })
        && d.id.vendor == ahci::AHCI_VENDOR
        && d.id.device == ahci::AHCI_ICH9_DEV);
    if !has { return TestResult::Skip("no ICH9 AHCI"); }
    __reset_for_test();
    ahci::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci");
    }
    if !ahci::is_probed() {
        return TestResult::Fail("ahci probe didn't install controller");
    }
    let pi = ahci::with_controller(|c| c.ports_implemented()).unwrap_or(0);
    if pi == 0 { return TestResult::Fail("ports_implemented = 0"); }
    let n_ports = ahci::with_controller(|c| c.ports.len()).unwrap_or(0);
    if n_ports == 0 { return TestResult::Fail("no ports enumerated"); }
    let vs = ahci::with_controller(|c| c.version()).unwrap_or(0);
    if vs == 0 || vs == 0xFFFF_FFFF {
        return TestResult::Fail("version register reads as garbage");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_hba_bring_up);

fn smoke_ahci_identify_device() -> TestResult {
    // Issue IDENTIFY DEVICE on the first port whose probe-time
    // signature said "SATA". Verify the device-data block decodes
    // a non-empty model string. QEMU's emulated SATA disk reports
    // model "QEMU HARDDISK" (with trailing spaces).
    use narf_bus::{bootstrap_registry_authority, devices, BusKind, probe_all_pci};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use crate::ahci;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d|
        matches!(&d.kind, BusKind::Pcie { .. })
        && d.id.vendor == ahci::AHCI_VENDOR
        && d.id.device == ahci::AHCI_ICH9_DEV);
    if !has { return TestResult::Skip("no AHCI device"); }
    if !ahci::is_probed() {
        __reset_for_test();
        ahci::register_pci_driver();
        let authority = bootstrap_registry_authority();
        let _ = probe_all_pci(&authority);
    }
    if !ahci::is_probed() { return TestResult::Fail("ahci probe failed"); }
    let port = ahci::with_controller(|c|
        c.ports.iter().find(|p| p.kind == ahci::PortKind::Sata).map(|p| p.index)
    ).flatten();
    let idx = port.unwrap_or(0);
    // SAFETY: caller-trusted; the kernel-test harness owns the HBA.
    let id = match ahci::with_controller(|c|
        unsafe { c.identify_device(idx) }
    ).map(|r| r) {
        Some(Ok(buf)) => buf,
        Some(Err(_))  => return TestResult::Fail("identify_device failed"),
        None          => return TestResult::Fail("with_controller None"),
    };
    let model = ahci::identify_model(&id);
    if &model[..4] != b"QEMU" {
        return TestResult::Fail("IDENTIFY model != QEMU prefix");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_identify_device);

fn smoke_ahci_read_lba() -> TestResult {
    // Read sector 0 of the QEMU SATA disk and verify the pattern
    // xtask seeds the image with: byte i = (i * 0x6D) ^ 0x42.
    use narf_bus::{bootstrap_registry_authority, devices, BusKind, probe_all_pci};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use crate::ahci;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    if !devs.iter().any(|d|
        matches!(&d.kind, BusKind::Pcie { .. })
        && d.id.vendor == ahci::AHCI_VENDOR
        && d.id.device == ahci::AHCI_ICH9_DEV)
    { return TestResult::Skip("no AHCI device"); }
    if !ahci::is_probed() {
        __reset_for_test();
        ahci::register_pci_driver();
        let _ = probe_all_pci(&bootstrap_registry_authority());
    }
    if !ahci::is_probed() { return TestResult::Fail("ahci probe failed"); }
    let port = ahci::with_controller(|c|
        c.ports.iter().find(|p| p.kind == ahci::PortKind::Sata).map(|p| p.index)
    ).flatten().unwrap_or(0);
    let mut sector = [0u8; 512];
    let r = ahci::with_controller(|c|
        // SAFETY: kernel-test holds the HBA exclusively here.
        unsafe { ahci::ahci_read_lba(c, port, 0, 1, &mut sector) }
    );
    match r {
        Some(Ok(())) => {}
        Some(Err(_)) => return TestResult::Fail("ahci_read_lba failed"),
        None         => return TestResult::Fail("with_controller None"),
    }
    for i in 0..512usize {
        let expected = (i as u8).wrapping_mul(0x6D) ^ 0x42;
        if sector[i] != expected {
            return TestResult::Fail("AHCI read pattern mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_read_lba);

fn smoke_ahci_write_then_read_lba() -> TestResult {
    // Write a recognisable pattern at LBA 8 (well past the seeded
    // sector 0), read it back, verify.
    use narf_bus::{bootstrap_registry_authority, devices, BusKind, probe_all_pci};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use crate::ahci;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    if !devs.iter().any(|d|
        matches!(&d.kind, BusKind::Pcie { .. })
        && d.id.vendor == ahci::AHCI_VENDOR
        && d.id.device == ahci::AHCI_ICH9_DEV)
    { return TestResult::Skip("no AHCI device"); }
    if !ahci::is_probed() {
        __reset_for_test();
        ahci::register_pci_driver();
        let _ = probe_all_pci(&bootstrap_registry_authority());
    }
    if !ahci::is_probed() { return TestResult::Fail("ahci probe failed"); }
    let port = ahci::with_controller(|c|
        c.ports.iter().find(|p| p.kind == ahci::PortKind::Sata).map(|p| p.index)
    ).flatten().unwrap_or(0);
    let mut payload = [0u8; 512];
    for i in 0..512usize { payload[i] = (i as u8).wrapping_mul(0x29) ^ 0xA1; }
    let w = ahci::with_controller(|c|
        // SAFETY: kernel-test holds the HBA exclusively.
        unsafe { ahci::ahci_write_lba(c, port, 8, 1, &payload) }
    );
    if !matches!(w, Some(Ok(()))) {
        return TestResult::Fail("ahci_write_lba failed");
    }
    let mut readback = [0u8; 512];
    let r = ahci::with_controller(|c|
        // SAFETY: same.
        unsafe { ahci::ahci_read_lba(c, port, 8, 1, &mut readback) }
    );
    if !matches!(r, Some(Ok(()))) {
        return TestResult::Fail("ahci_read_lba(8) after write failed");
    }
    if readback != payload {
        return TestResult::Fail("AHCI write/read pattern mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_write_then_read_lba);

fn smoke_ahci_ncq_write_then_read_lba() -> TestResult {
    // NCQ round-trip: write at LBA 16 with WRITE FPDMA QUEUED on
    // tag 0, read back with READ FPDMA QUEUED on tag 1, verify
    // the payload survives the queued path.
    use narf_bus::{bootstrap_registry_authority, devices, BusKind, probe_all_pci};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use crate::ahci;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    if !devs.iter().any(|d|
        matches!(&d.kind, BusKind::Pcie { .. })
        && d.id.vendor == ahci::AHCI_VENDOR
        && d.id.device == ahci::AHCI_ICH9_DEV)
    { return TestResult::Skip("no AHCI device"); }
    if !ahci::is_probed() {
        __reset_for_test();
        ahci::register_pci_driver();
        let _ = probe_all_pci(&bootstrap_registry_authority());
    }
    if !ahci::is_probed() { return TestResult::Fail("ahci probe failed"); }
    let port = ahci::with_controller(|c|
        c.ports.iter().find(|p| p.kind == ahci::PortKind::Sata).map(|p| p.index)
    ).flatten().unwrap_or(0);
    let mut payload = [0u8; 512];
    for i in 0..512usize { payload[i] = (i as u8).wrapping_mul(0x53) ^ 0x9E; }
    let w = ahci::with_controller(|c|
        // SAFETY: kernel-test holds the HBA exclusively.
        unsafe { ahci::ahci_write_lba_ncq(c, port, 0, 0, 16, 1, &payload) }
    );
    if !matches!(w, Some(Ok(()))) {
        return TestResult::Fail("ahci_write_lba_ncq failed");
    }
    let mut readback = [0u8; 512];
    let r = ahci::with_controller(|c|
        // SAFETY: same.
        unsafe { ahci::ahci_read_lba_ncq(c, port, 0, 1, 16, 1, &mut readback) }
    );
    if !matches!(r, Some(Ok(()))) {
        return TestResult::Fail("ahci_read_lba_ncq failed");
    }
    if readback != payload {
        return TestResult::Fail("NCQ write/read pattern mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_ncq_write_then_read_lba);
