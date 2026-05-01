//! Per-driver smoke tests for `narf-drivers-nvme`. Tests register
//! via `narf_kernel_test::kernel_test_in!` so the runner groups
//! output under `drivers/nvme`.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_nvme_samsung_pci_matches() -> TestResult {
    // Structural smoke: register the NVMe driver and verify the
    // Samsung PM9A1 / 970 EVO / 990 PRO VID/DID entries plus the
    // QEMU pair plus the class-match backstop are all in the
    // bus's match table. Real-silicon binding only happens on a
    // host with a Samsung NVMe drive (the user's Ryzen 7 PRO
    // 8840HS reference laptop has a PM9A1), so the always-on bit
    // is the structural assertion that registration shipped.
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    use crate as nvme;
    __reset_for_test();
    nvme::register_pci_driver();
    let regs = registered_pci_drivers();
    let want: &[(u16, u16)] = &[
        (nvme::QEMU_NVME_VENDOR, nvme::QEMU_NVME_DEVICE),
        (nvme::SAMSUNG_VENDOR,   nvme::SAMSUNG_PM9A1),
        (nvme::SAMSUNG_VENDOR,   nvme::SAMSUNG_970EVO),
        (nvme::SAMSUNG_VENDOR,   nvme::SAMSUNG_990PRO),
    ];
    for (v, d) in want.iter().copied() {
        let found = regs.iter().any(|m|
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == v && device == d));
        if !found {
            return TestResult::Fail("missing nvme VID/DID match");
        }
    }
    let class_match = regs.iter().any(|m|
        matches!(m.kind, MatchKind::Class {
            class: 0x01, mask: 0xFF,
        }));
    if !class_match {
        return TestResult::Fail("nvme class-match backstop missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_samsung_pci_matches);

fn smoke_nvme_cap_register_decode() -> TestResult {
    use crate::NvmeCaps;
    // CAP layout: MQES[0..=15], DSTRD[32..=35], MPSMIN[48..=51],
    // MPSMAX[52..=55]. Craft a value with MQES=0x3FF, DSTRD=2,
    // MPSMIN=0, MPSMAX=4 and check the decoder.
    let raw: u64 = 0x3FF
        | (2u64 << 32)
        | (0u64 << 48)
        | (4u64 << 52);
    let c = NvmeCaps::from_raw(raw);
    if c.mqes != 0x3FF || c.dstrd != 2 || c.mpsmin != 0 || c.mpsmax != 4 {
        return TestResult::Fail("NvmeCaps::from_raw decoded wrong");
    }
    if c.doorbell_stride() != 16 {
        return TestResult::Fail("doorbell stride mis-computed (4 << 2 = 16)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_cap_register_decode);

fn smoke_nvme_probe_stub_surfaces_not_implemented() -> TestResult {
    use narf_capabilities::{Cap, Write};
    use crate::{Controller, NvmeError};
    let mut ctrl = Controller::new(0x8000_0000);
    let cap: Cap<narf_bus::BusDeviceCap, Write> = Cap::bootstrap();
    match ctrl.probe(&cap) {
        Err(NvmeError::NotImplemented) => {}
        _ => return TestResult::Fail("probe should surface NotImplemented"),
    }
    let mut bad = Controller::new(0);
    if bad.probe(&cap) != Err(NvmeError::BadBar) {
        return TestResult::Fail("zero BAR should surface BadBar");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_probe_stub_surfaces_not_implemented);

fn smoke_nvme_admin_identify_controller() -> TestResult {
    // End-to-end NVMe admin-queue bring-up against the QEMU NVMe
    // device (vendor 0x1B36 / device 0x0010).
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use crate::Controller;
    // SAFETY: ECAM is identity-mapped; bus::init is idempotent.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme_dev = devs.iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. })
            && d.id.vendor == 0x1B36
            && d.id.device == 0x0010
    });
    let Some(dev) = nvme_dev.copied() else {
        return TestResult::Skip("no QEMU NVMe controller in this flavour");
    };
    let authority = bootstrap_registry_authority();
    let (_handle, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok)  => ok,
        Err(_)  => return TestResult::Fail("claim_device_cap failed for NVMe"),
    };
    let mut ctrl = Controller::from_device(dev);
    if let Err(e) = ctrl.bring_up(&dev_cap) {
        let _ = e;
        return TestResult::Fail("Controller::bring_up failed");
    }
    if !ctrl.is_ready() {
        return TestResult::Fail("controller didn't transition to ready");
    }
    let id = match ctrl.identify() {
        Some(i) => i,
        None    => return TestResult::Fail("identify snapshot missing"),
    };
    if id.vid != 0x1B36 {
        return TestResult::Fail("identify VID mismatch");
    }
    if &id.mn[..4] != b"QEMU" {
        return TestResult::Fail("identify MN does not start with 'QEMU'");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_admin_identify_controller);

fn smoke_nvme_io_round_trip() -> TestResult {
    // End-to-end NVMe I/O: bring up, create one I/O queue pair,
    // write a 512-byte pattern at LBA 0, read it back, compare.
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use crate::Controller;
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme_dev = devs.iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. })
            && d.id.vendor == 0x1B36
            && d.id.device == 0x0010
    });
    let Some(dev) = nvme_dev.copied() else {
        return TestResult::Skip("no QEMU NVMe controller");
    };
    let authority = bootstrap_registry_authority();
    let (_h, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok)  => ok,
        Err(_)  => return TestResult::Fail("claim_device_cap failed"),
    };
    let mut ctrl = Controller::from_device(dev);
    if ctrl.bring_up(&dev_cap).is_err() {
        return TestResult::Fail("Controller::bring_up failed");
    }
    if ctrl.create_io_queue().is_err() {
        return TestResult::Fail("Controller::create_io_queue failed");
    }
    if ctrl.lba_bytes != 512 {
        return TestResult::Fail("expected 512-byte LBAs on QEMU default");
    }
    if ctrl.nsze == 0 {
        return TestResult::Fail("namespace reported zero size");
    }
    let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_coherent failed"),
    };
    let phys = buf.phys_addr().raw();
    // SAFETY: identity-mapped DMA buffer.
    unsafe {
        for i in 0..512usize {
            core::ptr::write_volatile((phys as *mut u8).add(i), (i as u8) ^ 0xA5);
        }
    }
    if ctrl.write_lba(0, 1, &buf).is_err() {
        return TestResult::Fail("write_lba(0) failed");
    }
    // SAFETY: still our identity-mapped DMA buffer.
    unsafe {
        for i in 0..4096usize {
            core::ptr::write_volatile((phys as *mut u8).add(i), 0);
        }
    }
    if ctrl.read_lba(0, 1, &buf).is_err() {
        return TestResult::Fail("read_lba(0) failed");
    }
    for i in 0..512usize {
        let v = unsafe { core::ptr::read_volatile((phys as *const u8).add(i)) };
        let expected = (i as u8) ^ 0xA5;
        if v != expected {
            return TestResult::Fail("read-back pattern mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_io_round_trip);

fn smoke_nvme_io_msix_irq_driven() -> TestResult {
    // End-to-end IRQ-driven NVMe I/O: bring up, enable MSI-X with
    // one vector wired to a fresh IDT slot, create the I/O queue
    // with IEN=1, do a write+read round trip, assert IRQ dispatch
    // observed ≥1 MSI delivery.
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use crate::{Controller, IoOpcode};
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme_dev = devs.iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. })
            && d.id.vendor == 0x1B36
            && d.id.device == 0x0010
    });
    let Some(dev) = nvme_dev.copied() else {
        return TestResult::Skip("no QEMU NVMe controller");
    };
    let authority = bootstrap_registry_authority();
    let (_h, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok)  => ok,
        Err(_)  => return TestResult::Fail("claim_device_cap failed"),
    };
    let mut ctrl = Controller::from_device(dev);
    if ctrl.bring_up(&dev_cap).is_err() {
        return TestResult::Fail("Controller::bring_up failed");
    }
    let v = match ctrl.create_io_queue_msix(&dev_cap) {
        Ok(v)  => v,
        Err(_) => return TestResult::Fail("create_io_queue_msix failed"),
    };
    // SAFETY: APIC is initialised; MSI lands in our IDT vector.
    unsafe { narf_arch::enable_interrupts(); }
    let baseline = narf_interrupts::fire_count(v);
    let buf = match alloc_coherent(4096, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_coherent failed"),
    };
    let phys = buf.phys_addr().raw();
    // SAFETY: identity-mapped DMA page.
    unsafe {
        for i in 0..512usize {
            core::ptr::write_volatile((phys as *mut u8).add(i), (i as u8).wrapping_mul(7));
        }
    }
    if ctrl.submit_io_irq(IoOpcode::Write as u8, 1, 1, &buf).is_err() {
        return TestResult::Fail("submit_io_irq(Write) failed");
    }
    // SAFETY: same.
    unsafe {
        for i in 0..4096usize {
            core::ptr::write_volatile((phys as *mut u8).add(i), 0);
        }
    }
    if ctrl.submit_io_irq(IoOpcode::Read as u8, 1, 1, &buf).is_err() {
        return TestResult::Fail("submit_io_irq(Read) failed");
    }
    for i in 0..512usize {
        let v = unsafe { core::ptr::read_volatile((phys as *const u8).add(i)) };
        if v != (i as u8).wrapping_mul(7) {
            return TestResult::Fail("IRQ-driven read-back pattern mismatch");
        }
    }
    let after = narf_interrupts::fire_count(v);
    // SAFETY: counterpart to the enable_interrupts above.
    unsafe { narf_arch::disable_interrupts(); }
    if after <= baseline {
        return TestResult::Fail("IRQ dispatch fire_count never advanced");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_io_msix_irq_driven);

fn smoke_nvme_params_typed_round_trip() -> TestResult {
    // Drive the typed driver-parameter surface end-to-end.
    use narf_bus::{bootstrap_registry_authority, devices, BusKind, probe_all_pci};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_capabilities::{Cap, Write};
    use narf_drivers::DriverHandle;
    use crate::{LogLevel, NvmeUpdate, PARAMS};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has_nvme = devs.iter().any(|d|
        matches!(&d.kind, BusKind::Pcie { .. })
        && d.id.vendor == 0x1B36 && d.id.device == 0x0010);
    if !has_nvme {
        return TestResult::Skip("no QEMU NVMe controller");
    }
    __reset_for_test();
    PARAMS.__reset_for_test();
    crate::register_pci_driver();
    let authority = bootstrap_registry_authority();
    if probe_all_pci(&authority).is_err() {
        return TestResult::Fail("probe_all_pci failed");
    }
    if !PARAMS.is_installed() {
        return TestResult::Fail("PARAMS not installed by probe");
    }
    let driver_cap: Cap<DriverHandle, Write> = Cap::bootstrap();
    let read_cap: Cap<DriverHandle, narf_capabilities::Read> =
        match driver_cap.derive() {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("Read derivation from Write failed"),
        };
    let snap = match PARAMS.read(&read_cap) {
        Ok(s)  => s,
        Err(_) => return TestResult::Fail("PARAMS.read failed"),
    };
    if snap.identify_vid != 0x1B36 {
        return TestResult::Fail("snapshot.identify_vid mismatch");
    }
    if snap.lba_bytes != 512 {
        return TestResult::Fail("snapshot.lba_bytes != 512");
    }
    if snap.log_level != LogLevel::Info {
        return TestResult::Fail("snapshot.log_level default != Info");
    }
    if PARAMS.write(&driver_cap, NvmeUpdate::SetLogLevel(LogLevel::Debug)).is_err() {
        return TestResult::Fail("PARAMS.write failed");
    }
    let snap2 = PARAMS.read(&read_cap).expect("re-read");
    if snap2.log_level != LogLevel::Debug {
        return TestResult::Fail("Update::SetLogLevel did not stick");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_params_typed_round_trip);
