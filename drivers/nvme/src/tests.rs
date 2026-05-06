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
    use crate as nvme;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    nvme::register_pci_driver();
    let regs = registered_pci_drivers();
    let want: &[(u16, u16)] = &[
        (nvme::QEMU_NVME_VENDOR, nvme::QEMU_NVME_DEVICE),
        (nvme::SAMSUNG_VENDOR, nvme::SAMSUNG_PM9A1),
        (nvme::SAMSUNG_VENDOR, nvme::SAMSUNG_970EVO),
        (nvme::SAMSUNG_VENDOR, nvme::SAMSUNG_990PRO),
    ];
    for (v, d) in want.iter().copied() {
        let found = regs.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor, device,
            } if vendor == v && device == d)
        });
        if !found {
            return TestResult::Fail("missing nvme VID/DID match");
        }
    }
    let class_match = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::Class {
                class: 0x01,
                mask: 0xFF,
            }
        )
    });
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
    let raw: u64 = 0x3FF | (2u64 << 32) | (0u64 << 48) | (4u64 << 52);
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
    use crate::{Controller, NvmeError};
    use narf_capabilities::{Cap, Write};
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
kernel_test_in!(
    "drivers/nvme",
    smoke_nvme_probe_stub_surfaces_not_implemented
);

fn smoke_nvme_admin_identify_controller() -> TestResult {
    // End-to-end NVMe admin-queue bring-up against the QEMU NVMe
    // device (vendor 0x1B36 / device 0x0010).
    use crate::Controller;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    // SAFETY: ECAM is identity-mapped; bus::init is idempotent.
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme_dev = devs.iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
    let Some(dev) = nvme_dev.copied() else {
        return TestResult::Skip("no QEMU NVMe controller in this flavour");
    };
    let authority = bootstrap_registry_authority();
    let (_handle, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed for NVMe"),
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
        None => return TestResult::Fail("identify snapshot missing"),
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
    use crate::Controller;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme_dev = devs.iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
    let Some(dev) = nvme_dev.copied() else {
        return TestResult::Skip("no QEMU NVMe controller");
    };
    let authority = bootstrap_registry_authority();
    let (_h, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed"),
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
    use crate::{Controller, IoOpcode};
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let nvme_dev = devs.iter().find(|d| {
        matches!(d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
    let Some(dev) = nvme_dev.copied() else {
        return TestResult::Skip("no QEMU NVMe controller");
    };
    let authority = bootstrap_registry_authority();
    let (_h, dev_cap) = match claim_device_cap(&authority, dev.addr) {
        Ok(ok) => ok,
        Err(_) => return TestResult::Fail("claim_device_cap failed"),
    };
    let mut ctrl = Controller::from_device(dev);
    if ctrl.bring_up(&dev_cap).is_err() {
        return TestResult::Fail("Controller::bring_up failed");
    }
    let v = match ctrl.create_io_queue_msix(&dev_cap) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("create_io_queue_msix failed"),
    };
    // SAFETY: APIC is initialised; MSI lands in our IDT vector.
    unsafe {
        narf_arch::enable_interrupts();
    }
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
    if ctrl
        .submit_io_irq(IoOpcode::Write as u8, 1, 1, &buf)
        .is_err()
    {
        return TestResult::Fail("submit_io_irq(Write) failed");
    }
    // SAFETY: same.
    unsafe {
        for i in 0..4096usize {
            core::ptr::write_volatile((phys as *mut u8).add(i), 0);
        }
    }
    if ctrl
        .submit_io_irq(IoOpcode::Read as u8, 1, 1, &buf)
        .is_err()
    {
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
    unsafe {
        narf_arch::disable_interrupts();
    }
    if after <= baseline {
        return TestResult::Fail("IRQ dispatch fire_count never advanced");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_io_msix_irq_driven);

fn smoke_nvme_params_typed_round_trip() -> TestResult {
    // Drive the typed driver-parameter surface end-to-end.
    use crate::{LogLevel, NvmeUpdate, PARAMS};
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    use narf_capabilities::{Cap, Write};
    use narf_drivers::DriverHandle;
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has_nvme = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
    });
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
    let read_cap: Cap<DriverHandle, narf_capabilities::Read> = match driver_cap.derive() {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("Read derivation from Write failed"),
    };
    let snap = match PARAMS.read(&read_cap) {
        Ok(s) => s,
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
    if PARAMS
        .write(&driver_cap, NvmeUpdate::SetLogLevel(LogLevel::Debug))
        .is_err()
    {
        return TestResult::Fail("PARAMS.write failed");
    }
    let snap2 = PARAMS.read(&read_cap).expect("re-read");
    if snap2.log_level != LogLevel::Debug {
        return TestResult::Fail("Update::SetLogLevel did not stick");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme", smoke_nvme_params_typed_round_trip);

// ── NVMe-MI message framing smokes ─────────────────────────────────

fn smoke_mi_nmh_round_trip() -> TestResult {
    use crate::mi::{Nmh, NMIMT_MI_COMMAND, MET_OUT_OF_BAND};
    let nmh = Nmh {
        mctp_ic: true,
        command_slot: false,
        response: false,
        nmimt: NMIMT_MI_COMMAND,
        met: MET_OUT_OF_BAND,
    };
    let bytes = nmh.encode();
    let back = Nmh::decode(&bytes);
    if back != nmh {
        return TestResult::Fail("NMH round-trip mismatch");
    }
    if bytes[0] & 0x80 == 0 {
        return TestResult::Fail("MCTP IC bit should be at byte 0 bit 7");
    }
    if (bytes[1] >> 4) != NMIMT_MI_COMMAND {
        return TestResult::Fail("NMIMT lives in byte 1 high nibble");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/mi", smoke_mi_nmh_round_trip);

fn smoke_mi_mic_crc32_matches_known_vector() -> TestResult {
    use crate::mi::mic;
    // CRC-32/Ethernet of "123456789" is 0xCBF43926 (well-known).
    let r = mic(b"123456789");
    if r != 0xCBF4_3926 {
        return TestResult::Fail("CRC-32/Ethernet test vector mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/mi", smoke_mi_mic_crc32_matches_known_vector);

fn smoke_mi_build_and_decode_command_round_trip() -> TestResult {
    use crate::mi::{
        build_command, decode_message, read_data_structure, Nmh, DTYPE_CONTROLLER_LIST,
        MI_OPCODE_READ_DATA_STRUCTURE, NMIMT_MI_COMMAND,
    };
    let nmh = Nmh {
        mctp_ic: true,
        nmimt: NMIMT_MI_COMMAND,
        ..Default::default()
    };
    let body = read_data_structure(DTYPE_CONTROLLER_LIST, 0x0042);
    let frame = build_command(nmh, &body);
    // 4 (NMH) + 12 (opcode + 2 cdw header) + 4 (MIC) = 20 bytes.
    if frame.len() != 20 {
        return TestResult::Fail("expected 20-byte minimal NVMe-MI command");
    }
    let (back_nmh, back_body) = decode_message(&frame).expect("decode");
    if back_nmh != nmh {
        return TestResult::Fail("NMH decode mismatch");
    }
    if back_body.opcode != MI_OPCODE_READ_DATA_STRUCTURE {
        return TestResult::Fail("opcode lost");
    }
    let dtype = (back_body.cdw0 & 0xFF) as u8;
    let cid = (back_body.cdw0 >> 16) as u16;
    if dtype != DTYPE_CONTROLLER_LIST {
        return TestResult::Fail("DTYPE lives in CDW0[7:0]");
    }
    if cid != 0x0042 {
        return TestResult::Fail("controller id lives in CDW0[31:16]");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/mi", smoke_mi_build_and_decode_command_round_trip);

fn smoke_mi_bad_mic_rejected() -> TestResult {
    use crate::mi::{build_command, decode_message, read_data_structure, MiError, Nmh, NMIMT_MI_COMMAND};
    let nmh = Nmh { mctp_ic: true, nmimt: NMIMT_MI_COMMAND, ..Default::default() };
    let mut frame = build_command(nmh, &read_data_structure(0, 0));
    let last = frame.len() - 1;
    frame[last] = frame[last].wrapping_add(1);
    match decode_message(&frame) {
        Err(MiError::BadMic) => TestResult::Pass,
        _ => TestResult::Fail("tampered MIC must be rejected"),
    }
}
kernel_test_in!("drivers/nvme/mi", smoke_mi_bad_mic_rejected);

fn smoke_mi_subsystem_health_status_poll_clear_bit() -> TestResult {
    use crate::mi::{subsystem_health_status_poll, MI_OPCODE_NVM_SUBSYSTEM_HEALTH_STATUS_POLL};
    let cmd = subsystem_health_status_poll(true);
    if cmd.opcode != MI_OPCODE_NVM_SUBSYSTEM_HEALTH_STATUS_POLL {
        return TestResult::Fail("opcode 0x01 expected");
    }
    if cmd.cdw1 & (1 << 31) == 0 {
        return TestResult::Fail("Clear Status flag lives at CDW1 bit 31");
    }
    let cmd2 = subsystem_health_status_poll(false);
    if cmd2.cdw1 != 0 {
        return TestResult::Fail("CDW1 should be zero when Clear Status not requested");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/mi", smoke_mi_subsystem_health_status_poll_clear_bit);

fn smoke_mi_subsystem_health_parse() -> TestResult {
    use crate::mi::SubsystemHealth;
    // 8-byte response data: NSS=0x02 (CFS), warnings=0x10, temp=0x2A,
    // pct_used=0x05, composite controller status (LE) = 0x0007.
    let buf = [0x02u8, 0x10, 0x2A, 0x05, 0x07, 0x00, 0x00, 0x00];
    let h = SubsystemHealth::parse(&buf).expect("parse");
    if h.nss != 0x02 || h.smart_warnings != 0x10 {
        return TestResult::Fail("NSS / warning byte mismatch");
    }
    if h.composite_temperature != 0x2A || h.percentage_used != 0x05 {
        return TestResult::Fail("temperature / wear byte mismatch");
    }
    if h.composite_controller_status != 0x0007 {
        return TestResult::Fail("CCS LE decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/mi", smoke_mi_subsystem_health_parse);

// ── NVMe admin-command builder smokes ──────────────────────────────

fn smoke_admin_sqe_cdw0_packs_opcode_and_cid() -> TestResult {
    use crate::admin::{AdminSqe, OPC_IDENTIFY};
    let mut sqe = AdminSqe::new(OPC_IDENTIFY);
    sqe.cid = 0x1234;
    let cdw0 = sqe.cdw0();
    if (cdw0 & 0xFF) != OPC_IDENTIFY as u32 {
        return TestResult::Fail("opcode lives in CDW0[7:0]");
    }
    if (cdw0 >> 16) != 0x1234 {
        return TestResult::Fail("CID lives in CDW0[31:16]");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_sqe_cdw0_packs_opcode_and_cid);

fn smoke_admin_sqe_encode_is_64_bytes() -> TestResult {
    use crate::admin::AdminSqe;
    let sqe = AdminSqe::new(0x06);
    let bytes = sqe.encode();
    if bytes.len() != 64 {
        return TestResult::Fail("SQE wire form is 64 bytes per Base 2.0c §3.3.3");
    }
    // CDW0 LE byte 0 should equal opcode 0x06.
    if bytes[0] != 0x06 {
        return TestResult::Fail("CDW0 LE byte 0 should carry opcode");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_sqe_encode_is_64_bytes);

fn smoke_admin_format_nvm_cdw10_layout() -> TestResult {
    use crate::admin::{format_nvm, OPC_FORMAT_NVM, SES_CRYPTO_ERASE};
    let sqe = format_nvm(7, 1, 0x03, SES_CRYPTO_ERASE);
    if sqe.opcode != OPC_FORMAT_NVM {
        return TestResult::Fail("opcode = 0x80 for Format NVM");
    }
    if sqe.nsid != 1 {
        return TestResult::Fail("NSID lost");
    }
    // CDW10[3:0] = LBAF, CDW10[11:9] = SES.
    if (sqe.cdw10 & 0x0F) != 0x03 {
        return TestResult::Fail("LBAF should be in CDW10 low nibble");
    }
    if ((sqe.cdw10 >> 9) & 0x07) != SES_CRYPTO_ERASE as u32 {
        return TestResult::Fail("SES should be at CDW10 bits 11..9");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_format_nvm_cdw10_layout);

fn smoke_admin_sanitize_block_erase_layout() -> TestResult {
    use crate::admin::{sanitize, OPC_SANITIZE, SANACT_BLOCK_ERASE};
    let sqe = sanitize(11, SANACT_BLOCK_ERASE, true, 0, false, 0xDEAD_BEEF);
    if sqe.opcode != OPC_SANITIZE {
        return TestResult::Fail("opcode = 0x84 for Sanitize");
    }
    if (sqe.cdw10 & 0x07) != SANACT_BLOCK_ERASE as u32 {
        return TestResult::Fail("SANACT lives in CDW10[2:0]");
    }
    if (sqe.cdw10 & (1 << 3)) == 0 {
        return TestResult::Fail("AUSE bit should be set");
    }
    if sqe.cdw11 != 0xDEAD_BEEF {
        return TestResult::Fail("overwrite pattern goes in CDW11");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_sanitize_block_erase_layout);

fn smoke_admin_get_log_page_smart_layout() -> TestResult {
    use crate::admin::{get_smart_log, LID_SMART_HEALTH, OPC_GET_LOG_PAGE};
    let sqe = get_smart_log(2, 0xCAFE_F000_0000_0000);
    if sqe.opcode != OPC_GET_LOG_PAGE {
        return TestResult::Fail("opcode = 0x02 for Get Log Page");
    }
    if sqe.nsid != 0xFFFF_FFFF {
        return TestResult::Fail("SMART log uses controller-wide NSID 0xFFFF_FFFF");
    }
    // CDW10[7:0] = LID, CDW10[31:16] = NUMDL.
    if (sqe.cdw10 & 0xFF) != LID_SMART_HEALTH as u32 {
        return TestResult::Fail("LID should be in CDW10 low byte");
    }
    if (sqe.cdw10 >> 16) != 127 {
        return TestResult::Fail("NUMDL should encode 512-byte transfer (numd=127)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_get_log_page_smart_layout);

fn smoke_admin_set_features_number_of_queues() -> TestResult {
    use crate::admin::{set_features_number_of_queues, FID_NUMBER_OF_QUEUES, OPC_SET_FEATURES};
    let sqe = set_features_number_of_queues(0, 7, 5);
    if sqe.opcode != OPC_SET_FEATURES {
        return TestResult::Fail("opcode = 0x09 for Set Features");
    }
    if (sqe.cdw10 & 0xFF) != FID_NUMBER_OF_QUEUES as u32 {
        return TestResult::Fail("FID = 0x07");
    }
    if (sqe.cdw11 & 0xFFFF) != 7 {
        return TestResult::Fail("NSQR lives in CDW11[15:0]");
    }
    if (sqe.cdw11 >> 16) != 5 {
        return TestResult::Fail("NCQR lives in CDW11[31:16]");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_set_features_number_of_queues);

fn smoke_admin_smart_log_round_trip() -> TestResult {
    use crate::admin::{encode_smart_log, SmartLog};
    let s = SmartLog {
        critical_warning: 0x02,
        composite_temperature_k: 313,
        available_spare: 100,
        available_spare_threshold: 10,
        percentage_used: 5,
        power_on_hours: 1234,
        unsafe_shutdowns: 7,
        media_errors: 0,
    };
    let buf = encode_smart_log(s);
    let back = SmartLog::parse(&buf).expect("parse");
    if back != s {
        return TestResult::Fail("SMART log round-trip mismatch");
    }
    if back.composite_temperature_c() != 313 - 273 {
        return TestResult::Fail("Kelvin → Celsius conversion wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_smart_log_round_trip);

fn smoke_admin_set_features_boot_partition_wp_layout() -> TestResult {
    use crate::admin::{set_features_boot_partition_wp, FID_BOOT_PARTITION_WRITE_PROTECTION};
    let sqe = set_features_boot_partition_wp(0, 1, 0x02);
    if (sqe.cdw10 & 0xFF) != FID_BOOT_PARTITION_WRITE_PROTECTION as u32 {
        return TestResult::Fail("FID = 0x1A for Boot Partition WP");
    }
    if (sqe.cdw11 & 0x07) != 0x02 {
        return TestResult::Fail("BPWPS lives in CDW11[2:0]");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/admin", smoke_admin_set_features_boot_partition_wp_layout);
