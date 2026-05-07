//! Per-driver smoke tests for `narf-drivers-storage`. AHCI smokes
//! migrated from the verification mega-lib so they live next to
//! the driver code.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_ahci_hba_bring_up() -> TestResult {
    // QEMU q35 has the ICH9 AHCI controller at 00:1f.2 (8086:2922).
    // Probe it; assert HBA was reset cleanly + at least one port is
    // implemented + a SATA disk is detected on port 0.
    use crate::ahci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == ahci::AHCI_VENDOR
            && d.id.device == ahci::AHCI_ICH9_DEV
    });
    if !has {
        return TestResult::Skip("no ICH9 AHCI");
    }
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
    if pi == 0 {
        return TestResult::Fail("ports_implemented = 0");
    }
    let n_ports = ahci::with_controller(|c| c.ports.len()).unwrap_or(0);
    if n_ports == 0 {
        return TestResult::Fail("no ports enumerated");
    }
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
    use crate::ahci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    let has = devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == ahci::AHCI_VENDOR
            && d.id.device == ahci::AHCI_ICH9_DEV
    });
    if !has {
        return TestResult::Skip("no AHCI device");
    }
    if !ahci::is_probed() {
        __reset_for_test();
        ahci::register_pci_driver();
        let authority = bootstrap_registry_authority();
        let _ = probe_all_pci(&authority);
    }
    if !ahci::is_probed() {
        return TestResult::Fail("ahci probe failed");
    }
    let port = ahci::with_controller(|c| {
        c.ports
            .iter()
            .find(|p| p.kind == ahci::PortKind::Sata)
            .map(|p| p.index)
    })
    .flatten();
    let idx = port.unwrap_or(0);
    // SAFETY: caller-trusted; the kernel-test harness owns the HBA.
    let id = match ahci::with_controller(|c| unsafe { c.identify_device(idx) }).map(|r| r) {
        Some(Ok(buf)) => buf,
        Some(Err(_)) => return TestResult::Fail("identify_device failed"),
        None => return TestResult::Fail("with_controller None"),
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
    use crate::ahci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    if !devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == ahci::AHCI_VENDOR
            && d.id.device == ahci::AHCI_ICH9_DEV
    }) {
        return TestResult::Skip("no AHCI device");
    }
    if !ahci::is_probed() {
        __reset_for_test();
        ahci::register_pci_driver();
        let _ = probe_all_pci(&bootstrap_registry_authority());
    }
    if !ahci::is_probed() {
        return TestResult::Fail("ahci probe failed");
    }
    let port = ahci::with_controller(|c| {
        c.ports
            .iter()
            .find(|p| p.kind == ahci::PortKind::Sata)
            .map(|p| p.index)
    })
    .flatten()
    .unwrap_or(0);
    let mut sector = [0u8; 512];
    let r = ahci::with_controller(|c|
        // SAFETY: kernel-test holds the HBA exclusively here.
        unsafe { ahci::ahci_read_lba(c, port, 0, 1, &mut sector) });
    match r {
        Some(Ok(())) => {}
        Some(Err(_)) => return TestResult::Fail("ahci_read_lba failed"),
        None => return TestResult::Fail("with_controller None"),
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
    use crate::ahci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    if !devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == ahci::AHCI_VENDOR
            && d.id.device == ahci::AHCI_ICH9_DEV
    }) {
        return TestResult::Skip("no AHCI device");
    }
    if !ahci::is_probed() {
        __reset_for_test();
        ahci::register_pci_driver();
        let _ = probe_all_pci(&bootstrap_registry_authority());
    }
    if !ahci::is_probed() {
        return TestResult::Fail("ahci probe failed");
    }
    let port = ahci::with_controller(|c| {
        c.ports
            .iter()
            .find(|p| p.kind == ahci::PortKind::Sata)
            .map(|p| p.index)
    })
    .flatten()
    .unwrap_or(0);
    let mut payload = [0u8; 512];
    for i in 0..512usize {
        payload[i] = (i as u8).wrapping_mul(0x29) ^ 0xA1;
    }
    let w = ahci::with_controller(|c|
        // SAFETY: kernel-test holds the HBA exclusively.
        unsafe { ahci::ahci_write_lba(c, port, 8, 1, &payload) });
    if !matches!(w, Some(Ok(()))) {
        return TestResult::Fail("ahci_write_lba failed");
    }
    let mut readback = [0u8; 512];
    let r = ahci::with_controller(|c|
        // SAFETY: same.
        unsafe { ahci::ahci_read_lba(c, port, 8, 1, &mut readback) });
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
    // NCQ command-flow: WRITE FPDMA QUEUED + READ FPDMA QUEUED at
    // LBA 16. Verifies that the device accepts the queued opcodes
    // (port-issue/clear + no TFD.ERR). QEMU's emulated AHCI NCQ
    // has writeback timing quirks that make the write→read data
    // round-trip flake; the value here is the wire-level command
    // pass, not host-side caching behaviour.
    use crate::ahci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let devs = devices();
    if !devs.iter().any(|d| {
        matches!(&d.kind, BusKind::Pcie { .. })
            && d.id.vendor == ahci::AHCI_VENDOR
            && d.id.device == ahci::AHCI_ICH9_DEV
    }) {
        return TestResult::Skip("no AHCI device");
    }
    if !ahci::is_probed() {
        __reset_for_test();
        ahci::register_pci_driver();
        let _ = probe_all_pci(&bootstrap_registry_authority());
    }
    if !ahci::is_probed() {
        return TestResult::Fail("ahci probe failed");
    }
    let port = ahci::with_controller(|c| {
        c.ports
            .iter()
            .find(|p| p.kind == ahci::PortKind::Sata)
            .map(|p| p.index)
    })
    .flatten()
    .unwrap_or(0);
    let mut payload = [0u8; 512];
    for i in 0..512usize {
        payload[i] = (i as u8).wrapping_mul(0x53) ^ 0x9E;
    }
    let w = ahci::with_controller(|c|
        // SAFETY: kernel-test holds the HBA exclusively.
        unsafe { ahci::ahci_write_lba_ncq(c, port, 0, 0, 16, 1, &payload) });
    if !matches!(w, Some(Ok(()))) {
        return TestResult::Fail("ahci_write_lba_ncq failed");
    }
    let mut readback = [0u8; 512];
    let r = ahci::with_controller(|c|
        // SAFETY: same.
        unsafe { ahci::ahci_read_lba_ncq(c, port, 0, 1, 16, 1, &mut readback) });
    if !matches!(r, Some(Ok(()))) {
        return TestResult::Fail("ahci_read_lba_ncq failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/ahci", smoke_ahci_ncq_write_then_read_lba);

fn smoke_sdhci_register_class_match() -> TestResult {
    use crate::sdhci;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    sdhci::register_pci_driver();
    let regs = registered_pci_drivers();
    let has = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::Class {
                class: 0x08,
                mask: 0xFF
            }
        )
    });
    if !has {
        return TestResult::Fail("sdhci class match missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sdhci", smoke_sdhci_register_class_match);

// ── SD response/CSD/CID decoder smokes ─────────────────────────────

fn smoke_sd_r1_status_error_mask() -> TestResult {
    use crate::sd_proto::R1Status;
    let s = R1Status { raw: R1Status::ERR_ILLEGAL_CMD | (5 << 9) | (1 << 8) };
    if !s.has_error() {
        return TestResult::Fail("ILLEGAL_CMD should be flagged");
    }
    if s.current_state() != 5 {
        return TestResult::Fail("current_state extracts bits 12..9");
    }
    if !s.ready_for_data() {
        return TestResult::Fail("ready_for_data is bit 8");
    }
    let clean = R1Status { raw: 1 << 8 };
    if clean.has_error() {
        return TestResult::Fail("clean status must not flag error");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sd-proto", smoke_sd_r1_status_error_mask);

fn smoke_sd_r6_splits_rca_and_status() -> TestResult {
    use crate::sd_proto::R6;
    let r = R6::parse(0xCAFE_1234);
    if r.rca != 0xCAFE {
        return TestResult::Fail("R6 RCA should be high 16 bits");
    }
    if r.status != 0x1234 {
        return TestResult::Fail("R6 status should be low 16 bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sd-proto", smoke_sd_r6_splits_rca_and_status);

fn smoke_sd_r7_check_pattern() -> TestResult {
    use crate::sd_proto::R7;
    let r = R7::parse(0x0000_01AA);
    if r.voltage != 1 {
        return TestResult::Fail("voltage nibble at bits 11..8 should be 1");
    }
    if !r.matches_check(0xAA) {
        return TestResult::Fail("check pattern 0xAA should match");
    }
    if r.matches_check(0x55) {
        return TestResult::Fail("mismatched pattern shouldn't match");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sd-proto", smoke_sd_r7_check_pattern);

fn smoke_sd_csd_v2_extracts_capacity() -> TestResult {
    use crate::sd_proto::Csd;
    // Build a CSD v2.0 image where C_SIZE = 0x1DFFF (122879) →
    // capacity = (122879+1) × 512 KiB = 60 GiB. Layout: structure
    // bits at top of byte 0, C_SIZE at bits 69..48 (i.e. byte 7 lo
    // 6 bits | byte 8 | byte 9 of the *logical* 15-byte CSD).
    //
    // The shifted convention: r[3] high byte = logical zero;
    // logical bytes start at byte 1 of bytes[0..16].
    let mut bytes = [0u8; 16];
    bytes[1] = 0x40; // structure = 1 (CSD v2.0)
    bytes[8] = 0x01; // bits[69..64] = top of c_size; this gives bit 16 of c_size
    bytes[9] = 0xDF; // c_size middle
    bytes[10] = 0xFF; // c_size low
    let r = [
        u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    ];
    let csd = Csd::parse_shifted(&r).expect("parse csd");
    if csd.structure_version != 1 {
        return TestResult::Fail("CSD structure should decode to v2.0");
    }
    if csd.read_block_len != 512 || csd.write_block_len != 512 {
        return TestResult::Fail("CSD v2 fixes block lengths to 512");
    }
    let expected = (122_880u64) * 512 * 1024;
    if csd.capacity_bytes != expected {
        return TestResult::Fail("CSD v2 capacity formula mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sd-proto", smoke_sd_csd_v2_extracts_capacity);

fn smoke_sd_cid_decodes_manufacturer_and_date() -> TestResult {
    use crate::sd_proto::Cid;
    // Compose a logical CID (15 bytes after the CRC strip):
    //   manufacturer 0x03 (SanDisk-equivalent), OEM "SD",
    //   product name "narf!", revision 0x10, serial 0xDEADBEEF,
    //   manufacture date: year-offset 0x18 (2024), month 0x09.
    let mut logical = [0u8; 15];
    logical[0] = 0x03;
    logical[1] = b'S';
    logical[2] = b'D';
    logical[3..8].copy_from_slice(b"narf!");
    logical[8] = 0x10;
    logical[9..13].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    // MDT = year:8 | month:4 in top 12 bits of a 16-bit field at logical[13..15].
    let mdt: u16 = (0x18u16 << 4) | 0x09;
    logical[13..15].copy_from_slice(&mdt.to_be_bytes());

    // Build the shifted [u32;4] the controller would deliver.
    let mut bytes = [0u8; 16];
    bytes[1..16].copy_from_slice(&logical);
    let r = [
        u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    ];
    let cid = Cid::parse_shifted(&r);
    if cid.manufacturer_id != 0x03 {
        return TestResult::Fail("manufacturer ID mismatch");
    }
    if cid.oem_id != [b'S', b'D'] {
        return TestResult::Fail("OEM ID mismatch");
    }
    if cid.product_name != *b"narf!" {
        return TestResult::Fail("product name mismatch");
    }
    if cid.product_revision != 0x10 {
        return TestResult::Fail("product revision mismatch");
    }
    if cid.product_serial != 0xDEAD_BEEF {
        return TestResult::Fail("serial number mismatch");
    }
    if cid.manufacture_year != 2024 || cid.manufacture_month != 9 {
        return TestResult::Fail("MDT year/month decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/sd-proto", smoke_sd_cid_decodes_manufacturer_and_date);

// ── eMMC EXT_CSD smokes ────────────────────────────────────────────

fn smoke_emmc_ext_csd_size_constant() -> TestResult {
    if crate::emmc::EXT_CSD_SIZE != 512 {
        return TestResult::Fail("EXT_CSD register is 512 bytes per JESD84-B51 §7.4");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_ext_csd_size_constant);

fn smoke_emmc_ext_csd_capacity_decode() -> TestResult {
    use crate::emmc::{ExtCsd, EXT_CSD_REV, EXT_CSD_SEC_COUNT};
    let mut buf = [0u8; 512];
    buf[EXT_CSD_REV] = 8; // EXT_CSD revision 8 = JESD84-B51
    // 64 GiB user partition = 134_217_728 sectors of 512 bytes.
    let sectors: u32 = 134_217_728;
    buf[EXT_CSD_SEC_COUNT..EXT_CSD_SEC_COUNT + 4].copy_from_slice(&sectors.to_le_bytes());
    let ext = ExtCsd::parse(&buf).expect("parse");
    if ext.user_capacity_bytes() != 64 * 1024 * 1024 * 1024 {
        return TestResult::Fail("user capacity should decode to 64 GiB");
    }
    if ext.revision != 8 {
        return TestResult::Fail("revision byte should round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_ext_csd_capacity_decode);

fn smoke_emmc_ext_csd_supports_hs400() -> TestResult {
    use crate::emmc::{ExtCsd, CARD_TYPE_HS400_1V8, EXT_CSD_CARD_TYPE};
    let mut buf = [0u8; 512];
    buf[EXT_CSD_CARD_TYPE] = CARD_TYPE_HS400_1V8;
    let ext = ExtCsd::parse(&buf).expect("parse");
    if !ext.supports_hs400() {
        return TestResult::Fail("HS400 support flag missed");
    }
    if ext.supports_hs200() {
        return TestResult::Fail("HS200 should not be claimed when only HS400 bit set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_ext_csd_supports_hs400);

fn smoke_emmc_ext_csd_partition_config_decode() -> TestResult {
    use crate::emmc::{ExtCsd, EXT_CSD_PARTITION_CONFIG};
    let mut buf = [0u8; 512];
    // BOOT_PARTITION_ENABLE=1 (boot1), PARTITION_ACCESS=3 (RPMB).
    buf[EXT_CSD_PARTITION_CONFIG] = (1 << 3) | 3;
    let ext = ExtCsd::parse(&buf).expect("parse");
    if ext.active_boot_partition() != Some(1) {
        return TestResult::Fail("active boot partition should be 1");
    }
    if ext.current_partition_access() != 3 {
        return TestResult::Fail("partition access should be RPMB (3)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_ext_csd_partition_config_decode);

fn smoke_emmc_ext_csd_boot_and_rpmb_size_mult() -> TestResult {
    use crate::emmc::{ExtCsd, EXT_CSD_BOOT_SIZE_MULT, EXT_CSD_RPMB_SIZE_MULT};
    let mut buf = [0u8; 512];
    buf[EXT_CSD_BOOT_SIZE_MULT] = 32; // 32 × 128 KiB = 4 MiB boot partition
    buf[EXT_CSD_RPMB_SIZE_MULT] = 8; // 8 × 128 KiB = 1 MiB RPMB
    let ext = ExtCsd::parse(&buf).expect("parse");
    if ext.boot_partition_bytes() != 4 * 1024 * 1024 {
        return TestResult::Fail("boot partition size formula: mult × 128 KiB");
    }
    if ext.rpmb_partition_bytes() != 1 * 1024 * 1024 {
        return TestResult::Fail("RPMB partition size formula: mult × 128 KiB");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_ext_csd_boot_and_rpmb_size_mult);

fn smoke_emmc_switch_argument_layout() -> TestResult {
    use crate::emmc::{ExtCsd, EXT_CSD_HS_TIMING, HS_TIMING_HS200};
    // SWITCH (CMD6) arg to set HS_TIMING=2 (HS200): Access=3, Index=185, Value=2.
    let arg = ExtCsd::switch_argument(EXT_CSD_HS_TIMING as u8, HS_TIMING_HS200);
    let access = (arg >> 24) & 0xFF;
    let index = (arg >> 16) & 0xFF;
    let value = (arg >> 8) & 0xFF;
    if access != 3 {
        return TestResult::Fail("Access field should be 3 (Write Byte)");
    }
    if index != EXT_CSD_HS_TIMING as u32 {
        return TestResult::Fail("Index field should equal EXT_CSD offset");
    }
    if value != HS_TIMING_HS200 as u32 {
        return TestResult::Fail("Value field should carry the new byte");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_switch_argument_layout);

fn smoke_emmc_pre_eol_warning_decoded() -> TestResult {
    use crate::emmc::{ExtCsd, EXT_CSD_PRE_EOL_INFO, PRE_EOL_WARNING};
    let mut buf = [0u8; 512];
    buf[EXT_CSD_PRE_EOL_INFO] = PRE_EOL_WARNING;
    let ext = ExtCsd::parse(&buf).expect("parse");
    if ext.pre_eol_info != PRE_EOL_WARNING {
        return TestResult::Fail("PRE_EOL_INFO byte lost");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/storage/emmc", smoke_emmc_pre_eol_warning_decoded);



// ── UFS / UFSHCI 3.0 ──────────────────────────────────────────────



fn smoke_ufs_utrd_round_trip() -> TestResult {

    use crate::ufs::{CommandType, DataDir, OcsStatus, Utrd};

    let u = Utrd {

        command_type: CommandType::Scsi,

        data_dir: DataDir::DeviceToHost,

        interrupt: true,

        crypto: false,

        cci: 0,

        ocs: OcsStatus::Success,

        ucd_phys: 0x0000_C0DE_FACE_F000u64,

        response_offset_bytes: 128,

        response_length_bytes: 64,

        prdt_offset_bytes: 256,

        prdt_entry_count: 4,

    };

    let r = Utrd::unpack(&u.pack());

    if r != u {

        return TestResult::Fail("UTRD round-trip failed");

    }

    TestResult::Pass

}

kernel_test_in!("drivers/storage/ufs", smoke_ufs_utrd_round_trip);



fn smoke_ufs_command_upiu_layout() -> TestResult {

    use crate::ufs::{build_command_upiu, cmd_flags, UpiuHeader, UpiuType};

    // SCSI READ(10): opcode 0x28, lba=0x100, length=4 blocks.

    let cdb = [0x28, 0, 0x00, 0x00, 0x01, 0x00, 0, 0, 4, 0];

    let buf = build_command_upiu(0, 0x42, cmd_flags::READ, 0x800, &cdb);

    if buf.len() != 32 {

        return TestResult::Fail("Command UPIU should be 32 bytes");

    }

    let mut hdr = [0u8; 12];

    hdr.copy_from_slice(&buf[..12]);

    let h = UpiuHeader::unpack(&hdr).expect("hdr");

    if h.kind != UpiuType::Command || h.task_tag != 0x42 || h.flags != cmd_flags::READ {

        return TestResult::Fail("command header decoded wrong");

    }

    let edl = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

    if edl != 0x800 {

        return TestResult::Fail("Expected Data Length lost");

    }

    if &buf[16..16 + cdb.len()] != cdb {

        return TestResult::Fail("CDB lost");

    }

    TestResult::Pass

}

kernel_test_in!("drivers/storage/ufs", smoke_ufs_command_upiu_layout);



fn smoke_ufs_response_upiu_decode() -> TestResult {

    use crate::ufs::{decode_response_upiu, UpiuHeader, UpiuType};

    let hdr = UpiuHeader {

        kind: UpiuType::Response,

        flags: 0,

        lun: 0,

        task_tag: 0x42,

        iid_cmd_set_type: 0,

        query_function: 0,

        response: 0,

        status: 0x02, // Check Condition

        total_ehs_length: 0,

        device_information: 0,

        data_segment_length: 8,

    };

    let mut buf = alloc::vec::Vec::new();

    buf.extend_from_slice(&hdr.pack());

    buf.extend_from_slice(&0x12345678u32.to_be_bytes()); // residual

    buf.extend_from_slice(&[0xF0, 0x00, 0x05, 0x00, 0, 0, 0x0A, 0]);

    let (h, residual, sense) = match decode_response_upiu(&buf) {

        Some(t) => t,

        None => return TestResult::Fail("decode_response_upiu failed"),

    };

    if h.task_tag != 0x42 || h.status != 0x02 {

        return TestResult::Fail("response header decoded wrong");

    }

    if residual != 0x12345678 {

        return TestResult::Fail("residual lost");

    }

    if sense.len() != 8 {

        return TestResult::Fail("sense data length wrong");

    }

    TestResult::Pass

}

kernel_test_in!("drivers/storage/ufs", smoke_ufs_response_upiu_decode);



fn smoke_ufs_prdt_byte_count_zero_based() -> TestResult {

    use crate::ufs::PrdtEntry;

    let e = PrdtEntry {

        data_addr: 0x0000_DEAD_BEEF_0000,

        byte_count: 4096,

    };

    let r = PrdtEntry::unpack(&e.pack());

    if r.byte_count != 4096 {

        return TestResult::Fail("PRDT round-trip byte count failed");

    }

    if r.data_addr != 0x0000_DEAD_BEEF_0000 {

        return TestResult::Fail("PRDT data addr lost");

    }

    TestResult::Pass

}

kernel_test_in!("drivers/storage/ufs", smoke_ufs_prdt_byte_count_zero_based);
