use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn identity() -> Identity {
    Identity {
        revision: 0xc0,
        subsystem_vendor: 0x1002,
        subsystem_device: 0x0b36,
    }
}
fn table() -> Vec<u8> {
    let mut bytes = vec![0xa5; TABLE_BYTES];
    put16(&mut bytes, 0, TABLE_BYTES as u16);
    bytes[2..5].copy_from_slice(&[16, 0, 2]);
    put16(&mut bytes, 5, DRIVER_BYTES as u16);
    put16(&mut bytes, 15, 0x81);
    put32(&mut bytes, 17, 0x18);
    bytes[21] = 28;
    put16(&mut bytes, 28, 118);
    put32(&mut bytes, DRIVER_BYTES, 1);
    for (i, clock) in bytes[DRIVER_BYTES + GFX_CLOCKS..DRIVER_BYTES + GFX_CLOCKS + 32]
        .chunks_exact_mut(2)
        .enumerate()
    {
        clock.copy_from_slice(&(1000 + i as u16 * 150).to_le_bytes());
    }
    bytes
}
fn bios(id: u32) -> Vec<u8> {
    let mut bytes = vec![0; 0x400 + TABLE_BYTES];
    bytes[..2].copy_from_slice(&[0x55, 0xaa]);
    put16(&mut bytes, 0x48, 0x80);
    bytes[0x80..0x88].copy_from_slice(&[40, 0, 2, 1, b'A', b'T', b'O', b'M']);
    put16(&mut bytes, 0xa0, 0xc0);
    bytes[0xc0..0xc4].copy_from_slice(&[36, 0, 2, 1]);
    put16(&mut bytes, 0xc8, 0x200); // SMC DPM data index 2
    put16(&mut bytes, 0xcc, 0x100); // FirmwareInfo index 4
    put16(&mut bytes, 0xe2, 0x400); // PowerPlay index 15
    bytes[0x100..0x104].copy_from_slice(&[108, 0, 3, 4]);
    put32(&mut bytes, 0x13c, id);
    bytes[0x200..0x328].fill(0x5a);
    bytes[0x200..0x204].copy_from_slice(&[40, 1, 4, 9]); // 296 bytes
    bytes[0x400..].copy_from_slice(&table());
    bytes
}
fn navi22_power_selects_board_source_and_preserves_sku_fields() -> TestResult {
    let mut firmware = table();
    firmware[DRIVER_BYTES + 100] = 0x7b;
    for id in [0, 4, u32::MAX] {
        let bios = bios(id);
        let prepared = prepare(&bios, Some(&firmware), identity()).unwrap();
        let selected = if id == 0 { &bios[0x400..] } else { &firmware };
        let info = prepared.info();
        if prepared.bytes()[..BOARD_START] != selected[DRIVER_BYTES..DRIVER_BYTES + BOARD_START]
            || prepared.bytes()[BOARD_START..BOARD_END] != bios[0x204..0x328]
            || prepared.bytes()[BOARD_END..] != selected[DRIVER_BYTES + BOARD_END..]
            || info.source
                != if id == 0 {
                    Source::Vbios
                } else {
                    Source::SmcFirmware
                }
            || info.table_id != id
            || info.platform_caps != 0x18
            || info.thermal_controller != 28
            || info.software_shutdown_celsius != 118
        {
            return TestResult::Fail("PowerPlay source/board overlay boundary");
        }
    }
    if prepare(&bios(1), None, identity()).err() != Some(Error::MissingTable) {
        return TestResult::Fail("missing selected firmware table fell back to VBIOS");
    }
    let mut missing = bios(0);
    put16(&mut missing, 0xe2, 0);
    if prepare(&missing, Some(&firmware), identity()).err() != Some(Error::MissingTable) {
        return TestResult::Fail("missing selected VBIOS table fell back to firmware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/power-navi22",
    navi22_power_selects_board_source_and_preserves_sku_fields
);

fn navi22_power_bounds_and_revisions_fail_closed() -> TestResult {
    let template = table();
    for len in 0..template.len() {
        if validate_table(&template[..len]).is_ok() {
            return TestResult::Fail("truncated PowerPlay accepted");
        }
    }
    for (offset, value) in [
        (0, 0),
        (2, 15),
        (3, 1),
        (4, 3),
        (5, 0),
        (15, 0x80),
        (DRIVER_BYTES, 7),
    ] {
        let mut invalid = template.clone();
        invalid[offset] = value;
        if validate_table(&invalid).is_ok() {
            return TestResult::Fail("wrong PowerPlay layout accepted");
        }
    }
    for (offset, value) in [
        (0xc2, 1),
        (0x102, 2),
        (0x103, 2),
        (0x200, 39),
        (0x202, 3),
        (0x203, 10),
    ] {
        let mut invalid = bios(1);
        invalid[offset] = value;
        if prepare(&invalid, Some(&template), identity()).is_ok() {
            return TestResult::Fail("wrong board metadata accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/power-navi22",
    navi22_power_bounds_and_revisions_fail_closed
);

fn navi22_power_oem_quirks_match_exact_pci_identity() -> TestResult {
    for revision in [0xc0, 0xc3] {
        for vendor in [0x1002, 0x1043] {
            for device in [0x16c2, 0x133c, 0x133d] {
                let matches = revision == 0xc3 && vendor == 0x1043 && device != 0x133d;
                let identity = Identity {
                    revision,
                    subsystem_vendor: vendor,
                    subsystem_device: device,
                };
                let prepared = prepare(&bios(0), None, identity).unwrap();
                if prepared.info().oem_quirk != matches
                    || u32_at(prepared.bytes(), BOARD_RESERVED)
                        != if matches && device == 0x16c2 {
                            1387
                        } else {
                            0x5a5a5a5a
                        }
                {
                    return TestResult::Fail("OEM quirk applied to wrong board");
                }
                for index in 0..16 {
                    let original = 1000 + index as u16 * 150;
                    let want = if matches {
                        original.min(2500)
                    } else {
                        original
                    };
                    if u16_at(prepared.bytes(), GFX_CLOCKS + index * 2) != want {
                        return TestResult::Fail("OEM clock clamp altered unrelated level");
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/power-navi22",
    navi22_power_oem_quirks_match_exact_pci_identity
);

fn navi22_boot_power_policy_preserves_display_and_protection() -> TestResult {
    let policy = BootPolicy::from_features(u64::MAX).unwrap();
    // Independent SMU feature numbers: memory/link/display clocks, deep sleep,
    // GFXOFF/BACO, multimedia/hub gating and unassigned bits must stay off.
    let forbidden = (1 << 3)
        | (1 << 4)
        | (1 << 5)
        | (1 << 7)
        | (1 << 8)
        | (0x3ff << 12)
        | (1 << 22)
        | (1 << 34)
        | (1 << 40)
        | (1 << 41)
        | (1 << 63);
    if policy.allowed() & forbidden != 0 || !policy.validate_enabled(policy.allowed()) {
        return TestResult::Fail("boot policy changes unowned display/memory power state");
    }
    // sienna_cichlid_init_allowed_features always allows RSMU_SMN_CG and
    // DF_CSTATE, and Linux never fails on extra running features such as
    // FW_DSTATE (19) or DPM_MP0CLK (6).
    if policy.allowed() & (3 << 44) != 3 << 44
        || !policy.validate_enabled(policy.allowed() | (1 << 19) | (1 << 6))
    {
        return TestResult::Fail("Linux-allowed or harmless running PMFW feature refused");
    }
    for required in [1, 24, 25, 31, 32, 33] {
        if BootPolicy::from_features(u64::MAX & !(1 << required)).is_ok()
            || policy.validate_enabled(policy.allowed() & !(1 << required))
        {
            return TestResult::Fail("GFX DPM accepted without autonomous protection");
        }
    }
    for optional in [0, 29, 37, 38, 42] {
        let board = u64::MAX & !(1 << optional);
        if BootPolicy::from_features(board).unwrap().allowed() & (1 << optional) != 0 {
            return TestResult::Fail("driver enabled a feature absent from board policy");
        }
    }
    if policy.validate_enabled(policy.allowed() | (1 << 3)) {
        return TestResult::Fail("unexpected UCLK DPM accepted");
    }
    // Actual Navy Flounder SKU FeaturesToRun from firmware, as numeric metadata.
    if BootPolicy::from_features(0x3767a37ffdff).is_err() {
        return TestResult::Fail("Navy Flounder feature set refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/power-navi22",
    navi22_boot_power_policy_preserves_display_and_protection
);

fn navi22_display_dpm_respects_board_features_and_excludes_sleep() -> TestResult {
    let p = BootPolicy::from_features(u64::MAX).unwrap();
    let allowed = p.display_allowed().unwrap();
    if allowed & !p.allowed() != 0xd38
        || !p.validate_display(allowed)
        || p.validate_display(allowed | (1 << 17))
        || p.validate_display(allowed & !(1 << 31))
    {
        return TestResult::Fail("display DPM mask or protection validation");
    }
    for bit in [3, 4, 5, 8] {
        if BootPolicy::from_features(u64::MAX & !(1 << bit))
            .unwrap()
            .display_allowed()
            .is_ok()
        {
            return TestResult::Fail("board-missing display DPM feature invented");
        }
    }
    for bit in [10, 11] {
        if BootPolicy::from_features(u64::MAX & !(1 << bit))
            .unwrap()
            .display_allowed()
            .unwrap()
            & (1 << bit)
            != 0
        {
            return TestResult::Fail("unsupported memory rail scaling enabled");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/power-navi22",
    navi22_display_dpm_respects_board_features_and_excludes_sleep
);

fn rdna2_power_tables_preserve_profile_and_board_overlay() -> TestResult {
    for (profile, revision, format, version, size, start, end) in [
        (&crate::amdgpu_rdna2::NAVI21, 15, 0x80, 1, 1668, 1344, 1636),
        (&crate::amdgpu_rdna2::NAVI22, 16, 0x81, 1, 1668, 1344, 1636),
        (&crate::amdgpu_rdna2::NAVI23, 18, 0x83, 6, 1668, 1344, 1636),
        (&crate::amdgpu_rdna2::NAVI24, 19, 0x84, 3, 1700, 1376, 1668),
        (&crate::amdgpu_rdna2::NAVI24, 19, 0x84, 3, 1888, 1564, 1856),
    ] {
        let mut data = bios(0);
        data.resize(0x400 + DRIVER_BYTES + size, 0xa5);
        put16(&mut data, 0x400, (DRIVER_BYTES + size) as u16);
        data[0x402] = revision;
        put16(&mut data, 0x40f, format);
        put32(&mut data, 0x400 + DRIVER_BYTES, version);
        let image = prepare_for(&data, |_| None, identity(), profile).unwrap();
        for firmware_revision in [3, 4, 5] {
            data[0x103] = firmware_revision;
            if prepare_for(&data, |_| None, identity(), profile).is_err() {
                return TestResult::Fail("RDNA2 FirmwareInfo v3.3/v3.4/v3.5 selection");
            }
        }
        if image.profile != profile
            || image.bytes().len() != size
            || image.bytes()[start..end] != data[0x204..0x328]
            || image.bytes()[end..] != data[0x400 + DRIVER_BYTES + end..]
        {
            return TestResult::Fail(
                "PowerPlay family layout/overlay corrupted SKU or private bytes",
            );
        }
        for other in crate::amdgpu_rdna2::PROFILES {
            if other != profile && prepare_for(&data, |_| None, identity(), other).is_ok() {
                return TestResult::Fail("PowerPlay accepted another ASIC's wire layout");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_power_tables_preserve_profile_and_board_overlay
);
