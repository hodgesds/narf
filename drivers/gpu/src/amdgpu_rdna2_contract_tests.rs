//! Internal inventory and serialized-ABI contracts. These execute the actual
//! profile/admission functions; external source or hardware conformance is not
//! established by these tests.
use super::*;
use alloc::{collections::BTreeSet, format};
use narf_kernel_test::{kernel_test_in, TestResult};

fn rdna2_profile_inventory_resolves_exact_ids_and_asic_firmware() -> TestResult {
    let mut ids = BTreeSet::new();
    for (profile, prefix) in PROFILES.iter().zip([
        "sienna_cichlid",
        "navy_flounder",
        "dimgrey_cavefish",
        "beige_goby",
    ]) {
        for &id in profile.pci_ids {
            if !ids.insert(id)
                || for_pci_id(0x1002, id) != Some(profile)
                || !native_start_available(0x1002, id)
                || for_pci_id(0x10de, id).is_some()
            {
                return TestResult::Fail("RDNA2 duplicate identity, wrong vendor or lookup");
            }
        }
        let firmware = profile.firmware;
        for (name, kind) in [
            (firmware.sos, "sos"),
            (firmware.smc, "smc"),
            (firmware.sdma, "sdma"),
            (firmware.ce, "ce"),
            (firmware.pfp, "pfp"),
            (firmware.me, "me"),
            (firmware.mec, "mec"),
            (firmware.mec2, "mec2"),
            (firmware.rlc, "rlc"),
            (firmware.vcn, "vcn"),
            (firmware.dmcub, "dmcub"),
        ] {
            if name != format!("amdgpu/{prefix}_{kind}.bin") {
                return TestResult::Fail("RDNA2 firmware crossed ASIC identity");
            }
        }
    }
    if PROFILES.len() != 4 || ids.len() != 40 {
        return TestResult::Fail("RDNA2 inventory changed without explicit fixture review");
    }
    for id in [
        0, 0xffff, 0x73a4, 0x73c2, 0x73ee, 0x743e, 0x1681, 0x164e, 0x1636, 0x744c, 0x7550,
    ] {
        if for_pci_id(0x1002, id).is_some() || native_start_available(0x1002, id) {
            return TestResult::Fail("RDNA2 lookup promoted a hole, APU or other generation");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_profile_inventory_resolves_exact_ids_and_asic_firmware
);

fn rdna2_power_table_admission_pins_complete_board_ranges_and_exact_sizes() -> TestResult {
    // Reviewed serialized SKU/board boundaries; preserve both shipping Navi24
    // layouts. A neighbouring byte count or another ASIC cannot select one.
    for (index, bytes, revision, format, start, end) in [
        (0, 1668, 15, 0x80, 1344, 1636),
        (1, 1668, 16, 0x81, 1344, 1636),
        (2, 1668, 18, 0x83, 1344, 1636),
        (3, 1700, 19, 0x84, 1376, 1668),
        (3, 1888, 19, 0x84, 1564, 1856),
    ] {
        let profile = &PROFILES[index];
        let expected = PowerTableLayout {
            format_revision: revision,
            format_id: format,
            smc_bytes: bytes,
            board_start: start,
            board_end: end,
        };
        if profile.power_table_layout(bytes) != Some(expected)
            || start >= end
            || end + 32 != bytes
            || profile.power_table_layout(bytes - 1).is_some()
            || profile.power_table_layout(bytes + 1).is_some()
        {
            return TestResult::Fail(
                "RDNA2 PowerPlay board range or exact container-size admission",
            );
        }
    }
    for (index, profile) in PROFILES.iter().enumerate() {
        for bytes in [0, 1668, 1700, 1888, usize::MAX] {
            let admitted = if index == 3 {
                matches!(bytes, 1700 | 1888)
            } else {
                bytes == 1668
            };
            if profile.power_table_layout(bytes).is_some() != admitted {
                return TestResult::Fail("PowerPlay layout accepted another ASIC's container");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_power_table_admission_pins_complete_board_ranges_and_exact_sizes
);

/// Raphael is an RDNA2 APU: its own lookup, never the discrete one, so no
/// discrete path (trained VRAM, driver-loaded SOS/SMC, PSP/SMU 11) can admit
/// it. Its graphics, media and display names are Linux's and agree with
/// `amdgpu::RAPHAEL_FW` in its UCODE_ID order; SOS and SMC are BIOS-resident.
fn rdna2_raphael_is_an_apu_profile_with_linux_firmware() -> TestResult {
    let raphael = crate::amdgpu::RAPHAEL;
    if apu_for_pci_id(0x1002, raphael) != Some(&RAPHAEL)
        || apu_for_pci_id(0x10de, raphael).is_some()
        || for_pci_id(0x1002, raphael).is_some()
        || native_start_available(0x1002, raphael)
        || PROFILES.iter().any(|p| p.pci_ids.contains(&raphael))
    {
        return TestResult::Fail("Raphael reachable through the discrete RDNA2 lookup");
    }
    for profile in PROFILES {
        if profile
            .pci_ids
            .iter()
            .any(|&id| apu_for_pci_id(0x1002, id).is_some())
        {
            return TestResult::Fail("discrete RDNA2 reachable through the APU lookup");
        }
    }
    let f = RAPHAEL.firmware;
    if !f.sos.is_empty() || !f.smc.is_empty() {
        return TestResult::Fail("Raphael names a driver-loaded SOS or SMC");
    }
    let names: alloc::vec::Vec<&str> = crate::amdgpu::RAPHAEL_FW
        .iter()
        .filter(|e| e.cmd == crate::amdgpu_psp::PSP_CMD_LOAD_IP_FW)
        .map(|e| e.name)
        .collect();
    let expected = [
        f.sdma, f.ce, f.pfp, f.me, f.mec, f.mec2, f.rlc, f.vcn, f.dmcub,
    ];
    if names != expected
        || (
            RAPHAEL.gc_version,
            RAPHAEL.psp_version,
            RAPHAEL.sdma_version,
        ) != ((10, 3, 6), (13, 0, 5), (5, 2, 6))
        || (RAPHAEL.dcn_version, RAPHAEL.vcn_versions) != ((3, 1, 5), &[(3, 1, 2)][..])
    {
        return TestResult::Fail("Raphael firmware or IP identity differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_raphael_is_an_apu_profile_with_linux_firmware
);

/// `golden_settings_gc_10_3_6`: 22 rows from `gc_10_1_0_offset.h`, with
/// `gfx_v10_0.c`'s local `mmGCR_GENERAL_CNTL_Vangogh`, in Linux's order.
fn rdna2_raphael_golden_matches_gc_10_3_6() -> TestResult {
    let rows = golden::RAPHAEL;
    let row = |i: usize| {
        let r = &rows[i];
        (r.base_index, r.offset, r.and_mask, r.or_mask)
    };
    if golden::for_gc((10, 3, 6)).map(<[_]>::as_ptr) != Some(rows.as_ptr())
        || rows.len() != 22
        // mmCGTT_SPI_CS_CLK_CTRL
        || row(0) != (1, 0x507c, 0xff7f0fff, 0x78000100)
        // mmGB_ADDR_CONFIG
        || row(5) != (0, 0x13de, 0x0c1807ff, 0x00000042)
        // mmGCR_GENERAL_CNTL_Vangogh
        || row(6) != (0, 0x1580, 0x1ff1ffff, 0x00000500)
        // mmGL2C_CM_CTRL1
        || row(12) != (1, 0x2e08, 0xff8fff0f, 0x580f1008)
        // mmUTCL1_CTRL
        || row(21) != (0, 0x1588, 0xffffffff, 0x00100000)
    {
        return TestResult::Fail("GC 10.3.6 golden sequence differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/rdna2",
    rdna2_raphael_golden_matches_gc_10_3_6
);
