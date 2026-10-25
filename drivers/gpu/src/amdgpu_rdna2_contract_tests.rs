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
