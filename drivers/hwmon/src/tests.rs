//! Smoke tests for `narf-drivers-hwmon`.
//!
//! These are structural (no live hardware required) and pure host-side.
//! All tests use `narf_kernel_test::kernel_test_in!` so the runner
//! groups them under `"drivers/hwmon/*"`.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

// ── k10temp ───────────────────────────────────────────────────────────

/// PCI IDs for Zen2 (Renoir 0x1448) and Zen4 (Phoenix 0x14F4) are
/// present in the chip table.
fn smoke_k10temp_device_ids() -> TestResult {
    use crate::k10temp;
    let zen2 = k10temp::chip_info(k10temp::AMD_RENOIR_NB);
    if zen2.is_none() {
        return TestResult::Fail("Zen2 Renoir NB ID 0x1448 missing from chip table");
    }
    let zen4 = k10temp::chip_info(k10temp::AMD_PHOENIX_NB);
    if zen4.is_none() {
        return TestResult::Fail("Zen4 Phoenix NB ID 0x14F4 missing from chip table");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/k10temp", smoke_k10temp_device_ids);

/// Strix Point (Zen5) ID 0x1590 also present.
fn smoke_k10temp_zen5_id() -> TestResult {
    use crate::k10temp;
    let zen5 = k10temp::chip_info(k10temp::AMD_STRIX_NB);
    if zen5.is_none() {
        return TestResult::Fail("Zen5 Strix NB ID 0x1590 missing from chip table");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/k10temp", smoke_k10temp_zen5_id);

/// SMN address decode: Tdie lives at 0x00059E3C.
fn smoke_k10temp_smn_tdie_addr() -> TestResult {
    use crate::k10temp;
    if k10temp::SMN_TDIE != 0x0005_9E3C {
        return TestResult::Fail("SMN_TDIE address mismatch");
    }
    if k10temp::SMN_TCCD0 != 0x0005_9800 {
        return TestResult::Fail("SMN_TCCD0 address mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/k10temp", smoke_k10temp_smn_tdie_addr);

/// raw_to_mc decode: verify the formula `(raw >> 21) * 125`.
///
/// Cross-check: if raw bits 31:21 = 840 (decimal), then
///   840 * 125 mC = 105_000 mC = 105 °C.
///
/// Raw value that gives 840 in bits 31:21:
///   840 << 21 = 0x69_C00000. Verify:
///   0x69C00000 >> 21 = 0x69C00000 / 2097152 = 840.
fn smoke_k10temp_raw_to_mc() -> TestResult {
    use crate::k10temp::raw_to_mc;
    // 840 * 125 = 105000 mC = 105 °C
    let raw: u32 = 840 << 21;
    let mc = raw_to_mc(raw, 0);
    if mc != 105_000 {
        return TestResult::Fail("k10temp raw→mC conversion wrong (expected 105000)");
    }
    // Zero raw → 0 mC
    if raw_to_mc(0, 0) != 0 {
        return TestResult::Fail("k10temp raw=0 should give 0 mC");
    }
    // Offset subtraction: offset 1000 mC (1 °C) → 104 °C
    if raw_to_mc(840 << 21, 1000) != 104_000 {
        return TestResult::Fail("k10temp tctl_offset subtraction wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/k10temp", smoke_k10temp_raw_to_mc);

/// PCI driver registration: register_pci_driver inserts entries for
/// both Renoir and Phoenix.
fn smoke_k10temp_pci_registration() -> TestResult {
    use crate::k10temp;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    k10temp::register_pci_driver();
    let regs = registered_pci_drivers();
    let want = &[
        (k10temp::AMD_VENDOR, k10temp::AMD_RENOIR_NB),
        (k10temp::AMD_VENDOR, k10temp::AMD_PHOENIX_NB),
    ];
    for &(v, d) in want {
        let found = regs.iter().any(|m| {
            m.name == "k10temp"
                && matches!(m.kind, MatchKind::VendorDevice { vendor, device } if vendor == v && device == d)
        });
        if !found {
            return TestResult::Fail("k10temp PCI match entry missing");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/k10temp", smoke_k10temp_pci_registration);

// ── coretemp ──────────────────────────────────────────────────────────

/// MSR_IA32_THERM_STATUS decode: valid bit 31, readout bits 22:16.
fn smoke_coretemp_therm_status_decode() -> TestResult {
    use crate::coretemp::decode_therm_status;
    // Valid bit set, readout = 0x1F (31 °C below Tjmax).
    let msr: u64 = (1 << 31) | (0x1F << 16);
    match decode_therm_status(msr) {
        Some(31) => {}
        other => {
            let _ = other;
            return TestResult::Fail("coretemp therm_status readout wrong");
        }
    }
    // Valid bit clear → None.
    if decode_therm_status(0x001F_0000).is_some() {
        return TestResult::Fail("coretemp should return None when valid bit clear");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/coretemp", smoke_coretemp_therm_status_decode);

/// MSR_TEMPERATURE_TARGET decode: Tjmax = bits 23:16.
fn smoke_coretemp_tjmax_decode() -> TestResult {
    use crate::coretemp::decode_tjmax;
    // Tjmax = 100 °C at bits 23:16 of MSR 0x1A2.
    let msr: u64 = (100u64) << 16;
    let tjmax = decode_tjmax(msr);
    if tjmax != 100 {
        return TestResult::Fail("coretemp Tjmax decode wrong");
    }
    // Typical Phoenix value: 105 °C.
    let msr: u64 = 105u64 << 16;
    if decode_tjmax(msr) != 105 {
        return TestResult::Fail("coretemp Tjmax=105 decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/coretemp", smoke_coretemp_tjmax_decode);

/// therm_to_mc: Tjmax=100, readout=20 → 80_000 mC (80 °C).
fn smoke_coretemp_therm_to_mc() -> TestResult {
    use crate::coretemp::therm_to_mc;
    let mc = therm_to_mc(100, 20);
    if mc != 80_000 {
        return TestResult::Fail("coretemp therm_to_mc wrong (expected 80000)");
    }
    // At Tjmax itself (readout=0): exactly Tjmax.
    if therm_to_mc(105, 0) != 105_000 {
        return TestResult::Fail("coretemp at Tjmax wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/coretemp", smoke_coretemp_therm_to_mc);

// ── nct6775 ───────────────────────────────────────────────────────────

/// NCT6775F chip ID is 0xB470. Linux nct6775_core.c `match_chip_id`.
fn smoke_nct6775_chip_id() -> TestResult {
    use crate::nct6775::{NctChip, NCT6775F_ID};
    if NCT6775F_ID != 0xB470 {
        return TestResult::Fail("NCT6775F_ID constant wrong (expected 0xB470)");
    }
    let chip = NctChip::from_id(NCT6775F_ID);
    if chip != NctChip::Nct6775F {
        return TestResult::Fail("NCT6775F ID does not decode to Nct6775F variant");
    }
    // NCT6798D = 0xD42B
    let chip = NctChip::from_id(0xD42B);
    if chip != NctChip::Nct6798D {
        return TestResult::Fail("NCT6798D decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/nct6775", smoke_nct6775_chip_id);

/// Unknown chip IDs decode to Unknown variant (not panic).
fn smoke_nct6775_unknown_id() -> TestResult {
    use crate::nct6775::NctChip;
    let chip = NctChip::from_id(0xDEAD);
    if !matches!(chip, NctChip::Unknown(_)) {
        return TestResult::Fail("unknown chip ID should decode to Unknown");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/nct6775", smoke_nct6775_unknown_id);

/// Fan tach register layout: fan_count_to_rpm(0) = None (no fan).
/// fan_count_to_rpm(1350) = 1000 RPM.
fn smoke_nct6775_fan_tach_layout() -> TestResult {
    use crate::nct6775::fan_count_to_rpm;
    // Count=0 means stopped / not present.
    if fan_count_to_rpm(0).is_some() {
        return TestResult::Fail("fan count=0 should return None");
    }
    // Count=0xFFFF means overflow / not connected.
    if fan_count_to_rpm(0xFFFF).is_some() {
        return TestResult::Fail("fan count=0xFFFF should return None");
    }
    // 1350000 / 1350 = 1000 RPM.
    match fan_count_to_rpm(1350) {
        Some(1000) => {}
        other => {
            let _ = other;
            return TestResult::Fail("fan_count_to_rpm(1350) should return 1000");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/nct6775", smoke_nct6775_fan_tach_layout);

/// num_fans / num_temps counts for a few variants.
fn smoke_nct6775_chip_caps() -> TestResult {
    use crate::nct6775::NctChip;
    if NctChip::Nct6775F.num_fans() != 3 {
        return TestResult::Fail("NCT6775F should have 3 fans");
    }
    if NctChip::Nct6779D.num_fans() != 5 {
        return TestResult::Fail("NCT6779D should have 5 fans");
    }
    if NctChip::Nct6775F.num_temps() != 3 {
        return TestResult::Fail("NCT6775F should have 3 temp inputs");
    }
    if NctChip::Nct6779D.num_temps() != 6 {
        return TestResult::Fail("NCT6779D should have 6 temp inputs");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/nct6775", smoke_nct6775_chip_caps);

// ── registry ──────────────────────────────────────────────────────────

/// Registry starts empty; after registering one device it has count=1.
fn smoke_hwmon_registry() -> TestResult {
    // Note: registry is shared across tests; this test only checks that
    // sensors() works without panicking and count() returns a number.
    let count_before = crate::registry::count();
    crate::registry::register(crate::registry::RegisteredSensor {
        name: "test-sensor",
        description: "test",
        bus_loc: "test",
    });
    let count_after = crate::registry::count();
    if count_after <= count_before {
        return TestResult::Fail("registry count did not increase after register");
    }
    let sensors = crate::registry::sensors();
    if sensors.is_empty() {
        return TestResult::Fail("sensors() returned empty after registration");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/registry", smoke_hwmon_registry);
