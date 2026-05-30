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

// ── sysfs bridge ──────────────────────────────────────────────────────

/// After registering a k10temp device and populating the hwmon class,
/// `/sys/class/hwmon/hwmon0` appears with a `name` attribute.
fn smoke_bridge_k10temp_hwmon0_enumerated() -> TestResult {
    use alloc::sync::Arc;
    use crate::k10temp::{K10temp, chip_info, AMD_RENOIR_NB};
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let chip = match chip_info(AMD_RENOIR_NB) {
        Some(c) => c,
        None => return TestResult::Fail("Renoir chip info missing"),
    };
    let dev = K10temp::new(0, 0, 0, chip);
    crate::registry::register_device(Arc::new(dev));
    crate::sysfs_bridge::populate_hwmon_class();
    // /sys/class/hwmon/hwmon0 must exist.
    let root = narf_filesystem::sysfs::sysfs_root().get_child("class")
        .and_then(|c| c.get_child("hwmon"))
        .and_then(|h| h.get_child("hwmon0"));
    if root.is_none() {
        return TestResult::Fail("hwmon0 kobject not found under /sys/class/hwmon/");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/bridge", smoke_bridge_k10temp_hwmon0_enumerated);

/// `hwmon0/name` returns the chip name (`"k10temp\n"`).
fn smoke_bridge_name_attr_reads_k10temp() -> TestResult {
    use alloc::sync::Arc;
    use crate::k10temp::{K10temp, chip_info, AMD_RENOIR_NB};
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let chip = match chip_info(AMD_RENOIR_NB) {
        Some(c) => c,
        None => return TestResult::Fail("Renoir chip info missing"),
    };
    crate::registry::register_device(Arc::new(K10temp::new(0, 0, 0, chip)));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match narf_filesystem::sysfs::sysfs_root().get_child("class")
        .and_then(|c| c.get_child("hwmon"))
        .and_then(|h| h.get_child("hwmon0"))
    {
        Some(k) => k,
        None => return TestResult::Fail("hwmon0 not found"),
    };
    match kobj.attr_show("name") {
        Some(s) if s == "k10temp\n" => TestResult::Pass,
        Some(s) => {
            let _ = s;
            TestResult::Fail("hwmon0/name did not return 'k10temp\\n'")
        }
        None => TestResult::Fail("hwmon0/name attr missing"),
    }
}
kernel_test_in!("drivers/hwmon/bridge", smoke_bridge_name_attr_reads_k10temp);

/// `temp1_input` attr exists and returns ASCII digits (the value may
/// be 0 if no hardware is accessible in the test environment).
fn smoke_bridge_temp1_input_returns_ascii() -> TestResult {
    use alloc::sync::Arc;
    use crate::k10temp::{K10temp, chip_info, AMD_PHOENIX_NB};
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let chip = match chip_info(AMD_PHOENIX_NB) {
        Some(c) => c,
        None => return TestResult::Fail("Phoenix chip info missing"),
    };
    crate::registry::register_device(Arc::new(K10temp::new(0, 0, 0, chip)));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match narf_filesystem::sysfs::sysfs_root().get_child("class")
        .and_then(|c| c.get_child("hwmon"))
        .and_then(|h| h.get_child("hwmon0"))
    {
        Some(k) => k,
        None => return TestResult::Fail("hwmon0 not found"),
    };
    match kobj.attr_show("temp1_input") {
        Some(s) => {
            // Value must be a number (possibly "0\n" in test env).
            let trimmed = s.trim();
            if trimmed.parse::<i64>().is_err() {
                return TestResult::Fail("temp1_input is not numeric ASCII");
            }
            TestResult::Pass
        }
        None => TestResult::Fail("temp1_input attr missing from hwmon0"),
    }
}
kernel_test_in!("drivers/hwmon/bridge", smoke_bridge_temp1_input_returns_ascii);

/// `temp1_label` returns the label string with a newline.
fn smoke_bridge_temp1_label_returns_tctl() -> TestResult {
    use alloc::sync::Arc;
    use crate::k10temp::{K10temp, chip_info, AMD_RENOIR_NB};
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let chip = match chip_info(AMD_RENOIR_NB) {
        Some(c) => c,
        None => return TestResult::Fail("Renoir chip info missing"),
    };
    crate::registry::register_device(Arc::new(K10temp::new(0, 0, 0, chip)));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match narf_filesystem::sysfs::sysfs_root().get_child("class")
        .and_then(|c| c.get_child("hwmon"))
        .and_then(|h| h.get_child("hwmon0"))
    {
        Some(k) => k,
        None => return TestResult::Fail("hwmon0 not found"),
    };
    match kobj.attr_show("temp1_label") {
        // k10temp's first label is "Tctl"
        Some(s) if s.trim_end_matches('\n') == "Tctl" => TestResult::Pass,
        Some(s) => {
            let _ = s;
            TestResult::Fail("temp1_label did not return 'Tctl'")
        }
        None => TestResult::Fail("temp1_label attr missing"),
    }
}
kernel_test_in!("drivers/hwmon/bridge", smoke_bridge_temp1_label_returns_tctl);

/// Two devices produce hwmon0 and hwmon1.
fn smoke_bridge_multiple_devices_enumerated() -> TestResult {
    use alloc::sync::Arc;
    use crate::k10temp::{K10temp, chip_info, AMD_RENOIR_NB};
    use crate::coretemp::Coretemp;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let chip = match chip_info(AMD_RENOIR_NB) {
        Some(c) => c,
        None => return TestResult::Fail("Renoir chip info missing"),
    };
    crate::registry::register_device(Arc::new(K10temp::new(0, 0, 0, chip)));
    crate::registry::register_device(Arc::new(Coretemp::new(100, 0)));
    crate::sysfs_bridge::populate_hwmon_class();
    let class_hwmon = match narf_filesystem::sysfs::sysfs_root().get_child("class")
        .and_then(|c| c.get_child("hwmon"))
    {
        Some(k) => k,
        None => return TestResult::Fail("/sys/class/hwmon not found"),
    };
    let names = class_hwmon.child_names();
    if !names.iter().any(|n| n == "hwmon0") {
        return TestResult::Fail("hwmon0 missing");
    }
    if !names.iter().any(|n| n == "hwmon1") {
        return TestResult::Fail("hwmon1 missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/bridge", smoke_bridge_multiple_devices_enumerated);

/// NCT6779D has 5 fans; bridge should expose fan1_input through fan5_input.
fn smoke_bridge_nct6779d_five_fan_inputs() -> TestResult {
    use alloc::sync::Arc;
    use crate::nct6775::{Nct6775, NctChip, NCT6779D_ID};
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let dev = Nct6775::new(NctChip::Nct6779D, NCT6779D_ID, 0x2E, 0x2F);
    crate::registry::register_device(Arc::new(dev));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match narf_filesystem::sysfs::sysfs_root().get_child("class")
        .and_then(|c| c.get_child("hwmon"))
        .and_then(|h| h.get_child("hwmon0"))
    {
        Some(k) => k,
        None => return TestResult::Fail("hwmon0 not found"),
    };
    for i in 1u32..=5 {
        let attr = alloc::format!("fan{}_input", i);
        if kobj.attr_show(&attr).is_none() {
            return TestResult::Fail("NCT6779D fan attr missing");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/bridge", smoke_bridge_nct6779d_five_fan_inputs);

/// `update_interval` attr exists and returns "1000\n".
fn smoke_bridge_update_interval_attr() -> TestResult {
    use alloc::sync::Arc;
    use crate::coretemp::Coretemp;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    crate::registry::register_device(Arc::new(Coretemp::new(105, 0)));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match narf_filesystem::sysfs::sysfs_root().get_child("class")
        .and_then(|c| c.get_child("hwmon"))
        .and_then(|h| h.get_child("hwmon0"))
    {
        Some(k) => k,
        None => return TestResult::Fail("hwmon0 not found"),
    };
    match kobj.attr_show("update_interval") {
        Some(s) if s == "1000\n" => TestResult::Pass,
        Some(_) => TestResult::Fail("update_interval did not return '1000\\n'"),
        None => TestResult::Fail("update_interval attr missing"),
    }
}
kernel_test_in!("drivers/hwmon/bridge", smoke_bridge_update_interval_attr);
