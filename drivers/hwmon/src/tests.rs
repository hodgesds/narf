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

fn smoke_coretemp_cpu_match() -> TestResult {
    use crate::coretemp::supports_coretemp;
    use narf_arch::x86_64::microcode::Vendor;

    for (vendor, max_basic, thermal_eax, expected) in [
        (Vendor::Intel, 6, 1, true),
        (Vendor::Intel, 0x20, 0x81, true),
        (Vendor::Intel, 5, 1, false),
        (Vendor::Intel, 6, 0, false),
        (Vendor::Intel, 6, 1 << 6, false),
        (Vendor::Amd, 0x20, 1, false),
        (Vendor::Unknown, 0x20, 1, false),
    ] {
        if supports_coretemp(vendor, max_basic, thermal_eax) != expected {
            return TestResult::Fail("coretemp CPU match accepted an unsupported thermal MSR CPU");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/coretemp", smoke_coretemp_cpu_match);

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

/// PWM channel resolution: the trait's fan labels and the chip's
/// native pwm labels name the same channels; sensor labels don't
/// resolve.
fn smoke_nct6775_pwm_channel_labels() -> TestResult {
    use crate::nct6775::pwm_channel;
    if pwm_channel("fan1") != Some(0) || pwm_channel("pwm1") != Some(0) {
        return TestResult::Fail("fan1/pwm1 should both resolve to PWM channel 0");
    }
    if pwm_channel("fan5") != Some(4) || pwm_channel("pwm5") != Some(4) {
        return TestResult::Fail("fan5/pwm5 should both resolve to PWM channel 4");
    }
    if pwm_channel("temp1").is_some() || pwm_channel("in0").is_some() {
        return TestResult::Fail("sensor labels must not resolve to a PWM channel");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/nct6775", smoke_nct6775_pwm_channel_labels);

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
    use crate::k10temp::{chip_info, K10temp, AMD_RENOIR_NB};
    use alloc::sync::Arc;
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
    let root = narf_filesystem::sysfs::sysfs_root()
        .get_child("class")
        .and_then(|c| c.get_child("hwmon"))
        .and_then(|h| h.get_child("hwmon0"));
    if root.is_none() {
        return TestResult::Fail("hwmon0 kobject not found under /sys/class/hwmon/");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/bridge",
    smoke_bridge_k10temp_hwmon0_enumerated
);

/// `hwmon0/name` returns the chip name (`"k10temp\n"`).
fn smoke_bridge_name_attr_reads_k10temp() -> TestResult {
    use crate::k10temp::{chip_info, K10temp, AMD_RENOIR_NB};
    use alloc::sync::Arc;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let chip = match chip_info(AMD_RENOIR_NB) {
        Some(c) => c,
        None => return TestResult::Fail("Renoir chip info missing"),
    };
    crate::registry::register_device(Arc::new(K10temp::new(0, 0, 0, chip)));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match narf_filesystem::sysfs::sysfs_root()
        .get_child("class")
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

/// `temp1_input` on a hardware-less k10temp (no ECAM window attached,
/// so every SMN read fails) renders EMPTY — never a fabricated "0\n".
/// Before the #909 fix this fixture asserted the opposite: it accepted
/// the sentinel 0 the bridge invented for failed reads.
fn smoke_bridge_temp1_input_failed_read_renders_empty() -> TestResult {
    use crate::k10temp::{chip_info, K10temp, AMD_PHOENIX_NB};
    use alloc::sync::Arc;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let chip = match chip_info(AMD_PHOENIX_NB) {
        Some(c) => c,
        None => return TestResult::Fail("Phoenix chip info missing"),
    };
    crate::registry::register_device(Arc::new(K10temp::new(0, 0, 0, chip)));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match narf_filesystem::sysfs::sysfs_root()
        .get_child("class")
        .and_then(|c| c.get_child("hwmon"))
        .and_then(|h| h.get_child("hwmon0"))
    {
        Some(k) => k,
        None => return TestResult::Fail("hwmon0 not found"),
    };
    match kobj.attr_show("temp1_input") {
        Some(s) if s.is_empty() => TestResult::Pass,
        Some(_) => TestResult::Fail("temp1_input fabricated a value for a failed read"),
        None => TestResult::Fail("temp1_input attr missing from hwmon0"),
    }
}
kernel_test_in!(
    "drivers/hwmon/bridge",
    smoke_bridge_temp1_input_failed_read_renders_empty
);

// ── Bridge read honesty (#909) ──────────────────────────────────────

/// Fake device whose every sensor read fails (returns `None`),
/// like a chip whose hardware window is not attached.
#[derive(Debug)]
struct FakeFailDevice;

impl crate::HwmonDevice for FakeFailDevice {
    fn name(&self) -> &str {
        "fakefail"
    }

    fn read_temp(&self, _label: &str) -> Option<i32> {
        None
    }

    fn read_fan(&self, _label: &str) -> Option<u32> {
        None
    }

    fn read_voltage(&self, _label: &str) -> Option<i32> {
        None
    }

    fn set_fan(&self, _label: &str, _level: u8) -> bool {
        false
    }

    fn list_labels(&self) -> alloc::vec::Vec<&str> {
        alloc::vec!["Tdie", "fan1", "in0"]
    }
}

/// Fake device whose every sensor read succeeds with a genuine zero.
#[derive(Debug)]
struct FakeZeroDevice;

impl crate::HwmonDevice for FakeZeroDevice {
    fn name(&self) -> &str {
        "fakezero"
    }

    fn read_temp(&self, _label: &str) -> Option<i32> {
        Some(0)
    }

    fn read_fan(&self, _label: &str) -> Option<u32> {
        Some(0)
    }

    fn read_voltage(&self, _label: &str) -> Option<i32> {
        Some(0)
    }

    fn set_fan(&self, _label: &str, _level: u8) -> bool {
        false
    }

    fn list_labels(&self) -> alloc::vec::Vec<&str> {
        alloc::vec!["Tdie", "fan1", "in0"]
    }
}

/// #909: across all three sensor classes, a failed read renders empty
/// while a genuine zero renders "0\n" — the two must never be
/// indistinguishable again.
fn smoke_bridge_failed_reads_empty_genuine_zero_renders() -> TestResult {
    use alloc::sync::Arc;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    crate::registry::register_device(Arc::new(FakeFailDevice));
    crate::registry::register_device(Arc::new(FakeZeroDevice));
    crate::sysfs_bridge::populate_hwmon_class();
    let class_hwmon = match narf_filesystem::sysfs::sysfs_root()
        .get_child("class")
        .and_then(|c| c.get_child("hwmon"))
    {
        Some(k) => k,
        None => return TestResult::Fail("/sys/class/hwmon not found"),
    };
    let fail_kobj = match class_hwmon.get_child("hwmon0") {
        Some(k) => k,
        None => return TestResult::Fail("hwmon0 (failing device) not found"),
    };
    let zero_kobj = match class_hwmon.get_child("hwmon1") {
        Some(k) => k,
        None => return TestResult::Fail("hwmon1 (zero device) not found"),
    };
    for attr in ["temp1_input", "fan1_input", "in1_input"] {
        match fail_kobj.attr_show(attr) {
            Some(s) if s.is_empty() => {}
            Some(_) => return TestResult::Fail("failed read rendered a value instead of empty"),
            None => return TestResult::Fail("input attr missing on failing device"),
        }
        match zero_kobj.attr_show(attr) {
            Some(s) if s == "0\n" => {}
            Some(_) => return TestResult::Fail("genuine zero did not render as '0\\n'"),
            None => return TestResult::Fail("input attr missing on zero device"),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/bridge",
    smoke_bridge_failed_reads_empty_genuine_zero_renders
);

/// Fake device with real hardware limits and one controllable fan
/// channel. `set_fan` records the duty it was driven with;
/// `read_pwm` reports it back — the shape a real PWM chip (nct6775,
/// it87) presents to the bridge.
#[derive(Debug)]
struct FakeControlDevice {
    duty: core::sync::atomic::AtomicU8,
    set_fan_called: core::sync::atomic::AtomicBool,
}

impl FakeControlDevice {
    fn new() -> Self {
        Self {
            duty: core::sync::atomic::AtomicU8::new(0),
            set_fan_called: core::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl crate::HwmonDevice for FakeControlDevice {
    fn name(&self) -> &str {
        "fakecontrol"
    }

    fn read_temp(&self, label: &str) -> Option<i32> {
        if label == "Tdie" {
            Some(42_000)
        } else {
            None
        }
    }

    fn read_fan(&self, label: &str) -> Option<u32> {
        if label == "fan1" {
            Some(1200)
        } else {
            None
        }
    }

    fn read_voltage(&self, _label: &str) -> Option<i32> {
        None
    }

    fn set_fan(&self, label: &str, level: u8) -> bool {
        use core::sync::atomic::Ordering;
        if label != "fan1" {
            return false;
        }
        self.duty.store(level, Ordering::SeqCst);
        self.set_fan_called.store(true, Ordering::SeqCst);
        true
    }

    fn temp_limits(&self, label: &str) -> (Option<i32>, Option<i32>) {
        if label == "Tdie" {
            (Some(85_000), Some(95_000))
        } else {
            (None, None)
        }
    }

    fn read_pwm(&self, label: &str) -> Option<u8> {
        if label == "fan1" {
            Some(self.duty.load(core::sync::atomic::Ordering::SeqCst))
        } else {
            None
        }
    }

    fn supports_fan_control(&self, label: &str) -> bool {
        label == "fan1"
    }

    fn list_labels(&self) -> alloc::vec::Vec<&str> {
        alloc::vec!["Tdie", "fan1"]
    }
}

/// Fetch `hwmon0` from a freshly populated class with exactly one
/// device registered. Returns `None` (fixture failure) when absent.
fn hwmon0_kobj() -> Option<alloc::sync::Arc<narf_filesystem::sysfs::Kobject>> {
    narf_filesystem::sysfs::sysfs_root()
        .get_child("class")
        .and_then(|c| c.get_child("hwmon"))
        .and_then(|h| h.get_child("hwmon0"))
}

/// #909: `temp1_max` / `temp1_crit` render the DEVICE's limits
/// (85 °C / 95 °C here) — before the fix the bridge rendered its own
/// hardcoded 100000 / 105000 constants for every chip.
fn smoke_bridge_thresholds_come_from_device() -> TestResult {
    use alloc::sync::Arc;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    crate::registry::register_device(Arc::new(FakeControlDevice::new()));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match hwmon0_kobj() {
        Some(k) => k,
        None => return TestResult::Fail("hwmon0 not found"),
    };
    match kobj.attr_show("temp1_max") {
        Some(s) if s == "85000\n" => {}
        Some(_) => return TestResult::Fail("temp1_max did not render the device limit 85000"),
        None => return TestResult::Fail("temp1_max missing though the device reports a limit"),
    }
    match kobj.attr_show("temp1_crit") {
        Some(s) if s == "95000\n" => {}
        Some(_) => return TestResult::Fail("temp1_crit did not render the device limit 95000"),
        None => return TestResult::Fail("temp1_crit missing though the device reports a limit"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/bridge",
    smoke_bridge_thresholds_come_from_device
);

/// #909: a device that reports no limits gets NO threshold
/// attributes (never the old fabricated constants), and a fan
/// channel without control support gets NO `pwm1` attribute — a
/// published control is never a dead end.
fn smoke_bridge_no_limits_no_threshold_attrs_no_pwm() -> TestResult {
    use alloc::sync::Arc;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    crate::registry::register_device(Arc::new(FakeFailDevice));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match hwmon0_kobj() {
        Some(k) => k,
        None => return TestResult::Fail("hwmon0 not found"),
    };
    if kobj.attr_show("temp1_max").is_some() {
        return TestResult::Fail("temp1_max published for a device with no hardware limit");
    }
    if kobj.attr_show("temp1_crit").is_some() {
        return TestResult::Fail("temp1_crit published for a device with no hardware limit");
    }
    if kobj.attr_show("pwm1").is_some() || kobj.attr_is_writable("pwm1") {
        return TestResult::Fail("pwm1 published for a fan channel with no control support");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/bridge",
    smoke_bridge_no_limits_no_threshold_attrs_no_pwm
);

/// #909: coretemp's `temp1_crit` is the device's Tjmax (95 °C for
/// this fixture device — a value the old hardcoded bridge could
/// never produce in the crit slot), and coretemp gets no `temp1_max`
/// because the hardware exposes no separate high limit.
fn smoke_bridge_coretemp_crit_is_device_tjmax() -> TestResult {
    use crate::coretemp::Coretemp;
    use alloc::sync::Arc;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    crate::registry::register_device(Arc::new(Coretemp::new(95, 0)));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match hwmon0_kobj() {
        Some(k) => k,
        None => return TestResult::Fail("hwmon0 not found"),
    };
    match kobj.attr_show("temp1_crit") {
        Some(s) if s == "95000\n" => {}
        Some(_) => return TestResult::Fail("temp1_crit did not render the device Tjmax 95000"),
        None => return TestResult::Fail("temp1_crit missing for coretemp"),
    }
    if kobj.attr_show("temp1_max").is_some() {
        return TestResult::Fail("temp1_max published though coretemp has no max limit");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/bridge",
    smoke_bridge_coretemp_crit_is_device_tjmax
);

/// #909: the `pwm1` store is the userspace production caller of
/// `set_fan` — a valid write lands in the driver with the exact
/// duty, the show reads the duty back, and malformed / out-of-range
/// writes are rejected without touching the driver.
fn smoke_bridge_pwm_store_drives_set_fan() -> TestResult {
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let dev = Arc::new(FakeControlDevice::new());
    crate::registry::register_device(dev.clone());
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match hwmon0_kobj() {
        Some(k) => k,
        None => return TestResult::Fail("hwmon0 not found"),
    };
    if !kobj.attr_is_writable("pwm1") {
        return TestResult::Fail("pwm1 not writable for a controllable fan channel");
    }
    match kobj.attr_show("pwm1") {
        Some(s) if s == "0\n" => {}
        Some(_) => return TestResult::Fail("pwm1 did not show the initial duty 0"),
        None => return TestResult::Fail("pwm1 attr missing"),
    }
    match kobj.attr_store("pwm1", b"200\n") {
        Some(Ok(())) => {}
        Some(Err(_)) => return TestResult::Fail("pwm1 store of 200 was rejected"),
        None => return TestResult::Fail("pwm1 has no store callback"),
    }
    if !dev.set_fan_called.load(Ordering::SeqCst) || dev.duty.load(Ordering::SeqCst) != 200 {
        return TestResult::Fail("pwm1 store did not drive set_fan with duty 200");
    }
    match kobj.attr_show("pwm1") {
        Some(s) if s == "200\n" => {}
        Some(_) => return TestResult::Fail("pwm1 did not read back duty 200"),
        None => return TestResult::Fail("pwm1 attr missing after store"),
    }
    for bad in [
        &b"256"[..],
        &b"1000"[..],
        &b"fast"[..],
        &b""[..],
        &b"-1"[..],
    ] {
        match kobj.attr_store("pwm1", bad) {
            Some(Err(_)) => {}
            Some(Ok(())) => return TestResult::Fail("pwm1 store accepted invalid input"),
            None => return TestResult::Fail("pwm1 has no store callback"),
        }
    }
    if dev.duty.load(Ordering::SeqCst) != 200 {
        return TestResult::Fail("a rejected pwm1 store changed the driven duty");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/bridge",
    smoke_bridge_pwm_store_drives_set_fan
);

// ── Thermal composition (#909) ──────────────────────────────────────

/// The cooling adapter forwards the governor's level to `set_fan`
/// unchanged — the adapter is the in-kernel production caller that
/// connects the thermal loop to the hwmon drivers.
fn smoke_cooling_adapter_drives_set_fan() -> TestResult {
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;
    use narf_power::thermal::CoolingDevice as _;
    let dev = Arc::new(FakeControlDevice::new());
    let cooling = crate::cooling::HwmonCoolingDevice::new(dev.clone(), "fan1");
    cooling.set_level(77);
    if !dev.set_fan_called.load(Ordering::SeqCst) || dev.duty.load(Ordering::SeqCst) != 77 {
        return TestResult::Fail("cooling adapter did not drive set_fan with level 77");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/cooling",
    smoke_cooling_adapter_drives_set_fan
);

/// End to end: a controllable device in the hwmon registry is picked
/// up by `register_hwmon_cooling_devices`, and the thermal
/// governor's `set_cooling_level` reaches its `set_fan`.
fn smoke_cooling_registration_reaches_governor() -> TestResult {
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;
    narf_power::thermal::init();
    crate::registry::__reset_devices_for_test();
    let dev = Arc::new(FakeControlDevice::new());
    crate::registry::register_device(dev.clone());
    crate::cooling::register_hwmon_cooling_devices();
    match narf_power::thermal::set_cooling_level(55) {
        Ok(()) => {}
        Err(_) => return TestResult::Fail("set_cooling_level failed after registration"),
    }
    if dev.duty.load(Ordering::SeqCst) != 55 {
        return TestResult::Fail("governor level 55 did not reach the device's set_fan");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/cooling",
    smoke_cooling_registration_reaches_governor
);

// ── Power-service temperature provider (#914) ───────────────────────

/// Minimal `HwmonDevice` whose temperature reads come from fixed
/// per-label values — the fake the provider fixtures resolve
/// against in the shared registry.
#[derive(Debug)]
struct FakeTempDevice {
    name: &'static str,
    tdie: Option<i32>,
    tpackage: Option<i32>,
}

impl crate::HwmonDevice for FakeTempDevice {
    fn name(&self) -> &str {
        self.name
    }

    fn read_temp(&self, label: &str) -> Option<i32> {
        match label {
            "Tdie" => self.tdie,
            "Tpackage" => self.tpackage,
            _ => None,
        }
    }

    fn read_fan(&self, _label: &str) -> Option<u32> {
        None
    }

    fn read_voltage(&self, _label: &str) -> Option<i32> {
        None
    }

    fn set_fan(&self, _label: &str, _level: u8) -> bool {
        false
    }

    fn list_labels(&self) -> alloc::vec::Vec<&str> {
        let mut labels = alloc::vec::Vec::new();
        if self.tdie.is_some() {
            labels.push("Tdie");
        }
        if self.tpackage.is_some() {
            labels.push("Tpackage");
        }
        labels
    }
}

/// Restore the power service's CPU temperature provider to a
/// None-returning one, so a fixture's registration cannot leak a
/// live provider into other tests sharing the boot.
fn restore_none_cpu_provider() {
    use alloc::sync::Arc;
    let cap = narf_power::bootstrap_power_authority();
    let providers = narf_power::service::StateProviders {
        ac_adapter: None,
        lid: None,
        battery: None,
        cpu_temp_mc: Some(Arc::new(|| None)),
        gpu_temp_mc: None,
    };
    let _ = narf_power::service::register_state_providers(&cap, providers);
}

/// With both CPU temperature drivers present, the provider reads
/// k10temp's `Tdie` — and the fused snapshot the power service
/// produces carries it in `cpu_tdie_mc`.
fn smoke_power_provider_prefers_k10temp_tdie() -> TestResult {
    use alloc::sync::Arc;
    crate::registry::__reset_devices_for_test();
    crate::registry::register_device(Arc::new(FakeTempDevice {
        name: "coretemp",
        tdie: None,
        tpackage: Some(55_000),
    }));
    crate::registry::register_device(Arc::new(FakeTempDevice {
        name: "k10temp",
        tdie: Some(67_500),
        tpackage: None,
    }));
    if crate::power_providers::cpu_temp_mc() != Some(67_500) {
        crate::registry::__reset_devices_for_test();
        return TestResult::Fail("provider must prefer k10temp Tdie");
    }
    crate::power_providers::register_temp_providers();
    let got = narf_power::service::snapshot().cpu_tdie_mc;
    restore_none_cpu_provider();
    crate::registry::__reset_devices_for_test();
    if got != Some(67_500) {
        return TestResult::Fail("snapshot cpu_tdie_mc must carry the Tdie reading");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/power-providers",
    smoke_power_provider_prefers_k10temp_tdie
);

/// Intel fallback: with no k10temp device, coretemp's package
/// sensor feeds the provider.
fn smoke_power_provider_coretemp_fallback() -> TestResult {
    use alloc::sync::Arc;
    crate::registry::__reset_devices_for_test();
    crate::registry::register_device(Arc::new(FakeTempDevice {
        name: "coretemp",
        tdie: None,
        tpackage: Some(55_000),
    }));
    let got = crate::power_providers::cpu_temp_mc();
    crate::registry::__reset_devices_for_test();
    if got != Some(55_000) {
        return TestResult::Fail("provider must fall back to coretemp Tpackage");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/power-providers",
    smoke_power_provider_coretemp_fallback
);

/// No CPU temperature driver probed: the provider yields `None`
/// and the snapshot field stays unknown — never a fabricated zero.
fn smoke_power_provider_absent_is_none() -> TestResult {
    crate::registry::__reset_devices_for_test();
    if crate::power_providers::cpu_temp_mc().is_some() {
        return TestResult::Fail("provider must be None with an empty registry");
    }
    crate::power_providers::register_temp_providers();
    let got = narf_power::service::snapshot().cpu_tdie_mc;
    restore_none_cpu_provider();
    if got.is_some() {
        return TestResult::Fail("snapshot cpu_tdie_mc must stay None without a source");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/power-providers",
    smoke_power_provider_absent_is_none
);

/// `temp1_label` returns the label string with a newline.
fn smoke_bridge_temp1_label_returns_tctl() -> TestResult {
    use crate::k10temp::{chip_info, K10temp, AMD_RENOIR_NB};
    use alloc::sync::Arc;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let chip = match chip_info(AMD_RENOIR_NB) {
        Some(c) => c,
        None => return TestResult::Fail("Renoir chip info missing"),
    };
    crate::registry::register_device(Arc::new(K10temp::new(0, 0, 0, chip)));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match narf_filesystem::sysfs::sysfs_root()
        .get_child("class")
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
kernel_test_in!(
    "drivers/hwmon/bridge",
    smoke_bridge_temp1_label_returns_tctl
);

/// Two devices produce hwmon0 and hwmon1.
fn smoke_bridge_multiple_devices_enumerated() -> TestResult {
    use crate::coretemp::Coretemp;
    use crate::k10temp::{chip_info, K10temp, AMD_RENOIR_NB};
    use alloc::sync::Arc;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let chip = match chip_info(AMD_RENOIR_NB) {
        Some(c) => c,
        None => return TestResult::Fail("Renoir chip info missing"),
    };
    crate::registry::register_device(Arc::new(K10temp::new(0, 0, 0, chip)));
    crate::registry::register_device(Arc::new(Coretemp::new(100, 0)));
    crate::sysfs_bridge::populate_hwmon_class();
    let class_hwmon = match narf_filesystem::sysfs::sysfs_root()
        .get_child("class")
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
kernel_test_in!(
    "drivers/hwmon/bridge",
    smoke_bridge_multiple_devices_enumerated
);

/// NCT6779D has 5 fans; bridge should expose fan1_input through fan5_input.
fn smoke_bridge_nct6779d_five_fan_inputs() -> TestResult {
    use crate::nct6775::{Nct6775, NctChip, NCT6779D_ID};
    use alloc::sync::Arc;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let dev = Nct6775::new(NctChip::Nct6779D, NCT6779D_ID, 0x2E, 0x2F);
    crate::registry::register_device(Arc::new(dev));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match narf_filesystem::sysfs::sysfs_root()
        .get_child("class")
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
kernel_test_in!(
    "drivers/hwmon/bridge",
    smoke_bridge_nct6779d_five_fan_inputs
);

/// `update_interval` attr exists and returns "1000\n".
fn smoke_bridge_update_interval_attr() -> TestResult {
    use crate::coretemp::Coretemp;
    use alloc::sync::Arc;
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    crate::registry::register_device(Arc::new(Coretemp::new(105, 0)));
    crate::sysfs_bridge::populate_hwmon_class();
    let kobj = match narf_filesystem::sysfs::sysfs_root()
        .get_child("class")
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

/// nct6775 voltage decode: 8 mV/LSB for the undivided inputs, and the
/// per-input scaled form `DIV_ROUND_CLOSEST(raw * scale, 100)`.
fn smoke_nct6775_voltage_decode() -> TestResult {
    use crate::nct6775::{in_from_reg, in_from_reg_scaled};
    if in_from_reg(0) != 0 || in_from_reg(100) != 800 || in_from_reg(255) != 2040 {
        return TestResult::Fail("nct6775 in_from_reg (8 mV/LSB) wrong");
    }
    if in_from_reg_scaled(100, 800) != 800 || in_from_reg_scaled(255, 1600) != 4080 {
        return TestResult::Fail("nct6775 in_from_reg_scaled wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/nct6775", smoke_nct6775_voltage_decode);

/// nct6775 temperature decode: lm75-style 16-bit (1/128 °C) and the
/// byte-register helper. 0x3200 → 50.0 °C, 0x3280 → 50.5 °C, and a
/// negative two's-complement value 0xCE00 → -50.0 °C.
fn smoke_nct6775_temp_decode() -> TestResult {
    use crate::nct6775::{reg_is_word_sized, temp_from_reg, temp_from_reg_word};
    if temp_from_reg_word(0x3200) != 50_000
        || temp_from_reg_word(0x3280) != 50_500
        || temp_from_reg_word(0xCE00) != -50_000
    {
        return TestResult::Fail("nct6775 temp_from_reg_word wrong");
    }
    if temp_from_reg(50) != 50_000 || temp_from_reg(0) != 0 || temp_from_reg(206) != -50_000 {
        return TestResult::Fail("nct6775 temp_from_reg (byte) wrong");
    }
    if !reg_is_word_sized(0x150) || !reg_is_word_sized(0x630) || reg_is_word_sized(0x27) {
        return TestResult::Fail("nct6775 reg_is_word_sized classification wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/nct6775", smoke_nct6775_temp_decode);

// ── it87 ──────────────────────────────────────────────────────────────

/// it87 fan tach decode: 16-bit `1350000/(count*2)` and 8-bit with a
/// divisor. count 0 / 0xffff → None (stopped / disconnected).
fn smoke_it87_fan_decode() -> TestResult {
    use crate::it87::{fan16_to_rpm, fan8_to_rpm};
    if fan16_to_rpm(0).is_some() || fan16_to_rpm(0xffff).is_some() {
        return TestResult::Fail("it87 fan16 count 0/0xffff should be None");
    }
    if fan16_to_rpm(675) != Some(1000) || fan16_to_rpm(1350) != Some(500) {
        return TestResult::Fail("it87 fan16_to_rpm wrong");
    }
    if fan8_to_rpm(0, 2).is_some() || fan8_to_rpm(255, 2).is_some() {
        return TestResult::Fail("it87 fan8 count 0/255 should be None");
    }
    if fan8_to_rpm(54, 2) != Some(12_500) {
        return TestResult::Fail("it87 fan8_to_rpm wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/it87", smoke_it87_fan_decode);

/// it87 voltage (16 mV/LSB) and signed-byte temperature decode.
fn smoke_it87_voltage_temp_decode() -> TestResult {
    use crate::it87::{temp_from_reg, vin_from_reg};
    if vin_from_reg(0) != 0 || vin_from_reg(75) != 1200 || vin_from_reg(255) != 4080 {
        return TestResult::Fail("it87 vin_from_reg wrong");
    }
    if temp_from_reg(0) != 0 || temp_from_reg(40) != 40_000 || temp_from_reg(0xFF) != -1000 {
        return TestResult::Fail("it87 temp_from_reg (signed byte) wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/it87", smoke_it87_voltage_temp_decode);

// ── applesmc ──────────────────────────────────────────────────────────

/// applesmc SMC value decode: sp78 (signed 8.8) → millidegrees, and
/// fpe2 (14.2 unsigned) → RPM.
fn smoke_applesmc_value_decode() -> TestResult {
    use crate::applesmc::{fpe2_to_rpm, sp78_to_mc};
    if sp78_to_mc(0x1E, 0x00) != 30_000
        || sp78_to_mc(0x32, 0x80) != 50_500
        || sp78_to_mc(0xFF, 0x00) != -1000
    {
        return TestResult::Fail("applesmc sp78_to_mc wrong");
    }
    if fpe2_to_rpm(0x0B, 0xB8) != 750
        || fpe2_to_rpm(0x4E, 0x20) != 5000
        || fpe2_to_rpm(0x00, 0x00) != 0
    {
        return TestResult::Fail("applesmc fpe2_to_rpm wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/applesmc", smoke_applesmc_value_decode);

// ── jc42 ──────────────────────────────────────────────────────────────

/// jc42 temperature decode: 13-bit two's-complement, 0.0625 °C/LSB,
/// with the top three alarm-flag bits masked off. 0x0190 → 25 °C;
/// 0x1FFF → one LSB below zero; 0x1C00 → -64 °C.
fn smoke_jc42_temp_decode() -> TestResult {
    use crate::jc42::temp_from_reg;
    if temp_from_reg(0x0190) != 25_000 {
        return TestResult::Fail("jc42 temp_from_reg(0x0190) should be 25000");
    }
    if temp_from_reg(0x1FFF) != -62 {
        return TestResult::Fail("jc42 temp_from_reg(0x1FFF) should be -62");
    }
    if temp_from_reg(0x1C00) != -64_000 {
        return TestResult::Fail("jc42 temp_from_reg(0x1C00) should be -64000");
    }
    // Alarm flag bits [15:13] must not affect the decoded value.
    if temp_from_reg(0xE190) != temp_from_reg(0x0190) {
        return TestResult::Fail("jc42 alarm flag bits leaked into temperature");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/jc42", smoke_jc42_temp_decode);

// ── dell_smm ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod dell_smm_tests {
    use crate::dell_smm::{DellSmm, SMM_MOCK};
    use crate::HwmonDevice;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Last `SMM_SET_FAN` argument the mock received
    /// (`fan_idx | level << 8`); `u32::MAX` until the first call.
    static LAST_SET_FAN_ARG: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(u32::MAX);

    fn mock_smm_call(cmd: u32, arg: u32) -> crate::dell_smm::SmmResult {
        use crate::dell_smm::*;
        match cmd {
            SMM_GET_TEMP => {
                if arg == 0 {
                    SmmResult { eax: 45, edx: 0 }
                } else if arg == 1 {
                    SmmResult { eax: 55, edx: 0 }
                } else {
                    SmmResult {
                        eax: SMM_ERR_NOSUPPORT,
                        edx: 0,
                    }
                }
            }
            SMM_GET_FAN_STATUS => {
                if arg == 0 {
                    SmmResult { eax: 2, edx: 0 }
                } else if arg == 1 {
                    SmmResult { eax: 1, edx: 0 }
                } else {
                    SmmResult {
                        eax: SMM_ERR_NOSUPPORT,
                        edx: 0,
                    }
                }
            }
            SMM_GET_FAN_NOMINAL_RPM => {
                if arg == 0 {
                    SmmResult { eax: 100, edx: 0 }
                } else if arg == 1 {
                    SmmResult { eax: 80, edx: 0 }
                } else {
                    SmmResult {
                        eax: SMM_ERR_NOSUPPORT,
                        edx: 0,
                    }
                }
            }
            SMM_SET_FAN => {
                LAST_SET_FAN_ARG.store(arg, core::sync::atomic::Ordering::SeqCst);
                let fan_idx = arg & 0xFF;
                let level = (arg >> 8) & 0xFF;
                if fan_idx < 2 && level <= 3 {
                    SmmResult { eax: 0, edx: 0 }
                } else {
                    SmmResult {
                        eax: SMM_ERR_NOSUPPORT,
                        edx: 0,
                    }
                }
            }
            _ => SmmResult {
                eax: SMM_ERR_NOSUPPORT,
                edx: 0,
            },
        }
    }

    /// Verify Dell SMM temp, fan read/write operations when mocked.
    fn smoke_dell_smm_operations() -> TestResult {
        *SMM_MOCK.lock() = Some(mock_smm_call);

        let dev = DellSmm::new();

        // Verify temp readings
        if dev.read_temp("cpu") != Some(45_000) {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Expected cpu temp 45_000 mC");
        }
        if dev.read_temp("gpu") != Some(55_000) {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Expected gpu temp 55_000 mC");
        }
        if dev.read_temp("hdd").is_some() {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Expected hdd temp to be None (nosupport)");
        }

        // Verify fan readings (RPM = nominal * 30)
        if dev.read_fan("fan1") != Some(3000) {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Expected fan1 RPM to be 3000");
        }
        if dev.read_fan("fan2") != Some(2400) {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Expected fan2 RPM to be 2400");
        }

        // Verify fan writes: `set_fan` takes the trait's 0–255 duty
        // and the driver scales it to an SMM tier at the boundary —
        // duty 255 reaches the firmware as tier 3 (max) for fan 0,
        // duty 85 as tier 1 (low) for fan 1.
        use core::sync::atomic::Ordering;
        LAST_SET_FAN_ARG.store(u32::MAX, Ordering::SeqCst);
        if !dev.set_fan("fan1", 255) {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Expected set_fan(fan1, 255) to succeed");
        }
        if LAST_SET_FAN_ARG.load(Ordering::SeqCst) != (3 << 8) {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Duty 255 should reach SMM as tier 3 for fan 0");
        }
        if !dev.set_fan("fan2", 85) {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Expected set_fan(fan2, 85) to succeed");
        }
        if LAST_SET_FAN_ARG.load(Ordering::SeqCst) != (1 | (1 << 8)) {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Duty 85 should reach SMM as tier 1 for fan 1");
        }
        // The raw firmware boundary still rejects out-of-range tiers.
        if crate::dell_smm::set_fan_level(0, 5) {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Expected SMM to reject tier 5");
        }
        // Unknown fan labels are refused at the trait surface.
        if dev.set_fan("fan9", 100) {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Expected set_fan on an unknown label to fail");
        }

        // read_pwm reports the firmware's current tier as its duty:
        // the mock's fan status is tier 2 for fan1 (duty 170) and
        // tier 1 for fan2 (duty 85).
        if dev.read_pwm("fan1") != Some(170) {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Expected fan1 read_pwm to be 170 (tier 2)");
        }
        if dev.read_pwm("fan2") != Some(85) {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("Expected fan2 read_pwm to be 85 (tier 1)");
        }
        if !dev.supports_fan_control("fan1") || dev.supports_fan_control("fan3") {
            *SMM_MOCK.lock() = None;
            return TestResult::Fail("supports_fan_control disagrees with the fan labels");
        }

        *SMM_MOCK.lock() = None;
        TestResult::Pass
    }
    kernel_test_in!("drivers/hwmon/dell_smm", smoke_dell_smm_operations);

    /// Duty↔tier scaling: the four tier duties map to their own
    /// tiers, the scale is monotonic across the duty range, and the
    /// round trip tier → duty → tier is exact.
    fn smoke_dell_smm_duty_tier_scaling() -> TestResult {
        use crate::dell_smm::{duty_to_tier, tier_to_duty};
        if duty_to_tier(0) != 0
            || duty_to_tier(85) != 1
            || duty_to_tier(170) != 2
            || duty_to_tier(255) != 3
        {
            return TestResult::Fail("tier duties should map to their own tiers");
        }
        if duty_to_tier(128) != 2 || duty_to_tier(42) != 0 || duty_to_tier(43) != 1 {
            return TestResult::Fail("duty_to_tier rounding wrong at band edges");
        }
        if tier_to_duty(0) != 0
            || tier_to_duty(1) != 85
            || tier_to_duty(2) != 170
            || tier_to_duty(3) != 255
        {
            return TestResult::Fail("tier_to_duty values wrong");
        }
        for tier in 0..=3u32 {
            if duty_to_tier(tier_to_duty(tier)) != tier as u8 {
                return TestResult::Fail("duty↔tier round trip not exact");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/hwmon/dell_smm", smoke_dell_smm_duty_tier_scaling);

    fn set_mock_system_manufacturer(mfr: &[u8]) {
        let fixed_len: u8 = 25;
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        buf.push(1); // Type 1: System Info
        buf.push(fixed_len);
        buf.extend_from_slice(&0u16.to_le_bytes()); // Handle
        buf.push(1); // Manufacturer str
        buf.push(2); // Product str
        buf.push(3); // Version str
        buf.push(4); // Serial str
        buf.extend_from_slice(&[0u8; 16]); // UUID
        buf.push(0x06); // Wake-up type

        buf.extend_from_slice(mfr);
        buf.push(0);
        buf.extend_from_slice(b"MockProduct\0");
        buf.extend_from_slice(b"v1.0\0");
        buf.extend_from_slice(b"SN-123\0");
        buf.push(0); // End of strings

        // Type 127 (End-of-table)
        buf.push(127);
        buf.push(4);
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(0);
        buf.push(0);

        narf_firmware_smbios::parse_stream(&buf);
    }

    /// Verify that non-Dell systems skip registering the dell_smm driver.
    fn smoke_dell_smm_registration_skips_non_dell() -> TestResult {
        crate::registry::__reset_devices_for_test();
        set_mock_system_manufacturer(b"QEMU\0");

        crate::dell_smm::register_smm_driver();

        if crate::registry::device_count() != 0 {
            return TestResult::Fail("Expected dell_smm driver to be skipped on non-Dell systems");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/hwmon/dell_smm",
        smoke_dell_smm_registration_skips_non_dell
    );

    /// Verify that Dell systems successfully register the dell_smm driver.
    fn smoke_dell_smm_registration_accepts_dell() -> TestResult {
        crate::registry::__reset_devices_for_test();
        set_mock_system_manufacturer(b"Dell Inc.\0");

        crate::dell_smm::register_smm_driver();

        if crate::registry::device_count() != 1 {
            return TestResult::Fail("Expected dell_smm driver to be registered on Dell systems");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/hwmon/dell_smm",
        smoke_dell_smm_registration_accepts_dell
    );
}
