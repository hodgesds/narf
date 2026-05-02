//! rtl8125 driver smokes — co-located per project convention.
//!
//! Stage 1: PCI match-table entries for RTL8125 + RTL8125B.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    name_for, RTL_DEV_8125, RTL_DEV_8125B, RTL_VENDOR,
};

// ── Stage 1: PCI match table ───────────────────────────────────────

fn smoke_rtl8125_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    for did in [RTL_DEV_8125, RTL_DEV_8125B] {
        let matched = registered.iter().any(|m|
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: RTL_VENDOR, device,
            } if device == did));
        if !matched {
            return TestResult::Fail("rtl8125 PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_pci_match_table);

fn smoke_rtl8125_name_for_known_ids() -> TestResult {
    if name_for(RTL_DEV_8125)  != "rtl8125"  { return TestResult::Fail("rtl8125 name"); }
    if name_for(RTL_DEV_8125B) != "rtl8125b" { return TestResult::Fail("rtl8125b name"); }
    if name_for(0xFFFF)        != "rtl8125"  { return TestResult::Fail("default name"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_name_for_known_ids);
