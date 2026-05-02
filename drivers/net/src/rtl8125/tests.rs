//! rtl8125 driver smokes — co-located per project convention.
//!
//! Stage 1: PCI match-table entries for RTL8125 + RTL8125B.
//! Stage 2: MAC-address decode + reset-value bit pattern.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    cr_reset_value, decode_mac, mac_is_invalid, name_for,
    CR_RST, RTL_DEV_8125, RTL_DEV_8125B, RTL_VENDOR,
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

// ── Stage 2: MAC decode + CR.RST ───────────────────────────────────

fn smoke_rtl8125_mac_decode_round_trip() -> TestResult {
    // IDR0..5 → on-wire MAC, byte-by-byte.
    let raw = [0x52u8, 0x54, 0x00, 0xAB, 0xCD, 0xEF, 0xFF, 0xFF];
    let mac = match decode_mac(&raw) {
        Some(m) => m,
        None    => return TestResult::Fail("decode_mac returned None on 8-byte input"),
    };
    if mac != [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF] {
        return TestResult::Fail("MAC bytes did not match IDR0..5 input");
    }
    if mac_is_invalid(mac) {
        return TestResult::Fail("locally-administered MAC flagged as invalid");
    }
    if decode_mac(&[0u8; 5]).is_some() {
        return TestResult::Fail("decode_mac accepted < 6-byte input");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_mac_decode_round_trip);

fn smoke_rtl8125_mac_invalid_sentinels() -> TestResult {
    if !mac_is_invalid([0; 6])    { return TestResult::Fail("all-zero MAC not flagged"); }
    if !mac_is_invalid([0xFF; 6]) { return TestResult::Fail("all-FF MAC not flagged"); }
    if  mac_is_invalid([0, 0, 0, 0, 0, 1]) {
        return TestResult::Fail("non-zero MAC false-flagged");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_mac_invalid_sentinels);

fn smoke_rtl8125_cr_reset_bit() -> TestResult {
    // §2.4 places RST at bit 4. cr_reset_value() must produce exactly
    // that bit so the bring-up path's CR write doesn't accidentally
    // flip TE/RE in the same cycle.
    if cr_reset_value() != CR_RST     { return TestResult::Fail("cr_reset_value != CR_RST"); }
    if cr_reset_value() != 1 << 4     { return TestResult::Fail("CR_RST not at bit 4 per §2.4"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/rtl8125", smoke_rtl8125_cr_reset_bit);
