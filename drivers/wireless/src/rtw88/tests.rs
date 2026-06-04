//! RTW88 smoke tests — co-located per project convention.
//!
//! All smokes are pure-data: PCI match table presence, register-
//! constant sanity, MAC-validity classifier. None of them touch live
//! silicon, so they Pass on QEMU instead of Skip. The "real silicon"
//! smoke (probe-bound device + live EFUSE read) lands in the
//! follow-up commit alongside the firmware loader; it would Skip
//! cleanly on QEMU since no RTW88 part is emulated.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::efuse::{mac_is_valid, EfuseError};
use super::pci::{name_for, register_pci_driver};
use super::power::PowerError;
use super::regs::*;

// ── PCI match table ────────────────────────────────────────────────

fn smoke_rtw88_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    register_pci_driver();
    let registered = registered_pci_drivers();
    for did in [RTL_DEV_8821CE, RTL_DEV_8822CE, RTL_DEV_8822BE] {
        let matched = registered.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: REALTEK_VENDOR,
                    device,
                } if device == did
            )
        });
        if !matched {
            return TestResult::Fail("rtw88 PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw88", smoke_rtw88_pci_match_table);

fn smoke_rtw88_name_for_known_ids() -> TestResult {
    if name_for(RTL_DEV_8821CE) != "rtw88-8821ce" {
        return TestResult::Fail("8821ce name mismatch");
    }
    if name_for(RTL_DEV_8822CE) != "rtw88-8822ce" {
        return TestResult::Fail("8822ce name mismatch");
    }
    if name_for(RTL_DEV_8822BE) != "rtw88-8822be" {
        return TestResult::Fail("8822be name mismatch");
    }
    if name_for(0xFFFF) != "rtw88" {
        return TestResult::Fail("default name mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw88", smoke_rtw88_name_for_known_ids);

// ── Register constants ─────────────────────────────────────────────

fn smoke_rtw88_cr_open_bits() -> TestResult {
    // CR_OPEN must cover every per-block enable bit. If a follow-up
    // commit silently widens CR_*, the mask should be re-derived
    // explicitly — this smoke catches drift.
    let expect = CR_HCI_TXDMA_EN
        | CR_HCI_RXDMA_EN
        | CR_TXDMA_EN
        | CR_RXDMA_EN
        | CR_PROTOCOL_EN
        | CR_SCHEDULE_EN
        | CR_MAC_TX_EN
        | CR_MAC_RX_EN;
    if CR_OPEN != expect {
        return TestResult::Fail("CR_OPEN not equal to OR of per-block enable bits");
    }
    // All CR enable bits live in the low byte.
    if CR_OPEN & 0xFF00 != 0 {
        return TestResult::Fail("CR_OPEN spilled into bits 8..15");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw88", smoke_rtw88_cr_open_bits);

fn smoke_rtw88_efuse_ctrl_layout() -> TestResult {
    // Per `rtw88/efuse.c`: VALID is bit 31, addr field shifts in at
    // bit 8, data byte sits in bits[7:0]. Catch typos.
    if EFUSE_CTRL_VALID != 1u32 << 31 {
        return TestResult::Fail("EFUSE_CTRL_VALID not at bit 31");
    }
    if EFUSE_CTRL_ADDR_SHIFT != 8 {
        return TestResult::Fail("EFUSE_CTRL_ADDR_SHIFT not 8");
    }
    if EFUSE_CTRL_DATA_MASK != 0x0000_00FF {
        return TestResult::Fail("EFUSE_CTRL_DATA_MASK wrong");
    }
    if LDO_EFUSE_EN != 1u32 << 31 {
        return TestResult::Fail("LDO_EFUSE_EN not at bit 31");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw88", smoke_rtw88_efuse_ctrl_layout);

fn smoke_rtw88_register_offsets_distinct() -> TestResult {
    // Soft sanity that no two registers we touch share an offset by
    // accident — easy to break with a typo on the next register
    // addition.
    let offsets = [
        REG_SYS_FUNC_EN,
        REG_SYS_PW_CTRL,
        REG_SYS_CLK_CTRL,
        REG_RSV_CTRL,
        REG_AFE_CTRL3,
        REG_CR,
        REG_EFUSE_CTRL,
        REG_LDO_EFUSE_CTRL,
    ];
    for i in 0..offsets.len() {
        for j in (i + 1)..offsets.len() {
            if offsets[i] == offsets[j] {
                return TestResult::Fail("two RTW88 registers share an offset");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_register_offsets_distinct
);

// ── MAC validity ───────────────────────────────────────────────────

fn smoke_rtw88_mac_is_valid_classifier() -> TestResult {
    if mac_is_valid([0u8; 6]) {
        return TestResult::Fail("all-zero MAC mis-classified as valid");
    }
    if mac_is_valid([0xFFu8; 6]) {
        return TestResult::Fail("all-FF MAC mis-classified as valid");
    }
    if !mac_is_valid([0x00, 0xE0, 0x4C, 0x68, 0x12, 0x34]) {
        return TestResult::Fail("Realtek-prefix MAC mis-classified as invalid");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_mac_is_valid_classifier
);

// ── Error-type debug-presence sanity ───────────────────────────────
//
// Cheap presence check: the typed errors are stable enough that downstream
// match expressions don't bit-rot silently. The Debug format is also
// what the kernel-side panic bundle dumps for these.

fn smoke_rtw88_error_types_debug() -> TestResult {
    use core::fmt::Write;
    let mut buf = alloc::string::String::new();
    let _ = write!(buf, "{:?}", PowerError::Timeout);
    let _ = write!(buf, "{:?}", PowerError::DeviceGone);
    let _ = write!(buf, "{:?}", EfuseError::Timeout);
    let _ = write!(buf, "{:?}", EfuseError::MacUninitialized);
    if buf.is_empty() {
        return TestResult::Fail("error type Debug formatter produced nothing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw88", smoke_rtw88_error_types_debug);

// ── Live-silicon smoke (Skip on QEMU) ──────────────────────────────
//
// QEMU doesn't emulate any RTW88 part, so this smoke is here so a
// future real-HW test run lights up without changing the test list.
// It Skips cleanly when the probe path hasn't bound a device.

fn smoke_rtw88_probe_bound_or_skip() -> TestResult {
    if !super::pci::is_probed() {
        return TestResult::Skip("rtw88: no RTL8821CE/8822BE/8822CE bound (expected on QEMU)");
    }
    let mac = match super::pci::with_controller(|d| d.mac) {
        Some(m) => m,
        None => return TestResult::Skip("rtw88: probed flag set but no controller borrowable"),
    };
    if !mac_is_valid(mac) {
        return TestResult::Fail("rtw88: bound device reports invalid EFUSE MAC");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw88", smoke_rtw88_probe_bound_or_skip);
