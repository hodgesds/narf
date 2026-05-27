//! RTW89 smoke tests — co-located per project convention.
//!
//! All smokes are pure-data: PCI match table presence, register-
//! constant sanity, chip-id classifier, MAC-validity classifier. None
//! of them touch live silicon, so they Pass on QEMU instead of Skip.
//! The "real silicon" smoke (probe-bound device + live EFUSE read)
//! lands in Stage-2 alongside the firmware loader; it would Skip
//! cleanly on QEMU since no RTW89 part is emulated.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::efuse::{mac_is_valid, EfuseError};
use super::fw::{expected_blob_name, FwError};
use super::mac::*;
use super::pci::{name_for, register_pci_driver};
use super::phy::PhyError;
use super::*;

// ── PCI match table ────────────────────────────────────────────────

fn smoke_rtw89_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    register_pci_driver();
    let registered = registered_pci_drivers();
    for did in [
        RTL_DEV_8852AE,
        RTL_DEV_8852BE,
        RTL_DEV_8852CE,
        RTL_DEV_8851BE,
        RTL_DEV_8922AE,
    ] {
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
            return TestResult::Fail("rtw89 PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_pci_match_table);

fn smoke_rtw89_name_for_known_ids() -> TestResult {
    if name_for(RTL_DEV_8852AE) != "rtw89-8852ae" {
        return TestResult::Fail("8852ae name mismatch");
    }
    if name_for(RTL_DEV_8852AE_VT) != "rtw89-8852ae-vt" {
        return TestResult::Fail("8852ae_vt name mismatch");
    }
    if name_for(RTL_DEV_8852BE) != "rtw89-8852be" {
        return TestResult::Fail("8852be name mismatch");
    }
    if name_for(RTL_DEV_8852BE_ALT) != "rtw89-8852be-alt" {
        return TestResult::Fail("8852be_alt name mismatch");
    }
    if name_for(RTL_DEV_8852CE) != "rtw89-8852ce" {
        return TestResult::Fail("8852ce name mismatch");
    }
    if name_for(RTL_DEV_8851BE) != "rtw89-8851be" {
        return TestResult::Fail("8851be name mismatch");
    }
    if name_for(RTL_DEV_8922AE) != "rtw89-8922ae" {
        return TestResult::Fail("8922ae name mismatch");
    }
    if name_for(RTL_DEV_8922AE_ALT) != "rtw89-8922ae-alt" {
        return TestResult::Fail("8922ae_alt name mismatch");
    }
    if name_for(0xFFFF) != "rtw89" {
        return TestResult::Fail("default name mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_name_for_known_ids);

// ── Chip-id classifier ─────────────────────────────────────────────

fn smoke_rtw89_chip_id_classifier() -> TestResult {
    if ChipId::from_pci_did(RTL_DEV_8852AE) != Some(ChipId::Rtl8852A) {
        return TestResult::Fail("8852ae did not classify to Rtl8852A");
    }
    if ChipId::from_pci_did(RTL_DEV_8852BE) != Some(ChipId::Rtl8852B) {
        return TestResult::Fail("8852be did not classify to Rtl8852B");
    }
    if ChipId::from_pci_did(RTL_DEV_8852CE) != Some(ChipId::Rtl8852C) {
        return TestResult::Fail("8852ce did not classify to Rtl8852C");
    }
    if ChipId::from_pci_did(RTL_DEV_8851BE) != Some(ChipId::Rtl8851B) {
        return TestResult::Fail("8851be did not classify to Rtl8851B");
    }
    if ChipId::from_pci_did(RTL_DEV_8922AE) != Some(ChipId::Rtl8922A) {
        return TestResult::Fail("8922ae did not classify to Rtl8922A");
    }
    if ChipId::from_pci_did(0xFFFF).is_some() {
        return TestResult::Fail("unknown did mis-classified");
    }
    // Generation split: 8852/8851 → Ax, 8922 → Be.
    if ChipId::Rtl8852A.generation() != ChipGeneration::Ax {
        return TestResult::Fail("8852A generation not Ax");
    }
    if ChipId::Rtl8852C.generation() != ChipGeneration::Ax {
        return TestResult::Fail("8852C generation not Ax");
    }
    if ChipId::Rtl8922A.generation() != ChipGeneration::Be {
        return TestResult::Fail("8922A generation not Be");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_chip_id_classifier);

// ── Register-constant sanity ────────────────────────────────────────

fn smoke_rtw89_register_offsets_distinct() -> TestResult {
    let offsets = [
        R_AX_SYS_ISO_CTRL,
        R_AX_SYS_FUNC_EN,
        R_AX_SYS_PW_CTRL,
        R_AX_SYS_CLK_CTRL,
        R_AX_SYS_WL_EFUSE_CTRL,
        R_AX_RSV_CTRL,
        R_AX_EFUSE_CTRL,
        R_AX_SYS_SDIO_CTRL,
        R_AX_PLATFORM_ENABLE,
        R_AX_SYS_CFG1,
    ];
    for i in 0..offsets.len() {
        for j in (i + 1)..offsets.len() {
            if offsets[i] == offsets[j] {
                return TestResult::Fail("two RTW89 registers share an offset");
            }
        }
    }
    // Pin a few concrete values to catch typo drift against `rtw89/reg.h`.
    if R_AX_SYS_FUNC_EN != 0x0002 {
        return TestResult::Fail("R_AX_SYS_FUNC_EN drifted");
    }
    if R_AX_EFUSE_CTRL != 0x0030 {
        return TestResult::Fail("R_AX_EFUSE_CTRL drifted");
    }
    if R_AX_PLATFORM_ENABLE != 0x0088 {
        return TestResult::Fail("R_AX_PLATFORM_ENABLE drifted");
    }
    if R_AX_SYS_CFG1 != 0x00F0 {
        return TestResult::Fail("R_AX_SYS_CFG1 drifted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_register_offsets_distinct);

fn smoke_rtw89_efuse_field_layout() -> TestResult {
    // Per `rtw89/reg.h`:
    //   B_AX_EF_ADDR_MASK = GENMASK(26, 16) = 0x07FF_0000
    //   B_AX_EF_DATA_MASK = GENMASK(15,  0) = 0x0000_FFFF
    //   B_AX_EF_RDY = BIT(29)
    //   B_AX_EF_MODE_SEL_MASK = GENMASK(31, 30) = 0xC000_0000
    if B_AX_EF_ADDR_MASK != 0x07FF_0000 {
        return TestResult::Fail("B_AX_EF_ADDR_MASK wrong");
    }
    if B_AX_EF_ADDR_SHIFT != 16 {
        return TestResult::Fail("B_AX_EF_ADDR_SHIFT not 16");
    }
    if B_AX_EF_DATA_MASK != 0x0000_FFFF {
        return TestResult::Fail("B_AX_EF_DATA_MASK wrong");
    }
    if B_AX_EF_RDY != 1u32 << 29 {
        return TestResult::Fail("B_AX_EF_RDY not BIT(29)");
    }
    if B_AX_EF_MODE_SEL_MASK != 0xC000_0000 {
        return TestResult::Fail("B_AX_EF_MODE_SEL_MASK wrong");
    }
    // Address and data masks must not overlap; otherwise a write would
    // clobber the data byte.
    if B_AX_EF_ADDR_MASK & B_AX_EF_DATA_MASK != 0 {
        return TestResult::Fail("EFUSE addr/data masks overlap");
    }
    // Mode-select and address masks must not overlap either.
    if B_AX_EF_ADDR_MASK & B_AX_EF_MODE_SEL_MASK != 0 {
        return TestResult::Fail("EFUSE addr/mode-sel masks overlap");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_efuse_field_layout);

fn smoke_rtw89_platform_enable_bits() -> TestResult {
    // The four enable bits in R_AX_PLATFORM_ENABLE all live in the
    // low nibble (bits 0..3). Catch drift.
    if B_AX_PLATFORM_EN != 1 << 0 {
        return TestResult::Fail("B_AX_PLATFORM_EN not BIT(0)");
    }
    if B_AX_WCPU_EN != 1 << 1 {
        return TestResult::Fail("B_AX_WCPU_EN not BIT(1)");
    }
    if B_AX_APB_WRAP_EN != 1 << 2 {
        return TestResult::Fail("B_AX_APB_WRAP_EN not BIT(2)");
    }
    if B_AX_AXIDMA_EN != 1 << 3 {
        return TestResult::Fail("B_AX_AXIDMA_EN not BIT(3)");
    }
    let mask = B_AX_PLATFORM_EN | B_AX_WCPU_EN | B_AX_APB_WRAP_EN | B_AX_AXIDMA_EN;
    if mask != 0x0F {
        return TestResult::Fail("platform-enable bits spilled out of the low nibble");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_platform_enable_bits);

// ── MAC validity ───────────────────────────────────────────────────

fn smoke_rtw89_mac_is_valid_classifier() -> TestResult {
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
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_mac_is_valid_classifier);

// ── Firmware-blob name table ───────────────────────────────────────

fn smoke_rtw89_fw_blob_names() -> TestResult {
    // The blob names mirror Linux's `request_firmware` keys. Catch
    // accidental rename drift.
    if expected_blob_name(ChipId::Rtl8852A) != Some("rtw89/8852a_fw.bin") {
        return TestResult::Fail("8852A blob name drift");
    }
    if expected_blob_name(ChipId::Rtl8852B) != Some("rtw89/8852b_fw.bin") {
        return TestResult::Fail("8852B blob name drift");
    }
    if expected_blob_name(ChipId::Rtl8852C) != Some("rtw89/8852c_fw.bin") {
        return TestResult::Fail("8852C blob name drift");
    }
    if expected_blob_name(ChipId::Rtl8851B) != Some("rtw89/8851b_fw.bin") {
        return TestResult::Fail("8851B blob name drift");
    }
    if expected_blob_name(ChipId::Rtl8922A) != Some("rtw89/8922a_fw.bin") {
        return TestResult::Fail("8922A blob name drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_fw_blob_names);

// ── Error-type debug-presence sanity ───────────────────────────────

fn smoke_rtw89_error_types_debug() -> TestResult {
    use core::fmt::Write;
    let mut buf = alloc::string::String::new();
    let _ = write!(buf, "{:?}", MacError::Timeout);
    let _ = write!(buf, "{:?}", MacError::DeviceGone);
    let _ = write!(buf, "{:?}", EfuseError::Timeout);
    let _ = write!(buf, "{:?}", EfuseError::MacUninitialized);
    let _ = write!(buf, "{:?}", FwError::BlobMissing);
    let _ = write!(buf, "{:?}", FwError::BadFormat);
    let _ = write!(buf, "{:?}", FwError::DmaTimeout);
    let _ = write!(buf, "{:?}", FwError::WcpuTimeout);
    let _ = write!(buf, "{:?}", PhyError::UnknownChip);
    let _ = write!(buf, "{:?}", PhyError::SettleTimeout);
    if buf.is_empty() {
        return TestResult::Fail("error type Debug formatter produced nothing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_error_types_debug);

// ── Live-silicon smoke (Skip on QEMU) ──────────────────────────────
//
// QEMU doesn't emulate any RTW89 part, so this smoke is here so a
// future real-HW test run lights up without changing the test list.
// It Skips cleanly when the probe path hasn't bound a device.

fn smoke_rtw89_probe_bound_or_skip() -> TestResult {
    if !super::pci::is_probed() {
        return TestResult::Skip("rtw89: no Wi-Fi-6 Realtek part bound (expected on QEMU)");
    }
    let mac = match super::pci::with_controller(|d| d.mac) {
        Some(m) => m,
        None => return TestResult::Skip("rtw89: probed flag set but no controller borrowable"),
    };
    if !mac_is_valid(mac) {
        return TestResult::Fail("rtw89: bound device reports invalid EFUSE MAC");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_probe_bound_or_skip);
