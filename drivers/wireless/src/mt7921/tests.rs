//! MT7921 smoke tests — co-located per project convention.
//!
//! All smokes are pure-data: PCI match table presence, register
//! constant sanity, L1 remap arithmetic, firmware-blob resolution.
//! None of them touch live silicon, so they Pass on QEMU.
//!
//! A "real-silicon" smoke (probe-bound device + live chip-id read)
//! is included so a future bare-metal test run lights up without
//! changing the test list; it Skips cleanly on QEMU since no MT7921
//! PCIe model is emulated.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::mac::PowerError;
use super::mcu::{mcu_ext_cmd_header, McuError, EFUSE_BLOCK_LEN};
use super::pci::{firmware_blobs_for, l1_remap, name_for, register_pci_driver};
use super::regs::*;

// ── PCI match table ────────────────────────────────────────────────

fn smoke_mt7921_pci_match_table_covers_all_ids() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    register_pci_driver();
    let regs = registered_pci_drivers();
    for &did in ALL_DEV_IDS {
        let matched = regs.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: MTK_VENDOR,
                    device,
                } if device == did
            )
        });
        if !matched {
            return TestResult::Fail("mt7921 match table missing a MediaTek device id");
        }
    }
    // ITTIM SKU.
    let ittim_present = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::VendorDevice {
                vendor: ITTIM_VENDOR,
                device: MTK_DEV_MT7922,
            },
        )
    });
    if !ittim_present {
        return TestResult::Fail("mt7921 match table missing the ITTIM 0e8d:7922 SKU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_pci_match_table_covers_all_ids
);

fn smoke_mt7921_name_for_known_ids() -> TestResult {
    if name_for(MTK_DEV_MT7961) != "mt7921-7961" {
        return TestResult::Fail("MT7961 name mismatch");
    }
    if name_for(MTK_DEV_MT7922) != "mt7921-7922" {
        return TestResult::Fail("MT7922 name mismatch");
    }
    if name_for(MTK_DEV_MT7921) != "mt7921-0608" {
        return TestResult::Fail("MT7921 (0608) name mismatch");
    }
    if name_for(MTK_DEV_MT7921_ALT) != "mt7921-0616" {
        return TestResult::Fail("MT7921 (0616) name mismatch");
    }
    if name_for(MTK_DEV_MT7920) != "mt7921-7920" {
        return TestResult::Fail("MT7920 name mismatch");
    }
    if name_for(0xFFFF) != "mt7921" {
        return TestResult::Fail("default name mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_name_for_known_ids);

// ── Register constants ─────────────────────────────────────────────

fn smoke_mt7921_pcie_lpcr_bits() -> TestResult {
    // PCIE_LPCR_HOST_SET_OWN = BIT(0); _CLR_OWN = BIT(1); _OWN_SYNC = BIT(2).
    // Catch typos that swap the OWN bits and would silently flip the
    // handshake direction.
    if PCIE_LPCR_HOST_SET_OWN != 1 << 0 {
        return TestResult::Fail("PCIE_LPCR_HOST_SET_OWN not BIT(0)");
    }
    if PCIE_LPCR_HOST_CLR_OWN != 1 << 1 {
        return TestResult::Fail("PCIE_LPCR_HOST_CLR_OWN not BIT(1)");
    }
    if PCIE_LPCR_HOST_OWN_SYNC != 1 << 2 {
        return TestResult::Fail("PCIE_LPCR_HOST_OWN_SYNC not BIT(2)");
    }
    if MT_CONN_ON_LPCTL != 0x7c06_0010 {
        return TestResult::Fail("MT_CONN_ON_LPCTL absolute address drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_pcie_lpcr_bits);

fn smoke_mt7921_hw_id_addresses() -> TestResult {
    if MT_HW_CHIPID != 0x7001_0200 {
        return TestResult::Fail("MT_HW_CHIPID drifted");
    }
    if MT_HW_REV != 0x7001_0204 {
        return TestResult::Fail("MT_HW_REV drifted");
    }
    if MT_HW_BOUND != 0x7001_0020 {
        return TestResult::Fail("MT_HW_BOUND drifted");
    }
    if MT_HW_BOUND_DBDC != 1 << 7 {
        return TestResult::Fail("MT_HW_BOUND_DBDC not BIT(7)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_hw_id_addresses);

fn smoke_mt7921_pcie_mac_block() -> TestResult {
    if MT_PCIE_MAC_BASE != 0x10000 {
        return TestResult::Fail("MT_PCIE_MAC_BASE drifted");
    }
    if MT_PCIE_MAC_INT_ENABLE != 0x10188 {
        return TestResult::Fail("MT_PCIE_MAC_INT_ENABLE drifted");
    }
    if MT_PCIE_MAC_PM != 0x10194 {
        return TestResult::Fail("MT_PCIE_MAC_PM drifted");
    }
    if MT_PCIE_MAC_PM_L0S_DIS != 1 << 8 {
        return TestResult::Fail("MT_PCIE_MAC_PM_L0S_DIS not BIT(8)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_pcie_mac_block);

fn smoke_mt7921_wfdma0_block() -> TestResult {
    if MT_WFDMA0_BASE != 0xd4000 {
        return TestResult::Fail("MT_WFDMA0_BASE drifted");
    }
    if MT_WFDMA0_RST != 0xd4100 {
        return TestResult::Fail("MT_WFDMA0_RST drifted");
    }
    if MT_WFDMA0_GLO_CFG != 0xd4208 {
        return TestResult::Fail("MT_WFDMA0_GLO_CFG drifted");
    }
    if MT_MCU_CMD != 0xd41f0 {
        return TestResult::Fail("MT_MCU_CMD drifted");
    }
    if MT_WFDMA0_GLO_CFG_TX_DMA_EN != 1 << 0 {
        return TestResult::Fail("GLO_CFG_TX_DMA_EN not BIT(0)");
    }
    if MT_WFDMA0_GLO_CFG_RX_DMA_EN != 1 << 2 {
        return TestResult::Fail("GLO_CFG_RX_DMA_EN not BIT(2)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_wfdma0_block);

// ── L1 remap arithmetic ────────────────────────────────────────────

fn smoke_mt7921_l1_remap_direct_window() -> TestResult {
    // Addresses below 0x100_0000 land directly in BAR0.
    if l1_remap(0) != 0 {
        return TestResult::Fail("zero address didn't remap to zero");
    }
    if l1_remap(0x10188) != 0x10188 {
        return TestResult::Fail("PCIe-MAC INT_ENABLE didn't direct-map");
    }
    if l1_remap(MT_PCIE_MAC_INT_ENABLE) != MT_PCIE_MAC_INT_ENABLE {
        return TestResult::Fail("MT_PCIE_MAC_INT_ENABLE didn't direct-map");
    }
    if l1_remap(0x00ff_ffff) != 0x00ff_ffff {
        return TestResult::Fail("upper edge of direct window didn't direct-map");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_l1_remap_direct_window
);

fn smoke_mt7921_l1_remap_high_window() -> TestResult {
    // Addresses >= 0x100_0000 fold into the upper 8 MiB of BAR0.
    let remapped = l1_remap(MT_HW_CHIPID);
    if remapped & 0x0080_0000 == 0 {
        return TestResult::Fail("high address didn't land in upper half of BAR0");
    }
    // Low 23 bits preserved.
    if (remapped & 0x007f_ffff) != (MT_HW_CHIPID & 0x007f_ffff) {
        return TestResult::Fail("low 23 bits of remapped address dropped");
    }
    // Same for MT_CONN_ON_LPCTL.
    let lpctl_remap = l1_remap(MT_CONN_ON_LPCTL);
    if lpctl_remap & 0x0080_0000 == 0 {
        return TestResult::Fail("LPCTL didn't land in upper half of BAR0");
    }
    if (lpctl_remap & 0x007f_ffff) != (MT_CONN_ON_LPCTL & 0x007f_ffff) {
        return TestResult::Fail("LPCTL low 23 bits dropped");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_l1_remap_high_window);

// ── Firmware blob resolution ───────────────────────────────────────

fn smoke_mt7921_firmware_blobs_for_each_chip() -> TestResult {
    // MT7922 ships its own patch + RAM code.
    let (p, r) = firmware_blobs_for(MTK_DEV_MT7922);
    if p != MT7922_ROM_PATCH || r != MT7922_FIRMWARE_WM {
        return TestResult::Fail("MT7922 firmware blob names drift");
    }
    // MT7920 (DBDC) uses 7961 RAM code with a chip-specific patch.
    let (p, r) = firmware_blobs_for(MTK_DEV_MT7920);
    if p != MT7920_ROM_PATCH || r != MT7961_FIRMWARE_WM {
        return TestResult::Fail("MT7920 firmware blob names drift");
    }
    // Default (MT7961, MT7921 either SKU) falls through to 7961 blobs.
    for &did in [MTK_DEV_MT7961, MTK_DEV_MT7921, MTK_DEV_MT7921_ALT].iter() {
        let (p, r) = firmware_blobs_for(did);
        if p != MT7961_ROM_PATCH || r != MT7961_FIRMWARE_WM {
            return TestResult::Fail("MT7961-family firmware blob names drift");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_firmware_blobs_for_each_chip
);

// ── TX / RX ring queue ids ─────────────────────────────────────────

fn smoke_mt7921_txrx_ring_layout() -> TestResult {
    // Four data TX rings (AC ordering) + BMC, two RX rings.
    if MT7921_TXQ_AC_VO != 0
        || MT7921_TXQ_AC_VI != 1
        || MT7921_TXQ_AC_BE != 2
        || MT7921_TXQ_AC_BK != 3
        || MT7921_TXQ_BMC != 4
    {
        return TestResult::Fail("TX ring AC ordering wrong");
    }
    if MT7921_TX_RING_COUNT != 5 {
        return TestResult::Fail("TX_RING_COUNT not 5 (4 AC + BMC)");
    }
    if MT7921_RXQ_DATA != 0 || MT7921_RXQ_MCU_EVENT != 1 {
        return TestResult::Fail("RX ring id ordering wrong");
    }
    if MT7921_RX_RING_COUNT != 2 {
        return TestResult::Fail("RX_RING_COUNT not 2");
    }
    // Sanity on the ring depth — must be a power of two for ptr-mask
    // bookkeeping in Stage-2.
    if !MT7921_RING_DEPTH.is_power_of_two() {
        return TestResult::Fail("MT7921_RING_DEPTH must be power of two");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_txrx_ring_layout);

// ── MCU encoder ────────────────────────────────────────────────────

fn smoke_mt7921_mcu_ext_cmd_encoder() -> TestResult {
    // The encoder is a pass-through today but the assertion makes
    // sure the EFUSE access opcode stays at the expected value
    // (Linux's `MCU_EXT_CMD_EFUSE_ACCESS == 0x01`).
    if MCU_EXT_CMD_EFUSE_ACCESS != 0x01 {
        return TestResult::Fail("MCU_EXT_CMD_EFUSE_ACCESS drifted");
    }
    if mcu_ext_cmd_header(MCU_EXT_CMD_EFUSE_ACCESS) != 0x01 {
        return TestResult::Fail("mcu_ext_cmd_header didn't pass-through opcode");
    }
    if EFUSE_BLOCK_LEN != 16 {
        return TestResult::Fail("EFUSE block length drift (Linux: 16 bytes)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_mcu_ext_cmd_encoder
);

// ── Register-offset uniqueness ─────────────────────────────────────

fn smoke_mt7921_register_offsets_distinct() -> TestResult {
    // Cheap sanity that none of the registers we model share an
    // offset by accident. Catches copy-paste typos on the next
    // register-block addition.
    let offsets = [
        MT_HW_CHIPID,
        MT_HW_REV,
        MT_HW_BOUND,
        MT_PCIE_MAC_INT_ENABLE,
        MT_PCIE_MAC_PM,
        MT_CONN_ON_LPCTL,
        MT_TOP_MISC,
        MT_WFDMA0_RST,
        MT_WFDMA0_GLO_CFG,
        MT_MCU_CMD,
    ];
    for i in 0..offsets.len() {
        for j in (i + 1)..offsets.len() {
            if offsets[i] == offsets[j] {
                return TestResult::Fail("two MT7921 registers share an offset");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_register_offsets_distinct
);

// ── Error-type Debug presence ──────────────────────────────────────
//
// Cheap presence check that the typed errors stay stable enough that
// downstream `match` clauses don't bit-rot silently.

fn smoke_mt7921_error_types_debug() -> TestResult {
    use core::fmt::Write;
    let mut buf = alloc::string::String::new();
    let _ = write!(buf, "{:?}", PowerError::Timeout);
    let _ = write!(buf, "{:?}", PowerError::DeviceGone);
    let _ = write!(buf, "{:?}", McuError::BlobMissing);
    let _ = write!(buf, "{:?}", McuError::Timeout);
    let _ = write!(buf, "{:?}", McuError::NotImplemented);
    if buf.is_empty() {
        return TestResult::Fail("error type Debug formatter produced nothing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_error_types_debug);

// ── Live-silicon smoke (Skip on QEMU) ──────────────────────────────
//
// QEMU doesn't emulate the MT7921 PCIe model, so this Skips on every
// emulated boot. Bare-metal test runs against a Phoenix HawkPoint1
// laptop with a real MT7922 fitted should Pass.

fn smoke_mt7921_probe_bound_or_skip() -> TestResult {
    if !super::pci::is_probed() {
        return TestResult::Skip("mt7921: no MT7921/MT7922 bound (expected on QEMU)");
    }
    let chip = match super::pci::with_controller(|d| d.chip_id) {
        Some(c) => c,
        None => return TestResult::Skip("mt7921: probed flag set but no controller borrowable"),
    };
    if chip == 0 || chip == 0xFFFF_FFFF {
        return TestResult::Fail("mt7921: bound device reports sentinel chip-id");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_probe_bound_or_skip
);
