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
use super::txrx::{
    decode_rxd, encode_rxd_for_test, encode_sta_rec_update, encode_txd, RxdInfo, STA_REC_CMD_SIZE,
    TXD_SIZE, TxdInfo, MCU_EXT_CMD_STA_REC_UPDATE,
    TXD0_PKT_FMT_802_3, TXD1_LONG_FORMAT, TXD5_TX_STATUS_HOST,
    RXD_BASE_SIZE, RXD0_PKT_TYPE_NORMAL,
};

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

// ── Stage-3: TXD / RXD encode + MCU init command ──────────────────

fn smoke_mt7921_txd_encode() -> TestResult {
    // Build a TXD for a 1514-byte 802.3 frame on AC_BE ring (q_idx=2),
    // wlan_idx=1, own_mac_idx=0. Mirrors the fields
    // `mt76_connac2_mac_write_txwi` fills at ~L1..L90, v6.6.
    let info = TxdInfo {
        q_idx: MT7921_TXQ_AC_BE,
        wlan_idx: 1,
        own_mac_idx: 0,
        tx_bytes: 1514 + TXD_SIZE as u16,
        is_mcast: false,
        pid: 7,
    };
    let mut buf = [0u8; TXD_SIZE];
    if encode_txd(&info, &mut buf).is_none() {
        return TestResult::Fail("encode_txd returned None");
    }
    let dw0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    // PKT_FMT 802.3 must be set.
    if dw0 & TXD0_PKT_FMT_802_3 == 0 {
        return TestResult::Fail("TXD dw0: PKT_FMT_802_3 not set");
    }
    // Queue index must land in bits 31-25.
    let q_check = (dw0 >> 25) & 0x7F;
    if q_check != MT7921_TXQ_AC_BE as u32 {
        return TestResult::Fail("TXD dw0: q_idx not encoded correctly");
    }
    let dw1 = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    // Long-format flag must be set for 8-dword TXD.
    if dw1 & TXD1_LONG_FORMAT == 0 {
        return TestResult::Fail("TXD dw1: LONG_FORMAT not set");
    }
    // WLAN index = 1.
    if dw1 & 0x3FF != 1 {
        return TestResult::Fail("TXD dw1: wlan_idx wrong");
    }
    let dw5 = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
    // TX_STATUS_HOST must be set.
    if dw5 & TXD5_TX_STATUS_HOST == 0 {
        return TestResult::Fail("TXD dw5: TX_STATUS_HOST not set");
    }
    // PID = 7.
    if dw5 & 0xFF != 7 {
        return TestResult::Fail("TXD dw5: PID wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_txd_encode);

fn smoke_mt7921_rxd_decode_roundtrip() -> TestResult {
    // Build a 1-frame normal-data RXD and decode it back.
    let original = RxdInfo {
        frame_len: 1024,
        pkt_type: RXD0_PKT_TYPE_NORMAL as u8,
        wlan_idx: 3,
        fcs_err: false,
        icv_err: false,
    };
    let bytes = encode_rxd_for_test(&original);
    if bytes.len() != RXD_BASE_SIZE {
        return TestResult::Fail("encode_rxd_for_test size wrong");
    }
    let decoded = match decode_rxd(&bytes) {
        Some(v) => v,
        None => return TestResult::Fail("decode_rxd returned None"),
    };
    if decoded != original {
        return TestResult::Fail("RXD decode round-trip mismatch");
    }
    // FCS error round-trip.
    let bad = RxdInfo {
        frame_len: 64,
        pkt_type: 0,
        wlan_idx: 0,
        fcs_err: true,
        icv_err: false,
    };
    let bad_bytes = encode_rxd_for_test(&bad);
    let dec_bad = decode_rxd(&bad_bytes).unwrap();
    if !dec_bad.fcs_err {
        return TestResult::Fail("fcs_err not preserved through round-trip");
    }
    if dec_bad.icv_err {
        return TestResult::Fail("icv_err incorrectly set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_rxd_decode_roundtrip);

fn smoke_mt7921_sta_rec_update_encode() -> TestResult {
    // The minimal STA_REC_UPDATE command must have opcode=0x25 at byte 0
    // and the wlan_idx at bytes 4-7 LE.
    // Reference: Linux `mt76_connac_mcu.h:1226` + `mt76_connac_mcu.c`.
    let mut buf = [0xFFu8; STA_REC_CMD_SIZE];
    if encode_sta_rec_update(42, &mut buf).is_none() {
        return TestResult::Fail("encode_sta_rec_update returned None");
    }
    if buf[0] != MCU_EXT_CMD_STA_REC_UPDATE {
        return TestResult::Fail("STA_REC opcode wrong (expected 0x25)");
    }
    let wlan_idx = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if wlan_idx != 42 {
        return TestResult::Fail("STA_REC wlan_idx not encoded correctly");
    }
    // Tag bitmap must be 0 (minimal record, no crypto).
    let tag_bitmap = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if tag_bitmap != 0 {
        return TestResult::Fail("STA_REC tag_bitmap should be 0 for minimal command");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_sta_rec_update_encode);

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

// ── Stage-4: DMA ring scaffolding ──────────────────────────────────

fn smoke_mt7921_ring_regs_per_block() -> TestResult {
    use super::dma::{mt7921_tx_ring_regs, mt7921_rx_ring_regs, RingRegs};
    // TX ring 0 must land at MT_TX_RING_BASE + 0.
    let tx0 = match mt7921_tx_ring_regs(0) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("tx ring 0 lookup failed"),
    };
    if tx0.base_lo != MT_TX_RING_BASE {
        return TestResult::Fail("TX ring 0 base_lo not at MT_TX_RING_BASE");
    }
    if tx0.depth != MT_TX_RING_BASE + 0x04 {
        return TestResult::Fail("TX ring 0 depth offset wrong");
    }
    if tx0.cidx != MT_TX_RING_BASE + 0x08 {
        return TestResult::Fail("TX ring 0 cidx offset wrong");
    }
    if tx0.didx != MT_TX_RING_BASE + 0x0c {
        return TestResult::Fail("TX ring 0 didx offset wrong");
    }
    // TX ring 4 (BMC) must be at base + 4 * 16.
    let tx4 = mt7921_tx_ring_regs(4).unwrap();
    if tx4.base_lo != MT_TX_RING_BASE + 4 * RING_REG_STRIDE {
        return TestResult::Fail("TX ring 4 (BMC) stride wrong");
    }
    // FWDL (queue 16) and MCU (queue 17) land contiguously after BMC.
    let fwdl = mt7921_tx_ring_regs(16).unwrap();
    if fwdl.base_lo != MT_TX_RING_BASE + 5 * RING_REG_STRIDE {
        return TestResult::Fail("FWDL ring stride wrong");
    }
    let mcu = mt7921_tx_ring_regs(17).unwrap();
    if mcu.base_lo != MT_TX_RING_BASE + 6 * RING_REG_STRIDE {
        return TestResult::Fail("MCU_WM ring stride wrong");
    }
    // RX rings — data at MT_RX_DATA_RING_BASE, MCU pre-FW at
    // MT_RX_EVENT_RING_BASE, MCU post-FW at MT_RX_MCU_WA_RING_BASE.
    let rx0 = mt7921_rx_ring_regs(0).unwrap();
    if rx0.base_lo != MT_RX_DATA_RING_BASE {
        return TestResult::Fail("RX data ring not at MT_RX_DATA_RING_BASE");
    }
    let rx1 = mt7921_rx_ring_regs(1).unwrap();
    if rx1.base_lo != MT_RX_EVENT_RING_BASE {
        return TestResult::Fail("RX MCU event ring not at MT_RX_EVENT_RING_BASE");
    }
    let rx2 = mt7921_rx_ring_regs(2).unwrap();
    if rx2.base_lo != MT_RX_MCU_WA_RING_BASE {
        return TestResult::Fail("RX MCU WA ring not at MT_RX_MCU_WA_RING_BASE");
    }
    // Bad queue id must error.
    if mt7921_tx_ring_regs(127).is_ok() {
        return TestResult::Fail("invalid TX queue id was accepted");
    }
    if mt7921_rx_ring_regs(99).is_ok() {
        return TestResult::Fail("invalid RX queue id was accepted");
    }
    // Stride helper itself.
    let custom = RingRegs::for_block(0x1000, 3);
    if custom.base_lo != 0x1000 + 3 * 16 {
        return TestResult::Fail("RingRegs::for_block stride math wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_ring_regs_per_block
);

fn smoke_mt7921_desc_size_and_dma_ctl() -> TestResult {
    use super::dma::{
        Mt76Desc, MT76_DESC_SIZE, MT_DMA_CTL_DMA_DONE, MT_DMA_CTL_LAST_SEC0,
        MT_DMA_CTL_SD_LEN0_MASK, MT_DMA_CTL_SD_LEN0_SHIFT,
    };
    // The Linux struct mt76_desc must be exactly 16 bytes.
    if MT76_DESC_SIZE != 16 {
        return TestResult::Fail("Mt76Desc not 16 bytes");
    }
    if core::mem::size_of::<Mt76Desc>() != 16 {
        return TestResult::Fail("Mt76Desc size_of wrong");
    }
    // DMA_DONE is BIT(31).
    if MT_DMA_CTL_DMA_DONE != 1 << 31 {
        return TestResult::Fail("MT_DMA_CTL_DMA_DONE not BIT(31)");
    }
    // LAST_SEC0 is BIT(30).
    if MT_DMA_CTL_LAST_SEC0 != 1 << 30 {
        return TestResult::Fail("MT_DMA_CTL_LAST_SEC0 not BIT(30)");
    }
    // SD_LEN0 occupies bits 29..16 — that's 14 bits.
    if MT_DMA_CTL_SD_LEN0_SHIFT != 16 {
        return TestResult::Fail("MT_DMA_CTL_SD_LEN0_SHIFT not 16");
    }
    if MT_DMA_CTL_SD_LEN0_MASK != 0x3FFF << 16 {
        return TestResult::Fail("MT_DMA_CTL_SD_LEN0_MASK wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_desc_size_and_dma_ctl
);

fn smoke_mt7921_tx_ring_alloc() -> TestResult {
    use super::dma::{alloc_tx_ring, MT76_DESC_SIZE};
    // Allocate a TX ring of the baseline depth. Buffer pool stays
    // empty (TX path allocs at submit time).
    let depth = MT7921_BASELINE_RING_DEPTH;
    let ring = match alloc_tx_ring(0, depth) {
        Ok(r) => r,
        Err(e) => {
            // If the allocator is unavailable (early-boot) skip.
            let _ = e;
            return TestResult::Skip("alloc_coherent unavailable");
        }
    };
    if ring.depth() != depth {
        return TestResult::Fail("ring depth mismatch");
    }
    if ring.q_idx() != 0 {
        return TestResult::Fail("ring q_idx mismatch");
    }
    if ring.cpu_idx() != 0 {
        return TestResult::Fail("TX ring cpu_idx not 0 at alloc");
    }
    // Descriptor block has exactly `depth` entries of MT76_DESC_SIZE.
    if ring.descriptors().len() * MT76_DESC_SIZE != depth * MT76_DESC_SIZE {
        return TestResult::Fail("descriptor slice length wrong");
    }
    // Depth out-of-range must error.
    if alloc_tx_ring(0, 9999).is_ok() {
        return TestResult::Fail("oversized depth was accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_tx_ring_alloc);

fn smoke_mt7921_rx_ring_alloc_primed() -> TestResult {
    use super::dma::{alloc_rx_ring, Mt76Desc, MT_DMA_CTL_SD_LEN0_MASK, RX_BUF_LEN};
    let depth = MT7921_BASELINE_RING_DEPTH;
    let ring = match alloc_rx_ring(0, depth, RX_BUF_LEN) {
        Ok(r) => r,
        Err(_) => return TestResult::Skip("alloc_coherent unavailable"),
    };
    if ring.buffers().len() != depth {
        return TestResult::Fail("RX buffer pool not pre-filled");
    }
    // CPU pointer sits at depth-1 — all entries primed for HW pickup.
    if ring.cpu_idx() != depth - 1 {
        return TestResult::Fail("RX cpu_idx not at depth-1 after prime");
    }
    // Every descriptor must have a non-zero buf0 (the buffer's phys
    // addr) and ctrl.SD_LEN0 set.
    for (i, d) in ring.descriptors().iter().enumerate() {
        let dummy: &Mt76Desc = d;
        if dummy.buf0 == 0 {
            return TestResult::Fail("RX descriptor buf0 not primed");
        }
        let sd_len0 = (dummy.ctrl & MT_DMA_CTL_SD_LEN0_MASK) >> 16;
        if sd_len0 == 0 {
            return TestResult::Fail("RX descriptor SD_LEN0 not set");
        }
        let _ = i;
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_rx_ring_alloc_primed
);

fn smoke_mt7921_l1_remap_helper() -> TestResult {
    use super::dma::l1_remapped_offset;
    // After programming MT_HIF_REMAP_L1 to cover upper-bits `0x7c06`,
    // accessing absolute address 0x7c060010 lands at BAR0 offset
    // MT_HIF_REMAP_BASE_L1 + (addr & MT_HIF_REMAP_L1_MASK)
    //                     = 0x40000 + 0x0010 = 0x40010.
    let off = l1_remapped_offset(MT_CONN_ON_LPCTL);
    if off & MT_HIF_REMAP_L1_BASE != MT_HIF_REMAP_BASE_L1 {
        return TestResult::Fail("L1 remap base bits wrong");
    }
    if off & MT_HIF_REMAP_L1_MASK != (MT_CONN_ON_LPCTL & MT_HIF_REMAP_L1_MASK) {
        return TestResult::Fail("L1 remap offset bits wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_l1_remap_helper);

fn smoke_mt7921_ring_set_allocates() -> TestResult {
    use super::dma::allocate_ring_set;
    let set = match allocate_ring_set() {
        Ok(s) => s,
        Err(_) => return TestResult::Skip("ring set alloc unavailable"),
    };
    if set.tx_data.len() != MT7921_TX_RING_COUNT {
        return TestResult::Fail("ring set TX count wrong");
    }
    if set.tx_fwdl.q_idx() != 16 {
        return TestResult::Fail("FWDL q_idx wrong");
    }
    if set.tx_mcu.q_idx() != 17 {
        return TestResult::Fail("MCU q_idx wrong");
    }
    if set.rx_data.q_idx() != 0 {
        return TestResult::Fail("RX data q_idx wrong");
    }
    if set.rx_mcu_evt.q_idx() != 1 {
        return TestResult::Fail("RX MCU event q_idx wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_ring_set_allocates
);

fn smoke_mt7921_linux_ring_sizes_visible() -> TestResult {
    // Pin the Linux ring sizes against drift in mt7921.h.
    if LINUX_MT7921_TX_RING_SIZE != 2048 {
        return TestResult::Fail("LINUX_MT7921_TX_RING_SIZE drifted");
    }
    if LINUX_MT7921_TX_MCU_RING_SIZE != 256 {
        return TestResult::Fail("LINUX_MT7921_TX_MCU_RING_SIZE drifted");
    }
    if LINUX_MT7921_TX_FWDL_RING_SIZE != 128 {
        return TestResult::Fail("LINUX_MT7921_TX_FWDL_RING_SIZE drifted");
    }
    if LINUX_MT7921_RX_RING_SIZE != 1536 {
        return TestResult::Fail("LINUX_MT7921_RX_RING_SIZE drifted");
    }
    if LINUX_MT7921_RX_MCU_RING_SIZE != 8 {
        return TestResult::Fail("LINUX_MT7921_RX_MCU_RING_SIZE drifted");
    }
    if LINUX_MT7921_RX_MCU_WA_RING_SIZE != 512 {
        return TestResult::Fail("LINUX_MT7921_RX_MCU_WA_RING_SIZE drifted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_linux_ring_sizes_visible
);

fn smoke_mt7921_extended_mcu_opcodes() -> TestResult {
    // Pin the Linux MCU_EXT_CMD_* opcodes against drift in
    // mt76_connac_mcu.h. Stage-5..7 depend on these.
    if MCU_EXT_CMD_PM_STATE_CTRL != 0x07 {
        return TestResult::Fail("MCU_EXT_CMD_PM_STATE_CTRL not 0x07");
    }
    if MCU_EXT_CMD_CHANNEL_SWITCH != 0x08 {
        return TestResult::Fail("MCU_EXT_CMD_CHANNEL_SWITCH not 0x08");
    }
    if MCU_EXT_CMD_BSS_INFO_UPDATE != 0x26 {
        return TestResult::Fail("MCU_EXT_CMD_BSS_INFO_UPDATE not 0x26");
    }
    if MCU_EXT_CMD_DEV_INFO_UPDATE != 0x2A {
        return TestResult::Fail("MCU_EXT_CMD_DEV_INFO_UPDATE not 0x2A");
    }
    if MCU_UNI_CMD_DEV_INFO_UPDATE != 0x01 {
        return TestResult::Fail("MCU_UNI_CMD_DEV_INFO_UPDATE not 0x01");
    }
    if MCU_CMD_TARGET_ADDRESS_LEN_REQ != 0x01 {
        return TestResult::Fail("MCU_CMD_TARGET_ADDRESS_LEN_REQ not 0x01");
    }
    if MCU_CMD_FW_START_REQ != 0x02 {
        return TestResult::Fail("MCU_CMD_FW_START_REQ not 0x02");
    }
    if MCU_CMD_PATCH_START_REQ != 0x05 {
        return TestResult::Fail("MCU_CMD_PATCH_START_REQ not 0x05");
    }
    if MCU_CMD_FW_SCATTER != 0xEE {
        return TestResult::Fail("MCU_CMD_FW_SCATTER not 0xEE");
    }
    if MCU_EXT_CMD_INIT_RA_CFG != 0x90 {
        return TestResult::Fail("MCU_EXT_CMD_INIT_RA_CFG not 0x90");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_extended_mcu_opcodes
);

fn smoke_mt7921_infra_window_constants() -> TestResult {
    // Catch drift on the INFRA L1 remap window constants — these are
    // cross-referenced from `mt7921/regs.h:63..70`.
    if MT_INFRA_CFG_BASE != 0xfe000 {
        return TestResult::Fail("MT_INFRA_CFG_BASE drifted");
    }
    if MT_HIF_REMAP_L1 != 0xfe000 + 0x24c {
        return TestResult::Fail("MT_HIF_REMAP_L1 drifted");
    }
    if MT_HIF_REMAP_BASE_L1 != 0x40000 {
        return TestResult::Fail("MT_HIF_REMAP_BASE_L1 drifted");
    }
    if MT_HIF_REMAP_L1_MASK != 0x0000_FFFF {
        return TestResult::Fail("MT_HIF_REMAP_L1_MASK drifted");
    }
    if MT_HIF_REMAP_L1_BASE != 0xFFFF_0000 {
        return TestResult::Fail("MT_HIF_REMAP_L1_BASE drifted");
    }
    if MT_WFSYS_SW_RST_B != 0x18000140 {
        return TestResult::Fail("MT_WFSYS_SW_RST_B drifted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_infra_window_constants
);

fn smoke_mt7921_wfdma0_extended_bits() -> TestResult {
    // Catch drift on the GLO_CFG flag bits we add in Stage-4.
    if MT_WFDMA0_GLO_CFG_TX_DMA_BUSY != 1 << 1 {
        return TestResult::Fail("TX_DMA_BUSY not BIT(1)");
    }
    if MT_WFDMA0_GLO_CFG_RX_DMA_BUSY != 1 << 3 {
        return TestResult::Fail("RX_DMA_BUSY not BIT(3)");
    }
    if MT_WFDMA0_GLO_CFG_FIFO_LITTLE_ENDIAN != 1 << 12 {
        return TestResult::Fail("FIFO_LE not BIT(12)");
    }
    if MT_WFDMA0_GLO_CFG_RX_WB_DDONE != 1 << 13 {
        return TestResult::Fail("RX_WB_DDONE not BIT(13)");
    }
    if MT_WFDMA0_GLO_CFG_OMIT_RX_INFO != 1 << 27 {
        return TestResult::Fail("OMIT_RX_INFO not BIT(27)");
    }
    if MT_WFDMA0_GLO_CFG_OMIT_TX_INFO != 1 << 28 {
        return TestResult::Fail("OMIT_TX_INFO not BIT(28)");
    }
    if MT_WFDMA0_GLO_CFG_CLK_GAT_DIS != 1 << 30 {
        return TestResult::Fail("CLK_GAT_DIS not BIT(30)");
    }
    // Per-ring stride is 16 bytes.
    if RING_REG_STRIDE != 0x10 {
        return TestResult::Fail("RING_REG_STRIDE drifted");
    }
    // The TX/RX ring base addresses must match Linux's
    // `MT_TX_RING_BASE` (MT_WFDMA0(0x300)) and `MT_RX_*_RING_BASE`.
    if MT_TX_RING_BASE != MT_WFDMA0_BASE + 0x300 {
        return TestResult::Fail("MT_TX_RING_BASE drifted");
    }
    if MT_RX_DATA_RING_BASE != MT_WFDMA0_BASE + 0x520 {
        return TestResult::Fail("MT_RX_DATA_RING_BASE drifted");
    }
    if MT_RX_EVENT_RING_BASE != MT_WFDMA0_BASE + 0x500 {
        return TestResult::Fail("MT_RX_EVENT_RING_BASE drifted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_wfdma0_extended_bits
);
