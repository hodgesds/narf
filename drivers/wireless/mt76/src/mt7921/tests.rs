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
    decode_rxd, encode_rxd_for_test, encode_sta_rec_update, encode_txd, RxdInfo, TxdInfo,
    MCU_EXT_CMD_STA_REC_UPDATE, RXD0_PKT_TYPE_NORMAL, RXD_BASE_SIZE, STA_REC_CMD_SIZE,
    TXD0_PKT_FMT_802_3, TXD1_LONG_FORMAT, TXD5_TX_STATUS_HOST, TXD_SIZE,
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
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_mcu_ext_cmd_encoder);

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
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_sta_rec_update_encode
);

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
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_probe_bound_or_skip);

// ── Stage-4: DMA ring scaffolding ──────────────────────────────────

fn smoke_mt7921_ring_regs_per_block() -> TestResult {
    use super::dma::{mt7921_rx_ring_regs, mt7921_tx_ring_regs, RingRegs};
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
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_ring_regs_per_block);

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
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_rx_ring_alloc_primed);

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
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_ring_set_allocates);

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
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_extended_mcu_opcodes);

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
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_wfdma0_extended_bits);

// ── Stage-5/6/7: firmware download parsers ────────────────────────

fn smoke_mt7921_patch_hdr_parse_too_short() -> TestResult {
    use super::fwdl::{parse_patch_header, FwParseError};
    let blob = [0u8; 4];
    match parse_patch_header(&blob) {
        Err(FwParseError::TooShort) => TestResult::Pass,
        _ => TestResult::Fail("expected TooShort for stub blob"),
    }
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_patch_hdr_parse_too_short
);

fn smoke_mt7921_patch_hdr_parse_round_trip() -> TestResult {
    use super::fwdl::{parse_patch_header, PATCH_HDR_SIZE};
    let mut blob = [0u8; PATCH_HDR_SIZE];
    blob[0..16].copy_from_slice(b"20260528-153000\0");
    blob[16..20].copy_from_slice(b"MT79");
    blob[20..24].copy_from_slice(&0x01020304u32.to_be_bytes());
    blob[24..28].copy_from_slice(&0xAABBCCDDu32.to_be_bytes());
    blob[28..30].copy_from_slice(&0x1234u16.to_be_bytes());
    blob[44..48].copy_from_slice(&3u32.to_be_bytes());

    let hdr = match parse_patch_header(&blob) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("parse_patch_header returned Err"),
    };
    if hdr.hw_sw_ver != 0x01020304 {
        return TestResult::Fail("hw_sw_ver round-trip wrong");
    }
    if hdr.patch_ver != 0xAABBCCDD {
        return TestResult::Fail("patch_ver round-trip wrong");
    }
    if hdr.n_region != 3 {
        return TestResult::Fail("n_region round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_patch_hdr_parse_round_trip
);

fn smoke_mt7921_patch_section_parse() -> TestResult {
    use super::fwdl::{
        iter_patch_sections, parse_patch_header, FwParseError, PATCH_HDR_SIZE, PATCH_SEC_SIZE,
        PATCH_SEC_TYPE_INFO,
    };
    let n_sec = 2usize;
    let total = PATCH_HDR_SIZE + n_sec * PATCH_SEC_SIZE;
    let mut blob = alloc::vec![0u8; total];
    blob[44..48].copy_from_slice(&(n_sec as u32).to_be_bytes());
    let s0_start = PATCH_HDR_SIZE;
    blob[s0_start..s0_start + 4].copy_from_slice(&PATCH_SEC_TYPE_INFO.to_be_bytes());
    blob[s0_start + 4..s0_start + 8].copy_from_slice(&0x80u32.to_be_bytes());
    blob[s0_start + 8..s0_start + 12].copy_from_slice(&64u32.to_be_bytes());
    blob[s0_start + 12..s0_start + 16].copy_from_slice(&0x100000u32.to_be_bytes());
    blob[s0_start + 16..s0_start + 20].copy_from_slice(&64u32.to_be_bytes());
    let s1_start = s0_start + PATCH_SEC_SIZE;
    blob[s1_start..s1_start + 4].copy_from_slice(&PATCH_SEC_TYPE_INFO.to_be_bytes());
    blob[s1_start + 12..s1_start + 16].copy_from_slice(&0x200000u32.to_be_bytes());

    let hdr = parse_patch_header(&blob).unwrap();
    let iter = match iter_patch_sections(&blob, &hdr) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("iter_patch_sections returned Err"),
    };
    let sections: alloc::vec::Vec<_> = iter.collect();
    if sections.len() != 2 {
        return TestResult::Fail("expected 2 sections");
    }
    if let Ok(s0) = sections[0] {
        if s0.addr != 0x100000 {
            return TestResult::Fail("section 0 addr wrong");
        }
    } else {
        return TestResult::Fail("section 0 parse failed");
    }
    // Malformed section type must error.
    let mut bad = blob.clone();
    bad[s0_start..s0_start + 4].copy_from_slice(&0xFFu32.to_be_bytes());
    let it = iter_patch_sections(&bad, &hdr).unwrap();
    let res: alloc::vec::Vec<_> = it.collect();
    match res[0] {
        Err(FwParseError::BadSectionType) => {}
        _ => return TestResult::Fail("bad section type not rejected"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_patch_section_parse);

fn smoke_mt7921_fw_trailer_parse() -> TestResult {
    use super::fwdl::{parse_fw_trailer, FW_TRAILER_SIZE};
    let mut blob = alloc::vec![0u8; 256];
    let trailer_start = blob.len() - FW_TRAILER_SIZE;
    blob[trailer_start] = 0x79;
    blob[trailer_start + 1] = 0x01;
    blob[trailer_start + 2] = 4;
    blob[trailer_start + 32..trailer_start + 36].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
    let t = parse_fw_trailer(&blob).unwrap();
    if t.chip_id != 0x79 {
        return TestResult::Fail("chip_id round-trip wrong");
    }
    if t.n_region != 4 {
        return TestResult::Fail("n_region round-trip wrong");
    }
    if t.crc != 0xDEADBEEF {
        return TestResult::Fail("crc round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_fw_trailer_parse);

fn smoke_mt7921_patch_sem_control_encode() -> TestResult {
    use super::fwdl::{encode_patch_sem_control, PatchSemOp};
    let mut buf = [0xFFu8; 4];
    encode_patch_sem_control(PatchSemOp::Get, &mut buf).unwrap();
    let v = u32::from_le_bytes(buf);
    if v != 1 {
        return TestResult::Fail("PATCH_SEM_GET should encode to 1");
    }
    encode_patch_sem_control(PatchSemOp::Release, &mut buf).unwrap();
    let v = u32::from_le_bytes(buf);
    if v != 0 {
        return TestResult::Fail("PATCH_SEM_RELEASE should encode to 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_patch_sem_control_encode
);

fn smoke_mt7921_fw_scatter_chunking() -> TestResult {
    use super::fwdl::{iter_fw_scatter_chunks, PCIE_FWDL_CHUNK_SIZE};
    let blob = alloc::vec![0u8; 10 * 1024];
    let chunks: alloc::vec::Vec<_> = iter_fw_scatter_chunks(&blob, PCIE_FWDL_CHUNK_SIZE).collect();
    if chunks.is_empty() {
        return TestResult::Fail("chunk iterator empty");
    }
    let total: usize = chunks.iter().map(|c| c.len).sum();
    if total != blob.len() {
        return TestResult::Fail("chunk total != blob len");
    }
    let last = &chunks[chunks.len() - 1];
    if last.offset + last.len != blob.len() {
        return TestResult::Fail("last chunk doesn't close the blob");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_fw_scatter_chunking);

fn smoke_mt7921_target_addr_len_encode() -> TestResult {
    use super::fwdl::encode_target_address_len_req;
    let mut out = [0u8; 12];
    encode_target_address_len_req(0xDEAD_BEEF, 0x0000_2000, 0x1, &mut out).unwrap();
    let addr = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
    let len = u32::from_le_bytes([out[4], out[5], out[6], out[7]]);
    let mode = u32::from_le_bytes([out[8], out[9], out[10], out[11]]);
    if addr != 0xDEAD_BEEF || len != 0x0000_2000 || mode != 0x1 {
        return TestResult::Fail("target_address_len_req round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_target_addr_len_encode
);

// ── Stage-8: MCU init commands ────────────────────────────────────

fn smoke_mt7921_pm_state_ctrl_encode() -> TestResult {
    use super::cmd::{encode_pm_state_ctrl, PM_STATE_ACTIVE, PM_STATE_CTRL_SIZE, PM_STATE_DOZE};
    let mut buf = [0xFFu8; PM_STATE_CTRL_SIZE];
    encode_pm_state_ctrl(PM_STATE_ACTIVE, 0, &mut buf).unwrap();
    if buf[0] != PM_STATE_ACTIVE {
        return TestResult::Fail("PM_STATE_ACTIVE byte wrong");
    }
    encode_pm_state_ctrl(PM_STATE_DOZE, 1, &mut buf).unwrap();
    if buf[0] != PM_STATE_DOZE || buf[1] != 1 {
        return TestResult::Fail("PM_STATE_DOZE round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_pm_state_ctrl_encode);

fn smoke_mt7921_init_ra_cfg_encode() -> TestResult {
    use super::cmd::{encode_init_ra_cfg, INIT_RA_CFG_SIZE};
    let mut buf = [0xFFu8; INIT_RA_CFG_SIZE];
    encode_init_ra_cfg(0, 2, true, false, true, 1, true, 0x12345678, &mut buf).unwrap();
    if buf[0] != 0
        || buf[1] != 2
        || buf[2] != 1
        || buf[3] != 0
        || buf[4] != 1
        || buf[5] != 1
        || buf[6] != 1
    {
        return TestResult::Fail("init_ra_cfg byte fields wrong");
    }
    let mr = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if mr != 0x12345678 {
        return TestResult::Fail("max_rate round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_init_ra_cfg_encode);

fn smoke_mt7921_uni_dev_info_update_encode() -> TestResult {
    use super::cmd::{
        encode_uni_dev_info_update, UNI_DEV_INFO_BODY_SIZE, UNI_DEV_INFO_HDR_SIZE,
        UNI_DEV_INFO_TAG_ACTIVE, UNI_DEV_INFO_TAG_INFO,
    };
    let mac = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
    let mut buf = [0xFFu8; UNI_DEV_INFO_BODY_SIZE];
    encode_uni_dev_info_update(0, 0, true, mac, &mut buf).unwrap();
    let tag = u16::from_le_bytes([buf[UNI_DEV_INFO_HDR_SIZE], buf[UNI_DEV_INFO_HDR_SIZE + 1]]);
    if tag != UNI_DEV_INFO_TAG_ACTIVE {
        return TestResult::Fail("ACTIVE TLV tag wrong");
    }
    if buf[UNI_DEV_INFO_HDR_SIZE + 4] != 1 {
        return TestResult::Fail("active byte wrong");
    }
    let p = UNI_DEV_INFO_HDR_SIZE + 8;
    let info_tag = u16::from_le_bytes([buf[p], buf[p + 1]]);
    if info_tag != UNI_DEV_INFO_TAG_INFO {
        return TestResult::Fail("INFO TLV tag wrong");
    }
    if buf[p + 8..p + 8 + 6] != mac {
        return TestResult::Fail("own_mac round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_uni_dev_info_update_encode
);

// ── Stage-9: MAC vif setup ────────────────────────────────────────

fn smoke_mt7921_bss_info_basic_tlv_encode() -> TestResult {
    use super::cmd::{
        encode_bss_info_basic_tlv, BSS_INFO_BASIC_TLV_SIZE, BSS_INFO_TAG_BASIC, NETWORK_TYPE_INFRA,
        PHY_MODE_HE,
    };
    let bssid = [0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x42];
    let mut buf = [0xFFu8; BSS_INFO_BASIC_TLV_SIZE];
    encode_bss_info_basic_tlv(
        NETWORK_TYPE_INFRA,
        0,
        0,
        bssid,
        100,
        2,
        PHY_MODE_HE,
        1,
        true,
        &mut buf,
    )
    .unwrap();
    let tag = u16::from_le_bytes([buf[0], buf[1]]);
    if tag != BSS_INFO_TAG_BASIC {
        return TestResult::Fail("BSS_INFO_BASIC tag wrong");
    }
    let nt = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if nt != NETWORK_TYPE_INFRA {
        return TestResult::Fail("network_type wrong");
    }
    if buf[12..18] != bssid {
        return TestResult::Fail("bssid round-trip wrong");
    }
    if buf[21] != PHY_MODE_HE {
        return TestResult::Fail("phy_mode wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_bss_info_basic_tlv_encode
);

fn smoke_mt7921_dev_info_update_legacy_encode() -> TestResult {
    use super::cmd::{encode_dev_info_update, DEV_INFO_UPDATE_SIZE};
    let mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let mut buf = [0xFFu8; DEV_INFO_UPDATE_SIZE];
    encode_dev_info_update(0, true, mac, &mut buf).unwrap();
    if buf[8..14] != mac {
        return TestResult::Fail("own_mac round-trip wrong");
    }
    if buf[4] != 1 {
        return TestResult::Fail("active byte wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_dev_info_update_legacy_encode
);

fn smoke_mt7921_sta_rec_basic_tlv_encode() -> TestResult {
    use super::cmd::{
        encode_sta_rec_basic_tlv, CONN_STATE_PORT_SECURE, CONN_TYPE_STA_INFRA, PHY_MODE_HE,
        STA_REC_BASIC_TLV_SIZE,
    };
    let peer = [0xDE, 0xAD, 0xBE, 0xEF, 0x55, 0x55];
    let mut buf = [0xFFu8; STA_REC_BASIC_TLV_SIZE];
    encode_sta_rec_basic_tlv(
        CONN_TYPE_STA_INFRA,
        CONN_STATE_PORT_SECURE,
        1,
        peer,
        PHY_MODE_HE,
        2,
        true,
        &mut buf,
    )
    .unwrap();
    let conn = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if conn != CONN_TYPE_STA_INFRA {
        return TestResult::Fail("conn_type wrong");
    }
    if buf[12..18] != peer {
        return TestResult::Fail("peer_addr round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_sta_rec_basic_tlv_encode
);

// ── Stage-10: channel switch ──────────────────────────────────────

fn smoke_mt7921_channel_switch_default_5g() -> TestResult {
    use super::cmd::{build_default_channel_switch_vec, CHANNEL_SWITCH_SIZE, CH_BAND_5G, CH_BW_20};
    let body = build_default_channel_switch_vec();
    if body.len() != CHANNEL_SWITCH_SIZE {
        return TestResult::Fail("channel switch body size wrong");
    }
    if body[1] != MT7921_DEFAULT_CHAN_5G {
        return TestResult::Fail("control channel not 36");
    }
    if body[2] != MT7921_DEFAULT_CHAN_5G {
        return TestResult::Fail("center channel not 36");
    }
    if body[3] != CH_BW_20 {
        return TestResult::Fail("bw not 20 MHz");
    }
    if body[4] != 2 || body[5] != 2 {
        return TestResult::Fail("tx/rx streams not 2");
    }
    if body[12] != CH_BAND_5G {
        return TestResult::Fail("band not 5 GHz");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_channel_switch_default_5g
);

// ── Stage-11: association MGMT frames ────────────────────────────

fn smoke_mt7921_ieee80211_mgmt_hdr_encode() -> TestResult {
    use super::cmd::{encode_ieee80211_mgmt_hdr, FC_MGMT_AUTH, IEEE80211_MAC_HDR_SIZE};
    let da = [0x11; 6];
    let sa = [0x22; 6];
    let bssid = [0x33; 6];
    let mut buf = [0u8; IEEE80211_MAC_HDR_SIZE];
    encode_ieee80211_mgmt_hdr(FC_MGMT_AUTH, da, sa, bssid, 7, &mut buf).unwrap();
    let fc = u16::from_le_bytes([buf[0], buf[1]]);
    if fc != FC_MGMT_AUTH {
        return TestResult::Fail("frame control round-trip wrong");
    }
    if buf[4..10] != da {
        return TestResult::Fail("addr1 (DA) wrong");
    }
    if buf[10..16] != sa {
        return TestResult::Fail("addr2 (SA) wrong");
    }
    if buf[16..22] != bssid {
        return TestResult::Fail("addr3 (BSSID) wrong");
    }
    let seq_ctrl = u16::from_le_bytes([buf[22], buf[23]]);
    if (seq_ctrl >> 4) & 0x0FFF != 7 {
        return TestResult::Fail("sequence wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_ieee80211_mgmt_hdr_encode
);

fn smoke_mt7921_open_auth_frame_encode() -> TestResult {
    use super::cmd::{encode_open_auth_frame, IEEE80211_AUTH_FRAME_SIZE, IEEE80211_MAC_HDR_SIZE};
    let sta = [0x11; 6];
    let bssid = [0x22; 6];
    let mut buf = [0u8; IEEE80211_AUTH_FRAME_SIZE];
    encode_open_auth_frame(sta, bssid, &mut buf).unwrap();
    let p = IEEE80211_MAC_HDR_SIZE;
    let algo = u16::from_le_bytes([buf[p], buf[p + 1]]);
    let seq = u16::from_le_bytes([buf[p + 2], buf[p + 3]]);
    let status = u16::from_le_bytes([buf[p + 4], buf[p + 5]]);
    if algo != 0 || seq != 1 || status != 0 {
        return TestResult::Fail("auth payload round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_open_auth_frame_encode
);

fn smoke_mt7921_assoc_req_frame_encode() -> TestResult {
    use super::cmd::{encode_assoc_req_frame, IEEE80211_MAC_HDR_SIZE};
    let sta = [0x11; 6];
    let bssid = [0x22; 6];
    let ssid = b"narf-test";
    let mut buf = [0u8; 64];
    let n = encode_assoc_req_frame(sta, bssid, 0x0011, 5, ssid, &mut buf).unwrap();
    if n != IEEE80211_MAC_HDR_SIZE + 2 + 2 + 2 + ssid.len() {
        return TestResult::Fail("assoc_req frame length wrong");
    }
    let p = IEEE80211_MAC_HDR_SIZE;
    let cap = u16::from_le_bytes([buf[p], buf[p + 1]]);
    if cap != 0x0011 {
        return TestResult::Fail("capability round-trip wrong");
    }
    if buf[p + 4] != 0 {
        return TestResult::Fail("SSID IE id should be 0");
    }
    if buf[p + 5] as usize != ssid.len() {
        return TestResult::Fail("SSID IE len wrong");
    }
    if &buf[p + 6..p + 6 + ssid.len()] != ssid {
        return TestResult::Fail("SSID octets round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_assoc_req_frame_encode
);

// ── Stage-12: cipher suites + STA_REC WTBL ───────────────────────

fn smoke_mt7921_cipher_suite_constants() -> TestResult {
    use super::cmd::{StaCipher, AKM_PSK_OUI, AKM_SAE_OUI, CIPHER_CCMP_128_OUI};
    if CIPHER_CCMP_128_OUI != [0x00, 0x0F, 0xAC, 0x04] {
        return TestResult::Fail("CCMP-128 OUI wrong");
    }
    if AKM_PSK_OUI != [0x00, 0x0F, 0xAC, 0x02] {
        return TestResult::Fail("WPA2-PSK AKM OUI wrong");
    }
    if AKM_SAE_OUI != [0x00, 0x0F, 0xAC, 0x08] {
        return TestResult::Fail("WPA3-SAE AKM OUI wrong");
    }
    if !StaCipher::Ccmp128.needs_eapol() {
        return TestResult::Fail("Ccmp128 should need EAPOL");
    }
    if !StaCipher::Ccmp128Sae.needs_eapol() {
        return TestResult::Fail("Ccmp128Sae should need EAPOL");
    }
    if StaCipher::None.needs_eapol() {
        return TestResult::Fail("None should not need EAPOL");
    }
    if StaCipher::Ccmp128.as_wire() != 6 {
        return TestResult::Fail("Ccmp128 wire byte should be 6");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_cipher_suite_constants
);

fn smoke_mt7921_sta_rec_wtbl_encode() -> TestResult {
    use super::cmd::{encode_sta_rec_wtbl_tlv, StaCipher, STA_REC_WTBL_TLV_SIZE};
    let key = [0xAAu8; 16];
    let mut buf = [0u8; STA_REC_WTBL_TLV_SIZE];
    encode_sta_rec_wtbl_tlv(StaCipher::Ccmp128, 0, &key, &mut buf).unwrap();
    let tag = u16::from_le_bytes([buf[0], buf[1]]);
    if tag != 1 {
        return TestResult::Fail("STA_REC_WTBL tag should be 1");
    }
    if buf[4] != 6 {
        return TestResult::Fail("cipher byte should be 6 (CCMP-128)");
    }
    if buf[8..24] != key {
        return TestResult::Fail("key round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_sta_rec_wtbl_encode);

fn smoke_mt7921_build_sta_rec_body_for_join() -> TestResult {
    use super::cmd::{
        build_sta_rec_body_for_join, StaCipher, PHY_MODE_HE, STA_REC_BASIC_TLV_SIZE,
        STA_REC_WTBL_TLV_SIZE,
    };
    let peer = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
    let key = [0x11u8; 16];
    let mut buf = [0u8; STA_REC_BASIC_TLV_SIZE + STA_REC_WTBL_TLV_SIZE];
    let n = build_sta_rec_body_for_join(
        1,
        peer,
        2,
        PHY_MODE_HE,
        StaCipher::Ccmp128,
        0,
        &key,
        &mut buf,
    )
    .unwrap();
    if n != STA_REC_BASIC_TLV_SIZE + STA_REC_WTBL_TLV_SIZE {
        return TestResult::Fail("combined body length wrong");
    }
    let p = STA_REC_BASIC_TLV_SIZE;
    let wtbl_tag = u16::from_le_bytes([buf[p], buf[p + 1]]);
    if wtbl_tag != 1 {
        return TestResult::Fail("WTBL TLV tag not at expected offset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_build_sta_rec_body_for_join
);

// ── Stage-13: TX submit / ring-full detection ────────────────────

fn smoke_mt7921_tx_ring_full_detection() -> TestResult {
    use super::dma::alloc_tx_ring;
    let depth = MT7921_BASELINE_RING_DEPTH;
    let mut ring = match alloc_tx_ring(0, depth) {
        Ok(r) => r,
        Err(_) => return TestResult::Skip("alloc_coherent unavailable"),
    };
    ring.set_cpu_idx(depth - 1);
    ring.set_hw_idx(0);
    if (ring.cpu_idx() + 1) % depth != ring.hw_idx() {
        return TestResult::Fail("ring-full math wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_tx_ring_full_detection
);

// ── Bring-up orchestrator ────────────────────────────────────────

fn smoke_mt7921_mcu_init_sequence_layout() -> TestResult {
    use super::bringup::{build_mcu_init_sequence, BringUpConfig};
    use super::cmd::{
        INIT_RA_CFG_SIZE, PM_STATE_ACTIVE, PM_STATE_CTRL_SIZE, UNI_DEV_INFO_BODY_SIZE,
    };
    let cfg = BringUpConfig::default();
    let seq = build_mcu_init_sequence(&cfg);
    let expected = PM_STATE_CTRL_SIZE + INIT_RA_CFG_SIZE + UNI_DEV_INFO_BODY_SIZE;
    if seq.len() != expected {
        return TestResult::Fail("init sequence length wrong");
    }
    // First body: PM_STATE_CTRL with PM_STATE_ACTIVE.
    if seq[0] != PM_STATE_ACTIVE {
        return TestResult::Fail("first body should start with PM_STATE_ACTIVE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_mcu_init_sequence_layout
);

fn smoke_mt7921_mac_vif_setup_layout() -> TestResult {
    use super::bringup::{build_mac_vif_setup_sequence, BringUpConfig};
    use super::cmd::{BSS_INFO_BASIC_TLV_SIZE, DEV_INFO_UPDATE_SIZE, STA_REC_BASIC_TLV_SIZE};
    let cfg = BringUpConfig::default();
    let bssid = [0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x42];
    let seq = build_mac_vif_setup_sequence(&cfg, bssid);
    let expected = DEV_INFO_UPDATE_SIZE + BSS_INFO_BASIC_TLV_SIZE + STA_REC_BASIC_TLV_SIZE;
    if seq.len() != expected {
        return TestResult::Fail("mac vif setup sequence length wrong");
    }
    // BSS_INFO_BASIC TLV at offset DEV_INFO_UPDATE_SIZE — bssid at +12.
    let bssid_at = DEV_INFO_UPDATE_SIZE + 12;
    if seq[bssid_at..bssid_at + 6] != bssid {
        return TestResult::Fail("BSS_INFO bssid not at expected offset");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_mac_vif_setup_layout);

fn smoke_mt7921_assoc_open_frames_for_ssid() -> TestResult {
    use super::bringup::{build_assoc_open_frames, BringUpConfig};
    use super::cmd::{IEEE80211_AUTH_FRAME_SIZE, IEEE80211_MAC_HDR_SIZE};
    let cfg = BringUpConfig {
        own_mac: [0x11; 6],
        ..Default::default()
    };
    let bssid = [0x22; 6];
    let ssid = b"narf";
    let (auth, assoc) = build_assoc_open_frames(&cfg, bssid, ssid);
    if auth.len() != IEEE80211_AUTH_FRAME_SIZE {
        return TestResult::Fail("auth frame length wrong");
    }
    // Auth's addr1 (DA) is bssid; addr3 (BSSID) is bssid; addr2
    // (SA) is own_mac.
    if auth[4..10] != bssid {
        return TestResult::Fail("auth addr1 not bssid");
    }
    if auth[10..16] != cfg.own_mac {
        return TestResult::Fail("auth addr2 not own_mac");
    }
    // Assoc carries the SSID IE at offset MAC_HDR + 4.
    let p = IEEE80211_MAC_HDR_SIZE + 4;
    if assoc[p] != 0 {
        return TestResult::Fail("SSID IE id should be 0");
    }
    if assoc[p + 1] as usize != ssid.len() {
        return TestResult::Fail("SSID IE len wrong");
    }
    if &assoc[p + 2..p + 2 + ssid.len()] != ssid {
        return TestResult::Fail("SSID octets wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_assoc_open_frames_for_ssid
);

fn smoke_mt7921_secure_sta_rec_for_wpa2() -> TestResult {
    use super::bringup::{build_secure_sta_rec_body, BringUpConfig};
    use super::cmd::{StaCipher, STA_REC_BASIC_TLV_SIZE, STA_REC_WTBL_TLV_SIZE};
    let cfg = BringUpConfig::default();
    let bssid = [0x42; 6];
    let key = [0xAAu8; 16];
    let body = build_secure_sta_rec_body(&cfg, bssid, StaCipher::Ccmp128, 0, &key);
    if body.len() != STA_REC_BASIC_TLV_SIZE + STA_REC_WTBL_TLV_SIZE {
        return TestResult::Fail("secure sta_rec body length wrong");
    }
    // The WTBL TLV starts at offset STA_REC_BASIC_TLV_SIZE — cipher
    // byte 6 (CCMP-128) at +4.
    let p = STA_REC_BASIC_TLV_SIZE;
    if body[p + 4] != 6 {
        return TestResult::Fail("WTBL cipher should be CCMP-128 (6)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_secure_sta_rec_for_wpa2
);
