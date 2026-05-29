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

use super::dma::{
    addr_set_for, addr_set_for_chip, pack_idx, split_idx, RingState, AX_DMA_ADDR_SET,
    AX_V1_DMA_ADDR_SET, DEFAULT_RXBD_NUM, DEFAULT_TXBD_NUM, RING_IDX_HOST_SHIFT, RING_IDX_HW_MASK,
    RXCH_NUM, RXCH_RPQ, RXCH_RXQ, RX_BD_SIZE, TXCH_ACH0, TXCH_CH12, TXCH_NUM, TX_BD_SIZE,
};
use super::phy_table::{
    pd, pp, pw, tx_pwr_clamp, PhyEntry, PhyOp, TxPwrByRate, BB_RF_BOOTSTRAP_TABLE,
    TXPWR_BYRATE_TABLE_SIZE,
};
use super::fwdl::{
    detect_version, packet_count, parse_auto, parse_v0, parse_v1, FwSection, FwdlPacketIter,
    FWDL_SECTION_CHKSUM_LEN, FWDL_SECTION_MAX_NUM, FWDL_SECTION_PER_PKT_LEN, FW_HDR_V0_BASE_SIZE,
    FW_HDR_V0_SECTION_SIZE, FW_HDR_V1_BASE_SIZE, FW_HDR_V1_SECTION_SIZE, FW_TYPE_BBMCU0,
    FW_TYPE_LOGFMT, FW_TYPE_NORMAL, FW_TYPE_WOWLAN,
};
use super::h2c::{
    make_fwhdr_dl_h2c, make_joininfo_h2c, make_log_cfg_h2c, make_ofld_cfg_h2c,
    make_ra_macidcfg_h2c, make_scanofld_h2c, H2cBuilder, H2cSeqAllocator,
    H2C_CAT_CTL_DRV_GEN, H2C_CAT_MAC as H2C_CAT_MAC_H2C, H2C_CAT_OUTSRC, H2C_CAT_TEST,
    H2C_CL_FW_INFO, H2C_CL_MAC_FR_EXCHG, H2C_CL_MAC_FWDL as H2C_CL_MAC_FWDL_H2C,
    H2C_CL_MAC_FW_OFLD, H2C_CL_MAC_MEDIA_RPT, H2C_CL_OUTSRC_RA, H2C_CL_OUTSRC_RF_FW_RFK,
    H2C_FUNC_MAC_BCN_UPD, H2C_FUNC_MAC_JOININFO, H2C_FUNC_OFLD_CFG, H2C_FUNC_OUTSRC_RA_MACIDCFG,
    H2C_FUNC_SCANOFLD, H2C_FUNC_SCANOFLD_BE,
};
use super::mac_init::{
    QtaMode, B_AX_CMAC_DMA_EN, B_AX_CMAC_EN, B_AX_DLE_DMAC_EN, B_AX_DMAC_FUNC_EN,
    B_AX_DMAC_MIX_EN, B_AX_DMAC_PKT_IN_EN, B_AX_HCI_RXDMA_EN, B_AX_HCI_TXDMA_EN, B_AX_PHYINTF_EN,
    B_AX_PTCLTOP_EN, B_AX_RMAC_EN, B_AX_SCHEDULER_EN, B_AX_TMAC_EN, B_AX_WLRF1_CTRL_1,
    B_AX_WLRF1_CTRL_7, B_AX_WLRF_CTRL_1, B_AX_WLRF_CTRL_7, CMAC_ENABLE_MASK, DMAC_PRE_EN_MASK,
    PHYREG_SET_ALL_CYCLE, R_AX_CMAC_FUNC_EN, R_AX_DMAC_FUNC_EN, R_AX_HCI_FUNC_EN,
    R_AX_PHYREG_SET, R_AX_WLRF_CTRL, WLRF_ENABLE_MASK,
};
use super::efuse::{mac_is_valid, EfuseError};
use super::fw::{expected_blob_name, FwError};
use super::mac::*;
use super::pci::{name_for, register_pci_driver};
use super::phy::PhyError;
use super::txrx::{
    decode_rxd, encode_h2c_header, encode_rxd_for_test, encode_txwd as encode_txd, RxdInfo, TxwdInfo,
    H2C_CAT_MAC, H2C_CL_MAC_FWDL, H2C_FUNC_MAC_FWHDR_DL, H2C_HEADER_LEN, H2C_HDR_REC_ACK,
    TXWD_BODY0_CHANNEL_MASK, TXWD_BODY0_WD_INFO_EN, TXWD_BODY2_MACID_MASK,
    TXWD_BODY2_QSEL_MASK, TXWD_BODY2_TXPKT_SIZE_MASK, TXWD_BODY_SIZE,
    AX_RXD_CRC32_ERR, AX_RXD_RPKT_TYPE_WIFI, RXD_SHORT_SIZE,
    QSEL_B0_BE,
};
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

// ── Stage-3: TXWD / AX RXD / H2C header smokes ────────────────────

fn smoke_rtw89_txwd_encode() -> TestResult {
    // Build a TXWD body for a 1000-byte frame on ACH0 (channel=0),
    // best-effort queue, mac_id=1. Mirrors the fields
    // `rtw89_core_tx_build_txwd` fills at ~L300, v6.6.
    let info = TxwdInfo {
        channel: 0,          // RTW89_TXCH_ACH0
        qsel: QSEL_B0_BE,
        mac_id: 1,
        pkt_size: 1000,
    };
    let mut buf = [0u8; TXWD_BODY_SIZE];
    if encode_txd(&info, &mut buf).is_none() {
        return TestResult::Fail("encode_txd returned None");
    }
    if buf.len() != 24 {
        return TestResult::Fail("TXWD_BODY_SIZE not 24 bytes");
    }
    let dw0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    // WD_INFO_EN must be set.
    if dw0 & TXWD_BODY0_WD_INFO_EN == 0 {
        return TestResult::Fail("TXWD_BODY0_WD_INFO_EN not set");
    }
    // channel = 0 → CHANNEL_DMA bits should be zero.
    if dw0 & TXWD_BODY0_CHANNEL_MASK != 0 {
        return TestResult::Fail("channel field not zero for ACH0");
    }
    let dw2 = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    // mac_id must land in bits 30-24.
    let mac_id_check = (dw2 & TXWD_BODY2_MACID_MASK) >> 24;
    if mac_id_check != 1 {
        return TestResult::Fail("mac_id not encoded correctly in dword2");
    }
    // pkt_size = 1000 must be in GENMASK(13,0).
    if dw2 & TXWD_BODY2_TXPKT_SIZE_MASK != 1000 {
        return TestResult::Fail("pkt_size not encoded correctly in dword2");
    }
    // qsel = QSEL_B0_BE = 0, verify the field is zero.
    if dw2 & TXWD_BODY2_QSEL_MASK != 0 {
        return TestResult::Fail("qsel field not zero for QSEL_B0_BE=0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_txwd_encode);

fn smoke_rtw89_rxd_decode_roundtrip() -> TestResult {
    // Normal data frame, 512 bytes, no errors.
    let original = RxdInfo {
        pkt_len: 512,
        pkt_type: AX_RXD_RPKT_TYPE_WIFI as u8,
        crc32_err: false,
        icv_err: false,
    };
    let bytes = encode_rxd_for_test(&original);
    if bytes.len() != RXD_SHORT_SIZE {
        return TestResult::Fail("encode_rxd_for_test size wrong");
    }
    let decoded = match decode_rxd(&bytes) {
        Some(v) => v,
        None => return TestResult::Fail("decode_rxd returned None"),
    };
    if decoded != original {
        return TestResult::Fail("RXD round-trip mismatch");
    }
    // CRC32 error round-trip.
    let bad = RxdInfo {
        pkt_len: 64,
        pkt_type: 0,
        crc32_err: true,
        icv_err: false,
    };
    let bad_bytes = encode_rxd_for_test(&bad);
    let dec_bad = decode_rxd(&bad_bytes).unwrap();
    if !dec_bad.crc32_err {
        return TestResult::Fail("crc32_err not preserved through round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_rxd_decode_roundtrip);

fn smoke_rtw89_h2c_header_encode() -> TestResult {
    // Encode a LOG_CFG command (CAT=MAC, CLASS=FW_INFO, FUNC=0x0,
    // seq=3, payload=16 bytes). Mirrors `rtw89_h2c_pkt_set_hdr` call
    // shape from `fw.c:1564`.
    let mut hdr = [0u8; H2C_HEADER_LEN];
    if encode_h2c_header(H2C_CAT_MAC, H2C_CL_MAC_FWDL, H2C_FUNC_MAC_FWHDR_DL,
                         3, 16, true, false, &mut hdr).is_none() {
        return TestResult::Fail("encode_h2c_header returned None");
    }
    let dw0 = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    // CAT = 0x1 in bits 1-0.
    if dw0 & 0x3 != H2C_CAT_MAC as u32 {
        return TestResult::Fail("H2C CAT field wrong");
    }
    // SEQ = 3 in bits 31-24.
    let seq_check = (dw0 >> 24) & 0xFF;
    if seq_check != 3 {
        return TestResult::Fail("H2C SEQ field wrong");
    }
    let dw1 = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    // total_len = 16 + 8 = 24.
    let total_len = dw1 & 0x3FFF;
    if total_len != 24 {
        return TestResult::Fail("H2C total_len wrong (expected 24)");
    }
    // REC_ACK must be set.
    if dw1 & H2C_HDR_REC_ACK == 0 {
        return TestResult::Fail("H2C REC_ACK not set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_h2c_header_encode);

// ── Stage-4: DMA-ring address tables + bookkeeping ─────────────────

fn smoke_rtw89_dma_txch_count() -> TestResult {
    if TXCH_NUM != 13 {
        return TestResult::Fail("RTW89 TXCH count drifted from 13");
    }
    if RXCH_NUM != 2 {
        return TestResult::Fail("RTW89 RXCH count drifted from 2");
    }
    // ACH0 must be channel 0 (matches RTW89_TXCH_ACH0 in txrx.h:660).
    if TXCH_ACH0 != 0 {
        return TestResult::Fail("RTW89_TXCH_ACH0 not 0");
    }
    // CH12 must be channel 12 (FW command ring).
    if TXCH_CH12 != 12 {
        return TestResult::Fail("RTW89_TXCH_CH12 not 12");
    }
    if RXCH_RXQ != 0 || RXCH_RPQ != 1 {
        return TestResult::Fail("RTW89 RX channel numbering drifted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_txch_count);

fn smoke_rtw89_dma_ax_addr_set_pins() -> TestResult {
    // Pin a handful of AX baseline offsets against pci.c:1093..1113.
    // ACH0 doorbell: 0x1058. ACH0 desa_l: 0x1110.
    let set = AX_DMA_ADDR_SET;
    if set.tx[0].idx != 0x1058 {
        return TestResult::Fail("AX ACH0 doorbell drift");
    }
    if set.tx[0].desa_l != 0x1110 {
        return TestResult::Fail("AX ACH0 desa_l drift");
    }
    if set.tx[0].desa_h != 0x1114 {
        return TestResult::Fail("AX ACH0 desa_h drift");
    }
    // CH12 (FW cmd) doorbell: 0x1080.
    if set.tx[12].idx != 0x1080 {
        return TestResult::Fail("AX CH12 (FW cmd) doorbell drift");
    }
    // RXQ doorbell: 0x1050.
    if set.rx[0].idx != 0x1050 {
        return TestResult::Fail("AX RXQ doorbell drift");
    }
    if set.rx[1].idx != 0x1054 {
        return TestResult::Fail("AX RPQ doorbell drift");
    }
    // CH10 / CH11 sit in the Type-1 BDRAM offset region.
    if set.tx[10].idx != 0x137C || set.tx[11].idx != 0x1380 {
        return TestResult::Fail("AX CH10/CH11 Type-1 BDRAM drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_ax_addr_set_pins);

fn smoke_rtw89_dma_ax_v1_addr_set_pins() -> TestResult {
    // 8852C V1 layout. ACH0 doorbell still 0x1058 (doorbells unchanged),
    // but desa_l moves to the V1 base at 0x1230.
    let set = AX_V1_DMA_ADDR_SET;
    if set.tx[0].idx != 0x1058 {
        return TestResult::Fail("V1 ACH0 doorbell drift");
    }
    if set.tx[0].desa_l != 0x1230 {
        return TestResult::Fail("V1 ACH0 desa_l should be at 0x1230 base");
    }
    // RX rings: RXQ doorbell at 0x1218 in V1.
    if set.rx[0].idx != 0x1218 {
        return TestResult::Fail("V1 RXQ doorbell drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_ax_v1_addr_set_pins);

fn smoke_rtw89_dma_addr_set_for_chip() -> TestResult {
    // AX baseline parts → AX_DMA_ADDR_SET.
    let s1 = addr_set_for_chip(ChipId::Rtl8852A);
    if s1.tx[0].idx != AX_DMA_ADDR_SET.tx[0].idx {
        return TestResult::Fail("8852A not on AX baseline");
    }
    let s2 = addr_set_for_chip(ChipId::Rtl8852B);
    if s2.tx[0].idx != AX_DMA_ADDR_SET.tx[0].idx {
        return TestResult::Fail("8852B not on AX baseline");
    }
    let s3 = addr_set_for_chip(ChipId::Rtl8851B);
    if s3.tx[0].idx != AX_DMA_ADDR_SET.tx[0].idx {
        return TestResult::Fail("8851B not on AX baseline");
    }
    // 8852C → V1.
    let s4 = addr_set_for_chip(ChipId::Rtl8852C);
    if s4.tx[0].desa_l != AX_V1_DMA_ADDR_SET.tx[0].desa_l {
        return TestResult::Fail("8852C not on V1 layout");
    }
    // 8922A (BE) reuses V1 in our mapping.
    let s5 = addr_set_for_chip(ChipId::Rtl8922A);
    if s5.tx[0].desa_l != AX_V1_DMA_ADDR_SET.tx[0].desa_l {
        return TestResult::Fail("8922A not on V1 layout");
    }
    // generation-only dispatch: Ax → baseline, Be → V1.
    let g_ax = addr_set_for(ChipGeneration::Ax);
    if g_ax.tx[0].idx != AX_DMA_ADDR_SET.tx[0].idx {
        return TestResult::Fail("addr_set_for(Ax) wrong");
    }
    let g_be = addr_set_for(ChipGeneration::Be);
    if g_be.tx[0].desa_l != AX_V1_DMA_ADDR_SET.tx[0].desa_l {
        return TestResult::Fail("addr_set_for(Be) wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_addr_set_for_chip);

fn smoke_rtw89_dma_ring_state_avail() -> TestResult {
    // Brand new ring: 256 slots, all empty, all avail = 255 (one slot
    // reserved to distinguish full from empty — matches
    // `rtw89_pci_get_avail_txbd_num` at pci.c:1222).
    let mut r = RingState::new(DEFAULT_TXBD_NUM);
    if r.avail() != DEFAULT_TXBD_NUM - 1 {
        return TestResult::Fail("empty ring avail wrong");
    }
    if r.is_full() {
        return TestResult::Fail("empty ring claims full");
    }
    // Push 10 slots; HW hasn't moved yet.
    r.advance_wp(10);
    if r.avail() != DEFAULT_TXBD_NUM - 1 - 10 {
        return TestResult::Fail("post-push avail wrong");
    }
    // HW reads 5 of them — 5 slots come back.
    r.set_rp(5);
    if r.avail() != DEFAULT_TXBD_NUM - 1 - 5 {
        return TestResult::Fail("post-HW-advance avail wrong");
    }
    // Fill the rest of the ring; should report full.
    let push = r.avail();
    r.advance_wp(push);
    if !r.is_full() {
        return TestResult::Fail("ring should be full at avail=0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_ring_state_avail);

fn smoke_rtw89_dma_idx_pack_unpack() -> TestResult {
    // pack_idx / split_idx round-trip — the index register format is
    // (host_wp << 16) | hw_rp.
    let packed = pack_idx(0x0AB, 0xCD12);
    let (hw, host) = split_idx(packed);
    if hw != 0x0AB {
        return TestResult::Fail("HW pointer round-trip failed");
    }
    if host != 0xCD12 {
        return TestResult::Fail("host pointer round-trip failed");
    }
    // Mask widths.
    if RING_IDX_HW_MASK != 0x0FFF {
        return TestResult::Fail("HW pointer mask not 12 bits");
    }
    if RING_IDX_HOST_SHIFT != 16 {
        return TestResult::Fail("host shift not 16");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_idx_pack_unpack);

fn smoke_rtw89_dma_bd_sizes() -> TestResult {
    // BD descriptor sizes (`struct rtw89_pci_tx_bd_32` /
    // `rtw89_pci_rx_bd_32`, pci.h:1283/1289). Both 8 bytes.
    if TX_BD_SIZE != 8 {
        return TestResult::Fail("TX BD size not 8");
    }
    if RX_BD_SIZE != 8 {
        return TestResult::Fail("RX BD size not 8");
    }
    // Default ring depths.
    if DEFAULT_TXBD_NUM != 256 {
        return TestResult::Fail("default TX BD count drifted");
    }
    if DEFAULT_RXBD_NUM != 256 {
        return TestResult::Fail("default RX BD count drifted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_bd_sizes);

fn smoke_rtw89_dma_all_ax_offsets_distinct() -> TestResult {
    // The AX baseline doorbells should all sit at distinct offsets —
    // no two channels share a doorbell register. Catches transcription
    // typos against pci.c:1093..1113.
    let set = AX_DMA_ADDR_SET;
    for i in 0..TXCH_NUM {
        for j in (i + 1)..TXCH_NUM {
            if set.tx[i].idx == set.tx[j].idx {
                return TestResult::Fail("two AX TX channels share a doorbell");
            }
        }
    }
    for i in 0..RXCH_NUM {
        for j in (i + 1)..RXCH_NUM {
            if set.rx[i].idx == set.rx[j].idx {
                return TestResult::Fail("two AX RX rings share a doorbell");
            }
        }
    }
    // And the same for V1.
    let v1 = AX_V1_DMA_ADDR_SET;
    for i in 0..TXCH_NUM {
        for j in (i + 1)..TXCH_NUM {
            if v1.tx[i].idx == v1.tx[j].idx {
                return TestResult::Fail("two V1 TX channels share a doorbell");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_dma_all_ax_offsets_distinct);

// ── Stage-5: MAC init register addresses + bit masks ──────────────

fn smoke_rtw89_mac_init_register_pins() -> TestResult {
    // R_AX_WLRF_CTRL = 0x02F0 per reg.h:307.
    if R_AX_WLRF_CTRL != 0x02F0 {
        return TestResult::Fail("R_AX_WLRF_CTRL drifted from reg.h:307");
    }
    // R_AX_PHYREG_SET = 0x8040 per reg.h:506.
    if R_AX_PHYREG_SET != 0x8040 {
        return TestResult::Fail("R_AX_PHYREG_SET drifted from reg.h:506");
    }
    // PHYREG_SET_ALL_CYCLE = 0x8 per reg.h:507.
    if PHYREG_SET_ALL_CYCLE != 0x08 {
        return TestResult::Fail("PHYREG_SET_ALL_CYCLE drifted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_mac_init_register_pins);

fn smoke_rtw89_mac_init_wlrf_mask() -> TestResult {
    // The WLRF init mask in `rtw89_mac_enable_bb_rf` (mac.c:4176)
    // ORs four bits: WLRF1_CTRL_7 | WLRF1_CTRL_1 | WLRF_CTRL_7 |
    // WLRF_CTRL_1. Check the composite.
    let expected = B_AX_WLRF1_CTRL_7 | B_AX_WLRF1_CTRL_1 | B_AX_WLRF_CTRL_7 | B_AX_WLRF_CTRL_1;
    if WLRF_ENABLE_MASK != expected {
        return TestResult::Fail("WLRF_ENABLE_MASK doesn't recompose");
    }
    // Bits must be distinct.
    let bits = [B_AX_WLRF_CTRL_1, B_AX_WLRF_CTRL_7, B_AX_WLRF1_CTRL_1, B_AX_WLRF1_CTRL_7];
    for i in 0..bits.len() {
        for j in (i + 1)..bits.len() {
            if bits[i] & bits[j] != 0 {
                return TestResult::Fail("WLRF bits overlap");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_mac_init_wlrf_mask);

fn smoke_rtw89_mac_init_hci_dmac_cmac_bits() -> TestResult {
    // HCI DMA-TRX bits — TXDMA at bit 0, RXDMA at bit 1.
    if B_AX_HCI_TXDMA_EN != 1 << 0 {
        return TestResult::Fail("HCI TXDMA bit drift");
    }
    if B_AX_HCI_RXDMA_EN != 1 << 1 {
        return TestResult::Fail("HCI RXDMA bit drift");
    }
    // DMAC pre-en mask must include all the dispatcher/DLE/TBL/MIX bits.
    let needed = B_AX_DMAC_FUNC_EN | B_AX_DLE_DMAC_EN | B_AX_DMAC_PKT_IN_EN | B_AX_DMAC_MIX_EN;
    if DMAC_PRE_EN_MASK & needed != needed {
        return TestResult::Fail("DMAC_PRE_EN_MASK missing required bits");
    }
    // CMAC enable mask must include TMAC + RMAC.
    let cmac_needed = B_AX_CMAC_EN | B_AX_TMAC_EN | B_AX_RMAC_EN
        | B_AX_PHYINTF_EN | B_AX_CMAC_DMA_EN | B_AX_PTCLTOP_EN | B_AX_SCHEDULER_EN;
    if CMAC_ENABLE_MASK & cmac_needed != cmac_needed {
        return TestResult::Fail("CMAC_ENABLE_MASK missing required bits");
    }
    // Register addresses must be distinct.
    let regs = [R_AX_HCI_FUNC_EN, R_AX_DMAC_FUNC_EN, R_AX_CMAC_FUNC_EN, R_AX_WLRF_CTRL, R_AX_PHYREG_SET];
    for i in 0..regs.len() {
        for j in (i + 1)..regs.len() {
            if regs[i] == regs[j] {
                return TestResult::Fail("Two MAC-init registers share an offset");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_mac_init_hci_dmac_cmac_bits);

fn smoke_rtw89_mac_init_qta_mode_enum() -> TestResult {
    // QtaMode covers the two values the FW-DL path uses.
    let dlfw = QtaMode::DlFw;
    let scc = QtaMode::Scc;
    if dlfw == scc {
        return TestResult::Fail("QtaMode variants compare equal");
    }
    // Debug-presence check.
    use core::fmt::Write;
    let mut buf = alloc::string::String::new();
    let _ = write!(buf, "{:?} {:?}", dlfw, scc);
    if buf.is_empty() {
        return TestResult::Fail("QtaMode Debug doesn't render");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_mac_init_qta_mode_enum);

// ── Stage-6: H2C dispatch ──────────────────────────────────────────

fn smoke_rtw89_h2c_category_values() -> TestResult {
    // Pin all three real categories against fw.h:4505..4694.
    if H2C_CAT_TEST != 0x0 {
        return TestResult::Fail("H2C_CAT_TEST not 0x0");
    }
    if H2C_CAT_MAC_H2C != 0x1 {
        return TestResult::Fail("H2C_CAT_MAC not 0x1");
    }
    if H2C_CAT_OUTSRC != 0x2 {
        return TestResult::Fail("H2C_CAT_OUTSRC not 0x2");
    }
    // Driver-only sentinel must be outside the 2-bit cat field width.
    if H2C_CAT_CTL_DRV_GEN <= H2C_CAT_OUTSRC {
        return TestResult::Fail("H2C_CAT_CTL_DRV_GEN clashes with real cat");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_h2c_category_values);

fn smoke_rtw89_h2c_class_pins() -> TestResult {
    // MAC classes.
    if H2C_CL_FW_INFO != 0x0 {
        return TestResult::Fail("FW_INFO class drift");
    }
    if H2C_CL_MAC_FWDL_H2C != 0x3 {
        return TestResult::Fail("FWDL class drift");
    }
    if H2C_CL_MAC_FR_EXCHG != 0x5 {
        return TestResult::Fail("FR_EXCHG class drift");
    }
    if H2C_CL_MAC_MEDIA_RPT != 0x8 {
        return TestResult::Fail("MEDIA_RPT class drift");
    }
    if H2C_CL_MAC_FW_OFLD != 0x9 {
        return TestResult::Fail("FW_OFLD class drift");
    }
    // OUTSRC classes.
    if H2C_CL_OUTSRC_RA != 0x1 {
        return TestResult::Fail("OUTSRC RA class drift");
    }
    if H2C_CL_OUTSRC_RF_FW_RFK != 0xB {
        return TestResult::Fail("OUTSRC RFK class drift");
    }
    // Frame-exchange functions.
    if H2C_FUNC_MAC_BCN_UPD != 0x5 {
        return TestResult::Fail("BCN_UPD function drift");
    }
    if H2C_FUNC_MAC_JOININFO != 0x0 {
        return TestResult::Fail("JOININFO function drift");
    }
    if H2C_FUNC_OFLD_CFG != 0x14 {
        return TestResult::Fail("OFLD_CFG function drift");
    }
    if H2C_FUNC_SCANOFLD != 0x17 {
        return TestResult::Fail("SCANOFLD function drift");
    }
    if H2C_FUNC_SCANOFLD_BE != 0x2C {
        return TestResult::Fail("SCANOFLD_BE function drift");
    }
    if H2C_FUNC_OUTSRC_RA_MACIDCFG != 0x0 {
        return TestResult::Fail("RA_MACIDCFG function drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_h2c_class_pins);

fn smoke_rtw89_h2c_builder() -> TestResult {
    // Build a JOININFO H2C with a 16-byte payload.
    let payload = [0xAAu8; 16];
    let mut buf = [0u8; 64];
    let h = make_joininfo_h2c(42);
    let total = match h.build(&payload, &mut buf) {
        Some(n) => n,
        None => return TestResult::Fail("H2cBuilder::build returned None"),
    };
    // 8 byte header + 16 byte payload.
    if total != 24 {
        return TestResult::Fail("H2C builder produced wrong total length");
    }
    // Decode dword 0 of the header.
    let dw0 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if dw0 & 0x3 != H2C_CAT_MAC_H2C as u32 {
        return TestResult::Fail("H2C builder didn't encode cat=MAC");
    }
    // SEQ in bits 31-24 should be 42.
    if (dw0 >> 24) & 0xFF != 42 {
        return TestResult::Fail("H2C builder didn't encode seq");
    }
    // Payload must be at offset 8.
    if buf[8..24] != payload {
        return TestResult::Fail("H2C builder mis-placed payload");
    }
    // Tiny buffer should refuse.
    let mut small = [0u8; 4];
    if h.build(&payload, &mut small).is_some() {
        return TestResult::Fail("H2C builder accepted undersized buffer");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_h2c_builder);

fn smoke_rtw89_h2c_seq_allocator() -> TestResult {
    let a = H2cSeqAllocator::new();
    let s0 = a.next();
    let s1 = a.next();
    let s2 = a.next();
    if s0 != 0 || s1 != 1 || s2 != 2 {
        return TestResult::Fail("H2C seq allocator didn't return 0,1,2");
    }
    // Burn through to test wrap.
    for _ in 0..253 {
        let _ = a.next();
    }
    let wrap = a.next();
    // After 256 calls total, next should be 0 again (wrap).
    if wrap != 0 {
        return TestResult::Fail("H2C seq allocator didn't wrap at 256");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_h2c_seq_allocator);

fn smoke_rtw89_h2c_prebuilt_helpers() -> TestResult {
    // LOG_CFG: MAC category, FW_INFO class.
    let h = make_log_cfg_h2c(0);
    if h.cat != H2C_CAT_MAC_H2C || h.class != H2C_CL_FW_INFO {
        return TestResult::Fail("LOG_CFG H2C wrong target");
    }
    // OFLD_CFG: MAC + FW_OFLD + OFLD_CFG, done_ack on.
    let h = make_ofld_cfg_h2c(1);
    if h.func != H2C_FUNC_OFLD_CFG || !h.done_ack {
        return TestResult::Fail("OFLD_CFG H2C wrong setup");
    }
    // JOININFO: done_ack must be on (driver needs to know assoc landed).
    let h = make_joininfo_h2c(2);
    if !h.done_ack {
        return TestResult::Fail("JOININFO H2C should request done_ack");
    }
    // RA_MACIDCFG: OUTSRC category.
    let h = make_ra_macidcfg_h2c(3);
    if h.cat != H2C_CAT_OUTSRC {
        return TestResult::Fail("RA_MACIDCFG should be OUTSRC");
    }
    // SCANOFLD AX vs BE.
    let h_ax = make_scanofld_h2c(4, false);
    let h_be = make_scanofld_h2c(4, true);
    if h_ax.func != H2C_FUNC_SCANOFLD || h_be.func != H2C_FUNC_SCANOFLD_BE {
        return TestResult::Fail("SCANOFLD AX/BE dispatch wrong");
    }
    // FWHDR_DL: MAC + FWDL.
    let h = make_fwhdr_dl_h2c(5);
    if h.cat != H2C_CAT_MAC_H2C || h.class != H2C_CL_MAC_FWDL_H2C {
        return TestResult::Fail("FWHDR_DL H2C wrong setup");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_h2c_prebuilt_helpers);

// ── Stage-7: FW downloader (header parser + packet segmentation) ──

fn smoke_rtw89_fwdl_constants() -> TestResult {
    if FW_TYPE_NORMAL != 1 { return TestResult::Fail("FW_TYPE_NORMAL drift"); }
    if FW_TYPE_WOWLAN != 3 { return TestResult::Fail("FW_TYPE_WOWLAN drift"); }
    if FW_TYPE_BBMCU0 != 64 { return TestResult::Fail("FW_TYPE_BBMCU0 drift"); }
    if FW_TYPE_LOGFMT != 255 { return TestResult::Fail("FW_TYPE_LOGFMT drift"); }
    if FWDL_SECTION_PER_PKT_LEN != 2020 { return TestResult::Fail("PER_PKT_LEN drift"); }
    if FWDL_SECTION_CHKSUM_LEN != 8 { return TestResult::Fail("CHKSUM_LEN drift"); }
    if FWDL_SECTION_MAX_NUM != 10 { return TestResult::Fail("MAX_NUM drift"); }
    if FW_HDR_V0_BASE_SIZE != 32 { return TestResult::Fail("v0 base hdr"); }
    if FW_HDR_V0_SECTION_SIZE != 12 { return TestResult::Fail("v0 section"); }
    if FW_HDR_V1_BASE_SIZE != 48 { return TestResult::Fail("v1 base hdr"); }
    if FW_HDR_V1_SECTION_SIZE != 16 { return TestResult::Fail("v1 section"); }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_fwdl_constants);

fn smoke_rtw89_fwdl_v0_parse() -> TestResult {
    let section_num = 1u32;
    let mut blob = alloc::vec::Vec::new();
    let mut hdr = [0u32; 8];
    hdr[1] = 0x0001_0002;
    hdr[6] = section_num << 8;
    hdr[7] = 0;
    for w in hdr.iter() { blob.extend_from_slice(&w.to_le_bytes()); }
    let sw0 = 0x0000_1000u32;
    let sw1 = (1u32 << 24) | 512u32;
    let sw2 = 0u32;
    blob.extend_from_slice(&sw0.to_le_bytes());
    blob.extend_from_slice(&sw1.to_le_bytes());
    blob.extend_from_slice(&sw2.to_le_bytes());
    blob.extend(core::iter::repeat(0xABu8).take(512));

    let mut sections = [FwSection {
        kind: 0, dladdr: 0, len: 0, chksum: false, redl: false, payload_off: 0,
    }; FWDL_SECTION_MAX_NUM];
    let h = match parse_v0(&blob, &mut sections) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("v0 parse failed"),
    };
    if h.section_num != 1 { return TestResult::Fail("section_num"); }
    if h.fw_major != 2 || h.fw_minor != 1 { return TestResult::Fail("major/minor"); }
    if h.version != 0 { return TestResult::Fail("version"); }
    if h.hdr_len != 44 { return TestResult::Fail("hdr_len"); }
    let s = &sections[0];
    if s.kind != 1 { return TestResult::Fail("section type"); }
    if s.dladdr != 0x1000 { return TestResult::Fail("dladdr"); }
    if s.len != 512 { return TestResult::Fail("section len"); }
    if s.payload_off != 44 { return TestResult::Fail("payload_off"); }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_fwdl_v0_parse);

fn smoke_rtw89_fwdl_v0_chksum() -> TestResult {
    let mut blob = alloc::vec::Vec::new();
    let hdr = [0u32, 0, 0, 0, 0, 0, 1u32 << 8, 0];
    for w in hdr.iter() { blob.extend_from_slice(&w.to_le_bytes()); }
    let sw0 = 0u32;
    let sw1 = (1u32 << 24) | (1u32 << 28) | 1000u32;
    let sw2 = 0u32;
    blob.extend_from_slice(&sw0.to_le_bytes());
    blob.extend_from_slice(&sw1.to_le_bytes());
    blob.extend_from_slice(&sw2.to_le_bytes());
    blob.extend(core::iter::repeat(0x55u8).take(1008));

    let mut sections = [FwSection {
        kind: 0, dladdr: 0, len: 0, chksum: false, redl: false, payload_off: 0,
    }; FWDL_SECTION_MAX_NUM];
    let _ = match parse_v0(&blob, &mut sections) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("v0+chksum parse failed"),
    };
    let s = &sections[0];
    if !s.chksum { return TestResult::Fail("chksum bit"); }
    if s.len != 1008 { return TestResult::Fail("len did not add 8"); }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_fwdl_v0_chksum);

fn smoke_rtw89_fwdl_v1_parse() -> TestResult {
    let mut blob = alloc::vec::Vec::new();
    let mut hdr = [0u32; 12];
    hdr[1] = 0x0405;
    hdr[3] = 1u32 << 24;
    hdr[6] = 1u32 << 8;
    hdr[7] = 0;
    for w in hdr.iter() { blob.extend_from_slice(&w.to_le_bytes()); }
    let sw0 = 0x4000_0000u32;
    let sw1 = (64u32 << 24) | 256u32;
    let sw2 = 0u32;
    let sw3 = 0u32;
    blob.extend_from_slice(&sw0.to_le_bytes());
    blob.extend_from_slice(&sw1.to_le_bytes());
    blob.extend_from_slice(&sw2.to_le_bytes());
    blob.extend_from_slice(&sw3.to_le_bytes());
    blob.extend(core::iter::repeat(0xCDu8).take(256));

    let mut sections = [FwSection {
        kind: 0, dladdr: 0, len: 0, chksum: false, redl: false, payload_off: 0,
    }; FWDL_SECTION_MAX_NUM];
    let h = match parse_v1(&blob, &mut sections) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("v1 parse failed"),
    };
    if h.version != 1 { return TestResult::Fail("v1 version"); }
    if h.section_num != 1 { return TestResult::Fail("v1 section_num"); }
    if h.fw_major != 5 || h.fw_minor != 4 { return TestResult::Fail("v1 major/minor"); }
    let s = &sections[0];
    if s.kind != 64 { return TestResult::Fail("v1 BBMCU0"); }
    if s.dladdr != 0x4000_0000 { return TestResult::Fail("v1 dladdr"); }
    if s.len != 256 { return TestResult::Fail("v1 section len"); }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_fwdl_v1_parse);

fn smoke_rtw89_fwdl_auto_detect() -> TestResult {
    let mut v0 = alloc::vec::Vec::new();
    let hdr0 = [0u32; 8];
    for w in hdr0.iter() { v0.extend_from_slice(&w.to_le_bytes()); }
    if detect_version(&v0).map_err(|_| ()) != Ok(0) { return TestResult::Fail("v0 detect"); }
    let mut v1 = alloc::vec::Vec::new();
    let mut hdr1 = [0u32; 12];
    hdr1[3] = 1 << 24;
    for w in hdr1.iter() { v1.extend_from_slice(&w.to_le_bytes()); }
    if detect_version(&v1).map_err(|_| ()) != Ok(1) { return TestResult::Fail("v1 detect"); }
    let mut sections = [FwSection {
        kind: 0, dladdr: 0, len: 0, chksum: false, redl: false, payload_off: 0,
    }; FWDL_SECTION_MAX_NUM];
    let _ = parse_auto(&v1, &mut sections);
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_fwdl_auto_detect);

fn smoke_rtw89_fwdl_packet_segment() -> TestResult {
    let mut iter = FwdlPacketIter::new(5060, FWDL_SECTION_PER_PKT_LEN);
    let p0 = iter.next().expect("p0");
    if p0.section_off != 0 || p0.len != 2020 || p0.is_last { return TestResult::Fail("pkt0"); }
    let p1 = iter.next().expect("p1");
    if p1.section_off != 2020 || p1.len != 2020 || p1.is_last { return TestResult::Fail("pkt1"); }
    let p2 = iter.next().expect("p2");
    if p2.section_off != 4040 || p2.len != 1020 || !p2.is_last { return TestResult::Fail("pkt2"); }
    if iter.next().is_some() { return TestResult::Fail("extra pkt"); }
    if packet_count(5060, 2020) != 3 { return TestResult::Fail("count(5060,2020)"); }
    if packet_count(2020, 2020) != 1 { return TestResult::Fail("exact"); }
    if packet_count(0, 2020) != 0 { return TestResult::Fail("zero"); }
    if packet_count(5060, 0) != 3 { return TestResult::Fail("default fallback"); }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_fwdl_packet_segment);

// ── Stage-8: PHY/RF init-table walker + TX power clamps ───────────

fn smoke_rtw89_phy_entry_helpers() -> TestResult {
    let w = pw(0x1000, 0xDEAD_BEEF, 0xFFFF_FFFF);
    if w.op != PhyOp::Write || w.reg != 0x1000 {
        return TestResult::Fail("pw() helper drift");
    }
    let p = pp(0x2000, 0x00000001, 0x00000001);
    if p.op != PhyOp::Poll {
        return TestResult::Fail("pp() helper drift");
    }
    let d = pd(500);
    if d.op != PhyOp::Delay || d.delay_us != 500 {
        return TestResult::Fail("pd() helper drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_phy_entry_helpers);

fn smoke_rtw89_phy_bootstrap_table_shape() -> TestResult {
    // The BB/RF bootstrap snippet must have ≥ 3 entries (WLRF write +
    // PHYREG_SET write + settle delay).
    if BB_RF_BOOTSTRAP_TABLE.len() < 3 {
        return TestResult::Fail("BB_RF_BOOTSTRAP_TABLE too short");
    }
    // First write targets WLRF.
    let first = BB_RF_BOOTSTRAP_TABLE[0];
    if first.op != PhyOp::Write {
        return TestResult::Fail("First entry not Write");
    }
    if first.reg != super::mac_init::R_AX_WLRF_CTRL {
        return TestResult::Fail("First entry not at WLRF_CTRL");
    }
    // The last entry should be a Delay.
    let last = BB_RF_BOOTSTRAP_TABLE[BB_RF_BOOTSTRAP_TABLE.len() - 1];
    if last.op != PhyOp::Delay {
        return TestResult::Fail("Last entry not Delay");
    }
    if last.delay_us == 0 {
        return TestResult::Fail("Delay entry has 0 us");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_phy_bootstrap_table_shape);

fn smoke_rtw89_txpwr_clamp() -> TestResult {
    let envelope = TxPwrByRate { rate_idx: 0, max_pwr_q1: 60 }; // +30.0 dBm
    // Target above envelope.
    if tx_pwr_clamp(100, envelope) != 60 {
        return TestResult::Fail("upper clamp wrong");
    }
    // Target below envelope.
    if tx_pwr_clamp(-100, envelope) != -60 {
        return TestResult::Fail("lower clamp wrong");
    }
    // Target inside envelope — unchanged.
    if tx_pwr_clamp(40, envelope) != 40 {
        return TestResult::Fail("inside-envelope value clipped");
    }
    // Boundary cases.
    if tx_pwr_clamp(60, envelope) != 60 {
        return TestResult::Fail("at-max should pass through");
    }
    if tx_pwr_clamp(-60, envelope) != -60 {
        return TestResult::Fail("at-min should pass through");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_txpwr_clamp);

fn smoke_rtw89_txpwr_table_size() -> TestResult {
    // AX byrate table: 12 MCS × 3 mode × 4 BW = 144 entries.
    if TXPWR_BYRATE_TABLE_SIZE != 144 {
        return TestResult::Fail("TXPWR table size != 144");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_txpwr_table_size);

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
