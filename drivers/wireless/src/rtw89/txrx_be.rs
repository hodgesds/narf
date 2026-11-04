// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! BE-generation TX descriptor (TXWD_BODY_V2) and RX descriptor
//! (RXDESC_SHORT_V2) codecs for RTL8922A.
//!
//! Mirrors the AX codecs in `txrx.rs`, with the BE layouts from Linux
//! `rtw89/txrx.h` (torvalds/linux @ cbbddb6). The TXWD body v2 is 8
//! dwords (32 bytes, `core.h:1121`); the short RXD v2 is 6 dwords
//! (24 bytes, `core.h:1199`, and `chip_8922a::H2C_DESC_SIZE`).
//!
//! Bit-field source: `txrx.h:154..246` (BE TXD) and `txrx.h:490..560`
//! (BE RXD dword0..dword5). The BE TXWD fill in Linux `core.c` uses
//! the `_V1` dword-2 fields (QSEL_V1, TID_IND_V1, MACID_V1); the
//! un-suffixed dword-2 fields are the AX positions and are NOT used
//! here. RXD dword4 (PPDU rate report) belongs to the PHY-status path
//! and is intentionally not decoded by the short parser; RXD dword6+
//! belong to the long descriptor only.

use core::convert::TryInto;

// ── BE TXWD body v2 (8 dwords) ───────────────────────────────────────

/// BE TXWD body v2 size in bytes (`chip_8922a::TXWD_BODY_SIZE`).
pub(super) const TXWD_BODY_V2_SIZE: usize = 32;

/// BODY0 `WDINFO_EN` bit 22: enable the TXWD_INFO block that follows.
/// Set by this body-only codec, as the AX codec does; the transport
/// clears it when no info block follows.
pub(super) const BODY0_WDINFO_EN: u32 = 1 << 22;
/// BODY0 `CH_DMA` bits 19..16.
pub(super) const BODY0_CH_DMA_SHIFT: u32 = 16;
/// BODY0 `CH_DMA` mask.
pub(super) const BODY0_CH_DMA_MASK: u32 = 0xF << BODY0_CH_DMA_SHIFT;
/// BODY2 `TXPKTSIZE` bits 13..0.
pub(super) const BODY2_TXPKTSIZE_MASK: u32 = 0x3FFF;
/// BODY2 `QSEL_V1` bits 20..15.
pub(super) const BODY2_QSEL_V1_SHIFT: u32 = 15;
/// BODY2 `QSEL_V1` mask.
pub(super) const BODY2_QSEL_V1_MASK: u32 = 0x3F << BODY2_QSEL_V1_SHIFT;
/// BODY2 `MACID_V1` bits 31..22.
pub(super) const BODY2_MACID_V1_SHIFT: u32 = 22;
/// BODY2 `MACID_V1` mask.
pub(super) const BODY2_MACID_V1_MASK: u32 = 0x3FF << BODY2_MACID_V1_SHIFT;

/// Routing fields for one BE TXWD body, mirroring `txrx::TxwdInfo`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) struct TxwdBeInfo {
    /// DMA channel / TX ring index.
    pub(super) channel: u8,
    /// TX queue selector (BE `QSEL_V1` field).
    pub(super) qsel: u8,
    /// Firmware-assigned MAC-ID for the destination station.
    pub(super) mac_id: u16,
    /// Packet size in bytes (802.11 payload, excluding TXWD).
    pub(super) pkt_size: u16,
}

/// Encode a 32-byte BE TXWD_BODY_V2 into `out`.
///
/// Fills dwords 0 and 2 with the routing fields; the rest are zeroed
/// (aggregation sequence, security IV, rate selection, and reserved),
/// so the firmware's defaults apply — same contract as the AX codec.
/// This body-only codec is not a complete PCI submission.
pub(super) fn encode_txwd_be(info: &TxwdBeInfo, out: &mut [u8]) -> Option<()> {
    if out.len() < TXWD_BODY_V2_SIZE {
        return None;
    }
    let dw0: u32 =
        BODY0_WDINFO_EN | ((info.channel as u32) << BODY0_CH_DMA_SHIFT & BODY0_CH_DMA_MASK);
    out[0..4].copy_from_slice(&dw0.to_le_bytes());
    // Dword 1: aggregation / security — zeroed for unencrypted.
    out[4..8].fill(0);
    // Dword 2: packet size + queue selector + MAC-ID (all _V1 fields).
    let dw2: u32 = (info.pkt_size as u32 & BODY2_TXPKTSIZE_MASK)
        | ((info.qsel as u32) << BODY2_QSEL_V1_SHIFT & BODY2_QSEL_V1_MASK)
        | ((info.mac_id as u32) << BODY2_MACID_V1_SHIFT & BODY2_MACID_V1_MASK);
    out[8..12].copy_from_slice(&dw2.to_le_bytes());
    // Dwords 3-7: sequence, checksum, IV, rate — zeroed.
    out[12..TXWD_BODY_V2_SIZE].fill(0);
    Some(())
}

// ── BE RXD short v2 (6 dwords) ───────────────────────────────────────

/// BE RXD short v2 size in bytes (`chip_8922a::H2C_DESC_SIZE`).
pub(super) const RXD_SHORT_V2_SIZE: usize = 24;

/// Dword0 `RPKT_LEN` bits 13..0.
const RXD_D0_RPKT_LEN_MASK: u32 = 0x3FFF;
/// Dword0 `SHIFT` bits 15..14.
const RXD_D0_SHIFT_SHIFT: u32 = 14;
/// Dword0 `SHIFT` mask.
const RXD_D0_SHIFT_MASK: u32 = 0x3 << RXD_D0_SHIFT_SHIFT;
/// Dword0 `DRV_INFO_SZ` bits 19..18.
const RXD_D0_DRV_INFO_SZ_SHIFT: u32 = 18;
/// Dword0 `DRV_INFO_SZ` mask.
const RXD_D0_DRV_INFO_SZ_MASK: u32 = 0x3 << RXD_D0_DRV_INFO_SZ_SHIFT;
/// Dword0 `HDR_CNV_SZ` bits 21..20.
const RXD_D0_HDR_CNV_SZ_SHIFT: u32 = 20;
/// Dword0 `HDR_CNV_SZ` mask.
const RXD_D0_HDR_CNV_SZ_MASK: u32 = 0x3 << RXD_D0_HDR_CNV_SZ_SHIFT;
/// Dword0 `PHY_RPT_SZ` bits 23..22.
const RXD_D0_PHY_RPT_SZ_SHIFT: u32 = 22;
/// Dword0 `PHY_RPT_SZ` mask.
const RXD_D0_PHY_RPT_SZ_MASK: u32 = 0x3 << RXD_D0_PHY_RPT_SZ_SHIFT;
/// Dword0 `RPKT_TYPE` bits 29..24.
const RXD_D0_RPKT_TYPE_SHIFT: u32 = 24;
/// Dword0 `RPKT_TYPE` mask.
const RXD_D0_RPKT_TYPE_MASK: u32 = 0x3F << RXD_D0_RPKT_TYPE_SHIFT;
/// Dword2 `MAC_ID_V1` bits 9..0.
const RXD_D2_MAC_ID_V1_MASK: u32 = 0x3FF;
/// Dword2 `LAST_MSDU` bit 12.
const RXD_D2_LAST_MSDU: u32 = 1 << 12;
/// Dword2 `AMSDU_CUT` bit 13.
const RXD_D2_AMSDU_CUT: u32 = 1 << 13;
/// Dword2 `REORDER` bit 15.
const RXD_D2_REORDER: u32 = 1 << 15;
/// Dword2 `SEQ` bits 27..16.
const RXD_D2_SEQ_SHIFT: u32 = 16;
/// Dword2 `SEQ` mask.
const RXD_D2_SEQ_MASK: u32 = 0xFFF << RXD_D2_SEQ_SHIFT;
/// Dword2 `TID` bits 31..28.
const RXD_D2_TID_SHIFT: u32 = 28;
/// Dword2 `TID` mask.
const RXD_D2_TID_MASK: u32 = 0xF << RXD_D2_TID_SHIFT;
/// Dword3 `CRC32_ERR` bit 6.
const RXD_D3_CRC32_ERR: u32 = 1 << 6;
/// Dword3 `ICV_ERR` bit 7.
const RXD_D3_ICV_ERR: u32 = 1 << 7;
/// Dword3 `HW_DEC` bit 8.
const RXD_D3_HW_DEC: u32 = 1 << 8;
/// Dword3 `SW_DEC` bit 9.
const RXD_D3_SW_DEC: u32 = 1 << 9;
/// Dword3 `A1_MATCH` bit 10.
const RXD_D3_A1_MATCH: u32 = 1 << 10;
/// Dword3 `AMPDU` bit 11.
const RXD_D3_AMPDU: u32 = 1 << 11;

/// Decoded fields from the 24-byte short BE RXD, mirroring
/// `txrx::RxdInfo` extended with the fields the RX path needs to walk
/// the buffer (driver-info / header-conversion / PHY-report sizes) and
/// to reorder (MAC-ID, sequence, TID).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) struct RxdBeInfo {
    /// Received packet length in bytes.
    pub(super) pkt_len: u16,
    /// Packet type (0 = normal Wi-Fi frame).
    pub(super) pkt_type: u8,
    /// RXD shift: offset of the packet data within the buffer.
    pub(super) shift: u8,
    /// Driver-info size in dwords (prefix after the RXD itself).
    pub(super) drv_info_sz: u8,
    /// Header-conversion size in dwords.
    pub(super) hdr_cnv_sz: u8,
    /// PHY-report size in dwords.
    pub(super) phy_rpt_sz: u8,
    /// MAC-ID of the source station (BE `MAC_ID_V1` field).
    pub(super) mac_id: u16,
    /// Last MSDU of an A-MSDU.
    pub(super) last_msdu: bool,
    /// A-MSDU cut flag.
    pub(super) amsdu_cut: bool,
    /// Reorder required for this frame.
    pub(super) reorder: bool,
    /// 802.11 sequence number.
    pub(super) seq: u16,
    /// Traffic identifier.
    pub(super) tid: u8,
    /// FCS (CRC32) error — frame should be dropped.
    pub(super) crc32_err: bool,
    /// ICV (CCMP/TKIP MIC) error.
    pub(super) icv_err: bool,
    /// Hardware-decrypted.
    pub(super) hw_dec: bool,
    /// Software-decrypted.
    pub(super) sw_dec: bool,
    /// Address-1 matched this device.
    pub(super) a1_match: bool,
    /// Part of an A-MPDU.
    pub(super) ampdu: bool,
    /// Free-running counter (dword5, whole word).
    pub(super) freerun_cnt: u32,
}

/// Decode the short BE RXD from `bytes` (must be `>= 24`).
///
/// Reference: Linux `txrx.h` BE_RXD_* constants, dword0..dword5, plus
/// the RXD parsing in `rtw89/core.c` (which consumes the short v2
/// layout for BE chips).
pub(super) fn decode_rxd_be(bytes: &[u8]) -> Option<RxdBeInfo> {
    if bytes.len() < RXD_SHORT_V2_SIZE {
        return None;
    }
    let dw0 = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let dw2 = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    let dw3 = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
    let dw5 = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
    Some(RxdBeInfo {
        pkt_len: (dw0 & RXD_D0_RPKT_LEN_MASK) as u16,
        pkt_type: ((dw0 & RXD_D0_RPKT_TYPE_MASK) >> RXD_D0_RPKT_TYPE_SHIFT) as u8,
        shift: ((dw0 & RXD_D0_SHIFT_MASK) >> RXD_D0_SHIFT_SHIFT) as u8,
        drv_info_sz: ((dw0 & RXD_D0_DRV_INFO_SZ_MASK) >> RXD_D0_DRV_INFO_SZ_SHIFT) as u8,
        hdr_cnv_sz: ((dw0 & RXD_D0_HDR_CNV_SZ_MASK) >> RXD_D0_HDR_CNV_SZ_SHIFT) as u8,
        phy_rpt_sz: ((dw0 & RXD_D0_PHY_RPT_SZ_MASK) >> RXD_D0_PHY_RPT_SZ_SHIFT) as u8,
        mac_id: (dw2 & RXD_D2_MAC_ID_V1_MASK) as u16,
        last_msdu: dw2 & RXD_D2_LAST_MSDU != 0,
        amsdu_cut: dw2 & RXD_D2_AMSDU_CUT != 0,
        reorder: dw2 & RXD_D2_REORDER != 0,
        seq: ((dw2 & RXD_D2_SEQ_MASK) >> RXD_D2_SEQ_SHIFT) as u16,
        tid: ((dw2 & RXD_D2_TID_MASK) >> RXD_D2_TID_SHIFT) as u8,
        crc32_err: dw3 & RXD_D3_CRC32_ERR != 0,
        icv_err: dw3 & RXD_D3_ICV_ERR != 0,
        hw_dec: dw3 & RXD_D3_HW_DEC != 0,
        sw_dec: dw3 & RXD_D3_SW_DEC != 0,
        a1_match: dw3 & RXD_D3_A1_MATCH != 0,
        ampdu: dw3 & RXD_D3_AMPDU != 0,
        freerun_cnt: dw5,
    })
}
