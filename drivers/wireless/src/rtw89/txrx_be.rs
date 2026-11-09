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

// ── BE TXWD_INFO EHT fields ───────────────────────────────────────────
//
// The EHT contribution to the BE TXWD_INFO block (`struct
// rtw89_txwd_info_v2`, 8 dwords, `core.h:1141`): only the two EHT
// fields, as (info4 bits, info7 bits), for the future BE transport
// fill to OR into its complete info block. Linux's v2/v3 fill
// (`core.c::rtw89_core_fill_txdesc_v2/v3`) programs info0/1/2 and
// info4 = RTS_EN + HW_RTS_EN only, leaving info7 unfilled in this
// kernel — so these EHT bits have no Linux fill site to copy, and
// this function encodes exactly the txrx.h positions with
// caller-supplied values instead of inventing trigger conditions.
// Composition contract: [`fill_txwd_info_v2`] is the complete
// info-block fill — it ORs these bits into its info4/info7
// alongside the RTS and UL fields, and the transport keeps
// BODY0_WDINFO_EN cleared until a complete info block follows,
// as today (see `tx_8922a::build_header_with_info`).

/// BE TXWD_INFO dword 4 `SW_EHT_NLTF_SWITCH` bit 20 (`txrx.h:307`).
pub(super) const INFO4_SW_EHT_NLTF_SWITCH: u32 = 1 << 20;
/// BE TXWD_INFO dword 4 `SW_EHT_NLTF` bits 22:21 (`txrx.h:308`).
pub(super) const INFO4_SW_EHT_NLTF_MASK: u32 = 0x3 << 21;
/// BE TXWD_INFO dword 7 `UL_EHT_USR_PRES` bit 16 (`txrx.h:336`).
pub(super) const INFO7_UL_EHT_USR_PRES: u32 = 1 << 16;

/// TXWD_INFO v2 block size in bytes (`chip_8922a::TXWD_INFO_SIZE`).
pub(super) const TXWD_INFO_V2_SIZE: usize = 32;

// ── BE TXWD_INFO v2 fill ────────────────────────────────────────────
//
// The complete info-block fill, mirroring Linux
// `rtw89_core_fill_txdesc_v2` (`core.c:1849..1876`, torvalds/linux
// @ cbbddb6) with the EHT bits from `eht_info_fields` OR'd into
// info4/info7. Linux fills info0/1/2/4 only and leaves
// info3/5/6/7 zero (info7 has no Linux fill site — the EHT bit
// is this tree's only info7 contribution, as in `eht.rs`);
// this fill does the same, so a zeroed info block is the
// documented default for every field the caller does not set.

/// BE TXWD_INFO dword 0 `DATA_STBC` bit 12 (`txrx.h:254`).
pub(super) const INFO0_DATA_STBC: u32 = 1 << 12;
/// BE TXWD_INFO dword 0 `DATA_LDPC` bit 11 (`txrx.h:253`).
pub(super) const INFO0_DATA_LDPC: u32 = 1 << 11;
/// BE TXWD_INFO dword 0 `DISDATAFB` bit 10 (`txrx.h:252`).
pub(super) const INFO0_DISDATAFB: u32 = 1 << 10;
/// BE TXWD_INFO dword 0 `MULTIPORT_ID` bits 6:4 (`txrx.h:250`).
pub(super) const INFO0_MULTIPORT_ID_SHIFT: u32 = 4;
/// BE TXWD_INFO dword 0 `MULTIPORT_ID` mask.
pub(super) const INFO0_MULTIPORT_ID_MASK: u32 = 0x7 << INFO0_MULTIPORT_ID_SHIFT;
/// BE TXWD_INFO dword 0 `DATA_TXCNT_LMT_SEL` bit 22 (`txrx.h:256`).
pub(super) const INFO0_DATA_TXCNT_LMT_SEL: u32 = 1 << 22;
/// BE TXWD_INFO dword 0 `DATA_TXCNT_LMT` bits 21:16 (`txrx.h:255`).
pub(super) const INFO0_DATA_TXCNT_LMT_SHIFT: u32 = 16;
/// BE TXWD_INFO dword 0 `DATA_TXCNT_LMT` mask.
pub(super) const INFO0_DATA_TXCNT_LMT_MASK: u32 = 0x3F << INFO0_DATA_TXCNT_LMT_SHIFT;
/// BE TXWD_INFO dword 1 `MAX_AGG_NUM` bits 7:0 (`txrx.h:262`).
pub(super) const INFO1_MAX_AGG_NUM_MASK: u32 = 0xFF;
/// BE TXWD_INFO dword 1 `A_CTRL_BSR` bit 14 (`txrx.h:266`).
pub(super) const INFO1_A_CTRL_BSR: u32 = 1 << 14;
/// BE TXWD_INFO dword 1 `DATA_RTY_LOWEST_RATE` bits 27:16
/// (`txrx.h:268`).
pub(super) const INFO1_DATA_RTY_LOWEST_RATE_SHIFT: u32 = 16;
/// BE TXWD_INFO dword 1 `DATA_RTY_LOWEST_RATE` mask.
pub(super) const INFO1_DATA_RTY_LOWEST_RATE_MASK: u32 = 0xFFF << INFO1_DATA_RTY_LOWEST_RATE_SHIFT;
/// BE TXWD_INFO dword 1 `SW_DEFINE` bits 31:28 (`txrx.h:269`).
pub(super) const INFO1_SW_DEFINE_SHIFT: u32 = 28;
/// BE TXWD_INFO dword 1 `SW_DEFINE` mask.
pub(super) const INFO1_SW_DEFINE_MASK: u32 = 0xF << INFO1_SW_DEFINE_SHIFT;
/// BE TXWD_INFO dword 2 `AMPDU_DENSITY` bits 20:18 (`txrx.h:278`).
pub(super) const INFO2_AMPDU_DENSITY_SHIFT: u32 = 18;
/// BE TXWD_INFO dword 2 `AMPDU_DENSITY` mask.
pub(super) const INFO2_AMPDU_DENSITY_MASK: u32 = 0x7 << INFO2_AMPDU_DENSITY_SHIFT;
/// BE TXWD_INFO dword 2 `FORCE_KEY_EN` bit 8 (`txrx.h:273`).
pub(super) const INFO2_FORCE_KEY_EN: u32 = 1 << 8;
/// BE TXWD_INFO dword 2 `SEC_CAM_IDX` bits 7:0 (`txrx.h:272`).
pub(super) const INFO2_SEC_CAM_IDX_MASK: u32 = 0xFF;
/// BE TXWD_INFO dword 2 `SPE_RPT_V1` bit 30 (`txrx.h:281`).
pub(super) const INFO2_SPE_RPT_V1: u32 = 1 << 30;
/// BE TXWD_INFO dword 4 `RTS_EN` bit 27 (`txrx.h:310`).
pub(super) const INFO4_RTS_EN: u32 = 1 << 27;
/// BE TXWD_INFO dword 4 `HW_RTS_EN` bit 31 (`txrx.h:312`).
pub(super) const INFO4_HW_RTS_EN: u32 = 1 << 31;

/// Inputs for one BE TXWD_INFO v2 block, mirroring the
/// `struct rtw89_tx_desc_info` fields
/// `rtw89_core_fill_txdesc_v2` reads (`core.c:1798..1867`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TxwdInfoV2 {
    /// STBC for this frame (info0 `DATA_STBC`).
    pub(super) stbc: bool,
    /// LDPC for this frame (info0 `DATA_LDPC`).
    pub(super) ldpc: bool,
    /// Disable data-rate fallback (info0 `DISDATAFB`).
    pub(super) dis_data_fb: bool,
    /// Multi-port id, 0..=7 (info0 `MULTIPORT_ID`).
    pub(super) port: u8,
    /// TX-count-limit select (info0 `DATA_TXCNT_LMT_SEL`).
    pub(super) tx_cnt_lmt_en: bool,
    /// TX-count limit, 0..=63 (info0 `DATA_TXCNT_LMT`).
    pub(super) tx_cnt_lmt: u8,
    /// Maximum A-MPDU aggregation (info1 `MAX_AGG_NUM`).
    pub(super) ampdu_num: u8,
    /// A-Control BSR present (info1 `A_CTRL_BSR`).
    pub(super) a_ctrl_bsr: bool,
    /// Lowest rate for data retries, 0..=4095 (info1
    /// `DATA_RTY_LOWEST_RATE`).
    pub(super) data_retry_lowest_rate: u16,
    /// Software sequence number, 0..=15 (info1 `SW_DEFINE`).
    pub(super) sn: u8,
    /// A-MPDU density, 0..=7 (info2 `AMPDU_DENSITY`).
    pub(super) ampdu_density: u8,
    /// Force key encryption (info2 `FORCE_KEY_EN`).
    pub(super) sec_en: bool,
    /// Security CAM index, 0..=255 (info2 `SEC_CAM_IDX`).
    pub(super) sec_cam_idx: u16,
    /// Special report request (info2 `SPE_RPT_V1`).
    pub(super) report: bool,
    /// Broadcast/multicast frame: `RTS_EN` is the negation of
    /// this (`core.c:1858`, `rts_en = !desc_info->is_bmc`).
    pub(super) is_bmc: bool,
    /// EHT software-NLTF switch (info4, via `eht_info_fields`).
    pub(super) nltf_switch: bool,
    /// EHT software-NLTF value, 0..=3 (info4).
    pub(super) nltf: u8,
    /// UL EHT user present (info7, via `eht_info_fields`).
    pub(super) ul_eht_usr_pres: bool,
}

impl Default for TxwdInfoV2 {
    /// All-zero info block (unicast, no EHT overrides): the
    /// fail-closed default — only `HW_RTS_EN` (always 1) and
    /// `RTS_EN` (unicast) are set by the fill itself.
    fn default() -> Self {
        Self {
            stbc: false,
            ldpc: false,
            dis_data_fb: false,
            port: 0,
            tx_cnt_lmt_en: false,
            tx_cnt_lmt: 0,
            ampdu_num: 0,
            a_ctrl_bsr: false,
            data_retry_lowest_rate: 0,
            sn: 0,
            ampdu_density: 0,
            sec_en: false,
            sec_cam_idx: 0,
            report: false,
            is_bmc: false,
            nltf_switch: false,
            nltf: 0,
            ul_eht_usr_pres: false,
        }
    }
}

/// Fill a 32-byte BE TXWD_INFO v2 block from `info`, mirroring
/// Linux `rtw89_core_fill_txdesc_v2` info0/1/2/4 plus the EHT
/// bits. `None` when a field overflows its wire width or `out`
/// is short — never truncated. Dwords 3/5/6 are zero (Linux
/// leaves them unfilled); dword 7 carries only the EHT UL-user
/// bit.
pub(super) fn fill_txwd_info_v2(info: &TxwdInfoV2, out: &mut [u8]) -> Option<()> {
    if out.len() < TXWD_INFO_V2_SIZE
        || info.port > 7
        || info.tx_cnt_lmt > 0x3F
        || info.data_retry_lowest_rate > 0xFFF
        || info.sn > 0xF
        || info.ampdu_density > 7
        || info.sec_cam_idx > 0xFF
    {
        return None;
    }
    let (eht4, eht7) = eht_info_fields(info.nltf_switch, info.nltf, info.ul_eht_usr_pres)?;
    let mut dw0: u32 = 0;
    if info.stbc {
        dw0 |= INFO0_DATA_STBC;
    }
    if info.ldpc {
        dw0 |= INFO0_DATA_LDPC;
    }
    if info.dis_data_fb {
        dw0 |= INFO0_DISDATAFB;
    }
    dw0 |= ((info.port as u32) << INFO0_MULTIPORT_ID_SHIFT) & INFO0_MULTIPORT_ID_MASK;
    if info.tx_cnt_lmt_en {
        dw0 |= INFO0_DATA_TXCNT_LMT_SEL;
    }
    dw0 |= ((info.tx_cnt_lmt as u32) << INFO0_DATA_TXCNT_LMT_SHIFT) & INFO0_DATA_TXCNT_LMT_MASK;
    let mut dw1: u32 = (info.ampdu_num as u32) & INFO1_MAX_AGG_NUM_MASK;
    if info.a_ctrl_bsr {
        dw1 |= INFO1_A_CTRL_BSR;
    }
    dw1 |= ((info.data_retry_lowest_rate as u32) << INFO1_DATA_RTY_LOWEST_RATE_SHIFT)
        & INFO1_DATA_RTY_LOWEST_RATE_MASK;
    dw1 |= ((info.sn as u32) << INFO1_SW_DEFINE_SHIFT) & INFO1_SW_DEFINE_MASK;
    let mut dw2: u32 = 0;
    dw2 |= ((info.ampdu_density as u32) << INFO2_AMPDU_DENSITY_SHIFT) & INFO2_AMPDU_DENSITY_MASK;
    if info.sec_en {
        dw2 |= INFO2_FORCE_KEY_EN;
    }
    dw2 |= (info.sec_cam_idx as u32) & INFO2_SEC_CAM_IDX_MASK;
    if info.report {
        dw2 |= INFO2_SPE_RPT_V1;
    }
    let mut dw4: u32 = INFO4_HW_RTS_EN | eht4;
    if !info.is_bmc {
        dw4 |= INFO4_RTS_EN;
    }
    out[0..4].copy_from_slice(&dw0.to_le_bytes());
    out[4..8].copy_from_slice(&dw1.to_le_bytes());
    out[8..12].copy_from_slice(&dw2.to_le_bytes());
    out[12..16].fill(0);
    out[16..20].copy_from_slice(&dw4.to_le_bytes());
    out[20..28].fill(0);
    out[28..32].copy_from_slice(&eht7.to_le_bytes());
    Some(())
}

/// EHT field contribution to the BE TXWD_INFO block: the info4
/// software-NLTF bits and the info7 UL-EHT-user bit for one frame.
/// `nltf` is the 2-bit software NLTF value; `None` when it does not
/// fit (fail-closed: no truncated NLTF value is ever encoded).
/// Firmware honors the NLTF value when the switch bit is set; the
/// bits are encoded as given either way, and the fail-closed
/// default (switch off, NLTF 0, no UL user) yields (0, 0).
pub(super) const fn eht_info_fields(
    nltf_switch: bool,
    nltf: u8,
    ul_eht_usr_pres: bool,
) -> Option<(u32, u32)> {
    if nltf > 3 {
        return None;
    }
    let mut info4: u32 = 0;
    if nltf_switch {
        info4 |= INFO4_SW_EHT_NLTF_SWITCH;
    }
    info4 |= ((nltf as u32) << 21) & INFO4_SW_EHT_NLTF_MASK;
    let info7: u32 = if ul_eht_usr_pres {
        INFO7_UL_EHT_USR_PRES
    } else {
        0
    };
    Some((info4, info7))
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
