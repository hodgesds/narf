//! RTW89 TX descriptor (TXWD_BODY) and RX descriptor (AX_RXD) encoders
//! + H2C command header — Stage-3.
//!
//! ## TX descriptor ("TXWD body", 24 bytes)
//!
//! The AX-generation RTW89 silicon uses a 6-dword (24-byte) "TXWD body"
//! prefix on every host-submitted frame. The v1 variant (8852C) is 8
//! dwords (32 bytes); the baseline here targets the 8852A/B/8851B
//! variant (6 dwords) because those are the parts in the build targets.
//!
//! Bit-field source: Linux `rtw89/txrx.h` (~L69..L115, v6.6).
//! Fill logic: `rtw89/core.c::rtw89_core_tx_build_txwd` (~L300..L350).
//!
//! ## RX descriptor (AX RXD, 16 bytes)
//!
//! The short RXD is a 4-dword (16-byte) prefix on every inbound frame.
//! Bit-field source: `rtw89/txrx.h` (~L344..L395).
//!
//! ## H2C command header (8 bytes)
//!
//! Every Host-to-Card (H2C) command is prepended with an 8-byte header
//! built by `rtw89_h2c_pkt_set_hdr` (`rtw89/fw.c:1564`). The header
//! encodes the command category, class, function, sequence, and total
//! length.
//!
//! ## References (all GPL-2.0; NARF is GPL-2.0-or-later since 2026-05-20)
//!
//! - Linux `rtw89/txrx.h` (~L69..L115) — TXWD_BODY bit fields.
//! - Linux `rtw89/txrx.h` (~L344..L420) — AX RXD bit fields.
//! - Linux `rtw89/fw.h:4493..4500` — H2C header field masks.
//! - Linux `rtw89/fw.c:1564` — `rtw89_h2c_pkt_set_hdr`.
//! - Linux `rtw89/core.h:1047` — `struct rtw89_txwd_body` layout.
//! - Linux `rtw89/core.h:1134` — `struct rtw89_rxdesc_short` layout.

#![allow(dead_code)]

use core::convert::TryInto;

// ── TXWD_BODY bit-field constants ───────────────────────────────────
//
// Per `rtw89/txrx.h` (~L69..L115). Each dword is prefixed by its dword
// index (BODY0..BODY5).

/// TXWD_BODY0 — `RTW89_TXWD_BODY0_WD_INFO_EN`: enable TX info dword.
/// Must be set if the optional TXWD_INFO follows.
/// Linux `txrx.h:72`.
pub const TXWD_BODY0_WD_INFO_EN: u32 = 1 << 22;
/// TXWD_BODY0 — `RTW89_TXWD_BODY0_CHANNEL_DMA` shift / mask.
/// GENMASK(19, 16). Selects which PCI TX ring this frame goes to.
pub const TXWD_BODY0_CHANNEL_SHIFT: u32 = 16;
pub const TXWD_BODY0_CHANNEL_MASK: u32 = 0xF << TXWD_BODY0_CHANNEL_SHIFT;
/// TXWD_BODY0 — `RTW89_TXWD_BODY0_WD_PAGE`. BIT(7).
/// Set when the frame spans multiple TX-page descriptors.
pub const TXWD_BODY0_WD_PAGE: u32 = 1 << 7;

/// TXWD_BODY2 — `RTW89_TXWD_BODY2_MACID` shift / mask.
/// GENMASK(30, 24). Firmware-assigned MAC-ID (station index).
pub const TXWD_BODY2_MACID_SHIFT: u32 = 24;
pub const TXWD_BODY2_MACID_MASK: u32 = 0x7F << TXWD_BODY2_MACID_SHIFT;
/// TXWD_BODY2 — `RTW89_TXWD_BODY2_QSEL` shift / mask.
/// GENMASK(22, 17). TX queue selector (maps to `rtw89_tx_qsel`).
pub const TXWD_BODY2_QSEL_SHIFT: u32 = 17;
pub const TXWD_BODY2_QSEL_MASK: u32 = 0x3F << TXWD_BODY2_QSEL_SHIFT;
/// TXWD_BODY2 — `RTW89_TXWD_BODY2_TXPKT_SIZE`. GENMASK(13, 0).
/// Total packet size in bytes (802.11 header + payload, excl. TXWD).
pub const TXWD_BODY2_TXPKT_SIZE_MASK: u32 = 0x3FFF;

/// TX queue selector values (`enum rtw89_tx_qsel`).
/// `RTW89_TX_QSEL_B0_BE` — Band-0 best-effort (default data path).
/// Linux `rtw89/core.h::rtw89_tx_qsel`.
pub const QSEL_B0_BE: u8 = 0;
/// `RTW89_TX_QSEL_B0_BK` — Band-0 background.
pub const QSEL_B0_BK: u8 = 1;
/// `RTW89_TX_QSEL_B0_VI` — Band-0 video.
pub const QSEL_B0_VI: u8 = 2;
/// `RTW89_TX_QSEL_B0_VO` — Band-0 voice (highest priority data).
pub const QSEL_B0_VO: u8 = 3;
/// `RTW89_TX_QSEL_B0_MGMT` — Band-0 management.
pub const QSEL_B0_MGMT: u8 = 6;

/// Wire size of the baseline TXWD body (6 dwords = 24 bytes).
/// `sizeof(struct rtw89_txwd_body)`. Linux `rtw89/core.h:1047`.
pub const TXWD_BODY_SIZE: usize = 24;

/// Wire size of the v1 TXWD body (8 dwords = 32 bytes, used by 8852C).
/// `sizeof(struct rtw89_txwd_body_v1)`.
pub const TXWD_BODY_V1_SIZE: usize = 32;

// ── AX RXD bit-field constants ──────────────────────────────────────
//
// Per `rtw89/txrx.h` (~L344..L395). These cover the dword-0 and
// dword-3 fields that carry the packet length and error flags.

/// AX_RXD_RPKT_LEN_MASK — GENMASK(13, 0). Frame length in bytes.
pub const AX_RXD_RPKT_LEN_MASK: u32 = 0x3FFF;
/// AX_RXD_RPKT_TYPE_MASK — GENMASK(27, 24). Packet type:
///   0 = normal data, 1 = MAC info, 2 = PPDU stats, 3 = WDT, 4 = CSI.
pub const AX_RXD_RPKT_TYPE_SHIFT: u32 = 24;
pub const AX_RXD_RPKT_TYPE_MASK: u32 = 0xF << AX_RXD_RPKT_TYPE_SHIFT;
/// Packet type: normal Wi-Fi data frame.
pub const AX_RXD_RPKT_TYPE_WIFI: u32 = 0;

/// AX_RXD_CRC32_ERR — BIT(9) in dword3. FCS error flag.
pub const AX_RXD_CRC32_ERR: u32 = 1 << 9;
/// AX_RXD_ICV_ERR — BIT(10) in dword3. CCMP/TKIP ICV error.
pub const AX_RXD_ICV_ERR: u32 = 1 << 10;

/// Wire size of the short AX RXD (4 dwords = 16 bytes).
/// `sizeof(struct rtw89_rxdesc_short)`. Linux `rtw89/core.h:1134`.
pub const RXD_SHORT_SIZE: usize = 16;

// ── H2C header constants ────────────────────────────────────────────
//
// Per `rtw89/fw.h` (~L4493..L4500).

/// H2C header length in bytes. `H2C_HEADER_LEN`. Linux `fw.h:4493`.
pub const H2C_HEADER_LEN: usize = 8;

/// H2C_HDR_CAT field: GENMASK(1, 0) in dword 0.
pub const H2C_HDR_CAT_SHIFT: u32 = 0;
pub const H2C_HDR_CAT_MASK: u32 = 0x3;
/// H2C_HDR_CLASS field: GENMASK(7, 2) in dword 0.
pub const H2C_HDR_CLASS_SHIFT: u32 = 2;
pub const H2C_HDR_CLASS_MASK: u32 = 0x3F << H2C_HDR_CLASS_SHIFT;
/// H2C_HDR_FUNC field: GENMASK(15, 8) in dword 0.
pub const H2C_HDR_FUNC_SHIFT: u32 = 8;
pub const H2C_HDR_FUNC_MASK: u32 = 0xFF << H2C_HDR_FUNC_SHIFT;
/// H2C_HDR_DEL_TYPE field: GENMASK(19, 16) in dword 0.
pub const H2C_HDR_DEL_TYPE_SHIFT: u32 = 16;
pub const H2C_HDR_DEL_TYPE_MASK: u32 = 0xF << H2C_HDR_DEL_TYPE_SHIFT;
/// H2C_HDR_H2C_SEQ field: GENMASK(31, 24) in dword 0.
pub const H2C_HDR_SEQ_SHIFT: u32 = 24;
pub const H2C_HDR_SEQ_MASK: u32 = 0xFF << H2C_HDR_SEQ_SHIFT;

/// H2C_HDR_TOTAL_LEN field: GENMASK(13, 0) in dword 1.
pub const H2C_HDR_TOTAL_LEN_MASK: u32 = 0x3FFF;
/// H2C_HDR_REC_ACK: BIT(14) in dword 1. Request acknowledgement.
pub const H2C_HDR_REC_ACK: u32 = 1 << 14;
/// H2C_HDR_DONE_ACK: BIT(15) in dword 1.
pub const H2C_HDR_DONE_ACK: u32 = 1 << 15;

/// FWCMD_TYPE_H2C — delivery-type value for normal commands.
pub const FWCMD_TYPE_H2C: u8 = 0;

/// H2C_CAT_MAC — standard MAC commands category.
pub const H2C_CAT_MAC: u8 = 0x1;
/// H2C_CL_MAC_FWDL — firmware download class.
pub const H2C_CL_MAC_FWDL: u8 = 0x3;
/// H2C_FUNC_MAC_FWHDR_DL — firmware header download function.
pub const H2C_FUNC_MAC_FWHDR_DL: u8 = 0x0;

// ── TXWD_BODY encoder ────────────────────────────────────────────────

/// Inputs for building one RTW89 TXWD body.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxwdInfo {
    /// DMA channel / TX ring index (`RTW89_TXCH_*`).
    pub channel: u8,
    /// TX queue selector (`QSEL_*` constants above).
    pub qsel: u8,
    /// Firmware-assigned MAC-ID for the destination station.
    pub mac_id: u8,
    /// Packet size in bytes (802.11 payload, excluding TXWD).
    pub pkt_size: u16,
}

/// Encode a 24-byte TXWD_BODY into `out`.
///
/// Fills dwords 0, 2 with the key frame-routing fields; dwords 1, 3-5
/// are zeroed (security IV, aggregation sequence, and reserved) so the
/// firmware's defaults apply.
///
/// Reference: Linux `rtw89/core.c::rtw89_core_tx_build_txwd` (~L300).
pub fn encode_txwd(info: &TxwdInfo, out: &mut [u8]) -> Option<()> {
    if out.len() < TXWD_BODY_SIZE {
        return None;
    }
    // Dword 0: channel DMA select + WD_INFO_EN (required for the WD
    // info block that follows in the full pipeline; harmless when the
    // block is absent because it just tells the firmware to look).
    let dw0: u32 = TXWD_BODY0_WD_INFO_EN
        | ((info.channel as u32) << TXWD_BODY0_CHANNEL_SHIFT & TXWD_BODY0_CHANNEL_MASK);
    out[0..4].copy_from_slice(&dw0.to_le_bytes());

    // Dword 1: security key / address info — zeroed for unencrypted.
    out[4..8].fill(0);

    // Dword 2: MAC-ID + queue selector + packet size.
    let dw2: u32 = ((info.mac_id as u32) << TXWD_BODY2_MACID_SHIFT & TXWD_BODY2_MACID_MASK)
        | ((info.qsel as u32) << TXWD_BODY2_QSEL_SHIFT & TXWD_BODY2_QSEL_MASK)
        | (info.pkt_size as u32 & TXWD_BODY2_TXPKT_SIZE_MASK);
    out[8..12].copy_from_slice(&dw2.to_le_bytes());

    // Dwords 3-5: aggregation sequence + IV high bytes + reserved.
    out[12..TXWD_BODY_SIZE].fill(0);

    Some(())
}

// ── AX RXD decoder ──────────────────────────────────────────────────

/// Decoded fields from the 16-byte short AX RXD.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxdInfo {
    /// Received packet length in bytes.
    pub pkt_len: u16,
    /// Packet type (0 = normal Wi-Fi frame).
    pub pkt_type: u8,
    /// FCS (CRC32) error — frame should be dropped.
    pub crc32_err: bool,
    /// ICV (CCMP/TKIP MIC) error.
    pub icv_err: bool,
}

/// Decode the short AX RXD from `bytes` (must be `≥ 16`).
///
/// Reference: Linux `rtw89/txrx.h` AX_RXD_* constants + the RXD
/// parsing in `rtw89/mac.c::rtw89_mac_rx_handle_dle_state`.
pub fn decode_rxd(bytes: &[u8]) -> Option<RxdInfo> {
    if bytes.len() < RXD_SHORT_SIZE {
        return None;
    }
    let dw0 = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let dw3 = u32::from_le_bytes(bytes[12..16].try_into().ok()?);

    let pkt_len = (dw0 & AX_RXD_RPKT_LEN_MASK) as u16;
    let pkt_type = ((dw0 & AX_RXD_RPKT_TYPE_MASK) >> AX_RXD_RPKT_TYPE_SHIFT) as u8;
    let crc32_err = (dw3 & AX_RXD_CRC32_ERR) != 0;
    let icv_err = (dw3 & AX_RXD_ICV_ERR) != 0;

    Some(RxdInfo {
        pkt_len,
        pkt_type,
        crc32_err,
        icv_err,
    })
}

/// Build a 16-byte test AX RXD for a clean data frame. Used to exercise
/// `decode_rxd` without live silicon.
pub fn encode_rxd_for_test(info: &RxdInfo) -> [u8; RXD_SHORT_SIZE] {
    let mut buf = [0u8; RXD_SHORT_SIZE];
    let dw0: u32 = ((info.pkt_type as u32) << AX_RXD_RPKT_TYPE_SHIFT)
        | (info.pkt_len as u32 & AX_RXD_RPKT_LEN_MASK);
    let dw3: u32 = if info.crc32_err { AX_RXD_CRC32_ERR } else { 0 }
        | if info.icv_err { AX_RXD_ICV_ERR } else { 0 };
    buf[0..4].copy_from_slice(&dw0.to_le_bytes());
    // dwords 1-2 stay zero.
    buf[12..16].copy_from_slice(&dw3.to_le_bytes());
    buf
}

// ── H2C header encoder ───────────────────────────────────────────────

/// Build the 8-byte H2C command header into `out`.
///
/// Layout per `rtw89/fw.h` (~L4493..L4500) and
/// `rtw89/fw.c::rtw89_h2c_pkt_set_hdr` (~L1564):
///
/// ```text
/// dword 0 (bits 31-0):
///   [31-24] seq      — host-side sequence counter
///   [19-16] del_type — delivery type; 0 = H2C command
///   [15- 8] func     — command function within the class
///   [ 7- 2] class    — command class within the category
///   [ 1- 0] cat      — category (H2C_CAT_MAC = 1)
///
/// dword 1 (bits 31-0):
///   [15]    done_ack — done acknowledgement request
///   [14]    rec_ack  — receive acknowledgement request
///   [13- 0] total_len — payload len + H2C_HEADER_LEN (8)
/// ```
// Eight parameters map directly to the H2C header wire fields; grouping
// them into a struct would add churn at every call site without benefit.
#[allow(clippy::too_many_arguments)]
pub fn encode_h2c_header(
    cat: u8,
    class: u8,
    func: u8,
    seq: u8,
    payload_len: u16,
    rec_ack: bool,
    done_ack: bool,
    out: &mut [u8],
) -> Option<()> {
    if out.len() < H2C_HEADER_LEN {
        return None;
    }
    let dw0: u32 = ((seq as u32) << H2C_HDR_SEQ_SHIFT)
        | (FWCMD_TYPE_H2C as u32) << H2C_HDR_DEL_TYPE_SHIFT
        | ((func as u32) << H2C_HDR_FUNC_SHIFT)
        | ((class as u32) << H2C_HDR_CLASS_SHIFT)
        | ((cat as u32) & H2C_HDR_CAT_MASK);
    let total_len = (payload_len + H2C_HEADER_LEN as u16) as u32;
    let dw1: u32 = (total_len & H2C_HDR_TOTAL_LEN_MASK)
        | if rec_ack { H2C_HDR_REC_ACK } else { 0 }
        | if done_ack { H2C_HDR_DONE_ACK } else { 0 };
    out[0..4].copy_from_slice(&dw0.to_le_bytes());
    out[4..8].copy_from_slice(&dw1.to_le_bytes());
    Some(())
}
