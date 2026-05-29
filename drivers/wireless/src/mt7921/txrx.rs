//! MT7921 / MT7922 MAC TX descriptor (TXD) and RX descriptor (RXD)
//! encoders — Stage-3.
//!
//! ## TX descriptor (TXD)
//!
//! The CONNAC2 TXD is an 8-dword (32-byte) descriptor prepended to
//! every frame the host submits on a WFDMA TX ring. The bit-field
//! layout comes from Linux's
//! `drivers/net/wireless/mediatek/mt76/mt76_connac2_mac.h` (v6.6,
//! ~L50..L128) and the fill logic from
//! `drivers/net/wireless/mediatek/mt76/mt76_connac2_mac.c::
//! mt76_connac2_mac_write_txwi` (~L1..L90).
//!
//! This file provides a pure-data encoder that takes the key per-frame
//! fields and marshals them into the 32-byte wire layout. The DMA
//! submission path (WFDMA0 ring pointer writes) sits in the `mac.rs`
//! hardware layer and is not represented here.
//!
//! ## RX descriptor (RXD)
//!
//! The CONNAC2 RXD is a 16-byte prefix on every inbound frame. The
//! host reads these from `MT7921_RXQ_DATA` after the WFDMA RX interrupt
//! fires and uses them to determine the payload length and any error
//! conditions.
//!
//! Bit-field source: `mt76_connac2_mac.h` (~L185..L232).
//!
//! ## MCU init / STA-record commands
//!
//! `MCU_EXT_CMD_STA_REC_UPDATE` (opcode 0x25, from
//! `mt76_connac_mcu.h:1226`) registers a station entry with the
//! firmware's MAC layer. This is the minimum MCU command needed after
//! `take_driver_own` before data-path traffic can flow.
//!
//! Reference:
//!   `drivers/net/wireless/mediatek/mt76/mt76_connac_mcu.c::
//!    mt76_connac_mcu_sta_cmd` (~L1..L50)

#![allow(dead_code)]

// ── TXD bit-field constants ─────────────────────────────────────────
//
// Per Linux `mt76_connac2_mac.h` (~L50..L128). Each TXD dword index
// is prefixed with the dword number (TXD0..TXD7).

/// TXD dword 0 — queue index + packet format + byte count.
///
/// `MT_TXD0_Q_IDX`  = GENMASK(31, 25).  Queue/ring index.
/// `MT_TXD0_PKT_FMT`= GENMASK(24, 23).  Packet format:
///     0 = 802.11 (L-SIG), 1 = CT (control token), 2 = 802.3.
/// `MT_TXD0_TX_BYTES`= GENMASK(15, 0).  Total bytes (TXD + frame).
pub const TXD0_Q_IDX_SHIFT: u32 = 25;
pub const TXD0_Q_IDX_MASK: u32 = 0x7F << TXD0_Q_IDX_SHIFT;
pub const TXD0_PKT_FMT_SHIFT: u32 = 23;
pub const TXD0_PKT_FMT_MASK: u32 = 0x3 << TXD0_PKT_FMT_SHIFT;
/// Packet format: 802.3 Ethernet (the default for data frames the MCU
/// re-encaps to 802.11).
pub const TXD0_PKT_FMT_802_3: u32 = 2 << TXD0_PKT_FMT_SHIFT;
pub const TXD0_TX_BYTES_MASK: u32 = 0xFFFF;

/// TXD dword 1 — long-format flag + own-MAC + WLAN-IDX.
///
/// `MT_TXD1_LONG_FORMAT` = BIT(31).   Set for the 8-dword (long) form.
/// `MT_TXD1_OWN_MAC`     = GENMASK(29, 24). BSS / own-MAC index.
/// `MT_TXD1_WLAN_IDX`    = GENMASK(9, 0).  Per-station WLAN index.
pub const TXD1_LONG_FORMAT: u32 = 1 << 31;
pub const TXD1_OWN_MAC_SHIFT: u32 = 24;
pub const TXD1_OWN_MAC_MASK: u32 = 0x3F << TXD1_OWN_MAC_SHIFT;
pub const TXD1_WLAN_IDX_MASK: u32 = 0x3FF;

/// TXD dword 2 — fixed-rate + fragment + misc flags.
///
/// `MT_TXD2_MULTICAST` = BIT(10). Frame is multicast/broadcast.
/// `MT_TXD2_NO_NAT`    = BIT(6).  Disable NAT translation.
pub const TXD2_MULTICAST: u32 = 1 << 10;

/// TXD dword 3 — sequence + retry.
///
/// `MT_TXD3_NO_ACK`    = BIT(0).  No ACK requested (broadcast).
pub const TXD3_NO_ACK: u32 = 1 << 0;

/// TXD dword 5 — TX status reporting.
///
/// `MT_TXD5_TX_STATUS_HOST` = BIT(10). Report TX status to host.
/// `MT_TXD5_PID`            = GENMASK(7, 0). Packet-ID echo.
pub const TXD5_TX_STATUS_HOST: u32 = 1 << 10;
pub const TXD5_PID_MASK: u32 = 0xFF;

/// Wire size of the short (4-dword) TXD.
pub const TXD_SHORT_SIZE: usize = 16;
/// Wire size of the long (8-dword) TXD used for data frames.
/// `MT_TXD_SIZE`. Linux `mt76_connac.h:34`.
pub const TXD_SIZE: usize = 32;

// ── RXD bit-field constants ─────────────────────────────────────────
//
// Per Linux `mt76_connac2_mac.h` (~L185..L232).

/// RXD dword 0 — packet length + type.
///
/// `MT_RXD0_LENGTH`   = GENMASK(15, 0). Total frame length.
/// `MT_RXD0_PKT_TYPE` = GENMASK(31, 27). Type: 0=normal, 1=event.
pub const RXD0_LENGTH_MASK: u32 = 0xFFFF;
pub const RXD0_PKT_TYPE_SHIFT: u32 = 27;
pub const RXD0_PKT_TYPE_MASK: u32 = 0x1F << RXD0_PKT_TYPE_SHIFT;
/// Packet type: normal data frame.
pub const RXD0_PKT_TYPE_NORMAL: u32 = 0;
/// Packet type: MCU event frame (delivered to `RXQ_MCU_EVENT`).
pub const RXD0_PKT_TYPE_EVENT: u32 = 1 << RXD0_PKT_TYPE_SHIFT;

/// RXD dword 1 — WLAN index + security + error flags.
///
/// `MT_RXD1_NORMAL_WLAN_IDX` = GENMASK(9, 0).
/// `MT_RXD1_NORMAL_FCS_ERR`  = BIT(27). FCS error.
/// `MT_RXD1_NORMAL_ICV_ERR`  = BIT(25). ICV error.
pub const RXD1_WLAN_IDX_MASK: u32 = 0x3FF;
pub const RXD1_FCS_ERR: u32 = 1 << 27;
pub const RXD1_ICV_ERR: u32 = 1 << 25;

/// RXD dword 2 — BSSID + header offset.
///
/// `MT_RXD2_NORMAL_HDR_OFFSET` = GENMASK(15, 14).
///     0 = 0 extra bytes, 1 = 2 bytes, 2 = 6 bytes (802.3 Eth header).
pub const RXD2_HDR_OFFSET_SHIFT: u32 = 14;
pub const RXD2_HDR_OFFSET_MASK: u32 = 0x3 << RXD2_HDR_OFFSET_SHIFT;

/// Wire size of the base RXD (4 dwords = 16 bytes).
/// Per Linux `mt76_connac2_mac.h` the normal RXD is 4 dwords; extended
/// group descriptors (groups 1-5) follow but are optional.
pub const RXD_BASE_SIZE: usize = 16;

// ── MCU command opcodes ─────────────────────────────────────────────
//
// Per `mt76_connac_mcu.h`.

/// `MCU_EXT_CMD_STA_REC_UPDATE` — register / update a station record.
/// Opcode 0x25. Linux `mt76_connac_mcu.h:1226`.
pub const MCU_EXT_CMD_STA_REC_UPDATE: u8 = 0x25;

/// `MCU_CMD_PATCH_SEM_CONTROL` — patch semaphore acquire/release.
/// Opcode 0x10. Linux `mt76_connac_mcu.h:1322`.
pub const MCU_CMD_PATCH_SEM_CONTROL: u8 = 0x10;

/// `MCU_CMD_PATCH_FINISH_REQ` — signal patch download is complete.
/// Opcode 0x07. Linux `mt76_connac_mcu.h:1321`.
pub const MCU_CMD_PATCH_FINISH_REQ: u8 = 0x07;

// ── TXD encoder ─────────────────────────────────────────────────────

/// Inputs for building one MT7921 TXD.
///
/// Derived from the fields `mt76_connac2_mac_write_txwi` sets in
/// `mt76_connac2_mac.c` (~L1..L90, v6.6).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxdInfo {
    /// WFDMA TX queue index. Typically one of `MT7921_TXQ_AC_*`.
    pub q_idx: u8,
    /// Per-station WLAN index (firmware-assigned). 0 for broadcast.
    pub wlan_idx: u16,
    /// BSS / own-MAC index (0 for the default STA interface).
    pub own_mac_idx: u8,
    /// Total frame byte count (includes TXD itself).
    pub tx_bytes: u16,
    /// Frame is multicast / broadcast (disables ACK).
    pub is_mcast: bool,
    /// Packet-ID for TX-status correlation.
    pub pid: u8,
}

/// Encode a TXD into `out` (must be `≥ TXD_SIZE` = 32 bytes).
///
/// The 8-dword long form (`MT_TXD1_LONG_FORMAT`) is always used for
/// data frames. Dwords 4-7 are reserved/zeroed at this stage — the
/// rate-selection and security fields are filled by the firmware or
/// set by the TX-info follow-up.
///
/// Reference: Linux `mt76_connac2_mac.c::mt76_connac2_mac_write_txwi`
/// (~L1..L90).
pub fn encode_txd(info: &TxdInfo, out: &mut [u8]) -> Option<()> {
    if out.len() < TXD_SIZE {
        return None;
    }
    // Dword 0: queue index + 802.3 packet format + byte count.
    let dw0: u32 = ((info.q_idx as u32) << TXD0_Q_IDX_SHIFT) & TXD0_Q_IDX_MASK
        | TXD0_PKT_FMT_802_3
        | ((info.tx_bytes as u32) & TXD0_TX_BYTES_MASK);
    out[0..4].copy_from_slice(&dw0.to_le_bytes());

    // Dword 1: long-format flag + own-MAC + wlan-idx.
    let dw1: u32 = TXD1_LONG_FORMAT
        | (((info.own_mac_idx as u32) << TXD1_OWN_MAC_SHIFT) & TXD1_OWN_MAC_MASK)
        | ((info.wlan_idx as u32) & TXD1_WLAN_IDX_MASK);
    out[4..8].copy_from_slice(&dw1.to_le_bytes());

    // Dword 2: multicast flag if applicable.
    let dw2: u32 = if info.is_mcast { TXD2_MULTICAST } else { 0 };
    out[8..12].copy_from_slice(&dw2.to_le_bytes());

    // Dword 3: NO_ACK for multicast frames (no ACK expected).
    let dw3: u32 = if info.is_mcast { TXD3_NO_ACK } else { 0 };
    out[12..16].copy_from_slice(&dw3.to_le_bytes());

    // Dword 4-4: reserved (PN low — only used for encrypted frames).
    out[16..20].fill(0);

    // Dword 5: TX status reporting + PID.
    let dw5: u32 = TXD5_TX_STATUS_HOST | ((info.pid as u32) & TXD5_PID_MASK);
    out[20..24].copy_from_slice(&dw5.to_le_bytes());

    // Dwords 6-7: rate / BW overrides. Leave at 0 so firmware chooses.
    out[24..TXD_SIZE].fill(0);

    Some(())
}

// ── RXD decoder ─────────────────────────────────────────────────────

/// Decoded fields from the 16-byte base RXD.
///
/// The host reads this from `MT7921_RXQ_DATA` after the DMA interrupt,
/// uses `frame_len` to locate the payload in the DMA buffer, and checks
/// the error bits before handing the frame upward.
///
/// Reference: Linux `mt76_connac2_mac.c::mt7921_mac_decode_rx_desc`
/// and the RXD field layout in `mt76_connac2_mac.h` (~L185..L232).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxdInfo {
    /// Total length of the received frame payload in bytes.
    pub frame_len: u16,
    /// Packet type: 0 = normal data, 1 = MCU event.
    pub pkt_type: u8,
    /// WLAN index (station that sent the frame).
    pub wlan_idx: u16,
    /// FCS error — frame should be dropped.
    pub fcs_err: bool,
    /// ICV (MIC/CCMP) error — encrypted frame failed integrity check.
    pub icv_err: bool,
}

/// Decode the base RXD from `bytes` (must be `≥ RXD_BASE_SIZE` = 16
/// bytes).
///
/// Returns `None` if the slice is too short.
pub fn decode_rxd(bytes: &[u8]) -> Option<RxdInfo> {
    if bytes.len() < RXD_BASE_SIZE {
        return None;
    }
    let dw0 = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let dw1 = u32::from_le_bytes(bytes[4..8].try_into().ok()?);

    let frame_len = (dw0 & RXD0_LENGTH_MASK) as u16;
    let pkt_type = ((dw0 & RXD0_PKT_TYPE_MASK) >> RXD0_PKT_TYPE_SHIFT) as u8;
    let wlan_idx = (dw1 & RXD1_WLAN_IDX_MASK) as u16;
    let fcs_err = (dw1 & RXD1_FCS_ERR) != 0;
    let icv_err = (dw1 & RXD1_ICV_ERR) != 0;

    Some(RxdInfo {
        frame_len,
        pkt_type,
        wlan_idx,
        fcs_err,
        icv_err,
    })
}

/// Build the minimal 16-byte RXD byte pattern for a clean data frame
/// of the given length and wlan index. Used in round-trip tests to
/// exercise the decoder without live silicon.
pub fn encode_rxd_for_test(info: &RxdInfo) -> [u8; RXD_BASE_SIZE] {
    let mut buf = [0u8; RXD_BASE_SIZE];
    let dw0: u32 = ((info.pkt_type as u32) << RXD0_PKT_TYPE_SHIFT)
        | (info.frame_len as u32 & RXD0_LENGTH_MASK);
    let dw1: u32 = (info.wlan_idx as u32 & RXD1_WLAN_IDX_MASK)
        | if info.fcs_err { RXD1_FCS_ERR } else { 0 }
        | if info.icv_err { RXD1_ICV_ERR } else { 0 };
    buf[0..4].copy_from_slice(&dw0.to_le_bytes());
    buf[4..8].copy_from_slice(&dw1.to_le_bytes());
    // dwords 2-3 stay zeroed (BSSID / HDR_OFFSET / etc.).
    buf
}

// ── MCU STA-record command encoder ──────────────────────────────────

/// Wire size of the minimal `STA_REC_UPDATE` MCU command payload.
/// The actual command carries a much larger structure on Linux; the
/// NARF baseline ships only the 8-byte opcode header + 4-byte tag/len.
/// Full station-record payloads land with the association path.
pub const STA_REC_CMD_SIZE: usize = 12;

/// Build the minimal `MCU_EXT_CMD_STA_REC_UPDATE` command payload.
///
/// Layout (12 bytes, all LE):
///
/// ```text
///   byte 0:    opcode = MCU_EXT_CMD_STA_REC_UPDATE (0x25)
///   bytes 1-3: reserved (must be zero)
///   bytes 4-7: WLAN index (u32 LE)
///   bytes 8-11: tag bitmap (u32 LE) — 0 = minimal (no cipher / BA setup)
/// ```
///
/// Reference: Linux `mt76_connac_mcu.c::mt76_connac_mcu_sta_cmd`
/// (~L1..L50). The full command is up to 256 bytes; this 12-byte form
/// is the baseline "register station exists, no crypto" entry.
pub fn encode_sta_rec_update(wlan_idx: u16, out: &mut [u8]) -> Option<()> {
    if out.len() < STA_REC_CMD_SIZE {
        return None;
    }
    out[0] = MCU_EXT_CMD_STA_REC_UPDATE;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4..8].copy_from_slice(&(wlan_idx as u32).to_le_bytes());
    out[8..STA_REC_CMD_SIZE].fill(0); // tag bitmap = 0
    Some(())
}

use core::convert::TryInto;
