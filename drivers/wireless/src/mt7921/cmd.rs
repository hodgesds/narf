//! MT7921 MCU command body encoders — Stages 8/9/10.
//!
//! Stage-3 covered the bare `STA_REC_UPDATE` 12-byte body. This module
//! adds the wire layouts for the MCU init sequence + the vif setup +
//! channel switch + the auth/assoc TX framing that Stage-11 needs.
//!
//! ## Stage-8: MCU init cmd sequence
//!
//! - `MCU_EXT_CMD_PM_STATE_CTRL` — set the on-chip MCU's power state
//!   (Linux `mt76_connac_pm_state_ctrl`). Body: `{ pm_state: u8,
//!   pm_mode: u8 }`.
//! - `MCU_EXT_CMD_INIT_RA_CFG` — initialise the rate-adaptation
//!   config. Body: per-PHY rate-table indices + bandwidth.
//! - `MCU_UNI_CMD_DEV_INFO_UPDATE` — device-info update (UNI variant
//!   used by mt7921 firmware). Body: omac_idx + active + own_mac +
//!   band_idx (mirrors `struct dev_info`).
//!
//! ## Stage-9: MAC vif setup
//!
//! - `MCU_EXT_CMD_DEV_INFO_UPDATE` — non-UNI variant.
//! - `MCU_EXT_CMD_BSS_INFO_UPDATE` — BSS-info (TLV stream).
//! - `MCU_EXT_CMD_STA_REC_UPDATE` — Stage-3 12-byte body, extended
//!   here with the auth-method tag for Stage-11.
//!
//! ## Stage-10: Channel switch
//!
//! - `MCU_EXT_CMD_CHANNEL_SWITCH` body — primary channel, bandwidth,
//!   tx-streams, rx-streams.
//!
//! ## References (all GPL-2.0)
//!
//! - `mt76_connac_mcu.c::mt76_connac_mcu_set_deep_sleep` (~L1500)
//!   — `MCU_EXT_CMD_PM_STATE_CTRL` body shape.
//! - `mt76_connac_mcu.c::mt76_connac_mcu_uni_add_dev` (~L1100)
//!   — `MCU_UNI_CMD_DEV_INFO_UPDATE` TLV stream.
//! - `mt76_connac_mcu.c::mt76_connac_mcu_bss_basic_tlv` (~L1180)
//!   — `BSS_INFO_BASIC` TLV.
//! - `mt76_connac_mcu.c::mt76_connac_mcu_sta_basic_tlv` (~L1670)
//!   — `STA_REC_BASIC` TLV.
//! - `mt76_connac_mcu.c::mt7921_mcu_set_channel_domain` /
//!   `mt76_connac_mcu_set_chan_info` — channel switch body.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use super::regs::*;

// ── PM_STATE_CTRL ────────────────────────────────────────────────

/// Power state values (Linux `mt76_connac_mcu.c::pm_state` enum).
pub const PM_STATE_ACTIVE: u8 = 0;
pub const PM_STATE_DOZE: u8 = 1;
pub const PM_STATE_DEEP_SLEEP: u8 = 2;

/// PM_STATE_CTRL body — 8 bytes.
///
/// Linux `mt76_connac_mcu_set_deep_sleep` packs `pm_state` + `pm_mode`
/// + 6 reserved bytes. We model it as a simple LE-encoded struct.
pub const PM_STATE_CTRL_SIZE: usize = 8;

pub fn encode_pm_state_ctrl(pm_state: u8, pm_mode: u8, out: &mut [u8]) -> Option<()> {
    if out.len() < PM_STATE_CTRL_SIZE {
        return None;
    }
    out[0] = pm_state;
    out[1] = pm_mode;
    for b in &mut out[2..PM_STATE_CTRL_SIZE] {
        *b = 0;
    }
    Some(())
}

// ── INIT_RA_CFG ──────────────────────────────────────────────────

/// `MCU_EXT_CMD_INIT_RA_CFG` body — 16 bytes.
///
/// `{ band: u8, phy_type: u8, sgi: u8, ht_amsdu: u8, stbc: u8,
///    bw: u8, ldpc: u8, max_rate: u32 LE, rsv: u8[4] }`.
///
/// `band` = 0 for the primary 2.4/5 GHz band on mt7921 (single-band
/// silicon at the host visibility).
pub const INIT_RA_CFG_SIZE: usize = 16;

pub fn encode_init_ra_cfg(
    band: u8,
    phy_type: u8,
    sgi: bool,
    ht_amsdu: bool,
    stbc: bool,
    bw: u8,
    ldpc: bool,
    max_rate: u32,
    out: &mut [u8],
) -> Option<()> {
    if out.len() < INIT_RA_CFG_SIZE {
        return None;
    }
    out[0] = band;
    out[1] = phy_type;
    out[2] = sgi as u8;
    out[3] = ht_amsdu as u8;
    out[4] = stbc as u8;
    out[5] = bw;
    out[6] = ldpc as u8;
    out[7] = 0;
    out[8..12].copy_from_slice(&max_rate.to_le_bytes());
    for b in &mut out[12..INIT_RA_CFG_SIZE] {
        *b = 0;
    }
    Some(())
}

// ── UNI DEV_INFO_UPDATE (Stage-8 + Stage-9 dual-use) ─────────────

/// `MCU_UNI_CMD_DEV_INFO_UPDATE` header — 4 bytes opcode + 4 bytes
/// padding + N TLV-encoded options.
pub const UNI_DEV_INFO_HDR_SIZE: usize = 8;
/// One UNI TLV: `{ tag: u16 LE, len: u16 LE, data[len-4] }`.
pub const UNI_TLV_HDR_SIZE: usize = 4;
/// `UNI_DEV_INFO_TAG_ACTIVE` — toggle the device active. Linux
/// `mt76_connac_mcu.c::mt76_connac_mcu_uni_add_dev` (~L1100).
pub const UNI_DEV_INFO_TAG_ACTIVE: u16 = 0x00;
/// `UNI_DEV_INFO_TAG_INFO` — set the own-MAC + omac index.
pub const UNI_DEV_INFO_TAG_INFO: u16 = 0x01;

/// Build the UNI DEV_INFO_UPDATE body. Two TLVs:
///
///   - ACTIVE TLV (tag 0): `{ active: u8, dbdc: u8, rsv: u8[2] }`
///     — 4 data bytes, 4 hdr = 8 bytes total.
///   - INFO TLV (tag 1): `{ omac_idx: u8, band_idx: u8, rsv: u8[2],
///     own_mac: u8[6], rsv: u8[2] }` — 12 data bytes, 4 hdr = 16
///     bytes total.
///
/// Total body: 4 (hdr) + 8 + 16 = 28 bytes.
pub const UNI_DEV_INFO_BODY_SIZE: usize = UNI_DEV_INFO_HDR_SIZE + 8 + 16;

pub fn encode_uni_dev_info_update(
    omac_idx: u8,
    band_idx: u8,
    active: bool,
    own_mac: [u8; MAC_ADDR_LEN],
    out: &mut [u8],
) -> Option<()> {
    if out.len() < UNI_DEV_INFO_BODY_SIZE {
        return None;
    }
    // Header (8 bytes): { bss_idx: u8, rsv: u8[3], opcode_pad: u8[4] }.
    out[0] = 0; // bss_idx
    for b in &mut out[1..UNI_DEV_INFO_HDR_SIZE] {
        *b = 0;
    }

    // ACTIVE TLV at offset 8.
    let mut p = UNI_DEV_INFO_HDR_SIZE;
    out[p..p + 2].copy_from_slice(&UNI_DEV_INFO_TAG_ACTIVE.to_le_bytes());
    out[p + 2..p + 4].copy_from_slice(&8u16.to_le_bytes()); // len = 8 (TLV total)
    out[p + 4] = active as u8;
    out[p + 5] = 0; // dbdc
    out[p + 6] = 0;
    out[p + 7] = 0;
    p += 8;

    // INFO TLV at offset 16.
    out[p..p + 2].copy_from_slice(&UNI_DEV_INFO_TAG_INFO.to_le_bytes());
    out[p + 2..p + 4].copy_from_slice(&16u16.to_le_bytes()); // len = 16
    out[p + 4] = omac_idx;
    out[p + 5] = band_idx;
    out[p + 6] = 0;
    out[p + 7] = 0;
    out[p + 8..p + 8 + MAC_ADDR_LEN].copy_from_slice(&own_mac);
    out[p + 8 + MAC_ADDR_LEN] = 0;
    out[p + 8 + MAC_ADDR_LEN + 1] = 0;
    Some(())
}

// ── DEV_INFO_UPDATE (legacy ext-cmd) ─────────────────────────────

/// `MCU_EXT_CMD_DEV_INFO_UPDATE` body — 16 bytes.
///
/// Linux `mt76_connac_mcu_set_dev_info` packs `{ tag: u16, len: u16,
/// active: u8, dbdc: u8, omac_idx: u8, rsv: u8, own_mac: u8[6],
/// rsv: u8[2] }`.
pub const DEV_INFO_UPDATE_SIZE: usize = 16;

pub fn encode_dev_info_update(
    omac_idx: u8,
    active: bool,
    own_mac: [u8; MAC_ADDR_LEN],
    out: &mut [u8],
) -> Option<()> {
    if out.len() < DEV_INFO_UPDATE_SIZE {
        return None;
    }
    out[0..2].copy_from_slice(&UNI_DEV_INFO_TAG_INFO.to_le_bytes()); // tag
    out[2..4].copy_from_slice(&(DEV_INFO_UPDATE_SIZE as u16).to_le_bytes()); // len
    out[4] = active as u8;
    out[5] = 0; // dbdc
    out[6] = omac_idx;
    out[7] = 0;
    out[8..8 + MAC_ADDR_LEN].copy_from_slice(&own_mac);
    out[8 + MAC_ADDR_LEN] = 0;
    out[8 + MAC_ADDR_LEN + 1] = 0;
    Some(())
}

// ── BSS_INFO_UPDATE / BSS_INFO_BASIC ─────────────────────────────

/// `BSS_INFO_BASIC` TLV tag.
pub const BSS_INFO_TAG_BASIC: u16 = 0x00;

/// `BSS_INFO_BASIC` TLV body — 28 bytes.
/// `{ network_type: u32 LE, active: u8, omac_idx: u8, hw_bss_idx: u8,
///    band_idx: u8, bssid: u8[6], bcn_interval: u16 LE,
///    dtim_period: u8, phy_mode: u8, sta_idx: u16 LE, conn_state: u8,
///    rsv: u8[5] }`.
pub const BSS_INFO_BASIC_DATA_SIZE: usize = 28;
pub const BSS_INFO_BASIC_TLV_SIZE: usize = 4 + BSS_INFO_BASIC_DATA_SIZE;

/// Network-type values per `mt76_connac_mcu.h`:
pub const NETWORK_TYPE_INFRA: u32 = 0x02;
pub const NETWORK_TYPE_ADHOC: u32 = 0x04;

/// Phy-mode values (mt76_connac_mcu.h):
pub const PHY_MODE_HE: u8 = 0x40;
pub const PHY_MODE_VHT: u8 = 0x20;
pub const PHY_MODE_HT: u8 = 0x10;
pub const PHY_MODE_OFDM: u8 = 0x04;
pub const PHY_MODE_CCK: u8 = 0x01;

/// Build the `BSS_INFO_BASIC` TLV (the only TLV Stage-9 needs).
pub fn encode_bss_info_basic_tlv(
    network_type: u32,
    omac_idx: u8,
    band_idx: u8,
    bssid: [u8; MAC_ADDR_LEN],
    bcn_interval: u16,
    dtim_period: u8,
    phy_mode: u8,
    sta_idx: u16,
    active: bool,
    out: &mut [u8],
) -> Option<()> {
    if out.len() < BSS_INFO_BASIC_TLV_SIZE {
        return None;
    }
    out[0..2].copy_from_slice(&BSS_INFO_TAG_BASIC.to_le_bytes());
    out[2..4].copy_from_slice(&(BSS_INFO_BASIC_TLV_SIZE as u16).to_le_bytes());
    out[4..8].copy_from_slice(&network_type.to_le_bytes());
    out[8] = active as u8;
    out[9] = omac_idx;
    out[10] = 0; // hw_bss_idx
    out[11] = band_idx;
    out[12..18].copy_from_slice(&bssid);
    out[18..20].copy_from_slice(&bcn_interval.to_le_bytes());
    out[20] = dtim_period;
    out[21] = phy_mode;
    out[22..24].copy_from_slice(&sta_idx.to_le_bytes());
    out[24] = 0; // conn_state
    for b in &mut out[25..BSS_INFO_BASIC_TLV_SIZE] {
        *b = 0;
    }
    Some(())
}

// ── STA_REC_UPDATE (extended for auth) ───────────────────────────

/// `STA_REC_BASIC` TLV tag.
pub const STA_REC_TAG_BASIC: u16 = 0x00;
/// `STA_REC_WTBL` TLV tag (wireless table — drives the firmware's
/// AES-CCMP key state for the station).
pub const STA_REC_TAG_WTBL: u16 = 0x01;

/// `STA_REC_BASIC` TLV body — 28 bytes.
/// `{ conn_type: u32 LE, conn_state: u8, qos: u8, aid: u16 LE,
///    peer_addr: u8[6], extra_info: u16 LE, dtim_period: u8,
///    rsv: u8[3], phy_mode: u8, sta_idx: u16 LE, rsv2: u8[5] }`.
pub const STA_REC_BASIC_DATA_SIZE: usize = 28;
pub const STA_REC_BASIC_TLV_SIZE: usize = 4 + STA_REC_BASIC_DATA_SIZE;

/// Connection types.
pub const CONN_TYPE_STA_INFRA: u32 = 0x01;
pub const CONN_TYPE_AP_INFRA: u32 = 0x02;

/// Connection states.
pub const CONN_STATE_PORT_SECURE: u8 = 0x02;
pub const CONN_STATE_DISCONNECT: u8 = 0x00;

pub fn encode_sta_rec_basic_tlv(
    conn_type: u32,
    conn_state: u8,
    aid: u16,
    peer_addr: [u8; MAC_ADDR_LEN],
    phy_mode: u8,
    sta_idx: u16,
    qos: bool,
    out: &mut [u8],
) -> Option<()> {
    if out.len() < STA_REC_BASIC_TLV_SIZE {
        return None;
    }
    out[0..2].copy_from_slice(&STA_REC_TAG_BASIC.to_le_bytes());
    out[2..4].copy_from_slice(&(STA_REC_BASIC_TLV_SIZE as u16).to_le_bytes());
    out[4..8].copy_from_slice(&conn_type.to_le_bytes());
    out[8] = conn_state;
    out[9] = qos as u8;
    out[10..12].copy_from_slice(&aid.to_le_bytes());
    out[12..18].copy_from_slice(&peer_addr);
    out[18..20].copy_from_slice(&0u16.to_le_bytes()); // extra_info
    out[20] = 0; // dtim_period
    out[21] = 0;
    out[22] = 0;
    out[23] = 0;
    out[24] = phy_mode;
    out[25..27].copy_from_slice(&sta_idx.to_le_bytes());
    for b in &mut out[27..STA_REC_BASIC_TLV_SIZE] {
        *b = 0;
    }
    Some(())
}

// ── CHANNEL_SWITCH ───────────────────────────────────────────────

/// `MCU_EXT_CMD_CHANNEL_SWITCH` body — 32 bytes.
///
/// Layout per Linux `mt76_connac_mcu_set_chan_info` (`mt76_connac_mcu.c`
/// ~L1640):
///
/// ```c
/// struct mcu_ext_channel_switch {
///     u8 dbdc_idx;
///     u8 control_chan;
///     u8 center_chan;
///     u8 bw;
///     u8 tx_streams;
///     u8 rx_streams;
///     u8 ss_type;
///     u8 center_chan2;
///     __le16 ext_pa;
///     u8 outband_freq;
///     u8 ack_mode;
///     u8 band;
///     u8 cmd_mode;
///     u8 rsv[3];
///     u8 channel_band;
///     __le32 ht_op_info;
///     __le16 he_op_info;
///     u8 rsv2[6];
/// };
/// ```
///
/// We model the active subset (channel + bandwidth + streams + band)
/// — the firmware fills in derived fields.
pub const CHANNEL_SWITCH_SIZE: usize = 32;

/// Bandwidth values.
pub const CH_BW_20: u8 = 0;
pub const CH_BW_40: u8 = 1;
pub const CH_BW_80: u8 = 2;
pub const CH_BW_160: u8 = 3;
pub const CH_BW_5: u8 = 4;
pub const CH_BW_10: u8 = 5;

/// Band values.
pub const CH_BAND_24G: u8 = 0;
pub const CH_BAND_5G: u8 = 1;
pub const CH_BAND_6G: u8 = 2;

pub fn encode_channel_switch(
    control_chan: u8,
    center_chan: u8,
    bw: u8,
    tx_streams: u8,
    rx_streams: u8,
    band: u8,
    out: &mut [u8],
) -> Option<()> {
    if out.len() < CHANNEL_SWITCH_SIZE {
        return None;
    }
    out[0] = 0; // dbdc_idx
    out[1] = control_chan;
    out[2] = center_chan;
    out[3] = bw;
    out[4] = tx_streams;
    out[5] = rx_streams;
    out[6] = 0; // ss_type
    out[7] = 0; // center_chan2
    out[8..10].copy_from_slice(&0u16.to_le_bytes()); // ext_pa
    out[10] = 0; // outband_freq
    out[11] = 0; // ack_mode
    out[12] = band;
    out[13] = 0; // cmd_mode
    for b in &mut out[14..16] {
        *b = 0;
    }
    out[16] = band; // channel_band (repeated)
    out[17..20].fill(0);
    out[20..24].copy_from_slice(&0u32.to_le_bytes()); // ht_op_info
    out[24..26].copy_from_slice(&0u16.to_le_bytes()); // he_op_info
    out[26..CHANNEL_SWITCH_SIZE].fill(0);
    Some(())
}

// ── Aggregate helpers ────────────────────────────────────────────

/// Build the canonical Stage-10 channel-switch body for the default
/// 5 GHz channel (ch36 / 5180 MHz / 20 MHz BW / 2 stream).
pub fn encode_default_channel_switch(out: &mut [u8]) -> Option<()> {
    encode_channel_switch(
        MT7921_DEFAULT_CHAN_5G,
        MT7921_DEFAULT_CHAN_5G,
        CH_BW_20,
        2,
        2,
        CH_BAND_5G,
        out,
    )
}

// ── 802.11 MGMT TX framing (Stage-11) ────────────────────────────
//
// Auth + assoc frames piggy-back on the regular TXD path with the
// packet-format set to 802.11 (not 802.3). Stage-11 builds the
// 802.11 MAC header + a trivial payload and submits it on the BMC
// ring (queue 4) so it bypasses the per-station rate fallback.

/// 802.11 MGMT frame control: type=Management (0), subtype=Auth (11).
pub const FC_MGMT_AUTH: u16 = (0 << 2) | (11 << 4);
/// 802.11 MGMT frame control: type=Management, subtype=AssocReq (0).
pub const FC_MGMT_ASSOC_REQ: u16 = (0 << 2) | (0 << 4);
/// 802.11 MGMT frame control: type=Management, subtype=AssocResp (1).
pub const FC_MGMT_ASSOC_RESP: u16 = (0 << 2) | (1 << 4);
/// 802.11 MGMT frame control: type=Management, subtype=Beacon (8).
pub const FC_MGMT_BEACON: u16 = (0 << 2) | (8 << 4);
/// 802.11 MGMT frame control: type=Data, subtype=QoS Data (8).
pub const FC_DATA_QOS: u16 = (2 << 2) | (8 << 4);

/// 802.11 MAC header size for a non-QoS MGMT frame (no addr4).
pub const IEEE80211_MAC_HDR_SIZE: usize = 24;

/// Build an 802.11 MGMT MAC header.
///
/// Layout: `{ fc: u16 LE, duration: u16 LE, addr1: u8[6] (DA),
///   addr2: u8[6] (SA), addr3: u8[6] (BSSID), seq_ctrl: u16 LE }`.
pub fn encode_ieee80211_mgmt_hdr(
    fc: u16,
    da: [u8; MAC_ADDR_LEN],
    sa: [u8; MAC_ADDR_LEN],
    bssid: [u8; MAC_ADDR_LEN],
    seq: u16,
    out: &mut [u8],
) -> Option<()> {
    if out.len() < IEEE80211_MAC_HDR_SIZE {
        return None;
    }
    out[0..2].copy_from_slice(&fc.to_le_bytes());
    out[2..4].copy_from_slice(&0u16.to_le_bytes()); // duration
    out[4..10].copy_from_slice(&da);
    out[10..16].copy_from_slice(&sa);
    out[16..22].copy_from_slice(&bssid);
    // seq_ctrl: low 4 bits frag (0), high 12 bits seq.
    out[22..24].copy_from_slice(&((seq & 0x0FFF) << 4).to_le_bytes());
    Some(())
}

/// Build an Open-system Auth frame (sequence 1, no auth challenge).
///
/// Payload after the MAC header: `{ algo: u16 LE = 0 (Open),
/// seq: u16 LE = 1, status: u16 LE = 0 }` — 6 bytes.
pub const IEEE80211_AUTH_PAYLOAD_SIZE: usize = 6;
pub const IEEE80211_AUTH_FRAME_SIZE: usize =
    IEEE80211_MAC_HDR_SIZE + IEEE80211_AUTH_PAYLOAD_SIZE;

pub fn encode_open_auth_frame(
    sta: [u8; MAC_ADDR_LEN],
    bssid: [u8; MAC_ADDR_LEN],
    out: &mut [u8],
) -> Option<()> {
    if out.len() < IEEE80211_AUTH_FRAME_SIZE {
        return None;
    }
    encode_ieee80211_mgmt_hdr(FC_MGMT_AUTH, bssid, sta, bssid, 0, out)?;
    let p = IEEE80211_MAC_HDR_SIZE;
    out[p..p + 2].copy_from_slice(&0u16.to_le_bytes()); // algo: Open
    out[p + 2..p + 4].copy_from_slice(&1u16.to_le_bytes()); // seq: 1
    out[p + 4..p + 6].copy_from_slice(&0u16.to_le_bytes()); // status: success
    Some(())
}

/// Build an Association Request frame.
///
/// Payload after the MAC header: `{ cap: u16 LE, listen_interval: u16
/// LE, SSID IE, supported rates IE }`. We accept an inline SSID and
/// emit a minimal frame with no rate IE (firmware fills the rates).
pub fn encode_assoc_req_frame(
    sta: [u8; MAC_ADDR_LEN],
    bssid: [u8; MAC_ADDR_LEN],
    capability: u16,
    listen_interval: u16,
    ssid: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let fixed = IEEE80211_MAC_HDR_SIZE + 2 + 2 + 2 + ssid.len();
    if out.len() < fixed {
        return None;
    }
    encode_ieee80211_mgmt_hdr(FC_MGMT_ASSOC_REQ, bssid, sta, bssid, 0, out)?;
    let mut p = IEEE80211_MAC_HDR_SIZE;
    out[p..p + 2].copy_from_slice(&capability.to_le_bytes());
    p += 2;
    out[p..p + 2].copy_from_slice(&listen_interval.to_le_bytes());
    p += 2;
    // SSID IE: { id: u8 = 0, len: u8, octets[len] }.
    out[p] = 0; // element id: SSID
    out[p + 1] = ssid.len() as u8;
    out[p + 2..p + 2 + ssid.len()].copy_from_slice(ssid);
    p += 2 + ssid.len();
    Some(p)
}

// ── WPA2-PSK / WPA3-SAE handshake stubs (Stage-12) ───────────────
//
// Real EAPOL-key handshake lives in `narf-wireless::eapol`. Stage-12
// surfaces the cipher-suite selectors that the STA_REC TLV stream
// needs to flag the connection as encrypted.

/// CCMP-128 cipher suite OUI: 00-0F-AC-04.
pub const CIPHER_CCMP_128_OUI: [u8; 4] = [0x00, 0x0F, 0xAC, 0x04];
/// WPA2-PSK AKM suite OUI: 00-0F-AC-02.
pub const AKM_PSK_OUI: [u8; 4] = [0x00, 0x0F, 0xAC, 0x02];
/// WPA3-SAE AKM suite OUI: 00-0F-AC-08.
pub const AKM_SAE_OUI: [u8; 4] = [0x00, 0x0F, 0xAC, 0x08];

/// Per-station crypto state passed into STA_REC_WTBL.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StaCipher {
    /// No encryption (open auth path).
    None,
    /// AES-CCMP-128 (WPA2-PSK).
    Ccmp128,
    /// AES-CCMP-128 with SAE-derived PMK (WPA3-SAE).
    Ccmp128Sae,
}

impl StaCipher {
    /// The wire byte the WTBL TLV uses to identify the cipher.
    /// Per Linux `mt76_connac_mcu.h` MT_CIPHER_* enum.
    pub const fn as_wire(self) -> u8 {
        match self {
            StaCipher::None => 0,
            StaCipher::Ccmp128 => 6,
            StaCipher::Ccmp128Sae => 6, // CCMP-128 with PMK derived via SAE
        }
    }

    /// `true` if the cipher requires a PMK / EAPOL handshake before
    /// the data path opens.
    pub const fn needs_eapol(self) -> bool {
        matches!(self, StaCipher::Ccmp128 | StaCipher::Ccmp128Sae)
    }
}

/// Build the STA_REC_WTBL TLV body for the given cipher.
///
/// TLV layout: `{ tag: u16 = 1, len: u16, cipher: u8, key_id: u8,
///   rsv: u8[2], key: u8[16] }` — total 24 bytes.
pub const STA_REC_WTBL_TLV_SIZE: usize = 24;

pub fn encode_sta_rec_wtbl_tlv(
    cipher: StaCipher,
    key_id: u8,
    key: &[u8],
    out: &mut [u8],
) -> Option<()> {
    if out.len() < STA_REC_WTBL_TLV_SIZE {
        return None;
    }
    out[0..2].copy_from_slice(&STA_REC_TAG_WTBL.to_le_bytes());
    out[2..4].copy_from_slice(&(STA_REC_WTBL_TLV_SIZE as u16).to_le_bytes());
    out[4] = cipher.as_wire();
    out[5] = key_id;
    out[6] = 0;
    out[7] = 0;
    let k = key.len().min(16);
    out[8..8 + k].copy_from_slice(&key[..k]);
    for b in &mut out[8 + k..STA_REC_WTBL_TLV_SIZE] {
        *b = 0;
    }
    Some(())
}

// ── Aggregate STA_REC builder for the join path ─────────────────

/// Build the combined STA_REC body used at the start of the assoc
/// path: BASIC TLV + WTBL TLV for the cipher.
///
/// Returns the byte length written.
pub fn build_sta_rec_body_for_join(
    aid: u16,
    peer_addr: [u8; MAC_ADDR_LEN],
    sta_idx: u16,
    phy_mode: u8,
    cipher: StaCipher,
    key_id: u8,
    key: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let need = STA_REC_BASIC_TLV_SIZE + STA_REC_WTBL_TLV_SIZE;
    if out.len() < need {
        return None;
    }
    encode_sta_rec_basic_tlv(
        CONN_TYPE_STA_INFRA,
        if cipher == StaCipher::None {
            CONN_STATE_PORT_SECURE
        } else {
            CONN_STATE_DISCONNECT
        },
        aid,
        peer_addr,
        phy_mode,
        sta_idx,
        true,
        &mut out[..STA_REC_BASIC_TLV_SIZE],
    )?;
    encode_sta_rec_wtbl_tlv(
        cipher,
        key_id,
        key,
        &mut out[STA_REC_BASIC_TLV_SIZE..STA_REC_BASIC_TLV_SIZE + STA_REC_WTBL_TLV_SIZE],
    )?;
    Some(need)
}

// ── Convenience: vec-returning encoders for tests ────────────────

pub fn build_default_channel_switch_vec() -> Vec<u8> {
    let mut v = alloc::vec![0u8; CHANNEL_SWITCH_SIZE];
    let _ = encode_default_channel_switch(&mut v);
    v
}

pub fn build_default_open_auth_vec(
    sta: [u8; MAC_ADDR_LEN],
    bssid: [u8; MAC_ADDR_LEN],
) -> Vec<u8> {
    let mut v = alloc::vec![0u8; IEEE80211_AUTH_FRAME_SIZE];
    let _ = encode_open_auth_frame(sta, bssid, &mut v);
    v
}
