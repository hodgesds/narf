//! RTW89 channel set + JOININFO H2C payload — Stage-9.
//!
//! Two related pieces:
//!
//! 1. **JOININFO payload encoder** — `rtw89_fw_h2c_join_info`
//!    (fw.c:4953) packs the per-STA association into one (or two)
//!    dwords addressed by the per-field GENMASKs in fw.h:1815..1827.
//!    The driver fires this on every assoc / disconnect.
//!
//! 2. **Channel selector** — Wi-Fi 6/6E supports 2.4 / 5 / 6 GHz bands.
//!    `rtw89/chan.h::enum rtw89_band` enumerates them. We provide a
//!    map from operating freq (MHz) → (band, ch_num) and the default
//!    `5180 MHz` (5 GHz channel 36) for the live-test path.
//!
//! ## References (all GPL-2.0)
//!
//! - Linux `rtw89/fw.h:1805..1827` — `rtw89_h2c_join` + field masks.
//! - Linux `rtw89/fw.c:4953..5046` — `rtw89_fw_h2c_join_info` builder.
//! - Linux `rtw89/chan.h::enum rtw89_band` — band enumeration.

#![allow(dead_code)]

// ── JOININFO W0 field constants ─────────────────────────────────────

/// `RTW89_H2C_JOININFO_W0_MACID` — bits[7:0]. Per-STA MAC index.
/// `fw.h:1815`.
pub const JOININFO_W0_MACID_MASK: u32 = 0xFF;
/// `RTW89_H2C_JOININFO_W0_OP` — bit 8. 1 = disconnect.
pub const JOININFO_W0_OP: u32 = 1 << 8;
/// `RTW89_H2C_JOININFO_W0_BAND` — bit 9. 0 = band 0, 1 = band 1.
pub const JOININFO_W0_BAND: u32 = 1 << 9;
/// `RTW89_H2C_JOININFO_W0_WMM` — bits[11:10]. `fw.h:1818`.
pub const JOININFO_W0_WMM_SHIFT: u32 = 10;
pub const JOININFO_W0_WMM_MASK: u32 = 0x3 << JOININFO_W0_WMM_SHIFT;
/// `RTW89_H2C_JOININFO_W0_TGR` — bit 12. Triggered-uplink capable.
pub const JOININFO_W0_TGR: u32 = 1 << 12;
/// `RTW89_H2C_JOININFO_W0_ISHESTA` — bit 13. STA is HE-capable.
pub const JOININFO_W0_ISHESTA: u32 = 1 << 13;
/// `RTW89_H2C_JOININFO_W0_PORT_ID` — bits[23:21]. `fw.h:1824`.
pub const JOININFO_W0_PORT_ID_SHIFT: u32 = 21;
pub const JOININFO_W0_PORT_ID_MASK: u32 = 0x7 << JOININFO_W0_PORT_ID_SHIFT;
/// `RTW89_H2C_JOININFO_W0_NET_TYPE` — bits[25:24]. `fw.h:1825`.
pub const JOININFO_W0_NET_TYPE_SHIFT: u32 = 24;
pub const JOININFO_W0_NET_TYPE_MASK: u32 = 0x3 << JOININFO_W0_NET_TYPE_SHIFT;
/// `RTW89_H2C_JOININFO_W0_WIFI_ROLE` — bits[29:26]. `fw.h:1826`.
pub const JOININFO_W0_WIFI_ROLE_SHIFT: u32 = 26;
pub const JOININFO_W0_WIFI_ROLE_MASK: u32 = 0xF << JOININFO_W0_WIFI_ROLE_SHIFT;
/// `RTW89_H2C_JOININFO_W0_SELF_ROLE` — bits[31:30]. `fw.h:1827`.
pub const JOININFO_W0_SELF_ROLE_SHIFT: u32 = 30;
pub const JOININFO_W0_SELF_ROLE_MASK: u32 = 0x3 << JOININFO_W0_SELF_ROLE_SHIFT;

// ── Net-type enumeration ────────────────────────────────────────────
//
// Per `rtw89/core.h::enum rtw89_net_type`.

/// Not connected.
pub const NET_TYPE_NO_LINK: u8 = 0;
/// IBSS / ad-hoc.
pub const NET_TYPE_AD_HOC: u8 = 1;
/// STA / infra (connected to AP).
pub const NET_TYPE_INFRA: u8 = 2;
/// SoftAP / hosting mode.
pub const NET_TYPE_AP_MODE: u8 = 3;

// ── Self-role enumeration ───────────────────────────────────────────
//
// Per `rtw89/core.h::enum rtw89_self_role`.

/// No role yet (used during transition).
pub const SELF_ROLE_NONE: u8 = 0;
/// Acting as a client.
pub const SELF_ROLE_CLIENT: u8 = 1;
/// Acting as an AP.
pub const SELF_ROLE_AP: u8 = 2;
/// Client of our own SoftAP (used by `RTW89_SELF_ROLE_AP_CLIENT`).
pub const SELF_ROLE_AP_CLIENT: u8 = 3;

// ── WiFi-role enumeration ───────────────────────────────────────────
//
// Per `rtw89/core.h::enum rtw89_wifi_role`. We pin the values we care
// about for assoc.

/// Station/Client role.
pub const WIFI_ROLE_STATION: u8 = 0;
/// AP role.
pub const WIFI_ROLE_AP: u8 = 1;

// ── JOININFO encoder ────────────────────────────────────────────────

/// Encoded JOININFO inputs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct JoinInfo {
    /// Per-STA MAC index. Comes from `rtw89_sta_link::mac_id`.
    pub mac_id: u8,
    /// `true` = disconnect (clears the STA), `false` = associate.
    pub disconnect: bool,
    /// Which band (0 or 1) the link lives on.
    pub band: u8,
    /// Triggered-uplink capable.
    pub trigger: bool,
    /// STA is HE-capable.
    pub is_hesta: bool,
    /// Port id (0..7).
    pub port_id: u8,
    /// Net type (see `NET_TYPE_*`).
    pub net_type: u8,
    /// Wi-Fi role (see `WIFI_ROLE_*`).
    pub wifi_role: u8,
    /// Self-role (see `SELF_ROLE_*`).
    pub self_role: u8,
}

impl JoinInfo {
    /// Default for assoc: STA client on band 0, port 0, infra mode,
    /// WiFi role station, self-role client.
    pub const fn for_assoc(mac_id: u8) -> Self {
        Self {
            mac_id,
            disconnect: false,
            band: 0,
            trigger: false,
            is_hesta: true, // we drive 11ax silicon
            port_id: 0,
            net_type: NET_TYPE_INFRA,
            wifi_role: WIFI_ROLE_STATION,
            self_role: SELF_ROLE_CLIENT,
        }
    }

    /// Default for disconnect.
    pub const fn for_disconnect(mac_id: u8) -> Self {
        Self {
            mac_id,
            disconnect: true,
            band: 0,
            trigger: false,
            is_hesta: false,
            port_id: 0,
            net_type: NET_TYPE_NO_LINK,
            wifi_role: WIFI_ROLE_STATION,
            self_role: SELF_ROLE_NONE,
        }
    }

    /// Encode into the 4-byte W0 payload dword (the only one the AX
    /// path uses; BE extends to W1+W2 — that's Stage-10 work).
    pub const fn encode_w0(&self) -> u32 {
        let mut w: u32 = self.mac_id as u32 & JOININFO_W0_MACID_MASK;
        if self.disconnect {
            w |= JOININFO_W0_OP;
        }
        if self.band != 0 {
            w |= JOININFO_W0_BAND;
        }
        if self.trigger {
            w |= JOININFO_W0_TGR;
        }
        if self.is_hesta {
            w |= JOININFO_W0_ISHESTA;
        }
        w |= ((self.port_id as u32) << JOININFO_W0_PORT_ID_SHIFT) & JOININFO_W0_PORT_ID_MASK;
        w |= ((self.net_type as u32) << JOININFO_W0_NET_TYPE_SHIFT) & JOININFO_W0_NET_TYPE_MASK;
        w |= ((self.wifi_role as u32) << JOININFO_W0_WIFI_ROLE_SHIFT) & JOININFO_W0_WIFI_ROLE_MASK;
        w |= ((self.self_role as u32) << JOININFO_W0_SELF_ROLE_SHIFT) & JOININFO_W0_SELF_ROLE_MASK;
        w
    }

    /// Encode into a 4-byte little-endian buffer.
    pub fn encode_into(&self, out: &mut [u8]) -> Option<()> {
        if out.len() < 4 {
            return None;
        }
        out[0..4].copy_from_slice(&self.encode_w0().to_le_bytes());
        Some(())
    }
}

// ── Band / channel mapping ──────────────────────────────────────────

/// `enum rtw89_band` band identifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Band {
    /// 2.4 GHz (channels 1..14).
    G24,
    /// 5 GHz (channels 36..177).
    G5,
    /// 6 GHz (channels 1..233, Wi-Fi 6E).
    G6,
}

/// Centre frequency → (band, channel number). Returns `None` for
/// frequencies that aren't on a defined channel grid.
pub const fn freq_to_band_chan(freq_mhz: u32) -> Option<(Band, u8)> {
    // 2.4 GHz: ch1..13 at 2412..2472, ch14 at 2484.
    if freq_mhz == 2484 {
        return Some((Band::G24, 14));
    }
    if freq_mhz >= 2412 && freq_mhz <= 2472 {
        let ch = ((freq_mhz - 2407) / 5) as u8;
        if ch >= 1 && ch <= 13 {
            return Some((Band::G24, ch));
        }
    }
    // 5 GHz: 5180..5825, ch36..165 in steps of 5 MHz (channels at 5 MHz boundaries).
    if freq_mhz >= 5180 && freq_mhz <= 5825 {
        let ch = ((freq_mhz - 5000) / 5) as u8;
        if ch >= 36 && ch <= 165 {
            return Some((Band::G5, ch));
        }
    }
    // 6 GHz: 5955..7115, ch1..233 (PSC channels at 5955 + 80×(ch-1)).
    if freq_mhz >= 5955 && freq_mhz <= 7115 {
        let ch_idx = ((freq_mhz - 5950) / 5) as u32;
        if ch_idx >= 1 && ch_idx <= 233 {
            return Some((Band::G6, ch_idx as u8));
        }
    }
    None
}

/// Default test channel: 5180 MHz = 5 GHz channel 36.
pub const DEFAULT_FREQ_MHZ: u32 = 5180;
pub const DEFAULT_BAND: Band = Band::G5;
pub const DEFAULT_CHAN: u8 = 36;
