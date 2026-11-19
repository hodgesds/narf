// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Exact AX (RTL8852B) H2C words for an AP link and its associated peers,
//! and the AP TX queue selection. Formatting only: no firmware, MMIO, RF,
//! key or peer authority, and nothing here is submitted by itself.
//!
//! Sources (Linux rtw89):
//! - fw.c `rtw89_fw_h2c_role_maintain` (`RTW89_H2C_ROLE_MAINTAIN_W0_*`);
//! - fw.c `rtw89_fw_h2c_join_info` AX format (`RTW89_H2C_JOININFO_W0_*`);
//! - fw.c `rtw89_fw_h2c_update_beacon` (`RTW89_H2C_BCN_UPD_W0/W1_*`,
//!   W2 zero from `rtw89_fw_h2c_alloc_skb`'s memset);
//! - core.c `rtw89_core_tx_update_desc_info`/`_mgmt_info`/`_data_info`,
//!   `rtw89_core_get_qsel_mgmt` and `rtw89_core_get_ch_dma` (RTL8852B);
//! - core.c `rtw89_vif_type_mapping`: AP → `NET_TYPE_AP_MODE`,
//!   `SELF_ROLE_AP`, `WIFI_ROLE_AP`.
extern crate alloc;

use alloc::vec::Vec;

/// `enum rtw89_net_type`.
pub(in crate::rtw89) const NET_TYPE_NO_LINK: u8 = 0;
pub(in crate::rtw89) const NET_TYPE_AP_MODE: u8 = 3;
/// `enum rtw89_wifi_role`: NONE, STATION, AP, ...
pub(in crate::rtw89) const WIFI_ROLE_AP: u8 = 2;
/// `enum rtw89_self_role`.
pub(in crate::rtw89) const SELF_ROLE_AP: u8 = 1;
pub(in crate::rtw89) const SELF_ROLE_AP_CLIENT: u8 = 2;
/// `RTW89_MGMT_HW_SSN_SEL` / `RTW89_MGMT_HW_SEQ_MODE`.
const MGMT_HW_SSN_SEL: u32 = 1;
const MGMT_HW_SEQ_MODE: u32 = 1;
/// `RTW89_HW_RATE_CCK1` / `RTW89_HW_RATE_OFDM6`.
const HW_RATE_CCK1: u32 = 0x0;
const HW_RATE_OFDM6: u32 = 0x4;
/// AX `struct rtw89_h2c_bcn_upd` (W0..W2).
pub(in crate::rtw89) const BCN_UPD_LEN: usize = 12;
/// 802.11 management header length (beacons carry no HT Control).
const MGMT_HDR: usize = 24;

/// `enum rtw89_upd_mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(in crate::rtw89) enum UpdMode {
    Create = 0,
    Remove = 1,
    TypeChange = 2,
    InfoChange = 3,
    ConDisconn = 4,
    BandSw = 5,
    FwRestore = 6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) enum Error {
    /// MACID/port/band/WMM outside the AX field widths.
    Field,
    /// Beacon shorter than its header or TIM beyond the 7-bit
    /// `GRP_IE_OFST` range (Linux ORs `BIT(7)` into an 8-bit field).
    Beacon,
}

/// One AP `rtw89_vif_link` on RTL8852B: its own MACID, port and band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct ApLink {
    pub(in crate::rtw89) mac_id: u8,
    /// `rtwvif_link->port` (0..4 on AX).
    pub(in crate::rtw89) port: u8,
    /// `rtwvif_link->mac_idx` (RTL8852B is single band: 0).
    pub(in crate::rtw89) mac_idx: u8,
    /// `rtwvif_link->wmm` hardware EDCA set.
    pub(in crate::rtw89) wmm: u8,
}

impl ApLink {
    pub(in crate::rtw89) fn new(mac_id: u8, port: u8, mac_idx: u8, wmm: u8) -> Result<Self, Error> {
        if port > 4 || mac_idx > 1 || wmm > 3 {
            return Err(Error::Field);
        }
        Ok(Self {
            mac_id,
            port,
            mac_idx,
            wmm,
        })
    }

    /// `rtw89_fw_h2c_role_maintain` W0: the AP self role, or
    /// `SELF_ROLE_AP_CLIENT` for an associated peer's MACID.
    pub(in crate::rtw89) fn role_maintain(&self, peer: Option<u8>, mode: UpdMode) -> [u8; 4] {
        let (mac_id, self_role) = match peer {
            Some(id) => (id, SELF_ROLE_AP_CLIENT),
            None => (self.mac_id, SELF_ROLE_AP),
        };
        (u32::from(mac_id)
            | u32::from(self_role) << 8
            | u32::from(mode as u8) << 10
            | u32::from(WIFI_ROLE_AP) << 13
            | u32::from(self.mac_idx) << 17
            | u32::from(self.port) << 19)
            .to_le_bytes()
    }

    /// AX `rtw89_fw_h2c_join_info` W0. For a peer the self role becomes
    /// `AP_CLIENT` and a disconnect reports `NET_TYPE_NO_LINK`; the AP
    /// link itself keeps `NET_TYPE_AP_MODE` even with `dis_conn` (start_ap
    /// and stop_ap both send `dis_conn = true` for the vif). ISHESTA, DLBW,
    /// TF_MAC_PAD, DL_T_PE are zero and TGR follows `rtwvif_link->trigger`
    /// (only set for an HE station; false for AP).
    pub(in crate::rtw89) fn join_info(&self, peer: Option<u8>, dis_conn: bool) -> [u8; 4] {
        let (mac_id, self_role, net_type) = match peer {
            Some(id) => (
                id,
                SELF_ROLE_AP_CLIENT,
                if dis_conn {
                    NET_TYPE_NO_LINK
                } else {
                    NET_TYPE_AP_MODE
                },
            ),
            None => (self.mac_id, SELF_ROLE_AP, NET_TYPE_AP_MODE),
        };
        (u32::from(mac_id)
            | u32::from(dis_conn) << 8
            | u32::from(self.mac_idx & 1) << 9
            | u32::from(self.wmm) << 10
            | u32::from(self.port) << 21
            | u32::from(net_type) << 24
            | u32::from(WIFI_ROLE_AP) << 26
            | u32::from(self_role) << 30)
            .to_le_bytes()
    }

    /// `rtw89_fw_h2c_update_beacon` payload: W0..W2 followed by the whole
    /// beacon (`ieee80211_beacon_get_tim`). `tim_at` is the TIM element
    /// offset in the full frame; firmware receives it relative to the
    /// 24-byte header with `BIT(7)` set. `p2p` (GO) and 5 GHz use OFDM6,
    /// 2.4 GHz uses CCK1.
    pub(in crate::rtw89) fn beacon_update(
        &self,
        beacon: &[u8],
        tim_at: usize,
        ghz2: bool,
        p2p: bool,
    ) -> Result<Vec<u8>, Error> {
        if beacon.len() < MGMT_HDR || tim_at < MGMT_HDR || tim_at + 2 > beacon.len() {
            return Err(Error::Beacon);
        }
        if beacon[tim_at] != 5 {
            return Err(Error::Beacon);
        }
        let ofst = tim_at - MGMT_HDR;
        if ofst >= 0x80 {
            return Err(Error::Beacon);
        }
        let rate = if !p2p && ghz2 {
            HW_RATE_CCK1
        } else {
            HW_RATE_OFDM6
        };
        let w0 = u32::from(self.port) | u32::from(self.mac_idx) << 16 | (ofst as u32 | 0x80) << 24;
        let w1 =
            u32::from(self.mac_id) | MGMT_HW_SSN_SEL << 8 | MGMT_HW_SEQ_MODE << 10 | rate << 12;
        let mut out = Vec::with_capacity(BCN_UPD_LEN + beacon.len());
        out.extend_from_slice(&w0.to_le_bytes());
        out.extend_from_slice(&w1.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(beacon);
        Ok(out)
    }
}

/// Compose `NL80211_ATTR_BEACON_HEAD || TIM || NL80211_ATTR_BEACON_TAIL`
/// (mac80211 `ieee80211_beacon_get_tim`): returns the frame and the TIM
/// element offset.
pub(in crate::rtw89) fn compose_beacon(head: &[u8], tim: &[u8], tail: &[u8]) -> (Vec<u8>, usize) {
    let mut frame = Vec::with_capacity(head.len() + tim.len() + tail.len());
    frame.extend_from_slice(head);
    frame.extend_from_slice(tim);
    frame.extend_from_slice(tail);
    (frame, head.len())
}

/// AX TX queue (`enum rtw89_tx_qsel`) and RTL8852B DMA channel
/// (`rtw89_core_get_ch_dma`) plus TXWD port for one AP frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct Placement {
    pub(in crate::rtw89) qsel: u8,
    pub(in crate::rtw89) channel: u8,
    /// `desc_info->port`: the vif port only for HIQ, else 0.
    pub(in crate::rtw89) port: u8,
}

/// `rtw89_core_tx_update_desc_info` for an AP link on band 0. `after_dtim`
/// is `IEEE80211_TX_CTL_SEND_AFTER_DTIM` (see `ap_ps::group_after_dtim`);
/// for data `tid` selects BE/BK/VI/VO (`rtw89_core_get_qsel`).
pub(in crate::rtw89) fn placement(
    link: &ApLink,
    management: bool,
    tid: u8,
    after_dtim: bool,
) -> Placement {
    if after_dtim {
        // RTW89_TX_QSEL_B0_HI -> RTW89_TXCH_CH9.
        return Placement {
            qsel: 0x11,
            channel: 9,
            port: link.port,
        };
    }
    if management {
        // RTW89_TX_QSEL_B0_MGMT -> RTW89_TXCH_CH8.
        return Placement {
            qsel: 0x12,
            channel: 8,
            port: 0,
        };
    }
    // ieee802_1d_to_ac: BE 0/3, BK 1/2, VI 4/5, VO 6/7 -> QSEL_{BE,BK,VI,VO}_0.
    let qsel = match tid & 7 {
        1 | 2 => 1,
        4 | 5 => 2,
        6 | 7 => 3,
        _ => 0,
    };
    Placement {
        qsel,
        channel: qsel,
        port: 0,
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "ap_wire_tests.rs"]
mod tests;
