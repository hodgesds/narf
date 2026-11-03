// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Exact AX-v0 MAC0/MACID0 fields. No firmware/radio or key authority.
fn word(bytes: &mut [u8], index: usize, value: u32) {
    bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn role(remove: bool) -> [u8; 4] {
    ((1u32 << 13) | (u32::from(remove) << 10)).to_le_bytes()
}
/// `rtw89_fw_h2c_role_maintain(RTW89_ROLE_FW_RESTORE)` for the station
/// role (`upd_mode` 6, W0[12:10]) after a firmware swap.
pub(super) fn role_restore() -> [u8; 4] {
    ((1u32 << 13) | (6 << 10)).to_le_bytes()
}
pub(super) fn join(connected: bool) -> [u8; 4] {
    ((1u32 << 26) | if connected { 2 << 24 } else { 1 << 8 }).to_le_bytes()
}
pub(super) fn pause(paused: bool) -> [u8; 32] {
    pause_at(0, paused)
}
/// `rtw89_fw_h2c_macid_pause` (`struct rtw89_fw_macid_pause_grp`): pause
/// group `macid >> 5`, bit `macid & 31`, with only that bit in the mask
/// (mac.c `rtw89_mac_set_macid_pause`).
pub(in crate::rtw89) fn pause_at(macid: u8, paused: bool) -> [u8; 32] {
    let mut bytes = [0; 32];
    let group = usize::from(macid >> 5);
    let bit = 1u32 << (macid & 31);
    word(&mut bytes, group, if paused { bit } else { 0 });
    word(&mut bytes, 4 + group, bit);
    bytes
}
/// `R_AX_SS_MACID_PAUSE_0 + 4 * group` and the bit of `macid`.
pub(in crate::rtw89) fn pause_register(macid: u8) -> (u32, u32) {
    (0x9eb0 + 4 * u32::from(macid >> 5), 1 << (macid & 31))
}
pub(super) fn cam(
    own: [u8; 6],
    peer: [u8; 6],
    aid: u16,
    associated: bool,
    valid: bool,
) -> [u8; 60] {
    cam_entry(&Cam {
        macid: 0,
        port: 0,
        addr_idx: 0,
        bssid_idx: 0,
        net_type: if associated { NET_TYPE_INFRA } else { 0 },
        valid,
        bssid_valid: valid,
        sma: own,
        tma: peer,
        bssid: peer,
        aid: if associated { aid } else { 0 },
    })
}
/// `RTW89_NET_TYPE_INFRA`.
pub(in crate::rtw89) const NET_TYPE_INFRA: u8 = 2;
/// One AX v0 address-CAM + BSSID-CAM H2C (`struct rtw89_h2c_addr_cam_v0`),
/// cam.c `rtw89_cam_fill_addr_cam_info` / `rtw89_cam_fill_bssid_cam_info`
/// with `addr_mask` 0, `hit_rule`/`bcn_hit_cond` 0 (mac80211.c
/// `rtw89_vif_link_init`), PHY0, no trigger/LSIG/target indication,
/// `RTW89_ADDR_CAM_SEC_NORMAL` with every security entry/key index 0
/// (host crypto), BSS colour 0 and `RTW89_BSSID_MATCH_ALL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct Cam {
    /// `rtwsta_link ? sta mac_id : vif mac_id` (W8 `MACID`).
    pub(in crate::rtw89) macid: u8,
    /// `rtwvif_link->port` (W8 `PORT_INT` and `TSF_SYNC`).
    pub(in crate::rtw89) port: u8,
    /// `addr_cam_idx` (W1, entry size 0x40).
    pub(in crate::rtw89) addr_idx: u8,
    /// `bssid_cam_idx` (W3 and W12, entry size 8).
    pub(in crate::rtw89) bssid_idx: u8,
    /// `rtwvif_link->net_type` (W2 `NET_TYPE`).
    pub(in crate::rtw89) net_type: u8,
    /// Address-CAM entry valid (`rtw89_cam_deinit_addr_cam` clears it
    /// before the AP-client disconnect H2C).
    pub(in crate::rtw89) valid: bool,
    /// BSSID-CAM entry valid (the vif's entry outlives its AP clients).
    pub(in crate::rtw89) bssid_valid: bool,
    /// Own (or scan) address.
    pub(in crate::rtw89) sma: [u8; 6],
    /// `link_sta->addr` for a peer, else `rtwvif_link->bssid`.
    pub(in crate::rtw89) tma: [u8; 6],
    pub(in crate::rtw89) bssid: [u8; 6],
    /// W9 `AID12` (INFRA: own AID, AP_MODE: peer AID or 0).
    pub(in crate::rtw89) aid: u16,
}
pub(in crate::rtw89) fn cam_entry(c: &Cam) -> [u8; 60] {
    let mut bytes = [0; 60];
    let sma_hash = c.sma.into_iter().fold(0u8, |a, b| a ^ b);
    let tma_hash = c.tma.into_iter().fold(0u8, |a, b| a ^ b);
    word(&mut bytes, 1, u32::from(c.addr_idx) | 0x40 << 16);
    word(
        &mut bytes,
        2,
        u32::from(c.valid)
            | u32::from(c.net_type & 3) << 1
            | u32::from(sma_hash) << 16
            | u32::from(tma_hash) << 24,
    );
    word(&mut bytes, 3, u32::from(c.bssid_idx & 0x3f));
    word(
        &mut bytes,
        4,
        u32::from_le_bytes(c.sma[..4].try_into().unwrap()),
    );
    word(
        &mut bytes,
        5,
        u32::from_le_bytes([c.sma[4], c.sma[5], c.tma[0], c.tma[1]]),
    );
    word(
        &mut bytes,
        6,
        u32::from_le_bytes(c.tma[2..].try_into().unwrap()),
    );
    let port = u32::from(c.port & 7);
    word(&mut bytes, 8, u32::from(c.macid) | port << 8 | port << 11);
    // Source SEC_NORMAL mode, with every security-entry valid bit/key index0.
    word(&mut bytes, 9, 2 << 16 | u32::from(c.aid & 0xfff));
    word(&mut bytes, 12, u32::from(c.bssid_idx) | 8 << 16);
    word(
        &mut bytes,
        13,
        u32::from(c.bssid_valid)
            | (0x3f << 2)
            | u32::from(c.bssid[0]) << 16
            | u32::from(c.bssid[1]) << 24,
    );
    word(
        &mut bytes,
        14,
        u32::from_le_bytes(c.bssid[2..].try_into().unwrap()),
    );
    bytes
}
fn field(bytes: &mut [u8; 68], index: usize, mask: u32, value: u32) {
    let p = index * 4;
    let old = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
    word(
        bytes,
        index,
        old & !mask | (value << mask.trailing_zeros()) & mask,
    );
    let mp = (index + 8) * 4;
    let old = u32::from_le_bytes(bytes[mp..mp + 4].try_into().unwrap());
    word(bytes, index + 8, old | mask);
}
pub(super) fn default_cctl() -> [u8; 68] {
    default_cctl_at(0, false)
}
/// fw.c `rtw89_fw_h2c_default_cmac_tbl` for `macid`; `ap` adds the
/// `NET_TYPE_AP_MODE` `DATA_DCM` 0 setter.
pub(in crate::rtw89) fn default_cctl_at(macid: u8, ap: bool) -> [u8; 68] {
    let mut bytes = [0; 68];
    word(&mut bytes, 0, u32::from(macid & 0x7f) | 1 << 7); // MACID, operation1
    field(&mut bytes, 5, 0x0000_0e00, 0); // source TX power mode
    field(&mut bytes, 6, 0x000f_0000, 1); // source explicit TX-A
    for mask in [
        0x0030_0000,
        0x00c0_0000,
        0x0300_0000,
        0x0c00_0000,
        1 << 28,
        1 << 29,
        1 << 30,
        1 << 31,
    ] {
        field(&mut bytes, 6, mask, 0);
    }
    field(&mut bytes, 1, 1 << 21, 0); // no optional firmware MGQ report
    field(&mut bytes, 7, 0x000c_0000, 0);
    field(&mut bytes, 7, 0x0f00_0000, 0);
    if ap {
        field(&mut bytes, 5, 1 << 12, 0); // AP_MODE DATA_DCM
    }
    bytes
}
/// fw.h `H2C_FUNC_MAC_CCTLINFO_UD_V1`: RTL8852C `h2c_cctl_func_id`.
pub(super) const CCTL_V1: u8 = 0x0a;
/// RTL8852C fw.c `rtw89_fw_h2c_default_cmac_tbl` for MACID0: with
/// `CCTLINFO_UD_V1` Linux sets no TXPWR_MODE / TX path / ANTSEL field, only
/// MGQ_RPT_EN (0), DOPPLER_CTRL (0) and TXPWR_TOLERENCE (0).
pub(super) fn default_cctl_v1() -> [u8; 68] {
    let mut bytes = [0; 68];
    word(&mut bytes, 0, 1 << 7); // MACID0, operation1
    field(&mut bytes, 1, 1 << 21, 0); // no optional firmware MGQ report
    field(&mut bytes, 7, 0x000c_0000, 0);
    field(&mut bytes, 7, 0x0f00_0000, 0);
    bytes
}
/// RTL8852C fw.c `rtw89_fw_h2c_assoc_cmac_tbl` for the MACID0 station on
/// port 0: every setter equals [`fixed_cctl`] except the nominal packet
/// padding, which `CCTLINFO_UD_V1` places at W7 [1:0]/[3:2]/[5:4]/[7:6]
/// (`SET_CMC_TBL_NOMINAL_PKT_PADDING{,40,80,160}_V1`) instead of the
/// `CCTLINFO_UD` W7 [21:20]/[23:22]/[31:30] and W8 [29:28].
pub(super) fn fixed_cctl_v1(ghz5: bool) -> [u8; 68] {
    let mut bytes = fixed_cctl(ghz5);
    // Drop the CCTLINFO_UD padding setters (value and mask words).
    for (index, mask) in [(7, 3 << 20), (7, 3 << 22), (7, 3 << 30), (8, 3 << 28)] {
        for at in [index, index + 8] {
            let p = at * 4;
            let old = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
            word(&mut bytes, at, old & !mask);
        }
    }
    for mask in [3, 3 << 2, 3 << 4, 3 << 6] {
        field(&mut bytes, 7, mask, 0);
    }
    bytes
}
/// `ghz5`: fw.c `rtw89_fw_h2c_assoc_cmac_tbl` lowest rate is OFDM6 off
/// 2.4GHz (`RTS_RTY_LOWEST_RATE`), and the fixed legacy DATARATE follows
/// core.c `rtw89_core_get_mgmt_rate` (OFDM6 on 5GHz).
pub(super) fn fixed_cctl(ghz5: bool) -> [u8; 68] {
    fixed_cctl_at(ghz5, 0, 0, None)
}
/// `rtw89_fw_h2c_assoc_cmac_tbl` for `macid` on vif `port`. `ap` is
/// `Some(peer)` for an AP link: `ULDL` 0 (not `NL80211_IFTYPE_STATION`),
/// `DATA_DCM` 0 (`NET_TYPE_AP_MODE`) and, for a peer (`Some(true)`), the
/// non-HE `BSR_QUEUE_SIZE_FORMAT` 0 (`Some(false)` is the AP vif itself,
/// `rtwsta_link == NULL`).
pub(in crate::rtw89) fn fixed_cctl_at(
    ghz5: bool,
    macid: u8,
    port: u8,
    ap: Option<bool>,
) -> [u8; 68] {
    let lowest = if ghz5 { 4 } else { 0 }; // RTW89_HW_RATE_OFDM6 / CCK1
    let mut bytes = [0; 68];
    word(&mut bytes, 0, u32::from(macid & 0x7f) | 1 << 7);
    field(&mut bytes, 1, 1 << 25, 1); // source disable RTS fallback
    field(&mut bytes, 1, 1 << 26, 1); // source disable data fallback
    field(&mut bytes, 2, 0xf000_0000, lowest); // source RTS retry lowest CCK1/OFDM6
    field(&mut bytes, 2, 1 << 11, 0); // source retry-limit select
    field(&mut bytes, 3, 1 << 6, 0);
    field(&mut bytes, 7, 1 << 17, u32::from(ap.is_none())); // source STA ULDL
    field(&mut bytes, 5, 7, u32::from(port)); // source MULTI_PORT_ID
    for mask in [3 << 20, 3 << 22, 3 << 30] {
        field(&mut bytes, 7, mask, 0);
    }
    field(&mut bytes, 8, 3 << 28, 0); // source non-HE160 padding
                                      // Explicit source setters for the fixed legacy/raw software-crypto path.
    field(&mut bytes, 1, 0x1ff, lowest); // CCK1 (2.4GHz) / OFDM6 (5GHz)
    field(&mut bytes, 1, 3 << 10, 0); //20MHz
    field(&mut bytes, 1, 1 << 27, 0); // no trial rate
    field(&mut bytes, 4, 0xf000_0000, 0); // no hardware security type
    if let Some(peer) = ap {
        if peer {
            field(&mut bytes, 6, 1 << 13, 0); // non-HE BSR_QUEUE_SIZE_FORMAT
        }
        field(&mut bytes, 5, 1 << 12, 0); // AP_MODE DATA_DCM
    }
    bytes
}
pub(super) fn edca(ac: u8, short: bool, ghz5: bool) -> [u8; 12] {
    let mut bytes = [0; 12];
    word(&mut bytes, 0, u32::from(ac) << 5);
    if ghz5 {
        // mac80211 `ieee80211_set_wmm_default` non-QoS 5GHz (OFDM, not
        // 11b): CWmin15/CWmax1023/AIFSN2/TXOP0; 5GHz is always short slot
        // and mac80211.c `rtw89_conf_tx_aifs` uses SIFS16: 2*9+16.
        word(&mut bytes, 1, (10 << 12) | (4 << 8) | 34);
        return bytes;
    }
    // Non-QoS legacy-b CWmin31/CWmax1023/AIFSN2/TXOP0, 2.4GHz SIFS10.
    word(
        &mut bytes,
        1,
        (10 << 12) | (5 << 8) | if short { 28 } else { 50 },
    );
    bytes
}
/// `rtw89_phy_ra_sta_update` + `rtw89_fw_h2c_ra` (AX, no CSI) for a
/// legacy 2.4GHz station: `rates` is the response-bound supported-rate
/// bitmap in hardware order (CCK1,2,5.5,11, OFDM6..54). No calibrated RSSI
/// exists, so the RSSI floor keeps every rate and `init_rate_lv` is 0, as
/// Linux does for an RSSI of 0/1.
/// `rtw89_fw_h2c_ba_cam` (BA CAM v0, RTL8852B): W0 VALID, INIT_REQ (hardware
/// takes the SSN), ENTRY_IDX[3:2], TID[7:4], MACID[15:8], BMAP_SIZE[19:16]
/// (0 for <=64), SSN[31:20]; W1 unused. An invalidation carries only MACID
/// and ENTRY_IDX.
pub(super) fn ba_cam(valid: bool, entry: u8, tid: u8, buf: u16, ssn: u16) -> [u8; 8] {
    ba_cam_at(0, valid, entry, tid, buf, ssn)
}
pub(super) fn ba_cam_at(macid: u8, valid: bool, entry: u8, tid: u8, buf: u16, ssn: u16) -> [u8; 8] {
    let mut bytes = [0; 8];
    let mut w0 = u32::from(entry & 3) << 2 | u32::from(macid) << 8;
    if valid {
        w0 |= 1
            | 1 << 1
            | u32::from(tid & 0xf) << 4
            | if buf > 64 { 4 << 16 } else { 0 }
            | u32::from(ssn & 0xfff) << 20;
    }
    word(&mut bytes, 0, w0);
    bytes
}
/// `rtw89_fw_h2c_ba_cam` under `RTW89_BACAM_V0_EXT` (RTL8852C): W0 VALID,
/// INIT_REQ, TID, MACID, BMAP_SIZE, SSN as v0 but no W0 ENTRY_IDX; W1
/// `ENTRY_IDX_V1`[31:28], `STD_EN` BIT 8 and `BAND` BIT 9 (`mac_idx` 0).
/// An invalidation carries only MACID and W1 ENTRY_IDX_V1.
pub(super) fn ba_cam_v0_ext(valid: bool, entry: u8, tid: u8, buf: u16, ssn: u16) -> [u8; 8] {
    let mut bytes = [0; 8];
    let mut w0 = 0u32;
    let mut w1 = u32::from(entry & 0xf) << 28;
    if valid {
        w0 |= 1
            | 1 << 1
            | u32::from(tid & 0xf) << 4
            | if buf > 64 { 4 << 16 } else { 0 }
            | u32::from(ssn & 0xfff) << 20;
        w1 |= 1 << 8;
    }
    word(&mut bytes, 0, w0);
    word(&mut bytes, 1, w1);
    bytes
}
/// fw.c `rtw89_fw_h2c_init_ba_cam_v0_ext` for dynamic entry `entry` /
/// `uid`: W0 VALID; W1 ENTRY_IDX_V1, UID[7:0], BAND 0, STD_EN 0.
pub(super) fn init_ba_cam_v0_ext(entry: u8, uid: u8) -> [u8; 8] {
    let mut bytes = [0; 8];
    word(&mut bytes, 0, 1);
    word(&mut bytes, 1, u32::from(entry & 0xf) << 28 | u32::from(uid));
    bytes
}
/// Negotiated HT facts consumed by `rtw89_phy_ra_sta_update`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct HtRa {
    /// Peer RX MCS bitmap bytes 0..3 (`ht_cap.mcs.rx_mask`).
    pub(in crate::rtw89) peer_rx_mcs: [u8; 4],
    /// Peer RX SGI20 intersected with local TX SGI20.
    pub(in crate::rtw89) sgi20: bool,
    /// Peer RX LDPC intersected with local TX LDPC.
    pub(in crate::rtw89) ldpc: bool,
}
/// Negotiated HE facts consumed by `rtw89_phy_ra_sta_update`'s HE branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct HeRa {
    /// Peer RX HE-MCS map at the operating width, intersected with the
    /// local TX map (mac80211 `ieee80211_he_mcs_intersection`).
    pub(in crate::rtw89) peer_rx_mcs: u16,
    /// Peer HE PHY LDPC in payload (`IEEE80211_HE_PHY_CAP1_LDPC_...`).
    pub(in crate::rtw89) ldpc: bool,
    /// Peer DCM RX constellation nonzero (`DCM_MAX_CONST_RX_16_QAM` mask).
    pub(in crate::rtw89) dcm: bool,
}
/// Negotiated VHT facts consumed by `rtw89_phy_ra_sta_update`'s VHT branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct VhtRa {
    /// Peer RX VHT-MCS map intersected with the local TX map (mac80211
    /// `ieee80211_vht_cap_ie_to_sta_vht_cap` `rx_mcs_map`).
    pub(in crate::rtw89) peer_rx_mcs: u16,
    /// Peer RXLDPC intersected with local TX LDPC.
    pub(in crate::rtw89) ldpc: bool,
}
/// The 40/80MHz part of `rtw89_phy_ra_sta_update`: `bw_cap` from
/// `link_sta->bandwidth` and the SGI of that bandwidth (40MHz: HT SGI_40;
/// 80MHz: VHT SHORT_GI_80), plus the VHT facts when VHT (and not HE) was
/// negotiated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct WideRa {
    /// `RTW89_CHANNEL_WIDTH_40` (1) or `RTW89_CHANNEL_WIDTH_80` (2).
    pub(in crate::rtw89) bw: u8,
    pub(in crate::rtw89) sgi: bool,
    pub(in crate::rtw89) vht: Option<VhtRa>,
}
/// `get_mcs_ra_mask(mcs_map, 9, 1)`: the non-20MHz VHT branch (MCS9/8/7
/// per NSS at bit 12 + 12 * nss).
pub(super) fn vht_mcs_mask(map: u16) -> u64 {
    (0..4).fold(0u64, |mask, i| {
        let top = match (map >> (2 * i)) & 3 {
            2 => 9,
            1 => 8,
            0 => 7,
            _ => return mask,
        };
        mask | ((1u64 << (top + 1)) - 1) << (12 + 12 * i)
    })
}
/// VHT branch of `rtw89_phy_ra_sta_update` (`mode = VHT|OFDM[|CCK]`, mask
/// from the intersected peer RX map, masked to this profile's one TX stream
/// `rtw89_ra_mask_vht_rates[0]` plus SUBOFDM/SUBCCK, LDPC from the peer
/// RXLDPC, STBC0 like HT: no local TX STBC).
fn ra_vht(rates: u16, vht: VhtRa) -> Option<[u8; 16]> {
    const CCK: u64 = 0xf;
    const OFDM: u64 = 0xff0;
    const SUBCCK: u64 = 0x5;
    let legacy = u64::from(rates) & (CCK | OFDM);
    if legacy == 0 {
        return None;
    }
    let mut mode = 0x8u32; // RTW89_RA_MODE_VHT
    if legacy & CCK != 0 {
        mode |= 1;
    }
    if legacy & OFDM != 0 {
        mode |= 2;
    }
    let backup = legacy | vht_mcs_mask(vht.peer_rx_mcs);
    let mut allowed = 0x3ff000; // RA_MASK_VHT_1SS_RATES
    if mode & 2 != 0 {
        allowed |= 0x10; // RA_MASK_SUBOFDM_RATES
    }
    if mode & 1 != 0 {
        allowed |= SUBCCK;
    }
    let mut mask = backup & allowed;
    if mask & !(CCK | OFDM) == 0 {
        mask |= backup & !(CCK | OFDM);
    }
    if mask == 0 {
        mask |= backup & (CCK | OFDM);
    }
    let mut bytes = [0; 16];
    word(
        &mut bytes,
        0,
        mode << 1 | 1 << 20 | u32::from(vht.ldpc) << 22,
    );
    word(&mut bytes, 1, mask as u32);
    word(&mut bytes, 2, (mask >> 32) as u32 & 0x7fff_ffff);
    Some(bytes)
}
/// `rtw89_phy_ra_sta_update` on an admitted 40/80MHz channel: the HE, VHT
/// or HT branch body (in that precedence, as Linux), then `BW_CAP[7:6]` =
/// `wide.bw` and `SGI` = the SGI of that bandwidth.
pub(super) fn ra_wide(rates: u16, ht: HtRa, he: Option<HeRa>, wide: WideRa) -> Option<[u8; 16]> {
    if !matches!(wide.bw, 1 | 2) || wide.bw == 2 && wide.vht.is_none() {
        return None;
    }
    let mut bytes = match (he, wide.vht) {
        (Some(he), _) => ra_he(rates, ht, he)?,
        (None, Some(vht)) => ra_vht(rates, vht)?,
        (None, None) => ra_ht(rates, Some(ht))?,
    };
    let w0 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & !(3 << 6 | 1 << 21)
        | u32::from(wide.bw) << 6
        | u32::from(wide.sgi) << 21;
    word(&mut bytes, 0, w0);
    Some(bytes)
}
pub(in crate::rtw89) fn ra(rates: u16) -> Option<[u8; 16]> {
    ra_ht(rates, None)
}
/// `get_mcs_ra_mask(mcs_map, 11, 2)` (phy.c `get_he_ra_mask`): per NSS,
/// MCS0..11/0..9/0..7 at bit 12 + 12 * nss.
pub(super) fn he_mcs_mask(map: u16) -> u64 {
    (0..4).fold(0u64, |mask, i| {
        let top = match (map >> (2 * i)) & 3 {
            2 => 11,
            1 => 9,
            0 => 7,
            _ => return mask,
        };
        mask | ((1u64 << (top + 1)) - 1) << (12 + 12 * i)
    })
}
/// HE branch of `rtw89_phy_ra_sta_update`: `mode = HE|CCK|OFDM` (no HT
/// bit), HE mask from the intersected peer RX map, masked to this profile's
/// one TX stream (`rtw89_ra_mask_he_rates[0]`) plus SUBOFDM/SUBCCK, SGI from
/// the HT SGI20 negotiation (Linux reads `ht_cap` for 20MHz), LDPC and DCM
/// from the peer HE PHY capabilities. `fix_giltf_en` stays clear, so firmware
/// selects GI/LTF. ER is zero: Linux sets `er_cap` only after
/// `rtw89_phy_ra_assoc`.
pub(super) fn ra_he(rates: u16, ht: HtRa, he: HeRa) -> Option<[u8; 16]> {
    const CCK: u64 = 0xf;
    const OFDM: u64 = 0xff0;
    const SUBCCK: u64 = 0x5;
    let legacy = u64::from(rates) & (CCK | OFDM);
    if legacy == 0 {
        return None;
    }
    let mut mode = 0x10u32; // RTW89_RA_MODE_HE
    if legacy & CCK != 0 {
        mode |= 1;
    }
    if legacy & OFDM != 0 {
        mode |= 2;
    }
    let backup = legacy | he_mcs_mask(he.peer_rx_mcs);
    let mut allowed = 0xfff000; // RA_MASK_HE_1SS_RATES
    if mode & 2 != 0 {
        allowed |= 0x10; // RA_MASK_SUBOFDM_RATES
    }
    if mode & 1 != 0 {
        allowed |= SUBCCK;
    }
    let mut mask = backup & allowed;
    if mask & !(CCK | OFDM) == 0 {
        mask |= backup & !(CCK | OFDM);
    }
    if mask == 0 {
        mask |= backup & (CCK | OFDM);
    }
    let mut bytes = [0; 16];
    word(
        &mut bytes,
        0,
        mode << 1
            | u32::from(he.dcm) << 16
            | 1 << 20
            | u32::from(ht.sgi20) << 21
            | u32::from(he.ldpc) << 22,
    );
    word(&mut bytes, 1, mask as u32);
    word(&mut bytes, 2, (mask >> 32) as u32 & 0x7fff_ffff);
    Some(bytes)
}
/// HT branch: `mode |= HT`, MCS mask from the peer RX bitmap, then masked
/// to this profile's one TX stream (`rtw89_ra_mask_ht_rates[0]`) plus
/// `RA_MASK_SUBOFDM_RATES`/`RA_MASK_SUBCCK_RATES`.
pub(super) fn ra_ht(rates: u16, ht: Option<HtRa>) -> Option<[u8; 16]> {
    const CCK: u64 = 0xf;
    const OFDM: u64 = 0xff0;
    const SUBCCK: u64 = 0x5;
    let supported = u64::from(rates) & (CCK | OFDM);
    if supported == 0 {
        return None;
    }
    let mut mode = 0u32;
    if supported & CCK != 0 {
        mode |= 1; // RTW89_RA_MODE_CCK
    }
    if supported & OFDM != 0 {
        mode |= 2; // RTW89_RA_MODE_OFDM
    }
    let mut supported = supported;
    if let Some(ht) = ht {
        mode |= 4; // RTW89_RA_MODE_HT
        let m = ht.peer_rx_mcs;
        supported |= u64::from(m[3]) << 48
            | u64::from(m[2]) << 36
            | u64::from(m[1]) << 24
            | u64::from(m[0]) << 12;
    }
    let backup = supported;
    let mut mask = supported;
    if mode >= 4 {
        let mut allowed = 0xff000; // RA_MASK_HT_1SS_RATES
        if mode & 2 != 0 {
            allowed |= 0x10; // RA_MASK_SUBOFDM_RATES
        }
        if mode & 1 != 0 {
            allowed |= SUBCCK;
        }
        mask &= allowed;
    } else if mode & 2 != 0 {
        mask &= OFDM | SUBCCK;
    }
    // rtw89_phy_ra_mask_recover
    if mask & !(CCK | OFDM) == 0 {
        mask |= backup & !(CCK | OFDM);
    }
    if mask == 0 {
        mask |= backup & (CCK | OFDM);
    }
    let mut bytes = [0; 16];
    // MODE[5:1], BW_CAP 20MHz, MACID0, INIT_RATE_LV0, UPD_ALL, SS_NUM0.
    let (sgi, ldpc) = ht.map_or((false, false), |ht| (ht.sgi20, ht.ldpc));
    word(
        &mut bytes,
        0,
        mode << 1 | 1 << 20 | u32::from(sgi) << 21 | u32::from(ldpc) << 22,
    );
    word(&mut bytes, 1, mask as u32);
    word(&mut bytes, 2, (mask >> 32) as u32 & 0x7fff_ffff);
    Some(bytes)
}
/// `ghz5`: mac80211.c `rtw89_conf_tx_aifs` SIFS16 (10 on 2.4GHz), and
/// 5GHz always uses the short slot.
pub(super) fn wmm_edca(
    p: narf_wireless::wmm::Parameters,
    short: bool,
    ghz5: bool,
) -> Option<[[u8; 12]; 4]> {
    let (slot, sifs) = if ghz5 {
        (9, 16)
    } else if short {
        (9, 10)
    } else {
        (20, 10)
    };
    if p.ac[0].admission_control
        || p.ac.iter().any(|a| {
            a.ecw_min == 0
                || a.ecw_min > 15
                || a.ecw_max > 15
                || a.ecw_min > a.ecw_max
                || a.aifsn < 2
                || a.aifsn > 15
        })
    {
        return None;
    }
    let mut commands = [[0; 12]; 4];
    for (i, a) in p.ac.iter().enumerate() {
        let aifs = u32::from(if i == 0 { a.aifsn.max(3) } else { a.aifsn }) * slot + sifs;
        if aifs > 255 {
            return None;
        }
        word(&mut commands[i], 0, (i as u32) << 5);
        word(
            &mut commands[i],
            1,
            u32::from(if i == 0 { 0 } else { a.txop }) << 16
                | u32::from(if i == 0 { a.ecw_max.max(10) } else { a.ecw_max }) << 12
                | u32::from(if i == 0 { a.ecw_min.max(5) } else { a.ecw_min }) << 8
                | aifs,
        );
    }
    Some(commands)
}
/// mac.c `rtw89_mac_dmac_tbl_init` / `rtw89_mac_cmac_tbl_init` (AX,
/// nonsecure): the indirect `R_AX_FILTER_MODEL_ADDR` window base and the
/// words written through `R_AX_INDIR_ACCESS_ENTRY` for `macid`.
pub(in crate::rtw89) fn table_init(macid: u8) -> ([u32; 4], u32, [u32; 8]) {
    let dmac = core::array::from_fn(|i| 0x1880_0000 + (u32::from(macid) << 4) + (i as u32) * 4);
    (
        dmac,
        0x1884_0000 + u32::from(macid) * 32,
        [4, 0x400a_0004, 0, 0, 0, 0x0e43_000b, 0, 0x000b_8109],
    )
}
/// fw.c `rtw89_fw_h2c_ra`: place `RTW89_H2C_RA_W0_MACID` (bits 15:8) into
/// an `ra`/`ra_ht`/`ra_he` body built for MACID0.
pub(in crate::rtw89) fn ra_at(macid: u8, body: [u8; 16]) -> [u8; 16] {
    let mut body = body;
    let w0 = u32::from_le_bytes(body[..4].try_into().unwrap()) & !0xff00 | u32::from(macid) << 8;
    word(&mut body, 0, w0);
    body
}
