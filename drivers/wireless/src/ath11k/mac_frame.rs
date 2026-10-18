//! 802.11 management frames and information elements for the ath11k
//! station mac layer.
//!
//! NARF has no mac80211, so the frame work mac80211 does for ath11k —
//! parsing beacons / probe responses into BSS entries
//! (`cfg80211_inform_bss_frame_data`, `ieee802_11_parse_elems`), and
//! building the Authentication / (Re)Association Request /
//! Deauthentication frames (`ieee80211_send_auth`,
//! `ieee80211_send_assoc`, `ieee80211_send_deauth_disassoc`) — lives
//! here, ported from Linux `net/mac80211/{mlme,util}.c` and
//! `net/wireless/scan.c` (GPL-2.0, citable since the 2026-05-20
//! relicense). Field layouts are IEEE Std 802.11-2020 §9.
//!
//! Pure functions only: no WMI, no state.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── Element IDs (`enum ieee80211_eid`, include/linux/ieee80211.h) ───

pub mod eid {
    pub const SSID: u8 = 0;
    pub const SUPP_RATES: u8 = 1;
    pub const DS_PARAMS: u8 = 3;
    pub const TIM: u8 = 5;
    pub const COUNTRY: u8 = 7;
    pub const PWR_CONSTRAINT: u8 = 32;
    pub const PWR_CAPABILITY: u8 = 33;
    pub const SUPPORTED_CHANNELS: u8 = 36;
    pub const ERP_INFO: u8 = 42;
    pub const HT_CAPABILITY: u8 = 45;
    pub const QOS_CAPA: u8 = 46;
    pub const RSN: u8 = 48;
    pub const EXT_SUPP_RATES: u8 = 50;
    pub const MOBILITY_DOMAIN: u8 = 54;
    pub const FAST_BSS_TRANSITION: u8 = 55;
    pub const RIC_DATA: u8 = 57;
    pub const SUPPORTED_REGULATORY_CLASSES: u8 = 59;
    pub const HT_OPERATION: u8 = 61;
    pub const RRM_ENABLED_CAPABILITIES: u8 = 70;
    pub const BSS_COEX_2040: u8 = 72;
    pub const QOS_TRAFFIC_CAPA: u8 = 89;
    pub const TIM_BCAST_REQ: u8 = 94;
    pub const INTERWORKING: u8 = 107;
    pub const EXT_CAPABILITY: u8 = 127;
    pub const VHT_CAPABILITY: u8 = 191;
    pub const VHT_OPERATION: u8 = 192;
    pub const OPMODE_NOTIF: u8 = 199;
    pub const VENDOR_SPECIFIC: u8 = 221;
    pub const RSNX: u8 = 244;
    pub const EXTENSION: u8 = 255;
}

/// `WLAN_CAPABILITY_*`.
pub mod capab {
    pub const ESS: u16 = 1 << 0;
    pub const IBSS: u16 = 1 << 1;
    pub const PRIVACY: u16 = 1 << 4;
    pub const SHORT_PREAMBLE: u16 = 1 << 5;
    pub const SPECTRUM_MGMT: u16 = 1 << 8;
    pub const SHORT_SLOT_TIME: u16 = 1 << 10;
    pub const RADIO_MEASURE: u16 = 1 << 12;
}

/// `WLAN_ERP_*` (ERP Information element).
pub mod erp {
    pub const NON_ERP_PRESENT: u8 = 1 << 0;
    pub const USE_PROTECTION: u8 = 1 << 1;
    pub const BARKER_PREAMBLE: u8 = 1 << 2;
}

/// Management subtypes, already shifted into frame-control bits
/// (`IEEE80211_STYPE_*`, type management = 0).
pub mod stype {
    pub const ASSOC_REQ: u16 = 0x0000;
    pub const ASSOC_RESP: u16 = 0x0010;
    pub const REASSOC_REQ: u16 = 0x0020;
    pub const REASSOC_RESP: u16 = 0x0030;
    pub const PROBE_REQ: u16 = 0x0040;
    pub const PROBE_RESP: u16 = 0x0050;
    pub const BEACON: u16 = 0x0080;
    pub const DISASSOC: u16 = 0x00A0;
    pub const AUTH: u16 = 0x00B0;
    pub const DEAUTH: u16 = 0x00C0;
    pub const ACTION: u16 = 0x00D0;
}

/// `IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE`.
pub const FCTL_TYPE_STYPE: u16 = 0x00FC;
/// `IEEE80211_FCTL_PROTECTED`.
pub const FCTL_PROTECTED: u16 = 0x4000;

/// `WLAN_AUTH_OPEN`.
pub const WLAN_AUTH_OPEN: u16 = 0;
/// `WLAN_REASON_UNSPECIFIED`.
pub const WLAN_REASON_UNSPECIFIED: u16 = 1;
/// `WLAN_STATUS_SUCCESS`.
pub const WLAN_STATUS_SUCCESS: u16 = 0;
/// `WLAN_REASON_DEAUTH_LEAVING`.
pub const WLAN_REASON_DEAUTH_LEAVING: u16 = 3;
/// `WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY`.
pub const WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY: u16 = 4;
/// `WLAN_REASON_IE_DIFFERENT` (4-way M3 RSN IE ≠ beacon RSN IE).
pub const WLAN_REASON_IE_DIFFERENT: u16 = 17;
/// `WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT`.
pub const WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT: u16 = 15;

/// `IEEE80211_MAX_SSID_LEN`.
pub const MAX_SSID_LEN: usize = 32;
/// Header length of a 3-address management frame.
pub const MGMT_HDR_LEN: usize = 24;

// ── Element walk (`for_each_element`) ───────────────────────────────

/// One information element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elem<'a> {
    pub id: u8,
    pub data: &'a [u8],
}

/// `for_each_element`: stop at the first element whose header or body
/// runs past the buffer. Returns the well-formed prefix and whether the
/// buffer ended exactly (`for_each_element_completed`).
pub fn elements(ies: &[u8]) -> (Vec<Elem<'_>>, bool) {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 2 <= ies.len() {
        let len = ies[pos + 1] as usize;
        if pos + 2 + len > ies.len() {
            return (out, false);
        }
        out.push(Elem {
            id: ies[pos],
            data: &ies[pos + 2..pos + 2 + len],
        });
        pos += 2 + len;
    }
    (out, pos == ies.len())
}

/// `cfg80211_find_elem`: the first well-formed element with `id`.
pub fn find_elem(ies: &[u8], id: u8) -> Option<&[u8]> {
    elements(ies)
        .0
        .into_iter()
        .find(|e| e.id == id)
        .map(|e| e.data)
}

/// `cfg80211_find_vendor_elem(oui, oui_type)`.
pub fn find_vendor_elem(ies: &[u8], oui: [u8; 3], oui_type: u8) -> Option<&[u8]> {
    elements(ies)
        .0
        .into_iter()
        .find(|e| {
            e.id == eid::VENDOR_SPECIFIC
                && e.data.len() >= 4
                && e.data[0..3] == oui
                && e.data[3] == oui_type
        })
        .map(|e| e.data)
}

/// `WLAN_OUI_MICROSOFT`.
pub const OUI_MICROSOFT: [u8; 3] = [0x00, 0x50, 0xF2];
/// `WLAN_OUI_TYPE_MICROSOFT_WPA`.
pub const OUI_TYPE_MICROSOFT_WPA: u8 = 1;
/// `WLAN_OUI_TYPE_MICROSOFT_WMM`.
pub const OUI_TYPE_MICROSOFT_WMM: u8 = 2;

// ── HT / VHT element bodies ─────────────────────────────────────────

/// `struct ieee80211_ht_cap` (26 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HtCapIe {
    pub cap_info: u16,
    pub ampdu_params_info: u8,
    /// `mcs.rx_mask[10]`.
    pub rx_mask: [u8; 10],
    pub rx_highest: u16,
    pub tx_params: u8,
    pub extended_ht_cap_info: u16,
    pub tx_bf_cap_info: u32,
    pub antenna_selection_info: u8,
}

/// `sizeof(struct ieee80211_ht_cap)`.
pub const HT_CAP_LEN: usize = 26;

impl HtCapIe {
    pub fn parse(d: &[u8]) -> Option<Self> {
        if d.len() < HT_CAP_LEN {
            return None;
        }
        let mut rx_mask = [0u8; 10];
        rx_mask.copy_from_slice(&d[3..13]);
        Some(HtCapIe {
            cap_info: u16::from_le_bytes([d[0], d[1]]),
            ampdu_params_info: d[2],
            rx_mask,
            rx_highest: u16::from_le_bytes([d[13], d[14]]),
            tx_params: d[15],
            extended_ht_cap_info: u16::from_le_bytes([d[19], d[20]]),
            tx_bf_cap_info: u32::from_le_bytes([d[21], d[22], d[23], d[24]]),
            antenna_selection_info: d[25],
        })
    }

    /// `ieee80211_ie_build_ht_cap` body (the reserved / extended /
    /// TxBF / ASEL fields are zero — mac80211 memsets them).
    pub fn put(&self, out: &mut Vec<u8>) {
        out.push(eid::HT_CAPABILITY);
        out.push(HT_CAP_LEN as u8);
        out.extend_from_slice(&self.cap_info.to_le_bytes());
        out.push(self.ampdu_params_info);
        out.extend_from_slice(&self.rx_mask);
        out.extend_from_slice(&self.rx_highest.to_le_bytes());
        out.push(self.tx_params);
        out.extend_from_slice(&[0, 0, 0]); // mcs.reserved[3]
        out.extend_from_slice(&self.extended_ht_cap_info.to_le_bytes());
        out.extend_from_slice(&self.tx_bf_cap_info.to_le_bytes());
        out.push(self.antenna_selection_info);
    }
}

/// `struct ieee80211_ht_operation` (22 bytes), the fields used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HtOperIe {
    pub primary_chan: u8,
    pub ht_param: u8,
    pub operation_mode: u16,
}

/// `sizeof(struct ieee80211_ht_operation)`.
pub const HT_OPER_LEN: usize = 22;
/// `IEEE80211_HT_PARAM_CHA_SEC_OFFSET`.
pub const HT_PARAM_CHA_SEC_OFFSET: u8 = 0x03;
/// `IEEE80211_HT_PARAM_CHA_SEC_ABOVE`.
pub const HT_PARAM_CHA_SEC_ABOVE: u8 = 0x01;
/// `IEEE80211_HT_PARAM_CHA_SEC_BELOW`.
pub const HT_PARAM_CHA_SEC_BELOW: u8 = 0x03;

impl HtOperIe {
    pub fn parse(d: &[u8]) -> Option<Self> {
        if d.len() < HT_OPER_LEN {
            return None;
        }
        Some(HtOperIe {
            primary_chan: d[0],
            ht_param: d[1],
            operation_mode: u16::from_le_bytes([d[2], d[3]]),
        })
    }
}

/// `struct ieee80211_vht_cap` (12 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VhtCapIe {
    pub vht_cap_info: u32,
    pub rx_mcs_map: u16,
    pub rx_highest: u16,
    pub tx_mcs_map: u16,
    pub tx_highest: u16,
}

/// `sizeof(struct ieee80211_vht_cap)`.
pub const VHT_CAP_LEN: usize = 12;

impl VhtCapIe {
    pub fn parse(d: &[u8]) -> Option<Self> {
        if d.len() < VHT_CAP_LEN {
            return None;
        }
        let w = |i: usize| u16::from_le_bytes([d[i], d[i + 1]]);
        Some(VhtCapIe {
            vht_cap_info: u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
            rx_mcs_map: w(4),
            rx_highest: w(6),
            tx_mcs_map: w(8),
            tx_highest: w(10),
        })
    }

    /// `ieee80211_ie_build_vht_cap`.
    pub fn put(&self, out: &mut Vec<u8>) {
        out.push(eid::VHT_CAPABILITY);
        out.push(VHT_CAP_LEN as u8);
        out.extend_from_slice(&self.vht_cap_info.to_le_bytes());
        for v in [
            self.rx_mcs_map,
            self.rx_highest,
            self.tx_mcs_map,
            self.tx_highest,
        ] {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
}

/// `struct ieee80211_vht_operation` (5 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VhtOperIe {
    /// `IEEE80211_VHT_CHANWIDTH_*`: 0 = 20/40, 1 = 80, 2 = 160, 3 = 80+80.
    pub chan_width: u8,
    pub center_freq_seg0_idx: u8,
    pub center_freq_seg1_idx: u8,
    pub basic_mcs_set: u16,
}

impl VhtOperIe {
    pub fn parse(d: &[u8]) -> Option<Self> {
        if d.len() < 5 {
            return None;
        }
        Some(VhtOperIe {
            chan_width: d[0],
            center_freq_seg0_idx: d[1],
            center_freq_seg1_idx: d[2],
            basic_mcs_set: u16::from_le_bytes([d[3], d[4]]),
        })
    }
}

/// One AC record of the WMM Parameter element.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WmmAc {
    /// `aci_aifsn`.
    pub aci_aifsn: u8,
    /// `cw` (ECWmin | ECWmax << 4).
    pub cw: u8,
    pub txop_limit: u16,
}

/// The WMM Parameter element (`struct ieee80211_wmm_param_ie` minus the
/// vendor header).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WmmParam {
    pub qos_info: u8,
    /// Indexed by ACI (0 = BE, 1 = BK, 2 = VI, 3 = VO).
    pub ac: [WmmAc; 4],
}

impl WmmParam {
    /// Vendor body `00 50 f2 02 01 01 qos rsvd ac[4]` (24 bytes); the
    /// OUI subtype must be 1 (parameter element) and version 1, as
    /// `ieee80211_parse_extension_element` / `ieee802_11_parse_vendor_specific`
    /// require.
    pub fn parse(vendor: &[u8]) -> Option<Self> {
        if vendor.len() < 24 || vendor[4] != 1 || vendor[5] != 1 {
            return None;
        }
        let mut p = WmmParam {
            qos_info: vendor[6],
            ..Default::default()
        };
        for (i, ac) in p.ac.iter_mut().enumerate() {
            let o = 8 + 4 * i;
            *ac = WmmAc {
                aci_aifsn: vendor[o],
                cw: vendor[o + 1],
                txop_limit: u16::from_le_bytes([vendor[o + 2], vendor[o + 3]]),
            };
        }
        Some(p)
    }
}

/// True when the vendor element is a WMM Information or Parameter
/// element (`bss->wmm_used`: `cfg80211_find_vendor_elem(WMM)` with
/// subtype 0 or 1).
pub fn has_wmm(ies: &[u8]) -> bool {
    elements(ies).0.iter().any(|e| {
        e.id == eid::VENDOR_SPECIFIC
            && e.data.len() >= 7
            && e.data[0..3] == OUI_MICROSOFT
            && e.data[3] == OUI_TYPE_MICROSOFT_WMM
            && (e.data[4] == 0 || e.data[4] == 1)
            && e.data[5] == 1
    })
}

/// `ieee80211_add_wmm_info_ie`: `dd 07 00 50 f2 02 00 01 qos_info`.
pub fn put_wmm_info(out: &mut Vec<u8>, qos_info: u8) {
    out.extend_from_slice(&[
        eid::VENDOR_SPECIFIC,
        7,
        0x00,
        0x50,
        0xF2,
        OUI_TYPE_MICROSOFT_WMM,
        0, // OUI subtype: information element
        1, // version
        qos_info,
    ]);
}

// ── Parsed BSS elements ─────────────────────────────────────────────

/// The elements of a beacon / probe response / association response
/// the station needs (`struct ieee802_11_elems`, first occurrence of
/// each element like `cfg80211_find_elem`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedIes {
    pub ssid: Option<Vec<u8>>,
    /// Supported Rates followed by Extended Supported Rates, raw
    /// (basic flag in bit 7).
    pub rates: Vec<u8>,
    pub ds_channel: Option<u8>,
    /// `(dtim_count, dtim_period)`.
    pub tim: Option<(u8, u8)>,
    pub erp: Option<u8>,
    pub ht_cap: Option<HtCapIe>,
    pub ht_oper: Option<HtOperIe>,
    pub vht_cap: Option<VhtCapIe>,
    pub vht_oper: Option<VhtOperIe>,
    /// RSN element body.
    pub rsn: Option<Vec<u8>>,
    /// RSNXE (`WLAN_EID_RSNX`, 244) body.
    pub rsnxe: Option<Vec<u8>>,
    /// WPA (Microsoft OUI type 1) vendor element body.
    pub wpa: Option<Vec<u8>>,
    pub wmm_param: Option<WmmParam>,
    pub wmm_used: bool,
    /// The element walk ended exactly at the buffer end.
    pub well_formed: bool,
}

impl ParsedIes {
    /// Parse the variable part of a management frame.
    pub fn parse(ies: &[u8]) -> Self {
        let (elems, complete) = elements(ies);
        let mut p = ParsedIes {
            well_formed: complete,
            ..Default::default()
        };
        let mut seen_rates = false;
        let mut seen_ext = false;
        for e in &elems {
            match e.id {
                eid::SSID if p.ssid.is_none() => p.ssid = Some(e.data.to_vec()),
                eid::SUPP_RATES if !seen_rates => {
                    seen_rates = true;
                    let mut r = e.data.to_vec();
                    r.extend_from_slice(&p.rates);
                    p.rates = r;
                }
                eid::EXT_SUPP_RATES if !seen_ext => {
                    seen_ext = true;
                    p.rates.extend_from_slice(e.data);
                }
                eid::DS_PARAMS if p.ds_channel.is_none() && e.data.len() == 1 => {
                    p.ds_channel = Some(e.data[0])
                }
                eid::TIM if p.tim.is_none() && e.data.len() >= 2 => {
                    p.tim = Some((e.data[0], e.data[1]))
                }
                eid::ERP_INFO if p.erp.is_none() && !e.data.is_empty() => p.erp = Some(e.data[0]),
                eid::HT_CAPABILITY if p.ht_cap.is_none() => p.ht_cap = HtCapIe::parse(e.data),
                eid::HT_OPERATION if p.ht_oper.is_none() => p.ht_oper = HtOperIe::parse(e.data),
                eid::VHT_CAPABILITY if p.vht_cap.is_none() => p.vht_cap = VhtCapIe::parse(e.data),
                eid::VHT_OPERATION if p.vht_oper.is_none() => p.vht_oper = VhtOperIe::parse(e.data),
                eid::RSN if p.rsn.is_none() => p.rsn = Some(e.data.to_vec()),
                eid::RSNX if p.rsnxe.is_none() => p.rsnxe = Some(e.data.to_vec()),
                eid::VENDOR_SPECIFIC if e.data.len() >= 4 && e.data[0..3] == OUI_MICROSOFT => {
                    match e.data[3] {
                        OUI_TYPE_MICROSOFT_WPA if p.wpa.is_none() => p.wpa = Some(e.data.to_vec()),
                        OUI_TYPE_MICROSOFT_WMM => {
                            if e.data.len() >= 6
                                && (e.data[4] == 0 || e.data[4] == 1)
                                && e.data[5] == 1
                            {
                                p.wmm_used = true;
                            }
                            if p.wmm_param.is_none() {
                                p.wmm_param = WmmParam::parse(e.data);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        p
    }
}

// ── Received management frames ──────────────────────────────────────

/// A management frame header (3-address).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtHdr {
    pub fc: u16,
    pub da: [u8; 6],
    pub sa: [u8; 6],
    pub bssid: [u8; 6],
    pub seq_ctrl: u16,
}

impl MgmtHdr {
    pub fn parse(f: &[u8]) -> Option<Self> {
        if f.len() < MGMT_HDR_LEN {
            return None;
        }
        let mac = |o: usize| {
            let mut m = [0u8; 6];
            m.copy_from_slice(&f[o..o + 6]);
            m
        };
        Some(MgmtHdr {
            fc: u16::from_le_bytes([f[0], f[1]]),
            da: mac(4),
            sa: mac(10),
            bssid: mac(16),
            seq_ctrl: u16::from_le_bytes([f[22], f[23]]),
        })
    }

    /// `fc & (FTYPE | STYPE)` with type management (FTYPE = 0).
    pub fn stype(&self) -> Option<u16> {
        if self.fc & 0x000C != 0 {
            return None; // not a management frame
        }
        Some(self.fc & FCTL_TYPE_STYPE)
    }
}

/// A beacon / probe response (`struct ieee80211_mgmt.u.beacon`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeaconFrame<'a> {
    pub hdr: MgmtHdr,
    pub is_probe_resp: bool,
    pub tsf: u64,
    pub beacon_int: u16,
    pub capability: u16,
    pub ies: &'a [u8],
}

/// Parse a beacon / probe response; `None` for any other frame or a
/// frame too short for the fixed fields (`ieee80211_scan_rx` drops
/// `len < 24 + 12`).
pub fn parse_beacon(f: &[u8]) -> Option<BeaconFrame<'_>> {
    let hdr = MgmtHdr::parse(f)?;
    let st = hdr.stype()?;
    if st != stype::BEACON && st != stype::PROBE_RESP {
        return None;
    }
    if f.len() < MGMT_HDR_LEN + 12 {
        return None;
    }
    let b = &f[MGMT_HDR_LEN..];
    Some(BeaconFrame {
        hdr,
        is_probe_resp: st == stype::PROBE_RESP,
        tsf: u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        beacon_int: u16::from_le_bytes([b[8], b[9]]),
        capability: u16::from_le_bytes([b[10], b[11]]),
        ies: &f[MGMT_HDR_LEN + 12..],
    })
}

/// `struct ieee80211_mgmt.u.auth`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthFrame {
    pub hdr: MgmtHdr,
    pub alg: u16,
    pub transaction: u16,
    pub status: u16,
}

/// Parse an Authentication frame (`ieee80211_rx_mgmt_auth`: `len < 24 + 6`
/// is dropped).
pub fn parse_auth(f: &[u8]) -> Option<AuthFrame> {
    let hdr = MgmtHdr::parse(f)?;
    if hdr.stype()? != stype::AUTH || f.len() < MGMT_HDR_LEN + 6 {
        return None;
    }
    let b = &f[MGMT_HDR_LEN..];
    Some(AuthFrame {
        hdr,
        alg: u16::from_le_bytes([b[0], b[1]]),
        transaction: u16::from_le_bytes([b[2], b[3]]),
        status: u16::from_le_bytes([b[4], b[5]]),
    })
}

/// `struct ieee80211_mgmt.u.assoc_resp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssocRespFrame<'a> {
    pub hdr: MgmtHdr,
    pub reassoc: bool,
    pub capab_info: u16,
    pub status: u16,
    /// Raw AID field (bits 14/15 normally set).
    pub aid_field: u16,
    pub ies: &'a [u8],
}

impl AssocRespFrame<'_> {
    /// `ieee80211_assoc_success`: `aid = le16_to_cpu(aid) & 0x7ff`
    /// (`IEEE80211_AID_MASK` for non-S1G).
    pub fn aid(&self) -> u16 {
        self.aid_field & 0x7FF
    }
}

/// Parse a (Re)Association Response (`ieee80211_rx_mgmt_assoc_resp`:
/// `len < 24 + 6` is dropped).
pub fn parse_assoc_resp(f: &[u8]) -> Option<AssocRespFrame<'_>> {
    let hdr = MgmtHdr::parse(f)?;
    let st = hdr.stype()?;
    if (st != stype::ASSOC_RESP && st != stype::REASSOC_RESP) || f.len() < MGMT_HDR_LEN + 6 {
        return None;
    }
    let b = &f[MGMT_HDR_LEN..];
    Some(AssocRespFrame {
        hdr,
        reassoc: st == stype::REASSOC_RESP,
        capab_info: u16::from_le_bytes([b[0], b[1]]),
        status: u16::from_le_bytes([b[2], b[3]]),
        aid_field: u16::from_le_bytes([b[4], b[5]]),
        ies: &f[MGMT_HDR_LEN + 6..],
    })
}

/// A Deauthentication / Disassociation frame: `(hdr, is_deauth, reason)`.
pub fn parse_deauth_disassoc(f: &[u8]) -> Option<(MgmtHdr, bool, u16)> {
    let hdr = MgmtHdr::parse(f)?;
    let st = hdr.stype()?;
    if (st != stype::DEAUTH && st != stype::DISASSOC) || f.len() < MGMT_HDR_LEN + 2 {
        return None;
    }
    Some((hdr, st == stype::DEAUTH, u16::from_le_bytes([f[24], f[25]])))
}

// ── Transmitted management frames ───────────────────────────────────

/// The 24-byte header mac80211 writes: frame control, duration 0
/// (ath11k has `HAS_RATE_CONTROL`, so `ieee80211_duration` returns 0),
/// DA / SA / BSSID, sequence control 0 (mac80211's TX path stamps
/// `sdata->sequence_number` on the way to the driver:
/// `runtime::Rt::mgmt_tx_prepare` → `tx_hdr::tx_h_sequence`).
pub fn mgmt_hdr(fc: u16, da: &[u8; 6], sa: &[u8; 6], bssid: &[u8; 6]) -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    f.extend_from_slice(&fc.to_le_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(da);
    f.extend_from_slice(sa);
    f.extend_from_slice(bssid);
    f.extend_from_slice(&[0, 0]);
    f
}

/// `ieee80211_send_auth` for Open System: algorithm 0, transaction 1,
/// status 0, no extra elements.
pub fn build_auth_open(own: &[u8; 6], bssid: &[u8; 6]) -> Vec<u8> {
    let mut f = mgmt_hdr(stype::AUTH, bssid, own, bssid);
    f.extend_from_slice(&WLAN_AUTH_OPEN.to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes());
    f.extend_from_slice(&WLAN_STATUS_SUCCESS.to_le_bytes());
    f
}

/// `ieee80211_send_deauth_disassoc(…, IEEE80211_STYPE_DEAUTH, reason)`.
pub fn build_deauth(own: &[u8; 6], bssid: &[u8; 6], reason: u16) -> Vec<u8> {
    let mut f = mgmt_hdr(stype::DEAUTH, bssid, own, bssid);
    f.extend_from_slice(&reason.to_le_bytes());
    f
}

// ── Block Ack action frames (`include/linux/ieee80211.h`) ──────────

/// `WLAN_CATEGORY_BACK`.
pub const WLAN_CATEGORY_BACK: u8 = 3;
/// `WLAN_ACTION_ADDBA_REQ` / `_RESP` / `WLAN_ACTION_DELBA`.
pub const WLAN_ACTION_ADDBA_REQ: u8 = 0;
pub const WLAN_ACTION_ADDBA_RESP: u8 = 1;
pub const WLAN_ACTION_DELBA: u8 = 2;
/// `IEEE80211_MIN_ACTION_SIZE` (header + category).
pub const IEEE80211_MIN_ACTION_SIZE: usize = MGMT_HDR_LEN + 1;
/// `sizeof(mgmt->u.action.u.addba_req)` / `addba_resp` / `delba`.
pub const ADDBA_REQ_LEN: usize = 8;
pub const ADDBA_RESP_LEN: usize = 8;
pub const DELBA_LEN: usize = 5;
pub const IEEE80211_ADDBA_PARAM_AMSDU_MASK: u16 = 0x0001;
pub const IEEE80211_ADDBA_PARAM_POLICY_MASK: u16 = 0x0002;
pub const IEEE80211_ADDBA_PARAM_TID_MASK: u16 = 0x003C;
pub const IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK: u16 = 0xFFC0;
pub const IEEE80211_DELBA_PARAM_TID_MASK: u16 = 0xF000;
pub const IEEE80211_DELBA_PARAM_INITIATOR_MASK: u16 = 0x0800;
/// `enum ieee80211_back_parties`.
pub const WLAN_BACK_RECIPIENT: u16 = 0;
pub const WLAN_BACK_INITIATOR: u16 = 1;
/// `WLAN_STATUS_UNSPECIFIED_QOS` / `REQUEST_DECLINED` / `INVALID_QOS_PARAM`.
pub const WLAN_STATUS_UNSPECIFIED_QOS: u16 = 32;
pub const WLAN_STATUS_REQUEST_DECLINED: u16 = 37;
pub const WLAN_STATUS_INVALID_QOS_PARAM: u16 = 38;
/// `WLAN_REASON_QSTA_LEAVE_QBSS`.
pub const WLAN_REASON_QSTA_LEAVE_QBSS: u16 = 36;

/// `mgmt->u.action.u.addba_req` as `ieee80211_process_addba_request`
/// extracts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddbaReq {
    pub dialog_token: u8,
    pub timeout: u16,
    /// `start_seq_num >> 4`.
    pub ssn: u16,
    pub policy: u16,
    pub tid: u16,
    pub buf_size: u16,
}

/// Parse an ADDBA Request action frame (`ieee80211_rx_h_action`: `len <
/// IEEE80211_MIN_ACTION_SIZE + sizeof(addba_req)` is invalid).
pub fn parse_addba_req(f: &[u8]) -> Option<AddbaReq> {
    if f.len() < IEEE80211_MIN_ACTION_SIZE + ADDBA_REQ_LEN
        || f[MGMT_HDR_LEN] != WLAN_CATEGORY_BACK
        || f[MGMT_HDR_LEN + 1] != WLAN_ACTION_ADDBA_REQ
    {
        return None;
    }
    let b = &f[MGMT_HDR_LEN + 2..];
    let capab = u16::from_le_bytes([b[1], b[2]]);
    Some(AddbaReq {
        dialog_token: b[0],
        timeout: u16::from_le_bytes([b[3], b[4]]),
        ssn: u16::from_le_bytes([b[5], b[6]]) >> 4,
        policy: (capab & IEEE80211_ADDBA_PARAM_POLICY_MASK) >> 1,
        tid: (capab & IEEE80211_ADDBA_PARAM_TID_MASK) >> 2,
        buf_size: (capab & IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK) >> 6,
    })
}

/// Parse a DELBA action frame: `(tid, initiator)`
/// (`ieee80211_process_delba`).
pub fn parse_delba(f: &[u8]) -> Option<(u16, u16)> {
    if f.len() < IEEE80211_MIN_ACTION_SIZE + DELBA_LEN
        || f[MGMT_HDR_LEN] != WLAN_CATEGORY_BACK
        || f[MGMT_HDR_LEN + 1] != WLAN_ACTION_DELBA
    {
        return None;
    }
    let params = u16::from_le_bytes([f[MGMT_HDR_LEN + 2], f[MGMT_HDR_LEN + 3]]);
    Some((
        (params & IEEE80211_DELBA_PARAM_TID_MASK) >> 12,
        (params & IEEE80211_DELBA_PARAM_INITIATOR_MASK) >> 11,
    ))
}

/// `ieee80211_send_addba_resp` (`ieee80211_mgmt_ba`: DA = the
/// originator, SA = us, BSSID = the AP for a station): A-MSDU in A-MPDU
/// is advertised (`SUPPORTS_AMSDU_IN_AMPDU`, which ath11k sets); no
/// ADDBA Extension element (that needs HE).
#[allow(clippy::too_many_arguments)] // the frame's fields
pub fn build_addba_resp(
    own: &[u8; 6],
    da: &[u8; 6],
    bssid: &[u8; 6],
    tid: u16,
    dialog_token: u8,
    status: u16,
    policy: u16,
    buf_size: u16,
    timeout: u16,
) -> Vec<u8> {
    let mut f = mgmt_hdr(stype::ACTION, da, own, bssid);
    f.push(WLAN_CATEGORY_BACK);
    f.push(WLAN_ACTION_ADDBA_RESP);
    f.push(dialog_token);
    f.extend_from_slice(&status.to_le_bytes());
    let capab = (IEEE80211_ADDBA_PARAM_AMSDU_MASK & 1)
        | ((policy << 1) & IEEE80211_ADDBA_PARAM_POLICY_MASK)
        | ((tid << 2) & IEEE80211_ADDBA_PARAM_TID_MASK)
        | ((buf_size << 6) & IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK);
    f.extend_from_slice(&capab.to_le_bytes());
    f.extend_from_slice(&timeout.to_le_bytes());
    f
}

/// `ieee80211_send_delba`: params = initiator << 11 | tid << 12.
pub fn build_delba(
    own: &[u8; 6],
    da: &[u8; 6],
    bssid: &[u8; 6],
    tid: u16,
    initiator: u16,
    reason: u16,
) -> Vec<u8> {
    let mut f = mgmt_hdr(stype::ACTION, da, own, bssid);
    f.push(WLAN_CATEGORY_BACK);
    f.push(WLAN_ACTION_DELBA);
    let params = (initiator << 11) | (tid << 12);
    f.extend_from_slice(&params.to_le_bytes());
    f.extend_from_slice(&reason.to_le_bytes());
    f
}

/// `ieee80211_id_in_list`: `ids` may contain `EXTENSION, ext_id` pairs.
fn id_in_list(ids: &[u8], id: u8, ext: Option<u8>) -> bool {
    let mut i = 0;
    while i < ids.len() {
        if ids[i] == eid::EXTENSION {
            if i + 1 < ids.len() && Some(ids[i + 1]) == ext && id == eid::EXTENSION {
                return true;
            }
            i += 2;
            continue;
        }
        if ids[i] == id {
            return true;
        }
        i += 1;
    }
    false
}

/// `ieee80211_ie_split` (no RIC handling): advance `offset` past the
/// elements whose id is in `ids`.
pub fn ie_split(ies: &[u8], ids: &[u8], mut offset: usize) -> usize {
    while offset + 2 <= ies.len() {
        let id = ies[offset];
        let ext = if id == eid::EXTENSION && offset + 2 < ies.len() {
            Some(ies[offset + 2])
        } else {
            None
        };
        if !id_in_list(ids, id, ext) {
            break;
        }
        offset += 2 + ies[offset + 1] as usize;
    }
    offset.min(ies.len())
}

/// `ieee80211_ie_split_vendor`: advance past every non-vendor element.
pub fn ie_split_vendor(ies: &[u8], mut offset: usize) -> usize {
    while offset + 2 <= ies.len() && ies[offset] != eid::VENDOR_SPECIFIC {
        offset += 2 + ies[offset + 1] as usize;
    }
    offset.min(ies.len())
}

/// `before_ht[]` of `ieee80211_add_before_ht_elems`.
pub const BEFORE_HT: &[u8] = &[
    eid::SSID,
    eid::SUPP_RATES,
    eid::EXT_SUPP_RATES,
    eid::PWR_CAPABILITY,
    eid::SUPPORTED_CHANNELS,
    eid::RSN,
    eid::QOS_CAPA,
    eid::RRM_ENABLED_CAPABILITIES,
    eid::MOBILITY_DOMAIN,
    eid::FAST_BSS_TRANSITION,
    eid::RIC_DATA,
    eid::SUPPORTED_REGULATORY_CLASSES,
];

/// `before_vht[]` of `ieee80211_add_before_vht_elems`.
pub const BEFORE_VHT: &[u8] = &[
    eid::BSS_COEX_2040,
    eid::EXT_CAPABILITY,
    eid::QOS_TRAFFIC_CAPA,
    eid::TIM_BCAST_REQ,
    eid::INTERWORKING,
];

/// What `ieee80211_send_assoc` / `ieee80211_add_link_elems` need for a
/// non-MLO (Re)Association Request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssocReqParams {
    pub own: [u8; 6],
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    /// `local->hw.conf.listen_interval` (= `max_listen_interval`).
    pub listen_interval: u16,
    /// Capability bits computed by the caller (ESS, PRIVACY, the 2.4 GHz
    /// short slot / preamble bits, SPECTRUM_MGMT).
    pub capab: u16,
    /// Supported-rate octets (`DIV_ROUND_UP(bitrate, 5)`, basic bit
    /// clear) in sband order: the first 8 go in Supported Rates, the
    /// rest in Extended Supported Rates (`ieee80211_put_srates_elem`).
    pub rates: Vec<u8>,
    /// `(min, max)` for the Power Capability element, when
    /// `capab & (SPECTRUM_MGMT | RADIO_MEASURE)`.
    pub pwr_capability: Option<(u8, u8)>,
    /// Supported Channels element channel numbers, when
    /// `capab & SPECTRUM_MGMT` (not 6 GHz).
    pub supported_channels: Vec<u8>,
    pub ht_cap: Option<HtCapIe>,
    pub vht_cap: Option<VhtCapIe>,
    /// `Some(qos_info)` when `assoc_data->wmm`.
    pub wmm_qos_info: Option<u8>,
    /// `assoc_data->ie`: the SME's elements (RSN, ...).
    pub extra_ies: Vec<u8>,
    /// Reassociation: the current AP.
    pub prev_bssid: Option<[u8; 6]>,
}

/// `ieee80211_send_assoc` for a single-link association: header,
/// capability, listen interval [, current AP], SSID, rates, power
/// capability, supported channels, SME elements before HT, HT
/// capabilities, SME elements before VHT, VHT capabilities, the SME's
/// remaining non-vendor elements, WMM Information, the SME's vendor
/// elements.
pub fn build_assoc_req(p: &AssocReqParams) -> Vec<u8> {
    let st = if p.prev_bssid.is_some() {
        stype::REASSOC_REQ
    } else {
        stype::ASSOC_REQ
    };
    let mut f = mgmt_hdr(st, &p.bssid, &p.own, &p.bssid);
    f.extend_from_slice(&p.capab.to_le_bytes());
    f.extend_from_slice(&p.listen_interval.to_le_bytes());
    if let Some(prev) = p.prev_bssid {
        f.extend_from_slice(&prev);
    }
    f.push(eid::SSID);
    f.push(p.ssid.len() as u8);
    f.extend_from_slice(&p.ssid);
    // ieee80211_assoc_add_rates → ieee80211_put_srates_elem ×2
    let n = p.rates.len().min(8);
    f.push(eid::SUPP_RATES);
    f.push(n as u8);
    f.extend_from_slice(&p.rates[..n]);
    if p.rates.len() > 8 {
        f.push(eid::EXT_SUPP_RATES);
        f.push((p.rates.len() - 8) as u8);
        f.extend_from_slice(&p.rates[8..]);
    }
    if let Some((min, max)) = p.pwr_capability {
        f.extend_from_slice(&[eid::PWR_CAPABILITY, 2, min, max]);
    }
    if !p.supported_channels.is_empty() {
        f.push(eid::SUPPORTED_CHANNELS);
        f.push((2 * p.supported_channels.len()) as u8);
        for &c in &p.supported_channels {
            f.push(c);
            f.push(1);
        }
    }
    let ies = &p.extra_ies;
    let mut offset = ie_split(ies, BEFORE_HT, 0);
    f.extend_from_slice(&ies[..offset]);
    if let Some(ht) = &p.ht_cap {
        ht.put(&mut f);
    }
    let next = ie_split(ies, BEFORE_VHT, offset);
    f.extend_from_slice(&ies[offset..next]);
    offset = next;
    if let Some(vht) = &p.vht_cap {
        vht.put(&mut f);
    }
    let next = ie_split_vendor(ies, offset);
    f.extend_from_slice(&ies[offset..next]);
    offset = next;
    if let Some(q) = p.wmm_qos_info {
        put_wmm_info(&mut f, q);
    }
    f.extend_from_slice(&ies[offset..]);
    f
}

// ── EAPOL over Ethernet ─────────────────────────────────────────────

/// `ETH_P_PAE`.
pub const ETH_P_PAE: u16 = 0x888E;

/// An 802.3 frame carrying EAPOL (what the DP layer hands up / takes
/// down in native-wifi mode after 802.11 ↔ 802.3 conversion).
pub fn eapol_eth(dst: &[u8; 6], src: &[u8; 6], eapol: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + eapol.len());
    f.extend_from_slice(dst);
    f.extend_from_slice(src);
    f.extend_from_slice(&ETH_P_PAE.to_be_bytes());
    f.extend_from_slice(eapol);
    f
}

/// `(src, eapol)` of an 802.3 EAPOL frame.
pub fn parse_eapol_eth(f: &[u8]) -> Option<([u8; 6], &[u8])> {
    if f.len() < 14 || u16::from_be_bytes([f[12], f[13]]) != ETH_P_PAE {
        return None;
    }
    let mut src = [0u8; 6];
    src.copy_from_slice(&f[6..12]);
    Some((src, &f[14..]))
}

// ── Channel numbering (`ieee80211_channel_to_frequency`) ────────────

/// Radio band (`enum nl80211_band` order: 2 GHz, 5 GHz, 6 GHz).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Band {
    Ghz2,
    Ghz5,
    Ghz6,
}

/// `ieee80211_channel_to_frequency(chan, band)`.
pub fn channel_to_freq(chan: u32, band: Band) -> Option<u32> {
    match band {
        Band::Ghz2 => match chan {
            14 => Some(2484),
            1..=13 => Some(2407 + chan * 5),
            _ => None,
        },
        Band::Ghz5 => match chan {
            182..=196 => Some(4000 + chan * 5),
            1..=181 => Some(5000 + chan * 5),
            _ => None,
        },
        Band::Ghz6 => match chan {
            2 => Some(5935),
            1..=233 => Some(5950 + chan * 5),
            _ => None,
        },
    }
}

/// `ieee80211_frequency_to_channel`.
pub fn freq_to_channel(freq: u32) -> u32 {
    if freq == 2484 {
        14
    } else if freq < 2484 {
        freq.saturating_sub(2407) / 5
    } else if (4910..=4980).contains(&freq) {
        (freq - 4000) / 5
    } else if freq < 5925 {
        (freq - 5000) / 5
    } else if freq == 5935 {
        2
    } else if freq <= 45000 {
        (freq - 5950) / 5
    } else {
        0
    }
}

/// Band of a centre frequency.
pub fn freq_band(freq: u32) -> Band {
    if freq < 3000 {
        Band::Ghz2
    } else if freq < 5925 {
        Band::Ghz5
    } else {
        Band::Ghz6
    }
}
