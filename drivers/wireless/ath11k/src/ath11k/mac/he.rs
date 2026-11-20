//! HE (802.11ax) for the station: what ath11k (`ath11k_mac_setup_he_cap`,
//! `ath11k_peer_assoc_h_he`, `ath11k_mac_get_phymode_he`,
//! `ath11k_mac_vif_recalc_sta_he_txbf`, the STA arm of
//! `BSS_CHANGED_HE_BSS_COLOR`) and mac80211 (`ieee80211_put_he_cap`,
//! `ieee80211_he_cap_ie_to_sta_he_cap`, `ieee80211_verify_*_he_mcs_support`,
//! `ieee80211_he_spr_ie_to_bss_conf`) do on 2.4 / 5 / 6 GHz.
//!
//! The 6 GHz association pieces include HE 6 GHz Band Capabilities and the
//! optional HE Operation field. Regulatory connectivity / power type
//! enforcement remains in `mac_reg`; non-contiguous 80+80 MHz carries both
//! centre frequencies through the channel and WMI layers. Station TWT tracks
//! mac80211's requester-capability gates and maps `BSS_CHANGED_TWT` to the
//! firmware's enable / disable commands in `mac`.

extern crate alloc;

use alloc::vec::Vec;

use super::super::mac_frame::Band;
use super::super::mac_peer::Width;
use super::super::wmi::{BandCap, PdevCap, PpeThreshold};

/// `WLAN_EID_EXT_HE_CAPABILITY` / `_HE_OPERATION` / `_HE_SPR` /
/// `_HE_6GHZ_CAPA`.
pub const EID_EXT_HE_CAPABILITY: u8 = 35;
pub const EID_EXT_HE_OPERATION: u8 = 36;
pub const EID_EXT_HE_SPR: u8 = 39;
pub const EID_EXT_HE_6GHZ_CAPABILITY: u8 = 59;

/// `IEEE80211_HE_*` bits used here (`include/linux/ieee80211-he.h`).
pub mod cap {
    pub const MAC0_TWT_REQ: u8 = 0x02;
    pub const MAC0_TWT_RES: u8 = 0x04;
    pub const MAC1_TF_MAC_PAD_DUR_MASK: u8 = 0x0c;
    pub const MAC3_MAX_AMPDU_LEN_EXP_MASK: u8 = 0x18;
    pub const PHY0_40MHZ_IN_2G: u8 = 0x02;
    pub const PHY0_40MHZ_80MHZ_IN_5G: u8 = 0x04;
    pub const PHY0_160MHZ_IN_5G: u8 = 0x08;
    pub const PHY0_80PLUS80_MHZ_IN_5G: u8 = 0x10;
    pub const PHY2_UL_MU_FULL_MU_MIMO: u8 = 0x40;
    pub const PHY3_SU_BEAMFORMER: u8 = 0x80;
    pub const PHY4_SU_BEAMFORMEE: u8 = 0x01;
    pub const PHY4_MU_BEAMFORMER: u8 = 0x02;
    pub const PHY5_BEAMFORMEE_NUM_SND_DIM_UNDER_80MHZ_MASK: u8 = 0x07;
    pub const PHY5_BEAMFORMEE_NUM_SND_DIM_ABOVE_80MHZ_MASK: u8 = 0x38;
    pub const PHY6_PPE_THRESHOLD_PRESENT: u8 = 0x80;
    pub const PHY7_STBC_TX_ABOVE_80MHZ: u8 = 0x10;
    pub const PHY7_STBC_RX_ABOVE_80MHZ: u8 = 0x20;
    pub const PHY8_DCM_MAX_RU_MASK: u8 = 0xc0;
    pub const PHY9_LONGER_THAN_16_SIGB_OFDM_SYM: u8 = 0x01;
    pub const PHY9_TX_1024_QAM_LESS_THAN_242_TONE_RU: u8 = 0x04;
}

/// `IEEE80211_HE_6GHZ_CAP_*`.
pub mod cap_6ghz {
    pub const MIN_MPDU_START_MASK: u16 = 0x0007;
    pub const MAX_AMPDU_LEN_EXP_MASK: u16 = 0x0038;
    pub const MAX_MPDU_LEN_MASK: u16 = 0x00c0;
    pub const SM_PS_MASK: u16 = 0x0600;
    pub const RX_ANTPAT_CONS: u16 = 0x1000;
    pub const TX_ANTPAT_CONS: u16 = 0x2000;
}

/// `IEEE80211_HE_OPERATION_*` flags for optional operation fields.
pub mod oper {
    pub const VHT_OPER_INFO: u32 = 1 << 14;
    pub const CO_HOSTED_BSS: u32 = 1 << 15;
    pub const SIX_GHZ_OP_INFO: u32 = 1 << 17;
}

/// `IEEE80211_HE_MCS_SUPPORT_0_11` / `_NOT_SUPPORTED`.
pub const HE_MCS_SUPPORT_0_11: u16 = 2;
pub const HE_MCS_NOT_SUPPORTED: u16 = 3;
/// `IEEE80211_PPE_THRES_*`.
const PPE_NSS_MASK: u8 = 7;
const PPE_RU_MASK: u8 = 0x78;
const PPE_RU_POS: u8 = 3;

/// `struct ieee80211_sta_he_cap`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StaHeCap {
    pub has_he: bool,
    pub mac: [u8; 6],
    pub phy: [u8; 11],
    /// rx_80, tx_80, rx_160, tx_160, rx_80p80, tx_80p80.
    pub mcs: [u16; 6],
    pub ppe: Vec<u8>,
}

/// `ieee80211_he_mcs_nss_size`.
pub fn mcs_nss_size(phy: &[u8]) -> usize {
    let mut n = 4;
    if phy[0] & cap::PHY0_160MHZ_IN_5G != 0 {
        n += 4;
    }
    if phy[0] & cap::PHY0_80PLUS80_MHZ_IN_5G != 0 {
        n += 4;
    }
    n
}

/// `ieee80211_he_ppe_size`.
pub fn ppe_size(hdr: u8, phy: &[u8]) -> usize {
    if phy[6] & cap::PHY6_PPE_THRESHOLD_PRESENT == 0 {
        return 0;
    }
    let n = (hdr & PPE_RU_MASK).count_ones() as usize * (1 + (hdr & PPE_NSS_MASK) as usize);
    (n * 3 * 2 + 7).div_ceil(8)
}

/// `ath11k_gen_ppe_thresh`: the firmware's PPET16 / PPET8 words as the
/// PPE Thresholds field.
pub fn gen_ppe_thresh(fw: &PpeThreshold) -> Vec<u8> {
    let mut out = alloc::vec![0u8; 25];
    out[0] = (fw.numss_m1 as u8) & PPE_NSS_MASK;
    out[0] |= ((fw.ru_bit_mask as u8) << PPE_RU_POS) & PPE_RU_MASK;
    let mut bit = 7usize;
    for nss in 0..=(fw.numss_m1 as usize).min(7) {
        for ru in 0..4 {
            if fw.ru_bit_mask & (1 << ru) == 0 {
                continue;
            }
            let mut val = ((fw.ppet16_ppet8_ru3_ru0[nss] >> (ru * 6)) & 0x3f) as u8;
            val = ((val >> 3) & 0x7) | ((val & 0x7) << 3);
            for i in (0..6).rev() {
                out[bit / 8] |= ((val >> i) & 0x1) << (bit % 8);
                bit += 1;
            }
        }
    }
    out
}

/// `ath11k_mac_copy_he_cap` for `NL80211_IFTYPE_STATION` +
/// `ath11k_mac_set_hemcsmap` (`cfg_tx/rx_chainmask` = the pdev's; the rx
/// map shifts by `tx_chain_mask_shift`, as Linux does).
pub fn own_he_cap(pdev: &PdevCap, band: &BandCap, num_tx: u32, num_rx: u32) -> StaHeCap {
    let mut mac = [0u8; 6];
    let mut phy = [0u8; 11];
    let mut info = [0u8; 8];
    info[..4].copy_from_slice(&band.he_cap_info[0].to_le_bytes());
    info[4..].copy_from_slice(&band.he_cap_info[1].to_le_bytes());
    mac.copy_from_slice(&info[..6]);
    let mut p = [0u8; 12];
    for (i, w) in band.he_cap_phy_info.iter().enumerate() {
        p[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    phy.copy_from_slice(&p[..11]);
    mac[1] &= cap::MAC1_TF_MAC_PAD_DUR_MASK;
    phy[5] &= !cap::PHY5_BEAMFORMEE_NUM_SND_DIM_UNDER_80MHZ_MASK;
    phy[5] |= (num_tx.saturating_sub(1) as u8) & 0x7;
    // NL80211_IFTYPE_STATION
    mac[0] &= !cap::MAC0_TWT_RES;
    mac[0] |= cap::MAC0_TWT_REQ;
    phy[9] |= cap::PHY9_TX_1024_QAM_LESS_THAN_242_TONE_RU;
    let (mut tx, mut rx) = (0u16, 0u16);
    let shift = pdev.tx_chain_mask_shift.min(31);
    for i in 0..8u32 {
        let t = if i < num_tx && (pdev.tx_chain_mask >> shift) & (1 << i) != 0 {
            HE_MCS_SUPPORT_0_11
        } else {
            HE_MCS_NOT_SUPPORTED
        };
        let r = if i < num_rx && (pdev.rx_chain_mask >> shift) & (1 << i) != 0 {
            HE_MCS_SUPPORT_0_11
        } else {
            HE_MCS_NOT_SUPPORTED
        };
        tx |= t << (2 * i);
        rx |= r << (2 * i);
    }
    let ppe = if phy[6] & cap::PHY6_PPE_THRESHOLD_PRESENT != 0 {
        gen_ppe_thresh(&band.he_ppet)
    } else {
        alloc::vec![0u8; 25]
    };
    StaHeCap {
        has_he: true,
        mac,
        phy,
        mcs: [rx, tx, rx, tx, rx, tx],
        ppe,
    }
}

/// `ath11k_mac_setup_he_6ghz_cap`: synthesize the station's HE 6 GHz Band
/// Capabilities from the firmware's copied 5/6 GHz capability set.
pub fn own_he_6ghz_cap(pdev: &PdevCap, band: &BandCap) -> u16 {
    use super::super::mac_peer::{sm_ps, vht, wmi_ht};

    let mut out = 0u16; // IEEE80211_HT_MPDU_DENSITY_NONE
    out |= if band.ht_cap_info & wmi_ht::DYNAMIC_SMPS != 0 {
        sm_ps::DYNAMIC << 9
    } else {
        sm_ps::DISABLED << 9
    };
    out |= ((pdev.vht_cap & vht::MAX_A_MPDU_LENGTH_EXPONENT_MASK) >> 20) as u16;
    out |= ((pdev.vht_cap & vht::MAX_MPDU_MASK) << 6) as u16;
    if pdev.vht_cap & vht::RX_ANTENNA_PATTERN != 0 {
        out |= cap_6ghz::RX_ANTPAT_CONS;
    }
    if pdev.vht_cap & vht::TX_ANTENNA_PATTERN != 0 {
        out |= cap_6ghz::TX_ANTPAT_CONS;
    }
    out
}

/// `ieee80211_ie_build_he_6ghz_cap`: a complete Extension IE.
pub fn put_he_6ghz_cap(cap: u16) -> Vec<u8> {
    let mut out = alloc::vec![0xFF, 3, EID_EXT_HE_6GHZ_CAPABILITY];
    out.extend_from_slice(&cap.to_le_bytes());
    out
}

/// Validate and decode the two-byte HE 6 GHz Band Capabilities extension
/// payload (the bytes after extension id 59).
pub fn parse_he_6ghz_cap(d: &[u8]) -> Option<u16> {
    (d.len() == 2).then(|| u16::from_le_bytes([d[0], d[1]]))
}

/// `ieee80211_get_adjusted_he_cap` + `ieee80211_put_he_cap`: the HE
/// Capabilities element of the Association Request for the connection
/// width `width` (`conn->bw_limit`).
pub fn put_he_cap(own: &StaHeCap, width: Width) -> Vec<u8> {
    let mut phy = own.phy;
    let ru_limit = match width {
        Width::W20NoHt | Width::W20 => 0x00,
        Width::W40 => 0x40,
        Width::W80 => 0x80,
        Width::W80P80 => 0xc0,
        Width::W160 => 0xc0,
    };
    let max_ru = (phy[8] & cap::PHY8_DCM_MAX_RU_MASK).min(ru_limit);
    phy[8] = (phy[8] & !cap::PHY8_DCM_MAX_RU_MASK) | max_ru;
    if width < Width::W40 {
        phy[0] &= !(cap::PHY0_40MHZ_80MHZ_IN_5G | cap::PHY0_40MHZ_IN_2G);
        phy[9] &= !cap::PHY9_LONGER_THAN_16_SIGB_OFDM_SYM;
    }
    if !matches!(width, Width::W160 | Width::W80P80) {
        phy[0] &= !(cap::PHY0_160MHZ_IN_5G | cap::PHY0_80PLUS80_MHZ_IN_5G);
        phy[5] &= !cap::PHY5_BEAMFORMEE_NUM_SND_DIM_ABOVE_80MHZ_MASK;
        phy[7] &= !(cap::PHY7_STBC_TX_ABOVE_80MHZ | cap::PHY7_STBC_RX_ABOVE_80MHZ);
    } else if width == Width::W160 {
        phy[0] &= !cap::PHY0_80PLUS80_MHZ_IN_5G;
    } else {
        phy[0] &= !cap::PHY0_160MHZ_IN_5G;
    }
    let mut out = alloc::vec![0xFF, 0, EID_EXT_HE_CAPABILITY];
    out.extend_from_slice(&own.mac);
    out.extend_from_slice(&phy);
    for &(rx, tx, required_bit) in &[
        (0usize, 1usize, 0u8),
        (2, 3, cap::PHY0_160MHZ_IN_5G),
        (4, 5, cap::PHY0_80PLUS80_MHZ_IN_5G),
    ] {
        if required_bit == 0 || phy[0] & required_bit != 0 {
            out.extend_from_slice(&own.mcs[rx].to_le_bytes());
            out.extend_from_slice(&own.mcs[tx].to_le_bytes());
        }
    }
    // PPE presence and size from the unadjusted capabilities.
    let p = ppe_size(own.ppe.first().copied().unwrap_or(0), &own.phy);
    out.extend_from_slice(&own.ppe[..p.min(own.ppe.len())]);
    out[1] = (out.len() - 2) as u8;
    out
}

/// A parsed HE Capabilities element (`ieee80211_he_capa_size_ok`).
pub fn parse_he_cap(d: &[u8]) -> Option<StaHeCap> {
    if d.len() < 17 {
        return None;
    }
    let phy: [u8; 11] = d[6..17].try_into().unwrap();
    let n = mcs_nss_size(&phy);
    if d.len() < 17 + n {
        return None;
    }
    let ppe_hdr = d.get(17 + n).copied().unwrap_or(0);
    let p = ppe_size(ppe_hdr, &phy);
    if d.len() < 17 + n + p {
        return None;
    }
    let mut mcs = [HE_MCS_NOT_SUPPORTED * 0x5555; 6];
    let mut pos = 17;
    for &(rx, tx, required_bit) in &[
        (0usize, 1usize, 0u8),
        (2, 3, cap::PHY0_160MHZ_IN_5G),
        (4, 5, cap::PHY0_80PLUS80_MHZ_IN_5G),
    ] {
        if required_bit == 0 || phy[0] & required_bit != 0 {
            mcs[rx] = u16::from_le_bytes([d[pos], d[pos + 1]]);
            mcs[tx] = u16::from_le_bytes([d[pos + 2], d[pos + 3]]);
            pos += 4;
        }
    }
    Some(StaHeCap {
        has_he: true,
        mac: d[..6].try_into().unwrap(),
        phy,
        mcs,
        ppe: d[17 + n..17 + n + p].to_vec(),
    })
}

/// `struct ieee80211_he_6ghz_oper`, the optional tail of HE Operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct He6GhzOper {
    pub primary: u8,
    /// Channel-width bits 0..1, duplicate-beacon bit 2, regulatory-info
    /// bits 3..6.
    pub control: u8,
    pub ccfs0: u8,
    pub ccfs1: u8,
    pub minrate: u8,
}

impl He6GhzOper {
    pub const WIDTH_MASK: u8 = 0x03;
    pub const WIDTH_20: u8 = 0;
    pub const WIDTH_40: u8 = 1;
    pub const WIDTH_80: u8 = 2;
    pub const WIDTH_160: u8 = 3;
}

/// The HE Operation element's fixed fields (`struct ieee80211_he_operation`)
/// plus its validated optional six-GHz operation field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeOper {
    /// `he_oper_params` (params + BSS Color Information in the top byte).
    pub params: u32,
    /// Basic HE-MCS And NSS Set.
    pub mcs_nss_set: u16,
    pub six_ghz: Option<He6GhzOper>,
}

impl HeOper {
    /// `ieee80211_he_oper_size_ok`, including optional fields that precede
    /// `ieee80211_he_6ghz_oper`.
    pub fn parse(d: &[u8]) -> Option<Self> {
        if d.len() < 6 {
            return None;
        }
        let params = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        let mut pos = 6;
        if params & oper::VHT_OPER_INFO != 0 {
            pos += 3;
        }
        if params & oper::CO_HOSTED_BSS != 0 {
            pos += 1;
        }
        let six_ghz = if params & oper::SIX_GHZ_OP_INFO != 0 {
            let d = d.get(pos..pos + 5)?;
            Some(He6GhzOper {
                primary: d[0],
                control: d[1],
                ccfs0: d[2],
                ccfs1: d[3],
                minrate: d[4],
            })
        } else {
            None
        };
        Some(HeOper {
            params,
            mcs_nss_set: u16::from_le_bytes([d[4], d[5]]),
            six_ghz,
        })
    }
    /// `IEEE80211_HE_OPERATION_BSS_COLOR_MASK` / `_DISABLED`.
    pub fn bss_color(&self) -> u8 {
        ((self.params >> 24) & 0x3f) as u8
    }
    pub fn bss_color_disabled(&self) -> bool {
        self.params & (1 << 31) != 0
    }
}

/// `ieee80211_he_spr_ie_to_bss_conf` → `he_obss_pd` (enable, min, max).
pub fn spr_obss_pd(d: Option<&[u8]>) -> (u32, i32, i32) {
    let Some(d) = d.filter(|d| !d.is_empty()) else {
        return (0, 0, 0);
    };
    let ctrl = d[0];
    let mut pos = 1;
    // IEEE80211_HE_SPR_NON_SRG_OFFSET_PRESENT
    if ctrl & 0x04 != 0 {
        pos += 1;
    }
    // IEEE80211_HE_SPR_SRG_INFORMATION_PRESENT
    if ctrl & 0x08 != 0 && d.len() >= pos + 2 {
        return (1, d[pos] as i32, d[pos + 1] as i32);
    }
    (0, 0, 0)
}

/// `ieee80211_verify_peer_he_mcs_support` && `ieee80211_verify_sta_he_mcs_support`
/// (non-STRICT: an all-zero basic set is accepted).
pub fn he_mcs_ok(own: &StaHeCap, ap: &StaHeCap, op: &HeOper) -> bool {
    let (ap_rx, ap_tx) = (ap.mcs[0], ap.mcs[1]);
    if ap_tx & 3 == HE_MCS_NOT_SUPPORTED || ap_rx & 3 == HE_MCS_NOT_SUPPORTED {
        return false;
    }
    let req = op.mcs_nss_set;
    if req == 0 {
        return true;
    }
    let g = |m: u16, nss: u16| (m >> (2 * (nss - 1))) & 3;
    for nss in (1..=8).rev() {
        let v = g(req, nss);
        if v == HE_MCS_NOT_SUPPORTED {
            continue;
        }
        let (r, t) = (g(ap_rx, nss), g(ap_tx, nss));
        if r == HE_MCS_NOT_SUPPORTED || t == HE_MCS_NOT_SUPPORTED || r < v || t < v {
            return false;
        }
    }
    'bw: for i in 0..3 {
        let (rx, tx) = (own.mcs[2 * i], own.mcs[2 * i + 1]);
        for nss in (1..=8).rev() {
            let v = g(req, nss);
            if v == HE_MCS_NOT_SUPPORTED {
                continue;
            }
            let (r, t) = (g(rx, nss), g(tx, nss));
            if r == HE_MCS_NOT_SUPPORTED || t == HE_MCS_NOT_SUPPORTED || v > r || v > t {
                continue 'bw;
            }
        }
        return true;
    }
    false
}

/// `ieee80211_he_mcs_intersection`.
fn mcs_intersection(own_rx: u16, peer_rx: &mut u16, own_tx: u16, peer_tx: &mut u16) {
    for i in 0..8 {
        let s = 2 * i;
        let (orx, otx) = ((own_rx >> s) & 3, (own_tx >> s) & 3);
        let (mut prx, mut ptx) = ((*peer_rx >> s) & 3, (*peer_tx >> s) & 3);
        if ptx != HE_MCS_NOT_SUPPORTED {
            if orx == HE_MCS_NOT_SUPPORTED {
                ptx = HE_MCS_NOT_SUPPORTED;
            } else if orx < ptx {
                ptx = orx;
            }
        }
        if prx != HE_MCS_NOT_SUPPORTED {
            if otx == HE_MCS_NOT_SUPPORTED {
                prx = HE_MCS_NOT_SUPPORTED;
            } else if otx < prx {
                prx = otx;
            }
        }
        *peer_rx = (*peer_rx & !(3 << s)) | (prx << s);
        *peer_tx = (*peer_tx & !(3 << s)) | (ptx << s);
    }
}

/// `ieee80211_he_cap_ie_to_sta_he_cap`: the AP's HE capabilities with
/// the MCS maps intersected with ours (160 / 80+80 disabled individually
/// when we lack them).
pub fn sta_he_cap(own: &StaHeCap, ap: &StaHeCap) -> StaHeCap {
    let mut h = ap.clone();
    let (a, b) = h.mcs.split_at_mut(1);
    mcs_intersection(own.mcs[0], &mut a[0], own.mcs[1], &mut b[0]);
    for (bit, idx) in [
        (cap::PHY0_160MHZ_IN_5G, 2usize),
        (cap::PHY0_80PLUS80_MHZ_IN_5G, 4),
    ] {
        let peer = h.phy[0] & bit != 0;
        let mine = own.phy[0] & bit != 0;
        if peer && mine {
            let (mut rx, mut tx) = (h.mcs[idx], h.mcs[idx + 1]);
            mcs_intersection(own.mcs[idx], &mut rx, own.mcs[idx + 1], &mut tx);
            h.mcs[idx] = rx;
            h.mcs[idx + 1] = tx;
        } else if peer {
            h.mcs[idx] |= 0xffff;
            h.mcs[idx + 1] |= 0xffff;
            h.phy[0] &= !bit;
        }
    }
    h
}

/// `_ieee80211_sta_cap_rx_bw` for an HE station: the widths its HE PHY
/// capabilities allow on `band`.
pub fn he_cap_rx_bw(h: &StaHeCap, band: Band) -> u32 {
    let info = h.phy[0];
    if band == Band::Ghz2 {
        return if info & cap::PHY0_40MHZ_IN_2G != 0 {
            40
        } else {
            20
        };
    }
    if info & (cap::PHY0_160MHZ_IN_5G | cap::PHY0_80PLUS80_MHZ_IN_5G) != 0 {
        160
    } else if info & cap::PHY0_40MHZ_80MHZ_IN_5G != 0 {
        80
    } else {
        20
    }
}

/// `ieee80211_sta_init_nss`'s HE part: NSS of the rx 80 MHz map (and
/// the 160 MHz one when supported).
pub fn he_rx_nss(h: &StaHeCap) -> u8 {
    let top = |m: u16| {
        (0..8)
            .rev()
            .find(|&i| (m >> (2 * i)) & 3 != HE_MCS_NOT_SUPPORTED)
            .map_or(0, |i| i + 1)
    };
    let mut n = top(h.mcs[0]);
    if h.phy[0] & cap::PHY0_160MHZ_IN_5G != 0 {
        n = n.min(top(h.mcs[2]));
    }
    n as u8
}

/// `HE_MODE_*` fields of `WMI_VDEV_PARAM_SET_HEMU_MODE` (ath11k `wmi.h`).
pub mod hemode {
    pub const SU_TX_BFEE: u32 = 1 << 0;
    pub const SU_TX_BFER: u32 = 1 << 1;
    pub const MU_TX_BFEE: u32 = 1 << 2;
    pub const MU_TX_BFER: u32 = 1 << 3;
    pub const DL_OFDMA: u32 = 1 << 4;
    pub const UL_OFDMA: u32 = 1 << 5;
    pub const UL_MUMIMO: u32 = 1 << 6;
}

/// `ath11k_mac_vif_recalc_sta_he_txbf`'s `hemode` (`HECAP_PHY_SUBFME_GET`
/// = our phy[4] bit 0, `HECAP_PHY_SUBFMR_GET` / `_MUBFMR_GET` = the AP's
/// phy[3] bit 7 / phy[4] bit 1, `HECAP_PHY_ULMUMIMO_GET` = phy[2] bit 6).
pub fn sta_hemu_mode(own: &StaHeCap, ap: &StaHeCap) -> u32 {
    let mut m = 0;
    if own.phy[4] & cap::PHY4_SU_BEAMFORMEE != 0 {
        if ap.phy[3] & cap::PHY3_SU_BEAMFORMER != 0 {
            m |= hemode::SU_TX_BFEE;
        }
        if ap.phy[4] & cap::PHY4_MU_BEAMFORMER != 0 {
            m |= hemode::MU_TX_BFEE;
        }
    }
    m |= hemode::DL_OFDMA | hemode::UL_OFDMA;
    if own.phy[2] & cap::PHY2_UL_MU_FULL_MU_MIMO != 0
        && ap.phy[2] & cap::PHY2_UL_MU_FULL_MU_MIMO != 0
    {
        m |= hemode::UL_MUMIMO;
    }
    if m & hemode::MU_TX_BFEE != 0 {
        m |= hemode::SU_TX_BFEE;
    }
    if m & hemode::MU_TX_BFER != 0 {
        m |= hemode::SU_TX_BFER;
    }
    m
}
