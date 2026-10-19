//! HT / VHT capabilities, channel-definition selection and
//! `WMI_PEER_ASSOC_CMDID` parameters for the AP peer.
//!
//! - Own capabilities: `ath11k_create_ht_cap` / `ath11k_create_vht_cap`
//!   / `ath11k_set_vht_txbf_cap` (ath11k mac.c), from the firmware's
//!   SERVICE_READY_EXT pdev capabilities.
//! - What we advertise in the Association Request: mac80211
//!   `ieee80211_add_ht_ie` / `ieee80211_add_vht_ie`.
//! - The AP station's capabilities: mac80211
//!   `ieee80211_ht_cap_ie_to_sta_ht_cap`,
//!   `ieee80211_vht_cap_ie_to_sta_vht_cap`, `ieee80211_sta_init_nss`,
//!   `ieee80211_sta_cur_vht_bw`.
//! - The operating channel: mac80211 `ieee80211_determine_ap_chan`
//!   (HT / VHT operation), downgraded until `cfg80211_chandef_usable`.
//! - `ath11k_peer_assoc_prepare` and its `ath11k_peer_assoc_h_*`
//!   helpers.
//!
//! NARF advertises HT, VHT and HE on 2.4 / 5 / 6 GHz. It carries both
//! contiguous 160 MHz and non-contiguous 80+80 MHz channel definitions
//! through Linux's VHT/HE and WMI representation.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use narf_wireless::TxBitrateBand;

use super::mac_frame::{
    channel_to_freq, Band, HtCapIe, HtOperIe, VhtCapIe, VhtOperIe, HT_PARAM_CHA_SEC_ABOVE,
    HT_PARAM_CHA_SEC_BELOW, HT_PARAM_CHA_SEC_OFFSET,
};
use super::mac_reg::{chan_flag, Wiphy};
use super::wmi::{phy_mode, PdevCap, PeerAssocParams};

// ── Constants ───────────────────────────────────────────────────────

/// `IEEE80211_HT_CAP_*`.
pub mod ht {
    pub const LDPC_CODING: u16 = 0x0001;
    pub const SUP_WIDTH_20_40: u16 = 0x0002;
    pub const SM_PS: u16 = 0x000C;
    pub const SM_PS_SHIFT: u16 = 2;
    pub const GRN_FLD: u16 = 0x0010;
    pub const SGI_20: u16 = 0x0020;
    pub const SGI_40: u16 = 0x0040;
    pub const TX_STBC: u16 = 0x0080;
    pub const RX_STBC: u16 = 0x0300;
    pub const RX_STBC_SHIFT: u16 = 8;
    pub const MAX_AMSDU: u16 = 0x0800;
    pub const DSSSCCK40: u16 = 0x1000;
    pub const LSIG_TXOP_PROT: u16 = 0x8000;
    /// `IEEE80211_HT_MCS_TX_DEFINED`.
    pub const MCS_TX_DEFINED: u8 = 0x01;
    pub const MCS_TX_RX_DIFF: u8 = 0x02;
    pub const MCS_TX_MAX_STREAMS_MASK: u8 = 0x0C;
    pub const MCS_TX_MAX_STREAMS_SHIFT: u8 = 2;
    pub const MCS_TX_UNEQUAL_MODULATION: u8 = 0x10;
    /// `IEEE80211_HT_MAX_AMPDU_FACTOR`.
    pub const MAX_AMPDU_FACTOR: u32 = 13;
    /// `IEEE80211_HT_MAX_AMPDU_64K`.
    pub const MAX_AMPDU_64K: u8 = 3;
}

/// `WLAN_HT_CAP_SM_PS_*`.
pub mod sm_ps {
    pub const STATIC: u16 = 0;
    pub const DYNAMIC: u16 = 1;
    pub const INVALID: u16 = 2;
    pub const DISABLED: u16 = 3;
}

/// `WMI_HT_CAP_*` (ath11k mac.h) — the firmware's `ht_cap_info`.
pub mod wmi_ht {
    pub const ENABLED: u32 = 0x0001;
    pub const HT20_SGI: u32 = 0x0002;
    pub const DYNAMIC_SMPS: u32 = 0x0004;
    pub const TX_STBC: u32 = 0x0008;
    pub const RX_STBC: u32 = 0x0030;
    pub const RX_STBC_MASK_SHIFT: u32 = 4;
    pub const L_SIG_TXOP_PROT: u32 = 0x0080;
    pub const HT40_SGI: u32 = 0x0800;
    pub const RX_LDPC: u32 = 0x1000;
    /// `WMI_VHT_CAP_MAX_MPDU_LEN_MASK`.
    pub const VHT_MAX_MPDU_LEN_MASK: u32 = 0x3;
}

/// `IEEE80211_VHT_CAP_*`.
pub mod vht {
    pub const MAX_MPDU_MASK: u32 = 0x0000_0003;
    pub const SUPP_CHAN_WIDTH_160MHZ: u32 = 0x0000_0004;
    pub const SUPP_CHAN_WIDTH_160_80PLUS80MHZ: u32 = 0x0000_0008;
    pub const SUPP_CHAN_WIDTH_MASK: u32 = 0x0000_000C;
    pub const RXLDPC: u32 = 0x0000_0010;
    pub const SHORT_GI_80: u32 = 0x0000_0020;
    pub const SHORT_GI_160: u32 = 0x0000_0040;
    pub const TXSTBC: u32 = 0x0000_0080;
    pub const RXSTBC_MASK: u32 = 0x0000_0700;
    pub const SU_BEAMFORMER_CAPABLE: u32 = 0x0000_0800;
    pub const SU_BEAMFORMEE_CAPABLE: u32 = 0x0000_1000;
    pub const BEAMFORMEE_STS_SHIFT: u32 = 13;
    pub const BEAMFORMEE_STS_MASK: u32 = 0x7 << 13;
    pub const SOUNDING_DIMENSIONS_SHIFT: u32 = 16;
    pub const SOUNDING_DIMENSIONS_MASK: u32 = 0x7 << 16;
    pub const MU_BEAMFORMER_CAPABLE: u32 = 0x0008_0000;
    pub const MU_BEAMFORMEE_CAPABLE: u32 = 0x0010_0000;
    pub const VHT_TXOP_PS: u32 = 0x0020_0000;
    pub const HTC_VHT: u32 = 0x0040_0000;
    pub const MAX_A_MPDU_LENGTH_EXPONENT_SHIFT: u32 = 23;
    pub const MAX_A_MPDU_LENGTH_EXPONENT_MASK: u32 = 0x7 << 23;
    pub const LINK_ADAPTATION_VHT_UNSOL_MFB: u32 = 0x0800_0000;
    pub const LINK_ADAPTATION_VHT_MRQ_MFB: u32 = 0x0C00_0000;
    pub const RX_ANTENNA_PATTERN: u32 = 0x1000_0000;
    pub const TX_ANTENNA_PATTERN: u32 = 0x2000_0000;
    pub const EXT_NSS_BW_MASK: u32 = 0xC000_0000;
    /// `IEEE80211_VHT_EXT_NSS_BW_CAPABLE` (in `tx_highest`).
    pub const EXT_NSS_BW_CAPABLE: u16 = 1 << 13;
    pub const MCS_SUPPORT_0_7: u16 = 0;
    pub const MCS_SUPPORT_0_8: u16 = 1;
    pub const MCS_SUPPORT_0_9: u16 = 2;
    pub const MCS_NOT_SUPPORTED: u16 = 3;
    /// ath11k mac.h `IEEE80211_VHT_MCS_SUPPORT_0_11_MASK` / `IEEE80211_DISABLE_VHT_MCS_SUPPORT_0_11`.
    pub const MCS_SUPPORT_0_11_MASK: u32 = 0x00FF_0000;
    pub const DISABLE_MCS_SUPPORT_0_11: u32 = 1 << 24;
}

/// `WMI_HOST_RC_*` (ath11k mac.h).
pub mod rc {
    pub const DS_FLAG: u32 = 0x01;
    pub const CW40_FLAG: u32 = 0x02;
    pub const SGI_FLAG: u32 = 0x04;
    pub const HT_FLAG: u32 = 0x08;
    pub const TX_STBC_FLAG: u32 = 0x20;
    pub const RX_STBC_FLAG_S: u32 = 6;
    pub const TS_FLAG: u32 = 0x200;
    pub const UAPSD_FLAG: u32 = 0x400;
}

/// `ATH11K_BW_NSS_MAP_ENABLE`, `ATH11K_PEER_RX_NSS_160MHZ`, and
/// `ATH11K_PEER_RX_NSS_80_80MHZ` in ath11k's peer-association argument.
/// Each field holds NSS - 1.
const BW_NSS_MAP_ENABLE: u32 = 1 << 31;
const PEER_RX_NSS_160MHZ_MASK: u32 = 0x7;
const PEER_RX_NSS_80_80MHZ_MASK: u32 = 0x38;

/// `enum wmi_nss_ratio`, as Linux's `ath11k_get_nss_160mhz` accepts it.
/// Firmware values for unsupported ratios intentionally produce no override,
/// matching ath11k's warning-and-return behavior.
mod nss_ratio {
    pub const ONE_HALF: u32 = 0;
    pub const ONE: u32 = 2;
}

fn nss_wide_override(nss: u32, is_80p80: bool) -> Option<u32> {
    nss.checked_sub(1)
        .filter(|&nss_m1| nss_m1 <= PEER_RX_NSS_160MHZ_MASK)
        .map(|nss_m1| {
            let field = if is_80p80 {
                (nss_m1 << 3) & PEER_RX_NSS_80_80MHZ_MASK
            } else {
                nss_m1
            };
            BW_NSS_MAP_ENABLE | field
        })
}

fn nss_160_limit(nss_ratio_info: u32, max_nss: u32) -> Option<u32> {
    match nss_ratio_info {
        nss_ratio::ONE_HALF => Some(max_nss >> 1),
        nss_ratio::ONE => Some(max_nss),
        _ => None,
    }
}

/// `enum wmi_peer_smps_state` via `ath11k_smps_map[]`.
pub fn smps_map(sm: u16) -> Option<u32> {
    match sm {
        sm_ps::STATIC => Some(1),
        sm_ps::DYNAMIC => Some(2),
        sm_ps::INVALID | sm_ps::DISABLED => Some(0),
        _ => None,
    }
}

/// Number of set bits (`get_num_chains`).
pub fn num_chains(mask: u32) -> u32 {
    mask.count_ones()
}

// ── Own capabilities ────────────────────────────────────────────────

/// `struct ieee80211_sta_ht_cap`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StaHtCap {
    pub ht_supported: bool,
    pub cap: u16,
    pub ampdu_factor: u8,
    pub ampdu_density: u8,
    pub rx_mask: [u8; 10],
    pub rx_highest: u16,
    pub tx_params: u8,
}

/// `struct ieee80211_sta_vht_cap`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StaVhtCap {
    pub vht_supported: bool,
    pub cap: u32,
    pub rx_mcs_map: u16,
    pub rx_highest: u16,
    pub tx_mcs_map: u16,
    pub tx_highest: u16,
}

/// The per-band capabilities the wiphy advertises (`sband->ht_cap`,
/// `sband->vht_cap`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnCaps {
    pub ht_2g: StaHtCap,
    pub ht_5g: StaHtCap,
    pub vht_5g: StaVhtCap,
    pub num_tx_chains: u32,
    pub num_rx_chains: u32,
    /// The last band's `ht_cap_info` (`ath11k_mac_setup_ht_vht_cap`'s
    /// out-parameter), which decides `NL80211_FEATURE_DYNAMIC_SMPS`.
    pub ht_cap_info: u32,
}

impl OwnCaps {
    pub fn ht(&self, b: Band) -> &StaHtCap {
        match b {
            Band::Ghz2 => &self.ht_2g,
            _ => &self.ht_5g,
        }
    }

    pub fn vht(&self, b: Band) -> Option<&StaVhtCap> {
        match b {
            Band::Ghz5 if self.vht_5g.vht_supported => Some(&self.vht_5g),
            _ => None,
        }
    }
}

/// `ath11k_create_ht_cap(ar, ht_cap_info, rate_cap_rx_chainmask)`.
pub fn create_ht_cap(
    ar_ht_cap: u32,
    rx_chainmask: u32,
    num_rx_chains: u32,
    ar_vht_cap: u32,
) -> StaHtCap {
    let mut c = StaHtCap::default();
    if ar_ht_cap & wmi_ht::ENABLED == 0 {
        return c;
    }
    c.ht_supported = true;
    c.ampdu_factor = ht::MAX_AMPDU_64K;
    c.ampdu_density = 0;
    c.cap |= ht::SUP_WIDTH_20_40 | ht::DSSSCCK40;
    c.cap |= sm_ps::STATIC << ht::SM_PS_SHIFT;
    if ar_ht_cap & wmi_ht::HT20_SGI != 0 {
        c.cap |= ht::SGI_20;
    }
    if ar_ht_cap & wmi_ht::HT40_SGI != 0 {
        c.cap |= ht::SGI_40;
    }
    if ar_ht_cap & wmi_ht::DYNAMIC_SMPS != 0 {
        c.cap |= sm_ps::DYNAMIC << ht::SM_PS_SHIFT;
    }
    if ar_ht_cap & wmi_ht::TX_STBC != 0 {
        c.cap |= ht::TX_STBC;
    }
    if ar_ht_cap & wmi_ht::RX_STBC != 0 {
        let stbc = ((ar_ht_cap & wmi_ht::RX_STBC) >> wmi_ht::RX_STBC_MASK_SHIFT) as u16;
        c.cap |= (stbc << ht::RX_STBC_SHIFT) & ht::RX_STBC;
    }
    if ar_ht_cap & wmi_ht::RX_LDPC != 0 {
        c.cap |= ht::LDPC_CODING;
    }
    if ar_ht_cap & wmi_ht::L_SIG_TXOP_PROT != 0 {
        c.cap |= ht::LSIG_TXOP_PROT;
    }
    if ar_vht_cap & wmi_ht::VHT_MAX_MPDU_LEN_MASK != 0 {
        c.cap |= ht::MAX_AMSDU;
    }
    for i in 0..num_rx_chains.min(10) {
        if rx_chainmask & (1 << i) != 0 {
            c.rx_mask[i as usize] = 0xFF;
        }
    }
    c.tx_params |= ht::MCS_TX_DEFINED;
    c
}

/// `ath11k_set_vht_txbf_cap`.
pub fn set_vht_txbf_cap(cap: &mut u32, num_tx: u32, num_rx: u32) {
    let mut subfer = *cap & vht::SU_BEAMFORMER_CAPABLE != 0;
    let mut subfee = *cap & vht::SU_BEAMFORMEE_CAPABLE != 0;
    if num_tx < 2 {
        *cap &= !vht::SU_BEAMFORMER_CAPABLE;
        subfer = false;
    }
    if num_rx < 2 {
        *cap &= !vht::SU_BEAMFORMEE_CAPABLE;
        subfee = false;
    }
    if !subfer {
        *cap &= !vht::MU_BEAMFORMER_CAPABLE;
    }
    if !subfee {
        *cap &= !vht::MU_BEAMFORMEE_CAPABLE;
    }
    let mut sound_dim = (*cap & vht::SOUNDING_DIMENSIONS_MASK) >> vht::SOUNDING_DIMENSIONS_SHIFT;
    *cap &= !vht::SOUNDING_DIMENSIONS_MASK;
    let nsts = (*cap & vht::BEAMFORMEE_STS_MASK) >> vht::BEAMFORMEE_STS_SHIFT;
    *cap &= !vht::BEAMFORMEE_STS_MASK;
    if subfer {
        if sound_dim > num_tx.saturating_sub(1) {
            sound_dim = num_tx.saturating_sub(1);
        }
        *cap |= (sound_dim << vht::SOUNDING_DIMENSIONS_SHIFT) & vht::SOUNDING_DIMENSIONS_MASK;
    }
    if subfee {
        *cap |= (nsts << vht::BEAMFORMEE_STS_SHIFT) & vht::BEAMFORMEE_STS_MASK;
    }
}

/// `ath11k_create_vht_cap(ar, rate_cap_tx_chainmask, rate_cap_rx_chainmask)`.
pub fn create_vht_cap(
    pdev: &PdevCap,
    tx_mask: u32,
    rx_mask: u32,
    num_tx: u32,
    num_rx: u32,
) -> StaVhtCap {
    let mut v = StaVhtCap {
        vht_supported: true,
        cap: pdev.vht_cap,
        ..Default::default()
    };
    if pdev.nss_ratio_enabled != 0 {
        v.tx_highest |= vht::EXT_NSS_BW_CAPABLE;
    }
    set_vht_txbf_cap(&mut v.cap, num_tx, num_rx);
    let (mut rxm, mut txm) = (0u16, 0u16);
    for i in 0..8u32 {
        let s = (i * 2) as u16;
        if i < num_tx && tx_mask & (1 << i) != 0 {
            txm |= vht::MCS_SUPPORT_0_9 << s;
        } else {
            txm |= vht::MCS_NOT_SUPPORTED << s;
        }
        if i < num_rx && rx_mask & (1 << i) != 0 {
            rxm |= vht::MCS_SUPPORT_0_9 << s;
        } else {
            rxm |= vht::MCS_NOT_SUPPORTED << s;
        }
    }
    if tx_mask <= 1 {
        v.cap &= !vht::TXSTBC;
    }
    v.rx_mcs_map = rxm;
    v.tx_mcs_map = txm;
    v
}

/// `ath11k_mac_setup_ht_vht_cap` with `cfg_{tx,rx}_chainmask` = the pdev
/// chain masks (`ath11k_mac_register`).
pub fn own_caps(pdev: &PdevCap) -> OwnCaps {
    let tx_mask = pdev.tx_chain_mask >> pdev.tx_chain_mask_shift;
    let rx_mask = pdev.rx_chain_mask >> pdev.rx_chain_mask_shift;
    let num_tx = num_chains(pdev.tx_chain_mask);
    let num_rx = num_chains(pdev.rx_chain_mask);
    let mut o = OwnCaps {
        num_tx_chains: num_tx,
        num_rx_chains: num_rx,
        ..Default::default()
    };
    if pdev.supported_bands & super::wmi::WMI_HOST_WLAN_2G_CAP != 0 {
        o.ht_cap_info = pdev.band_2g.ht_cap_info;
        o.ht_2g = create_ht_cap(pdev.band_2g.ht_cap_info, rx_mask, num_rx, pdev.vht_cap);
    }
    if pdev.supported_bands & super::wmi::WMI_HOST_WLAN_5G_CAP != 0 {
        o.ht_cap_info = pdev.band_5g.ht_cap_info;
        o.ht_5g = create_ht_cap(pdev.band_5g.ht_cap_info, rx_mask, num_rx, pdev.vht_cap);
        o.vht_5g = create_vht_cap(pdev, tx_mask, rx_mask, num_tx, num_rx);
    }
    o
}

// ── Channel definition ──────────────────────────────────────────────

/// `enum nl80211_chan_width` subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Width {
    W20NoHt,
    W20,
    W40,
    W80,
    /// Two non-contiguous 80 MHz segments (`center_freq1`, `center_freq2`).
    W80P80,
    /// A contiguous 160 MHz channel.
    W160,
}

/// `struct cfg80211_chan_def`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChanDef {
    pub freq: u32,
    pub band: Band,
    pub width: Width,
    pub center_freq1: u32,
    /// Zero except [`Width::W80P80`].
    pub center_freq2: u32,
}

/// `enum ieee80211_conn_mode` subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConnMode {
    Legacy,
    Ht,
    Vht,
    He,
}

/// `cfg80211_chandef_usable` for the flags NARF tracks: every 20 MHz
/// sub-channel enabled, `NO_HT40±` on the primary for 40 MHz, `NO_80MHZ`
/// for 80 MHz, and `NO_160MHZ` for 160 MHz.
pub fn chandef_usable(w: &Wiphy, c: &ChanDef) -> bool {
    let Some(prim) = w.get(c.freq) else {
        return false;
    };
    if prim.flags & chan_flag::DISABLED != 0 {
        return false;
    }
    if c.width == Width::W80P80 {
        if prim.flags & chan_flag::NO_80MHZ != 0
            || c.center_freq2 == 0
            || c.center_freq1.abs_diff(c.center_freq2) <= 80
        {
            return false;
        }
        for center in [c.center_freq1, c.center_freq2] {
            let mut f = center - 30;
            while f <= center + 30 {
                match w.get(f) {
                    Some(x) if x.flags & (chan_flag::DISABLED | chan_flag::NO_80MHZ) == 0 => {}
                    _ => return false,
                }
                f += 20;
            }
        }
        return true;
    }
    let (lo, hi) = match c.width {
        Width::W20NoHt | Width::W20 => return true,
        Width::W40 => {
            let f = if c.center_freq1 > c.freq {
                chan_flag::NO_HT40PLUS
            } else {
                chan_flag::NO_HT40MINUS
            };
            if prim.flags & f != 0 {
                return false;
            }
            (c.center_freq1 - 10, c.center_freq1 + 10)
        }
        Width::W80 => {
            if prim.flags & chan_flag::NO_80MHZ != 0 {
                return false;
            }
            (c.center_freq1 - 30, c.center_freq1 + 30)
        }
        Width::W160 => {
            if prim.flags & (chan_flag::NO_80MHZ | chan_flag::NO_160MHZ) != 0 {
                return false;
            }
            (c.center_freq1 - 70, c.center_freq1 + 70)
        }
        Width::W80P80 => unreachable!("handled above"),
    };
    let width_flags = match c.width {
        Width::W80 => chan_flag::NO_80MHZ,
        Width::W160 => chan_flag::NO_80MHZ | chan_flag::NO_160MHZ,
        Width::W80P80 => unreachable!("handled above"),
        _ => 0,
    };
    let mut f = lo;
    while f <= hi {
        match w.get(f) {
            Some(x) if x.flags & (chan_flag::DISABLED | width_flags) == 0 => {}
            _ => return false,
        }
        f += 20;
    }
    true
}

/// `ieee80211_determine_ap_chan` (HT / VHT only) + our own limits and
/// the regulatory downgrade loop. Returns the connection mode and
/// channel definition.
pub fn determine_chan(
    w: &Wiphy,
    own: &OwnCaps,
    freq: u32,
    ht_cap: Option<&HtCapIe>,
    ht_oper: Option<&HtOperIe>,
    vht_cap: Option<&VhtCapIe>,
    vht_oper: Option<&VhtOperIe>,
) -> (ConnMode, ChanDef) {
    let band = super::mac_frame::freq_band(freq);
    let legacy = ChanDef {
        freq,
        band,
        width: Width::W20NoHt,
        center_freq1: freq,
        center_freq2: 0,
    };
    let own_ht = own.ht(band);
    let (Some(_), Some(op)) = (ht_cap, ht_oper) else {
        return (ConnMode::Legacy, legacy);
    };
    if !own_ht.ht_supported || band == Band::Ghz6 {
        return (ConnMode::Legacy, legacy);
    }
    // "Wrong control channel: center-freq … ht-cfreq …" → no HT.
    if channel_to_freq(op.primary_chan as u32, band) != Some(freq) {
        return (ConnMode::Legacy, legacy);
    }
    let mut def = ChanDef {
        freq,
        band,
        width: Width::W20,
        center_freq1: freq,
        center_freq2: 0,
    };
    if own_ht.cap & ht::SUP_WIDTH_20_40 != 0 {
        match op.ht_param & HT_PARAM_CHA_SEC_OFFSET {
            HT_PARAM_CHA_SEC_ABOVE => {
                def.width = Width::W40;
                def.center_freq1 = freq + 10;
            }
            HT_PARAM_CHA_SEC_BELOW => {
                def.width = Width::W40;
                def.center_freq1 = freq - 10;
            }
            _ => {}
        }
    }
    let mut mode = ConnMode::Ht;
    if let (Some(ap), Some(vop), Some(own_vht)) = (vht_cap, vht_oper, own.vht(band)) {
        mode = ConnMode::Vht;
        let seg0 = channel_to_freq(vop.center_freq_seg0_idx as u32, band);
        let seg1 = channel_to_freq(vop.center_freq_seg1_idx as u32, band);
        match (vop.chan_width, seg0, seg1) {
            (1, Some(c), _) if freq + 30 >= c && freq <= c + 30 => {
                def.width = Width::W80;
                def.center_freq1 = c;
            }
            // VHT Operation: segment 0 is the primary 80 MHz segment and
            // segment 1 identifies the non-contiguous second segment.
            (3, Some(c0), Some(c1))
                if own_vht.cap & vht::SUPP_CHAN_WIDTH_160_80PLUS80MHZ != 0
                    && ap.vht_cap_info & vht::SUPP_CHAN_WIDTH_160_80PLUS80MHZ != 0
                    && c0.abs_diff(c1) > 80
                    && freq + 30 >= c0
                    && freq <= c0 + 30 =>
            {
                def.width = Width::W80P80;
                def.center_freq1 = c0;
                def.center_freq2 = c1;
            }
            (2, Some(c160), _) => {
                // The VHT Operation IE's segment 0 is the 160 MHz centre.
                if own_vht.cap & vht::SUPP_CHAN_WIDTH_MASK != 0
                    && ap.vht_cap_info & vht::SUPP_CHAN_WIDTH_MASK != 0
                    && freq + 70 >= c160
                    && freq <= c160 + 70
                {
                    def.width = Width::W160;
                    def.center_freq1 = c160;
                }
            }
            _ => {}
        }
    }
    // ieee80211_chandef_downgrade until usable.
    loop {
        if chandef_usable(w, &def) {
            return (mode, def);
        }
        match def.width {
            Width::W80P80 => {
                // A failed second segment reduces to the primary 80 MHz.
                def.width = Width::W80;
                def.center_freq2 = 0;
            }
            Width::W160 => {
                // Downgrade to the 80 MHz segment containing the primary.
                def.width = Width::W80;
                def.center_freq1 = if freq < def.center_freq1 {
                    def.center_freq1 - 40
                } else {
                    def.center_freq1 + 40
                };
                def.center_freq2 = 0;
            }
            Width::W80 => {
                // Keep the HT operation's 40 MHz half if any.
                def.width = Width::W40;
                def.center_freq1 = match op.ht_param & HT_PARAM_CHA_SEC_OFFSET {
                    HT_PARAM_CHA_SEC_ABOVE => freq + 10,
                    HT_PARAM_CHA_SEC_BELOW => freq - 10,
                    _ => {
                        def.width = Width::W20;
                        freq
                    }
                };
            }
            Width::W40 => {
                def.width = Width::W20;
                def.center_freq1 = freq;
                def.center_freq2 = 0;
            }
            Width::W20 | Width::W20NoHt => return (mode, def),
        }
    }
}

/// A six-GHz HE channel may only be used when every constituent 20 MHz
/// channel is enabled for HE. `cfg80211_chandef_usable` supplies the common
/// regulatory checks; this adds its `NO_HE` constraint.
fn he_chandef_usable(w: &Wiphy, c: &ChanDef) -> bool {
    if !chandef_usable(w, c) {
        return false;
    }
    if c.width == Width::W80P80 {
        for center in [c.center_freq1, c.center_freq2] {
            let mut freq = center - 30;
            while freq <= center + 30 {
                if !matches!(w.get(freq), Some(ch) if ch.flags & chan_flag::NO_HE == 0) {
                    return false;
                }
                freq += 20;
            }
        }
        return true;
    }
    let (lo, hi) = match c.width {
        Width::W20NoHt | Width::W20 => (c.freq, c.freq),
        Width::W40 => (c.center_freq1 - 10, c.center_freq1 + 10),
        Width::W80 => (c.center_freq1 - 30, c.center_freq1 + 30),
        Width::W160 => (c.center_freq1 - 70, c.center_freq1 + 70),
        Width::W80P80 => unreachable!("handled above"),
    };
    let mut freq = lo;
    while freq <= hi {
        if !matches!(w.get(freq), Some(ch) if ch.flags & chan_flag::NO_HE == 0) {
            return false;
        }
        freq += 20;
    }
    true
}

/// Downgrade a HE 6 GHz definition while retaining the 80 MHz segment that
/// contains the primary channel. The HE Operation field has no explicit
/// 40 MHz centre, so derive it from the primary's position in that 80 MHz
/// segment, exactly as cfg80211's channel-definition downgrade does.
fn downgrade_he_6ghz(def: &mut ChanDef, primary_80: u32) {
    match def.width {
        Width::W80P80 => {
            def.width = Width::W80;
            def.center_freq1 = primary_80;
            def.center_freq2 = 0;
        }
        Width::W160 => {
            def.width = Width::W80;
            def.center_freq1 = primary_80;
            def.center_freq2 = 0;
        }
        Width::W80 => {
            let base = def.center_freq1.saturating_sub(30);
            let offset = def.freq.saturating_sub(base);
            if offset > 60 || offset % 20 != 0 {
                def.width = Width::W20;
                def.center_freq1 = def.freq;
            } else {
                def.width = Width::W40;
                def.center_freq1 = if offset % 40 == 0 {
                    def.freq + 10
                } else {
                    def.freq - 10
                };
            }
        }
        Width::W40 => {
            def.width = Width::W20;
            def.center_freq1 = def.freq;
            def.center_freq2 = 0;
        }
        Width::W20 | Width::W20NoHt => {}
    }
}

/// The raw channel definition encoded by a 6 GHz HE Operation.
/// `ieee80211_chandef_he_6ghz_oper` uses the same information before the
/// station later restricts it to local regulatory and capability limits.
pub fn he_6ghz_oper_chandef(freq: u32, oper: &super::mac::he::HeOper) -> Option<ChanDef> {
    let op = oper.six_ghz?;
    if channel_to_freq(op.primary as u32, Band::Ghz6) != Some(freq) {
        return None;
    }
    let center0 = channel_to_freq(op.ccfs0 as u32, Band::Ghz6)?;
    let width = op.control & super::mac::he::He6GhzOper::WIDTH_MASK;
    let mut def = ChanDef {
        freq,
        band: Band::Ghz6,
        width: Width::W20,
        center_freq1: center0,
        center_freq2: 0,
    };
    match width {
        super::mac::he::He6GhzOper::WIDTH_20 if center0 == freq => {}
        super::mac::he::He6GhzOper::WIDTH_40 if freq.abs_diff(center0) == 10 => {
            def.width = Width::W40;
        }
        super::mac::he::He6GhzOper::WIDTH_80 if matches!(freq.abs_diff(center0), 10 | 30) => {
            def.width = Width::W80;
        }
        super::mac::he::He6GhzOper::WIDTH_160 => {
            let Some(center1) = channel_to_freq(op.ccfs1 as u32, Band::Ghz6) else {
                // Linux falls back to the primary 80 MHz when ccfs1 is zero.
                if !matches!(freq.abs_diff(center0), 10 | 30) {
                    return None;
                }
                def.width = Width::W80;
                return Some(def);
            };
            if op.ccfs1.abs_diff(op.ccfs0) == 8 {
                if !matches!(freq.abs_diff(center1), 10 | 30 | 50 | 70) {
                    return None;
                }
                def.width = Width::W160;
                def.center_freq1 = center1;
            } else {
                if !matches!(freq.abs_diff(center0), 10 | 30) {
                    return None;
                }
                if center0.abs_diff(center1) <= 80 {
                    return None;
                }
                def.width = Width::W80P80;
                def.center_freq2 = center1;
            }
        }
        _ => return None,
    }
    Some(def)
}

/// `ieee80211_chandef_he_6ghz_oper` plus local capability and regulatory
/// downgrade.
///
/// Six GHz has no HT or VHT Operation IEs. The optional HE Operation tail
/// supplies the primary, width and centres. A 160 MHz operation whose
/// centres do not differ by eight channels represents 80+80 and requires
/// both ends to advertise the separate HE 80+80 capability bit.
pub fn determine_he_6ghz_chan(
    w: &Wiphy,
    freq: u32,
    oper: &super::mac::he::HeOper,
    max_width: Width,
    allow_80p80: bool,
) -> Option<ChanDef> {
    let op = oper.six_ghz?;
    let center0 = channel_to_freq(op.ccfs0 as u32, Band::Ghz6)?;
    let mut def = he_6ghz_oper_chandef(freq, oper)?;
    if def.width == Width::W80P80 && !allow_80p80 {
        downgrade_he_6ghz(&mut def, center0);
    }
    he_6ghz_downgrade_until_usable(w, def, center0, max_width)
}

fn he_6ghz_downgrade_until_usable(
    w: &Wiphy,
    mut def: ChanDef,
    primary_80: u32,
    max_width: Width,
) -> Option<ChanDef> {
    loop {
        if def.width <= max_width && he_chandef_usable(w, &def) {
            return Some(def);
        }
        if def.width <= Width::W20 {
            return None;
        }
        downgrade_he_6ghz(&mut def, primary_80);
    }
}

/// `ath11k_phymodes[band][width]` (vdev start).
pub fn vdev_phymode(def: &ChanDef) -> u32 {
    use phy_mode::*;
    match (def.band, def.width) {
        (Band::Ghz2, Width::W20NoHt | Width::W20) => MODE_11AX_HE20_2G,
        (Band::Ghz2, Width::W40) => MODE_11AX_HE40_2G,
        (Band::Ghz2, Width::W80) => MODE_11AX_HE80_2G,
        (Band::Ghz2, Width::W80P80) => MODE_UNKNOWN,
        (Band::Ghz2, Width::W160) => MODE_UNKNOWN,
        (_, Width::W20NoHt | Width::W20) => MODE_11AX_HE20,
        (_, Width::W40) => MODE_11AX_HE40,
        (_, Width::W80) => MODE_11AX_HE80,
        (_, Width::W80P80) => MODE_11AX_HE80_80,
        (_, Width::W160) => MODE_11AX_HE160,
    }
}

// ── Advertised capabilities (assoc request) ─────────────────────────

/// `enum ieee80211_smps_mode` subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmpsMode {
    Off,
    Static,
    Dynamic,
}

/// `ieee80211_add_ht_ie`: our HT capabilities for this association.
pub fn assoc_ht_cap(own: &StaHtCap, def: &ChanDef, smps: SmpsMode) -> HtCapIe {
    let mut cap = own.cap;
    if def.width <= Width::W20 {
        cap &= !(ht::SUP_WIDTH_20_40 | ht::SGI_40);
    }
    cap &= !ht::SM_PS;
    cap |= match smps {
        SmpsMode::Off => sm_ps::DISABLED,
        SmpsMode::Static => sm_ps::STATIC,
        SmpsMode::Dynamic => sm_ps::DYNAMIC,
    } << ht::SM_PS_SHIFT;
    HtCapIe {
        cap_info: cap,
        ampdu_params_info: own.ampdu_factor | (own.ampdu_density << 2),
        rx_mask: own.rx_mask,
        rx_highest: own.rx_highest,
        tx_params: own.tx_params,
        ..Default::default()
    }
}

/// `ieee80211_add_vht_ie` (single interface, so we own MU-MIMO). The
/// capability is limited to the negotiated channel width.
pub fn assoc_vht_cap(own: &StaVhtCap, ap: &VhtCapIe, width: Width) -> VhtCapIe {
    let mut cap = own.cap;
    if !matches!(width, Width::W160 | Width::W80P80) {
        cap &= !(vht::SHORT_GI_160 | vht::SUPP_CHAN_WIDTH_MASK);
    } else if width == Width::W160 {
        cap &= !vht::SUPP_CHAN_WIDTH_160_80PLUS80MHZ;
        cap |= vht::SUPP_CHAN_WIDTH_160MHZ;
    } else {
        cap &= !vht::SUPP_CHAN_WIDTH_160MHZ;
        cap |= vht::SUPP_CHAN_WIDTH_160_80PLUS80MHZ;
    }
    if ap.vht_cap_info & vht::SU_BEAMFORMER_CAPABLE == 0 {
        cap &= !(vht::SU_BEAMFORMEE_CAPABLE | vht::MU_BEAMFORMEE_CAPABLE);
    } else if ap.vht_cap_info & vht::MU_BEAMFORMER_CAPABLE == 0 {
        cap &= !vht::MU_BEAMFORMEE_CAPABLE;
    }
    let ap_sts = ap.vht_cap_info & vht::BEAMFORMEE_STS_MASK;
    if ap_sts < cap & vht::BEAMFORMEE_STS_MASK {
        cap &= !vht::BEAMFORMEE_STS_MASK;
        cap |= ap_sts;
    }
    VhtCapIe {
        vht_cap_info: cap,
        rx_mcs_map: own.rx_mcs_map,
        rx_highest: own.rx_highest,
        tx_mcs_map: own.tx_mcs_map,
        tx_highest: own.tx_highest,
    }
}

// ── The AP station ──────────────────────────────────────────────────

/// `enum ieee80211_sta_rx_bandwidth` subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StaBw {
    Bw20,
    Bw40,
    Bw80,
    Bw160,
}

/// The `ieee80211_sta` fields ath11k reads for the AP.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApSta {
    pub addr: [u8; 6],
    pub ht_cap: StaHtCap,
    pub vht_cap: StaVhtCap,
    /// `supp_rates[band]`: bit i ⇔ `sband->bitrates[i]`.
    pub supp_rates: u32,
    pub bandwidth: Option<StaBw>,
    pub rx_nss: u8,
    pub wme: bool,
    /// `ieee80211_sta::uapsd_queues`, in WMM QoS-info AC bit order.
    pub uapsd_queues: u8,
    /// `ieee80211_sta::max_sp` (0 = unlimited; 1/2/3 = 2/4/6 frames).
    pub max_sp: u8,
    pub mfp: bool,
}

/// The HE side of the AP station (`link_sta->pub->he_cap`) and
/// `bss_conf.he_oper.params`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApHe {
    pub cap: super::mac::he::StaHeCap,
    pub oper_params: u32,
    /// `ieee80211_sta_he_cap::he_6ghz_capa`, when this is a 6 GHz AP.
    pub six_ghz_cap: Option<u16>,
}

/// `ieee80211_ht_cap_ie_to_sta_ht_cap`.
pub fn sta_ht_cap(own: &StaHtCap, ie: Option<&HtCapIe>) -> StaHtCap {
    let mut h = StaHtCap::default();
    let Some(ie) = ie else { return h };
    if !own.ht_supported {
        return h;
    }
    h.ht_supported = true;
    h.cap = ie.cap_info
        & (own.cap
            | !(ht::LDPC_CODING
                | ht::SUP_WIDTH_20_40
                | ht::GRN_FLD
                | ht::SGI_20
                | ht::SGI_40
                | ht::DSSSCCK40));
    if own.cap & ht::TX_STBC == 0 {
        h.cap &= !ht::RX_STBC;
    }
    if own.cap & ht::RX_STBC == 0 {
        h.cap &= !ht::TX_STBC;
    }
    h.ampdu_factor = ie.ampdu_params_info & 0x03;
    h.ampdu_density = (ie.ampdu_params_info & 0x1C) >> 2;
    h.tx_params = ie.tx_params;
    let tx_cap = own.tx_params;
    if tx_cap & ht::MCS_TX_DEFINED == 0 {
        return h;
    }
    let max_tx = if tx_cap & ht::MCS_TX_RX_DIFF != 0 {
        (((tx_cap & ht::MCS_TX_MAX_STREAMS_MASK) >> ht::MCS_TX_MAX_STREAMS_SHIFT) + 1) as usize
    } else {
        4
    };
    for i in 0..max_tx {
        h.rx_mask[i] = own.rx_mask[i] & ie.rx_mask[i];
    }
    if tx_cap & ht::MCS_TX_UNEQUAL_MODULATION != 0 {
        for i in 4..10 {
            h.rx_mask[i] = own.rx_mask[i] & ie.rx_mask[i];
        }
    }
    if own.rx_mask[4] & ie.rx_mask[4] & 1 != 0 {
        h.rx_mask[4] |= 1;
    }
    h.rx_highest = ie.rx_highest;
    h
}

/// `ieee80211_vht_cap_ie_to_sta_vht_cap` (no capability overrides, no
/// `SUPPORTS_VHT_EXT_NSS_BW`). `have_80mhz` ⇔ some channel of the band
/// is enabled without `NO_80MHZ`.
pub fn sta_vht_cap(
    own: &StaVhtCap,
    sta_ht: &StaHtCap,
    ie: Option<&VhtCapIe>,
    have_80mhz: bool,
) -> StaVhtCap {
    let mut v = StaVhtCap::default();
    let Some(ie) = ie else { return v };
    if !sta_ht.ht_supported || !own.vht_supported || !have_80mhz {
        return v;
    }
    v.vht_supported = true;
    let ci = ie.vht_cap_info;
    v.cap = ci
        & (vht::RXLDPC
            | vht::VHT_TXOP_PS
            | vht::HTC_VHT
            | vht::MAX_A_MPDU_LENGTH_EXPONENT_MASK
            | vht::LINK_ADAPTATION_VHT_UNSOL_MFB
            | vht::LINK_ADAPTATION_VHT_MRQ_MFB
            | vht::RX_ANTENNA_PATTERN
            | vht::TX_ANTENNA_PATTERN);
    v.cap |= (ci & vht::MAX_MPDU_MASK).min(own.cap & vht::MAX_MPDU_MASK);
    match own.cap & vht::SUPP_CHAN_WIDTH_MASK {
        vht::SUPP_CHAN_WIDTH_160MHZ => v.cap |= ci & vht::SUPP_CHAN_WIDTH_160MHZ,
        vht::SUPP_CHAN_WIDTH_160_80PLUS80MHZ => v.cap |= ci & vht::SUPP_CHAN_WIDTH_MASK,
        _ => {}
    }
    v.cap |= ci & own.cap & (vht::SHORT_GI_80 | vht::SHORT_GI_160);
    if own.cap & vht::SU_BEAMFORMEE_CAPABLE != 0 {
        v.cap |= ci & (vht::SU_BEAMFORMER_CAPABLE | vht::SOUNDING_DIMENSIONS_MASK);
    }
    if own.cap & vht::SU_BEAMFORMER_CAPABLE != 0 {
        v.cap |= ci & (vht::SU_BEAMFORMEE_CAPABLE | vht::BEAMFORMEE_STS_MASK);
    }
    if own.cap & vht::MU_BEAMFORMER_CAPABLE != 0 {
        v.cap |= ci & vht::MU_BEAMFORMEE_CAPABLE;
    }
    if own.cap & vht::MU_BEAMFORMEE_CAPABLE != 0 {
        v.cap |= ci & vht::MU_BEAMFORMER_CAPABLE;
    }
    if own.cap & vht::TXSTBC != 0 {
        v.cap |= ci & vht::RXSTBC_MASK;
    }
    if own.cap & vht::RXSTBC_MASK != 0 {
        v.cap |= ci & vht::TXSTBC;
    }
    v.rx_mcs_map = ie.rx_mcs_map;
    v.rx_highest = ie.rx_highest;
    v.tx_mcs_map = ie.tx_mcs_map;
    v.tx_highest = ie.tx_highest & !vht::EXT_NSS_BW_CAPABLE;
    for i in 0..8 {
        let s = i * 2;
        let ns = vht::MCS_NOT_SUPPORTED;
        let own_rx = (own.rx_mcs_map >> s) & ns;
        let own_tx = (own.tx_mcs_map >> s) & ns;
        let mut peer_rx = (v.rx_mcs_map >> s) & ns;
        let mut peer_tx = (v.tx_mcs_map >> s) & ns;
        if peer_tx != ns {
            if own_rx == ns {
                peer_tx = ns;
            } else if own_rx < peer_tx {
                peer_tx = own_rx;
            }
        }
        if peer_rx != ns {
            if own_tx == ns {
                peer_rx = ns;
            } else if own_tx < peer_rx {
                peer_rx = own_tx;
            }
        }
        v.rx_mcs_map = (v.rx_mcs_map & !(ns << s)) | (peer_rx << s);
        v.tx_mcs_map = (v.tx_mcs_map & !(ns << s)) | (peer_tx << s);
    }
    if v.rx_mcs_map == 0xFFFF {
        return StaVhtCap::default();
    }
    v
}

/// `ieee80211_sta_cap_rx_bw` → `ieee80211_sta_cur_vht_bw` (min with the
/// channel width).
pub fn sta_bandwidth(ht: &StaHtCap, v: &StaVhtCap, def: &ChanDef) -> StaBw {
    let cap = if v.vht_supported {
        if v.cap & vht::SUPP_CHAN_WIDTH_MASK != 0 {
            StaBw::Bw160
        } else {
            StaBw::Bw80
        }
    } else if ht.ht_supported && ht.cap & ht::SUP_WIDTH_20_40 != 0 {
        StaBw::Bw40
    } else {
        StaBw::Bw20
    };
    let chan = match def.width {
        Width::W20NoHt | Width::W20 => StaBw::Bw20,
        Width::W40 => StaBw::Bw40,
        Width::W80 => StaBw::Bw80,
        Width::W80P80 => StaBw::Bw160,
        Width::W160 => StaBw::Bw160,
    };
    cap.min(chan)
}

/// `ieee80211_sta_init_nss` (no HE / EHT, no op-mode notification).
pub fn sta_rx_nss(ht: &StaHtCap, v: &StaVhtCap) -> u8 {
    let mut ht_nss = 0u8;
    if ht.ht_supported {
        for i in 0..4 {
            if ht.rx_mask[i] != 0 {
                ht_nss += 1;
            }
        }
    }
    let mut vht_nss = 0u8;
    if v.vht_supported {
        for i in (0..8).rev() {
            if (v.rx_mcs_map >> (2 * i)) & 3 != vht::MCS_NOT_SUPPORTED {
                vht_nss = i as u8 + 1;
                break;
            }
        }
    }
    ht_nss.max(vht_nss).max(1)
}

// ── Legacy rates ────────────────────────────────────────────────────

/// `ath11k_legacy_rates[]`: `(bitrate in 100 kbps, hw_value)`.
pub const LEGACY_RATES: [(u16, u32); 12] = [
    (10, 3),  // ATH11K_HW_RATE_CCK_LP_1M
    (20, 2),  // CCK_LP_2M
    (55, 1),  // CCK_LP_5_5M
    (110, 0), // CCK_LP_11M
    (60, 3),  // OFDM_6M
    (90, 7),  // OFDM_9M
    (120, 2), // OFDM_12M
    (180, 6), // OFDM_18M
    (240, 1), // OFDM_24M
    (360, 5), // OFDM_36M
    (480, 0), // OFDM_48M
    (540, 4), // OFDM_54M
];

/// The band's `sband->bitrates` (`ath11k_g_rates` = all 12,
/// `ath11k_a_rates` = OFDM only).
pub fn sband_rates(b: Band) -> &'static [(u16, u32)] {
    match b {
        Band::Ghz2 => &LEGACY_RATES,
        _ => &LEGACY_RATES[4..],
    }
}

/// `ath11k_mac_bitrate_is_cck`.
pub fn bitrate_is_cck(bitrate: u16) -> bool {
    matches!(bitrate, 10 | 20 | 55 | 110)
}

/// `ieee80211_parse_bitrates` / `ieee80211_get_rates`: map rate octets
/// (500 kbps units, bit 7 = basic) onto the band's bitrate indices.
/// Returns `(supported, basic)` bitmaps.
pub fn rates_to_mask(b: Band, octets: &[u8]) -> (u32, u32) {
    let mut supp = 0u32;
    let mut basic = 0u32;
    for &o in octets {
        let rate = (o & 0x7F) as u16 * 5;
        for (i, &(br, _)) in sband_rates(b).iter().enumerate() {
            if br == rate {
                supp |= 1 << i;
                if o & 0x80 != 0 {
                    basic |= 1 << i;
                }
            }
        }
    }
    (supp, basic)
}

/// `ATH11K_HW_RATE_CODE(hw_value, 0, preamble)` for the lowest basic
/// rate (`ath11k_recalculate_mgmt_rate`); `None` without basic rates.
pub fn mgmt_rate_code(b: Band, basic: u32) -> Option<u32> {
    if basic == 0 {
        return None;
    }
    let (br, hw) = sband_rates(b)[basic.trailing_zeros() as usize];
    let preamble = if bitrate_is_cck(br) { 1 } else { 0 };
    Some((1 << 28) | (preamble << 8) | hw)
}

/// `ath11k_mac_bitrate_to_rate`.
pub fn bitrate_to_rate(bitrate: u16) -> u8 {
    (bitrate.div_ceil(5) as u8) | if bitrate_is_cck(bitrate) { 0x80 } else { 0 }
}

/// `ath11k_parse_mpdudensity`.
pub fn parse_mpdudensity(d: u8) -> u32 {
    match d {
        0 => 0,
        1..=3 => 1,
        4 => 2,
        5 => 4,
        6 => 8,
        7 => 16,
        _ => 0,
    }
}

/// `ath11k_mac_get_max_vht_mcs_map`.
fn max_vht_mcs_map(map: u16, nss: u32) -> u16 {
    match (map >> (2 * nss)) & 3 {
        vht::MCS_SUPPORT_0_7 => (1 << 8) - 1,
        vht::MCS_SUPPORT_0_8 => (1 << 9) - 1,
        vht::MCS_SUPPORT_0_9 => (1 << 10) - 1,
        _ => 0,
    }
}

/// `ath11k_peer_assoc_h_vht_limit` with the default (all-ones) mask.
pub fn vht_limit(mut set: u16, limit: &[u16; 8]) -> u16 {
    for nss in 0..8u32 {
        let m = max_vht_mcs_map(set, nss) & limit[nss as usize];
        let idx: i32 = if m != 0 {
            15 - m.leading_zeros() as i32
        } else {
            -1
        };
        let mcs = match idx {
            0..=7 => vht::MCS_SUPPORT_0_7,
            8 => vht::MCS_SUPPORT_0_8,
            9 => vht::MCS_SUPPORT_0_9,
            _ => vht::MCS_NOT_SUPPORTED,
        };
        set &= !(0x3 << (nss * 2));
        set |= mcs << (nss * 2);
    }
    set
}

/// `ath11k_peer_assoc_h_he_limit`: intersect an HE MCS/NSS capability map
/// with nl80211's per-NSS allowed-MCS bitmaps.  The two-bit map carries the
/// greatest contiguous supported MCS range, so a sparse mask is represented
/// only when it selects one rate (the fixed-rate path handles that case).
pub fn he_limit(mut set: u16, limit: &[u16; 8]) -> u16 {
    const HE_MCS_0_7: u16 = 0;
    const HE_MCS_0_9: u16 = 1;
    const HE_MCS_0_11: u16 = 2;
    const HE_MCS_NOT_SUPPORTED: u16 = 3;
    for nss in 0..8u32 {
        let supported = match (set >> (nss * 2)) & 3 {
            HE_MCS_0_7 => 0x00ff,
            HE_MCS_0_9 => 0x03ff,
            HE_MCS_0_11 => 0x0fff,
            _ => 0,
        };
        let limited = supported & limit[nss as usize];
        let value = match limited {
            0 => HE_MCS_NOT_SUPPORTED,
            1..=0x00ff => HE_MCS_0_7,
            0x0100..=0x03ff => HE_MCS_0_9,
            _ => HE_MCS_0_11,
        };
        set &= !(0x3 << (nss * 2));
        set |= value << (nss * 2);
    }
    set
}

/// Reject cfg80211 masks that ath11k cannot represent faithfully.  The
/// target's peer-association format can carry VHT/HE contiguous ranges; a
/// sparse multi-rate VHT/HE selection needs the unimplemented RATEMASK WMI
/// command and therefore has the same `-EINVAL` result as Linux ath11k.
pub fn validate_tx_bitrate_band(mask: &TxBitrateBand) -> Result<(), ()> {
    if mask.gi == Some(2) {
        // `NL80211_TXRATE_FORCE_LGI` is explicitly refused by ath11k.
        return Err(());
    }
    let contiguous = |value: u16, maximum: u16| {
        value == 0
            || value == 0x00ff
            || value == 0x01ff
            || (maximum == 0x0fff && value == 0x03ff)
            || (maximum == 0x0fff && value == 0x07ff)
            || value == maximum
    };
    if let Some(vht) = mask.vht_mcs {
        if vht.iter().any(|value| *value & !0x03ff != 0)
            || vht.iter().map(|value| value.count_ones()).sum::<u32>() > 1
                && vht.iter().any(|value| !contiguous(*value, 0x03ff))
        {
            return Err(());
        }
    }
    if let Some(he) = mask.he_mcs {
        if he.iter().any(|value| *value & !0x0fff != 0)
            || he.iter().map(|value| value.count_ones()).sum::<u32>() > 1
                && he.iter().any(|value| !contiguous(*value, 0x0fff))
        {
            return Err(());
        }
    }
    Ok(())
}

/// Apply one band's cfg80211 rate restriction to an already constructed WMI
/// peer-association record.  This is deliberately after capability parsing:
/// the restriction can only remove rates the peer and local radio negotiated.
pub fn apply_tx_bitrate_band(a: &mut PeerAssocParams, mask: Option<&TxBitrateBand>) {
    let Some(mask) = mask else { return };
    if let Some(legacy) = mask.legacy.as_ref() {
        a.peer_legacy_rates.retain(|rate| {
            legacy
                .iter()
                .any(|allowed| (allowed & 0x7f) == (rate & 0x7f))
        });
    }
    if let Some(ht) = mask.ht_mcs.as_ref() {
        a.peer_ht_rates.retain(|mcs| {
            let byte = (*mcs / 8) as usize;
            byte < ht.len() && ht[byte] & (1 << (*mcs % 8)) != 0
        });
    }
    if let Some(vht) = mask.vht_mcs.as_ref() {
        a.rx_mcs_set = vht_limit(a.rx_mcs_set as u16, vht) as u32;
        a.tx_mcs_set = vht_limit(a.tx_mcs_set as u16, vht) as u32;
    }
    if let Some(he) = mask.he_mcs.as_ref() {
        for (rx, tx) in &mut a.peer_he_mcs {
            *rx = he_limit(*rx as u16, he) as u32;
            *tx = he_limit(*tx as u16, he) as u32;
        }
    }
}

/// Maximum requested NSS in a rate mask, corresponding to
/// `ath11k_mac_max_nss`.  `None` means all negotiated MCS masks remain
/// available, so it places no additional NSS limit.
pub fn tx_bitrate_max_nss(mask: Option<&TxBitrateBand>) -> Option<u32> {
    let mask = mask?;
    let mut maximum = 0u32;
    if let Some(ht) = mask.ht_mcs.as_ref() {
        maximum = maximum.max(
            ht.iter()
                .rposition(|entry| *entry != 0)
                .map_or(0, |index| index as u32 + 1),
        );
    }
    if let Some(vht) = mask.vht_mcs.as_ref() {
        maximum = maximum.max(
            vht.iter()
                .rposition(|entry| *entry != 0)
                .map_or(0, |index| index as u32 + 1),
        );
    }
    if let Some(he) = mask.he_mcs.as_ref() {
        maximum = maximum.max(
            he.iter()
                .rposition(|entry| *entry != 0)
                .map_or(0, |index| index as u32 + 1),
        );
    }
    (maximum != 0).then_some(maximum)
}

/// One of the target's peer fixed-rate codes, or `None` when normal rate
/// control must remain enabled.  This follows ath11k's VHT → HE → HT
/// precedence and validates that the selected NSS exists on the peer.
pub fn tx_bitrate_fixed_rate(
    mask: Option<&TxBitrateBand>,
    vht: bool,
    he: bool,
    ht: bool,
    peer_nss: u32,
) -> Result<Option<u32>, ()> {
    let Some(mask) = mask else { return Ok(None) };
    let one = |maps: &[u16; 8], preamble: u32| {
        let mut selected = None;
        for (index, mcs) in maps.iter().enumerate() {
            if mcs.count_ones() == 1 {
                selected = Some((index as u32 + 1, mcs.trailing_zeros()));
            }
        }
        let total: u32 = maps.iter().map(|entry| entry.count_ones()).sum();
        (total == 1)
            .then_some(selected)
            .flatten()
            .map(|(nss, rate)| (nss, rate, preamble))
    };
    let ht_one = || {
        let ht = mask.ht_mcs.as_ref()?;
        let mut selected = None;
        for (index, mcs) in ht.iter().enumerate() {
            if mcs.count_ones() == 1 {
                selected = Some((index as u32 + 1, mcs.trailing_zeros()));
            }
        }
        let total: u32 = ht.iter().map(|entry| entry.count_ones()).sum();
        (total == 1)
            .then_some(selected)
            .flatten()
            .map(|(nss, rate)| (nss, rate, 2))
    };
    let mut selected = if vht {
        mask.vht_mcs.as_ref().and_then(|mcs| one(mcs, 3))
    } else {
        None
    };
    if selected.is_none() && he {
        selected = mask.he_mcs.as_ref().and_then(|mcs| one(mcs, 4));
    }
    if selected.is_none() && ht {
        selected = ht_one();
    }
    let Some((nss, rate, preamble)) = selected else {
        return Ok(None);
    };
    if nss > peer_nss {
        return Err(());
    }
    // ATH11K_HW_RATE_CODE(rate, nss - 1, preamble).
    Ok(Some((1 << 28) | ((nss - 1) << 5) | (preamble << 8) | rate))
}

// ── ath11k_peer_assoc_prepare ───────────────────────────────────────

/// Inputs of `ath11k_peer_assoc_prepare` for the BSS peer of a STA vdev.
#[derive(Clone, Debug)]
pub struct PeerAssocInput<'a> {
    pub vdev_id: u32,
    pub aid: u16,
    /// `vif->bss_conf.assoc_capability`.
    pub assoc_capability: u16,
    /// `hw->conf.listen_interval`.
    pub listen_interval: u32,
    /// SERVICE_READY_EXT's `nss_ratio_info`: the device's maximum 160 MHz
    /// NSS relative to the map advertised at 80 MHz.
    pub nss_ratio_info: u32,
    pub def: ChanDef,
    pub sta: &'a ApSta,
    /// HE (`sta->deflink.he_cap.has_he`).
    pub he: Option<&'a ApHe>,
    /// The BSS carries an RSN or WPA element (`ath11k_peer_assoc_h_crypto`).
    pub rsn: bool,
    pub wpa: bool,
}

/// `ath11k_peer_assoc_prepare(ar, vif, sta, arg, reassoc = false)` then
/// `arg->is_assoc = true` (`ath11k_bss_assoc`). The bitrate mask is the
/// default (`legacy = ~0`, `gi = NL80211_TXRATE_FORCE_SGI`, all MCS).
pub fn peer_assoc_prepare(p: &PeerAssocInput<'_>) -> PeerAssocParams {
    let sta = p.sta;
    let mut a = PeerAssocParams {
        peer_new_assoc: 1,
        ..Default::default()
    };
    // h_basic
    a.peer_mac = sta.addr;
    a.vdev_id = p.vdev_id;
    a.peer_associd = p.aid as u32;
    a.auth_flag = true;
    a.peer_listen_intval = p.listen_interval;
    a.peer_nss = 1;
    a.peer_caps = p.assoc_capability as u32;
    // h_crypto
    if p.rsn || p.wpa {
        a.need_ptk_4_way = true;
    }
    if p.wpa {
        a.need_gtk_2_way = true;
    }
    if sta.mfp {
        a.is_pmf_enabled = true;
    }
    // h_rates
    let rates = sband_rates(p.def.band);
    for (i, &(br, _)) in rates.iter().enumerate() {
        if sta.supp_rates & (1 << i) != 0 {
            a.peer_legacy_rates.push(bitrate_to_rate(br));
        }
    }
    // h_phymode (before HT/VHT in Linux)
    let bw = sta.bandwidth.unwrap_or(StaBw::Bw20);
    let he = p.he.filter(|h| h.cap.has_he);
    a.peer_phymode = match (p.def.band, he) {
        // ath11k_peer_assoc_h_phymode: HE first.
        (Band::Ghz2, Some(_)) => match bw {
            StaBw::Bw80 => phy_mode::MODE_11AX_HE80_2G,
            StaBw::Bw40 => phy_mode::MODE_11AX_HE40_2G,
            _ => phy_mode::MODE_11AX_HE20_2G,
        },
        // ath11k_mac_get_phymode_he. `StaBw::Bw160` covers both contiguous
        // 160 MHz and 80+80; the ChanDef selects their distinct WMI modes.
        (_, Some(_)) => match bw {
            StaBw::Bw160 if p.def.width == Width::W80P80 => phy_mode::MODE_11AX_HE80_80,
            StaBw::Bw160 => phy_mode::MODE_11AX_HE160,
            StaBw::Bw80 => phy_mode::MODE_11AX_HE80,
            StaBw::Bw40 => phy_mode::MODE_11AX_HE40,
            StaBw::Bw20 => phy_mode::MODE_11AX_HE20,
        },
        _ => match p.def.band {
            Band::Ghz2 => {
                if sta.vht_cap.vht_supported {
                    if bw == StaBw::Bw40 {
                        phy_mode::MODE_11AC_VHT40
                    } else {
                        phy_mode::MODE_11AC_VHT20
                    }
                } else if sta.ht_cap.ht_supported {
                    if bw == StaBw::Bw40 {
                        phy_mode::MODE_11NG_HT40
                    } else {
                        phy_mode::MODE_11NG_HT20
                    }
                } else if sta.supp_rates >> 4 != 0 {
                    phy_mode::MODE_11G
                } else {
                    phy_mode::MODE_11B
                }
            }
            _ => {
                if sta.vht_cap.vht_supported {
                    match bw {
                        StaBw::Bw160 if p.def.width == Width::W80P80 => {
                            phy_mode::MODE_11AC_VHT80_80
                        }
                        StaBw::Bw160 => phy_mode::MODE_11AC_VHT160,
                        StaBw::Bw80 => phy_mode::MODE_11AC_VHT80,
                        StaBw::Bw40 => phy_mode::MODE_11AC_VHT40,
                        StaBw::Bw20 => phy_mode::MODE_11AC_VHT20,
                    }
                } else if sta.ht_cap.ht_supported {
                    if bw >= StaBw::Bw40 {
                        phy_mode::MODE_11NA_HT40
                    } else {
                        phy_mode::MODE_11NA_HT20
                    }
                } else {
                    phy_mode::MODE_11A
                }
            }
        },
    };
    // h_ht
    let h = &sta.ht_cap;
    if h.ht_supported {
        a.ht_flag = true;
        a.peer_max_mpdu = (1u32 << (ht::MAX_AMPDU_FACTOR + h.ampdu_factor as u32)) - 1;
        a.peer_mpdu_density = parse_mpdudensity(h.ampdu_density);
        a.peer_ht_caps = h.cap as u32;
        a.peer_rate_caps |= rc::HT_FLAG;
        if h.cap & ht::LDPC_CODING != 0 {
            a.ldpc_flag = true;
        }
        if bw >= StaBw::Bw40 {
            a.bw_40 = true;
            a.peer_rate_caps |= rc::CW40_FLAG;
        }
        // gi = FORCE_SGI: neither the DEFAULT_GI clear nor FORCE_LGI.
        if h.cap & (ht::SGI_20 | ht::SGI_40) != 0 {
            a.peer_rate_caps |= rc::SGI_FLAG;
        }
        if h.cap & ht::TX_STBC != 0 {
            a.peer_rate_caps |= rc::TX_STBC_FLAG;
            a.stbc_flag = true;
        }
        if h.cap & ht::RX_STBC != 0 {
            let stbc = ((h.cap & ht::RX_STBC) >> ht::RX_STBC_SHIFT) as u32;
            a.peer_rate_caps |= stbc << rc::RX_STBC_FLAG_S;
            a.stbc_flag = true;
        }
        if h.rx_mask[1] != 0 && h.rx_mask[2] != 0 {
            a.peer_rate_caps |= rc::TS_FLAG;
        } else if h.rx_mask[1] != 0 {
            a.peer_rate_caps |= rc::DS_FLAG;
        }
        let mut max_nss = 0u32;
        for i in 0..80u32 {
            if h.rx_mask[(i / 8) as usize] & (1 << (i % 8)) != 0 {
                max_nss = i / 8 + 1;
                a.peer_ht_rates.push(i as u8);
            }
        }
        if a.peer_ht_rates.is_empty() {
            a.peer_ht_rates = (0..8).collect();
        } else {
            a.peer_nss = (sta.rx_nss as u32).min(max_nss);
        }
    }
    // h_vht
    let v = &sta.vht_cap;
    if v.vht_supported {
        a.vht_flag = true;
        a.vht_capable = true;
        a.peer_vht_caps = v.cap;
        let ampdu_factor =
            (v.cap & vht::MAX_A_MPDU_LENGTH_EXPONENT_MASK) >> vht::MAX_A_MPDU_LENGTH_EXPONENT_SHIFT;
        a.peer_max_mpdu = a
            .peer_max_mpdu
            .max((1u32 << (ht::MAX_AMPDU_FACTOR + ampdu_factor)) - 1);
        if bw == StaBw::Bw80 {
            a.bw_80 = true;
        }
        if bw == StaBw::Bw160 {
            a.bw_160 = true;
        }
        let mask = [0xFFFFu16; 8];
        let mut max_nss = 0u32;
        for i in 0..8u32 {
            let m = (v.rx_mcs_map >> (2 * i)) & 3;
            if m != vht::MCS_NOT_SUPPORTED && mask[i as usize] != 0 {
                max_nss = i + 1;
            }
        }
        a.peer_nss = (sta.rx_nss as u32).min(max_nss);
        // Linux's `ath11k_peer_assoc_h_vht` computes this only after the
        // VHT RX MCS map has constrained peer_nss.  Sending the pre-VHT
        // value would silently cap a two-stream 160 MHz peer at one stream.
        if bw == StaBw::Bw160 {
            let nss_160 =
                nss_160_limit(p.nss_ratio_info, max_nss).map(|limit| a.peer_nss.min(limit));
            if let Some(override_) =
                nss_160.and_then(|nss| nss_wide_override(nss, p.def.width == Width::W80P80))
            {
                a.peer_bw_rxnss_override = override_;
            }
        }
        a.rx_max_rate = v.rx_highest as u32;
        a.rx_mcs_set = vht_limit(v.rx_mcs_map, &mask) as u32;
        a.tx_max_rate = v.tx_highest as u32;
        a.tx_mcs_set = v.tx_mcs_map as u32;
        a.tx_mcs_set &= !vht::MCS_SUPPORT_0_11_MASK;
        a.tx_mcs_set |= vht::DISABLE_MCS_SUPPORT_0_11;
        if a.tx_mcs_set & vht::MCS_NOT_SUPPORTED as u32 == vht::MCS_NOT_SUPPORTED as u32 {
            a.peer_vht_caps &= !vht::MU_BEAMFORMEE_CAPABLE;
        }
    }
    // h_he (default bitrate mask: every HE MCS allowed)
    if let Some(h) = he {
        peer_assoc_h_he(&mut a, p, sta, &h.cap, h.oper_params, h.six_ghz_cap, bw);
    }
    // ath11k_peer_assoc_h_qos. AP clients with a non-zero U-APSD AC
    // bitmap need both WMI_PEER_APSD and WMI_HOST_RC_UAPSD_FLAG; the
    // follow-up AP-PS peer commands carry the exact queues and max SP.
    if sta.wme {
        a.is_wme_set = true;
        a.qos_flag = true;
        if sta.uapsd_queues != 0 {
            a.apsd_flag = true;
            a.peer_rate_caps |= rc::UAPSD_FLAG;
        }
    }
    // h_smps
    if h.ht_supported {
        match (h.cap & ht::SM_PS) >> ht::SM_PS_SHIFT {
            sm_ps::STATIC => a.static_mimops_flag = true,
            sm_ps::DYNAMIC => a.dynamic_mimops_flag = true,
            sm_ps::DISABLED => a.spatial_mux_flag = true,
            _ => {}
        }
    } else if p.def.band == Band::Ghz6 {
        if let Some(cap) = he.and_then(|h| h.six_ghz_cap) {
            match (cap & super::mac::he::cap_6ghz::SM_PS_MASK) >> 9 {
                sm_ps::STATIC => a.static_mimops_flag = true,
                sm_ps::DYNAMIC => a.dynamic_mimops_flag = true,
                sm_ps::DISABLED => a.spatial_mux_flag = true,
                _ => {}
            }
        }
    }
    a.is_assoc = true;
    a
}

/// `ath11k_peer_assoc_h_he` with the default bitrate mask (`he_mcs` all
/// ones: `ath11k_peer_assoc_h_he_limit` leaves the maps as they are).
fn peer_assoc_h_he(
    a: &mut PeerAssocParams,
    p: &PeerAssocInput<'_>,
    sta: &ApSta,
    h: &super::mac::he::StaHeCap,
    oper: u32,
    six_ghz_cap: Option<u16>,
    bw: StaBw,
) {
    use super::mac::he::{cap, HE_MCS_NOT_SUPPORTED};
    a.he_flag = true;
    let support_160 = h.phy[0] & cap::PHY0_160MHZ_IN_5G != 0;
    let support_80p80 = h.phy[0] & cap::PHY0_80PLUS80_MHZ_IN_5G != 0;
    let top = |m: u16| {
        (0..8u32)
            .rev()
            .find(|&i| (m >> (2 * i)) & 3 != HE_MCS_NOT_SUPPORTED)
            .map_or(9, |i| i + 1)
    };
    let rx_mcs_80 = top(h.mcs[0]);
    let wide_rx_mcs = if p.def.width == Width::W80P80 && support_80p80 {
        top(h.mcs[4])
    } else if support_160 {
        top(h.mcs[2])
    } else {
        9
    };
    let max_nss = if bw == StaBw::Bw160 {
        rx_mcs_80.min(wide_rx_mcs)
    } else {
        rx_mcs_80
    };
    a.peer_nss = (sta.rx_nss as u32).min(max_nss);
    let mut mac = [0u8; 8];
    mac[..6].copy_from_slice(&h.mac);
    a.peer_he_cap_macinfo = [
        u32::from_le_bytes(mac[..4].try_into().unwrap()),
        u32::from_le_bytes(mac[4..].try_into().unwrap()),
    ];
    let mut phy = [0u8; 12];
    phy[..11].copy_from_slice(&h.phy);
    for i in 0..3 {
        a.peer_he_cap_phyinfo[i] = u32::from_le_bytes(phy[4 * i..4 * i + 4].try_into().unwrap());
    }
    a.peer_he_ops = oper & 0xff_ffff;
    let ampdu_factor = ((h.mac[3] & cap::MAC3_MAX_AMPDU_LEN_EXP_MASK) >> 3) as u32;
    if ampdu_factor != 0 {
        if sta.vht_cap.vht_supported {
            a.peer_max_mpdu = (1 << (20 + ampdu_factor)) - 1;
        } else if sta.ht_cap.ht_supported {
            a.peer_max_mpdu = (1 << (16 + ampdu_factor)) - 1;
        }
    }
    if h.phy[6] & cap::PHY6_PPE_THRESHOLD_PRESENT != 0 && !h.ppe.is_empty() {
        let p = &mut a.peer_ppet;
        p.numss_m1 = (h.ppe[0] & 7) as u32;
        p.ru_bit_mask = ((h.ppe[0] & 0x78) >> 3) as u32;
        let mut bit = 7usize;
        for nss in 0..=(p.numss_m1 as usize) {
            for ru in 0..4 {
                if p.ru_bit_mask & (1 << ru) == 0 {
                    continue;
                }
                let mut val = 0u32;
                for _ in 0..6 {
                    val >>= 1;
                    val |=
                        ((h.ppe.get(bit / 8).copied().unwrap_or(0) as u32 >> (bit % 8)) & 1) << 5;
                    bit += 1;
                }
                p.ppet16_ppet8_ru3_ru0[nss] |= val << (ru * 6);
            }
        }
    }
    if h.mac[0] & cap::MAC0_TWT_RES != 0 {
        a.twt_responder = true;
    }
    if h.mac[0] & cap::MAC0_TWT_REQ != 0 {
        a.twt_requester = true;
    }
    // WMI rate-set indices are 80 MHz, contiguous 160 MHz, then 80+80.
    // An 80+80 peer therefore carries the unused contiguous-160 slot as
    // a placeholder so its 80+80 map reaches index two, as ath11k does.
    a.peer_he_mcs.clear();
    a.peer_he_mcs.push((h.mcs[0] as u32, h.mcs[1] as u32));
    let tx_mcs = if bw == StaBw::Bw160 && p.def.width == Width::W80P80 && support_80p80 {
        a.peer_he_mcs.push((h.mcs[2] as u32, h.mcs[3] as u32));
        a.peer_he_mcs.push((h.mcs[4] as u32, h.mcs[5] as u32));
        a.bw_160 = true;
        h.mcs[5]
    } else if bw == StaBw::Bw160 && support_160 {
        a.peer_he_mcs.push((h.mcs[2] as u32, h.mcs[3] as u32));
        a.bw_160 = true;
        h.mcs[3]
    } else {
        h.mcs[1]
    };
    let tx_nss = top(tx_mcs);
    a.peer_nss = (sta.rx_nss as u32).min(tx_nss);
    if bw == StaBw::Bw160 {
        let nss_160 = nss_160_limit(p.nss_ratio_info, tx_nss).map(|limit| a.peer_nss.min(limit));
        if let Some(override_) =
            nss_160.and_then(|nss| nss_wide_override(nss, p.def.width == Width::W80P80))
        {
            a.peer_bw_rxnss_override = override_;
        }
    }
    // `ath11k_peer_assoc_h_he_6ghz`: no HT/VHT peer capability exists in
    // this band, so carry the HE 6 GHz Capabilities in the WMI peer command
    // and derive the aggregate MPDU/SMPS constraints from it.
    if p.def.band == Band::Ghz6 {
        let Some(cap6) = six_ghz_cap else { return };
        match bw {
            StaBw::Bw40 => a.bw_40 = true,
            StaBw::Bw80 => a.bw_80 = true,
            StaBw::Bw160 => a.bw_160 = true,
            StaBw::Bw20 => {}
        }
        a.peer_he_caps_6ghz = cap6 as u32;
        a.peer_mpdu_density =
            parse_mpdudensity((cap6 & super::mac::he::cap_6ghz::MIN_MPDU_START_MASK) as u8);
        let ampdu = ((h.mac[3] & cap::MAC3_MAX_AMPDU_LEN_EXP_MASK) >> 3) as u32
            + ((cap6 & super::mac::he::cap_6ghz::MAX_AMPDU_LEN_EXP_MASK) >> 3) as u32;
        a.peer_max_mpdu = (1u32 << (13 + ampdu)) - 1;
    }
}

/// `ath11k_mac_set_txbf_conf` value (`None` ⇔ no command).
pub fn txbf_conf(vht_cap: u32, num_tx_chains: u32) -> Option<u32> {
    let mut value = 0u32;
    if vht_cap & vht::SU_BEAMFORMEE_CAPABLE != 0 {
        let nsts = (vht_cap & vht::BEAMFORMEE_STS_MASK) >> vht::BEAMFORMEE_STS_SHIFT;
        value |= (nsts << 4) & 0x70; // SM(nsts, WMI_TXBF_STS_CAP_OFFSET)
    }
    if vht_cap & vht::SU_BEAMFORMER_CAPABLE != 0 {
        let mut sd = (vht_cap & vht::SOUNDING_DIMENSIONS_MASK) >> vht::SOUNDING_DIMENSIONS_SHIFT;
        if sd > num_tx_chains.saturating_sub(1) {
            sd = num_tx_chains.saturating_sub(1);
        }
        value |= (sd << 8) & 0x700; // SM(sound_dim, WMI_BF_SOUND_DIM_OFFSET)
    }
    if value == 0 {
        return None;
    }
    if vht_cap & vht::SU_BEAMFORMER_CAPABLE != 0 {
        value |= 1 << 2; // WMI_VDEV_PARAM_TXBF_SU_TX_BFER
    }
    if vht_cap & vht::SU_BEAMFORMEE_CAPABLE != 0 {
        value |= 1 << 0; // SU_TX_BFEE
        if vht_cap & vht::MU_BEAMFORMEE_CAPABLE != 0 {
            value |= 1 << 1; // MU_TX_BFEE (STA vdev)
        }
    }
    Some(value)
}

/// Supported channels list for the Supported Channels element: every
/// channel of the band (`sband->channels`, disabled ones included).
pub fn supported_channel_numbers(w: &Wiphy, b: Band) -> Vec<u8> {
    w.band(b).iter().map(|c| c.hw_value as u8).collect()
}
