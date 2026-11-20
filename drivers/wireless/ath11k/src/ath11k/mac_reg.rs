//! Regulatory: firmware reg rules → regdomain → wiphy channel flags →
//! `WMI_SCAN_CHAN_LIST_CMDID` parameters.
//!
//! Ports Linux `drivers/net/wireless/ath/ath11k/reg.c`
//! (`ath11k_reg_build_regd`, `ath11k_regd_intersect`,
//! `ath11k_reg_handle_chan_list`, `ath11k_reg_update_chan_list`), the
//! channel tables and filtering of `ath11k_mac_setup_channels_rates` /
//! `ath11k_mac_update_ch_list` (mac.c), and the part of
//! `net/wireless/reg.c` a self-managed wiphy goes through when the
//! driver hands it a regdomain (`reg_process_self_managed_hint` →
//! `handle_band_custom` → `handle_channel_custom`, then
//! `reg_process_ht_flags`).
//!
//! Units: the regdomain is kept in MHz / dBm / dBi. Linux stores kHz /
//! mBm / mBi but only ever converts the firmware's MHz / dBm values by
//! exact factors (`MHZ_TO_KHZ`, `DBM_TO_MBM`, `DBI_TO_MBI`) and back
//! (`MBM_TO_DBM`, `MBI_TO_DBI`), so every comparison and min/max is
//! identical.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use super::mac_frame::Band;
use super::wmi::{
    phy_mode, ChannelParam, HalRegCapExt, RegInfo, RegRule, ATH11K_MIN_6G_FREQ,
    WMI_HOST_WLAN_2G_CAP, WMI_HOST_WLAN_5G_CAP, WMI_REG_DEFAULT_CLIENT, WMI_REG_INDOOR_AP,
};

// ── Flags ───────────────────────────────────────────────────────────

/// `REGULATORY_CHAN_*` (wmi.h): firmware reg-rule flags.
pub mod fw_flag {
    pub const DISABLED: u16 = 1 << 0;
    pub const NO_IR: u16 = 1 << 1;
    pub const RADAR: u16 = 1 << 3;
    pub const NO_HT40: u16 = 1 << 4;
    pub const NO_OFDM: u16 = 1 << 6;
    pub const NO_80MHZ: u16 = 1 << 7;
    pub const NO_160MHZ: u16 = 1 << 8;
    pub const INDOOR_ONLY: u16 = 1 << 9;
}

/// `enum nl80211_reg_rule_flags`.
pub mod rrf {
    pub const NO_OFDM: u32 = 1 << 0;
    pub const NO_OUTDOOR: u32 = 1 << 3;
    pub const DFS: u32 = 1 << 4;
    pub const NO_IR: u32 = 1 << 7;
    /// `__NL80211_RRF_NO_IBSS`.
    pub const NO_IBSS: u32 = 1 << 8;
    pub const AUTO_BW: u32 = 1 << 11;
    pub const NO_HT40MINUS: u32 = 1 << 13;
    pub const NO_HT40PLUS: u32 = 1 << 14;
    pub const NO_HT40: u32 = NO_HT40MINUS | NO_HT40PLUS;
    pub const NO_80MHZ: u32 = 1 << 15;
    pub const NO_160MHZ: u32 = 1 << 16;
    pub const NO_HE: u32 = 1 << 17;
    pub const NO_320MHZ: u32 = 1 << 18;
    pub const PSD: u32 = 1 << 20;
    /// `NL80211_RRF_NO_IR_ALL`.
    pub const NO_IR_ALL: u32 = NO_IR | NO_IBSS;
}

/// `enum ieee80211_channel_flags`.
pub mod chan_flag {
    pub const DISABLED: u32 = 1 << 0;
    pub const NO_IR: u32 = 1 << 1;
    pub const RADAR: u32 = 1 << 3;
    pub const NO_HT40PLUS: u32 = 1 << 4;
    pub const NO_HT40MINUS: u32 = 1 << 5;
    pub const NO_HT40: u32 = NO_HT40PLUS | NO_HT40MINUS;
    pub const NO_OFDM: u32 = 1 << 6;
    pub const NO_80MHZ: u32 = 1 << 7;
    pub const NO_160MHZ: u32 = 1 << 8;
    pub const INDOOR_ONLY: u32 = 1 << 9;
    pub const NO_10MHZ: u32 = 1 << 12;
    pub const NO_20MHZ: u32 = 1 << 13;
    pub const NO_HE: u32 = 1 << 14;
    pub const NO_320MHZ: u32 = 1 << 21;
    pub const PSD: u32 = 1 << 23;
}

/// `enum ath11k_dfs_region`.
pub mod dfs_region {
    pub const UNSET: u32 = 0;
    pub const FCC: u32 = 1;
    pub const ETSI: u32 = 2;
    pub const MKK: u32 = 3;
    pub const CN: u32 = 4;
    pub const KR: u32 = 5;
    pub const MKK_N: u32 = 6;
}

/// `ATH11K_REG_PHY_BITMAP_NO11AX`.
pub const ATH11K_REG_PHY_BITMAP_NO11AX: u32 = 1 << 5;
/// `ETSI_WEATHER_RADAR_BAND_LOW` / `_HIGH` (MHz).
pub const ETSI_WEATHER_RADAR_BAND_LOW: u32 = 5590;
pub const ETSI_WEATHER_RADAR_BAND_HIGH: u32 = 5650;
/// `ETSI_WEATHER_RADAR_BAND_CAC_TIMEOUT` (ms).
pub const ETSI_WEATHER_RADAR_BAND_CAC_TIMEOUT: u32 = 600_000;
/// `REG_SET_CC_STATUS_PASS`.
pub const REG_SET_CC_STATUS_PASS: u32 = 0;

/// `ath11k_map_fw_reg_flags`. Note `NO_IR` is an assignment in Linux,
/// not an OR; it is the first test, so the result is the same.
pub fn map_fw_reg_flags(f: u16) -> u32 {
    let mut flags = 0;
    if f & fw_flag::NO_IR != 0 {
        flags = rrf::NO_IR;
    }
    if f & fw_flag::RADAR != 0 {
        flags |= rrf::DFS;
    }
    if f & fw_flag::NO_OFDM != 0 {
        flags |= rrf::NO_OFDM;
    }
    if f & fw_flag::INDOOR_ONLY != 0 {
        flags |= rrf::NO_OUTDOOR;
    }
    if f & fw_flag::NO_HT40 != 0 {
        flags |= rrf::NO_HT40;
    }
    if f & fw_flag::NO_80MHZ != 0 {
        flags |= rrf::NO_80MHZ;
    }
    if f & fw_flag::NO_160MHZ != 0 {
        flags |= rrf::NO_160MHZ;
    }
    flags
}

/// `ath11k_map_fw_phy_flags`.
pub fn map_fw_phy_flags(phy: u32) -> u32 {
    if phy & ATH11K_REG_PHY_BITMAP_NO11AX != 0 {
        rrf::NO_HE
    } else {
        0
    }
}

/// `map_regdom_flags` (cfg80211, the bits a regdomain from ath11k can
/// carry).
pub fn map_regdom_flags(r: u32) -> u32 {
    let mut c = 0;
    if r & rrf::NO_IR_ALL != 0 {
        c |= chan_flag::NO_IR;
    }
    if r & rrf::DFS != 0 {
        c |= chan_flag::RADAR;
    }
    if r & rrf::NO_OFDM != 0 {
        c |= chan_flag::NO_OFDM;
    }
    if r & rrf::NO_OUTDOOR != 0 {
        c |= chan_flag::INDOOR_ONLY;
    }
    if r & rrf::NO_HT40MINUS != 0 {
        c |= chan_flag::NO_HT40MINUS;
    }
    if r & rrf::NO_HT40PLUS != 0 {
        c |= chan_flag::NO_HT40PLUS;
    }
    if r & rrf::NO_80MHZ != 0 {
        c |= chan_flag::NO_80MHZ;
    }
    if r & rrf::NO_160MHZ != 0 {
        c |= chan_flag::NO_160MHZ;
    }
    if r & rrf::NO_HE != 0 {
        c |= chan_flag::NO_HE;
    }
    if r & rrf::NO_320MHZ != 0 {
        c |= chan_flag::NO_320MHZ;
    }
    if r & rrf::PSD != 0 {
        c |= chan_flag::PSD;
    }
    c
}

// ── Regdomain ───────────────────────────────────────────────────────

/// `struct ieee80211_reg_rule` (MHz / dBm / dBi).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rule {
    pub start: u32,
    pub end: u32,
    pub max_bw: u32,
    pub max_antenna_gain: u32,
    pub max_eirp: u32,
    pub psd: i8,
    pub flags: u32,
    pub dfs_cac_ms: u32,
}

/// `struct ieee80211_regdomain`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Regd {
    pub alpha2: [u8; 2],
    /// `enum nl80211_dfs_regions` (0 unset, 1 FCC, 2 ETSI, 3 JP).
    pub dfs_region: u32,
    pub rules: Vec<Rule>,
}

/// `ath11k_map_fw_dfs_region`.
pub fn map_fw_dfs_region(r: u32) -> u32 {
    match r {
        dfs_region::FCC | dfs_region::CN => 1,
        dfs_region::ETSI | dfs_region::KR => 2,
        dfs_region::MKK | dfs_region::MKK_N => 3,
        _ => 0,
    }
}

/// `ath11k_reg_adjust_bw`.
pub fn adjust_bw(start: u32, end: u32, max_bw: u32) -> u32 {
    if end <= start {
        return 0;
    }
    let bw = (end - start).min(max_bw) as u16 as u32;
    if (80..160).contains(&bw) {
        80
    } else if (40..80).contains(&bw) {
        40
    } else if (20..40).contains(&bw) {
        20
    } else {
        0
    }
}

fn rule(start: u32, end: u32, bw: u32, r: &RegRule, flags: u32) -> Rule {
    Rule {
        start,
        end,
        max_bw: bw,
        max_antenna_gain: r.ant_gain as u32,
        max_eirp: r.reg_power as u32,
        psd: r.psd_eirp,
        flags,
        dfs_cac_ms: 0,
    }
}

/// `ath11k_reg_update_weather_radar_band`: replace the ETSI rule
/// covering 5590–5650 MHz by up to three rules.
fn weather_radar_split(out: &mut Vec<Rule>, r: &RegRule, flags: u32, max_bw: u32) {
    let (s, e) = (r.start_freq as u32, r.end_freq as u32);
    let bw = adjust_bw(s, ETSI_WEATHER_RADAR_BAND_LOW, max_bw);
    if bw > 0 {
        out.push(rule(s, ETSI_WEATHER_RADAR_BAND_LOW, bw, r, flags));
    }
    let ws = s.max(ETSI_WEATHER_RADAR_BAND_LOW);
    let we = e.min(ETSI_WEATHER_RADAR_BAND_HIGH);
    let bw = adjust_bw(ws, we, max_bw);
    if bw > 0 {
        let mut x = rule(ws, we, bw, r, flags);
        x.dfs_cac_ms = ETSI_WEATHER_RADAR_BAND_CAC_TIMEOUT;
        out.push(x);
    }
    let bw = adjust_bw(ETSI_WEATHER_RADAR_BAND_HIGH, e, max_bw);
    if bw > 0 {
        out.push(rule(ETSI_WEATHER_RADAR_BAND_HIGH, e, bw, r, flags));
    }
}

/// 6 GHz client selection `ath11k_reg_build_regd` makes for a STA vdev
/// (`ap_type` from the AP's power type, LPI when unset or empty).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VdevKind {
    /// `WMI_VDEV_TYPE_UNSPEC` / AP: the 6 GHz indoor AP rules.
    NotSta,
    /// `WMI_VDEV_TYPE_STA` with `ap_type`.
    Sta { ap_type: usize },
}

/// `ath11k_reg_build_regd` (the `intersect` step is
/// [`regd_intersect`]). `None` when the event carries no rules.
///
/// NARF deviation: Linux sizes the rule array as `num_rules (+2 for
/// ETSI)` and lets a second weather-radar split write past it; here the
/// vector grows instead.
pub fn build_regd(info: &RegInfo, vdev: VdevKind) -> Option<Regd> {
    let (rules6, max_bw6): (&[RegRule], u32) = if info.is_ext_reg_event {
        match vdev {
            VdevKind::Sta { ap_type } => {
                let mut ap = ap_type.min(2);
                // `ath11k_reg_build_regd` always builds the wiphy's active
                // station domain from the default-client rules. Firmware's
                // `client_type` is instead consumed by `mac` to choose a
                // subordinate versus default AP TPE category.
                let client = WMI_REG_DEFAULT_CLIENT;
                if info.rules_6ghz_client[ap][client].is_empty() {
                    ap = WMI_REG_INDOOR_AP;
                }
                (
                    &info.rules_6ghz_client[ap][client],
                    info.max_bw_6ghz_client[ap][client],
                )
            }
            VdevKind::NotSta => (
                &info.rules_6ghz_ap[WMI_REG_INDOOR_AP],
                info.max_bw_6ghz_ap[WMI_REG_INDOOR_AP],
            ),
        }
    } else {
        (&[], 0)
    };
    if info.rules_2ghz.len() + info.rules_5ghz.len() + rules6.len() == 0 {
        return None;
    }
    let mut out = Regd {
        alpha2: info.alpha2,
        dfs_region: map_fw_dfs_region(info.dfs_region),
        rules: Vec::new(),
    };
    let phy = map_fw_phy_flags(info.phybitmap);
    let push = |r: &RegRule, max_bw: u32, base: u32, out: &mut Vec<Rule>| {
        let flags = base | map_fw_reg_flags(r.flags) | phy;
        if flags & rrf::DFS != 0
            && info.dfs_region == dfs_region::ETSI
            && (r.end_freq as u32) > ETSI_WEATHER_RADAR_BAND_LOW
            && (r.start_freq as u32) < ETSI_WEATHER_RADAR_BAND_HIGH
        {
            weather_radar_split(out, r, flags, max_bw);
        } else {
            out.push(rule(
                r.start_freq as u32,
                r.end_freq as u32,
                max_bw,
                r,
                flags,
            ));
        }
    };
    for r in &info.rules_2ghz {
        push(
            r,
            (r.max_bw as u32).min(info.max_bw_2ghz as u16 as u32),
            0,
            &mut out.rules,
        );
    }
    for r in &info.rules_5ghz {
        push(
            r,
            (r.max_bw as u32).min(info.max_bw_5ghz as u16 as u32),
            rrf::AUTO_BW,
            &mut out.rules,
        );
    }
    for r in rules6 {
        let mut base = rrf::AUTO_BW;
        if r.psd_flag {
            base |= rrf::PSD;
        }
        push(
            r,
            (r.max_bw as u32).min(max_bw6 as u16 as u32),
            base,
            &mut out.rules,
        );
    }
    Some(out)
}

/// `ath11k_reg_can_intersect`.
fn can_intersect(a: &Rule, b: &Rule) -> bool {
    (a.start >= b.start && a.start < b.end) || (b.start > a.start && b.start < a.end)
}

/// `ath11k_regd_intersect(default_regd, curr_regd)`; `None` when no
/// rule pair overlaps.
pub fn regd_intersect(default: &Regd, curr: &Regd) -> Option<Regd> {
    let mut rules = Vec::new();
    for a in &default.rules {
        for b in &curr.rules {
            if !can_intersect(a, b) {
                continue;
            }
            let start = a.start.max(b.start);
            let end = a.end.min(b.end);
            let mut flags = a.flags | b.flags;
            let psd = if a.flags & rrf::PSD != 0 && b.flags & rrf::PSD != 0 {
                a.psd.min(b.psd)
            } else {
                flags &= !rrf::PSD;
                0
            };
            rules.push(Rule {
                start,
                end,
                max_bw: a.max_bw.min(b.max_bw).min(end - start),
                max_antenna_gain: a.max_antenna_gain.min(b.max_antenna_gain),
                max_eirp: a.max_eirp.min(b.max_eirp),
                psd,
                flags,
                dfs_cac_ms: a.dfs_cac_ms.max(b.dfs_cac_ms),
            });
        }
    }
    if rules.is_empty() {
        return None;
    }
    Some(Regd {
        alpha2: curr.alpha2,
        dfs_region: curr.dfs_region,
        rules,
    })
}

/// `ath11k_reg_is_world_alpha`.
pub fn is_world_alpha(a: [u8; 2]) -> bool {
    a == *b"00" || a == *b"na"
}

/// `ath11k_world_regd`, used when the firmware never sent a regdomain.
pub fn world_regd() -> Regd {
    let r = |s, e, bw, eirp, flags| Rule {
        start: s,
        end: e,
        max_bw: bw,
        max_antenna_gain: 0,
        max_eirp: eirp,
        psd: 0,
        flags,
        dfs_cac_ms: 0,
    };
    Regd {
        alpha2: *b"00",
        dfs_region: 0,
        rules: alloc::vec![
            r(2412 - 10, 2462 + 10, 40, 20, 0),
            r(5150 - 10, 5350 + 10, 80, 30, rrf::NO_IR),
            r(5725 - 10, 5850 + 10, 80, 30, rrf::NO_IR),
        ],
    }
}

// ── Wiphy channels ──────────────────────────────────────────────────

/// One `struct ieee80211_channel` of the wiphy.
///
/// DFS state is separate from regulatory flags: a RADAR channel remains a
/// legal channel while it is `Usable` (CAC required) or `Available`; only an
/// `Unavailable` channel is inside the regulatory non-occupancy period.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DfsState {
    /// Not a DFS channel, or no dynamic DFS restriction applies.
    #[default]
    Available,
    /// CAC is required before AP / GO operation.
    Usable,
    /// Radar was detected; NOP prevents operation until its expiry.
    Unavailable,
}

/// One `struct ieee80211_channel` of the wiphy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    pub band: Band,
    pub hw_value: u16,
    pub center_freq: u32,
    pub flags: u32,
    /// `orig_flags`, captured at wiphy registration.
    pub orig_flags: u32,
    pub max_antenna_gain: i32,
    pub max_power: i32,
    pub max_reg_power: i32,
    /// `ieee80211_channel::dfs_state` for RADAR channels.
    pub dfs_state: DfsState,
    /// `ieee80211_channel::dfs_cac_ms`, 60 seconds by default and longer
    /// only for regulatory rules such as ETSI weather radar.
    pub dfs_cac_ms: u32,
    /// `ieee80211_channel::psd`, in dBm/MHz. Meaningful only with
    /// [`chan_flag::PSD`]; retained so the 6 GHz WCN6855 TPC command can
    /// combine regulatory PSD with an AP's Transmit Power Envelope.
    pub psd: i8,
}

const fn ch(band: Band, hw: u16, freq: u32) -> Channel {
    Channel {
        band,
        hw_value: hw,
        center_freq: freq,
        flags: 0,
        orig_flags: 0,
        max_antenna_gain: 0,
        max_power: 30,
        max_reg_power: 0,
        dfs_state: DfsState::Available,
        dfs_cac_ms: 0,
        psd: 0,
    }
}

/// `ath11k_2ghz_channels[]`.
pub fn channels_2ghz() -> Vec<Channel> {
    (1..=14u16)
        .map(|c| {
            let f = if c == 14 { 2484 } else { 2407 + 5 * c as u32 };
            ch(Band::Ghz2, c, f)
        })
        .collect()
}

/// `ath11k_5ghz_channels[]`.
pub fn channels_5ghz() -> Vec<Channel> {
    const C: [u16; 28] = [
        36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
        149, 153, 157, 161, 165, 169, 173, 177,
    ];
    C.iter()
        .map(|&c| ch(Band::Ghz5, c, 5000 + 5 * c as u32))
        .collect()
}

/// `ath11k_6ghz_channels[]` (1, 5, …, 233, then 2 = 5935 MHz last).
pub fn channels_6ghz() -> Vec<Channel> {
    let mut v: Vec<Channel> = (0..59u16)
        .map(|i| {
            let c = 1 + 4 * i;
            ch(Band::Ghz6, c, 5950 + 5 * c as u32)
        })
        .collect();
    v.push(ch(Band::Ghz6, 2, 5935));
    v
}

/// The wiphy's bands as `ath11k_mac_setup_channels_rates` registers
/// them, in `enum nl80211_band` order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Wiphy {
    pub ghz2: Vec<Channel>,
    pub ghz5: Vec<Channel>,
    pub ghz6: Vec<Channel>,
}

impl Wiphy {
    /// `ath11k_mac_setup_channels_rates(ar, supported_bands)` with the
    /// single-pdev `hal_reg_cap[phy_id]` lookup, then
    /// `ath11k_mac_update_ch_list`, then wiphy registration
    /// (`orig_flags = flags`). `reg_cap` is `hal_reg_cap[pdev_idx]`;
    /// `reg_cap_2g` / `reg_cap_5g` the per-band ones (identical for a
    /// single-phy WCN6855).
    pub fn new(
        supported_bands: u32,
        reg_cap: &HalRegCapExt,
        reg_cap_2g: &HalRegCapExt,
        reg_cap_5g: &HalRegCapExt,
    ) -> Self {
        let mut w = Wiphy::default();
        let limit = |v: &mut Vec<Channel>, lo: u32, hi: u32| {
            if lo != 0 && hi != 0 {
                for c in v.iter_mut() {
                    if c.center_freq < lo || c.center_freq > hi {
                        c.flags |= chan_flag::DISABLED;
                    }
                }
            }
        };
        if supported_bands & WMI_HOST_WLAN_2G_CAP != 0 {
            w.ghz2 = channels_2ghz();
            limit(
                &mut w.ghz2,
                reg_cap_2g.low_2ghz_chan,
                reg_cap_2g.high_2ghz_chan,
            );
        }
        if supported_bands & WMI_HOST_WLAN_5G_CAP != 0 {
            if reg_cap.high_5ghz_chan >= ATH11K_MIN_6G_FREQ {
                w.ghz6 = channels_6ghz();
                limit(
                    &mut w.ghz6,
                    reg_cap_5g.low_5ghz_chan,
                    reg_cap_5g.high_5ghz_chan,
                );
            }
            if reg_cap.low_5ghz_chan < ATH11K_MIN_6G_FREQ {
                w.ghz5 = channels_5ghz();
                limit(
                    &mut w.ghz5,
                    reg_cap_5g.low_5ghz_chan,
                    reg_cap_5g.high_5ghz_chan,
                );
            }
        }
        for c in w.iter_mut() {
            c.orig_flags = c.flags;
        }
        w
    }

    pub fn supports_6ghz(&self) -> bool {
        !self.ghz6.is_empty()
    }

    pub fn band(&self, b: Band) -> &[Channel] {
        match b {
            Band::Ghz2 => &self.ghz2,
            Band::Ghz5 => &self.ghz5,
            Band::Ghz6 => &self.ghz6,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Channel> {
        self.ghz2
            .iter()
            .chain(self.ghz5.iter())
            .chain(self.ghz6.iter())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Channel> {
        self.ghz2
            .iter_mut()
            .chain(self.ghz5.iter_mut())
            .chain(self.ghz6.iter_mut())
    }

    /// `ieee80211_get_channel(wiphy, freq)`.
    pub fn get(&self, freq: u32) -> Option<&Channel> {
        self.iter().find(|c| c.center_freq == freq)
    }

    /// Set the dynamic DFS state of every 20-MHz subchannel in `def`.
    /// The caller supplies the affected vdev's channel definition.
    pub fn set_dfs_state(&mut self, def: &super::mac_peer::ChanDef, state: DfsState) {
        let mut set = |center: u32, span: u32| {
            let Some(mut freq) = center.checked_sub(span) else {
                return;
            };
            let end = center.saturating_add(span);
            while freq <= end {
                if let Some(channel) = self.iter_mut().find(|channel| channel.center_freq == freq) {
                    if channel.flags & chan_flag::RADAR != 0 {
                        channel.dfs_state = state;
                    }
                }
                freq = freq.saturating_add(20);
                if freq == 0 {
                    break;
                }
            }
        };
        match def.width {
            super::mac_peer::Width::W20NoHt | super::mac_peer::Width::W20 => set(def.freq, 0),
            super::mac_peer::Width::W40 => set(def.center_freq1, 10),
            super::mac_peer::Width::W80 => set(def.center_freq1, 30),
            super::mac_peer::Width::W160 => set(def.center_freq1, 70),
            super::mac_peer::Width::W80P80 => {
                set(def.center_freq1, 30);
                set(def.center_freq2, 30);
            }
        }
    }

    /// `reg_process_self_managed_hint`: `handle_band_custom` on every
    /// band, then `reg_process_ht_flags`.
    pub fn apply_regd(&mut self, regd: &Regd) {
        for c in self.iter_mut() {
            handle_channel_custom(c, regd);
        }
        for b in [Band::Ghz2, Band::Ghz5, Band::Ghz6] {
            let snapshot: Vec<Channel> = self.band(b).to_vec();
            let band = match b {
                Band::Ghz2 => &mut self.ghz2,
                Band::Ghz5 => &mut self.ghz5,
                Band::Ghz6 => &mut self.ghz6,
            };
            for c in band.iter_mut() {
                process_ht_flags_channel(c, &snapshot, regd);
            }
        }
    }

    /// `ath11k_reg_update_chan_list`: one [`ChannelParam`] per enabled
    /// channel, 2 GHz then 5 GHz then 6 GHz.
    pub fn scan_chan_list(&self) -> Vec<ChannelParam> {
        self.iter()
            .filter(|c| c.flags & chan_flag::DISABLED == 0)
            .map(|c| {
                let dfs = c.flags & chan_flag::RADAR != 0;
                ChannelParam {
                    allow_ht: true,
                    allow_vht: true,
                    allow_he: true,
                    dfs_set: dfs,
                    is_chan_passive: c.flags & chan_flag::NO_IR != 0 || dfs,
                    mhz: c.center_freq,
                    cfreq1: c.center_freq,
                    minpower: 0,
                    maxpower: (c.max_power * 2) as u8,
                    maxregpower: (c.max_reg_power * 2) as u8,
                    antennamax: (c.max_antenna_gain * 2) as u8,
                    phy_mode: if c.band == Band::Ghz2 {
                        phy_mode::MODE_11G
                    } else {
                        phy_mode::MODE_11A
                    },
                    psc_channel: c.band == Band::Ghz6 && is_psc(c.center_freq),
                    ..Default::default()
                }
            })
            .collect()
    }
}

/// `cfg80211_channel_is_psc`: 6 GHz channel numbers 5, 21, 37, … (every
/// 16th starting at 5).
pub fn is_psc(freq: u32) -> bool {
    if !(5950..=7115).contains(&freq) {
        return false;
    }
    let chan = (freq - 5950) / 5;
    chan % 16 == 5
}

/// `cfg80211_does_bw_fit_range`.
fn bw_fits(r: &Rule, center: u32, bw: u32) -> bool {
    // Linux works in kHz; ×1000 keeps odd half-widths exact.
    let c = center * 1000;
    let half = bw * 1000 / 2;
    c - half >= r.start * 1000 && c + half <= r.end * 1000
}

/// `freq_reg_info_regd(center, regd, 20 MHz)` — the band test only
/// changes the error code, which `handle_channel_custom` ignores.
fn rule_for(regd: &Regd, center: u32, bw: u32) -> Option<(usize, &Rule)> {
    regd.rules
        .iter()
        .enumerate()
        .find(|(_, r)| bw_fits(r, center, bw))
}

/// `reg_get_max_bandwidth`.
fn max_bandwidth(regd: &Regd, idx: usize) -> u32 {
    let rule = &regd.rules[idx];
    let mut lo = rule;
    let mut no = idx;
    while no > 0 {
        no -= 1;
        let t = &regd.rules[no];
        if t.end < lo.start {
            break;
        }
        lo = t;
    }
    let start = lo.start;
    let mut hi = rule;
    let mut no = idx;
    while no + 1 < regd.rules.len() {
        no += 1;
        let t = &regd.rules[no];
        if t.start > hi.end {
            break;
        }
        hi = t;
    }
    let mut bw = hi.end - start;
    if rule.flags & rrf::NO_320MHZ != 0 {
        bw = bw.min(160);
    }
    if rule.flags & rrf::NO_160MHZ != 0 {
        bw = bw.min(80);
    }
    if rule.flags & rrf::NO_80MHZ != 0 {
        bw = bw.min(40);
    }
    if rule.flags & rrf::NO_HT40MINUS != 0 && rule.flags & rrf::NO_HT40PLUS != 0 {
        bw = bw.min(20);
    }
    bw
}

/// `reg_rule_to_chan_bw_flags` (non-S1G).
fn chan_bw_flags(regd: &Regd, idx: usize, center: u32) -> u32 {
    let r = &regd.rules[idx];
    let max_bw = if r.flags & rrf::AUTO_BW != 0 {
        max_bandwidth(regd, idx)
    } else {
        r.max_bw
    };
    let mut f = 0;
    if !bw_fits(r, center, 10) {
        f |= chan_flag::NO_10MHZ;
    }
    if !bw_fits(r, center, 20) {
        f |= chan_flag::NO_20MHZ;
    }
    if max_bw < 10 {
        f |= chan_flag::NO_10MHZ;
    }
    if max_bw < 20 {
        f |= chan_flag::NO_20MHZ;
    }
    if max_bw < 40 {
        f |= chan_flag::NO_HT40;
    }
    if max_bw < 80 {
        f |= chan_flag::NO_80MHZ;
    }
    if max_bw < 160 {
        f |= chan_flag::NO_160MHZ;
    }
    if max_bw < 320 {
        f |= chan_flag::NO_320MHZ;
    }
    f
}

/// `handle_channel_custom` for a `REGULATORY_WIPHY_SELF_MANAGED` wiphy,
/// `min_bw` = 20 MHz (the loop therefore tries 20 MHz only).
pub fn handle_channel_custom(c: &mut Channel, regd: &Regd) {
    let Some((idx, r)) = rule_for(regd, c.center_freq, 20) else {
        c.flags |= chan_flag::DISABLED;
        return;
    };
    let bw = chan_bw_flags(regd, idx, c.center_freq);
    let was_radar = c.flags & chan_flag::RADAR != 0;
    c.flags = c.orig_flags | bw | map_regdom_flags(r.flags);
    c.max_antenna_gain = r.max_antenna_gain as i32;
    c.max_reg_power = r.max_eirp as i32;
    c.max_power = c.max_reg_power;
    c.dfs_state = if c.flags & chan_flag::RADAR != 0 {
        if was_radar {
            c.dfs_state
        } else {
            DfsState::Usable
        }
    } else {
        DfsState::Available
    };
    c.dfs_cac_ms = if c.flags & chan_flag::RADAR != 0 {
        r.dfs_cac_ms.max(60_000)
    } else {
        0
    };
    c.psd = if r.flags & rrf::PSD != 0 { r.psd } else { 0 };
}

/// `is_ht40_allowed`.
fn ht40_allowed(c: Option<&Channel>) -> bool {
    match c {
        None => false,
        Some(c) => {
            c.flags & chan_flag::DISABLED == 0 && c.flags & chan_flag::NO_HT40 != chan_flag::NO_HT40
        }
    }
}

/// `reg_process_ht_flags_channel`.
fn process_ht_flags_channel(c: &mut Channel, band: &[Channel], regd: &Regd) {
    if !ht40_allowed(Some(c)) {
        c.flags |= chan_flag::NO_HT40;
        return;
    }
    let before = band.iter().find(|x| x.center_freq + 20 == c.center_freq);
    let after = band.iter().find(|x| x.center_freq == c.center_freq + 20);
    let flags = rule_for(regd, c.center_freq, 20).map_or(0, |(_, r)| r.flags);
    if !ht40_allowed(before) || flags & rrf::NO_HT40MINUS != 0 {
        c.flags |= chan_flag::NO_HT40MINUS;
    } else {
        c.flags &= !chan_flag::NO_HT40MINUS;
    }
    if !ht40_allowed(after) || flags & rrf::NO_HT40PLUS != 0 {
        c.flags |= chan_flag::NO_HT40PLUS;
    } else {
        c.flags &= !chan_flag::NO_HT40PLUS;
    }
}

// ── Regulatory state (`ab->default_regd` / `new_regd` / store) ─────

/// Outcome of [`RegState::handle_chan_list`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegUpdate {
    /// First regdomain: became `default_regd` (applied at registration).
    Default,
    /// A later one: `new_regd`, applied now (`ath11k_regd_update_work`),
    /// after which cfg80211's driver-initiated notifier re-sends the
    /// channel list.
    New,
    /// Same alpha2 as the default during start/stop: ignored.
    Unchanged,
}

/// Per-pdev regulatory state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegState {
    pub default_regd: Option<Regd>,
    pub new_regd: Option<Regd>,
    /// `ab->reg_info_store[pdev_idx]` (the last `IEEE80211_REG_UNSET_AP`
    /// event, re-handled when a STA vdev appears).
    pub store: Option<RegInfo>,
    pub dfs_region: u32,
}

/// Why a regulatory event was refused (`ath11k_reg_handle_chan_list`
/// returns `-EINVAL`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegError {
    /// `status_code != REG_SET_CC_STATUS_PASS` (detail = status).
    Status(u32),
    /// `pdev_idx >= num_radios` on a multi-pdev part (fallback path).
    BadPhy(u32),
    /// `ath11k_reg_build_regd` (or the intersection) produced nothing.
    Build,
}

impl RegState {
    /// `ath11k_reg_handle_chan_list(ab, reg_info, power_type)`;
    /// `unset_ap` ⇔ `power_type == IEEE80211_REG_UNSET_AP`. `num_radios`
    /// is 1 on WCN6855 (single-pdev: events for phy 1 —
    /// `num_rxdma_per_pdev` = 2 — are accepted and dropped).
    pub fn handle_chan_list(
        &mut self,
        info: &RegInfo,
        unset_ap: bool,
        vdev: VdevKind,
        num_radios: u32,
        single_pdev_rxdma: u32,
    ) -> Result<RegUpdate, RegError> {
        if info.status_code != REG_SET_CC_STATUS_PASS {
            return Err(RegError::Status(info.status_code));
        }
        if info.phy_id >= num_radios {
            if info.phy_id < single_pdev_rxdma {
                return Ok(RegUpdate::Unchanged);
            }
            return Err(RegError::BadPhy(info.phy_id));
        }
        if let Some(d) = &self.default_regd {
            if self.new_regd.is_none() && d.alpha2 == info.alpha2 && unset_ap {
                return Ok(RegUpdate::Unchanged);
            }
        }
        let intersect = self
            .default_regd
            .as_ref()
            .is_some_and(|d| !is_world_alpha(d.alpha2) && !is_world_alpha(info.alpha2));
        let built = build_regd(info, vdev).ok_or(RegError::Build)?;
        let regd = if intersect {
            regd_intersect(self.default_regd.as_ref().unwrap(), &built).ok_or(RegError::Build)?
        } else {
            built
        };
        if unset_ap {
            self.store = Some(info.clone());
        }
        self.dfs_region = info.dfs_region;
        if self.default_regd.is_some() {
            self.new_regd = Some(regd);
            Ok(RegUpdate::New)
        } else {
            self.default_regd = Some(regd);
            Ok(RegUpdate::Default)
        }
    }

    /// `ath11k_regd_update`: the regdomain handed to cfg80211.
    pub fn current(&self) -> Regd {
        self.new_regd
            .clone()
            .or_else(|| self.default_regd.clone())
            .unwrap_or_else(world_regd)
    }
}
