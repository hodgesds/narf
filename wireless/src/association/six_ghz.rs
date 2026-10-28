// SPDX-License-Identifier: GPL-2.0-or-later
//! HE 6 GHz band facts: the HE 6 GHz Band Capabilities element (element ID
//! extension 59, IEEE802.11ax-2021 9.4.2.263), the 6 GHz Operation
//! Information of HE Operation (9.4.2.249), and the station admission
//! mac80211 applies to a 6 GHz BSS before it chooses a connection mode.
//!
//! Linux v7.2 references: include/linux/ieee80211-he.h
//! (`struct ieee80211_he_6ghz_oper`, `IEEE80211_HE_6GHZ_OPER_CTRL_*`,
//! `IEEE80211_6GHZ_CTRL_REG_*`), include/linux/ieee80211.h
//! (`IEEE80211_HE_6GHZ_CAP_*`), net/mac80211/mlme.c
//! `ieee80211_determine_chan_mode` (6 GHz needs HE Capabilities and HE 6 GHz
//! band capability), net/mac80211/util.c `ieee80211_chandef_he_6ghz_oper`
//! (HE-only path) and include/net/cfg80211.h `cfg80211_6ghz_power_type` /
//! net/wireless/scan.c `cfg80211_6ghz_power_type_valid`.
//!
//! These are facts about a received BSS; they grant no channel, transmit
//! power or association authority. `JoinPlan` stays a 2.4/5 GHz plan.
use super::channel::{self, Band};
use super::he::{self, HeCapability, HeOperation};
use super::phy::Width;
use super::Error;
use crate::reg::{PowerType6Ghz, RegRule};

/// Element ID extension of HE 6 GHz Band Capabilities.
pub const EXT_HE_6GHZ_CAPABILITIES: u8 = 59;

/// `IEEE80211_HE_6GHZ_CAP_MIN_MPDU_START`.
pub const CAP_MIN_MPDU_START: u16 = 0x0007;
/// `IEEE80211_HE_6GHZ_CAP_MAX_AMPDU_LEN_EXP`.
pub const CAP_MAX_AMPDU_LEN_EXP: u16 = 0x0038;
/// `IEEE80211_HE_6GHZ_CAP_MAX_MPDU_LEN`.
pub const CAP_MAX_MPDU_LEN: u16 = 0x00c0;
/// `IEEE80211_HE_6GHZ_CAP_SM_PS`.
pub const CAP_SM_PS: u16 = 0x0600;
/// `IEEE80211_HE_6GHZ_CAP_RD_RESPONDER`.
pub const CAP_RD_RESPONDER: u16 = 0x0800;
/// `IEEE80211_HE_6GHZ_CAP_RX_ANTPAT_CONS`.
pub const CAP_RX_ANTPAT_CONS: u16 = 0x1000;
/// `IEEE80211_HE_6GHZ_CAP_TX_ANTPAT_CONS`.
pub const CAP_TX_ANTPAT_CONS: u16 = 0x2000;

/// HE 6 GHz Band Capabilities Information (`struct ieee80211_he_6ghz_capa`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct He6GhzCapability(u16);
impl He6GhzCapability {
    pub const fn new(capa: u16) -> Self {
        Self(capa)
    }
    /// Parse the body after the extension ID octet: exactly two octets.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        match body {
            [lo, hi] => Ok(Self(u16::from_le_bytes([*lo, *hi]))),
            _ => Err(Error::InvalidBss),
        }
    }
    pub fn bits(self) -> u16 {
        self.0
    }
    /// Minimum MPDU Start Spacing (HT A-MPDU density encoding).
    pub fn min_mpdu_start(self) -> u8 {
        (self.0 & CAP_MIN_MPDU_START) as u8
    }
    /// Maximum A-MPDU Length Exponent (VHT encoding, 0..=7).
    pub fn max_ampdu_len_exp(self) -> u8 {
        ((self.0 & CAP_MAX_AMPDU_LEN_EXP) >> 3) as u8
    }
    /// Maximum MPDU Length (VHT encoding: 0 = 3895, 1 = 7991, 2 = 11454).
    pub fn max_mpdu_len(self) -> u8 {
        ((self.0 & CAP_MAX_MPDU_LEN) >> 6) as u8
    }
    /// SM Power Save (`WLAN_HT_CAP_SM_PS_*`).
    pub fn sm_ps(self) -> u8 {
        ((self.0 & CAP_SM_PS) >> 9) as u8
    }
    pub fn rd_responder(self) -> bool {
        self.0 & CAP_RD_RESPONDER != 0
    }
    /// The element as transmitted, including ID 255, length and extension ID
    /// (mac80211 `ieee80211_put_he_6ghz_cap`).
    pub fn element(self) -> [u8; 5] {
        let [lo, hi] = self.0.to_le_bytes();
        [255, 3, EXT_HE_6GHZ_CAPABILITIES, lo, hi]
    }
}

/// `IEEE80211_HE_6GHZ_OPER_CTRL_CHANWIDTH`.
const CTRL_CHANWIDTH: u8 = 0x03;
/// `IEEE80211_HE_6GHZ_OPER_CTRL_DUP_BEACON`.
const CTRL_DUP_BEACON: u8 = 0x04;
/// `IEEE80211_HE_6GHZ_OPER_CTRL_REG_INFO` (Linux v7.2: four bits).
const CTRL_REG_INFO: u8 = 0x78;

/// 6 GHz Operation Information (`struct ieee80211_he_6ghz_oper`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct He6GhzOperation {
    pub primary: u8,
    pub control: u8,
    pub ccfs0: u8,
    pub ccfs1: u8,
    /// Minimum rate in 1 Mb/s units.
    pub min_rate: u8,
}
impl He6GhzOperation {
    pub const fn from_bytes(b: [u8; 5]) -> Self {
        Self {
            primary: b[0],
            control: b[1],
            ccfs0: b[2],
            ccfs1: b[3],
            min_rate: b[4],
        }
    }
    pub fn duplicate_beacon(&self) -> bool {
        self.control & CTRL_DUP_BEACON != 0
    }
    /// Regulatory Info subfield (`IEEE80211_6GHZ_CTRL_REG_*`).
    pub fn regulatory_info(&self) -> u8 {
        (self.control & CTRL_REG_INFO) >> 3
    }
    /// cfg80211 `cfg80211_6ghz_power_type`. `no_afc_client` is the
    /// channel's `NO_6GHZ_AFC_CLIENT` restriction (Indoor SP falls back to
    /// LPI). `None` is `IEEE80211_REG_UNSET_AP`.
    pub fn power_type(&self, no_afc_client: bool) -> Option<PowerType6Ghz> {
        match self.regulatory_info() {
            // LPI, Indoor LPI, AP role not relevant, old Indoor SP.
            0 | 3 | 4 | 7 => Some(PowerType6Ghz::Lpi),
            1 => Some(PowerType6Ghz::Sp),
            2 => Some(PowerType6Ghz::Vlp),
            8 if no_afc_client => Some(PowerType6Ghz::Lpi),
            8 => Some(PowerType6Ghz::Sp),
            _ => None,
        }
    }
    /// mac80211 `ieee80211_chandef_he_6ghz_oper` without an EHT Operation:
    /// the operating channel this AP announces, validated as
    /// `cfg80211_chandef_valid` would (primary inside the span, aligned to
    /// a 20 MHz subchannel; 80+80 segments 80 MHz apart at least).
    pub fn channel(&self) -> Result<SixGhzChannel, Error> {
        let mhz = |ch| channel::frequency_in(Band::Ghz6, ch).ok_or(Error::InvalidBss);
        let primary_mhz = mhz(self.primary)?;
        // A 6 GHz primary is a 20 MHz channel: 1 + 4k (or channel 2).
        if self.primary != 2 && self.primary % 4 != 1 {
            return Err(Error::InvalidBss);
        }
        let (width, discontiguous, center) = match self.control & CTRL_CHANWIDTH {
            0 => (Width::Twenty, false, self.ccfs0),
            1 => (Width::Forty, false, self.ccfs0),
            2 => (Width::Eighty, false, self.ccfs0),
            _ if self.ccfs1 == 0 => (Width::Eighty, false, self.ccfs0),
            _ if self.ccfs1.abs_diff(self.ccfs0) == 8 => (Width::OneSixty, false, self.ccfs1),
            _ => (Width::OneSixty, true, self.ccfs0),
        };
        let center_mhz = mhz(center)?;
        let span = match (width, discontiguous) {
            (Width::Twenty, _) => 20,
            (Width::Forty, _) => 40,
            (Width::Eighty, _) | (Width::OneSixty, true) => 80,
            (Width::OneSixty, false) => 160,
        };
        let in_segment = |center: u32| {
            let low = center - span / 2;
            primary_mhz > low && primary_mhz < low + span && (primary_mhz - low) % 20 == 10
        };
        let center2_mhz = if discontiguous {
            let second = mhz(self.ccfs1)?;
            if second.abs_diff(center_mhz) <= 80 {
                return Err(Error::InvalidBss);
            }
            Some(second)
        } else {
            None
        };
        if !in_segment(center_mhz) && !center2_mhz.is_some_and(in_segment) {
            return Err(Error::InvalidBss);
        }
        Ok(SixGhzChannel {
            primary: self.primary,
            primary_mhz,
            width,
            discontiguous,
            center_mhz,
            center2_mhz,
        })
    }
}
/// A validated 6 GHz operating channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SixGhzChannel {
    pub primary: u8,
    pub primary_mhz: u32,
    pub width: Width,
    /// 80+80 MHz (`width` is then `OneSixty`).
    pub discontiguous: bool,
    /// `center_freq1`.
    pub center_mhz: u32,
    /// `center_freq2` of an 80+80 MHz channel.
    pub center2_mhz: Option<u32>,
}

/// The admitted 6 GHz facts of one BSS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SixGhzBss {
    pub he_capability: HeCapability,
    pub he_operation: HeOperation,
    pub capability: He6GhzCapability,
    pub operation: He6GhzOperation,
    pub channel: SixGhzChannel,
    /// `None` is `IEEE80211_REG_UNSET_AP`.
    pub power_type: Option<PowerType6Ghz>,
}

/// mac80211 `ieee80211_determine_chan_mode` for a 6 GHz BSS on `primary`,
/// HE-only path: the AP must send HE Capabilities, HE 6 GHz Band
/// Capabilities and an HE Operation carrying 6 GHz Operation Information
/// whose primary is `primary` and whose channel is valid. There is no legacy
/// fallback on 6 GHz, so anything else is refused. Every element is singular.
pub fn admit(ies: &[u8], primary: u8) -> Result<SixGhzBss, Error> {
    if ies.len() > 2048 {
        return Err(Error::InvalidBss);
    }
    let (mut cap, mut op, mut six) = (None, None, None);
    let mut rest = ies;
    while !rest.is_empty() {
        let head = rest.get(..2).ok_or(Error::InvalidBss)?;
        let body = rest
            .get(2..2 + usize::from(head[1]))
            .ok_or(Error::InvalidBss)?;
        if head[0] == 255 {
            let once = |seen: bool| if seen { Err(Error::InvalidBss) } else { Ok(()) };
            match body.split_first() {
                None => return Err(Error::InvalidBss),
                Some((&he::EXT_HE_CAPABILITIES, b)) => {
                    once(cap.is_some())?;
                    cap = Some(HeCapability::parse(b)?);
                }
                Some((&he::EXT_HE_OPERATION, b)) => {
                    once(op.is_some())?;
                    op = Some(HeOperation::parse(b)?);
                }
                Some((&EXT_HE_6GHZ_CAPABILITIES, b)) => {
                    once(six.is_some())?;
                    six = Some(He6GhzCapability::parse(b)?);
                }
                _ => {}
            }
        }
        rest = &rest[2 + usize::from(head[1])..];
    }
    let (Some(he_capability), Some(capability), Some(he_operation)) = (cap, six, op) else {
        // "HE 6 GHz AP is missing HE/HE 6 GHz band capability".
        return Err(Error::UnsupportedRates);
    };
    let operation = he_operation.six_ghz_operation().ok_or(Error::InvalidBss)?;
    // HE Operation on 6 GHz carries no VHT Operation Information.
    if he_operation.vht_operation_information().is_some() || operation.primary != primary {
        return Err(Error::InvalidBss);
    }
    let channel = operation.channel()?;
    Ok(SixGhzBss {
        he_capability,
        he_operation,
        capability,
        operation,
        channel,
        power_type: operation.power_type(false),
    })
}

/// `admit` plus the regulatory check cfg80211 applies before a 6 GHz BSS
/// is usable (`cfg80211_6ghz_power_type_valid`): the rule covering the
/// primary must allow a client of the AP's power type.
pub fn admit_with_rule(ies: &[u8], primary: u8, rule: &RegRule) -> Result<SixGhzBss, Error> {
    let mut bss = admit(ies, primary)?;
    if !rule.covers_mhz(bss.channel.primary_mhz) {
        return Err(Error::InvalidBss);
    }
    bss.power_type = bss.operation.power_type(rule.no_6ghz_afc_client());
    match bss.power_type {
        Some(power) if rule.allows_6ghz_client(power) => Ok(bss),
        // NL80211_BSS_CANNOT_USE_6GHZ_PWR_MISMATCH.
        _ => Err(Error::UnsupportedRates),
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "six_ghz_tests.rs"]
mod tests;
