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
//! `admit`/`admit_with_rule` are facts about a received BSS; they grant no
//! channel, transmit power or association authority. `plan` builds the 6 GHz
//! part of a `JoinPlan` (`JoinPlan::prepare_6ghz`): mac80211
//! `ieee80211_determine_chan_mode` / `ieee80211_chandef_he_6ghz_oper`
//! (including the EHT Operation path), `ieee80211_put_he_6ghz_cap` and
//! `ieee80211_put_reg_conn` (net/mac80211/{mlme,util}.c, Linux v7.2).
use super::channel::{self, Band};
use super::eht::{self, EhtCapability, EhtNegotiation, EhtOperation, LocalEht};
use super::he::{self, HeCapability, HeNegotiation, HeOperation, LocalHe};
use super::phy::Width;
use super::Error;
use crate::reg::{PowerType6Ghz, RegRule};
use alloc::vec::Vec;

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

/// Element ID extension of the Non-AP STA Regulatory Connectivity element
/// (`WLAN_EID_EXT_NON_AP_STA_REG_CON`).
pub const EXT_NON_AP_STA_REG_CON: u8 = 137;
/// `IEEE80211_REG_CONN_LPI_VALID`.
pub const REG_CONN_LPI_VALID: u8 = 0x01;
/// `IEEE80211_REG_CONN_LPI_VALUE`.
pub const REG_CONN_LPI_VALUE: u8 = 0x02;
/// `IEEE80211_REG_CONN_SP_VALID`.
pub const REG_CONN_SP_VALID: u8 = 0x04;
/// `IEEE80211_REG_CONN_SP_VALUE`.
pub const REG_CONN_SP_VALUE: u8 = 0x08;
/// `WLAN_HT_CAP_SM_PS_DISABLED` in the HE 6 GHz SM Power Save subfield.
const SM_PS_DISABLED: u16 = 3 << 9;

/// A 6 GHz operating channel width, including the EHT 320MHz channel that
/// `phy::Width` (the 2.4/5 GHz selection) does not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SixGhzWidth {
    Twenty,
    Forty,
    Eighty,
    /// 160MHz, or 80+80MHz when `SixGhzOperatingChannel::discontiguous`.
    OneSixty,
    /// EHT 320MHz (only when EHT is negotiated).
    ThreeTwenty,
}
impl SixGhzWidth {
    /// Span in MHz (80+80 reports 160).
    pub fn mhz(self) -> u32 {
        match self {
            Self::Twenty => 20,
            Self::Forty => 40,
            Self::Eighty => 80,
            Self::OneSixty => 160,
            Self::ThreeTwenty => 320,
        }
    }
    fn from_width(width: Width) -> Self {
        match width {
            Width::Twenty => Self::Twenty,
            Width::Forty => Self::Forty,
            Width::Eighty => Self::Eighty,
            Width::OneSixty => Self::OneSixty,
        }
    }
    /// The `phy::Width` of an HE/EHT negotiation (320 reports `OneSixty`).
    fn phy_width(self) -> Width {
        match self {
            Self::Twenty => Width::Twenty,
            Self::Forty => Width::Forty,
            Self::Eighty => Width::Eighty,
            Self::OneSixty | Self::ThreeTwenty => Width::OneSixty,
        }
    }
    fn narrower(self) -> Self {
        match self {
            Self::Twenty | Self::Forty => Self::Twenty,
            Self::Eighty => Self::Forty,
            Self::OneSixty => Self::Eighty,
            Self::ThreeTwenty => Self::OneSixty,
        }
    }
}

/// The 6 GHz channel-number centre of the aligned `width` block that
/// contains `primary` (cfg80211 `cfg80211_chandef_downgrade` on the 6 GHz
/// raster). 320MHz has two overlapping rasters, so it is never derived.
fn block_center(primary: u8, width: SixGhzWidth) -> Option<u8> {
    let base = primary.checked_sub(1)?;
    match width {
        SixGhzWidth::Twenty => Some(primary),
        SixGhzWidth::Forty => Some(base / 8 * 8 + 3),
        SixGhzWidth::Eighty => Some(base / 16 * 16 + 7),
        SixGhzWidth::OneSixty => Some(base / 32 * 32 + 15),
        SixGhzWidth::ThreeTwenty => None,
    }
    .filter(|center| channel::valid_6ghz(*center))
}

/// The station's own 6 GHz facts: its 6 GHz HE capability, HE 6 GHz Band
/// Capabilities (`sband_iftype_data.he_6ghz_capa`), optional EHT, and the
/// regulatory rule covering the BSS primary (cfg80211 channel flags). It
/// grants no channel or transmit authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SixGhzLocal {
    he: LocalHe,
    capability: He6GhzCapability,
    eht: Option<LocalEht>,
    rule: RegRule,
}
impl SixGhzLocal {
    /// A zero band capability is refused: mac80211
    /// `ieee80211_put_he_6ghz_cap` omits the element without a device HE
    /// 6 GHz capability, and a 6 GHz BSS cannot be joined without it.
    pub fn new(he: LocalHe, capability: He6GhzCapability, rule: RegRule) -> Result<Self, Error> {
        if capability.bits() == 0 {
            return Err(Error::UnsupportedRates);
        }
        Ok(Self {
            he,
            capability,
            eht: None,
            rule,
        })
    }
    /// Opt into EHT, including 320MHz (`LocalEht::with_320mhz`). The set
    /// form must match the local HE Channel Width Set.
    pub fn with_eht(mut self, eht: LocalEht) -> Result<Self, Error> {
        if !eht.matches_he(self.he.capability().phy_capability()[0]) {
            return Err(Error::UnsupportedRates);
        }
        self.eht = Some(eht);
        Ok(self)
    }
    pub fn he(&self) -> &LocalHe {
        &self.he
    }
    pub fn eht(&self) -> Option<&LocalEht> {
        self.eht.as_ref()
    }
    pub fn capability(&self) -> He6GhzCapability {
        self.capability
    }
    pub fn rule(&self) -> &RegRule {
        &self.rule
    }
    /// The HE 6 GHz Band Capabilities sent in the association request:
    /// mac80211 `ieee80211_put_he_6ghz_cap` with `IEEE80211_SMPS_OFF`
    /// (SM Power Save = disabled).
    pub fn transmitted_capability(&self) -> He6GhzCapability {
        He6GhzCapability::new(self.capability.bits() & !CAP_SM_PS | SM_PS_DISABLED)
    }
    /// The Non-AP STA Regulatory Connectivity value (mac80211
    /// `ieee80211_put_reg_conn`): LPI valid and set, SP valid, SP set unless
    /// the channel is `NO_6GHZ_AFC_CLIENT`.
    pub fn regulatory_connectivity(&self) -> u8 {
        REG_CONN_LPI_VALID
            | REG_CONN_LPI_VALUE
            | REG_CONN_SP_VALID
            | if self.rule.no_6ghz_afc_client() {
                0
            } else {
                REG_CONN_SP_VALUE
            }
    }
}

/// The negotiated 6 GHz operating channel a driver programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SixGhzOperatingChannel {
    pub primary: u8,
    pub primary_mhz: u32,
    pub width: SixGhzWidth,
    /// 80+80MHz (`width` is then `OneSixty`).
    pub discontiguous: bool,
    /// Channel number and frequency of `center_freq1`.
    pub center: u8,
    pub center_mhz: u32,
    /// `center_freq2` of an 80+80MHz channel.
    pub center2: Option<u8>,
    pub center2_mhz: Option<u32>,
}
impl SixGhzOperatingChannel {
    fn contiguous(primary: u8, width: SixGhzWidth, center: u8) -> Result<Self, Error> {
        let mhz = |ch| channel::frequency_in(Band::Ghz6, ch).ok_or(Error::InvalidBss);
        let (primary_mhz, center_mhz) = (mhz(primary)?, mhz(center)?);
        let low = center_mhz
            .checked_sub(width.mhz() / 2)
            .ok_or(Error::InvalidBss)?;
        if primary_mhz <= low || primary_mhz >= low + width.mhz() || (primary_mhz - low) % 20 != 10
        {
            return Err(Error::InvalidBss);
        }
        Ok(Self {
            primary,
            primary_mhz,
            width,
            discontiguous: false,
            center,
            center_mhz,
            center2: None,
            center2_mhz: None,
        })
    }
    /// The same primary at `width` (narrower or equal).
    fn downgrade(&self, width: SixGhzWidth) -> Result<Self, Error> {
        if width == self.width && !self.discontiguous {
            return Ok(*self);
        }
        let center = block_center(self.primary, width).ok_or(Error::InvalidBss)?;
        Self::contiguous(self.primary, width, center)
    }
    /// True when `other` (same primary) lies inside this channel:
    /// cfg80211 `cfg80211_chandef_compatible` for contiguous channels.
    fn contains(&self, other: &Self) -> bool {
        other.width <= self.width
            && !other.discontiguous
            && !self.discontiguous
            && self.downgrade(other.width).ok().as_ref() == Some(other)
    }
}

/// The negotiated 6 GHz state of a `JoinPlan` (`JoinPlan::six_ghz`), for a
/// driver's STA_REC_HE_6G / band-capability and channel programming.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SixGhzPlan {
    operation: He6GhzOperation,
    power_type: PowerType6Ghz,
    channel: SixGhzOperatingChannel,
    peer_capability: He6GhzCapability,
    local_capability: He6GhzCapability,
    regulatory_connectivity: u8,
    he: HeNegotiation,
    eht: Option<EhtNegotiation>,
}
impl SixGhzPlan {
    /// The AP's 6 GHz Operation Information.
    pub fn operation(&self) -> &He6GhzOperation {
        &self.operation
    }
    /// The client power type admitted under the regulatory rule.
    pub fn power_type(&self) -> PowerType6Ghz {
        self.power_type
    }
    /// The operating channel: the AP's HE (or EHT) 6 GHz channel narrowed
    /// to both stations' channel-width capability.
    pub fn channel(&self) -> &SixGhzOperatingChannel {
        &self.channel
    }
    pub fn width(&self) -> SixGhzWidth {
        self.channel.width
    }
    /// The AP's HE 6 GHz Band Capabilities (min MPDU spacing, max A-MPDU
    /// exponent, max MPDU length, SM PS: mt76 `STA_REC_HE_6G`).
    pub fn peer_capability(&self) -> He6GhzCapability {
        self.peer_capability
    }
    /// The HE 6 GHz Band Capabilities this request transmitted.
    pub fn local_capability(&self) -> He6GhzCapability {
        self.local_capability
    }
    /// The transmitted Non-AP STA Regulatory Connectivity value.
    pub fn regulatory_connectivity(&self) -> u8 {
        self.regulatory_connectivity
    }
    /// HE facts; HE is mandatory on 6 GHz. Its width never exceeds 160MHz.
    pub fn he(&self) -> &HeNegotiation {
        &self.he
    }
    /// EHT facts when negotiated (`EhtNegotiation::width320` for 320MHz).
    pub fn eht(&self) -> Option<&EhtNegotiation> {
        self.eht.as_ref()
    }
    /// The capability elements appended to the association request after
    /// RSNE/RSNXE, in mac80211 `ieee80211_add_link_elems` order: HE
    /// Capabilities, HE 6 GHz Band Capabilities, Non-AP STA Regulatory
    /// Connectivity, then EHT Capabilities. No HT or VHT element is sent.
    pub(super) fn append_capabilities(&self, bytes: &mut Vec<u8>) {
        let he = self.he.local_capability();
        bytes.extend_from_slice(&[255, he.len() as u8]);
        bytes.extend_from_slice(&he);
        bytes.extend_from_slice(&self.local_capability.element());
        bytes.extend_from_slice(&[255, 2, EXT_NON_AP_STA_REG_CON, self.regulatory_connectivity]);
        if let Some(eht) = self.eht.as_ref() {
            let body = eht.local_capability();
            bytes.extend_from_slice(&[255, body.len() as u8]);
            bytes.extend_from_slice(&body);
        }
    }
}

/// The EHT channel announced by EHT Operation Information on 6 GHz
/// (mac80211 `ieee80211_chandef_eht_oper`: the primary comes from the 6 GHz
/// Operation Information, 160/320MHz centre from CCFS1).
fn eht_channel(primary: u8, info: [u8; 3]) -> Result<SixGhzOperatingChannel, Error> {
    let (width, center) = match info[0] & 0x07 {
        0 => (SixGhzWidth::Twenty, info[1]),
        1 => (SixGhzWidth::Forty, info[1]),
        2 => (SixGhzWidth::Eighty, info[1]),
        3 => (SixGhzWidth::OneSixty, info[2]),
        4 => (SixGhzWidth::ThreeTwenty, info[2]),
        _ => return Err(Error::InvalidBss),
    };
    // A 320MHz centre is 31 + 32k (320-1 and 320-2 overlap).
    if width == SixGhzWidth::ThreeTwenty && center % 32 != 31 {
        return Err(Error::InvalidBss);
    }
    if width != SixGhzWidth::ThreeTwenty && block_center(primary, width) != Some(center) {
        return Err(Error::InvalidBss);
    }
    SixGhzOperatingChannel::contiguous(primary, width, center)
}

/// Build the 6 GHz part of a `JoinPlan` (mac80211
/// `ieee80211_determine_chan_mode` for `NL80211_BAND_6GHZ`).
/// - `admit_with_rule` against `local.rule()`: HE, HE 6 GHz Band
///   Capabilities and 6 GHz Operation Information are required and the
///   client power type (LPI/SP/VLP; SP needs AFC, refused under
///   `NO_6GHZ_AFC_CLIENT`) must be allowed.
/// - With local EHT and both AP EHT elements, EHT Operation Information (if
///   present) defines the channel and must contain the HE channel (STRICT
///   "HE/EHT incompatible"); 320MHz needs both sides' 320MHz capability,
///   otherwise the channel is narrowed. A punctured EHT channel falls back
///   to HE, as on the 2.4/5 GHz plan.
/// - The channel is narrowed to both stations' Channel Width Set; HE is
///   mandatory, so no usable HE refuses the BSS (`UnsupportedRates`).
pub fn plan(ies: &[u8], primary: u8, local: &SixGhzLocal) -> Result<SixGhzPlan, Error> {
    let bss = admit_with_rule(ies, primary, &local.rule)?;
    let power_type = bss.power_type.ok_or(Error::UnsupportedRates)?;
    let ap_phy0 = bss.he_capability.phy_capability()[0];
    let (mut eht_cap, mut eht_op) = (None, None);
    super::ies(ies, |id, body| {
        if id == 255 {
            match body.split_first() {
                Some((&eht::EXT_EHT_CAPABILITIES, b)) => {
                    if eht_cap.is_some() {
                        return Err(Error::InvalidBss);
                    }
                    eht_cap = Some(EhtCapability::parse(b, ap_phy0, true)?);
                }
                Some((&eht::EXT_EHT_OPERATION, b)) => {
                    if eht_op.is_some() {
                        return Err(Error::InvalidBss);
                    }
                    eht_op = Some(EhtOperation::parse(b)?);
                }
                _ => {}
            }
        }
        Ok(())
    })?;
    let ap = bss.channel;
    let he_channel = SixGhzOperatingChannel {
        primary: ap.primary,
        primary_mhz: ap.primary_mhz,
        width: SixGhzWidth::from_width(ap.width),
        discontiguous: ap.discontiguous,
        center: if ap.width == Width::OneSixty && !ap.discontiguous {
            bss.operation.ccfs1
        } else {
            bss.operation.ccfs0
        },
        center_mhz: ap.center_mhz,
        center2: ap.discontiguous.then_some(bss.operation.ccfs1),
        center2_mhz: ap.center2_mhz,
    };
    let he = he::negotiate_6ghz(
        local.he,
        bss.he_capability,
        bss.he_operation,
        ap.width,
        ap.discontiguous,
    )
    .ok_or(Error::UnsupportedRates)?;
    let he_operating = if he.discontiguous() {
        he_channel
    } else {
        he_channel.downgrade(SixGhzWidth::from_width(he.width()))?
    };
    let mut channel = he_operating;
    let mut eht = None;
    // EHT has no 80+80 channel: an 80+80 HE BSS is joined as HE.
    if let (false, Some(local_eht), Some(cap), Some(op)) =
        (he_channel.discontiguous, local.eht, eht_cap, eht_op)
    {
        let announced = match op.information() {
            Some(info) => {
                let announced = eht_channel(primary, info)?;
                if !announced.contains(&he_channel) {
                    // mac80211 STRICT: "HE/EHT incompatible".
                    return Err(Error::InvalidBss);
                }
                announced
            }
            None => he_channel,
        };
        let punctured = op.disabled_subchannels().is_some_and(|b| b != 0);
        if !punctured {
            // Narrow to both sides' widths: 320 (EHT B1), 160 (HE B3),
            // 40/80 (HE B2).
            let both_he = |bit: u8| local.he.capability().phy_capability()[0] & ap_phy0 & bit != 0;
            let both_320 = local_eht.width320()
                && cap.phy_capability()[0] & 0x02 != 0
                && cap.mcs_nss().len() == 9;
            let mut width = announced.width;
            loop {
                let ok = match width {
                    SixGhzWidth::ThreeTwenty => both_320,
                    SixGhzWidth::OneSixty => both_he(0x08),
                    SixGhzWidth::Forty | SixGhzWidth::Eighty => both_he(0x04),
                    SixGhzWidth::Twenty => true,
                };
                if ok {
                    break;
                }
                width = width.narrower();
            }
            let selected = announced.downgrade(width)?;
            if let Some(neg) = eht::negotiate_6ghz(
                local_eht,
                cap,
                op,
                width.phy_width(),
                width == SixGhzWidth::ThreeTwenty,
            ) {
                channel = selected;
                eht = Some(neg);
            }
        }
    }
    Ok(SixGhzPlan {
        operation: bss.operation,
        power_type,
        channel,
        peer_capability: bss.capability,
        local_capability: local.transmitted_capability(),
        regulatory_connectivity: local.regulatory_connectivity(),
        he,
        eht,
    })
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "six_ghz_tests.rs"]
mod tests;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "six_ghz_plan_tests.rs"]
mod plan_tests;
