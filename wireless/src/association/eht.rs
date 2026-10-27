// SPDX-License-Identifier: GPL-2.0-or-later
//! EHT (IEEE Std 802.11be-2024) Capabilities/Operation facts and non-MLO
//! station negotiation for the 2.4/5GHz `JoinPlan` PHY path.
//!
//! Wire layout: IEEE802.11be-2024 9.4.2.323 (EHT Capabilities, element ID
//! extension 108) and 9.4.2.322 (EHT Operation, extension 106); Linux
//! include/linux/ieee80211-eht.h (`ieee80211_eht_mcs_nss_size`,
//! `ieee80211_eht_ppe_size`, `ieee80211_eht_capa_size_ok`,
//! `ieee80211_eht_oper_size_ok`). Admission mirrors mac80211 mlme.c
//! `ieee80211_determine_ap_chan` (EHT only on top of HE, with both EHT
//! elements) and `ieee80211_verify_sta_eht_mcs_support` /
//! `ieee80211_get_eht_cap_mcs_nss`; peer limits mirror eht.c
//! `ieee80211_eht_cap_ie_to_sta_eht_cap`. Six-GHz 320MHz operation and
//! multi-link operation are outside this 2.4/5GHz single-link plan.
use super::he::HeNegotiation;
use super::phy::Width;
use super::Error;
use alloc::vec::Vec;

/// Element ID extension of EHT Operation (IEEE802.11be-2024 Table 9-128).
pub const EXT_EHT_OPERATION: u8 = 106;
/// Element ID extension of EHT Capabilities.
pub const EXT_EHT_CAPABILITIES: u8 = 108;

const HE_PHY0_40_2G: u8 = 0x02;
const HE_PHY0_40_80_5G: u8 = 0x04;
const HE_PHY0_160_5G: u8 = 0x08;
const PHY0_320_6G: u8 = 0x02;
const PHY0_SU_BEAMFORMER: u8 = 0x20;
const PHY0_SU_BEAMFORMEE: u8 = 0x40;
const PHY5_PPE_PRESENT: u8 = 0x08;
const OP_INFO_PRESENT: u8 = 0x01;
const OP_DISABLED_BITMAP_PRESENT: u8 = 0x02;

/// Linux `IEEE80211_EHT_PPE_THRES_MAX_LEN`: larger PPE fields (NSS > 8)
/// are refused, as `ieee80211_eht_cap_ie_to_sta_eht_cap` refuses them.
pub const MAX_PPE: usize = 32;

/// `ieee80211_eht_ppe_size` from the 16-bit PPE header.
fn ppe_size(header: u16) -> usize {
    let ru = (header & 0x1f0).count_ones() as usize;
    let nss = usize::from(header & 0xf) + 1;
    (ru * nss * 6 + 9).div_ceil(8)
}

/// `ieee80211_eht_mcs_nss_size`: the Supported EHT-MCS And NSS Set length
/// from the same STA's HE PHY Channel Width Set.
fn mcs_nss_size(he_phy0: u8, eht_phy0: u8, from_ap: bool) -> usize {
    if he_phy0 & HE_PHY0_40_2G != 0 {
        return 3;
    }
    let mut count = 0;
    if he_phy0 & HE_PHY0_40_80_5G != 0 {
        count += 3;
    }
    if he_phy0 & HE_PHY0_160_5G != 0 {
        count += 3;
    }
    if eht_phy0 & PHY0_320_6G != 0 {
        count += 3;
    }
    match (count, from_ap) {
        (0, true) => 3,
        (0, false) => 4,
        (n, _) => n,
    }
}

/// A parsed EHT Capabilities body (after the extension ID). `mcs` holds
/// the variable-length Supported EHT-MCS And NSS Set: four octets for a
/// 20MHz-only non-AP STA, otherwise three octets each for <=80, 160 and
/// (6GHz) 320MHz. Each octet is RX max NSS (bits0..3) | TX max NSS
/// (bits4..7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EhtCapability {
    mac: [u8; 2],
    phy: [u8; 9],
    mcs: [u8; 9],
    mcs_len: u8,
    ppe: [u8; MAX_PPE],
    ppe_len: u8,
}
impl EhtCapability {
    /// Parse a body without the extension-ID octet. `he_phy0` is octet0 of
    /// the same STA's HE PHY Capabilities; the body must end exactly after
    /// the MCS/NSS set and optional PPE Thresholds.
    pub fn parse(body: &[u8], he_phy0: u8, from_ap: bool) -> Result<Self, Error> {
        if body.len() < 11 {
            return Err(Error::InvalidBss);
        }
        let mac = [body[0], body[1]];
        let phy: [u8; 9] = body[2..11].try_into().map_err(|_| Error::InvalidBss)?;
        let size = mcs_nss_size(he_phy0, phy[0], from_ap);
        let set = body.get(11..11 + size).ok_or(Error::InvalidBss)?;
        let mut mcs = [0; 9];
        mcs[..size].copy_from_slice(set);
        let mut at = 11 + size;
        let mut ppe = [0; MAX_PPE];
        let mut ppe_len = 0;
        if phy[5] & PHY5_PPE_PRESENT != 0 {
            let header = body.get(at..at + 2).ok_or(Error::InvalidBss)?;
            let len = ppe_size(u16::from_le_bytes([header[0], header[1]]));
            if len > MAX_PPE {
                return Err(Error::InvalidBss);
            }
            ppe[..len].copy_from_slice(body.get(at..at + len).ok_or(Error::InvalidBss)?);
            ppe_len = len as u8;
            at += len;
        }
        if at != body.len() {
            return Err(Error::InvalidBss);
        }
        Ok(Self {
            mac,
            phy,
            mcs,
            mcs_len: size as u8,
            ppe,
            ppe_len,
        })
    }
    pub fn mac_capability(&self) -> [u8; 2] {
        self.mac
    }
    pub fn phy_capability(&self) -> [u8; 9] {
        self.phy
    }
    /// The raw Supported EHT-MCS And NSS Set octets.
    pub fn mcs_nss(&self) -> &[u8] {
        &self.mcs[..usize::from(self.mcs_len)]
    }
    pub fn ppe_thresholds(&self) -> &[u8] {
        &self.ppe[..usize::from(self.ppe_len)]
    }
    /// The body including the extension-ID octet.
    pub fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 11 + 9 + MAX_PPE);
        out.push(EXT_EHT_CAPABILITIES);
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.phy);
        out.extend_from_slice(self.mcs_nss());
        out.extend_from_slice(self.ppe_thresholds());
        out
    }
    /// `ieee80211_get_eht_cap_mcs_nss` in uniform form: the max-NSS octet
    /// for MCS0-7, 8-9, 10-11 and 12-13 at <=80MHz (`bw160` = false) or
    /// 160MHz. A 20MHz-only set has four ranges; the others report MCS0-9
    /// for both of the first two.
    fn ranges(&self, bw160: bool) -> [u8; 4] {
        if self.mcs_len == 4 {
            return [self.mcs[0], self.mcs[1], self.mcs[2], self.mcs[3]];
        }
        let at = if bw160 { 3 } else { 0 };
        [
            self.mcs[at],
            self.mcs[at],
            self.mcs[at + 1],
            self.mcs[at + 2],
        ]
    }
    fn has_160(&self) -> bool {
        self.mcs_len >= 6
    }
}

/// Local EHT implementation facts for one band, from the driver's station
/// iftype EHT capability. The Supported EHT-MCS And NSS Set form follows
/// the local HE Channel Width Set and is checked by `LocalPhy::with_eht`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalEht(EhtCapability);
impl LocalEht {
    fn build(mac: [u8; 2], phy: [u8; 9], set: &[u8]) -> Result<Self, Error> {
        // B0 is reserved; 320MHz is a 6GHz capability; PPE presence is
        // owned by `with_ppe_thresholds`. Single-stream MCS0-7 must be
        // supported in both directions (IEEE802.11be-2024 36.1.1).
        if phy[0] & (0x01 | PHY0_320_6G) != 0
            || phy[5] & PHY5_PPE_PRESENT != 0
            || set[0] & 0x0f == 0
            || set[0] >> 4 == 0
        {
            return Err(Error::UnsupportedRates);
        }
        let mut mcs = [0; 9];
        mcs[..set.len()].copy_from_slice(set);
        Ok(Self(EhtCapability {
            mac,
            phy,
            mcs,
            mcs_len: set.len() as u8,
            ppe: [0; MAX_PPE],
            ppe_len: 0,
        }))
    }
    /// A STA whose HE profile supports more than 20MHz: one octet each for
    /// MCS0-9, 10-11 and 12-13 at <=80MHz.
    pub fn new(mac: [u8; 2], phy: [u8; 9], le80: [u8; 3]) -> Result<Self, Error> {
        Self::build(mac, phy, &le80)
    }
    /// A 20MHz-only non-AP STA: MCS0-7, 8-9, 10-11 and 12-13.
    pub fn twenty_only(mac: [u8; 2], phy: [u8; 9], set: [u8; 4]) -> Result<Self, Error> {
        Self::build(mac, phy, &set)
    }
    /// Add the 160MHz MCS/NSS set (needs a <=80MHz set and HE160).
    pub fn with_160mhz(mut self, set: [u8; 3]) -> Result<Self, Error> {
        if self.0.mcs_len != 3 || set[0] & 0x0f == 0 || set[0] >> 4 == 0 {
            return Err(Error::UnsupportedRates);
        }
        self.0.mcs[3..6].copy_from_slice(&set);
        self.0.mcs_len = 6;
        Ok(self)
    }
    /// Advertise a complete EHT PPE Thresholds field (sets PHY B37).
    pub fn with_ppe_thresholds(mut self, ppe: &[u8]) -> Result<Self, Error> {
        if ppe.len() < 2
            || ppe.len() > MAX_PPE
            || ppe.len() != ppe_size(u16::from_le_bytes([ppe[0], ppe[1]]))
            || ppe[0] & 0xf0 == 0 && ppe[1] & 0x01 == 0
        {
            return Err(Error::UnsupportedRates);
        }
        self.0.phy[5] |= PHY5_PPE_PRESENT;
        self.0.ppe = [0; MAX_PPE];
        self.0.ppe[..ppe.len()].copy_from_slice(ppe);
        self.0.ppe_len = ppe.len() as u8;
        Ok(self)
    }
    /// The set form must equal `ieee80211_eht_mcs_nss_size` for the local
    /// HE PHY octet0 (non-AP).
    pub(super) fn matches_he(&self, he_phy0: u8) -> bool {
        usize::from(self.0.mcs_len) == mcs_nss_size(he_phy0, self.0.phy[0], false)
    }
    pub fn capability_body(&self) -> Vec<u8> {
        self.0.body()
    }
    pub fn capability(&self) -> &EhtCapability {
        &self.0
    }
}

/// A parsed EHT Operation body (after the extension ID).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EhtOperation {
    params: u8,
    basic: [u8; 4],
    info: Option<[u8; 3]>,
    disabled: Option<u16>,
}
impl EhtOperation {
    /// Exact `ieee80211_eht_oper_size_ok` length.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        if body.len() < 5 {
            return Err(Error::InvalidBss);
        }
        let params = body[0];
        let info_present = params & OP_INFO_PRESENT != 0;
        let bitmap = info_present && params & OP_DISABLED_BITMAP_PRESENT != 0;
        let expected = 5 + if info_present { 3 } else { 0 } + if bitmap { 2 } else { 0 };
        if body.len() != expected {
            return Err(Error::InvalidBss);
        }
        Ok(Self {
            params,
            basic: [body[1], body[2], body[3], body[4]],
            info: info_present.then(|| [body[5], body[6], body[7]]),
            disabled: bitmap.then(|| u16::from_le_bytes([body[8], body[9]])),
        })
    }
    /// Basic EHT-MCS And NSS Set (20MHz-only form: MCS0-7/8-9/10-11/12-13,
    /// RX NSS bits0..3, TX NSS bits4..7).
    pub fn basic_mcs_nss(&self) -> [u8; 4] {
        self.basic
    }
    /// EHT Operation Information: channel width (0=20..3=160, 4=320),
    /// CCFS0, CCFS1.
    pub fn information(&self) -> Option<[u8; 3]> {
        self.info
    }
    /// Disabled Subchannel Bitmap (preamble puncturing), if present.
    pub fn disabled_subchannels(&self) -> Option<u16> {
        self.disabled
    }
    pub fn default_pe_duration(&self) -> bool {
        self.params & 0x04 != 0
    }
    pub fn group_addressed_bu_indication_limit(&self) -> bool {
        self.params & 0x08 != 0
    }
    pub fn group_addressed_bu_indication_exponent(&self) -> u8 {
        self.params >> 4 & 3
    }
    pub fn mcs15_disabled(&self) -> bool {
        self.params & 0x40 != 0
    }
}

/// Directional non-MLO EHT facts for the HE operating width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EhtNegotiation {
    local: LocalEht,
    peer: EhtCapability,
    operation: EhtOperation,
    width: Width,
    tx: [u8; 4],
    allowed: u8,
}
const FLAG_BFEE: u8 = 1;
const FLAG_BFER: u8 = 2;
impl EhtNegotiation {
    /// EHT PPDU bandwidth (the negotiated HE width).
    pub fn width(&self) -> Width {
        self.width
    }
    /// Per-range TX max NSS (MCS0-7, 8-9, 10-11, 12-13): local TX limited
    /// by the AP's RX at `width()`. Zero means the range is unusable.
    pub fn tx_max_nss(&self) -> [u8; 4] {
        self.tx
    }
    /// Per-range local RX max NSS promise at `width()`.
    pub fn rx_max_nss(&self) -> [u8; 4] {
        self.local
            .0
            .ranges(self.width == Width::OneSixty)
            .map(|v| v & 0x0f)
    }
    pub fn peer_capability(&self) -> &EhtCapability {
        &self.peer
    }
    pub fn operation(&self) -> &EhtOperation {
        &self.operation
    }
    pub fn local_capability(&self) -> Vec<u8> {
        self.local.capability_body()
    }
    pub fn su_beamformee(&self) -> bool {
        self.allowed & FLAG_BFEE != 0
            && self.local.0.phy[0] & PHY0_SU_BEAMFORMEE != 0
            && self.peer.phy[0] & PHY0_SU_BEAMFORMER != 0
    }
    pub fn su_beamformer(&self) -> bool {
        self.allowed & FLAG_BFER != 0
            && self.local.0.phy[0] & PHY0_SU_BEAMFORMER != 0
            && self.peer.phy[0] & PHY0_SU_BEAMFORMEE != 0
    }
    pub(super) fn narrow_to(&mut self, old: &EhtNegotiation) -> Result<(), Error> {
        let rank = |w: Width| match w {
            Width::Twenty => 0,
            Width::Forty => 1,
            Width::Eighty => 2,
            Width::OneSixty => 3,
        };
        if rank(self.width) > rank(old.width) {
            return Err(Error::UnsupportedRates);
        }
        for (new, old) in self.tx.iter_mut().zip(old.tx) {
            *new = (*new).min(old);
        }
        self.allowed =
            u8::from(old.su_beamformee()) * FLAG_BFEE | u8::from(old.su_beamformer()) * FLAG_BFER;
        if self.tx[0] == 0 || !local_covers(&self.local, old.operation.basic) {
            return Err(Error::UnsupportedRates);
        }
        Ok(())
    }
}

/// `ieee80211_verify_sta_eht_mcs_support`: every basic RX/TX NSS fits the
/// local set at <=80MHz and, when the local HE profile has it, 160MHz.
fn local_covers(local: &LocalEht, basic: [u8; 4]) -> bool {
    let widths: &[bool] = if local.0.has_160() {
        &[false, true]
    } else {
        &[false]
    };
    widths.iter().all(|bw160| {
        let have = local.0.ranges(*bw160);
        basic
            .iter()
            .zip(have)
            .all(|(req, have)| req & 0x0f <= have & 0x0f && req >> 4 <= have >> 4)
    })
}

/// The EHT Operation Information encoding of an HT/VHT selection, or
/// `None` for an 80+80 selection (EHT has no 80+80 operation).
fn info_for(width: Width, center: u8, primary80: u8, discontiguous: bool) -> Option<[u8; 3]> {
    Some(match (width, discontiguous) {
        (_, true) => return None,
        (Width::Twenty, _) => [0, center, 0],
        (Width::Forty, _) => [1, center, 0],
        (Width::Eighty, _) => [2, center, 0],
        (Width::OneSixty, _) => [3, primary80, center],
    })
}

/// Negotiate EHT after HE. `Ok(None)` keeps HE where mac80211 falls back:
/// no local EHT, an AP without both EHT elements, no negotiated HE, an
/// unsupported Basic EHT-MCS/NSS set, or no usable single-stream range.
/// EHT Operation Information must describe exactly the HT/VHT-selected
/// channel without punctured subchannels: wider, punctured or 80+80 EHT
/// operation is outside this plan and also falls back to HE.
#[allow(clippy::too_many_arguments)]
pub(super) fn negotiate(
    local: Option<LocalEht>,
    cap: Option<EhtCapability>,
    op: Option<EhtOperation>,
    he: Option<&HeNegotiation>,
    width: Width,
    center: u8,
    primary80: u8,
    discontiguous: bool,
) -> Result<Option<EhtNegotiation>, Error> {
    let (Some(local), Some(peer), Some(operation), Some(he)) = (local, cap, op, he) else {
        return Ok(None);
    };
    if he.discontiguous() {
        return Ok(None);
    }
    if let Some(info) = operation.info {
        if info_for(width, center, primary80, discontiguous) != Some(info)
            || operation.disabled.is_some_and(|b| b != 0)
        {
            return Ok(None);
        }
    }
    if !local_covers(&local, operation.basic) {
        return Ok(None);
    }
    let bw160 = he.width() == Width::OneSixty;
    if bw160 && (!local.0.has_160() || !peer.has_160()) {
        return Ok(None);
    }
    let mine = local.0.ranges(bw160);
    let theirs = peer.ranges(bw160);
    let tx: [u8; 4] = core::array::from_fn(|i| (mine[i] >> 4).min(theirs[i] & 0x0f));
    if tx[0] == 0 {
        return Ok(None);
    }
    Ok(Some(EhtNegotiation {
        local,
        peer,
        operation,
        width: he.width(),
        tx,
        allowed: 0xff,
    }))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "eht_tests.rs"]
mod tests;
