// SPDX-License-Identifier: GPL-2.0-or-later
//! Checked legacy station management plan, shared by SoftMAC drivers.
//! Extracted from MT76 association; no firmware command/rate index, PMK,
//! regulatory authority, key installation or controlled-port state is stored.
use crate::rsn::{self, RsnIe, Suite};
use alloc::{vec, vec::Vec};
#[path = "association/channel.rs"]
pub mod channel;
#[path = "association/eht.rs"]
pub mod eht;
#[path = "association/he.rs"]
pub mod he;
#[path = "association/phy.rs"]
pub mod phy;
#[path = "association/sae_join.rs"]
mod sae_join;
pub use sae_join::{SaeJoin, SaePwe, SaeStep};

/// One validated beacon/probe response, retaining original IEs for the SME.
#[derive(Clone, Debug)]
pub struct Bss {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub channel: u8,
    pub signal_dbm: Option<i8>,
    pub capability: u16,
    pub beacon_interval: u16,
    pub information_elements: Vec<u8>,
}
/// Decoded raw beacon/probe facts. These carry no channel, transmit, key or
/// association authority; the driver supplies its immutable receive channel.
#[derive(Clone, Debug)]
pub struct ObservedBss {
    pub bss: Bss,
    pub ap_rsne: Option<Vec<u8>>,
    pub ap_rsnxe: Option<Vec<u8>>,
    pub rates: u16,
    pub basic_rates: u16,
}
const RATES: [u8; 12] = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];

/// Negotiated mode without retaining a PMK in a management-frame plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityMode {
    Open,
    Wpa2Psk,
    /// WPA3-Personal: SAE authentication (AKM 8, or AKM 24 under H2E),
    /// CCMP-128 and PMF required. `pwe` is wpa_supplicant's `sae_pwe`
    /// policy; the plan resolves the actual PWE method and AKM from the
    /// AP's RSNE/RSNXE and SAE-H2E membership selector.
    Wpa3Sae {
        pwe: SaePwe,
    },
}

impl SecurityMode {
    /// WPA2-Personal (PSK) only.
    pub fn is_wpa2(self) -> bool {
        matches!(self, Self::Wpa2Psk)
    }
    /// SAE (WPA3-Personal).
    pub fn is_sae(self) -> bool {
        matches!(self, Self::Wpa3Sae { .. })
    }
    /// Any RSN-protected mode (Privacy bit, RSNE in the request).
    pub fn is_rsn(self) -> bool {
        !matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidBss,
    UnsupportedRates,
    UnsupportedSecurity,
    Protocol,
    Rejected(u16),
    Busy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    AwaitAuthentication,
    AwaitAssociation,
    Associated { aid: u16 },
    Failed,
}

/// No PMK or temporal keys are stored in a frame/command plan.
#[derive(Debug)]
pub struct JoinPlan {
    own: [u8; 6],
    peer: [u8; 6],
    channel: u8,
    security: SecurityMode,
    rates: u16,
    basic: u16,
    auth: Vec<u8>,
    assoc: Vec<u8>,
    phase: Phase,
    phy_enabled: bool,
    offered_phy: Option<phy::Offer>,
    negotiated_phy: Option<phy::Negotiated>,
    spp_amsdu: bool,
    /// SAE authentication state and the negotiated AKM/PWE.
    sae: Option<SaeJoin>,
}

/// BSS membership selectors (IEEE802.11-2020 Table 9-80 as amended;
/// Linux include/linux/ieee80211.h `BSS_MEMBERSHIP_SELECTOR_*`), recorded
/// as bits of `RateElements::selectors`.
pub(crate) const SEL_HT: u8 = 1; // 127
pub(crate) const SEL_VHT: u8 = 2; // 126
pub(crate) const SEL_SAE_H2E: u8 = 4; // 123
pub(crate) const SEL_HE: u8 = 8; // 122
pub(crate) const SEL_EHT: u8 = 16; // 121
pub(crate) const SEL_UHR: u8 = 32; // 120
pub(crate) const SEL_GLK: u8 = 64; // 125
pub(crate) const SEL_EPD: u8 = 128; // 124
/// PHY selectors recognized by the opt-in PHY path; each is admitted only
/// when the corresponding PHY is actually negotiated.
pub(crate) const SEL_PHY: u8 = SEL_HT | SEL_VHT | SEL_HE | SEL_EHT | SEL_UHR;
fn selector_bit(value: u8) -> u8 {
    match value {
        127 => SEL_HT,
        126 => SEL_VHT,
        125 => SEL_GLK,
        124 => SEL_EPD,
        123 => SEL_SAE_H2E,
        122 => SEL_HE,
        121 => SEL_EHT,
        120 => SEL_UHR,
        _ => 0,
    }
}

#[derive(Default)]
struct RateElements {
    supported: bool,
    extended: bool,
    rates: u16,
    basic: u16,
    /// Membership selectors this context can evaluate; others fail closed
    /// while the element is parsed.
    allowed: u8,
    selectors: u8,
}
impl RateElements {
    fn observe(&mut self, id: u8, body: &[u8]) -> Result<(), Error> {
        let seen = match id {
            1 if body.len() <= 8 => &mut self.supported,
            50 => &mut self.extended,
            1 => return Err(Error::InvalidBss),
            _ => return Ok(()),
        };
        if body.is_empty() || *seen {
            return Err(Error::InvalidBss);
        }
        *seen = true;
        for rate in body {
            if let Some(index) = RATES.iter().position(|local| *local == rate & 127) {
                self.rates |= 1 << index;
                if rate & 128 != 0 {
                    self.basic |= 1 << index;
                }
            } else if rate & 128 != 0 && self.allowed & selector_bit(rate & 127) != 0 {
                self.selectors |= selector_bit(rate & 127);
            } else if rate & 128 != 0 {
                // Unknown basic rates and selectors this context cannot
                // negotiate fail closed. Unknown optional rates do not
                // become offers.
                return Err(Error::UnsupportedRates);
            }
        }
        Ok(())
    }
}

fn unicast(address: [u8; 6]) -> bool {
    address != [0; 6] && address[0] & 1 == 0
}
fn ies(
    mut bytes: &[u8],
    mut visit: impl FnMut(u8, &[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    while !bytes.is_empty() {
        let head = bytes.get(..2).ok_or(Error::InvalidBss)?;
        let len = usize::from(head[1]);
        let body = bytes.get(2..2 + len).ok_or(Error::InvalidBss)?;
        visit(head[0], body)?;
        bytes = &bytes[2 + len..];
    }
    Ok(())
}
/// Observe one unmodified legacy management MPDU, without FCS. The channel
/// comes from the retained radio, never a caller RX label or an untrusted IE.
/// Signal is already converted to dBm by that driver's native status decoder.
pub fn observe(
    frame: &impl crate::station_security::RawFrame,
    channel: u8,
    own: [u8; 6],
    signal_dbm: Option<i8>,
) -> Result<ObservedBss, Error> {
    observe_inner(frame, channel, own, signal_dbm, None)
}
/// Opt into factual HT/VHT admission from the actual retained raw BSS.
/// The local profile does not confer channel, transmit or association rights.
pub fn observe_with_phy(
    frame: &impl crate::station_security::RawFrame,
    channel: u8,
    own: [u8; 6],
    signal_dbm: Option<i8>,
    local: &phy::LocalPhy,
) -> Result<ObservedBss, Error> {
    observe_inner(frame, channel, own, signal_dbm, Some(local))
}
fn observe_inner(
    frame: &impl crate::station_security::RawFrame,
    channel: u8,
    own: [u8; 6],
    signal_dbm: Option<i8>,
    local: Option<&phy::LocalPhy>,
) -> Result<ObservedBss, Error> {
    let bytes = frame.bytes();
    if !frame.unmodified()
        || channel::band(channel).is_none()
        || !unicast(own)
        || !(36..=2084).contains(&bytes.len())
        || !matches!(bytes[0], 0x50 | 0x80)
        || bytes[1] & 0xc7 != 0
        || bytes[22] & 15 != 0
        || bytes[10..16] == own
        || !unicast(bytes[10..16].try_into().map_err(|_| Error::InvalidBss)?)
        || bytes[10..16] != bytes[16..22]
        || bytes[0] == 0x80 && bytes[4..10] != [255; 6]
        || bytes[0] == 0x50 && bytes[4..10] != own
    {
        return Err(Error::InvalidBss);
    }
    let capability = u16::from_le_bytes([bytes[34], bytes[35]]);
    let beacon_interval = u16::from_le_bytes([bytes[32], bytes[33]]);
    if capability & 3 != 1 || beacon_interval == 0 {
        return Err(Error::InvalidBss);
    }
    let (mut ssid, mut ap_rsne, mut ap_rsnxe) = (None, None, None);
    let mut ds_seen = false;
    // A scan observation also records an SAE-H2E-only BSS; JoinPlan admits
    // it only for an SAE H2E security mode.
    let mut rates = RateElements {
        allowed: if local.is_some() { SEL_PHY } else { 0 } | SEL_SAE_H2E,
        ..Default::default()
    };
    ies(&bytes[36..], |id, body| {
        match id {
            0 => {
                if ssid.is_some() || body.len() > 32 {
                    return Err(Error::InvalidBss);
                }
                ssid = Some(body.to_vec());
            }
            1 | 50 => rates.observe(id, body)?,
            3 => {
                if ds_seen || body != [channel] {
                    return Err(Error::InvalidBss);
                }
                ds_seen = true;
            }
            48 => {
                if ap_rsne.is_some() {
                    return Err(Error::InvalidBss);
                }
                ap_rsne = Some(body.to_vec());
            }
            244 => {
                if ap_rsnxe.is_some() || body.is_empty() {
                    return Err(Error::InvalidBss);
                }
                ap_rsnxe = Some(body.to_vec());
            }
            _ => {}
        }
        Ok(())
    })?;
    if !rates.supported || rates.rates == 0 || rates.basic == 0 {
        return Err(Error::UnsupportedRates);
    }
    if let Some(local) = local {
        phy::Offer::prepare(*local, &bytes[36..], channel, rates.selectors)?;
    }
    Ok(ObservedBss {
        bss: Bss {
            bssid: bytes[10..16].try_into().map_err(|_| Error::InvalidBss)?,
            ssid: ssid.ok_or(Error::InvalidBss)?,
            channel,
            signal_dbm,
            capability,
            beacon_interval,
            information_elements: bytes[36..].to_vec(),
        },
        ap_rsne,
        ap_rsnxe,
        rates: rates.rates,
        basic_rates: rates.basic,
    })
}
pub fn validate_sme_ies(bytes: &[u8], protected: bool) -> Result<(), Error> {
    if bytes.len() > 2048 {
        return Err(Error::InvalidBss);
    }
    let mut rsn_seen = false;
    ies(bytes, |id, body| match id {
        0 | 1 | 50 => Err(Error::InvalidBss),
        48 => {
            if rsn_seen {
                return Err(Error::InvalidBss);
            }
            rsn_seen = true;
            let rsn = RsnIe::decode_body(body).ok_or(Error::InvalidBss)?;
            if !protected || rsn != RsnIe::wpa2_psk_ccmp() {
                return Err(Error::UnsupportedSecurity);
            }
            Ok(())
        }
        54..=56 | 244 => Err(Error::UnsupportedSecurity),
        45 | 191 => Err(Error::UnsupportedRates),
        255 if body.is_empty() => Err(Error::InvalidBss),
        255 if body
            .first()
            .is_some_and(|id| matches!(*id, 35 | 36 | 108 | 109)) =>
        {
            Err(Error::UnsupportedRates)
        }
        221 if body.starts_with(&[0, 0x50, 0xf2, 1]) => Err(Error::UnsupportedSecurity),
        221 if body.starts_with(&[0, 0x50, 0xf2, 2]) => Err(Error::UnsupportedRates),
        221 if body.len() < 3 => Err(Error::InvalidBss),
        _ => Ok(()),
    })
}
fn management(subtype: u8, own: [u8; 6], peer: [u8; 6]) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[0] = subtype;
    frame[4..10].copy_from_slice(&peer);
    frame[10..16].copy_from_slice(&own);
    frame[16..22].copy_from_slice(&peer);
    frame
}
impl JoinPlan {
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn channel(&self) -> u8 {
        self.channel
    }
    pub fn security(&self) -> SecurityMode {
        self.security
    }

    /// Append validated optional SME elements before the first transmission.
    /// Its RSNE is checked above and replaced by the driver's negotiated one.
    /// Advertise SPP A-MSDU Capable (RSN Capabilities bit10, IEEE802.11-2020
    /// 9.4.2.24.4) in the WPA2 association-request RSNE before first
    /// transmission. Only a native owner whose CCMP path keeps A-MSDU Present
    /// in the AAD (`station_security::Security` with this `rsn_body()`) may
    /// opt in; SPP is in force only if the AP RSNE also sets the bit.
    pub fn enable_spp_amsdu(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::Busy);
        }
        if !self.security.is_wpa2() {
            return Err(Error::UnsupportedSecurity);
        }
        // Fixed fields: 24-byte header, Capability and Listen Interval.
        let mut at = 28;
        while at + 2 <= self.assoc.len() {
            let len = usize::from(self.assoc[at + 1]);
            if self.assoc[at] == 48 {
                let body = self
                    .assoc
                    .get_mut(at + 2..at + 2 + len)
                    .ok_or(Error::Protocol)?;
                let caps = body.len().checked_sub(2).ok_or(Error::Protocol)?;
                let value = u16::from_le_bytes([body[caps], body[caps + 1]])
                    | rsn::RSN_CAP_SPP_AMSDU_CAPABLE;
                body[caps..].copy_from_slice(&value.to_le_bytes());
                self.spp_amsdu = true;
                return Ok(());
            }
            at += 2 + len;
        }
        Err(Error::Protocol)
    }
    pub fn append_sme_ies(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::Busy);
        }
        if self.assoc.len().saturating_add(bytes.len()) > 4096 {
            return Err(Error::InvalidBss);
        }
        validate_sme_ies(bytes, self.security.is_wpa2())?;
        if self.phy_enabled {
            ies(bytes, |id, _| {
                if matches!(id, 61 | 192) {
                    Err(Error::UnsupportedRates)
                } else {
                    Ok(())
                }
            })?;
        }
        ies(bytes, |id, body| {
            if id != 48 {
                self.assoc.extend_from_slice(&[id, body.len() as u8]);
                self.assoc.extend_from_slice(body);
            }
            Ok(())
        })
    }
    pub fn prepare(
        bss: &Bss,
        own: [u8; 6],
        ssid: &[u8],
        security: SecurityMode,
    ) -> Result<Self, Error> {
        Self::prepare_inner(bss, own, ssid, security, None)
    }
    /// Prepare using an implementation profile derived by the native owner.
    /// AP facts are reparsed and bound here, never accepted as an external grant.
    pub fn prepare_with_phy(
        bss: &Bss,
        own: [u8; 6],
        ssid: &[u8],
        security: SecurityMode,
        local: phy::LocalPhy,
    ) -> Result<Self, Error> {
        Self::prepare_inner(bss, own, ssid, security, Some(local))
    }
    pub fn offered_phy(&self) -> Option<&phy::Offer> {
        self.offered_phy.as_ref()
    }
    pub fn negotiated_phy(&self) -> Option<&phy::Negotiated> {
        self.negotiated_phy.as_ref()
    }
    fn prepare_inner(
        bss: &Bss,
        own: [u8; 6],
        ssid: &[u8],
        security: SecurityMode,
        local: Option<phy::LocalPhy>,
    ) -> Result<Self, Error> {
        if !unicast(own)
            || !unicast(bss.bssid)
            || own == bss.bssid
            || channel::band(bss.channel).is_none()
            || bss.information_elements.len() > 2048
            || ssid.is_empty()
            || ssid.len() > 32
            || (!bss.ssid.is_empty() && bss.ssid != ssid)
            || bss.capability & 3 != 1
        {
            return Err(Error::InvalidBss);
        }
        let mut rate_elements = RateElements {
            allowed: if local.is_some() { SEL_PHY } else { 0 }
                | if security.is_sae() { SEL_SAE_H2E } else { 0 },
            ..Default::default()
        };
        let mut rsn = None;
        let mut rsnxe: Option<Vec<u8>> = None;
        let mut wpa = false;
        let mut seen_ssid = false;
        ies(&bss.information_elements, |id, body| {
            match id {
                0 => {
                    if seen_ssid || body != bss.ssid {
                        return Err(Error::InvalidBss);
                    }
                    seen_ssid = true;
                }
                1 | 50 => {
                    rate_elements.observe(id, body)?;
                }
                48 => {
                    if rsn.is_some() {
                        return Err(Error::InvalidBss);
                    }
                    rsn = Some(RsnIe::decode_body(body).ok_or(Error::InvalidBss)?);
                }
                244 => {
                    if rsnxe.is_some() || body.is_empty() {
                        return Err(Error::InvalidBss);
                    }
                    rsnxe = Some(body.to_vec());
                }
                221 => wpa |= body.starts_with(&[0, 0x50, 0xf2, 1]),
                _ => {}
            }
            Ok(())
        })?;
        let mut rates = rate_elements.rates;
        let basic = rate_elements.basic;
        if channel::band(bss.channel) == Some(channel::Band::Ghz5) {
            if basic & 15 != 0 {
                return Err(Error::UnsupportedRates);
            }
            rates &= !15;
        }
        if !seen_ssid || !rate_elements.supported || rates == 0 || basic == 0 {
            return Err(Error::UnsupportedRates);
        }
        let offered_phy = match local {
            Some(local) => phy::Offer::prepare(
                local,
                &bss.information_elements,
                bss.channel,
                rate_elements.selectors,
            )?,
            None => None,
        };
        let mut sae = None;
        let negotiated = match security {
            SecurityMode::Open => {
                if bss.capability & 0x10 != 0 || rsn.is_some() || wpa {
                    return Err(Error::UnsupportedSecurity);
                }
                None
            }
            SecurityMode::Wpa2Psk => {
                let rsn = rsn.ok_or(Error::UnsupportedSecurity)?;
                if bss.capability & 0x10 == 0
                    || rsn.group_cipher != Suite::standard(rsn::CIPHER_CCMP_128)
                    || !rsn
                        .pairwise_ciphers
                        .contains(&Suite::standard(rsn::CIPHER_CCMP_128))
                    || !rsn.akms.contains(&Suite::standard(rsn::AKM_PSK))
                    || rsn.rsn_capabilities & (rsn::RSN_CAP_MFP_REQUIRED | rsn::RSN_CAP_NO_PAIRWISE)
                        != 0
                {
                    return Err(Error::UnsupportedSecurity);
                }
                Some(RsnIe::wpa2_psk_ccmp().encode_body())
            }
            SecurityMode::Wpa3Sae { pwe } => {
                let rsn = rsn.as_ref().ok_or(Error::UnsupportedSecurity)?;
                let join = SaeJoin::negotiate(
                    pwe,
                    bss.capability,
                    rsn,
                    rsnxe.as_deref(),
                    rate_elements.selectors & SEL_SAE_H2E != 0,
                )?;
                let body = join.station_rsne(None);
                sae = Some(join);
                Some(body)
            }
        };
        let mut auth = management(0xb0, own, bss.bssid);
        auth.extend_from_slice(&[0, 0, 1, 0, 0, 0]);
        let mut assoc = management(0, own, bss.bssid);
        // ESS, negotiated privacy, and only AP-supported short preamble/slot.
        let optional = if channel::band(bss.channel) == Some(channel::Band::Ghz5) {
            0x0400
        } else {
            0x0420
        };
        let capability = 1 | (bss.capability & optional) | if security.is_rsn() { 0x10 } else { 0 };
        assoc.extend_from_slice(&capability.to_le_bytes());
        assoc.extend_from_slice(&5u16.to_le_bytes());
        assoc.extend_from_slice(&[0, ssid.len() as u8]);
        assoc.extend_from_slice(ssid);
        let selected: Vec<_> = RATES
            .iter()
            .enumerate()
            .filter_map(|(i, rate)| {
                (rates & (1 << i) != 0)
                    .then_some(*rate | if basic & (1 << i) != 0 { 128 } else { 0 })
            })
            .collect();
        let split = selected.len().min(8);
        assoc.extend_from_slice(&[1, split as u8]);
        assoc.extend_from_slice(&selected[..split]);
        if split < selected.len() {
            assoc.extend_from_slice(&[50, (selected.len() - split) as u8]);
            assoc.extend_from_slice(&selected[split..]);
        }
        if let Some(rsn) = negotiated {
            assoc.extend_from_slice(&[48, rsn.len() as u8]);
            assoc.extend_from_slice(&rsn);
        }
        if let Some(rsnxe) = sae.as_ref().and_then(SaeJoin::station_rsnxe) {
            assoc.extend_from_slice(&[244, rsnxe.len() as u8]);
            assoc.extend_from_slice(&rsnxe);
        }
        if let Some(offer) = offered_phy.as_ref() {
            offer.append_capabilities(&mut assoc);
        }
        Ok(Self {
            own,
            peer: bss.bssid,
            channel: bss.channel,
            security,
            rates,
            basic,
            auth,
            assoc,
            phase: Phase::Prepared,
            phy_enabled: local.is_some(),
            offered_phy,
            negotiated_phy: None,
            spp_amsdu: false,
            sae,
        })
    }
    pub fn start_authentication(&mut self) -> Result<&[u8], Error> {
        if self.sae.is_some() {
            // SAE uses `start_sae_authentication`; open auth is refused.
            return Err(Error::UnsupportedSecurity);
        }
        if self.phase != Phase::Prepared {
            return Err(Error::Busy);
        }
        self.phase = Phase::AwaitAuthentication;
        Ok(&self.auth)
    }
    fn response(&self, bytes: &[u8], subtype: u8) -> bool {
        bytes.len() >= 24
            && bytes[0] == subtype
            && bytes[1] & 0xc7 == 0
            && bytes[22] & 15 == 0
            && bytes[4..10] == self.own
            && bytes[10..16] == self.peer
            && bytes[16..22] == self.peer
    }
    /// Ignore other peers/subtypes; a matching rejection is terminal.
    pub fn authentication_response(&mut self, bytes: &[u8]) -> Result<Option<&[u8]>, Error> {
        if self.phase != Phase::AwaitAuthentication || self.sae.is_some() {
            return Err(Error::Busy);
        }
        if !self.response(bytes, 0xb0) {
            return Ok(None);
        }
        if !(30..=4096).contains(&bytes.len()) || bytes[24..28] != [0, 0, 2, 0] {
            self.phase = Phase::Failed;
            return Err(Error::Protocol);
        }
        let status = u16::from_le_bytes([bytes[28], bytes[29]]);
        if status != 0 {
            self.phase = Phase::Failed;
            return Err(Error::Rejected(status));
        }
        self.phase = Phase::AwaitAssociation;
        Ok(Some(&self.assoc))
    }
    /// Negotiate legacy rates from a successful bound response. The response
    /// can narrow the request's offer but must preserve every beacon basic
    /// rate. New mandatory rates must have been offered. This conservative
    /// legacy profile retains beacon basics even if the response omits flags.
    /// Successful association does not authorize a WPA2 controlled port.
    pub fn association_response(&mut self, bytes: &[u8]) -> Result<Option<u16>, Error> {
        if self.phase != Phase::AwaitAssociation {
            return Err(Error::Busy);
        }
        if !self.response(bytes, 0x10) {
            return Ok(None);
        }
        if !(30..=2078).contains(&bytes.len()) {
            self.phase = Phase::Failed;
            return Err(Error::Protocol);
        }
        let status = u16::from_le_bytes([bytes[26], bytes[27]]);
        if status != 0 {
            self.phase = Phase::Failed;
            return Err(Error::Rejected(status));
        }
        let capability = u16::from_le_bytes([bytes[24], bytes[25]]);
        if capability & 3 != 1 || (capability & 0x10 != 0) != self.security.is_rsn() {
            self.phase = Phase::Failed;
            return Err(Error::Protocol);
        }
        let raw = u16::from_le_bytes([bytes[28], bytes[29]]);
        let aid = raw & 0x3fff;
        if raw & 0xc000 != 0xc000 || !(1..=2007).contains(&aid) {
            self.phase = Phase::Failed;
            return Err(Error::Protocol);
        }
        let mut response = RateElements {
            allowed: if self.offered_phy.is_some() {
                SEL_PHY
            } else {
                0
            },
            ..Default::default()
        };
        if let Err(error) = ies(&bytes[30..], |id, body| response.observe(id, body)) {
            self.phase = Phase::Failed;
            return Err(if error == Error::InvalidBss {
                Error::Protocol
            } else {
                error
            });
        }
        let rates = self.rates & response.rates;
        let basic = self.basic | response.basic;
        if !response.supported || rates == 0 || basic & !rates != 0 {
            self.phase = Phase::Failed;
            return Err(Error::UnsupportedRates);
        }
        let negotiated_phy = if self.phy_enabled {
            // Validate every relevant element before committing any AID/rate/PHY.
            let result = (|| {
                phy::ApElements::parse(&bytes[30..])?;
                let mut rsn_seen = false;
                ies(&bytes[30..], |id, body| {
                    if id == 48 {
                        if rsn_seen || !self.response_rsne_matches(body) {
                            return Err(Error::UnsupportedSecurity);
                        }
                        rsn_seen = true;
                    }
                    Ok(())
                })?;
                self.offered_phy
                    .as_ref()
                    .map(|offer| offer.response(&bytes[30..], response.selectors))
                    .transpose()
            })();
            match result {
                Ok(value) => value,
                Err(error) => {
                    self.phase = Phase::Failed;
                    return Err(error);
                }
            }
        } else {
            None
        };
        // Commit only after all frame, IE and rate checks have passed.
        self.rates = rates;
        self.basic = basic;
        self.negotiated_phy = negotiated_phy;
        self.phase = Phase::Associated { aid };
        Ok(Some(aid))
    }
    pub fn cancel(&mut self) {
        self.phase = Phase::Failed;
        self.negotiated_phy = None;
        if let Some(sae) = self.sae.as_mut() {
            sae.cancel();
        }
    }

    /// Before association: the validated request offer. After association:
    /// the negotiated supported/basic bitmaps. Failed replies leave these
    /// unchanged. Bit order is IEEE legacy order (not increasing bit rate):
    /// 1,2,5.5,11,6,9,12,18,24,36,48,54Mbps. Hardware indices stay driver-owned.
    pub fn legacy_rates(&self) -> (u16, u16) {
        (self.rates, self.basic)
    }
    pub fn rsn_body(&self) -> Option<Vec<u8>> {
        if let Some(sae) = self.sae.as_ref() {
            return Some(sae.station_rsne(sae.pmkid()));
        }
        if self.security.is_wpa2() {
            let mut rsne = RsnIe::wpa2_psk_ccmp();
            if self.spp_amsdu {
                rsne.rsn_capabilities |= rsn::RSN_CAP_SPP_AMSDU_CAPABLE;
            }
            Some(rsne.encode_body())
        } else {
            None
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "association_tests.rs"]
mod tests;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "association/observe_tests.rs"]
mod observe_tests;
