// SPDX-License-Identifier: GPL-2.0-or-later
//! Checked legacy station management plan, shared by SoftMAC drivers.
//! Extracted from MT76 association; no firmware command/rate index, PMK,
//! regulatory authority, key installation or controlled-port state is stored.
use crate::rsn::{self, RsnIe, Suite};
use alloc::{vec, vec::Vec};
#[path = "association/channel.rs"]
pub mod channel;

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
const RATES: [u8; 12] = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];

/// Negotiated mode without retaining a PMK in a management-frame plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityMode {
    Open,
    Wpa2Psk,
}

impl SecurityMode {
    pub fn is_wpa2(self) -> bool {
        matches!(self, Self::Wpa2Psk)
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
}

#[derive(Default)]
struct RateElements {
    supported: bool,
    extended: bool,
    rates: u16,
    basic: u16,
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
            } else if rate & 128 != 0 {
                // This legacy profile has no HT/VHT/HE membership-selector
                // negotiation. Unknown optional rates do not become offers.
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
    pub fn append_sme_ies(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::Busy);
        }
        if self.assoc.len().saturating_add(bytes.len()) > 4096 {
            return Err(Error::InvalidBss);
        }
        validate_sme_ies(bytes, self.security.is_wpa2())?;
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
        let mut rate_elements = RateElements::default();
        let mut rsn = None;
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
        let capability =
            1 | (bss.capability & optional) | if security.is_wpa2() { 0x10 } else { 0 };
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
        Ok(Self {
            own,
            peer: bss.bssid,
            channel: bss.channel,
            security: if security.is_wpa2() {
                SecurityMode::Wpa2Psk
            } else {
                SecurityMode::Open
            },
            rates,
            basic,
            auth,
            assoc,
            phase: Phase::Prepared,
        })
    }
    pub fn start_authentication(&mut self) -> Result<&[u8], Error> {
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
        if self.phase != Phase::AwaitAuthentication {
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
        if capability & 3 != 1 || (capability & 0x10 != 0) != self.security.is_wpa2() {
            self.phase = Phase::Failed;
            return Err(Error::Protocol);
        }
        let raw = u16::from_le_bytes([bytes[28], bytes[29]]);
        let aid = raw & 0x3fff;
        if raw & 0xc000 != 0xc000 || !(1..=2007).contains(&aid) {
            self.phase = Phase::Failed;
            return Err(Error::Protocol);
        }
        let mut response = RateElements::default();
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
        // Commit only after all frame, IE and rate checks have passed.
        self.rates = rates;
        self.basic = basic;
        self.phase = Phase::Associated { aid };
        Ok(Some(aid))
    }
    pub fn cancel(&mut self) {
        self.phase = Phase::Failed;
    }

    /// Before association: the validated request offer. After association:
    /// the negotiated supported/basic bitmaps. Failed replies leave these
    /// unchanged. Bit order is IEEE legacy order (not increasing bit rate):
    /// 1,2,5.5,11,6,9,12,18,24,36,48,54Mbps. Hardware indices stay driver-owned.
    pub fn legacy_rates(&self) -> (u16, u16) {
        (self.rates, self.basic)
    }
    pub fn rsn_body(&self) -> Option<Vec<u8>> {
        if self.security.is_wpa2() {
            Some(RsnIe::wpa2_psk_ccmp().encode_body())
        } else {
            None
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "association_tests.rs"]
mod tests;
