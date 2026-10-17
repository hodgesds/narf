//! Checked legacy 2.4 GHz station preparation and open authentication MLME.
//! Firmware layouts follow Linux ecd997b0189a mt76_connac_mcu.{c,h}.
//! This module prepares frames/commands; it does not authorize RF transmission
//! or mark a WPA2 controlled port secure.
use super::firmware_transport::ScanBss;
use alloc::{vec, vec::Vec};
use narf_wireless::rsn::{self, RsnIe, Suite};

const RATES: [u8; 12] = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    Open,
    Wpa2Psk { psk: [u8; 32] },
}

impl Security {
    #[inline]
    pub fn is_wpa2(&self) -> bool {
        matches!(self, Self::Wpa2Psk { .. })
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
    security: Security,
    rates: u16,
    basic: u16,
    auth: Vec<u8>,
    assoc: Vec<u8>,
    phase: Phase,
}
fn unicast(address: [u8; 6]) -> bool {
    address != [0; 6] && address[0] & 1 == 0
}
fn tlv(bytes: &mut Vec<u8>, id: u16, len: usize) -> usize {
    let offset = bytes.len();
    bytes.resize(offset + len, 0);
    bytes[offset..offset + 2].copy_from_slice(&id.to_le_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&(len as u16).to_le_bytes());
    offset
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
    pub fn security(&self) -> Security {
        self.security
    }
    pub fn prepare(
        bss: &ScanBss,
        own: [u8; 6],
        ssid: &[u8],
        security: Security,
    ) -> Result<Self, Error> {
        if !unicast(own)
            || !unicast(bss.bssid)
            || own == bss.bssid
            || !(1..=11).contains(&bss.channel)
            || ssid.is_empty()
            || ssid.len() > 32
            || (!bss.ssid.is_empty() && bss.ssid != ssid)
            || bss.capability & 3 != 1
        {
            return Err(Error::InvalidBss);
        }
        let mut rates = 0u16;
        let mut basic = 0u16;
        let mut rate_ie = false;
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
                    if body.is_empty() || id == 1 && (rate_ie || body.len() > 8) {
                        return Err(Error::InvalidBss);
                    }
                    rate_ie |= id == 1;
                    for rate in body {
                        if let Some(index) = RATES.iter().position(|local| *local == rate & 127) {
                            rates |= 1 << index;
                            if rate & 128 != 0 {
                                basic |= 1 << index;
                            }
                        } else if rate & 128 != 0 {
                            return Err(Error::UnsupportedRates);
                        }
                    }
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
        if !seen_ssid || !rate_ie || rates & 1 == 0 || basic == 0 {
            return Err(Error::UnsupportedRates);
        }
        let negotiated = match security {
            Security::Open => {
                if bss.capability & 0x10 != 0 || rsn.is_some() || wpa {
                    return Err(Error::UnsupportedSecurity);
                }
                None
            }
            Security::Wpa2Psk { .. } => {
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
        let capability = 1 | (bss.capability & 0x0420) | if security.is_wpa2() { 0x10 } else { 0 };
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
            security,
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
        if bytes.len() < 30 || bytes[24..28] != [0, 0, 2, 0] {
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
    /// Successful association does not authorize a WPA2 controlled port.
    pub fn association_response(&mut self, bytes: &[u8]) -> Result<Option<u16>, Error> {
        if self.phase != Phase::AwaitAssociation {
            return Err(Error::Busy);
        }
        if !self.response(bytes, 0x10) {
            return Ok(None);
        }
        if bytes.len() < 30 {
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
        if raw & 0xc000 != 0xc000
            || !(1..=2007).contains(&aid)
            || ies(&bytes[30..], |_, _| Ok(())).is_err()
        {
            self.phase = Phase::Failed;
            return Err(Error::Protocol);
        }
        self.phase = Phase::Associated { aid };
        Ok(Some(aid))
    }
    pub fn cancel(&mut self) {
        self.phase = Phase::Failed;
    }

    /// Initial unencrypted AP record: CONN_STATE_CONNECT, never PORT_SECURE.
    /// Native RX remains enabled so later EAPOL processing sees full MPDUs.
    pub fn peer_record(&self, aid: u16, associated: bool) -> Result<Vec<u8>, Error> {
        if aid > 2007 || associated && aid == 0 {
            return Err(Error::Protocol);
        }
        if self.phase == Phase::Failed || associated && self.phase != (Phase::Associated { aid }) {
            return Err(Error::Busy);
        }
        if !associated && aid != 0 {
            return Err(Error::Protocol);
        }
        let mut out = vec![0u8; 8];
        out[1] = 1;
        out[2] = 5;
        out[4] = 1; // WCID 1, five TLVs, append
        let basic = tlv(&mut out, 0, 20);
        out[basic + 4..basic + 8].copy_from_slice(&0x10002u32.to_le_bytes());
        out[basic + 8] = 1;
        out[basic + 10..basic + 12].copy_from_slice(&aid.to_le_bytes());
        out[basic + 12..basic + 18].copy_from_slice(&self.peer);
        out[basic + 18..basic + 20]
            .copy_from_slice(&(if associated { 1u16 } else { 3 }).to_le_bytes());
        let phy = tlv(&mut out, 0x15, 12);
        out[phy + 4..phy + 6].copy_from_slice(&self.basic.to_le_bytes());
        out[phy + 6] = 3; // HR-DSSS | ERP, no HT/VHT/HE
        let ra = tlv(&mut out, 1, 16);
        out[ra + 4..ra + 6]
            .copy_from_slice(&((self.rates & 15) | ((self.rates >> 4) << 6)).to_le_bytes());
        let state = tlv(&mut out, 7, 12);
        out[state + 8] = if associated { 2 } else { 1 };
        let wtbl = tlv(&mut out, 13, 12); // outer TLV + eight-byte WTBL request
        out[wtbl + 4] = 1;
        out[wtbl + 5] = 1;
        out[wtbl + 6] = 3;
        let generic = tlv(&mut out, 0, 20);
        out[generic + 4..generic + 10].copy_from_slice(&self.peer);
        out[generic + 16..generic + 18].copy_from_slice(&aid.to_le_bytes());
        let rx = tlv(&mut out, 1, 12);
        out[rx + 5..rx + 8].fill(1); // RCA1, RCA2, RV
        let trans = tlv(&mut out, 6, 8);
        out[trans + 4] = 1;
        out[trans + 6] = 1; // to-DS, no RX translation
        let length = (out.len() - wtbl) as u16;
        out[wtbl + 2..wtbl + 4].copy_from_slice(&length.to_le_bytes());
        Ok(out)
    }

    pub fn rsn_body(&self) -> Option<Vec<u8>> {
        if self.security.is_wpa2() {
            Some(RsnIe::wpa2_psk_ccmp().encode_body())
        } else {
            None
        }
    }

    /// Emits a completed station record for WCID 1 containing CCMP-128
    /// key installation and CONN_STATE_PORT_SECURE.
    pub fn secure_peer_record(&self, aid: u16, key: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = self.peer_record(aid, true)?;
        out[2] += 1; // 6 TLVs
        let sec = tlv(&mut out, 0x12, 44);
        out[sec + 4] = 1; // cmd = SET_KEY
        out[sec + 5] = 1; // n_cipher = 1
        out[sec + 8] = 6; // cipher_id = MCU_CIPHER_AES_CCMP (6)
        out[sec + 9] = 36; // cipher_len
        out[sec + 10] = 0; // key_id = 0
        out[sec + 11] = 16; // key_len = 16
        let k = key.len().min(16);
        out[sec + 12..sec + 12 + k].copy_from_slice(&key[..k]);
        Ok(out)
    }
}

/// Disconnect station record: CONN_STATE_DISCONNECT for WCID 1.
pub fn disconnect_record(peer: [u8; 6]) -> Vec<u8> {
    let mut out = vec![0u8; 8];
    out[1] = 1;
    out[2] = 2; // Two TLVs: basic + state
    out[4] = 1; // WCID 1
    let basic = tlv(&mut out, 0, 20);
    out[basic + 4..basic + 8].copy_from_slice(&0x10002u32.to_le_bytes());
    out[basic + 8] = 1;
    out[basic + 12..basic + 18].copy_from_slice(&peer);
    out[basic + 18..basic + 20].copy_from_slice(&3u16.to_le_bytes());
    let state = tlv(&mut out, 7, 12);
    out[state + 8] = 0; // CONN_STATE_DISCONNECT
    out
}

#[cfg(any(test, feature = "builtin"))]
#[path = "association_tests.rs"]
mod tests;
