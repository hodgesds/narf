// SPDX-License-Identifier: GPL-2.0-or-later
//! Response-bound HT20, following Linux ath10k mac.c peer-association and
//! SERVICE_READY capability handling. No BA agreement follows an HT offer.
use super::Error;
use crate::ath10k::wmi_boot::Capabilities;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    pub(super) capabilities: u16,
    pub(super) ampdu: u8,
    pub(super) mcs: u8,
    pub(super) short_gi: bool,
    receive_short_gi: bool,
}

fn elements(mut ies: &[u8], primary: u8) -> Result<Option<Profile>, Error> {
    let (mut capability, mut operation) = (None, None);
    while !ies.is_empty() {
        let h = ies.get(..2).ok_or(Error::Malformed)?;
        let body = ies.get(2..2 + usize::from(h[1])).ok_or(Error::Malformed)?;
        match h[0] {
            45 => {
                if capability.replace(body).is_some() || body.len() != 26 {
                    return Err(Error::Malformed);
                }
            }
            61 => {
                if operation.replace(body).is_some() || body.len() != 22 {
                    return Err(Error::Malformed);
                }
            }
            _ => {}
        }
        ies = &ies[2 + body.len()..];
    }
    let (capability, operation) = match (capability, operation) {
        (None, None) => return Ok(None),
        (Some(c), Some(o)) => (c, o),
        _ => return Err(Error::Malformed),
    };
    if operation[0] != primary || operation[1] & 3 == 2 || capability[2] & 0xe0 != 0 {
        return Err(Error::Malformed);
    }
    // This first native profile owns MCS0..7 and20MHz. Wider/basic MCS
    // requirements cannot be silently downgraded to an unsupported station.
    if capability[3] == 0
        || operation[6] & !capability[3] != 0
        || operation[7..].iter().any(|byte| *byte != 0)
    {
        return Err(Error::Unsupported);
    }
    let capabilities = u16::from_le_bytes([capability[0], capability[1]]);
    Ok(Some(Profile {
        capabilities,
        ampdu: capability[2],
        mcs: capability[3],
        short_gi: capabilities & (1 << 5) != 0,
        receive_short_gi: false,
    }))
}

pub(super) fn supported(caps: &Capabilities) -> bool {
    caps.ht & 1 != 0 && (1..=4).contains(&caps.rf_chains)
}
pub(super) fn capability(caps: &Capabilities) -> Option<[u8; 26]> {
    supported(caps).then(|| information(caps.ht & 2 != 0)[2..].try_into().unwrap())
}
fn information(short_gi: bool) -> [u8; 28] {
    let mut ie = [0; 28];
    ie[..2].copy_from_slice(&[45, 26]);
    // One spatial stream,20MHz, SMPS disabled, no GF/STBC/LDPC or
    // maximum-A-MSDU claim. No BA agreement is negotiated here.
    ie[2] = 0x0c | if short_gi { 0x20 } else { 0 };
    ie[4] = 6 << 2; //8KiB A-MPDU ceiling,8us minimum MPDU spacing.
    ie[5] = 0xff;
    ie[17] = 1; // TX MCS defined and equal to RX.
    ie
}

impl Profile {
    pub(super) fn offer(
        caps: &Capabilities,
        ies: &[u8],
        primary: u8,
    ) -> Result<Option<Self>, Error> {
        let parsed = elements(ies, primary)?;
        let wmm = narf_wireless::wmm::Parameters::parse(ies).map_err(|_| Error::Malformed)?;
        if !supported(caps) || wmm.is_none_or(|p| p.ac[0].admission_control) {
            return Ok(None);
        }
        Ok(parsed.map(|mut p| {
            p.short_gi &= caps.ht & 2 != 0;
            p.receive_short_gi = p.short_gi;
            p
        }))
    }
    pub(super) fn information(self) -> [u8; 28] {
        information(self.receive_short_gi)
    }
    pub(super) fn response(self, ies: &[u8], primary: u8) -> Result<Self, Error> {
        let mut received = elements(ies, primary)?.ok_or(Error::Unsupported)?;
        received.mcs &= self.mcs;
        if received.mcs == 0 {
            return Err(Error::Unsupported);
        }
        received.short_gi &= self.short_gi;
        received.receive_short_gi = self.receive_short_gi;
        Ok(received)
    }
    pub(super) fn mode(self, frequency: u16) -> u32 {
        if frequency < 3000 {
            5
        } else {
            4
        }
    }
    pub(super) fn density(self) -> u32 {
        match (self.ampdu >> 2) & 7 {
            0 => 0,
            1..=3 => 1,
            n => 1 << (n - 3),
        }
    }
    pub(super) fn accepts(self, descriptor: &[u8]) -> bool {
        let word = |at| u32::from_le_bytes(descriptor[at..at + 4].try_into().unwrap());
        match word(104) >> 24 {
            4 => true,
            8 | 9 => {
                let sig = word(108);
                descriptor[103] & 1 == 0
                    && sig & 0x80 == 0
                    && sig & 0x7f < 8
                    && (word(112) & 0x80 == 0 || self.receive_short_gi)
            }
            _ => false,
        }
    }
}
