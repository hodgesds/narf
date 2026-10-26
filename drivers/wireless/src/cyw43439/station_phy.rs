// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware-owned HT20/40 admission. Linux brcmfmac/cfg80211.c
//! brcmf_setup_wiphybands, brcmf_update_ht_cap and brcmf_get_assoc_ies.
use super::{channel, get_var, policy::TxGrant, set_var, Error, Fullmac, Station, MAX_REPLY};

#[derive(Clone, Debug)]
pub(super) struct Capabilities {
    ht: [u8; 26],
    wide: [bool; 2],
    chanspecs: alloc::vec::Vec<u16>,
}
impl Capabilities {
    pub(super) fn body(&self, five: bool) -> [u8; 26] {
        let mut ht = self.ht;
        if self.wide[usize::from(five)] {
            ht[0] |= 2 | 64; // SUP_WIDTH_20_40 and SGI40 from actual bw_cap.
        }
        ht
    }
    pub(super) fn prepare(
        &self,
        ies: &[u8],
        channel: u8,
        valid: &[u8],
    ) -> Result<Option<Profile>, Error> {
        let Elements { ht, operation } = elements(ies)?;
        if ht.is_none() && operation.is_none() {
            return Ok(None);
        }
        let mut profile = Profile {
            ht: self.ht,
            channel: channel::Operating::twenty(channel).ok_or(Error::Unsupported)?,
        };
        profile.ap(ies)?;
        let ht = ht.ok_or(Error::Unsupported)?;
        let operation = operation.ok_or(Error::Unsupported)?;
        if self.wide[usize::from(channel > 14)]
            && ht[0] & 2 != 0
            && ht[1] & 0x40 == 0
            && operation[1] & 4 != 0
        {
            let secondary = match operation[1] & 3 {
                1 => channel.checked_add(4),
                3 => channel.checked_sub(4),
                _ => None,
            };
            if let Some(occupied) = secondary
                .filter(|ch| valid.contains(ch))
                .and_then(|ch| channel::Operating::forty(channel, ch))
            {
                if self.chanspecs.contains(&occupied.chanspec()) {
                    profile.channel = occupied;
                    profile.ht = self.body(channel > 14);
                }
            }
        }
        Ok(Some(profile))
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Profile {
    ht: [u8; 26],
    pub(super) channel: channel::Operating,
}
impl Profile {
    pub(super) fn narrow(mut self) -> Self {
        self.ht[0] &= !(2 | 64);
        self.channel = channel::Operating::twenty(self.channel.primary).expect("validated primary");
        self
    }
    fn ap(self, ies: &[u8]) -> Result<(), Error> {
        let Elements { ht, operation } = elements(ies)?;
        let ht = ht.ok_or(Error::Unsupported)?;
        let operation = operation.ok_or(Error::Unsupported)?;
        if operation[0] != self.channel.primary
            || operation[1] & 3 == 2
            || operation[1] & 0xf0 != 0
            || ht[3] == 0
            || ht[2] & 0xe0 != 0
            || ht[0] & 12 == 8
            || operation[6..16]
                .iter()
                .zip(&self.ht[3..13])
                .any(|(required, local)| required & !local != 0)
            || operation[16..].iter().any(|byte| *byte != 0)
            || narf_wireless::wmm::Parameters::parse(ies)
                .map_err(|_| Error::Malformed)?
                .is_none()
        {
            return Err(Error::Unsupported);
        }
        if let Some(secondary) = self.channel.secondary {
            let offset = if secondary > self.channel.primary {
                1
            } else {
                3
            };
            if ht[0] & 2 == 0 || ht[1] & 0x40 != 0 || operation[1] & 7 != (4 | offset) {
                return Err(Error::Unsupported);
            }
        }
        Ok(())
    }
    fn request(self, ies: &[u8]) -> Result<(), Error> {
        let Elements { ht, operation } = elements(ies)?;
        let ht = ht.ok_or(Error::Unsupported)?;
        // The source profile is bounded to its configured width, short GI
        // and actual RX chains.
        // Firmware may select SMPS; it cannot advertise unqualified wider PHY.
        if operation.is_some()
            || ht[0] & !12 != self.ht[0]
            || ht[0] & 12 == 8
            || ht[1..] != self.ht[1..]
            || narf_wireless::wmm::Parameters::parse(ies).is_err()
        {
            return Err(Error::Unsupported);
        }
        let mut rest = ies;
        while !rest.is_empty() {
            let length = 2 + usize::from(rest[1]); // Validated by elements().
            if rest[..length] == narf_wireless::wmm::INFORMATION {
                return Ok(());
            }
            rest = &rest[length..];
        }
        Err(Error::Unsupported)
    }
}

struct Elements<'a> {
    ht: Option<&'a [u8]>,
    operation: Option<&'a [u8]>,
}
fn elements(mut ies: &[u8]) -> Result<Elements<'_>, Error> {
    if ies.len() > 2048 {
        return Err(Error::Malformed);
    }
    let (mut ht, mut operation) = (None, None);
    while !ies.is_empty() {
        let header = ies.get(..2).ok_or(Error::Malformed)?;
        let end = 2 + usize::from(header[1]);
        let body = ies.get(2..end).ok_or(Error::Malformed)?;
        match header[0] {
            45 if body.len() == 26 && ht.is_none() => ht = Some(body),
            61 if body.len() == 22 && operation.is_none() => operation = Some(body),
            45 | 61 => return Err(Error::Malformed),
            _ => {}
        }
        ies = &ies[end..];
    }
    Ok(Elements { ht, operation })
}

pub(super) async fn probe<R: Fullmac>(runtime: &mut R) -> Result<Option<Capabilities>, Error> {
    async fn optional<R: Fullmac>(runtime: &mut R, name: &str) -> Result<Option<u32>, Error> {
        match get_var(runtime, name, 4).await {
            Ok(bytes) if bytes.len() == 4 => {
                Ok(Some(u32::from_le_bytes(bytes.try_into().unwrap())))
            }
            Ok(_) => Err(Error::Malformed),
            Err(Error::Firmware(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }
    let mode = optional(runtime, "nmode").await?.unwrap_or(0);
    let mut available = [0u32; 2];
    // Discover before narrowing; a configured20MHz cap is not the original
    // firmware capability. Linux brcmf_get_bwcap queries each explicit band.
    for band in if R::BAND_5GHZ {
        &[2u32, 1][..]
    } else {
        &[2u32][..]
    } {
        let mut query = b"bw_cap\0".to_vec();
        query.extend_from_slice(&band.to_le_bytes());
        if mode == 0 && !R::BAND_5GHZ {
            break;
        }
        let reply = runtime
            .command(super::Direction::Get, 262, &query, 4)
            .await?;
        if reply.len() != 4 {
            return Err(Error::Malformed);
        }
        let value = u32::from_le_bytes(reply.try_into().unwrap());
        if value & 1 == 0 || value & !15 != 0 {
            return Err(Error::Unsupported);
        }
        available[usize::from(*band == 1)] = value;
    }
    let mut chanspecs = alloc::vec::Vec::new();
    if mode != 0 && available.iter().any(|cap| cap & 2 != 0) {
        // brcmf_chanspec_list is count:u32 followed by chanspec:u32 rows.
        // The native response, not an HT/chip alias, qualifies exact40MHz
        // primary/secondary pairs. Unsupported queries retain20MHz.
        // Source BRCMF_DCMD_MEDLEN1536, hence at most383 u32 entries.
        match get_var(runtime, "chanspecs", 1536).await {
            Ok(reply) => {
                let count = super::le32(&reply, 0)? as usize;
                let end = count
                    .checked_mul(4)
                    .and_then(|n| n.checked_add(4))
                    .ok_or(Error::Malformed)?;
                if count > 383 || end > reply.len() || reply[end..].iter().any(|b| *b != 0) {
                    return Err(Error::Malformed);
                }
                for row in reply[4..end].chunks_exact(4) {
                    let value = u32::from_le_bytes(row.try_into().unwrap());
                    let value = u16::try_from(value).map_err(|_| Error::Malformed)?;
                    if let Some(occupied) = channel::Operating::decode40(value) {
                        if (occupied.primary <= 14 || R::BAND_5GHZ) && !chanspecs.contains(&value) {
                            chanspecs.push(value);
                        }
                    }
                }
            }
            Err(Error::Firmware(_)) => {}
            Err(error) => return Err(error),
        }
    }
    // WLC_UP and scans remain constrained20MHz. A later fully authorized
    // association sets/readbacks the selected width under its occupied grant.
    for band in if R::BAND_5GHZ {
        &[2u32, 1][..]
    } else if mode != 0 {
        &[2u32][..]
    } else {
        &[][..]
    } {
        let mut cap = [0; 8];
        cap[..4].copy_from_slice(&band.to_le_bytes());
        cap[4..].copy_from_slice(&1u32.to_le_bytes());
        set_var(runtime, "bw_cap", &cap).await?;
        let mut query = b"bw_cap\0".to_vec();
        query.extend_from_slice(&band.to_le_bytes());
        if runtime
            .command(super::Direction::Get, 262, &query, 4)
            .await?
            .as_slice()
            != 1u32.to_le_bytes()
        {
            return Err(Error::Unsupported);
        }
    }
    if mode == 0 {
        return Ok(None);
    }
    let Some(chains) = optional(runtime, "rxchain").await? else {
        return Ok(None);
    };
    // Even an unavailable RX-chain query cannot undo the20MHz firmware cap
    // above. No guessed fallback chain count or device alias grants HT.
    if chains == 0 || chains & !7 != 0 {
        return Err(Error::Unsupported);
    }
    let mut ht = [0; 26];
    ht[0] = 32; // SGI20, no HT40; source capability shape.
    ht[1] = 16; // DSSS/CCK in40 capability does not enable40MHz.
    ht[2] = 31; // Source64K A-MPDU factor,16us density; firmware owns BA/RX.
    ht[3..3 + chains.count_ones() as usize].fill(255);
    ht[15] = 1; // TX MCS defined/equal RX, as brcmf_update_ht_cap.
    let wide = [false, true].map(|five| {
        available[usize::from(five)] & 2 != 0
            && chanspecs.iter().any(|value| (*value & 0xc000 != 0) == five)
    });
    Ok(Some(Capabilities {
        ht,
        wide,
        chanspecs,
    }))
}

impl<R: Fullmac> Station<R> {
    pub(super) async fn verify_phy(
        &mut self,
        grant: TxGrant,
        peer: [u8; 6],
        channel: u8,
        profile: Profile,
    ) -> Result<(), Error> {
        if self.tx_get(grant, 23, &[], 6).await?.as_slice() != peer {
            return Err(Error::Malformed);
        }
        let actual = self.tx_query(grant, "chanspec", 4).await?;
        if actual.as_slice() != u32::from(profile.channel.chanspec()).to_le_bytes() {
            return Err(Error::Unsupported);
        }
        let info = self.tx_query(grant, "assoc_info", 8).await?;
        if info.len() != 8 {
            return Err(Error::Malformed);
        }
        let request = u32::from_le_bytes(info[..4].try_into().unwrap()) as usize;
        let response = u32::from_le_bytes(info[4..].try_into().unwrap()) as usize;
        if !(2..=MAX_REPLY).contains(&request) || !(2..=MAX_REPLY).contains(&response) {
            return Err(Error::Malformed);
        }
        let request_ies = self.tx_query(grant, "assoc_req_ies", request).await?;
        if request_ies.len() != request {
            return Err(Error::Malformed);
        }
        profile.request(&request_ies)?;
        let response_ies = self.tx_query(grant, "assoc_resp_ies", response).await?;
        if response_ies.len() != response {
            return Err(Error::Malformed);
        }
        if profile.channel.primary != channel {
            return Err(Error::Malformed);
        }
        profile.ap(&response_ies)
    }

    pub(super) async fn configure_width(
        &mut self,
        grant: TxGrant,
        occupied: channel::Operating,
    ) -> Result<(), Error> {
        if let Some(secondary) = occupied.secondary {
            // cfg80211::brcmf_construct_chaninfo queries per_chan_info on
            // each20MHz constituent. Index0 uses the plain iovar (fwil.c).
            // Never discard a firmware-only passive/radar/invalid restriction.
            for channel in [occupied.primary, secondary] {
                let mut query = b"per_chan_info\0".to_vec();
                query.extend_from_slice(
                    &u32::from(channel::encode20(channel).ok_or(Error::Unsupported)?).to_le_bytes(),
                );
                let reply = self.tx_get(grant, 262, &query, 4).await?;
                let flags = super::le32(&reply, 0)?;
                let expected = 3 | if channel > 14 { 4 } else { 0 }; // VALID_HW, VALID_SW, BAND_5G.
                if reply.len() != 4 || flags != expected {
                    return Err(Error::Unsupported);
                }
            }
        }
        let band = if occupied.primary <= 14 { 2u32 } else { 1u32 };
        let width = if occupied.secondary.is_some() {
            3u32
        } else {
            1u32
        };
        let mut cap = [0; 8];
        cap[..4].copy_from_slice(&band.to_le_bytes());
        cap[4..].copy_from_slice(&width.to_le_bytes());
        self.tx_var(grant, "bw_cap", &cap).await?;
        let mut query = b"bw_cap\0".to_vec();
        query.extend_from_slice(&band.to_le_bytes());
        if self.tx_get(grant, 262, &query, 4).await?.as_slice() != width.to_le_bytes() {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
}
