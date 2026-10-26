// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware-owned HT20 admission. Linux brcmfmac/cfg80211.c
//! brcmf_setup_wiphybands, brcmf_update_ht_cap and brcmf_get_assoc_ies.
use super::{channel, get_var, policy::TxGrant, set_var, Error, Fullmac, Station, MAX_REPLY};

#[derive(Clone, Copy, Debug)]
pub(super) struct Capabilities {
    ht: [u8; 26],
}
impl Capabilities {
    pub(super) fn body(self) -> [u8; 26] {
        self.ht
    }
    pub(super) fn prepare(self, ies: &[u8], channel: u8) -> Result<Option<Self>, Error> {
        let Elements { ht, operation } = elements(ies)?;
        if ht.is_none() && operation.is_none() {
            return Ok(None);
        }
        self.ap(ies, channel)?;
        Ok(Some(self))
    }
    fn ap(self, ies: &[u8], channel: u8) -> Result<(), Error> {
        let Elements { ht, operation } = elements(ies)?;
        let ht = ht.ok_or(Error::Unsupported)?;
        let operation = operation.ok_or(Error::Unsupported)?;
        if operation[0] != channel
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
        Ok(())
    }
    fn request(self, ies: &[u8]) -> Result<(), Error> {
        let Elements { ht, operation } = elements(ies)?;
        let ht = ht.ok_or(Error::Unsupported)?;
        // The source profile is bounded to HT20, SGI20 and actual RX chains.
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
    let Some(mode) = optional(runtime, "nmode").await? else {
        return Ok(None);
    };
    if mode == 0 {
        return Ok(None);
    }
    if !R::BAND_5GHZ {
        let mut cap = [0; 8];
        cap[..4].copy_from_slice(&2u32.to_le_bytes());
        cap[4..].copy_from_slice(&1u32.to_le_bytes());
        set_var(runtime, "bw_cap", &cap).await?;
    }
    for band in if R::BAND_5GHZ {
        &[2u32, 1][..]
    } else {
        &[2u32][..]
    } {
        let mut query = b"bw_cap\0".to_vec();
        query.extend_from_slice(&band.to_le_bytes());
        let reply = runtime
            .command(super::Direction::Get, 262, &query, 4)
            .await?;
        if reply.as_slice() != 1u32.to_le_bytes() {
            return Err(Error::Unsupported);
        }
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
    Ok(Some(Capabilities { ht }))
}

impl<R: Fullmac> Station<R> {
    pub(super) async fn verify_phy(
        &mut self,
        grant: TxGrant,
        peer: [u8; 6],
        channel: u8,
        profile: Capabilities,
    ) -> Result<(), Error> {
        if self.tx_get(grant, 23, &[], 6).await?.as_slice() != peer {
            return Err(Error::Malformed);
        }
        let actual = self.tx_query(grant, "chanspec", 4).await?;
        if actual.as_slice()
            != u32::from(channel::encode20(channel).ok_or(Error::Unsupported)?).to_le_bytes()
        {
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
        profile.ap(&response_ies, channel)
    }
}
