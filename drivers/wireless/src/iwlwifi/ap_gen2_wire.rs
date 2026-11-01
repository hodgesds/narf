//! API77's actual legacy command/RX consumer. Retaining these ABI facts
//! grants no AP role, power, key, beacon or controlled-port authority.
//! Linux mvm/{sta,phy-ctxt}.c and fw/api/{sta,phy-ctxt}.h.
use super::{
    boot_context::{put16, put32},
    firmware_api::FirmwareApi,
    station_api::Nvm,
};
use alloc::{vec, vec::Vec};

pub(super) struct Adapter {
    ultra: bool,
    rlc: u8,
    chains: (u32, u32),
    channels: Vec<u8>,
    stations: u32,
    pub software_bip: bool,
}

#[cfg(feature = "kernel-test")]
#[path = "ap_gen2_tests.rs"]
mod tests;
impl Adapter {
    pub fn read(api: &FirmwareApi<'_>, nvm: &Nvm) -> Result<Self, &'static str> {
        let default_version = |g, c, default| match api.versions(g, c).map(|v| v.0) {
            None | Some(99) => default,
            Some(v) => v,
        };
        if !api.has_capability(110)
            || api.api_changes[0] & (1 << 30) == 0 // actual STA_TYPE API
            || api.versions(3, 8).map(|v| v.0) != Some(1)
            || default_version(3, 9, 1) != 1
            || !matches!(default_version(1, 8, 1), 1 | 2)
            || api.versions(1, 0x18) != Some((12, 2))
            || api.versions(1, 0x19) != Some((2, 0))
            || api.versions(5, 0xf).map(|v| v.0) != Some(4)
            || api.versions(5, 0x18).map(|v| v.0) != Some(1)
            || api.versions(5, 0x17) != Some((3, 2))
            || api.versions(1, 0x91).map(|v| v.0) != Some(13)
            || api.versions(1, 0x1e) != Some((2, 1))
            || api.command_version(0, 0x1c) != Some(9)
            || !matches!(api.versions(1, 0x1c).map(|v| v.1), Some(6..=8))
            || api.versions(0, 0xc1).map(|v| v.1) != Some(4)
            || api.versions(5, 0xf7).map(|v| v.1) != Some(3)
            || !matches!(nvm.tx_chains, 1..=3)
            || !matches!(nvm.rx_chains, 1..=3)
            || nvm.channels.is_empty()
        {
            return Err("API77 AP has no complete actual legacy ABI/NVM consumer");
        }
        Ok(Self {
            ultra: api.has_capability(48),
            rlc: default_version(5, 8, 0),
            chains: (nvm.tx_chains, nvm.rx_chains),
            channels: nvm.channels.clone(),
            stations: 0,
            // Linux mac80211.c set_key declines AP group CMAC without
            // this actual capability, even when SEC_KEY_CMD is present.
            software_bip: !api.has_capability(109),
        })
    }
    pub fn peer(&self, canonical: &[u8; 104]) -> Result<(u8, [u8; 48]), &'static str> {
        let word = |at| u32::from_le_bytes(canonical[at..at + 4].try_into().unwrap());
        let id = u8::try_from(word(0)).map_err(|_| "API77 AP station ID overflow")?;
        let kind = word(24);
        let aid = word(28);
        let sp = word(64);
        let ac = word(68);
        if id >= super::ap_wire::FIRST_PEER + super::ap_wire::MAX_PEERS as u8
            || kind > 2
            || (kind == 0) != (id >= super::ap_wire::FIRST_PEER)
            || kind == 1 && id != super::ap_wire::BCAST
            || kind == 2 && id != super::ap_wire::MCAST
            || kind == 0 && (!(1..=2007).contains(&aid) || !matches!(sp, 2 | 4 | 6 | 128))
            || ac > 255
            || ac & 15 != ac >> 4
            || canonical[8..14] == [0; 6]
            || kind == 0 && canonical[8] & 1 != 0
            || canonical[16..22] != canonical[8..14]
            || canonical[4..8] != [0; 4]
            || canonical[14..16] != [0; 2]
            || canonical[22..24] != [0; 2]
            || canonical[32..36] != [0; 4]
            || word(36) > 1
            || canonical[40..64] != [0; 24]
            || canonical[72..] != [0; 32]
            || kind != 0 && (aid != 0 || sp != 0 || ac != 0)
            || kind == 1 && canonical[8..14] != [255; 6]
            || kind == 2 && canonical[8..14] != [3, 0, 0, 0, 0, 0]
        {
            return Err("API77 AP station role/AID/UAPSD contract invalid");
        }
        let mut body = [0; 48];
        body[0] = u8::from(self.stations & (1u32 << id) != 0);
        put16(&mut body, 2, u16::MAX); // no aggregation TID is admitted
        body[8..14].copy_from_slice(&canonical[8..14]);
        body[16] = id;
        body[35] = kind as u8;
        if kind == 0 {
            // Linux's legacy station producer does not set CLASS_AUTH /
            // CLASS_ASSOC or a fictitious station MFP flag. The host port
            // and actual SEC_KEY MFP bit retain those separate authorities.
            put32(&mut body, 24, (3 << 26) | (3 << 28) | (1 << 17));
            put16(&mut body, 36, aid as u16);
            body[17] = 1 << 2; // STA_MODIFY_UAPSD_ACS
            body[46] = sp as u8;
            body[47] = ac as u8;
        }
        Ok((id, body))
    }
    pub fn added(&mut self, id: u8, reply: &[u8]) -> Result<(), &'static str> {
        if id >= 32 || reply.len() != 4 || u32::from_le_bytes(reply.try_into().unwrap()) & 255 != 1
        {
            return Err("API77 AP ADD_STA requires exact successful native status");
        }
        self.stations |= 1u32 << id;
        Ok(())
    }
    pub fn remove(&self, id: u8) -> Result<[u8; 4], &'static str> {
        if id >= 32 || self.stations & (1u32 << id) == 0 {
            return Err("API77 AP REMOVE_STA has no retained native station");
        }
        Ok(u32::from(id).to_le_bytes())
    }
    pub fn removed(&mut self, id: u8) {
        self.stations &= !(1u32 << id);
    }
    pub fn phy(&self, canonical: &[u8; 32]) -> Result<(Vec<u8>, Option<[u8; 32]>), &'static str> {
        let action = u32::from_le_bytes(canonical[4..8].try_into().unwrap());
        let channel = u8::try_from(u32::from_le_bytes(canonical[8..12].try_into().unwrap()))
            .map_err(|_| "API77 AP channel overflow")?;
        if !matches!(action, 1 | 3)
            || !self.channels.contains(&channel)
            || canonical[12] != u8::from(channel <= 14)
            || canonical[13..16] != [0; 3]
            || canonical[..4] != [0; 4]
        {
            return Err("API77 AP PHY has no exact legacy20 NVM channel");
        }
        let tail = if self.ultra { 24 } else { 20 };
        let mut body = vec![0; tail + 16];
        put32(&mut body, 4, action);
        if self.ultra {
            put32(&mut body, 16, u32::from(channel));
            body[20] = canonical[12];
        } else {
            body[16] = canonical[12];
            body[17] = channel;
        }
        let (tx, rx) = self.chains;
        let count = rx.count_ones();
        let rx = (rx << 1) | (count << 10) | (count << 12);
        put32(&mut body, tail, tx);
        put32(&mut body, tail + 4, rx);
        let rlc = (self.rlc == 2).then(|| {
            let mut b = [0; 32];
            put32(&mut b, 4, rx);
            b
        });
        Ok((body, rlc))
    }
}
