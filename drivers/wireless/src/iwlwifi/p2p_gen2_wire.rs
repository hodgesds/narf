//! API77's separate legacy P2P hardware adapter. These factual codecs do
//! not grant a control child, native SESSION, RF power or packet authority.
//! Linux mvm/{sta,phy-ctxt}.c, fw/api/{sta,phy-ctxt}.h and actual image TLVs.
use super::{
    boot_context::{put16, put32},
    firmware_api::FirmwareApi,
    native_band::{Band, Channel},
    p2p_wire::Abi,
    station_api::Nvm,
};
use alloc::{vec, vec::Vec};

pub(super) struct Adapter {
    ultra: bool,
    rlc: u8,
    chains: (u32, u32),
    channels: Vec<u8>,
    station: u8,
}
impl Adapter {
    pub fn read(api: &FirmwareApi<'_>, nvm: &Nvm) -> Result<Self, &'static str> {
        let version = |g, c, default| match api.command_version(g, c) {
            None | Some(99) => default,
            Some(v) => v,
        };
        if Abi::read(api)? != Abi::Session1
            || !api.has_capability(110)
            || api.api_changes[0] & (1 << 30) == 0
            || api.api_changes[1] & (1 << 27) == 0
            || version(3, 9, 1) != 1
            || !matches!(version(1, 8, 1), 1 | 2)
            || api.versions(1, 0x18) != Some((12, 2))
            || api.versions(1, 0x19) != Some((2, 0))
            || api.versions(5, 0x17) != Some((3, 2))
            || api.versions(1, 0x1e) != Some((2, 1))
            || api.versions(0, 0xc1).map(|v| v.1) != Some(4)
            || api.versions(5, 0xf7).map(|v| v.1) != Some(3)
            || api.command_version(0, 0x1c) != Some(9)
            || !matches!(api.versions(1, 0x1c).map(|v| v.1), Some(6..=8))
            || !matches!(api.num_stations, Some(2..=16))
            || !matches!(api.num_links, Some(2..=4))
            || !matches!(nvm.tx_chains, 1..=3)
            || !matches!(nvm.rx_chains, 1..=3)
            || nvm.channels.is_empty()
        {
            return Err("API77 P2P has no complete actual SESSION/legacy ABI/NVM consumer");
        }
        Ok(Self {
            ultra: api.has_capability(48),
            rlc: version(5, 8, 0),
            chains: (nvm.tx_chains, nvm.rx_chains),
            channels: nvm.channels.clone(),
            station: api.num_stations.unwrap() - 1,
        })
    }
    pub fn phy(
        &self,
        action: u32,
        channel: Channel,
    ) -> Result<(Vec<u8>, Option<[u8; 32]>), &'static str> {
        if !matches!(action, 1 | 3)
            || channel.band == Band::Six
            || channel.number == 14
            || Channel::legacy(channel.number) != Some(channel)
            || !self.channels.contains(&channel.number)
        {
            return Err("API77 P2P PHY1 lacks exact original legacy20 NVM channel");
        }
        let tail = if self.ultra { 24 } else { 20 };
        let mut body = vec![0; tail + 16];
        put32(&mut body, 0, 1); // Actual separately allocated PHY1.
        put32(&mut body, 4, action);
        if self.ultra {
            put32(&mut body, 16, u32::from(channel.number));
            body[20] = channel.band as u8;
        } else {
            body[16] = channel.band as u8;
            body[17] = channel.number;
        }
        let (tx, rx) = self.chains;
        let count = rx.count_ones();
        let receive = (rx << 1) | (count << 10) | (count << 12);
        put32(&mut body, tail, tx);
        put32(&mut body, tail + 4, receive);
        let rlc = (self.rlc == 2 && action == 1).then(|| {
            let mut b = [0; 32];
            put32(&mut b, 0, 1); // RLC is per-PHY, never inherit PHY0.
            put32(&mut b, 4, receive);
            b
        });
        Ok((body, rlc))
    }
    pub fn broadcast(&self) -> [u8; 48] {
        let mut b = [0; 48];
        put16(&mut b, 2, u16::MAX);
        // ADD_STA v12 overloads this as LMAC only for AUX_ACTIVITY. An
        // actual BCAST_MGMT retains FW_CMD_ID_AND_COLOR(MAC1, color0).
        put32(&mut b, 4, 1);
        b[8..14].fill(255);
        b[16] = self.station;
        b[35] = 1; // IWL_STA_BCAST_MGMT; no invented legacy MFP flag.
        b
    }
    pub fn added(&self, reply: &[u8]) -> Result<(), &'static str> {
        if reply.len() != 4 || u32::from_le_bytes(reply.try_into().unwrap()) & 255 != 1 {
            return Err("API77 P2P ADD_STA lacks exact successful native status");
        }
        Ok(())
    }
    pub fn remove(&self) -> [u8; 4] {
        u32::from(self.station).to_le_bytes()
    }
}
