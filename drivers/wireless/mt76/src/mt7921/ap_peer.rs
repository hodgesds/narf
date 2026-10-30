//! AP peer reservation and bounded legacy association admission.
//! Native record and controlled-port publication remain separate receipts.
use crate::mt7921::{ap_wire, firmware_transport::Error};
use alloc::collections::BTreeMap;
use narf_wireless::StationConfig;

#[derive(Clone)]
pub(super) struct Peer {
    pub config: StationConfig,
    pub wcid: u8,
    pub rates: u16,
    pub associated: bool,
    pub authorized: bool,
}
impl core::fmt::Debug for Peer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApPeer")
            .field("mac", &self.config.mac)
            .field("wcid", &self.wcid)
            .field("aid", &self.config.aid)
            .field("associated", &self.associated)
            .field("authorized", &self.authorized)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Default)]
pub(super) struct Peers {
    peers: BTreeMap<[u8; 6], Peer>,
    /// A request owns a reservation before any native command. A dropped
    /// borrowed waiter cannot return that WCID to the free pool.
    reserved: u16,
}
impl Peers {
    pub fn addresses(&self) -> alloc::vec::Vec<[u8; 6]> {
        self.peers.keys().copied().collect()
    }
    pub fn any_authorized(&self) -> bool {
        self.peers
            .values()
            .any(|peer| peer.associated && peer.authorized)
    }
    pub fn get(&self, mac: [u8; 6]) -> Option<&Peer> {
        self.peers.get(&mac)
    }
    pub fn get_mut(&mut self, mac: [u8; 6]) -> Option<&mut Peer> {
        self.peers.get_mut(&mac)
    }
    pub fn reserve(
        &mut self,
        own: [u8; 6],
        config: StationConfig,
        five: bool,
        basic: u16,
    ) -> Result<Peer, Error> {
        if self.peers.contains_key(&config.mac) {
            return Err(Error::Busy);
        }
        let peer = Peer::prepare(own, config, five, basic)?;
        if self
            .peers
            .values()
            .any(|old| old.config.aid == peer.config.aid)
        {
            return Err(Error::Bounds);
        }
        let wcid = (ap_wire::FIRST_PEER..=ap_wire::LAST_PEER)
            .find(|index| self.reserved & (1 << index) == 0)
            .ok_or(Error::Busy)?;
        self.reserved |= 1 << wcid;
        Ok(Peer { wcid, ..peer })
    }
    pub fn commit(&mut self, peer: Peer) -> Result<(), Error> {
        if self.reserved & (1 << peer.wcid) == 0
            || self.peers.contains_key(&peer.config.mac)
            || self.peers.values().any(|old| old.wcid == peer.wcid)
        {
            return Err(Error::Ring);
        }
        self.peers.insert(peer.config.mac, peer);
        Ok(())
    }
    /// Called only after native WTBL retirement, packet dual retirement and
    /// capture epoch closure. It does not itself prove those receipts.
    pub fn retire(&mut self, mac: [u8; 6]) -> Result<Peer, Error> {
        let peer = self.peers.remove(&mac).ok_or(Error::Bounds)?;
        self.reserved &= !(1 << peer.wcid);
        Ok(peer)
    }
}
impl Peer {
    fn prepare(
        own: [u8; 6],
        mut config: StationConfig,
        five: bool,
        basic: u16,
    ) -> Result<Self, Error> {
        if config.mac == [0; 6]
            || config.mac[0] & 1 != 0
            || config.mac == own
            || !(1..=ap_wire::MAX_AID).contains(&config.aid)
            || config.supported_rates.is_empty()
            || config.wme == Some(true)
            || config.uapsd_queues.is_some_and(|q| q != 0)
            || config.uapsd_max_sp.is_some_and(|s| s != 0)
            || config.mfp == Some(true)
            || config.ht_capability.is_some()
            || config.vht_capability.is_some()
            || config.he_capability.is_some()
            || config.he_6ghz_capability.is_some()
            || config.station_tx_power.is_some()
        {
            return Err(Error::Bounds);
        }
        let known = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
        let mut rates = 0u16;
        for rate in &config.supported_rates {
            let index = known
                .iter()
                .position(|known| *known == rate & 127)
                .ok_or(Error::Bounds)?;
            if five && index < 4 {
                return Err(Error::Bounds);
            }
            rates |= 1 << index;
        }
        if rates & basic != basic {
            return Err(Error::Bounds);
        }
        let authorized = config.authorized.unwrap_or(false);
        config.authorized = Some(authorized);
        Ok(Self {
            config,
            wcid: 0,
            rates,
            associated: false,
            authorized,
        })
    }
}
