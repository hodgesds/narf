//! Native AP peer transaction, owned before every firmware publication.
use super::*;
use crate::mt7921::ap_wire::PeerRecord;
use narf_wireless::StationConfig;
impl<B: Backend> Session<B> {
    /// Called by the concrete registered interface only after native START
    /// and before its carrier publication. It opens no per-peer port.
    pub(in crate::mt7921::firmware_transport) fn commit_ap_start(
        &mut self,
        authority: &ApControlAuthority,
    ) -> Result<u64, Error> {
        if !matches!(self.state, State::AccessPoint { .. }) || !authority.has_reservation() {
            return Err(Error::Busy);
        }
        self.check_ap_request(authority)?;
        self.renew_receive_epoch()?;
        let result = self
            .backend
            .open_receive_capture(self.receive_epoch)
            .and_then(|_| self.check_ap_request(authority));
        if let Err(error) = result {
            return Err(self.quarantine_ap_request(authority, error));
        }
        let owner = self.ap_owner.as_mut().ok_or(Error::Busy)?;
        owner.activated = true;
        owner.pending = None;
        Ok(self.receive_epoch)
    }
    pub(in crate::mt7921::firmware_transport) async fn ap_add_station(
        &mut self,
        authority: Arc<ApControlAuthority>,
        config: StationConfig,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::AccessPoint { .. }) || !authority.has_reservation() {
            return Err(Error::Busy);
        }
        self.check_ap_request(&authority)?;
        let owner = self.ap_owner.as_ref().ok_or(Error::Busy)?;
        if !owner.activated {
            return Err(Error::Busy);
        }
        if owner.plan.config.privacy && config.authorized == Some(true) {
            return Err(Error::Bounds);
        }
        let (own, five, basic, supported) = (
            owner.plan.own,
            owner.plan.five_ghz,
            owner.plan.basic_rates,
            owner.plan.rates,
        );
        let mut peer = self
            .ap_owner
            .as_mut()
            .unwrap()
            .peers
            .reserve(own, config, five, basic)?;
        peer.rates &= supported;
        if peer.rates & basic != basic {
            return Err(Error::Bounds);
        }
        let record = ap_wire::peer(PeerRecord {
            mac: peer.config.mac,
            wcid: peer.wcid,
            aid: peer.config.aid,
            newly: true,
            qos: false,
            five_ghz: five,
            rates: peer.rates,
            basic_rates: basic,
        })?;
        self.renew_receive_epoch()?;
        self.ap_owner.as_mut().unwrap().pending = Some(authority.clone());
        self.stage(Stage::ApPeer);
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            self.ap_exchange(&authority, Command::Unified { id: 3 }, &record)
                .await?;
            peer.associated = true;
            let owner = self.ap_owner.as_mut().ok_or(Error::Busy)?;
            let (info, frequency_mhz) = (owner.info, owner.plan.config.frequency_mhz);
            owner.peers.commit(peer)?;
            self.backend.open_receive_capture(self.receive_epoch)?;
            self.check_ap_request(&authority)?;
            self.state = State::AccessPoint {
                info,
                frequency_mhz,
            };
            self.ap_owner.as_mut().unwrap().pending = None;
            Ok(())
        }
        .await;
        self.boot_started = None;
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(self.ap_peer_failure(error).await),
        }
    }
    /// Host authorization is separate from BASIC.conn_state, which Linux
    /// programs PORT_SECURE for every enabled AP peer. No WTBL reset on an
    /// AUTHORIZED-only change: that would lose the native sequence owner.
    pub(in crate::mt7921::firmware_transport) fn ap_authorize_station(
        &mut self,
        authority: &ApControlAuthority,
        mac: [u8; 6],
        authorized: bool,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::AccessPoint { .. }) || !authority.has_reservation() {
            return Err(Error::Busy);
        }
        self.check_ap_request(authority)?;
        if !self.data_pending.is_empty() {
            return Err(Error::Busy);
        }
        let owner = self.ap_owner.as_ref().ok_or(Error::Busy)?;
        if owner.peers.get(mac).is_none_or(|peer| !peer.associated) {
            return Err(Error::Bounds);
        }
        if authorized && owner.plan.config.privacy && !self.ap_keys.has_pair(mac) {
            return Err(Error::Bounds);
        }
        self.renew_receive_epoch()?;
        self.ap_owner
            .as_mut()
            .unwrap()
            .peers
            .get_mut(mac)
            .unwrap()
            .authorized = authorized;
        self.ap_owner
            .as_mut()
            .unwrap()
            .peers
            .get_mut(mac)
            .unwrap()
            .config
            .authorized = Some(authorized);
        let result = self
            .check_ap_request(authority)
            .and_then(|_| self.backend.open_receive_capture(self.receive_epoch))
            .and_then(|_| self.check_ap_request(authority));
        if let Err(error) = result {
            return Err(self.quarantine_ap_request(authority, error));
        }
        Ok(())
    }
    fn quarantine_ap_request(&mut self, authority: &ApControlAuthority, error: Error) -> Error {
        self.backend.close_receive_capture(0);
        if let Some(owner) = self.ap_owner.as_mut() {
            owner.activated = false;
            owner.pending = Some(Arc::new(authority.clone()));
        }
        self.state = State::Failed {
            stage: Stage::ApPeer,
            error,
        };
        error
    }
    pub(super) async fn ap_peer_failure(&mut self, error: Error) -> Error {
        let Some(info) = self.ap_owner.as_ref().map(|o| o.info) else {
            return error;
        };
        self.state = State::Failed {
            stage: Stage::ApPeer,
            error,
        };
        let _ = self.recover(info.capabilities.mac).await;
        error
    }

    pub(super) fn begin_ap_peer_request(
        &mut self,
        authority: Arc<ApControlAuthority>,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::AccessPoint { .. }) || !authority.has_reservation() {
            return Err(Error::Busy);
        }
        self.check_ap_request(&authority)?;
        if !self.ap_owner.as_ref().is_some_and(|owner| owner.activated) {
            return Err(Error::Busy);
        }
        self.renew_receive_epoch()?;
        self.ap_owner.as_mut().unwrap().pending = Some(authority);
        self.stage(Stage::ApPeer);
        self.boot_started = Some(self.backend.now_ns());
        Ok(())
    }
    pub(super) fn finish_ap_peer_request(
        &mut self,
        authority: &ApControlAuthority,
    ) -> Result<(), Error> {
        self.check_ap_request(authority)?;
        self.backend.open_receive_capture(self.receive_epoch)?;
        self.check_ap_request(authority)?;
        let owner = self.ap_owner.as_mut().ok_or(Error::Busy)?;
        self.state = State::AccessPoint {
            info: owner.info,
            frequency_mhz: owner.plan.config.frequency_mhz,
        };
        owner.pending = None;
        self.boot_started = None;
        Ok(())
    }
    /// TX_FREE and native DMA retirement are both required by the backend's
    /// completion owner. Closing a host queue is not a packet receipt.
    pub(super) async fn ap_drain_packets(&mut self) -> Result<(), Error> {
        while !self.data_pending.is_empty() {
            let completion = self
                .wait(super::super::TIMEOUT_MS, |backend| {
                    backend.management_complete()
                })
                .await?;
            self.data_pending.pop_front();
            if completion.status != 0 {
                return Err(Error::Rejected(completion.status));
            }
        }
        Ok(())
    }
    pub(in crate::mt7921::firmware_transport) async fn ap_delete_station(
        &mut self,
        authority: Arc<ApControlAuthority>,
        mac: Option<[u8; 6]>,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::AccessPoint { .. }) || !authority.has_reservation() {
            return Err(Error::Busy);
        }
        self.check_ap_request(&authority)?;
        let owner = self.ap_owner.as_ref().ok_or(Error::Busy)?;
        let addresses = match mac {
            None => owner.peers.addresses(),
            Some(mac) if mac == [0xff; 6] => owner.peers.addresses(),
            Some(mac) if owner.peers.get(mac).is_some() => vec![mac],
            _ => return Err(Error::Bounds),
        };
        self.begin_ap_peer_request(authority.clone())?;
        let result = async {
            self.ap_drain_packets().await?;
            for mac in addresses {
                self.check_ap_request(&authority)?;
                let peer = self
                    .ap_owner
                    .as_ref()
                    .unwrap()
                    .peers
                    .get(mac)
                    .ok_or(Error::Bounds)?;
                let record = ap_wire::delete_peer(mac, peer.wcid, peer.config.aid)?;
                self.ap_exchange(&authority, Command::Unified { id: 3 }, &record)
                    .await?;
                // Hardware has never owned an AP encryption key. The native
                // WTBL reset plus packet dual retirement permits WCID reuse;
                // software nonce history survives this peer's deletion.
                if self.ap_keys.has_pair(mac) {
                    self.ap_keys
                        .remove(super::super::ap_crypto::Target::Pairwise(mac))
                        .map_err(|_| Error::Bounds)?;
                }
                self.ap_owner.as_mut().unwrap().peers.retire(mac)?;
            }
            self.finish_ap_peer_request(&authority)
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(self.ap_peer_failure(e).await),
        }
    }
    /// Initial legacy profile supports host AUTHORIZED changes while every
    /// native peer field remains unchanged. A port transition waits for all
    /// already-published packets and never resets its native sequence owner.
    pub(in crate::mt7921::firmware_transport) async fn ap_update_station(
        &mut self,
        authority: Arc<ApControlAuthority>,
        config: StationConfig,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::AccessPoint { .. }) || !authority.has_reservation() {
            return Err(Error::Busy);
        }
        self.check_ap_request(&authority)?;
        let owner = self.ap_owner.as_ref().ok_or(Error::Busy)?;
        let peer = owner
            .peers
            .get(config.mac)
            .filter(|p| p.associated)
            .ok_or(Error::Bounds)?;
        if config.aid != 0 && config.aid != peer.config.aid
            || config.listen_interval != 0 && config.listen_interval != peer.config.listen_interval
            || !config.supported_rates.is_empty()
                && config.supported_rates != peer.config.supported_rates
            || config.wme.is_some_and(|v| v)
            || config.uapsd_queues.is_some_and(|v| v != 0)
            || config.uapsd_max_sp.is_some_and(|v| v != 0)
            || config.mfp.is_some_and(|v| v)
            || config
                .capability
                .is_some_and(|v| Some(v) != peer.config.capability)
            || config.ext_capability.is_some()
            || config.ht_capability.is_some()
            || config.vht_capability.is_some()
            || config.he_capability.is_some()
            || config.he_6ghz_capability.is_some()
            || config.station_tx_power.is_some()
        {
            return Err(Error::Bounds);
        }
        let authorized = config.authorized.unwrap_or(peer.authorized);
        if authorized && owner.plan.config.privacy && !self.ap_keys.has_pair(config.mac) {
            return Err(Error::Bounds);
        }
        self.begin_ap_peer_request(authority.clone())?;
        let result = async {
            self.ap_drain_packets().await?;
            self.check_ap_request(&authority)?;
            let peer = self
                .ap_owner
                .as_mut()
                .unwrap()
                .peers
                .get_mut(config.mac)
                .ok_or(Error::Bounds)?;
            peer.authorized = authorized;
            peer.config.authorized = Some(authorized);
            self.finish_ap_peer_request(&authority)
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(self.ap_peer_failure(e).await),
        }
    }
}
