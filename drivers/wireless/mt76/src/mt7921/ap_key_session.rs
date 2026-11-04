//! Software AP keys share the actual BSS/control/capture owner. Fresh AP
//! start resets WTBL keys; none of these operations install a hardware key.
//! Old hardware plaintext is never a substitute for current CCMP proof.
use super::super::ap_crypto::{self, Install, Target};
use super::*;

impl<B: Backend> Session<B> {
    pub(in crate::mt7921::firmware_transport) async fn ap_install_key(
        &mut self,
        authority: Arc<ApControlAuthority>,
        key: Install,
    ) -> Result<(), Error> {
        self.ap_key_target(&authority, key.target)?;
        self.ap_keys
            .check_install(key.target, &key.tk, key.rsc)
            .map_err(|_| Error::Bounds)?;
        self.begin_ap_peer_request(authority.clone())?;
        let result = async {
            self.ap_drain_packets().await?;
            self.check_ap_request(&authority)?;
            self.ap_keys
                .install(key.target, &key.tk, key.rsc)
                .map_err(|_| Error::Bounds)?;
            self.finish_ap_peer_request(&authority)
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(self.ap_peer_failure(e).await),
        }
    }
    pub(in crate::mt7921::firmware_transport) async fn ap_delete_key(
        &mut self,
        authority: Arc<ApControlAuthority>,
        index: u8,
        pairwise: bool,
        peer: Option<[u8; 6]>,
    ) -> Result<(), Error> {
        let target = ap_crypto::target(index, pairwise, peer).map_err(|_| Error::Bounds)?;
        self.ap_key_target(&authority, target)?;
        if match target {
            Target::Pairwise(mac) => !self.ap_keys.has_pair(mac),
            Target::Group(id) => !self.ap_keys.has_group(id),
        } {
            return Err(Error::Bounds);
        }
        self.begin_ap_peer_request(authority.clone())?;
        let result = async {
            self.ap_drain_packets().await?;
            self.check_ap_request(&authority)?;
            self.ap_keys.remove(target).map_err(|_| Error::Bounds)?;
            let owner = self.ap_owner.as_mut().ok_or(Error::Busy)?;
            match target {
                Target::Pairwise(mac) => {
                    let peer = owner.peers.get_mut(mac).ok_or(Error::Bounds)?;
                    peer.authorized = false;
                    peer.config.authorized = Some(false);
                }
                Target::Group(id) if owner.default_group == Some(id) => owner.default_group = None,
                _ => (),
            }
            self.finish_ap_peer_request(&authority)
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(self.ap_peer_failure(e).await),
        }
    }
    pub(in crate::mt7921::firmware_transport) async fn ap_default_key(
        &mut self,
        authority: Arc<ApControlAuthority>,
        index: u8,
    ) -> Result<(), Error> {
        self.ap_key_target(&authority, Target::Group(index))?;
        if !self.ap_keys.has_group(index) {
            return Err(Error::Bounds);
        }
        self.begin_ap_peer_request(authority.clone())?;
        let result = async {
            self.ap_drain_packets().await?;
            self.check_ap_request(&authority)?;
            self.ap_owner.as_mut().ok_or(Error::Busy)?.default_group = Some(index);
            self.finish_ap_peer_request(&authority)
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(self.ap_peer_failure(e).await),
        }
    }
    fn ap_key_target(&self, authority: &ApControlAuthority, target: Target) -> Result<(), Error> {
        if !matches!(self.state, State::AccessPoint { .. }) || !authority.has_reservation() {
            return Err(Error::Busy);
        }
        self.check_ap_request(authority)?;
        let owner = self.ap_owner.as_ref().ok_or(Error::Busy)?;
        if !owner.activated || !owner.plan.config.privacy {
            return Err(Error::Bounds);
        }
        match target {
            Target::Pairwise(mac) if owner.peers.get(mac).is_some_and(|peer| peer.associated) => {
                Ok(())
            }
            Target::Group(0..=3) => Ok(()),
            _ => Err(Error::Bounds),
        }
    }
}
