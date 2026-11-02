// SPDX-License-Identifier: GPL-2.0-or-later
//! Native RAW/nohwcrypt AP keys. Installation is the actual zeroizing host
//! cipher owner after old native DATA terminals, never a fabricated WMI ACK.
use super::{
    ap::{self, Session},
    ap_key, Error, Hif, HostMemory, HttMemory, Radio,
};
use narf_wireless::{ap_control::ApEmissionAuthority, OwnedKey};

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) async fn ap_add_key(
        &mut self,
        key: OwnedKey,
        source: ApEmissionAuthority,
        domain: &narf_wireless::reg::RegulatoryDomain,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        validate()?;
        self.ap_current(domain)?;
        if !self.ap_running() || !source.current() {
            return Err(Error::Failed);
        }
        let candidate = ap_key::Key::new(key.params())?;
        let ap = self.ap.as_mut().unwrap();
        if !ap.plan.config.privacy {
            return Err(Error::Unsupported);
        }
        let peer = candidate
            .peer
            .map(|mac| {
                ap.peers
                    .iter()
                    .position(|peer| {
                        peer.record.mac == mac && peer.associated && peer.record.mapped()
                    })
                    .ok_or(Error::Unsupported)
            })
            .transpose()?;
        let same = if let Some(index) = peer {
            ap.peers[index]
                .key
                .as_ref()
                .is_some_and(|old| old.matches(key.params()))
        } else {
            ap.groups.iter().any(|old| old.key.matches(key.params()))
        };
        if same {
            return Ok(());
        }
        if peer.is_none() && !ap.groups.iter().any(|group| group.key.id == candidate.id) {
            if ap.groups.len() == 4 {
                return Err(Error::Unsupported);
            }
            ap.groups.try_reserve(1).map_err(|_| Error::NoMemory)?;
        }
        self.ap_history
            .as_ref()
            .ok_or(Error::Failed)?
            .lock()
            .remember(candidate.digest)?;
        let ap = self.ap.as_mut().unwrap();
        Session::advance(&ap.data_epoch)?;
        Session::advance(&ap.key_epoch)?;
        let target = peer.map(|index| ap::PeerFence::capture(&ap.peers[index]));
        let authorized = peer.is_some_and(|index| ap.peers[index].authorized);
        let capture = ap.capture(false, true)?.for_control_wait();
        let current = || {
            validate()?;
            if !source.current() || target.as_ref().is_some_and(|peer| !peer.current()) {
                return Err(Error::Failed);
            }
            capture.current(domain)
        };
        ap.busy = true;
        if let Some(index) = peer {
            ap.peers[index].authorized = false;
        }
        self.ap_quiet(&current).await?;
        current()?;
        let ap = self.ap.as_mut().unwrap();
        if let Some(index) = peer {
            let peer = &mut ap.peers[index];
            if !peer.associated || !peer.record.mapped() {
                return Err(Error::Failed);
            }
            peer.key = Some(candidate);
            peer.key_source = Some(source);
            peer.authorized = authorized;
        } else if let Some(index) = ap.groups.iter().position(|old| old.key.id == candidate.id) {
            ap.groups[index] = ap::Group {
                key: candidate,
                source,
            };
        } else {
            ap.groups.push(ap::Group {
                key: candidate,
                source,
            });
        }
        ap.busy = false;
        Ok(())
    }
    pub(in crate::ath10k) async fn ap_del_key(
        &mut self,
        index: u8,
        pairwise: bool,
        mac: Option<[u8; 6]>,
        source: ApEmissionAuthority,
        domain: &narf_wireless::reg::RegulatoryDomain,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        validate()?;
        self.ap_current(domain)?;
        if !self.ap_running() || !source.current() {
            return Err(Error::Failed);
        }
        let ap = self.ap.as_mut().unwrap();
        if pairwise != mac.is_some() || pairwise && index != 0 || index > 3 {
            return Err(Error::Unsupported);
        }
        let peer = mac
            .map(|mac| {
                ap.peers
                    .iter()
                    .position(|peer| {
                        peer.record.mac == mac
                            && peer.key.as_ref().is_some_and(|key| key.id == index)
                    })
                    .ok_or(Error::Unsupported)
            })
            .transpose()?;
        if peer.is_none() && !ap.groups.iter().any(|group| group.key.id == index) {
            return Err(Error::Unsupported);
        }
        Session::advance(&ap.data_epoch)?;
        Session::advance(&ap.key_epoch)?;
        let capture = ap.capture(false, true)?.for_control_wait();
        let current = || {
            validate()?;
            if !source.current() {
                return Err(Error::Failed);
            }
            capture.current(domain)
        };
        ap.busy = true;
        if let Some(i) = peer {
            ap.peers[i].authorized = false;
            Session::advance(&ap.peers[i].denial)?;
        }
        self.ap_quiet(&current).await?;
        if let Some(mac) = mac {
            self.ap_command(&super::ap_wire::peer_parameter(mac, 3, 0)?, &current)
                .await?;
            self.ap_barrier(&current).await?;
        }
        let ap = self.ap.as_mut().unwrap();
        if let Some(index) = peer {
            ap.peers[index].key = None;
            ap.peers[index].key_source = None;
            ap.peers[index].authorization = None;
            ap.peers[index].config.authorized = Some(false);
        } else {
            ap.groups.retain(|group| group.key.id != index);
            if ap.default_group == Some(index) {
                ap.default_group = None;
                ap.default_source = None;
            }
        }
        ap.busy = false;
        Ok(())
    }
    pub(in crate::ath10k) fn ap_default_key(
        &mut self,
        index: u8,
        flags: (bool, bool, bool, bool),
        source: ApEmissionAuthority,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), Error> {
        let (unicast, multicast, management, beacon) = flags;
        self.ap_current(domain)?;
        if !self.ap_running() || !source.current() || unicast || !multicast || management || beacon
        {
            return Err(Error::Unsupported);
        }
        let ap = self.ap.as_mut().unwrap();
        if !ap.groups.iter().any(|group| group.key.id == index) {
            return Err(Error::Unsupported);
        }
        Session::advance(&ap.data_epoch)?;
        Session::advance(&ap.key_epoch)?;
        ap.default_group = Some(index);
        ap.default_source = Some(source);
        Ok(())
    }
    pub(in crate::ath10k) fn ap_key_sequence(
        &self,
        index: u8,
        pairwise: bool,
        mac: Option<[u8; 6]>,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<([u8; 6], ap::Capture), Error> {
        self.ap_current(domain)?;
        if !self.ap_running() || pairwise != mac.is_some() || index > 3 || pairwise && index != 0 {
            return Err(Error::Unsupported);
        }
        let ap = self.ap.as_ref().unwrap();
        let key = if let Some(mac) = mac {
            ap.peers
                .iter()
                .find(|peer| peer.record.mac == mac && peer.associated && peer.record.mapped())
                .and_then(|peer| peer.key.as_ref())
        } else {
            ap.groups
                .iter()
                .find(|group| group.key.id == index)
                .map(|group| &group.key)
        }
        .ok_or(Error::Unsupported)?;
        let mut capture = ap.capture(false, true)?;
        if let Some(peer) = mac.and_then(|mac| ap.peers.iter().find(|peer| peer.record.mac == mac))
        {
            capture = capture.with_peer(ap::PeerFence::capture(peer));
        }
        Ok((key.sequence(), capture))
    }
}
