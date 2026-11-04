// SPDX-License-Identifier: GPL-2.0-or-later
//! Userspace-SME peer controls over the original AP/native/copy owner.
use super::{
    ap::{self, Session},
    ap_wire, Error, Hif, HostMemory, HttMemory, Radio,
};
use narf_wireless::{ap_control::ApEmissionAuthority, StationConfig};

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) async fn ap_add_station(
        &mut self,
        station: StationConfig,
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
        let assoc = ap_wire::associate(&ap.plan, &station, false)?;
        if station.mac == ap.own.mac
            || ap.peers.len() == ap_wire::MAX_PEERS
            || ap
                .peers
                .iter()
                .any(|peer| peer.record.mac == station.mac || peer.config.aid == station.aid)
            || ap.plan.config.privacy && station.authorized == Some(true)
        {
            return Err(Error::Unsupported);
        }
        ap.peers.try_reserve(1).map_err(|_| Error::NoMemory)?;
        let mac = station.mac;
        let authorized = station
            .authorized
            .unwrap_or(!ap.plan.settings.control_port.enabled);
        let ps = ap_wire::power_save(
            ap.plan.vdev,
            mac,
            station.uapsd_queues.unwrap_or(0),
            station.uapsd_max_sp.unwrap_or(0),
        )?;
        Session::advance(&ap.data_epoch)?;
        let capture = ap.capture(false, true)?.for_control_wait();
        ap.busy = true;
        let record = ap::Record::new(mac);
        ap.peers.push(ap::Peer {
            record,
            config: station,
            associated: false,
            authorized: false,
            key: None,
            source: source.clone(),
            key_source: None,
            authorization: None,
            denial: alloc::sync::Arc::new(core::sync::atomic::AtomicU64::new(1)),
        });
        let peer_fence = ap::PeerFence::capture(ap.peers.last().unwrap());
        let current = || {
            validate()?;
            if !source.current() || !peer_fence.current() {
                return Err(Error::Failed);
            }
            capture.current(domain)
        };
        self.ap_quiet(&current).await?;
        self.ap_create_peer(mac, &current).await?;
        self.ap_wait(
            |ap| {
                ap.peers
                    .iter()
                    .find(|peer| peer.record.mac == mac)
                    .is_some_and(|peer| peer.record.mapped())
            },
            &current,
        )
        .await?;
        self.ap_command(&assoc, &current).await?;
        if self.ap_uapsd() {
            for command in &ps {
                self.ap_command(command, &current).await?;
            }
        }
        self.ap_command(
            &ap_wire::peer_parameter(self.ap_vdev()?, mac, 3, u32::from(authorized))?,
            &current,
        )
        .await?;
        self.ap_barrier(&current).await?;
        // Consume actual queued native RX while the new port is still denied.
        // No preconfiguration DATA can be relabeled as fresh authorized DATA.
        self.ap_prefix(&current).await?;
        let ap = self.ap.as_mut().unwrap();
        let peer = ap
            .peers
            .iter_mut()
            .find(|peer| peer.record.mac == mac)
            .ok_or(Error::Failed)?;
        if !peer.record.mapped() {
            return Err(Error::Failed);
        }
        peer.associated = true;
        peer.authorized = authorized && peer_fence.current();
        peer.config.authorized = Some(peer.authorized);
        peer.authorization = peer.authorized.then_some(source);
        ap.busy = false;
        Ok(())
    }
    pub(in crate::ath10k) async fn ap_set_station(
        &mut self,
        change: StationConfig,
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
        let index = ap
            .peers
            .iter()
            .position(|peer| {
                peer.record.mac == change.mac && peer.associated && peer.record.mapped()
            })
            .ok_or(Error::Unsupported)?;
        let old = &ap.peers[index];
        let mut next = old.config.clone();
        if change.aid != 0 && change.aid != next.aid
            || change.listen_interval != 0 && change.listen_interval != next.listen_interval
        {
            return Err(Error::Unsupported);
        }
        if !change.supported_rates.is_empty() {
            next.supported_rates = change.supported_rates;
        }
        macro_rules! supplied { ($($field:ident),*) => { $(if change.$field.is_some() { next.$field = change.$field; })* }; }
        supplied!(
            wme,
            uapsd_queues,
            uapsd_max_sp,
            mfp,
            capability,
            ext_capability,
            ht_capability,
            vht_capability,
            he_capability,
            he_6ghz_capability,
            station_tx_power
        );
        let authorized = change.authorized.unwrap_or(old.authorized);
        if authorized && ap.plan.config.privacy && old.key.is_none() {
            return Err(Error::Unsupported);
        }
        next.authorized = Some(authorized);
        let assoc = ap_wire::associate(&ap.plan, &next, true)?;
        let ps = ap_wire::power_save(
            ap.plan.vdev,
            next.mac,
            next.uapsd_queues.unwrap_or(0),
            next.uapsd_max_sp.unwrap_or(0),
        )?;
        Session::advance(&ap.data_epoch)?;
        Session::advance(&ap.peers[index].denial)?;
        let peer_fence = ap::PeerFence::capture(&ap.peers[index]);
        let capture = ap.capture(false, true)?.for_control_wait();
        let current = || {
            validate()?;
            if !source.current() || !peer_fence.current() {
                return Err(Error::Failed);
            }
            capture.current(domain)
        };
        let mac = next.mac;
        ap.peers[index].authorized = false;
        ap.busy = true;
        self.ap_quiet(&current).await?;
        self.ap_command(
            &ap_wire::peer_parameter(self.ap_vdev()?, mac, 3, 0)?,
            &current,
        )
        .await?;
        self.ap_command(&assoc, &current).await?;
        if self.ap_uapsd() {
            for command in &ps {
                self.ap_command(command, &current).await?;
            }
        }
        self.ap_command(
            &ap_wire::peer_parameter(self.ap_vdev()?, mac, 3, u32::from(authorized))?,
            &current,
        )
        .await?;
        self.ap_barrier(&current).await?;
        self.ap_prefix(&current).await?;
        let ap = self.ap.as_mut().unwrap();
        let peer = &mut ap.peers[index];
        if !peer.associated || !peer.record.mapped() {
            return Err(Error::Failed);
        }
        let unchanged = peer_fence.current();
        // A genuine native peer loss during the command prefix denies only;
        // the accepted control cannot resurrect an intervening loss event.
        peer.authorized = authorized && unchanged;
        next.authorized = Some(peer.authorized);
        peer.config = next;
        peer.authorization = peer.authorized.then_some(source);
        ap.busy = false;
        Ok(())
    }
    pub(in crate::ath10k) async fn ap_del_station(
        &mut self,
        peer: Option<[u8; 6]>,
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
        if peer.is_some_and(|mac| !ap.peers.iter().any(|peer| peer.record.mac == mac)) {
            return Err(Error::Unsupported);
        }
        let macs: alloc::vec::Vec<_> = ap
            .peers
            .iter()
            .filter(|record| peer.is_none_or(|mac| record.record.mac == mac))
            .map(|record| record.record.mac)
            .collect();
        Session::advance(&ap.data_epoch)?;
        Session::advance(&ap.key_epoch)?;
        let capture = ap.capture(false, false)?;
        let current = || {
            validate()?;
            if !source.current() {
                return Err(Error::Failed);
            }
            capture.current(domain)
        };
        for record in &mut ap.peers {
            if macs.contains(&record.record.mac) {
                record.authorized = false;
            }
        }
        ap.busy = true;
        self.ap_quiet(&current).await?;
        for mac in macs {
            self.ap_delete_client(mac, &current).await?;
        }
        self.ap_barrier(&current).await?;
        self.ap.as_mut().unwrap().busy = false;
        Ok(())
    }
}
