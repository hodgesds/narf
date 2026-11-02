// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual firmware SCB verification, authorization and removal. An IOCTL
//! completion is not a replacement for real association/removal observations.
use super::{
    ap::{Event, Session},
    ap_native::{self, Guard},
    ap_peer,
    ap_scope::Use,
    ap_wire,
};
use crate::cyw43439::{fullmac::Fullmac, ioctl::Direction, runtime::Error, station::Station};
use core::sync::atomic::Ordering;

pub(super) async fn absent<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    mac: [u8; 6],
) -> Result<bool, Error> {
    let reply = ap_native::command(
        runtime,
        guard,
        Direction::Get,
        ap_wire::GET_ASSOCIATIONS,
        &32u32.to_le_bytes(),
        4 + 32 * 6,
    )
    .await?;
    if ap_wire::associations(&reply, 32)?.contains(&mac) {
        return Ok(false);
    }
    match ap_native::get_var(runtime, guard, "sta_info", &mac, 512).await {
        Err(Error::Firmware(code)) if code as i32 == -30 => Ok(true), // BCME_NOTFOUND
        Ok(_) => Ok(false), // Do not invent native SCB absence from host denial.
        Err(error) => Err(error),
    }
}
impl Session {
    pub(crate) async fn service<R: Fullmac>(
        &mut self,
        station: &mut Station<R>,
    ) -> Result<(), Error> {
        self.current()?;
        if !self.running.load(Ordering::Acquire) || self.busy {
            return Ok(());
        }
        if !self.prefix(&mut station.runtime)? {
            return Ok(());
        }
        let native = self.base.native.clone();
        let stop = Guard::Stop(&native);
        let mut index = 0;
        while index < self.rejected.len() {
            let mac = self.rejected[index].mac;
            if !self.rejected[index].sent {
                self.rejected[index].sent = true;
                self.rejected[index].deadline = Some(narf_time::Deadline::after_ms(2000));
                ap_native::command(
                    &mut station.runtime,
                    &stop,
                    Direction::Set,
                    ap_wire::DEAUTH_REASON,
                    &ap_wire::deauth(mac, 17)?,
                    12,
                )
                .await?;
            }
            self.prefix(&mut station.runtime)?;
            let receipt = self.rejected[index].epoch.capture();
            if absent(&mut station.runtime, &stop, mac).await?
                && station.runtime.ap_retire_peer(mac)?
                && self.prefix(&mut station.runtime)?
                && receipt.current()
            {
                self.rejected.remove(index);
            } else {
                if self.rejected[index]
                    .deadline
                    .is_some_and(|deadline| deadline.expired())
                {
                    return Err(Error::Timeout);
                }
                index += 1;
            }
        }
        for index in 0..self.peers.len() {
            if self.peers[index].remove_requested {
                self.retire_peer(station, index).await?;
                continue;
            }
            if !self.peers[index].verify {
                continue;
            }
            let mac = self.peers[index].mac;
            // Close host copies/port before any firmware wait; the capture
            // retains this original post-denial peer, not a later same-MAC.
            self.peers[index]
                .data
                .advance()
                .map_err(|_| Error::Failed)?;
            let original = self.capture(Use::Lifecycle, Some(mac), Some(&self.peers[index]));
            let guard = Guard::Program(&original);
            let observed = match ap_peer::query(&mut station.runtime, &guard, mac).await {
                Ok(observed) => observed,
                Err(_) => {
                    self.peers[index].deny(false)?;
                    self.peers[index].remove_requested = true;
                    continue;
                }
            };
            let automatic = !self.plan.config.privacy && !self.plan.settings.control_port.enabled;
            ap_native::command(
                &mut station.runtime,
                &guard,
                Direction::Set,
                if automatic {
                    ap_wire::AUTHORIZE
                } else {
                    ap_wire::DEAUTHORIZE
                },
                &mac,
                6,
            )
            .await?;
            // All old completed RX copies are consumed/dropped while this
            // peer still has no host port. No firmware FIFO/key quiescence is
            // inferred, and newly authorized data cannot recapture old copies.
            self.prefix(&mut station.runtime)?;
            if original.current().is_err() {
                self.current()?;
                continue;
            }
            let current = ap_peer::query(&mut station.runtime, &guard, mac).await?;
            if (current.flags & 0x20 != 0) != automatic
                || current.capability != observed.capability
                || current.rates != observed.rates
            {
                return Err(Error::Malformed);
            }
            self.prefix(&mut station.runtime)?;
            if original.current().is_err() {
                self.current()?;
                continue;
            }
            let peer = &mut self.peers[index];
            peer.observed = Some(current);
            peer.associated = true;
            peer.authorized = automatic;
            peer.authorization = automatic.then(|| self.base.source.clone());
            peer.verify = false;
            peer.notified = true;
            let generation = self.generation()?;
            let original = self.capture(Use::Receive, Some(mac), Some(&self.peers[index]));
            self.queue(
                Event::Associated {
                    peer: mac,
                    generation,
                    ies: self.peers[index].ies.clone(),
                },
                original,
            )?;
        }
        // A copied loss/control event owns a counted lease, so a callback
        // cannot prune its native peer and silently rebind its final proof.
        self.peers
            .retain(|peer| !(peer.removed && peer.absent && !peer.notified && peer.unused()));
        Ok(())
    }
    pub(super) async fn retire_peer<R: Fullmac>(
        &mut self,
        station: &mut Station<R>,
        index: usize,
    ) -> Result<bool, Error> {
        let mac = self.peers[index].mac;
        let native = self.base.native.clone();
        let stop = Guard::Stop(&native);
        if !self.peers[index].delete_sent {
            self.peers[index].delete_sent = true;
            self.peers[index].removal_deadline = Some(narf_time::Deadline::after_ms(2000));
            if !absent(&mut station.runtime, &stop, mac).await? {
                ap_native::command(
                    &mut station.runtime,
                    &stop,
                    Direction::Set,
                    ap_wire::DEAUTHORIZE,
                    &mac,
                    6,
                )
                .await?;
                ap_native::command(
                    &mut station.runtime,
                    &stop,
                    Direction::Set,
                    ap_wire::DEAUTH_REASON,
                    &ap_wire::deauth(mac, self.peers[index].removal_reason)?,
                    12,
                )
                .await?;
            }
        }
        self.prefix(&mut station.runtime)?;
        let receipt = self.peers[index].epoch.capture();
        if absent(&mut station.runtime, &stop, mac).await?
            && station.runtime.ap_retire_peer(mac)?
            && self.prefix(&mut station.runtime)?
            && receipt.current()
        {
            self.peers[index].absent = true;
            self.peers[index].removed = true;
            self.peers[index].remove_requested = false;
            return Ok(true);
        }
        if self.peers[index]
            .removal_deadline
            .is_some_and(|deadline| deadline.expired())
        {
            return Err(Error::Timeout);
        }
        Ok(false)
    }

    pub(crate) async fn authorize<R: Fullmac>(
        &mut self,
        station: &mut Station<R>,
        config: &narf_wireless::StationConfig,
        source: narf_wireless::ap_control::ApEmissionAuthority,
    ) -> Result<(), Error> {
        self.current()?;
        // Firmware AP SME supplied association/AID/rates. This command only
        // implements the source's AUTHORIZED transition; it cannot rewrite
        // a caller's synthetic association or enable unsupported PHY/WMM.
        if !self.active()
            || config.aid != 0
            || config.listen_interval != 0
            || !config.supported_rates.is_empty()
            || config.wme.is_some()
            || config.uapsd_queues.is_some()
            || config.uapsd_max_sp.is_some()
            || config.mfp.is_some()
            || config.capability.is_some()
            || config.ext_capability.is_some()
            || config.ht_capability.is_some()
            || config.vht_capability.is_some()
            || config.he_capability.is_some()
            || config.he_6ghz_capability.is_some()
            || config.station_tx_power.is_some()
        {
            return Err(Error::Unsupported);
        }
        let value = config.authorized.ok_or(Error::Unsupported)?;
        let index = self
            .peers
            .iter()
            .position(|peer| peer.mac == config.mac && peer.associated && !peer.removed)
            .ok_or(Error::Unsupported)?;
        if value
            && self.plan.config.privacy
            && !self.peers[index]
                .key
                .as_ref()
                .is_some_and(super::ap_key::Installed::current)
        {
            return Err(Error::Authority);
        }
        let original = self.command_capture(source.clone(), Some(&self.peers[index]))?;
        let operation = self.operation()?;
        self.peers[index]
            .data
            .advance()
            .map_err(|_| Error::Failed)?;
        self.group_data.advance().map_err(|_| Error::Failed)?;
        self.peers[index].authorized = false;
        self.peers[index].authorization = None;
        if !self.prefix(&mut station.runtime)? {
            return Err(Error::Busy);
        }
        original.current().map_err(|_| Error::Authority)?;
        let guard = Guard::Program(&original);
        ap_native::command(
            &mut station.runtime,
            &guard,
            Direction::Set,
            if value {
                ap_wire::AUTHORIZE
            } else {
                ap_wire::DEAUTHORIZE
            },
            &config.mac,
            6,
        )
        .await?;
        if !self.prefix(&mut station.runtime)? {
            return Err(Error::Busy);
        }
        let observed = ap_peer::query(&mut station.runtime, &guard, config.mac).await?;
        if (observed.flags & 0x20 != 0) != value {
            return Err(Error::Malformed);
        }
        if !self.prefix(&mut station.runtime)? {
            return Err(Error::Busy);
        }
        original.current().map_err(|_| Error::Authority)?;
        if value
            && self.plan.config.privacy
            && !self.peers[index]
                .key
                .as_ref()
                .is_some_and(super::ap_key::Installed::current)
        {
            return Err(Error::Authority);
        }
        self.peers[index].authorized = value;
        self.peers[index].authorization = value.then_some(source);
        self.peers[index].observed = Some(observed);
        self.busy = false;
        operation.finish();
        Ok(())
    }

    pub(crate) async fn remove_station<R: Fullmac>(
        &mut self,
        station: &mut Station<R>,
        mac: Option<[u8; 6]>,
        reason: u16,
        source: narf_wireless::ap_control::ApEmissionAuthority,
    ) -> Result<(), Error> {
        self.current()?;
        if !self.active() || reason == 0 || mac.is_some_and(|mac| !ap_wire::unicast(mac)) {
            return Err(Error::Unsupported);
        }
        self.command_capture(source.clone(), None)?;
        let targets: alloc::vec::Vec<_> = self
            .peers
            .iter()
            .enumerate()
            .filter(|(_, peer)| mac.is_none_or(|mac| peer.mac == mac) && !peer.absent)
            .map(|(index, _)| index)
            .collect();
        if targets.is_empty() {
            return Err(Error::Firmware((-30i32) as u32));
        }
        let operation = self.operation()?;
        self.group_data.advance().map_err(|_| Error::Failed)?;
        for &index in &targets {
            self.peers[index].deny(false)?;
            self.peers[index].remove_requested = true;
            self.peers[index].removal_reason = reason;
        }
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            let mut complete = true;
            for &index in &targets {
                complete &= self.retire_peer(station, index).await?;
            }
            if complete {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
        if !source.current() {
            return Err(Error::Authority);
        }
        self.current()?;
        self.busy = false;
        operation.finish();
        Ok(())
    }
}
