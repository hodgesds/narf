// SPDX-License-Identifier: GPL-2.0-or-later
//! Secondary-bsscfg firmware-SME AP of an AP [`VifDevice`] shell (Linux
//! 7.3-rc4 `cfg80211.c` `brcmf_cfg80211_start_ap`, `_stop_ap`,
//! `_change_beacon`, `_del_station`, `_change_station`, key ops on a
//! secondary `ifp`).
//!
//! The shell owns its own AP host state (`interface_ap::Host`: mode
//! generation, control reservation, staged keys, event source). Every
//! native step runs in the primary [`Device`] under its state mutex, with
//! the shell's persistent secondary `Station` rebound to the
//! `vif_bsscfg::Bsscfg` adapter, so the unchanged `brcmfmac::ap::Session`
//! drives that bsscfg on its own ifidx through the transport's per-ifidx
//! AP owner (`Fullmac::*_on`). `Session::prepare_secondary` applies the
//! `ap_native::Scope::Secondary` rules (no device-wide `event_msgs`
//! replacement, `nmode`, `vhtmode` or `qtxpower`). The same request,
//! emission and fixed-capture checks as the primary AP frontend gate every
//! publication; the shell carrier is up only between a committed START and
//! STOP/failure.
use super::*;
use crate::brcmfmac::{
    ap::{Event as ApEvent, Mode, Received, Session},
    ap_native::Scope,
    ap_scope::Capture,
};
use core::{num::NonZeroU64, task::Waker};
use narf_wireless::ap_control::{ApControlAuthority, ApEmissionAuthority};

pub(super) use super::super::ap::Operation;
use super::super::ap::Staging;

/// One received AP record for delivery after the state lock is released.
pub(super) type Delivery = (Arc<VifDevice>, Received);

impl VifDevice {
    pub(super) fn ap_capable(&self) -> bool {
        matches!(self.role, Role::Ap | Role::P2pGo)
            && self.phase() == LIVE
            && !self.closing.load(Ordering::Acquire)
            && self.ap.capable.load(Ordering::Acquire)
    }
    pub(super) fn ap_generation(&self) -> Option<NonZeroU64> {
        self.ap_capable()
            .then(|| self.ap.generation.load(Ordering::Acquire))
            .and_then(NonZeroU64::new)
            .filter(|value| value.get() != u64::MAX)
    }
    fn ap_role_matches(&self, source: &ApEmissionAuthority) -> bool {
        self.ap_generation()
            .is_some_and(|generation| source.matches_role(self, self.current_iftype(), generation))
    }
    /// AP carrier: up after a committed START (`brcmf_net_setcarrier(ifp,
    /// true)`), down on STOP or failure. No station disconnect is notified.
    pub(super) fn ap_set_carrier(&self, up: bool) {
        let went_down = {
            let _publication = self.publication.lock();
            let up = up && !self.closing.load(Ordering::Acquire);
            let was_up = self.up.swap(up, Ordering::AcqRel);
            if was_up != up {
                self.epoch.fetch_add(1, Ordering::AcqRel);
                narf_net::iface::set_link_metadata(&self.name, up, None, None);
            }
            was_up && !up
        };
        if went_down {
            self.drop_queued();
        }
    }
    /// A new AP data generation (peer/key epoch) invalidates every queued
    /// host frame, as the primary's `ap_sync_queue` does.
    fn ap_sync(&self, session: Option<&Session>) {
        let generation = session.map_or(0, Session::data_generation);
        if self.ap_data.swap(generation, Ordering::AcqRel) != generation {
            self.epoch.fetch_add(1, Ordering::AcqRel);
            self.pending.lock().take();
        }
    }
    /// Retire the AP host state with the shell (`brcmf_remove_interface`).
    pub(super) fn ap_retire(&self) {
        self.ap.retire();
    }
    fn this(&self) -> Result<Arc<VifDevice>, WirelessError> {
        SHELLS
            .lock()
            .iter()
            .find(|shell| core::ptr::eq(Arc::as_ptr(shell), self))
            .cloned()
            .ok_or(WirelessError::NotSupported)
    }
    /// The shell's AP control entry: reaches its wiphy's primary owner.
    pub(super) async fn ap_operation(
        &self,
        authority: &ApControlAuthority,
        operation: Operation,
    ) -> Result<bool, WirelessError> {
        if !self.ap_capable() {
            return Err(WirelessError::NotSupported);
        }
        let shell = self.this()?;
        let roles = primary(self.wiphy).ok_or(WirelessError::HardwareError)?;
        roles.vif_ap_control(shell, authority, operation).await
    }
}

/// The secondary AP slot of `cookie` with its station rebound, for `$body`.
macro_rules! with_ap {
    ($state:expr, $cookie:expr, |$station:ident, $ap:ident| $body:expr) => {{
        let State {
            station: primary,
            vif,
            secondaries,
            ..
        } = &mut *$state;
        match (
            vif.as_mut(),
            secondaries.iter_mut().find(|slot| slot.cookie == $cookie),
        ) {
            (Some(owner), Some(slot)) => match slot.station.take() {
                Some(parked) => {
                    let adapter = Bsscfg::new(&mut primary.runtime, owner, &mut slot.link);
                    let (mut $station, rest) = parked.rebind(adapter);
                    let $ap = &mut slot.ap;
                    let result = $body;
                    let (parked, _) = $station.rebind(rest);
                    slot.station = Some(parked);
                    Some(result)
                }
                None => None,
            },
            _ => None,
        }
    }};
}

impl<R: Fullmac + 'static> Device<R> {
    /// Fixed-capture final check: the bsscfg's actual completed prefix.
    fn secondary_ap_final(&self, shell: &VifDevice, original: &Capture) -> bool {
        if self.withdrawn() || !shell.ap_capable() {
            return false;
        }
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        let idle = with_ap!(state, shell.cookie, |station, ap| match ap.as_mut() {
            Some(session) => {
                let idle = session.prefix(&mut station.runtime).is_ok_and(|idle| idle);
                shell.ap_sync(Some(session));
                idle
            }
            None => false,
        });
        idle == Some(true) && original.current().is_ok()
    }

    pub(super) async fn secondary_ap_control(
        &self,
        shell: &Arc<VifDevice>,
        authority: &ApControlAuthority,
        operation: Operation,
    ) -> Result<bool, WirelessError> {
        let host = &shell.ap;
        authority.check_for(shell.as_ref())?;
        if !shell.ap_capable() || !authority.has_reservation() {
            return Err(WirelessError::Denied);
        }
        let source = authority.native_emission_for(shell.as_ref())?;
        if !shell.ap_role_matches(&source) || !source.watch(&Waker::from(host.wake.clone())) {
            return Err(WirelessError::Denied);
        }
        let starting = matches!(&operation, Operation::Start(..));
        let stopping = matches!(&operation, Operation::Stop);
        let event = if starting {
            Some(authority.event_authority()?)
        } else {
            None
        };
        let policy = if starting {
            Some(self.lifecycle.ap.policy().map_err(wireless_error)?)
        } else {
            None
        };
        let mut state = self.state.lock().await;
        if !shell.ap_role_matches(&source) {
            return Err(WirelessError::Denied);
        }
        // The primary must be a station or an AP (never monitor), as for
        // the secondary station (`brcmf_vif_change_validate`).
        if self.withdrawn() || !matches!(self.ap_mode(), 2 | 3) {
            return Err(WirelessError::NotSupported);
        }
        let cookie = shell.cookie;
        let running = state
            .secondaries
            .iter()
            .any(|slot| slot.cookie == cookie && slot.ap.is_some());
        if !running
            && matches!(
                &operation,
                Operation::Key(_) | Operation::DeleteKey(..) | Operation::DefaultKey(..)
            )
        {
            let result = host.stage(operation, source.clone());
            drop(state);
            authority.check_for(shell.as_ref())?;
            authority.require_up()?;
            if !source.current() {
                *host.staging.lock() = Staging::default();
                return Err(WirelessError::Denied);
            }
            return result.map(|_| false).map_err(wireless_error);
        }
        if starting {
            host.serial
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                    old.checked_add(1).filter(|next| *next < u64::MAX)
                })
                .map_err(|_| WirelessError::Denied)?;
        }
        let serial = host.serial.load(Ordering::Acquire);
        let features = state
            .vif
            .as_ref()
            .map(|owner| owner.features())
            .ok_or(WirelessError::Denied)?;
        // A P2P GO starts on its own connection bsscfg (`Scope::Go`).
        let scope = if shell.role == Role::P2pGo {
            let bsscfgidx = state
                .secondaries
                .iter()
                .find(|slot| slot.cookie == cookie)
                .map(|slot| slot.link.entry().bsscfgidx)
                .ok_or(WirelessError::Denied)?;
            Scope::Go { bsscfgidx }
        } else {
            Scope::secondary(features)
        };
        let mode = Mode {
            generation: host.generation.clone(),
            value: host.generation.load(Ordering::Acquire),
        };
        let history = host.history.clone();
        let other_ap = state.ap.is_some()
            || state
                .secondaries
                .iter()
                .any(|slot| slot.cookie != cookie && slot.ap.is_some());
        if starting {
            shell.ap_set_carrier(false);
        }
        let outcome = with_ap!(state, cookie, |station, ap| {
            let stop_native = if stopping {
                ap.as_ref().map(|session| session.native_source())
            } else {
                None
            };
            let result = async {
                match operation {
                    Operation::Start(config, settings) => {
                        if ap.is_some() || station.ap_station_busy() {
                            return Err(Error::Busy);
                        }
                        // Linux `vif->mbss` (another AP already created)
                        // skips the shared radio setup; that MBSS path is
                        // not implemented, so this AP must be the only one.
                        if other_ap {
                            return Err(Error::Unsupported);
                        }
                        let session = Session::prepare_secondary(
                            &station,
                            *config,
                            *settings,
                            source.clone(),
                            policy.unwrap(),
                            mode,
                            history,
                            scope,
                        )?;
                        // Stored before the first wait: a dropped START keeps
                        // a real cleanup owner in the slot.
                        let session = ap.insert(Box::new(session));
                        session.start(&mut station).await?;
                        let staged = core::mem::take(&mut *host.staging.lock());
                        let selected = staged.default.as_ref().map(|(index, _)| *index);
                        let mut keys = staged.keys;
                        keys.sort_by_key(|key| Some(key.key.params().idx) == selected);
                        for key in keys {
                            session
                                .add_key(&mut station, key.key.params(), key.source)
                                .await?;
                        }
                        if let Some((index, original)) = staged.default {
                            session.default_key(index, false, true, false, false, original)?;
                        }
                        session.commit_start()?;
                        Ok(false)
                    }
                    Operation::Stop => {
                        shell.ap_set_carrier(false);
                        match ap.as_mut() {
                            Some(session) => session.stop(&mut station).await.map(|_| false),
                            None => Err(Error::Unsupported),
                        }
                    }
                    operation => {
                        let session = ap.as_mut().ok_or(Error::Unsupported)?;
                        match operation {
                            Operation::Beacon(head, tail, probe) => session
                                .beacon(&mut station, head, tail, probe, source.clone())
                                .await
                                .map(|_| false),
                            Operation::Set(config) => session
                                .authorize(&mut station, &config, source.clone())
                                .await
                                .map(|_| false),
                            Operation::Delete(peer, reason) => session
                                .remove_station(&mut station, peer, reason, source.clone())
                                .await
                                .map(|_| false),
                            Operation::Key(key) => session
                                .add_key(&mut station, key.params(), source.clone())
                                .await
                                .map(|_| false),
                            Operation::DeleteKey(index, pairwise, peer) => session
                                .delete_key(&mut station, index, pairwise, peer, source.clone())
                                .await
                                .map(|_| false),
                            Operation::DefaultKey(index, flags) => session
                                .default_key(
                                    index,
                                    flags.0,
                                    flags.1,
                                    flags.2,
                                    flags.3,
                                    source.clone(),
                                )
                                .map(|_| false),
                            Operation::Control(request) => {
                                session
                                    .control(&mut station, &request, source.clone())
                                    .await
                            }
                            _ => Err(Error::Unsupported),
                        }
                    }
                }
            }
            .await;
            if stopping && result.is_ok() {
                *ap = None;
                host.events.lock().take();
            }
            shell.ap_sync(ap.as_deref());
            if result.is_err()
                && (starting
                    || ap
                        .as_ref()
                        .is_some_and(|session| session.cleanup_required()))
            {
                if let Some(session) = ap.as_mut() {
                    session.fail();
                }
                shell.ap_set_carrier(false);
            }
            let publication = if result.is_ok() && !stopping {
                ap.as_ref().and_then(|session| session.completion().ok())
            } else {
                None
            };
            (result, stop_native, publication)
        });
        drop(state);
        let (result, stop_native, publication) = outcome.ok_or(WirelessError::Denied)?;
        authority.check_for(shell.as_ref())?;
        authority.require_up()?;
        if !source.current() {
            shell.ap_set_carrier(false);
            return Err(WirelessError::Denied);
        }
        let result = result.map_err(wireless_error)?;
        if stopping {
            let state = self.state.lock().await;
            if state
                .secondaries
                .iter()
                .any(|slot| slot.cookie == cookie && slot.ap.is_some())
                || host.serial.load(Ordering::Acquire) != serial
                || !shell.ap_role_matches(&source)
            {
                return Err(WirelessError::Denied);
            }
            stop_native
                .ok_or(WirelessError::Denied)?
                .invoke(|| source.current() && host.serial.load(Ordering::Acquire) == serial)
                .map_err(|_| WirelessError::Denied)?
                .then_some(())
                .ok_or(WirelessError::Denied)?;
        } else {
            let original = publication.ok_or(WirelessError::Denied)?;
            if !self.secondary_ap_final(shell, &original) {
                return Err(WirelessError::Denied);
            }
            original
                .publish(|| {
                    if starting {
                        *host.events.lock() = event;
                        shell.ap_set_carrier(true);
                    }
                })
                .map_err(|_| WirelessError::Denied)?;
        }
        Ok(result)
    }

    /// Deliver received AP records outside every state/ring guard; each
    /// passes the fixed-capture final check first, as the primary's
    /// `ap_drain` does.
    pub(super) fn secondary_ap_deliver(&self, received: Vec<Delivery>) {
        for (shell, received) in received {
            let Received {
                event,
                original,
                lease: _lease,
            } = received;
            match event {
                ApEvent::Data(mut bytes) => {
                    if !self.secondary_ap_final(&shell, &original) {
                        continue;
                    }
                    let frame =
                        narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                            .ok()
                            .map(|buffer| {
                                let mut frame = Frame::new(buffer, bytes.len() as u32);
                                frame.payload_mut().copy_from_slice(&bytes);
                                frame
                            });
                    let admitted = original
                        .publish(|| {
                            let _publication = shell.publication.lock();
                            if !shell.up.load(Ordering::Acquire) {
                                return false;
                            }
                            if let (Some(frame), Some(rx)) =
                                (frame, shell.rx_producer.lock().as_mut())
                            {
                                let _ = rx.try_send(frame);
                            }
                            true
                        })
                        .unwrap_or(false);
                    if admitted && self.secondary_ap_final(&shell, &original) {
                        let _ = original.publish(|| {
                            narf_net::iface::on_rx_frame_from(&shell.name, &mut bytes);
                        });
                    }
                }
                event => {
                    let Some(source) = shell.ap.events.lock().clone() else {
                        continue;
                    };
                    let prepared = match event {
                        ApEvent::Associated {
                            peer,
                            generation,
                            ies,
                        } => source.prepare_station_associated(peer, generation, &ies),
                        ApEvent::Lost { peer, generation } => {
                            source.prepare_station_lost(peer, generation)
                        }
                        ApEvent::Control {
                            peer,
                            protocol,
                            pdu,
                        } => source.prepare_control_received(peer, protocol, &pdu, false),
                        ApEvent::Data(_) => continue,
                    };
                    if let Ok(prepared) = prepared {
                        if self.secondary_ap_final(&shell, &original) {
                            let _ = original.publish(|| prepared.deliver());
                        }
                    }
                }
            }
        }
    }
}

/// One worker pass of a live AP shell under the primary state mutex:
/// native AP service, one TX step from the shell ring, and the records to
/// deliver. Returns false when the role is gone (the shell then retires).
pub(super) async fn secondary_ap_pass<R: Fullmac>(
    runtime: &mut R,
    owner: &mut Owner,
    slot: &mut Secondary<R>,
    shell: &Arc<VifDevice>,
    delivered: &mut Vec<Delivery>,
) -> bool {
    let Some(parked) = slot.station.take() else {
        return false;
    };
    let (mut station, rest) = parked.rebind(Bsscfg::new(runtime, owner, &mut slot.link));
    let mut alive = true;
    let mut cleared = false;
    match slot.ap.as_mut() {
        None => {
            // No BSS: nothing on this ifidx is admitted to the host.
            let _ = station.runtime.poll();
            while station.runtime.pop_data().is_some() {}
            while station.runtime.pop_event().is_some() {}
        }
        Some(session) => {
            let result = if session.cleanup_required() {
                Err(Error::Authority)
            } else {
                match session.service(&mut station).await {
                    Ok(()) => transmit(&mut station, session, shell, &mut slot.ap_tx),
                    Err(error) => Err(error),
                }
            };
            shell.ap_sync(Some(session));
            match result {
                Ok(()) => {
                    delivered.extend(
                        session
                            .take_received()
                            .into_iter()
                            .map(|received| (shell.clone(), received)),
                    );
                }
                Err(_) => {
                    shell.ap_set_carrier(false);
                    session.fail();
                    if session.stop(&mut station).await.is_ok() {
                        cleared = true;
                        shell.ap.events.lock().take();
                        *shell.ap.staging.lock() = Staging::default();
                    } else {
                        // The bsscfg is fail-stopped; the transport's AP
                        // owner of this ifidx retires its flows/TX on
                        // removal (`ap_leave_on`), never by host fiat.
                        station.runtime.fail();
                        alive = false;
                    }
                }
            }
        }
    }
    let (parked, _) = station.rebind(rest);
    slot.station = Some(parked);
    if cleared {
        slot.ap = None;
        slot.ap_tx = None;
    }
    alive && !slot.link.failed()
}

/// A shell frame retained with the original data capture it was queued
/// under and that capture's data generation (never recaptured on Busy).
pub(super) type PendingTx = Option<(Frame, Capture, u64)>;

/// One TX step: the shell's next Ethernet frame under its data capture.
fn transmit<R: Fullmac>(
    station: &mut Station<R>,
    session: &mut Session,
    shell: &VifDevice,
    pending: &mut PendingTx,
) -> Result<(), Error> {
    if pending.as_ref().is_some_and(|(_, original, generation)| {
        *generation != session.data_generation() || original.current().is_err()
    }) {
        *pending = None;
    }
    if !shell.up.load(Ordering::Acquire) || !session.active() {
        return Ok(());
    }
    if pending.is_none() {
        let next = shell
            .tx_consumer
            .lock()
            .as_mut()
            .and_then(|tx| tx.try_recv().ok().flatten());
        let Some(frame) = next else {
            return Ok(());
        };
        if !super::super::ap::ethernet(frame.payload())
            || frame.tx_meta().csum_l4.is_some()
            || frame.tx_meta().tso_mss.is_some()
            || frame.tx_meta().vlan_tag.is_some()
        {
            return Ok(());
        }
        let Ok(original) = session.data_capture(frame.payload()) else {
            return Ok(());
        };
        *pending = Some((frame, original, session.data_generation()));
    }
    let Some((frame, original, _)) = pending.as_ref() else {
        return Ok(());
    };
    match session.begin_data(station, frame.payload(), original) {
        Ok(_ticket) => *pending = None,
        Err(Error::Busy) => {}
        Err(Error::Authority | Error::Unsupported | Error::Malformed) => *pending = None,
        Err(error) => return Err(error),
    }
    Ok(())
}

/// `brcmf_cfg80211_del_ap_iface` before `interface_remove`: stop a running
/// AP on its bsscfg. A failed stop fail-stops the bsscfg; the transport's
/// per-ifidx owner still retires its flows/TX afterwards (`ap_leave_on`).
pub(super) async fn secondary_ap_stop<R: Fullmac>(
    runtime: &mut R,
    owner: &mut Owner,
    slot: &mut Secondary<R>,
) {
    let Some(parked) = slot.station.take() else {
        return;
    };
    let (mut station, rest) = parked.rebind(Bsscfg::new(runtime, owner, &mut slot.link));
    let stopped = match slot.ap.as_mut() {
        Some(session) => session.stop(&mut station).await.is_ok(),
        None => true,
    };
    if !stopped {
        station.runtime.fail();
    }
    let (parked, _) = station.rebind(rest);
    slot.station = Some(parked);
    slot.ap = None;
    slot.ap_tx = None;
}
