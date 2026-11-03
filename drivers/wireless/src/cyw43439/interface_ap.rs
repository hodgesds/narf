// SPDX-License-Identifier: GPL-2.0-or-later
//! Original-authority firmware-SME AP frontend. Dynamic endpoint checks and
//! prepared events execute outside State; only retained fixed proofs reach
//! the actual native owner and final copied publication.
use super::*;
use crate::brcmfmac::{
    ap::{Event as ApEvent, Session},
    ap_scope::{Capture, Policy},
};
use core::{num::NonZeroU64, task::Waker};
use narf_wireless::ap_control::{
    ApControlAuthority, ApEmissionAuthority, ApEventAuthority, ExclusiveControl,
};

pub(super) struct WakeOwner {
    signal: IrqSafeSpinLock<Option<Arc<crate::brcmfmac::irq::Signal>>>,
}
impl alloc::task::Wake for WakeOwner {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(signal) = self.signal.lock().clone() {
            signal.raise();
        }
    }
}
struct Staged {
    key: narf_wireless::OwnedKey,
    source: ApEmissionAuthority,
}
#[derive(Default)]
struct Staging {
    keys: Vec<Staged>,
    default: Option<(u8, ApEmissionAuthority)>,
}
pub(super) struct Host {
    pub(super) capable: AtomicBool,
    pub(super) mode: AtomicU8,
    pub(super) generation: Arc<AtomicU64>,
    serial: AtomicU64,
    pub(super) control: Arc<ExclusiveControl>,
    wake: Arc<WakeOwner>,
    events: IrqSafeSpinLock<Option<ApEventAuthority>>,
    staging: IrqSafeSpinLock<Staging>,
    history: Arc<IrqSafeSpinLock<crate::brcmfmac::ap_key::History>>,
    pub(super) identity: IrqSafeSpinLock<Option<narf_net::iface::NetIfaceSnapshot>>,
    #[cfg(any(test, feature = "kernel-test"))]
    database: IrqSafeSpinLock<Option<Arc<narf_wireless::reg::db::Database>>>,
}
impl Host {
    pub(super) fn new() -> Self {
        Self {
            capable: AtomicBool::new(false),
            mode: AtomicU8::new(2),
            generation: Arc::new(AtomicU64::new(1)),
            control: Arc::new(ExclusiveControl::new()),
            serial: AtomicU64::new(1),
            wake: Arc::new(WakeOwner {
                signal: IrqSafeSpinLock::new(None),
            }),
            events: IrqSafeSpinLock::new(None),
            staging: IrqSafeSpinLock::new(Staging::default()),
            history: Arc::new(IrqSafeSpinLock::new(Default::default())),
            identity: IrqSafeSpinLock::new(None),
            #[cfg(any(test, feature = "kernel-test"))]
            database: IrqSafeSpinLock::new(None),
        }
    }
    pub(super) fn policy(&self) -> Result<Policy, Error> {
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(database) = self.database.lock().clone() {
            return Policy::scoped(database).map_err(|_| Error::Authority);
        }
        Policy::installed().map_err(|_| Error::Authority)
    }
    pub(super) fn retire(&self) {
        self.generation.store(u64::MAX, Ordering::Release);
        self.events.lock().take();
        *self.staging.lock() = Staging::default();
        alloc::task::Wake::wake_by_ref(&self.wake);
    }
}
pub(super) enum Operation {
    Start(
        Box<narf_wireless::ApConfig>,
        Box<narf_wireless::ApStartSettings>,
    ),
    Stop,
    Beacon(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>),
    Set(narf_wireless::StationConfig),
    Delete(Option<[u8; 6]>, u16),
    Key(narf_wireless::OwnedKey),
    DeleteKey(u8, bool, Option<[u8; 6]>),
    DefaultKey(u8, (bool, bool, bool, bool)),
    Control(narf_wireless::ControlPortTxRequest),
}
pub(super) fn errno(error: WirelessError) -> i32 {
    match error {
        WirelessError::Denied => 1,
        WirelessError::Busy => 16,
        WirelessError::InvalidArgs => 22,
        WirelessError::NotSupported => 95,
        WirelessError::Timeout => 110,
        WirelessError::HardwareError => 5,
    }
}
pub(super) fn ethernet(bytes: &[u8]) -> bool {
    (14..=1514).contains(&bytes.len())
        && bytes[..6] != [0; 6]
        && bytes[6..12] != [0; 6]
        && bytes[6] & 1 == 0
        && u16::from_be_bytes([bytes[12], bytes[13]]) >= 0x600
        && !matches!(u16::from_be_bytes([bytes[12], bytes[13]]), 0x888e | 0x88c7)
}

impl<R: Fullmac> State<R> {
    fn ap_sync_queue(&mut self) {
        let generation = self
            .ap
            .as_ref()
            .map_or(0, |session| session.data_generation());
        if generation != self.ap_data_generation {
            self.clear_transmit();
            self.ap_data_generation = generation;
            self.ap_epoch_changed = true;
        }
    }
    pub(super) fn ap_progress(&mut self) -> Result<(), Error> {
        let Some(ap) = self.ap.as_mut() else {
            return Ok(());
        };
        if !ap.active() {
            return Err(Error::Authority);
        }
        if self.pending.is_none() {
            for _ in 0..TX_RING_N {
                let Ok(Some(frame)) = self.tx.try_recv() else {
                    break;
                };
                if !ethernet(frame.payload())
                    || frame.tx_meta().csum_l4.is_some()
                    || frame.tx_meta().tso_mss.is_some()
                    || frame.tx_meta().vlan_tag.is_some()
                {
                    continue;
                }
                let Ok(original) = ap.data_capture(frame.payload()) else {
                    continue;
                };
                self.pending = Some(PendingTx {
                    frame,
                    original: Some(original),
                    deadline: narf_time::Deadline::after_ms(2000),
                });
                break;
            }
        }
        // Capture a queued original before draining native events. A loss
        // followed by same-MAC re-add cannot retarget the older Ethernet.
        let idle = ap.prefix(&mut self.station.runtime)?;
        self.ap_sync_queue();
        if !idle {
            return Ok(());
        }
        let ap = self.ap.as_mut().unwrap();
        let Some(pending) = &self.pending else {
            return Ok(());
        };
        let Some(original) = &pending.original else {
            self.pending = None;
            return Ok(());
        };
        if pending.deadline.expired() || original.current().is_err() {
            self.pending = None;
            return Ok(());
        }
        match ap.begin_data(&mut self.station, pending.frame.payload(), original) {
            Ok(_ticket) => {
                self.telemetry.transmitted(
                    crate::ath11k::tx_hdr::classify8021d(pending.frame.payload()),
                    pending.frame.payload().len(),
                );
                self.pending = None;
            }
            Err(Error::Busy) => {}
            Err(Error::Authority | Error::Unsupported | Error::Malformed) => self.pending = None,
            Err(error) => return Err(error),
        }
        Ok(())
    }
}

impl<R: Fullmac + 'static> Device<R> {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn ap_fixture_setup(&self, database: Arc<narf_wireless::reg::db::Database>) {
        *self.lifecycle.ap.database.lock() = Some(database);
        *self.lifecycle.ap.identity.lock() = narf_net::iface::lookup(&self.name);
        self.lifecycle
            .ap
            .capable
            .store(R::PRIMARY_AP, Ordering::Release);
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) async fn sdio_ap_fixture_setup(
        &self,
        database: Arc<narf_wireless::reg::db::Database>,
    ) -> Result<(), Error> {
        self.ap_fixture_setup(database);
        let mut state = self.state.lock().await;
        let capable = super::super::sdio_ap_discovery::discover(&mut state.station.runtime).await?;
        self.lifecycle.ap.capable.store(capable, Ordering::Release);
        Ok(())
    }
    pub(super) fn ap_capable(&self) -> bool {
        R::PRIMARY_AP && self.lifecycle.ap.capable.load(Ordering::Acquire) && !self.withdrawn()
    }
    pub(super) fn ap_mode(&self) -> u32 {
        u32::from(self.lifecycle.ap.mode.load(Ordering::Acquire))
    }
    pub(super) fn ap_generation(&self) -> Option<NonZeroU64> {
        self.ap_capable()
            .then(|| self.lifecycle.ap.generation.load(Ordering::Acquire))
            .and_then(NonZeroU64::new)
            .filter(|value| value.get() != u64::MAX)
    }
    pub(super) fn ap_set_mode(&self, mode: u32) -> Result<(), WirelessError> {
        if !matches!(mode, 2 | 3 | 6)
            || mode == 3 && !self.ap_capable()
            || mode == 6 && !self.monitor_capable()
        {
            return Err(WirelessError::NotSupported);
        }
        let _lease = self.lifecycle.ap.control.try_reserve()?;
        if self.withdrawn() || self.lifecycle.ap.generation.load(Ordering::Acquire) == u64::MAX {
            return Err(WirelessError::Denied);
        }
        if self.up.load(Ordering::Acquire)
            || narf_net::iface::lookup(&self.name).is_some_and(|iface| iface.link_up)
        {
            return Err(WirelessError::Busy);
        }
        let mut state = self.state.try_lock().ok_or(WirelessError::Busy)?;
        if state.ap.is_some() || state.monitor.is_some() || state.station.ap_station_busy() {
            return Err(WirelessError::Busy);
        }
        if mode == 3 {
            state
                .station
                .runtime
                .ap_source()
                .ok_or(WirelessError::NotSupported)?
                .current()
                .map_err(|_| WirelessError::Denied)?;
        }
        // cfg80211.c brcmf_cfg80211_change_iface -> brcmf_vif_change_validate:
        // the primary's new type must fit a combination beside the live
        // secondary interfaces (combo0: primary AP + one secondary STA).
        let primary_role = if mode == 3 {
            crate::brcmfmac::vif_owner::Role::Ap
        } else {
            crate::brcmfmac::vif_owner::Role::Station
        };
        if state
            .vif
            .as_ref()
            .is_some_and(|owner| !owner.can_change_primary(primary_role))
        {
            return Err(WirelessError::Busy);
        }
        if self.ap_mode() == mode {
            return Ok(());
        }
        narf_net::iface::set_link_layer(
            &self.name,
            if mode == 6 {
                narf_net::iface::LinkLayer::Ieee80211Radiotap
            } else {
                narf_net::iface::LinkLayer::Ethernet
            },
        )
        .map_err(|_| WirelessError::Busy)?;
        let _publication = self.publication.lock();
        let next = self
            .lifecycle
            .ap
            .generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .filter(|value| *value < u64::MAX)
            .ok_or(WirelessError::Denied)?;
        self.lifecycle.ap.generation.store(next, Ordering::Release);
        self.lifecycle.ap.mode.store(mode as u8, Ordering::Release);
        if let Some(owner) = state.vif.as_mut() {
            owner.set_primary_role(primary_role);
        }
        self.lifecycle.monitor.clear_selection();
        *self.lifecycle.ap.staging.lock() = Staging::default();
        self.lifecycle.ap.events.lock().take();
        self.external_ops.lock().clear();
        self.power_save.store(0, Ordering::Release);
        self.lifecycle.request.lock().take();
        state.clear_transmit();
        if !self.advance_epoch() {
            self.closing.store(true, Ordering::Release);
            return Err(WirelessError::Denied);
        }
        self.clear_rx();
        Ok(())
    }
    fn ap_authority(
        &self,
        authority: &ApControlAuthority,
    ) -> Result<ApEmissionAuthority, WirelessError> {
        authority.check_for(self)?;
        if !self.ap_capable() || self.ap_mode() != 3 || !authority.has_reservation() {
            return Err(WirelessError::Denied);
        }
        let source = authority.native_emission_for(self)?;
        if !self
            .ap_generation()
            .is_some_and(|generation| source.matches_role(self, 3, generation))
            || !source.watch(&Waker::from(self.lifecycle.ap.wake.clone()))
        {
            return Err(WirelessError::Denied);
        }
        Ok(source)
    }
    fn stage(&self, operation: Operation, source: ApEmissionAuthority) -> Result<(), Error> {
        let mut staged = self.lifecycle.ap.staging.lock();
        if !source.current() {
            return Err(Error::Authority);
        }
        // Erase revoked originals; never recapture one as a new source.
        staged.keys.retain(|old| old.source.current());
        if staged
            .default
            .as_ref()
            .is_some_and(|(_, source)| !source.current())
        {
            staged.default = None;
        }
        match operation {
            Operation::Key(key) => {
                crate::brcmfmac::ap_key::validate(key.params())?;
                if key.params().pairwise {
                    return Err(Error::Unsupported);
                }
                staged
                    .keys
                    .retain(|old| old.key.params().idx != key.params().idx);
                staged.keys.push(Staged { key, source });
            }
            Operation::DeleteKey(index, false, None) if (1..=3).contains(&index) => {
                staged.keys.retain(|old| old.key.params().idx != index);
                if staged
                    .default
                    .as_ref()
                    .is_some_and(|(old, _)| *old == index)
                {
                    staged.default = None;
                }
            }
            Operation::DefaultKey(index, (_, true, false, false))
                if staged.keys.iter().any(|old| old.key.params().idx == index) =>
            {
                staged.default = Some((index, source));
            }
            _ => return Err(Error::Unsupported),
        }
        Ok(())
    }
    pub(super) fn ap_carrier(&self, up: bool) {
        let _publication = self.publication.lock();
        self.bssid.store(0, Ordering::Release);
        let previous = self.up.swap(up, Ordering::AcqRel);
        if previous != up && !self.advance_epoch() {
            self.up.store(false, Ordering::Release);
            self.closing.store(true, Ordering::Release);
            self.lifecycle.ap.retire();
            return;
        }
        if let Some(identity) = self.lifecycle.ap.identity.lock().as_ref() {
            if up {
                narf_net::iface::set_link_metadata_for(identity, true, None, None);
            } else {
                narf_net::iface::withdraw_link_metadata_for(identity);
            }
        }
        if !up {
            self.clear_rx();
        }
    }
    pub(super) fn ap_retire_staging(&self) {
        *self.lifecycle.ap.staging.lock() = Staging::default();
        self.lifecycle.ap.events.lock().take();
    }
    fn ap_sync(&self, state: &mut State<R>) {
        let _publication = self.publication.lock();
        state.ap_sync_queue();
        if core::mem::take(&mut state.ap_epoch_changed) && !self.advance_epoch() {
            if let Some(session) = state.ap.as_mut() {
                session.fail();
            }
            self.closing.store(true, Ordering::Release);
        }
    }
    pub(super) async fn ap_control(
        &self,
        authority: &ApControlAuthority,
        operation: Operation,
    ) -> Result<bool, WirelessError> {
        let source = self.ap_authority(authority)?;
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
        // Recheck the fixed original role after waiting for native State.
        if !self
            .ap_generation()
            .is_some_and(|generation| source.matches_role(self, 3, generation))
        {
            return Err(WirelessError::Denied);
        }
        if state.ap.is_none()
            && matches!(
                &operation,
                Operation::Key(_) | Operation::DeleteKey(..) | Operation::DefaultKey(..)
            )
        {
            let result = self.stage(operation, source.clone());
            drop(state);
            authority.check_for(self)?;
            authority.require_up()?;
            if !source.current() {
                *self.lifecycle.ap.staging.lock() = Staging::default();
                return Err(WirelessError::Denied);
            }
            return result.map(|_| false).map_err(wireless_error);
        }
        let stop_native = if stopping {
            state.ap.as_ref().map(|session| session.native_source())
        } else {
            None
        };
        if starting {
            self.lifecycle
                .ap
                .serial
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                    old.checked_add(1).filter(|next| *next < u64::MAX)
                })
                .map_err(|_| WirelessError::Denied)?;
        }
        let serial = self.lifecycle.ap.serial.load(Ordering::Acquire);
        let result = match operation {
            Operation::Start(config, settings) => {
                if state.ap.is_some() || state.station.ap_station_busy() {
                    return Err(WirelessError::Busy);
                }
                let session = Session::prepare(
                    &state.station,
                    *config,
                    *settings,
                    source.clone(),
                    policy.unwrap(),
                    crate::brcmfmac::ap::Mode {
                        generation: self.lifecycle.ap.generation.clone(),
                        value: self.lifecycle.ap.generation.load(Ordering::Acquire),
                    },
                    self.lifecycle.ap.history.clone(),
                )
                .map_err(wireless_error)?;
                state.clear_transmit();
                self.clear_rx();
                state.ap = Some(Box::new(session));
                // Stored before the first wait: dropped START keeps a real
                // cleanup owner in State, never an unreferenced stack draft.
                let State { station, ap, .. } = &mut *state;
                let session = ap.as_mut().unwrap();
                let result = async {
                    session.start(station).await?;
                    let staged = core::mem::take(&mut *self.lifecycle.ap.staging.lock());
                    // PRIMARY ADD is native GTK selection. Install the staged
                    // chosen default last, without rewriting any prior key.
                    let selected = staged.default.as_ref().map(|(index, _)| *index);
                    let mut keys = staged.keys;
                    keys.sort_by_key(|key| Some(key.key.params().idx) == selected);
                    for key in keys {
                        session
                            .add_key(station, key.key.params(), key.source)
                            .await?;
                    }
                    if let Some((index, original)) = staged.default {
                        session.default_key(index, false, true, false, false, original)?;
                    }
                    session.commit_start()?;
                    Ok::<bool, Error>(false)
                }
                .await;
                result
            }
            Operation::Stop => {
                self.ap_carrier(false);
                state.clear_transmit();
                let State { station, ap, .. } = &mut *state;
                match ap.as_mut() {
                    Some(session) => session.stop(station).await.map(|_| false),
                    None => Err(Error::Unsupported),
                }
            }
            operation => {
                let State { station, ap, .. } = &mut *state;
                let session = ap.as_mut().ok_or(WirelessError::NotSupported)?;
                match operation {
                    Operation::Beacon(head, tail, probe) => session
                        .beacon(station, head, tail, probe, source.clone())
                        .await
                        .map(|_| false),
                    Operation::Set(config) => session
                        .authorize(station, &config, source.clone())
                        .await
                        .map(|_| false),
                    Operation::Delete(peer, reason) => session
                        .remove_station(station, peer, reason, source.clone())
                        .await
                        .map(|_| false),
                    Operation::Key(key) => session
                        .add_key(station, key.params(), source.clone())
                        .await
                        .map(|_| false),
                    Operation::DeleteKey(index, pairwise, peer) => session
                        .delete_key(station, index, pairwise, peer, source.clone())
                        .await
                        .map(|_| false),
                    Operation::DefaultKey(index, flags) => session
                        .default_key(index, flags.0, flags.1, flags.2, flags.3, source.clone())
                        .map(|_| false),
                    Operation::Control(request) => {
                        session.control(station, &request, source.clone()).await
                    }
                    _ => unreachable!(),
                }
            }
        };
        if stopping && result.is_ok() {
            state.ap = None;
            self.lifecycle.ap.events.lock().take();
        }
        self.ap_sync(&mut state);
        if result.is_err()
            && (starting
                || state
                    .ap
                    .as_ref()
                    .is_some_and(|session| session.cleanup_required()))
        {
            if let Some(session) = state.ap.as_mut() {
                session.fail();
            }
            self.ap_carrier(false);
        }
        let publication = if result.is_ok() && !stopping {
            state
                .ap
                .as_ref()
                .and_then(|session| session.completion().ok())
        } else {
            None
        };
        drop(state);
        // All arbitrary interface/socket callbacks are before the final
        // fixed native/source/role proof, with no State lock retained.
        authority.check_for(self)?;
        authority.require_up()?;
        if !source.current() {
            self.ap_carrier(false);
            return Err(WirelessError::Denied);
        }
        let result = result.map_err(wireless_error)?;
        if stopping {
            let state = self.state.lock().await;
            if state.ap.is_some()
                || self.lifecycle.ap.serial.load(Ordering::Acquire) != serial
                || !self
                    .ap_generation()
                    .is_some_and(|generation| source.matches_role(self, 3, generation))
            {
                return Err(WirelessError::Denied);
            }
            stop_native
                .ok_or(WirelessError::Denied)?
                .invoke(|| {
                    source.current() && self.lifecycle.ap.serial.load(Ordering::Acquire) == serial
                })
                .map_err(|_| WirelessError::Denied)?
                .then_some(())
                .ok_or(WirelessError::Denied)?;
        } else {
            let original = publication.ok_or(WirelessError::Denied)?;
            if !self.ap_final(&original) {
                return Err(WirelessError::Denied);
            }
            original
                .publish(|| {
                    if starting {
                        *self.lifecycle.ap.events.lock() = event;
                        self.closing.store(false, Ordering::Release);
                        self.ap_carrier(true);
                    }
                })
                .map_err(|_| WirelessError::Denied)?;
        }
        Ok(result)
    }

    /// Real completed-prefix observation after every arbitrary allocation or
    /// event-preparation callback. This never recaptures the copied owner.
    fn ap_final(&self, original: &Capture) -> bool {
        if self.withdrawn() || self.ap_mode() != 3 {
            return false;
        }
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        let State { station, ap, .. } = &mut *state;
        let Some(session) = ap.as_mut() else {
            return false;
        };
        let idle = session.prefix(&mut station.runtime).is_ok_and(|idle| idle);
        self.ap_sync(&mut state);
        idle && original.current().is_ok()
    }

    pub(super) async fn ap_worker(&self) {
        let Some(mut state) = self.state.try_lock() else {
            return;
        };
        if let Some((signal, _)) = state.station.runtime.wake_source() {
            *self.lifecycle.ap.wake.signal.lock() = Some(signal);
        }
        let result = {
            let State { station, ap, .. } = &mut *state;
            let Some(session) = ap.as_mut() else {
                return;
            };
            if session.cleanup_required() {
                Err(Error::Authority)
            } else {
                session.service(station).await
            }
        };
        self.ap_sync(&mut state);
        if result.is_err() {
            state.clear_transmit();
            self.ap_carrier(false);
            let State { station, ap, .. } = &mut *state;
            let session = ap.as_mut().unwrap();
            session.fail();
            if session.stop(station).await.is_err() {
                // Runtime retains all uncertain mappings. Only existing
                // whole-device teardown/recovery may later reclaim them.
                station.runtime.fail();
                // A dropped native transaction poisoned the command path;
                // existing whole-device CR4/DMA stop may still terminate it
                // under the retained physical owner. No memory is released
                // here and an unproved stop remains pinned/quarantined.
                let _ = station.runtime.stop_transport().await;
                self.closing.store(true, Ordering::Release);
                self.power_save.store(2, Ordering::Release);
                self.lifecycle.ap.retire();
            } else {
                *ap = None;
                self.lifecycle.ap.events.lock().take();
                *self.lifecycle.ap.staging.lock() = Staging::default();
            }
        }
    }

    pub(super) fn ap_drain(&self) -> bool {
        if self.withdrawn() || self.ap_mode() != 3 || self.closing.load(Ordering::Acquire) {
            return false;
        }
        let received = {
            let Some(mut state) = self.state.try_lock() else {
                return false;
            };
            let _publication = self.publication.lock();
            if state.ap.is_none() {
                return false;
            }
            if state.ap_progress().is_err() {
                if let Some(session) = state.ap.as_mut() {
                    session.fail();
                }
                state.clear_transmit();
                drop(_publication);
                self.ap_carrier(false);
                return false;
            }
            if core::mem::take(&mut state.ap_epoch_changed) && !self.advance_epoch() {
                if let Some(session) = state.ap.as_mut() {
                    session.fail();
                }
                self.closing.store(true, Ordering::Release);
                return false;
            }
            state.ap.as_mut().unwrap().take_received()
        };
        let progressed = !received.is_empty();
        let event_source = self.lifecycle.ap.events.lock().clone();
        for received in received {
            // The counted copy lease remains alive through every prepare,
            // allocation and final publication; a known peer cannot be
            // pruned/rebound underneath a copied event.
            let crate::brcmfmac::ap::Received {
                event,
                original,
                lease: _lease,
            } = received;
            match event {
                ApEvent::Data(mut bytes) => {
                    let frame =
                        narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0)
                            .ok()
                            .map(|memory| {
                                let mut frame = Frame::new(memory, bytes.len() as u32);
                                frame.payload_mut().copy_from_slice(&bytes);
                                frame
                            });
                    #[cfg(any(test, feature = "kernel-test"))]
                    self.receive_hook(ReceivePoint::AfterFrameAllocation);
                    // Ordinary peer DATA crosses two independent sinks. Both
                    // re-run the native completed-prefix receipt (a CARD_INT
                    // newly queuing peer loss/key/port records denies) and
                    // the original fixed Capture inside its own source
                    // invocation. A frame denied at the ring boundary is
                    // never later admitted to the stack callback: denial is
                    // monotonic for this copied event, mirroring the station
                    // `deliver_received` break on a failed publication.
                    let admitted = self.ap_final(&original)
                        && original
                            .publish(|| {
                                let Some(mut state) = self.state.try_lock() else {
                                    return false;
                                };
                                // Retain State through the actual ring copy:
                                // a concurrent peer/key transition cannot
                                // finish between its final epoch check and
                                // this independent IPC publication.
                                if original.current().is_err() || state.ap.is_none() {
                                    return false;
                                }
                                if let Some(frame) = frame {
                                    let _ = state.rx.try_send(frame);
                                }
                                true
                            })
                            .unwrap_or(false);
                    if !admitted {
                        continue;
                    }
                    #[cfg(any(test, feature = "kernel-test"))]
                    self.receive_hook(ReceivePoint::BeforeCallback);
                    if self.ap_final(&original) {
                        let _ = original.publish(|| {
                            self.telemetry.received(
                                crate::ath11k::tx_hdr::classify8021d(&bytes),
                                bytes.len(),
                            );
                            narf_net::iface::on_rx_frame_from(&self.name, &mut bytes);
                        });
                    }
                }
                event => {
                    let Some(source) = event_source.as_ref() else {
                        continue;
                    };
                    // No lock/native State survives arbitrary shared source
                    // callbacks. EAPOL's absent NO_ENCRYPT flag is not a
                    // reconstructed firmware encryption/key-index claim.
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
                        ApEvent::Data(_) => unreachable!(),
                    };
                    if let Ok(prepared) = prepared {
                        if self.ap_final(&original) {
                            let _ = original.publish(|| prepared.deliver());
                        }
                    }
                }
            }
        }
        progressed
    }
}
