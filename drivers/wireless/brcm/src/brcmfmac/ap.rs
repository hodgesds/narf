// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded primary-bsscfg FullMAC AP owner. Firmware is the AP SME and owns
//! CCMP/replay/SCB internals; host epochs bind actual consumed native records
//! and copies, never invent hardware key IDs, PNs or firmware generations.
use super::{
    ap_key::{History, Installed},
    ap_native::{self, Phase, Saved, Scope},
    ap_peer::Peer,
    ap_plan::Plan,
    ap_scope::{Capture, Epoch, Policy, Use},
};
use crate::cyw43439::{
    fullmac::Fullmac,
    runtime::{Error, Event as NativeEvent},
    station::Station,
};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_wireless::{ap_control::ApEmissionAuthority, ApConfig, ApStartSettings};

pub(crate) enum Event {
    Associated {
        peer: [u8; 6],
        generation: u32,
        ies: Vec<u8>,
    },
    Lost {
        peer: [u8; 6],
        generation: u32,
    },
    Control {
        peer: [u8; 6],
        protocol: u16,
        pdu: Vec<u8>,
    },
    Data(Vec<u8>),
}
pub(crate) struct Received {
    pub(crate) event: Event,
    pub(crate) original: Capture,
    pub(crate) lease: Option<super::ap_peer::CopyLease>,
}
pub(crate) struct Mode {
    pub(crate) generation: Arc<AtomicU64>,
    pub(crate) value: u64,
}
pub(crate) struct Session {
    pub(super) plan: Plan,
    /// Interface this AP programs: the primary, or a secondary bsscfg.
    pub(super) scope: Scope,
    pub(super) base: Capture,
    pub(super) power: u8,
    pub(super) saved: Option<Saved>,
    pub(super) phase: Phase,
    pub(super) native_entered: bool,
    pub(super) running: Arc<AtomicBool>,
    pub(super) failed: bool,
    pub(super) cancelled: Arc<AtomicBool>,
    pub(super) busy: bool,
    pub(super) peers: Vec<Peer>,
    pub(super) group: Vec<Installed>,
    pub(super) selected_group: Option<u8>,
    pub(super) native_group: Option<u8>,
    pub(super) default_source: Option<ApEmissionAuthority>,
    pub(super) group_data: Epoch,
    pub(super) history: Arc<narf_lib::sync::IrqSafeSpinLock<History>>,
    pub(super) received: VecDeque<Received>,
    pub(super) early_control: VecDeque<Received>,
    pub(super) generation: u32,
    pub(super) rejected: Vec<super::ap_peer::Rejected>,
    pub(super) pending_template: Option<(Vec<u8>, Vec<u8>)>,
}
impl Session {
    pub(crate) fn prepare<R: Fullmac>(
        station: &Station<R>,
        config: ApConfig,
        settings: ApStartSettings,
        source: ApEmissionAuthority,
        policy: Policy,
        mode: Mode,
        history: Arc<narf_lib::sync::IrqSafeSpinLock<History>>,
    ) -> Result<Self, Error> {
        if !R::PRIMARY_AP {
            return Err(Error::Authority);
        }
        Self::prepare_in(
            station,
            config,
            settings,
            source,
            policy,
            mode,
            history,
            Scope::Primary,
        )
    }
    /// A firmware-SME AP on a secondary bsscfg (`station` is bound to a
    /// `vif_bsscfg::Bsscfg`), with the Linux `start_ap` rules of `scope`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_secondary<R: Fullmac>(
        station: &Station<R>,
        config: ApConfig,
        settings: ApStartSettings,
        source: ApEmissionAuthority,
        policy: Policy,
        mode: Mode,
        history: Arc<narf_lib::sync::IrqSafeSpinLock<History>>,
        scope: Scope,
    ) -> Result<Self, Error> {
        if scope == Scope::Primary {
            return Err(Error::Authority);
        }
        Self::prepare_in(
            station, config, settings, source, policy, mode, history, scope,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_in<R: Fullmac>(
        station: &Station<R>,
        config: ApConfig,
        settings: ApStartSettings,
        source: ApEmissionAuthority,
        policy: Policy,
        mode: Mode,
        history: Arc<narf_lib::sync::IrqSafeSpinLock<History>>,
        scope: Scope,
    ) -> Result<Self, Error> {
        scope.admits::<R>()?;
        if mode.value == 0
            || mode.value == u64::MAX
            || mode.generation.load(Ordering::Acquire) != mode.value
            || !source.current()
        {
            return Err(Error::Authority);
        }
        let plan = Plan::new(config, settings, station.mac)?;
        // Linux programs `closednet` only in the AP branch of `start_ap`;
        // a hidden P2P GO SSID would be silently ignored, so refuse it.
        if scope.go().is_some() && plan.config.hidden_ssid != 0 {
            return Err(Error::Unsupported);
        }
        let channel = station.ap_channel(&policy, plan.primary)?;
        if channel.chanspec != plan.chanspec {
            return Err(Error::Unsupported);
        }
        let native = station.runtime.ap_source().ok_or(Error::Unsupported)?;
        native.current().map_err(|_| Error::Authority)?;
        let base = Capture {
            native,
            source,
            sources: Vec::new(),
            policy,
            scope,
            role: Epoch::new(),
            copy: Epoch::new(),
            peer: None,
            data: None,
            key: None,
            epochs: Vec::new(),
            purpose: Use::Lifecycle,
            target: None,
            own: station.mac,
            running: None,
            mode: mode.generation,
            mode_value: mode.value,
        };
        base.current().map_err(|_| Error::Authority)?;
        Ok(Self {
            plan,
            scope,
            base,
            power: channel.power_dbm,
            saved: None,
            phase: Phase::Prepared,
            native_entered: false,
            running: Arc::new(AtomicBool::new(false)),
            failed: false,
            cancelled: Arc::new(AtomicBool::new(false)),
            busy: false,
            peers: Vec::new(),
            group: Vec::new(),
            selected_group: None,
            native_group: None,
            default_source: None,
            group_data: Epoch::new(),
            history,
            received: VecDeque::new(),
            early_control: VecDeque::new(),
            generation: 0,
            rejected: Vec::new(),
            pending_template: None,
        })
    }
    pub(crate) async fn start<R: Fullmac>(
        &mut self,
        station: &mut Station<R>,
    ) -> Result<(), Error> {
        self.current()?;
        if self.saved.is_some() || self.phase != Phase::Prepared {
            return Err(Error::Busy);
        }
        let operation = self.operation()?;
        // A new AP does not inherit an old station's queued native input.
        // Actual terminal processing continues; no DMA is cleared by hand.
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            let count = station.runtime.poll()?;
            while station.runtime.pop_event().is_some() {}
            while station.runtime.pop_data().is_some() {}
            if count == 0 && station.runtime.ap_completed_prefix()? {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
        self.saved = Some(Saved::read(&mut station.runtime, &self.base, self.scope).await?);
        station.runtime.ap_enter(self.base.clone())?;
        self.native_entered = true;
        let mfp = station.supports_management_protection();
        ap_native::program(
            &mut station.runtime,
            &self.base,
            &self.plan,
            self.power,
            mfp,
            self.saved.as_mut().unwrap(),
            &mut self.phase,
        )
        .await?;
        self.current()?;
        self.busy = false;
        operation.finish();
        // Software staging is still only metadata here. The frontend must
        // install its staged group keys/default through actual native receipts
        // before it commits this BSS or publishes a carrier.
        Ok(())
    }
    pub(crate) fn commit_start(&mut self) -> Result<(), Error> {
        self.current()?;
        if self.phase != Phase::Formed {
            return Err(Error::Failed);
        }
        self.running.store(true, Ordering::Release);
        self.busy = false;
        Ok(())
    }
    pub(super) fn current(&self) -> Result<(), Error> {
        if self.failed || self.cancelled.load(Ordering::Acquire) {
            return Err(Error::Failed);
        }
        self.base.current().map_err(|_| Error::Authority)
    }
    pub(crate) fn active(&self) -> bool {
        !self.failed && self.running.load(Ordering::Acquire) && self.current().is_ok()
    }
    /// This session's BSS chanspec as prepared (before or after START).
    pub(crate) fn chanspec(&self) -> u16 {
        self.plan.chanspec
    }
    /// Live BSS chanspec, for MBSS channel agreement (None unless active).
    pub(crate) fn running_chanspec(&self) -> Option<u16> {
        self.active().then_some(self.plan.chanspec)
    }
    /// Whether this session is a P2P GO BSS (never an MBSS peer).
    pub(crate) fn is_go(&self) -> bool {
        self.scope.go().is_some()
    }
    pub(crate) fn cleanup_required(&self) -> bool {
        self.failed || self.cancelled.load(Ordering::Acquire) || self.current().is_err()
    }
    pub(crate) fn publication(&self) -> Result<Capture, Error> {
        if !self.active() {
            return Err(Error::Authority);
        }
        Ok(self.capture(Use::Lifecycle, None, None))
    }
    pub(crate) fn completion(&self) -> Result<Capture, Error> {
        let mut capture = self.publication()?;
        capture.epochs.push(self.group_data.capture());
        for peer in &self.peers {
            capture.epochs.push(peer.epoch.capture());
            capture.epochs.push(peer.data.capture());
            capture.epochs.push(peer.key_epoch.capture());
            if let Some(actor) = &peer.authorization {
                capture.sources.push(actor.clone());
            }
            if let Some(key) = &peer.key {
                capture.epochs.push(key.epoch.capture());
                capture.sources.push(key.source.clone());
            }
        }
        for key in &self.group {
            capture.epochs.push(key.epoch.capture());
            capture.sources.push(key.source.clone());
        }
        if let Some(actor) = &self.default_source {
            capture.sources.push(actor.clone());
        }
        capture.current().map_err(|_| Error::Authority)?;
        Ok(capture)
    }
    pub(crate) fn native_source(&self) -> super::ap_source::Source {
        self.base.native.clone()
    }
    pub(crate) fn data_generation(&self) -> u64 {
        self.group_data.serial()
    }
    pub(crate) fn fail(&mut self) {
        self.failed = true;
        self.running.store(false, Ordering::Release);
        self.base.copy.close();
        self.base.role.close();
        self.group_data.close();
        for peer in &mut self.peers {
            let _ = peer.deny(false);
        }
        self.received.clear();
        self.early_control.clear();
    }
    pub(super) fn generation(&mut self) -> Result<u32, Error> {
        self.generation = self.generation.checked_add(1).ok_or(Error::Failed)?;
        Ok(self.generation)
    }
    pub(super) fn capture(
        &self,
        purpose: Use,
        target: Option<[u8; 6]>,
        peer: Option<&Peer>,
    ) -> Capture {
        let mut capture = self.base.clone();
        capture.copy = self.base.copy.capture();
        capture.purpose = purpose;
        capture.target = target;
        capture.running = Some(self.running.clone());
        if let Some(peer) = peer {
            capture.peer = Some(peer.epoch.capture());
            capture.data = Some(peer.data.capture());
        }
        capture
    }
    pub(super) fn command_capture(
        &self,
        source: ApEmissionAuthority,
        peer: Option<&Peer>,
    ) -> Result<Capture, Error> {
        self.current()?;
        let mut capture = self.capture(Use::Lifecycle, peer.map(|peer| peer.mac), peer);
        capture.sources.push(self.base.source.clone());
        capture.source = source;
        // A native key/port command may be used during pre-START staging.
        // Peer identity is retained, but a port's denial epoch must not
        // invalidate a still-installed key merely on SET_STATION(false).
        capture.running = None;
        capture.data = None;
        capture.current().map_err(|_| Error::Authority)?;
        Ok(capture)
    }
    pub(super) fn queue(&mut self, event: Event, original: Capture) -> Result<(), Error> {
        if self.received.len() == 32 {
            return if matches!(event, Event::Data(_)) {
                Ok(())
            } else {
                Err(Error::EventOverflow)
            };
        }
        let mac = match &event {
            Event::Associated { peer, .. }
            | Event::Lost { peer, .. }
            | Event::Control { peer, .. } => Some(*peer),
            Event::Data(bytes) => bytes.get(6..12).and_then(|mac| mac.try_into().ok()),
        };
        let lease = mac
            .and_then(|mac| self.peers.iter().find(|peer| peer.mac == mac))
            .map(Peer::copy)
            .transpose()?;
        self.received.push_back(Received {
            event,
            original,
            lease,
        });
        Ok(())
    }
    pub(super) fn verified_control(&mut self, mac: [u8; 6]) -> Result<(), Error> {
        if !self
            .peers
            .iter()
            .any(|peer| peer.mac == mac && peer.associated && !peer.removed)
        {
            return Err(Error::Authority);
        }
        // Move the original held proof/lease, never capture a new peer/source.
        // Association notification was queued before this release.
        for _ in 0..self.early_control.len() {
            let received = self.early_control.pop_front().ok_or(Error::Failed)?;
            if received.original.current().is_err() {
                continue;
            }
            if matches!(&received.event, Event::Control { peer, .. } if *peer == mac) {
                if self.received.len() == 32 {
                    return Err(Error::EventOverflow);
                }
                self.received.push_back(received);
            } else {
                self.early_control.push_back(received);
            }
        }
        Ok(())
    }
    pub(crate) fn take_received(&mut self) -> Vec<Received> {
        self.received.drain(..).collect()
    }
    /// Poll actual native input, capture its original owner before any host
    /// callback, and only claim Idle after the final posted-index observation.
    pub(crate) fn prefix<R: Fullmac>(&mut self, runtime: &mut R) -> Result<bool, Error> {
        self.current()?;
        let mut idle = false;
        for _ in 0..4 {
            let count = runtime.poll()?;
            while let Some(event) = runtime.pop_event() {
                self.native_event(event)?;
            }
            while let Some(bytes) = runtime.pop_data() {
                self.native_data(bytes)?;
            }
            self.early_control
                .retain(|held| held.original.current().is_ok());
            if count == 0 && runtime.ap_completed_prefix()? {
                idle = true;
                break;
            }
        }
        self.current()?;
        Ok(idle)
    }
    fn native_event(&mut self, event: NativeEvent) -> Result<(), Error> {
        let header = event.header;
        use super::ap_wire::{event_transition, Transition};
        let transition = event_transition(&header, self.plan.own, self.scope.indices())?;
        if transition == Transition::Failed {
            return Err(Error::Failed);
        }
        let mac = header.source_mac;
        if self.rejected.len() == super::ap_peer::MAX_PEERS {
            return Err(Error::EventOverflow);
        }
        match transition {
            Transition::Associated => {
                self.group_data.advance().map_err(|_| Error::Failed)?;
                if let Some(old) = self.rejected.iter_mut().find(|old| old.mac == mac) {
                    old.epoch.advance().map_err(|_| Error::Failed)?;
                    return Ok(());
                }
                if let Some(old) = self.peers.iter_mut().find(|peer| peer.mac == mac) {
                    if old.removed && old.absent {
                        let next = Peer::indication(mac, event.payload, &self.plan)?;
                        *old = next;
                        return Ok(());
                    }
                    // An in-place reassociation cannot silently inherit the
                    // original SCB/key/port. A real absence boundary is needed.
                    old.deny(false)?;
                    old.remove_requested = true;
                    return Ok(());
                }
                if self.peers.iter().filter(|peer| !peer.removed).count()
                    == super::ap_peer::MAX_PEERS
                {
                    self.reject(mac);
                    return Ok(());
                }
                match Peer::indication(mac, event.payload, &self.plan) {
                    Ok(peer) => self.peers.push(peer),
                    Err(_) if super::ap_wire::unicast(mac) && mac != self.plan.own => {
                        self.reject(mac)
                    }
                    Err(error) => return Err(error),
                }
            }
            Transition::Lost => {
                if let Some(index) = self.peers.iter().position(|peer| peer.mac == mac) {
                    let observed = header.status == 0;
                    let notify = observed && self.peers[index].notified;
                    let peer = &mut self.peers[index];
                    peer.deny(observed)?;
                    peer.removal_observed |= observed;
                    peer.remove_requested = true;
                    if observed {
                        peer.notified = false;
                    }
                    self.group_data.advance().map_err(|_| Error::Failed)?;
                    if notify {
                        let generation = self.generation()?;
                        let original =
                            self.capture(Use::Receive, Some(mac), Some(&self.peers[index]));
                        self.queue(
                            Event::Lost {
                                peer: mac,
                                generation,
                            },
                            original,
                        )?;
                    }
                }
            }
            Transition::Roamed => {
                if let Some(peer) = self.peers.iter_mut().find(|peer| peer.mac == mac) {
                    peer.deny(false)?;
                    peer.remove_requested = true;
                    self.group_data.advance().map_err(|_| Error::Failed)?;
                }
            }
            Transition::Benign => {}
            Transition::Failed => return Err(Error::Failed),
        }
        Ok(())
    }
    fn reject(&mut self, mac: [u8; 6]) {
        if !self.rejected.iter().any(|old| old.mac == mac) {
            self.rejected.push(super::ap_peer::Rejected {
                mac,
                sent: false,
                deadline: None,
                epoch: Epoch::new(),
            });
        }
    }
    fn native_data(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        if !self.active() || !(14..=1514).contains(&bytes.len()) {
            return Ok(());
        }
        if bytes[6] & 1 != 0
            || bytes[6..12] == [0; 6]
            || bytes[0] & 1 == 0 && bytes[..6] != self.plan.own
        {
            return Ok(());
        }
        let mac: [u8; 6] = bytes[6..12].try_into().unwrap();
        let Some(peer) = self
            .peers
            .iter()
            .find(|peer| peer.mac == mac && !peer.removed)
        else {
            return Ok(());
        };
        let protocol = u16::from_be_bytes([bytes[12], bytes[13]]);
        if !peer.associated {
            if !peer.verify
                || protocol != 0x888e
                || !self.plan.settings.control_port.over_nl80211
                || bytes[..6] != self.plan.own
                || bytes.len() < 18
            {
                return Ok(());
            }
            if self.early_control.len() == 32
                || self
                    .early_control
                    .iter()
                    .filter(
                        |held| matches!(&held.event, Event::Control { peer, .. } if *peer == mac),
                    )
                    .count()
                    == 4
            {
                // Peer-controlled pre-SCB EAPOL is bounded by dropping the
                // newest frame (the supplicant/authenticator retransmits);
                // it never fails the whole firmware-SME BSS session.
                return Ok(());
            }
            let mut original = self.capture(Use::EarlyControl, Some(mac), Some(peer));
            // This owns no DATA/key/port grant. Verification deliberately
            // advances the DATA-only epoch before querying actual SCB facts.
            original.data = None;
            let lease = Some(peer.copy()?);
            self.early_control.push_back(Received {
                event: Event::Control {
                    peer: mac,
                    protocol,
                    pdu: bytes[14..].to_vec(),
                },
                original,
                lease,
            });
            return Ok(());
        }
        // A real M2/M4 can arrive in the same native drain as the outgoing
        // M1/M3 terminal. Control serialization closes ordinary DATA, not
        // firmware-SME EAPOL. Its fixed original peer still gates delivery.
        if self.busy && protocol != 0x888e {
            return Ok(());
        }
        let mut capture = self.capture(Use::Receive, Some(mac), Some(peer));
        if matches!(protocol, 0x888e | 0x88c7) {
            if !self.plan.settings.control_port.over_nl80211 {
                return Ok(());
            }
            if protocol == 0x88c7 && !peer.data_current(self.plan.config.privacy) {
                return Ok(());
            }
            if protocol == 0x88c7 {
                capture
                    .sources
                    .push(peer.authorization.clone().ok_or(Error::Authority)?);
                if let Some(key) = &peer.key {
                    capture.sources.push(key.source.clone());
                    capture.key = Some(key.epoch.capture());
                }
            }
            if bytes[..6] != self.plan.own || bytes.len() < 18 {
                return Ok(());
            }
            self.queue(
                Event::Control {
                    peer: mac,
                    protocol,
                    pdu: bytes[14..].to_vec(),
                },
                capture,
            )?;
        } else if protocol >= 0x600 && peer.data_current(self.plan.config.privacy) {
            let mut capture = capture;
            if let Some(source) = &peer.authorization {
                capture.sources.push(source.clone());
            }
            if let Some(key) = &peer.key {
                capture.sources.push(key.source.clone());
                capture.key = Some(key.epoch.capture());
            }
            self.queue(Event::Data(bytes), capture)?;
        }
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.fail();
    }
}
