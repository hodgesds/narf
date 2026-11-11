// SPDX-License-Identifier: GPL-2.0-or-later
//! One retained AR9285 exact-channel legacy/qualified-HT20 station, host RSNA/CCMP.
use super::{
    descriptor::Mpdu,
    packet::{self, Packet, Port},
};
use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
};
use narf_lib::sync::IrqSafeSpinLock;
use narf_wireless::{
    association::{self, JoinPlan, ObservedBss, SecurityMode},
    station_security::{self, Security},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    State,
    Busy,
    Profile,
    Entropy,
    Timeout,
    PeerLost,
    WidthFallback,
    Transport(packet::Error),
    Management(association::Error),
    Security(station_security::Error),
}
impl From<packet::Error> for Error {
    fn from(error: packet::Error) -> Self {
        Self::Transport(error)
    }
}
impl From<association::Error> for Error {
    fn from(error: association::Error) -> Self {
        Self::Management(error)
    }
}
impl From<station_security::Error> for Error {
    fn from(error: station_security::Error) -> Self {
        Self::Security(error)
    }
}
/// `ath9k.h::enum ath_reset_type` causes this tree recovers with an
/// in-place `main.c::ath_reset` (the station generation, its association,
/// peer and host keys stay; only the chip and its DMA engines restart)
/// instead of retiring the generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResetType {
    /// `RESET_TYPE_FATAL_INT` (`ath9k_tasklet`, `ATH9K_INT_FATAL`).
    FatalInt,
    /// `RESET_TYPE_BB_WATCHDOG` (`ATH9K_INT_BB_WATCHDOG`).
    BbWatchdog,
    /// `RESET_TYPE_TX_HANG` (`link.c::ath_tx_complete_check`).
    TxHang,
    /// `RESET_TYPE_RX_INACTIVE` (`link.c::ath_hw_rx_inactive_check`).
    RxInactive,
    /// `RESET_TYPE_CALIBRATION` (`link.c::ath_ani_calibrate`).
    Calibration,
}
/// `link.c::RX_INACTIVE_CHECK_INTERVAL` (4 s).
pub(super) const RX_INACTIVE_CHECK_INTERVAL_MS: u64 = 4_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Prepared,
    Passive,
    Authentication,
    Association,
    FourWay,
    Open,
    Failed,
    Stopped,
}
pub(super) trait Environment: Send + Sync {
    fn retune(&self, _frequency: u16) -> Option<super::channels::Transition> {
        None
    }
    fn wide_qualification(
        &self,
        _base: Arc<super::ht::Grant>,
        _geometry: super::channel_width::Geometry,
    ) -> Result<Option<Arc<super::ht40::Grant>>, Error> {
        Ok(None)
    }
    fn retune_geometry(
        &self,
        geometry: super::channel_width::Geometry,
        _wide: Option<Arc<super::ht40::Grant>>,
    ) -> Option<super::channels::Transition> {
        if geometry.is_wide() {
            None
        } else {
            self.retune(geometry.control())
        }
    }
    fn now_ms(&self) -> u64;
    fn nonce(&self) -> Option<[u8; 32]>;
    fn pause(&self) -> impl Future<Output = ()> + Send;
}
pub(super) struct NativeEnvironment {
    pub(super) generation: u32,
}
impl Environment for NativeEnvironment {
    fn retune(&self, frequency: u16) -> Option<super::channels::Transition> {
        Some(
            super::channels::request(frequency, self.generation)
                .unwrap_or_else(|error| alloc::boxed::Box::pin(async move { Err(error) })),
        )
    }
    fn wide_qualification(
        &self,
        base: Arc<super::ht::Grant>,
        geometry: super::channel_width::Geometry,
    ) -> Result<Option<Arc<super::ht40::Grant>>, Error> {
        super::wide_qualification(base, geometry, self.generation)
    }
    fn retune_geometry(
        &self,
        geometry: super::channel_width::Geometry,
        wide: Option<Arc<super::ht40::Grant>>,
    ) -> Option<super::channels::Transition> {
        Some(
            super::channels::request_geometry(geometry, self.generation, wide)
                .unwrap_or_else(|error| alloc::boxed::Box::pin(async move { Err(error) })),
        )
    }
    fn now_ms(&self) -> u64 {
        narf_time::monotonic_ns() / 1_000_000
    }
    fn nonce(&self) -> Option<[u8; 32]> {
        let mut bytes = [0; 32];
        narf_crypto::try_fill_random_bytes(&mut bytes).ok()?;
        Some(bytes)
    }
    async fn pause(&self) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Probe,
    Authentication,
    Association,
    Security,
    Data,
    Decline,
    BaResponse(Option<u64>),
    Delba(u64),
    TxRequest(u64),
    TxRetry(u64, usize),
    TxBar(u64),
    TxDelba(u64),
    PsNull(u64),
    PsPoll(u64),
}
struct Pending {
    id: u64,
    bytes: Vec<u8>,
    security_original: Option<Vec<u8>>,
    kind: Kind,
    epoch: u64,
}
struct PairPending {
    id: u64,
    originals: Vec<Vec<u8>>,
}
struct Entry {
    candidate: ObservedBss,
    seen: u64,
}
struct Incoming {
    frame: Mpdu,
    admitted: bool,
    ba_token: Option<(u8, u64)>,
    epoch: u64,
}
struct Attempt {
    closed: Arc<AtomicBool>,
    publication: Arc<IrqSafeSpinLock<()>>,
    armed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.armed {
            let _publication = self.publication.lock();
            self.closed.store(true, Ordering::Release);
        }
    }
}
pub(super) struct Radio<P: Port, E: Environment, K: Engine = Packet<P>> {
    packet: K,
    _port: core::marker::PhantomData<fn() -> P>,
    environment: E,
    own: [u8; 6],
    noise: i16,
    phase: Phase,
    closed: Arc<AtomicBool>,
    publication: Arc<IrqSafeSpinLock<()>>,
    cache: Vec<Entry>,
    peer: Option<ObservedBss>,
    plan: Option<JoinPlan>,
    security: Option<Security>,
    incoming: VecDeque<Incoming>,
    received: VecDeque<Vec<u8>>,
    pending: Option<Pending>,
    delivered_reply: Option<Pending>,
    delivered_ba: Option<Pending>,
    ba: Option<super::rx_ba::Owner<Incoming>>,
    tx_ba: Option<super::tx_ba::Owner>,
    tx_ba_checked: bool,
    pair_pending: Option<PairPending>,
    ps: Option<super::ps::Owner>,
    ps_bound: bool,
    delivered_ps: Option<Pending>,
    // Bounded unpublished BA replies while an actual PS receipt owns TX.
    // Key/peer epoch retirement withdraws these before any publication.
    ps_controls: VecDeque<(Vec<u8>, Kind)>,
    rx_idle: bool,
    tx_sequence: Option<u16>,
    initial_nonce: Option<[u8; 32]>,
    sequence: u16,
    qos_sequence: [u16; 16],
    established: bool,
    deadline: u64,
    last_peer: u64,
    last_now: u64,
    rates: Option<super::rates::Control>,
    ht: Option<u8>,
    force_twenty: bool,
    epoch: u64,
    /// `ATH_OP_HW_RESET`: an `ath9k_queue_reset` cause awaiting the owner's
    /// in-place reset. No packet operation runs until it completes.
    reset_wanted: Option<ResetType>,
    /// `sc->rx_active_count` / `sc->rx_active_check_time` (ms).
    rx_active_count: u32,
    rx_active_check_ms: u64,
}
impl<P: Port, E: Environment, K: Engine> core::fmt::Debug for Radio<P, E, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ar9285Station")
            .field("phase", &self.phase)
            .field("established", &self.established)
            .finish_non_exhaustive()
    }
}
impl<P: Port, E: Environment, K: Engine> Radio<P, E, K> {
    pub(super) fn new(packet: K, own: [u8; 6], noise: i16, environment: E) -> Self {
        Self {
            packet,
            _port: core::marker::PhantomData,
            environment,
            own,
            noise,
            phase: Phase::Prepared,
            closed: Arc::new(AtomicBool::new(false)),
            publication: Arc::new(IrqSafeSpinLock::new(())),
            cache: Vec::new(),
            peer: None,
            plan: None,
            security: None,
            incoming: VecDeque::new(),
            received: VecDeque::new(),
            pending: None,
            delivered_reply: None,
            delivered_ba: None,
            ba: None,
            tx_ba: None,
            tx_ba_checked: false,
            pair_pending: None,
            ps: None,
            ps_bound: false,
            delivered_ps: None,
            ps_controls: VecDeque::new(),
            rx_idle: false,
            tx_sequence: None,
            initial_nonce: None,
            sequence: 1,
            qos_sequence: [1; 16],
            established: false,
            deadline: 0,
            last_peer: 0,
            last_now: 0,
            rates: None,
            ht: None,
            force_twenty: false,
            epoch: 1,
            reset_wanted: None,
            rx_active_count: 0,
            rx_active_check_ms: 0,
        }
    }
    pub(super) fn closed(&self) -> Arc<AtomicBool> {
        self.closed.clone()
    }
    pub(super) fn publication(&self) -> Arc<IrqSafeSpinLock<()>> {
        self.publication.clone()
    }
    /// Capture an owned transition before releasing this generation's lock.
    pub(super) fn retune(&self, frequency: u16) -> Option<super::channels::Transition> {
        self.environment.retune(frequency)
    }
    pub(super) fn geometry(&self) -> super::channel_width::Geometry {
        self.packet.geometry()
    }
    pub(super) fn ht_grant(&self) -> Option<Arc<super::ht::Grant>> {
        self.packet.ht_grant()
    }
    pub(super) fn retune_width(
        &self,
        geometry: super::channel_width::Geometry,
        wide: Option<Arc<super::ht40::Grant>>,
    ) -> Option<super::channels::Transition> {
        self.environment.retune_geometry(geometry, wide)
    }
    pub(super) fn preferred_width(
        &self,
        peer: [u8; 6],
    ) -> Result<Option<Arc<super::ht40::Grant>>, Error> {
        if self.geometry().is_wide() {
            return Ok(None);
        }
        let Some(base) = self.packet.ht_grant() else {
            return Ok(None);
        };
        base.check()?;
        let candidate = self
            .candidates()
            .into_iter()
            .find(|entry| entry.bss.bssid == peer)
            .ok_or(Error::Profile)?;
        let elements = narf_wireless::association::phy::ApElements::parse(
            &candidate.bss.information_elements,
        )?;
        let Some(operation) = elements.ht_operation() else {
            return Ok(None);
        };
        if operation[0] != self.channel() || operation[1] & 4 == 0 {
            return Ok(None);
        }
        let width = match operation[1] & 3 {
            1 => super::channel_width::Width::FortyAbove,
            3 => super::channel_width::Width::FortyBelow,
            _ => return Ok(None),
        };
        let geometry = super::channel_width::Geometry::new(self.channel(), width)
            .map_err(|_| Error::Profile)?;
        let Some(grant) = self.environment.wide_qualification(base, geometry)? else {
            return Ok(None);
        };
        // Fully validate the offered primary/secondary and peer capabilities
        // through the real common parser, not just the preliminary IE hint.
        let mode = if candidate.ap_rsne.is_some() {
            SecurityMode::Wpa2Psk
        } else {
            SecurityMode::Open
        };
        let plan = JoinPlan::prepare_with_phy(
            &candidate.bss,
            self.own,
            &candidate.bss.ssid,
            mode,
            grant.local(),
        )?;
        if !plan.offered_phy().is_some_and(|offer| {
            offer.width() == association::phy::Width::Forty
                && offer.ht().operation().secondary() == geometry.secondary()
        }) {
            return Ok(None);
        }
        Ok(Some(grant))
    }
    pub(super) fn frequency_mhz(&self) -> u16 {
        self.packet.frequency_mhz()
    }
    pub(super) fn channel_mask(&self) -> u64 {
        self.packet.channel_mask()
    }
    pub(super) fn channel(&self) -> u8 {
        self.packet.channel()
    }
    pub(super) fn local(&self) -> [u8; 6] {
        self.own
    }
    pub(super) fn phase(&self) -> Phase {
        if self.closed.load(Ordering::Acquire) && self.phase != Phase::Stopped {
            Phase::Failed
        } else {
            self.phase
        }
    }
    pub(super) fn peer(&self) -> Option<[u8; 6]> {
        if self.established && !self.closed.load(Ordering::Acquire) {
            self.peer.as_ref().map(|peer| peer.bss.bssid)
        } else {
            None
        }
    }
    pub(super) fn ready(&self) -> bool {
        self.receive_open()
            && (!self.ps_bound || self.rx_idle)
            && self.ps.as_ref().is_none_or(super::ps::Owner::data_ready)
            && self.delivered_ps.is_none()
            && self.ps_controls.is_empty()
            && self.pair_pending.is_none()
            && self.tx_ba.as_ref().is_none_or(super::tx_ba::Owner::ready)
            && self.pending.is_none()
            && self.delivered_reply.is_none()
            && self.delivered_ba.is_none()
            && self.security.as_ref().is_none_or(Security::port_open)
            && self.reset_wanted.is_none()
    }
    pub(super) fn receive_open(&self) -> bool {
        self.peer().is_some() && self.security.as_ref().is_none_or(Security::port_open)
    }
    /// Factual idle admission, not a hardware quiet receipt. The retained RX
    /// tail is intentionally allowed; actual retirement owns its DMA proof.
    pub(super) fn idle_admissible(&self) -> bool {
        self.phase() == Phase::Passive
            && !self.established
            && self.peer.is_none()
            && self.plan.is_none()
            && self.security.is_none()
            && self.pending.is_none()
            && self.pair_pending.is_none()
            && self.delivered_reply.is_none()
            && self.delivered_ba.is_none()
            && self.delivered_ps.is_none()
            && self.ps_controls.is_empty()
            && self.incoming.is_empty()
            && self.received.is_empty()
            && self.packet.idle_admissible()
    }
    /// Counted use is not IO authority: a public wake-use return also requires
    /// the current native source, PCI and actual awake program to admit access.
    pub(super) fn idle_wake_current(&self) -> Result<(), Error> {
        if self.terminal() || self.packet.phase() != packet::Phase::Running {
            return Err(Error::State);
        }
        self.packet.check_transmit().map_err(Error::Transport)
    }
    pub(super) fn interrupt(&self) -> Option<Arc<super::irq::Signal>> {
        self.packet.interrupt()
    }
    /// One periodic calibration tick of a live station (AR9287
    /// `ath_ani_calibrate` NF/IQ/open-loop temperature compensation); a
    /// closed station has none. A failed calibration closes this generation
    /// (Linux `ath9k_queue_reset(RESET_TYPE_CALIBRATION)`); a busy owner
    /// retries on the next tick.
    pub(super) fn long_calibration(&mut self) -> Result<Option<i32>, Error> {
        if self.terminal() {
            return Err(Error::State);
        }
        match self.packet.long_calibration() {
            Err(packet::Error::Busy) => Err(Error::Transport(packet::Error::Busy)),
            Err(error) => {
                self.fail_or_queue_reset();
                Err(Error::Transport(error))
            }
            ok => ok.map_err(Error::Transport),
        }
    }
    /// Stop (if still running) and report whether the packet owner proved
    /// DMA quiescence and released its storage.
    pub(super) fn retire(&mut self) -> bool {
        let _ = self.stop();
        self.packet.reclaimed()
    }
    pub(super) fn terminal(&self) -> bool {
        matches!(self.phase(), Phase::Stopped | Phase::Failed)
    }
    pub(super) fn receive_epoch(&self) -> u64 {
        self.epoch
    }
    pub(super) fn rx_ba_request(&self) -> Option<super::rx_ba::Request> {
        self.packet.ht_grant().map(|g| super::rx_ba::request(&g))
    }
    pub(super) fn qos_request(&self) -> Option<super::qos::Request> {
        self.packet.ht_grant().map(|g| super::qos::request(&g))
    }
    /// Transmit TID the native owner will use for one 802.3 frame: TID0
    /// unless the measured N85Q program is active.
    pub(super) fn transmit_tid(&self, frame: &[u8]) -> u8 {
        self.packet.qos().map_or(0, |p| p.tid(frame))
    }
    pub(super) fn tx_ba_request(&self) -> Option<super::tx_ba::Request> {
        self.packet.ht_grant().map(|g| super::tx_ba::request(&g))
    }
    pub(super) fn tx_aggregate_request(&self) -> Option<super::tx_ba::Request> {
        self.packet
            .ht_grant()
            .map(|g| super::tx_ba::large_request(&g))
    }
    pub(super) fn can_aggregate(&self) -> bool {
        self.ready() && self.tx_ba.as_ref().is_some_and(super::tx_ba::Owner::paired)
    }
    pub(super) fn ps_request(&self) -> Option<super::ps::Request> {
        self.packet.ht_grant().map(|base| super::ps::request(&base))
    }
    pub(super) fn periodic_request(&self) -> Option<super::periodic::Request> {
        self.packet
            .ht_grant()
            .map(|base| super::periodic::request(&base))
    }
    pub(super) fn power_save(&self) -> Option<bool> {
        if self.terminal() {
            return None;
        }
        if self.packet.periodic_bound() {
            return None;
        }
        if let Some(owner) = &self.ps {
            return owner.grant.check().ok().map(|_| owner.desired());
        }
        self.packet
            .ps_grant()
            .filter(|source| source.check().is_ok())
            .map(|_| false)
    }
    pub(super) fn set_power_save(&mut self, desired: bool) -> Result<(), Error> {
        let result = (|| {
            let publication = self.publication.clone();
            let _publication = publication.lock();
            if self.terminal() {
                return Err(Error::State);
            }
            if self.packet.periodic_bound() {
                return Err(Error::Profile);
            }
            if self.ps.is_none() {
                let source = self.packet.ps_grant().ok_or(Error::Profile)?;
                source.check()?;
                self.ps = Some(super::ps::Owner::new(source, self.epoch));
            }
            self.ps.as_mut().ok_or(Error::State)?.set(desired)?;
            if let Some(signal) = self.packet.interrupt() {
                signal.raise();
            }
            Ok(())
        })();
        // Missing qualification is an unsupported setting. A formerly
        // admitted owner losing authority is a terminal hardware boundary;
        // retire only after releasing publication to avoid lock reentry.
        if result.is_err() && !matches!(result, Err(Error::Profile)) {
            self.fail();
        }
        result
    }
    fn ps_aid(&self) -> Result<u16, Error> {
        match self.plan.as_ref().ok_or(Error::State)?.phase() {
            association::Phase::Associated { aid } => Ok(aid),
            _ => Err(Error::State),
        }
    }
    fn ps_data(&mut self, frame: &[u8]) {
        if let Some(owner) = &mut self.ps {
            owner.accepted_data(
                frame.get(4).is_some_and(|a| a & 1 == 0),
                frame.get(1).is_some_and(|flags| flags & 0x20 != 0),
                frame.get(1).is_some_and(|flags| flags & 4 != 0),
            );
        }
    }
    pub(super) fn current_receive(&self, epoch: u64) -> Result<bool, Error> {
        if self.packet.periodic_deferred()? {
            return Ok(false);
        }
        self.packet.check_transmit()?;
        Ok(self.epoch == epoch && self.receive_open())
    }
    fn retire_receive(&mut self) -> Result<(), Error> {
        self.epoch = self.epoch.checked_add(1).ok_or(Error::State)?;
        self.packet.periodic_epoch();
        if let Some(owner) = &mut self.ps {
            owner.key_epoch(self.epoch);
        }
        self.received.clear();
        self.ps_controls.clear();
        // Retain only exact unprotected EAPOL for the supplicant, never data
        // captured before this key/controlled-port boundary.
        self.incoming.retain(|i| plaintext_eapol(i.frame.bytes()));
        if let Some(ba) = &mut self.ba {
            ba.key_epoch(self.last_now.saturating_mul(1_000_000))?;
        }
        if let (Some(ba), Some(next)) = (&mut self.tx_ba, self.tx_sequence) {
            ba.key_epoch(next, self.last_now.saturating_mul(1_000_000))?;
        }
        Ok(())
    }
    pub(super) fn start(&mut self) -> Result<(), Error> {
        let publication = self.publication.clone();
        let _publication = publication.lock();
        if self.phase() != Phase::Prepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.packet.start()?;
        self.packet.enable_interrupts()?;
        self.last_now = self.environment.now_ms();
        self.phase = Phase::Passive;
        Ok(())
    }
    pub(super) fn stop(&mut self) -> Result<(), Error> {
        let publication = self.publication.clone();
        let _publication = publication.lock();
        self.closed.store(true, Ordering::Release);
        self.established = false;
        self.phase = Phase::Stopped;
        if let Some(security) = &mut self.security {
            security.fail();
        }
        self.incoming.clear();
        self.received.clear();
        self.ps_controls.clear();
        if let Some(ba) = &mut self.ba {
            ba.retire();
        }
        if let Some(ba) = &mut self.tx_ba {
            ba.retire();
        }
        self.epoch = self.epoch.saturating_add(1);
        if self.packet.phase() != packet::Phase::Stopped {
            self.packet.stop()?;
        }
        Ok(())
    }
    fn fail(&mut self) {
        let _ = self.stop();
        self.phase = Phase::Failed;
    }
    /// `ath9k_queue_reset`: a cause the packet engine raised is kept for the
    /// owner's in-place reset when this generation can survive one;
    /// anything else (or a generation that cannot) closes it as before.
    fn fail_or_queue_reset(&mut self) {
        match self.packet.reset_request() {
            Some(kind) if self.reset_admissible() => self.reset_wanted = Some(kind),
            _ => self.fail(),
        }
    }
    /// The pending in-place reset cause, if any.
    pub(super) fn reset_pending(&self) -> Option<ResetType> {
        if self.terminal() {
            None
        } else {
            self.reset_wanted
        }
    }
    /// An in-place reset keeps this generation only from a settled phase
    /// (passive or associated, never mid-join) with nothing but a plain data
    /// frame in flight: `ath_drain_all_txq` fails that frame, while a
    /// handshake, block-ack or power-save exchange could not resume.
    fn reset_admissible(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
            && matches!(self.phase, Phase::Passive | Phase::Open)
            && self.pending.as_ref().is_none_or(|p| p.kind == Kind::Data)
            && self.pair_pending.is_none()
            && self.delivered_reply.is_none()
            && self.delivered_ba.is_none()
            && self.delivered_ps.is_none()
            && self.ps_controls.is_empty()
            && !self.ps_bound
            && self
                .security
                .as_ref()
                .is_none_or(|security| !security.handshake_active())
    }
    /// `link.c::ath_hw_rx_inactive_check`, one `ath_hw_check_work` pass:
    /// at least one RX service per second over a 4..8 s window, else
    /// `ath9k_queue_reset(RESET_TYPE_RX_INACTIVE)`. Policy: only an
    /// associated station is checked (its AP's beacons bound the expected
    /// RX rate; an idle unassociated receiver may legitimately hear
    /// nothing). Returns the queued cause.
    pub(super) fn rx_inactive_check(&mut self, now_ms: u64) -> Option<ResetType> {
        if self.terminal() || self.reset_wanted.is_some() {
            return None;
        }
        let interval = now_ms.saturating_sub(self.rx_active_check_ms);
        if interval < RX_INACTIVE_CHECK_INTERVAL_MS {
            return None;
        }
        let count = core::mem::take(&mut self.rx_active_count);
        self.rx_active_check_ms = now_ms;
        if interval > RX_INACTIVE_CHECK_INTERVAL_MS * 2
            || u64::from(count) >= interval / 1000
            || self.peer().is_none()
            || !self.reset_admissible()
        {
            return None;
        }
        self.reset_wanted = Some(ResetType::RxInactive);
        self.reset_wanted
    }
    /// `ath_prepare_reset`'s station half: the generation must still be
    /// admissible, and the plain data frame `ath_drain_all_txq` fails is
    /// withdrawn (counted lost, never re-sent). Association, peer, host
    /// keys, sequence numbers and the receive epoch stay.
    pub(super) fn begin_reset(&mut self) -> Result<ResetType, Error> {
        let kind = self.reset_pending().ok_or(Error::State)?;
        if !self.reset_admissible() {
            return Err(Error::State);
        }
        // A drained (never completed) submission does not train rate control.
        self.pending = None;
        Ok(kind)
    }
    /// `ath_complete_reset`'s station half after the engine restarted:
    /// `ATH_OP_HW_RESET` clears and the RX-activity window restarts.
    pub(super) fn finish_reset(&mut self) -> Result<(), Error> {
        if self.terminal() || self.reset_wanted.is_none() {
            return Err(Error::State);
        }
        self.reset_wanted = None;
        let now = self.environment.now_ms();
        self.last_now = self.last_now.max(now);
        self.rx_active_count = 0;
        self.rx_active_check_ms = self.last_now;
        Ok(())
    }
    fn now(&mut self) -> Result<u64, Error> {
        let now = self.environment.now_ms();
        if now < self.last_now {
            return Err(Error::State);
        }
        self.last_now = now;
        Ok(now)
    }
    pub(super) fn candidates(&self) -> Vec<ObservedBss> {
        if self.closed.load(Ordering::Acquire) {
            return Vec::new();
        }
        let now = self.environment.now_ms();
        self.cache
            .iter()
            .filter(|entry| now >= entry.seen && now - entry.seen < 10_000)
            .map(|entry| entry.candidate.clone())
            .collect()
    }
    pub(super) fn information_elements(&self, bssid: [u8; 6]) -> Option<Vec<u8>> {
        self.candidates()
            .into_iter()
            .find(|candidate| candidate.bss.bssid == bssid)
            .map(|candidate| candidate.bss.information_elements)
    }
    fn recipient_delba(&mut self, frame: &[u8], ap: [u8; 6]) -> bool {
        if self
            .ba
            .as_mut()
            .is_none_or(|ba| !ba.delba(frame, self.own, ap))
        {
            return false;
        }
        // Unlike already-published DMA, an unpublished reply can be
        // withdrawn for this actual current peer TID. Check again during
        // incoming processing: the ADDBA may have created the owner only
        // after the raw RX batch was initially copied.
        let tid = u16::from_le_bytes([frame[26], frame[27]]) >> 12;
        self.ps_controls.retain(|(bytes, _)| {
            bytes.len() != 33
                || bytes[24..26] != [3, 1]
                || u16::from_le_bytes([bytes[29], bytes[30]]) >> 2 & 15 != tid
        });
        true
    }
    /// A completed PS native TX receipt must drain all queued key/peer
    /// updates before AP PM commit. Retain BA replies without publishing or
    /// activating their tickets; blocking this RX loop would deadlock that
    /// fresh-idle fence. The same epoch owner clears this queue on rekey.
    fn transmit_or_defer_ps_control(&mut self, bytes: Vec<u8>, kind: Kind) -> Result<(), Error> {
        if self.delivered_ps.is_some() {
            if self.ps_controls.len() == 8 {
                return Err(Error::State);
            }
            self.ps_controls.push_back((bytes, kind));
            Ok(())
        } else {
            self.transmit(bytes, kind)
        }
    }
    fn transmit(&mut self, mut bytes: Vec<u8>, kind: Kind) -> Result<(), Error> {
        // Caller holds publication; this helper never awaits or re-enters it.
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        if self.pending.is_some()
            || self.pair_pending.is_some()
            || self.delivered_reply.is_some()
            || self.delivered_ba.is_some()
            || self.delivered_ps.is_some()
        {
            return Err(Error::Busy);
        }
        if !matches!(
            kind,
            Kind::Security
                | Kind::Data
                | Kind::TxRetry(..)
                | Kind::TxBar(_)
                | Kind::PsNull(_)
                | Kind::PsPoll(_)
        ) {
            bytes[22..24].copy_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
        }
        let security_original = if kind == Kind::Security
            && self.ps_bound
            && self.ps.as_ref().is_some_and(super::ps::Owner::mark_pm)
        {
            Some(bytes.clone())
        } else {
            None
        };
        if matches!(kind, Kind::Data | Kind::Security)
            && self.ps_bound
            && self.ps.as_ref().is_some_and(super::ps::Owner::mark_pm)
        {
            bytes[1] |= 0x10;
        }
        let id = if matches!(kind, Kind::PsNull(_) | Kind::PsPoll(_)) {
            self.packet.submit_ps(
                &bytes,
                self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                self.ps_aid()?,
                self.rates.ok_or(Error::State)?.basic(),
            )?
        } else if matches!(kind, Kind::Data | Kind::TxRetry(..)) {
            let control = self.rates.ok_or(Error::State)?;
            if let Some(mask) = self.ht {
                self.packet
                    .submit_ht(&bytes, 7 - mask.leading_zeros() as u8, control.basic())?
            } else {
                self.packet.submit_rates(&bytes, control.series())?
            }
        } else if matches!(kind, Kind::TxRequest(_) | Kind::TxDelba(_)) {
            self.packet
                .submit_sender_action(&bytes, self.rates.ok_or(Error::State)?.basic())?
        } else if matches!(kind, Kind::TxBar(_)) {
            self.packet
                .submit_bar(&bytes, self.rates.ok_or(Error::State)?.basic())?
        } else if matches!(kind, Kind::Delba(_)) {
            self.packet
                .submit_delba(&bytes, self.rates.ok_or(Error::State)?.basic())?
        } else if matches!(kind, Kind::BaResponse(_)) {
            self.packet
                .submit_ba_response(&bytes, self.rates.ok_or(Error::State)?.basic())?
        } else {
            let rate = if kind == Kind::Probe {
                // 1 Mbps CCK on 2.4 GHz; 6 Mbps OFDM (`rates::BITRATES[4]`)
                // on 5 GHz, where CCK does not exist.
                if self.frequency_mhz() >= 5000 {
                    4
                } else {
                    0
                }
            } else {
                self.rates.ok_or(Error::State)?.basic()
            };
            self.packet.submit(&bytes, rate)?
        };
        self.pending = Some(Pending {
            id,
            bytes,
            security_original,
            kind,
            epoch: self.epoch,
        });
        Ok(())
    }
    fn cache(&mut self, frame: &Mpdu, now: u64) -> Result<(), Error> {
        // Linux uses a -95dBm reference, adjusted only for NF above nominal+6.
        let signal = (frame.rssi != i8::MIN).then(|| {
            (-95 + (self.noise + 112).max(0) + i16::from(frame.rssi)).clamp(-127, 0) as i8
        });
        let grant = self.packet.ht_grant().filter(|g| g.check().is_ok());
        let bytes = frame.bytes();
        let current = self.ht.is_some()
            && bytes.len() >= 36
            && matches!(bytes[0], 0x50 | 0x80)
            && self.peer.as_ref().is_some_and(|peer| {
                bytes[10..16] == peer.bss.bssid
                    && bytes[16..22] == peer.bss.bssid
                    && (bytes[4..10] == self.own || bytes[4..10] == [255; 6])
            });
        let observed = if let Some(g) = &grant {
            association::observe_with_phy(frame, self.channel(), self.own, signal, &g.local())
        } else {
            association::observe(frame, self.channel(), self.own, signal)
        };
        let Ok(candidate) = observed else {
            if current {
                return Err(Error::Profile);
            }
            return Ok(());
        };
        if self
            .peer
            .as_ref()
            .is_some_and(|peer| peer.bss.bssid == candidate.bss.bssid)
        {
            if bytes.first() == Some(&0x80) && frame.rssi != i8::MIN {
                self.packet.periodic_beacon(frame.rssi);
            }
            if self.ht.is_some() {
                let peer = self.peer.as_ref().ok_or(Error::State)?;
                let mode = if self.security.is_some() {
                    SecurityMode::Wpa2Psk
                } else {
                    SecurityMode::Open
                };
                let plan = JoinPlan::prepare_with_phy(
                    &candidate.bss,
                    self.own,
                    &peer.bss.ssid,
                    mode,
                    grant.as_ref().ok_or(Error::State)?.local(),
                )?;
                self.packet.observe_ht(
                    plan.offered_phy().ok_or(Error::Profile)?,
                    &candidate.bss.information_elements,
                    self.rates.ok_or(Error::State)?.basic(),
                )?;
                if let Some(owner) = &mut self.tx_ba {
                    owner.observe(
                        plan.offered_phy().ok_or(Error::Profile)?,
                        self.packet.ht_profile().ok_or(Error::State)?,
                    )?;
                }
            }
            if self.ps_bound
                && self.ps.as_ref().is_some_and(super::ps::Owner::active)
                && bytes.first() == Some(&0x80)
            {
                let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                if let Some(tim) = super::ps::tim::Tim::parse(bytes, self.own, ap, self.ps_aid()?)?
                {
                    let tsf = self.packet.ps_tsf()?;
                    if let Some(plan) = self.ps.as_mut().ok_or(Error::State)?.beacon(tim, tsf) {
                        self.packet.ps_timers(plan)?;
                    }
                }
            }
            self.last_peer = now;
        }
        if let Some(entry) = self
            .cache
            .iter_mut()
            .find(|entry| entry.candidate.bss.bssid == candidate.bss.bssid)
        {
            *entry = Entry {
                candidate,
                seen: now,
            };
        } else {
            if self.cache.len() == 32 {
                let oldest = self
                    .cache
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.seen)
                    .map(|(index, _)| index)
                    .unwrap_or(0);
                self.cache.swap_remove(oldest);
            }
            self.cache.push(Entry {
                candidate,
                seen: now,
            });
        }
        Ok(())
    }
    fn lost(&self, frame: &Mpdu) -> bool {
        let Some(peer) = &self.peer else {
            return false;
        };
        let bytes = frame.bytes();
        bytes.len() >= 26
            && matches!(bytes[0], 0xa0 | 0xc0)
            && bytes[1] & 0xc7 == 0
            && bytes[22] & 15 == 0
            && bytes[10..16] == peer.bss.bssid
            && bytes[16..22] == peer.bss.bssid
            && (bytes[4..10] == self.own || bytes[4..10] == [255; 6])
    }
    fn delivery(&mut self) -> Result<(), Error> {
        if let Some(p) = &self.pair_pending {
            let Some(d) = self.packet.pair_delivery()? else {
                return Ok(());
            };
            if d.id != p.id
                || d.originals != p.originals
                || !(12..20).contains(&d.feedback.rate)
                || self
                    .ht
                    .is_none_or(|m| m & (1 << (d.feedback.rate - 12)) == 0)
            {
                return Err(Error::State);
            }
            if let Some(ba) = &mut self.tx_ba {
                ba.pair_delivered(d.acked, self.last_now.saturating_mul(1_000_000), self.epoch)?;
            }
            self.pair_pending = None;
            return Ok(());
        }
        let Some(delivery) = self.packet.delivery()? else {
            return Ok(());
        };
        let pending = self.pending.take().ok_or(Error::State)?;
        if pending.id != delivery.id || pending.bytes != delivery.bytes {
            return Err(Error::State);
        }
        if !delivery.delivered && !matches!(pending.kind, Kind::Data | Kind::TxRetry(..)) {
            return Err(Error::State);
        }
        if matches!(pending.kind, Kind::Data | Kind::TxRetry(..)) && self.ht.is_some() {
            if delivery.feedback.rate < 12
                || delivery.feedback.rate >= 20
                || self
                    .ht
                    .is_none_or(|m| m & (1 << (delivery.feedback.rate - 12)) == 0)
            {
                return Err(Error::State);
            }
        } else if pending.kind == Kind::Data
            && !self
                .rates
                .as_mut()
                .ok_or(Error::State)?
                .complete(delivery.delivered, delivery.feedback)
        {
            return Err(Error::State);
        }
        if let Some(ba) = &mut self.tx_ba {
            if let Kind::TxRetry(ticket, index) = pending.kind {
                ba.retry_delivered(
                    ticket,
                    index,
                    delivery.delivered,
                    self.last_now.saturating_mul(1_000_000),
                    self.epoch,
                )?;
            } else if pending.kind == Kind::Data
                && pending.bytes.first() == Some(&0x88)
                && pending.bytes.get(24..26) == Some(&[0, 0])
            {
                // This agreement owns TID0 only. N85Q singles on other
                // queues consume an independent SC and cannot advance it.
                ba.single_delivered(
                    u16::from_le_bytes([pending.bytes[22], pending.bytes[23]]) >> 4,
                    delivery.delivered,
                    self.last_now.saturating_mul(1_000_000),
                    self.epoch,
                    pending.epoch,
                )?;
            }
        }
        if matches!(pending.kind, Kind::PsNull(_) | Kind::PsPoll(_)) {
            self.delivered_ps = Some(pending);
        } else if pending.kind == Kind::Security {
            self.delivered_reply = Some(pending);
        } else if matches!(
            pending.kind,
            Kind::BaResponse(_)
                | Kind::Delba(_)
                | Kind::TxRequest(_)
                | Kind::TxBar(_)
                | Kind::TxDelba(_)
        ) {
            self.delivered_ba = Some(pending);
        }
        Ok(())
    }
    pub(super) fn poll(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        if self.reset_pending().is_some() {
            return Err(Error::Busy);
        }
        let result = {
            let publication = self.publication.clone();
            let _publication = publication.lock();
            // Interrupt bottom half brackets one service pass: causes are
            // read and IER killed first, then resumed after RX/TX work.
            self.packet
                .periodic_service(false)
                .map_err(Error::from)
                .and_then(|_| {
                    self.ps
                        .as_ref()
                        .map_or(Ok(()), |owner| owner.grant.check())
                        .map_err(Error::from)
                })
                .and_then(|_| self.packet.service_begin().map_err(Error::from))
                .and_then(|events| {
                    if let Some(events) = events {
                        if events.bmiss && self.ps_bound {
                            return Err(Error::PeerLost);
                        }
                        if self.ps_bound && (events.tim_timer || events.tsf_oor) {
                            self.packet.ps_receive_on()?;
                            let owner = self.ps.as_mut().ok_or(Error::State)?;
                            if events.tsf_oor {
                                owner.resync();
                            } else {
                                owner.wake_beacon();
                            }
                        }
                    }
                    self.progress()
                })
                .and_then(|frames| {
                    self.packet.service_end()?;
                    self.restore_ps_inner()?;
                    let periodic_idle = self.ps.is_none()
                        && self.ready()
                        && self.rx_idle
                        && self.incoming.is_empty();
                    self.packet.periodic_service(periodic_idle)?;
                    Ok(frames)
                })
        };
        if result.is_err() {
            self.fail_or_queue_reset();
        }
        result
    }
    fn restore_ps_inner(&mut self) -> Result<(), Error> {
        if self.ps_bound
            && self.ps.as_ref().is_some_and(super::ps::Owner::quiet)
            && self.pending.is_none()
            && self.pair_pending.is_none()
            && self.delivered_ps.is_none()
            && self.ps_controls.is_empty()
            && self.delivered_reply.is_none()
            && self.delivered_ba.is_none()
            && self.incoming.is_empty()
            && self.rx_idle
            && self.receive_open()
            && self.tx_ba.as_ref().is_none_or(super::tx_ba::Owner::ready)
            && self
                .security
                .as_ref()
                .is_none_or(|security| !security.handshake_active())
        {
            self.packet.ps_sleep()?;
        }
        Ok(())
    }
    pub(super) fn restore_power_save(&mut self) -> Result<(), Error> {
        let result = {
            let publication = self.publication.clone();
            let _publication = publication.lock();
            self.restore_ps_inner()
        };
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn progress(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        if self.closed.load(Ordering::Acquire)
            || matches!(self.phase, Phase::Prepared | Phase::Failed | Phase::Stopped)
        {
            return Err(Error::State);
        }
        self.packet.check_transmit()?;
        let now = self.now()?;
        if let Some(owner) = &self.ps {
            owner.tick(now.saturating_mul(1_000_000))?;
        }
        self.delivery()?;
        self.rx_idle = false;
        let mut idle = false;
        let mut serviced = false;
        for _ in 0..32 {
            let step = self.packet.receive()?;
            if !step.consumed {
                idle = true;
                break;
            }
            if !serviced {
                // `ath9k_tasklet`: one `rx_active_count` per RX service.
                serviced = true;
                self.rx_active_count = self.rx_active_count.saturating_add(1);
            }
            if let Some(frame) = step.frame {
                if self.lost(&frame) {
                    return Err(Error::PeerLost);
                }
                self.cache(&frame, now)?;
                let peer = self.peer.as_ref().map(|p| p.bss.bssid);
                if let Some(peer) = peer {
                    if let Some(ba) = &mut self.tx_ba {
                        if ba.peer_delba(frame.bytes(), self.own, peer) {
                            continue;
                        }
                    }
                }
                if peer.is_some_and(|ap| self.recipient_delba(frame.bytes(), ap)) {
                    continue;
                }
                if let (Some(peer), Some(_)) = (peer, &mut self.ba) {
                    if frame.bytes().first() == Some(&0x84) {
                        self.ba.as_mut().ok_or(Error::State)?.discard_ppdu();
                        if self.receive_open() {
                            let released = self.ba.as_mut().ok_or(Error::State)?.bar(
                                frame.bytes(),
                                self.own,
                                peer,
                                now.saturating_mul(1_000_000),
                            )?;
                            if let Some(released) = released {
                                self.queue_originals(released)?;
                            }
                        }
                        continue;
                    }
                }
                if self.phase != Phase::Passive {
                    if self.incoming.len() == 256 {
                        return Err(Error::State);
                    }
                    let admitted = self.receive_open();
                    if !admitted {
                        if let Some(ba) = &mut self.ba {
                            ba.discard_ppdu();
                        }
                    }
                    if admitted
                        || (self.security.is_some() && plaintext_eapol(frame.bytes()))
                        || matches!(self.phase, Phase::Authentication | Phase::Association)
                    {
                        let route = if admitted {
                            match (&mut self.ba, peer) {
                                (Some(ba), Some(peer)) => ba.route(
                                    &frame,
                                    self.own,
                                    peer,
                                    now.saturating_mul(1_000_000),
                                    self.epoch,
                                ),
                                _ => super::rx_ba::Route::Pass,
                            }
                        } else {
                            super::rx_ba::Route::Pass
                        };
                        let mut item = Incoming {
                            frame,
                            admitted,
                            ba_token: None,
                            epoch: self.epoch,
                        };
                        match route {
                            super::rx_ba::Route::Drop => {}
                            super::rx_ba::Route::Pass => self.incoming.push_back(item),
                            super::rx_ba::Route::Ordered {
                                tid,
                                sequence,
                                generation,
                            } => {
                                item.ba_token = Some((tid, generation));
                                let batch = self.ba.as_mut().ok_or(Error::State)?.push(
                                    tid,
                                    sequence,
                                    now.saturating_mul(1_000_000),
                                    item,
                                )?;
                                self.queue_originals(batch)?;
                            }
                            super::rx_ba::Route::Pending {
                                tid,
                                sequence,
                                generation,
                            } => {
                                item.ba_token = Some((tid, generation));
                                self.ba.as_mut().ok_or(Error::State)?.stage(
                                    generation,
                                    sequence,
                                    now.saturating_mul(1_000_000),
                                    item,
                                )?;
                            }
                        }
                    }
                }
            } else if let Some(ba) = &mut self.ba {
                ba.discard_ppdu();
            }
        }
        self.rx_idle = idle;
        if self.established {
            if let (Some(ba), Some(peer)) = (&mut self.ba, self.peer.as_ref()) {
                let frames = ba.expire(now.saturating_mul(1_000_000), self.own, peer.bss.bssid)?;
                self.queue_originals(frames)?;
            }
        }
        // A CRC/report descriptor is consumed input, never an RX-idle fence.
        // Inspect all queued peer loss before committing an exact M4 receipt.
        if idle {
            if let Some(receipt) = self.delivered_ba.take() {
                if let Kind::BaResponse(Some(ticket)) = receipt.kind {
                    let staged = self.ba.as_mut().ok_or(Error::State)?.activate(
                        ticket,
                        now.saturating_mul(1_000_000),
                        self.epoch,
                    )?;
                    self.queue_originals(staged)?;
                } else if let Kind::Delba(ticket) = receipt.kind {
                    self.ba
                        .as_mut()
                        .ok_or(Error::State)?
                        .teardown_delivered(ticket)?;
                } else if let Some(ba) = &mut self.tx_ba {
                    match receipt.kind {
                        Kind::TxRequest(t) => ba.request_delivered(t)?,
                        Kind::TxBar(t) => ba.bar_delivered(t, self.epoch)?,
                        Kind::TxDelba(t) => ba.delba_delivered(t),
                        _ => {}
                    }
                }
            }
            if let Some(receipt) = self.delivered_reply.take() {
                let security = self.security.as_mut().ok_or(Error::State)?;
                // Native proves the exact transmitted PM-marked original;
                // shared Security commits its exact original message. Only
                // the S-authorized CCMP-mutable PM bit distinguishes them.
                let original = receipt
                    .security_original
                    .as_deref()
                    .unwrap_or(&receipt.bytes);
                if security.pending_frame() != Some(original) {
                    return Err(Error::State);
                }
                security.reply_delivered(original.len())?;
                self.retire_receive()?;
            }
        }
        if self.established
            && self.pending.is_none()
            && self.pair_pending.is_none()
            && self.delivered_ps.is_none()
            && self.ps_controls.is_empty()
            && self.delivered_reply.is_none()
            && self.delivered_ba.is_none()
            && self
                .security
                .as_ref()
                .is_none_or(|s| s.pending_frame().is_none())
        {
            if let Some((ticket, bytes)) = self
                .ba
                .as_mut()
                .and_then(super::rx_ba::Owner::take_teardown)
            {
                self.transmit(bytes, Kind::Delba(ticket))?;
            }
        }
        let receive_budget = self.incoming.len().min(64);
        for _ in 0..receive_budget {
            if self
                .pending
                .as_ref()
                .is_some_and(|p| !matches!(p.kind, Kind::Data | Kind::TxRetry(..)))
                || self.delivered_reply.is_some()
                || self.delivered_ba.is_some()
                || self
                    .security
                    .as_ref()
                    .is_some_and(|s| s.pending_frame().is_some())
            {
                break;
            }
            let Some(Incoming {
                frame,
                admitted,
                ba_token,
                epoch,
            }) = self.incoming.pop_front()
            else {
                break;
            };
            if (self.pair_pending.is_some()
                || self
                    .pending
                    .as_ref()
                    .is_some_and(|p| matches!(p.kind, Kind::Data | Kind::TxRetry(..))))
                && frame.bytes().first() == Some(&0xd0)
            {
                self.incoming.push_back(Incoming {
                    frame,
                    admitted,
                    ba_token,
                    epoch,
                });
                continue;
            }
            match self.phase {
                Phase::Authentication => {
                    if let Some(mut association) = self
                        .plan
                        .as_mut()
                        .ok_or(Error::State)?
                        .authentication_response(frame.bytes())?
                        .map(|bytes| bytes.to_vec())
                    {
                        if self
                            .plan
                            .as_ref()
                            .is_some_and(|p| p.offered_phy().is_some())
                        {
                            association.extend_from_slice(&narf_wireless::wmm::INFORMATION);
                        }
                        self.phase = Phase::Association;
                        self.transmit(association, Kind::Association)?;
                    }
                }
                Phase::Association => {
                    if let Some(aid) = self
                        .plan
                        .as_mut()
                        .ok_or(Error::State)?
                        .association_response(frame.bytes())?
                    {
                        if self.geometry().is_wide()
                            && self
                                .plan
                                .as_ref()
                                .and_then(JoinPlan::negotiated_phy)
                                .is_none_or(|n| {
                                    n.width() != association::phy::Width::Forty
                                        || n.ht().operation().secondary()
                                            != self.geometry().secondary()
                                })
                        {
                            return Err(Error::WidthFallback);
                        }
                        let peer = self.peer.as_ref().ok_or(Error::State)?;
                        let response_cap =
                            u16::from_le_bytes([frame.bytes()[24], frame.bytes()[25]]);
                        let short = peer.bss.capability & response_cap & 0x400 != 0;
                        let (rates, basic) = self.plan.as_ref().ok_or(Error::State)?.legacy_rates();
                        self.rates =
                            Some(super::rates::Control::new(rates, basic).ok_or(Error::Profile)?);
                        self.packet
                            .set_peer(Some((peer.bss.bssid, aid)), if short { 9 } else { 20 })?;
                        if let Some(n) = self.plan.as_ref().and_then(JoinPlan::negotiated_phy) {
                            let offer = self
                                .plan
                                .as_ref()
                                .and_then(JoinPlan::offered_phy)
                                .ok_or(Error::State)?;
                            let profile = super::ht::response(
                                offer,
                                n,
                                &peer.bss.information_elements,
                                &frame.bytes()[30..],
                                self.rates.ok_or(Error::State)?.basic(),
                                self.geometry(),
                                self.force_twenty,
                            )?;
                            self.packet.set_ht(profile)?;
                            self.ht = Some(profile.mcs());
                            // A malformed non-BE AC keeps the qualified
                            // BE-only profile; no new queue was programmed.
                            if let Some(grant) = self.packet.qos_grant() {
                                if let Ok(qos) = super::qos::Profile::parse(&frame.bytes()[30..]) {
                                    self.packet.enable_qos(&grant, qos)?;
                                }
                            }
                        }
                        self.last_peer = now;
                        self.phase = Phase::FourWay;
                    }
                }
                Phase::FourWay | Phase::Open => {
                    if epoch != self.epoch && !plaintext_eapol(frame.bytes()) {
                        continue;
                    }
                    if let Some((tid, generation)) = ba_token {
                        if self.ba.as_ref().is_none_or(|b| !b.live(tid, generation)) {
                            continue;
                        }
                    }
                    if admitted && self.receive_open() {
                        let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                        if self.recipient_delba(frame.bytes(), ap) {
                            continue;
                        }
                    }
                    if self.ps_bound && admitted && self.receive_open() {
                        let bytes = frame.bytes();
                        let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                        // Linux PS-Poll wait may finish on a plaintext Null
                        // response. It grants no DATA/key/PN/replay receipt.
                        if bytes.len() == 24
                            && bytes[0] == 0x48
                            && bytes[1] & !0x20 == 2
                            && bytes[4..10] == self.own
                            && bytes[10..16] == ap
                            && bytes[16..22] == ap
                            && bytes[22] & 15 == 0
                        {
                            self.ps_data(bytes);
                            continue;
                        }
                    }
                    if self.ht.is_some() && admitted && self.receive_open() {
                        if let Some(ba) = &mut self.tx_ba {
                            if ba.response(
                                frame.bytes(),
                                self.own,
                                self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                                now.saturating_mul(1_000_000),
                                self.epoch,
                            )? {
                                continue;
                            }
                        }
                        if let Some(reply) = super::ht::decline(
                            frame.bytes(),
                            self.own,
                            self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                        ) {
                            let answer = if let Some(ba) = &mut self.ba {
                                ba.request(
                                    frame.bytes(),
                                    self.own,
                                    self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                                    now.saturating_mul(1_000_000),
                                    self.epoch,
                                )?
                            } else if let Some(grant) = self.packet.rx_ba_grant() {
                                let mut ba = super::rx_ba::Owner::new(grant.window())?;
                                let answer = ba.request(
                                    frame.bytes(),
                                    self.own,
                                    self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                                    now.saturating_mul(1_000_000),
                                    self.epoch,
                                )?;
                                if answer.as_ref().is_some_and(|r| r.bytes[27..29] == [0, 0]) {
                                    // The complete explicit-SSN reorder storage
                                    // exists before live filter/response writes.
                                    self.packet.enable_rx_ba(&grant)?;
                                    self.ba = Some(ba);
                                }
                                answer
                            } else {
                                None
                            };
                            if let Some(answer) = answer {
                                let kind = if answer.bytes[27..29] == [0, 0] {
                                    Kind::BaResponse(answer.ticket)
                                } else {
                                    Kind::Decline
                                };
                                self.transmit_or_defer_ps_control(answer.bytes, kind)?;
                            } else {
                                self.transmit_or_defer_ps_control(reply, Kind::Decline)?;
                            }
                            continue;
                        }
                    }
                    if !admitted && !plaintext_eapol(frame.bytes()) {
                        continue;
                    }
                    if frame.bytes().first() == Some(&0x88)
                        && frame.bytes().get(24).is_some_and(|b| b & 0x80 != 0)
                    {
                        if self.ht.is_none() || !admitted || !self.receive_open() {
                            continue;
                        }
                        let f = frame.bytes();
                        let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                        if f[10..16] != peer
                            || f[16..22] != peer
                            || (f[4..10] != self.own && f[4] & 1 == 0)
                        {
                            continue;
                        }
                        // Reserve the complete worst-case subframe owner
                        // before Security can commit this original MPDU PN.
                        if self.received.len() + narf_wireless::amsdu::MAX_SUBFRAMES > 256 {
                            return Err(Error::State);
                        }
                        self.received
                            .try_reserve(narf_wireless::amsdu::MAX_SUBFRAMES)
                            .map_err(|_| Error::State)?;
                        let batch = if let Some(security) = &mut self.security {
                            if frame.bytes()[24] & 0xf0 == 0xe0 {
                                if ba_token.is_some() {
                                    security.receive_amsdu_block_ack(&frame).ok().flatten()
                                } else {
                                    None
                                }
                            } else {
                                security.receive_amsdu(&frame).ok().flatten()
                            }
                        } else if frame.bytes()[1] & 0x40 == 0 {
                            narf_wireless::amsdu::decode(
                                &frame.bytes()[26..],
                                self.own,
                                frame.bytes()[4..10].try_into().unwrap(),
                            )
                            .ok()
                        } else {
                            None
                        };
                        if let Some(batch) = batch {
                            self.ps_data(frame.bytes());
                            if self.received.len() + batch.len() > 256 {
                                return Err(Error::State);
                            }
                            self.last_peer = now;
                            self.received.extend(batch);
                        }
                        continue;
                    }
                    if let Some(security) = &mut self.security {
                        let handshake_active = security.handshake_active();
                        let environment = &self.environment;
                        let initial = &mut self.initial_nonce;
                        match security.receive_with_nonce(&frame, || {
                            initial.take().or_else(|| environment.nonce())
                        })? {
                            station_security::Rx::Data(bytes) => {
                                if let Some(bytes) = ethernet(
                                    &bytes,
                                    self.own,
                                    self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                                ) {
                                    self.ps_data(frame.bytes());
                                    self.last_peer = now;
                                    if self.received.len() == 256 {
                                        return Err(Error::State);
                                    }
                                    self.received.push_back(bytes);
                                }
                            }
                            station_security::Rx::ReplyReady => {
                                if self.established && !handshake_active {
                                    self.deadline = now.saturating_add(5000);
                                }
                                self.retire_receive()?;
                            }
                            station_security::Rx::Ignored => {}
                        }
                    } else if let Some(bytes) = ethernet(
                        frame.bytes(),
                        self.own,
                        self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                    ) {
                        self.ps_data(frame.bytes());
                        self.last_peer = now;
                        if self.received.len() == 256 {
                            return Err(Error::State);
                        }
                        self.received.push_back(bytes);
                    }
                }
                _ => {}
            }
        }
        if self.pending.is_none()
            && self.pair_pending.is_none()
            && self.delivered_reply.is_none()
            && self.delivered_ps.is_none()
        {
            if let Some(reply) = self
                .security
                .as_ref()
                .and_then(Security::pending_frame)
                .map(|bytes| bytes.to_vec())
            {
                self.transmit(reply, Kind::Security)?;
            }
        }
        if idle
            && self.incoming.is_empty()
            && self.pending.is_none()
            && self.delivered_reply.is_none()
            && self.phase == Phase::FourWay
            && self.security.as_ref().is_none_or(Security::port_open)
        {
            self.established = true;
            self.phase = Phase::Open;
            self.last_peer = now;
        }
        if !self.ps_bound
            && self.receive_open()
            && self.pending.is_none()
            && self.pair_pending.is_none()
            && self.delivered_reply.is_none()
            && self.delivered_ba.is_none()
            && self.delivered_ps.is_none()
        {
            if let Some(owner) = self.ps.as_ref().filter(|owner| owner.active()) {
                self.packet.enable_ps(&owner.grant)?;
                self.ps_bound = true;
            }
        }
        if idle && self.incoming.is_empty() {
            if let Some(receipt) = self.delivered_ps.take() {
                let ticket = match receipt.kind {
                    Kind::PsNull(ticket) | Kind::PsPoll(ticket) => ticket,
                    _ => return Err(Error::State),
                };
                if let Some(false) = self.ps.as_mut().ok_or(Error::State)?.delivered(
                    ticket,
                    now.saturating_mul(1_000_000),
                    self.epoch,
                )? {
                    self.packet.ps_awake_mode()?;
                }
            }
        }
        if idle
            && self.incoming.is_empty()
            && self.receive_open()
            && self.pending.is_none()
            && self.pair_pending.is_none()
            && self.delivered_ps.is_none()
            && self.delivered_reply.is_none()
            && self.delivered_ba.is_none()
            && self
                .security
                .as_ref()
                .is_none_or(|security| !security.handshake_active())
        {
            if let Some((bytes, kind)) = self.ps_controls.pop_front() {
                self.transmit(bytes, kind)?;
            }
        }
        if self.ps_bound
            && idle
            && self.incoming.is_empty()
            && self.receive_open()
            && self.ps_controls.is_empty()
            && self.tx_ba_checked
            && self.pending.is_none()
            && self.pair_pending.is_none()
            && self.delivered_ps.is_none()
            && self.delivered_reply.is_none()
            && self.delivered_ba.is_none()
            && self.tx_ba.as_ref().is_none_or(super::tx_ba::Owner::ready)
            && self
                .security
                .as_ref()
                .is_none_or(|security| !security.handshake_active())
        {
            if self.ps.as_ref().is_some_and(super::ps::Owner::active) {
                let grant = self.ps.as_ref().ok_or(Error::State)?.grant.clone();
                self.packet.enable_ps(&grant)?;
            }
            if let Some(action) = self
                .ps
                .as_mut()
                .ok_or(Error::State)?
                .next(now.saturating_mul(1_000_000), self.epoch)?
            {
                let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                let (bytes, kind) = match action {
                    super::ps::Action::Null(ticket, on) => {
                        let sequence = if let Some(security) = &mut self.security {
                            security.reserve_plain_control_sequence()?
                        } else {
                            let sequence = self.sequence;
                            self.sequence = (sequence + 1) & 4095;
                            sequence
                        };
                        (
                            super::ps::null(self.own, ap, sequence, on),
                            Kind::PsNull(ticket),
                        )
                    }
                    super::ps::Action::Poll(ticket) => (
                        super::ps::poll(self.own, ap, self.ps_aid()?),
                        Kind::PsPoll(ticket),
                    ),
                };
                self.transmit(bytes, kind)?;
            }
        }
        if self.receive_open()
            && self.pending.is_none()
            && self.pair_pending.is_none()
            && self.delivered_reply.is_none()
            && self.delivered_ba.is_none()
            && self.delivered_ps.is_none()
        {
            if !self.tx_ba_checked && self.ht.is_some() {
                self.tx_ba_checked = true;
                if let Some(grant) = self.packet.tx_ba_grant() {
                    let plan = self.plan.as_ref().ok_or(Error::State)?;
                    let owner = super::tx_ba::Owner::new(
                        grant.clone(),
                        plan.offered_phy().ok_or(Error::State)?,
                        plan.negotiated_phy().ok_or(Error::State)?,
                    )?;
                    self.packet.enable_tx_ba(&grant)?;
                    self.tx_ba = Some(owner);
                }
            }
            if self.tx_ba.is_some() {
                let next = if let Some(s) = &self.security {
                    s.next_qos_sequence(0)?
                } else {
                    self.qos_sequence[0]
                };
                self.tx_sequence = Some(next);
                let ba = self.tx_ba.as_mut().unwrap();
                ba.progress_bar(now.saturating_mul(1_000_000))?;
                if let Some(action) = ba.next(
                    self.own,
                    self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                    next,
                    now.saturating_mul(1_000_000),
                    self.epoch,
                )? {
                    use super::tx_ba::Action;
                    let (bytes, kind) = match action {
                        Action::Request(t, b) => (b, Kind::TxRequest(t)),
                        Action::Retry(t, i, b) => (b, Kind::TxRetry(t, i)),
                        Action::Bar(t, b) => (b, Kind::TxBar(t)),
                        Action::Delba(t, b) => (b, Kind::TxDelba(t)),
                    };
                    self.transmit(bytes, kind)?;
                }
            }
        }
        if self.phase != Phase::Passive {
            let expired = if self.established {
                now.saturating_sub(self.last_peer) >= 5000
                    || now >= self.deadline
                        && self
                            .security
                            .as_ref()
                            .is_some_and(Security::handshake_active)
            } else {
                now >= self.deadline
            };
            if expired {
                return Err(Error::Timeout);
            }
        }
        if idle
            && self.incoming.is_empty()
            && self.established
            && self.security.as_ref().is_none_or(Security::port_open)
        {
            Ok(self.received.drain(..).collect())
        } else {
            Ok(Vec::new())
        }
    }
    fn queue_originals(&mut self, batch: Vec<Incoming>) -> Result<(), Error> {
        if self.incoming.len() + batch.len() > 256 {
            return Err(Error::State);
        }
        self.incoming
            .try_reserve(batch.len())
            .map_err(|_| Error::State)?;
        self.incoming.extend(batch);
        Ok(())
    }
    pub(super) async fn scan_for(&mut self, dwell_ms: u64) -> Result<Vec<ObservedBss>, Error> {
        if !(1..=1024).contains(&dwell_ms) {
            return Err(Error::Profile);
        }
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        let until = self.now()?.saturating_add(dwell_ms);
        loop {
            self.poll()?;
            if self.now()? >= until {
                return Ok(self.candidates());
            }
            self.environment.pause().await;
        }
    }
    /// Actual broadcast probes use the same calibrated/policy/RF-silent
    /// packet owner and terminal descriptor receipts as every management TX.
    pub(super) async fn active_scan_for(
        &mut self,
        dwell_ms: u64,
        ssids: &[Vec<u8>],
    ) -> Result<Vec<ObservedBss>, Error> {
        if self.reset_pending().is_some() {
            return Err(Error::Busy);
        }
        if !(1..=1024).contains(&dwell_ms)
            || ssids.len() > 4
            || ssids.iter().any(|ssid| ssid.len() > 32)
        {
            return Err(Error::Profile);
        }
        if self.phase() != Phase::Passive || self.pending.is_some() {
            return Err(Error::Busy);
        }
        let mut attempt = Attempt {
            closed: self.closed.clone(),
            publication: self.publication.clone(),
            armed: true,
        };
        self.cache.clear();
        let until = self.now()?.saturating_add(dwell_ms);
        let wildcard = Vec::new();
        let names = if ssids.is_empty() {
            core::slice::from_ref(&wildcard)
        } else {
            ssids
        };
        for name in names {
            if self.now()? >= until {
                return Err(Error::Timeout);
            }
            let mut probe = vec![0x40, 0, 0, 0];
            probe.extend_from_slice(&[255; 6]);
            probe.extend_from_slice(&self.own);
            probe.extend_from_slice(&[255; 6]);
            probe.extend_from_slice(&[0, 0, 0, name.len() as u8]);
            probe.extend_from_slice(name);
            if self.frequency_mhz() >= 5000 {
                // 5 GHz (AR9280): the eight OFDM rates only and no DS
                // Parameter Set (`mac80211 ieee80211_build_preq_ies_band`
                // adds DS params on 2.4 GHz only).
                probe.extend_from_slice(&[1, 8, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c]);
            } else {
                // Driver-owned legacy CCK/OFDM rates, no HT/VHT/WMM promotion.
                probe.extend_from_slice(&[
                    1,
                    4,
                    0x82,
                    0x84,
                    0x8b,
                    0x96,
                    50,
                    8,
                    12,
                    18,
                    24,
                    36,
                    48,
                    72,
                    96,
                    108,
                    3,
                    1,
                    self.channel(),
                ]);
            }
            {
                let publication = self.publication.clone();
                let _publication = publication.lock();
                self.transmit(probe, Kind::Probe)?;
            }
            loop {
                self.poll()?;
                if self.now()? > until {
                    return Err(Error::Timeout);
                }
                if self.pending.is_none() {
                    break;
                }
                if self.now()? >= until {
                    return Err(Error::Timeout);
                }
                self.environment.pause().await;
            }
        }
        loop {
            self.poll()?;
            if self.now()? >= until {
                let result = self.candidates();
                attempt.armed = false;
                return Ok(result);
            }
            self.environment.pause().await;
        }
    }
    #[cfg(feature = "kernel-test")]
    pub(super) async fn associate(
        &mut self,
        bssid: [u8; 6],
        ssid: &[u8],
        pmk: Option<Zeroizing<[u8; 32]>>,
        ies: &[u8],
    ) -> Result<(), Error> {
        self.associate_mode(bssid, ssid, pmk, ies, false).await
    }
    pub(super) async fn associate_mode(
        &mut self,
        bssid: [u8; 6],
        ssid: &[u8],
        pmk: Option<Zeroizing<[u8; 32]>>,
        ies: &[u8],
        force_twenty: bool,
    ) -> Result<(), Error> {
        self.force_twenty = force_twenty;
        if self.reset_pending().is_some() {
            return Err(Error::Busy);
        }
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        let candidate = self
            .candidates()
            .into_iter()
            .find(|c| c.bss.bssid == bssid)
            .ok_or(Error::Profile)?;
        if candidate.bss.channel != self.channel() {
            return Err(Error::Profile);
        }
        let mode = if pmk.is_some() {
            SecurityMode::Wpa2Psk
        } else {
            SecurityMode::Open
        };
        let grant = self.packet.ht_grant().filter(|g| g.check().is_ok());
        let mut plan = if let Some(g) = grant {
            let plan = JoinPlan::prepare_with_phy(&candidate.bss, self.own, ssid, mode, g.local())?;
            if let Some(offer) = plan.offered_phy() {
                if !self.geometry().is_wide()
                    && !force_twenty
                    && offer.ht().operation().secondary().is_some()
                {
                    return Err(Error::Profile);
                }
                if self.geometry().is_wide()
                    && (offer.width() != association::phy::Width::Forty
                        || offer.ht().operation().secondary() != self.geometry().secondary())
                {
                    return Err(Error::WidthFallback);
                }
                super::ht::contention(&candidate.bss.information_elements)?;
            }
            plan
        } else {
            JoinPlan::prepare(&candidate.bss, self.own, ssid, mode)?
        };
        plan.append_sme_ies(ies)?;
        let (rates, basic) = plan.legacy_rates();
        let rates = super::rates::Control::new(rates, basic).ok_or(Error::Profile)?;
        if let Some(pmk) = pmk {
            let nonce = self.environment.nonce().ok_or(Error::Entropy)?;
            let station_rsne = plan.rsn_body().ok_or(Error::Profile)?;
            self.security = Some(Security::new(
                self.own,
                bssid,
                &pmk,
                &station_rsne,
                candidate.ap_rsne.as_deref().ok_or(Error::Profile)?,
                candidate.ap_rsnxe.as_deref(),
                3,
            )?);
            self.initial_nonce = Some(nonce);
        }
        let mut attempt = Attempt {
            closed: self.closed.clone(),
            publication: self.publication.clone(),
            armed: true,
        };
        self.peer = Some(candidate);
        self.rates = Some(rates);
        self.deadline = self.now()?.saturating_add(5000);
        self.last_peer = self.last_now;
        let auth = plan.start_authentication()?.to_vec();
        self.plan = Some(plan);
        self.phase = Phase::Authentication;
        {
            let publication = self.publication.clone();
            let _publication = publication.lock();
            self.transmit(auth, Kind::Authentication)?;
        }
        loop {
            self.poll()?;
            if self.established {
                attempt.armed = false;
                return Ok(());
            }
            self.environment.pause().await;
        }
    }
    pub(super) fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
        let result = {
            let publication = self.publication.clone();
            let _publication = publication.lock();
            self.send_inner(frame)
        };
        if result
            .as_ref()
            .is_err_and(|e| !matches!(e, Error::Busy | Error::Profile))
        {
            self.fail();
        }
        result
    }
    fn send_inner(&mut self, frame: &[u8]) -> Result<(), Error> {
        if !self.ready() {
            return Err(Error::Busy);
        }
        self.packet.check_transmit()?;
        let native = self.native_data(frame)?;
        self.transmit(native, Kind::Data)
    }
    fn native_data(&mut self, frame: &[u8]) -> Result<Vec<u8>, Error> {
        let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
        let tid = self.transmit_tid(frame);
        let mut native = if let Some(security) = &mut self.security {
            if self.ht.is_some() {
                security.transmit_ethernet_qos(frame, tid)?
            } else {
                security.transmit_ethernet(frame)?
            }
        } else {
            if !admitted(frame, self.own) {
                return Err(Error::Profile);
            }
            let mut bytes = vec![if self.ht.is_some() { 0x88 } else { 8 }, 1, 0, 0];
            bytes.extend_from_slice(&peer);
            bytes.extend_from_slice(&self.own);
            bytes.extend_from_slice(&frame[..6]);
            let sequence = if self.ht.is_some() {
                self.qos_sequence[usize::from(tid)]
            } else {
                self.sequence
            };
            bytes.extend_from_slice(&(sequence << 4).to_le_bytes());
            if self.ht.is_some() {
                self.qos_sequence[usize::from(tid)] = (sequence + 1) & 4095;
            } else {
                self.sequence = (sequence + 1) & 4095;
            }
            if self.ht.is_some() {
                bytes.extend_from_slice(&[tid, 0]);
            }
            bytes.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
            bytes.extend_from_slice(&frame[12..]);
            bytes
        };
        if self.ps_bound && self.ps.as_ref().is_some_and(super::ps::Owner::mark_pm) {
            native[1] |= 0x10;
        }
        if self.ht.is_some() && tid == 0 {
            self.tx_sequence =
                Some(((u16::from_le_bytes([native[22], native[23]]) >> 4) + 1) & 4095);
        }
        Ok(native)
    }
    /// Exact Ethernet prefix capacity before any shared QoS SN/CCMP PN is
    /// consumed. Does not manufacture a packet or grant native publication.
    pub(super) fn aggregate_count(&self, frames: &[&[u8]]) -> Result<usize, Error> {
        if !self.can_aggregate() {
            return Ok(1);
        }
        self.packet.check_transmit()?;
        let mut lengths = Vec::new();
        for frame in frames.iter().take(super::tx_ba::MAX_MEMBERS) {
            if !admitted(frame, self.own) || self.transmit_tid(frame) != 0 {
                break;
            }
            // QoS26 + SNAP8 - Ethernet14; CCMP ExtIV8 + MIC8 only
            // when the retained shared security owner protects the original.
            lengths.push(frame.len() + 20 + if self.security.is_some() { 16 } else { 0 });
        }
        let mcs = 7 - self.ht.ok_or(Error::State)?.leading_zeros() as u8;
        Ok(self
            .tx_ba
            .as_ref()
            .ok_or(Error::State)?
            .prefix(&lengths, mcs))
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn send_pair(&mut self, a: &[u8], b: &[u8]) -> Result<(), Error> {
        self.send_aggregate(&[a, b])
    }
    pub(super) fn send_aggregate(&mut self, ethernet: &[&[u8]]) -> Result<(), Error> {
        let result = {
            let publication = self.publication.clone();
            let _publication = publication.lock();
            (|| {
                if !self.can_aggregate() {
                    return Err(Error::Busy);
                }
                if ethernet.len() < 2
                    || ethernet.len() > super::tx_ba::MAX_MEMBERS
                    || self.aggregate_count(ethernet)? != ethernet.len()
                {
                    return Err(Error::Profile);
                }
                // Preflight all lengths/TIDs/source bounds before the first
                // reservation. Encoding failure is terminal; consumed PNs and
                // sequence numbers are never reused or silently retried fresh.
                let frames: Vec<Vec<u8>> = ethernet
                    .iter()
                    .map(|frame| self.native_data(frame))
                    .collect::<Result<_, _>>()?;
                let mcs = 7 - self.ht.ok_or(Error::State)?.leading_zeros() as u8;
                let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                let copies: Option<Vec<Vec<u8>>> =
                    if frames.iter().any(|frame| frame[1] & 0x10 != 0) {
                        let source = &self.ps.as_ref().ok_or(Error::State)?.grant;
                        Some(
                            frames
                                .iter()
                                .map(|frame| {
                                    super::descriptor::ps_unmark(frame, source)
                                        .map_err(|_| Error::Profile)
                                })
                                .collect::<Result<_, _>>()?,
                        )
                    } else {
                        None
                    };
                let ba = self.tx_ba.as_mut().ok_or(Error::State)?;
                let refs: Vec<&[u8]> = copies
                    .as_deref()
                    .unwrap_or(&frames)
                    .iter()
                    .map(Vec::as_slice)
                    .collect();
                let permit = ba.permit(&refs, self.own, peer, mcs)?;
                ba.begin_pair(permit, frames.clone(), self.epoch)?;
                let id = self.packet.submit_aggregate(
                    &frames,
                    mcs,
                    self.rates.ok_or(Error::State)?.basic(),
                    permit,
                )?;
                self.pair_pending = Some(PairPending {
                    id,
                    originals: frames,
                });
                Ok(())
            })()
        };
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, Error::Busy | Error::Profile))
        {
            self.fail();
        }
        result
    }
}
/// The in-place `ath_reset` of an AR9003 EDMA station (the only engine
/// with one). The owner runs `ath9k_hw_reset` on [`Self::reset_port`]
/// between the two halves while it holds this station.
impl<P: Port, E: Environment> Radio<P, E, Dispatch<P>> {
    /// `ath_prepare_reset`: the station half ([`Self::begin_reset`]) then
    /// the EDMA engine stop that keeps every ring and buffer. A failure
    /// closes the generation (the owner then retires it).
    pub(super) fn pause_for_reset(&mut self) -> Result<ResetType, Error> {
        let result = (|| {
            let kind = self.begin_reset()?;
            let Dispatch::Ar9003(packet) = &mut self.packet else {
                return Err(Error::State);
            };
            packet.pause_for_reset()?;
            Ok(kind)
        })();
        if result.is_err() {
            self.fail();
        }
        result
    }
    /// The paused engine's port.
    pub(super) fn reset_port(&self) -> Option<&P> {
        match &self.packet {
            Dispatch::Ar9003(packet) => packet.paused_port(),
            Dispatch::Ar9002(_) => None,
        }
    }
    /// `ath_complete_reset`: restart RX/TX DMA on the retained rings, re-write
    /// the BSSID/AID and slot, re-enable interrupts, then the station half
    /// ([`Self::finish_reset`]). A failure closes the generation.
    pub(super) fn resume_after_reset(&mut self) -> Result<(), Error> {
        let result = (|| {
            let publication = self.publication.clone();
            let _publication = publication.lock();
            let Dispatch::Ar9003(packet) = &mut self.packet else {
                return Err(Error::State);
            };
            packet.resume_after_reset()?;
            self.finish_reset()
        })();
        if result.is_err() {
            self.fail();
        }
        result
    }
}
pub(super) fn admitted(frame: &[u8], own: [u8; 6]) -> bool {
    (14..=1514).contains(&frame.len())
        && frame[6..12] == own
        && frame[..6] != [0; 6]
        && u16::from_be_bytes([frame[12], frame[13]]) >= 0x600
        && !matches!(
            u16::from_be_bytes([frame[12], frame[13]]),
            0x888e | 0x80f3 | 0x8137
        )
}
fn ethernet(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> Option<Vec<u8>> {
    let h = if frame.first() == Some(&0x88) { 26 } else { 24 };
    if !(h + 8..=h + 1508).contains(&frame.len())
        || !matches!(frame[0], 8 | 0x88)
        || h == 26 && (!matches!(frame[24] & 0xf0, 0 | 0x60) || frame[25] != 0)
        || frame[1] & 0xc7 != 2
        || frame[22] & 15 != 0
        || frame[10..16] != peer
        || (frame[4..10] != own && frame[4] & 1 == 0)
        || frame[16] & 1 != 0
        || frame[16..22] == [0; 6]
        || frame[h..h + 6] != [0xaa, 0xaa, 3, 0, 0, 0]
    {
        return None;
    }
    let proto = u16::from_be_bytes([frame[h + 6], frame[h + 7]]);
    if proto < 0x600 || matches!(proto, 0x888e | 0x80f3 | 0x8137) {
        return None;
    }
    let mut bytes = Vec::with_capacity(frame.len() - 18);
    bytes.extend_from_slice(&frame[4..10]);
    bytes.extend_from_slice(&frame[16..22]);
    bytes.extend_from_slice(&frame[h + 6..]);
    Some(bytes)
}
fn plaintext_eapol(f: &[u8]) -> bool {
    f.len() >= 36
        && f[..2] == [8, 2]
        && f[22] & 15 == 0
        && f[24..32] == [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]
}

#[cfg(feature = "kernel-test")]
#[path = "station/tests.rs"]
pub(super) mod tests;

mod engine;
pub(in crate::ath9k) use engine::{Dispatch, Engine};
