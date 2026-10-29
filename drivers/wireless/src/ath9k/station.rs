// SPDX-License-Identifier: GPL-2.0-or-later
//! One retained AR9285 channel1 legacy/qualified-HT20 station, host RSNA/CCMP.
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
    fn now_ms(&self) -> u64;
    fn nonce(&self) -> Option<[u8; 32]>;
    fn pause(&self) -> impl Future<Output = ()> + Send;
}
pub(super) struct NativeEnvironment;
impl Environment for NativeEnvironment {
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
}
struct Pending {
    id: u64,
    bytes: Vec<u8>,
    kind: Kind,
    epoch: u64,
}
struct PairPending {
    id: u64,
    originals: [Vec<u8>; 2],
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
pub(super) struct Radio<P: Port, E: Environment> {
    packet: Packet<P>,
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
    epoch: u64,
}
impl<P: Port, E: Environment> core::fmt::Debug for Radio<P, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ar9285Station")
            .field("phase", &self.phase)
            .field("established", &self.established)
            .finish_non_exhaustive()
    }
}
impl<P: Port, E: Environment> Radio<P, E> {
    pub(super) fn new(packet: Packet<P>, own: [u8; 6], noise: i16, environment: E) -> Self {
        Self {
            packet,
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
            epoch: 1,
        }
    }
    pub(super) fn closed(&self) -> Arc<AtomicBool> {
        self.closed.clone()
    }
    pub(super) fn publication(&self) -> Arc<IrqSafeSpinLock<()>> {
        self.publication.clone()
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
            && self.pair_pending.is_none()
            && self.tx_ba.as_ref().is_none_or(super::tx_ba::Owner::ready)
            && self.pending.is_none()
            && self.delivered_reply.is_none()
            && self.delivered_ba.is_none()
            && self.security.as_ref().is_none_or(Security::port_open)
    }
    pub(super) fn receive_open(&self) -> bool {
        self.peer().is_some() && self.security.as_ref().is_none_or(Security::port_open)
    }
    pub(super) fn interrupt(&self) -> Option<Arc<super::irq::Signal>> {
        self.packet.interrupt()
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
    pub(super) fn can_aggregate(&self) -> bool {
        self.ready() && self.tx_ba.as_ref().is_some_and(super::tx_ba::Owner::paired)
    }
    pub(super) fn current_receive(&self, epoch: u64) -> Result<bool, Error> {
        self.packet.check_transmit()?;
        Ok(self.epoch == epoch && self.receive_open())
    }
    fn retire_receive(&mut self) -> Result<(), Error> {
        self.epoch = self.epoch.checked_add(1).ok_or(Error::State)?;
        self.received.clear();
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
    fn transmit(&mut self, mut bytes: Vec<u8>, kind: Kind) -> Result<(), Error> {
        // Caller holds publication; this helper never awaits or re-enters it.
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        if self.pending.is_some()
            || self.pair_pending.is_some()
            || self.delivered_reply.is_some()
            || self.delivered_ba.is_some()
        {
            return Err(Error::Busy);
        }
        if !matches!(
            kind,
            Kind::Security | Kind::Data | Kind::TxRetry(..) | Kind::TxBar(_)
        ) {
            bytes[22..24].copy_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
        }
        let id = if matches!(kind, Kind::Data | Kind::TxRetry(..)) {
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
                0
            } else {
                self.rates.ok_or(Error::State)?.basic()
            };
            self.packet.submit(&bytes, rate)?
        };
        self.pending = Some(Pending {
            id,
            bytes,
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
            association::observe_with_phy(frame, 1, self.own, signal, &g.local())
        } else {
            association::observe(frame, 1, self.own, signal)
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
            } else if pending.kind == Kind::Data {
                ba.single_delivered(
                    u16::from_le_bytes([pending.bytes[22], pending.bytes[23]]) >> 4,
                    delivery.delivered,
                    self.last_now.saturating_mul(1_000_000),
                    self.epoch,
                    pending.epoch,
                )?;
            }
        }
        if pending.kind == Kind::Security {
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
        let result = {
            let publication = self.publication.clone();
            let _publication = publication.lock();
            // Interrupt bottom half brackets one service pass: causes are
            // read and IER killed first, then resumed after RX/TX work.
            self.packet
                .service_begin()
                .map_err(Error::from)
                .and_then(|_| self.progress())
                .and_then(|frames| {
                    self.packet.service_end()?;
                    Ok(frames)
                })
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
        self.delivery()?;
        let mut idle = false;
        for _ in 0..32 {
            let step = self.packet.receive()?;
            if !step.consumed {
                idle = true;
                break;
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
                if let (Some(peer), Some(ba)) = (peer, &mut self.ba) {
                    if ba.delba(frame.bytes(), self.own, peer) {
                        continue;
                    }
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
                if security.pending_frame() != Some(receipt.bytes.as_slice()) {
                    return Err(Error::State);
                }
                security.reply_delivered(receipt.bytes.len())?;
                self.retire_receive()?;
            }
        }
        if self.established
            && self.pending.is_none()
            && self.pair_pending.is_none()
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
                                self.transmit(answer.bytes, kind)?;
                            } else {
                                self.transmit(reply, Kind::Decline)?;
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
        if self.pending.is_none() && self.pair_pending.is_none() && self.delivered_reply.is_none() {
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
        if self.receive_open()
            && self.pending.is_none()
            && self.pair_pending.is_none()
            && self.delivered_reply.is_none()
            && self.delivered_ba.is_none()
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
            // Driver-owned legacy CCK/OFDM rates, no HT/VHT/WMM promotion.
            probe.extend_from_slice(&[
                1, 4, 0x82, 0x84, 0x8b, 0x96, 50, 8, 12, 18, 24, 36, 48, 72, 96, 108, 3, 1, 1,
            ]);
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
    pub(super) async fn associate(
        &mut self,
        bssid: [u8; 6],
        ssid: &[u8],
        pmk: Option<Zeroizing<[u8; 32]>>,
        ies: &[u8],
    ) -> Result<(), Error> {
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        let candidate = self
            .candidates()
            .into_iter()
            .find(|c| c.bss.bssid == bssid)
            .ok_or(Error::Profile)?;
        if candidate.bss.channel != 1 {
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
                if offer.ht().operation().secondary().is_some() {
                    return Err(Error::Profile);
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
        let native = if let Some(security) = &mut self.security {
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
        if self.ht.is_some() && tid == 0 {
            self.tx_sequence =
                Some(((u16::from_le_bytes([native[22], native[23]]) >> 4) + 1) & 4095);
        }
        Ok(native)
    }
    pub(super) fn send_pair(&mut self, a: &[u8], b: &[u8]) -> Result<(), Error> {
        let result = {
            let publication = self.publication.clone();
            let _publication = publication.lock();
            (|| {
                if !self.can_aggregate() {
                    return Err(Error::Busy);
                }
                self.packet.check_transmit()?;
                if !admitted(a, self.own) || !admitted(b, self.own) {
                    return Err(Error::Profile);
                }
                // The measured sender agreement owns BE/TID0 only.
                if self.transmit_tid(a) != 0 || self.transmit_tid(b) != 0 {
                    return Err(Error::Profile);
                }
                let frames = [self.native_data(a)?, self.native_data(b)?];
                let mcs = 7 - self.ht.ok_or(Error::State)?.leading_zeros() as u8;
                let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                let ba = self.tx_ba.as_mut().ok_or(Error::State)?;
                let permit = ba.permit([&frames[0], &frames[1]], self.own, peer, mcs)?;
                ba.begin_pair(permit, frames.clone(), self.epoch)?;
                let id = self.packet.submit_pair(
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
            .is_err_and(|e| !matches!(e, Error::Busy | Error::Profile))
        {
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
