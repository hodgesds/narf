// SPDX-License-Identifier: GPL-2.0-or-later
//! One retained AR9285 legacy channel1 station, with host RSNA/CCMP.
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
}
struct Pending {
    id: u64,
    bytes: Vec<u8>,
    kind: Kind,
}
struct Entry {
    candidate: ObservedBss,
    seen: u64,
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
    incoming: VecDeque<Mpdu>,
    received: VecDeque<Vec<u8>>,
    pending: Option<Pending>,
    delivered_reply: Option<Pending>,
    initial_nonce: Option<[u8; 32]>,
    sequence: u16,
    established: bool,
    deadline: u64,
    last_peer: u64,
    last_now: u64,
    rates: Option<super::rates::Control>,
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
            initial_nonce: None,
            sequence: 1,
            established: false,
            deadline: 0,
            last_peer: 0,
            last_now: 0,
            rates: None,
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
        self.peer().is_some()
            && self.pending.is_none()
            && self.delivered_reply.is_none()
            && self.security.as_ref().is_none_or(Security::port_open)
    }
    pub(super) fn start(&mut self) -> Result<(), Error> {
        let publication = self.publication.clone();
        let _publication = publication.lock();
        if self.phase() != Phase::Prepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.packet.start()?;
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
        if self.pending.is_some() || self.delivered_reply.is_some() {
            return Err(Error::Busy);
        }
        if !matches!(kind, Kind::Security | Kind::Data) {
            bytes[22..24].copy_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
        }
        let id = if kind == Kind::Data {
            let control = self.rates.ok_or(Error::State)?;
            self.packet.submit_rates(&bytes, control.series())?
        } else {
            let rate = if kind == Kind::Probe {
                0
            } else {
                self.rates.ok_or(Error::State)?.basic()
            };
            self.packet.submit(&bytes, rate)?
        };
        self.pending = Some(Pending { id, bytes, kind });
        Ok(())
    }
    fn cache(&mut self, frame: &Mpdu, now: u64) {
        // Linux uses a -95dBm reference, adjusted only for NF above nominal+6.
        let signal = (frame.rssi != i8::MIN).then(|| {
            (-95 + (self.noise + 112).max(0) + i16::from(frame.rssi)).clamp(-127, 0) as i8
        });
        let Ok(candidate) = association::observe(frame, 1, self.own, signal) else {
            return;
        };
        if self
            .peer
            .as_ref()
            .is_some_and(|peer| peer.bss.bssid == candidate.bss.bssid)
        {
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
        let Some(delivery) = self.packet.delivery()? else {
            return Ok(());
        };
        let pending = self.pending.take().ok_or(Error::State)?;
        if pending.id != delivery.id || pending.bytes != delivery.bytes {
            return Err(Error::State);
        }
        if !delivery.delivered && !matches!(pending.kind, Kind::Data) {
            return Err(Error::State);
        }
        if pending.kind == Kind::Data
            && !self
                .rates
                .as_mut()
                .ok_or(Error::State)?
                .complete(delivery.delivered, delivery.feedback)
        {
            return Err(Error::State);
        }
        if pending.kind == Kind::Security {
            self.delivered_reply = Some(pending);
        }
        Ok(())
    }
    pub(super) fn poll(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let result = {
            let publication = self.publication.clone();
            let _publication = publication.lock();
            self.progress()
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
                self.cache(&frame, now);
                if self.phase != Phase::Passive {
                    if self.incoming.len() == 64 {
                        return Err(Error::State);
                    }
                    self.incoming.push_back(frame);
                }
            }
        }
        // A CRC/report descriptor is consumed input, never an RX-idle fence.
        // Inspect all queued peer loss before committing an exact M4 receipt.
        if idle {
            if let Some(receipt) = self.delivered_reply.take() {
                let security = self.security.as_mut().ok_or(Error::State)?;
                if security.pending_frame() != Some(receipt.bytes.as_slice()) {
                    return Err(Error::State);
                }
                security.reply_delivered(receipt.bytes.len())?;
            }
        }
        for _ in 0..64 {
            if self.pending.is_some()
                || self.delivered_reply.is_some()
                || self
                    .security
                    .as_ref()
                    .is_some_and(|s| s.pending_frame().is_some())
            {
                break;
            }
            let Some(frame) = self.incoming.pop_front() else {
                break;
            };
            match self.phase {
                Phase::Authentication => {
                    if let Some(association) = self
                        .plan
                        .as_mut()
                        .ok_or(Error::State)?
                        .authentication_response(frame.bytes())?
                        .map(|bytes| bytes.to_vec())
                    {
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
                        self.last_peer = now;
                        self.phase = Phase::FourWay;
                    }
                }
                Phase::FourWay | Phase::Open => {
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
                                    if self.received.len() == 64 {
                                        return Err(Error::State);
                                    }
                                    self.received.push_back(bytes);
                                }
                            }
                            station_security::Rx::ReplyReady => {
                                if self.established && !handshake_active {
                                    self.deadline = now.saturating_add(5000);
                                }
                            }
                            station_security::Rx::Ignored => {}
                        }
                    } else if let Some(bytes) = ethernet(
                        frame.bytes(),
                        self.own,
                        self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                    ) {
                        self.last_peer = now;
                        if self.received.len() == 64 {
                            return Err(Error::State);
                        }
                        self.received.push_back(bytes);
                    }
                }
                _ => {}
            }
        }
        if self.pending.is_none() && self.delivered_reply.is_none() {
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
        if idle && self.established && self.security.as_ref().is_none_or(Security::port_open) {
            Ok(self.received.drain(..).collect())
        } else {
            Ok(Vec::new())
        }
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
        let mut plan = JoinPlan::prepare(&candidate.bss, self.own, ssid, mode)?;
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
        let publication = self.publication.clone();
        let _publication = publication.lock();
        if !self.ready() {
            return Err(Error::Busy);
        }
        let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
        let native = if let Some(security) = &mut self.security {
            security.transmit_ethernet(frame)?
        } else {
            if !admitted(frame, self.own) {
                return Err(Error::Profile);
            }
            let mut bytes = vec![8, 1, 0, 0];
            bytes.extend_from_slice(&peer);
            bytes.extend_from_slice(&self.own);
            bytes.extend_from_slice(&frame[..6]);
            bytes.extend_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
            bytes.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
            bytes.extend_from_slice(&frame[12..]);
            bytes
        };
        self.transmit(native, Kind::Data)
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
    if !(32..=1532).contains(&frame.len())
        || frame[0] != 8
        || frame[1] & 0xc7 != 2
        || frame[22] & 15 != 0
        || frame[10..16] != peer
        || (frame[4..10] != own && frame[4] & 1 == 0)
        || frame[16] & 1 != 0
        || frame[16..22] == [0; 6]
        || frame[24..30] != [0xaa, 0xaa, 3, 0, 0, 0]
    {
        return None;
    }
    let proto = u16::from_be_bytes([frame[30], frame[31]]);
    if proto < 0x600 || matches!(proto, 0x888e | 0x80f3 | 0x8137) {
        return None;
    }
    let mut bytes = Vec::with_capacity(frame.len() - 18);
    bytes.extend_from_slice(&frame[4..10]);
    bytes.extend_from_slice(&frame[16..22]);
    bytes.extend_from_slice(&frame[30..]);
    Some(bytes)
}

#[cfg(feature = "kernel-test")]
#[path = "station/tests.rs"]
pub(super) mod tests;
