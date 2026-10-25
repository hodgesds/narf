// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RTL8822CE channel1 host station state. The exact firmware Owner
//! keeps its native backend; this state never owns or reconstructs hardware.
use super::{
    firmware_transport::{self, Io},
    packet_core::{self as packet, Frame as Mpdu, Receipt},
    station_control::{self, Admission},
};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec, vec::Vec};
use narf_wireless::{
    association::{self, JoinPlan, ObservedBss, SecurityMode},
    station_security::{self, RawFrame, Security},
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
    Native(firmware_transport::Error),
    Management(association::Error),
    Security(station_security::Error),
}
impl From<packet::Error> for Error {
    fn from(error: packet::Error) -> Self {
        Self::Transport(error)
    }
}
impl From<firmware_transport::Error> for Error {
    fn from(error: firmware_transport::Error) -> Self {
        Self::Native(error)
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
#[async_trait::async_trait]
pub(super) trait Environment: Send + Sync {
    fn now_ms(&self) -> u64;
    fn nonce(&self) -> Option<[u8; 32]>;
    async fn pause(&self);
}
pub(super) struct NativeEnvironment;
#[async_trait::async_trait]
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
    admission: Admission,
    armed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.armed {
            self.admission.close();
        }
    }
}
pub(super) struct State {
    environment: Arc<dyn Environment>,
    own: [u8; 6],
    phase: Phase,
    admission: Admission,
    prepared: bool,
    peer_commit: Option<(u16, bool)>,
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
}
impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8822ceStation")
            .field("phase", &self.phase)
            .field("established", &self.established)
            .finish_non_exhaustive()
    }
}
impl State {
    pub(super) fn new(
        own: [u8; 6],
        environment: Arc<dyn Environment>,
        admission: Admission,
    ) -> Self {
        Self {
            environment,
            own,
            phase: Phase::Prepared,
            admission,
            prepared: false,
            peer_commit: None,
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
        }
    }
    pub(super) fn admission(&self) -> Admission {
        self.admission.clone()
    }
    pub(super) fn local(&self) -> [u8; 6] {
        self.own
    }
    pub(super) fn phase(&self) -> Phase {
        if self.admission.closed() && self.phase != Phase::Stopped {
            Phase::Failed
        } else {
            self.phase
        }
    }
    pub(super) fn peer(&self) -> Option<[u8; 6]> {
        if self.established && !self.admission.closed() {
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
    pub(super) async fn start(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if self.phase() != Phase::Prepared {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let mut attempt = Attempt {
            admission: self.admission.clone(),
            armed: true,
        };
        station_control::prepare_initial(io, self.own, &self.admission).await?;
        self.admission
            .run(|| Ok(io.packet_prepare(self.own, 0)))??;
        self.prepared = true;
        self.admission.run(|| Ok(io.packet_start()))??;
        self.last_now = self.environment.now_ms();
        self.phase = Phase::Passive;
        attempt.armed = false;
        Ok(())
    }
    pub(super) fn stop(&mut self, io: &mut impl Io) -> Result<(), Error> {
        self.admission.close();
        self.established = false;
        self.phase = Phase::Stopped;
        if let Some(security) = &mut self.security {
            security.fail();
        }
        self.incoming.clear();
        self.received.clear();
        self.peer_commit = None;
        if self.prepared {
            io.packet_stop()?;
        }
        Ok(())
    }
    fn fail(&mut self, io: &mut impl Io) {
        let _ = self.stop(io);
        self.phase = Phase::Failed;
    }
    pub(super) async fn disconnect(&mut self, io: &mut impl Io) -> Result<(), Error> {
        // Public Device reserves before waiting for this owner's mutex.
        // Direct private callers need the same cancellation/worker ordering.
        let reservation = if self.admission.teardown_pending() {
            None
        } else {
            Some(self.admission.begin_disconnect()?)
        };
        self.admission.close();
        self.established = false;
        if let Some(security) = &mut self.security {
            security.fail();
        }
        let mut attempt = Attempt {
            admission: self.admission.clone(),
            armed: true,
        };
        let control = if let Some(peer) = &self.peer {
            station_control::disconnect(io, peer.bss.bssid).await
        } else {
            Ok(())
        };
        let stopped = self.stop(io);
        attempt.armed = false;
        drop(reservation);
        control?;
        stopped
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
    fn transmit(&mut self, io: &mut impl Io, mut bytes: Vec<u8>, kind: Kind) -> Result<(), Error> {
        // Caller holds publication; this helper never awaits or re-enters it.
        if self.admission.closed() {
            return Err(Error::State);
        }
        if self.pending.is_some() || self.delivered_reply.is_some() {
            return Err(Error::Busy);
        }
        if !matches!(kind, Kind::Security | Kind::Data) {
            bytes[22..24].copy_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
        }
        let id = io.packet_submit(&bytes, kind != Kind::Data)?;
        self.pending = Some(Pending { id, bytes, kind });
        Ok(())
    }
    fn cache(&mut self, frame: &Mpdu, now: u64) {
        // This native profile exposes no calibrated per-frame dBm estimate.
        let signal = None;
        let Ok(candidate) = association::observe(frame, 1, self.own, signal) else {
            return;
        };
        if candidate.basic_rates & 1 == 0 {
            return;
        }
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
    fn delivery(&mut self, delivery: Receipt) -> Result<(), Error> {
        let pending = self.pending.take().ok_or(Error::State)?;
        if pending.id != delivery.id || pending.bytes != delivery.bytes {
            return Err(Error::State);
        }
        if !delivery.radio_acknowledged && !matches!(pending.kind, Kind::Data) {
            return Err(Error::State);
        }
        if pending.kind == Kind::Security {
            self.delivered_reply = Some(pending);
        }
        Ok(())
    }
    pub(super) fn poll(&mut self, io: &mut impl Io) -> Result<Vec<Vec<u8>>, Error> {
        let admission = self.admission.clone();
        let result = admission
            .run(|| Ok(self.progress(io)))
            .map_err(Error::Native)
            .and_then(|result| result);
        if result.is_err() && !self.admission.teardown_pending() {
            self.fail(io);
        }
        result
    }
    fn progress(&mut self, io: &mut impl Io) -> Result<Vec<Vec<u8>>, Error> {
        if self.admission.closed()
            || matches!(self.phase, Phase::Prepared | Phase::Failed | Phase::Stopped)
        {
            return Err(Error::State);
        }
        io.station_allowed()?;
        let now = self.now()?;
        let mut idle = false;
        for _ in 0..32 {
            let step = io.packet_poll()?;
            if let Some(receipt) = step.receipt {
                self.delivery(receipt)?;
            }
            if !step.consumed_rx {
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
                || self.peer_commit.is_some()
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
                        self.transmit(io, association, Kind::Association)?;
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
                        self.peer_commit = Some((aid, short));
                        self.last_peer = now;
                        // Firmware peer commit is an awaited continuation in associate().
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
                self.transmit(io, reply, Kind::Security)?;
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
    pub(super) async fn scan_for(
        &mut self,
        io: &mut impl Io,
        dwell_ms: u64,
    ) -> Result<Vec<ObservedBss>, Error> {
        if !(1..=1024).contains(&dwell_ms) {
            return Err(Error::Profile);
        }
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        let until = self.now()?.saturating_add(dwell_ms);
        loop {
            self.poll(io)?;
            if self.now()? >= until {
                return Ok(self.candidates());
            }
            self.environment.pause().await;
        }
    }
    pub(super) async fn associate(
        &mut self,
        io: &mut impl Io,
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
        if candidate.bss.channel != 1 || candidate.basic_rates & 1 == 0 {
            return Err(Error::Profile);
        }
        let mode = if pmk.is_some() {
            SecurityMode::Wpa2Psk
        } else {
            SecurityMode::Open
        };
        let mut plan = JoinPlan::prepare(&candidate.bss, self.own, ssid, mode)?;
        plan.append_sme_ies(ies)?;
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
            admission: self.admission.clone(),
            armed: true,
        };
        station_control::prepare_peer(io, bssid, &self.admission).await?;
        self.peer = Some(candidate);
        self.deadline = self.now()?.saturating_add(5000);
        self.last_peer = self.last_now;
        let auth = plan.start_authentication()?.to_vec();
        self.plan = Some(plan);
        self.phase = Phase::Authentication;
        let admission = self.admission.clone();
        admission.run(|| Ok(self.transmit(io, auth, Kind::Authentication)))??;
        loop {
            self.poll(io)?;
            if let Some((aid, short)) = self.peer_commit {
                station_control::commit_peer(io, bssid, aid, short, &self.admission).await?;
                self.admission.run(|| {
                    self.peer_commit = None;
                    self.phase = Phase::FourWay;
                    Ok(())
                })?;
            }
            if self.established {
                attempt.armed = false;
                return Ok(());
            }
            self.environment.pause().await;
        }
    }
    pub(super) fn send(&mut self, io: &mut impl Io, frame: &[u8]) -> Result<(), Error> {
        let admission = self.admission.clone();
        let result = admission
            .run(|| Ok(self.send_inner(io, frame)))
            .map_err(Error::Native)
            .and_then(|result| result);
        // Closure happens after run releases the publication lock; stopping
        // inside it would re-enter that lock. Fatal native/key errors cannot
        // leave established metadata visible until an unrelated later poll.
        if !self.admission.teardown_pending()
            && result.as_ref().is_err_and(|error| {
                !matches!(
                    error,
                    Error::Busy | Error::Profile | Error::Transport(packet::Error::Busy)
                )
            })
        {
            self.fail(io);
        }
        result
    }
    fn send_inner(&mut self, io: &mut impl Io, frame: &[u8]) -> Result<(), Error> {
        if !self.ready() || !io.packet_ready() {
            return Err(Error::Busy);
        }
        if !admitted(frame, self.own) {
            return Err(Error::Profile);
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
        self.transmit(io, native, Kind::Data)
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
