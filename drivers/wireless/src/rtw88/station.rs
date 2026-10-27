// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RTL8821CE/RTL8822CE channel1 host station state. The exact firmware Owner
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
// One whole mandatory A-MSDU must fit after a bounded ordinary-frame batch.
const RECEIVE_OUTPUTS: usize = 64 + narf_wireless::amsdu::MAX_SUBFRAMES;

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
    RtsData,
    Decline,
    Ba,
    TxBa,
    /// Broadcast software-scan Probe Request: no ACK, so no CCX report.
    Probe,
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
    extension: Option<Arc<super::station_profile::Grant>>,
    ht: Option<Arc<super::ht::Grant>>,
    rx_ba_grant: Option<Arc<super::rx_ba_power::Grant>>,
    rx_ba: super::rx_ba::Table,
    tx_ba_grant: Option<Arc<super::tx_ba_power::Grant>>,
    protection: Option<Arc<super::protection::Grant>>,
    tx_ba: super::tx_ba::Originator,
    tx_config: Option<super::packet_format::Aggregation>,
    data_pending: VecDeque<Pending>,
    data_drain: Option<u64>,
    qos_sequence: u16,
    local_ht: Option<association::phy::LocalPhy>,
    decline: Option<Vec<u8>>,
    wmm_requested: bool,
    wmm: Option<narf_wireless::wmm::Parameters>,
    data_profile: super::packet_format::DataProfile,
    peer_commit: Option<(u16, bool)>,
    cache: Vec<Entry>,
    peer: Option<ObservedBss>,
    plan: Option<JoinPlan>,
    security: Option<Security>,
    incoming: VecDeque<(Mpdu, bool, u64, bool)>,
    ordered: VecDeque<(Mpdu, u64)>,
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
        f.debug_struct("Rtw88Station")
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
            extension: None,
            ht: None,
            rx_ba_grant: None,
            rx_ba: super::rx_ba::Table::new(),
            tx_ba_grant: None,
            protection: None,
            tx_ba: super::tx_ba::Originator::new(),
            tx_config: None,
            data_pending: VecDeque::new(),
            data_drain: None,
            qos_sequence: 1,
            local_ht: None,
            decline: None,
            wmm_requested: false,
            wmm: None,
            data_profile: super::packet_format::DataProfile::LEGACY,
            peer_commit: None,
            cache: Vec::new(),
            peer: None,
            plan: None,
            security: None,
            incoming: VecDeque::new(),
            ordered: VecDeque::new(),
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
            && self.data_pending.is_empty()
            && self.data_drain.is_none()
            && !self.tx_ba.waiting()
            && self.security.as_ref().is_none_or(Security::port_open)
    }
    pub(super) fn receive_open(&self) -> bool {
        self.peer().is_some() && self.security.as_ref().is_none_or(Security::port_open)
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
        self.local_ht = io.station_ht_facts().and_then(super::ht::Facts::local);
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
        self.ordered.clear();
        self.rx_ba.clear();
        self.tx_ba.terminal();
        self.tx_config = None;
        self.data_pending.clear();
        self.data_drain = None;
        self.received.clear();
        self.peer_commit = None;
        self.decline = None;
        self.wmm = None;
        self.wmm_requested = false;
        self.data_profile = super::packet_format::DataProfile::LEGACY;
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
        if self.pending.is_some()
            || self.delivered_reply.is_some()
            || !self.data_pending.is_empty()
            || self.data_drain.is_some()
        {
            return Err(Error::Busy);
        }
        if !matches!(kind, Kind::Security | Kind::Data | Kind::RtsData) && bytes.len() != 20 {
            bytes[22..24].copy_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
        }
        let id = io.packet_submit(&bytes, !matches!(kind, Kind::Data | Kind::Probe))?;
        if kind == Kind::Ba {
            self.rx_ba.submitted(&bytes)?;
        }
        if kind == Kind::TxBa {
            self.tx_ba.submitted(&bytes)?;
        }
        self.pending = Some(Pending { id, bytes, kind });
        Ok(())
    }
    fn cache(&mut self, frame: &Mpdu, now: u64) {
        // This native profile exposes no calibrated per-frame dBm estimate.
        let signal = None;
        let observed = match &self.local_ht {
            Some(p) => association::observe_with_phy(frame, 1, self.own, signal, p),
            None => association::observe(frame, 1, self.own, signal),
        };
        let Ok(candidate) = observed else {
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
        if let Some(data) = self.data_pending.front() {
            if data.id != delivery.id
                || data.bytes != delivery.bytes
                || !delivery.radio_acknowledged
            {
                return Err(Error::State);
            }
            self.data_pending.pop_front();
            return Ok(());
        }
        let pending = self.pending.take().ok_or(Error::State)?;
        if pending.id != delivery.id || pending.bytes != delivery.bytes {
            return Err(Error::State);
        }
        if !delivery.radio_acknowledged && !matches!(pending.kind, Kind::Data | Kind::Probe) {
            return Err(Error::State);
        }
        if pending.kind == Kind::Security {
            self.delivered_reply = Some(pending);
        } else if pending.kind == Kind::Ba {
            self.rx_ba.delivered(&pending.bytes)?;
        } else if pending.kind == Kind::TxBa {
            self.tx_ba.delivered(&pending.bytes)?;
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
            if let Some(mut frame) = step.frame {
                if frame.phy.is_some_and(|p| !p.initial_channel()) {
                    continue;
                }
                let aggregate = frame.bytes().first() == Some(&0x88)
                    && frame.bytes().get(24).is_some_and(|q| q & 0x80 != 0);
                if frame.bytes().len() > super::packet_format::MAX_MPDU && !aggregate
                    || aggregate && (self.ht.is_none() || frame.rate < 12)
                {
                    continue;
                }
                if self.lost(&frame) {
                    return Err(Error::PeerLost);
                }
                if self.receive_open() && self.tx_ba_grant.is_some() {
                    let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                    if super::tx_ba::peer_delba(frame.bytes(), self.own, ap) {
                        self.tx_ba.retire();
                        continue;
                    }
                    if self.tx_ba.response(frame.bytes(), self.own, ap) {
                        continue;
                    }
                }
                // A peer DELBA can arrive while the success response's native
                // receipt is held. Retire its proposal before any idle commit.
                if self.receive_open() && self.rx_ba_grant.is_some() {
                    let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                    if let Some(tid) = super::rx_ba::delba(frame.bytes(), self.own, ap) {
                        self.rx_ba.retire(tid);
                        // Requests captured earlier in this same native batch
                        // have not produced a Table proposal yet. Retire those
                        // too, so a later loop cannot emit stale success.
                        self.incoming.retain(|(f, _, _, _)| {
                            super::rx_ba::request(f.bytes(), self.own, ap)
                                .is_none_or(|r| r.tid() != tid)
                        });
                        continue;
                    }
                    if let Some((tid, ssn)) = super::rx_ba::bar(frame.bytes(), self.own, ap) {
                        let epoch = self.admission.receive_generation();
                        self.ordered.extend(
                            self.rx_ba
                                .advance(tid, ssn, now)?
                                .into_iter()
                                .map(|f| (f, epoch)),
                        );
                        continue;
                    }
                    frame = match self.rx_ba.stage_pending(
                        frame,
                        self.own,
                        ap,
                        self.admission.receive_generation(),
                        now,
                    )? {
                        Some(f) => f,
                        None => continue,
                    };
                }
                self.cache(&frame, now);
                if self.phase != Phase::Passive {
                    if self.incoming.len() == 64 {
                        return Err(Error::State);
                    }
                    let admitted =
                        self.established && self.security.as_ref().is_none_or(Security::port_open);
                    let captured = self
                        .peer
                        .as_ref()
                        .is_some_and(|p| self.rx_ba.captured(&frame, self.own, p.bss.bssid));
                    self.incoming.push_back((
                        frame,
                        admitted,
                        self.admission.receive_generation(),
                        captured,
                    ));
                }
            }
        }
        // A CRC/report descriptor is consumed input, never an RX-idle fence.
        // Inspect all queued peer loss before committing an exact M4 receipt.
        if idle {
            if let Some(receipt) = self.delivered_reply.take() {
                let publication = io.station_publication()?;
                let security = self.security.as_mut().ok_or(Error::State)?;
                if security.pending_frame() != Some(receipt.bytes.as_slice()) {
                    return Err(Error::State);
                }
                publication.invoke(|| Ok(security.reply_delivered(receipt.bytes.len())))??;
                self.admission.retire_receive()?;
                self.rx_ba.clear();
                self.tx_ba.after_key();
                self.ordered.clear();
            }
            if self.receive_open() {
                io.station_publication()?.invoke(|| {
                    let epoch = self.admission.receive_generation();
                    self.ordered.extend(
                        self.rx_ba
                            .idle(now, epoch)
                            .map_err(|_| firmware_transport::Error::State)?
                            .into_iter()
                            .map(|f| (f, epoch)),
                    );
                    Ok(())
                })?;
            }
        }
        if self.receive_open() && self.rx_ba_grant.is_some() {
            let epoch = self.admission.receive_generation();
            let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
            self.ordered.extend(
                self.rx_ba
                    .expire(now, self.own, ap)?
                    .into_iter()
                    .map(|f| (f, epoch)),
            );
        }
        for _ in 0..64 {
            if self.received.len() >= 64 {
                break;
            }
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
            let (frame, mut data_admitted, epoch, captured, ordered) =
                match self.ordered.pop_front() {
                    Some((f, e)) => (f, true, e, true, true),
                    None => match self.incoming.pop_front() {
                        Some((f, a, e, c)) => (f, a, e, c, false),
                        None => break,
                    },
                };
            // M3 can arrive in native DMA before the host observes the M2
            // CCX/idle receipt. That receipt retires DATA/publication epochs,
            // but cannot discard this still-private EAPOL transaction. Only
            // an exact original plaintext authenticator control may cross;
            // shared Security must still validate its phase/MIC/replay. Its
            // captured DATA admission remains false, and it grants no BA.
            let private_eapol = !ordered
                && self
                    .peer
                    .as_ref()
                    .is_some_and(|p| plaintext_eapol(frame.bytes(), self.own, p.bss.bssid));
            if epoch != self.admission.receive_generation() {
                if !private_eapol {
                    continue;
                }
                // A previous open capture is not current DATA/BA admission.
                // In particular a QoS EAPOL must not enter a successor TID
                // window before the real Supplicant validates its control.
                data_admitted = false;
            }
            if !ordered && self.receive_open() && data_admitted && self.rx_ba_grant.is_some() {
                let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                if let Some((tid, seq)) = super::rx_ba::data(frame.bytes(), self.own, ap) {
                    if self.rx_ba.active(tid) {
                        // Originals observed before the agreement's terminal
                        // publication cannot be authorized retrospectively.
                        if captured {
                            self.ordered.extend(
                                self.rx_ba
                                    .push(tid, seq, now, frame)?
                                    .into_iter()
                                    .map(|f| (f, epoch)),
                            );
                        }
                        continue;
                    }
                }
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
                        if self.wmm_requested {
                            association.extend_from_slice(&narf_wireless::wmm::INFORMATION);
                        }
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
                        if let Some(grant) = &self.extension {
                            let (rates, basic) =
                                self.plan.as_ref().ok_or(Error::State)?.legacy_rates();
                            let rates = rates & grant.rates();
                            if rates & 1 == 0 || basic & !rates != 0 {
                                return Err(Error::Profile);
                            }
                            if self.wmm_requested {
                                let p = narf_wireless::wmm::Parameters::parse(&frame.bytes()[30..])
                                    .map_err(|_| Error::Profile)?
                                    .ok_or(Error::Profile)?;
                                super::wmm::words(p, short)?;
                                self.wmm = Some(p);
                            }
                            self.data_profile = super::packet_format::DataProfile {
                                rates,
                                qos: self.wmm.is_some(),
                                mcs: 0,
                                sgi: false,
                            };
                            if let Some(h) = &self.ht {
                                let negotiated = self
                                    .plan
                                    .as_ref()
                                    .and_then(JoinPlan::negotiated_phy)
                                    .ok_or(Error::Profile)?;
                                if negotiated.width() != association::phy::Width::Twenty
                                    || negotiated.ht().operation().protection() != 0
                                {
                                    return Err(Error::Profile);
                                }
                                self.data_profile = h.profile(
                                    rates,
                                    negotiated.ht().tx_mcs()[0],
                                    negotiated.ht().tx_sgi20(),
                                )?;
                            }
                        }
                        self.peer_commit = Some((aid, short));
                        self.last_peer = now;
                        // Firmware peer commit is an awaited continuation in associate().
                    }
                }
                Phase::FourWay | Phase::Open => {
                    if self.receive_open() && data_admitted {
                        if let Some(g) = &self.rx_ba_grant {
                            let ap = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                            if let Some(r) = super::rx_ba::request(frame.bytes(), self.own, ap) {
                                if let Some(maximum) = g.window(r.tid()) {
                                    g.check()?;
                                    io.station_profile_readback()?;
                                    let c21 =
                                        self.ht.as_ref().ok_or(Error::State)?.rx_ba_identity().2
                                            == 0xc821;
                                    super::rx_ba::readback(io, c21)?;
                                    if self.rx_ba.propose(
                                        r,
                                        maximum,
                                        self.own,
                                        ap,
                                        now,
                                        self.admission.receive_generation(),
                                    )? {
                                        if !self.rx_ba.active(r.tid()) {
                                            self.incoming.retain(|(f, _, _, _)| {
                                                super::rx_ba::data(f.bytes(), self.own, ap)
                                                    .is_none_or(|(tid, _)| tid != r.tid())
                                            });
                                        }
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    if self.ht.is_some() {
                        if let Some(bytes) = super::ht::decline(
                            frame.bytes(),
                            self.own,
                            self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                        ) {
                            if self
                                .decline
                                .as_ref()
                                .is_some_and(|pending| pending != &bytes)
                            {
                                return Err(Error::State);
                            }
                            self.decline = Some(bytes);
                            continue;
                        }
                    }
                    if self.extension.is_some()
                        && (if frame.rate >= 12 {
                            self.ht.is_none() || frame.rate >= 20
                        } else {
                            self.data_profile.rates & (1 << frame.rate) == 0
                        })
                    {
                        continue;
                    }
                    let qos = frame.bytes().get(24..26);
                    let live_ba = ordered && qos.is_some_and(|q| self.rx_ba.active(q[0] & 15));
                    let aggregate = frame.bytes().first() == Some(&0x88)
                        && qos.is_some_and(|q| q[0] & 0x80 != 0);
                    if frame.bytes().first() == Some(&0x88)
                        && (!self.data_profile.qos
                            || if self.ht.is_some() {
                                qos.is_none_or(|q| {
                                    q[0] & 0x10 != 0
                                        || q[1] != 0
                                        || q[0] & 0x60 != 0 && !(live_ba && q[0] & 0x60 == 0x60)
                                })
                            } else {
                                qos != Some(&[0, 0])
                            })
                    {
                        continue;
                    }
                    if !data_admitted
                        && !plaintext_eapol(
                            frame.bytes(),
                            self.own,
                            self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                        )
                    {
                        continue;
                    }
                    if aggregate {
                        let b = frame.bytes();
                        if self.ht.is_none()
                            || frame.rate < 12
                            || !self.established
                            || b.len() < 26
                            || b[1] & 0x87 != 2
                            || b[22] & 15 != 0
                            || b[10..16] != self.peer.as_ref().ok_or(Error::State)?.bss.bssid
                            || b[16..22] == [0; 6]
                            || b[16] & 1 != 0
                        {
                            continue;
                        }
                        let decoded = if let Some(s) = &mut self.security {
                            if !s.port_open() {
                                continue;
                            }
                            if live_ba && qos.is_some_and(|q| q[0] & 0x60 == 0x60) {
                                s.receive_amsdu_block_ack(&frame)?
                            } else {
                                s.receive_amsdu(&frame)?
                            }
                        } else if b[1] & 0x40 == 0 {
                            narf_wireless::amsdu::decode(
                                &b[26..],
                                self.own,
                                b[4..10].try_into().unwrap(),
                            )
                            .ok()
                        } else {
                            None
                        };
                        if let Some(frames) = decoded {
                            if self.received.len().saturating_add(frames.len()) > RECEIVE_OUTPUTS {
                                return Err(Error::State);
                            }
                            self.received.extend(frames);
                            self.last_peer = now;
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
                                if let Some(bytes) = ethernet_profile(
                                    &bytes,
                                    self.own,
                                    self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                                    self.data_profile.qos,
                                    self.ht.is_some(),
                                ) {
                                    self.last_peer = now;
                                    if self.received.len() == RECEIVE_OUTPUTS {
                                        return Err(Error::State);
                                    }
                                    self.received.push_back(bytes);
                                }
                            }
                            station_security::Rx::ReplyReady => {
                                self.admission.retire_receive()?;
                                self.received.clear();
                                self.incoming.clear();
                                self.ordered.clear();
                                self.rx_ba.clear();
                                self.tx_ba.stop(
                                    self.own,
                                    self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                                    now,
                                );
                                self.decline = None;
                                if self.established && !handshake_active {
                                    self.deadline = now.saturating_add(5000);
                                }
                            }
                            station_security::Rx::Ignored => {}
                        }
                    } else if let Some(bytes) = ethernet_profile(
                        frame.bytes(),
                        self.own,
                        self.peer.as_ref().ok_or(Error::State)?.bss.bssid,
                        self.data_profile.qos,
                        self.ht.is_some(),
                    ) {
                        self.last_peer = now;
                        if self.received.len() == RECEIVE_OUTPUTS {
                            return Err(Error::State);
                        }
                        self.received.push_back(bytes);
                    }
                }
                _ => {}
            }
        }
        self.service_tx_ba(io, now, idle)?;
        if self.pending.is_none()
            && self.delivered_reply.is_none()
            && self.data_pending.is_empty()
            && self.data_drain.is_none()
        {
            if let Some(reply) = self
                .security
                .as_ref()
                .and_then(Security::pending_frame)
                .map(|bytes| bytes.to_vec())
            {
                self.transmit(io, reply, Kind::Security)?;
            } else if let Some(reply) = self.decline.take() {
                self.transmit(io, reply, Kind::Decline)?;
            } else if let Some(reply) = self.rx_ba.next() {
                self.transmit(io, reply, Kind::Ba)?;
            } else if let Some(reply) = self.tx_ba.next() {
                self.transmit(io, reply, Kind::TxBa)?;
            }
        }
        if idle
            && self.incoming.is_empty()
            && self.pending.is_none()
            && self.delivered_reply.is_none()
            && self.phase == Phase::FourWay
            && self.security.as_ref().is_none_or(Security::port_open)
        {
            io.station_publication()?.invoke(|| {
                self.admission.check()?;
                self.established = true;
                self.phase = Phase::Open;
                self.last_peer = now;
                Ok(())
            })?;
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
            io.station_publication()?
                .invoke(|| {
                    self.admission.check()?;
                    Ok(self.received.drain(..).collect())
                })
                .map_err(Error::Native)
        } else {
            Ok(Vec::new())
        }
    }
    /// mac80211 software scan on the retained channel: each Probe Request
    /// is published and retired (DMA consumption, no ACK) before the next,
    /// then the dwell runs from the last retirement. Empty `probes` is the
    /// original passive scan.
    pub(super) async fn scan_for(
        &mut self,
        io: &mut impl Io,
        dwell_ms: u64,
        probes: &[Vec<u8>],
    ) -> Result<Vec<ObservedBss>, Error> {
        if !(1..=1024).contains(&dwell_ms) || probes.len() > 4 {
            return Err(Error::Profile);
        }
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        for probe in probes {
            if probe.len() < 24
                || probe[..4] != [0x40, 0, 0, 0]
                || probe[4..10] != [255; 6]
                || probe[10..16] != self.own
                || probe[16..22] != [255; 6]
            {
                return Err(Error::Profile);
            }
            let admission = self.admission.clone();
            admission.run(|| Ok(self.transmit(io, probe.clone(), Kind::Probe)))??;
            while self.pending.is_some() {
                self.poll(io)?;
                if self.pending.is_none() {
                    break;
                }
                self.environment.pause().await;
            }
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
        let extension = io
            .station_extension()?
            .filter(|g| candidate.basic_rates & !g.rates() == 0);
        let proposed = match &extension {
            Some(g)
                if g.wmm()
                    && narf_wireless::wmm::Parameters::parse(
                        &candidate.bss.information_elements,
                    )
                    .map_err(|_| Error::Profile)?
                    .is_some() =>
            {
                io.station_ht_extension(g.clone())?
            }
            _ => None,
        };
        let mut plan = match &proposed {
            Some(h) => JoinPlan::prepare_with_phy(&candidate.bss, self.own, ssid, mode, h.local())?,
            None => JoinPlan::prepare(&candidate.bss, self.own, ssid, mode)?,
        };
        let ht = proposed.filter(|_| plan.offered_phy().is_some());
        if plan.offered_phy().is_some_and(|p| {
            p.width() != association::phy::Width::Twenty || p.ht().operation().protection() != 0
        }) {
            return Err(Error::Profile);
        }
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
        // Missing/unqualified extension preserves the original CCK1 profile.
        // Each chip can supply only its own exact-board sealed extension.
        if let Some(grant) = extension {
            if candidate.basic_rates & !grant.rates() == 0 {
                let p = if grant.wmm() {
                    narf_wireless::wmm::Parameters::parse(&candidate.bss.information_elements)
                        .map_err(|_| Error::Profile)?
                } else {
                    None
                };
                if let Some(p) = p {
                    super::wmm::words(p, candidate.bss.capability & 0x400 != 0)?;
                }
                self.wmm_requested = p.is_some();
                self.admission
                    .run(|| io.station_bind_extension(grant.clone()))?;
                self.extension = Some(grant);
            }
        }
        if let Some(h) = ht {
            self.admission.run(|| io.station_bind_ht(h.clone()))?;
            h.program(io, &self.admission).await?;
            // RX may arrive at negotiated HT rates immediately after the AP's
            // association response, before the awaited native peer commit.
            // The native RX bound is the locally advertised MCS0..7, whereas
            // ordinary TX remains phase-gated until the bound response.
            let p = h.profile(
                candidate.rates & self.extension.as_ref().ok_or(Error::State)?.rates(),
                h.mcs(),
                false,
            )?;
            self.admission.run(|| io.packet_profile(p))?;
            if let Some(g) = io.station_rx_ba_extension(h.clone())? {
                self.admission.run(|| io.station_bind_rx_ba(g.clone()))?;
                self.rx_ba_grant = Some(g);
            }
            if let Some(g) = io.station_tx_ba_extension()? {
                self.admission.run(|| io.station_bind_tx_ba(g.clone()))?;
                super::tx_ba::program(io)?;
                self.tx_ba_grant = Some(g);
            }
            if let Some(g) = io.station_protection_extension()? {
                self.admission
                    .run(|| io.station_bind_protection(g.clone()))?;
                self.protection = Some(g);
            }
            self.ht = Some(h);
        }
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
                if self.extension.is_some() {
                    super::wmm::commit(io, self.data_profile, self.wmm, short, &self.admission)
                        .await?;
                }
                self.admission.run(|| {
                    self.peer_commit = None;
                    self.phase = Phase::FourWay;
                    Ok(())
                })?;
            }
            if self.established && (self.tx_ba_grant.is_none() || self.tx_ba.settled()) {
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
        if self.tx_ba.active().is_some() {
            self.send_batch_inner(io, &[frame])?;
            return Ok(());
        }
        if !self.ready() || !io.packet_ready() {
            return Err(Error::Busy);
        }
        if !admitted(frame, self.own) {
            return Err(Error::Profile);
        }
        let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
        let native = if let Some(security) = &mut self.security {
            if self.data_profile.qos {
                security.transmit_ethernet_qos(frame, 0)?
            } else {
                security.transmit_ethernet(frame)?
            }
        } else {
            if !admitted(frame, self.own) {
                return Err(Error::Profile);
            }
            let mut bytes = vec![if self.data_profile.qos { 0x88 } else { 8 }, 1, 0, 0];
            bytes.extend_from_slice(&peer);
            bytes.extend_from_slice(&self.own);
            bytes.extend_from_slice(&frame[..6]);
            let sequence = if self.tx_ba_grant.is_some() && self.data_profile.qos {
                let s = self.qos_sequence;
                self.qos_sequence = (s + 1) & 4095;
                s
            } else {
                let s = self.sequence;
                self.sequence = (s + 1) & 4095;
                s
            };
            bytes.extend_from_slice(&(sequence << 4).to_le_bytes());
            if self.data_profile.qos {
                bytes.extend_from_slice(&[0, 0]);
            }
            bytes.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
            bytes.extend_from_slice(&frame[12..]);
            bytes
        };
        let rts = self
            .protection
            .as_ref()
            .is_some_and(|g| native.len() as u64 > u64::from(g.threshold()));
        self.transmit(io, native, if rts { Kind::RtsData } else { Kind::Data })?;
        if rts {
            self.data_drain = Some(self.now()?);
        }
        Ok(())
    }
}
#[path = "station_tx_ba.rs"]
mod tx;
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
    ethernet_profile(frame, own, peer, false, false)
}
fn ethernet_profile(
    frame: &[u8],
    own: [u8; 6],
    peer: [u8; 6],
    qos: bool,
    ht: bool,
) -> Option<Vec<u8>> {
    let header = if frame.first() == Some(&0x88)
        && qos
        && frame.get(24..26).is_some_and(|q| {
            q[1] == 0
                && if ht {
                    q[0] & 0x90 == 0 && matches!(q[0] & 0x60, 0 | 0x60)
                } else {
                    q[0] == 0
                }
        }) {
        26
    } else {
        24
    };
    if !(header + 8..=header + 1508).contains(&frame.len())
        || frame[0] != if header == 26 { 0x88 } else { 8 }
        || frame[1] & 0xc7 != 2
        || frame[22] & 15 != 0
        || frame[10..16] != peer
        || (frame[4..10] != own && frame[4] & 1 == 0)
        || frame[16] & 1 != 0
        || frame[16..22] == [0; 6]
        || frame[header..header + 6] != [0xaa, 0xaa, 3, 0, 0, 0]
    {
        return None;
    }
    let proto = u16::from_be_bytes([frame[header + 6], frame[header + 7]]);
    if proto < 0x600 || matches!(proto, 0x888e | 0x80f3 | 0x8137) {
        return None;
    }
    let mut bytes = Vec::with_capacity(frame.len() - 18);
    bytes.extend_from_slice(&frame[4..10]);
    bytes.extend_from_slice(&frame[16..22]);
    bytes.extend_from_slice(&frame[header + 6..]);
    Some(bytes)
}
fn plaintext_eapol(b: &[u8], own: [u8; 6], ap: [u8; 6]) -> bool {
    let at = if b.first() == Some(&0x88) { 26 } else { 24 };
    b.len() >= at + 12
        && matches!(b[0], 8 | 0x88)
        && b[22] & 15 == 0
        && b[1] & 0xc7 == 2
        && b[4..10] == own
        && b[10..16] == ap
        && b[16..22] == ap
        && (at != 26 || b[24] & 0xf0 == 0 && b[25] == 0)
        && b[at..at + 8] == [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]
        && (1..=3).contains(&b[at + 8])
        && b[at + 9] == 3
        && usize::from(u16::from_be_bytes([b[at + 10], b[at + 11]])) + at + 12 == b.len()
}
