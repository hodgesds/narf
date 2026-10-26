// SPDX-License-Identifier: GPL-2.0-or-later
//! One retained channel1 legacy station. The logical owner, MLME, pending
//! replies and key history stay beside the actual Prepared DMA/mailbox owner.
use super::{
    packet::{Mpdu, Port},
    Error as RadioError, Io, Memory, Phase as Hardware, Prepared,
};
use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
};
use narf_wireless::{
    association::{self, Bss, JoinPlan, SecurityMode},
    station_security::{self, Security},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    State,
    Busy,
    Profile,
    Timeout,
    PeerLost,
    Entropy,
    Allocation,
    Radio(RadioError),
    Management(association::Error),
    Security(station_security::Error),
}
impl From<RadioError> for Error {
    fn from(error: RadioError) -> Self {
        Self::Radio(error)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Dormant,
    Starting,
    Passive,
    Joining,
    Authentication,
    Association,
    Configuring,
    FourWay,
    Open,
    Stopping,
    Stopped,
    Failed,
}
pub(crate) trait Environment: Send + Sync {
    fn now_ms(&self) -> u64;
    fn fresh_nonce(&self) -> Option<[u8; 32]>;
    fn domain(&self) -> Result<narf_wireless::reg::RegulatoryDomain, Error>;
    fn pause(&self) -> impl Future<Output = ()> + Send;
    fn preparation_failed(&self) -> bool {
        false
    }
    fn admission(&self) -> Option<&Arc<Admission>> {
        None
    }
}
/// Shared public closure and bounded publication gate. No guard crosses an
/// await; an already-entered native publication completes before close returns.
pub(crate) struct Admission {
    pub(crate) closed: AtomicBool,
    pub(crate) abort: AtomicBool,
    pub(crate) publication: narf_lib::sync::IrqSafeSpinLock<()>,
}
impl Admission {
    pub(crate) fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            abort: AtomicBool::new(false),
            publication: narf_lib::sync::IrqSafeSpinLock::new(()),
        }
    }
    pub(crate) fn publish<T, E>(
        &self,
        closed: E,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let _publication = self.publication.lock();
        if self.closed.load(Ordering::Acquire) {
            Err(closed)
        } else {
            operation()
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    pub bss: Bss,
    pub rsne: Option<Vec<u8>>,
    pub rsnxe: Option<Vec<u8>>,
}
impl Candidate {
    fn receive(frame: &Mpdu, local: [u8; 6]) -> Result<Self, Error> {
        if frame.channel() != 1 {
            return Err(Error::Profile);
        }
        let observed = association::observe(frame, 1, local, None).map_err(Error::Management)?;
        if observed.basic_rates & 1 == 0 {
            return Err(Error::Profile);
        }
        Ok(Self {
            bss: observed.bss,
            rsne: observed.ap_rsne,
            rsnxe: observed.ap_rsnxe,
        })
    }
}
struct Entry {
    candidate: Candidate,
    seen: u64,
}
#[derive(Clone, Copy)]
enum Kind {
    Authentication,
    Association,
    Eapol,
    Data,
}
struct Pending {
    id: u64,
    kind: Kind,
    bytes: Vec<u8>,
    deadline: u64,
}
pub(super) struct State {
    phase: Phase,
    failed: Arc<AtomicBool>,
    calibration: Option<super::super::channel_power::Calibration>,
    cache: Vec<Entry>,
    candidate: Option<Candidate>,
    plan: Option<JoinPlan>,
    pmk: Option<Zeroizing<[u8; 32]>>,
    security: Option<Security>,
    pending: Option<Pending>,
    incoming: VecDeque<Mpdu>,
    received: VecDeque<Vec<u8>>,
    aid: Option<u16>,
    native_associated: bool,
    admitted: bool,
    sequence: u16,
    deadline: u64,
    last_now: u64,
    last_peer: u64,
    capability: u16,
    wmm: Option<narf_wireless::wmm::Parameters>,
}
impl State {
    pub(super) fn new() -> Self {
        Self {
            phase: Phase::Dormant,
            failed: Arc::new(AtomicBool::new(false)),
            calibration: None,
            cache: Vec::new(),
            candidate: None,
            plan: None,
            pmk: None,
            security: None,
            pending: None,
            incoming: VecDeque::new(),
            received: VecDeque::new(),
            aid: None,
            native_associated: false,
            admitted: false,
            sequence: 0,
            deadline: 0,
            last_now: 0,
            last_peer: 0,
            capability: 0,
            wmm: None,
        }
    }
    fn fail(&mut self) {
        self.failed.store(true, Ordering::Release);
        self.phase = Phase::Failed;
        self.admitted = false;
        self.incoming.clear();
        self.received.clear();
        self.pmk = None;
        self.wmm = None;
        if let Some(plan) = &mut self.plan {
            plan.cancel();
        }
        if let Some(security) = &mut self.security {
            security.fail();
        }
    }
}
struct Attempt {
    failed: Arc<AtomicBool>,
    armed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.armed {
            self.failed.store(true, Ordering::Release);
        }
    }
}
fn ethernet(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> Option<Vec<u8>> {
    if frame.len() < 32
        || !matches!(frame[0], 8 | 0x88)
        || frame[1] & 0xc7 != 2
        || frame[22] & 15 != 0
        || frame[10..16] != peer
        || frame[4..10] != own && frame[4] & 1 == 0
        || frame[16..22] == [0; 6]
        || frame[16] & 1 != 0
    {
        return None;
    }
    let offset = if frame[0] == 0x88 {
        let qos = frame.get(24..26)?;
        if qos[0] & 0xf0 != 0 || qos[1] != 0 {
            return None;
        }
        26
    } else {
        24
    };
    let snap = frame.get(offset..offset + 8)?;
    let protocol = u16::from_be_bytes([snap[6], snap[7]]);
    if snap[..6] != [0xaa, 0xaa, 3, 0, 0, 0]
        || protocol < 0x600
        || matches!(protocol, 0x888e | 0x80f3 | 0x8137)
        || frame.len() + 6 - offset > 1514
    {
        return None;
    }
    let mut bytes = frame[4..10].to_vec();
    bytes.extend_from_slice(&frame[16..22]);
    bytes.extend_from_slice(&frame[offset + 6..]);
    Some(bytes)
}
fn eapol(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> bool {
    let offset = if frame.first() == Some(&0x88) {
        if frame
            .get(24..26)
            .is_none_or(|q| q[0] & 0xf0 != 0 || q[1] != 0)
        {
            return false;
        }
        26
    } else {
        24
    };
    frame.len() >= offset + 8
        && matches!(frame[0], 8 | 0x88)
        && frame[1] & 0x87 == 2
        && frame[4..10] == own
        && frame[10..16] == peer
        && frame[16..22] == peer
        && frame[22] & 15 == 0
        && frame[offset..offset + 8] == [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]
}
impl<I: Io, M: Memory> Prepared<I, M> {
    pub(crate) fn station_calibration_present(&self) -> bool {
        self.station.calibration.is_some()
    }
    pub(crate) fn station_cancellation(&self) -> Arc<AtomicBool> {
        self.station.failed.clone()
    }
    pub(crate) fn station_phase(&self) -> Phase {
        if self.station.failed.load(Ordering::Acquire) || self.phase == Hardware::Failed {
            Phase::Failed
        } else {
            self.station.phase
        }
    }
    pub(crate) fn stage_station_calibration(
        &mut self,
        calibration: super::super::channel_power::Calibration,
        domain: &narf_wireless::reg::RegulatoryDomain,
    ) -> Result<(), Error> {
        if self.phase != Hardware::MacConfigured
            || self.station.phase != Phase::Dormant
            || Some(
                calibration
                    .permission(domain, 1)
                    .map_err(|_| Error::Profile)?,
            ) != self.permission
        {
            return Err(Error::Profile);
        }
        self.station.calibration = Some(calibration);
        Ok(())
    }
    pub(crate) fn station_peer(&self) -> Option<[u8; 6]> {
        if self.station_phase() != Phase::Open
            || !self.station.native_associated
            || !self.station.admitted
        {
            return None;
        }
        self.station
            .candidate
            .as_ref()
            .map(|candidate| candidate.bss.bssid)
    }
    pub(crate) fn station_candidates(&self, now: u64) -> Vec<Candidate> {
        self.station
            .cache
            .iter()
            .filter(|entry| now >= entry.seen && now - entry.seen < 10_000)
            .map(|entry| entry.candidate.clone())
            .collect()
    }
    pub(super) fn check_station_policy(&self, environment: &impl Environment) -> Result<(), Error> {
        if environment
            .admission()
            .is_some_and(|control| control.closed.load(Ordering::Acquire))
        {
            return Err(Error::State);
        }
        let domain = environment.domain()?;
        let permission = self
            .station
            .calibration
            .as_ref()
            .ok_or(Error::Profile)?
            .permission(&domain, 1)
            .map_err(|_| Error::Profile)?;
        if Some(permission) != self.permission {
            return Err(Error::Profile);
        }
        Ok(())
    }
}
impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    pub(crate) fn abort_station(&mut self) {
        self.station.fail();
        if self.phase != Hardware::Stopped {
            let _ = self.stop_packets();
        }
    }
    pub(crate) async fn start_station_service(
        &mut self,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if self.station_phase() != Phase::Dormant || self.phase != Hardware::MacConfigured {
            return Err(Error::State);
        }
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        self.station.phase = Phase::Starting;
        let result = async {
            self.check_station_policy(environment)?;
            self.awake_station().await?;
            if let Some(admission) = environment.admission() {
                admission.publish(Error::State, || self.start_packets().map_err(Error::Radio))?;
            } else {
                self.start_packets()?;
            }
            let now = environment.now_ms();
            self.station.last_now = now;
            self.station.last_peer = now;
            self.station.phase = Phase::Passive;
            Ok(())
        }
        .await;
        attempt.armed = false;
        if result.is_err() {
            self.abort_station();
        }
        result
    }
    fn cache_candidate(&mut self, candidate: Candidate, now: u64) {
        if let Some(entry) = self
            .station
            .cache
            .iter_mut()
            .find(|entry| entry.candidate.bss.bssid == candidate.bss.bssid)
        {
            *entry = Entry {
                candidate,
                seen: now,
            };
        } else {
            if self.station.cache.len() == 32 {
                let index = self
                    .station
                    .cache
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.seen)
                    .map(|(index, _)| index)
                    .unwrap();
                self.station.cache.swap_remove(index);
            }
            self.station.cache.push(Entry {
                candidate,
                seen: now,
            });
        }
    }
    fn queue_station(
        &mut self,
        mut bytes: Vec<u8>,
        kind: Kind,
        now: u64,
        sequence: bool,
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if self.station.pending.is_some() || !self.transmit_ready() {
            return Err(Error::Busy);
        }
        super::super::station_control::radio_on(&self.io)?;
        if sequence {
            bytes[22..24].copy_from_slice(&(self.station.sequence << 4).to_le_bytes());
            self.station.sequence = (self.station.sequence + 1) & 4095;
        }
        let id = if let Some(admission) = environment.admission() {
            admission.publish(Error::State, || {
                self.check_station_policy(environment)?;
                self.submit(&bytes, 0).map_err(Error::Radio)
            })?
        } else {
            self.check_station_policy(environment)?;
            self.submit(&bytes, 0)?
        };
        self.station.pending = Some(Pending {
            id,
            kind,
            bytes,
            deadline: now.saturating_add(1000),
        });
        Ok(())
    }
    pub(crate) async fn connect_station(
        &mut self,
        bssid: [u8; 6],
        ssid: &[u8],
        mode: SecurityMode,
        pmk: Option<Zeroizing<[u8; 32]>>,
        ies: &[u8],
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if self.station_phase() != Phase::Passive || self.station.plan.is_some() {
            return Err(Error::State);
        }
        if mode.is_wpa2() != pmk.is_some() {
            return Err(Error::Profile);
        }
        self.check_station_policy(environment)?;
        let now = environment.now_ms();
        let candidate = self
            .station_candidates(now)
            .into_iter()
            .find(|candidate| candidate.bss.bssid == bssid)
            .ok_or(Error::Profile)?;
        let mut plan = JoinPlan::prepare(
            &candidate.bss,
            self.local().ok_or(Error::State)?,
            ssid,
            mode,
        )
        .map_err(Error::Management)?;
        plan.append_sme_ies(ies).map_err(Error::Management)?;
        let (rates, basic) = plan.legacy_rates();
        let capability = candidate.bss.capability;
        let wmm = narf_wireless::wmm::Parameters::parse(&candidate.bss.information_elements)
            .map_err(|_| Error::Profile)?;
        if let Some(p) = wmm {
            super::super::wmm::admit(p, capability & 0x400 != 0)?;
        }
        if rates & 1 == 0 || basic & 1 == 0 || basic & !0x15f != 0 {
            return Err(Error::Profile);
        }
        self.station.phase = Phase::Joining;
        self.station.candidate = Some(candidate);
        self.station.plan = Some(plan);
        self.station.pmk = pmk;
        self.station.capability = capability;
        self.station.wmm = wmm;
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        let result = async {
            self.prepare_station_peer(bssid, rates, basic, capability)
                .await?;
            let auth = self
                .station
                .plan
                .as_mut()
                .ok_or(Error::State)?
                .start_authentication()
                .map_err(Error::Management)?
                .to_vec();
            self.queue_station(auth, Kind::Authentication, now, true, environment)?;
            self.station.phase = Phase::Authentication;
            self.station.deadline = now.saturating_add(5000);
            self.station.last_peer = now;
            loop {
                let idle = self.progress_station_inner(environment)?;
                if self.station.phase == Phase::Configuring {
                    self.check_station_policy(environment)?;
                    let (rates, basic) = self
                        .station
                        .plan
                        .as_ref()
                        .ok_or(Error::State)?
                        .legacy_rates();
                    super::super::station_control::configure_rates(
                        &self.io,
                        rates,
                        basic,
                        self.station.capability,
                    )?;
                    if let Some(p) = self.station.wmm {
                        let calibration =
                            self.station.calibration.as_ref().ok_or(Error::Profile)?;
                        calibration.with_current(|| {
                            super::super::wmm::program(
                                &self.io,
                                p,
                                self.station.capability & 0x400 != 0,
                            )
                        })?;
                        self.check_station_policy(environment)?;
                        self.packet.qos = true;
                    }
                    self.complete_station_peer_admitted(
                        bssid,
                        self.station.aid.ok_or(Error::State)?,
                        environment.admission().map(Arc::as_ref),
                        |owner| {
                            owner.check_station_policy(environment).map_err(|_| {
                                RadioError::Power(super::super::channel_power::Error::Policy)
                            })
                        },
                    )
                    .await?;
                    self.check_station_policy(environment)?;
                    self.station.native_associated = true;
                    if mode.is_wpa2() {
                        let candidate = self.station.candidate.as_ref().ok_or(Error::State)?;
                        let body = self
                            .station
                            .plan
                            .as_ref()
                            .ok_or(Error::State)?
                            .rsn_body()
                            .ok_or(Error::State)?;
                        let pmk = self.station.pmk.take().ok_or(Error::State)?;
                        self.station.security = Some(
                            Security::new(
                                self.local().ok_or(Error::State)?,
                                bssid,
                                &pmk,
                                &body,
                                candidate.rsne.as_deref().ok_or(Error::Profile)?,
                                candidate.rsnxe.as_deref(),
                                self.station.sequence,
                            )
                            .map_err(Error::Security)?,
                        );
                        self.station.phase = Phase::FourWay;
                        self.station.deadline = environment.now_ms().saturating_add(10_000);
                    } else {
                        self.station.phase = Phase::Open;
                    }
                    // A native peer command can have queued deauthentication
                    // or early EAPOL while this owner awaited its receipt.
                    // Drain that actual RX generation before publishing link.
                    continue;
                }
                if idle
                    && self.station.phase == Phase::Open
                    && self.station.native_associated
                    && self
                        .station
                        .security
                        .as_ref()
                        .is_none_or(Security::port_open)
                {
                    self.station.admitted = true;
                    return Ok(());
                }
                environment.pause().await;
            }
        }
        .await;
        attempt.armed = false;
        if result.is_err() {
            self.abort_station();
        }
        result
    }
    pub(crate) fn progress_station(
        &mut self,
        environment: &impl Environment,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if self.station_phase() == Phase::Failed {
            self.abort_station();
            return Err(Error::State);
        }
        if !matches!(self.station.phase, Phase::Passive | Phase::Open) {
            return Err(Error::State);
        }
        let result = self.progress_station_inner(environment);
        if result.is_err() {
            self.abort_station();
        }
        if result?
            && self.station_peer().is_some()
            && self
                .station
                .security
                .as_ref()
                .is_none_or(Security::port_open)
        {
            Ok(self.station.received.drain(..).collect())
        } else {
            Ok(Vec::new())
        }
    }
    fn progress_station_inner(&mut self, environment: &impl Environment) -> Result<bool, Error> {
        if self.station.failed.load(Ordering::Acquire) || self.phase != Hardware::Running {
            return Err(Error::State);
        }
        self.check_station_policy(environment)?;
        super::super::station_control::radio_on(&self.io)?;
        let now = environment.now_ms();
        if now < self.station.last_now {
            return Err(Error::State);
        }
        self.station.last_now = now;
        if self.station.phase != Phase::Passive
            && self.station.phase != Phase::Open
            && now >= self.station.deadline
        {
            return Err(Error::Timeout);
        }
        if self.station.phase == Phase::Open && now.saturating_sub(self.station.last_peer) >= 5000 {
            return Err(Error::PeerLost);
        }
        if self.station.admitted
            && now >= self.station.deadline
            && self
                .station
                .security
                .as_ref()
                .is_some_and(Security::handshake_active)
        {
            return Err(Error::Timeout);
        }
        if let Some(pending) = &self.station.pending {
            if now >= pending.deadline {
                return Err(Error::Timeout);
            }
            if let Some(delivery) = self.poll_delivery()? {
                let pending = self.station.pending.take().ok_or(Error::State)?;
                if delivery.id != pending.id || delivery.bytes != pending.bytes {
                    return Err(Error::Profile);
                }
                if matches!(pending.kind, Kind::Eapol) {
                    let security = self.station.security.as_mut().ok_or(Error::State)?;
                    if security.pending_frame() != Some(delivery.bytes.as_slice()) {
                        return Err(Error::Profile);
                    }
                    security
                        .reply_delivered(delivery.bytes.len())
                        .map_err(Error::Security)?;
                    if security.port_open() {
                        self.station.phase = Phase::Open;
                    }
                }
            }
        }
        let own = self.local().ok_or(Error::State)?;
        let peer = self
            .station
            .candidate
            .as_ref()
            .map(|candidate| candidate.bss.bssid);
        let mut idle = false;
        for _ in 0..64 {
            let step = self.poll_receive_step()?;
            if !step.consumed {
                idle = true;
                break;
            }
            let Some(frame) = step.packet else {
                continue;
            };
            if let Ok(candidate) = Candidate::receive(&frame, own) {
                if self.station.phase == Phase::Passive {
                    self.cache_candidate(candidate, now);
                } else if Some(candidate.bss.bssid) == peer {
                    let old = self.station.candidate.as_ref().ok_or(Error::State)?;
                    if candidate.bss.ssid != old.bss.ssid
                        || candidate.rsne != old.rsne
                        || candidate.rsnxe != old.rsnxe
                        || self.station.native_associated
                            && self.station.wmm.is_some()
                            && narf_wireless::wmm::Parameters::parse(
                                &candidate.bss.information_elements,
                            )
                            .ok()
                            .flatten()
                                != self.station.wmm
                    {
                        return Err(Error::Profile);
                    }
                    self.station.last_peer = now;
                }
                continue;
            }
            let bytes = frame.bytes();
            if bytes.len() < 24 || Some(bytes[10..16].try_into().unwrap()) != peer {
                continue;
            }
            if matches!(bytes[0], 0xa0 | 0xc0)
                && bytes[16..22] == bytes[10..16]
                && (bytes[4..10] == own || bytes[4..10] == [255; 6])
            {
                if bytes[1] & 0xc7 != 0 || bytes.get(24..26).is_none_or(|reason| reason == [0, 0]) {
                    return Err(Error::Profile);
                }
                return Err(Error::PeerLost);
            }
            let management = matches!(
                self.station.phase,
                Phase::Authentication | Phase::Association
            ) && matches!(bytes[0], 0xb0 | 0x10);
            let key = eapol(bytes, own, peer.ok_or(Error::State)?);
            let data = self.station.phase == Phase::Open
                && (bytes[0] == 8 || self.station.wmm.is_some() && bytes[0] == 0x88);
            if management || key && self.station.phase != Phase::Passive || data {
                if self.station.incoming.len() == 64 {
                    return Err(Error::Allocation);
                }
                self.station.incoming.push_back(frame);
            }
        }
        while self.station.pending.is_none() {
            let Some(frame) = self.station.incoming.pop_front() else {
                break;
            };
            let bytes = frame.bytes();
            match self.station.phase {
                Phase::Authentication => {
                    if let Some(assoc) = self
                        .station
                        .plan
                        .as_mut()
                        .ok_or(Error::State)?
                        .authentication_response(bytes)
                        .map_err(Error::Management)?
                    {
                        let mut assoc = assoc.to_vec();
                        if self.station.wmm.is_some() {
                            assoc.extend_from_slice(&narf_wireless::wmm::INFORMATION);
                        }
                        self.queue_station(assoc, Kind::Association, now, true, environment)?;
                        self.station.phase = Phase::Association;
                        self.station.deadline = now.saturating_add(5000);
                    }
                }
                Phase::Association => {
                    if let Some(aid) = self
                        .station
                        .plan
                        .as_mut()
                        .ok_or(Error::State)?
                        .association_response(bytes)
                        .map_err(Error::Management)?
                    {
                        let capability = u16::from_le_bytes([bytes[24], bytes[25]]);
                        if self.station.wmm.is_some() {
                            let p = narf_wireless::wmm::Parameters::parse(
                                bytes.get(30..).ok_or(Error::Profile)?,
                            )
                            .map_err(|_| Error::Profile)?
                            .ok_or(Error::Profile)?;
                            super::super::wmm::admit(
                                p,
                                self.station.capability & capability & 0x400 != 0,
                            )?;
                            self.station.wmm = Some(p);
                        }
                        self.station.capability &= capability;
                        self.station.aid = Some(aid);
                        self.station.phase = Phase::Configuring;
                        return Ok(false);
                    }
                }
                Phase::FourWay | Phase::Open => {
                    if let Some(security) = &mut self.station.security {
                        let handshake_active = security.handshake_active();
                        match security
                            .receive_with_nonce(&frame, || environment.fresh_nonce())
                            .map_err(Error::Security)?
                        {
                            station_security::Rx::Ignored => {}
                            station_security::Rx::ReplyReady => {
                                let reply = security.pending_frame().ok_or(Error::State)?.to_vec();
                                if self.station.admitted && !handshake_active {
                                    self.station.deadline = now.saturating_add(5000);
                                }
                                self.queue_station(reply, Kind::Eapol, now, false, environment)?;
                                self.station.last_peer = now;
                            }
                            station_security::Rx::Data(normalized) => {
                                if let Some(bytes) =
                                    ethernet(&normalized, own, peer.ok_or(Error::State)?)
                                {
                                    if self.station.received.len() == 64 {
                                        return Err(Error::Allocation);
                                    }
                                    self.station.received.push_back(bytes);
                                    self.station.last_peer = now;
                                }
                            }
                        }
                    } else if let Some(bytes) = ethernet(bytes, own, peer.ok_or(Error::State)?) {
                        if self.station.received.len() == 64 {
                            return Err(Error::Allocation);
                        }
                        self.station.received.push_back(bytes);
                        self.station.last_peer = now;
                    }
                }
                _ => {}
            }
        }
        Ok(idle)
    }
    pub(crate) fn station_transmit_ready(&self) -> bool {
        self.station_peer().is_some()
            && self.station.pending.is_none()
            && self.transmit_ready()
            && self
                .station
                .security
                .as_ref()
                .is_none_or(|security| security.port_open() && security.pending_frame().is_none())
    }
    pub(crate) fn send_station_ethernet(
        &mut self,
        bytes: &[u8],
        environment: &impl Environment,
    ) -> Result<(), Error> {
        if !self.station_transmit_ready() {
            return Err(Error::Busy);
        }
        let result = (|| {
            self.check_station_policy(environment)?;
            let own = self.local().ok_or(Error::State)?;
            let peer = self.station_peer().ok_or(Error::State)?;
            let frame = if let Some(security) = &mut self.station.security {
                if self.station.wmm.is_some() {
                    security.transmit_ethernet_qos(bytes, 0)
                } else {
                    security.transmit_ethernet(bytes)
                }
                .map_err(Error::Security)?
            } else {
                if !(14..=1514).contains(&bytes.len())
                    || bytes[6..12] != own
                    || bytes[..6] == [0; 6]
                {
                    return Err(Error::Profile);
                }
                let protocol = u16::from_be_bytes([bytes[12], bytes[13]]);
                if protocol < 0x600 || matches!(protocol, 0x888e | 0x80f3 | 0x8137) {
                    return Err(Error::Profile);
                }
                let mut frame = vec![if self.station.wmm.is_some() { 0x88 } else { 8 }, 1, 0, 0];
                frame.extend_from_slice(&peer);
                frame.extend_from_slice(&own);
                frame.extend_from_slice(&bytes[..6]);
                frame.extend_from_slice(&(self.station.sequence << 4).to_le_bytes());
                self.station.sequence = (self.station.sequence + 1) & 4095;
                if self.station.wmm.is_some() {
                    frame.extend_from_slice(&[0, 0]);
                }
                frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
                frame.extend_from_slice(&bytes[12..]);
                frame
            };
            self.queue_station(frame, Kind::Data, environment.now_ms(), false, environment)
        })();
        if result.is_err() {
            self.abort_station();
        }
        result
    }
    pub(crate) async fn disconnect_station(&mut self) -> Result<(), Error> {
        if self.station.phase == Phase::Stopped {
            return Ok(());
        }
        self.station.phase = Phase::Stopping;
        self.station.received.clear();
        self.station.incoming.clear();
        self.station.pmk = None;
        if let Some(security) = &mut self.station.security {
            security.fail();
        }
        let mut attempt = Attempt {
            failed: self.station.failed.clone(),
            armed: true,
        };
        let result = self.disconnect_station_peer().await.map_err(Error::Radio);
        attempt.armed = false;
        if result.is_err() {
            self.abort_station();
        } else {
            self.station.native_associated = false;
            self.station.phase = Phase::Stopped;
        }
        result
    }
}
