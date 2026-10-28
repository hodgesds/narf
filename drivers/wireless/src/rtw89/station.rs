// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RTL8852B channel1 host station state. The exact firmware Owner
//! keeps its native backend; this state never owns or reconstructs hardware.
use super::{
    packet_core::{self as packet, Frame as Mpdu, Receipt},
    power,
    station_control::Admission,
};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec, vec::Vec};
use narf_wireless::{
    association::{self, JoinPlan, ObservedBss, SecurityMode},
    station_security::{self, RawFrame, Security},
};
use zeroize::Zeroizing;

/// Same retained cold/firmware/radio owner. Implementations must invoke
/// current device and exact ordinary RF/response authority at publication;
/// calibration-only qualification cannot satisfy this interface.
///
/// # Safety
/// Every operation borrows the same exclusive retained native owner. All
/// packet mappings remain owned across cancellation and ambiguous failure;
/// current capability and qualified ordinary RF/response checks enclose
/// actual hardware publication, including after an asynchronous wait.
#[async_trait::async_trait]
pub(super) unsafe trait Io: Send {
    fn station_allowed(&mut self) -> Result<(), power::Error>;
    fn station_own(&mut self) -> Result<[u8; 6], power::Error>;
    fn station_wmm_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    /// Signed firmware rate-adaptation program (`Program::FirmwareRa`).
    fn station_firmware_ra_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    /// Program firmware RA for the WMM-configured peer.
    async fn station_configure_ra(
        &mut self,
        _: u16,
        _: Option<super::station_control::HtRa>,
        _: Option<super::station_control::HeRa>,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    /// `rtw89_fw_h2c_ba_cam` for a recipient session start/stop.
    async fn station_configure_ba(
        &mut self,
        _: bool,
        _: u8,
        _: u16,
        _: u16,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Signed HT20 program (`Program::Ht`).
    fn station_ht_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    /// Signed HE20 program (`Program::He`).
    fn station_he_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    /// Signed all-AC/TID QoS program (`radio_policy::Program::QosAll`).
    fn station_qos_all_allowed(&mut self) -> Result<bool, power::Error> {
        Ok(false)
    }
    async fn station_configure_wmm(
        &mut self,
        _: narf_wireless::wmm::Parameters,
        _: bool,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Reprogram EDCA for an already admitted QoS peer.
    async fn station_update_wmm(
        &mut self,
        _: narf_wireless::wmm::Parameters,
        _: bool,
        _: &Admission,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn station_prepare_initial(
        &mut self,
        own: [u8; 6],
        admission: &Admission,
    ) -> Result<(), power::Error>;
    async fn station_prepare_peer(
        &mut self,
        peer: [u8; 6],
        admission: &Admission,
    ) -> Result<(), power::Error>;
    async fn station_commit_peer(
        &mut self,
        peer: [u8; 6],
        aid: u16,
        short_slot: bool,
        admission: &Admission,
    ) -> Result<(), power::Error>;
    async fn station_disconnect(
        &mut self,
        peer: [u8; 6],
        admission: &Admission,
    ) -> Result<(), power::Error>;
    fn packet_prepare(&mut self, own: [u8; 6], macid: u8) -> Result<(), packet::Error>;
    fn packet_start(&mut self) -> Result<(), packet::Error>;
    fn packet_ready(&self) -> bool;
    fn packet_submit(&mut self, bytes: &[u8], report: bool) -> Result<u64, packet::Error>;
    fn packet_submit_rate(
        &mut self,
        bytes: &[u8],
        report: bool,
        rate: u8,
    ) -> Result<u64, packet::Error> {
        if rate == 0 {
            self.packet_submit(bytes, report)
        } else {
            Err(packet::Error::Packet)
        }
    }
    fn packet_poll(&mut self) -> Result<packet::Step, packet::Error>;
    fn packet_stop(&mut self) -> Result<(), packet::Error>;
    /// Bind interrupt delivery to `line` once packets are started. Owners
    /// without an MSI path stay in polled mode.
    fn irq_start(&mut self, _line: &Arc<super::irq::Line>) -> Result<u8, power::Error> {
        Err(power::Error::Unsupported)
    }
    /// Mask, recognize and acknowledge pending interrupt sources.
    fn irq_service(&mut self) -> Result<super::irq::Events, power::Error> {
        Ok(super::irq::Events::default())
    }
    /// Re-enable the interrupt mask after the rings were drained.
    fn irq_rearm(&mut self) -> Result<(), power::Error> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    State,
    Busy,
    Profile,
    Entropy,
    Timeout,
    PeerLost,
    Transport(packet::Error),
    Native(power::Error),
    Management(association::Error),
    Security(station_security::Error),
    /// Firmware halt (SER) or watchdog interrupt from the device.
    Halted,
}
impl From<packet::Error> for Error {
    fn from(error: packet::Error) -> Self {
        Self::Transport(error)
    }
}
impl From<power::Error> for Error {
    fn from(error: power::Error) -> Self {
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
    /// Block Ack action frames: like data, a missing ACK is not fatal.
    Action,
    /// Broadcast probe request (never acknowledged).
    Probe,
}
/// Active-scan probe content: SSIDs (empty = wildcard) and caller IEs.
pub(super) struct Probe {
    pub(super) ssids: Vec<Vec<u8>>,
    pub(super) ies: Vec<u8>,
}
/// mac80211 `ieee80211_build_probe_req` for this 2.4GHz channel1 profile:
/// SSID, Supported Rates (1,2,5.5,11,6,9,12,18), Extended Supported Rates
/// (24,36,48,54), DS Parameter Set, then the caller's extra IEs.
pub(super) fn probe_request(own: [u8; 6], ssid: &[u8], ies: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x40, 0, 0, 0];
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&own);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0, ssid.len() as u8]);
    frame.extend_from_slice(ssid);
    frame.extend_from_slice(&[1, 8, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24]);
    frame.extend_from_slice(&[50, 4, 0x30, 0x48, 0x60, 0x6c]);
    frame.extend_from_slice(&[3, 1, 1]);
    frame.extend_from_slice(ies);
    frame
}
enum BaOp {
    Start(super::block_ack::Request, u16),
    Stop(u8),
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
    wmm: Option<narf_wireless::wmm::Parameters>,
    /// Newer AP EDCA set observed in a peer beacon, awaiting reprogramming.
    edca_pending: Option<narf_wireless::wmm::Parameters>,
    short_slot: bool,
    /// All-AC/TID QoS routing is active for this association.
    qos_all: bool,
    /// Firmware rate adaptation owns DATA rates for this association.
    firmware_ra: bool,
    /// HT20 was negotiated for this association.
    ht: bool,
    /// HE20 was negotiated for this association.
    he: bool,
    /// Data TXWD `DATA_ER` (Linux `er_cap`: HE operation allows ER SU).
    er: bool,
    /// Recipient Block Ack sessions per TID.
    ba: [Option<super::block_ack::Session<Mpdu>>; 8],
    /// BA CAM programming awaiting the async owner.
    ba_ops: VecDeque<BaOp>,
    /// Queued ADDBA responses / DELBAs.
    mgmt_out: VecDeque<Vec<u8>>,
    deadline: u64,
    last_peer: u64,
    last_now: u64,
}
impl core::fmt::Debug for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8852bStation")
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
            wmm: None,
            edca_pending: None,
            short_slot: false,
            qos_all: false,
            firmware_ra: false,
            ht: false,
            he: false,
            er: false,
            ba: core::array::from_fn(|_| None),
            ba_ops: VecDeque::new(),
            mgmt_out: VecDeque::new(),
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
        io.station_prepare_initial(self.own, &self.admission)
            .await?;
        self.admission
            .run(|| Ok(io.packet_prepare(self.own, 0)))??;
        self.prepared = true;
        let started = self
            .admission
            .run(|| Ok(io.packet_start()))
            .map_err(Error::Native)
            .and_then(|result| result.map_err(Error::Transport));
        if let Err(error) = started {
            self.fail(io);
            return Err(error);
        }
        self.last_now = self.environment.now_ms();
        self.phase = Phase::Passive;
        attempt.armed = false;
        Ok(())
    }
    pub(super) fn stop(&mut self, io: &mut impl Io) -> Result<(), Error> {
        self.wmm = None;
        self.edca_pending = None;
        self.qos_all = false;
        self.firmware_ra = false;
        self.ht = false;
        self.he = false;
        self.er = false;
        self.clear_block_ack();
        self.admission.close();
        self.established = false;
        self.phase = Phase::Stopped;
        if let Some(security) = &mut self.security {
            security.fail();
        }
        self.incoming.clear();
        self.received.clear();
        self.peer_commit = None;
        // Controller initialization can already own live CH12/RX DMA before
        // the ordinary packet core exists. The adapter closes that same
        // Native even when preparation was cancelled before Core::prepare.
        io.packet_stop()?;
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
        self.wmm = None;
        self.edca_pending = None;
        self.qos_all = false;
        self.firmware_ra = false;
        self.ht = false;
        self.he = false;
        self.er = false;
        self.clear_block_ack();
        if let Some(security) = &mut self.security {
            security.fail();
        }
        let mut attempt = Attempt {
            admission: self.admission.clone(),
            armed: true,
        };
        let control = if let Some(peer) = &self.peer {
            io.station_disconnect(peer.bss.bssid, &self.admission).await
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
        let rate = if kind == Kind::Data && self.wmm.is_some() && self.firmware_ra {
            // rtw89_core_get_data_rate: lowest negotiated rate bounds retries.
            let rates = self.plan.as_ref().ok_or(Error::State)?.legacy_rates().0 & 0xfff;
            if rates == 0 {
                return Err(Error::Profile);
            }
            let er = if self.er {
                super::packet_format::DATA_ER
            } else {
                0
            };
            super::packet_format::FIRMWARE_RA | er | rates.trailing_zeros() as u8
        } else if kind == Kind::Data && self.wmm.is_some() {
            let rates = self.plan.as_ref().ok_or(Error::State)?.legacy_rates().0;
            [11, 10, 9, 8, 7, 6, 3, 5, 4, 2, 1, 0]
                .into_iter()
                .find(|rate| rates & (1 << rate) != 0)
                .ok_or(Error::Profile)?
        } else {
            0
        };
        let id = io.packet_submit_rate(&bytes, kind != Kind::Data, rate)?;
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
    /// mac80211 `ieee80211_sta_wmm_params` on a bound peer beacon/probe
    /// response. An unchanged parameter-set count (and U-APSD bit) is
    /// ignored. A new count on an established peer queues an EDCA update
    /// that the async owner applies; loss of WMM, an inadmissible set or a
    /// change before the link is open still closes the station.
    fn observe_wmm(&mut self, frame: &Mpdu) -> Result<(), Error> {
        let (Some(current), Some(peer)) = (self.wmm, &self.peer) else {
            return Ok(());
        };
        let Some(candidate) = association::observe(frame, 1, self.own, None)
            .ok()
            .filter(|candidate| candidate.bss.bssid == peer.bss.bssid)
        else {
            return Ok(());
        };
        let offered = narf_wireless::wmm::Parameters::parse(&candidate.bss.information_elements)
            .ok()
            .flatten();
        let Some(offered) = offered else {
            return Err(Error::PeerLost);
        };
        let base = self.edca_pending.unwrap_or(current);
        if offered == base
            || (offered.parameter_set_count == base.parameter_set_count
                && offered.uapsd == base.uapsd)
        {
            return Ok(());
        }
        if self.phase != Phase::Open
            || offered.uapsd != current.uapsd
            || super::station_control::wmm_admit(offered, self.short_slot).is_err()
        {
            return Err(Error::PeerLost);
        }
        self.edca_pending = Some(offered);
        Ok(())
    }
    fn clear_block_ack(&mut self) {
        // Drop discards ownership only (shared Reorder contract).
        self.ba = core::array::from_fn(|_| None);
        self.ba_ops.clear();
        self.mgmt_out.clear();
    }
    fn queue_incoming(&mut self, frames: Vec<Mpdu>) -> Result<(), Error> {
        for frame in frames {
            if self.incoming.len() == 64 {
                return Err(Error::State);
            }
            self.incoming.push_back(frame);
        }
        Ok(())
    }
    /// mac80211 Block Ack receive steps for an open link: ADDBA/DELBA
    /// actions, BlockAckReq and reorder admission of QoS DATA on a live
    /// session. Returns the frame when it continues the ordinary path.
    fn block_ack_rx(&mut self, frame: Mpdu, now: u64) -> Result<Option<Mpdu>, Error> {
        use super::block_ack as ba;
        let control = frame.bytes().first().is_some_and(|fc| fc & 0x0c == 0x04);
        let Some(peer) = self.peer.as_ref().map(|p| p.bss.bssid) else {
            return Ok((!control).then_some(frame));
        };
        if self.phase != Phase::Open {
            return Ok((!control).then_some(frame));
        }
        let now_ns = now.saturating_mul(1_000_000);
        if let Some(action) = ba::parse_action(frame.bytes(), self.own, peer) {
            match action {
                ba::Action::AddbaRequest(request) => {
                    let (status, buf) = ba::decide(&request, self.ht);
                    if status == ba::STATUS_SUCCESS {
                        let tid = usize::from(request.tid);
                        if self.ba[tid].take().is_some() {
                            self.ba_ops.push_back(BaOp::Stop(request.tid));
                        }
                        self.ba_ops.push_back(BaOp::Start(request, buf));
                    } else {
                        self.mgmt_out.push_back(ba::addba_response(
                            self.own,
                            peer,
                            &request,
                            status,
                            request.buf_size,
                        ));
                    }
                }
                ba::Action::Delba {
                    tid,
                    initiator: true,
                    ..
                } => {
                    if self
                        .ba
                        .get_mut(usize::from(tid))
                        .and_then(Option::take)
                        .is_some()
                    {
                        self.ba_ops.push_back(BaOp::Stop(tid));
                    }
                }
                _ => {}
            }
            return Ok(None);
        }
        if let Some((tid, ssn)) = ba::bar(frame.bytes(), self.own, peer) {
            if let Some(session) = self.ba.get_mut(usize::from(tid)).and_then(Option::as_mut) {
                session.last_ms = now;
                let released = session.reorder.advance(ssn, now_ns).unwrap_or_default();
                self.queue_incoming(released)?;
            }
            return Ok(None);
        }
        if control {
            // Only BlockAckReq is consumed; other control frames carry no
            // host state for this station.
            return Ok(None);
        }
        if frame.bytes().get(10..16) == Some(&peer[..]) {
            if let Some((tid, sequence)) = ba::qos_sequence(frame.bytes()) {
                if let Some(session) = self.ba.get_mut(usize::from(tid)).and_then(Option::as_mut) {
                    session.last_ms = now;
                    // Old/duplicate sequence numbers are dropped (mac80211
                    // ieee80211_sta_manage_reorder_buf).
                    let released = session
                        .reorder
                        .push(sequence, now_ns, frame)
                        .unwrap_or_default();
                    self.queue_incoming(released)?;
                    return Ok(None);
                }
            }
        }
        Ok(Some(frame))
    }
    /// Reorder release timer and session inactivity timeout
    /// (`sta_rx_agg_reorder_timer_expired`, `sta_rx_agg_session_timer_expired`).
    fn block_ack_tick(&mut self, now: u64) -> Result<(), Error> {
        let now_ns = now.saturating_mul(1_000_000);
        let peer = self.peer.as_ref().map(|p| p.bss.bssid);
        for tid in 0..8u8 {
            let Some(session) = self.ba[usize::from(tid)].as_mut() else {
                continue;
            };
            let released = session.reorder.expire(now_ns).unwrap_or_default();
            let idle_ms = (u64::from(session.timeout_tu) * 1024).div_ceil(1000);
            let expired = session.timeout_tu != 0 && now.saturating_sub(session.last_ms) > idle_ms;
            self.queue_incoming(released)?;
            if expired {
                self.ba[usize::from(tid)] = None;
                self.ba_ops.push_back(BaOp::Stop(tid));
                if let Some(peer) = peer {
                    self.mgmt_out.push_back(super::block_ack::delba(
                        self.own,
                        peer,
                        tid,
                        super::block_ack::REASON_TIMEOUT,
                    ));
                }
            }
        }
        Ok(())
    }
    /// Live Block Ack sessions (bitmap by TID).
    pub(super) fn block_ack_sessions(&self) -> u8 {
        self.ba
            .iter()
            .enumerate()
            .fold(0, |m, (tid, s)| if s.is_some() { m | 1 << tid } else { m })
    }
    /// Work that needs awaited firmware receipts (EDCA, BA CAM).
    pub(super) fn async_pending(&self) -> bool {
        self.edca_pending() || self.phase == Phase::Open && !self.ba_ops.is_empty()
    }
    pub(super) async fn apply_async(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if self.edca_pending() {
            self.apply_edca(io).await?;
        }
        while let Some(op) = self.ba_ops.pop_front() {
            if self.phase != Phase::Open {
                return Err(Error::State);
            }
            let result = match op {
                BaOp::Start(request, buf) => {
                    let result = io
                        .station_configure_ba(true, request.tid, buf, request.ssn, &self.admission)
                        .await;
                    if result.is_ok() {
                        let mut reorder = narf_wireless::reorder::Reorder::new(
                            buf as u8,
                            super::block_ack::REORDER_TIMEOUT_NS,
                        )
                        .map_err(|_| Error::State)?;
                        // mac80211 head_seq_num = start_seq_num.
                        let now = self.now()?;
                        let _ = reorder.advance(request.ssn, now.saturating_mul(1_000_000));
                        self.ba[usize::from(request.tid)] = Some(super::block_ack::Session {
                            reorder,
                            timeout_tu: request.timeout,
                            last_ms: now,
                            ssn: request.ssn,
                        });
                        let peer = self.peer.as_ref().ok_or(Error::State)?.bss.bssid;
                        self.mgmt_out.push_back(super::block_ack::addba_response(
                            self.own,
                            peer,
                            &request,
                            super::block_ack::STATUS_SUCCESS,
                            buf,
                        ));
                    }
                    result
                }
                BaOp::Stop(tid) => {
                    io.station_configure_ba(false, tid, 0, 0, &self.admission)
                        .await
                }
            };
            if let Err(error) = result {
                if !self.admission.teardown_pending() {
                    self.fail(io);
                }
                return Err(Error::Native(error));
            }
        }
        Ok(())
    }
    pub(super) fn ht(&self) -> bool {
        self.ht
    }
    pub(super) fn he(&self) -> bool {
        self.he
    }
    pub(super) fn qos_all(&self) -> bool {
        self.qos_all && self.wmm.is_some()
    }
    /// 802.1d TID for an outgoing Ethernet frame: classified and ACM
    /// downgraded with the all-AC program, otherwise the BE/TID0 recipe.
    fn tid(&self, frame: &[u8]) -> u8 {
        match self.wmm {
            Some(p) if self.qos_all => {
                super::qos::tid_for(frame, p.ac.map(|ac| ac.admission_control))
            }
            _ => 0,
        }
    }
    pub(super) fn edca_pending(&self) -> bool {
        self.edca_pending.is_some() && self.phase == Phase::Open
    }
    /// Apply a queued live EDCA change through the source H2C path.
    pub(super) async fn apply_edca(&mut self, io: &mut impl Io) -> Result<(), Error> {
        let Some(next) = self.edca_pending else {
            return Ok(());
        };
        if self.phase != Phase::Open || self.wmm.is_none() {
            return Err(Error::State);
        }
        let result = io
            .station_update_wmm(next, self.short_slot, &self.admission)
            .await;
        match result {
            Ok(()) => {
                self.wmm = Some(next);
                if self.edca_pending == Some(next) {
                    self.edca_pending = None;
                }
                Ok(())
            }
            Err(error) => {
                if !self.admission.teardown_pending() {
                    self.fail(io);
                }
                Err(Error::Native(error))
            }
        }
    }
    fn delivery(&mut self, delivery: Receipt) -> Result<(), Error> {
        let pending = self.pending.take().ok_or(Error::State)?;
        if pending.id != delivery.id || pending.bytes != delivery.bytes {
            return Err(Error::State);
        }
        if !delivery.radio_acknowledged
            && !matches!(pending.kind, Kind::Data | Kind::Action | Kind::Probe)
        {
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
                self.observe_wmm(&frame)?;
                if self.lost(&frame) {
                    return Err(Error::PeerLost);
                }
                let frame = match self.block_ack_rx(frame, now)? {
                    Some(frame) => frame,
                    None => continue,
                };
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
                    if let Some(mut association) = self
                        .plan
                        .as_mut()
                        .ok_or(Error::State)?
                        .authentication_response(frame.bytes())?
                        .map(|bytes| bytes.to_vec())
                    {
                        if self.wmm.is_some() {
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
                        if self.wmm.is_some() {
                            let p = narf_wireless::wmm::Parameters::parse(
                                frame.bytes().get(30..).ok_or(Error::Profile)?,
                            )
                            .map_err(|_| Error::Profile)?
                            .ok_or(Error::Profile)?;
                            super::station_control::wmm_admit(p, short)?;
                            self.wmm = Some(p);
                        }
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
        self.block_ack_tick(now)?;
        if self.pending.is_none()
            && self.delivered_reply.is_none()
            && self.phase == Phase::Open
            && self
                .security
                .as_ref()
                .is_none_or(|s| s.pending_frame().is_none())
        {
            if let Some(frame) = self.mgmt_out.pop_front() {
                self.transmit(io, frame, Kind::Action)?;
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
        self.scan_with(io, dwell_ms, None).await
    }
    /// Scan channel 1 for `dwell_ms`. An active scan first transmits one
    /// probe request per SSID (wildcard when none) like mac80211's software
    /// scan, then listens for the dwell.
    pub(super) async fn scan_with(
        &mut self,
        io: &mut impl Io,
        dwell_ms: u64,
        probe: Option<Probe>,
    ) -> Result<Vec<ObservedBss>, Error> {
        if !(1..=1024).contains(&dwell_ms) {
            return Err(Error::Profile);
        }
        if self.phase() != Phase::Passive {
            return Err(Error::State);
        }
        let until = self.now()?.saturating_add(dwell_ms);
        if let Some(probe) = probe {
            let ssids = if probe.ssids.is_empty() {
                vec![Vec::new()]
            } else {
                probe.ssids
            };
            for ssid in ssids {
                while self.pending.is_some() {
                    self.poll(io)?;
                    if self.pending.is_none() {
                        break;
                    }
                    if self.now()? >= until {
                        return Ok(self.candidates());
                    }
                    self.environment.pause().await;
                }
                let frame = probe_request(self.own, &ssid, &probe.ies);
                let admission = self.admission.clone();
                admission.run(|| Ok(self.transmit(io, frame, Kind::Probe)))??;
            }
        }
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
        // HT is offered only with an AP WMM element and the signed HT20
        // program (which itself requires WMM and firmware RA).
        let ap_wmm = narf_wireless::wmm::Parameters::parse(&candidate.bss.information_elements)
            .ok()
            .flatten()
            .is_some();
        let mut plan = if ap_wmm && io.station_wmm_allowed()? && io.station_ht_allowed()? {
            let mut local =
                narf_wireless::association::phy::LocalPhy::ht20(super::station_control::local_ht())
                    .map_err(|_| Error::Profile)?;
            // HE is offered only under the signed HE20 program (which
            // itself requires HT20).
            if io.station_he_allowed()? {
                let he = super::station_control::local_he().ok_or(Error::Profile)?;
                local = local.with_he(he).map_err(|_| Error::Profile)?;
            }
            JoinPlan::prepare_with_phy(&candidate.bss, self.own, ssid, mode, local)?
        } else {
            JoinPlan::prepare(&candidate.bss, self.own, ssid, mode)?
        };
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
        let offered = narf_wireless::wmm::Parameters::parse(&candidate.bss.information_elements)
            .map_err(|_| Error::Profile)?;
        self.wmm = if io.station_wmm_allowed()? {
            offered
        } else {
            None
        };
        if let Some(p) = self.wmm {
            super::station_control::wmm_admit(p, candidate.bss.capability & 0x400 != 0)?;
        }
        self.qos_all = self.wmm.is_some() && io.station_qos_all_allowed()?;
        self.firmware_ra = self.wmm.is_some() && io.station_firmware_ra_allowed()?;
        io.station_prepare_peer(bssid, &self.admission).await?;
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
                io.station_commit_peer(bssid, aid, short, &self.admission)
                    .await?;
                self.short_slot = short;
                if let Some(p) = self.wmm {
                    io.station_configure_wmm(p, short, &self.admission).await?;
                    if self.firmware_ra {
                        let plan = self.plan.as_ref().ok_or(Error::State)?;
                        let rates = plan.legacy_rates().0;
                        let ht = plan.negotiated_phy().map(|phy| {
                            let ht = phy.ht();
                            let m = ht.peer_rx_mcs();
                            super::station_control::HtRa {
                                peer_rx_mcs: [m[0], m[1], m[2], m[3]],
                                sgi20: ht.tx_sgi20(),
                                ldpc: ht.tx_ldpc(),
                            }
                        });
                        let he = plan.negotiated_phy().and_then(|phy| phy.he()).map(|he| {
                            let peer = he.peer_capability().phy_capability();
                            (
                                super::station_control::HeRa {
                                    peer_rx_mcs: he.tx_mcs_map(),
                                    ldpc: he.tx_ldpc(),
                                    dcm: peer[3] & 0x18 != 0,
                                },
                                !he.operation().er_su_disabled(),
                            )
                        });
                        self.ht = ht.is_some();
                        self.he = he.is_some();
                        self.er = he.is_some_and(|(_, er)| er);
                        io.station_configure_ra(rates, ht, he.map(|(he, _)| he), &self.admission)
                            .await?;
                    }
                }
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
        let tid = self.tid(frame);
        let native = if let Some(security) = &mut self.security {
            if self.wmm.is_some() {
                security.transmit_ethernet_qos(frame, tid)?
            } else {
                security.transmit_ethernet(frame)?
            }
        } else {
            if !admitted(frame, self.own) {
                return Err(Error::Profile);
            }
            let mut bytes = vec![if self.wmm.is_some() { 0x88 } else { 8 }, 1, 0, 0];
            bytes.extend_from_slice(&peer);
            bytes.extend_from_slice(&self.own);
            bytes.extend_from_slice(&frame[..6]);
            bytes.extend_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
            if self.wmm.is_some() {
                bytes.extend_from_slice(&[tid, 0]);
            }
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
    if !(32..=1534).contains(&frame.len())
        || !matches!(frame[0], 8 | 0x88)
        || frame[1] & 0xc7 != 2
        || frame[22] & 15 != 0
        || frame[10..16] != peer
        || (frame[4..10] != own && frame[4] & 1 == 0)
        || frame[16] & 1 != 0
        || frame[16..22] == [0; 6]
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
    if snap[..6] != [0xaa, 0xaa, 3, 0, 0, 0] || frame.len() + 6 - offset > 1514 {
        return None;
    }
    let proto = u16::from_be_bytes([snap[6], snap[7]]);
    if proto < 0x600 || matches!(proto, 0x888e | 0x80f3 | 0x8137) {
        return None;
    }
    let mut bytes = Vec::with_capacity(frame.len() - 18);
    bytes.extend_from_slice(&frame[4..10]);
    bytes.extend_from_slice(&frame[16..22]);
    bytes.extend_from_slice(&frame[offset + 6..]);
    Some(bytes)
}
