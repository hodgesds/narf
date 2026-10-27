//! Retained single-channel legacy station transaction over the native radio.
//! USB publication, MLME response, firmware media state and RSNA reply delivery
//! are distinct proofs. No caller cancellation reconstructs the radio/keys.
use super::{
    firmware_transport::ControlIo,
    management_runtime::{self, Action, Candidate, Join, SecurityMode},
    packet_codec::Mpdu,
    packet_transport, power_policy,
    receive_runtime::{self, Receiver},
    security_runtime::{self, Security},
};
use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use zeroize::Zeroizing;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    State,
    Timeout,
    PeerLost,
    Profile,
    Radio(receive_runtime::Error),
    Management(management_runtime::Error),
    Security(security_runtime::Error),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    Starting,
    Authentication,
    Association,
    FourWay,
    Open,
    Stopping,
    Stopped,
    Failed,
}
#[derive(Debug, Clone, Copy)]
enum Tx {
    Authentication,
    Association,
    Eapol,
    Data,
    Decline,
}
struct Captured {
    frame: Mpdu,
    admitted: bool,
    epoch: u64,
}
struct Pending {
    kind: Tx,
    deadline: u64,
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
pub struct Station<C: ControlIo, B: packet_transport::Io> {
    radio: Receiver<C, B>,
    plan: Join,
    mode: SecurityMode,
    phase: Phase,
    permission: power_policy::Permission,
    pmk: Option<Zeroizing<[u8; 32]>>,
    security: Option<Security>,
    failed: Arc<AtomicBool>,
    pending: Option<Pending>,
    batch: VecDeque<Captured>,
    received: VecDeque<Vec<u8>>,
    controls: VecDeque<Vec<u8>>,
    delivered_reply: Option<usize>,
    epoch: Arc<AtomicU64>,
    retire: Option<Arc<dyn Fn() + Send + Sync>>,
    deadline: u64,
    last_now: u64,
    last_peer: u64,
    sequence: u16,
}
impl<C: ControlIo, B: packet_transport::Io> core::fmt::Debug for Station<C, B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188euStation")
            .field("phase", &self.phase())
            .field("channel", &self.radio.channel())
            .finish_non_exhaustive()
    }
}
impl<C: ControlIo, B: packet_transport::Io> Station<C, B> {
    pub fn new(
        mut radio: Receiver<C, B>,
        candidate: Candidate,
        ssid: &[u8],
        mode: SecurityMode,
        pmk: Option<Zeroizing<[u8; 32]>>,
        permission: power_policy::Permission,
    ) -> Result<Self, Error> {
        if candidate.channel() != radio.channel()
            || candidate.channel() != permission.channel()
            || mode.is_wpa2() != pmk.is_some()
            || !radio.matches_power(permission)
        {
            return Err(Error::Profile);
        }
        let own = radio.local().ok_or(Error::State)?;
        let plan = Join::prepare_with_phy(candidate, own, ssid, mode, radio.ht_local())
            .map_err(Error::Management)?;
        if plan.wmm().is_some() {
            radio.qualify_wmm(permission).map_err(Error::Radio)?;
        }
        Ok(Self {
            radio,
            plan,
            mode,
            phase: Phase::Prepared,
            permission,
            pmk,
            security: None,
            failed: Arc::new(AtomicBool::new(false)),
            pending: None,
            batch: VecDeque::new(),
            received: VecDeque::new(),
            controls: VecDeque::new(),
            delivered_reply: None,
            epoch: Arc::new(AtomicU64::new(1)),
            retire: None,
            deadline: 0,
            last_now: 0,
            last_peer: 0,
            sequence: 2,
        })
    }
    pub fn append_sme_ies(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.phase() != Phase::Prepared {
            return Err(Error::State);
        }
        self.plan.append_sme_ies(bytes).map_err(Error::Management)
    }
    pub fn peer(&self) -> [u8; 6] {
        self.plan.candidate().bssid()
    }
    pub fn transmit_ready(&self) -> bool {
        self.controlled_port_open()
            && self.pending.is_none()
            && self.controls.is_empty()
            && self.batch.is_empty()
    }
    pub fn phase(&self) -> Phase {
        if self.failed.load(Ordering::Acquire)
            || self.radio.phase() == receive_runtime::Phase::Failed
        {
            Phase::Failed
        } else {
            self.phase
        }
    }
    pub fn carrier_up(&self) -> bool {
        self.phase() == Phase::Open
    }
    pub fn controlled_port_open(&self) -> bool {
        self.carrier_up()
            && self.delivered_reply.is_none()
            && self.security.as_ref().is_none_or(Security::port_open)
    }
    pub(super) fn authority(&self) -> receive_runtime::Authority {
        self.radio.authority()
    }
    pub(super) fn ht_enabled(&self) -> bool {
        self.radio.ht_enabled()
    }
    pub(super) fn receive_epoch(&self) -> (Arc<AtomicU64>, u64) {
        (self.epoch.clone(), self.epoch.load(Ordering::Acquire))
    }
    pub(super) fn set_retirement(&mut self, retire: Option<Arc<dyn Fn() + Send + Sync>>) {
        self.retire = retire;
    }
    fn retire_receive(&mut self) {
        self.received.clear();
        self.controls.clear();
        if self
            .epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .is_err()
        {
            self.failed.store(true, Ordering::Release);
        }
        if let Some(retire) = &self.retire {
            retire();
        }
    }
    fn attempt(&self) -> Attempt {
        Attempt {
            failed: self.failed.clone(),
            armed: true,
        }
    }
    pub(super) fn abort(&mut self) {
        self.fail();
        self.received.clear();
    }
    fn fail(&mut self) {
        self.retire_receive();
        self.batch.clear();
        self.plan.cancel();
        self.failed.store(true, Ordering::Release);
        self.phase = Phase::Failed;
        self.radio.fail_terminal();
        if let Some(s) = &mut self.security {
            s.fail();
        }
    }
    pub async fn begin(&mut self, now_ms: u64) -> Result<(), Error> {
        if self.phase() != Phase::Prepared {
            return Err(Error::State);
        }
        self.phase = Phase::Starting;
        let mut attempt = self.attempt();
        let proof = self.radio.wmm_proof();
        let operation = async {
            match self.radio.phase() {
                receive_runtime::Phase::Prepared | receive_runtime::Phase::Stopped => {
                    self.radio.start().await.map_err(Error::Radio)?
                }
                receive_runtime::Phase::Receiving => (),
                _ => return Err(Error::State),
            }
            self.radio
                .enable_transmit(self.permission)
                .await
                .map_err(Error::Radio)?;
            self.radio
                .prepare_station(
                    self.plan.candidate().bssid(),
                    self.plan.candidate().capability() & 0x400 != 0,
                )
                .await
                .map_err(Error::Radio)?;
            let Action::Transmit(frame) = self.plan.begin().map_err(Error::Management)? else {
                return Err(Error::State);
            };
            self.radio.submit_management(&frame).map_err(Error::Radio)?;
            self.pending = Some(Pending {
                kind: Tx::Authentication,
                deadline: now_ms.saturating_add(1000),
            });
            self.phase = Phase::Authentication;
            self.deadline = now_ms.saturating_add(5000);
            self.last_now = now_ms;
            self.last_peer = now_ms;
            Ok(())
        };
        let result = if let Some(proof) = proof {
            proof.fence(operation, Error::Radio).await
        } else {
            operation.await
        };
        attempt.armed = false;
        if result.is_err() {
            self.fail();
        }
        result
    }
    /// Bounded self-driven service. A production worker supplies monotonic
    /// milliseconds and fresh CSPRNG SNonce bytes and yields between calls.
    pub async fn step(&mut self, now_ms: u64, fresh_snonce: [u8; 32]) -> Result<(), Error> {
        self.step_with_nonce(now_ms, || Some(fresh_snonce)).await
    }
    pub async fn step_with_nonce(
        &mut self,
        now_ms: u64,
        mut fresh_snonce: impl FnMut() -> Option<[u8; 32]> + Send,
    ) -> Result<(), Error> {
        if !matches!(
            self.phase(),
            Phase::Authentication | Phase::Association | Phase::FourWay | Phase::Open
        ) {
            return Err(Error::State);
        }
        let mut attempt = self.attempt();
        let proof = self.radio.wmm_proof();
        let operation = self.step_inner(now_ms, &mut fresh_snonce);
        let result = if let Some(proof) = proof {
            proof.fence(operation, Error::Radio).await
        } else {
            operation.await
        };
        attempt.armed = false;
        if result.is_err() {
            self.fail();
        }
        result
    }
    async fn step_inner(
        &mut self,
        now: u64,
        nonce: &mut (impl FnMut() -> Option<[u8; 32]> + Send),
    ) -> Result<(), Error> {
        if self.phase == Phase::Open {
            return self.network_inner(now, nonce);
        }
        if !self.progress(now)? {
            return Ok(());
        }
        for _ in 0..16 {
            let Some(captured) = self.batch.pop_front() else {
                break;
            };
            let Some((frame, admitted)) = self.admit_capture(captured) else {
                continue;
            };
            if let Ok(beacon) = Candidate::from_receive(
                &frame,
                self.radio.channel(),
                self.radio.local().ok_or(Error::State)?,
            ) {
                if beacon.bssid() == self.plan.candidate().bssid()
                    && beacon.ssid() == self.plan.candidate().ssid()
                {
                    if matches!(
                        self.plan.phase(),
                        management_runtime::Phase::Associated { .. }
                    ) {
                        if let Some(p) = self.plan.wmm() {
                            if narf_wireless::wmm::Parameters::parse(beacon.information_elements())
                                .ok()
                                .flatten()
                                != Some(p)
                            {
                                return Err(Error::PeerLost);
                            }
                        }
                    }
                    self.last_peer = now;
                }
                continue;
            }
            if let Some(action) = self.plan.receive(&frame).map_err(Error::Management)? {
                self.last_peer = now;
                match action {
                    Action::Transmit(frame) => {
                        self.radio.submit_management(&frame).map_err(Error::Radio)?;
                        self.pending = Some(Pending {
                            kind: Tx::Association,
                            deadline: now.saturating_add(1000),
                        });
                        self.phase = Phase::Association;
                        self.deadline = now.saturating_add(5000);
                        return Ok(());
                    }
                    Action::Associated { aid } => {
                        if let Some(p) = self.plan.wmm() {
                            self.radio
                                .configure_wmm_phy(
                                    p,
                                    self.plan.candidate().capability() & 0x400 != 0,
                                    self.plan.ht_selected(),
                                )
                                .await
                                .map_err(Error::Radio)?;
                        }
                        self.radio
                            .association(aid, true)
                            .await
                            .map_err(Error::Radio)?;
                        if self.mode.is_wpa2() {
                            let own = self.radio.local().ok_or(Error::State)?;
                            let body = self.plan.rsn_body().ok_or(Error::State)?;
                            let candidate = self.plan.candidate();
                            let pmk = self.pmk.take().ok_or(Error::State)?;
                            self.security = Some(
                                Security::new(
                                    own,
                                    candidate.bssid(),
                                    &pmk,
                                    &body,
                                    candidate.ap_rsne().ok_or(Error::State)?,
                                    candidate.ap_rsnxe(),
                                    self.sequence,
                                )
                                .map_err(Error::Security)?,
                            );
                            self.phase = Phase::FourWay;
                            self.deadline = now.saturating_add(10000);
                        } else {
                            self.phase = Phase::Open;
                        }
                    }
                }
                continue;
            }
            if !matches!(self.phase, Phase::FourWay | Phase::Open) {
                continue;
            }
            if self.control_frame(&frame, admitted)? {
                continue;
            }
            if self.data_frame(&frame, admitted, now, &mut *nonce)? {
                return Ok(());
            }
        }
        Ok(())
    }
    fn progress(&mut self, now: u64) -> Result<bool, Error> {
        self.radio.current_wmm().map_err(Error::Radio)?;
        if now < self.last_now {
            return Err(Error::State);
        }
        self.last_now = now;
        if self.phase != Phase::Open && now >= self.deadline {
            return Err(Error::Timeout);
        }
        if self.phase == Phase::Open && now.saturating_sub(self.last_peer) >= 5000 {
            return Err(Error::PeerLost);
        }
        if let Some(pending) = &self.pending {
            if let Some(delivered) = self.radio.poll_delivery().map_err(Error::Radio)? {
                if matches!(pending.kind, Tx::Eapol) {
                    self.delivered_reply = Some(delivered.native_bytes);
                }
                self.pending = None;
            } else if now >= pending.deadline {
                return Err(Error::Timeout);
            }
        }
        let mut idle = false;
        for _ in 0..4 {
            let Some(frames) = self.radio.poll().map_err(Error::Radio)? else {
                idle = true;
                break;
            };
            let admitted = self.controlled_port_open();
            let epoch = self.epoch.load(Ordering::Acquire);
            for frame in frames {
                if self.batch.len() == 256 {
                    return Err(Error::State);
                }
                self.batch.push_back(Captured {
                    frame,
                    admitted,
                    epoch,
                });
            }
        }
        if idle {
            if let Some(bytes) = self.delivered_reply.take() {
                self.security
                    .as_mut()
                    .ok_or(Error::State)?
                    .reply_delivered(bytes)
                    .map_err(Error::Security)?;
                self.retire_receive();
                if self.phase == Phase::FourWay
                    && self.security.as_ref().is_some_and(Security::port_open)
                {
                    self.phase = Phase::Open;
                    self.last_peer = now;
                }
            }
        }
        if self.pending.is_none() && self.delivered_reply.is_none() && self.controlled_port_open() {
            if let Some(mut frame) = self.controls.pop_front() {
                frame[22..24].copy_from_slice(&(self.sequence << 4).to_le_bytes());
                self.sequence = (self.sequence + 1) & 4095;
                self.radio.submit_management(&frame).map_err(Error::Radio)?;
                self.pending = Some(Pending {
                    kind: Tx::Decline,
                    deadline: now.saturating_add(1000),
                });
            }
        }
        Ok(self.pending.is_none() && self.delivered_reply.is_none())
    }
    fn admit_capture(&self, captured: Captured) -> Option<(Mpdu, bool)> {
        let mut admitted = captured.admitted;
        if captured.epoch != self.epoch.load(Ordering::Acquire) {
            if !private_eapol(&captured.frame.bytes, self.radio.local()?, self.peer()) {
                return None;
            }
            admitted = false;
        }
        Some((captured.frame, admitted))
    }
    fn control_frame(&mut self, frame: &Mpdu, admitted: bool) -> Result<bool, Error> {
        self.radio.current_wmm().map_err(Error::Radio)?;
        let b = &frame.bytes;
        if b.first() != Some(&0xd0) {
            return Ok(false);
        }
        if !admitted
            || !self.controlled_port_open()
            || !self.plan.ht_selected()
            || !frame.admitted(false)
            || b.len() != 33
            || b[1] & 0xc7 != 0
            || b[4..10] != self.radio.local().ok_or(Error::State)?
            || b[10..16] != self.peer()
            || b[16..22] != self.peer()
            || b[22] & 15 != 0
            || b[24..26] != [3, 0]
        {
            return Ok(true);
        }
        let p = u16::from_le_bytes([b[27], b[28]]);
        if p & 2 == 0 || (p >> 2) & 15 >= 8 || p >> 6 == 0 || b[31] & 15 != 0 {
            return Ok(true);
        }
        if self.controls.len() == 8 {
            return Err(Error::State);
        }
        let mut response = vec![0xd0, 0, 0, 0];
        response.extend_from_slice(&self.peer());
        response.extend_from_slice(&self.radio.local().ok_or(Error::State)?);
        response.extend_from_slice(&self.peer());
        response.extend_from_slice(&[0, 0, 3, 1, b[26], 37, 0]);
        response.extend_from_slice(&(p & !1).to_le_bytes());
        response.extend_from_slice(&b[29..31]);
        self.controls.push_back(response);
        Ok(true)
    }
    fn data_frame(
        &mut self,
        frame: &Mpdu,
        admitted: bool,
        now: u64,
        nonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<bool, Error> {
        self.radio.current_wmm().map_err(Error::Radio)?;
        let authority = self.radio.authority();
        if !frame.admitted(self.plan.ht_selected()) {
            return Ok(false);
        }
        let b = &frame.bytes;
        let own = self.radio.local().ok_or(Error::State)?;
        let aggregate = b.first() == Some(&0x88) && b.get(24).is_some_and(|q| q & 0x80 != 0);
        if aggregate {
            if !admitted
                || !self.controlled_port_open()
                || !self.plan.ht_selected()
                || self.received.len() + narf_wireless::amsdu::MAX_SUBFRAMES > 256
            {
                return Ok(false);
            }
            let frames = if let Some(security) = &mut self.security {
                authority
                    .invoke(|| security.receive_amsdu(frame))
                    .map_err(Error::Radio)?
                    .map_err(Error::Security)?
            } else if b.len() >= 26
                && b[1] & 0xc7 == 2
                && b[4..10] == own
                && b[10..16] == self.peer()
                && b[16] & 1 == 0
                && b[16..22] != [0; 6]
                && b[22] & 15 == 0
                && b[24] & 0x70 == 0
                && b[25] == 0
            {
                narf_wireless::amsdu::decode(&b[26..], own, b[4..10].try_into().unwrap()).ok()
            } else {
                None
            };
            if let Some(frames) = frames {
                self.received.extend(frames);
                self.last_peer = now;
            }
            return Ok(false);
        }
        if !admitted && !private_eapol(b, own, self.peer()) {
            return Ok(false);
        }
        if let Some(security) = &mut self.security {
            match authority
                .invoke(|| security.receive_with_nonce(frame, nonce))
                .map_err(Error::Radio)?
                .map_err(Error::Security)?
            {
                security_runtime::Rx::Ignored => (),
                security_runtime::Rx::ReplyReady => {
                    let reply = security.pending_frame().ok_or(Error::State)?.to_vec();
                    self.retire_receive();
                    self.radio
                        .submit_native_data(&reply)
                        .map_err(Error::Radio)?;
                    self.pending = Some(Pending {
                        kind: Tx::Eapol,
                        deadline: now.saturating_add(1000),
                    });
                    self.last_peer = now;
                    return Ok(true);
                }
                security_runtime::Rx::Data(frame) => {
                    if !admitted {
                        return Ok(false);
                    }
                    self.last_peer = now;
                    if let Some(ethernet) = ethernet(&frame) {
                        if self.received.len() < 32 {
                            self.received.push_back(ethernet);
                        }
                    }
                }
            }
        } else if let Some(ethernet) = self.open_receive(frame) {
            self.last_peer = now;
            if self.received.len() < 32 {
                self.received.push_back(ethernet);
            }
        }
        Ok(false)
    }
    /// The network wait path must make progress without awaiting another
    /// executor task. After association, USB polling, shared RSNA and packet
    /// crypto are synchronous; radio/firmware control awaits are excluded.
    pub fn poll_network(&mut self, now: u64, nonce: [u8; 32]) -> Result<(), Error> {
        self.poll_network_with_nonce(now, || Some(nonce))
    }
    pub fn poll_network_with_nonce(
        &mut self,
        now: u64,
        mut nonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<(), Error> {
        if self.phase() != Phase::Open {
            return Err(Error::State);
        }
        let result = self.network_inner(now, &mut nonce);
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn network_inner(
        &mut self,
        now: u64,
        nonce: &mut impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<(), Error> {
        if !self.progress(now)? {
            return Ok(());
        }
        for _ in 0..16 {
            let Some(captured) = self.batch.pop_front() else {
                break;
            };
            let Some((frame, admitted)) = self.admit_capture(captured) else {
                continue;
            };
            if let Ok(beacon) = Candidate::from_receive(
                &frame,
                self.radio.channel(),
                self.radio.local().ok_or(Error::State)?,
            ) {
                if beacon.bssid() == self.plan.candidate().bssid()
                    && beacon.ssid() == self.plan.candidate().ssid()
                {
                    if let Some(p) = self.plan.wmm() {
                        if narf_wireless::wmm::Parameters::parse(beacon.information_elements())
                            .ok()
                            .flatten()
                            != Some(p)
                        {
                            return Err(Error::PeerLost);
                        }
                    }
                    self.last_peer = now;
                }
                continue;
            }
            if self
                .plan
                .receive(&frame)
                .map_err(Error::Management)?
                .is_some()
            {
                return Err(Error::State);
            }
            if self.control_frame(&frame, admitted)? {
                continue;
            }
            if self.data_frame(&frame, admitted, now, &mut *nonce)? {
                return Ok(());
            }
        }
        Ok(())
    }
    fn open_receive(&self, frame: &Mpdu) -> Option<Vec<u8>> {
        let b = &frame.bytes;
        let own = self.radio.local()?;
        if frame.decrypted
            || !frame.admitted(self.plan.ht_selected())
            || b.len() < 24
            || b[10..16] != self.plan.candidate().bssid()
            || b[4..10] != own && b[4] & 1 == 0
            || b[16..22] == [0; 6]
            || b[16] & 1 != 0
            || b[4] & 1 != 0 && b[16..22] == own
        {
            return None;
        }
        ethernet(b)
    }
    pub fn pop_received(&mut self) -> Option<Vec<u8>> {
        if self.controlled_port_open() {
            self.received.pop_front()
        } else {
            None
        }
    }
    /// Close host admission before awaiting any teardown. A completed USB
    /// Stop retires pending native TX/RX without assuming a radio ACK. This
    /// initial lifecycle is deliberately one association per firmware claim;
    /// key history cannot be reset by creating another station after stop.
    pub async fn disconnect(&mut self) -> Result<(), Error> {
        if self.phase() == Phase::Stopped {
            return Ok(());
        }
        if !matches!(
            self.phase(),
            Phase::Authentication | Phase::Association | Phase::FourWay | Phase::Open
        ) {
            return Err(Error::State);
        }
        self.phase = Phase::Stopping;
        self.retire_receive();
        self.received.clear();
        self.pmk = None;
        if let Some(security) = &mut self.security {
            security.fail();
        }
        let mut attempt = self.attempt();
        let proof = self.radio.authority();
        let operation = async {
            // The media command reports local station state. It does not
            // reuse/cancel the independent native bulk receipt.
            self.radio
                .association(0, false)
                .await
                .map_err(Error::Radio)?;
            self.radio.stop().await.map_err(Error::Radio)
        };
        let result = proof.fence(operation, Error::Radio).await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.pending = None;
                self.batch.clear();
                self.plan.cancel();
                self.phase = Phase::Stopped;
                Ok(())
            }
            Err(error) => {
                self.fail();
                Err(error)
            }
        }
    }
    /// Backpressure precedes encryption/PN consumption. EAPOL is never admitted
    /// from an Ethernet client; only shared-Supplicant replies own that path.
    pub fn send_ethernet(&mut self, frame: &[u8], now: u64) -> Result<(), Error> {
        if let Err(error) = self.radio.current_wmm() {
            self.fail();
            return Err(Error::Radio(error));
        }
        if !self.transmit_ready() {
            return Err(Error::State);
        }
        let native = if let Some(security) = &mut self.security {
            match if self.plan.wmm().is_some() {
                security.transmit_ethernet_qos(frame, 0)
            } else {
                security.transmit_ethernet(frame)
            } {
                Ok(frame) => frame,
                Err(error) => {
                    if !security.port_open() {
                        self.fail();
                    }
                    return Err(Error::Security(error));
                }
            }
        } else {
            let own = self.radio.local().ok_or(Error::State)?;
            if !(14..=1514).contains(&frame.len()) || frame[6..12] != own || frame[..6] == [0; 6] {
                return Err(Error::Profile);
            }
            let proto = u16::from_be_bytes([frame[12], frame[13]]);
            if proto < 0x600 || matches!(proto, 0x888e | 0x80f3 | 0x8137) {
                return Err(Error::Profile);
            }
            let mut h = vec![if self.plan.wmm().is_some() { 0x88 } else { 8 }, 1, 0, 0];
            h.extend_from_slice(&self.plan.candidate().bssid());
            h.extend_from_slice(&own);
            h.extend_from_slice(&frame[..6]);
            h.extend_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
            if self.plan.wmm().is_some() {
                h.extend_from_slice(&[0, 0]);
            }
            h.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
            h.extend_from_slice(&frame[12..]);
            h
        };
        let rate = if self.plan.wmm().is_some() {
            self.plan.data_rate().map_err(Error::Management)?
        } else {
            0
        };
        if let Err(error) = self.radio.submit_native_data_rate(&native, rate) {
            self.fail();
            return Err(Error::Radio(error));
        }
        self.pending = Some(Pending {
            kind: Tx::Data,
            deadline: now.saturating_add(1000),
        });
        Ok(())
    }
}
/// A complete private authenticator EAPOL-Key original may cross only the
/// M2/terminal-reply receive epoch. It never inherits captured DATA admission.
fn private_eapol(b: &[u8], own: [u8; 6], peer: [u8; 6]) -> bool {
    if b.len() < 24
        || !matches!(b[0], 8 | 0x88)
        || b[1] & 0xc7 != 2
        || b[22] & 15 != 0
        || b[4..10] != own
        || b[10..16] != peer
        || b[16..22] != peer
    {
        return false;
    }
    let offset = if b[0] == 0x88 {
        if b.get(24..26).is_none_or(|q| q[0] & 0xf0 != 0 || q[1] != 0) {
            return false;
        }
        26
    } else {
        24
    };
    let Some(payload) = b.get(offset..) else {
        return false;
    };
    if payload.len() < 12
        || payload[..8] != [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]
        || !(1..=3).contains(&payload[8])
        || payload[9] != 3
    {
        return false;
    }
    usize::from(u16::from_be_bytes([payload[10], payload[11]])) + 12 == payload.len()
}
fn ethernet(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 24
        || !matches!(frame[0], 8 | 0x88)
        || frame[1] & 0xc7 != 2
        || frame[22] & 15 != 0
    {
        return None;
    }
    let offset = if frame[0] == 0x88 {
        if frame
            .get(24..26)
            .is_none_or(|q| q[0] & 0xf0 != 0 || q[1] != 0)
        {
            return None;
        }
        26
    } else {
        24
    };
    let snap = frame.get(offset..offset + 8)?;
    let proto = u16::from_be_bytes([snap[6], snap[7]]);
    if snap[..6] != [0xaa, 0xaa, 3, 0, 0, 0]
        || proto < 0x600
        || matches!(proto, 0x888e | 0x80f3 | 0x8137)
        || frame.len() - offset - 8 > 1500
    {
        return None;
    }
    let mut out = Vec::with_capacity(frame.len() - offset + 6);
    out.extend_from_slice(&frame[4..10]);
    out.extend_from_slice(&frame[16..22]);
    out.extend_from_slice(&snap[6..]);
    out.extend_from_slice(&frame[offset + 8..]);
    Some(out)
}
