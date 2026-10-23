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
use core::sync::atomic::{AtomicBool, Ordering};
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
    batch: Option<alloc::vec::IntoIter<Mpdu>>,
    received: VecDeque<Vec<u8>>,
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
        radio: Receiver<C, B>,
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
        let plan = Join::prepare(candidate, own, ssid, mode).map_err(Error::Management)?;
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
            batch: None,
            received: VecDeque::new(),
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
        self.controlled_port_open() && self.pending.is_none()
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
        self.carrier_up() && self.security.as_ref().is_none_or(Security::port_open)
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
        let result = async {
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
        }
        .await;
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
        let result = self.step_inner(now_ms, &mut fresh_snonce).await;
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
            let Some(frame) = self.batch.as_mut().and_then(Iterator::next) else {
                break;
            };
            if let Ok(beacon) = Candidate::from_receive(
                &frame,
                self.radio.channel(),
                self.radio.local().ok_or(Error::State)?,
            ) {
                if beacon.bssid() == self.plan.candidate().bssid()
                    && beacon.ssid() == self.plan.candidate().ssid()
                {
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
            if self.data_frame(&frame, now, &mut *nonce)? {
                return Ok(());
            }
        }
        Ok(())
    }
    fn progress(&mut self, now: u64) -> Result<bool, Error> {
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
            let Some(delivered) = self.radio.poll_delivery().map_err(Error::Radio)? else {
                if now >= pending.deadline {
                    return Err(Error::Timeout);
                }
                return Ok(false);
            };
            if matches!(pending.kind, Tx::Eapol) {
                self.security
                    .as_mut()
                    .ok_or(Error::State)?
                    .reply_delivered(delivered.native_bytes)
                    .map_err(Error::Security)?;
                if self.phase == Phase::FourWay && self.security.as_ref().unwrap().port_open() {
                    self.phase = Phase::Open;
                    self.last_peer = now;
                }
            }
            self.pending = None;
        }
        if self.batch.as_ref().is_none_or(|batch| batch.len() == 0) {
            self.batch = self.radio.poll().map_err(Error::Radio)?.map(Vec::into_iter);
        }
        Ok(true)
    }
    fn data_frame(
        &mut self,
        frame: &Mpdu,
        now: u64,
        nonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<bool, Error> {
        if let Some(security) = &mut self.security {
            match security
                .receive_with_nonce(frame, nonce)
                .map_err(Error::Security)?
            {
                security_runtime::Rx::Ignored => (),
                security_runtime::Rx::ReplyReady => {
                    self.radio
                        .submit_native_data(security.pending_frame().ok_or(Error::State)?)
                        .map_err(Error::Radio)?;
                    self.pending = Some(Pending {
                        kind: Tx::Eapol,
                        deadline: now.saturating_add(1000),
                    });
                    self.last_peer = now;
                    return Ok(true);
                }
                security_runtime::Rx::Data(frame) => {
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
            let Some(frame) = self.batch.as_mut().and_then(Iterator::next) else {
                break;
            };
            if let Ok(beacon) = Candidate::from_receive(
                &frame,
                self.radio.channel(),
                self.radio.local().ok_or(Error::State)?,
            ) {
                if beacon.bssid() == self.plan.candidate().bssid()
                    && beacon.ssid() == self.plan.candidate().ssid()
                {
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
            if self.data_frame(&frame, now, &mut *nonce)? {
                return Ok(());
            }
        }
        Ok(())
    }
    fn open_receive(&self, frame: &Mpdu) -> Option<Vec<u8>> {
        let b = &frame.bytes;
        let own = self.radio.local()?;
        if frame.decrypted
            || frame.ht
            || frame.bandwidth40
            || frame.rate > 11
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
        self.received.clear();
        self.pmk = None;
        if let Some(security) = &mut self.security {
            security.fail();
        }
        let mut attempt = self.attempt();
        let result = async {
            // The media command reports local station state. It does not
            // reuse/cancel the independent native bulk receipt.
            self.radio
                .association(0, false)
                .await
                .map_err(Error::Radio)?;
            self.radio.stop().await.map_err(Error::Radio)
        }
        .await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.pending = None;
                self.batch = None;
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
        if !self.controlled_port_open() || self.pending.is_some() {
            return Err(Error::State);
        }
        let native = if let Some(security) = &mut self.security {
            match security.transmit_ethernet(frame) {
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
            let mut h = vec![8, 1, 0, 0];
            h.extend_from_slice(&self.plan.candidate().bssid());
            h.extend_from_slice(&own);
            h.extend_from_slice(&frame[..6]);
            h.extend_from_slice(&(self.sequence << 4).to_le_bytes());
            self.sequence = (self.sequence + 1) & 4095;
            h.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
            h.extend_from_slice(&frame[12..]);
            h
        };
        if let Err(error) = self.radio.submit_native_data(&native) {
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
fn ethernet(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 24
        || !matches!(frame[0], 8 | 0x88)
        || frame[1] & 0xc7 != 2
        || frame[22] & 15 != 0
    {
        return None;
    }
    let offset = if frame[0] == 0x88 {
        if frame.get(24)? & 0x80 != 0 {
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
