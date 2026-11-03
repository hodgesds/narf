// SPDX-License-Identifier: GPL-2.0-or-later
//! One legacy 20 MHz station transaction over the gen2 radio, shared by
//! RTL8192EU and RTL8723BU. The join plan, the shared RSNA/software-CCMP
//! supplicant and the Ethernet conversion are the RTL8188EU station's
//! (`station_runtime`); rate control is the gen2 firmware's (`ra_connect`
//! at association, `rtl8xxxu_ra_iter` every 2 s, C2H RA reports), and the
//! RTL8723BU BT-coexistence policy sees `rtl8xxxu_is_assoc` from here.
use super::{
    firmware_transport::ControlIo,
    gen2_radio::{self, Radio},
    management_runtime::{self, Action, Candidate, Join, SecurityMode},
    packet_codec::Mpdu,
    packet_transport, rtl8192e_ra, security_runtime,
    security_runtime::Security,
    station_runtime::{ethernet, private_eapol},
};
use alloc::{collections::VecDeque, vec, vec::Vec};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    State,
    Timeout,
    PeerLost,
    Profile,
    Radio(gen2_radio::Error),
    Management(management_runtime::Error),
    Security(security_runtime::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    Authentication,
    Association,
    FourWay,
    Open,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tx {
    Management,
    Eapol,
    Data,
}
struct Pending {
    kind: Tx,
    deadline: u64,
}

/// Per-attempt management/handshake bound (as `station_runtime`).
const JOIN_MS: u64 = 5000;
const HANDSHAKE_MS: u64 = 10_000;
const TX_MS: u64 = 1000;
/// Beacon loss bound for the open station.
const PEER_LOSS_MS: u64 = 5000;
const RX_QUEUE: usize = 32;
const BATCH: usize = 256;

/// `rtl8xxxu_refresh_rate_mask` peer inputs for a legacy association:
/// the negotiated `supp_rates[0]`; no HT capability is advertised.
pub(super) fn legacy_peer(legacy: u16) -> rtl8192e_ra::Peer {
    rtl8192e_ra::Peer {
        legacy: legacy & 0xfff,
        mcs: [0, 0],
        ht: false,
        sgi: false,
    }
}

/// A plaintext Ethernet frame as a non-QoS ToDS DATA MPDU (open station).
pub(super) fn open_data(
    frame: &[u8],
    own: [u8; 6],
    bssid: [u8; 6],
    sequence: u16,
) -> Option<Vec<u8>> {
    if !(14..=1514).contains(&frame.len()) || frame[6..12] != own || frame[..6] == [0; 6] {
        return None;
    }
    let proto = u16::from_be_bytes([frame[12], frame[13]]);
    if proto < 0x600 || matches!(proto, 0x888e | 0x80f3 | 0x8137) {
        return None;
    }
    let mut h = vec![8, 1, 0, 0];
    h.extend_from_slice(&bssid);
    h.extend_from_slice(&own);
    h.extend_from_slice(&frame[..6]);
    h.extend_from_slice(&(sequence << 4).to_le_bytes());
    h.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    h.extend_from_slice(&frame[12..]);
    Some(h)
}

pub struct Station<C: ControlIo, B: packet_transport::Io> {
    radio: Radio<C, B>,
    plan: Join,
    mode: SecurityMode,
    phase: Phase,
    pmk: Option<Zeroizing<[u8; 32]>>,
    security: Option<Security>,
    pending: Option<Pending>,
    batch: VecDeque<(Mpdu, bool)>,
    received: VecDeque<Vec<u8>>,
    delivered_reply: Option<usize>,
    deadline: u64,
    last_now: u64,
    last_peer: u64,
    sequence: u16,
}
impl<C: ControlIo, B: packet_transport::Io> core::fmt::Debug for Station<C, B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8xxxuGen2Station")
            .field("phase", &self.phase())
            .field("radio", &self.radio)
            .finish_non_exhaustive()
    }
}

impl<C: ControlIo, B: packet_transport::Io> Station<C, B> {
    pub fn new(
        radio: Radio<C, B>,
        candidate: Candidate,
        ssid: &[u8],
        mode: SecurityMode,
        pmk: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<Self, Error> {
        if candidate.channel() != radio.channel() || mode.is_wpa2() != pmk.is_some() {
            return Err(Error::Profile);
        }
        let plan = Join::prepare(candidate, radio.local(), ssid, mode)
            .map_err(Error::Management)?
            .without_wmm();
        Ok(Self {
            radio,
            plan,
            mode,
            phase: Phase::Prepared,
            pmk,
            security: None,
            pending: None,
            batch: VecDeque::new(),
            received: VecDeque::new(),
            delivered_reply: None,
            deadline: 0,
            last_now: 0,
            last_peer: 0,
            sequence: 2,
        })
    }
    pub fn append_sme_ies(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.phase != Phase::Prepared {
            return Err(Error::State);
        }
        self.plan.append_sme_ies(bytes).map_err(Error::Management)
    }
    pub fn peer(&self) -> [u8; 6] {
        self.plan.candidate().bssid()
    }
    pub fn local(&self) -> [u8; 6] {
        self.radio.local()
    }
    pub fn phase(&self) -> Phase {
        if self.radio.phase() == gen2_radio::Phase::Failed {
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
    pub fn transmit_ready(&self) -> bool {
        self.controlled_port_open() && self.pending.is_none()
    }
    /// The firmware RA state (`priv->ra_info`) while associated.
    pub(super) fn rate(&self) -> Option<&rtl8192e_ra::Ra> {
        self.radio.ra()
    }
    pub(super) fn coex(&self) -> Option<&super::btcoex::Coex> {
        self.radio.coex()
    }
    fn fail(&mut self) {
        self.batch.clear();
        self.received.clear();
        self.pending = None;
        self.plan.cancel();
        self.phase = Phase::Failed;
        self.pmk = None;
        if let Some(s) = &mut self.security {
            s.fail();
        }
        self.radio.fail_terminal();
    }
    /// `rtl8xxxu_start` (if the radio is not yet receiving), the port-0
    /// station/BSSID programming, then the Authentication request.
    pub async fn begin(&mut self, now: u64) -> Result<(), Error> {
        if self.phase() != Phase::Prepared {
            return Err(Error::State);
        }
        let result = async {
            match self.radio.phase() {
                gen2_radio::Phase::Prepared => self.radio.start().await.map_err(Error::Radio)?,
                gen2_radio::Phase::Receiving => (),
                _ => return Err(Error::State),
            }
            let candidate = self.plan.candidate();
            let (bssid, short_slot) = (candidate.bssid(), candidate.capability() & 0x400 != 0);
            self.radio
                .prepare_station(bssid, short_slot)
                .await
                .map_err(Error::Radio)?;
            let Action::Transmit(frame) = self.plan.begin().map_err(Error::Management)? else {
                return Err(Error::State);
            };
            self.radio.submit_management(&frame).map_err(Error::Radio)?;
            self.pending = Some(Pending {
                kind: Tx::Management,
                deadline: now.saturating_add(TX_MS),
            });
            self.phase = Phase::Authentication;
            self.deadline = now.saturating_add(JOIN_MS);
            self.last_now = now;
            self.last_peer = now;
            Ok(())
        }
        .await;
        if result.is_err() {
            self.fail();
        }
        result
    }
    /// Bounded self-driven service (management, RSNA, DATA delivery). The
    /// worker supplies monotonic milliseconds and fresh CSPRNG SNonce bytes.
    pub async fn step(
        &mut self,
        now: u64,
        mut nonce: impl FnMut() -> Option<[u8; 32]> + Send,
    ) -> Result<(), Error> {
        if !matches!(
            self.phase(),
            Phase::Authentication | Phase::Association | Phase::FourWay | Phase::Open
        ) {
            return Err(Error::State);
        }
        let result = self.step_inner(now, &mut nonce).await;
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
        if self.radio.maintenance_pending(now) {
            self.radio.maintain(now).await.map_err(Error::Radio)?;
        }
        if !self.progress(now)? {
            return Ok(());
        }
        let own = self.radio.local();
        for _ in 0..16 {
            let Some((frame, admitted)) = self.batch.pop_front() else {
                break;
            };
            if let Ok(beacon) = Candidate::from_receive(&frame, self.radio.channel(), own) {
                if beacon.bssid() == self.peer() && beacon.ssid() == self.plan.candidate().ssid() {
                    self.last_peer = now;
                }
                continue;
            }
            if let Some(action) = self.plan.receive(&frame).map_err(Error::Management)? {
                if matches!(self.phase, Phase::FourWay | Phase::Open) {
                    return Err(Error::State);
                }
                self.last_peer = now;
                match action {
                    Action::Transmit(frame) => {
                        self.radio.submit_management(&frame).map_err(Error::Radio)?;
                        self.pending = Some(Pending {
                            kind: Tx::Management,
                            deadline: now.saturating_add(TX_MS),
                        });
                        self.phase = Phase::Association;
                        self.deadline = now.saturating_add(JOIN_MS);
                        return Ok(());
                    }
                    Action::Associated { aid } => {
                        self.associated(aid, now).await?;
                        return Ok(());
                    }
                }
            }
            if matches!(self.phase, Phase::FourWay | Phase::Open)
                && self.data_frame(&frame, admitted, now, &mut *nonce)?
            {
                return Ok(());
            }
        }
        Ok(())
    }
    /// `BSS_CHANGED_ASSOC`: firmware RA over the negotiated legacy rates
    /// within the signed admitted mask, then the RSNA owner or the open port.
    async fn associated(&mut self, aid: u16, now: u64) -> Result<(), Error> {
        let (legacy, _, _) = self.plan.rate_mask_inputs();
        self.radio
            .associate(aid, legacy_peer(legacy), now)
            .await
            .map_err(Error::Radio)?;
        if self.mode.is_wpa2() {
            let own = self.radio.local();
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
            self.deadline = now.saturating_add(HANDSHAKE_MS);
        } else {
            self.phase = Phase::Open;
            self.last_peer = now;
        }
        Ok(())
    }
    /// Deadlines, TX completion, one RX transfer into the batch and
    /// EAPOL-reply retirement. Captured frames keep the port state at
    /// capture; they are processed only with no TX or reply outstanding.
    fn progress(&mut self, now: u64) -> Result<bool, Error> {
        if now < self.last_now {
            return Err(Error::State);
        }
        self.last_now = now;
        if self.phase != Phase::Open && now >= self.deadline {
            return Err(Error::Timeout);
        }
        if self.phase == Phase::Open && now.saturating_sub(self.last_peer) >= PEER_LOSS_MS {
            return Err(Error::PeerLost);
        }
        if let Some(pending) = &self.pending {
            if let Some(delivered) = self.radio.poll_delivery().map_err(Error::Radio)? {
                if pending.kind == Tx::Eapol {
                    self.delivered_reply = Some(delivered.native_bytes);
                }
                self.pending = None;
            } else if now >= pending.deadline {
                return Err(Error::Timeout);
            }
        }
        let admitted = self.controlled_port_open();
        match self.radio.poll().map_err(Error::Radio)? {
            Some(frames) => {
                if self.batch.len() + frames.len() > BATCH {
                    return Err(Error::State);
                }
                self.batch.extend(frames.into_iter().map(|f| (f, admitted)));
            }
            None => {
                if let Some(bytes) = self.delivered_reply.take() {
                    self.security
                        .as_mut()
                        .ok_or(Error::State)?
                        .reply_delivered(bytes)
                        .map_err(Error::Security)?;
                    // Frames captured before the receipt never inherit DATA
                    // admission; only the private EAPOL original passes.
                    for (_, admitted) in self.batch.iter_mut() {
                        *admitted = false;
                    }
                    if self.phase == Phase::FourWay
                        && self.security.as_ref().is_some_and(Security::port_open)
                    {
                        self.phase = Phase::Open;
                        self.last_peer = now;
                    }
                }
            }
        }
        Ok(self.pending.is_none() && self.delivered_reply.is_none())
    }
    fn data_frame(
        &mut self,
        frame: &Mpdu,
        admitted: bool,
        now: u64,
        nonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<bool, Error> {
        if !frame.admitted(false) {
            return Ok(false);
        }
        let b = &frame.bytes;
        let own = self.radio.local();
        if !admitted && !private_eapol(b, own, self.peer()) {
            return Ok(false);
        }
        if let Some(security) = &mut self.security {
            match security
                .receive_with_nonce(frame, nonce)
                .map_err(Error::Security)?
            {
                security_runtime::Rx::Ignored => (),
                security_runtime::Rx::ReplyReady => {
                    let reply = security.pending_frame().ok_or(Error::State)?.to_vec();
                    self.radio.submit_data(&reply).map_err(Error::Radio)?;
                    self.pending = Some(Pending {
                        kind: Tx::Eapol,
                        deadline: now.saturating_add(TX_MS),
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
                        if self.received.len() < RX_QUEUE {
                            self.received.push_back(ethernet);
                        }
                    }
                }
            }
        } else if let Some(ethernet) = self.open_receive(frame) {
            self.last_peer = now;
            if self.received.len() < RX_QUEUE {
                self.received.push_back(ethernet);
            }
        }
        Ok(false)
    }
    fn open_receive(&self, frame: &Mpdu) -> Option<Vec<u8>> {
        let b = &frame.bytes;
        let own = self.radio.local();
        if frame.decrypted
            || b.len() < 24
            || b[10..16] != self.peer()
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
    /// Backpressure precedes encryption/PN consumption; EAPOL is never
    /// admitted from an Ethernet client.
    pub fn send_ethernet(&mut self, frame: &[u8], now: u64) -> Result<(), Error> {
        if !self.transmit_ready() {
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
            let native = open_data(frame, self.radio.local(), self.peer(), self.sequence)
                .ok_or(Error::Profile)?;
            self.sequence = (self.sequence + 1) & 4095;
            native
        };
        if let Err(error) = self.radio.submit_data(&native) {
            self.fail();
            return Err(Error::Radio(error));
        }
        self.pending = Some(Pending {
            kind: Tx::Data,
            deadline: now.saturating_add(TX_MS),
        });
        Ok(())
    }
    /// Close host admission, then `ra_disconnect_8192e` + `rtl8xxxu_stop`.
    /// Key history dies with this station; `into_radio` returns the stopped
    /// radio for park and a fresh owner lifecycle.
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
        match self.radio.stop().await {
            Ok(()) => {
                self.pending = None;
                self.batch.clear();
                self.delivered_reply = None;
                self.plan.cancel();
                self.phase = Phase::Stopped;
                Ok(())
            }
            Err(error) => {
                self.fail();
                Err(Error::Radio(error))
            }
        }
    }
    /// Only a `Stopped` (or failed) station hands its radio back.
    pub(super) fn into_radio(self) -> Radio<C, B> {
        self.radio
    }
}

#[cfg(feature = "kernel-test")]
#[path = "gen2_station_tests.rs"]
mod tests;
