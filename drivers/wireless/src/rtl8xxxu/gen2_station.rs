// SPDX-License-Identifier: GPL-2.0-or-later
//! One station transaction over the gen2 radio, shared by RTL8192EU
//! and RTL8723BU: legacy, optional WMM and, against a WMM HT AP when the
//! signed record admits MCS, optional HT20 (`Radio::ht_local`) with host
//! Block Ack sessions (`ba_sessions`). Against a 40 MHz BSS, when the
//! signed record and domain grant the wide channel, the station offers
//! HT40 (`Radio::ht40_local`), programs it with `Radio::widen` on a
//! Forty negotiation, and admits 40 MHz RX under that grant. The join plan, the shared RSNA/software-CCMP
//! supplicant and the Ethernet conversion are the RTL8188EU station's
//! (`station_runtime`); rate control is the gen2 firmware's (`ra_connect`
//! at association, `rtl8xxxu_ra_iter` every 2 s, C2H RA reports), and the
//! RTL8723BU BT-coexistence policy sees `rtl8xxxu_is_assoc` from here.
use super::{
    ba_sessions::{Sessions, Work},
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
    /// Driver-owned BA action (ADDBA Request/Response, DELBA).
    Control,
}
/// One captured MPDU with the controlled-port state at capture.
struct Captured {
    frame: Mpdu,
    admitted: bool,
    /// Already released by a recipient BA reorder buffer.
    ordered: bool,
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
/// Bound on queued BA action frames.
const CONTROLS: usize = 8;
const BATCH: usize = 256;

/// Single-TID BlockAckReq parse (gen2 F9): a 20-byte control frame
/// (FC + Duration + RA + TA + BAR Control + Starting Sequence
/// Control, FCS stripped by the hardware) from the bound peer to this
/// station, with the Multi-TID bit clear and Fragment Number zero.
/// Returns (TID, SSN) or `None` for a non-BAR frame, a malformed BAR,
/// or a multi-TID BAR (consumed without advance). Pure; pinned by
/// `gen2_station_tests`.
pub(super) fn bar_requests(frame: &Mpdu, own: [u8; 6], peer: [u8; 6]) -> Option<(u8, u16)> {
    let b = &frame.bytes;
    if b.len() != 20 || b[0] != 0x84 {
        return None;
    }
    let control = u16::from_le_bytes([b[16], b[17]]);
    let ssn_raw = u16::from_le_bytes([b[18], b[19]]);
    if b[4..10] != own || b[10..16] != peer || control & 0x0002 != 0 || ssn_raw & 0x000f != 0 {
        return None;
    }
    let tid = (control >> 12) as u8;
    if tid >= 8 {
        return None;
    }
    Some((tid, ssn_raw >> 4))
}

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

/// A plaintext Ethernet frame as a ToDS QoS DATA MPDU (TID, normal ACK).
pub(super) fn open_qos_data(
    frame: &[u8],
    own: [u8; 6],
    bssid: [u8; 6],
    sequence: u16,
    tid: u8,
) -> Option<Vec<u8>> {
    if tid > 7 {
        return None;
    }
    let mut native = open_data(frame, own, bssid, sequence)?;
    native[0] = 0x88;
    drop(native.splice(24..24, [tid, 0]));
    Some(native)
}

pub struct Station<C: ControlIo, B: packet_transport::Io> {
    radio: Radio<C, B>,
    plan: Join,
    mode: SecurityMode,
    phase: Phase,
    pmk: Option<Zeroizing<[u8; 32]>>,
    security: Option<Security>,
    pending: Option<Pending>,
    batch: VecDeque<Captured>,
    received: VecDeque<Vec<u8>>,
    delivered_reply: Option<usize>,
    deadline: u64,
    last_now: u64,
    last_peer: u64,
    sequence: u16,
    /// Associated-scan capture of home-channel BSS observations
    /// `(candidate, seen, receive generation)`, bounded like the cache.
    observed: Option<Vec<(Candidate, u64, u64)>>,
    /// EDCA rows last programmed through `configure_edca` (WMM peer).
    edca: Option<narf_wireless::wmm::Parameters>,
    /// A bound-AP beacon's changed WMM Parameter Set awaiting `conf_tx`.
    edca_pending: Option<narf_wireless::wmm::Parameters>,
    /// Open-station per-TID QoS DATA sequence spaces.
    qos_sequence: [u16; 8],
    /// Recipient/originator BA sessions (HT association only).
    ba: Sessions<Captured>,
    controls: VecDeque<Vec<u8>>,
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
        mut radio: Radio<C, B>,
        candidate: Candidate,
        ssid: &[u8],
        mode: SecurityMode,
        pmk: Option<Zeroizing<[u8; 32]>>,
        wide: Option<gen2_radio::Grant>,
    ) -> Result<Self, Error> {
        if candidate.channel() != radio.channel() || mode.is_wpa2() != pmk.is_some() {
            return Err(Error::Profile);
        }
        radio.offer_wide(wide).map_err(Error::Radio)?;
        // A WMM AP selects the optional QoS station: the join plan appends
        // the Information IE (no U-APSD) and requires valid response rows.
        // mac80211 `ieee80211_determine_chan_mode` disables HT without WMM;
        // with WMM the signed record's HT capability is offered (HT40 when
        // a wide grant is held, else HT20; a non-HT AP still negotiates
        // the legacy/QoS station).
        let wmm = narf_wireless::wmm::Parameters::parse(candidate.information_elements())
            .ok()
            .flatten()
            .is_some();
        let phy = if wmm { radio.ht_local() } else { None };
        let plan = Join::prepare_with_phy(candidate, radio.local(), ssid, mode, phy)
            .map_err(Error::Management)?;
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
            observed: None,
            edca: None,
            edca_pending: None,
            qos_sequence: [0; 8],
            ba: Sessions::default(),
            controls: VecDeque::new(),
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
        self.ba.retire();
        self.controls.clear();
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
    /// `rtl8xxxu_watchdog_callback` for this station's radio: the RA
    /// iteration once per period while associated (a no-op otherwise).
    /// Failure is terminal, as for `step`.
    pub async fn watchdog(&mut self, now: u64) -> Result<(), Error> {
        if !matches!(self.phase(), Phase::FourWay | Phase::Open) {
            return Ok(());
        }
        let result = self.radio.ra_watchdog(now).await.map_err(Error::Radio);
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
        if self.radio.maintenance_pending() {
            self.radio.maintain().await.map_err(Error::Radio)?;
        }
        if let Some(p) = self.edca_pending.take() {
            self.program_edca(p).await?;
        }
        if matches!(self.phase, Phase::FourWay | Phase::Open) {
            self.apply_tx_ba().await?;
        }
        if !self.progress(now)? {
            return Ok(());
        }
        self.service_ba(now)?;
        let own = self.radio.local();
        let local = self.radio.ht_local();
        for _ in 0..16 {
            let Some(captured) = self.batch.pop_front() else {
                break;
            };
            let Some(Captured {
                frame, admitted, ..
            }) = self.reorder_gate(captured, now)
            else {
                continue;
            };
            if let Ok(beacon) =
                Candidate::from_receive_with_phy(&frame, self.radio.channel(), own, local.as_ref())
            {
                if let Some(observed) = &mut self.observed {
                    let generation = self.radio.generation();
                    observed.retain(|(old, _, _)| old.bssid() != beacon.bssid());
                    if observed.len() < 32 {
                        observed.push((beacon.clone(), now, generation));
                    }
                }
                if beacon.bssid() == self.peer() && beacon.ssid() == self.plan.candidate().ssid() {
                    self.last_peer = now;
                    self.observe_wmm(beacon.information_elements())?;
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
            if !matches!(self.phase, Phase::FourWay | Phase::Open) {
                continue;
            }
            if self.control_frame(&frame, admitted, now)? {
                continue;
            }
            if self.bar_frame(&frame, admitted, now)? {
                continue;
            }
            if self.data_frame(&frame, admitted, now, &mut *nonce)? {
                return Ok(());
            }
        }
        Ok(())
    }
    /// Activate the offered 40 MHz channel when the negotiated geometry
    /// is Forty, or clear the offer when it is Twenty. A Forty geometry
    /// without a matching wide grant (same primary, secondary on the
    /// offered side), or a widen failure, fails the association rather
    /// than silently falling back to 20 MHz. `rejoin` reuses this: the
    /// retained wide grant survives `leave`/`stop` (which clear only the
    /// activation), so a Forty rejoin re-programs the wide channel.
    async fn widen_if_forty(&mut self) -> Result<(), Error> {
        let Some(geometry) = self.plan.negotiated_geometry().map_err(Error::Management)? else {
            self.radio.offer_wide(None).map_err(Error::Radio)?;
            return Ok(());
        };
        let primary = self.radio.channel();
        let wide_ok = match self.radio.wide_width() {
            Some(super::rtl8192e_radio::Width::Ht40Above) => {
                geometry.primary() == primary && geometry.secondary() == primary.saturating_add(4)
            }
            Some(super::rtl8192e_radio::Width::Ht40Below) => {
                geometry.primary() == primary && geometry.secondary() == primary.saturating_sub(4)
            }
            _ => false,
        };
        if !wide_ok {
            return Err(Error::Profile);
        }
        self.radio.widen().await.map_err(Error::Radio)
    }
    /// `BSS_CHANGED_ASSOC`: firmware RA over the negotiated legacy rates
    /// within the signed admitted mask, then the RSNA owner or the open port.
    async fn associated(&mut self, aid: u16, now: u64) -> Result<(), Error> {
        // mac80211 `ieee80211_assoc_success`: `ieee80211_sta_wmm_params`
        // (`drv_conf_tx` per AC) precedes `BSS_CHANGED_ASSOC`.
        if let Some(p) = self.plan.wmm() {
            self.program_edca(p).await?;
        }
        self.widen_if_forty().await?;
        self.radio
            .associate(aid, self.ra_peer(), now)
            .await
            .map_err(Error::Radio)?;
        self.sync_ba();
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
    /// `rtl8xxxu_conf_tx` for all four ACs through the radio's checked
    /// EDCA/ACM writes; host classification then follows the new rows.
    async fn program_edca(&mut self, p: narf_wireless::wmm::Parameters) -> Result<(), Error> {
        let short_slot = self.plan.candidate().capability() & 0x400 != 0;
        self.radio
            .configure_edca(p, short_slot, self.plan.ht_selected())
            .await
            .map_err(Error::Radio)?;
        self.edca = Some(p);
        Ok(())
    }
    /// mac80211 `ieee80211_sta_wmm_params`: a bound-AP beacon whose WMM
    /// Parameter Set Count differs from the installed rows carries new rows
    /// (an unchanged count is ignored even if the bytes differ). Losing WMM
    /// after a WMM association, or rows this profile cannot program, is
    /// terminal before any EP0 write.
    fn observe_wmm(&mut self, information_elements: &[u8]) -> Result<(), Error> {
        let Some(current) = self.edca_pending.or(self.edca) else {
            return Ok(());
        };
        let fresh = narf_wireless::wmm::Parameters::parse(information_elements)
            .ok()
            .flatten()
            .ok_or(Error::PeerLost)?;
        if fresh.parameter_set_count == current.parameter_set_count {
            return Ok(());
        }
        super::wmm_runtime::words_profile(
            fresh,
            self.plan.candidate().capability() & 0x400 != 0,
            self.plan.ht_selected(),
        )
        .map_err(|_| Error::Profile)?;
        self.edca_pending = Some(fresh);
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
                self.batch.extend(frames.into_iter().map(|frame| Captured {
                    frame,
                    admitted,
                    ordered: false,
                }));
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
                    for captured in self.batch.iter_mut() {
                        captured.admitted = false;
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
        if self.pending.is_none() && self.delivered_reply.is_none() && self.controlled_port_open() {
            if let Some(body) = self.controls.pop_front() {
                let frame = self.action_frame(&body)?;
                self.radio.submit_management(&frame).map_err(Error::Radio)?;
                self.pending = Some(Pending {
                    kind: Tx::Control,
                    deadline: now.saturating_add(TX_MS),
                });
            }
        }
        Ok(self.pending.is_none() && self.delivered_reply.is_none())
    }
    /// `rtl8xxxu_refresh_rate_mask` peer inputs: the negotiated
    /// `supp_rates[0]` and, for an HT association, `ht_cap.mcs.rx_mask[0..2]`
    /// (peer RX MCS within the signed TX selection) and SGI_20.
    fn ra_peer(&self) -> rtl8192e_ra::Peer {
        let (legacy, _, _) = self.plan.rate_mask_inputs();
        match self.plan.ht_peer() {
            Some((mcs, sgi)) => rtl8192e_ra::Peer {
                legacy: legacy & 0xfff,
                mcs,
                ht: true,
                sgi,
            },
            None => legacy_peer(legacy),
        }
    }
    /// The peer density and operational originator TIDs for txdesc40, and
    /// the recipient-session TIDs for A-MPDU RX admission.
    fn sync_ba(&mut self) {
        let tx = self
            .plan
            .peer_ampdu()
            .map(|(_, density)| (density, self.ba.operational()));
        self.radio.set_ba(tx, self.ba.rx_tids());
    }
    /// The BA action MPDU: peer-bound, SN from the shared non-QoS space.
    fn action_frame(&mut self, body: &[u8]) -> Result<Vec<u8>, Error> {
        let sequence = match &mut self.security {
            Some(security) => security
                .reserve_plain_control_sequence()
                .map_err(Error::Security)?,
            None => {
                let sequence = self.sequence;
                self.sequence = (sequence + 1) & 4095;
                sequence
            }
        };
        let (own, peer) = (self.radio.local(), self.peer());
        let mut frame = vec![0xd0, 0, 0, 0];
        frame.extend_from_slice(&peer);
        frame.extend_from_slice(&own);
        frame.extend_from_slice(&peer);
        frame.extend_from_slice(&(sequence << 4).to_le_bytes());
        frame.extend_from_slice(body);
        Ok(frame)
    }
    /// mac80211 `ieee80211_rx_reorder_ampdu`: unicast QoS DATA from the bound
    /// peer on a TID with a recipient session is ordered before CCMP/PN and
    /// delivery; released captures re-enter the batch head in sequence order
    /// with their capture-time admission. An A-MPDU member (`ba`) outside a
    /// session is dropped.
    fn reorder_gate(&mut self, mut captured: Captured, now: u64) -> Option<Captured> {
        if captured.ordered || !self.plan.ht_selected() {
            return Some(captured);
        }
        let b = &captured.frame.bytes;
        if b.len() < 26
            || b[0] != 0x88
            || b[1] & 3 != 2
            || b[4..10] != self.radio.local()
            || b[10..16] != self.peer()
            || b[22] & 15 != 0
        {
            return (!captured.frame.ba).then_some(captured);
        }
        let tid = b[24] & 15;
        let sequence = u16::from_le_bytes([b[22], b[23]]) >> 4;
        captured.ordered = true;
        match self.ba.reorder(tid, sequence, now, captured) {
            Ok(released) => {
                for item in released.into_iter().rev() {
                    self.batch.push_front(item);
                }
                None
            }
            Err(captured) => (!captured.frame.ba).then_some(captured),
        }
    }
    /// BA session timers (`ba_sessions::Sessions::service`): reorder-hole
    /// releases re-enter the batch, recipient timeouts queue their DELBA.
    fn service_ba(&mut self, now: u64) -> Result<(), Error> {
        if !self.plan.ht_selected() || !matches!(self.phase, Phase::FourWay | Phase::Open) {
            return Ok(());
        }
        let (released, delba) = self.ba.service(now);
        for item in released.into_iter().rev() {
            self.batch.push_front(item);
        }
        for body in delba {
            if self.controls.len() >= CONTROLS {
                return Err(Error::State);
            }
            self.controls.push_back(body);
        }
        self.sync_ba();
        Ok(())
    }
    /// Peer-bound plaintext Block Ack action frames on an authorized HT
    /// association; every other Action frame is consumed unchanged.
    fn control_frame(&mut self, frame: &Mpdu, admitted: bool, now: u64) -> Result<bool, Error> {
        let b = &frame.bytes;
        if b.first() != Some(&0xd0) {
            return Ok(false);
        }
        let own = self.radio.local();
        if !admitted
            || !self.controlled_port_open()
            || !self.plan.ht_selected()
            || !gen2_radio::station_admitted(frame, false, false)
            || b.len() < 26
            || b[1] & 0xc7 != 0
            || b[4..10] != own
            || b[10..16] != self.peer()
            || b[16..22] != self.peer()
            || b[22] & 15 != 0
            || b[24] != 3
        {
            return Ok(true);
        }
        if self.controls.len() >= CONTROLS {
            return Err(Error::State);
        }
        if let Some(body) = self.ba.action(&b[24..], now) {
            self.controls.push_back(body);
        }
        self.sync_ba();
        Ok(true)
    }
    /// BlockAckReq gate (gen2 F9): a single-TID BAR from the bound peer
    /// on the station's own address advances the recipient reorder
    /// session (or earns one recipient DELBA for an unexpected TID);
    /// every other control frame is consumed without action, so a BA
    /// (which the descriptor layer admits) never reaches the DATA path
    /// as an ethernet frame. Multi-TID BARs are consumed but not
    /// advanced: the BlockAck bitmap layout is per-TID and the session
    /// advance is single-TID (a follow-up if APs send multi-TID BARs).
    /// Returns true when the frame is consumed (all control frames).
    fn bar_frame(&mut self, frame: &Mpdu, admitted: bool, now: u64) -> Result<bool, Error> {
        let Some((tid, ssn)) = bar_requests(frame, self.radio.local(), self.peer()) else {
            // Not a BAR: control frames are still consumed (never DATA),
            // management/data frames fall through to the DATA path.
            return Ok(frame.bytes.first().is_some_and(|f| f & 0x0c == 0x04));
        };
        if !admitted || !self.controlled_port_open() || !self.plan.ht_selected() {
            return Ok(true);
        }
        let (released, delba) = self.ba.bar(tid, ssn, now);
        for item in released.into_iter().rev() {
            self.batch.push_front(item);
        }
        for body in delba {
            if self.controls.len() >= CONTROLS {
                return Err(Error::State);
            }
            self.controls.push_back(body);
        }
        self.sync_ba();
        Ok(true)
    }
    /// `rtl8xxxu_ampdu_action` TX_START/TX_STOP EP0 work, then the ADDBA
    /// Request (SSN = the TID's next QoS sequence) or the initiator DELBA.
    async fn apply_tx_ba(&mut self) -> Result<(), Error> {
        let now = self.last_now;
        while let Some(work) = self.ba.work() {
            if self.controls.len() >= CONTROLS {
                return Err(Error::State);
            }
            let body = match work {
                Work::Start(tid) => {
                    let (factor, density) = self.plan.peer_ampdu().ok_or(Error::State)?;
                    self.radio
                        .configure_ampdu(factor, density)
                        .await
                        .map_err(Error::Radio)?;
                    let ssn = match &self.security {
                        Some(security) => {
                            security.next_qos_sequence(tid).map_err(Error::Security)?
                        }
                        None => self.qos_sequence[usize::from(tid)],
                    };
                    self.ba.requested(tid, ssn, now)
                }
                Work::Stop(tid) => {
                    self.radio
                        .configure_ampdu(0, 0)
                        .await
                        .map_err(Error::Radio)?;
                    self.ba.stopped(tid)
                }
            };
            if let Some(body) = body {
                self.controls.push_back(body);
            }
            self.sync_ba();
        }
        Ok(())
    }
    fn data_frame(
        &mut self,
        frame: &Mpdu,
        admitted: bool,
        now: u64,
        nonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<bool, Error> {
        let ht = self.plan.ht_selected();
        if !gen2_radio::station_admitted(frame, ht, self.radio.wide_active()) {
            return Ok(false);
        }
        let b = &frame.bytes;
        let own = self.radio.local();
        if b.first() == Some(&0x88) && b.get(24).is_some_and(|q| q & 0x80 != 0) {
            // A standalone A-MSDU (HT only): whole-aggregate authentication
            // and deaggregation; a bad MIC or subframe publishes nothing.
            if !admitted || !self.controlled_port_open() || !ht || self.received.len() >= RX_QUEUE {
                return Ok(false);
            }
            let frames = if let Some(security) = &mut self.security {
                security.receive_amsdu(frame).map_err(Error::Security)?
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
                if self.received.len() + frames.len() <= RX_QUEUE {
                    self.received.extend(frames);
                    self.last_peer = now;
                }
            }
            return Ok(false);
        }
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
        // `cfg80211_classify8021d` + `ieee80211_downgrade_queue` over the
        // installed AP rows choose the TID; the codec maps its AC to the
        // txdesc40 queue and the queue-map bulk-OUT pipe.
        let tid = self.edca.map(|p| crate::rtlwifi::wmm::priority(frame, &p));
        // `rtl8xxxu_tx`: the first QoS DATA on an idle TID to an HT peer
        // starts its originator session (the frame itself goes unaggregated).
        if let (Some(tid), true) = (tid, self.plan.ht_selected()) {
            self.ba.note_tx(tid, now);
        }
        let native = if let Some(security) = &mut self.security {
            match match tid {
                Some(tid) => security.transmit_ethernet_qos(frame, tid),
                None => security.transmit_ethernet(frame),
            } {
                Ok(frame) => frame,
                Err(error) => {
                    if !security.port_open() {
                        self.fail();
                    }
                    return Err(Error::Security(error));
                }
            }
        } else if let Some(tid) = tid {
            let (own, peer) = (self.radio.local(), self.peer());
            let counter = &mut self.qos_sequence[usize::from(tid)];
            let native = open_qos_data(frame, own, peer, *counter, tid).ok_or(Error::Profile)?;
            *counter = (*counter + 1) & 4095;
            native
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
        self.ba.retire();
        self.controls.clear();
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
    /// mac80211 `ieee80211_scan_state_decision`/`offchannel` admission: an
    /// authorized station with no outstanding TX, EAPOL reply or RSNA
    /// handshake (a rekey refuses the scan).
    pub(super) fn scan_admissible(&self) -> bool {
        self.transmit_ready()
            && self.delivered_reply.is_none()
            && !self
                .security
                .as_ref()
                .is_some_and(Security::handshake_active)
    }
    /// No host TX or EAPOL reply receipt outstanding.
    pub(super) fn quiescent(&self) -> bool {
        self.pending.is_none() && self.delivered_reply.is_none()
    }
    pub(super) fn radio(&self) -> &Radio<C, B> {
        &self.radio
    }
    /// The away/probe radio during an associated scan visit (after `leave`,
    /// before `rejoin`): only the scan candidate parser sees its MPDUs.
    pub(super) fn radio_mut(&mut self) -> &mut Radio<C, B> {
        &mut self.radio
    }
    /// Start/stop capturing home-channel observations; stopping returns them.
    pub(super) fn observe(&mut self, on: bool) -> Vec<(Candidate, u64, u64)> {
        let old = self.observed.take().unwrap_or_default();
        if on {
            self.observed = Some(Vec::new());
        }
        old
    }
    /// One SN from the shared non-QoS DATA/EAPOL space (Open: the station
    /// counter; WPA2: `reserve_plain_control_sequence`), consuming no PN.
    pub(super) fn reserve_sequence(&mut self) -> Result<u16, Error> {
        if !self.scan_admissible() {
            return Err(Error::State);
        }
        if let Some(security) = &mut self.security {
            security
                .reserve_plain_control_sequence()
                .map_err(Error::Security)
        } else {
            let sequence = self.sequence;
            self.sequence = (sequence + 1) & 4095;
            Ok(sequence)
        }
    }
    /// mac80211 `ieee80211_send_nullfunc` around an off-channel visit: the
    /// plaintext ToDS non-QoS Null with PM1 (`asleep`) or PM0, best effort
    /// (rtl8xxxu sets no `REPORTS_TX_ACK_STATUS`); the USB receipt is the
    /// only completion tracked.
    pub(super) fn send_null(&mut self, asleep: bool, now: u64) -> Result<(), Error> {
        // `ieee80211_nullfunc_get`: QoS Null TID7/SN0 for a WMM peer (no
        // DATA sequence consumed), otherwise the non-QoS Null.
        let qos = self.edca.is_some();
        let sequence = if qos {
            if !self.scan_admissible() {
                return Err(Error::State);
            }
            0
        } else {
            self.reserve_sequence()?
        };
        let null =
            super::ps_null::Prepared::new(self.radio.local(), self.peer(), asleep, qos, sequence)
                .map_err(|_| Error::State)?;
        if let Err(error) = self.radio.submit_null(&null) {
            self.fail();
            return Err(Error::Radio(error));
        }
        self.pending = Some(Pending {
            kind: Tx::Data,
            deadline: now.saturating_add(TX_MS),
        });
        Ok(())
    }
    /// Leave the home channel: `ra_disconnect_8192e` + `rtl8xxxu_stop` on a
    /// quiescent station. The join plan, keys, PN/replay and sequence owners
    /// stay with this station; `rejoin` restores the radio side.
    pub(super) async fn leave(&mut self) -> Result<(), Error> {
        if self.phase() != Phase::Open || !self.quiescent() {
            return Err(Error::State);
        }
        self.batch.clear();
        if let Err(error) = self.radio.stop().await {
            self.fail();
            return Err(Error::Radio(error));
        }
        Ok(())
    }
    /// Return to `home` through a cold restart, then the port-0 station,
    /// BSSID/slot and `ra_connect_8192e` programming for the same AID and
    /// negotiated rates. Monitoring restarts as `ieee80211_offchannel_return`
    /// resets it; no BSS observation is refreshed.
    pub(super) async fn rejoin(&mut self, home: gen2_radio::Grant, now: u64) -> Result<(), Error> {
        let management_runtime::Phase::Associated { aid } = self.plan.phase() else {
            return Err(Error::State);
        };
        if self.phase() != Phase::Open || self.radio.bound() {
            return Err(Error::State);
        }
        let result = async {
            self.radio.retune(home).await.map_err(Error::Radio)?;
            let candidate = self.plan.candidate();
            let (bssid, short_slot) = (candidate.bssid(), candidate.capability() & 0x400 != 0);
            self.radio
                .prepare_station(bssid, short_slot)
                .await
                .map_err(Error::Radio)?;
            if let Some(p) = self.edca {
                self.radio
                    .configure_edca(p, short_slot, self.plan.ht_selected())
                    .await
                    .map_err(Error::Radio)?;
            }
            self.widen_if_forty().await?;
            self.radio
                .associate(aid, self.ra_peer(), now)
                .await
                .map_err(Error::Radio)?;
            self.sync_ba();
            // The cold restart reset REG_AGGLEN_LMT/REG_AMPDU_MIN_SPACE; a
            // started originator session keeps its TX_START limits.
            if self.ba.tx_started() {
                let (factor, density) = self.plan.peer_ampdu().ok_or(Error::State)?;
                self.radio
                    .configure_ampdu(factor, density)
                    .await
                    .map_err(Error::Radio)?;
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                self.batch.clear();
                self.last_now = self.last_now.max(now);
                self.last_peer = now;
                Ok(())
            }
            Err(error) => {
                self.fail();
                Err(error)
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
