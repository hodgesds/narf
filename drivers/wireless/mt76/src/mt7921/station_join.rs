//! MT76 live station join and disassociate dispatch.
//! Channel/power authorization, MLME open authentication/association
//! request/response loops, and peer record installation.
use super::{
    scan::rx_on_channel, station::Command, Backend, Error, ScanBss, Session, Stage, State,
    TIMEOUT_MS,
};
use crate::mt7921::{
    association::{disconnect_record, JoinPlan, Security},
    cmd, packet_tx,
};
use alloc::{collections::VecDeque, vec, vec::Vec};
use narf_wireless::eapol::{EapolRx, EapolRxError, Gtk, KeyMgmt, RsnaParams, Supplicant};
use zeroize::{Zeroize, Zeroizing};

/// Association-owned RSNA state. Key bytes are never included in driver
/// diagnostics. Keeping the same supplicant across RX permits PTK/GTK rekeys
/// and preserves its key-reinstallation and EAPOL replay checks.
pub(super) struct StationSecurity {
    supplicant: Supplicant,
    pairwise: [u64; 17],
    group: [Option<[u64; 17]>; 4],
    pending: VecDeque<(Vec<u8>, bool)>,
}

impl core::fmt::Debug for StationSecurity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StationSecurity").finish_non_exhaustive()
    }
}

impl StationSecurity {
    pub(super) fn new(
        bss: &ScanBss,
        plan: &JoinPlan,
        own: [u8; 6],
        psk: [u8; 32],
    ) -> Result<Self, Error> {
        let body = plan.rsn_body().ok_or(Error::Bounds)?;
        let mut assoc_ie = vec![48, body.len() as u8];
        assoc_ie.extend_from_slice(&body);
        let mut ies = &bss.information_elements[..];
        let mut ap_rsn_ie = None;
        let mut ap_rsnxe = None;
        while !ies.is_empty() {
            let header = ies.get(..2).ok_or(Error::Bounds)?;
            let ie = ies.get(..2 + usize::from(header[1])).ok_or(Error::Bounds)?;
            if header[0] == 48 {
                ap_rsn_ie = Some(ie.to_vec());
            }
            if header[0] == 244 {
                if ap_rsnxe.is_some() || ie.len() < 3 || usize::from(ie[2] & 15) + 3 != ie.len() {
                    return Err(Error::Bounds);
                }
                ap_rsnxe = Some(ie.to_vec());
            }
            ies = &ies[ie.len()..];
        }
        Ok(Self {
            supplicant: Supplicant::new(bss.bssid, own, [0; 32]).with_rsna(RsnaParams {
                key_mgmt: KeyMgmt::Psk,
                pmk: psk.to_vec(),
                assoc_ie,
                ap_rsn_ie: ap_rsn_ie.ok_or(Error::Bounds)?,
                ap_rsnxe,
                pairwise_key_len: 16,
                group_key_len: 16,
                mgmt_group_key_len: None,
                pmf: false,
            }),
            pairwise: [0; 17],
            group: [None; 4],
            pending: VecDeque::new(),
        })
    }

    fn process(
        &mut self,
        pdu: &[u8],
        encrypted: bool,
        mut fill: impl FnMut(&mut [u8]) -> Result<(), Error>,
    ) -> Result<Option<EapolRx>, Error> {
        let mut failure = None;
        let result = self.supplicant.rx_eapol_with_nonce(pdu, encrypted, || {
            let mut fresh = Zeroizing::new([0; 32]);
            match fill(&mut fresh[..]) {
                Ok(()) => Some(*fresh),
                Err(error) => {
                    failure = Some(error);
                    None
                }
            }
        });
        match result {
            Ok(rx) => Ok(Some(rx)),
            Err(EapolRxError::Drop(_)) => Ok(None),
            Err(EapolRxError::NonceUnavailable) => {
                Err(failure.unwrap_or(Error::EntropyUnavailable))
            }
            Err(_) => Err(Error::MalformedEvent),
        }
    }

    pub(super) fn commit_group(&mut self, gtk: &Gtk) -> Result<(), Error> {
        if gtk.key_id > 3 || gtk.key.len() != 16 || gtk.rsc[6..] != [0, 0] {
            return Err(Error::MalformedEvent);
        }
        self.group[usize::from(gtk.key_id)] = Some([u64::from_le_bytes(gtk.rsc); 17]);
        self.supplicant.group_keys_installed(Some(&gtk.key), None);
        Ok(())
    }
}

impl Drop for StationSecurity {
    fn drop(&mut self) {
        // Supplicant owns the only PMK/PTK/GTK copies retained by this driver.
        if let Some(params) = &mut self.supplicant.rsna {
            params.pmk.zeroize();
        }
        for ptk in [&mut self.supplicant.ptk, &mut self.supplicant.tptk]
            .into_iter()
            .flatten()
        {
            ptk.kck.zeroize();
            ptk.kek.zeroize();
            ptk.tk.zeroize();
        }
        for key in [&mut self.supplicant.gtk, &mut self.supplicant.igtk]
            .into_iter()
            .flatten()
        {
            key.zeroize();
        }
    }
}

pub(crate) fn extract_eapol(frame: &[u8]) -> Option<&[u8]> {
    let header = frame.get(..24)?;
    let fc = u16::from_le_bytes([header[0], header[1]]);
    if !matches!(fc & 0xff, 0x08 | 0x88)
        || !matches!(fc & 0xc700, 0x0100 | 0x0200)
        || header[22] & 15 != 0
    {
        return None;
    }
    let snap_offset = if fc & 0x80 != 0 {
        if frame.get(24)? & 0x80 != 0 {
            return None;
        }
        26
    } else {
        24
    };
    if frame.get(snap_offset..snap_offset + 8)? != [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e] {
        return None;
    }
    let pdu = frame.get(snap_offset + 8..)?;
    let eapol = pdu.get(..4)?;
    if !(1..=3).contains(&eapol[0]) || eapol[1] != 3 {
        return None;
    }
    pdu.get(..4 + usize::from(u16::from_be_bytes([eapol[2], eapol[3]])))
}

/// An authenticator EAPOL PDU must come from the negotiated AP to this
/// station, in a validated native FromDS MPDU. Ethernet/descriptor fallbacks
/// cannot establish peer identity for the controlled port.
pub(super) fn peer_eapol(packet: &[u8], own: [u8; 6], peer: [u8; 6], channel: u8) -> Option<&[u8]> {
    let frame = rx_on_channel(packet, channel)?;
    let header = frame.get(..24)?;
    if header[1] & 3 != 2
        || header[4..10] != own
        || header[10..16] != peer
        || header[16..22] != peer
    {
        return None;
    }
    extract_eapol(frame)
}

pub(crate) fn wrap_eapol_frame(own: [u8; 6], peer: [u8; 6], eapol: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(24 + 8 + eapol.len());
    frame.extend_from_slice(&[0x08, 0x01]); // 802.11 Data to-DS
    frame.extend_from_slice(&[0x00, 0x00]); // duration
    frame.extend_from_slice(&peer); // Addr1: BSSID
    frame.extend_from_slice(&own); // Addr2: SA
    frame.extend_from_slice(&peer); // Addr3: DA
    frame.extend_from_slice(&[0x00, 0x00]); // seq ctrl
    frame.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]); // LLC/SNAP EAPOL
    frame.extend_from_slice(eapol);
    frame
}

/// Convert an unfragmented native station RX frame with RFC1042 LLC/SNAP.
/// The retained transport disables RX header translation. Rejected native
/// frames must never be reinterpreted as an already translated Ethernet frame.
pub fn to_ethernet(frame: &[u8]) -> Option<Vec<u8>> {
    let header = frame.get(..24)?;
    let fc = u16::from_le_bytes([header[0], header[1]]);
    if !matches!(fc & 0xff, 0x08 | 0x88)
        || fc & 0xc700 != 0x0200 // FromDS only; no fragments, protection or HT control.
        || header[22] & 15 != 0
    {
        return None;
    }
    let snap_offset = if fc & 0x80 != 0 {
        let qos = frame.get(24..26)?;
        if qos[0] & 0x80 != 0 {
            return None; // A-MSDU needs its own bounded deaggregation path.
        }
        26
    } else {
        24
    };
    let snap = frame.get(snap_offset..snap_offset + 8)?;
    let protocol = u16::from_be_bytes([snap[6], snap[7]]);
    if snap[..6] != [0xaa, 0xaa, 3, 0, 0, 0]
        || protocol < 0x0600
        || matches!(protocol, 0x80f3 | 0x8137)
    {
        // Linux's ieee80211_get_8023_tunnel_proto preserves LLC for AARP/IPX;
        // that length-framed LLC path is not implemented by this profile.
        return None;
    }
    let payload = &frame[snap_offset + 8..];
    if payload.len() > 1500 {
        return None;
    }
    let mut eth = Vec::with_capacity(14 + payload.len());
    eth.extend_from_slice(&header[4..10]);
    eth.extend_from_slice(&header[16..22]);
    eth.extend_from_slice(&snap[6..8]);
    eth.extend_from_slice(payload);
    Some(eth)
}

impl<B: Backend> Session<B> {
    pub(super) fn prepare_ht20_receive(
        &mut self,
        bss: &ScanBss,
    ) -> Result<super::Ht20ReceiveInfo, Error> {
        let info = match self.state {
            State::RadioReady(info) | State::ScanReady(info) => info,
            _ => return Err(Error::Busy),
        };
        self.backend.check()?;
        let receiver = super::amsdu::Receiver::prepare(info, bss)?;
        let info = receiver.info();
        self.ht20_rx = Some(receiver);
        self.received_msdu.clear();
        Ok(info)
    }

    pub(super) fn clear_aggregate_receive(&mut self) {
        if let Some(receiver) = &mut self.ht20_rx {
            receiver.clear();
        }
        self.received_msdu.clear();
    }

    fn receive_aggregate(
        &mut self,
        native: &super::scan::NativeRx<'_>,
        own: [u8; 6],
        peer: [u8; 6],
        channel: u8,
    ) -> Option<Vec<u8>> {
        let receiver = self.ht20_rx.as_mut()?;
        if !receiver.matches(own, peer, channel) {
            receiver.clear();
            return None;
        }
        let Some(qos) = native.frame.get(24) else {
            receiver.clear();
            return None;
        };
        let tid = usize::from(*qos & 15);
        if self.rx_ba.owns(tid as u8)
            && (!self.rx_ba.active(tid as u8) || native.wcid != 1 || usize::from(native.tid) != tid)
        {
            receiver.clear();
            return None;
        }
        let floor = self
            .security
            .as_ref()
            .map(|security| security.pairwise[tid]);
        let complete = receiver.observe(native, floor, self.backend.now_ns())?;
        if self.rx_ba.active(tid as u8) {
            let sequence = u16::from_le_bytes([native.frame[22], native.frame[23]]) >> 4;
            self.rx_ba.insert(
                tid as u8,
                super::ba::Packet::new(
                    sequence,
                    complete.replay.map(|r| r.pn),
                    complete.frames,
                    None,
                ),
                self.backend.now_ns(),
            );
            return self.receive_ba_ready();
        }
        // Only a complete, checked MPDU can consume its PN, and only once
        // for all hardware-deaggregated MSDUs sharing that PN.
        if let Some(replay) = complete.replay {
            self.security.as_mut()?.pairwise[replay.tid] = replay.pn;
        }
        self.received_msdu = complete.frames;
        self.received_msdu.pop_front()
    }

    fn receive_ba_ready(&mut self) -> Option<Vec<u8>> {
        // Replay validation follows sequence reordering, as mt76_rx_complete
        // calls mt76_check_ccmp_pn only after mt76_rx_aggr_reorder.
        for _ in 0..32 {
            let Some((tid, mut packet)) = self.rx_ba.pop() else {
                break;
            };
            match (self.security.as_mut(), packet.pn) {
                (Some(security), Some(pn)) if pn > security.pairwise[usize::from(tid)] => {
                    security.pairwise[usize::from(tid)] = pn
                }
                (None, None) => {}
                (Some(_), None) if packet.eapol.is_some() => {}
                _ => continue,
            }
            if let Some(pdu) = packet.eapol.take() {
                if let Some(security) = &mut self.security {
                    if security.pending.len() < 16 {
                        security.pending.push_back((pdu, packet.pn.is_some()));
                    }
                }
                continue;
            }
            self.received_msdu = packet.frames;
            if let Some(frame) = self.received_msdu.pop_front() {
                return Some(frame);
            }
        }
        None
    }

    pub(super) fn keys_pending(&self) -> bool {
        !self.peer_lost
            && matches!(self.state, State::Associated { .. })
            && self.data_pending.is_none()
            && (!self.control_pending.is_empty()
                || self.rx_ba.pending(self.backend.now_ns())
                || self
                    .security
                    .as_ref()
                    .is_some_and(|security| !security.pending.is_empty()))
    }
    async fn install_group_key(&mut self, gtk: &Gtk) -> Result<(), Error> {
        if gtk.rsc[6..] != [0, 0] {
            return Err(Error::MalformedEvent);
        }
        let record = crate::mt7921::association::key_record(19, gtk.key_id, Some(&gtk.key))
            .map_err(|_| Error::MalformedEvent)?;
        self.exchange_station(Command::Unified { id: 3 }, &record)
            .await
            .map(|_| ())
    }

    /// Service authenticated PTK/GTK rekeys captured by the bounded RX step.
    /// The supplicant only reports a key when it differs from the installed
    /// one, so retransmissions cannot reset packet-number replay windows.
    pub(super) async fn service_keys(&mut self) -> Result<(), Error> {
        self.service_control().await?;
        let associated = self.state;
        let State::Associated { info, peer, .. } = associated else {
            return Ok(());
        };
        if self.data_pending.is_some() {
            return Ok(());
        }
        if self
            .security
            .as_ref()
            .is_none_or(|security| security.pending.is_empty())
        {
            return Ok(());
        }
        // A cancelled key operation cannot leave an authorized session with
        // its RSNA owner missing. The pending/running state survives cancellation.
        self.stage(Stage::EapolHandshake);
        self.clear_aggregate_receive();
        let Some(mut security) = self.security.take() else {
            return Ok(());
        };
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            self.retire_receive_ba(peer).await?;
            for _ in 0..4 {
                let Some((pdu, protected)) = security.pending.pop_front() else {
                    break;
                };
                let Some(result) =
                    security.process(&pdu, protected, |out| self.backend.random_bytes(out))?
                else {
                    continue;
                };
                let (reply, tk, gtk) = match result {
                    EapolRx::Pairwise1(m1) => (m1.reply, None, None),
                    EapolRx::Pairwise3(m3) => {
                        if !m3.secure {
                            return Err(Error::MalformedEvent);
                        }
                        (m3.reply, m3.tk, m3.gtk)
                    }
                    EapolRx::Group1(group) => (group.reply, None, group.gtk),
                };
                self.send_management(&wrap_eapol_frame(info.capabilities.mac, peer, &reply), 1)
                    .await?;
                if let Some(tk) = tk {
                    let record = crate::mt7921::association::key_record(1, 0, Some(&tk))
                        .map_err(|_| Error::MalformedEvent)?;
                    self.exchange_station(Command::Unified { id: 3 }, &record)
                        .await?;
                    security.supplicant.pairwise_key_installed();
                    security.pairwise.fill(0);
                }
                if let Some(gtk) = gtk {
                    self.install_group_key(&gtk).await?;
                    security.commit_group(&gtk)?;
                }
            }
            self.check_station_tx()?;
            Ok(())
        }
        .await;
        self.boot_started = None;
        if let Err(error) = result {
            self.wmm = None;
            self.station_permission = None;
            self.ht20_rx = None;
            self.ht20_profile = None;
            self.rx_ba.fence();
            self.state = State::Failed {
                stage: Stage::EapolHandshake,
                error,
            };
            return Err(error);
        }
        self.security = Some(security);
        self.state = associated;
        Ok(())
    }

    /// Receive only validated native data from this station's associated AP.
    /// A rejected RX descriptor is discarded with its payload; it is never
    /// returned as a raw Ethernet frame. The budget also bounds malformed bursts.
    pub(super) fn receive_ethernet(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.peer_lost {
            self.rx_ba.fence();
            self.clear_aggregate_receive();
            return Err(Error::DeviceGone);
        }
        let (own, peer, channel) = match self.state {
            State::Associated {
                info,
                peer,
                channel,
                ..
            } => (info.capabilities.mac, peer, channel),
            _ => return Err(Error::Busy),
        };
        self.backend.check()?;
        if self.rx_ba.tick(self.backend.now_ns()) {
            self.clear_aggregate_receive();
        }
        if let Some(frame) = self.received_msdu.pop_front() {
            return Ok(Some(frame));
        }
        if let Some(frame) = self.receive_ba_ready() {
            return Ok(Some(frame));
        }
        for _ in 0..16 {
            self.backend.check()?;
            let Some(packet) = self.backend.receive_data()? else {
                return Ok(None);
            };
            let Some(native) = super::scan::rx_native_with_amsdu(&packet) else {
                self.clear_aggregate_receive();
                continue;
            };
            if native.channel != channel {
                self.clear_aggregate_receive();
                continue;
            }
            if native.ampdu && native.amsdu != 0 {
                // Recipient BA explicitly leaves nested A-MSDU unnegotiated.
                self.clear_aggregate_receive();
                continue;
            }
            if native.amsdu != 0 {
                if let Some(frame) = self.receive_aggregate(&native, own, peer, channel) {
                    return Ok(Some(frame));
                }
                continue;
            }
            if let Some(receiver) = &mut self.ht20_rx {
                receiver.clear();
            }
            let frame = native.frame;
            if self.receive_ba_control(&native, own, peer) {
                if let Some(frame) = self.receive_ba_ready() {
                    return Ok(Some(frame));
                }
                continue;
            }
            let Some(header) = frame.get(..24) else {
                continue;
            };
            if let Some(profile) = self.ht20_profile {
                if matches!(header[0], 0x80 | 0x50)
                    && header[1] & 0xc7 == 0
                    && header[10..16] == peer
                    && header[16..22] == peer
                    && (header[4..10] == own || header[4..10] == [0xff; 6])
                    && frame.get(36..).is_some_and(|ies| {
                        crate::mt7921::ht20::Profile::parse(ies, channel)
                            .and_then(|p| p.with_secondary(profile.negotiated_secondary()))
                            != Ok(profile)
                    })
                {
                    self.peer_lost = true;
                    self.rx_ba.fence();
                    self.clear_aggregate_receive();
                    return Err(Error::DeviceGone);
                }
            }
            if let Some(parameters) = self.wmm {
                if native.ccmp.is_none()
                    && matches!(header[0], 0x80 | 0x50)
                    && header[1] & 0xc7 == 0
                    && header[22] & 15 == 0
                    && (header[4..10] == own || header[4..10] == [0xff; 6])
                    && header[10..16] == peer
                    && header[16..22] == peer
                    && frame.get(36..).is_some_and(|ies| {
                        crate::mt7921::association::wmm::Parameters::parse(ies)
                            != Ok(Some(parameters))
                    })
                {
                    // No asynchronous beacon-driven EDCA reconfiguration
                    // owner exists yet. A changed/missing/malformed bound AP
                    // parameter set closes the port until a fresh join.
                    self.peer_lost = true;
                    self.rx_ba.fence();
                    self.clear_aggregate_receive();
                    return Err(Error::DeviceGone);
                }
            }
            if native.ccmp.is_none()
                && matches!(header[0], 0xa0 | 0xc0)
                && header[1] & 0xc7 == 0
                && header[22] & 15 == 0
                && (header[4..10] == own || header[4..10] == [0xff; 6])
                && header[10..16] == peer
                && header[16..22] == peer
                && frame.get(24..26).is_some_and(|reason| reason != [0, 0])
            {
                self.peer_lost = true;
                self.rx_ba.fence();
                self.clear_aggregate_receive();
                return Err(Error::DeviceGone);
            }
            if header[10..16] != peer
                || header[4..10] != own && header[4] & 1 == 0
                || header[16..22] == [0; 6]
                || header[16] & 1 != 0
                || header[4] & 1 != 0 && header[16..22] == own
            {
                continue;
            }
            let qos = (header[0] == 0x88).then(|| frame.get(24..26)).flatten();
            let tid = qos.map(|qos| qos[0] & 15);
            let reordered = tid.is_some_and(|tid| self.rx_ba.active(tid));
            if (native.ampdu || tid.is_some_and(|tid| self.rx_ba.owns(tid)))
                && (!reordered
                    || native.wcid != 1
                    || tid != Some(native.tid)
                    || header[4..10] != own
                    || header[22] & 15 != 0
                    || qos.is_none_or(|q| q[1] != 0 || !matches!(q[0] & 0xe0, 0 | 0x60)))
            {
                continue;
            }
            let protected = header[1] & 0x40 != 0;
            let mut normalized;
            let mut replay = None;
            let frame = if let Some(ccmp) = native.ccmp {
                let Some(security) = self.security.as_mut() else {
                    continue;
                };
                if !protected {
                    continue;
                }
                let tid = if header[0] & 0x80 != 0 {
                    let Some(qos) = frame.get(24) else {
                        continue;
                    };
                    usize::from(qos & 15)
                } else {
                    16
                };
                let counter = if header[4] & 1 != 0 {
                    let Some(counters) = security.group[usize::from(ccmp.key_id)].as_ref() else {
                        continue;
                    };
                    counters[tid]
                } else {
                    if ccmp.key_id != 0 {
                        continue;
                    }
                    security.pairwise[tid]
                };
                if ccmp.pn <= counter {
                    continue;
                }
                replay = Some((tid, ccmp.pn, ccmp.key_id, header[4] & 1 != 0));
                // Native hardware-decrypted CCMP has IV/MIC stripped. Only
                // validated RX metadata authorizes removing the Protected bit.
                normalized = frame.to_vec();
                normalized[1] &= !0x40;
                &normalized[..]
            } else {
                if protected {
                    continue;
                }
                frame
            };
            if let Some(ethernet) = to_ethernet(frame) {
                let eapol = ethernet[12..14] == [0x88, 0x8e];
                if self.security.is_some() && !protected && !eapol {
                    continue;
                }
                if reordered {
                    let pdu = if eapol {
                        if ethernet[..6] != own || ethernet[6..12] != peer {
                            continue;
                        }
                        let Some(pdu) = extract_eapol(frame) else {
                            continue;
                        };
                        Some(pdu.to_vec())
                    } else {
                        None
                    };
                    let frames = if eapol {
                        VecDeque::new()
                    } else {
                        VecDeque::from([ethernet])
                    };
                    let sequence = u16::from_le_bytes([header[22], header[23]]) >> 4;
                    self.rx_ba.insert(
                        tid.unwrap(),
                        super::ba::Packet::new(sequence, replay.map(|r| r.1), frames, pdu),
                        self.backend.now_ns(),
                    );
                    if let Some(frame) = self.receive_ba_ready() {
                        return Ok(Some(frame));
                    }
                    continue;
                }
                if let Some(security) = self.security.as_mut() {
                    if let Some((tid, pn, key, group)) = replay {
                        if group {
                            security.group[usize::from(key)].as_mut().unwrap()[tid] = pn;
                        } else {
                            security.pairwise[tid] = pn;
                        }
                    }
                    if eapol {
                        if ethernet[..6] == own && ethernet[6..12] == peer {
                            if let Some(pdu) = extract_eapol(frame) {
                                if security.pending.len() < 16 {
                                    security.pending.push_back((pdu.to_vec(), protected));
                                }
                            }
                        }
                        continue;
                    }
                }
                if eapol {
                    continue;
                } // The retained driver owns the controlled port.
                return Ok(Some(ethernet));
            }
        }
        Ok(None)
    }

    pub(super) async fn send_management(
        &mut self,
        frame: &[u8],
        wcid: u16,
    ) -> Result<packet_tx::Completion, Error> {
        self.check_station_tx()?;
        self.transmit_management(frame, wcid).await
    }

    /// Only callers that just checked their station or one-shot closing
    /// permission may publish. The closing caller never restores a host grant.
    async fn transmit_management(
        &mut self,
        frame: &[u8],
        wcid: u16,
    ) -> Result<packet_tx::Completion, Error> {
        self.backend
            .submit_management(frame, wcid, self.management_rate)?;
        let completion = self
            .wait(TIMEOUT_MS, |backend| backend.management_complete())
            .await?;
        if completion.status != 0 {
            return Err(Error::Rejected(completion.status));
        }
        Ok(completion)
    }

    pub(super) async fn send_ethernet(
        &mut self,
        frame: &[u8],
    ) -> Result<packet_tx::Completion, Error> {
        self.start_ethernet(frame)?;
        self.wait(TIMEOUT_MS, |backend| backend.management_complete())
            .await
            .and_then(|completion| {
                self.data_pending = None;
                if completion.status == 0 {
                    Ok(completion)
                } else {
                    Err(Error::Rejected(completion.status))
                }
            })
    }

    /// Publish at most one frame; completion is advanced by the common
    /// bounded step, including from synchronous network waiters.
    pub(super) fn start_ethernet(&mut self, frame: &[u8]) -> Result<(), Error> {
        if self.peer_lost {
            return Err(Error::DeviceGone);
        }
        let State::Associated { info, .. } = self.state else {
            return Err(Error::Busy);
        };
        if !(14..=1514).contains(&frame.len())
            || frame[6..12] != info.capabilities.mac
            || u16::from_be_bytes([frame[12], frame[13]]) < 0x600
            || frame[12..14] == [0x88, 0x8e]
        {
            return Err(Error::Bounds);
        }
        if self.data_pending.is_some() {
            return Err(Error::Busy);
        }
        self.check_station_tx()?;
        self.backend
            .submit_data(frame, self.security.is_some(), self.wmm.is_some())?;
        self.data_pending = Some(self.backend.now_ns());
        Ok(())
    }

    pub(super) fn poll_data_tx(&mut self) -> Result<bool, Error> {
        let Some(started) = self.data_pending else {
            return Ok(true);
        };
        self.backend.check()?;
        if let Some(completion) = self.backend.management_complete()? {
            self.data_pending = None;
            if completion.status != 0 {
                return Err(Error::Rejected(completion.status));
            }
            return Ok(true);
        }
        if self.backend.now_ns().saturating_sub(started) >= TIMEOUT_MS * 1_000_000 {
            let error = Error::Timeout;
            self.security = None;
            self.state = State::Failed {
                stage: Stage::StaRecord,
                error,
            };
            return Err(error);
        }
        Ok(false)
    }

    pub(super) fn step_network(&mut self, tx: Option<&[u8]>) -> Result<super::PacketStep, Error> {
        if self.peer_lost || !matches!(self.state, State::Associated { .. }) {
            return Err(Error::DeviceGone);
        }
        let ready = self.poll_data_tx()?;
        let transmitted = if let Some(frame) = tx.filter(|_| ready) {
            self.start_ethernet(frame)?;
            true
        } else {
            false
        };
        let mut received = Vec::new();
        for _ in 0..4 {
            let Some(frame) = self.receive_ethernet()? else {
                break;
            };
            received.push(frame);
        }
        Ok(super::PacketStep {
            transmitted,
            received,
        })
    }

    pub(super) async fn associate_station(
        &mut self,
        bss: &ScanBss,
        ssid: &[u8],
        security: Security,
        permission: crate::mt7921::association::TxPermission,
        extra_ies: &[u8],
    ) -> Result<u16, Error> {
        let (info, setup) = match self.state {
            State::RadioReady(info) => (info, true),
            State::ScanReady(info) => (info, false),
            State::Associated { .. } => return Err(Error::Busy),
            _ => return Err(Error::Busy),
        };
        let band = crate::mt7921::channel::band(bss.channel).ok_or(Error::Bounds)?;
        if !permission.permits(bss.channel) {
            return Err(Error::Authority);
        }
        if info.capabilities.phy.bands & band.capability() == 0 {
            return Err(Error::InvalidIdentity);
        }
        let own = info.capabilities.mac;
        let mut plan = JoinPlan::prepare(bss, own, ssid, security).map_err(|e| match e {
            crate::mt7921::association::Error::InvalidBss => Error::Bounds,
            crate::mt7921::association::Error::UnsupportedRates => Error::UnsupportedFirmware,
            crate::mt7921::association::Error::UnsupportedSecurity => Error::Bounds,
            crate::mt7921::association::Error::Busy => Error::Busy,
            _ => Error::Bounds,
        })?;
        plan.append_sme_ies(extra_ies).map_err(|_| Error::Bounds)?;
        plan.offer_ht20(info, bss, permission)?;
        self.backend.check_tx_permission(permission)?;
        if !self.rx_ba.begin_connection() {
            return Err(Error::Busy);
        }

        self.management_rate = plan.management_rate();
        // Discard idle receive preparation. Any HT activation below must be
        // rebuilt from the bound AP response and completed native receipts.
        self.ht20_rx = None;
        self.ht20_profile = None;
        self.control_pending.clear();
        self.received_msdu.clear();
        self.boot_started = Some(self.backend.now_ns());
        self.security = None;
        self.wmm = None;
        self.station_permission = Some(permission);
        let result = async {
            if setup {
                self.stage(Stage::ScanSetup);
                self.scan_setup(info).await?;
            }
            self.stage(Stage::ChannelSwitch);
            self.check_station_tx()?;
            // 1. Authorize transmission on the target channel in channel domain (NO_IR = 0):
            let channels = permission.channels();
            let mut domain = vec![0u8; 12 + 8 * channels.len()];
            domain[..2].copy_from_slice(&permission.country);
            domain[4..7].fill(1); // 20 MHz
            if permission.secondary_channel().is_some() {
                domain[3 + usize::from(band.scan_tag())] = 0;
            } // Native BW20/40 enum.
            domain[7 + usize::from(band.scan_tag())] = channels.len() as u8;
            for (index, channel) in channels.into_iter().enumerate() {
                domain[12 + index * 8..14 + index * 8]
                    .copy_from_slice(&u16::from(channel).to_le_bytes());
                // Flags zero only after complete occupied-channel admission.
            }
            self.notify(
                Command::Ce {
                    id: 0x0f,
                    query: false,
                },
                &domain,
            )
            .await?;

            // The host policy's power ceiling is programmed before any
            // authentication/EAPOL/data frame can reach a TX descriptor.
            self.notify(
                Command::Ce {
                    id: 0x5d,
                    query: false,
                },
                &permission.rate_limits(),
            )
            .await?;
            self.confirm_command_progress().await?;
            self.check_station_tx()?;

            // 2. Switch channel:
            let mut switch = [0u8; cmd::CHANNEL_SWITCH_SIZE];
            cmd::encode_channel_switch(
                bss.channel,
                permission.center_channel(),
                permission.native_width(),
                1, // The retained legacy profile transmits on one chain.
                (1 << info.capabilities.phy.spatial_streams.min(2)) - 1,
                band.switch_tag(),
                &mut switch,
            )
            .ok_or(Error::Bounds)?;
            self.exchange_station(
                Command::Extended {
                    id: crate::mt7921::regs::MCU_EXT_CMD_CHANNEL_SWITCH,
                    query: false,
                },
                &switch,
            )
            .await?;

            // Publish BSSID and an unauthorized AP WCID before management
            // or EAPOL RX; a scan-only BSS has no peer address installed.
            let bss_record = crate::mt7921::association::bss_record_qos(bss, false, false)
                .map_err(|_| Error::Bounds)?;
            self.exchange_station(Command::Unified { id: 2 }, &bss_record)
                .await?;
            let peer_record = plan.peer_record(0, false).map_err(|_| Error::Bounds)?;
            self.exchange_station(Command::Unified { id: 3 }, &peer_record)
                .await?;

            // 3. Send Authentication Request:
            self.stage(Stage::Authenticate);
            let auth_req = plan.start_authentication().map_err(|_| Error::Busy)?;
            self.send_management(auth_req, 1).await?;

            // 4. Wait for Authentication Response:
            let assoc_req = self
                .wait(3_000, |backend| {
                    for _ in 0..16 {
                        let Some(packet) = backend.receive_data()? else {
                            break;
                        };
                        if let Some(frame) = rx_on_channel(&packet, bss.channel) {
                            if let Some(assoc) = plan
                                .authentication_response(frame)
                                .map_err(|_| Error::MalformedEvent)?
                            {
                                return Ok(Some(assoc.to_vec()));
                            }
                        }
                    }
                    Ok(None)
                })
                .await?;

            // 5. Send Association Request:
            self.stage(Stage::Associate);
            self.send_management(&assoc_req, 1).await?;

            // 6. Wait for Association Response:
            let aid = self
                .wait(3_000, |backend| {
                    for _ in 0..16 {
                        let Some(packet) = backend.receive_data()? else {
                            break;
                        };
                        if let Some(frame) = rx_on_channel(&packet, bss.channel) {
                            if let Some(aid) = plan
                                .association_response(frame)
                                .map_err(|_| Error::MalformedEvent)?
                            {
                                return Ok(Some(aid));
                            }
                        }
                    }
                    Ok(None)
                })
                .await?;

            self.management_rate = plan.management_rate();
            if let Some(profile) = plan.ht20() {
                let mut response_bss = bss.clone();
                response_bss.information_elements = profile.received_ies();
                self.ht20_rx = Some(super::amsdu::Receiver::prepare(info, &response_bss)?);
            }
            if let Some(parameters) = plan.wmm() {
                self.check_station_tx()?;
                // Native SET_EDCA_PARMS has no firmware reply. The following
                // matching PSE read bounds command progress before QoS WCID
                // publication; it is not an invented EDCA acceptance event.
                self.notify(
                    Command::Ce {
                        id: 0x1d,
                        query: false,
                    },
                    &parameters.edca(),
                )
                .await?;
                self.confirm_command_progress().await?;
                self.check_station_tx()?;
            }
            let bss_record = crate::mt7921::association::bss_record_ht20(
                bss,
                plan.wmm().is_some(),
                plan.ht20().is_some(),
            )
            .map_err(|_| Error::Bounds)?;
            self.exchange_station(Command::Unified { id: 2 }, &bss_record)
                .await?;
            if let Some(profile) = plan.ht20() {
                self.exchange_station(
                    Command::Unified { id: 2 },
                    &profile.rlm(
                        bss.channel,
                        (1 << info.capabilities.phy.spatial_streams.min(2)) - 1,
                    ),
                )
                .await?;
            }
            let peer_record = plan.peer_record(aid, true).map_err(|_| Error::Bounds)?;
            self.exchange_station(Command::Unified { id: 3 }, &peer_record)
                .await?;
            let group_record = crate::mt7921::association::group_record(bss.bssid, aid)
                .map_err(|_| Error::Bounds)?;
            self.exchange_station(Command::Unified { id: 3 }, &group_record)
                .await?;

            // 7. Update STA_REC / perform WPA2 4-way handshake:
            match security {
                Security::Open => {
                    self.stage(Stage::StaRecord);
                    let sta_rec = plan
                        .peer_record(aid, true)
                        .map_err(|_| Error::MalformedEvent)?;
                    self.exchange_station(Command::Unified { id: 3 }, &sta_rec)
                        .await?;
                }
                Security::Wpa2Psk { psk } => {
                    self.stage(Stage::EapolHandshake);
                    let mut security = StationSecurity::new(bss, &plan, own, psk)?;
                    let mut established = false;
                    // Retry replies remain bounded by the operation's 30 s budget.
                    for _ in 0..16 {
                        let result = self
                            .wait(3_000, |backend| {
                                for _ in 0..16 {
                                    let Some(packet) = backend.receive_data()? else {
                                        break;
                                    };
                                    if let Some(pdu) =
                                        peer_eapol(&packet, own, bss.bssid, bss.channel)
                                    {
                                        if let Some(result) =
                                            security.process(pdu, false, |out| {
                                                backend.random_bytes(out)
                                            })?
                                        {
                                            return Ok(Some(result));
                                        }
                                    }
                                }
                                Ok(None)
                            })
                            .await?;
                        match result {
                            EapolRx::Pairwise1(m1) => {
                                self.send_management(
                                    &wrap_eapol_frame(own, bss.bssid, &m1.reply),
                                    1,
                                )
                                .await?;
                            }
                            EapolRx::Pairwise3(m3) => {
                                if !m3.secure || m3.tk.is_none() || m3.gtk.is_none() {
                                    return Err(Error::MalformedEvent);
                                }
                                self.send_management(
                                    &wrap_eapol_frame(own, bss.bssid, &m3.reply),
                                    1,
                                )
                                .await?;
                                self.stage(Stage::StaRecord);
                                let record = plan
                                    .secure_peer_record(aid, m3.tk.as_deref().unwrap())
                                    .map_err(|_| Error::MalformedEvent)?;
                                self.exchange_station(Command::Unified { id: 3 }, &record)
                                    .await?;
                                security.supplicant.pairwise_key_installed();
                                let gtk = m3.gtk.as_ref().unwrap();
                                self.install_group_key(gtk).await?;
                                security.commit_group(gtk)?;
                                established = true;
                                break;
                            }
                            EapolRx::Group1(_) => return Err(Error::MalformedEvent),
                        }
                    }
                    if !established {
                        return Err(Error::Timeout);
                    }
                    self.security = Some(security);
                }
            }

            self.check_station_tx()?;
            Ok(aid)
        }
        .await;

        match result {
            Ok(aid) => {
                self.boot_started = None;
                self.peer_lost = false;
                self.station_bss = Some(bss.clone());
                self.wmm = plan.wmm();
                self.ht20_profile = plan.ht20();
                if let Some(receiver) = &mut self.ht20_rx {
                    receiver.active = true;
                }
                self.state = State::Associated {
                    info,
                    peer: bss.bssid,
                    channel: bss.channel,
                    aid,
                };
                Ok(aid)
            }
            Err(error) => {
                self.security = None;
                self.wmm = None;
                self.station_permission = None;
                self.ht20_rx = None;
                self.ht20_profile = None;
                plan.cancel();
                let stage = match self.state {
                    State::Running(stage) | State::Failed { stage, .. } => stage,
                    _ => Stage::Associate,
                };
                self.state = State::Failed { stage, error };
                Err(error)
            }
        }
    }

    pub(super) async fn disassociate_station(&mut self) -> Result<(), Error> {
        let (info, peer) = match self.state {
            State::Associated { info, peer, .. } => (info, peer),
            State::RadioReady(_) | State::ScanReady(_) | State::Stopped => return Ok(()),
            _ => return Err(Error::Busy),
        };
        self.boot_started = Some(self.backend.now_ns());
        let secure = self.security.take().is_some();
        let had_wmm = self.wmm.take().is_some();
        // Retire the host grant before the first wait. This local copy can
        // authorize only the closing deauth; a dropped waiter cannot leave a
        // reusable station permission in the retained running owner.
        let closing_permission = self.station_permission.take();
        self.rx_ba.fence();
        self.ht20_rx = None;
        self.ht20_profile = None;
        self.control_pending.clear();
        self.received_msdu.clear();
        let peer_lost = self.peer_lost;
        self.stage(Stage::StaRecord);
        let result = async {
            if self.data_pending.is_some() {
                self.wait(TIMEOUT_MS, |backend| backend.management_complete())
                    .await?;
                self.data_pending = None;
            }
            self.retire_receive_ba(peer).await?;
            if !peer_lost {
                let mut deauth = vec![0u8; 26];
                deauth[0] = 0xc0;
                deauth[4..10].copy_from_slice(&peer);
                deauth[10..16].copy_from_slice(&info.capabilities.mac);
                deauth[16..22].copy_from_slice(&peer);
                deauth[24..26].copy_from_slice(&3u16.to_le_bytes());
                self.backend
                    .check_tx_permission(closing_permission.ok_or(Error::Authority)?)?;
                match self.transmit_management(&deauth, 1).await {
                    Ok(_) | Err(Error::Rejected(_)) => {}
                    Err(error) => return Err(error),
                }
            }
            // Retire keys before removing the station WCIDs. No cleanup ACK
            // is optional: uncertainty cannot become a reusable ready radio.
            if secure {
                for wcid in [1, 19] {
                    let record = crate::mt7921::association::key_record(wcid, 0, None)
                        .map_err(|_| Error::Bounds)?;
                    self.exchange(Command::Unified { id: 3 }, &record).await?;
                }
            }
            for wcid in [1, 19] {
                let record = if wcid == 1 {
                    disconnect_record(peer)
                } else {
                    crate::mt7921::association::group_disconnect_record()
                };
                self.exchange(Command::Unified { id: 3 }, &record).await?;
            }
            if let Some(bss) = &self.station_bss {
                let record = crate::mt7921::association::bss_record_qos(bss, false, false)
                    .map_err(|_| Error::Bounds)?;
                self.exchange(Command::Unified { id: 2 }, &record).await?;
            }
            if had_wmm {
                self.notify(
                    Command::Ce {
                        id: 0x1d,
                        query: false,
                    },
                    &crate::mt7921::association::wmm::legacy_edca(),
                )
                .await?;
                self.confirm_command_progress().await?;
            }
            Ok(())
        }
        .await;
        self.boot_started = None;
        self.station_permission = None;
        if let Err(error) = result {
            self.state = State::Failed {
                stage: Stage::StaRecord,
                error,
            };
            return Err(error);
        }
        self.station_bss = None;
        self.peer_lost = false;
        self.state = State::ScanReady(info);
        Ok(())
    }

    pub(super) fn check_station_tx(&mut self) -> Result<(), Error> {
        let result = self
            .station_permission
            .ok_or(Error::Authority)
            .and_then(|permission| self.backend.check_tx_permission(permission));
        if let Err(error) = result {
            self.station_permission = None;
            self.wmm = None;
            self.security = None;
            self.ht20_rx = None;
            self.ht20_profile = None;
            self.rx_ba.fence();
            self.control_pending.clear();
            self.clear_aggregate_receive();
            let stage = match self.state {
                State::Running(stage) | State::Failed { stage, .. } => stage,
                _ => Stage::StaRecord,
            };
            self.state = State::Failed { stage, error };
        }
        result
    }

    /// Advance recipient BA and declined requests under the retained control
    /// owner. Dropping this future cannot restore an associated producer.
    async fn service_control(&mut self) -> Result<(), Error> {
        if self.control_pending.is_empty() && !self.rx_ba.pending(self.backend.now_ns())
            || self.data_pending.is_some()
        {
            return Ok(());
        }
        let associated = self.state;
        let State::Associated { info, peer, .. } = associated else {
            return Ok(());
        };
        if self.peer_lost {
            return Ok(());
        }
        self.stage(Stage::StaRecord);
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            self.service_receive_ba(info.capabilities.mac, peer).await?;
            for _ in 0..4 {
                let Some(frame) = self.control_pending.pop_front() else {
                    break;
                };
                self.send_management(&frame, 1).await?;
            }
            self.check_station_tx()
        }
        .await;
        self.boot_started = None;
        if let Err(error) = result {
            self.security = None;
            self.wmm = None;
            self.station_permission = None;
            self.ht20_profile = None;
            self.ht20_rx = None;
            self.rx_ba.fence();
            self.control_pending.clear();
            self.received_msdu.clear();
            self.state = State::Failed {
                stage: Stage::StaRecord,
                error,
            };
            return Err(error);
        }
        self.state = associated;
        Ok(())
    }

    /// Every association/key/port publication earns fresh authority after
    /// the preceding wait. Cleanup deliberately uses plain exchange instead.
    pub(super) async fn exchange_station(
        &mut self,
        command: Command,
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.check_station_tx()?;
        let reply = self.exchange(command, body).await?;
        self.check_station_tx()?;
        Ok(reply)
    }

    /// Linux drains the SKU command through MCU's PSE register read. Match
    /// the actual register identity and exact native receipt, not merely any
    /// command reply. The same bounded operation orders EDCA before QoS TX.
    async fn confirm_command_progress(&mut self) -> Result<(), Error> {
        let mut request = [0; 8];
        request[..4].copy_from_slice(&0x820c8000u32.to_le_bytes());
        let reply = self
            .exchange(
                Command::Ce {
                    id: 0xc0,
                    query: true,
                },
                &request,
            )
            .await?;
        if reply.len() != 8 || reply[..4] != request[..4] {
            return Err(Error::MalformedEvent);
        }
        Ok(())
    }
}
