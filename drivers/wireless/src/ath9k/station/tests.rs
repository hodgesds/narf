// A reactive AP consumes only bytes read from the actual published AR9285 DMA.
use super::*;
use crate::ath9k::packet::tests::Model;
use alloc::sync::Arc;
use core::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicU64},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::{udp_ipv4, ApPhase, DhcpServer, FakeAp, NetworkPlan};
use narf_wireless::eapol::{KeyFrame, KeyMgmt, Ptk};
const OWN: [u8; 6] = [2, 1, 2, 3, 4, 5];
pub(in crate::ath9k) const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
pub(in crate::ath9k) const SSID: &[u8] = b"narf-ar9";
pub(in crate::ath9k) const PMK: [u8; 32] = [0x55; 32];
const ANONCE: [u8; 32] = [0xaa; 32];
pub(in crate::ath9k) struct Env {
    pub now: AtomicU64,
    pub entropy: AtomicBool,
}
impl Environment for Arc<Env> {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::Acquire)
    }
    fn nonce(&self) -> Option<[u8; 32]> {
        self.entropy.load(Ordering::Acquire).then_some([0x33; 32])
    }
    async fn pause(&self) {
        let mut pending = true;
        core::future::poll_fn(|cx| {
            if pending {
                pending = false;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                self.now.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(())
            }
        })
        .await;
    }
}
pub(in crate::ath9k) struct Ccm;
impl narf_wireless::ccmp::AesCcm for Ccm {
    fn encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; 8], narf_wireless::ccmp::CcmpError> {
        narf_crypto::aes_ccm::seal(key, nonce, aad, body)
            .map_err(|_| narf_wireless::ccmp::CcmpError::TooLong)
    }
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), narf_wireless::ccmp::CcmpError> {
        narf_crypto::aes_ccm::open(key, nonce, aad, body, tag)
            .map_err(|_| narf_wireless::ccmp::CcmpError::AuthFailed)
    }
}
pub(in crate::ath9k) struct Peer {
    pub(in crate::ath9k) ap: FakeAp,
    pub(in crate::ath9k) plan: NetworkPlan,
    pub(in crate::ath9k) server: DhcpServer,
    pub(in crate::ath9k) ptk: Option<Ptk>,
    pub(in crate::ath9k) replay: narf_wireless::ccmp::ReplayWindow,
    qos_replay: [narf_wireless::ccmp::ReplayWindow; 16],
    pub(in crate::ath9k) pn: u64,
    pub(in crate::ath9k) uplink: Vec<Vec<u8>>,
    pub(in crate::ath9k) hold_m4: bool,
    pub(in crate::ath9k) hold_data: bool,
    pub(in crate::ath9k) ht: Option<Vec<u8>>,
    ht_response: Option<Vec<u8>>,
    pub(in crate::ath9k) ht_active: bool,
    pub(in crate::ath9k) declines: Vec<Vec<u8>>,
    pub(in crate::ath9k) hold_decline: bool,
    pub(in crate::ath9k) group_replies: usize,
    pub(in crate::ath9k) hold_group: bool,
    pub(in crate::ath9k) ba_accepts: Vec<Vec<u8>>,
    pub(in crate::ath9k) hold_ba: bool,
    pub(in crate::ath9k) delbas: Vec<Vec<u8>>,
    pub(in crate::ath9k) hold_delba: bool,
    pairwise_proposal: Option<([u8; 32], u64)>,
    pub(in crate::ath9k) pairwise_replies: usize,
    pub(in crate::ath9k) tx_ba_requests: Vec<Vec<u8>>,
    pub(in crate::ath9k) tx_ba_respond: bool,
    pub(in crate::ath9k) tx_ba_status: u16,
    pub(in crate::ath9k) tx_ba_window: u16,
    pub(in crate::ath9k) tx_ba_timeout: u16,
    pub(in crate::ath9k) hold_tx_request: bool,
    pub(in crate::ath9k) hold_bar: bool,
    pub(in crate::ath9k) bars: Vec<Vec<u8>>,
    pub(in crate::ath9k) sender_delbas: Vec<Vec<u8>>,
    sender_reorder: Option<narf_wireless::reorder::Reorder<Vec<u8>>>,
    rx_sequence: u16,
}
impl Peer {
    pub(in crate::ath9k) fn new_rates(protected: bool, rates: Option<&[u8]>) -> Self {
        let plan = NetworkPlan {
            station: OWN,
            bssid: AP,
            server_ip: [10, 9, 1, 1],
            lease_ip: [10, 9, 1, 42],
            netmask: [255, 255, 255, 0],
            lease_seconds: 3600,
        };
        let ap = if protected {
            FakeAp::wpa2(plan, SSID, 1, 42, PMK, ANONCE)
        } else {
            FakeAp::open(plan, SSID, 1, 42)
        }
        .unwrap();
        let ap = if let Some(rates) = rates {
            ap.with_legacy_rates(rates).unwrap()
        } else {
            ap.with_basic_1mbps().unwrap()
        };
        Self {
            ap,
            plan,
            server: DhcpServer::new(plan),
            ptk: None,
            replay: narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 },
            qos_replay: core::array::from_fn(|_| narf_wireless::ccmp::ReplayWindow {
                last_seen_pn: 0,
            }),
            pn: 1,
            uplink: Vec::new(),
            hold_m4: false,
            hold_data: false,
            ht: None,
            ht_response: None,
            ht_active: false,
            declines: Vec::new(),
            hold_decline: false,
            group_replies: 0,
            hold_group: false,
            ba_accepts: Vec::new(),
            hold_ba: false,
            delbas: Vec::new(),
            hold_delba: false,
            pairwise_proposal: None,
            pairwise_replies: 0,
            tx_ba_requests: Vec::new(),
            tx_ba_respond: true,
            tx_ba_status: 0,
            tx_ba_window: 64,
            tx_ba_timeout: 0,
            hold_tx_request: false,
            hold_bar: false,
            bars: Vec::new(),
            sender_delbas: Vec::new(),
            sender_reorder: None,
            rx_sequence: 0,
        }
    }
    pub(in crate::ath9k) fn downlink(&mut self, ethernet: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut frame = vec![
            if self.ht_active { 0x88 } else { 8 },
            if self.ap.protected() { 0x42 } else { 2 },
            0,
            0,
        ];
        frame.extend_from_slice(&ethernet[..6]);
        frame.extend_from_slice(&AP);
        frame.extend_from_slice(&ethernet[6..12]);
        frame.extend_from_slice(
            &(if self.ht_active {
                let sequence = self.rx_sequence;
                self.rx_sequence = (sequence + 1) & 4095;
                sequence << 4
            } else {
                0u16
            })
            .to_le_bytes(),
        );
        if self.ht_active {
            frame.extend_from_slice(&[0, 0]);
        }
        let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0];
        body.extend_from_slice(&ethernet[12..]);
        if self.ap.protected() {
            let key: &[u8; 16] = self
                .ptk
                .as_ref()
                .ok_or("AP missing TK")?
                .tk
                .as_slice()
                .try_into()
                .map_err(|_| "AP TK extent")?;
            body = narf_wireless::ccmp::protect(&Ccm, &frame, key, self.pn, 0, 0, false, &mut body)
                .map_err(|_| "AP downlink CCMP")?;
            self.pn += 1;
        }
        frame.extend_from_slice(&body);
        Ok(frame)
    }
    pub(in crate::ath9k) fn react(
        &mut self,
        frame: &[u8],
    ) -> Result<(Vec<Vec<u8>>, bool), &'static str> {
        if frame.first() == Some(&0x84) {
            if frame.len() != 20
                || frame[..2] != [0x84, 0]
                || frame[4..10] != AP
                || frame[10..16] != self.plan.station
                || frame[16..18] != [4, 0]
                || frame[18] & 15 != 0
            {
                return Err("native sender BAR identity/format");
            }
            let head = u16::from_le_bytes([frame[18], frame[19]]) >> 4;
            let released = self
                .sender_reorder
                .as_mut()
                .ok_or("BAR lacks actual air ADDBA")?
                .advance(head, 0)
                .map_err(|_| "AP BAR reorder")?;
            let mut responses = Vec::new();
            for original in released {
                responses.extend(self.receive_data(&original)?.0);
            }
            self.bars.push(frame.to_vec());
            let mut ba = vec![0x94, 0, 0, 0];
            ba.extend_from_slice(&self.plan.station);
            ba.extend_from_slice(&AP);
            ba.extend_from_slice(&[4, 0]);
            ba.extend_from_slice(&(head << 4).to_le_bytes());
            ba.extend_from_slice(&[0; 8]);
            responses.push(ba);
            return Ok((responses, self.hold_bar));
        }
        if frame.first() == Some(&0x40) {
            let length = usize::from(*frame.get(25).ok_or("probe extent")?);
            let name = frame.get(26..26 + length).ok_or("probe SSID")?;
            if frame[1] != 0
                || frame[4..10] != [255; 6]
                || frame[10..16] != self.plan.station
                || frame[16..22] != [255; 6]
                || frame[22] & 15 != 0
                || frame[24] != 0
                || length > 32
                || frame.get(26 + length..)
                    != Some(
                        &[
                            1, 4, 0x82, 0x84, 0x8b, 0x96, 50, 8, 12, 18, 24, 36, 48, 72, 96, 108,
                            3, 1, 1,
                        ][..],
                    )
            {
                return Err("native probe identity/rates/channel");
            }
            if name.is_empty() || name == SSID {
                let mut reply = self.beacon();
                reply[0] = 0x50;
                reply[4..10].copy_from_slice(&self.plan.station);
                return Ok((vec![reply], false));
            }
            return Ok((Vec::new(), false));
        }
        if frame.len() < 24 || frame[4..10] != AP || frame[10..16] != self.plan.station {
            return Err("native AP peer identity");
        }
        if frame[0] == 0xd0 {
            if frame.len() == 33 && frame[24..26] == [3, 0] {
                let parameter = u16::from_le_bytes([frame[27], frame[28]]);
                let requested = parameter >> 6;
                if !self.ht_active
                    || parameter & 0x3f != 2
                    || !(4..=64).contains(&requested)
                    || frame[26] == 0
                    || frame[29..31] != [0, 0]
                    || frame[31] & 15 != 0
                {
                    return Err("native sender ADDBA request");
                }
                self.tx_ba_requests.push(frame.to_vec());
                if !self.tx_ba_respond {
                    return Ok((Vec::new(), self.hold_tx_request));
                }
                let window = self.tx_ba_window.min(requested);
                if self.tx_ba_status == 0 && (1..=64).contains(&window) {
                    let mut reorder =
                        narf_wireless::reorder::Reorder::new(window as u8, 100_000_000)
                            .map_err(|_| "AP BA window allocation")?;
                    reorder
                        .advance(u16::from_le_bytes([frame[31], frame[32]]) >> 4, 0)
                        .map_err(|_| "AP explicit native SSN")?;
                    self.sender_reorder = Some(reorder);
                }
                let mut response = vec![0xd0, 0, 0, 0];
                response.extend_from_slice(&self.plan.station);
                response.extend_from_slice(&AP);
                response.extend_from_slice(&AP);
                response.extend_from_slice(&[0, 0, 3, 1, frame[26]]);
                response.extend_from_slice(&self.tx_ba_status.to_le_bytes());
                response.extend_from_slice(&(2 | (window << 6)).to_le_bytes());
                response.extend_from_slice(&self.tx_ba_timeout.to_le_bytes());
                return Ok((vec![response], self.hold_tx_request));
            }
            if frame.len() == 30
                && frame[24..26] == [3, 2]
                && frame[26..28] == [0, 8]
                && matches!(u16::from_le_bytes([frame[28], frame[29]]), 37 | 39)
            {
                self.sender_delbas.push(frame.to_vec());
                self.sender_reorder = None;
                return Ok((Vec::new(), false));
            }
            if frame.len() == 30 && frame[24..26] == [3, 2] {
                if !self.ht_active
                    || u16::from_le_bytes([frame[26], frame[27]]) & 0xfff != 0
                    || frame[28..30] != [39, 0]
                {
                    return Err("native recipient DELBA");
                }
                self.delbas.push(frame.to_vec());
                return Ok((Vec::new(), self.hold_delba));
            }
            if frame.len() == 33 && frame[24..26] == [3, 1] && frame[27..29] == [0, 0] {
                let p = u16::from_le_bytes([frame[29], frame[30]]);
                if !self.ht_active || p & 2 != 2 || !(1..=64).contains(&(p >> 6)) {
                    return Err("native accepted BA parameters");
                }
                self.ba_accepts.push(frame.to_vec());
                return Ok((Vec::new(), self.hold_ba));
            }
            if self.ht.is_none()
                || frame.len() != 33
                || frame[24..26] != [3, 1]
                || frame[27..29] != [37, 0]
            {
                return Err("native ADDBA decline");
            }
            self.declines.push(frame.to_vec());
            return Ok((Vec::new(), self.hold_decline));
        }
        if self.ap.phase() != ApPhase::Authorized || matches!(frame[0], 0 | 0xb0) {
            let before = self.ap.phase();
            let mut replies = self
                .ap
                .receive(frame)
                .map_err(|_| "shared AP rejected real native MLME/EAPOL")?;
            if before == ApPhase::Association {
                if let Some(elements) = &self.ht {
                    // Literal AP check: hardware implements mandatory ff, never SGI20.
                    let mut ies = &frame[28..];
                    let mut ht = None;
                    let mut wmm = false;
                    while !ies.is_empty() {
                        let end = 2 + usize::from(*ies.get(1).ok_or("association IE header")?);
                        let ie = ies.get(..end).ok_or("association IE extent")?;
                        if ie[0] == 45 {
                            if ht.is_some() {
                                return Err("duplicate station HT");
                            }
                            ht = Some(ie);
                        }
                        if ie == narf_wireless::wmm::INFORMATION {
                            wmm = true;
                        }
                        ies = &ies[end..];
                    }
                    if let Some(cap) = ht {
                        if cap.len() != 28 || cap[2..4] != [12, 1] || cap[5] != 255 || !wmm {
                            return Err("native local HT/WMM/SGI20");
                        }
                        replies[0]
                            .extend_from_slice(self.ht_response.as_deref().unwrap_or(elements));
                        self.ht_active = true;
                    }
                }
            }
            if before == ApPhase::Message2 {
                let key =
                    KeyFrame::decode(frame.get(36..).ok_or("M2 extent")?, 16).ok_or("M2 key")?;
                self.ptk = Some(narf_wireless::eapol::wpa_pmk_to_ptk(
                    KeyMgmt::Psk,
                    &PMK,
                    &AP,
                    &self.plan.station,
                    &ANONCE,
                    &key.key_nonce,
                    16,
                ));
            }
            return Ok((replies, before == ApPhase::Message4 && self.hold_m4));
        }
        if frame[0] == 0x88 && self.sender_reorder.is_some() {
            let seq = u16::from_le_bytes([frame[22], frame[23]]) >> 4;
            let released = self
                .sender_reorder
                .as_mut()
                .unwrap()
                .push(seq, 0, frame.to_vec())
                .map_err(|_| "AP BA original order")?;
            let mut responses = Vec::new();
            let mut held = self.hold_data;
            for original in released {
                let (replies, hold) = self.receive_data(&original)?;
                responses.extend(replies);
                held |= hold;
            }
            return Ok((responses, held));
        }
        self.receive_data(frame)
    }
    fn receive_data(&mut self, frame: &[u8]) -> Result<(Vec<Vec<u8>>, bool), &'static str> {
        if !matches!(frame[0], 8 | 0x88)
            || frame[1] & 3 != 1
            || (frame[1] & 0x40 != 0) != self.ap.protected()
        {
            return Err("native AP data protection/direction");
        }
        let h = if frame[0] == 0x88 { 26 } else { 24 };
        if h == 26 && frame[24..26] != [0, 0] {
            return Err("native AP QoS TID/header");
        }
        let mut body = frame[h..].to_vec();
        if self.ap.protected() {
            let key: &[u8; 16] = self
                .ptk
                .as_ref()
                .ok_or("AP missing uplink TK")?
                .tk
                .as_slice()
                .try_into()
                .map_err(|_| "AP uplink TK extent")?;
            body = narf_wireless::ccmp::unprotect(
                &Ccm,
                &frame[..h],
                key,
                0,
                false,
                if h == 26 {
                    &mut self.qos_replay[usize::from(frame[24] & 15)]
                } else {
                    &mut self.replay
                },
                &mut body,
            )
            .map_err(|_| "AP uplink CCMP/MIC/replay")?;
        }
        if body.get(..6) != Some(&[0xaa, 0xaa, 3, 0, 0, 0]) {
            return Err("native AP RFC1042 extent");
        }
        if body.get(6..8) == Some(&[0x88, 0x8e]) {
            let pdu = body.get(8..).ok_or("key reply extent")?;
            let key = KeyFrame::decode(pdu.get(4..).ok_or("key reply header")?, 16)
                .ok_or("key reply body")?;
            let pairwise = key.key_information == 0x30a;
            let candidate = if pairwise {
                let (anonce, replay) = self.pairwise_proposal.ok_or("unsolicited pairwise M2")?;
                let mut rsne = vec![48, 20];
                rsne.extend_from_slice(&narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body());
                if key.replay_counter != replay
                    || key.key_length != 0
                    || key.key_nonce == [0; 32]
                    || key.key_data != rsne
                {
                    return Err("pairwise rekey M2 identity/RSNE");
                }
                // The original MPDU above was opened with the OLD TK. M2's
                // EAPOL MIC instead belongs to the candidate PTK derived from
                // the actual replacement M1 and returned SNonce.
                Some(narf_wireless::eapol::wpa_pmk_to_ptk(
                    KeyMgmt::Psk,
                    &PMK,
                    &AP,
                    &self.plan.station,
                    &anonce,
                    &key.key_nonce,
                    16,
                ))
            } else {
                if key.key_information != 0x302 || key.replay_counter != 3 {
                    return Err("group reply key identity");
                }
                None
            };
            let mut check = pdu.to_vec();
            let mic = check.get(81..97).ok_or("group reply MIC extent")?.to_vec();
            check[81..97].fill(0);
            if mic
                != narf_crypto::pbkdf2_sha1::hmac_sha1(
                    &candidate
                        .as_ref()
                        .or(self.ptk.as_ref())
                        .ok_or("key reply PTK")?
                        .kck,
                    &check,
                )[..16]
            {
                return Err("key reply MIC");
            }
            if pairwise {
                let mut ethernet = self.plan.bssid.to_vec();
                ethernet.extend_from_slice(&self.plan.station);
                ethernet.extend_from_slice(&body[6..]);
                self.uplink.push(ethernet);
                self.pairwise_replies += 1;
                return Ok((Vec::new(), false)); // Deliberately withhold M3.
            }
            self.group_replies += 1;
            return Ok((Vec::new(), self.hold_group));
        }
        if (h == 26) != self.ht_active {
            return Err("native AP negotiated DATA QoS");
        }
        let mut ethernet = frame[16..22].to_vec();
        ethernet.extend_from_slice(&frame[10..16]);
        ethernet.extend_from_slice(&body[6..]);
        self.uplink.push(ethernet.clone());
        let replies = match self.server.receive(&ethernet) {
            Some(reply) => vec![self.downlink(&reply)?],
            None => Vec::new(),
        };
        Ok((replies, self.hold_data))
    }
    pub(in crate::ath9k) fn beacon(&self) -> Vec<u8> {
        let mut b = self.ap.beacon();
        if let Some(ht) = &self.ht {
            b.extend_from_slice(ht);
        }
        b
    }
    pub(in crate::ath9k) fn pairwise_rekey(&mut self) -> Vec<u8> {
        let mut m1 = KeyFrame::empty(16);
        m1.key_information = 0x8a;
        m1.key_length = 16;
        m1.replay_counter = 3;
        m1.key_nonce = [0xbb; 32];
        let mut ethernet = self.plan.station.to_vec();
        ethernet.extend_from_slice(&AP);
        ethernet.extend_from_slice(&[0x88, 0x8e]);
        ethernet.extend_from_slice(&m1.into_eapol());
        self.pairwise_proposal = Some(([0xbb; 32], 3));
        self.downlink(&ethernet).unwrap()
    }
    pub(in crate::ath9k) fn group_rekey(&mut self) -> Vec<u8> {
        let ptk = self.ptk.as_ref().unwrap();
        let mut clear = vec![48, 20];
        clear.extend_from_slice(&narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body());
        clear.extend_from_slice(&[221, 22, 0, 0x0f, 0xac, 1, 2, 0]);
        clear.extend_from_slice(&[0x66; 16]);
        if clear.len() % 8 != 0 {
            clear.push(221);
        }
        while clear.len() % 8 != 0 {
            clear.push(0);
        }
        let mut key = KeyFrame::empty(16);
        key.key_information = 0x1382;
        key.key_length = 16;
        key.replay_counter = 3;
        key.key_data =
            narf_crypto::aes_kw::aes_wrap(ptk.kek.as_slice().try_into().unwrap(), &clear).unwrap();
        let mut pdu = key.into_eapol();
        pdu[0] = 2;
        let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(&ptk.kck, &pdu);
        pdu[81..97].copy_from_slice(&mic[..16]);
        let mut eth = self.plan.station.to_vec();
        eth.extend_from_slice(&AP);
        eth.extend_from_slice(&[0x88, 0x8e]);
        eth.extend_from_slice(&pdu);
        self.downlink(&eth).unwrap()
    }
}

pub(in crate::ath9k) type TestRadio = Radio<Arc<Model>, Arc<Env>>;
pub(in crate::ath9k) struct Fixture {
    pub radio: TestRadio,
    pub model: Arc<Model>,
    pub peer: Arc<IrqSafeSpinLock<Peer>>,
    pub env: Arc<Env>,
    pub plan: NetworkPlan,
}
pub(in crate::ath9k) fn open_qos_start(f: &mut Fixture, sequence: u16) {
    assert!(!f.peer.lock().ap.protected() && sequence < 4096 && f.radio.phase() == Phase::Passive);
    f.radio.qos_sequence[0] = sequence;
}
pub(in crate::ath9k) fn fixture(protected: bool) -> Result<Fixture, &'static str> {
    fixture_rates(protected, None)
}
pub(in crate::ath9k) fn fixture_rates(
    protected: bool,
    rates: Option<&[u8]>,
) -> Result<Fixture, &'static str> {
    fixture_inner(protected, rates, None)
}
pub(in crate::ath9k) fn fixture_ht(protected: bool, mcs: u8) -> Result<Fixture, &'static str> {
    let elements = crate::ath9k::ht::tests::elements();
    fixture_inner(protected, None, Some((mcs, elements, None)))
}
pub(in crate::ath9k) fn fixture_ht_stbc(
    protected: bool,
    offer_tx_stbc: bool,
    response_tx_stbc: bool,
) -> Result<Fixture, &'static str> {
    let mut offer = crate::ath9k::ht::tests::elements();
    let mut response = offer.clone();
    if offer_tx_stbc {
        offer[2] |= 0x80;
    }
    if response_tx_stbc {
        response[2] |= 0x80;
    }
    fixture_ht_profile(protected, offer, response)
}
pub(in crate::ath9k) fn fixture_ht_profile(
    protected: bool,
    offer: Vec<u8>,
    response: Vec<u8>,
) -> Result<Fixture, &'static str> {
    fixture_inner(protected, None, Some((255, offer, Some(response))))
}
fn fixture_inner(
    protected: bool,
    rates: Option<&[u8]>,
    ht: Option<(u8, Vec<u8>, Option<Vec<u8>>)>,
) -> Result<Fixture, &'static str> {
    let model = Model::new();
    let peer = Arc::new(IrqSafeSpinLock::new(Peer::new_rates(protected, rates)));
    if let Some((mask, offer, response)) = ht {
        crate::ath9k::ht::tests::qualify(&model, mask)?;
        peer.lock().ht = Some(offer);
        peer.lock().ht_response = response;
    }
    let plan = peer.lock().plan;
    let reacting = peer.clone();
    *model.reaction.borrow_mut() = Some(Arc::new(move |bytes| {
        reacting
            .lock()
            .react(bytes)
            .map_err(|_| packet::Error::Packet)
    }));
    let env = Arc::new(Env {
        now: AtomicU64::new(0),
        entropy: AtomicBool::new(true),
    });
    // SAFETY: isolated parked device model. No physical controller or calibration authority is substituted.
    let packet = unsafe { Packet::prepare(model.clone(), OWN) }.map_err(|_| "packet prepare")?;
    let mut radio = Radio::new(packet, OWN, -118, env.clone());
    radio.start().map_err(|_| "radio start")?;
    let beacon = { peer.lock().beacon() };
    model.inject(&beacon, 0).map_err(|_| "beacon")?;
    radio.poll().map_err(|_| "scan poll")?;
    Ok(Fixture {
        radio,
        model,
        peer,
        env,
        plan,
    })
}
pub(in crate::ath9k) fn complete<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..20000 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("AR9285 station fixture stalled");
}
fn conversation() -> Result<(), &'static str> {
    for protected in [false, true] {
        let mut f = fixture(protected)?;
        complete(
            f.radio
                .associate(AP, SSID, protected.then(|| Zeroizing::new(PMK)), &[]),
        )
        .map_err(|_| "native association")?;
        if f.radio.peer() != Some(AP)
            || !f.radio.ready()
            || f.peer.lock().ap.phase() != ApPhase::Authorized
        {
            return Err("native station not authorized");
        }
        let outbound = udp_ipv4(
            f.plan.bssid,
            f.plan.station,
            f.plan.lease_ip,
            f.plan.server_ip,
            4001,
            4002,
            b"AR9285 uplink",
        );
        f.radio.send(&outbound).map_err(|_| "native send")?;
        f.radio.poll().map_err(|_| "native delivery")?;
        if f.peer.lock().uplink.last() != Some(&outbound) {
            return Err("exact native uplink bytes");
        }
        let inbound = udp_ipv4(
            f.plan.station,
            f.plan.bssid,
            f.plan.server_ip,
            f.plan.lease_ip,
            4002,
            4001,
            b"AR9285 downlink",
        );
        let wire = f.peer.lock().downlink(&inbound)?;
        f.model.inject(&wire, 0).map_err(|_| "native RX")?;
        if f.radio.poll().map_err(|_| "RX progress")? != vec![inbound] {
            return Err("exact native downlink bytes");
        }
        f.radio.stop().map_err(|_| "terminal stop")?;
        if f.radio.peer().is_some() || f.radio.send(&outbound) != Err(Error::Busy) {
            return Err("closed radio reopened");
        }
    }
    Ok(())
}

fn smoke_ar9285_native_rate_feedback_binds_exact_dma_and_peer_subset() -> TestResult {
    const RATES: &[u8] = &[0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    for protected in [false, true] {
        let mut f = fixture_rates(protected, Some(RATES)).unwrap();
        if complete(
            f.radio
                .associate(AP, SSID, protected.then(|| Zeroizing::new(PMK)), &[]),
        )
        .is_err()
        {
            return TestResult::Fail("rich-rate native association");
        }
        let ethernet = udp_ipv4(
            AP,
            f.plan.station,
            f.plan.lease_ip,
            f.plan.server_ip,
            4001,
            4002,
            b"native MRR receipt",
        );
        f.peer.lock().hold_data = true;
        if f.radio.send(&ethernet).is_err() {
            return TestResult::Fail("native rich-rate DATA send");
        }
        let descriptor = f.model.tx.get().unwrap();
        if f.model.word(descriptor + 16) != Ok(0x22248000)
            || f.model.word(descriptor + 20) != Ok(0x090d080c)
            || f.peer.lock().uplink.last() != Some(&ethernet)
        {
            return TestResult::Fail(
                "actual DMA retry chain or independently decrypted peer payload",
            );
        }
        let before = f.radio.rates.unwrap().series();
        if f.radio.poll().is_err() || f.radio.rates.unwrap().series() != before {
            return TestResult::Fail("pending native DATA trained rate policy");
        }
        f.model.complete(true).unwrap();
        f.model.put(descriptor + 92, 1 | (2 << 21)).unwrap();
        if f.radio.poll().is_err() || f.radio.rates.unwrap().series().rates[0] != 9 {
            return TestResult::Fail("actual native terminal fallback was ignored");
        }
        f.peer.lock().hold_data = false;
        for _ in 0..8 {
            if f.radio.send(&ethernet).is_err() || f.radio.poll().is_err() {
                return TestResult::Fail("real native clean DATA receipts");
            }
        }
        if f.radio.rates.unwrap().series().rates[0] != 10 {
            return TestResult::Fail("native clean receipts did not recover bitrate");
        }
        f.peer.lock().hold_data = true;
        if f.radio.send(&ethernet).is_err() {
            return TestResult::Fail("held rate publication");
        }
        let descriptor = f.model.tx.get().unwrap();
        f.model.complete(true).unwrap();
        // Disabled/foreign rate series cannot free/reopen the packet owner.
        f.model.put(descriptor + 16, 0x00048000).unwrap();
        if f.radio.poll().is_ok() || f.radio.phase() != Phase::Failed || f.radio.peer().is_some() {
            return TestResult::Fail("changed native retry descriptor revived station");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rates",
    smoke_ar9285_native_rate_feedback_binds_exact_dma_and_peer_subset
);

fn smoke_ar9285_active_probes_exact_native_dma_and_probe_cache_open_wpa2() -> TestResult {
    for protected in [false, true] {
        let mut f = fixture(protected).unwrap();
        let names = vec![SSID.to_vec(), Vec::new()];
        let result = complete(f.radio.active_scan_for(20, &names));
        if !matches!(result, Ok(ref bss) if bss.len() == 1 && bss[0].bss.information_elements[0] == 0)
            || f.radio.peer().is_some()
            || f.radio.ready()
        {
            return TestResult::Fail("active probe cache granted a peer or lost bounded BSS");
        }
        let sent = f.model.transmitted.borrow();
        if sent.len() != 2 {
            return TestResult::Fail("active names were not two exact native probes");
        }
        let mut expected = vec![0x40, 0, 0, 0];
        expected.extend_from_slice(&[255; 6]);
        expected.extend_from_slice(&OWN);
        expected.extend_from_slice(&[255; 6]);
        expected.extend_from_slice(&[0x10, 0, 0, SSID.len() as u8]);
        expected.extend_from_slice(SSID);
        expected.extend_from_slice(&[
            1, 4, 0x82, 0x84, 0x8b, 0x96, 50, 8, 12, 18, 24, 36, 48, 72, 96, 108, 3, 1, 1,
        ]);
        if sent[0] != expected || sent[1][22..26] != [0x20, 0, 0, 0] {
            return TestResult::Fail(
                "active probe DMA changed identity, sequence, name or rate IEs",
            );
        }
        drop(sent);
        if complete(
            f.radio
                .associate(AP, SSID, protected.then(|| Zeroizing::new(PMK)), &[]),
        )
        .is_err()
            || !f.radio.ready()
            || f.peer.lock().ap.phase() != ApPhase::Authorized
        {
            return TestResult::Fail("active cache did not enter native Open/WPA2 association");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/active-scan",
    smoke_ar9285_active_probes_exact_native_dma_and_probe_cache_open_wpa2
);

fn smoke_ar9285_active_probe_ssid_bounds_preflight_preserves_owner() -> TestResult {
    let mut f = fixture(false).unwrap();
    let before = f.model.count.get();
    for names in [vec![vec![0; 33]], vec![Vec::new(); 5]] {
        if !matches!(
            complete(f.radio.active_scan_for(20, &names)),
            Err(Error::Profile)
        ) {
            return TestResult::Fail("active SSID bound was not checked before publication");
        }
    }
    if f.model.count.get() != before
        || f.radio.phase() != Phase::Passive
        || f.radio.candidates().len() != 1
    {
        return TestResult::Fail("denied active preflight changed native owner or cache");
    }
    let names = vec![vec![0x80; 32], SSID.to_vec(), Vec::new(), vec![0; 32]];
    if !matches!(complete(f.radio.active_scan_for(20, &names)), Ok(ref bss) if bss.len() == 1)
        || f.model.transmitted.borrow().len() != 4
    {
        return TestResult::Fail(
            "four directed/wildcard binary probes failed native SSID encoding",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/active-scan",
    smoke_ar9285_active_probe_ssid_bounds_preflight_preserves_owner
);

fn smoke_ar9285_active_probe_cancel_and_late_receipt_never_reopen() -> TestResult {
    let mut f = fixture(false).unwrap();
    let peer = f.peer.clone();
    *f.model.reaction.borrow_mut() = Some(Arc::new(move |frame| {
        let (replies, _) = peer
            .lock()
            .react(frame)
            .map_err(|_| packet::Error::Packet)?;
        Ok((replies, true))
    }));
    let names = vec![SSID.to_vec()];
    {
        let mut scan = core::pin::pin!(f.radio.active_scan_for(20, &names));
        let mut cx = Context::from_waker(Waker::noop());
        if !scan.as_mut().poll(&mut cx).is_pending() {
            return TestResult::Fail(
                "active native cancellation never retained a pending descriptor",
            );
        }
    }
    let regions = f.model.regions.borrow().len();
    if f.model.tx.get().is_none()
        || f.radio.phase() != Phase::Failed
        || !f.radio.candidates().is_empty()
    {
        return TestResult::Fail("cancelled active probe exposed BSS or lost pending native owner");
    }
    f.model.complete(true).unwrap();
    if f.radio.poll().is_ok()
        || f.radio.peer().is_some()
        || f.model.regions.borrow().len() != regions
        || complete(f.radio.scan_for(1)).is_ok()
    {
        return TestResult::Fail("late broadcast completion reopened cancelled scan or freed DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/active-scan",
    smoke_ar9285_active_probe_cancel_and_late_receipt_never_reopen
);

fn smoke_ar9285_active_probe_live_policy_loss_and_failed_receipt_are_terminal() -> TestResult {
    for policy_loss in [false, true] {
        let mut f = fixture(false).unwrap();
        let peer = f.peer.clone();
        *f.model.reaction.borrow_mut() = Some(Arc::new(move |frame| {
            let (replies, _) = peer
                .lock()
                .react(frame)
                .map_err(|_| packet::Error::Packet)?;
            Ok((replies, true))
        }));
        let names = vec![SSID.to_vec()];
        let result = {
            let mut scan = core::pin::pin!(f.radio.active_scan_for(20, &names));
            let mut cx = Context::from_waker(Waker::noop());
            if !scan.as_mut().poll(&mut cx).is_pending() {
                return TestResult::Fail("probe failure fixture never suspended");
            }
            if policy_loss {
                f.model.allowed.set(false);
            } else {
                let descriptor = f.model.tx.get().unwrap();
                f.model.complete(false).unwrap();
                // A broadcast has no ACK: FrameOK=0 alone is legitimate.
                // Inject native FIFO underrun to supply an actual failed TX.
                f.model.put(descriptor + 60, 1 << 16).unwrap();
            }
            complete(scan.as_mut())
        };
        f.model.allowed.set(true);
        if result.is_ok()
            || f.radio.phase() != Phase::Failed
            || !f.radio.candidates().is_empty()
            || complete(f.radio.scan_for(1)).is_ok()
        {
            return TestResult::Fail(
                "active policy/TX failure was ignored or later reopened owner",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/active-scan",
    smoke_ar9285_active_probe_live_policy_loss_and_failed_receipt_are_terminal
);
fn held_m4() -> Result<(), &'static str> {
    let mut f = fixture(true)?;
    f.peer.lock().hold_m4 = true;
    let closed = f.radio.closed();
    {
        let mut future =
            core::pin::pin!(f.radio.associate(AP, SSID, Some(Zeroizing::new(PMK)), &[]));
        let mut cx = Context::from_waker(Waker::noop());
        let mut saw = false;
        for _ in 0..1000 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return Err("held M4 completed association");
            }
            if f.peer.lock().ap.phase() == ApPhase::Authorized && f.model.tx.get().is_some() {
                saw = true;
                break;
            }
        }
        if !saw {
            return Err("native M4 was never published");
        }
    }
    if !closed.load(Ordering::Acquire) || f.radio.peer().is_some() || f.radio.ready() {
        return Err("cancelled M4 opened controlled port");
    }
    f.model.complete(true).map_err(|_| "late M4 receipt")?;
    if f.radio.poll().is_ok() || f.radio.peer().is_some() || f.model.master.get() {
        return Err("late M4 reauthorized or DMA remained active");
    }
    Ok(())
}
fn smoke_ar9285_native_station_open_wpa2_and_exact_bidirectional_ip() -> TestResult {
    match conversation() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
fn smoke_ar9285_held_native_m4_drop_and_late_receipt_stay_terminal() -> TestResult {
    match held_m4() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/station",
    smoke_ar9285_native_station_open_wpa2_and_exact_bidirectional_ip
);
kernel_test_in!(
    "drivers/wireless/ath9k/station",
    smoke_ar9285_held_native_m4_drop_and_late_receipt_stay_terminal
);
fn smoke_ar9285_open_ht_native_qos_sequence_wrap_is_independent_of_legacy_control() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    let mut f = fixture_ht(false, 255).unwrap();
    complete(f.radio.associate(AP, SSID, None, &[])).unwrap();
    f.radio.qos_sequence[0] = 4095;
    let ethernet = udp_ipv4(
        AP,
        f.plan.station,
        f.plan.lease_ip,
        f.plan.server_ip,
        4001,
        4002,
        b"native QoS sequence domain",
    );
    f.radio.send(&ethernet).unwrap();
    f.radio.poll().unwrap();
    if f.model.transmitted.borrow().last().unwrap()[22..24] != [0xf0, 0xff] {
        return TestResult::Fail("native Open QoS frame did not use its own sequence counter");
    }
    let request = crate::ath9k::rx_ba::tests::addba(3, 1, 64, 0, false);
    f.model.inject(&request, 0).unwrap();
    f.radio.poll().unwrap();
    f.radio.poll().unwrap();
    if f.peer.lock().declines.len() != 1 {
        return TestResult::Fail("native legacy management response missing between DATA frames");
    }
    f.radio.send(&ethernet).unwrap();
    f.radio.poll().unwrap();
    if f.model.transmitted.borrow().last().unwrap()[22..24] != [0, 0] {
        return TestResult::Fail(
            "legacy native control reply consumed/reset the QoS sequence space",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_open_ht_native_qos_sequence_wrap_is_independent_of_legacy_control
);
