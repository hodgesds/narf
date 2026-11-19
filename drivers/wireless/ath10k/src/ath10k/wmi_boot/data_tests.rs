//! Firmware-side RAW packet conversation over actual HTT TX/RX DMA storage.
use super::*;
use alloc::boxed::Box;
use narf_wifi_fixtures::{udp_ipv4, ApPhase, DhcpServer, FakeAp, NetworkPlan};
use narf_wireless::eapol::{KeyFrame, KeyMgmt, Ptk};
const OWN: [u8; 6] = [2, 3, 4, 5, 6, 7];
const AP: [u8; 6] = [2, 8, 9, 10, 11, 12];
const PMK: [u8; 32] = [0x55; 32];
const ANONCE: [u8; 32] = [0xaa; 32];
// IEEE WMM Parameter IE: BE/BK/VI/VO, no U-APSD/ACM. Native expected
// TXOP values below are independently authored in microseconds (Linux
// mac.c::ath10k_conf_tx multiplies the IEEE32-us value by32).
const WMM_PARAMETERS: [u8; 26] = [
    221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 94, 0,
    0x62, 0x32, 47, 0,
];
const WMM_WORDS: [u32; 24] = [
    15, 1023, 3, 0, 0, 0, 15, 1023, 7, 0, 0, 0, 7, 15, 2, 3008, 0, 0, 3, 7, 2, 1504, 0, 0,
];
type TestPolicy =
    alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<Option<narf_wireless::reg::RegulatoryDomain>>>;
fn network() -> NetworkPlan {
    NetworkPlan {
        station: OWN,
        bssid: AP,
        server_ip: [10, 77, 0, 1],
        lease_ip: [10, 77, 0, 42],
        netmask: [255, 255, 255, 0],
        lease_seconds: 3600,
    }
}
struct Ccm;
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
pub(super) struct Fixture {
    pub(super) automatic: bool,
    control_phase: u8,
    group_replies: usize,
    pfc_responses: Vec<Vec<u8>>,
    server: DhcpServer,
    ap: FakeAp,
    ptk: Option<Ptk>,
    queue: VecDeque<Vec<u8>>,
    uplink: Vec<Vec<u8>>,
    held: VecDeque<u16>,
    pn: u64,
    /// Opt-in native AP QoS sequence owner for composed receive BA traffic.
    receive_sequence: Option<u16>,
    replay: narf_wireless::ccmp::ReplayWindow,
    hold_m4: bool,
    m4_before_receipt: Option<Vec<u8>>,
    m4_descriptor: Option<(u8, u8, u32, u32)>,
    m4_ba_window: Option<u8>,
    deferred_receipt: Option<(u16, u8)>,
    hold_data: bool,
    stall_ce: bool,
    status: u8,
    next_decap: u32,
    next_attention: u32,
    next_peer: Option<u16>,
    next_tid: Option<u8>,
    wmm_offer: Option<Vec<u8>>,
    wmm_response: Option<Vec<u8>>,
    ht_offer: Option<Vec<u8>>,
    pub(super) ht_expected: bool,
    pub(super) ht_secondary: Option<u16>,
    pub(super) ht_inventory: usize,
    pub(super) ht_inventory_hold: bool,
    protection_trace: Vec<(u32, u32)>,
    protection_request: Option<radio::StationProtection>,
    protection_hold: Option<usize>,
    protection_change_at: usize,
    protection_revoke:
        Option<narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>>,
    protection_policy: Option<TestPolicy>,
    protection_delay: u8,
    ht_response: Option<Vec<u8>>,
    ht_mcs: u8,
    pub(super) ht_mcs_more: [u8; 3],
    pub(super) ht_peer_nss: u32,
    ht_sgi: bool,
    ht_request_sgi: bool,
    pub(super) ht_request_sgi40: bool,
    pub(super) ht_request_nss: u8,
    ht_ampdu: u8,
    pub(super) ht_capabilities: u16,
    // Source-cited coding bits beyond the base request IE: IEEE LDPC 0x0001
    // and one-stream RX STBC 0x0100; native PEER_LDPC/PEER_STBC flags and
    // WMI_RC_TX_STBC_FLAG expected in PEER_ASSOC.
    pub(super) ht_request_coding: u16,
    pub(super) ht_peer_flags: u32,
    pub(super) ht_rate_caps: u32,
    /// Boxed VHT expectations (stack: the composed tests sit near the
    /// aarch64 kernel-test stack limit).
    pub(super) vht: Option<Box<VhtExpect>>,
    /// Robust management frames the host sent after authorization (SA
    /// Query responses, the PMF teardown deauthentication).
    pub(super) management_tx: Vec<Vec<u8>>,
    pub(super) rx_phy: Option<(u8, u32, u32)>,
    // Authored native descriptors per actual DMA frame, including invalid
    // stale middle PHY words that the host must never reinterpret.
    rx_descriptors: VecDeque<(u8, u8, u32, u32)>,
    wmm_words: [u32; 24],
    wmm_sent: usize,
    wmm_hold: bool,
    wmm_fail: bool,
    wmm_policy: Option<TestPolicy>,
    qos_frames: usize,
    /// Replay counter of the AP's next group-key handshake request.
    group_replay: u64,
    /// Firmware key cache of the hardware-key profile (Linux `cryptmode=0`).
    pub(super) hw: Option<Box<HwKeyCache>>,
    /// Native-WiFi decap firmware (INIT `rx_decap_mode` 1): data TX arrives
    /// as native-WiFi MSDUs, decryptable data RX leaves as native-WiFi
    /// MSDUs with the original header in `rx_hdr_status`.
    pub(super) native_wifi: bool,
    /// The firmware's own pairwise TX PN under native WiFi.
    pub(super) native_pn: u64,
    /// Native-WiFi MSDUs transmitted / delivered.
    pub(super) native_tx: usize,
    pub(super) native_rx: usize,
}
/// Source-derived VHT expectations: the exact association-request VHT
/// Capabilities body and the native PEER_ASSOC/VDEV_START VHT words.
#[derive(Clone, Copy)]
pub(super) struct VhtExpect {
    /// 0 = VHT20, 1 = VHT40, 2 = VHT80 (the AP-selected bandwidth).
    pub(super) width: u8,
    pub(super) center2: Option<u16>,
    pub(super) wide_override: u32,
    pub(super) half_dbm: u8,
    pub(super) request: [u8; 12],
    pub(super) capabilities: u32,
    pub(super) rates: [u32; 4],
    pub(super) max_mpdu: u32,
}
impl core::fmt::Debug for Fixture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeDataFirmware")
            .field("phase", &self.ap.phase())
            .finish_non_exhaustive()
    }
}
impl Fixture {
    fn new(secured: bool) -> Self {
        Self::on_channel(secured, 1)
    }
    fn on_channel(secured: bool, channel: u8) -> Self {
        let ap = if secured {
            FakeAp::wpa2(network(), b"narf", channel, 7, PMK, ANONCE)
        } else {
            FakeAp::open(network(), b"narf", channel, 7)
        }
        .unwrap();
        Self {
            automatic: false,
            control_phase: 0,
            wmm_offer: None,
            wmm_response: None,
            ht_offer: None,
            ht_expected: false,
            ht_secondary: None,
            ht_inventory: 0,
            ht_inventory_hold: false,
            protection_trace: Vec::new(),
            protection_request: None,
            protection_hold: None,
            protection_change_at: 0,
            protection_revoke: None,
            protection_policy: None,
            protection_delay: 0,
            ht_response: None,
            ht_mcs: 0xff,
            ht_mcs_more: [0; 3],
            ht_peer_nss: 1,
            ht_sgi: true,
            ht_request_sgi: true,
            ht_request_sgi40: false,
            ht_request_nss: 2,
            ht_ampdu: 0x1b,
            ht_capabilities: 0x002c,
            ht_request_coding: 0,
            ht_peer_flags: 0,
            ht_rate_caps: 0,
            vht: None,
            management_tx: Vec::new(),
            rx_phy: None,
            rx_descriptors: VecDeque::new(),
            wmm_words: WMM_WORDS,
            wmm_sent: 0,
            wmm_hold: false,
            wmm_fail: false,
            wmm_policy: None,
            qos_frames: 0,
            group_replay: 3,
            hw: None,
            native_wifi: false,
            native_pn: 0,
            native_tx: 0,
            native_rx: 0,
            group_replies: 0,
            pfc_responses: Vec::new(),
            server: DhcpServer::new(network()),
            ap,
            ptk: None,
            queue: VecDeque::new(),
            uplink: Vec::new(),
            held: VecDeque::new(),
            pn: 1,
            receive_sequence: None,
            replay: narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 },
            hold_m4: false,
            m4_before_receipt: None,
            m4_descriptor: None,
            m4_ba_window: None,
            deferred_receipt: None,
            hold_data: false,
            stall_ce: false,
            status: 0,
            next_decap: 0,
            next_attention: 0,
            next_peer: None,
            next_tid: None,
        }
    }
    pub(super) fn beacon(&self) -> Vec<u8> {
        let mut frame = self.ap.beacon();
        if let Some(wmm) = &self.wmm_offer {
            frame.extend_from_slice(wmm);
        }
        if let Some(ht) = &self.ht_offer {
            frame.extend_from_slice(ht);
        }
        frame
    }
    fn qos(&self) -> bool {
        self.wmm_offer.is_some() && self.wmm_response.is_some()
    }
    fn react(&mut self, frame: &[u8]) -> Result<bool, BmiError> {
        if self.ap.phase() != ApPhase::Authorized {
            let phase = self.ap.phase();
            let replies = self.ap.receive(frame).map_err(|_| BmiError::BadResponse)?;
            if phase == ApPhase::Message2 {
                let m2 = KeyFrame::decode(frame.get(36..).ok_or(BmiError::BadResponse)?, 16)
                    .ok_or(BmiError::BadResponse)?;
                self.ptk = Some(narf_wireless::eapol::wpa_pmk_to_ptk(
                    KeyMgmt::Psk,
                    &PMK,
                    &AP,
                    &OWN,
                    &ANONCE,
                    &m2.key_nonce,
                    16,
                ));
            }
            self.queue.extend(replies.into_iter().filter(|f| f[0] == 8));
            return Ok(phase == ApPhase::Message4);
        }
        if frame.len() < 32
            || !matches!(frame[0], 8 | 0x88)
            || frame[1] != if self.ap.protected() { 0x41 } else { 1 }
            || frame[4..10] != AP
            || frame[10..16] != OWN
        {
            return Err(BmiError::BadResponse);
        }
        let header = if frame[0] == 0x88 { 26 } else { 24 };
        if header == 26 && frame.get(24..26) != Some(&[0, 0]) {
            return Err(BmiError::BadResponse);
        }
        let mut body = frame.get(header..).ok_or(BmiError::BadResponse)?.to_vec();
        if self.ap.protected() {
            // The AP's own PTK (PSK, PSK-SHA256 or SAE derivation).
            let tk = self.ap.pairwise_tk().ok_or(BmiError::BadResponse)?;
            body = narf_wireless::ccmp::unprotect(
                &Ccm,
                &frame[..header],
                &tk,
                0,
                false,
                &mut self.replay,
                &mut body,
            )
            .map_err(|_| BmiError::BadResponse)?;
        }
        if body.get(..6) != Some(&[0xaa, 0xaa, 3, 0, 0, 0]) {
            return Err(BmiError::BadResponse);
        }
        if body.get(6..8) == Some(&[0x88, 0x8e]) {
            let pdu = body.get(8..).ok_or(BmiError::BadResponse)?;
            let key = KeyFrame::decode(pdu.get(4..).ok_or(BmiError::BadResponse)?, 16)
                .ok_or(BmiError::BadResponse)?;
            if key.key_information != 0x302 || key.replay_counter != self.group_replay {
                return Err(BmiError::BadResponse);
            }
            let mut checked = pdu.to_vec();
            let mic = checked.get(81..97).ok_or(BmiError::BadResponse)?.to_vec();
            checked[81..97].fill(0);
            if mic
                != narf_crypto::pbkdf2_sha1::hmac_sha1(
                    &self.ptk.as_ref().ok_or(BmiError::BadResponse)?.kck,
                    &checked,
                )[..16]
            {
                return Err(BmiError::BadResponse);
            }
            self.group_replies += 1;
            return Ok(false);
        }
        let mut ethernet = frame[16..22].to_vec();
        if (frame[0] == 0x88) != self.qos() {
            return Err(BmiError::BadResponse);
        }
        self.qos_frames += usize::from(frame[0] == 0x88);
        ethernet.extend_from_slice(&frame[10..16]);
        ethernet.extend_from_slice(&body[6..]);
        self.uplink.push(ethernet.clone());
        if let Some(reply) = self.server.receive(&ethernet) {
            let frame = self.downlink(&reply);
            self.queue.push_back(frame);
        }
        Ok(false)
    }
    fn downlink(&mut self, ethernet: &[u8]) -> Vec<u8> {
        let qos = self.qos() && ethernet[12..14] != [0x88, 0x8e];
        let mut frame = vec![
            if qos { 0x88 } else { 8 },
            if self.ap.protected() { 0x42 } else { 2 },
            0,
            0,
        ];
        frame.extend_from_slice(&ethernet[..6]);
        frame.extend_from_slice(&AP);
        frame.extend_from_slice(&ethernet[6..12]);
        let sequence = if qos {
            self.receive_sequence.as_mut().map_or(0, |sequence| {
                let current = *sequence;
                *sequence = (*sequence + 1) & 4095;
                current
            })
        } else {
            0
        };
        frame.extend_from_slice(&(sequence << 4).to_le_bytes());
        if qos {
            frame.extend_from_slice(&[0, 0]);
        }
        let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0];
        body.extend_from_slice(&ethernet[12..]);
        if self.ap.protected() {
            let tk = self.ap.pairwise_tk().unwrap();
            body = narf_wireless::ccmp::protect(&Ccm, &frame, &tk, self.pn, 0, 0, false, &mut body)
                .unwrap();
            self.pn += 1;
        }
        frame.extend_from_slice(&body);
        frame
    }
    fn group_rekey(&mut self) -> Vec<u8> {
        self.group_rekey_with(2, [0x66; 16])
    }
    /// A group-key handshake request delivering `gtk` under `key_id`, with
    /// the current `group_replay` counter.
    pub(super) fn group_rekey_with(&mut self, key_id: u8, gtk: [u8; 16]) -> Vec<u8> {
        let ptk = self.ptk.as_ref().unwrap();
        let mut clear = vec![48, 20];
        clear.extend_from_slice(&narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body());
        clear.extend_from_slice(&[0xdd, 22, 0, 0x0f, 0xac, 1, key_id, 0]);
        clear.extend_from_slice(&gtk);
        if clear.len() % 8 != 0 {
            clear.push(0xdd);
        }
        while clear.len() % 8 != 0 {
            clear.push(0);
        }
        let mut key = KeyFrame::empty(16);
        key.key_information = 0x1382;
        key.key_length = 16;
        key.replay_counter = self.group_replay;
        key.key_data =
            narf_crypto::aes_kw::aes_wrap(ptk.kek.as_slice().try_into().unwrap(), &clear).unwrap();
        let mut pdu = key.into_eapol();
        pdu[0] = 2;
        let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(&ptk.kck, &pdu);
        pdu[81..97].copy_from_slice(&mic[..16]);
        let mut ethernet = OWN.to_vec();
        ethernet.extend_from_slice(&AP);
        ethernet.extend_from_slice(&[0x88, 0x8e]);
        ethernet.extend_from_slice(&pdu);
        self.downlink(&ethernet)
    }
}
pub(super) async fn control(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let dialect = m.inner.inner.dialect;
    let command = &bytes[8..];
    let word = |at: usize| u32::from_le_bytes(command[at..at + 4].try_into().unwrap());
    let native_phase = m.data.as_ref().unwrap().control_phase;
    let qos = m.data.as_ref().unwrap().qos();
    let wmm_id: u32 = match dialect {
        Dialect::Main | Dialect::Tlv => 0x4006,
        Dialect::TenOne | Dialect::TenTwo | Dialect::TenTwoFour => 0x9009,
        Dialect::TenFour => 0x900b,
    };
    // After VDEV_UP (qos phase 5), only a beacon-driven ath10k_conf_tx
    // reprogramming is accepted, without advancing the association script.
    let late_wmm = qos && native_phase >= 5 && word(0) == wmm_id;
    let is_wmm = qos && native_phase == 2 || late_wmm;
    let phase = native_phase - u8::from(qos && native_phase > 2);
    let mut replies = Vec::new();
    let mut advance = !late_wmm;
    if is_wmm {
        let f = m.data.as_mut().unwrap();
        let mut expected = wmm_id.to_le_bytes().to_vec();
        if dialect == Dialect::Tlv {
            expected.extend_from_slice(&[8, 0, 83, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        }
        for ac in f.wmm_words.chunks_exact(6) {
            if dialect == Dialect::Tlv {
                expected.extend_from_slice(&[24, 0, 84, 0]);
            }
            for word in ac {
                expected.extend_from_slice(&word.to_le_bytes());
            }
        }
        if command != expected {
            return Err(BmiError::BadResponse);
        }
        f.wmm_sent += 1;
    } else if phase < 2 {
        let expected = match dialect {
            Dialect::Main => 0x7006,
            Dialect::TenOne => 0x9028,
            Dialect::TenTwo | Dialect::TenTwoFour => 0x9029,
            Dialect::TenFour => 0x9031,
            Dialect::Tlv => 0x7008,
        };
        if word(0) != expected {
            return Err(BmiError::BadResponse);
        }
        let frame = mlme_tests::native_frame(m, command)?;
        // SAE Commits precede the Confirm that completes authentication.
        advance = frame.get(24..28) != Some(&[3, 0, 1, 0]);
        if phase == 1 && m.data.as_ref().unwrap().wmm_offer.is_some() {
            let expected = [221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0];
            if frame
                .windows(expected.len())
                .filter(|w| *w == expected)
                .count()
                != 1
            {
                return Err(BmiError::BadResponse);
            }
        }
        if phase == 1 && m.data.as_ref().unwrap().ht_expected {
            // The host owns this exact HT20/1SS IE; no production encoder
            // supplies the device model's expectation.
            let mut expected = vec![
                45,
                26,
                (if m.data.as_ref().unwrap().ht_request_sgi {
                    0x2c
                } else {
                    0x0c
                }) | if m.data.as_ref().unwrap().ht_secondary.is_some()
                    || m.data.as_ref().unwrap().vht.is_some()
                {
                    // VHT's local HT element always offers 20/40.
                    2
                } else {
                    0
                } | if m.data.as_ref().unwrap().ht_secondary.is_some()
                    && m.data.as_ref().unwrap().ht_request_sgi40
                {
                    0x40
                } else {
                    0
                } | m.data.as_ref().unwrap().ht_request_coding as u8,
                (m.data.as_ref().unwrap().ht_request_coding >> 8) as u8,
                24,
                0xff,
            ];
            expected.extend_from_slice(&[0; 11]);
            expected.push(1);
            expected.extend_from_slice(&[0; 10]);
            expected[5..5 + usize::from(m.data.as_ref().unwrap().ht_request_nss)].fill(255);
            if !frame.windows(expected.len()).any(|ie| ie == expected) {
                return Err(BmiError::BadResponse);
            }
        }
        if phase == 1 {
            // VHT Capabilities appears exactly when a VHT profile is bound.
            let mut ie = vec![191, 12];
            let expected = m.data.as_ref().unwrap().vht.as_ref().map(|v| v.request);
            ie.extend_from_slice(&expected.unwrap_or([0; 12]));
            let count = frame.windows(2).filter(|w| *w == [191, 12]).count();
            if expected.is_some() != (count == 1)
                || count > 1
                || expected.is_some() && !frame.windows(14).any(|w| w == ie)
            {
                return Err(BmiError::BadResponse);
            }
        }
        m.native_management.push(frame.clone());
        replies = m
            .data
            .as_mut()
            .unwrap()
            .ap
            .receive(&frame)
            .map_err(|_| BmiError::BadResponse)?;
        if phase == 1 {
            if let Some(parameters) = &m.data.as_ref().unwrap().wmm_response {
                replies[0].extend_from_slice(parameters);
            }
            if let Some(ht) = &m.data.as_ref().unwrap().ht_response {
                replies[0].extend_from_slice(ht);
            }
        }
        if dialect == Dialect::Tlv {
            let mut terminal = vec![16, 0, 0xa7, 1];
            terminal.extend_from_slice(&word(12).to_le_bytes());
            terminal.extend_from_slice(&[0; 12]);
            add_event(m, 0x7006, &terminal);
        }
    } else if phase == 2 {
        let (expected, size) = match dialect {
            Dialect::Main => (0x6005, 360),
            Dialect::TenOne => (0x9020, 352),
            Dialect::TenTwo | Dialect::TenTwoFour => (0x9020, 356),
            Dialect::TenFour => (0x9026, 360),
            Dialect::Tlv => (0x6005, 116),
        };
        let f = m.data.as_ref().unwrap();
        let ht = f.ht_expected;
        let masks = [
            f.ht_mcs,
            f.ht_mcs_more[0],
            f.ht_mcs_more[1],
            f.ht_mcs_more[2],
        ];
        let ht_rates: Vec<u8> = (0..32)
            .filter(|n| masks[usize::from(*n / 8)] & (1 << (n % 8)) != 0)
            .collect();
        let size = size
            + if ht && dialect == Dialect::Tlv {
                ht_rates.len().next_multiple_of(4)
            } else {
                0
            };
        let at = if dialect == Dialect::Tlv { 8 } else { 4 };
        let secured = m.data.as_ref().unwrap().ap.protected();
        if word(0) != expected
            || command.len() != size
            || command[at..at + 6] != AP
            || word(at + 12) != 1
            || word(at + 16) != 7
            || word(at + 20)
                != ((if secured { 5 } else { 1 })
                    | f.hw.as_ref().map_or(0, |h| h.pmf_flag)
                    | if qos { 2 } else { 0 }
                    | if ht { 0x1000 } else { 0 }
                    | if f.ht_secondary.is_some() { 0x2000 } else { 0 }
                    | if ht { f.ht_peer_flags } else { 0 }
                    | f.vht.as_ref().map_or(0, |v| {
                        0x0200_0000
                            | if v.width == 3 {
                                0x2000_0000
                            } else if v.width == 2 {
                                0x0400_0000
                            } else {
                                0
                            }
                    }))
            || word(at + 24) != (if secured { 0x11 } else { 1 })
            || word(at + if dialect == Dialect::Tlv { 48 } else { 320 })
                != if ht { f.ht_peer_nss } else { 1 }
        {
            return Err(BmiError::BadResponse);
        }
        // Native VHT words: peer_vht_caps and wmi_vht_rate_set (TLV: the
        // trailing tag-102 struct; others: the common-command tail).
        let (caps_at, rates_at) = if dialect == Dialect::Tlv {
            (at + 52, command.len() - 16)
        } else {
            (at + 324, at + 332)
        };
        let vht = f.vht.as_deref().copied();
        if word(caps_at) != vht.map_or(0, |v| v.capabilities)
            || (0..4).any(|i| word(rates_at + i * 4) != vht.map_or(0, |v| v.rates[i]))
        {
            return Err(BmiError::BadResponse);
        }
        if dialect == Dialect::TenFour && word(at + 352) != vht.map_or(0, |v| v.wide_override) {
            return Err(BmiError::BadResponse);
        }
        let count = at + if dialect == Dialect::Tlv { 68 } else { 48 };
        let rates = count + if dialect == Dialect::Tlv { 12 } else { 4 };
        let phy = at + if dialect == Dialect::Tlv { 56 } else { 328 };
        if word(count) != 3
            || command[rates..rates + 3] != [12, 24, 48]
            || word(phy)
                != if let Some(v) = f.vht.as_deref() {
                    if v.width == 3 {
                        14
                    } else {
                        8 + u32::from(v.width)
                    }
                } else if ht {
                    if f.ht_secondary.is_some() {
                        if m.frequency < 3000 {
                            7
                        } else {
                            6
                        }
                    } else if m.frequency < 3000 {
                        5
                    } else {
                        4
                    }
                } else {
                    u32::from(m.frequency < 3000)
                }
        {
            return Err(BmiError::BadResponse);
        }
        if ht {
            let ht_count = at + if dialect == Dialect::Tlv { 72 } else { 184 };
            let ht_at = if dialect == Dialect::Tlv {
                at + 88
            } else {
                at + 188
            };
            let density = [0, 1, 1, 1, 2, 4, 8, 16][usize::from((f.ht_ampdu >> 2) & 7)];
            if word(at + 32) != u32::from(f.ht_capabilities)
                || word(at + 36)
                    != f.vht
                        .as_ref()
                        .map_or((1 << (13 + (f.ht_ampdu & 3))) - 1, |v| v.max_mpdu)
                || word(at + 40) != density
                || word(at + 44)
                    != (if f.ht_sgi { 12 } else { 8 }
                        | if f.ht_secondary.is_some() { 2 } else { 0 }
                        | f.ht_rate_caps)
                || word(ht_count) != ht_rates.len() as u32
                || command.get(ht_at..ht_at + ht_rates.len()) != Some(&ht_rates)
            {
                return Err(BmiError::BadResponse);
            }
        }
    } else if phase == 3 {
        let expected = match dialect {
            Dialect::Main | Dialect::Tlv => 0x5005,
            Dialect::TenOne => 0x9015,
            Dialect::TenTwo | Dialect::TenTwoFour => 0x9014,
            Dialect::TenFour => 0x9017,
        };
        let at = if dialect == Dialect::Tlv { 8 } else { 4 };
        if word(0) != expected
            || command.len() != at + 16
            || word(at) != 0
            || word(at + 4) != 7
            || command[at + 8..at + 14] != AP
        {
            return Err(BmiError::BadResponse);
        }
    } else {
        return Err(BmiError::BadResponse);
    }
    if advance {
        m.data.as_mut().unwrap().control_phase += 1;
    }
    m.sent.push(bytes.to_vec());
    if is_wmm {
        if let Some(policy) = &m.data.as_ref().unwrap().wmm_policy {
            // Actual native WMM command receipt coincides with an external
            // policy update. PEER_ASSOC/UP must revalidate even when every
            // nested future can otherwise complete in one outer poll.
            policy.lock().as_mut().unwrap().rules[0].flags =
                narf_wireless::reg::RegFlags::INDOOR_ONLY;
        }
    }
    if is_wmm && m.data.as_ref().unwrap().wmm_fail {
        return Err(BmiError::BadResponse);
    }
    if is_wmm && m.data.as_ref().unwrap().wmm_hold {
        core::future::pending::<()>().await;
    }
    m.inner.inner.rx.push_back((
        2,
        vec![
            2,
            2,
            8,
            0,
            8,
            0,
            0,
            0,
            1,
            4,
            0,
            0,
            2,
            bytes.len().div_ceil(256) as u8,
            0,
            0,
        ],
    ));
    for frame in replies {
        if frame[0] == 8 {
            m.data.as_mut().unwrap().queue.push_back(frame);
        } else {
            management_frame(m, frame);
        }
    }
    Ok(())
}
fn complete(m: &mut RadioModel, id: u16, status: u8) {
    let mut b = vec![7, status, 1, 0];
    b.extend_from_slice(&id.to_le_bytes());
    b.extend_from_slice(&[0, 0]);
    m.inner
        .inner
        .rx
        .push_back((m.inner.receive_pipe, header(1, &b)));
}
pub(super) async fn send(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    send_now(m, bytes)?;
    if m.data.as_ref().unwrap().stall_ce {
        core::future::pending::<()>().await;
    }
    Ok(())
}
/// Actual HTT3 TX_FRM management for the bounded legacy auth/association
/// composition. Firmware without WMI MGMT_TX still sends these frames over
/// pipe4; decoding them as raw DATA would reject before the independent AP.
fn initial_htt_management(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let body = bytes.get(8..).ok_or(BmiError::BadResponse)?;
    let fixture = m.data.as_ref().ok_or(BmiError::BadResponse)?;
    let phase = fixture.control_phase;
    if m.inner.version < 3
        || bytes[0] != 1
        || bytes[1] != 0
        || bytes[5] != m.inner.sequence
        || bytes[2..4] != (bytes.len() as u16 - 8).to_le_bytes()
        || body.len() < 16
        || body[..4] != [1, 0x65, 0x40, 0x0c] // MGMT/plaintext, extTID17, vdev0.
        || body[12..16] != [0xff, 0xff, 0, 0] // Home-channel peer/freq union.
        || phase >= 2
        || fixture.qos()
        || fixture.ht_expected
        || m.station.as_ref().is_none_or(|station| station.phase < 4)
    {
        return Err(BmiError::BadResponse);
    }
    let length = usize::from(u16::from_le_bytes(body[4..6].try_into().unwrap()));
    let id = u16::from_le_bytes(body[6..8].try_into().unwrap());
    let frame = {
        let storage = m.inner.storage.as_ref().ok_or(BmiError::BadResponse)?;
        let (address, payload) = storage.tx.snapshot(id).ok_or(BmiError::BadResponse)?;
        let prefetch = length.min(50).div_ceil(4) * 4;
        if u32::from_le_bytes(body[8..12].try_into().unwrap()) != address as u32
            || body.len() != 16 + prefetch
            || payload.get(..prefetch) != body.get(16..)
        {
            return Err(BmiError::BadResponse);
        }
        payload.get(..length).ok_or(BmiError::BadResponse)?.to_vec()
    };
    if frame.len() < 24
        || frame[..2] != if phase == 0 { [0xb0, 0] } else { [0, 0] }
        || frame[4..10] != AP
        || frame[10..16] != OWN
        || frame[16..22] != AP
    {
        return Err(BmiError::BadResponse);
    }
    // The real AP validates authentication/RSNE and creates the actual early
    // M1. No key/controlled-port or synthetic association receipt is supplied.
    let replies = m
        .data
        .as_mut()
        .unwrap()
        .ap
        .receive(&frame)
        .map_err(|_| BmiError::BadResponse)?;
    m.inner.sequence = m.inner.sequence.wrapping_add(1);
    m.native_management.push(frame);
    m.sent.push(bytes.to_vec());
    m.data.as_mut().unwrap().control_phase += 1;
    // A real ID from the retained DMA slot is completed through the normal
    // HTT3 TX terminal event, independently of the AP management response.
    complete(m, id, 0);
    for reply in replies {
        if reply[0] == 8 {
            m.data.as_mut().unwrap().queue.push_back(reply);
        } else {
            management_frame(m, reply);
        }
    }
    Ok(())
}
pub(super) fn send_now(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    if bytes.get(8..10) == Some(&[1, 0x65]) {
        return initial_htt_management(m, bytes);
    }
    let body = bytes.get(8..).ok_or(BmiError::BadResponse)?;
    if bytes[0] != 1
        || bytes[1] != 0
        || bytes[5] != m.inner.sequence
        || bytes[2..4] != (bytes.len() as u16 - 8).to_le_bytes()
        || body.len() < 16
        || body[0] != 1
        || !matches!(body[1], 1 | 5 | 0x21 | 0x25)
        || body[12..16] != [0xff, 0xff, 0, 0]
    {
        return Err(BmiError::BadResponse);
    }
    m.inner.sequence = m.inner.sequence.wrapping_add(1);
    let length = usize::from(u16::from_le_bytes(body[4..6].try_into().unwrap()));
    let id = u16::from_le_bytes(body[6..8].try_into().unwrap());
    let storage = m.inner.storage.as_ref().ok_or(BmiError::BadResponse)?;
    let (address, payload) = storage.tx.snapshot(id).ok_or(BmiError::BadResponse)?;
    let frame = payload.get(..length).ok_or(BmiError::BadResponse)?;
    let prefetch = length.min(50).div_ceil(4) * 4;
    if body.len() != 16 + prefetch || body[16..] != payload[..prefetch] {
        return Err(BmiError::BadResponse);
    }
    if let Some(fragments) = &storage.fragments {
        let at = usize::from(id) * 64;
        let pointer = u32::from_le_bytes(body[8..12].try_into().unwrap());
        if u64::from(pointer) != fragments.address + at as u64
            || fragments.bytes[at + 16..at + 20] != (address as u32).to_le_bytes()
            || fragments.bytes[at + 22..at + 24] != (length as u16).to_le_bytes()
        {
            return Err(BmiError::BadResponse);
        }
    }
    let fixture = m.data.as_mut().unwrap();
    // PKT_TYPE native WiFi (flags0 bit 5): only native-WiFi firmware, and
    // the firmware rebuilds QoS from the descriptor TID and, without
    // NO_ENCRYPT, inserts its own CCMP header.
    let native;
    let frame = if body[1] & 0x20 != 0 {
        if !fixture.native_wifi {
            return Err(BmiError::BadResponse);
        }
        let flags1 = u16::from_le_bytes([body[2], body[3]]);
        native = fixture.native_frame(frame, (flags1 >> 6) as u8 & 31, body[1] & 4 == 0)?;
        &native[..]
    } else if fixture.native_wifi {
        return Err(BmiError::BadResponse);
    } else {
        frame
    };
    // flags0 without HTT_DATA_TX_DESC_FLAGS0_NO_ENCRYPT: the firmware
    // encrypts the header-only MPDU with its installed pairwise key.
    let encrypted;
    let frame = if body[1] & 4 == 0 {
        encrypted = fixture.firmware_encrypt(frame)?;
        &encrypted[..]
    } else {
        frame
    };
    let expected_tid = if frame[0] == 0x88 { 0 } else { 16 };
    if body[2..4] != (0x800u16 | (expected_tid << 6)).to_le_bytes() {
        return Err(BmiError::BadResponse);
    }
    let m4 = fixture.react(frame)?;
    if m4 && fixture.m4_before_receipt.is_some() {
        fixture
            .queue
            .push_front(fixture.m4_before_receipt.take().unwrap());
        if let Some(descriptor) = fixture.m4_descriptor.take() {
            fixture.rx_descriptors.push_front(descriptor);
        }
        fixture.deferred_receipt = Some((id, fixture.status));
        if let Some(window) = fixture.m4_ba_window.take() {
            // Actual firmware HTT ADDBA arrives while M4 awaits its native
            // terminal receipt, before the following original RAW DMA frame.
            m.inner
                .inner
                .rx
                .push_back((m.inner.receive_pipe, header(1, &[5, window, 0x80, 0x70])));
        }
    } else if m4 && fixture.hold_m4
        || fixture.ap.phase() == ApPhase::Authorized && !m4 && fixture.hold_data
    {
        fixture.held.push_back(id);
    } else {
        let status = fixture.status;
        complete(m, id, status);
    }
    Ok(())
}
/// Independent native CE/HTC response observer. No response creates a DATA
/// receipt or releases HTT DMA; those still come only from complete().
pub(super) fn pfc_response(m: &mut RadioModel, bytes: &[u8]) -> Option<Result<(), BmiError>> {
    if !m.inner.config.pfc || bytes.get(8).copied() != Some(11) {
        return None;
    }
    Some((|| {
        let body = &bytes[8..];
        if bytes.len() > 256
            || body.len() < 12
            || bytes[0] != 1
            || bytes[1] != 0
            || bytes[5] != m.inner.sequence
            || bytes[2..4] != (body.len() as u16).to_le_bytes()
            || body[1..4] != [0; 3]
            || body.len()
                != 12 + usize::from(u16::from_le_bytes(body[6..8].try_into().unwrap())) * 8
        {
            return Err(BmiError::BadResponse);
        }
        if let Some(ce) = &m.ce {
            let actual = ce.source_bytes(4);
            if actual.get(..bytes.len()) != Some(bytes) {
                return Err(BmiError::BadResponse);
            }
        }
        m.data
            .as_mut()
            .ok_or(BmiError::BadResponse)?
            .pfc_responses
            .push(body.to_vec());
        m.inner.sequence = m.inner.sequence.wrapping_add(1);
        Ok(())
    })())
}
pub(super) fn poll(m: &mut RadioModel) -> Result<(), BmiError> {
    if let Some(f) = &mut m.data {
        if f.protection_delay != 0 {
            f.protection_delay -= 1;
            if f.protection_delay == 0 {
                if let Some(id) = f.held.pop_front() {
                    complete(m, id, 0);
                }
            }
        }
    }
    let Some(fixture) = m.data.as_mut() else {
        return Ok(());
    };
    if !m.inner.inner.rx.is_empty() {
        return Ok(());
    }
    let Some(mut frame) = fixture.queue.pop_front() else {
        if let Some((id, status)) = fixture.deferred_receipt.take() {
            complete(m, id, status);
        }
        return Ok(());
    };
    let peer = fixture
        .next_peer
        .take()
        .unwrap_or(if m.inner.config.pfc { 17 } else { 1800 });
    let tid = fixture
        .next_tid
        .take()
        .unwrap_or(if frame[0] == 0x88 { 0 } else { 16 });
    let protected = frame[1] & 0x40 != 0;
    let decrypted = fixture.firmware_decrypt(&mut frame);
    let control = frame[0] == 0x84;
    let sequence = if control {
        0
    } else {
        u16::from_le_bytes([frame[22], frame[23]]) >> 4
    };
    let per_frame = fixture.rx_descriptors.pop_front();
    let mut descriptor = [0u8; 300];
    // htt_rx.c: a native-WiFi firmware decaps data it could decrypt (or
    // that was never protected); anything else stays RAW with its FCS.
    let native = fixture.native_wifi
        && !control
        && matches!(frame[0], 8 | 0x88)
        && (!protected || decrypted)
        && !(frame[0] == 0x88 && frame[24] & 0x80 != 0);
    if native {
        frame = fixture.native_rx_msdu(&frame, &mut descriptor);
    } else {
        frame.extend_from_slice(&[0; 4]);
    }
    u32at(
        &mut descriptor,
        4,
        (1 << 31)
            | u32::from(per_frame.map_or(3, |d| d.0))
            | if control { 1 << 9 } else { 0 }
            | if protected && !decrypted { 1 << 29 } else { 0 }
            | core::mem::take(&mut fixture.next_attention),
    );
    u32at(
        &mut descriptor,
        12,
        u32::from(peer)
            | if control { 0 } else { 1 << 11 }
            | (u32::from(sequence) << 16)
            | if protected { 6 << 28 } else { 7 << 28 },
    );
    u32at(
        &mut descriptor,
        20,
        u32::from(if tid == 16 { 0 } else { tid }) << 28,
    );
    u32at(&mut descriptor, 24, frame.len() as u32);
    // rx_msdu_start_common.info1 DECAP_FORMAT (after flow_id_crc).
    u32at(
        &mut descriptor,
        32,
        if native {
            1 << 8
        } else {
            core::mem::take(&mut fixture.next_decap) << 8
        },
    );
    u32at(&mut descriptor, 56, 0xc000);
    u32at(&mut descriptor, 104, 0x0400000b); // legacy OFDM6
    if let Some((preamble, sig, guard)) = per_frame.map(|d| (d.1, d.2, d.3)).or(fixture.rx_phy) {
        u32at(&mut descriptor, 104, u32::from(preamble) << 24);
        u32at(&mut descriptor, 108, sig);
        u32at(&mut descriptor, 112, guard);
    }
    let storage = m.inner.storage.as_mut().ok_or(BmiError::BadResponse)?;
    let index = *storage.order.front().ok_or(BmiError::BadResponse)?;
    let buffer = storage.buffers[index]
        .as_mut()
        .ok_or(BmiError::BadResponse)?;
    if frame.len() + 300 > buffer.bytes.len() {
        return Err(BmiError::BadResponse);
    }
    buffer.bytes[..300].copy_from_slice(&descriptor);
    buffer.bytes[300..300 + frame.len()].copy_from_slice(&frame);
    let body = if m.inner.config.dialect == 3 {
        let mut b = vec![0x12, tid];
        b.extend_from_slice(&peer.to_le_bytes());
        b.extend_from_slice(&[0, 0, 1, 0]);
        b.extend_from_slice(&(buffer.address as u32).to_le_bytes());
        b.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b
    } else {
        let mut b = vec![0; 52];
        b[0] = 1;
        b[1] = tid;
        b[2..4].copy_from_slice(&peer.to_le_bytes());
        b[7] = 1;
        b[48] = 1;
        b[49] = 1;
        b
    };
    m.inner
        .inner
        .rx
        .push_back((m.inner.receive_pipe, header(1, &body)));
    Ok(())
}
fn joined(version: u32, dialect: Dialect, secured: bool, raw: bool) -> radio::Radio<RadioModel> {
    joined_features(version, dialect, secured, raw, 0)
}
fn joined_features(
    version: u32,
    dialect: Dialect,
    secured: bool,
    raw: bool,
    extra: u64,
) -> radio::Radio<RadioModel> {
    let mut r = mlme_tests::prepared_profile_features(version, dialect, secured, raw, extra);
    if extra & (1 << 13) != 0 {
        r.htt.wmi.htc.transport.ce = Some(crate::ath10k::boot::CeFixture::new(HwRev::Qca9984));
        // alloc_coherent_masked retains a power-of-two page extent: the
        // 4772-byte native qstate therefore lives in8192 bytes. Exercise
        // that physical shape before any handshake/queue publication, and
        // retain a sentinel outside the exact advertised qstate span.
        r.htt
            .wmi
            .htc
            .transport
            .inner
            .storage
            .as_mut()
            .unwrap()
            .qstate
            .as_mut()
            .unwrap()
            .bytes
            .resize(8192, 0xa5);
    }
    let mode = if secured {
        narf_wireless::association::SecurityMode::Wpa2Psk
    } else {
        narf_wireless::association::SecurityMode::Open
    };
    assert!(matches!(
        drive(r.associate_station(&station_tests::policy(), b"narf", mode, &[])),
        Poll::Ready(Ok(_))
    ));
    let m = &mut r.htt.wmi.htc.transport;
    let mut fixture = Fixture::new(secured);
    // Seed the independent AP using the exact native frames transmitted by
    // real JoinPlan/WMI; its RSNA starts only after it verifies those requests.
    for frame in &m.native_management {
        let replies = fixture
            .ap
            .receive(frame)
            .expect("independent AP rejected actual native management");
        fixture
            .queue
            .extend(replies.into_iter().filter(|f| f[0] == 8));
    }
    m.data = Some(fixture);
    r
}
fn packets() -> (Vec<u8>, Vec<u8>) {
    let n = network();
    (
        udp_ipv4(
            AP,
            OWN,
            n.lease_ip,
            n.server_ip,
            49152,
            7,
            b"ath10k-native-uplink",
        ),
        udp_ipv4(
            OWN,
            AP,
            n.server_ip,
            n.lease_ip,
            7,
            49152,
            b"ath10k-native-downlink",
        ),
    )
}
fn start(
    r: &mut radio::Radio<RadioModel>,
    secured: bool,
) -> Poll<Result<radio::StationLink, radio::Error>> {
    drive(r.start_data_with_nonce(
        &station_tests::policy(),
        if secured { Some(&PMK) } else { None },
        || Some([0x73; 32]),
    ))
}
fn composition(version: u32, dialect: Dialect, secured: bool) -> Result<(), &'static str> {
    let mut r = joined(version, dialect, secured, true);
    let (uplink, downlink) = packets();
    if r.station_link().is_some()
        || !matches!(
            drive(r.transmit_ethernet(&station_tests::policy(), &uplink)),
            Poll::Ready(Err(_))
        )
    {
        return Err("native association authorized data before packet owner/RSNA");
    }
    if !matches!(start(&mut r, secured), Poll::Ready(Ok(_))) || r.station_link().is_none() {
        return Err("native RAW/EAPOL/Supplicant path did not authorize");
    }
    if !matches!(
        drive(r.transmit_ethernet(&station_tests::policy(), &uplink)),
        Poll::Ready(Ok(_))
    ) || r
        .htt
        .wmi
        .htc
        .transport
        .inner
        .storage
        .as_ref()
        .unwrap()
        .tx
        .pending()
        != 1
    {
        return Err("native CE receipt retired payload before HTT status");
    }
    if !matches!(
        drive(r.poll_ethernet(&station_tests::policy())),
        Poll::Ready(Ok(_))
    ) || r
        .htt
        .wmi
        .htc
        .transport
        .inner
        .storage
        .as_ref()
        .unwrap()
        .tx
        .pending()
        != 0
        || !r
            .htt
            .wmi
            .htc
            .transport
            .data
            .as_ref()
            .unwrap()
            .uplink
            .contains(&uplink)
    {
        return Err("native HTT/CCMP changed Ethernet uplink or terminal owner");
    }
    let m = &mut r.htt.wmi.htc.transport;
    let fixture = m.data.as_mut().unwrap();
    let frame = fixture.downlink(&downlink);
    fixture.queue.push_back(frame.clone());
    let Poll::Ready(Ok(received)) = drive(r.poll_ethernet(&station_tests::policy())) else {
        return Err("native RX packet polling failed");
    };
    if received != [downlink] {
        return Err("native RAW descriptor/CCMP/RFC1042 did not preserve exact downlink");
    }
    if secured {
        r.htt
            .wmi
            .htc
            .transport
            .data
            .as_mut()
            .unwrap()
            .queue
            .push_back(frame);
        if !matches!(drive(r.poll_ethernet(&station_tests::policy())),Poll::Ready(Ok(f)) if f.is_empty())
        {
            return Err("native replay escaped software per-key replay policy");
        }
    }
    Ok(())
}
fn smoke_ath10k_raw_native_open_wpa2_and_exact_bidirectional_ip() -> TestResult {
    for (version, dialect) in [
        (1, Dialect::Main),
        (2, Dialect::TenOne),
        (3, Dialect::TenTwo),
        (4, Dialect::Tlv),
        (5, Dialect::TenTwoFour),
        (6, Dialect::TenFour),
    ] {
        for secured in [false, true] {
            if let Err(e) = composition(version, dialect, secured) {
                return TestResult::Fail(e);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/data",
    smoke_ath10k_raw_native_open_wpa2_and_exact_bidirectional_ip
);
fn smoke_ath10k_data_requires_raw_init_and_exact_descriptor_peer_profile() -> TestResult {
    let mut r = joined(4, Dialect::Tlv, false, false);
    if start(&mut r, false) != Poll::Ready(Err(radio::Error::Unsupported)) {
        return TestResult::Fail("software crypto accepted native-WiFi WMI INIT");
    }
    let mut r = joined(4, Dialect::Tlv, false, true);
    assert!(matches!(start(&mut r, false), Poll::Ready(Ok(_))));
    let (_, downlink) = packets();
    for negative in 0..5 {
        let m = &mut r.htt.wmi.htc.transport;
        let f = m.data.as_mut().unwrap();
        let mut frame = f.downlink(&downlink);
        match negative {
            0 => f.next_peer = Some(1801),
            1 => f.next_tid = Some(3),
            2 => f.next_decap = 1,
            3 => f.next_attention = 1 << 30,
            _ => frame[10] ^= 2,
        };
        f.queue.push_back(frame);
        if !matches!(drive(r.poll_ethernet(&station_tests::policy())),Poll::Ready(Ok(frames)) if frames.is_empty())
        {
            return TestResult::Fail("foreign peer/TID/decap/CRC/TA reached native data owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/data",
    smoke_ath10k_data_requires_raw_init_and_exact_descriptor_peer_profile
);
fn smoke_ath10k_m4_receipt_and_cancel_close_data_with_native_dma_retained() -> TestResult {
    let mut r = joined(4, Dialect::Tlv, true, true);
    r.htt.wmi.htc.transport.data.as_mut().unwrap().hold_m4 = true;
    {
        let policy = station_tests::policy();
        let mut future =
            core::pin::pin!(r.start_data_with_nonce(&policy, Some(&PMK), || Some([0x73; 32])));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..32 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return TestResult::Fail("held M4 terminal HTT status authorized port");
            }
        }
    }
    let m = &r.htt.wmi.htc.transport;
    if r.station_link().is_some()
        || m.data.as_ref().unwrap().held.len() != 1
        || m.inner.storage.as_ref().unwrap().tx.pending() != 1
    {
        return TestResult::Fail("cancelled RSNA lost exact held M4 payload/closed admission");
    }
    if !matches!(
        drive(r.poll_ethernet(&station_tests::policy())),
        Poll::Ready(Err(radio::Error::Failed))
    ) {
        return TestResult::Fail("cancelled M4 owner resumed packet service");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/data",
    smoke_ath10k_m4_receipt_and_cancel_close_data_with_native_dma_retained
);

#[path = "dhcp_tests.rs"]
mod dhcp_tests;
#[path = "pfc_tests.rs"]
mod pfc_tests;
#[path = "tx_pipeline_tests.rs"]
mod tx_pipeline_tests;

fn management_id(dialect: Dialect) -> u32 {
    match dialect {
        Dialect::Main => 0x7006,
        Dialect::TenOne => 0x9028,
        Dialect::TenTwo | Dialect::TenTwoFour => 0x9029,
        Dialect::TenFour => 0x9031,
        Dialect::Tlv => 0x7008,
    }
}
/// A native management transmit after the AP authorized the station.
pub(super) fn captures_management(m: &RadioModel, command: &[u8]) -> bool {
    m.data
        .as_ref()
        .is_some_and(|d| d.ap.phase() == ApPhase::Authorized)
        && command.len() >= 4
        && u32::from_le_bytes(command[..4].try_into().unwrap())
            == management_id(m.inner.inner.dialect)
}
pub(super) fn capture_management(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let command = &bytes[8..];
    let frame = mlme_tests::native_frame(m, command)?;
    let frame = m.data.as_mut().unwrap().firmware_management_tx(frame)?;
    m.data.as_mut().unwrap().management_tx.push(frame);
    if m.inner.inner.dialect == Dialect::Tlv {
        let mut terminal = vec![16, 0, 0xa7, 1];
        terminal.extend_from_slice(&command[12..16]);
        terminal.extend_from_slice(&[0; 12]);
        add_event(m, 0x7006, &terminal);
    }
    m.sent.push(bytes.to_vec());
    m.inner.inner.rx.push_back((
        2,
        vec![
            2,
            2,
            8,
            0,
            8,
            0,
            0,
            0,
            1,
            4,
            0,
            0,
            2,
            bytes.len().div_ceil(256) as u8,
            0,
            0,
        ],
    ));
    Ok(())
}
pub(super) fn protection_handles(d: Dialect, b: &[u8]) -> bool {
    b.get(..4).is_some_and(|id| {
        id == match d {
            Dialect::Main | Dialect::Tlv => 0x5008u32,
            Dialect::TenOne => 0x901a,
            Dialect::TenTwo | Dialect::TenTwoFour => 0x9019,
            Dialect::TenFour => 0x901c,
        }
        .to_le_bytes()
    })
}
pub(super) async fn protection_send(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let d = m.inner.inner.dialect;
    let b = &bytes[8..];
    let tlv = d == Dialect::Tlv;
    let at = if tlv { 8 } else { 4 };
    if b.len() != at + 12
        || tlv && b[4..8] != ((95u32 << 16) | 12).to_le_bytes()
        || b[at..at + 4] != [0; 4]
    {
        return Err(BmiError::BadResponse);
    }
    let f = m.data.as_ref().ok_or(BmiError::BadResponse)?;
    let step = f.protection_trace.len() % 3;
    let (cts, enable) = match d {
        Dialect::Main | Dialect::Tlv => (26u32, 44u32),
        Dialect::TenOne | Dialect::TenTwo | Dialect::TenTwoFour => (24, 43),
        Dialect::TenFour => (26, 45),
    };
    let request = f.protection_request.unwrap_or(radio::StationProtection {
        rts_threshold: Some(0),
        cts_protection: false,
    });
    let (p, value) = match step {
        0 => (enable, 0x21),
        1 => (cts, u32::from(request.cts_protection)),
        _ => (1, request.rts_threshold.map_or(u32::MAX, u32::from)),
    };
    if b[at + 4..at + 8] != p.to_le_bytes()
        || b[at + 8..at + 12] != value.to_le_bytes()
        || !f.held.is_empty()
        || m.inner.storage.as_ref().unwrap().tx.pending() != 0
    {
        return Err(BmiError::BadResponse);
    }
    m.sent.push(bytes.to_vec());
    let f = m.data.as_mut().unwrap();
    f.protection_trace.push((p, value));
    if step == f.protection_change_at {
        if let Some(cap) = f.protection_revoke.take() {
            cap.revoke();
        }
        if let Some(policy) = f.protection_policy.take() {
            policy.lock().take();
        }
    }
    m.inner.inner.rx.push_back((
        2,
        vec![
            2,
            2,
            8,
            0,
            8,
            0,
            0,
            0,
            1,
            4,
            0,
            0,
            2,
            bytes.len().div_ceil(256) as u8,
            0,
            0,
        ],
    ));
    if m.data.as_ref().unwrap().protection_hold == Some(step) {
        core::future::pending::<()>().await;
    }
    Ok(())
}

/// Firmware key cache of the hardware-key profile: what Linux ath10k
/// `cryptmode=0` firmware holds after `WMI_VDEV_INSTALL_KEY` (wmi.h
/// `struct wmi_vdev_install_key_cmd`). The model encrypts header-only RAW
/// MPDUs, decrypts received MPDUs and PMF unicast management with it, and
/// answers each install with the HTT `SEC_IND` (htt.h
/// `struct htt_security_indication`, htt_rx.c `install_key_done`).
#[derive(Default)]
pub(super) struct HwKeyCache {
    /// (pairwise, key index, key) currently programmed.
    pub(super) keys: Vec<(bool, u8, [u8; 16])>,
    /// Every accepted install command.
    pub(super) installs: usize,
    /// PEER_ASSOC `peer_flags->pmf` this firmware expects (0: none).
    pub(super) pmf_flag: u32,
    /// Leave the next install unapplied (the stale key stays programmed and
    /// no indication is sent) until `release_install`.
    pub(super) hold: bool,
    held: Option<(bool, u8, [u8; 16])>,
    /// Header-only MPDUs the firmware encrypted.
    pub(super) hardware_tx: usize,
    /// Received MPDUs the firmware decrypted (no DECRYPT_ERR).
    pub(super) decrypted_rx: usize,
}
impl HwKeyCache {
    pub(super) fn key(&self, pairwise: bool, id: u8) -> Option<[u8; 16]> {
        self.keys
            .iter()
            .find(|k| k.0 == pairwise && k.1 == id)
            .map(|k| k.2)
    }
    pub(super) fn held(&self) -> bool {
        self.held.is_some()
    }
}
impl Fixture {
    /// RAW TX without NO_ENCRYPT: `[header][CCMP header][plaintext][8 zero
    /// MIC octets]` (mac80211 GENERATE_IV, htt_tx.c MIC tail). The firmware
    /// encrypts with its pairwise key at the host's PN.
    fn firmware_encrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>, BmiError> {
        let hw = self.hw.as_mut().ok_or(BmiError::BadResponse)?;
        let key = hw.key(true, 0).ok_or(BmiError::BadResponse)?;
        let header = if frame.first() == Some(&0x88) { 26 } else { 24 };
        if frame.len() < header + 16 || frame[1] & 0x40 == 0 {
            return Err(BmiError::BadResponse);
        }
        let (body, mic) = frame[header..].split_at(frame.len() - header - 8);
        let (pn, key_id) = narf_wireless::ccmp::decode_ccmp_header(body[..8].try_into().unwrap())
            .map_err(|_| BmiError::BadResponse)?;
        if mic != [0; 8] || key_id != 0 {
            return Err(BmiError::BadResponse);
        }
        let priority = if header == 26 { frame[24] & 15 } else { 0 };
        let mut plain = body[8..].to_vec();
        let mut out = frame[..header].to_vec();
        out.extend_from_slice(
            &narf_wireless::ccmp::protect(
                &Ccm,
                &frame[..header],
                &key,
                pn,
                0,
                priority,
                false,
                &mut plain,
            )
            .map_err(|_| BmiError::BadResponse)?,
        );
        hw.hardware_tx += 1;
        Ok(out)
    }
    /// Native-WiFi TX (mac.c `ath10k_tx_h_nwifi` reversed): QoS Control
    /// from the descriptor TID, then, when the firmware encrypts, a CCMP
    /// header at its own PN plus MIC space for `firmware_encrypt`.
    fn native_frame(&mut self, frame: &[u8], tid: u8, encrypt: bool) -> Result<Vec<u8>, BmiError> {
        if frame.len() < 24 || frame[0] != 8 || frame[1] & 0x03 != 1 {
            return Err(BmiError::BadResponse);
        }
        let protected = frame[1] & 0x40 != 0;
        if protected != encrypt {
            return Err(BmiError::BadResponse);
        }
        let mut out = frame[..24].to_vec();
        if tid < 16 {
            out[0] = 0x88;
            out.extend_from_slice(&[tid, 0]);
        }
        if encrypt {
            self.native_pn += 1;
            let pn = self.native_pn.to_le_bytes();
            out.extend_from_slice(&[pn[0], pn[1], 0, 0x20, pn[2], pn[3], pn[4], pn[5]]);
        }
        out.extend_from_slice(&frame[24..]);
        if encrypt {
            out.extend_from_slice(&[0; 8]);
        }
        self.native_tx += 1;
        Ok(out)
    }
    /// Native-WiFi RX (`ath10k_htt_rx_h_undecap_nwifi` reversed): the
    /// original header (+CCMP header at 4-byte alignment) in
    /// `rx_hdr_status`, the MSDU as `[nwifi header][LLC...]` without MIC/FCS.
    fn native_rx_msdu(&mut self, frame: &[u8], descriptor: &mut [u8; 300]) -> Vec<u8> {
        let header = if frame[0] == 0x88 { 26 } else { 24 };
        let protected = frame[1] & 0x40 != 0;
        let mut status = frame[..header].to_vec();
        let mut body = &frame[header..];
        if protected {
            status.resize(header.next_multiple_of(4), 0);
            status.extend_from_slice(&body[..8]);
            body = &body[8..body.len() - 8];
        }
        descriptor[236..236 + status.len()].copy_from_slice(&status);
        let mut native = vec![8, frame[1] & 0x03, 0, 0];
        native.extend_from_slice(&frame[4..10]);
        native.extend_from_slice(&frame[10..16]);
        native.extend_from_slice(&frame[16..22]);
        native.extend_from_slice(&frame[22..24]);
        native.extend_from_slice(body);
        self.native_rx += 1;
        native
    }
    /// RX: an MPDU under a programmed key leaves the firmware decrypted with
    /// Protected, CCMP header and MIC kept (htt_rx.c `is_decrypted`); any
    /// other protected MPDU keeps its ciphertext and DECRYPT_ERR.
    fn firmware_decrypt(&mut self, frame: &mut Vec<u8>) -> bool {
        let Some(hw) = self.hw.as_mut() else {
            return false;
        };
        if frame.len() < 24 || !matches!(frame[0], 8 | 0x88) || frame[1] & 0x40 == 0 {
            return false;
        }
        let header = if frame[0] == 0x88 { 26 } else { 24 };
        if frame.len() < header + 16 {
            return false;
        }
        let key_id = frame[header + 3] >> 6;
        let key = if frame[4] & 1 == 0 {
            hw.key(true, 0).filter(|_| key_id == 0)
        } else {
            hw.key(false, key_id)
        };
        let Some(key) = key else {
            return false;
        };
        let priority = if header == 26 { frame[24] & 15 } else { 0 };
        let mut wire = frame[header..].to_vec();
        let mic = wire[wire.len() - 8..].to_vec();
        let mut replay = narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 };
        let Ok(plain) = narf_wireless::ccmp::unprotect(
            &Ccm,
            &frame[..header],
            &key,
            priority,
            false,
            &mut replay,
            &mut wire,
        ) else {
            return false;
        };
        frame.truncate(header + 8);
        frame.extend_from_slice(&plain);
        frame.extend_from_slice(&mic);
        hw.decrypted_rx += 1;
        true
    }
    /// WMI management TX on a `peer_flags->pmf` peer: a protected unicast
    /// robust frame carries only the CCMP header plus MIC space (wmi.c
    /// `ath10k_wmi_op_gen_mgmt_tx`) and the firmware encrypts it with the
    /// pairwise key (management nonce/AAD). Other frames pass unchanged.
    fn firmware_management_tx(&mut self, frame: Vec<u8>) -> Result<Vec<u8>, BmiError> {
        let Some(hw) = self.hw.as_mut() else {
            return Ok(frame);
        };
        let Some(key) = hw.key(true, 0).filter(|_| hw.pmf_flag != 0) else {
            return Ok(frame);
        };
        if frame.len() < 24 || frame[1] & 0x40 == 0 || frame[4] & 1 != 0 {
            return Ok(frame);
        }
        if frame.len() < 24 + 16 || frame[frame.len() - 8..] != [0; 8] {
            return Err(BmiError::BadResponse);
        }
        let (pn, key_id) =
            narf_wireless::ccmp::decode_ccmp_header(frame[24..32].try_into().unwrap())
                .map_err(|_| BmiError::BadResponse)?;
        if key_id != 0 {
            return Err(BmiError::BadResponse);
        }
        let mut plain = frame[32..frame.len() - 8].to_vec();
        let mut out = frame[..24].to_vec();
        out.extend_from_slice(
            &narf_wireless::ccmp::protect(&Ccm, &frame[..24], &key, pn, 0, 0, true, &mut plain)
                .map_err(|_| BmiError::BadResponse)?,
        );
        hw.hardware_tx += 1;
        Ok(out)
    }
    /// WMI management RX on a `peer_flags->pmf` peer: the firmware decrypts
    /// a protected unicast robust frame with the pairwise key and keeps
    /// Protected, CCMP header and MIC (wmi.c `ath10k_wmi_rx_is_decrypted`).
    pub(super) fn firmware_management_rx(&mut self, frame: Vec<u8>) -> Vec<u8> {
        let Some(hw) = self.hw.as_mut() else {
            return frame;
        };
        let Some(key) = hw.key(true, 0).filter(|_| hw.pmf_flag != 0) else {
            return frame;
        };
        if frame.len() < 24 + 16 || frame[1] & 0x40 == 0 || frame[4] & 1 != 0 {
            return frame;
        }
        let mut wire = frame[24..].to_vec();
        let mic = wire[wire.len() - 8..].to_vec();
        let mut replay = narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 };
        let Ok(plain) = narf_wireless::ccmp::unprotect(
            &Ccm,
            &frame[..24],
            &key,
            0,
            true,
            &mut replay,
            &mut wire,
        ) else {
            return frame;
        };
        let mut out = frame[..32].to_vec();
        out.extend_from_slice(&plain);
        out.extend_from_slice(&mic);
        hw.decrypted_rx += 1;
        out
    }
}
/// `vdev_install_key_cmdid` (wmi.h main/TLV maps 0x5009; 10.1 0x901b;
/// 10.2 0x901a; 10.4 0x901d).
fn install_id(dialect: Dialect) -> u32 {
    match dialect {
        Dialect::Main | Dialect::Tlv => 0x5009,
        Dialect::TenOne => 0x901b,
        Dialect::TenTwo | Dialect::TenTwoFour => 0x901a,
        Dialect::TenFour => 0x901d,
    }
}
pub(super) fn install_handles(m: &RadioModel, command: &[u8]) -> bool {
    m.data.as_ref().is_some_and(|d| d.hw.is_some())
        && command.get(..4) == Some(&install_id(m.inner.inner.dialect).to_le_bytes()[..])
}
/// Firmware side of `WMI_VDEV_INSTALL_KEY`: vdev 0, the BSSID peer, a
/// CCMP-128 (`WMI_CIPHER_AES_CCM` = 4) pairwise (key 0) or group key, zero
/// RSC/TSC and MIC lengths; TLV wraps the struct in tag 96 and the key in an
/// ARRAY_BYTE (17) TLV (wmi-tlv.c `ath10k_wmi_tlv_op_gen_vdev_install_key`).
pub(super) fn install_key(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let tlv = m.inner.inner.dialect == Dialect::Tlv;
    let c = &bytes[8..];
    let at = if tlv { 8 } else { 4 };
    let size = at + 92 + if tlv { 4 } else { 0 } + 16;
    let word = |o: usize| u32::from_le_bytes(c[o..o + 4].try_into().unwrap());
    if c.len() != size
        || tlv && word(4) != (96 << 16) | 92
        || word(at) != 0
        || c[at + 4..at + 10] != AP
        || c[at + 10..at + 12] != [0, 0]
        || word(at + 12) > 3
        || word(at + 16) > 1
        || word(at + 16) == 0 && word(at + 12) != 0
        || word(at + 20) != 4
        || c[at + 24..at + 80].iter().any(|b| *b != 0)
        || word(at + 80) != 16
        || word(at + 84) != 0
        || word(at + 88) != 0
        || tlv && word(at + 92) != (17 << 16) | 16
    {
        return Err(BmiError::BadResponse);
    }
    let key = (
        word(at + 16) == 0,
        word(at + 12) as u8,
        c[size - 16..].try_into().unwrap(),
    );
    m.sent.push(bytes.to_vec());
    m.inner.inner.rx.push_back((
        2,
        vec![
            2,
            2,
            8,
            0,
            8,
            0,
            0,
            0,
            1,
            4,
            0,
            0,
            2,
            bytes.len().div_ceil(256) as u8,
            0,
            0,
        ],
    ));
    let hw = m.data.as_mut().unwrap().hw.as_mut().unwrap();
    hw.installs += 1;
    if hw.hold {
        hw.hold = false;
        hw.held = Some(key);
    } else {
        apply_install(m, key);
    }
    Ok(())
}
/// Program a held install and send its indication.
pub(super) fn release_install(m: &mut RadioModel) {
    if let Some(key) = m
        .data
        .as_mut()
        .and_then(|d| d.hw.as_mut())
        .and_then(|h| h.held.take())
    {
        apply_install(m, key);
    }
}
fn apply_install(m: &mut RadioModel, key: (bool, u8, [u8; 16])) {
    let hw = m.data.as_mut().unwrap().hw.as_mut().unwrap();
    hw.keys.retain(|k| !(k.0 == key.0 && k.1 == key.1));
    hw.keys.push(key);
    let peer: u16 = if m.inner.config.pfc { 17 } else { 1800 };
    // HTT_SECURITY_AES_CCMP (6) | HTT_SECURITY_IS_UNICAST, peer_id, then
    // michael_key[8] and wapi_rsc[16].
    let mut b = vec![0x0b, if key.0 { 0x86 } else { 6 }];
    b.extend_from_slice(&peer.to_le_bytes());
    b.extend_from_slice(&[0; 24]);
    m.inner
        .inner
        .rx
        .push_back((m.inner.receive_pipe, header(1, &b)));
}
