//! Native key/control/TX/RX conversation with an independent authenticator.
use super::super::super::{firmware_api::FirmwareApi, firmware_parser_tests, runtime};
use super::super::{
    data::{
        tests::{associated, policy, prepare},
        LegacyReceive,
    },
    power::tests::retained_source,
    queue::tests::Fixture,
};
use super::*;
use alloc::vec;
use core::{
    cell::Cell,
    future::Future,
    pin::{pin, Pin},
    task::{Context as TaskContext, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::{ApPhase, FakeAp, NetworkPlan};
use narf_wireless::{
    ccmp::{self, AesCcm, CcmpError, ReplayWindow},
    eapol::{self, HmacPrimitive, Ptk},
};

const OWN: [u8; 6] = [2; 6];
const AP: [u8; 6] = [2, 4, 6, 8, 10, 12];
const PMK: [u8; 32] = [0x55; 32];
const SNONCE: [u8; 32] = [0x11; 32];
const ANONCE: [u8; 32] = [0x22; 32];
const GTK: [u8; 16] = [0x77; 16];
struct Sha1;
impl HmacPrimitive for Sha1 {
    fn out_len(&self) -> usize {
        20
    }
    fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
    }
}
struct Ccm;
impl AesCcm for Ccm {
    fn encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; 8], CcmpError> {
        narf_crypto::aes_ccm::seal(key, nonce, aad, body).map_err(|_| CcmpError::TooLong)
    }
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), CcmpError> {
        narf_crypto::aes_ccm::open(key, nonce, aad, body, tag).map_err(|_| CcmpError::AuthFailed)
    }
}
fn check(test: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    test().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn poll<T>(future: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    let result = future.poll(&mut TaskContext::from_waker(Waker::noop()));
    if result.is_pending() {
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    result
}
fn header(fc: u8, to: [u8; 6], from: [u8; 6], third: [u8; 6]) -> Vec<u8> {
    let mut b = vec![fc, 0, 0, 0];
    b.extend_from_slice(&to);
    b.extend_from_slice(&from);
    b.extend_from_slice(&third);
    b.extend_from_slice(&[0, 0]);
    b
}
fn envelope(frame: &[u8], status: u32) -> Vec<u8> {
    let mut b = vec![0; 48];
    b[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    b[12..16].copy_from_slice(&status.to_le_bytes());
    b[32] = 40;
    b[34] = 1;
    b[16..20].copy_from_slice(&0x7f000000u32.to_le_bytes());
    b.extend_from_slice(frame);
    b
}
fn data_from_ap(ethernet: &[u8], sequence: u16) -> Vec<u8> {
    let mut b = header(
        8,
        ethernet[..6].try_into().unwrap(),
        AP,
        ethernet[6..12].try_into().unwrap(),
    );
    b[1] = 2;
    b[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
    b.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    b.extend_from_slice(&ethernet[12..]);
    b
}
fn ip(outgoing: bool) -> Vec<u8> {
    let remote = [6, 1, 2, 3, 4, 5];
    let mut b = vec![];
    b.extend_from_slice(if outgoing { &remote } else { &OWN });
    b.extend_from_slice(if outgoing { &OWN } else { &remote });
    b.extend_from_slice(&[8, 0, 1, 2, 3, 4]);
    b
}

#[derive(Clone)]
struct Receipt {
    command: u8,
    group: u8,
    sequence: u16,
    body: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::iwlwifi) enum Kind {
    Enable,
    Message2,
    Message4,
    GroupReply,
    Disable,
    PairKey,
    GroupKey,
    Fence,
    RemovePair,
    RemoveGroup,
    RemoveQueue,
    Data,
}
pub(in crate::iwlwifi) struct Device {
    pub(in crate::iwlwifi) ap: FakeAp,
    pub(in crate::iwlwifi) m1: Vec<u8>,
    ptk: Option<Ptk>,
    keys: [Option<[u8; 16]>; 5],
    pub(in crate::iwlwifi) events: Vec<Kind>,
    held: Vec<Receipt>,
    enabled: bool,
    api: u8,
    tx_pn: u64,
    m4: bool,
    pair_adds: usize,
    group_adds: usize,
    sync: u32,
    pub(in crate::iwlwifi) data: Vec<Vec<u8>>,
    gtk: [u8; 16],
    rsc: u64,
    rekey: Option<Rekey>,
    last_m3: Vec<u8>,
    last_m4: Vec<u8>,
    rx_pn: u64,
    expected_group_floor: Option<u64>,
}
struct Rekey {
    anonce: Option<[u8; 32]>,
    ptk: Option<Ptk>,
    replay: u64,
    gtk: [u8; 16],
    rsc: u64,
}
fn signed(key: KeyFrame, kck: &[u8]) -> Vec<u8> {
    let mut bytes = key.into_eapol();
    let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(kck, &bytes);
    bytes[81..97].copy_from_slice(&mic[..16]);
    bytes
}
fn verify(pdu: &[u8], kck: &[u8]) -> Result<(), &'static str> {
    let mut clear = pdu.to_vec();
    clear[81..97].fill(0);
    if pdu[81..97] != narf_crypto::pbkdf2_sha1::hmac_sha1(kck, &clear)[..16] {
        return Err("independent authenticator MIC rejection");
    }
    Ok(())
}
fn rsn() -> Vec<u8> {
    vec![
        48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
    ]
}
fn key_data(ptk: &Ptk, gtk: [u8; 16], pairwise: bool) -> Result<Vec<u8>, &'static str> {
    let mut clear = if pairwise { rsn() } else { vec![] };
    clear.extend_from_slice(&[221, 22, 0, 15, 172, 1, 1, 0]);
    clear.extend_from_slice(&gtk);
    if clear.len() % 8 != 0 {
        clear.push(221);
    }
    while clear.len() % 8 != 0 {
        clear.push(0);
    }
    narf_crypto::aes_kw::aes_wrap(ptk.kek.as_slice().try_into().unwrap(), &clear)
        .ok_or("authenticator key wrap")
}
fn ap_ethernet(pdu: &[u8]) -> Vec<u8> {
    let mut bytes = OWN.to_vec();
    bytes.extend_from_slice(&AP);
    bytes.extend_from_slice(&[0x88, 0x8e]);
    bytes.extend_from_slice(pdu);
    bytes
}
impl Device {
    pub(in crate::iwlwifi) fn restart_authenticator(
        &mut self,
        expected_group_floor: u64,
    ) -> Result<(), &'static str> {
        if self.enabled || self.keys.iter().any(Option::is_some) || !self.held.is_empty() {
            return Err("model reconnect before native key/packet retirement");
        }
        let mut next = Self::new(self.api)?;
        next.sync = self.sync;
        next.events = core::mem::take(&mut self.events);
        next.data = core::mem::take(&mut self.data);
        next.expected_group_floor = Some(expected_group_floor);
        *self = next;
        Ok(())
    }
    /// Device-side aggregate model: authenticate the actual packet/key program
    /// using the ordinary native model, but defer its single receipt. The
    /// caller must supply a real model BA prefix or fallback TX_CMD later.
    pub(in crate::iwlwifi) fn aggregate_packet(
        &mut self,
        p: runtime::model::Published,
        fw: &mut runtime::model::Firmware,
    ) -> Result<(), &'static str> {
        if !self.held.is_empty() {
            return Err("aggregate model overwrote a held control receipt");
        }
        let index = self.events.len();
        self.react(p, fw, Some(index), None)?;
        if self.events.last() != Some(&Kind::Data)
            || self.held.len() != 1
            || self.held[0].command != 0x1c
            || self.held[0].body.len() != 48
        {
            return Err("aggregate model captured non-data transaction");
        }
        self.held.clear();
        Ok(())
    }
    pub(in crate::iwlwifi) fn release(&mut self, fw: &mut runtime::model::Firmware) {
        for receipt in core::mem::take(&mut self.held) {
            Self::inject(fw, receipt);
        }
    }
    pub(in crate::iwlwifi) fn holding(&self) -> bool {
        !self.held.is_empty()
    }
    pub(in crate::iwlwifi) fn new(api: u8) -> Result<Self, &'static str> {
        let plan = NetworkPlan {
            station: OWN,
            bssid: AP,
            server_ip: [10, 1, 1, 1],
            lease_ip: [10, 1, 1, 2],
            netmask: [255, 255, 255, 0],
            lease_seconds: 60,
        };
        let mut ap = FakeAp::wpa2(plan, b"net", 1, 7, PMK, ANONCE)
            .map_err(|_| "authenticator config")?
            .with_basic_1mbps()
            .map_err(|_| "authenticator rate")?;
        // Independently authored post-association AP precondition. The
        // retained native Owner separately composes real auth/association.
        let mut auth = header(0xb0, AP, OWN, AP);
        auth.extend_from_slice(&[0, 0, 1, 0, 0, 0]);
        ap.receive(&auth).map_err(|_| "authenticator auth")?;
        let mut assoc = header(0, AP, OWN, AP);
        assoc.extend_from_slice(&[
            17, 0, 1, 0, 0, 3, b'n', b'e', b't', 1, 1, 0x82, 48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0,
            15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
        ]);
        let reply = ap
            .receive(&assoc)
            .map_err(|_| "authenticator association")?;
        let m1 = reply.get(1).ok_or("authenticator M1 absent")?.clone();
        Ok(Self {
            ap,
            m1,
            ptk: None,
            keys: core::array::from_fn(|_| None),
            events: Vec::new(),
            held: Vec::new(),
            enabled: false,
            api,
            tx_pn: 0,
            m4: false,
            pair_adds: 0,
            group_adds: 0,
            sync: 0,
            data: Vec::new(),
            gtk: GTK,
            rsc: 0,
            rekey: None,
            last_m3: Vec::new(),
            last_m4: Vec::new(),
            rx_pn: 100,
            expected_group_floor: None,
        })
    }
    fn seed(&self, fw: &mut runtime::model::Firmware) {
        fw.inject(0xc1, 0, 0x8000, &envelope(&self.m1, 3));
    }
    fn inject(fw: &mut runtime::model::Firmware, receipt: Receipt) {
        fw.inject(
            receipt.command,
            receipt.group,
            receipt.sequence,
            &receipt.body,
        );
    }
    pub(in crate::iwlwifi) fn react(
        &mut self,
        p: runtime::model::Published,
        fw: &mut runtime::model::Firmware,
        hold: Option<usize>,
        fail: Option<usize>,
    ) -> Result<bool, &'static str> {
        let mut output = Vec::new();
        let kind;
        if p.queue == 0 {
            if p.bytes.len() < 8 || p.bytes[7] != 0 {
                return Err("native control header/version");
            }
            let op = p.bytes[0];
            let group = p.bytes[1];
            let sequence = u16::from_le_bytes([p.bytes[2], p.bytes[3]]);
            let b = &p.bytes[8..];
            let response_group = if group == 1 && matches!(op, 0x17 | 0x18) {
                0
            } else {
                group
            };
            let mut response = vec![];
            match (group, op) {
                (1, 0x18) => {
                    let mut expected = [0; 48];
                    expected[0] = 1;
                    expected[24] = 16;
                    if b.get(20) == Some(&16) {
                        expected[20] = 16;
                        self.enabled = false;
                        kind = Kind::Disable;
                    } else {
                        self.enabled = true;
                        kind = Kind::Enable;
                    }
                    if b != expected {
                        return Err("native RSNA peer modify bytes");
                    }
                    response = vec![1, 0, 0, 0];
                }
                (1, 0x17) => {
                    if b.len() != 76 || b[0] != 0 || usize::from(b[1]) >= 5 {
                        return Err("native key extent/station/slot");
                    }
                    let slot = usize::from(b[1]);
                    let flags = u16::from_le_bytes([b[2], b[3]]);
                    let group_key = flags & 0x4000 != 0;
                    let id = ((flags >> 8) & 3) as usize;
                    if self.enabled
                        || (group_key && slot != id + 1)
                        || (!group_key && (slot != 0 || id != 0))
                    {
                        return Err("key reuse/identity before native disable");
                    }
                    if flags & 0x800 != 0 {
                        let expected_flags =
                            8 | 0x800 | ((id as u16) << 8) | if group_key { 0x4000 } else { 0 };
                        if flags != expected_flags || b[4..] != [0; 72] || self.keys[slot].is_none()
                        {
                            return Err("native REMOVE key bytes/owner");
                        }
                        self.keys[slot] = None;
                        kind = if group_key {
                            Kind::RemoveGroup
                        } else {
                            Kind::RemovePair
                        };
                    } else {
                        let expected = if group_key {
                            self.gtk
                        } else {
                            self.ptk
                                .as_ref()
                                .ok_or("native key before actual M2")?
                                .tk
                                .as_slice()
                                .try_into()
                                .unwrap()
                        };
                        let expected_flags =
                            10 | ((id as u16) << 8) | if group_key { 0x4000 } else { 0 };
                        let mut pn = [0; 40];
                        if group_key {
                            // Literal Linux CCMP RX-sequence wire cases,
                            // independent of the production key encoder.
                            let bytes =
                                match (self.api, self.expected_group_floor.unwrap_or(self.rsc)) {
                                    (_, 0) => [0; 8],
                                    (2, 20) => [0, 0, 0, 0, 0, 0, 0, 20],
                                    (3, 20) => [0, 0, 0, 0, 0, 20, 0, 0],
                                    (2, 0x0102_0304_0506) => [1, 2, 0, 0, 3, 4, 5, 6],
                                    (3, 0x0102_0304_0506) => [1, 2, 3, 4, 5, 6, 0, 0],
                                    (2, 0x0203_0405_0607) => [2, 3, 0, 0, 4, 5, 6, 7],
                                    (3, 0x0203_0405_0607) => [2, 3, 4, 5, 6, 7, 0, 0],
                                    _ => return Err("fixture lacks literal RSC case"),
                                };
                            pn[..8].copy_from_slice(&bytes);
                        }
                        if !self.m4
                            || flags != expected_flags
                            || b[4..20] != expected
                            || b[20..36] != [0; 16]
                            || b[36..] != pn
                            || self.keys[slot].is_some()
                        {
                            return Err("native key mismatch/reinstall or key before M4 receipt");
                        }
                        self.keys[slot] = Some(expected);
                        kind = if group_key {
                            self.expected_group_floor = None;
                            self.group_adds += 1;
                            Kind::GroupKey
                        } else {
                            self.pair_adds += 1;
                            self.tx_pn = 0;
                            Kind::PairKey
                        };
                    }
                    response = vec![1, 0, 0, 0];
                }
                (5, 2) => {
                    let delba = b.get(12) == Some(&1);
                    let mut expected = vec![0; if delba { 24 } else { 20 }];
                    expected[4] = 1;
                    expected[8] = if delba { 12 } else { 8 };
                    expected[12] = u8::from(delba);
                    expected[14] = 1;
                    self.sync = self.sync.checked_add(1).ok_or("fixture sync overflow")?;
                    expected[16..20].copy_from_slice(&self.sync.to_le_bytes());
                    if delba {
                        if b.len() != 24 || b[20] >= 32 {
                            return Err("native DEL_BA marker BAID/extent");
                        }
                        expected[20..24].copy_from_slice(&[b[20], 0, 0, 0]);
                    }
                    if b != expected || self.enabled && !delba {
                        return Err("native one-queue RX fence bytes/order");
                    }
                    kind = Kind::Fence;
                    let mut marker = vec![
                        if delba { 12 } else { 8 },
                        0,
                        0,
                        0,
                        u8::from(delba),
                        0,
                        1,
                        0,
                    ];
                    marker.extend_from_slice(&self.sync.to_le_bytes());
                    if delba {
                        marker.extend_from_slice(&b[20..24]);
                    }
                    output.push(Receipt {
                        command: 0xff,
                        group: 5,
                        sequence: 0x8000,
                        body: marker,
                    });
                }
                (5, 0x17) => {
                    let mut expected = [0; 36];
                    expected[0] = 1;
                    expected[4] = 1;
                    if b != expected || self.keys.iter().any(Option::is_some) || self.enabled {
                        return Err("queue removed before native key retirement");
                    }
                    kind = Kind::RemoveQueue;
                    response = vec![24, 0, 0, 0, 0x91, 0, 0, 0];
                }
                _ => return Err("unexpected native RSNA control"),
            }
            output.insert(
                0,
                Receipt {
                    command: op,
                    group: response_group,
                    sequence,
                    body: response,
                },
            );
        } else {
            if !self.enabled || !matches!(p.queue, 23 | 24) || p.bytes.len() < 56 {
                return Err("native packet without enabled owned queue");
            }
            let flags = u32::from_le_bytes(p.bytes[8..12].try_into().unwrap());
            let mut frame = p.bytes[24..].to_vec();
            let header = if frame[0] == 0x88 { 26 } else { 24 };
            if header == 26 {
                if p.bytes[6..8] != [0, 0x2d]
                    || frame.get(26..28) != Some(&[0, 0])
                    || frame[24..26] != [0, 0]
                {
                    return Err("native QoS TX-v9 padding/TID/offload geometry");
                }
                frame.drain(26..28);
            }
            if !matches!(frame[0], 8 | 0x88)
                || frame[1] & 0x87 != 1
                || frame[4..10] != AP
                || frame[10..16] != OWN
            {
                return Err("native EAPOL/data BSS header");
            }
            let encrypted = frame[1] & 0x40 != 0;
            if encrypted {
                if flags & 2 != 0 {
                    return Err("protected packet disabled hardware crypto");
                }
                let actual = self.keys[0].ok_or("encrypted native packet before PTK ACK")?;
                self.tx_pn += 1;
                let mut body = frame[header..].to_vec();
                let wire = ccmp::protect(
                    &Ccm,
                    &frame[..header],
                    &actual,
                    self.tx_pn,
                    0,
                    0,
                    false,
                    &mut body,
                )
                .map_err(|_| "firmware CCMP TX")?;
                let mut cipher = wire;
                let expected = self
                    .ptk
                    .as_ref()
                    .ok_or("AP PTK missing")?
                    .tk
                    .as_slice()
                    .try_into()
                    .unwrap();
                let plain = ccmp::unprotect(
                    &Ccm,
                    &frame[..header],
                    expected,
                    0,
                    false,
                    &mut ReplayWindow {
                        last_seen_pn: self.tx_pn - 1,
                    },
                    &mut cipher,
                )
                .map_err(|_| "AP rejected actual firmware key/ciphertext")?;
                frame.truncate(header);
                frame.extend_from_slice(&plain);
                frame[1] &= !0x40;
            } else if flags & 2 == 0 {
                return Err("plaintext EAPOL did not disable firmware crypto");
            }
            if p.queue == 23 {
                if frame.get(24..32) != Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]) {
                    return Err("management queue carried non-EAPOL");
                }
                let pdu = &frame[32..];
                let key = KeyFrame::decode(&pdu[4..], 16).ok_or("AP EAPOL descriptor")?;
                if let Some(mut rekey) = self.rekey.take() {
                    if let Some(anonce) = rekey.anonce {
                        if key.key_information == 0x10a {
                            kind = Kind::Message2;
                            if key.replay_counter != rekey.replay
                                || key.key_nonce == SNONCE
                                || key.key_data != rsn()
                            {
                                return Err("rekey M2 reused initial nonce/RSN/replay");
                            }
                            let ptk = eapol::derive_ptk(
                                &Sha1,
                                &PMK,
                                &AP,
                                &OWN,
                                &anonce,
                                &key.key_nonce,
                                16,
                            );
                            verify(pdu, &ptk.kck)?;
                            let mut m3 = KeyFrame::empty(16);
                            m3.key_information = 0x13ca;
                            m3.key_length = 16;
                            m3.replay_counter = rekey.replay + 1;
                            m3.key_nonce = anonce;
                            m3.key_rsc = rekey.rsc.to_le_bytes();
                            m3.key_data = key_data(&ptk, rekey.gtk, true)?;
                            let pdu = signed(m3, &ptk.kck);
                            self.last_m3 = pdu.clone();
                            self.rx_pn += 1;
                            output.push(Receipt {
                                command: 0xc1,
                                group: 0,
                                sequence: 0x8000,
                                body: self.encrypted_rx(&ap_ethernet(&pdu), self.rx_pn, false)?,
                            });
                            rekey.ptk = Some(ptk);
                            self.rekey = Some(rekey);
                        } else {
                            kind = Kind::Message4;
                            if key.key_information != 0x30a
                                || key.replay_counter != rekey.replay + 1
                                || !key.key_data.is_empty()
                            {
                                return Err("rekey M4 flags/replay/data");
                            }
                            let ptk = rekey.ptk.take().ok_or("rekey M4 before M2")?;
                            verify(pdu, &ptk.kck)?;
                            self.ptk = Some(ptk);
                            self.gtk = rekey.gtk;
                            self.rsc = rekey.rsc;
                            self.last_m4 = pdu.to_vec();
                            self.m4 = true;
                        }
                    } else {
                        kind = Kind::GroupReply;
                        if key.key_information != 0x302
                            || key.replay_counter != rekey.replay
                            || !key.key_data.is_empty()
                        {
                            return Err("group reply flags/replay/data");
                        }
                        verify(pdu, &self.ptk.as_ref().unwrap().kck)?;
                        self.gtk = rekey.gtk;
                        self.rsc = rekey.rsc;
                        self.last_m4 = pdu.to_vec();
                        self.m4 = true;
                    }
                } else if self.ap.phase() == ApPhase::Authorized {
                    kind = Kind::Message4;
                    if pdu != self.last_m4 {
                        return Err("duplicate M3 did not return exact cached M4");
                    }
                    verify(pdu, &self.ptk.as_ref().unwrap().kck)?;
                } else {
                    if key.key_information == 0x10a {
                        kind = Kind::Message2;
                        self.ptk = Some(eapol::derive_ptk(
                            &Sha1,
                            &PMK,
                            &AP,
                            &OWN,
                            &ANONCE,
                            &key.key_nonce,
                            16,
                        ));
                    } else {
                        kind = Kind::Message4;
                        self.last_m4 = pdu.to_vec();
                        self.m4 = true;
                    }
                    for reply in self
                        .ap
                        .receive(&frame)
                        .map_err(|_| "independent AP rejected native M2/M4 MIC/replay")?
                    {
                        self.last_m3 = reply[32..].to_vec();
                        output.push(Receipt {
                            command: 0xc1,
                            group: 0,
                            sequence: 0x8000,
                            body: envelope(&reply, 3),
                        });
                    }
                }
            } else {
                if !encrypted || flags != 0 || self.ap.phase() != ApPhase::Authorized {
                    return Err("ordinary secured Ethernet lacked native key/authorization");
                }
                let mut ethernet = frame[16..22].to_vec();
                ethernet.extend_from_slice(&frame[10..16]);
                ethernet.extend_from_slice(&frame[header + 6..]);
                self.data.push(ethernet);
                kind = Kind::Data;
            }
            let mut complete = vec![0; 48];
            complete[0] = 1;
            complete[36..38].copy_from_slice(&p.queue.to_le_bytes());
            complete[40] = 1;
            complete[44..48].copy_from_slice(&u32::from(p.pointer).to_le_bytes());
            output.insert(
                0,
                Receipt {
                    command: 0x1c,
                    group: 0,
                    sequence: 0x8000,
                    body: complete,
                },
            );
        }
        let index = self.events.len();
        self.events.push(kind);
        if fail == Some(index) {
            if p.queue == 0 {
                output[0].body = vec![0; 4];
            } else {
                output[0].body[40] = 0x82;
            }
        }
        if hold == Some(index) {
            self.held = output;
            Ok(true)
        } else {
            for receipt in output {
                Self::inject(fw, receipt);
            }
            Ok(false)
        }
    }
    pub(in crate::iwlwifi) fn encrypted_rx(
        &self,
        ethernet: &[u8],
        pn: u64,
        group: bool,
    ) -> Result<Vec<u8>, &'static str> {
        self.encrypted_rx_profile(ethernet, pn, group, None)
    }
    pub(in crate::iwlwifi) fn encrypted_rx_profile(
        &self,
        ethernet: &[u8],
        pn: u64,
        group: bool,
        tid: Option<u8>,
    ) -> Result<Vec<u8>, &'static str> {
        let mut frame = data_from_ap(ethernet, 12);
        let header = if let Some(tid) = tid {
            frame[0] = 0x88;
            frame.splice(24..24, [tid, 0]);
            26
        } else {
            24
        };
        frame[1] |= 0x40;
        let expected: &[u8; 16] = if group {
            &self.gtk
        } else {
            self.ptk.as_ref().unwrap().tk.as_slice().try_into().unwrap()
        };
        let mut clear = frame[header..].to_vec();
        let cipher = ccmp::protect(
            &Ccm,
            &frame[..header],
            expected,
            pn,
            if group { 1 } else { 0 },
            tid.unwrap_or(0),
            false, // All fixture MPDUs are data, including multicast GTK data.
            &mut clear,
        )
        .map_err(|_| "AP CCMP RX encode")?;
        let mut wire = cipher.clone();
        let installed = self.keys[if group { 2 } else { 0 }].ok_or("native RX no installed key")?;
        let plain = ccmp::unprotect(
            &Ccm,
            &frame[..header],
            &installed,
            tid.unwrap_or(0),
            false,
            &mut ReplayWindow {
                last_seen_pn: pn - 1,
            },
            &mut wire,
        )
        .map_err(|_| "native RX key/MIC did not authenticate AP ciphertext")?;
        frame.truncate(header);
        frame.extend_from_slice(&cipher[..8]);
        frame.extend_from_slice(&plain);
        Ok(envelope(&frame, 0xa4f))
    }
    /// Independent authenticator aggregate: one genuine CCMP ciphertext/MIC
    /// authenticates all inner DA/SA/length/LLC bytes before this fake device
    /// emits the API4 deaggregated MPDUs. No production deaggregator is used.
    pub(in crate::iwlwifi) fn encrypted_amsdu(
        &self,
        frames: &[Vec<u8>],
        pn: u64,
        tid: u8,
    ) -> Result<Vec<Vec<u8>>, &'static str> {
        if frames.is_empty() || frames.len() > 128 || tid > 7 {
            return Err("AP aggregate shape");
        }
        let mut outer = data_from_ap(&frames[0], 23);
        outer.truncate(24);
        outer[0] = 0x88;
        outer[1] |= 0x40;
        outer.extend_from_slice(&[tid | 0x80, 0]);
        let mut body = Vec::new();
        for (index, ethernet) in frames.iter().enumerate() {
            if !(14..=1514).contains(&ethernet.len()) {
                return Err("AP aggregate MSDU extent");
            }
            body.extend_from_slice(&ethernet[..12]);
            body.extend_from_slice(&((ethernet.len() - 6) as u16).to_be_bytes());
            body.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
            body.extend_from_slice(&ethernet[12..]);
            if index + 1 < frames.len() {
                body.resize(body.len().next_multiple_of(4), 0);
            }
        }
        let ap_key = self
            .ptk
            .as_ref()
            .ok_or("AP aggregate PTK absent")?
            .tk
            .as_slice()
            .try_into()
            .unwrap();
        let cipher = ccmp::protect(&Ccm, &outer, ap_key, pn, 0, tid, false, &mut body)
            .map_err(|_| "AP aggregate CCMP")?;
        let mut wire = cipher.clone();
        let native_key = self.keys[0].ok_or("native aggregate key absent")?;
        let clear = ccmp::unprotect(
            &Ccm,
            &outer,
            &native_key,
            tid,
            false,
            &mut ReplayWindow {
                last_seen_pn: pn - 1,
            },
            &mut wire,
        )
        .map_err(|_| "native aggregate MIC/key rejection")?;
        let mut cursor = clear.as_slice();
        let mut output = Vec::new();
        for index in 0..frames.len() {
            let h = cursor.get(..14).ok_or("native aggregate subheader")?;
            let length = usize::from(u16::from_be_bytes([h[12], h[13]]));
            let sub = cursor
                .get(14..14 + length)
                .ok_or("native aggregate payload")?;
            let mut frame = outer.clone();
            frame[4..10].copy_from_slice(&h[..6]);
            frame[16..22].copy_from_slice(&h[6..12]);
            frame.extend_from_slice(&cipher[..8]);
            frame.extend_from_slice(sub);
            let mut packet = envelope(&frame, 0xa4f);
            packet[3] |= 0x40;
            packet[4] = index as u8 | if index + 1 == frames.len() { 0x80 } else { 0 };
            packet[28..32].copy_from_slice(&0x00100207u32.to_le_bytes());
            output.push(packet);
            let consumed = if index + 1 == frames.len() {
                14 + length
            } else {
                (14 + length).next_multiple_of(4)
            };
            cursor = cursor.get(consumed..).ok_or("native aggregate alignment")?;
        }
        if !cursor.is_empty() {
            return Err("native aggregate trailing bytes");
        }
        Ok(output)
    }

    pub(in crate::iwlwifi) fn challenge(
        &mut self,
        fw: &mut runtime::model::Firmware,
        anonce: Option<[u8; 32]>,
        replay: u64,
        gtk: [u8; 16],
        rsc: u64,
    ) -> Result<(), &'static str> {
        let mut key = KeyFrame::empty(16);
        key.key_length = 16;
        key.replay_counter = replay;
        let envelope = if let Some(nonce) = anonce {
            key.key_nonce = nonce;
            key.key_information = 0x8a;
            envelope(&data_from_ap(&ap_ethernet(&key.into_eapol()), 14), 3)
        } else {
            key.key_information = 0x1382;
            key.key_rsc = rsc.to_le_bytes();
            key.key_data = key_data(self.ptk.as_ref().unwrap(), gtk, false)?;
            let pdu = signed(key, &self.ptk.as_ref().unwrap().kck);
            self.last_m3 = pdu.clone();
            self.rx_pn += 1;
            self.encrypted_rx(&ap_ethernet(&pdu), self.rx_pn, false)?
        };
        self.m4 = false;
        self.rekey = Some(Rekey {
            anonce,
            ptk: None,
            replay,
            gtk,
            rsc,
        });
        fw.inject(0xc1, 0, 0x8000, &envelope);
        Ok(())
    }
}
fn fixture(api: u8) -> Result<(Fixture, Device), &'static str> {
    let mut f = associated(true, 3, false)?;
    prepare(&mut f, true)?;
    while f.trace.take().is_some() {}
    let owner = f.owner.as_mut().unwrap();
    let image = firmware_parser_tests::mvm_image();
    let parsed = super::super::super::parse_ucode(&image).unwrap();
    let mut versions = parsed.api.commands.to_vec();
    versions.extend_from_slice(&[
        0x1c, 0, 9, 0, 0x1c, 1, 0, 6, 0xc1, 0, 0, 4, 0xf7, 5, 0, 3, 15, 5, 3, 0, 0x17, 1, api, 0,
        2, 5, 1, 0, 0xff, 5, 0, 1,
    ]);
    runtime::model::versions(&mut owner.hardware, &versions);
    let mut caps = FirmwareApi::default();
    caps.api_changes[0] = 1 << 29;
    owner.security = super::Context::new(&caps);
    Ok((f, Device::new(api)?))
}
fn drive<T>(
    mut op: Pin<&mut impl Future<Output = Result<T, &'static str>>>,
    trace: &runtime::model::TxTrace,
    fw: &mut runtime::model::Firmware,
    model: &mut Device,
    hold: Option<usize>,
    fail: Option<usize>,
) -> Result<Poll<Result<T, &'static str>>, &'static str> {
    for _ in 0..256 {
        let result = poll(op.as_mut());
        while let Some(p) = trace.take() {
            if model.react(p, fw, hold, fail)? {
                return Ok(result);
            }
        }
        if result.is_ready() {
            return Ok(result);
        }
    }
    Err("native RSNA fixture progress budget")
}

fn smoke_gen2_wpa2_native_m4_keys_epoch_encrypted_data_and_close() -> TestResult {
    check(|| {
        for api in [2, 3] {
            let (mut f, mut model) = fixture(api)?;
            model.seed(&mut f.firmware);
            let owner = f.owner.as_mut().unwrap();
            {
                let mut op = pin!(owner.secure_using(PMK, || Ok(SNONCE), || Ok(policy())));
                if !matches!(
                    drive(
                        op.as_mut(),
                        &f.trace,
                        &mut f.firmware,
                        &mut model,
                        None,
                        None
                    )?,
                    Poll::Ready(Ok(()))
                ) {
                    return Err("native WPA2 did not reach completed port");
                }
            }
            if owner.phase() != Phase::DataPrepared
                || !owner.security.ready()
                || !owner.data_port_using(|| Ok(policy()))
                || model.ap.phase() != ApPhase::Authorized
                || model.events
                    != [
                        Kind::Enable,
                        Kind::Message2,
                        Kind::Message4,
                        Kind::Disable,
                        Kind::PairKey,
                        Kind::GroupKey,
                        Kind::Fence,
                        Kind::Enable,
                    ]
            {
                return Err("M4/key/RX-fence/native-enable port order");
            }
            let frame = ip(true);
            {
                let mut tx = pin!(owner.transmit_data_using(&frame, || Ok(policy())));
                if !matches!(
                    drive(
                        tx.as_mut(),
                        &f.trace,
                        &mut f.firmware,
                        &mut model,
                        None,
                        None
                    )?,
                    Poll::Ready(Ok(()))
                ) {
                    return Err("native encrypted Ethernet TX completion");
                }
            }
            if model.data != [frame] {
                return Err("actual firmware key did not produce expected encrypted Ethernet");
            }
            let frame = ip(false);
            let packet = model.encrypted_rx(&frame, 1, false)?;
            f.firmware.inject(0xc1, 0, 0x8000, &packet);
            if owner.receive_data_using(|| Ok(policy()))? != Some(LegacyReceive::Ethernet(frame)) {
                return Err("native authenticated CCM/MIC/PN did not admit Ethernet");
            }
            {
                let mut close = pin!(owner.release_legacy_data());
                if !matches!(
                    drive(
                        close.as_mut(),
                        &f.trace,
                        &mut f.firmware,
                        &mut model,
                        None,
                        None
                    )?,
                    Poll::Ready(Ok(()))
                ) {
                    return Err("native secure close receipt chain");
                }
            }
            if model.events[9..]
                != [
                    Kind::Disable,
                    Kind::RemovePair,
                    Kind::RemoveGroup,
                    Kind::Fence,
                    Kind::RemoveQueue,
                ]
                || owner.phase() != Phase::Associated
                || owner.security.started()
                || runtime::model::retained(&owner.hardware) != (0, 1, 0)
            {
                return Err("secure close released queue before key/epoch receipts");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_native_m4_keys_epoch_encrypted_data_and_close
);

fn secure(f: &mut Fixture, model: &mut Device) -> Result<(), &'static str> {
    model.seed(&mut f.firmware);
    let mut op = pin!(f
        .owner
        .as_mut()
        .unwrap()
        .secure_using(PMK, || Ok(SNONCE), || Ok(policy())));
    match drive(op.as_mut(), &f.trace, &mut f.firmware, model, None, None)? {
        Poll::Ready(result) => result,
        Poll::Pending => Err("native secure helper stalled"),
    }
}
fn service(f: &mut Fixture, model: &mut Device) -> Result<(), &'static str> {
    let owner = f.owner.as_mut().unwrap();
    if owner.receive_data_using(|| Ok(policy()))?.is_some() {
        return Err("native EAPOL escaped controlled port");
    }
    let mut op = pin!(owner.service_security_using(|| Ok([0x33; 32]), || Ok(policy())));
    match drive(op.as_mut(), &f.trace, &mut f.firmware, model, None, None)? {
        Poll::Ready(result) => result,
        Poll::Pending => Err("native rekey helper stalled"),
    }
}

fn smoke_gen2_wpa2_cancel_each_native_wait_retains_keys_dma_and_closed_port() -> TestResult {
    check(|| {
        for stage in 0..8 {
            let (mut f, mut model) = fixture(3)?;
            model.seed(&mut f.firmware);
            let owner = f.owner.as_mut().unwrap();
            let dma = runtime::model::queue_dma_addresses(&owner.hardware, 24);
            {
                let mut op = pin!(owner.secure_using(PMK, || Ok(SNONCE), || Ok(policy())));
                if !drive(
                    op.as_mut(),
                    &f.trace,
                    &mut f.firmware,
                    &mut model,
                    Some(stage),
                    None,
                )?
                .is_pending()
                {
                    return Err("cancelled WPA2 skipped native receipt wait");
                }
            }
            let retained = runtime::model::retained(&owner.hardware);
            if owner.phase() != Phase::SecuringData
                || owner.data_port_using(|| Ok(policy()))
                || retained.1 != 2
                || retained.0 + retained.2 != 1
                || owner.security.active.as_ref().unwrap().pending.is_some() != (stage > 0)
                || !matches!(poll(pin!(owner.release_legacy_data())), Poll::Ready(Err(_)))
                || !matches!(
                    poll(pin!(owner.secure_using(
                        PMK,
                        || Ok(SNONCE),
                        || Ok(policy())
                    ))),
                    Poll::Ready(Err(_))
                )
            {
                return Err("cancelled RSNA released ownership or reopened ordinary producers");
            }
            for receipt in core::mem::take(&mut model.held) {
                Device::inject(&mut f.firmware, receipt);
            }
            owner.hardware.poll()?;
            if owner.phase() != Phase::SecuringData
                || owner.data_port_using(|| Ok(policy()))
                || runtime::model::retained(&owner.hardware).1 != 2
                || runtime::model::queue_dma_addresses(&owner.hardware, 24) != dma
                || f.trace.take().is_some()
            {
                return Err("late RSNA receipt reopened cancelled owner or retired DMA");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_cancel_each_native_wait_retains_keys_dma_and_closed_port
);

fn smoke_gen2_wpa2_every_native_wait_rechecks_current_policy_and_source() -> TestResult {
    check(|| {
        for stage in 0..8 {
            for revoke in [false, true] {
                let (mut f, mut model) = fixture(2)?;
                model.seed(&mut f.firmware);
                let owner = f.owner.as_mut().unwrap();
                let source = retained_source(owner);
                let denied = Cell::new(false);
                {
                    let mut op = pin!(owner.secure_using(
                        PMK,
                        || Ok(SNONCE),
                        || {
                            if denied.get() {
                                Err("fixture removed host grant")
                            } else {
                                Ok(policy())
                            }
                        }
                    ));
                    if !drive(
                        op.as_mut(),
                        &f.trace,
                        &mut f.firmware,
                        &mut model,
                        Some(stage),
                        None,
                    )?
                    .is_pending()
                    {
                        return Err("policy fixture skipped pending native RSNA stage");
                    }
                    if revoke {
                        source.revoke();
                    } else {
                        denied.set(true);
                    }
                    for receipt in core::mem::take(&mut model.held) {
                        Device::inject(&mut f.firmware, receipt);
                    }
                    if !matches!(poll(op.as_mut()), Poll::Ready(Err(_))) {
                        return Err("RSNA native wait ignored current qualification/policy");
                    }
                }
                if owner.phase() != Phase::Failed
                    || owner.data_port_using(|| Ok(policy()))
                    || runtime::model::retained(&owner.hardware).1 != 2
                    || f.trace.take().is_some()
                {
                    return Err(
                        "failed RSNA authority released uncertain keys/queues or reinstalled port",
                    );
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_every_native_wait_rechecks_current_policy_and_source
);

fn smoke_gen2_wpa2_native_error_receipts_never_install_or_commit_port() -> TestResult {
    check(|| {
        for stage in 0..8 {
            let (mut f, mut model) = fixture(3)?;
            model.seed(&mut f.firmware);
            let owner = f.owner.as_mut().unwrap();
            {
                let mut op = pin!(owner.secure_using(PMK, || Ok(SNONCE), || Ok(policy())));
                if !matches!(
                    drive(
                        op.as_mut(),
                        &f.trace,
                        &mut f.firmware,
                        &mut model,
                        None,
                        Some(stage)
                    )?,
                    Poll::Ready(Err(_))
                ) {
                    return Err("failed native RSNA/TX/key/fence receipt accepted");
                }
            }
            if owner.phase() != Phase::Failed
                || owner.data_port_using(|| Ok(policy()))
                || runtime::model::retained(&owner.hardware).1 != 2
                || (stage <= 2 && (model.pair_adds != 0 || model.group_adds != 0))
                || model.events.len() != stage + 1
            {
                return Err("failed M4/key chain installed keys or published a secured port");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_native_error_receipts_never_install_or_commit_port
);

fn smoke_gen2_wpa2_rekeys_use_old_ptk_until_m4_and_never_reinstall_duplicates() -> TestResult {
    check(|| {
        for api in [2, 3] {
            let (mut f, mut model) = fixture(api)?;
            secure(&mut f, &mut model)?;
            let initial = model.ptk.as_ref().unwrap().tk.clone();
            // An independently authenticated duplicate M3 returns cached M4,
            // encrypted by the installed PTK, without key or replay reset.
            let duplicate = data_from_ap(&ap_ethernet(&model.last_m3), 15);
            f.firmware.inject(0xc1, 0, 0x8000, &envelope(&duplicate, 3));
            service(&mut f, &mut model)?;
            if model.pair_adds != 1 || model.group_adds != 1 || model.sync != 1 {
                return Err("duplicate M3 reinstalled keys or reset native PN epoch");
            }
            // Native encrypted group handshake has nonzero RSC: assert all
            // six bytes in both key-v2's hole and key-v3's contiguous layout.
            let rsc = 0x0102_0304_0506;
            model.challenge(&mut f.firmware, None, 3, [0x88; 16], rsc)?;
            service(&mut f, &mut model)?;
            if model.pair_adds != 1
                || model.group_adds != 2
                || model.sync != 2
                || model.events[9..]
                    != [
                        Kind::GroupReply,
                        Kind::Disable,
                        Kind::RemoveGroup,
                        Kind::GroupKey,
                        Kind::Fence,
                        Kind::Enable,
                    ]
            {
                return Err("native group rekey reset PTK or skipped slot retirement");
            }
            let owner = f.owner.as_mut().unwrap();
            let data = owner
                .power
                .prepared
                .as_ref()
                .unwrap()
                .mlme
                .data
                .as_ref()
                .unwrap();
            if data.replay.group[1] != [rsc; 17] || !owner.data_port_using(|| Ok(policy())) {
                return Err("authenticated group RSC did not commit after RX fence");
            }
            // New pairwise M1 gets fresh SNonce; M2 and M4 are actually
            // CCMP-protected by the old native key until M4's positive TX.
            model.challenge(&mut f.firmware, Some([0x44; 32]), 4, [0x88; 16], rsc)?;
            service(&mut f, &mut model)?;
            if model.pair_adds != 2
                || model.group_adds != 2
                || model.sync != 3
                || model.ptk.as_ref().unwrap().tk == initial
                || model.events[15..]
                    != [
                        Kind::Message2,
                        Kind::Message4,
                        Kind::Disable,
                        Kind::RemovePair,
                        Kind::PairKey,
                        Kind::Fence,
                        Kind::Enable,
                    ]
            {
                return Err(
                    "pairwise native rekey did not preserve old key until M4 or reused GTK",
                );
            }
            let ethernet = ip(false);
            let packet = model.encrypted_rx(&ethernet, 1, false)?;
            f.firmware.inject(0xc1, 0, 0x8000, &packet);
            if f.owner
                .as_mut()
                .unwrap()
                .receive_data_using(|| Ok(policy()))?
                != Some(LegacyReceive::Ethernet(ethernet))
            {
                return Err("fresh PTK epoch did not admit new native PN1");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_rekeys_use_old_ptk_until_m4_and_never_reinstall_duplicates
);

fn smoke_gen2_wpa2_api_entropy_preflight_is_silent() -> TestResult {
    check(|| {
        for case in 0..5 {
            let (mut f, model) = fixture(if case == 0 { 1 } else { 3 })?;
            if case == 1 {
                f.owner.as_mut().unwrap().security.mic_keys = false;
            }
            if case == 2 {
                retained_source(f.owner.as_ref().unwrap()).revoke();
            }
            model.seed(&mut f.firmware);
            let owner = f.owner.as_mut().unwrap();
            if !matches!(
                poll(pin!(owner.secure_using(
                    PMK,
                    || Err("fixture entropy unavailable"),
                    || if case == 4 {
                        Err("fixture absent host grant")
                    } else {
                        Ok(policy())
                    }
                ))),
                Poll::Ready(Err(_))
            ) || owner.phase()
                != if matches!(case, 2 | 4) {
                    Phase::Failed
                } else {
                    Phase::DataPrepared
                }
                || owner.security.started()
                || runtime::model::retained(&owner.hardware) != (0, 2, 0)
                || f.trace.take().is_some()
            {
                return Err("unsupported key API/source/entropy emitted native key or opened port");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_api_entropy_preflight_is_silent
);

fn smoke_gen2_wpa2_rx_epoch_cookie_orders_old_packets_before_replay_reset() -> TestResult {
    check(|| {
        let (mut f, mut model) = fixture(3)?;
        model.seed(&mut f.firmware);
        let owner = f.owner.as_mut().unwrap();
        {
            let mut op = pin!(owner.secure_using(PMK, || Ok(SNONCE), || Ok(policy())));
            if !drive(
                op.as_mut(),
                &f.trace,
                &mut f.firmware,
                &mut model,
                Some(6),
                None,
            )?
            .is_pending()
            {
                return Err("key epoch fixture skipped sync wait");
            }
            let receipts = core::mem::take(&mut model.held);
            Device::inject(&mut f.firmware, receipts[0].clone());
            let prefix = model.encrypted_rx(&ip(false), 9000, false)?;
            f.firmware.inject(0xc1, 0, 0x8000, &prefix);
            let mut foreign = receipts[1].clone();
            foreign.body[8..12].copy_from_slice(&999u32.to_le_bytes());
            Device::inject(&mut f.firmware, foreign);
            if !poll(op.as_mut()).is_pending() || f.trace.take().is_some() {
                return Err("foreign RX cookie enabled peer/committed replay epoch");
            }
            Device::inject(&mut f.firmware, receipts[1].clone());
            if !matches!(
                drive(
                    op.as_mut(),
                    &f.trace,
                    &mut f.firmware,
                    &mut model,
                    None,
                    None
                )?,
                Poll::Ready(Ok(()))
            ) {
                return Err("matching native RX marker did not retire prefix");
            }
        }
        if owner
            .power
            .prepared
            .as_ref()
            .unwrap()
            .mlme
            .data
            .as_ref()
            .unwrap()
            .replay
            .pairwise
            != [0; 17]
        {
            return Err("retired RX prefix committed PN into new native epoch");
        }
        let frame = ip(false);
        let packet = model.encrypted_rx(&frame, 1, false)?;
        f.firmware.inject(0xc1, 0, 0x8000, &packet);
        if owner.receive_data_using(|| Ok(policy()))? != Some(LegacyReceive::Ethernet(frame)) {
            return Err("new native epoch did not admit actual PN1");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_rx_epoch_cookie_orders_old_packets_before_replay_reset
);

fn smoke_gen2_wpa2_malformed_native_markers_and_full_key_status_are_terminal() -> TestResult {
    check(|| {
        for case in 0..6 {
            let (mut f, mut model) = fixture(2)?;
            model.seed(&mut f.firmware);
            let owner = f.owner.as_mut().unwrap();
            {
                let mut op = pin!(owner.secure_using(PMK, || Ok(SNONCE), || Ok(policy())));
                let stage = if case == 5 { 4 } else { 6 };
                if !drive(
                    op.as_mut(),
                    &f.trace,
                    &mut f.firmware,
                    &mut model,
                    Some(stage),
                    None,
                )?
                .is_pending()
                {
                    return Err("malformed native receipt fixture skipped wait");
                }
                let mut receipts = core::mem::take(&mut model.held);
                if case == 5 {
                    receipts[0].body[1] = 1; // status0x101 is not ADD_STA_SUCCESS1.
                } else {
                    let marker = &mut receipts[1].body;
                    match case {
                        0 => {
                            marker.pop();
                        }
                        1 => marker.push(0),
                        2 => marker[0] = 4,
                        3 => marker[4] = 1,
                        _ => marker[6] = 0,
                    }
                }
                for receipt in receipts {
                    Device::inject(&mut f.firmware, receipt);
                }
                if !matches!(poll(op.as_mut()), Poll::Ready(Err(_))) {
                    return Err("malformed native key status/RX marker accepted");
                }
            }
            if owner.phase() != Phase::Failed
                || owner.data_port_using(|| Ok(policy()))
                || runtime::model::retained(&owner.hardware).1 != 2
                || f.trace.take().is_some()
            {
                return Err("malformed key epoch reopened producer or dropped native queue");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_malformed_native_markers_and_full_key_status_are_terminal
);

fn smoke_gen2_wpa2_native_rx_crypto_identity_pn_and_group_floor_are_required() -> TestResult {
    check(|| {
        let (mut f, mut model) = fixture(3)?;
        secure(&mut f, &mut model)?;
        let owner = f.owner.as_mut().unwrap();
        let ethernet = ip(false);
        let original = model.encrypted_rx(&ethernet, 1, false)?;
        for bit in [2, 3, 6, 9, 11, 24] {
            let mut bad = original.clone();
            let status = u32::from_le_bytes(bad[12..16].try_into().unwrap()) ^ (1 << bit);
            bad[12..16].copy_from_slice(&status.to_le_bytes());
            f.firmware.inject(0xc1, 0, 0x8000, &bad);
            if owner.receive_data_using(|| Ok(policy()))?.is_some() {
                return Err("native RX forged station/key/CCM/decrypted/MIC metadata accepted");
            }
        }
        f.firmware.inject(0xc1, 0, 0x8000, &original);
        if owner.receive_data_using(|| Ok(policy()))? != Some(LegacyReceive::Ethernet(ethernet)) {
            return Err("invalid metadata advanced PN before authenticated native RX");
        }
        f.firmware.inject(0xc1, 0, 0x8000, &original);
        if owner.receive_data_using(|| Ok(policy()))?.is_some() {
            return Err("native decrypted replay accepted twice");
        }
        model.challenge(&mut f.firmware, None, 3, [0x99; 16], 0x0203_0405_0607)?;
        service(&mut f, &mut model)?;
        let mut multicast = ip(false);
        multicast[..6].copy_from_slice(&[1, 0, 0x5e, 1, 2, 3]);
        for pn in [model.rsc - 1, model.rsc, model.rsc + 1] {
            let packet = model.encrypted_rx(&multicast, pn, true)?;
            f.firmware.inject(0xc1, 0, 0x8000, &packet);
            let received = f
                .owner
                .as_mut()
                .unwrap()
                .receive_data_using(|| Ok(policy()))?;
            if (pn <= model.rsc && received.is_some())
                || (pn > model.rsc && received != Some(LegacyReceive::Ethernet(multicast.clone())))
            {
                return Err("native GTK receipt did not bind authenticated RSC replay floor");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_native_rx_crypto_identity_pn_and_group_floor_are_required
);

fn smoke_gen2_wpa2_close_cancel_every_key_epoch_wait_retains_exact_owner() -> TestResult {
    check(|| {
        for stage in 8..13 {
            let (mut f, mut model) = fixture(3)?;
            secure(&mut f, &mut model)?;
            let owner = f.owner.as_mut().unwrap();
            retained_source(owner).revoke();
            let dma = runtime::model::queue_dma_addresses(&owner.hardware, 24);
            {
                let mut close = pin!(owner.release_legacy_data());
                if !drive(
                    close.as_mut(),
                    &f.trace,
                    &mut f.firmware,
                    &mut model,
                    Some(stage),
                    None,
                )?
                .is_pending()
                {
                    return Err("secure close skipped native key/epoch/queue receipt");
                }
            }
            if owner.phase() != Phase::ClosingData
                || owner.data_port_using(|| Ok(policy()))
                || runtime::model::retained(&owner.hardware).1 != 2
                || runtime::model::queue_dma_addresses(&owner.hardware, 24) != dma
                || !matches!(poll(pin!(owner.release_legacy_data())), Poll::Ready(Err(_)))
            {
                return Err("cancelled secure close retired DMA or reentered key slots");
            }
            for receipt in core::mem::take(&mut model.held) {
                Device::inject(&mut f.firmware, receipt);
            }
            owner.hardware.poll()?;
            if owner.phase() != Phase::ClosingData
                || runtime::model::retained(&owner.hardware).1 != 2
            {
                return Err("late close receipt retired uncertain native owner");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_close_cancel_every_key_epoch_wait_retains_exact_owner
);

fn smoke_gen2_wpa2_pairwise_rekey_cancel_never_reopens_old_or_new_epoch() -> TestResult {
    check(|| {
        for stage in 8..15 {
            let (mut f, mut model) = fixture(3)?;
            secure(&mut f, &mut model)?;
            model.challenge(&mut f.firmware, Some([0x44; 32]), 3, GTK, 0)?;
            let owner = f.owner.as_mut().unwrap();
            if owner.receive_data_using(|| Ok(policy()))?.is_some() {
                return Err("pairwise M1 escaped native RSNA input");
            }
            {
                let mut op = pin!(owner.service_security_using(|| Ok([0x33; 32]), || Ok(policy())));
                if !drive(
                    op.as_mut(),
                    &f.trace,
                    &mut f.firmware,
                    &mut model,
                    Some(stage),
                    None,
                )?
                .is_pending()
                {
                    return Err("rekey cancellation skipped native old-key/receipt stage");
                }
            }
            let active = owner.security.active.as_ref().unwrap();
            let pending = active
                .pending
                .as_ref()
                .ok_or("cancelled rekey lost exact reply")?;
            let lost_keys = stage <= 12
                && active.keys[0].is_none()
                && !pending.install.iter().any(Option::is_some);
            if owner.phase() != Phase::SecuringData
                || owner.data_port_using(|| Ok(policy()))
                || lost_keys
                || runtime::model::retained(&owner.hardware).1 != 2
            {
                return Err("cancelled native rekey lost retained key record or reopened port");
            }
            for receipt in core::mem::take(&mut model.held) {
                Device::inject(&mut f.firmware, receipt);
            }
            owner.hardware.poll()?;
            if owner.phase() != Phase::SecuringData
                || owner.data_port_using(|| Ok(policy()))
                || f.trace.take().is_some()
            {
                return Err("late rekey receipt advanced a cancelled key epoch");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_pairwise_rekey_cancel_never_reopens_old_or_new_epoch
);

fn smoke_gen2_wpa2_retired_material_cannot_be_reinstalled_with_reset_pn() -> TestResult {
    check(|| {
        let (mut f, mut model) = fixture(3)?;
        secure(&mut f, &mut model)?;
        model.challenge(&mut f.firmware, None, 3, [0x88; 16], 20)?;
        service(&mut f, &mut model)?;
        let count = model.events.len();
        model.challenge(&mut f.firmware, None, 4, GTK, 0)?;
        if service(&mut f, &mut model).is_ok() {
            return Err("authenticated old GTK was reinstalled with PN0");
        }
        let owner = f.owner.as_mut().unwrap();
        if owner.phase() != Phase::Failed
            || owner.data_port_using(|| Ok(policy()))
            || model.events.len() != count
            || runtime::model::retained(&owner.hardware).1 != 2
        {
            return Err("retired key rejection emitted reply/key reset or released DMA");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_retired_material_cannot_be_reinstalled_with_reset_pn
);

fn smoke_gen2_wpa2_rx_epoch_preserves_bound_ap_disconnect() -> TestResult {
    check(|| {
        let (mut f, mut model) = fixture(3)?;
        model.seed(&mut f.firmware);
        let owner = f.owner.as_mut().unwrap();
        {
            let mut op = pin!(owner.secure_using(PMK, || Ok(SNONCE), || Ok(policy())));
            if !drive(
                op.as_mut(),
                &f.trace,
                &mut f.firmware,
                &mut model,
                Some(6),
                None,
            )?
            .is_pending()
            {
                return Err("AP-close epoch fixture skipped native marker wait");
            }
            let receipts = core::mem::take(&mut model.held);
            Device::inject(&mut f.firmware, receipts[0].clone());
            let mut close = header(0xc0, OWN, AP, AP);
            close.extend_from_slice(&[3, 0]);
            f.firmware.inject(0xc1, 0, 0x8000, &envelope(&close, 3));
            Device::inject(&mut f.firmware, receipts[1].clone());
            if !matches!(poll(op.as_mut()), Poll::Ready(Err(_))) {
                return Err("RX key transition discarded AP disconnect and reopened port");
            }
        }
        if owner.phase() != Phase::Failed
            || owner.data_port_using(|| Ok(policy()))
            || f.trace.take().is_some()
            || runtime::model::retained(&owner.hardware).1 != 2
        {
            return Err("AP disconnect during key epoch released native claims or enabled TX");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_rx_epoch_preserves_bound_ap_disconnect
);

fn smoke_gen2_wpa2_bound_original_m3_and_valid_mic_precede_native_m4() -> TestResult {
    check(|| {
        for case in 0..4 {
            let (mut f, mut model) = fixture(3)?;
            model.seed(&mut f.firmware);
            let owner = f.owner.as_mut().unwrap();
            {
                let mut op = pin!(owner.secure_using(PMK, || Ok(SNONCE), || Ok(policy())));
                if !drive(
                    op.as_mut(),
                    &f.trace,
                    &mut f.firmware,
                    &mut model,
                    Some(1),
                    None,
                )?
                .is_pending()
                {
                    return Err("M3 binding fixture skipped native M2 completion");
                }
                let receipts = core::mem::take(&mut model.held);
                Device::inject(&mut f.firmware, receipts[0].clone());
                let mut bad = receipts[1].clone();
                match case {
                    0 => bad.body[58] ^= 2,           // foreign transmitter/BSSID
                    1 => bad.body[34] = 6,            // foreign native receive channel
                    2 => bad.body[49] |= 0x80,        // unsupported +HTC layout
                    _ => bad.body[48 + 32 + 81] ^= 1, // original EAPOL MIC
                }
                Device::inject(&mut f.firmware, bad);
                let result = poll(op.as_mut());
                if case == 3 {
                    if !matches!(result, Poll::Ready(Err(_))) || f.trace.take().is_some() {
                        return Err("bad original M3 MIC published native M4/key command");
                    }
                } else {
                    if !result.is_pending() || f.trace.take().is_some() {
                        return Err("unbound/unsupported native M3 layout advanced RSNA");
                    }
                    Device::inject(&mut f.firmware, receipts[1].clone());
                    if !matches!(
                        drive(
                            op.as_mut(),
                            &f.trace,
                            &mut f.firmware,
                            &mut model,
                            None,
                            None
                        )?,
                        Poll::Ready(Ok(()))
                    ) {
                        return Err("later valid bound M3 could not complete native RSNA");
                    }
                }
            }
            if case == 3
                && (owner.phase() != Phase::Failed || model.pair_adds != 0 || model.group_adds != 0)
            {
                return Err("invalid M3 MIC installed native keys or retained an open port");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_bound_original_m3_and_valid_mic_precede_native_m4
);

fn smoke_gen2_wpa2_linux_default_key_and_unversioned_rx_sync_contract() -> TestResult {
    check(|| {
        for unknown in [false, true] {
            let (mut f, mut model) = fixture(2)?;
            let image = firmware_parser_tests::mvm_image();
            let parsed = super::super::super::parse_ucode(&image).unwrap();
            let mut versions = parsed.api.commands.to_vec();
            versions.extend_from_slice(&[
                0x1c, 0, 9, 0, 0x1c, 1, 0, 6, 0xc1, 0, 0, 4, 0xf7, 5, 0, 3, 15, 5, 3, 0,
            ]);
            if unknown {
                versions.extend_from_slice(&[0x17, 1, 99, 99, 2, 5, 99, 99, 0xff, 5, 99, 99]);
            }
            runtime::model::versions(&mut f.owner.as_mut().unwrap().hardware, &versions);
            secure(&mut f, &mut model)?;
            model.challenge(&mut f.firmware, None, 3, [0x88; 16], 0x0102_0304_0506)?;
            service(&mut f, &mut model)?;
            if model.pair_adds != 1 || model.group_adds != 2 || model.sync != 2 {
                return Err("native default key-v2/RX-sync-v1 geometry/receipt path diverged");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_gen2_wpa2_linux_default_key_and_unversioned_rx_sync_contract
);

fn smoke_gen2_wpa2_native_history_capacity_keeps_rekey_and_floor_proofs_bounded() -> TestResult {
    check(|| {
        let (mut f, mut device) = fixture(3)?;
        secure(&mut f, &mut device)?;
        // One PTK + initial GTK +30 genuinely authenticated fresh GTKs.
        // Every rotation goes through native REMOVE/ADD and the RX marker.
        for round in 0..30u8 {
            device.challenge(
                &mut f.firmware,
                None,
                3 + u64::from(round),
                [0x80 + round; 16],
                20,
            )?;
            service(&mut f, &mut device)?;
        }
        let events = device.events.len();
        device.challenge(&mut f.firmware, None, 33, [0xb0; 16], 20)?;
        if service(&mut f, &mut device).is_ok() || device.events.len() != events {
            return Err(
                "exhausted native history evicted a replay/retirement proof or emitted new key I/O",
            );
        }
        let owner = f.owner.as_mut().unwrap();
        if owner.phase() != Phase::Failed
            || owner.data_port_using(|| Ok(policy()))
            || runtime::model::retained(&owner.hardware).1 != 2
        {
            return Err(
                "history exhaustion reopened secure port or reclaimed uncertain native DMA",
            );
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/reconnect",
    smoke_gen2_wpa2_native_history_capacity_keeps_rekey_and_floor_proofs_bounded
);

fn history_key(group: bool, id: u8, peer: [u8; 6]) -> NativeKey {
    NativeKey {
        material: Zeroizing::new([7; 16]),
        id,
        group,
        slot: if group { id + 1 } else { 0 },
        rsc: 3,
        api: 3,
        peer,
        tx_pn: 0,
        tx_base: 0,
        restored: None,
    }
}
fn history_entry(group: bool, id: u8, peer: [u8; 6], retired: bool) -> KeyHistory {
    let mut floors = [10; 17];
    floors[5] = 900;
    KeyHistory {
        digest: [1; 32],
        peer,
        group,
        id,
        floors,
        tx_floor: 4242,
        retired,
    }
}
fn smoke_gen2_key_history_restore_policy_cross_peer_index_and_ptk_reuse() -> TestResult {
    const A: [u8; 6] = [2, 4, 6, 8, 10, 12];
    const B: [u8; 6] = [2, 4, 6, 8, 10, 14];
    // Cross-peer and cross-index GTK restore after an initial exchange keep
    // the maximum committed floor and never lower a higher fresh RSC.
    for (peer, id) in [(A, 1), (B, 1), (A, 2), (B, 3)] {
        let mut key = history_key(true, id, peer);
        if restore_retired(&history_entry(true, 1, A, true), &mut key, true).is_err()
            || key.rsc != 900
            || key.tx_pn != 0
            || key.restored.is_some()
        {
            return TestResult::Fail("retired GTK cross-peer/index restore differs");
        }
    }
    let mut high = history_key(true, 1, A);
    high.rsc = 5000;
    if restore_retired(&history_entry(true, 1, A, true), &mut high, true).is_err()
        || high.rsc != 5000
    {
        return TestResult::Fail("GTK restore lowered a fresh RSC");
    }
    // A group rekey may not reinstall retired material; a live entry and a
    // role change are never reused.
    if restore_retired(
        &history_entry(true, 1, A, true),
        &mut history_key(true, 1, A),
        false,
    )
    .is_ok()
        || restore_retired(
            &history_entry(true, 1, A, false),
            &mut history_key(true, 1, A),
            true,
        )
        .is_ok()
        || restore_retired(
            &history_entry(false, 0, A, true),
            &mut history_key(true, 1, A),
            true,
        )
        .is_ok()
        || restore_retired(
            &history_entry(true, 1, A, true),
            &mut history_key(false, 0, A),
            true,
        )
        .is_ok()
    {
        return TestResult::Fail("unsafe retired key reuse accepted");
    }
    // Same-peer PTK reuse restores per-TID RX floors and starts TX above
    // every PN the old installation may have used.
    let mut ptk = history_key(false, 0, A);
    if restore_retired(&history_entry(false, 0, A, true), &mut ptk, true).is_err()
        || ptk.tx_pn != 4243
        || ptk.rsc != 900
        || ptk.restored.map(|f| f[5]) != Some(900)
    {
        return TestResult::Fail("same-peer PTK reuse floors differ");
    }
    let body = key_command(&ptk, false);
    if body[68..76] != 4243u64.to_le_bytes() {
        return TestResult::Fail("reused PTK transmit_seq_cnt not programmed");
    }
    if key_command(&history_key(false, 0, A), false)[68..76] != [0; 8]
        || key_command(&history_key(true, 1, A), false)[68..76] != [0; 8]
        || key_command(&ptk, true)[68..76] != [0; 8]
    {
        return TestResult::Fail("fresh/group/remove key carried a TX PN");
    }
    // A PTK is per peer: cross-peer reuse and an exhausted TX floor fail.
    if restore_retired(
        &history_entry(false, 0, A, true),
        &mut history_key(false, 0, B),
        true,
    )
    .is_ok()
    {
        return TestResult::Fail("cross-peer PTK reuse accepted");
    }
    let mut exhausted = history_entry(false, 0, A, true);
    exhausted.tx_floor = 0xffff_ffff_fffe;
    if restore_retired(&exhausted, &mut history_key(false, 0, A), true).is_ok() {
        return TestResult::Fail("PTK reuse at TX PN exhaustion accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/reconnect",
    smoke_gen2_key_history_restore_policy_cross_peer_index_and_ptk_reuse
);

fn smoke_gen2_key_history_ledger_crosses_native_owners_of_one_radio() -> TestResult {
    // Unique fixture identities: no RAM owner adopts a ledger by default.
    const RADIO: [u8; 6] = [0x02, 0xfe, 0xed, 0, 0, 1];
    const OTHER: [u8; 6] = [0x02, 0xfe, 0xed, 0, 0, 2];
    {
        let mut first = Context::default();
        first.adopt_ledger(RADIO);
        first.history.push(history_entry(true, 1, RADIO, true));
        let mut live = history_entry(false, 0, RADIO, false);
        live.digest = [2; 32];
        first.history.push(live);
    }
    // Another radio never sees this ledger.
    let mut other = Context::default();
    other.adopt_ledger(OTHER);
    if !other.history.is_empty() {
        return TestResult::Fail("ledger crossed to another radio");
    }
    let mut second = Context::default();
    // An entry the new owner already holds merges: floors rise and it is
    // reusable only if both copies were retired.
    let mut own = history_entry(true, 1, RADIO, false);
    own.floors = [2000; 17];
    own.tx_floor = 1;
    second.history.push(own);
    second.adopt_ledger(RADIO);
    let merged = second.history.iter().find(|h| h.digest == [1; 32]);
    let live = second.history.iter().find(|h| h.digest == [2; 32]);
    if second.history.len() != 2
        || !merged.is_some_and(|h| h.floors[5] == 2000 && h.tx_floor == 4242 && !h.retired)
        || !live.is_some_and(|h| !h.retired && h.tx_floor == 4242)
    {
        return TestResult::Fail("adopted ledger lost a floor or reuse proof");
    }
    // Adoption is one-shot; a dropped owner hands the ledger back intact.
    drop(second);
    let mut third = Context::default();
    third.adopt_ledger(RADIO);
    third.adopt_ledger(RADIO);
    if third.history.len() != 2 {
        return TestResult::Fail("ledger not returned by dropped owner");
    }
    // Leave no fixture ledger behind.
    third.ledger = None;
    other.ledger = None;
    LEDGERS
        .lock()
        .retain(|(mac, _)| *mac != RADIO && *mac != OTHER);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/reconnect",
    smoke_gen2_key_history_ledger_crosses_native_owners_of_one_radio
);
