use super::*;
use crate::eapol::{self, KeyFrame, KeyMgmt, Ptk};
use narf_kernel_test::{kernel_test_in, TestResult};
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
const PMK: [u8; 32] = [0x55; 32];
const AN: [u8; 32] = [0x11; 32];
const SN: [u8; 32] = [0x22; 32];
const GTK: [u8; 16] = [0x7c; 16];
fn rsne() -> Vec<u8> {
    crate::rsn::RsnIe::wpa2_psk_ccmp().encode_body()
}
fn security() -> Security {
    Security::new(OWN, AP, &PMK, &rsne(), &rsne(), None, 2).unwrap()
}
fn ptk(an: [u8; 32], sn: [u8; 32]) -> Ptk {
    eapol::wpa_pmk_to_ptk(KeyMgmt::Psk, &PMK, &AP, &OWN, &an, &sn, 16)
}
fn key_frame(ki: u16, rc: u64, nonce: [u8; 32], key_data: &[u8], ptk: Option<&Ptk>) -> Vec<u8> {
    let mut frame = KeyFrame::empty(16);
    frame.key_information = ki;
    frame.key_length = 16;
    frame.replay_counter = rc;
    frame.key_nonce = nonce;
    frame.key_rsc = [5, 0, 0, 0, 0, 0, 0, 0];
    frame.key_data = if ki & 0x1000 != 0 {
        let mut padded = key_data.to_vec();
        if padded.len() % 8 != 0 || padded.len() < 16 {
            padded.push(0xdd);
            while padded.len() % 8 != 0 || padded.len() < 16 {
                padded.push(0);
            }
        }
        narf_crypto::aes_kw::aes_wrap(ptk.unwrap().kek.as_slice().try_into().unwrap(), &padded)
            .unwrap()
    } else {
        key_data.to_vec()
    };
    let mut bytes = frame.into_eapol();
    bytes[0] = 2;
    if ki & 0x100 != 0 {
        let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(&ptk.unwrap().kck, &bytes);
        bytes[81..97].copy_from_slice(&mic[..16]);
    }
    bytes
}
fn kde(gtk: [u8; 16]) -> Vec<u8> {
    let mut bytes = ie(48, &rsne()).unwrap();
    bytes.extend_from_slice(&[0xdd, 22, 0, 0x0f, 0xac, 1, 2, 0]);
    bytes.extend_from_slice(&gtk);
    bytes
}
fn native(body: &[u8], multicast: bool) -> Vec<u8> {
    let mut frame = vec![8, 2, 0, 0];
    frame.extend_from_slice(&if multicast { [255; 6] } else { OWN });
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    frame.extend_from_slice(body);
    frame
}
struct Mpdu {
    bytes: Vec<u8>,
    raw: bool,
}
impl RawFrame for Mpdu {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn unmodified(&self) -> bool {
        self.raw
    }
}
fn mpdu(bytes: Vec<u8>) -> Mpdu {
    Mpdu { bytes, raw: true }
}
struct Ccm;
impl crate::ccmp::AesCcm for Ccm {
    fn encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; 8], crate::ccmp::CcmpError> {
        narf_crypto::aes_ccm::seal(key, nonce, aad, body).map_err(|error| match error {
            narf_crypto::aes_ccm::Error::Length => crate::ccmp::CcmpError::TooLong,
            narf_crypto::aes_ccm::Error::Authentication => crate::ccmp::CcmpError::AuthFailed,
        })
    }
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), crate::ccmp::CcmpError> {
        narf_crypto::aes_ccm::open(key, nonce, aad, body, tag)
            .map_err(|_| crate::ccmp::CcmpError::AuthFailed)
    }
}
fn encrypt(frame: &[u8], tk: &[u8], pn: u64, id: u8) -> Vec<u8> {
    let mut header = frame[..24].to_vec();
    header[1] |= 0x40;
    let mut body = frame[24..].to_vec();
    let wire = crate::ccmp::protect(
        &Ccm,
        &header,
        tk.try_into().unwrap(),
        pn,
        id,
        0,
        false,
        &mut body,
    )
    .unwrap();
    header.extend_from_slice(&wire);
    header
}
fn decrypt(frame: &[u8], tk: &[u8]) -> Vec<u8> {
    let mut window = crate::ccmp::ReplayWindow { last_seen_pn: 0 };
    let mut wire = frame[24..].to_vec();
    crate::ccmp::unprotect(
        &Ccm,
        &frame[..24],
        tk.try_into().unwrap(),
        0,
        false,
        &mut window,
        &mut wire,
    )
    .unwrap()
}
fn deliver(security: &mut Security) {
    let length = security.pending_frame().unwrap().len();
    security.reply_delivered(length).unwrap();
}
fn established() -> Security {
    let mut s = security();
    let p = ptk(AN, SN);
    assert_eq!(
        s.receive(&mpdu(native(&key_frame(0x8a, 1, AN, &[], None), false)), SN),
        Ok(Rx::ReplyReady)
    );
    deliver(&mut s);
    assert_eq!(
        s.receive(
            &mpdu(native(
                &key_frame(0x13ca, 2, AN, &kde(GTK), Some(&p)),
                false
            )),
            SN
        ),
        Ok(Rx::ReplyReady)
    );
    deliver(&mut s);
    s
}
fn smoke_station_raw_admission_precedes_nonce_and_key_state() -> TestResult {
    let mut security = security();
    let mut frame = mpdu(native(&key_frame(0x8a, 1, AN, &[], None), false));
    frame.raw = false;
    let mut requested = false;
    let result = security.receive_with_nonce(&frame, || {
        requested = true;
        Some(SN)
    });
    if result != Ok(Rx::Ignored)
        || requested
        || security.pending_frame().is_some()
        || security.pair.is_some()
        || security.port_open()
    {
        return TestResult::Fail("non-raw descriptor admission changed nonce/key/port ownership");
    }
    frame.raw = true;
    if security.receive(&frame, SN) != Ok(Rx::ReplyReady) {
        return TestResult::Fail("rejected descriptor poisoned subsequent valid native EAPOL");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security",
    smoke_station_raw_admission_precedes_nonce_and_key_state
);
fn smoke_station_retained_rsna_commits_only_after_exact_m4_delivery() -> TestResult {
    let mut s = security();
    let p = ptk(AN, SN);
    if s.port_open() {
        return TestResult::Fail("fresh association opened controlled port");
    }
    s.receive(&mpdu(native(&key_frame(0x8a, 1, AN, &[], None), false)), SN)
        .unwrap();
    if s.port_open() || s.pair.is_some() || s.pending_frame().unwrap()[1] & 0x40 != 0 {
        return TestResult::Fail("M1 installed packet keys or invented protection");
    }
    deliver(&mut s);
    s.receive(
        &mpdu(native(
            &key_frame(0x13ca, 2, AN, &kde(GTK), Some(&p)),
            false,
        )),
        SN,
    )
    .unwrap();
    if s.port_open() || s.pair.is_some() || s.group[2].is_some() {
        return TestResult::Fail("M3 opened before delivered M4");
    }
    deliver(&mut s);
    // Frozen independently with Python hmac/hashlib PRF-SHA1; no driver
    // derivation is used for this expected TK.
    if s.pair.as_ref().unwrap().material.as_slice()
        != [
            9, 36, 33, 102, 2, 66, 205, 32, 165, 12, 21, 137, 224, 88, 150, 106,
        ]
    {
        return TestResult::Fail("installed PTK differs from independent PSK vector");
    }
    if !s.port_open()
        || s.pair.as_ref().unwrap().material.as_slice() != p.tk
        || s.group[2].as_ref().unwrap().material.as_slice() != GTK
        || s.history.len() != 2
    {
        return TestResult::Fail("terminal M4 did not commit retained PTK/GTK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security",
    smoke_station_retained_rsna_commits_only_after_exact_m4_delivery
);
fn smoke_station_rsna_peer_binding_and_bad_delivery_fail_closed() -> TestResult {
    let m1 = native(&key_frame(0x8a, 1, AN, &[], None), false);
    for offset in [4, 10, 16, 22] {
        let mut s = security();
        let mut wrong = m1.clone();
        wrong[offset] ^= 1;
        if s.receive(&mpdu(wrong), SN) != Ok(Rx::Ignored)
            || s.pending_frame().is_some()
            || s.port_open()
        {
            return TestResult::Fail("foreign EAPOL identity/fragment advanced RSNA");
        }
    }
    let mut s = security();
    s.receive(&mpdu(m1), SN).unwrap();
    let n = s.pending_frame().unwrap().len();
    if s.reply_delivered(n - 1) != Err(Error::Protocol)
        || s.port_open()
        || s.handshake_active()
        || !s.failed
    {
        return TestResult::Fail("short host reply delivery opened port");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security",
    smoke_station_rsna_peer_binding_and_bad_delivery_fail_closed
);
fn smoke_station_rsna_rekey_reply_uses_old_packet_key_then_commits_new() -> TestResult {
    let mut s = established();
    if s.handshake_active() {
        return TestResult::Fail("established owner retained a completed handshake");
    }
    let old = ptk(AN, SN);
    let new = ptk([0x33; 32], [0x44; 32]);
    let m1 = encrypt(
        &native(&key_frame(0x8a, 3, [0x33; 32], &[], None), false),
        &old.tk,
        1,
        0,
    );
    if s.receive(&mpdu(m1), [0x44; 32]) != Ok(Rx::ReplyReady)
        || s.port_open()
        || !s.handshake_active()
    {
        return TestResult::Fail("rekey M1 did not serialize reply");
    }
    let m2 = decrypt(s.pending_frame().unwrap(), &old.tk);
    if m2[..8] != [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e] {
        return TestResult::Fail("M2 did not use installed old packet key");
    }
    deliver(&mut s);
    if s.pending_frame().is_some() || !s.port_open() || !s.handshake_active() {
        return TestResult::Fail("M2 receipt lost M3 wait while old-key port reopened");
    }
    let m3 = encrypt(
        &native(
            &key_frame(0x13ca, 4, [0x33; 32], &kde([0x7d; 16]), Some(&new)),
            false,
        ),
        &old.tk,
        2,
        0,
    );
    if s.receive(&mpdu(m3), [0x44; 32]) != Ok(Rx::ReplyReady)
        || s.pair.as_ref().unwrap().material.as_slice() != old.tk
        || s.port_open()
        || !s.handshake_active()
    {
        return TestResult::Fail("new PTK committed before M4 terminal delivery");
    }
    decrypt(s.pending_frame().unwrap(), &old.tk);
    deliver(&mut s);
    if !s.port_open()
        || s.handshake_active()
        || s.pair.as_ref().unwrap().material.as_slice() != new.tk
        || s.history.len() != 4
    {
        return TestResult::Fail("rekey lost retained state or new packet key");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security",
    smoke_station_rsna_rekey_reply_uses_old_packet_key_then_commits_new
);
fn smoke_station_controlled_port_and_ccmp_replay_survive_forgery() -> TestResult {
    let mut s = established();
    let p = ptk(AN, SN);
    let mut plain = native(&[0x45; 20], false);
    plain[30..32].copy_from_slice(&0x0800u16.to_be_bytes());
    if s.receive(&mpdu(plain.clone()), [0; 32]) != Ok(Rx::Ignored) {
        return TestResult::Fail("unprotected data crossed WPA2 controlled port");
    }
    let mut forged = encrypt(&plain, &p.tk, (1u64 << 48) - 1, 0);
    *forged.last_mut().unwrap() ^= 1;
    if s.receive(&mpdu(forged), [0; 32]) != Ok(Rx::Ignored) {
        return TestResult::Fail("forged data was delivered");
    }
    let valid = encrypt(&plain, &p.tk, 1, 0);
    if !matches!(s.receive(&mpdu(valid.clone()), [0; 32]), Ok(Rx::Data(_)))
        || s.receive(&mpdu(valid), [0; 32]) != Ok(Rx::Ignored)
    {
        return TestResult::Fail("MIC failure poisoned replay or duplicate was delivered");
    }
    let mut eth = vec![2, 0, 0, 0, 0, 3];
    eth.extend_from_slice(&OWN);
    eth.extend_from_slice(&[0x88, 0x8e, 1, 2, 3]);
    if s.transmit_ethernet(&eth) != Err(Error::Profile) {
        return TestResult::Fail("ring client injected EAPOL");
    }
    eth[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let wire = s.transmit_ethernet(&eth).unwrap();
    if wire[24..32] != [1, 0, 0, 0x20, 0, 0, 0, 0] {
        return TestResult::Fail("rejected ring EAPOL consumed or reset PN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security",
    smoke_station_controlled_port_and_ccmp_replay_survive_forgery
);

fn smoke_station_retired_temporal_key_cannot_restart_packet_numbers() -> TestResult {
    let mut s = established();
    let first = ptk(AN, SN);
    let second = ptk([0x33; 32], [0x44; 32]);
    s.receive(
        &mpdu(encrypt(
            &native(&key_frame(0x8a, 3, [0x33; 32], &[], None), false),
            &first.tk,
            1,
            0,
        )),
        [0x44; 32],
    )
    .unwrap();
    deliver(&mut s);
    s.receive(
        &mpdu(encrypt(
            &native(
                &key_frame(0x13ca, 4, [0x33; 32], &kde([0x7d; 16]), Some(&second)),
                false,
            ),
            &first.tk,
            2,
            0,
        )),
        [0x44; 32],
    )
    .unwrap();
    deliver(&mut s);
    // Explicit repeated-nonce fixture forces previously retired TK material;
    // this must fail even though the EAPOL replay counter and MIC are fresh.
    s.receive(
        &mpdu(encrypt(
            &native(&key_frame(0x8a, 5, AN, &[], None), false),
            &second.tk,
            1,
            0,
        )),
        SN,
    )
    .unwrap();
    deliver(&mut s);
    let rx = s.receive(
        &mpdu(encrypt(
            &native(
                &key_frame(0x13ca, 6, AN, &kde([0x7e; 16]), Some(&first)),
                false,
            ),
            &second.tk,
            2,
            0,
        )),
        SN,
    );
    if rx != Err(Error::KeyReuse)
        || s.port_open()
        || s.pending_frame().is_some()
        || s.history.len() != 4
        || s.pair.as_ref().unwrap().material.as_slice() != second.tk
    {
        return TestResult::Fail("retired TK reappeared with a fresh CCMP owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security",
    smoke_station_retired_temporal_key_cannot_restart_packet_numbers
);
fn smoke_station_rsna_retry_does_not_reset_installed_key_state() -> TestResult {
    let mut s = established();
    let p = ptk(AN, SN);
    let mut eth = vec![2, 0, 0, 0, 0, 3];
    eth.extend_from_slice(&OWN);
    eth.extend_from_slice(&[8, 0, 0x45]);
    let first = s.transmit_ethernet(&eth).unwrap();
    if first[24] != 1 {
        return TestResult::Fail("initial protected data PN");
    }
    let repeated = key_frame(0x13ca, 3, AN, &kde(GTK), Some(&p));
    if s.receive(&mpdu(native(&repeated, false)), SN) != Ok(Rx::ReplyReady) {
        return TestResult::Fail("fresh-counter M3 retry not answered");
    }
    let reply = s.pending_frame().unwrap();
    if reply[1] & 0x40 == 0 || reply[24] != 2 {
        return TestResult::Fail("M3 retry did not retain installed TX PN");
    }
    deliver(&mut s);
    let second = s.transmit_ethernet(&eth).unwrap();
    if second[24] != 3 || s.history.len() != 2 {
        return TestResult::Fail("retry reinstalled TK or reset TX PN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security",
    smoke_station_rsna_retry_does_not_reset_installed_key_state
);
fn smoke_station_group_rekey_zero_is_receive_only_and_keeps_replay_separate() -> TestResult {
    let mut s = established();
    let p = ptk(AN, SN);
    let mut data = kde([0x7d; 16]);
    // GTK KDE KeyID0, distinct from the installed pairwise KeyID0.
    data[28] = 0;
    let group = key_frame(0x1382, 3, [0; 32], &data, Some(&p));
    if s.receive(&mpdu(encrypt(&native(&group, false), &p.tk, 1, 0)), SN) != Ok(Rx::ReplyReady) {
        return TestResult::Fail("authenticated group rekey not answered");
    }
    deliver(&mut s);
    let mut plain = native(&[0x45; 20], true);
    plain[30..32].copy_from_slice(&[8, 0]);
    let frame = encrypt(&plain, &[0x7d; 16], 6, 0);
    if !matches!(s.receive(&mpdu(frame.clone()), SN), Ok(Rx::Data(_)))
        || s.receive(&mpdu(frame), SN) != Ok(Rx::Ignored)
    {
        return TestResult::Fail("GTK0 replay/role selection failed");
    }
    let previous = encrypt(&plain, &GTK, 6, 2);
    if !matches!(s.receive(&mpdu(previous), SN), Ok(Rx::Data(_))) {
        return TestResult::Fail("GTK0 replay poisoned retained GTK2");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security",
    smoke_station_group_rekey_zero_is_receive_only_and_keeps_replay_separate
);

fn smoke_station_rsna_forged_m3_and_original_ap_rsne_binding() -> TestResult {
    let p = ptk(AN, SN);
    let mut s = security();
    s.receive(&mpdu(native(&key_frame(0x8a, 1, AN, &[], None), false)), SN)
        .unwrap();
    deliver(&mut s);
    let valid = key_frame(0x13ca, 2, AN, &kde(GTK), Some(&p));
    let mut forged = valid.clone();
    forged[81] ^= 1;
    if s.receive(&mpdu(native(&forged, false)), SN) != Ok(Rx::Ignored)
        || s.pending_frame().is_some()
        || s.pair.is_some()
    {
        return TestResult::Fail("forged M3 installed keys or reply");
    }
    if s.receive(&mpdu(native(&valid, false)), SN) != Ok(Rx::ReplyReady) {
        return TestResult::Fail("forged M3 poisoned authentic handshake");
    }
    let mut ap = crate::rsn::RsnIe::wpa2_psk_ccmp();
    ap.rsn_capabilities = 0x80;
    let mut s = Security::new(OWN, AP, &PMK, &rsne(), &ap.encode_body(), None, 2).unwrap();
    s.receive(&mpdu(native(&key_frame(0x8a, 1, AN, &[], None), false)), SN)
        .unwrap();
    deliver(&mut s);
    if s.receive(&mpdu(native(&valid, false)), SN) != Err(Error::Protocol)
        || s.port_open()
        || s.pair.is_some()
    {
        return TestResult::Fail("M3 substituted canonical station RSNE for original AP RSNE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/station_security",
    smoke_station_rsna_forged_m3_and_original_ap_rsne_binding
);
