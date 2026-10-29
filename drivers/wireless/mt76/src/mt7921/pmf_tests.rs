//! WPA3-SAE and PMF: SAE authentication over the shared plan, the
//! `MCU_CIPHER_BIP_CMAC_128` IGTK record, robust-management protection on
//! TX/RX and the SA Query responder, against the shared `FakeAp` profiles.
use super::*;
use crate::mt7921::association::{SaePassword, Security};
use alloc::boxed::Box;
use narf_wifi_fixtures::{ApPhase, ApPmf, ApSaePwe, FakeAp};

const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
const PASSWORD: &[u8] = b"narf-sae-password";
const IGTK: [u8; 16] = [0x3c; 16];

fn sae_ap(pwe: ApSaePwe) -> FakeAp {
    FakeAp::wpa3_sae(
        super::wmm_tests::NETWORK,
        b"narf",
        6,
        42,
        PASSWORD,
        pwe,
        [0xaa; 32],
    )
    .and_then(|ap| ap.with_igtk(IGTK, 5, 7))
    .unwrap()
}

fn pmf_ap() -> FakeAp {
    FakeAp::wpa2(
        super::wmm_tests::NETWORK,
        b"narf",
        6,
        42,
        [0x55; 32],
        [0xaa; 32],
    )
    .and_then(|ap| ap.with_pmf(ApPmf::Required))
    .and_then(|ap| ap.with_igtk(IGTK, 4, 7))
    .unwrap()
}

/// A boxed, radio-ready session whose model peer is `ap`.
fn prepared(ap: FakeAp) -> (Box<Session<Model>>, ScanBss) {
    let mut model = Model::new();
    let beacon = ap.beacon();
    let bss = ScanBss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: 6,
        band: None,
        signal_dbm: Some(-45),
        capability: u16::from_le_bytes([beacon[34], beacon[35]]),
        beacon_interval: 100,
        information_elements: beacon[36..].to_vec(),
    };
    model.access_point = Some(ap);
    let mut session = Box::new(Session::new(model, firmware(32)));
    run(Box::pin(session.run())).unwrap();
    run(Box::pin(session.initialize_radio())).unwrap();
    (session, bss)
}

fn join(session: &mut Session<Model>, bss: &ScanBss, security: Security) -> Result<u16, Error> {
    run(Box::pin(session.associate_station(
        bss,
        b"narf",
        security,
        test_permission(),
        &[],
    )))
}

fn sae() -> Security {
    Security::Wpa3Sae {
        password: SaePassword::new(PASSWORD).unwrap(),
    }
}

/// The station's IGTK STA_REC_KEY_V2 record (`sta_rec_sec`, len 80).
fn igtk_record(session: &Session<Model>) -> Option<Vec<u8>> {
    session
        .backend
        .frames
        .iter()
        .map(|(_, f)| f)
        .find(|f| f.len() > 88 && f[f.len() - 80..f.len() - 72] == [17, 0, 80, 0, 0, 2, 0, 0])
        .map(|f| f[f.len() - 80..].to_vec())
}

fn protected_management(frame: &[u8], pn: u64) -> Vec<u8> {
    let mut frame = frame.to_vec();
    frame[1] |= 0x40;
    let mut packet = vec![0; 40];
    packet[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes());
    packet[..4].copy_from_slice(&((2u32 << 27) | (40 + frame.len()) as u32).to_le_bytes());
    packet[4..8].copy_from_slice(&((4u32 << 16) | (1 << 11) | 1).to_le_bytes());
    packet[24..30].copy_from_slice(&pn.to_le_bytes()[..6]);
    packet[12..16].copy_from_slice(&(6u32 << 8).to_le_bytes());
    packet.extend_from_slice(&frame);
    packet
}

fn management(subtype: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[0] = subtype;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend_from_slice(body);
    frame
}

fn alive(session: &mut Session<Model>) -> bool {
    session
        .receive_ethernet()
        .is_ok_and(|frame| frame.is_none())
        && !session.peer_lost
}

fn sae_join(pwe: ApSaePwe) -> Result<(), &'static str> {
    let (mut session, bss) = prepared(sae_ap(pwe));
    if join(&mut session, &bss, sae()) != Ok(42) {
        return Err("SAE association failed");
    }
    let ap = session.backend.access_point.as_ref().unwrap();
    if ap.phase() != ApPhase::Authorized
        || ap.akm() != Some(narf_wireless::eapol::KeyMgmt::Sae)
        || !ap.pmf()
    {
        return Err("AP did not authorize an SAE/PMF station");
    }
    let sae_frames = session
        .backend
        .frames
        .iter()
        .filter(|(_, f)| f.len() > 30 && f[0] == 0xb0 && f[24..26] == [3, 0])
        .count();
    if sae_frames != 2 {
        return Err("SAE did not send exactly Commit and Confirm");
    }
    let record = igtk_record(&session).ok_or("no IGTK record")?;
    let gtk = session
        .security
        .as_ref()
        .and_then(|s| s.gtk().map(|(id, g)| (id, g.to_vec())))
        .ok_or("no installed GTK")?;
    if record[8..12] != [5, 36, gtk.0, 16]
        || record[12..28] != gtk.1[..]
        || record[44..48] != [10, 36, 0, 16]
        || record[48..64] != IGTK
        || !session
            .security
            .as_ref()
            .is_some_and(|s| s.protects_management())
    {
        return Err("IGTK record is not the Linux BIP batch layout");
    }
    // Unprotected unicast deauth and a broadcast deauth without a valid
    // MMIE are dropped under PMF; the BIP-protected one closes the link.
    session
        .backend
        .packets
        .push_back(super::descriptor(&management(0xc0, &[3, 0])));
    if !alive(&mut session) {
        return Err("unprotected unicast deauth accepted under PMF");
    }
    let bip = session
        .backend
        .access_point
        .as_mut()
        .unwrap()
        .bip_broadcast_deauth(3)
        .map_err(|_| "BIP deauth")?;
    let mut forged = bip.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let mut plain = bip.clone();
    plain.truncate(26);
    for bad in [forged, plain] {
        session.backend.packets.push_back(super::descriptor(&bad));
        if !alive(&mut session) {
            return Err("forged/unprotected broadcast deauth accepted");
        }
    }
    session.backend.packets.push_back(super::descriptor(&bip));
    if session.receive_ethernet() != Err(Error::DeviceGone) {
        return Err("valid BIP broadcast deauth ignored");
    }
    // Teardown after a peer deauth sends no deauth but retires the keys.
    let before = session.backend.frames.len();
    if run(Box::pin(session.disassociate_station())).is_err()
        || session.backend.frames[before..]
            .iter()
            .any(|(_, f)| f.first() == Some(&0xc0))
        || session.security.is_some()
    {
        return Err("teardown after BIP deauth");
    }
    Ok(())
}

fn mt76_wpa3_sae_h2e_and_hunt_and_peck_install_bip_igtk_and_admit_only_bip_deauth() -> TestResult {
    for pwe in [ApSaePwe::HashToElement, ApSaePwe::HuntAndPeck] {
        if let Err(error) = sae_join(pwe) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/pmf",
    mt76_wpa3_sae_h2e_and_hunt_and_peck_install_bip_igtk_and_admit_only_bip_deauth
);

fn mt76_wpa3_sae_wrong_password_and_pmf_policy_failures_install_no_keys() -> TestResult {
    let (mut session, bss) = prepared(sae_ap(ApSaePwe::HashToElement));
    let wrong = Security::Wpa3Sae {
        password: SaePassword::new(b"not-the-password").unwrap(),
    };
    if join(&mut session, &bss, wrong).is_ok()
        || session.security.is_some()
        || igtk_record(&session).is_some()
    {
        return TestResult::Fail("wrong SAE password associated or installed keys");
    }
    // ieee80211w=2 refuses an AP without MFPC; an SAE station refuses a
    // WPA2-only AP; an empty or oversized SAE password is refused.
    let (mut session, bss) = prepared(
        FakeAp::wpa2(
            super::wmm_tests::NETWORK,
            b"narf",
            6,
            42,
            [0x55; 32],
            [0xaa; 32],
        )
        .unwrap(),
    );
    let required = Security::Wpa2PskPmf {
        psk: [0x55; 32],
        required: true,
    };
    if join(&mut session, &bss, required).is_ok()
        || join(&mut session, &bss, sae()).is_ok()
        || SaePassword::new(b"").is_some()
        || SaePassword::new(&[b'x'; 129]).is_some()
    {
        return TestResult::Fail("PMF/SAE policy admitted an incompatible AP");
    }
    if crate::mt7921::association::igtk_record(4, &[0; 16], &[0; 16]).is_ok()
        || crate::mt7921::association::igtk_record(1, &[0; 15], &[0; 16]).is_ok()
        || crate::mt7921::association::igtk_record(1, &[0; 16], &[0; 17]).is_ok()
    {
        return TestResult::Fail("malformed IGTK record accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/pmf",
    mt76_wpa3_sae_wrong_password_and_pmf_policy_failures_install_no_keys
);

fn mt76_wpa2_pmf_protects_robust_tx_answers_sa_query_and_checks_management_pn() -> TestResult {
    let (mut session, bss) = prepared(pmf_ap());
    let security = Security::Wpa2PskPmf {
        psk: [0x55; 32],
        required: false,
    };
    if join(&mut session, &bss, security) != Ok(42)
        || !session.backend.access_point.as_ref().unwrap().pmf()
        || igtk_record(&session).is_none_or(|r| r[48..64] != IGTK)
    {
        return TestResult::Fail("WPA2-PSK PMF association/IGTK");
    }
    // An unprotected SA Query Request is dropped under PMF.
    let request = management(0xd0, &[8, 0, 0x34, 0x12]);
    session
        .backend
        .packets
        .push_back(super::descriptor(&request));
    if !alive(&mut session) || !session.control_pending.is_empty() {
        return TestResult::Fail("unprotected SA Query answered under PMF");
    }
    // A hardware-decrypted one is answered, protected, with its ID.
    session
        .backend
        .packets
        .push_back(protected_management(&request, 1));
    if !alive(&mut session) || session.control_pending.len() != 1 {
        return TestResult::Fail("protected SA Query not queued");
    }
    let before = session.backend.frames.len();
    if run(Box::pin(session.service_keys())).is_err() {
        return TestResult::Fail("SA Query response service");
    }
    let response = management(0xd0, &[8, 1, 0x34, 0x12]);
    let sent: Vec<_> = session.backend.frames[before..]
        .iter()
        .filter(|(_, f)| f.first() == Some(&0xd0))
        .collect();
    let mut expected = response.clone();
    expected[4..10].copy_from_slice(&AP);
    expected[10..16].copy_from_slice(&OWN);
    expected[1] = 0x40;
    if sent.len() != 1 || sent[0].1 != expected {
        return TestResult::Fail("SA Query response not protected/exact");
    }
    let txd = crate::mt7921::packet_tx::management(
        &expected,
        0x1000,
        1,
        1,
        crate::mt7921::association::LegacyRate::ONE_MBPS,
    )
    .unwrap();
    let mut multicast = expected.clone();
    multicast[4] |= 1;
    if txd[12] & 2 == 0
        || crate::mt7921::packet_tx::management(
            &multicast,
            0x1000,
            1,
            1,
            crate::mt7921::association::LegacyRate::ONE_MBPS,
        )
        .is_ok()
    {
        return TestResult::Fail("MT_TXD3_PROTECT_FRAME not set for protected management");
    }
    // A replayed management PN is dropped; a fresh protected deauth ends it.
    let deauth = management(0xc0, &[3, 0]);
    session
        .backend
        .packets
        .push_back(protected_management(&deauth, 1));
    if !alive(&mut session) {
        return TestResult::Fail("replayed protected deauth accepted");
    }
    session
        .backend
        .packets
        .push_back(protected_management(&deauth, 2));
    if session.receive_ethernet() != Err(Error::DeviceGone) {
        return TestResult::Fail("protected unicast deauth ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/pmf",
    mt76_wpa2_pmf_protects_robust_tx_answers_sa_query_and_checks_management_pn
);

fn mt76_pmf_teardown_sends_protected_deauth_before_key_retirement() -> TestResult {
    let (mut session, bss) = prepared(sae_ap(ApSaePwe::HashToElement));
    if join(&mut session, &bss, sae()) != Ok(42) {
        return TestResult::Fail("SAE association");
    }
    let before = session.backend.frames.len();
    if run(Box::pin(session.disassociate_station())).is_err() {
        return TestResult::Fail("PMF teardown");
    }
    let frames = &session.backend.frames[before..];
    let deauth = frames
        .iter()
        .position(|(_, f)| f.len() == 26 && f[0] == 0xc0);
    let key_off = frames
        .iter()
        .position(|(_, f)| f.len() > 16 && f[f.len() - 8..] == [17, 0, 8, 0, 1, 0, 0, 0]);
    if deauth.is_none_or(|d| frames[d].1[1] != 0x40 || key_off.is_none_or(|k| k < d))
        || session.security.is_some()
        || session.backend.access_point.is_some()
    {
        return TestResult::Fail("protected deauth must precede key retirement");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/pmf",
    mt76_pmf_teardown_sends_protected_deauth_before_key_retirement
);
