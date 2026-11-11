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

pub(super) fn pmf_ap() -> FakeAp {
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
pub(super) fn prepared(ap: FakeAp) -> (Box<Session<Model>>, ScanBss) {
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
        && !session.station.peer_lost
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
        .station
        .security
        .as_ref()
        .and_then(|s| s.gtk().map(|(id, g)| (id, g.to_vec())))
        .ok_or("no installed GTK")?;
    if record[8..12] != [5, 36, gtk.0, 16]
        || record[12..28] != gtk.1[..]
        || record[44..48] != [10, 36, 0, 16]
        || record[48..64] != IGTK
        || !session
            .station
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
        || session.station.security.is_some()
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

/// The association elements wpa_supplicant 2.12 passes in an SAE-offload
/// CONNECT for a NetworkManager `key-mgmt=sae` profile (`ieee80211w=2`):
/// its RSNE (SAE, MFPC|MFPR, PTKSA replay counters, BIP-CMAC-128), Supported
/// Operating Classes, Extended Capabilities and the RSNXE (H2E).
fn wpa_supplicant_sae_ies() -> Vec<u8> {
    let mut ie = vec![
        48, 26, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 8,
        0xcc, 0x00, 0, 0, 0x00, 0x0f, 0xac, 6,
    ];
    ie.extend_from_slice(&[59, 4, 115, 115, 116, 117]);
    ie.extend_from_slice(&[127, 10, 0x04, 0, 0x08, 0, 0, 0, 0, 0x40, 0, 0x20]);
    ie.extend_from_slice(&[244, 1, 0x20]);
    ie
}

/// The (re)association request the station sent, if any.
fn association_request(session: &Session<Model>) -> Option<Vec<u8>> {
    session
        .backend
        .frames
        .iter()
        .map(|(_, f)| f)
        .find(|f| f.len() > 28 && f[0] == 0x00 && f[4..10] == AP)
        .cloned()
}

/// Count of element `id` in the association request body.
fn element_count(request: &[u8], id: u8) -> usize {
    let mut rest = &request[28..];
    let mut count = 0;
    while rest.len() >= 2 {
        let len = 2 + usize::from(rest[1]);
        if rest[0] == id {
            count += 1;
        }
        rest = rest.get(len..).unwrap_or_default();
    }
    count
}

/// wpa_supplicant 2.12's SAE-offload connect, as nl80211 hands it to the
/// MT7922 station owner (`Security::Wpa3Sae` + the supplicant's elements),
/// against a WPA3-only AP (H2E and hunting-and-pecking) and a WPA3-Personal
/// transition-mode AP. The owner must complete SAE, associate with exactly
/// one RSNE and at most one RSNXE (its own, not the supplicant's), run the
/// 4-way handshake to the AP's Authorized state — what nl80211 reports as
/// PORT_AUTHORIZED — and negotiate PMF.
fn mt7922_wpa_supplicant_sae_offload_connect_authorizes_wpa3_and_transition_aps() -> TestResult {
    use core::fmt::Write;
    let aps = [
        ("WPA3-only H2E", sae_ap(ApSaePwe::HashToElement)),
        (
            "WPA3-only hunting-and-pecking",
            sae_ap(ApSaePwe::HuntAndPeck),
        ),
        (
            "WPA3 transition",
            sae_ap(ApSaePwe::HashToElement)
                .with_sae_transition()
                .unwrap(),
        ),
    ];
    for (name, ap) in aps {
        let (mut session, bss) = prepared(ap);
        let aid = run(Box::pin(session.associate_station(
            &bss,
            b"narf",
            sae(),
            test_permission(),
            &wpa_supplicant_sae_ies(),
        )));
        if aid != Ok(42) {
            let _ = writeln!(narf_console::Writer, "mt7922 SAE offload {name}: {aid:?}");
            return TestResult::Fail("SAE-offload connect did not associate");
        }
        let ap = session.backend.access_point.as_ref().unwrap();
        if ap.phase() != ApPhase::Authorized
            || ap.akm() != Some(narf_wireless::eapol::KeyMgmt::Sae)
            || !ap.pmf()
        {
            let _ = writeln!(narf_console::Writer, "mt7922 SAE offload {name}");
            return TestResult::Fail("AP did not authorize the SAE/PMF station");
        }
        let Some(request) = association_request(&session) else {
            return TestResult::Fail("no association request");
        };
        if element_count(&request, 48) != 1
            || element_count(&request, 244) > 1
            || element_count(&request, 59) != 1
        {
            let _ = writeln!(narf_console::Writer, "mt7922 SAE offload {name}");
            return TestResult::Fail("association request elements are not one RSNE/RSNXE");
        }
        if igtk_record(&session).is_none_or(|r| r[48..64] != IGTK) {
            return TestResult::Fail("no BIP IGTK installed after SAE-offload connect");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/pmf",
    mt7922_wpa_supplicant_sae_offload_connect_authorizes_wpa3_and_transition_aps
);

fn mt76_wpa3_sae_wrong_password_and_pmf_policy_failures_install_no_keys() -> TestResult {
    let (mut session, bss) = prepared(sae_ap(ApSaePwe::HashToElement));
    let wrong = Security::Wpa3Sae {
        password: SaePassword::new(b"not-the-password").unwrap(),
    };
    if join(&mut session, &bss, wrong).is_ok()
        || session.station.security.is_some()
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
    if !alive(&mut session) || !session.station.control_pending.is_empty() {
        return TestResult::Fail("unprotected SA Query answered under PMF");
    }
    // A hardware-decrypted one is answered, protected, with its ID.
    session
        .backend
        .packets
        .push_back(protected_management(&request, 1));
    if !alive(&mut session) || session.station.control_pending.len() != 1 {
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
        || session.station.security.is_some()
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

/// wpa_supplicant's WPA2-Personal RSNE with `ieee80211w` = 1 or 2 toward a
/// WMM AP: AKM `akm`, MFPC (|MFPR), sixteen PTKSA replay counters, zero
/// PMKIDs, BIP-CMAC-128; then Extended Capabilities.
fn wpa_supplicant_wpa2_ies(akm: u8, required: bool) -> Vec<u8> {
    let caps: u8 = if required { 0xcc } else { 0x8c };
    let mut ie = vec![
        48, 26, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, akm,
        caps, 0x00, 0, 0, 0x00, 0x0f, 0xac, 6,
    ];
    ie.extend_from_slice(&[127, 10, 0x04, 0, 0x08, 0, 0, 0, 0, 0x40, 0, 0x20]);
    ie
}

/// The PMK-offload CONNECT of a NetworkManager WPA-PSK profile with PMF
/// optional or required, as nl80211 hands it to the MT7922 owner: the
/// supplicant's RSNE selects the owner profile (`wpa2_from_supplicant`),
/// and the owner joins the FakeAp with exactly that AKM (PSK or
/// PSK-SHA256), negotiates PMF, completes the 4-way handshake and installs
/// the BIP IGTK.
fn mt7922_wpa2_pmf_and_psk_sha256_from_the_supplicants_selection() -> TestResult {
    use narf_wireless::association::Pmf;
    use narf_wireless::eapol::KeyMgmt;
    let cases = [
        (2u8, true, KeyMgmt::Psk, pmf_ap()),
        (
            6,
            false,
            KeyMgmt::PskSha256,
            FakeAp::wpa2(
                super::wmm_tests::NETWORK,
                b"narf",
                6,
                42,
                [0x55; 32],
                [0xaa; 32],
            )
            .and_then(|ap| ap.with_pmf(ApPmf::Optional))
            .and_then(|ap| ap.with_akms(&[2, 6]))
            .and_then(|ap| ap.with_igtk(IGTK, 4, 7))
            .unwrap(),
        ),
    ];
    for (akm, required, expected, ap) in cases {
        let ies = wpa_supplicant_wpa2_ies(akm, required);
        let Some(security) = Security::wpa2_from_supplicant([0x55; 32], &ies) else {
            return TestResult::Fail("supplicant WPA2 PMF selection not mapped");
        };
        let want_pmf = if required {
            Pmf::Required
        } else {
            Pmf::Optional
        };
        if !matches!(security, Security::Wpa2PskSelected { akm: a, pmf, .. }
            if a == akm && pmf == want_pmf)
        {
            return TestResult::Fail("supplicant selection mapped to a different owner profile");
        }
        let (mut session, bss) = prepared(ap);
        let aid = run(Box::pin(session.associate_station(
            &bss,
            b"narf",
            security,
            test_permission(),
            &ies,
        )));
        if aid != Ok(42) {
            return TestResult::Fail("WPA2 PMF join with the supplicant's elements failed");
        }
        let ap = session.backend.access_point.as_ref().unwrap();
        if ap.phase() != ApPhase::Authorized || ap.akm() != Some(expected) || !ap.pmf() {
            return TestResult::Fail("AP did not authorize the selected AKM with PMF");
        }
        if igtk_record(&session).is_none_or(|r| r[48..64] != IGTK) {
            return TestResult::Fail("no BIP IGTK after the WPA2 PMF join");
        }
    }
    // Legacy and malformed selections.
    let legacy = [
        48, 20, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 2,
        0x0c, 0x00,
    ];
    let mut mfpr_only = wpa_supplicant_wpa2_ies(2, true);
    mfpr_only[20] = 0x4c;
    let mut sae = wpa_supplicant_wpa2_ies(2, true);
    sae[19] = 8;
    if !matches!(
        Security::wpa2_from_supplicant([0x55; 32], &legacy),
        Some(Security::Wpa2Psk { .. })
    ) || !matches!(
        Security::wpa2_from_supplicant([0x55; 32], &[]),
        Some(Security::Wpa2Psk { .. })
    ) || Security::wpa2_from_supplicant([0x55; 32], &mfpr_only).is_some()
        || Security::wpa2_from_supplicant([0x55; 32], &sae).is_some()
    {
        return TestResult::Fail("legacy / malformed WPA2 selection mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/pmf",
    mt7922_wpa2_pmf_and_psk_sha256_from_the_supplicants_selection
);

/// SAE / Open System Authentication frames the station sent from `from`.
fn auth_frames(session: &Session<Model>, from: usize, algorithm: u8) -> usize {
    session.backend.frames[from..]
        .iter()
        .filter(|(_, f)| f.len() >= 30 && f[0] == 0xb0 && f[24..26] == [algorithm, 0])
        .count()
}

/// PMKSA caching for an MT7922 WPA3 station, as wpa_supplicant does it for
/// SAE: the first join runs SAE and caches the PMKSA; a reconnect to the AP
/// that still holds it uses Open System authentication with the PMKID and
/// no SAE frames; an AP that lost it answers WLAN_STATUS_INVALID_PMKID and
/// the station falls back to full SAE within the same join, replacing the
/// entry; other credentials never use the entry; FLUSH_PMKSA empties it.
fn mt7922_sae_pmksa_cache_skips_sae_on_reconnect_and_falls_back() -> TestResult {
    let (mut session, bss) = prepared(sae_ap(ApSaePwe::HashToElement));
    session.backend.keep_access_point = true;
    if join(&mut session, &bss, sae()) != Ok(42) || session.pmksa.len() != 1 {
        return TestResult::Fail("first SAE join did not cache its PMKSA");
    }
    let reconnect =
        |session: &mut Session<Model>,
         ap: fn(&mut FakeAp) -> Result<(), narf_wifi_fixtures::ApError>| {
            if run(Box::pin(session.disassociate_station())).is_err() {
                return Err("teardown");
            }
            ap(session.backend.access_point.as_mut().unwrap()).map_err(|_| "AP restart")?;
            let before = session.backend.frames.len();
            if join(session, &bss, sae()) != Ok(42) {
                return Err("reconnect failed");
            }
            let ap = session.backend.access_point.as_ref().unwrap();
            if ap.phase() != ApPhase::Authorized || !ap.pmf() {
                return Err("AP did not authorize the reconnect with PMF");
            }
            Ok((
                auth_frames(session, before, 0),
                auth_frames(session, before, 3),
            ))
        };
    // The AP still holds the PMKSA: Open System + PMKID, no SAE.
    match reconnect(&mut session, FakeAp::restart_keeping_pmksa) {
        Ok((1, 0)) => {}
        Ok(_) => return TestResult::Fail("cached reconnect still ran SAE"),
        Err(reason) => return TestResult::Fail(reason),
    }
    // The AP lost it: one refused Open System attempt, then full SAE.
    match reconnect(&mut session, FakeAp::forget_pmksa) {
        Ok((1, 2)) if session.pmksa.len() == 1 => {}
        Ok(_) => return TestResult::Fail("no full-SAE fallback after INVALID_PMKID"),
        Err(reason) => return TestResult::Fail(reason),
    }
    // Other credentials for the same BSS never use the cached PMK.
    let other = crate::mt7921::pmksa::binding(b"narf", b"another-password");
    let mine = crate::mt7921::pmksa::binding(b"narf", PASSWORD);
    let now = session.backend.now_ns();
    if session.pmksa.lookup(bss.bssid, other, now).is_some()
        || session.pmksa.lookup(bss.bssid, mine, now).is_none()
        || session
            .pmksa
            .lookup(bss.bssid, mine, now + crate::mt7921::pmksa::LIFETIME_NS)
            .is_some()
    {
        return TestResult::Fail("PMKSA bound to the wrong credentials or lifetime");
    }
    // NL80211_CMD_FLUSH_PMKSA.
    let mut cache = crate::mt7921::pmksa::Cache::default();
    cache.insert(bss.bssid, mine, [1; 16], &[2; 32], 0);
    super::BOOT_PMKSA_REQUESTS
        .lock()
        .push(super::PmksaRequest::Flush);
    super::apply_pmksa_requests(&mut cache);
    if !cache.is_empty() {
        return TestResult::Fail("FLUSH_PMKSA left an entry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/pmf",
    mt7922_sae_pmksa_cache_skips_sae_on_reconnect_and_falls_back
);

/// Roaming within the ESS (cfg80211 CONNECT with PREV_BSSID, mac80211
/// reassociation): after leaving the current AP the owner's next join sends
/// a Reassociation Request naming that AP, accepts the Reassociation
/// Response and completes the RSNA (here from the cached SAE PMKSA); the
/// reassociation is consumed by that one join.
fn mt7922_roam_sends_a_reassociation_request_naming_the_current_ap() -> TestResult {
    let (mut session, bss) = prepared(sae_ap(ApSaePwe::HashToElement));
    session.backend.keep_access_point = true;
    if join(&mut session, &bss, sae()) != Ok(42)
        || run(Box::pin(session.disassociate_station())).is_err()
        || session
            .backend
            .access_point
            .as_mut()
            .unwrap()
            .restart_keeping_pmksa()
            .is_err()
    {
        return TestResult::Fail("first association or teardown");
    }
    session.station.reassociate_from = Some(AP);
    let before = session.backend.frames.len();
    if join(&mut session, &bss, sae()) != Ok(42) {
        return TestResult::Fail("reassociation failed");
    }
    let requests: Vec<_> = session.backend.frames[before..]
        .iter()
        .map(|(_, f)| f)
        .filter(|f| f.len() > 34 && f[0] & 0xfc == 0x20)
        .collect();
    let ap = session.backend.access_point.as_ref().unwrap();
    if requests.len() != 1
        || requests[0][28..34] != AP
        || ap.phase() != ApPhase::Authorized
        || session.station.reassociate_from.is_some()
    {
        return TestResult::Fail("no single Reassociation Request naming the current AP");
    }
    // Without a roam the request is a plain Association Request.
    if narf_wireless::association::reassociation_request(&requests[0][..], AP).is_some() {
        return TestResult::Fail("a Reassociation Request was converted again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/pmf",
    mt7922_roam_sends_a_reassociation_request_naming_the_current_ap
);
