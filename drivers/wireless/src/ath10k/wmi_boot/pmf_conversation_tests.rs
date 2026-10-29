//! Actual CE/HTT/RSNA/netdev WPA2-PMF and WPA3-SAE conversations against
//! the shared FakeAp (verification spec, WPA3 and PMF profiles). The AP
//! side protects robust frames with its own PTK/IGTK; nothing here reuses
//! the host encoder.
use super::*;
use narf_wifi_fixtures::{ApPmf, ApSaePwe};
use narf_wireless::eapol::KeyMgmt;

const PASSWORD: &[u8] = b"narf-sae-password";

fn pmf_harness(version: u32, dialect: Dialect) -> Harness {
    let h = Harness::new(version, dialect, true);
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.ap = FakeAp::wpa2(network(), b"narf", 1, 7, PMK, ANONCE)
            .and_then(|ap| ap.with_pmf(ApPmf::Required))
            .unwrap();
    });
    h
}
fn sae_harness(version: u32, dialect: Dialect, pwe: ApSaePwe, password: &[u8]) -> Harness {
    let h = Harness::new(version, dialect, true);
    h.model(|m| {
        m.data.as_mut().unwrap().ap =
            FakeAp::wpa3_sae(network(), b"narf", 1, 7, password, pwe, ANONCE).unwrap();
    });
    h
}
fn sae_request(h: &Harness) -> AssociateRequest {
    let mut request = h.request();
    request.security = SecurityConfig::Wpa3 {
        password: PASSWORD.to_vec(),
    };
    request
}
fn join_sae(h: &Harness) -> Result<(), &'static str> {
    h.scan()?;
    if !matches!(
        drive(h.device.associate_for_test(sae_request(h), [0x73; 32])),
        Poll::Ready(Ok(()))
    ) || !h.device.link_up()
    {
        return Err("native SAE/PMF association or RSNA failed");
    }
    Ok(())
}
/// A robust management frame from the AP, CCMP-protected with the AP's
/// PTK (mac80211 `ccmp_special_blocks` management AAD/nonce).
fn protected(h: &Harness, subtype: u8, body: &[u8], pn: u64) -> Vec<u8> {
    let mut header = vec![subtype, 0x40, 0, 0];
    header.extend_from_slice(&OWN);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&[0, 0]);
    let tk = h.model(|m| m.data.as_ref().unwrap().ap.pairwise_tk().unwrap());
    let mut plain = body.to_vec();
    let wire = narf_wireless::ccmp::protect(&Ccm, &header, &tk, pn, 0, 0, true, &mut plain).unwrap();
    header.extend_from_slice(&wire);
    header
}
fn unprotected(subtype: u8, destination: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut frame = vec![subtype, 0, 0, 0];
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(body);
    frame
}
fn inject(h: &Harness, frame: Vec<u8>) {
    h.model(|m| management_frame(m, frame));
    h.pump();
}
/// Decrypt one host robust frame with the AP's PTK; returns its body.
fn opened(h: &Harness, frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 24 + 16 || frame[1] != 0x40 || frame[4..10] != AP || frame[10..16] != OWN {
        return None;
    }
    let tk = h.model(|m| m.data.as_ref().unwrap().ap.pairwise_tk().unwrap());
    let mut replay = narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 };
    let mut body = frame[24..].to_vec();
    narf_wireless::ccmp::unprotect(&Ccm, &frame[..24], &tk, 0, true, &mut replay, &mut body).ok()
}
fn roundtrip(h: &Harness) -> Result<(), &'static str> {
    let (up, down) = packets();
    narf_net::iface::send_on(&h.name, &up).map_err(|_| "PMF uplink")?;
    h.pump();
    let bytes = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
    h.model(|m| m.data.as_mut().unwrap().queue.push_back(bytes));
    h.pump();
    if !h.received(&down) || !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up)) {
        return Err("PMF/SAE native Ethernet");
    }
    Ok(())
}
/// Local disconnect under PMF: exactly one CCMP-protected deauthentication
/// (reason 3) before the native teardown completes.
fn teardown(h: &Harness) -> Result<(), &'static str> {
    let before = h.model(|m| m.data.as_ref().unwrap().management_tx.len());
    h.model(|m| teardown_tests::arm_data_disconnect(m, false));
    if !matches!(drive(h.device.disassociate()), Poll::Ready(Ok(()))) {
        return Err("PMF native teardown failed");
    }
    h.pump();
    let sent = h.model(|m| m.data.as_ref().unwrap().management_tx[before..].to_vec());
    if sent.len() != 1
        || sent[0][0] != 0xc0
        || opened(h, &sent[0]).as_deref() != Some(&[3, 0])
        || !h.closed()
        || !h.model(|m| m.ce.as_ref().unwrap().retained())
    {
        return Err("PMF teardown lacked one protected deauthentication or kept the port");
    }
    Ok(())
}

fn smoke_ath10k_wpa2_pmf_six_dialects_bip_igtk_data_and_protected_teardown() -> TestResult {
    for (version, dialect) in BAND_DIALECTS {
        let result = (|| {
            let h = pmf_harness(version, dialect);
            h.join()?;
            if !h.model(|m| {
                let ap = &m.data.as_ref().unwrap().ap;
                ap.pmf() && ap.igtk().is_some()
            }) {
                return Err("WPA2 association did not negotiate PMF/IGTK");
            }
            roundtrip(&h)?;
            teardown(&h)
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/pmf",
    smoke_ath10k_wpa2_pmf_six_dialects_bip_igtk_data_and_protected_teardown
);

fn smoke_ath10k_pmf_drops_unprotected_robust_frames_and_answers_protected_sa_query() -> TestResult {
    for (version, dialect) in [(4, Dialect::Tlv), (1, Dialect::Main), (6, Dialect::TenFour)] {
        let result = (|| {
            let h = pmf_harness(version, dialect);
            h.join()?;
            // Unprotected unicast deauth/disassoc, a broadcast deauth without
            // a valid MMIE and an unprotected SA Query are all dropped.
            for frame in [
                unprotected(0xc0, OWN, &[7, 0]),
                unprotected(0xa0, OWN, &[8, 0]),
                unprotected(0xc0, [0xff; 6], &[7, 0]),
                unprotected(0xd0, OWN, &[8, 0, 0x34, 0x12]),
            ] {
                inject(&h, frame);
                let _ = drive(h.device.flush_management());
            }
            if !h.device.link_up() || h.model(|m| !m.data.as_ref().unwrap().management_tx.is_empty())
            {
                return Err("unprotected robust frame acted on under PMF");
            }
            roundtrip(&h)?;
            // A protected SA Query Request is answered, protected, with its id.
            inject(&h, protected(&h, 0xd0, &[8, 0, 0x34, 0x12], 1 << 20));
            // The service worker's await point after the synchronous drain.
            if !matches!(drive(h.device.flush_management()), Poll::Ready(Ok(()))) {
                return Err("queued SA Query response publication failed");
            }
            let sent = h.model(|m| m.data.as_ref().unwrap().management_tx.clone());
            if sent.len() != 1 || sent[0][0] != 0xd0 || opened(&h, &sent[0]).as_deref() != Some(&[8, 1, 0x34, 0x12])
            {
                return Err("protected SA Query not answered with a protected response");
            }
            // A replayed management PN is dropped; a forged MIC too.
            inject(&h, protected(&h, 0xc0, &[3, 0], 1 << 20));
            let mut forged = protected(&h, 0xc0, &[3, 0], (1 << 20) + 1);
            let last = forged.len() - 1;
            forged[last] ^= 1;
            inject(&h, forged);
            if !h.device.link_up() {
                return Err("replayed/forged protected deauthentication accepted");
            }
            // A fresh protected unicast deauthentication ends the link.
            inject(&h, protected(&h, 0xc0, &[3, 0], (1 << 20) + 2));
            if !h.closed() || !h.model(|m| m.ce.as_ref().unwrap().retained()) {
                return Err("protected deauthentication ignored or DMA released");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/pmf",
    smoke_ath10k_pmf_drops_unprotected_robust_frames_and_answers_protected_sa_query
);

fn smoke_ath10k_pmf_bip_broadcast_deauth_closes_and_non_pmf_ap_is_unchanged() -> TestResult {
    let result = (|| {
        let h = pmf_harness(4, Dialect::Tlv);
        h.join()?;
        let deauth = h.model(|m| m.data.as_mut().unwrap().ap.bip_broadcast_deauth(3).unwrap());
        inject(&h, deauth);
        if !h.closed() {
            return Err("BIP-protected broadcast deauthentication ignored");
        }
        // An AP without MFPC keeps the exact legacy WPA2 RSNE (the plain
        // FakeAp compares it byte-for-byte) and its unprotected deauth.
        let legacy = Harness::new(4, Dialect::Tlv, true);
        legacy.join()?;
        if legacy.model(|m| m.data.as_ref().unwrap().ap.pmf()) {
            return Err("non-PMF AP negotiated PMF");
        }
        inject(&legacy, unprotected(0xc0, OWN, &[7, 0]));
        if !legacy.closed() {
            return Err("legacy unprotected deauthentication ignored");
        }
        Ok(())
    })();
    result.map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/pmf",
    smoke_ath10k_pmf_bip_broadcast_deauth_closes_and_non_pmf_ap_is_unchanged
);

fn smoke_ath10k_wpa3_sae_h2e_and_hunt_and_peck_data_and_protected_teardown() -> TestResult {
    for (version, dialect, pwe) in [
        (4, Dialect::Tlv, ApSaePwe::HashToElement),
        (1, Dialect::Main, ApSaePwe::HuntAndPeck),
        (6, Dialect::TenFour, ApSaePwe::HashToElement),
    ] {
        let result = (|| {
            let h = sae_harness(version, dialect, pwe, PASSWORD);
            join_sae(&h)?;
            if !h.model(|m| {
                let ap = &m.data.as_ref().unwrap().ap;
                ap.pmf() && ap.akm() == Some(KeyMgmt::Sae) && ap.igtk().is_some()
            }) {
                return Err("SAE association did not negotiate AKM 8 with PMF");
            }
            roundtrip(&h)?;
            inject(&h, unprotected(0xc0, OWN, &[7, 0]));
            if !h.device.link_up() {
                return Err("SAE link accepted an unprotected deauthentication");
            }
            teardown(&h)
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wpa3",
    smoke_ath10k_wpa3_sae_h2e_and_hunt_and_peck_data_and_protected_teardown
);

fn smoke_ath10k_wpa3_wrong_password_or_non_sae_ap_never_opens() -> TestResult {
    for case in 0..2 {
        let result = (|| {
            let h = if case == 0 {
                sae_harness(4, Dialect::Tlv, ApSaePwe::HashToElement, b"other-password")
            } else {
                // A WPA2-only AP cannot satisfy a WPA3 request.
                Harness::new(4, Dialect::Tlv, true)
            };
            h.scan()?;
            if !matches!(
                drive(h.device.associate_for_test(sae_request(&h), [0x73; 32])),
                Poll::Ready(Err(_))
            ) || !h.never_opened()
                || !h.model(|m| m.ce.as_ref().unwrap().retained())
                || h.model(|m| m.data.as_ref().unwrap().ap.pairwise_tk().is_some())
            {
                return Err("failed SAE opened the port or installed keys");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wpa3",
    smoke_ath10k_wpa3_wrong_password_or_non_sae_ap_never_opens
);
