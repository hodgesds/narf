use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
fn bss() -> Bss {
    Bss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: 1,
        signal_dbm: None,
        capability: 1,
        beacon_interval: 100,
        information_elements: vec![0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96],
    }
}
fn smoke_shared_join_native_frames_and_rate_bitmaps() -> TestResult {
    let mut plan = JoinPlan::prepare(&bss(), OWN, b"narf", SecurityMode::Open).unwrap();
    if plan.legacy_rates() != (15, 15) || plan.security() != SecurityMode::Open {
        return TestResult::Fail("shared plan lost validated rates/mode");
    }
    let auth = plan.start_authentication().unwrap();
    if auth.len() != 30
        || auth[4..10] != AP
        || auth[10..16] != OWN
        || auth[16..22] != AP
        || auth[24..] != [0, 0, 1, 0, 0, 0]
    {
        return TestResult::Fail("shared authentication layout differs");
    }
    let mut response = management(0xb0, AP, OWN);
    response[16..22].copy_from_slice(&AP);
    response.extend_from_slice(&[0, 0, 2, 0, 0, 0]);
    let assoc = plan.authentication_response(&response).unwrap().unwrap();
    if assoc[24..]
        != [
            1, 0, 5, 0, 0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96,
        ]
    {
        return TestResult::Fail("shared association layout differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/association",
    smoke_shared_join_native_frames_and_rate_bitmaps
);
fn smoke_shared_join_bounded_native_inputs_and_security() -> TestResult {
    let mut ap = bss();
    ap.information_elements.resize(2050, 0);
    if !matches!(
        JoinPlan::prepare(&ap, OWN, b"narf", SecurityMode::Open),
        Err(Error::InvalidBss)
    ) {
        return TestResult::Fail("unbounded AP IE storage was accepted");
    }
    let mut ap = bss();
    ap.capability |= 0x10;
    if !matches!(
        JoinPlan::prepare(&ap, OWN, b"narf", SecurityMode::Open),
        Err(Error::UnsupportedSecurity)
    ) {
        return TestResult::Fail("protected AP downgraded");
    }
    let mut ap = bss();
    ap.channel = 14;
    if JoinPlan::prepare(&ap, OWN, b"narf", SecurityMode::Open).is_ok() {
        return TestResult::Fail("unsupported geometry was broadened by extraction");
    }
    let mut plan = JoinPlan::prepare(&bss(), OWN, b"narf", SecurityMode::Open).unwrap();
    plan.cancel();
    if plan.start_authentication() != Err(Error::Busy) || plan.phase() != Phase::Failed {
        return TestResult::Fail("cancelled management plan restarted");
    }
    let mut plan = JoinPlan::prepare(&bss(), OWN, b"narf", SecurityMode::Open).unwrap();
    let elements = [127, 2, 0, 0].repeat(512);
    plan.append_sme_ies(&elements).unwrap();
    let before = plan.assoc.clone();
    if plan.append_sme_ies(&elements) != Err(Error::InvalidBss) || plan.assoc != before {
        return TestResult::Fail("repeated SME append bypassed the frame bound");
    }
    plan.start_authentication().unwrap();
    let mut response = management(0xb0, AP, OWN);
    response[16..22].copy_from_slice(&AP);
    response.extend_from_slice(&[0, 0, 2, 0, 0, 0]);
    response.resize(4097, 0);
    if plan.authentication_response(&response) != Err(Error::Protocol)
        || plan.phase() != Phase::Failed
    {
        return TestResult::Fail("unbounded native authentication response accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/association",
    smoke_shared_join_bounded_native_inputs_and_security
);

fn smoke_shared_join_fragmented_responses_leave_phase_unchanged() -> TestResult {
    let mut plan = JoinPlan::prepare(&bss(), OWN, b"narf", SecurityMode::Open).unwrap();
    plan.start_authentication().unwrap();
    // Matching RA/local, TA/AP and BSSID/AP, valid open authentication,
    // More Fragments clear, but SequenceControl fragment number is one.
    let mut auth = vec![
        0xb0, 0, 0, 0, 2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 2, 1, 0, 0, 0, 2, 0, 0, 0,
    ];
    if plan.authentication_response(&auth) != Ok(None) || plan.phase() != Phase::AwaitAuthentication
    {
        return TestResult::Fail("fragmented matching authentication advanced phase");
    }
    auth[22] = 0;
    if plan.authentication_response(&auth).unwrap().is_none()
        || plan.phase() != Phase::AwaitAssociation
    {
        return TestResult::Fail("complete authentication no longer advances");
    }
    // Valid ESS/status/AID, same native identities, final fragment number one.
    let mut assoc = vec![
        0x10, 0, 0, 0, 2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 2, 1, 0, 1, 0, 0, 0, 1,
        0xc0,
    ];
    assoc.extend_from_slice(&[1, 4, 0x82, 0x84, 0x8b, 0x96]);
    if plan.association_response(&assoc) != Ok(None) || plan.phase() != Phase::AwaitAssociation {
        return TestResult::Fail("fragmented matching association advanced phase");
    }
    assoc[22] = 0;
    if plan.association_response(&assoc) != Ok(Some(1))
        || plan.phase() != (Phase::Associated { aid: 1 })
    {
        return TestResult::Fail("complete association no longer advances");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/association",
    smoke_shared_join_fragmented_responses_leave_phase_unchanged
);

fn awaiting_association(ap: &Bss) -> JoinPlan {
    let mut plan = JoinPlan::prepare(ap, OWN, b"narf", SecurityMode::Open).unwrap();
    plan.start_authentication().unwrap();
    let mut response = management(0xb0, AP, OWN);
    response[16..22].copy_from_slice(&AP);
    response.extend_from_slice(&[0, 0, 2, 0, 0, 0]);
    plan.authentication_response(&response).unwrap().unwrap();
    plan
}

fn association_reply(elements: &[u8]) -> Vec<u8> {
    // Literal IEEE AssocResp: peer/local/BSSID, ESS, success and AID42.
    let mut response = vec![
        0x10, 0, 0, 0, 2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 2, 0, 0, 1, 0, 0, 0, 42,
        0xc0,
    ];
    response.extend_from_slice(elements);
    response
}

fn offered_bss() -> Bss {
    let mut ap = bss();
    // Basic 1/2Mbps; optional 5.5/11/6/12/24/54Mbps.
    ap.information_elements = vec![
        0, 4, b'n', b'a', b'r', b'f', 1, 8, 0x82, 0x84, 11, 22, 12, 24, 48, 108,
    ];
    ap
}

fn smoke_shared_join_response_narrows_rates_transactionally() -> TestResult {
    let mut plan = awaiting_association(&offered_bss());
    if plan.legacy_rates() != (0x95f, 3) {
        return TestResult::Fail("request's literal offered rate set changed");
    }
    // Retain 1/2/6/24Mbps; new optional 36Mbps and unknown optional55.5
    // were not offered and cannot broaden the firmware rate set. 24 is
    // newly mandatory and the beacon's mandatory1/2 remain supported.
    let response = association_reply(&[1, 5, 0x82, 0x84, 12, 72, 111, 50, 1, 0xb0]);
    if plan.association_response(&response) != Ok(Some(42))
        || plan.legacy_rates() != (0x113, 0x103)
        || plan.phase() != (Phase::Associated { aid: 42 })
    {
        return TestResult::Fail("response did not narrow the offered rates/basic set");
    }
    if plan.association_response(&response) != Err(Error::Busy)
        || plan.legacy_rates() != (0x113, 0x103)
    {
        return TestResult::Fail("duplicate response altered negotiated rates");
    }
    // Some APs omit Basic flags in the response; keep the checked beacon
    // requirements instead of guessing a new mandatory rate.
    let mut plan = awaiting_association(&offered_bss());
    if plan.association_response(&association_reply(&[1, 3, 2, 4, 12])) != Ok(Some(42))
        || plan.legacy_rates() != (0x13, 3)
    {
        return TestResult::Fail("response without Basic flags lost beacon requirements");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/association",
    smoke_shared_join_response_narrows_rates_transactionally
);

fn smoke_shared_join_bad_response_rates_fail_without_committing() -> TestResult {
    for (elements, expected) in [
        (&[][..], Error::UnsupportedRates),
        (&[50, 2, 0x82, 0x84], Error::UnsupportedRates),
        (&[1, 0], Error::Protocol),
        (&[1, 9, 2, 4, 11, 22, 12, 24, 48, 96, 108], Error::Protocol),
        (&[1, 1, 0x82, 1, 1, 0x84], Error::Protocol),
        (&[1, 2, 0x82, 0x84, 50, 1, 12, 50, 1, 24], Error::Protocol),
        (&[1, 2, 0x82, 0x84, 50, 0], Error::Protocol),
        (&[1, 2, 0x82, 0x84, 127, 3, 0], Error::Protocol),
        (&[1, 2, 0x82, 0x84, 50], Error::Protocol),
        (&[1, 2, 0x82, 0xfe], Error::UnsupportedRates),
        (&[1, 1, 0x82], Error::UnsupportedRates),
        (&[1, 2, 0x82, 0x84, 50, 1, 0xc8], Error::UnsupportedRates),
        (&[1, 2, 0x8c, 0x98], Error::UnsupportedRates),
        (&[1, 2, 111, 112], Error::UnsupportedRates),
    ] {
        let mut plan = awaiting_association(&offered_bss());
        let offered = plan.legacy_rates();
        if plan.association_response(&association_reply(elements)) != Err(expected)
            || plan.phase() != Phase::Failed
            || plan.legacy_rates() != offered
            || plan.association_response(&association_reply(&[1, 2, 0x82, 0x84]))
                != Err(Error::Busy)
        {
            return TestResult::Fail("invalid response committed rates or reopened association");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/association",
    smoke_shared_join_bad_response_rates_fail_without_committing
);

fn smoke_shared_join_response_keeps_five_ghz_rates_in_band() -> TestResult {
    let mut ap = bss();
    ap.channel = 36;
    ap.information_elements = vec![
        0, 4, b'n', b'a', b'r', b'f', 1, 5, 0x8c, 0x98, 0xb0, 96, 108,
    ];
    let mut plan = awaiting_association(&ap);
    if plan.association_response(&association_reply(&[1, 5, 0x8c, 0x98, 0xb0, 96, 2]))
        != Ok(Some(42))
        || plan.legacy_rates() != (0x550, 0x150)
    {
        return TestResult::Fail("five-GHz response rates were not intersected in band");
    }
    let mut plan = awaiting_association(&ap);
    let offered = plan.legacy_rates();
    if plan.association_response(&association_reply(&[1, 4, 0x8c, 0x98, 0xb0, 0x82]))
        != Err(Error::UnsupportedRates)
        || plan.phase() != Phase::Failed
        || plan.legacy_rates() != offered
    {
        return TestResult::Fail("five-GHz response admitted mandatory CCK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/association",
    smoke_shared_join_response_keeps_five_ghz_rates_in_band
);

fn smoke_shared_join_spp_amsdu_opt_in_patches_request_rsne_before_tx() -> TestResult {
    let mut ap = bss();
    ap.capability |= 0x10;
    let mut rsne = RsnIe::wpa2_psk_ccmp();
    rsne.rsn_capabilities = rsn::RSN_CAP_SPP_AMSDU_CAPABLE;
    let body = rsne.encode_body();
    ap.information_elements
        .extend_from_slice(&[48, body.len() as u8]);
    ap.information_elements.extend_from_slice(&body);
    let mut plan = JoinPlan::prepare(&ap, OWN, b"narf", SecurityMode::Wpa2Psk).unwrap();
    let canonical = RsnIe::wpa2_psk_ccmp().encode_body();
    let before = plan.assoc.clone();
    if plan.rsn_body() != Some(canonical.clone()) || plan.enable_spp_amsdu() != Ok(()) {
        return TestResult::Fail("WPA2 plan refused the SPP A-MSDU opt-in");
    }
    let mut expected = before.clone();
    let at = expected.len() - 1;
    expected[at] |= 0x04; // bit10 lives in the second capability octet.
    if plan.rsn_body() != Some(body.clone())
        || plan.assoc != expected
        || crate::station_security::Security::new(
            OWN,
            AP,
            &[1; 32],
            &plan.rsn_body().unwrap(),
            &body,
            None,
            0,
        )
        .map(|s| s.spp_amsdu())
            != Ok(true)
    {
        return TestResult::Fail("SPP opt-in did not patch only RSN Capabilities bit10");
    }
    // Idempotent; then frozen once the first frame is emitted.
    plan.enable_spp_amsdu().unwrap();
    if plan.assoc != expected {
        return TestResult::Fail("repeated SPP opt-in changed the request");
    }
    plan.start_authentication().unwrap();
    if plan.enable_spp_amsdu() != Err(Error::Busy) {
        return TestResult::Fail("SPP opt-in changed a transmitted plan");
    }
    let mut open = JoinPlan::prepare(&bss(), OWN, b"narf", SecurityMode::Open).unwrap();
    if open.enable_spp_amsdu() != Err(Error::UnsupportedSecurity) || open.rsn_body().is_some() {
        return TestResult::Fail("Open plan gained an RSNE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/association",
    smoke_shared_join_spp_amsdu_opt_in_patches_request_rsne_before_tx
);
