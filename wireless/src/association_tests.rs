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
