//! Negotiated TTLM + ML reconfiguration vectors. Happy-path frames go
//! through the production builders; malformed frames are hand-built so a
//! builder/parser agreement bug cannot mask a parser hole. They exercise
//! the engine only and claim no firmware or over-air behaviour.
use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// All TIDs on links {0, 1} except TID 6, which sits on link 0 only.
fn m1() -> [u16; 8] {
    [0b011, 0b011, 0b011, 0b011, 0b011, 0b011, 0b001, 0b011]
}

/// `m1` with TID 6 moved from link 0 to link 1.
fn m2() -> [u16; 8] {
    let mut map = m1();
    map[6] = 0b010;
    map
}

fn ttlm_response(token: u8, status: u16, map: &[u16; 8], switch: u16, dur: u32) -> Vec<u8> {
    let mut frame = alloc::vec![PROT_EHT_CATEGORY, PROT_EHT_TTLM_RESPONSE, token];
    frame.extend_from_slice(&status.to_le_bytes());
    frame.extend_from_slice(&build_neg_element(Some(map), switch, dur));
    frame
}

fn reconf_response(
    token: u8,
    add: u16,
    remove: u16,
    map: &[u16; 8],
    switch: u16,
    dur: u32,
) -> Vec<u8> {
    let mut frame = alloc::vec![PROT_EHT_CATEGORY, PROT_EHT_ML_RECONF_RESPONSE, token];
    frame.extend_from_slice(&add.to_le_bytes());
    frame.extend_from_slice(&remove.to_le_bytes());
    frame.extend_from_slice(&build_neg_element(Some(map), switch, dur));
    frame
}

fn smoke_iwl_mld_negotiated_ttlm_frames() -> TestResult {
    // Golden TTLM Request bytes, hand-computed: category 37, action 0,
    // token 0x5a, element [255, len 19, ext 109], control 0x02 (both
    // directions, no switch time, no duration, 2-byte maps), presence
    // 0xff, then eight little-endian link maps.
    let golden: Vec<u8> = alloc::vec![
        37, 0, 0x5a, 255, 19, 109, 0x02, 0xff, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00,
        0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x03, 0x00,
    ];
    if build_ttlm_request(0x5a, &m1(), 0, 0) != golden {
        return TestResult::Fail("TTLM Request builder bytes differ from the golden frame");
    }
    // The parser recovers the golden frame's mapping (builder and
    // parser are different code paths, so this is not self-agreement).
    let Ok(info) = parse_neg_t2l(&golden[6..]) else {
        return TestResult::Fail("golden TTLM element did not parse");
    };
    if info.map != m1() || info.switch_time != 0 || info.duration != 0 || info.default {
        return TestResult::Fail("golden TTLM element parsed to the wrong mapping");
    }
    // Switch time + duration round-trip through builder and parser.
    let element = build_neg_element(Some(&m1()), 0x1234, 0x010203);
    let Ok(timed) = parse_neg_t2l(&element[3..]) else {
        return TestResult::Fail("timed TTLM element did not parse");
    };
    if timed.map != m1() || timed.switch_time != 0x1234 || timed.duration != 0x010203 {
        return TestResult::Fail("timed TTLM element parsed to the wrong values");
    }
    // Teardown is exactly the category + action code, per Linux's
    // `ttlm_tear_down` (action_code only).
    if build_ttlm_teardown() != alloc::vec![37, 2] {
        return TestResult::Fail("TTLM Teardown frame is not category + action only");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_negotiated_ttlm_frames
);

fn smoke_iwl_mld_negotiated_ttlm_exchange() -> TestResult {
    let valid = 0b111u16;
    let mut engine = NegotiatedTtlm::default();
    let mut ttlm = super::super::sc_emlsr::TtlmState::default();

    // Immediate acceptance installs the map and publishes dormant links.
    engine.begin_request(0x11, m1(), 0, 0);
    if engine.handle_response(
        &ttlm_response(0x11, 0, &m1(), 0, 0),
        valid,
        &mut ttlm,
        0,
        1000,
    ) != Ok(NegOutcome::Immediate)
    {
        return TestResult::Fail("immediate TTLM acceptance failed");
    }
    if engine.map() != Some(m1()) || !ttlm.active || !ttlm.negotiated || ttlm.dormant != 0b100 {
        return TestResult::Fail("immediate TTLM acceptance published the wrong state");
    }

    // A wrong token leaves the pending exchange untouched; the right
    // token then still succeeds.
    engine.begin_request(0x22, m2(), 0, 0);
    if engine.handle_response(
        &ttlm_response(0x23, 0, &m2(), 0, 0),
        valid,
        &mut ttlm,
        0,
        2000,
    ) != Err(NegError::WrongToken)
    {
        return TestResult::Fail("wrong-token TTLM response was not ignored");
    }
    if engine.handle_response(
        &ttlm_response(0x22, 0, &m2(), 0, 0),
        valid,
        &mut ttlm,
        0,
        2000,
    ) != Ok(NegOutcome::Immediate)
    {
        return TestResult::Fail("pending exchange did not survive a wrong-token frame");
    }
    if engine.map() != Some(m2()) {
        return TestResult::Fail("second TTLM acceptance did not replace the map");
    }

    // A rejected response clears pending and keeps the active map.
    engine.begin_request(0x33, m1(), 0, 0);
    if engine.handle_response(
        &ttlm_response(0x33, 7, &m1(), 0, 0),
        valid,
        &mut ttlm,
        0,
        3000,
    ) != Err(NegError::Rejected)
    {
        return TestResult::Fail("rejected TTLM response was not reported");
    }
    if engine.map() != Some(m2()) {
        return TestResult::Fail("rejected TTLM response changed the active map");
    }

    // Malformed responses terminate the exchange without touching state.
    engine.begin_request(0x44, m1(), 0, 0);
    let mut bad_category = ttlm_response(0x44, 0, &m1(), 0, 0);
    bad_category[0] = 36;
    if engine.handle_response(&bad_category, valid, &mut ttlm, 0, 4000)
        != Err(NegError::WrongCategory)
    {
        return TestResult::Fail("wrong-category TTLM response was not rejected");
    }
    engine.begin_request(0x44, m1(), 0, 0);
    if engine.handle_response(&[37, 1], valid, &mut ttlm, 0, 4000) != Err(NegError::Truncated) {
        return TestResult::Fail("truncated TTLM response was not rejected");
    }
    engine.begin_request(0x44, m1(), 0, 0);
    let mut zero_tid = m1();
    zero_tid[3] = 0;
    if engine.handle_response(
        &ttlm_response(0x44, 0, &zero_tid, 0, 0),
        valid,
        &mut ttlm,
        0,
        4000,
    ) != Err(NegError::Malformed)
    {
        return TestResult::Fail("TTLM response with an empty TID map was accepted");
    }
    engine.begin_request(0x44, m1(), 0, 0);
    let mut outside = m1();
    outside[0] = 0b1000;
    if engine.handle_response(
        &ttlm_response(0x44, 0, &outside, 0, 0),
        valid,
        &mut ttlm,
        0,
        4000,
    ) != Err(NegError::Malformed)
    {
        return TestResult::Fail("TTLM response outside the valid link set was accepted");
    }
    if engine.map() != Some(m2()) {
        return TestResult::Fail("malformed TTLM response changed the active map");
    }

    // A staged mapping does not apply before its switch time, then does.
    // TSF 0, switch time 100 TU: delay 100 TU = 102400 us, minus the
    // 100 ms safety buffer = 2400 us, so the switch lands at now + 2 ms.
    engine.begin_request(0x55, m1(), 100, 0);
    if engine.handle_response(
        &ttlm_response(0x55, 0, &m1(), 100, 0),
        valid,
        &mut ttlm,
        0,
        5000,
    ) != Ok(NegOutcome::Staged)
    {
        return TestResult::Fail("future-switch TTLM response was not staged");
    }
    if engine.map() != Some(m2()) || engine.due(5001, valid).is_some() {
        return TestResult::Fail("staged TTLM mapping applied early");
    }
    let Some((map, active, dormant)) = engine.due(5002, valid) else {
        return TestResult::Fail("staged TTLM mapping did not fire at its switch time");
    };
    if map != m1() || active != 0b011 || dormant != 0b100 || engine.map() != Some(m1()) {
        return TestResult::Fail("staged TTLM switch published the wrong mapping");
    }

    // A switch time already past applies immediately: a one-shot
    // response cannot be re-read like a repeating beacon.
    engine.begin_request(0x66, m2(), 0, 0);
    let past_tsf = 0x20u64 << 10;
    if engine.handle_response(
        &ttlm_response(0x66, 0, &m2(), 0x10, 0),
        valid,
        &mut ttlm,
        past_tsf,
        6000,
    ) != Ok(NegOutcome::Immediate)
    {
        return TestResult::Fail("past-switch TTLM response was not applied immediately");
    }
    if engine.map() != Some(m2()) {
        return TestResult::Fail("past-switch TTLM response did not install the map");
    }

    // A default-flag response restores the all-valid-links mapping.
    engine.begin_request(0x77, m1(), 0, 0);
    let mut default_frame = alloc::vec![PROT_EHT_CATEGORY, PROT_EHT_TTLM_RESPONSE, 0x77, 0, 0];
    default_frame.extend_from_slice(&build_neg_element(None, 0, 0));
    if engine.handle_response(&default_frame, valid, &mut ttlm, 0, 7000)
        != Ok(NegOutcome::Immediate)
    {
        return TestResult::Fail("default TTLM response was not accepted");
    }
    if engine.map() != Some([valid; 8]) || ttlm.dormant != 0 {
        return TestResult::Fail("default TTLM response did not restore the default mapping");
    }

    // Teardown returns to the default mapping and clears publication.
    if engine
        .handle_teardown(&build_ttlm_teardown(), &mut ttlm)
        .is_err()
        || engine.map().is_some()
        || ttlm.active
        || ttlm.negotiated
        || ttlm.dormant != 0
    {
        return TestResult::Fail("TTLM teardown did not revert to the default mapping");
    }

    // A negotiated acceptance cancels a planned advertised switch.
    ttlm.switch_at_ms = Some(9999);
    ttlm.info.switch_time = 0x100;
    engine.begin_request(0x88, m1(), 0, 0);
    if engine.handle_response(
        &ttlm_response(0x88, 0, &m1(), 0, 0),
        valid,
        &mut ttlm,
        0,
        8000,
    ) != Ok(NegOutcome::Immediate)
        || ttlm.switch_at_ms.is_some()
    {
        return TestResult::Fail("negotiated acceptance did not cancel the advertised plan");
    }

    // Beacon element absence never withdraws a negotiated mapping.
    if ttlm.process(&[], 0, 9000) != super::super::sc_emlsr::TtlmAction::None
        || !ttlm.active
        || !ttlm.negotiated
        || ttlm.dormant != 0b100
    {
        return TestResult::Fail("beacon path withdrew a negotiated mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_negotiated_ttlm_exchange
);

fn smoke_iwl_mld_ml_reconfiguration_moves_tid() -> TestResult {
    let valid = 0b111u16;
    let mut engine = NegotiatedTtlm::default();
    let mut ttlm = super::super::sc_emlsr::TtlmState::default();

    // Start from m1 (TID 6 on link 0), then reconfigure to m2 (TID 6 on
    // link 1) at a future switch time: before it, m1 still rules.
    engine.begin_request(0x11, m1(), 0, 0);
    if engine.handle_response(
        &ttlm_response(0x11, 0, &m1(), 0, 0),
        valid,
        &mut ttlm,
        0,
        1000,
    ) != Ok(NegOutcome::Immediate)
    {
        return TestResult::Fail("reconfiguration baseline negotiation failed");
    }
    engine.begin_reconf(0x22, 0, 0, m2(), 100, 0);
    let outcome = engine.handle_reconf_response(
        &reconf_response(0x22, 0, 0, &m2(), 100, 0),
        valid,
        &mut ttlm,
        0,
        2000,
    );
    if outcome
        != Ok(ReconfOutcome {
            new_valid: valid,
            outcome: NegOutcome::Staged,
        })
    {
        return TestResult::Fail("ML reconfiguration response was not staged");
    }
    if engine.map() != Some(m1()) || engine.due(2001, valid).is_some() {
        return TestResult::Fail("reconfigured mapping applied before its switch time");
    }
    let Some((map, _, _)) = engine.due(2002, valid) else {
        return TestResult::Fail("reconfigured mapping did not fire at its switch time");
    };
    if map != m2() || map[6] != 0b010 || map[0] != 0b011 {
        return TestResult::Fail("reconfiguration did not move TID 6 between links");
    }

    // Add link 2 / remove link 0: the valid set changes and the carried
    // mapping must fit inside the new set.
    let mut engine = NegotiatedTtlm::default();
    let mut ttlm = super::super::sc_emlsr::TtlmState::default();
    engine.begin_reconf(0x33, 0b1000, 0b001, [0b1110; 8], 0, 0);
    let outcome = engine.handle_reconf_response(
        &reconf_response(0x33, 0b1000, 0b001, &[0b1110; 8], 0, 0),
        valid,
        &mut ttlm,
        0,
        3000,
    );
    if outcome
        != Ok(ReconfOutcome {
            new_valid: 0b1110,
            outcome: NegOutcome::Immediate,
        })
    {
        return TestResult::Fail("ML reconfiguration add/remove produced the wrong valid set");
    }
    if engine.map() != Some([0b1110; 8]) {
        return TestResult::Fail("ML reconfiguration mapping was not installed");
    }

    // A response accepting an unrequested link, or emptying the valid
    // set, is malformed and leaves state untouched.
    engine.begin_reconf(0x44, 0, 0, m1(), 0, 0);
    if engine.handle_reconf_response(
        &reconf_response(0x44, 0b1000, 0, &m1(), 0, 0),
        valid,
        &mut ttlm,
        0,
        4000,
    ) != Err(NegError::Malformed)
    {
        return TestResult::Fail("reconfiguration accepting an unrequested link was allowed");
    }
    engine.begin_reconf(0x44, 0, 0b111, m1(), 0, 0);
    if engine.handle_reconf_response(
        &reconf_response(0x44, 0, 0b111, &m1(), 0, 0),
        valid,
        &mut ttlm,
        0,
        4000,
    ) != Err(NegError::Malformed)
    {
        return TestResult::Fail("reconfiguration emptying the valid set was allowed");
    }
    if engine.map() != Some([0b1110; 8]) {
        return TestResult::Fail("malformed reconfiguration changed the active map");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_ml_reconfiguration_moves_tid
);
