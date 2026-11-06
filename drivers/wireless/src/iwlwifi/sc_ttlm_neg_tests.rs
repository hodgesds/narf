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

/// A hand-built ML Reconfiguration Response in the Linux wire layout
/// (`ieee80211_process_ml_reconf_resp`, `net/mac80211/mlme.c:10985`):
/// category, action 12, dialog token, count, one status duple (link id
/// in the info low nibble + LE16 status) per changed link, then the
/// group key data length byte and bytes when `group_key_data` is
/// `Some` (omitted entirely when `None`). Malformed variants are
/// hand-built at the call site so a builder/parser agreement bug
/// cannot mask a parser hole.
fn reconf_response(token: u8, duples: &[(u8, u16)], group_key_data: Option<&[u8]>) -> Vec<u8> {
    let mut frame = alloc::vec![
        PROT_EHT_CATEGORY,
        PROT_EHT_ML_RECONF_RESPONSE,
        token,
        duples.len() as u8,
    ];
    for (link, status) in duples {
        frame.push(*link);
        frame.extend_from_slice(&status.to_le_bytes());
    }
    if let Some(data) = group_key_data {
        frame.push(data.len() as u8);
        frame.extend_from_slice(data);
    }
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

fn smoke_iwl_mld_negotiated_ttlm_wire_values_verified() -> TestResult {
    // Wire values verified #1553 against Linux
    // `include/linux/ieee80211-eht.h` `enum ieee80211_protected_eht_actioncode`
    // (lines 446-458) and `WLAN_CATEGORY_PROTECTED_EHT`
    // (`include/linux/ieee80211.h:1867`). The ML reconfiguration values
    // were corrected from 3/4 (EPCS enable request/response) to 11/12.
    if PROT_EHT_CATEGORY != 37
        || PROT_EHT_TTLM_REQUEST != 0
        || PROT_EHT_TTLM_RESPONSE != 1
        || PROT_EHT_TTLM_TEARDOWN != 2
        || PROT_EHT_ML_RECONF_REQUEST != 11
        || PROT_EHT_ML_RECONF_RESPONSE != 12
    {
        return TestResult::Fail(
            "Protected EHT action values differ from the Linux-verified values",
        );
    }
    // The ML reconfiguration builder emits the corrected action code
    // and the Linux ML RECONF element layout.
    let Some(req) = build_ml_reconf_request(
        0x5a,
        [0x02, 0, 0, 0, 0, 0x01],
        MLD_CAP_OP_TTLM_NEG_SAME | MLD_CAP_OP_LINK_RECONF_SUPPORT,
        0,
        &[],
        &[RemoveLink {
            link_id: 1,
            sta_addr: [0x02, 0, 0, 0, 0, 0x11],
        }],
    ) else {
        return TestResult::Fail("ML Reconfiguration Request builder refused a valid request");
    };
    if req.len() < 3 || req[0] != 37 || req[1] != 11 || req[2] != 0x5a {
        return TestResult::Fail(
            "ML Reconfiguration Request does not start with category/action/token",
        );
    }
    let resp = reconf_response(0x5a, &[(1, 0)], None);
    if resp.len() < 3 || resp[0] != 37 || resp[1] != 12 || resp[2] != 0x5a {
        return TestResult::Fail(
            "ML Reconfiguration Response fixture does not start with category/action/token",
        );
    }
    // Advertisement: TTLM negotiation SAME (0x20: the 0x0060 field with
    // value 1, `ieee80211-eht.h:537-540`) plus link reconfiguration
    // support (0x2000, `ieee80211-eht.h:544`).
    if MLD_CAP_OP_TTLM_NEG_SAME != 0x0020 || MLD_CAP_OP_LINK_RECONF_SUPPORT != 0x2000 {
        return TestResult::Fail("advertised MLD capability bits differ from the verified values");
    }
    if MLD_CAP_OP_TTLM_NEG_SAME | MLD_CAP_OP_LINK_RECONF_SUPPORT != 0x2020 {
        return TestResult::Fail("advertised MLD capabilities differ from the verified value");
    }
    // The ML element extension id matches the association module's
    // (`wireless/src/association/mlo.rs`).
    if ML_EXT_ID != narf_wireless::association::mlo::EXT_MULTI_LINK {
        return TestResult::Fail("ML element extension id differs from the association module");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_negotiated_ttlm_wire_values_verified
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

fn smoke_iwl_mld_ml_reconfiguration_request_layout() -> TestResult {
    let mld = [0x02, 0, 0, 0, 0, 0x01];
    let capa_ops = MLD_CAP_OP_TTLM_NEG_SAME | MLD_CAP_OP_LINK_RECONF_SUPPORT;
    let eml = narf_wireless::association::mlo::EmlCapabilities::INTEL_MLD_LOCAL.0;

    // Golden remove-only request, hand-computed from Linux
    // `ieee80211_build_ml_reconf_req` (mlme.c:11218): category 37,
    // action 11, token 0x5a, element [255, len 21, ext 107], control
    // 0x0012 (type RECONF + MLD MAC present), common length 7, MLD MAC,
    // then one DEL per-STA profile for link 1: subelement [0, len 9],
    // control 0x01a1 (link 1 + STA MAC present + DEL_LINK), STA info
    // length 7, STA MAC. No EML or MLD capa ops: nothing is added.
    let golden_del: Vec<u8> = alloc::vec![
        37, 11, 0x5a, 255, 21, 107, 0x12, 0x00, 7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0, 9,
        0xa1, 0x01, 7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x11,
    ];
    let Some(req) = build_ml_reconf_request(
        0x5a,
        mld,
        capa_ops,
        eml,
        &[],
        &[RemoveLink {
            link_id: 1,
            sta_addr: [0x02, 0, 0, 0, 0, 0x11],
        }],
    ) else {
        return TestResult::Fail("remove-only ML reconfiguration request was refused");
    };
    if req != golden_del {
        return TestResult::Fail("remove-only ML reconfiguration request bytes differ from golden");
    }

    // Golden add request, hand-computed the same way: control 0x0072
    // (type RECONF + MLD MAC + EML capa + MLD capa ops), common length
    // 11 (MLD MAC + EML capa 0x0033 + MLD capa ops 0x2020), then one
    // ADD per-STA profile for link 2: subelement [0, len 26], control
    // 0x0132 (link 2 + COMPLETE_PROFILE + STA MAC present + ADD_LINK),
    // STA info length 24, STA MAC, capability 0x0011, the opaque link
    // elements copied verbatim, and the WMM info IE
    // ([221, 7, 00:50:f2, 2, 0, 1, qos_info], util.c:4493).
    let golden_add: Vec<u8> = alloc::vec![
        37, 11, 0x5a, 255, 42, 107, 0x72, 0x00, 11, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x33,
        0x00, 0x20, 0x20, 0, 26, 0x32, 0x01, 24, 0x02, 0x00, 0x00, 0x00, 0x00, 0x22, 0x11, 0x00,
        45, 4, 0x01, 0x02, 0x03, 0x04, 221, 7, 0x00, 0x50, 0xf2, 2, 0, 1, 0x00,
    ];
    let Some(req) = build_ml_reconf_request(
        0x5a,
        mld,
        capa_ops,
        eml,
        &[AddLink {
            link_id: 2,
            sta_addr: [0x02, 0, 0, 0, 0, 0x22],
            capab: 0x0011,
            elems: &[45, 4, 0x01, 0x02, 0x03, 0x04],
            qos_info: 0,
        }],
        &[],
    ) else {
        return TestResult::Fail("add ML reconfiguration request was refused");
    };
    if req != golden_add {
        return TestResult::Fail("add ML reconfiguration request bytes differ from golden");
    }

    // No EML capabilities: adding a link carries MLD capa ops but no
    // EML field (control 0x0052, common length 9).
    let Some(req) = build_ml_reconf_request(
        0x5a,
        mld,
        capa_ops,
        0,
        &[AddLink {
            link_id: 2,
            sta_addr: [0x02, 0, 0, 0, 0, 0x22],
            capab: 0x0011,
            elems: &[],
            qos_info: 0,
        }],
        &[],
    ) else {
        return TestResult::Fail("no-EML ML reconfiguration request was refused");
    };
    if req.len() < 9 || req[6..8] != [0x52, 0x00] || req[8] != 9 {
        return TestResult::Fail("no-EML ML reconfiguration request carries the wrong common info");
    }

    // Profiles are emitted in ascending link-id order regardless of
    // the caller's list order: add link 2 sorts before remove link 3.
    let Some(req) = build_ml_reconf_request(
        0x5a,
        mld,
        capa_ops,
        0,
        &[AddLink {
            link_id: 2,
            sta_addr: [0x02, 0, 0, 0, 0, 0x22],
            capab: 0x0011,
            elems: &[],
            qos_info: 0,
        }],
        &[RemoveLink {
            link_id: 3,
            sta_addr: [0x02, 0, 0, 0, 0, 0x33],
        }],
    ) else {
        return TestResult::Fail("mixed ML reconfiguration request was refused");
    };
    // The ADD profile for link 2 (control 0x0132) precedes the DEL
    // profile for link 3 (control 0x01a3).
    let add_at = req.windows(2).position(|w| w == [0x32, 0x01]);
    let del_at = req.windows(2).position(|w| w == [0xa3, 0x01]);
    if add_at.is_none() || del_at.is_none() || add_at.unwrap() > del_at.unwrap() {
        return TestResult::Fail("ML reconfiguration profiles are not in ascending link-id order");
    }

    // Builder refusals: reserved link id 15, a link listed twice, a
    // link on both sides, and an ML element over 255 bytes (Linux
    // fragments it; this builder refuses rather than truncating).
    if build_ml_reconf_request(
        0x5a,
        mld,
        capa_ops,
        0,
        &[],
        &[RemoveLink {
            link_id: 15,
            sta_addr: [0x02, 0, 0, 0, 0, 0x11],
        }],
    )
    .is_some()
    {
        return TestResult::Fail("ML reconfiguration request accepted reserved link id 15");
    }
    if build_ml_reconf_request(
        0x5a,
        mld,
        capa_ops,
        0,
        &[],
        &[
            RemoveLink {
                link_id: 1,
                sta_addr: [0x02, 0, 0, 0, 0, 0x11],
            },
            RemoveLink {
                link_id: 1,
                sta_addr: [0x02, 0, 0, 0, 0, 0x11],
            },
        ],
    )
    .is_some()
    {
        return TestResult::Fail("ML reconfiguration request accepted a duplicated link");
    }
    if build_ml_reconf_request(
        0x5a,
        mld,
        capa_ops,
        0,
        &[AddLink {
            link_id: 1,
            sta_addr: [0x02, 0, 0, 0, 0, 0x11],
            capab: 0x0011,
            elems: &[],
            qos_info: 0,
        }],
        &[RemoveLink {
            link_id: 1,
            sta_addr: [0x02, 0, 0, 0, 0, 0x11],
        }],
    )
    .is_some()
    {
        return TestResult::Fail("ML reconfiguration request accepted a link on both sides");
    }
    let big_elems = [0xabu8; 300];
    if build_ml_reconf_request(
        0x5a,
        mld,
        capa_ops,
        0,
        &[AddLink {
            link_id: 2,
            sta_addr: [0x02, 0, 0, 0, 0, 0x22],
            capab: 0x0011,
            elems: &big_elems,
            qos_info: 0,
        }],
        &[],
    )
    .is_some()
    {
        return TestResult::Fail("ML reconfiguration request accepted an over-255-byte element");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_ml_reconfiguration_request_layout
);

fn smoke_iwl_mld_ml_reconfiguration_response() -> TestResult {
    let valid = 0b0111u16;
    let mut engine = NegotiatedTtlm::default();
    let mut ttlm = super::super::sc_emlsr::TtlmState::default();

    // Baseline negotiated mapping m1 (TID 6 on link 0, the rest on
    // links {0, 1}), so the reconf tests can check map clipping.
    engine.begin_request(0x11, m1(), 0, 0);
    if engine.handle_response(&ttlm_response(0x11, 0, &m1(), 0, 0), valid, &mut ttlm, 0, 1000)
        != Ok(NegOutcome::Immediate)
    {
        return TestResult::Fail("reconfiguration baseline negotiation failed");
    }

    // Add link 3 / remove link 0, both accepted, with group key data:
    // the new valid set takes effect immediately and the negotiated
    // map is clipped (TID 6's only link 0 is gone, so the map dies).
    engine.begin_reconf(0x22, 0b1000, 0b0001);
    let outcome = engine.handle_reconf_response(
        &reconf_response(0x22, &[(3, 0), (0, 0)], Some(&[0xaa, 0xbb])),
        valid,
        &mut ttlm,
    );
    if outcome
        != Ok(ReconfOutcome {
            new_valid: 0b1110,
            added: 0b1000,
            removed: 0b0001,
            group_key_data: alloc::vec![0xaa, 0xbb],
        })
    {
        return TestResult::Fail("accepted ML reconfiguration produced the wrong outcome");
    }
    if engine.map().is_some() || ttlm.active || ttlm.negotiated || ttlm.dormant != 0 {
        return TestResult::Fail("clipped-out negotiated mapping was not withdrawn");
    }

    // A failed add drops that link (no group key data is then needed,
    // and a group key field carried anyway is ignored, as in Linux);
    // the valid set is unchanged.
    engine.begin_reconf(0x33, 0b1000, 0);
    let outcome = engine.handle_reconf_response(
        &reconf_response(0x33, &[(3, 7)], Some(&[0xaa, 0xbb])),
        valid,
        &mut ttlm,
    );
    if outcome
        != Ok(ReconfOutcome {
            new_valid: valid,
            added: 0,
            removed: 0,
            group_key_data: Vec::new(),
        })
    {
        return TestResult::Fail("failed ML reconfiguration add was not dropped");
    }

    // A failed removal is a protocol error, and leaves state untouched.
    engine.begin_reconf(0x44, 0, 0b0001);
    if engine.handle_reconf_response(
        &reconf_response(0x44, &[(0, 7)], None),
        valid,
        &mut ttlm,
    ) != Err(NegError::Malformed)
    {
        return TestResult::Fail("failed ML reconfiguration removal was allowed");
    }

    // A response for an unrequested link, a duplicate duple, a missing
    // duple, or a reserved link id is malformed.
    engine.begin_reconf(0x55, 0b1000, 0);
    if engine.handle_reconf_response(
        &reconf_response(0x55, &[(2, 0)], None),
        valid,
        &mut ttlm,
    ) != Err(NegError::Malformed)
    {
        return TestResult::Fail("reconfiguration accepting an unrequested link was allowed");
    }
    engine.begin_reconf(0x55, 0b1000, 0b0001);
    if engine.handle_reconf_response(
        &reconf_response(0x55, &[(3, 0), (3, 0)], None),
        valid,
        &mut ttlm,
    ) != Err(NegError::Malformed)
    {
        return TestResult::Fail("reconfiguration with a duplicate status duple was allowed");
    }
    engine.begin_reconf(0x55, 0b1000, 0b0001);
    if engine.handle_reconf_response(
        &reconf_response(0x55, &[(3, 0)], Some(&[])),
        valid,
        &mut ttlm,
    ) != Err(NegError::Malformed)
    {
        return TestResult::Fail("reconfiguration missing a status duple was allowed");
    }
    engine.begin_reconf(0x55, 0b1000, 0);
    if engine.handle_reconf_response(
        &reconf_response(0x55, &[(15, 0)], None),
        valid,
        &mut ttlm,
    ) != Err(NegError::Malformed)
    {
        return TestResult::Fail("reconfiguration with reserved link id 15 was allowed");
    }

    // Truncated frames: fewer bytes than the count's duples need, and
    // a group key length byte promising more bytes than follow.
    engine.begin_reconf(0x66, 0b1000, 0b0001);
    let short = alloc::vec![PROT_EHT_CATEGORY, PROT_EHT_ML_RECONF_RESPONSE, 0x66, 2, 3, 0, 0];
    if engine.handle_reconf_response(&short, valid, &mut ttlm) != Err(NegError::Malformed) {
        return TestResult::Fail("truncated reconfiguration status duples were accepted");
    }
    engine.begin_reconf(0x66, 0b1000, 0);
    let short_key = alloc::vec![
        PROT_EHT_CATEGORY,
        PROT_EHT_ML_RECONF_RESPONSE,
        0x66,
        1,
        3,
        0,
        0,
        5,
        0xaa,
    ];
    if engine.handle_reconf_response(&short_key, valid, &mut ttlm) != Err(NegError::Malformed) {
        return TestResult::Fail("truncated reconfiguration group key data was accepted");
    }

    // Group key data absent when links were added is malformed.
    engine.begin_reconf(0x77, 0b1000, 0);
    if engine.handle_reconf_response(
        &reconf_response(0x77, &[(3, 0)], None),
        valid,
        &mut ttlm,
    ) != Err(NegError::Malformed)
    {
        return TestResult::Fail("reconfiguration without group key data for added links was allowed");
    }

    // A wrong token leaves the pending exchange untouched; the right
    // token then still succeeds. Wrong category/action and truncation
    // are rejected without touching the exchange, and a response with
    // no pending exchange is a token mismatch.
    engine.begin_reconf(0x88, 0b1000, 0);
    if engine.handle_reconf_response(
        &reconf_response(0x89, &[(3, 0)], Some(&[])),
        valid,
        &mut ttlm,
    ) != Err(NegError::WrongToken)
    {
        return TestResult::Fail("wrong-token reconfiguration response was not ignored");
    }
    if engine.handle_reconf_response(&[37, 12], valid, &mut ttlm) != Err(NegError::Truncated) {
        return TestResult::Fail("truncated reconfiguration response was not rejected");
    }
    let mut bad_category = reconf_response(0x88, &[(3, 0)], Some(&[]));
    bad_category[0] = 36;
    if engine.handle_reconf_response(&bad_category, valid, &mut ttlm) != Err(NegError::WrongCategory)
    {
        return TestResult::Fail("wrong-category reconfiguration response was not rejected");
    }
    let mut bad_action = reconf_response(0x88, &[(3, 0)], Some(&[]));
    bad_action[1] = 11;
    if engine.handle_reconf_response(&bad_action, valid, &mut ttlm) != Err(NegError::WrongAction) {
        return TestResult::Fail("wrong-action reconfiguration response was not rejected");
    }
    let mut no_pending = NegotiatedTtlm::default();
    if no_pending.handle_reconf_response(
        &reconf_response(0x88, &[(3, 0)], Some(&[])),
        valid,
        &mut ttlm,
    ) != Err(NegError::WrongToken)
    {
        return TestResult::Fail("reconfiguration response with no pending exchange was accepted");
    }
    if engine.handle_reconf_response(
        &reconf_response(0x88, &[(3, 0)], Some(&[])),
        valid,
        &mut ttlm,
    ) != Ok(ReconfOutcome {
        new_valid: 0b1111,
        added: 0b1000,
        removed: 0,
        group_key_data: Vec::new(),
    }) {
        return TestResult::Fail("pending reconfiguration did not survive a wrong-token frame");
    }

    // A zero-length group key field is valid when links were added.
    engine.begin_reconf(0x99, 0b1000, 0);
    if engine.handle_reconf_response(
        &reconf_response(0x99, &[(3, 0)], Some(&[])),
        valid,
        &mut ttlm,
    ) != Ok(ReconfOutcome {
        new_valid: 0b1111,
        added: 0b1000,
        removed: 0,
        group_key_data: Vec::new(),
    }) {
        return TestResult::Fail("zero-length group key data was not accepted");
    }

    // Map clipping that keeps every TID covered: remove link 1, and
    // every TID falls back to link 0.
    let mut engine = NegotiatedTtlm::default();
    let mut ttlm = super::super::sc_emlsr::TtlmState::default();
    engine.begin_request(0x11, m1(), 0, 0);
    if engine.handle_response(&ttlm_response(0x11, 0, &m1(), 0, 0), valid, &mut ttlm, 0, 1000)
        != Ok(NegOutcome::Immediate)
    {
        return TestResult::Fail("map-clipping baseline negotiation failed");
    }
    engine.begin_reconf(0x22, 0, 0b0010);
    if engine.handle_reconf_response(
        &reconf_response(0x22, &[(1, 0)], None),
        valid,
        &mut ttlm,
    ) != Ok(ReconfOutcome {
        new_valid: 0b0101,
        added: 0,
        removed: 0b0010,
        group_key_data: Vec::new(),
    }) {
        return TestResult::Fail("map-clipping reconfiguration failed");
    }
    if engine.map() != Some([0b001; 8]) || !ttlm.negotiated || ttlm.dormant != 0b0100 {
        return TestResult::Fail("negotiated mapping was not clipped to the new valid set");
    }

    // A staged mapping is clipped the same way: staging m2 (TID 6 on
    // link 1), then removing link 1, drops the staged map.
    let mut engine = NegotiatedTtlm::default();
    let mut ttlm = super::super::sc_emlsr::TtlmState::default();
    engine.begin_request(0x11, m2(), 100, 0);
    if engine.handle_response(&ttlm_response(0x11, 0, &m2(), 100, 0), valid, &mut ttlm, 0, 5000)
        != Ok(NegOutcome::Staged)
    {
        return TestResult::Fail("staged-map baseline negotiation failed");
    }
    engine.begin_reconf(0x22, 0, 0b0010);
    if engine.handle_reconf_response(
        &reconf_response(0x22, &[(1, 0)], None),
        valid,
        &mut ttlm,
    ) != Ok(ReconfOutcome {
        new_valid: 0b0101,
        added: 0,
        removed: 0b0010,
        group_key_data: Vec::new(),
    }) {
        return TestResult::Fail("staged-map reconfiguration failed");
    }
    if engine.due(5002, 0b0101).is_some() {
        return TestResult::Fail("staged mapping survived losing its only link for a TID");
    }

    // A staged mapping whose links all survive the reconfiguration
    // still fires at its switch time.
    let mut engine = NegotiatedTtlm::default();
    let mut ttlm = super::super::sc_emlsr::TtlmState::default();
    engine.begin_request(0x11, m1(), 100, 0);
    if engine.handle_response(&ttlm_response(0x11, 0, &m1(), 100, 0), valid, &mut ttlm, 0, 5000)
        != Ok(NegOutcome::Staged)
    {
        return TestResult::Fail("surviving staged-map baseline negotiation failed");
    }
    engine.begin_reconf(0x22, 0b1000, 0);
    if engine.handle_reconf_response(
        &reconf_response(0x22, &[(3, 0)], Some(&[])),
        valid,
        &mut ttlm,
    ) != Ok(ReconfOutcome {
        new_valid: 0b1111,
        added: 0b1000,
        removed: 0,
        group_key_data: Vec::new(),
    }) {
        return TestResult::Fail("surviving staged-map reconfiguration failed");
    }
    if engine.due(5001, 0b1111).is_some() {
        return TestResult::Fail("staged mapping applied before its switch time");
    }
    let Some((map, active, dormant)) = engine.due(5002, 0b1111) else {
        return TestResult::Fail("staged mapping did not fire at its switch time");
    };
    if map != m1() || active != 0b0011 || dormant != 0b1100 {
        return TestResult::Fail("staged mapping published the wrong masks after reconfiguration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/mlo",
    smoke_iwl_mld_ml_reconfiguration_response
);
