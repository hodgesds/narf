//! Country-specific WMM constraints: Linux v7.2 net/mac80211/util.c
//! `ieee80211_regulatory_limit_wmm_params` applied to the native EDCA rows.
use super::*;
use crate::mt7921::association::{wmm::Parameters, Security, TxPermission};
use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain, WmmRule};

/// The fixture WMM Parameter IE with an aggressive BE row (AIFSN 2,
/// CWmin 1, CWmax 7, TXOP 300 x 32 us).
fn aggressive(count: u8) -> [u8; 26] {
    let mut ie = wmm_tests::PARAMETERS;
    ie[8] = 0x80 | count;
    ie[14..18].copy_from_slice(&[0x02, 0x31, 0x2c, 0x01]);
    ie
}

fn permission(flags: RegFlags) -> Option<TxPermission> {
    TxPermission::from_domain(
        &RegulatoryDomain {
            country_code: *b"DE",
            rules: vec![RegRule {
                freq_start_mhz: 2402,
                freq_end_mhz: 2482,
                max_bandwidth_mhz: 40,
                max_power_dbm: 20,
                flags,
            }],
        },
        6,
    )
}

fn command(frame: &[u8], id: u8) -> bool {
    frame.len() >= 64 && frame[36] == id && frame[37] == 0xa0
}

fn edca_commands(session: &Session<Model>, before: usize) -> Vec<Vec<u8>> {
    session.backend.frames[before..]
        .iter()
        .filter(|(_, frame)| command(frame, 0x1d))
        .map(|(_, frame)| frame[64..].to_vec())
        .collect()
}

fn mt76_country_wmm_rule_limits_association_and_dynamic_edca() -> TestResult {
    let parameters = Parameters::parse(&aggressive(1)).unwrap().unwrap();
    // BE: cw_min max(1, 15), cw_max max(7, 1023), aifs max(2, 3), txop
    // min(300, 6000 us / 32 = 187); the other ACs already satisfy the ETSI
    // client rule and keep the AP's values.
    let mut expected = parameters.edca();
    expected[..10].copy_from_slice(&[15, 0, 255, 3, 187, 0, 3, 0, 0, 0]);
    let fixture = Parameters::parse(&wmm_tests::PARAMETERS).unwrap().unwrap();
    if parameters.edca_limited(Some(WmmRule::ETSI)) != expected
        || parameters.edca_limited(None) != parameters.edca()
        || fixture.edca_limited(Some(WmmRule::ETSI)) != fixture.edca()
    {
        return TestResult::Fail("regulatory WMM limit arithmetic");
    }
    // A WMM_ETSI rule is a constraint, not a prohibition; NO_IR still is.
    let Some(grant) = permission(RegFlags::WMM_ETSI) else {
        return TestResult::Fail("WMM_ETSI rule denied the station permission");
    };
    if grant.wmm_rule() != Some(WmmRule::ETSI)
        || permission(RegFlags::empty()).is_none_or(|p| p.wmm_rule().is_some())
        || permission(RegFlags::WMM_ETSI | RegFlags::NO_IR).is_some()
    {
        return TestResult::Fail("permission WMM rule selection");
    }
    let (mut session, mut bss) = wmm_tests::prepared(false, false);
    bss.information_elements.extend_from_slice(&aggressive(1));
    session.backend.wmm_reply = Some(aggressive(1).to_vec());
    let before = session.backend.frames.len();
    if run(session.associate_station(&bss, b"narf", Security::Open, grant, &[])) != Ok(42) {
        return TestResult::Fail("ETSI-rule association");
    }
    if edca_commands(&session, before) != [expected.to_vec()] {
        return TestResult::Fail("association EDCA not regulatory-limited");
    }
    // A dynamic update (new Parameter Set Count, VO CWmin 1) is limited by
    // the same retained grant: VO CWmin rises to the rule's 3.
    let mut update = aggressive(2);
    update[11] = 0x31;
    let packet = dynamic_wmm_tests::beacon(&session, &bss, &update);
    session.backend.packets.push_back(packet);
    let _ = session.receive_ethernet();
    let before = session.backend.frames.len();
    if run(session.service_keys()).is_err() {
        return TestResult::Fail("dynamic WMM service");
    }
    let updated = Parameters::parse(&update).unwrap().unwrap();
    let commands = edca_commands(&session, before);
    if commands.len() != 1
        || commands[0] != updated.edca_limited(Some(WmmRule::ETSI))
        || commands[0][30..32] != [3, 0]
        || session.wmm != Some(updated)
    {
        return TestResult::Fail("dynamic EDCA not regulatory-limited");
    }
    // Teardown restores the legacy EDCA, which the ETSI rule leaves alone.
    let before = session.backend.frames.len();
    if run(session.disassociate_station()).is_err()
        || edca_commands(&session, before)
            != [crate::mt7921::association::wmm::legacy_edca().to_vec()]
    {
        return TestResult::Fail("teardown legacy EDCA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_country_wmm_rule_limits_association_and_dynamic_edca
);
