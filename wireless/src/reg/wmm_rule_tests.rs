//! Regulatory WMM rule (cfg80211 `wmm_rule`, wireless-regdb `wmmrule=ETSI`).
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn rule(flags: RegFlags) -> RegRule {
    RegRule {
        freq_start_mhz: 5150,
        freq_end_mhz: 5250,
        max_bandwidth_mhz: 80,
        max_power_dbm: 23,
        flags,
    }
}
fn ac(aifsn: u8, ecw_min: u8, ecw_max: u8, txop: u16) -> crate::wmm::Ac {
    crate::wmm::Ac {
        aifsn,
        ecw_min,
        ecw_max,
        txop,
        admission_control: false,
    }
}

fn smoke_reg_wmm_rule_limits_edca() -> TestResult {
    if rule(RegFlags::empty()).wmm_rule().is_some() {
        return TestResult::Fail("rule without WMM_ETSI has a WMM rule");
    }
    let Some(wmm) = rule(RegFlags::WMM_ETSI | RegFlags::INDOOR_ONLY).wmm_rule() else {
        return TestResult::Fail("WMM_ETSI rule has no WMM rule");
    };
    // Client VO: CWmin 3 (ECW 2), CWmax 7 (ECW 3), AIFSN 2, COT 2 ms.
    // A more aggressive AP VO set (AIFSN 1, ECW 1/2, TXOP 94 * 32 us) is
    // raised to the floor and its TXOP capped at 2000 / 32 = 62.
    let limited = wmm.limit(0, false, ac(1, 1, 2, 94));
    if limited != ac(2, 2, 3, 62) {
        return TestResult::Fail("client VO not limited to the ETSI floor");
    }
    // Already-conservative parameters are unchanged (BE: 15/1023, AIFSN 3).
    let be = ac(3, 4, 10, 0);
    if wmm.limit(2, false, be) != be {
        return TestResult::Fail("conservative BE parameters changed");
    }
    // AP BE CWmax floor is 63 (ECW 6).
    if wmm.limit(2, true, ac(3, 4, 5, 0)).ecw_max != 6 || wmm.limit(9, false, be) != be {
        return TestResult::Fail("AP table or out-of-range AC");
    }
    // Parameters in ACI order BE, BK, VI, VO.
    let params = crate::wmm::Parameters {
        ac: [
            ac(3, 4, 10, 0),
            ac(7, 4, 10, 0),
            ac(1, 2, 3, 94),
            ac(1, 1, 2, 47),
        ],
        parameter_set_count: 0,
        uapsd: false,
    };
    let out = wmm.limit_parameters(false, params);
    if out.ac[2] != ac(2, 3, 4, 94) || out.ac[3] != ac(2, 2, 3, 47) || out.ac[0] != params.ac[0] {
        return TestResult::Fail("ACI mapping of the regulatory limit");
    }
    let domain = RegulatoryDomain {
        country_code: *b"DE",
        rules: alloc::vec![rule(RegFlags::WMM_ETSI)],
    };
    if domain.wmm_rule_for(5180) != Some(WmmRule::ETSI) || domain.wmm_rule_for(2412).is_some() {
        return TestResult::Fail("domain WMM lookup");
    }
    TestResult::Pass
}
kernel_test_in!("wireless/reg/wmm_rule", smoke_reg_wmm_rule_limits_edca);
