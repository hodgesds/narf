use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
fn smoke_ath10k_factory_regulatory_identity_matches_linux_all_u16() -> TestResult {
    // Frozen source-cited reference over every 16-bit EEPROM value, not
    // regenerated from the Rust resolver. The stored digest includes all
    // successful fields or a failure byte; no reference source is executed.
    let mut hash = 0xcbf29ce484222325u64;
    let mut byte = |value: u8| {
        hash = (hash ^ u64::from(value)).wrapping_mul(0x100000001b3);
    };
    let mut success = 0;
    for raw in 0..=u16::MAX {
        let Ok(f) = Factory::from_eeprom(u32::from(raw)) else {
            byte(0);
            continue;
        };
        success += 1;
        byte(1);
        for value in [f.eeprom, f.country, f.pair, f.ctl_5ghz, f.ctl_2ghz] {
            for value in value.to_le_bytes() {
                byte(value);
            }
        }
        for value in f.alpha2 {
            byte(value);
        }
    }
    if hash != 0xec8104beec6e96fc || success != 611 {
        return TestResult::Fail(
            "factory EEPROM identity differs from exhaustive native Linux oracle",
        );
    }
    if Factory::from_eeprom(0x1_0064).is_ok()
        || Factory::from_eeprom(0xffff).is_ok()
        || Factory::from_eeprom(0xc000).is_ok()
    {
        return TestResult::Fail("unsupported/ambiguous EEPROM identifier acquired a factory pair");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory",
    smoke_ath10k_factory_regulatory_identity_matches_linux_all_u16
);

fn us_domain(max_bandwidth_mhz: u32) -> narf_wireless::reg::RegulatoryDomain {
    let rule = |start, end| narf_wireless::reg::RegRule {
        freq_start_mhz: start,
        freq_end_mhz: end,
        max_bandwidth_mhz,
        max_power_dbm: 23,
        flags: narf_wireless::reg::RegFlags::empty(),
    };
    narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: alloc::vec![rule(5170, 5250), rule(5735, 5835)],
    }
}
fn us_factory() -> Factory {
    // CTRY_UNITED_STATES (840) with Linux COUNTRY_ERD_FLAG.
    Factory::from_eeprom(0x8348).unwrap()
}
fn smoke_ath10k_regulatory_vht80_segment_permission() -> TestResult {
    let f = us_factory();
    if f.alpha2 != *b"US" {
        return TestResult::Fail("US factory identity unavailable");
    }
    let domain = us_domain(80);
    for (primary, secondary, center) in [
        (5180, 5200, 5210),
        (5240, 5220, 5210),
        (5745, 5765, 5775),
        (5805, 5785, 5775),
    ] {
        let Ok(p) = Permission::from_factory_width(f, &domain, primary, Some(secondary), true)
        else {
            return TestResult::Fail("permitted 80 MHz segment refused");
        };
        if !p.width80 || p.center != center || p.secondary != Some(secondary) || p.half_dbm != 46 {
            return TestResult::Fail("80 MHz receipt has wrong center/secondary/power");
        }
        if p.check(&domain).is_err() {
            return TestResult::Fail("unchanged policy rejected the 80 MHz receipt");
        }
    }
    if Permission::center80(5825).is_some() || Permission::center80(2412).is_some() {
        return TestResult::Fail("channel without a non-DFS 80 MHz segment got a center");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory",
    smoke_ath10k_regulatory_vht80_segment_permission
);
fn smoke_ath10k_regulatory_vht80_refuses_narrow_or_split_rules() -> TestResult {
    let f = us_factory();
    // 40 MHz host ceiling: HT40 still admitted, 80 MHz refused.
    let narrow = us_domain(40);
    if Permission::from_factory_width(f, &narrow, 5180, Some(5200), false).is_err()
        || Permission::from_factory_width(f, &narrow, 5180, Some(5200), true).is_ok()
    {
        return TestResult::Fail("40 MHz rule admitted an 80 MHz segment");
    }
    // A rule that stops inside the segment does not cover it.
    let mut split = us_domain(80);
    split.rules[0].freq_end_mhz = 5230;
    if Permission::from_factory_width(f, &split, 5180, Some(5200), true).is_ok() {
        return TestResult::Fail("partially covered 80 MHz segment admitted");
    }
    // An overlapping DFS row touching the segment stays restrictive.
    let mut dfs = us_domain(80);
    let mut row = dfs.rules[0].clone();
    row.freq_start_mhz = 5240;
    row.freq_end_mhz = 5260;
    row.flags = narf_wireless::reg::RegFlags::DFS;
    dfs.rules.push(row);
    if Permission::from_factory_width(f, &dfs, 5180, Some(5200), true).is_ok() {
        return TestResult::Fail("overlapping DFS rule erased by 80 MHz admission");
    }
    // Width without a 40 MHz pair, a cross-segment pair or ch165 is refused.
    let domain = us_domain(80);
    for (primary, secondary) in [(5180, None), (5240, Some(5260)), (5825, Some(5805))] {
        if Permission::from_factory_width(f, &domain, primary, secondary, true).is_ok() {
            return TestResult::Fail("malformed 80 MHz geometry admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory",
    smoke_ath10k_regulatory_vht80_refuses_narrow_or_split_rules
);
fn smoke_ath10k_regulatory_vht80_receipt_closes_on_policy_change() -> TestResult {
    let f = us_factory();
    let domain = us_domain(80);
    let Ok(p) = Permission::from_factory_width(f, &domain, 5745, Some(5765), true) else {
        return TestResult::Fail("80 MHz receipt setup");
    };
    let mut lower = domain.clone();
    lower.rules[1].max_power_dbm = 17;
    let mut narrowed = domain.clone();
    narrowed.rules[1].max_bandwidth_mhz = 40;
    let mut cleared = domain.clone();
    cleared.rules.clear();
    let mut other = domain.clone();
    other.country_code = *b"CA";
    for changed in [&lower, &narrowed, &cleared, &other] {
        if p.check(changed).is_ok() {
            return TestResult::Fail("80 MHz receipt survived a changed host policy");
        }
    }
    // The 40 MHz receipt over the same pair is a different receipt.
    let Ok(forty) = Permission::from_factory_width(f, &narrowed, 5745, Some(5765), false) else {
        return TestResult::Fail("HT40 receipt setup");
    };
    if forty == p || forty.width80 {
        return TestResult::Fail("40 and 80 MHz receipts compared equal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory",
    smoke_ath10k_regulatory_vht80_receipt_closes_on_policy_change
);
