use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_ath10k_indoor_occupied_spans_need_each_current_installation_fact() -> TestResult {
    use narf_wireless::reg::RegFlags;
    let pair = RegFlags::INDOOR_ONLY | RegFlags::DEPLOYMENT_INDOOR;
    let mut domain = us_domain(80);
    for rule in &mut domain.rules {
        rule.flags = pair;
    }
    for (secondary, eighty) in [(None, false), (Some(5200), false), (Some(5200), true)] {
        let Ok(receipt) =
            Permission::from_factory_width(us_factory(), &domain, 5180, secondary, eighty)
        else {
            return TestResult::Fail("qualified indoor20/40/80 span was refused");
        };
        if receipt.half_dbm != 46 || receipt.check(&domain).is_err() {
            return TestResult::Fail("indoor permission raised source power or changed receipt");
        }
        for flags in [
            RegFlags::INDOOR_ONLY,
            RegFlags::DEPLOYMENT_INDOOR,
            pair | RegFlags::NO_IR,
            pair | RegFlags::DFS,
            pair | RegFlags::from_bits_retain(1 << 31),
        ] {
            let mut changed = domain.clone();
            changed.rules[0].flags = flags;
            if receipt.check(&changed).is_ok()
                || Permission::from_factory_width(us_factory(), &changed, 5180, secondary, eighty)
                    .is_ok()
            {
                return TestResult::Fail(
                    "indoor assertion erased missing fact or another restriction",
                );
            }
        }
        let mut overlap = domain.clone();
        let mut unproven = overlap.rules[0].clone();
        unproven.freq_start_mhz = 5179;
        unproven.freq_end_mhz = 5181;
        unproven.flags = RegFlags::INDOOR_ONLY;
        overlap.rules.push(unproven);
        if receipt.check(&overlap).is_ok() {
            return TestResult::Fail(
                "permissive indoor row erased unproven overlapping restriction",
            );
        }
    }
    // Installation facts do not resolve World factory5GHz or another country.
    if Permission::from_factory_width(
        Factory::from_eeprom(0x64).unwrap(),
        &domain,
        5180,
        None,
        false,
    )
    .is_ok()
    {
        return TestResult::Fail("indoor assertion replaced immutable World factory identity");
    }
    domain.country_code = *b"CA";
    if Permission::from_factory_width(us_factory(), &domain, 5180, None, false).is_ok() {
        return TestResult::Fail("indoor assertion replaced source country match");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/regulatory/indoor",
    smoke_ath10k_indoor_occupied_spans_need_each_current_installation_fact
);
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

fn smoke_ath10k_2ghz_ht40_occupied_edges_and_stricter_overlap_power() -> TestResult {
    let factory = Factory::from_eeprom(0x64).unwrap();
    let mut domain = us_domain(40);
    domain.rules = alloc::vec![narf_wireless::reg::RegRule {
        freq_start_mhz: 2402,
        freq_end_mhz: 2482,
        max_bandwidth_mhz: 40,
        max_power_dbm: 17,
        flags: narf_wireless::reg::RegFlags::empty()
    }];
    for primary in (2412..=2462u16).step_by(5) {
        for secondary in [primary.saturating_sub(20), primary + 20] {
            let valid = (2412..=2462).contains(&secondary);
            let result =
                Permission::from_factory_width(factory, &domain, primary, Some(secondary), false);
            if result.is_ok() != valid {
                return TestResult::Fail(
                    "2.4GHz actual40 admitted an unsupported primary/extension pair",
                );
            }
            if let Ok(receipt) = result {
                if receipt.center != (primary + secondary) / 2
                    || receipt.half_dbm != 34
                    || receipt.width80
                    || receipt.check(&domain).is_err()
                {
                    return TestResult::Fail("2.4GHz actual occupied center/power receipt");
                }
            }
        }
    }
    for (flags, width, power) in [
        (narf_wireless::reg::RegFlags::NO_IR, 40, 17),
        (narf_wireless::reg::RegFlags::empty(), 20, 17),
        (narf_wireless::reg::RegFlags::empty(), 40, -1),
    ] {
        let mut tightened = domain.clone();
        tightened.rules.push(narf_wireless::reg::RegRule {
            freq_start_mhz: 2439,
            freq_end_mhz: 2441,
            max_bandwidth_mhz: width,
            max_power_dbm: power,
            flags,
        });
        if Permission::from_factory_width(factory, &tightened, 2412, Some(2432), false).is_ok() {
            return TestResult::Fail("extension-edge restriction erased by broad40 rule");
        }
    }
    let mut limited = domain.clone();
    limited.rules.push(narf_wireless::reg::RegRule {
        freq_start_mhz: 2439,
        freq_end_mhz: 2441,
        max_bandwidth_mhz: 40,
        max_power_dbm: 8,
        flags: narf_wireless::reg::RegFlags::empty(),
    });
    if Permission::from_factory_width(factory, &limited, 2412, Some(2432), false)
        .map(|p| p.half_dbm)
        != Ok(16)
        || Permission::from_factory_width(factory, &domain, 2412, Some(2432), true).is_ok()
    {
        return TestResult::Fail("2.4GHz full-span power minimum or VHT80 boundary");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/coexistence",
    smoke_ath10k_2ghz_ht40_occupied_edges_and_stricter_overlap_power
);

fn smoke_ath10k_80p80_split_power_gap_and_second_span_current_receipt() -> TestResult {
    let factory = us_factory();
    let mut domain = us_domain(80);
    domain
        .rules
        .iter_mut()
        .filter(|r| r.freq_start_mhz > 5500)
        .for_each(|r| r.max_power_dbm = 9);
    let mut receipt =
        Permission::from_factory_width(factory, &domain, 5180, Some(5200), true).unwrap();
    let second = Permission::from_factory_width(factory, &domain, 5745, Some(5765), true).unwrap();
    receipt.center2 = Some(5775);
    receipt.half_dbm = receipt.half_dbm.min(second.half_dbm);
    if receipt.half_dbm != 18 || receipt.check(&domain).is_err() {
        return TestResult::Fail("second80 full-span minimum not carried by current receipt");
    }
    let mut gap = domain.clone();
    gap.rules.push(narf_wireless::reg::RegRule {
        freq_start_mhz: 5500,
        freq_end_mhz: 5700,
        max_bandwidth_mhz: 20,
        max_power_dbm: 0,
        flags: narf_wireless::reg::RegFlags::DFS | narf_wireless::reg::RegFlags::NO_IR,
    });
    if receipt.check(&gap).is_err() {
        return TestResult::Fail("80+80 invented occupancy/DFS authority across the gap");
    }
    let mut denied = domain.clone();
    denied.rules.push(narf_wireless::reg::RegRule {
        freq_start_mhz: 5800,
        freq_end_mhz: 5805,
        max_bandwidth_mhz: 80,
        max_power_dbm: 9,
        flags: narf_wireless::reg::RegFlags::NO_IR,
    });
    if receipt.check(&denied).is_ok() {
        return TestResult::Fail("second80 edge revocation erased by first80 permission");
    }
    for invalid in [Some(5210), Some(5530), Some(5770)] {
        let mut foreign = receipt;
        foreign.center2 = invalid;
        if foreign.check(&domain).is_ok() {
            return TestResult::Fail(
                "foreign/overlapping/nonprofile segment became a current80+80 receipt",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/vht80p80",
    smoke_ath10k_80p80_split_power_gap_and_second_span_current_receipt
);
