use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn fixture() -> Vec<u8> {
    let mut data = alloc::vec![0; 56];
    data[..4].copy_from_slice(b"RGDB");
    data[4..8].copy_from_slice(&20u32.to_be_bytes());
    data[8..10].copy_from_slice(b"00");
    data[10..12].copy_from_slice(&4u16.to_be_bytes());
    data[16..19].copy_from_slice(&[3, 2, 2]);
    data[20..22].copy_from_slice(&6u16.to_be_bytes());
    data[22..24].copy_from_slice(&10u16.to_be_bytes());
    for (at, flags, start, end, bw) in [
        (24, 0x1e, 2_400_001u32, 2_483_500u32, 40_001u32),
        (40, 1, 2_474_000u32, 2_494_000u32, 20_000u32),
    ] {
        data[at] = 16;
        data[at + 1] = flags;
        data[at + 2..at + 4].copy_from_slice(&2301u16.to_be_bytes());
        data[at + 4..at + 8].copy_from_slice(&start.to_be_bytes());
        data[at + 8..at + 12].copy_from_slice(&end.to_be_bytes());
        data[at + 12..at + 16].copy_from_slice(&bw.to_be_bytes());
    }
    data
}

fn smoke_linux_regdb_conservative_conversion_and_bounds() -> TestResult {
    let bytes = fixture();
    let Ok((domain, dfs)) = country(&bytes, *b"00") else {
        return TestResult::Fail("valid Linux v20 fixture refused");
    };
    if dfs != 2
        || domain.rules.len() != 1
        || domain.rules[0].freq_start_mhz != 2401
        || domain.rules[0].freq_end_mhz != 2483
        || domain.rules[0].max_bandwidth_mhz != 40
        || domain.rules[0].max_power_dbm != 23
        || domain.rules[0].flags
            != RegFlags::INDOOR_ONLY | RegFlags::DFS | RegFlags::NO_IR | RegFlags::AUTO_BW
        || domain.rule_for(2484).is_some()
    {
        return TestResult::Fail("Linux conversion enlarged a limit or lost a restriction");
    }
    for end in 0..bytes.len() {
        if country(&bytes[..end], *b"00").is_ok() {
            return TestResult::Fail("truncated Linux database accepted");
        }
    }
    for (at, value) in [
        (4, 1),
        (8, b'a'),
        (10, 0xff),
        (16, 4),
        (18, 4),
        (24, 17),
        (25, 0x80),
    ] {
        let mut bad = bytes.clone();
        bad[at] = value;
        if country(&bad, *b"00").is_ok() {
            return TestResult::Fail("malformed/unsupported Linux database accepted");
        }
    }
    for alpha2 in [*b"US", *b"0A", *b"us"] {
        if country(&bytes, alpha2).is_ok() {
            return TestResult::Fail("missing/invalid country invented");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/regulatory",
    smoke_linux_regdb_conservative_conversion_and_bounds
);

fn smoke_linux_regdb_upstream_world_jp_and_etsi() -> TestResult {
    let db = narf_firmware::linux_regulatory_database();
    for alpha2 in [*b"00", *b"JP", *b"US"] {
        let Ok((domain, _)) = country(db, alpha2) else {
            return TestResult::Fail("upstream world/JP/US country refused");
        };
        if domain.country_code != alpha2
            || domain.rule_for(2412).is_none()
            || domain.rule_for(2484).is_some()
        {
            return TestResult::Fail("country projection lost 2.4 GHz or enabled channel14");
        }
    }
    let Ok((gb, dfs)) = country(db, *b"GB") else {
        return TestResult::Fail("upstream ETSI country refused");
    };
    if dfs != 2 || gb.wmm_rule_for(5180) != Some(WmmRule::ETSI) {
        return TestResult::Fail("Linux ETSI WMM floor/DFS region lost");
    }
    // A different WMM floor and nonzero CAC cannot be represented by the
    // existing driver contract: refuse the country instead of relaxing it.
    let coll = collection(db, *b"GB").unwrap();
    let ptr = usize::from(be16(db, coll + 6).unwrap()) * 4;
    let wmm = usize::from(be16(db, ptr + 18).unwrap()) * 4;
    let mut changed = db.to_vec();
    changed[wmm + 1] += 1;
    if country(&changed, *b"GB").is_ok() {
        return TestResult::Fail("unsupported WMM floor silently erased");
    }
    let mut changed = db.to_vec();
    changed[ptr + 17] = 1;
    if country(&changed, *b"GB").is_ok() {
        return TestResult::Fail("unsupported CAC timeout silently erased");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/regulatory",
    smoke_linux_regdb_upstream_world_jp_and_etsi
);
