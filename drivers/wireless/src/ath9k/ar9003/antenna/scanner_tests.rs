// SPDX-License-Identifier: GPL-2.0-or-later
//! Literal Linux group2 traces; no hardware, HT or calibration credit.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
fn config() -> Config {
    Config {
        main: 2,
        alt: 1,
        bias: 9,
        main_gain: true,
        alt_gain: true,
    }
}
fn observation(main: u8, alt: u8, received: u8, more_aggr: bool) -> Observation {
    Observation {
        ctl: [main, alt, 8 | (received << 4)],
        antenna: 0,
        more_aggr,
    }
}
fn window(s: &mut Scanner, c: Config, main: u8, alt: u8) -> Option<Config> {
    let mut last = None;
    for _ in 0..512 {
        let mut sample = observation(main, alt, c.alt, false);
        sample.ctl[2] = (c.main << 2) | (c.alt << 4);
        last = s.observe(c, sample, 0).ok()?;
    }
    last
}
fn smoke_ath9k_ar9485_scanner_signed_rssi_and_aggregate_window() -> TestResult {
    let mut s = Scanner::new(20, 0);
    for (main, alt, expected) in [
        (0x80, 40, (30, 20)),
        (40, 0x80, (50, 50)),
        (0, 40, (30, 20)),
    ] {
        if s.observe(config(), observation(main, alt, 1, false), 0) != Ok(None)
            || s.total != 0
            || (s.ratio, s.ratio2) != expected
        {
            return TestResult::Fail("source signed RSSI/threshold admission");
        }
    }
    for _ in 0..511 {
        if s.observe(config(), observation(40, 20, 2, false), 0) != Ok(None) {
            return TestResult::Fail("source window evaluated before512");
        }
    }
    if s.observe(config(), observation(40, 20, 2, true), 0) != Ok(None)
        || s.total != 512
        || s.count != 95
    {
        return TestResult::Fail("moreaggr did not retain completed window");
    }
    let Ok(Some(c)) = s.observe(config(), observation(0x80, 20, 2, false), 0) else {
        return TestResult::Fail("nonpositive sample skipped source window evaluation");
    };
    if c != (Config {
        main: 2,
        alt: 1,
        bias: 1,
        main_gain: false,
        alt_gain: false,
    }) || s.count != 96
        || s.total != 0
        || s.main_total != 0
        || s.alt_total != 0
    {
        return TestResult::Fail("source window commit or gain/bias reset");
    }
    s.total = u16::MAX;
    if s.observe(c, observation(40, 20, 2, true), 0) != Err(Error::Descriptor) {
        return TestResult::Fail("unbounded aggregate count wrapped");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9485/antenna",
    smoke_ath9k_ar9485_scanner_signed_rssi_and_aggregate_window
);
fn quick() -> Scanner {
    let mut s = Scanner::new(0, 0);
    s.count = 0;
    s.scan = true;
    s.alt_good = true;
    s.scan_not_start = true;
    s.main = 2;
    s.first_conf = 0;
    s.second_conf = 3;
    s.start_ms = 100;
    s
}
fn smoke_ath9k_ar9485_scanner_exact_short_scan_boundaries() -> TestResult {
    let mut s = quick();
    if s.observe(config(), observation(0, 0, 2, true), 150) != Ok(None)
        || s.observe(config(), observation(0, 0, 2, true), 151)
            .ok()
            .flatten()
            .is_none()
        || s.quick != 1
        || s.start_ms != 151
    {
        return TestResult::Fail("source short scan must be strictly >50ms even with moreaggr");
    }
    let mut s = quick();
    for _ in 0..255 {
        if s.observe(config(), observation(40, 30, 2, true), 100) != Ok(None) {
            return TestResult::Fail("source short packet check ran before256");
        }
    }
    if s.observe(config(), observation(40, 30, 2, true), 100)
        .ok()
        .flatten()
        .is_none()
        || s.quick != 1
    {
        return TestResult::Fail("source256 low-alt-ratio did not bypass moreaggr");
    }
    let mut s = quick();
    s.total = 256;
    s.alt_recv = 256;
    s.main_total = 10240;
    s.alt_total = 7680;
    if s.observe(config(), observation(0, 0, 1, true), 100) != Ok(None) {
        return TestResult::Fail("source256 high-alt-ratio incorrectly short-scanned");
    }
    s.total = 257;
    s.alt_recv = 0;
    if s.observe(config(), observation(0, 0, 1, true), 100) != Ok(None) {
        return TestResult::Fail("source exact256 packet boundary became >=256");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9485/antenna",
    smoke_ath9k_ar9485_scanner_exact_short_scan_boundaries
);
fn smoke_ath9k_ar9485_scanner_periodic_quick_and_full_trials() -> TestResult {
    let mut s = Scanner::new(0, 0);
    s.count = 99;
    let Some(a) = window(&mut s, config(), 50, 50) else {
        return TestResult::Fail("initial quick scan window");
    };
    if (a.main, a.alt, a.bias, s.count, s.quick) != (1, 0, 2, 0, 1) || !s.scan || !s.alt_good {
        return TestResult::Fail("count100 source LNA2/A-B quick trial");
    }
    let Some(b) = window(&mut s, a, 40, 39) else {
        return TestResult::Fail("second quick scan window");
    };
    if (b.main, b.alt, b.bias, s.quick) != (1, 3, 2, 2) || !s.first_ratio {
        return TestResult::Fail("source first quick ratio/second A+B trial");
    }
    let Some(c) = window(&mut s, b, 40, 43) else {
        return TestResult::Fail("final quick scan window");
    };
    if (c.main, c.alt, c.bias, s.quick) != (2, 3, 1, 3)
        || s.scan
        || s.alt_good
        || s.scan_not_start
        || !s.second_ratio
        || (s.lna1, s.lna2, s.second, s.third) != (50, 40, 39, 43)
    {
        return TestResult::Fail("source quick final comparison/switch-delta-1/ratio choice");
    }
    let mut s = Scanner::new(20, 0);
    let Some(a) = window(&mut s, config(), 20, 19) else {
        return TestResult::Fail("normal LNA trial");
    };
    let Some(b) = window(&mut s, a, 20, 19) else {
        return TestResult::Fail("normal A+B trial");
    };
    let Some(c) = window(&mut s, b, 20, 18) else {
        return TestResult::Fail("normal A-B trial");
    };
    if (a.main, a.alt, b.alt, c.main, c.alt) != (2, 3, 0, 2, 1)
        || s.scan
        || (s.lna1, s.lna2, s.add, s.sub) != (20, 19, 19, 18)
    {
        return TestResult::Fail("complete source normal A+B/A-B selection");
    }
    for main in 0..4 {
        for alt in 0..4 {
            let mut c = Config {
                main,
                alt,
                ..config()
            };
            s.scan = true;
            s.fast_bias(&mut c, 31);
            let expected = match (main << 4) | alt {
                0x10 | 0x13 | 0x20 | 0x23 => 2,
                0x00 | 0x11 | 0x22 | 0x33 => 9,
                _ => 1,
            };
            if c.bias != expected || c.main_gain || c.alt_gain {
                return TestResult::Fail("literal group2 bias table");
            }
            s.bias = 3;
            s.fast_bias(&mut c, 31);
            s.bias = 0;
            if c.bias != 3 {
                return TestResult::Fail("CUS bias override");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9485/antenna",
    smoke_ath9k_ar9485_scanner_periodic_quick_and_full_trials
);

fn smoke_ath9k_ar9485_source_scan_delta_and_switch_delta_are_distinct() -> TestResult {
    // A low alt ratio avoids alt_check's early switch. The scan gate accepts
    // main-9 exactly (antenna.c:809), and refuses main-10.
    for (alt, scanning) in [(31, true), (30, false)] {
        let mut s = Scanner::new(0, 0);
        let mut last = None;
        for _ in 0..512 {
            last = match s.observe(config(), observation(40, alt, 2, false), 0) {
                Ok(last) => last,
                Err(_) => return TestResult::Fail("literal -9 scan boundary"),
            };
        }
        if last.is_none() || s.scan != scanning {
            return TestResult::Fail("source scan admission used switch delta instead of -9");
        }
    }
    // Both quick and normal selection use strict lna2 > lna1-1,
    // not the independent -9 scan-admission delta (source335/621).
    for (lna2, expected) in [(39, LNA1), (40, LNA2)] {
        let mut s = Scanner::new(0, 0);
        s.lna1 = 40;
        s.lna2 = lna2;
        s.add = 0;
        let mut c = config();
        s.try_scan(&mut c, SUB, 0, 0);
        if c.main != expected {
            return TestResult::Fail("source final normal LNA switch used -9 or lost strictness");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9485/antenna",
    smoke_ath9k_ar9485_source_scan_delta_and_switch_delta_are_distinct
);

fn smoke_ath9k_ar9565_group3_literal_thresholds_bias_and_final_switch() -> TestResult {
    let s = Scanner::new_9565();
    for (main, alt, sample, want) in [
        (LNA2, LNA1, 36, false),
        (LNA2, LNA1, 37, true),
        (LNA1, LNA2, 42, false),
        (LNA1, LNA2, 43, true),
    ] {
        let c = Config {
            main,
            alt,
            ..config()
        };
        if s.alt_check(c, 0, sample, 40) != want {
            return TestResult::Fail("group3 early -3/+3 thresholds differ from source");
        }
    }
    for (main, alt, bias) in [
        (0, 1, 1),
        (0, 2, 0x39),
        (0, 3, 1),
        (1, 0, 2),
        (1, 2, 0x3f),
        (1, 3, 2),
        (2, 0, 3),
        (2, 1, 3),
        (2, 3, 3),
        (3, 0, 1),
        (3, 1, 6),
        (3, 2, 1),
    ] {
        let mut c = Config {
            main,
            alt,
            main_gain: true,
            alt_gain: true,
            ..config()
        };
        s.fast_bias(&mut c, 100);
        if c.bias != bias || c.main_gain || c.alt_gain {
            return TestResult::Fail("group3 source bias/gain table became group2 alias");
        }
    }
    for (lna2, want) in [(43, LNA1), (44, LNA2)] {
        let mut s = Scanner::new_9565();
        s.lna1 = 40;
        s.lna2 = lna2;
        let mut c = config();
        s.try_scan(&mut c, SUB, 0, 0);
        if c.main != want {
            return TestResult::Fail("group3 normal final lost strict +3 delta");
        }
        s.quick = 2;
        s.main = ADD;
        s.second_conf = ADD;
        s.lna1 = 40;
        s.lna2 = lna2;
        s.quick_scan(&mut c, 40, 0, 0);
        if c.main != want {
            return TestResult::Fail("group3 quick final lost strict +3 delta");
        }
    }
    let mut s = Scanner::new_9565();
    s.count = 99;
    let Some(a) = window(&mut s, config(), 50, 50) else {
        return TestResult::Fail("group3 quick first");
    };
    let Some(b) = window(&mut s, a, 40, 39) else {
        return TestResult::Fail("group3 quick second");
    };
    let Some(c) = window(&mut s, b, 40, 43) else {
        return TestResult::Fail("group3 quick final");
    };
    if (a.bias, b.bias, c.bias, c.main, c.alt) != (2, 2, 3, LNA1, ADD) {
        return TestResult::Fail("group3 complete quick vector/source bias");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9565_group3_literal_thresholds_bias_and_final_switch
);
