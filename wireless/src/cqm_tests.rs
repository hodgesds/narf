use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn single(threshold: i32, hysteresis: u32) -> CqmRssiConfig {
    CqmRssiConfig {
        thresholds_dbm: vec![threshold],
        hysteresis_db: hysteresis,
    }
}

/// mac80211 `ieee80211_rx_bss_info`: no event before four Beacons, the
/// first crossing at the averaged level, nothing again until the level
/// moves beyond the hysteresis, and the opposite crossing after it.
fn smoke_cqm_single_threshold_follows_mac80211() -> TestResult {
    let config = single(-70, 4);
    let mut cqm = SoftwareCqm::default();
    for _ in 0..3 {
        if cqm.beacon(-80, Some(&config)).is_some() {
            return TestResult::Fail("event before IEEE80211_SIGNAL_AVE_MIN_COUNT beacons");
        }
    }
    if cqm.beacon(-80, Some(&config)) != Some(false) || cqm.level_dbm() != Some(-80) {
        return TestResult::Fail("first LOW crossing");
    }
    if cqm.beacon(-82, Some(&config)).is_some() {
        return TestResult::Fail("LOW repeated inside the hysteresis");
    }
    // The EWMA (weight 1/4) climbs over the threshold within a few beacons.
    let mut high = None;
    for _ in 0..12 {
        if let Some(event) = cqm.beacon(-50, Some(&config)) {
            high = Some(event);
            break;
        }
    }
    if high != Some(true) {
        return TestResult::Fail("HIGH crossing after the signal recovered");
    }
    // Without a configuration nothing is reported, though the average runs.
    let mut quiet = SoftwareCqm::default();
    for _ in 0..8 {
        if quiet.beacon(-90, None).is_some() {
            return TestResult::Fail("event without a configuration");
        }
    }
    if quiet.level_dbm() != Some(-90) {
        return TestResult::Fail("average without a configuration");
    }
    TestResult::Pass
}
kernel_test_in!("wireless/cqm", smoke_cqm_single_threshold_follows_mac80211);

/// The threshold-list form (`cfg80211_cqm_rssi_update`): crossing below
/// the active range's low edge reports LOW, the range then moves, and
/// crossing back above its high edge reports HIGH once.
fn smoke_cqm_threshold_list_ranges() -> TestResult {
    let config = CqmRssiConfig {
        thresholds_dbm: vec![-80, -65],
        hysteresis_db: 2,
    };
    let mut cqm = SoftwareCqm::default();
    let mut events = alloc::vec::Vec::new();
    for signal in [-60, -60, -60, -60, -60, -72, -72, -72, -72, -72, -72] {
        if let Some(event) = cqm.beacon(signal, Some(&config)) {
            events.push((event, cqm.level_dbm()));
        }
    }
    // From the 0 sentinel the range is (-65 - 2, MAX): -60 is inside; the
    // drop to about -72 crosses -67 once.
    if events.len() != 1 || events[0].0 {
        return TestResult::Fail("threshold list LOW crossing");
    }
    let mut back = None;
    for _ in 0..12 {
        if let Some(event) = cqm.beacon(-55, Some(&config)) {
            back = Some(event);
            break;
        }
    }
    if back != Some(true) {
        return TestResult::Fail("threshold list HIGH crossing");
    }
    if cqm.beacon(-55, Some(&config)).is_some() {
        return TestResult::Fail("HIGH repeated in the same range");
    }
    TestResult::Pass
}
kernel_test_in!("wireless/cqm", smoke_cqm_threshold_list_ranges);
