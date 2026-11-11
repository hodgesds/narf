use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// cfg80211's rates for known points (`iw` prints these as Mb/s), and
/// `None` for every out-of-table index instead of a panic.
fn smoke_rate_cfg80211_bitrates_and_bounds() -> TestResult {
    let known = [
        (ht_bitrate_100kbps(7, 1, 20, false), 650),
        (ht_bitrate_100kbps(7, 1, 20, true), 722),
        (ht_bitrate_100kbps(7, 2, 40, true), 3000),
        (vht_bitrate_100kbps(9, 2, 80, true), 8667),
        (vht_bitrate_100kbps(0, 1, 20, false), 65),
        (he_bitrate_100kbps(11, 2, 0, 80, None), 12009),
        (he_bitrate_100kbps(0, 1, 2, 20, None), 73),
        (he_bitrate_100kbps(11, 1, 0, 0, Some(2)), 500),
    ];
    for (got, want) in known {
        if got != Some(want) {
            return TestResult::Fail("bitrate differs from cfg80211_calculate_bitrate");
        }
    }
    if ht_bitrate_100kbps(8, 1, 20, false).is_some()
        || ht_bitrate_100kbps(0, 0, 20, false).is_some()
        || ht_bitrate_100kbps(0, 1, 80, false).is_some()
        || vht_bitrate_100kbps(10, 1, 20, false).is_some()
        || vht_bitrate_100kbps(0, 9, 20, false).is_some()
        || he_bitrate_100kbps(12, 1, 0, 20, None).is_some()
        || he_bitrate_100kbps(0, 1, 3, 20, None).is_some()
        || he_bitrate_100kbps(0, 1, 0, 20, Some(7)).is_some()
    {
        return TestResult::Fail("out-of-table rate index produced a bitrate");
    }
    TestResult::Pass
}
kernel_test_in!("wireless/rate", smoke_rate_cfg80211_bitrates_and_bounds);
