use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw89_track_edcca_threshold_matches_linux() -> TestResult {
    // rtw89_phy_edcca_get_thre_by_rssi: unlinked is EDCCA_MAX; linked is
    // rssi_min/2 - 110 + 128 - 3, floored at EDCCA_TH_L2H_LB.
    for (rssi, expected) in [
        (None, 249),
        (Some(0), 66),
        (Some(100), 66),
        (Some(102), 66),
        (Some(104), 67),
        (Some(140), 85),
        (Some(255), 142),
    ] {
        if edcca_threshold(rssi) != expected {
            return TestResult::Fail(
                "EDCCA threshold differs from rtw89_phy_edcca_get_thre_by_rssi",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_track_edcca_threshold_matches_linux
);

fn smoke_rtw89_track_rssi_ewma_matches_linux() -> TestResult {
    // DECLARE_EWMA(rssi, 10, 16): the first sample seeds, then 15/16 decay.
    let mut rssi = Rssi::default();
    rssi.add(160);
    if rssi.read() != 160 {
        return TestResult::Fail("first EWMA sample does not seed the average");
    }
    rssi.add(0);
    // ((160<<10)*15 + 0) >> 4 = 153600 -> 150
    if rssi.read() != 150 {
        return TestResult::Fail("EWMA weight differs from ewma_rssi_add");
    }
    for _ in 0..200 {
        rssi.add(80);
    }
    if !(80..=81).contains(&rssi.read()) {
        return TestResult::Fail("EWMA does not converge to a steady sample");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_track_rssi_ewma_matches_linux
);

fn smoke_rtw89_track_period_peer_reset_and_scan_skip() -> TestResult {
    let peer = Some([2, 0, 0, 0, 0, 1]);
    let mut track = Tracker::default();
    // First period: unlinked writes EDCCA_MAX once.
    if track.due(0, None, false) != Some(EDCCA_MAX) {
        return TestResult::Fail("first track period does not program EDCCA_MAX");
    }
    track.written(EDCCA_MAX);
    if track.due(1000, None, false).is_some() || track.due(2000, None, false).is_some() {
        return TestResult::Fail("track work runs early or rewrites an unchanged level");
    }
    // Unlinked samples are ignored; linked samples count.
    track.sample(None, 200);
    track.sample(peer, 180);
    if track.rssi() != 180 {
        return TestResult::Fail("linked RSSI sample not tracked");
    }
    if track.due(4000, peer, true).is_some() {
        return TestResult::Fail("track work ran while scanning");
    }
    if track.due(4000, peer, false) != Some(105) {
        return TestResult::Fail("linked level differs from the RSSI threshold");
    }
    track.written(105);
    // A different peer restarts the average (ewma_rssi_init at station add).
    if track.due(6000, Some([2, 0, 0, 0, 0, 2]), false) != Some(66) {
        return TestResult::Fail("new peer kept the previous RSSI average");
    }
    track.disable();
    if track.due(100_000, None, false).is_some() {
        return TestResult::Fail("disabled tracking still programs hardware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_track_period_peer_reset_and_scan_skip
);
