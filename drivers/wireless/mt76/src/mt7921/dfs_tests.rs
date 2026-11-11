//! Radar (DFS) and NO_IR channels: a station follows an AP it heard there,
//! scans stay passive, and a Channel Switch Announcement from the AP takes
//! the station off the channel.
use super::*;
use crate::mt7921::association::{announces_channel_switch, TxPermission};
use alloc::boxed::Box;
use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};

fn us_domain() -> RegulatoryDomain {
    let rule = |start, end, bandwidth, power, flags| RegRule {
        freq_start_mhz: start,
        freq_end_mhz: end,
        max_bandwidth_mhz: bandwidth,
        max_power_dbm: power,
        flags,
    };
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![
            rule(2400, 2472, 40, 30, RegFlags::empty()),
            rule(5150, 5250, 80, 23, RegFlags::AUTO_BW),
            rule(5250, 5350, 80, 24, RegFlags::DFS | RegFlags::AUTO_BW),
            rule(5470, 5730, 160, 24, RegFlags::DFS),
            rule(5730, 5850, 80, 30, RegFlags::AUTO_BW),
        ],
    }
}

fn dfs_bss(channel: u8) -> ScanBss {
    ScanBss {
        bssid: [2, 0xd0, 0xd1, 0xd2, 0xd3, channel],
        ssid: b"narf-dfs".to_vec(),
        channel,
        band: None,
        signal_dbm: Some(-50),
        capability: 0x0011,
        beacon_interval: 100,
        information_elements: vec![0, 8, b'n', b'a', b'r', b'f', b'-', b'd', b'f', b's'],
    }
}

/// cfg80211 lets a station join an AP operating on a radar or NO_IR
/// channel once it has heard it; only a disabled channel is refused. The
/// grant needs the AP's Beacon from this scan, keeps every non-radar
/// restriction, survives a policy re-check under the same relaxation, and
/// is revoked when the channel leaves the domain.
fn mt7922_station_follows_a_heard_ap_onto_radar_and_no_ir_channels() -> TestResult {
    let us = us_domain();
    for channel in [52u8, 64, 100, 144] {
        if TxPermission::from_domain(&us, channel).is_some() {
            return TestResult::Fail("radar channel granted without a heard AP");
        }
        let Some(grant) = TxPermission::from_heard_ap(&us, channel) else {
            return TestResult::Fail("heard AP on a radar channel refused");
        };
        if !grant.follows_heard_ap() || !grant.current(&us) || grant.power_dbm != 24 {
            return TestResult::Fail("heard-AP grant is not a current, rule-limited grant");
        }
    }
    // A channel that is already permitted keeps its ordinary grant.
    if TxPermission::from_heard_ap(&us, 36).is_none_or(|g| g.follows_heard_ap()) {
        return TestResult::Fail("non-radar channel took the heard-AP relaxation");
    }
    // World 00 keeps U-NII-1 NO_IR: a heard AP lifts it, as a beacon hint.
    let mut world = us_domain();
    world.country_code = *b"00";
    world.rules[1].flags |= RegFlags::NO_IR;
    if TxPermission::from_domain(&world, 40).is_some()
        || TxPermission::from_heard_ap(&world, 40).is_none()
    {
        return TestResult::Fail("NO_IR channel with a heard AP");
    }
    // INDOOR_ONLY and the absence of a rule are not relaxed.
    let mut indoor = us_domain();
    indoor.rules[2].flags |= RegFlags::INDOOR_ONLY;
    if TxPermission::from_heard_ap(&indoor, 52).is_some() {
        return TestResult::Fail("INDOOR_ONLY relaxed by a heard AP");
    }
    let mut gone = us_domain();
    gone.rules.remove(2);
    let grant = TxPermission::from_heard_ap(&us, 56).unwrap();
    if TxPermission::from_heard_ap(&gone, 56).is_some() || grant.current(&gone) {
        return TestResult::Fail("heard-AP grant outlived its regulatory rule");
    }
    // The join path: only a beaconed BSS is followed onto the channel.
    let (session, _) = super::pmf_tests::prepared(super::pmf_tests::pmf_ap());
    let (State::RadioReady(info) | State::ScanReady(info)) = session.state else {
        return TestResult::Fail("model radio not ready");
    };
    let bss = dfs_bss(52);
    if TxPermission::from_ap_heard(&us, info, &bss, false).is_some()
        || !TxPermission::from_ap_heard(&us, info, &bss, true)
            .is_some_and(|g| g.follows_heard_ap() && g.permits_bss(&bss))
    {
        return TestResult::Fail("join grant on a radar channel ignores the Beacon evidence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/dfs",
    mt7922_station_follows_a_heard_ap_onto_radar_and_no_ir_channels
);

/// A scan records a BSS as beaconed only for its Beacon frame: a Probe
/// Response alone is not the evidence a radar-channel join needs.
fn mt7922_scan_records_beacons_not_probe_responses() -> TestResult {
    use narf_wifi_fixtures::FakeAp;
    let ap = FakeAp::open(super::wmm_tests::NETWORK, b"narf", 6, 42).unwrap();
    let beacon = ap.beacon();
    let mut response = beacon.clone();
    response[0] = 0x50;
    response[4..10].copy_from_slice(&super::wmm_tests::NETWORK.station);
    let parse = |frame: &[u8]| {
        let packet = super::descriptor(frame);
        crate::mt7921::firmware_transport::scan::beacon(&packet, 1).map(|bss| (packet, bss))
    };
    let (Some((beacon_packet, beacon_bss)), Some((response_packet, response_bss))) =
        (parse(&beacon), parse(&response))
    else {
        return TestResult::Fail("fixture Beacon / Probe Response did not parse");
    };
    let mut report = ScanReport {
        bss: Vec::new(),
        beaconed: Vec::new(),
        received: 0,
        ignored: 0,
        truncated: false,
    };
    report.note_beacon(&response_packet, &response_bss);
    if !report.beaconed.is_empty() {
        return TestResult::Fail("Probe Response recorded as a Beacon");
    }
    report.note_beacon(&beacon_packet, &beacon_bss);
    report.note_beacon(&beacon_packet, &beacon_bss);
    if report.beaconed != [(beacon_bss.bssid, 6)] {
        return TestResult::Fail("Beacon not recorded exactly once");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/dfs",
    mt7922_scan_records_beacons_not_probe_responses
);

/// The AP announces a channel switch (CSA, or extended CSA) in its Beacon:
/// the associated station leaves the channel at once — its receive path
/// reports the link gone — instead of transmitting until the AP is gone.
fn mt7922_station_leaves_the_channel_on_the_aps_channel_switch() -> TestResult {
    if !announces_channel_switch(&[0, 1, b'x', 37, 3, 1, 100, 5])
        || !announces_channel_switch(&[60, 4, 1, 121, 100, 5])
        || announces_channel_switch(&[0, 1, b'x', 37, 2, 1, 100])
        || announces_channel_switch(&[37, 3, 1])
    {
        return TestResult::Fail("CSA element recognition");
    }
    for element in [&[37u8, 3, 1, 100, 5][..], &[60, 4, 1, 121, 100, 5]] {
        let (mut session, bss) = super::pmf_tests::prepared(super::pmf_tests::pmf_ap());
        let joined = run(Box::pin(session.associate_station(
            &bss,
            b"narf",
            crate::mt7921::association::Security::Wpa2PskPmf {
                psk: [0x55; 32],
                required: false,
            },
            test_permission(),
            &[],
        )));
        if joined != Ok(42) {
            return TestResult::Fail("WPA2 association for the CSA test");
        }
        let beacon = session.backend.access_point.as_ref().unwrap().beacon();
        // The AP's unchanged Beacon keeps the link.
        session
            .backend
            .packets
            .push_back(super::descriptor(&beacon));
        if session
            .receive_ethernet()
            .is_err_and(|error| error == Error::DeviceGone)
            || session.station.peer_lost
        {
            return TestResult::Fail("unchanged Beacon dropped the link");
        }
        let mut announced = beacon.clone();
        announced.extend_from_slice(element);
        session
            .backend
            .packets
            .push_back(super::descriptor(&announced));
        if session.receive_ethernet() != Err(Error::DeviceGone) || !session.station.peer_lost {
            return TestResult::Fail("station stayed on the channel after the AP's CSA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/dfs",
    mt7922_station_leaves_the_channel_on_the_aps_channel_switch
);
