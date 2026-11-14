//! Radar (DFS) and NO_IR channels: a station follows an AP it heard there,
//! scans stay passive, and the station follows the AP's Channel Switch
//! Announcement in place (or leaves when it cannot).
use super::*;
use crate::mt7921::association::{channel_switch, ChannelSwitch, TxPermission};
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

/// `frame` as a CONNAC2 RX packet received on 2.4 GHz `channel`.
fn on_channel(frame: &[u8], channel: u8) -> Vec<u8> {
    let mut packet = super::descriptor(frame);
    let r3 = u32::from_le_bytes(packet[12..16].try_into().unwrap());
    let r3 = (r3 & !0xff00) | u32::from(channel) << 8;
    packet[12..16].copy_from_slice(&r3.to_le_bytes());
    packet
}

fn us_2ghz_policy() -> Arc<CurrentPolicy> {
    let policy = Arc::new(CurrentPolicy {
        database: narf_wireless::reg::db::Database::new(),
        hold_bss_ack: core::sync::atomic::AtomicBool::new(false),
    });
    // Channels 1..11 at 20 MHz; 12 and 13 fall outside the rule.
    policy.database.install(RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    });
    policy
}

/// An MT7922 station associated (WPA2 + PMF) on channel 6 under a US
/// 2.4 GHz policy, with the fixture AP's Beacon.
fn associated_on_6() -> Option<(Box<Session<Model>>, Vec<u8>)> {
    let (mut session, bss) = super::pmf_tests::prepared(super::pmf_tests::pmf_ap());
    session.backend.tx_policy = Some(us_2ghz_policy());
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
        return None;
    }
    let beacon = session.backend.access_point.as_ref()?.beacon();
    Some((session, beacon))
}

fn with_element(beacon: &[u8], element: &[u8]) -> Vec<u8> {
    let mut frame = beacon.to_vec();
    frame.extend_from_slice(element);
    frame
}

fn mt7922_channel_switch_elements_parse() -> TestResult {
    let switch = |block_tx, channel, count, operating_class| ChannelSwitch {
        block_tx,
        channel,
        count,
        operating_class,
        secondary_offset: None,
        wide: None,
    };
    if channel_switch(&[0, 1, b'x', 37, 3, 1, 100, 5]) != Some(switch(true, 100, 5, None))
        || channel_switch(&[60, 4, 0, 121, 100, 5]) != Some(switch(false, 100, 5, Some(121)))
        || channel_switch(&[0, 1, b'x', 37, 2, 1, 100]).is_some()
        || channel_switch(&[37, 3, 1]).is_some()
        // New channel 0 is nothing this owner understands.
        || channel_switch(&[37, 3, 1, 0, 5]).is_some()
    {
        return TestResult::Fail("CSA / ECSA element parsing");
    }
    // The ECSA wins when its operating class names a band; otherwise the
    // CSA is used (ieee80211_parse_ch_switch_ie).
    if channel_switch(&[37, 3, 0, 52, 3, 60, 4, 1, 128, 100, 2])
        != Some(switch(true, 100, 2, Some(128)))
        || channel_switch(&[37, 3, 0, 52, 3, 60, 4, 1, 200, 100, 2])
            != Some(switch(false, 52, 3, None))
    {
        return TestResult::Fail("ECSA preference over CSA");
    }
    // Secondary Channel Offset and the Wide Bandwidth Channel Switch
    // subelement of the Channel Switch Wrapper; a bare element 194 (an
    // action-frame form) is not read from a Beacon.
    let full = [
        37, 3, 1, 100, 4, 62, 1, 1, 196, 9, 195, 2, 0, 0, 194, 3, 1, 106, 0,
    ];
    if channel_switch(&full).is_none_or(|s| {
        s.secondary_offset != Some(1) || s.wide != Some([1, 106, 0]) || s.channel != 100
    }) || channel_switch(&[37, 3, 1, 100, 4, 194, 3, 1, 106, 0]).is_none_or(|s| s.wide.is_some())
    {
        return TestResult::Fail("SCO / wide bandwidth channel switch parsing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/dfs",
    mt7922_channel_switch_elements_parse
);

/// The AP announces a switch to channel 11 in two Beacon intervals with
/// Channel Switch Mode 1 (mac80211 `ieee80211_sta_process_chanswitch`): the
/// station stops data at once but keeps the link; at the switch time it
/// retunes (channel domain, power limits, CHANNEL_SWITCH to channel 11)
/// under the current policy, keeps the association and resumes on the new
/// channel, where the AP's Beacons keep the link up.
fn mt7922_station_follows_the_aps_channel_switch_in_place() -> TestResult {
    let Some((mut session, beacon)) = associated_on_6() else {
        return TestResult::Fail("association on channel 6");
    };
    let announced = with_element(&beacon, &[37, 3, 1, 11, 2]);
    session.backend.packets.push_back(on_channel(&announced, 6));
    if session.receive_ethernet().is_err() || session.station.peer_lost {
        return TestResult::Fail("CSA ended the link instead of being followed");
    }
    if !session.station.csa_block_tx || session.station.csa.is_none() {
        return TestResult::Fail("Channel Switch Mode 1 not recorded");
    }
    let mut eth = vec![0xff; 60];
    eth[6..12].copy_from_slice(&[2, 0x11, 0x22, 0x33, 0x44, 0x55]);
    eth[12..14].copy_from_slice(&[8, 0]);
    if session.start_ethernet(&eth) != Err(Error::Busy) {
        return TestResult::Fail("data sent during Channel Switch Mode 1");
    }
    // Two beacon intervals later the switch is due.
    let now = session.backend.ticks.get();
    session.backend.ticks.set(now + 1_000_000_000);
    if !session.keys_pending() {
        return TestResult::Fail("due channel switch not scheduled");
    }
    let before = session.backend.frames.len();
    if run(Box::pin(session.service_keys())).is_err() {
        return TestResult::Fail("channel switch service failed");
    }
    // MCU TXD: cid 0xed (extended) at 36, ext_cid at 41.
    let switched = session.backend.frames[before..].iter().any(|(_, f)| {
        f.get(36) == Some(&0xed)
            && f.get(41) == Some(&crate::mt7921::regs::MCU_EXT_CMD_CHANNEL_SWITCH)
    });
    if !switched
        || !matches!(
            session.state,
            State::Associated {
                channel: 11,
                aid: 42,
                ..
            }
        )
        || !session.station.permission.is_some_and(|p| p.permits(11))
        || session.station.csa.is_some()
        || session.station.csa_block_tx
        || session.station.security.is_none()
    {
        return TestResult::Fail("station did not retune to channel 11 with its association");
    }
    // The AP's Beacon on the new channel keeps the link.
    session.backend.station_channel = 11;
    session.backend.packets.push_back(on_channel(&beacon, 11));
    if session.receive_ethernet().is_err() || session.station.peer_lost {
        return TestResult::Fail("Beacon on the new channel dropped the link");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/dfs",
    mt7922_station_follows_the_aps_channel_switch_in_place
);

/// A switch the station cannot follow ends the link (mac80211
/// `ieee80211_sta_connection_lost`): a channel the policy forbids
/// (channel 13 outside the US 2.4 GHz rule), and another band.
fn mt7922_station_leaves_on_a_channel_switch_it_cannot_follow() -> TestResult {
    for (target, reason) in [
        (13u8, "switch to a forbidden channel was followed"),
        (36, "switch to another band was followed"),
    ] {
        let Some((mut session, beacon)) = associated_on_6() else {
            return TestResult::Fail("association on channel 6");
        };
        let announced = with_element(&beacon, &[37, 3, 0, target, 0]);
        session.backend.packets.push_back(on_channel(&announced, 6));
        let _ = session.receive_ethernet();
        if session.station.csa_block_tx || !session.keys_pending() {
            return TestResult::Fail("immediate Mode 0 switch not scheduled");
        }
        let _ = run(Box::pin(session.service_keys()));
        if matches!(session.state, State::Associated { .. }) && !session.station.peer_lost {
            return TestResult::Fail(reason);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/dfs",
    mt7922_station_leaves_on_a_channel_switch_it_cannot_follow
);

/// The width an announced switch names (mac80211
/// `ieee80211_parse_ch_switch_ie`): the Wide Bandwidth Channel Switch
/// element for a VHT connection, else the ECSA operating class, else the
/// Secondary Channel Offset; never wider than the connection's limit, and
/// inconsistent channel data ends the link.
fn mt7922_channel_switch_width_follows_mac80211() -> TestResult {
    use crate::mt7921::csa::{switch_target, Chandef};
    let switch = |offset, wide, class| ChannelSwitch {
        block_tx: false,
        channel: 100,
        count: 1,
        operating_class: class,
        secondary_offset: offset,
        wide,
    };
    let (Some(twenty), Some(forty), Some(eighty), Some(one_sixty)) = (
        Chandef::twenty(100),
        Chandef::forty(100, 1),
        Chandef::eighty(100, 106),
        Chandef::one_sixty(100, 114),
    ) else {
        return TestResult::Fail("chandef geometry");
    };
    let cases = [
        // No offset element: 20 MHz even for a VHT connection.
        (switch(None, None, None), 2, true, Some((twenty, twenty))),
        // An offset alone keeps HT40.
        (switch(Some(1), None, None), 2, true, Some((forty, forty))),
        (
            switch(Some(1), Some([1, 106, 0]), None),
            2,
            true,
            Some((eighty, eighty)),
        ),
        // Revised 160 MHz encoding, narrowed to an 80 MHz connection.
        (
            switch(Some(1), Some([1, 106, 114]), None),
            2,
            true,
            Some((one_sixty, eighty)),
        ),
        (
            switch(Some(1), Some([1, 106, 114]), None),
            3,
            true,
            Some((one_sixty, one_sixty)),
        ),
        // An HT connection reads neither the wide element nor beyond HT40.
        (
            switch(Some(1), Some([1, 106, 0]), None),
            1,
            false,
            Some((forty, forty)),
        ),
        (
            switch(Some(1), None, Some(128)),
            1,
            false,
            Some((forty, forty)),
        ),
        // An ECSA operating class without the wide element.
        (
            switch(Some(1), None, Some(128)),
            2,
            true,
            Some((eighty, eighty)),
        ),
        // A 20 MHz connection ignores the width elements.
        (
            switch(Some(1), Some([1, 106, 0]), None),
            0,
            true,
            Some((twenty, twenty)),
        ),
        // The wide channel puts the secondary above; the offset says below.
        (switch(Some(3), Some([1, 106, 0]), None), 2, true, None),
        // An invalid wide element falls back to the offset's HT40.
        (
            switch(Some(1), Some([1, 107, 0]), None),
            2,
            true,
            Some((forty, forty)),
        ),
    ];
    if cases
        .into_iter()
        .any(|(announced, limit, vht, expected)| switch_target(&announced, limit, vht) != expected)
    {
        return TestResult::Fail("announced switch width");
    }
    // The downgrade chain and compatibility of the chandefs.
    if one_sixty.downgrade() != eighty
        || eighty.downgrade() != forty
        || forty.downgrade() != twenty
        || !eighty.compatible(forty)
        || !eighty.compatible(twenty)
        || Chandef::forty(104, 3).is_some_and(|other| eighty.compatible(other))
    {
        return TestResult::Fail("chandef downgrade / compatibility");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/dfs",
    mt7922_channel_switch_width_follows_mac80211
);

/// A policy for the VHT fixture: 5 GHz up to `wide` MHz, with 100..144 at
/// most `upper` MHz wide.
fn vht_policy(wide: u32, upper: u32) -> Arc<CurrentPolicy> {
    let policy = Arc::new(CurrentPolicy {
        database: narf_wireless::reg::db::Database::new(),
        hold_bss_ack: core::sync::atomic::AtomicBool::new(false),
    });
    let rule = |start, end, bandwidth| RegRule {
        freq_start_mhz: start,
        freq_end_mhz: end,
        max_bandwidth_mhz: bandwidth,
        max_power_dbm: 17,
        flags: RegFlags::empty(),
    };
    policy.database.install(RegulatoryDomain {
        country_code: *b"US",
        rules: vec![
            rule(5170, 5330, wide),
            rule(5490, 5730, upper),
            rule(5735, 5895, wide),
        ],
    });
    policy
}

/// An MT7922 VHT station associated (WPA2) at `width` on channel 36 under
/// `policy`, and the AP's address.
fn vht_associated(width: u8, policy: Arc<CurrentPolicy>) -> Option<(NativeSession, [u8; 6])> {
    let (mut session, bss, _) = super::vht_tests::prepared(width, true);
    session.backend.tx_policy = Some(policy.clone());
    let domain = policy.database.snapshot()?;
    let State::RadioReady(info) = session.state else {
        return None;
    };
    let grant = TxPermission::from_ap(&domain, info, &bss)?;
    if super::vht_tests::join(&mut session, &bss, grant, true) != Ok(42)
        || session
            .station
            .vht_profile
            .is_none_or(|v| v.width() != width)
    {
        return None;
    }
    Some((session, bss.bssid))
}

/// The AP's Beacon on `channel` at `width` (the VHT fixture's HT and VHT
/// Operation), followed by `extra` elements.
fn vht_beacon(ap: [u8; 6], channel: u8, width: u8, extra: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 36];
    frame[0] = 0x80;
    frame[4..10].fill(0xff);
    frame[10..16].copy_from_slice(&ap);
    frame[16..22].copy_from_slice(&ap);
    frame[32..34].copy_from_slice(&100u16.to_le_bytes());
    frame.extend_from_slice(&super::wmm_tests::PARAMETERS);
    let (ht, vht) = super::vht_tests::elements(width, channel);
    frame.extend_from_slice(&ht);
    frame.extend_from_slice(&vht);
    frame.extend_from_slice(extra);
    let mut packet = descriptor(&frame);
    packet[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
    packet
}

/// The last CHANNEL_SWITCH (primary, centre, width) and BSS RLM record
/// (control channel, centre, width, SCO) the station sent after `from`.
fn retune_records(session: &NativeSession, from: usize) -> Option<([u8; 3], [u8; 4])> {
    let frames = &session.backend.frames[from..];
    let switch = frames
        .iter()
        .rev()
        .find(|(_, f)| f.len() >= 140 && f[36] == 0xed && f[41] == 8)?;
    let rlm = frames
        .iter()
        .rev()
        .find(|(_, f)| f.len() == 68 && f[34..36] == [2, 0] && f[52..56] == [2, 0, 16, 0])?;
    Some((
        [switch.1[64], switch.1[65], switch.1[66]],
        [rlm.1[56], rlm.1[57], rlm.1[59], rlm.1[64]],
    ))
}

/// Deliver `packet`, then run the control work it made due.
fn deliver_and_service(session: &mut NativeSession, packet: Vec<u8>) -> Result<(), &'static str> {
    session.backend.packets.push_back(packet);
    if session.receive_ethernet().is_err() || session.station.peer_lost {
        return Err("AP frame ended the link");
    }
    let now = session.backend.ticks.get();
    session.backend.ticks.set(now + 1_000_000_000);
    if session.keys_pending() && run(Box::pin(session.service_keys())).is_err() {
        return Err("control work failed");
    }
    Ok(())
}

/// The station's grant, VHT profile and HT secondary at `primary`,
/// `width`, `center`, with the radio and BSS RLM retuned to it after
/// frame `from`.
fn at_width(
    session: &NativeSession,
    from: usize,
    primary: u8,
    width: u8,
    center: u8,
) -> Result<(), &'static str> {
    let sco = match width {
        0 => 0,
        _ if primary < center => 1,
        _ => 3,
    };
    let expected = crate::mt7921::csa::Chandef {
        primary,
        width,
        center,
    };
    if !matches!(session.state, State::Associated { channel, aid: 42, .. } if channel == primary)
        || session
            .station
            .permission
            .is_none_or(|p| p.chandef() != expected)
        || session
            .station
            .vht_profile
            .is_none_or(|v| v.width() != width || v.center() != center)
        || session
            .station
            .ht20_profile
            .is_none_or(|h| h.negotiated_secondary().is_some() != (width != 0))
        || session.station.security.is_none()
    {
        return Err("association not at the expected channel and width");
    }
    if retune_records(session, from)
        != Some(([primary, center, width], [primary, center, width, sco]))
    {
        return Err("radio and BSS RLM not retuned to the width");
    }
    Ok(())
}

/// An 80 MHz home AP moved by radar detection: the station follows each
/// switch at the width it names (80 -> 40 with only a Secondary Channel
/// Offset, 40 -> 20 without one), keeps the association and its VHT
/// profile, retunes the radio and the BSS RLM record (`mt7921_csa_work` ->
/// `mt76_connac_mcu_uni_set_chctx`), and the AP's Beacons on each new
/// channel keep the link.
fn eighty_forty_twenty() -> Result<(), &'static str> {
    let (mut session, ap) = vht_associated(2, vht_policy(80, 80)).ok_or("80 MHz association")?;
    let from = session.backend.frames.len();
    deliver_and_service(
        &mut session,
        vht_beacon(ap, 36, 2, &[37, 3, 1, 100, 1, 62, 1, 1]),
    )?;
    at_width(&session, from, 100, 1, 102)?;
    deliver_and_service(&mut session, vht_beacon(ap, 100, 1, &[]))?;
    let from = session.backend.frames.len();
    deliver_and_service(&mut session, vht_beacon(ap, 100, 1, &[37, 3, 0, 149, 1]))?;
    at_width(&session, from, 149, 0, 149)?;
    // A Beacon whose VHT Operation encodes the same 20 MHz differently only
    // rebinds the AP's elements.
    let from = session.backend.frames.len();
    deliver_and_service(&mut session, vht_beacon(ap, 149, 0, &[]))?;
    if session.backend.frames.len() != from
        || session.station.bw_change.is_some()
        || session
            .station
            .permission
            .is_none_or(|p| p.native_width() != 0)
    {
        return Err("same-width Beacon retuned the radio");
    }
    Ok(())
}

/// A VHT connection that associated at 20 MHz follows a switch to 80 MHz:
/// mac80211's limit is the connection's capability, not the width at
/// association.
fn twenty_eighty() -> Result<(), &'static str> {
    let (mut session, ap) = vht_associated(0, vht_policy(80, 80)).ok_or("20 MHz association")?;
    let from = session.backend.frames.len();
    let switch = [37, 3, 1, 100, 1, 62, 1, 1, 196, 5, 194, 3, 1, 106, 0];
    deliver_and_service(&mut session, vht_beacon(ap, 36, 0, &switch))?;
    at_width(&session, from, 100, 2, 106)?;
    deliver_and_service(&mut session, vht_beacon(ap, 100, 2, &[]))?;
    if session.station.bw_change.is_some() {
        return Err("80 MHz Beacon after the switch");
    }
    Ok(())
}

/// The policy allows 100..144 only at 40 MHz: an 80 MHz switch there is
/// followed at 40 MHz (`ieee80211_chandef_downgrade`), and the AP's 80 MHz
/// Beacons keep the link without widening it.
fn policy_downgrade() -> Result<(), &'static str> {
    let (mut session, ap) = vht_associated(2, vht_policy(80, 40)).ok_or("80 MHz association")?;
    let from = session.backend.frames.len();
    let switch = [37, 3, 1, 100, 1, 62, 1, 1, 196, 5, 194, 3, 1, 106, 0];
    deliver_and_service(&mut session, vht_beacon(ap, 36, 2, &switch))?;
    at_width(&session, from, 100, 1, 102)?;
    let from = session.backend.frames.len();
    deliver_and_service(&mut session, vht_beacon(ap, 100, 2, &[]))?;
    if session.backend.frames.len() != from
        || session
            .station
            .permission
            .is_none_or(|p| p.native_width() != 1)
    {
        return Err("80 MHz Beacon widened past the policy");
    }
    Ok(())
}

/// The first Beacon after a switch names a different width than the
/// announcement: the station follows the Beacon (`ieee80211_config_bw`),
/// and later width changes in ordinary Beacons the same way. A Beacon whose
/// operation elements are inconsistent ends the link.
fn beacon_disagrees() -> Result<(), &'static str> {
    let (mut session, ap) = vht_associated(2, vht_policy(80, 80)).ok_or("80 MHz association")?;
    let from = session.backend.frames.len();
    let switch = [37, 3, 1, 100, 1, 62, 1, 1, 196, 5, 194, 3, 1, 106, 0];
    deliver_and_service(&mut session, vht_beacon(ap, 36, 2, &switch))?;
    at_width(&session, from, 100, 2, 106)?;
    let from = session.backend.frames.len();
    session
        .backend
        .packets
        .push_back(vht_beacon(ap, 100, 1, &[]));
    if session.receive_ethernet().is_err() || session.station.bw_change.is_none() {
        return Err("narrower Beacon not recorded as a width change");
    }
    if !session.keys_pending() || run(Box::pin(session.service_keys())).is_err() {
        return Err("width change service");
    }
    at_width(&session, from, 100, 1, 102)?;
    let from = session.backend.frames.len();
    deliver_and_service(&mut session, vht_beacon(ap, 100, 2, &[]))?;
    at_width(&session, from, 100, 2, 106)?;
    // HT Operation names the secondary below the primary while the VHT
    // Operation's 80 MHz puts it above.
    let mut bad = vht_beacon(ap, 100, 2, &[]);
    let at = bad.len() - 21 - 21;
    bad[at] = 7;
    session.backend.packets.push_back(bad);
    let _ = session.receive_ethernet();
    if session.keys_pending() {
        let _ = run(Box::pin(session.service_keys()));
    }
    if !session.station.peer_lost {
        return Err("inconsistent Beacon operation kept the link");
    }
    Ok(())
}

fn mt7922_station_follows_a_channel_switch_at_the_announced_width() -> TestResult {
    for case in [
        eighty_forty_twenty as fn() -> Result<(), &'static str>,
        twenty_eighty,
        policy_downgrade,
        beacon_disagrees,
    ] {
        if let Err(reason) = case() {
            return TestResult::Fail(reason);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/dfs",
    mt7922_station_follows_a_channel_switch_at_the_announced_width
);
