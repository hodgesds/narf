//! GET_STATION facts from the live station receive path.
use super::*;
use alloc::boxed::Box;

/// `frame` as a CONNAC2 RX packet carrying RXD group 3 (P-RXV DW0 + the
/// RCPI word).
fn with_prxv(frame: &[u8], prxv: u32, rcpi: u32) -> Vec<u8> {
    let mut packet = super::descriptor(frame);
    let group: Vec<u8> = prxv
        .to_le_bytes()
        .into_iter()
        .chain(rcpi.to_le_bytes())
        .collect();
    packet.splice(24..24, group);
    let r0 = u32::from_le_bytes(packet[..4].try_into().unwrap());
    let r0 = (r0 & !0xffff) | packet.len() as u32;
    packet[..4].copy_from_slice(&r0.to_le_bytes());
    let r1 = u32::from_le_bytes(packet[4..8].try_into().unwrap()) | 1 << 13;
    packet[4..8].copy_from_slice(&r1.to_le_bytes());
    packet
}

/// An associated MT7922 station records the AP's Beacon signal from its
/// P-RXV RCPI (strongest chain as SIGNAL, both chains, the EWMA), hands it
/// out with every packet step, ignores another transmitter's frame, and
/// starts over with the next association.
fn mt7922_station_records_the_aps_signal_for_get_station() -> TestResult {
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
    if joined != Ok(42) || session.station.link_stats.signal_dbm.is_some() {
        return TestResult::Fail("association, or statistics before any frame");
    }
    let beacon = session.backend.access_point.as_ref().unwrap().beacon();
    // OFDM 6 Mb/s; RCPI 130 = -45 dBm on chain 0, 120 = -50 dBm on chain 1.
    let ofdm6 = 1 << 24 | 11;
    session
        .backend
        .packets
        .push_back(with_prxv(&beacon, ofdm6, 130 | 120 << 8));
    if session.receive_ethernet().is_err() {
        return TestResult::Fail("Beacon with P-RXV ended the link");
    }
    let stats = session.station.link_stats;
    if stats.signal_dbm != Some(-45)
        || stats.chain_signal_dbm != [Some(-45), Some(-50)]
        || stats.signal_avg_dbm() != Some(-45)
        || stats.rx_rate.is_some()
    {
        return TestResult::Fail("AP Beacon signal not recorded as mac80211 does");
    }
    // A frame from another transmitter does not count.
    let mut other = beacon.clone();
    other[10..16].copy_from_slice(&[2, 9, 9, 9, 9, 9]);
    other[16..22].copy_from_slice(&[2, 9, 9, 9, 9, 9]);
    session
        .backend
        .packets
        .push_back(with_prxv(&other, ofdm6, 200));
    let _ = session.receive_ethernet();
    if session.station.link_stats != stats {
        return TestResult::Fail("another transmitter's frame changed the AP statistics");
    }
    match session.step_network(None) {
        Ok(step) if step.link == Some(stats) => {}
        _ => return TestResult::Fail("packet step does not carry the link statistics"),
    }
    // A new association starts from no samples.
    if run(Box::pin(session.disassociate_station())).is_err() {
        return TestResult::Fail("teardown");
    }
    let (mut session, bss) = super::pmf_tests::prepared(super::pmf_tests::pmf_ap());
    let _ = run(Box::pin(session.associate_station(
        &bss,
        b"narf",
        crate::mt7921::association::Security::Wpa2PskPmf {
            psk: [0x55; 32],
            required: false,
        },
        test_permission(),
        &[],
    )));
    if session.station.link_stats != Default::default() {
        return TestResult::Fail("statistics survived into a new association");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/station",
    mt7922_station_records_the_aps_signal_for_get_station
);

/// NL80211_CMD_SET_POWER_SAVE on an associated MT7922 station: the owner
/// sends mt7921_mcu_uni_bss_ps (BSS_INFO_UPDATE, UNI_BSS_INFO_PS, dynamic
/// power save = 2) once, then the awake state (0) when it is turned off,
/// and a new association starts awake so the setting is applied again.
fn mt7922_power_save_follows_set_power_save_on_the_associated_bss() -> TestResult {
    let associate = || {
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
        (session, joined)
    };
    let (mut session, joined) = associate();
    if joined != Ok(42) || session.keys_pending() {
        return TestResult::Fail("association, or control work without a request");
    }
    let body = |enabled| super::join::bss_power_save(0, enabled);
    let sent = |session: &Session<Model>, from: usize, enabled: bool| {
        session.backend.frames[from..]
            .iter()
            .filter(|(_, frame)| frame.ends_with(&body(enabled)))
            .count()
    };
    for enabled in [true, false] {
        session.station.ps_wanted = enabled;
        if !session.keys_pending() {
            return TestResult::Fail("power-save change not scheduled as control work");
        }
        let before = session.backend.frames.len();
        if run(Box::pin(session.service_keys())).is_err()
            || sent(&session, before, enabled) != 1
            || session.station.ps_applied != enabled
            || session.keys_pending()
        {
            return TestResult::Fail("UNI_BSS_INFO_PS not sent exactly once");
        }
    }
    if body(true) != [0, 0, 0, 0, 21, 0, 8, 0, 2, 0, 0, 0] {
        return TestResult::Fail("UNI_BSS_INFO_PS layout");
    }
    let (mut session, _) = associate();
    session.station.ps_wanted = true;
    if session.station.ps_applied || !session.keys_pending() {
        return TestResult::Fail("a new association did not start awake");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/power",
    mt7922_power_save_follows_set_power_save_on_the_associated_bss
);

fn domain_2g(country: &[u8; 2], power: i8) -> narf_wireless::reg::RegulatoryDomain {
    narf_wireless::reg::RegulatoryDomain {
        country_code: *country,
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: power,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    }
}

/// cfg80211's `reg_notifier` reaching an associated MT7922 station: a new
/// country with a lower 2.4 GHz ceiling re-admits the same BSS, programs
/// the channel domain and power limits again and keeps the link; the same
/// rules reinstalled are no change; a policy without the operating
/// channel ends the link.
fn mt7922_regulatory_change_reprograms_or_leaves_the_channel() -> TestResult {
    let policy = Arc::new(CurrentPolicy {
        database: narf_wireless::reg::db::Database::new(),
        hold_bss_ack: core::sync::atomic::AtomicBool::new(false),
    });
    policy.database.install(domain_2g(b"US", 17));
    let (mut session, bss) = super::pmf_tests::prepared(super::pmf_tests::pmf_ap());
    session.backend.tx_policy = Some(policy.clone());
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
    if joined != Ok(42) || session.keys_pending() {
        return TestResult::Fail("association, or control work before a policy change");
    }
    // Identical rules reinstalled: no change.
    policy.database.install(domain_2g(b"US", 17));
    if session.keys_pending() {
        return TestResult::Fail("reinstalled identical policy scheduled a refresh");
    }
    let sku = |session: &Session<Model>, from: usize| {
        session.backend.frames[from..]
            .iter()
            .filter(|(_, f)| f.get(36) == Some(&0x5d))
            .count()
    };
    policy.database.install(domain_2g(b"DE", 14));
    if !session.keys_pending() {
        return TestResult::Fail("policy change not scheduled");
    }
    let before = session.backend.frames.len();
    if run(Box::pin(session.service_keys())).is_err()
        || sku(&session, before) != 1
        || !matches!(session.state, State::Associated { .. })
        || session
            .station
            .permission
            .is_none_or(|p| p.power_dbm != 14 || p.country != *b"DE")
        || session.keys_pending()
    {
        return TestResult::Fail("new country not re-programmed with the link kept");
    }
    // A policy without 2.4 GHz: the operating channel is no longer allowed.
    let mut five = domain_2g(b"JP", 20);
    five.rules[0].freq_start_mhz = 5170;
    five.rules[0].freq_end_mhz = 5330;
    policy.database.install(five);
    let _ = run(Box::pin(session.service_keys()));
    if matches!(session.state, State::Associated { .. }) && session.station.permission.is_some() {
        return TestResult::Fail("station kept a channel the new policy forbids");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/regulatory",
    mt7922_regulatory_change_reprograms_or_leaves_the_channel
);
