//! Actual retained MCU/descriptor owners: passive capture is never station RX.
use super::*;
use alloc::boxed::Box;
use narf_wireless::monitor::Channel;

fn policy() -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![
            RegRule {
                freq_start_mhz: 2402,
                freq_end_mhz: 2472,
                max_bandwidth_mhz: 40,
                max_power_dbm: 17,
                flags: RegFlags::NO_IR,
            },
            RegRule {
                freq_start_mhz: 5170,
                freq_end_mhz: 5895,
                max_bandwidth_mhz: 160,
                max_power_dbm: 17,
                flags: RegFlags::NO_IR | RegFlags::DFS,
            },
            RegRule {
                freq_start_mhz: 5945,
                freq_end_mhz: 7125,
                max_bandwidth_mhz: 160,
                max_power_dbm: 17,
                flags: RegFlags::NO_IR,
            },
        ],
    }
}
fn idle() -> Result<Session<Model>, &'static str> {
    let mut session = Session::new(Model::new(), firmware(32));
    run(session.run()).map_err(|_| "monitor firmware boot")?;
    run(session.initialize_radio()).map_err(|_| "monitor radio identity/calibration")?;
    Ok(session)
}
fn channel(frequency_mhz: u32) -> Channel {
    Channel {
        frequency_mhz,
        width: 0,
        center1_mhz: frequency_mhz,
        center2_mhz: 0,
    }
}
fn capture_packet(id: u8, protected: bool, groups: bool) -> (Vec<u8>, Vec<u8>) {
    let mut frame = if protected { vec![0; 44] } else { vec![0; 10] };
    frame[..2].copy_from_slice(&if protected { 0xc388u16 } else { 0x00d4u16 }.to_le_bytes());
    for (index, byte) in frame.iter_mut().enumerate().skip(2) {
        *byte = index as u8;
    }
    if protected {
        frame[22] = 0;
        frame[30] = 0;
    }
    let offset = 24 + if groups { 16 + 8 + 72 + 4 } else { 0 };
    let mut packet = vec![0; offset + frame.len()];
    let len = packet.len() as u32;
    packet[..4].copy_from_slice(&(len | 2 << 27).to_le_bytes());
    packet[12..16].copy_from_slice(&(u32::from(id) << 8).to_le_bytes());
    if groups {
        let r1 = (1 << 11) | (1 << 13) | (1 << 15) | if protected { 4 << 16 | 1 << 23 } else { 0 };
        packet[4..8].copy_from_slice(&(r1 as u32).to_le_bytes());
        packet[8..12].copy_from_slice(&(2u32 << 14).to_le_bytes());
        // P-RXV group3 followed by group5 C-RXV: actual per-chain RCPI.
        packet[48 + 24..48 + 28].copy_from_slice(&[136, 138, 0, 0]);
    }
    packet[offset..].copy_from_slice(&frame);
    (packet, frame)
}
fn native_monitor() -> Result<(), &'static str> {
    let mut session = idle()?;
    let info = match session.state {
        State::RadioReady(info) => info,
        _ => return Err("monitor radio state"),
    };
    let old_epoch = session.receive_epoch;
    let before = session.backend.frames.len();
    session
        .backend
        .packets
        .push_back(capture_packet(6, false, false).0);
    run(session.start_monitor_with_policy(channel(5180), || Ok(policy())))
        .map_err(|_| "native monitor start")?;
    if session.state
        != (State::Monitor {
            info,
            channel: channel(5180),
        })
        || session.receive_epoch == old_epoch
        || session.backend.receive_open
        || session.security.is_some()
        || session.receive_current(session.receive_epoch) != Ok(false)
        || !session.backend.packets.is_empty()
    {
        return Err("monitor borrowed station admission or stale pre-start frames");
    }
    let frames = &session.backend.frames[before..];
    let uni: Vec<_> = frames
        .iter()
        .filter(|(_, frame)| frame[43] == 7)
        .map(|(_, frame)| frame)
        .collect();
    if uni.len() != 4
        || uni[0][34..36] != [1, 0]
        || uni[1][34..36] != [2, 0]
        || uni[1][60..64] != [2, 0, 1, 0]
        || uni[2][34..36] != [0x24, 0]
        || uni[2][48..] != [0, 0, 0, 0, 0, 0, 8, 0, 1, 0, 0, 0]
        || uni[3][48..]
            != [
                0, 0, 0, 0, 1, 0, 16, 0, 0, 0, 2, 0, 36, 0, 36, 0, 1, 0, 0, 0,
            ]
    {
        return Err("monitor DEV/AP-type passive BSS/sniffer wire mismatch");
    }
    let filter = frames
        .iter()
        .find(|(_, frame)| frame[36] == 0x0a)
        .ok_or("monitor RX filter command")?;
    if filter.1[64..].len() != 68 || filter.1[68] != 1 || filter.1[72..76] != [0x60, 0, 0, 0x80] {
        return Err("monitor OTHER_BSS/CONTROL filter wire mismatch");
    }
    let (raw, original) = capture_packet(36, true, true);
    session.backend.packets.push_back(raw.clone());
    let (ack, original_ack) = capture_packet(36, false, false);
    session.backend.packets.push_back(ack);
    let mut invalid = raw.clone();
    invalid[4..8]
        .copy_from_slice(&((4u32 << 16) | (1 << 11) | (1 << 13) | (1 << 15)).to_le_bytes());
    session.backend.packets.push_back(invalid); // stripped native decryption
    let mut invalid = raw.clone();
    invalid[8] |= 0x00;
    invalid[9] |= 0x20;
    session.backend.packets.push_back(invalid); // HDR_TRANS
    let mut invalid = raw.clone();
    invalid[4..8].copy_from_slice(&(1u32 << 15).to_le_bytes());
    session.backend.packets.push_back(invalid); // group5 without group3
    let mut invalid = raw;
    invalid[0] = 30;
    invalid[1] = 0;
    session.backend.packets.push_back(invalid); // truncated group
    session
        .backend
        .packets
        .push_back(capture_packet(6, false, false).0); // genuine off-channel frame, not mislabeled
    let report = session
        .step_monitor(&policy())
        .map_err(|_| "native monitor bounded receive")?;
    if report.frames.len() != 2
        || report.ignored != 5
        || report.frames[0][..15] != [0, 0, 15, 0, 0x2a, 0, 0, 0, 4, 0, 0x3c, 0x14, 0, 1, 215]
        || report.frames[0][15..] != original
        || report.frames[1][..14] != [0, 0, 14, 0, 0x0a, 0, 0, 0, 0, 0, 0x3c, 0x14, 0, 1]
        || report.frames[1][14..] != original_ack
    {
        return Err("monitor fabricated metadata or changed raw MPDU/ciphertext");
    }
    if run(session.send_ethernet(&[0; 60])).is_ok()
        || session.receive_ethernet() != Err(Error::Busy)
    {
        return Err("monitor admitted station traffic/injection");
    }
    let before = session.backend.frames.len();
    run(session.stop_monitor()).map_err(|_| "native sniffer stop")?;
    let frames = &session.backend.frames[before..];
    if session.state != State::RadioReady(info)
        || frames[0].1[48..] != [0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0]
        || session.backend.receive_open
    {
        return Err("monitor stop did not retire sniffer/capture");
    }
    Ok(())
}
fn mt76_monitor_native_sniffer_receipts_and_exact_radiotap_ciphertext() -> TestResult {
    native_monitor().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/monitor",
    mt76_monitor_native_sniffer_receipts_and_exact_radiotap_ciphertext
);

fn lifecycle() -> Result<(), &'static str> {
    let mut session = idle()?;
    let State::RadioReady(info) = session.state else {
        return Err("monitor info");
    };
    for bad in [
        Channel {
            width: 3,
            center1_mhz: 5190,
            ..channel(5180)
        },
        Channel {
            center2_mhz: 5300,
            ..channel(5180)
        },
        channel(5001),
        Channel {
            width: 2,
            center1_mhz: 2467,
            ..channel(2462)
        },
    ] {
        let before = session.backend.frames.len();
        if run(session.start_monitor_with_policy(bad, || Ok(policy()))).is_ok()
            || session.backend.frames.len() != before
            || session.state != State::RadioReady(info)
        {
            return Err("invalid monitor geometry performed native writes");
        }
    }
    let no_policy = narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![],
    };
    let before = session.backend.frames.len();
    if run(session.start_monitor_with_policy(channel(5180), || Ok(no_policy.clone())))
        != Err(Error::Authority)
        || session.backend.frames.len() != before
    {
        return Err("missing receive policy wrote sniffer commands");
    }
    run(session.start_monitor_with_policy(channel(5180), || Ok(policy())))
        .map_err(|_| "monitor start before revoke")?;
    session
        .backend
        .packets
        .push_back(capture_packet(36, true, true).0);
    if session.step_monitor(&no_policy) != Err(Error::Authority)
        || !matches!(session.state, State::Failed { .. })
        || session.backend.packets.is_empty()
    {
        return Err("revoked monitor returned queued raw data");
    }
    let mut session = idle()?;
    session.backend.tx_stall_after = Some(session.backend.frames.len() + 1);
    let mut future = Box::pin(session.start_monitor_with_policy(channel(5180), || Ok(policy())));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..10 {
        if future.as_mut().poll(&mut cx).is_ready() {
            return Err("monitor cancellation fixture completed held native TX");
        }
    }
    drop(future);
    if session.state != State::Running(Stage::MonitorStart)
        || !session.backend.owner.published
        || session.step_monitor(&policy()) != Err(Error::Busy)
        || session.receive_ethernet() != Err(Error::Busy)
    {
        return Err("cancelled monitor released native owner or published traffic");
    }
    Ok(())
}
fn mt76_monitor_geometry_policy_and_cancelled_native_owner_stay_closed() -> TestResult {
    lifecycle().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/monitor",
    mt76_monitor_geometry_policy_and_cancelled_native_owner_stay_closed
);

fn station_monitor_station() -> Result<(), &'static str> {
    use crate::mt7921::association::Security;
    let (mut session, bss) = super::ht20_tests::prepared(6, true);
    run(Box::pin(session.associate_station(
        &bss,
        b"narf",
        Security::Wpa2Psk { psk: [0x55; 32] },
        test_permission(),
        &[],
    )))
    .map_err(|_| "secured station before monitor")?;
    let station_epoch = session.receive_epoch;
    session.backend.tx_ba_offer = Some((64, 0));
    if run(session.negotiate_transmit_ba_tid(0)) != Ok(true) {
        return Err("station BA before monitor");
    }
    session
        .backend
        .packets
        .push_back(super::rx_ba_tests::request_packet(1, 10, 32, 0, 6));
    session
        .receive_ethernet()
        .map_err(|_| "recipient BA before monitor")?;
    run(session.service_keys()).map_err(|_| "recipient native BA before monitor")?;
    session
        .backend
        .packets
        .push_back(super::rx_ba_tests::data_on(6, 1, 11, Some(9), 0x61));
    if session.receive_ethernet() != Ok(None) || !session.rx_ba.active(1) {
        return Err("station reorder queue before role change");
    }
    let mut outbound = vec![0x6f; 60];
    outbound[..6].copy_from_slice(&super::amsdu_rx_tests::AP);
    outbound[6..12].copy_from_slice(&super::amsdu_rx_tests::OWN);
    outbound[12..14].copy_from_slice(&[8, 0]);
    session.backend.tx_stall = true;
    session
        .start_ethernet(&outbound)
        .map_err(|_| "queued native station TX before role change")?;
    if session.data_pending.is_empty() {
        return Err("pending station TX fixture");
    }
    session.backend.tx_stall = false;
    let before = session.backend.frames.len();
    run(Box::pin(session.disassociate_station()))
        .map_err(|_| "station down native queue/key/BA retirement")?;
    if session.security.is_some()
        || session.tx_ba.published()
        || session.tx_ba.remote()
        || !session.rx_ba.records().is_empty()
        || !session.data_pending.is_empty()
        || !session.received_msdu.is_empty()
        || session.backend.receive_open
        || session.backend.tx_ba_native_tids != 0
    {
        return Err("station down left reusable key/BA/queue ownership");
    }
    let disabled_keys: Vec<_> = session.backend.frames[before..]
        .iter()
        .filter(|(_, f)| {
            f.get(34..36) == Some(&[3, 0]) && f.get(56..64) == Some(&[17, 0, 8, 0, 1, 0, 0, 0])
        })
        .collect();
    if disabled_keys.len() != 2 {
        return Err("station down omitted native PTK/GTK disable receipts");
    }
    // Original copy-time station admission survives in the descriptor copy,
    // but the monitor generation must drain it rather than publish it.
    session.backend.captured_packets.push_back(CapturedData {
        bytes: super::rx_ba_tests::data_on(6, 0, 20, Some(10), 0x71),
        epoch: station_epoch,
        port_open: true,
    });
    run(Box::pin(
        session.start_monitor_with_policy(channel(5180), || Ok(policy())),
    ))
    .map_err(|_| "station-to-monitor native lifecycle")?;
    if session.receive_current(station_epoch) != Ok(false)
        || !session.backend.captured_packets.is_empty()
    {
        return Err("monitor reused station copy epoch/queued data");
    }
    session
        .backend
        .packets
        .push_back(capture_packet(36, true, true).0);
    if session
        .step_monitor(&policy())
        .map_err(|_| "monitor after station")?
        .frames
        .len()
        != 1
    {
        return Err("native capture after actual station down");
    }
    run(Box::pin(session.stop_monitor())).map_err(|_| "monitor-to-station native stop")?;
    // Reset only the external AP fixture, just as reconnecting talks to a
    // fresh peer handshake; the retained device/session is not replaced.
    let (mut peer_fixture, _) = super::ht20_tests::prepared(6, true);
    session.backend.access_point = peer_fixture.backend.access_point.take();
    session.backend.ht_reply = peer_fixture.backend.ht_reply.take();
    run(Box::pin(session.associate_station(
        &bss,
        b"narf",
        Security::Wpa2Psk { psk: [0x55; 32] },
        test_permission(),
        &[],
    )))
    .map_err(|_| "fresh secured station after monitor stop")?;
    if session.receive_epoch == station_epoch
        || session.receive_current(station_epoch) != Ok(false)
        || session.receive_current(session.receive_epoch) != Ok(true)
        || session.tx_ba.active()
        || !session.rx_ba.records().is_empty()
    {
        return Err("station rejoin reused prior monitor/station grants");
    }
    Ok(())
}
fn mt76_secured_station_down_monitor_down_station_retires_keys_ba_and_queues() -> TestResult {
    station_monitor_station().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/monitor",
    mt76_secured_station_down_monitor_down_station_retires_keys_ba_and_queues
);
