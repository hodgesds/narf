//! Current AP contention updates through the production native control owner.
use super::*;
use crate::mt7921::association::{wmm::Parameters, Security};

const OWN: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];

fn joined(secured: bool) -> (Session<Model>, ScanBss) {
    let (mut session, bss) = wmm_tests::prepared(true, secured);
    let security = if secured {
        Security::Wpa2Psk { psk: [0x55; 32] }
    } else {
        Security::Open
    };
    assert_eq!(
        run(session.associate_station(&bss, b"narf", security, test_permission(), &[])),
        Ok(42)
    );
    (session, bss)
}

fn ethernet() -> Vec<u8> {
    let mut frame = vec![0; 60];
    frame[..6].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    frame[6..12].copy_from_slice(&OWN);
    frame[12..14].copy_from_slice(&[8, 0]);
    frame
}

pub(super) fn updated(count: u8) -> [u8; 26] {
    let mut parameters = wmm_tests::PARAMETERS;
    parameters[8] = 0x80 | count;
    parameters[14] = 7; // BE AIFSN7, CWmin63, CWmax2047.
    parameters[15] = 0xb6;
    parameters
}

pub(super) fn beacon(session: &Session<Model>, bss: &ScanBss, parameters: &[u8]) -> Vec<u8> {
    let mut frame = session.backend.access_point.as_ref().unwrap().beacon();
    frame.truncate(36);
    let mut ies = bss.information_elements.as_slice();
    while !ies.is_empty() {
        let end = 2 + usize::from(ies[1]);
        if ies[0] != 221 || !ies[2..end].starts_with(&[0, 0x50, 0xf2, 2]) {
            frame.extend_from_slice(&ies[..end]);
        }
        ies = &ies[end..];
    }
    frame.extend_from_slice(parameters);
    let mut packet = vec![0; 24];
    packet[..4].copy_from_slice(&((2u32 << 27) | (24 + frame.len()) as u32).to_le_bytes());
    packet[12..16].copy_from_slice(&(u32::from(bss.channel) << 8).to_le_bytes());
    packet.extend_from_slice(&frame);
    packet
}

fn command(frame: &[u8], id: u8) -> bool {
    frame.len() >= 64 && frame[36] == id && frame[37] == 0xa0
}

fn mt76_dynamic_wmm_open_wpa2_drain_and_native_progress_preserve_port() -> TestResult {
    for secured in [false, true] {
        let (mut session, bss) = joined(secured);
        let epoch = session.receive_epoch;
        let old = session.wmm;
        if secured {
            for tid in [0, 3] {
                let mut packet = ccmp_packet(41, 0, false);
                packet[64] = tid;
                session.backend.packets.push_back(packet);
                if session.receive_ethernet().unwrap().is_none() {
                    return TestResult::Fail(
                        "WMM update replay fixture did not receive actual CCMP DATA",
                    );
                }
            }
        }
        session.backend.tx_stall = true;
        session.start_ethernet(&ethernet()).unwrap();
        let before = session.backend.frames.len();
        let parameters = updated(2);
        let packet = beacon(&session, &bss, &parameters);
        session.backend.packets.push_back(packet);
        if session.receive_ethernet() != Ok(None)
            || session.wmm != old
            || session.wmm_pending != Parameters::parse(&parameters).unwrap()
            || session.peer_lost
            || session.start_ethernet(&ethernet()) != Err(Error::Busy)
            || run(session.service_keys()).is_err()
            || session.backend.frames.len() != before
        {
            return TestResult::Fail("AP update changed EDCA before submitted DATA retired");
        }
        session.backend.tx_stall = false;
        if session.poll_data_tx() != Ok(false)
            || !session.data_pending.is_empty()
            || !session.keys_pending()
            || run(session.service_keys()).is_err()
        {
            return TestResult::Fail("AP update did not advance through the drained control owner");
        }
        let commands = &session.backend.frames[before..];
        // Literal native BE row: CWmin63, CWmax2047, TXOP0, AIFS7,
        // guardtime0, ACM0; SET_EDCA has no invented acceptance reply.
        if commands.len() != 2
            || !command(&commands[0].1, 0x1d)
            || commands[0].1[64..74] != [63, 0, 255, 7, 0, 0, 7, 0, 0, 0]
            || commands[0].1[104..108] != [0, 1, 0, 0]
            || !command(&commands[1].1, 0xc0)
            || commands[1].1[64..72] != [0, 0x80, 0x0c, 0x82, 0, 0, 0, 0]
            || session.wmm_pending.is_some()
            || session.wmm != Parameters::parse(&parameters).unwrap()
            || session.receive_epoch != epoch
            || session.receive_current(epoch) != Ok(true)
            || session.start_ethernet(&ethernet()).is_err()
        {
            return TestResult::Fail("AP update lost native EDCA/PSE order, QoS or port epoch");
        }
        session.poll_data_tx().unwrap();
        if secured {
            for tid in [0, 3] {
                for pn in [41, 42] {
                    let mut packet = ccmp_packet(pn, 0, false);
                    packet[64] = tid;
                    session.backend.packets.push_back(packet);
                    if session.receive_ethernet().unwrap().is_some() != (pn == 42) {
                        return TestResult::Fail(
                            "WMM update changed a key or per-TID replay floor",
                        );
                    }
                }
            }
        }
        run(session.disassociate_station()).unwrap();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_dynamic_wmm_open_wpa2_drain_and_native_progress_preserve_port
);

fn mt76_dynamic_wmm_counter_wrap_coalescing_and_exact_repeats() -> TestResult {
    let (mut session, bss) = joined(false);
    for count in [15, 0, 0, 1] {
        let before = session.backend.frames.len();
        let parameters = updated(count);
        let expected = Parameters::parse(&parameters).unwrap();
        let changed = session.wmm != expected;
        let packet = beacon(&session, &bss, &parameters);
        session.backend.packets.push_back(packet);
        session.receive_ethernet().unwrap();
        run(session.service_keys()).unwrap();
        if session.wmm != expected
            || session.backend.frames.len() != before + if changed { 2 } else { 0 }
        {
            return TestResult::Fail(
                "four-bit WMM counter wrap/repetition changed native ownership",
            );
        }
    }
    let before = session.backend.frames.len();
    for count in [2, 3, 4] {
        let packet = beacon(&session, &bss, &updated(count));
        session.backend.packets.push_back(packet);
    }
    session.receive_ethernet().unwrap();
    run(session.service_keys()).unwrap();
    if session.backend.frames.len() != before + 2
        || session.wmm != Parameters::parse(&updated(4)).unwrap()
    {
        return TestResult::Fail("bounded WMM update did not retain the latest complete AP set");
    }
    run(session.disassociate_station()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_dynamic_wmm_counter_wrap_coalescing_and_exact_repeats
);

fn mt76_dynamic_wmm_cancelled_dma_and_progress_retain_closed_owner() -> TestResult {
    for at_progress in [false, true] {
        let (mut session, bss) = joined(true);
        let packet = beacon(&session, &bss, &updated(2));
        session.backend.packets.push_back(packet);
        session.receive_ethernet().unwrap();
        let old = session.wmm;
        let epoch = session.receive_epoch;
        session.backend.stall_edca = !at_progress;
        session.backend.rx_stall = at_progress;
        {
            let mut future = pin!(session.service_keys());
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("WMM cancellation did not reach actual native wait");
            }
        }
        if session.state != State::Running(Stage::StaRecord)
            || session.wmm != old
            || session.wmm_pending.is_none()
            || session.receive_current(epoch) != Ok(false)
            || session.start_ethernet(&ethernet()) != Err(Error::Busy)
            || !session.backend.owner.published
            || run(session.disassociate_station()) != Err(Error::Busy)
        {
            return TestResult::Fail("cancelled WMM command reopened or released its native owner");
        }
        let resources = session.backend.resources.clone();
        drop(session);
        if resources.load(Ordering::SeqCst) != 1 {
            return TestResult::Fail("cancelled WMM command freed published device resources");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_dynamic_wmm_cancelled_dma_and_progress_retain_closed_owner
);

fn mt76_dynamic_wmm_policy_loss_and_malformed_native_progress_fail_closed() -> TestResult {
    for fault in 0..6 {
        let (mut session, bss) = joined(false);
        let packet = beacon(&session, &bss, &updated(2));
        session.backend.packets.push_back(packet);
        session.receive_ethernet().unwrap();
        let before = session.backend.frames.len();
        if fault < 3 {
            session.backend.deny_tx_after = Some(before + fault);
        } else {
            session.backend.edca_progress_fault = (fault - 2) as u8;
        }
        if run(session.service_keys()).is_ok()
            || !matches!(session.state, State::Failed { .. })
            || session.wmm.is_some()
            || session.wmm_pending.is_some()
            || session.station_permission.is_some()
            || session.receive_current(session.receive_epoch) != Ok(false)
            || session.start_ethernet(&ethernet()) != Err(Error::Busy)
            || fault < 3 && session.backend.frames.len() != before + fault
        {
            return TestResult::Fail(
                "WMM native progress or changed grant published an active peer",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_dynamic_wmm_policy_loss_and_malformed_native_progress_fail_closed
);

fn mt76_dynamic_wmm_foreign_and_legacy_beacons_never_grant_qos() -> TestResult {
    let (mut session, bss) = joined(false);
    let mut foreign = beacon(&session, &bss, &updated(2));
    foreign[24 + 10] ^= 4;
    session.backend.packets.push_back(foreign);
    let mut wrong_channel = beacon(&session, &bss, &updated(2));
    wrong_channel[13] = 11;
    session.backend.packets.push_back(wrong_channel);
    session.receive_ethernet().unwrap();
    if session.wmm_pending.is_some() || session.peer_lost {
        return TestResult::Fail("foreign AP/channel scheduled a native contention update");
    }
    run(session.disassociate_station()).unwrap();
    let (mut session, bss) = wmm_tests::prepared(false, false);
    run(session.associate_station(&bss, b"narf", Security::Open, test_permission(), &[])).unwrap();
    let before = session.backend.frames.len();
    let packet = beacon(&session, &bss, &updated(2));
    session.backend.packets.push_back(packet);
    session.receive_ethernet().unwrap();
    run(session.service_keys()).unwrap();
    if session.wmm.is_some()
        || session.wmm_pending.is_some()
        || session.backend.frames.len() != before
    {
        return TestResult::Fail("unsolicited beacon promoted a legacy peer to WMM");
    }
    run(session.disassociate_station()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_dynamic_wmm_foreign_and_legacy_beacons_never_grant_qos
);

fn mt76_dynamic_wmm_rekey_runs_before_pending_contention_update() -> TestResult {
    let (mut session, bss) = joined(true);
    let packet = beacon(&session, &bss, &updated(2));
    session.backend.packets.push_back(packet);
    session.receive_ethernet().unwrap();
    // Replace the single-dialog reactive AP with the existing native M2/M3
    // adapter. The request, candidate PTK, MIC and key receipts remain real.
    session.backend.access_point = None;
    session.backend.psk = [0x55; 32];
    session.backend.own_mac = OWN;
    session.backend.ap_mac = [2, 1, 2, 3, 4, 5];
    session.backend.anonce = [0x55; 32];
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x55; 32];
    session
        .backend
        .packets
        .push_back(descriptor(&ap_eapol_frame(
            OWN,
            [2, 1, 2, 3, 4, 5],
            &m1.into_eapol(),
        )));
    session.receive_ethernet().unwrap();
    let before = session.backend.frames.len();
    run(session.service_keys()).unwrap();
    if session.wmm_pending.is_none()
        || session.backend.frames[before..]
            .iter()
            .any(|(_, frame)| command(frame, 0x1d))
        || session.receive_current(session.receive_epoch) != Ok(false)
    {
        return TestResult::Fail("pending contention update bypassed the actual replacement M2");
    }
    session.receive_ethernet().unwrap();
    run(session.service_keys()).unwrap();
    if session.wmm_pending.is_none()
        || session.backend.frames[before..]
            .iter()
            .any(|(_, frame)| command(frame, 0x1d))
        || session.receive_current(session.receive_epoch) != Ok(true)
        || session.start_ethernet(&ethernet()) != Err(Error::Busy)
    {
        return TestResult::Fail("replacement key receipts lost the pending native EDCA barrier");
    }
    run(session.service_keys()).unwrap();
    if session.wmm_pending.is_some()
        || session.backend.frames[before..]
            .iter()
            .filter(|(_, frame)| command(frame, 0x1d))
            .count()
            != 1
        || run(session.send_ethernet(&ethernet())).is_err()
    {
        return TestResult::Fail("completed rekey did not unblock the retained EDCA owner");
    }
    run(session.disassociate_station()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/wmm",
    mt76_dynamic_wmm_rekey_runs_before_pending_contention_update
);
