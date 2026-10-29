//! Real negotiated HT20 control/packet ownership over the production Session.
use super::*;
use crate::mt7921::association::Security;

pub(super) fn elements(channel: u8) -> Vec<u8> {
    let mut ht = [0; 26];
    ht[0] = 0x77; // AP SGI20, dynamic SMPS, LDPC, greenfield and40.
    ht[2] = 30; // AP RX factor2/density7, not an active BA agreement.
    ht[3] = 0xff;
    ht[4] = 0xff; // Actual two-stream AP; native NIC facts bound the local offer.
    let mut operation = [0; 22];
    operation[0] = channel;
    operation[1] = 5; // AP permits40MHz; station still selects primary20MHz.
    operation[6] = 0xff;
    let mut bytes = vec![45, 26];
    bytes.extend_from_slice(&ht);
    bytes.extend_from_slice(&[61, 22]);
    bytes.extend_from_slice(&operation);
    bytes
}

pub(super) fn prepared(channel: u8, secured: bool) -> (Session<Model>, ScanBss) {
    let (mut session, mut bss) = super::wmm_tests::prepared(true, secured);
    session.backend.station_channel = channel;
    session.backend.ht_reply = Some(elements(channel));
    bss.channel = channel;
    // The shared AP owns MLME/RSNA; the native adapter supplies the target
    // band/channel and its HT elements, without changing peer/security facts.
    let mut offset = 0;
    while offset < bss.information_elements.len() {
        let length = usize::from(bss.information_elements[offset + 1]);
        if bss.information_elements[offset] == 3 {
            bss.information_elements[offset + 2] = channel;
        }
        offset += 2 + length;
    }
    bss.information_elements
        .extend_from_slice(&elements(channel));
    (session, bss)
}
fn security(secured: bool) -> Security {
    if secured {
        Security::Wpa2Psk { psk: [0x55; 32] }
    } else {
        Security::Open
    }
}
fn join(session: &mut Session<Model>, bss: &ScanBss, secured: bool) -> Result<u16, Error> {
    run(session.associate_station(
        bss,
        b"narf",
        security(secured),
        test_permission_for(bss.channel),
        &[],
    ))
}

fn mt76_ht20_native_peer_rlm_rates_and_bound_association() -> TestResult {
    for channel in [6, 36] {
        for secured in [false, true] {
            let (mut session, bss) = prepared(channel, secured);
            if join(&mut session, &bss, secured) != Ok(42)
                || session.ht20_profile.is_none()
                || session
                    .ht20_rx
                    .as_ref()
                    .is_none_or(|receiver| !receiver.active)
                || !matches!(session.state, State::Associated { .. })
            {
                return TestResult::Fail(
                    "genuine HT20 association did not activate the bounded receiver",
                );
            }
            let frames = &session.backend.frames;
            let request = frames.iter().find(|(_, frame)| {
                frame.first() == Some(&0)
                    && frame.get(10..16) == Some(super::amsdu_rx_tests::OWN.as_slice())
            });
            let mut expected = [0; 26];
            // LDPC, SMPS disabled, greenfield, SGI20 and (two TX streams,
            // mt76_init_stream_cap) TX_STBC.
            expected[0] = 61 | 128;
            expected[1] = 1;
            expected[2] = 28;
            expected[3] = 255;
            expected[4] = 255;
            expected[15] = 1;
            if request.is_none_or(|(_, frame)| {
                !frame
                    .windows(28)
                    .any(|ie| ie[..2] == [45, 26] && ie[2..] == expected)
            }) {
                return TestResult::Fail(
                    "HT20 request advertised unsupported width/LDPC/NSS or lost SGI20",
                );
            }
            let peer = frames.iter().find(|(_, frame)| {
                frame.len() >= 196
                    && frame[34..36] == [3, 0]
                    && frame[43] == 7
                    && frame[49] == 1
                    && frame[65] == 1
            });
            let Some((_, peer)) = peer else {
                return TestResult::Fail("HT20 native associated peer missing");
            };
            if peer[82] != if channel <= 14 { 19 } else { 24 }
                || peer[83] != 30
                || peer[94..104] != [255, 255, 0, 0, 0, 0, 0, 0, 0, 0]
                || peer[118..124] != [72, 0, 1, 1, 5, 0]
                || peer[168..180] != [2, 0, 12, 0, 1, 1, 2, 7, 0, 0, 0, 0]
                || peer[180..188] != [13, 0, 8, 0, 1, 0, 0, 0]
                || peer[188..196] != [9, 0, 8, 0, 53, 0, 0, 0]
            {
                return TestResult::Fail(
                    "HT/PHY/RA/WTBL/SMPS native fields or stream intersection",
                );
            }
            let rlm = frames.iter().find(|(_, frame)| {
                frame.len() == 68
                    && frame[34..36] == [2, 0]
                    && frame[43] == 7
                    && frame[52..56] == [2, 0, 16, 0]
            });
            if rlm.is_none_or(|(_, frame)| {
                frame[56..]
                    != [
                        channel,
                        channel,
                        0,
                        0,
                        2,
                        3,
                        1,
                        0,
                        0,
                        u8::from(channel > 14),
                        0,
                        0,
                    ]
            }) {
                return TestResult::Fail("HT20 native BSS RLM width/streams/band");
            }
            if run(session.disassociate_station()).is_err()
                || session.ht20_profile.is_some()
                || session.ht20_rx.is_some()
                || session.station_permission.is_some()
            {
                return TestResult::Fail("HT20 teardown retained negotiated PHY/receive/grant");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht20",
    mt76_ht20_native_peer_rlm_rates_and_bound_association
);

fn mt76_ht20_sgi_intersects_bound_response_without_changing_width_or_smps() -> TestResult {
    for channel in [6, 36] {
        for scan_sgi in [false, true] {
            for response_sgi in [false, true] {
                let (mut session, mut bss) = prepared(channel, true);
                let mut offset = 0;
                while offset < bss.information_elements.len() {
                    if bss.information_elements[offset] == 45 {
                        bss.information_elements[offset + 2] &= !32;
                        bss.information_elements[offset + 2] |= u8::from(scan_sgi) << 5;
                    }
                    offset += 2 + usize::from(bss.information_elements[offset + 1]);
                }
                let reply = session.backend.ht_reply.as_mut().unwrap();
                reply[2] &= !32;
                reply[2] |= u8::from(response_sgi) << 5;
                if join(&mut session, &bss, true) != Ok(42)
                    || session
                        .ht20_profile
                        .is_none_or(|p| p.short_gi() != (scan_sgi && response_sgi))
                {
                    return TestResult::Fail(
                        "SGI20 used a stale scan capability instead of the bound AP response",
                    );
                }
                let peer = session.backend.frames.iter().find(|(_, p)| {
                    p.len() >= 196 && p[34..36] == [3, 0] && p[43] == 7 && p[65] == 1
                });
                if peer.is_none_or(|(_, p)| {
                    p[188..196]
                        != [
                            9,
                            0,
                            8,
                            0,
                            if scan_sgi && response_sgi { 53 } else { 21 },
                            0,
                            0,
                            0,
                        ]
                        || p[180..188] != [13, 0, 8, 0, 1, 0, 0, 0]
                        || p[122] != 5
                }) {
                    return TestResult::Fail(
                        "SGI20 lost dynamic SMPS or invented CONNAC1 raw WTBL fields",
                    );
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht20",
    mt76_ht20_sgi_intersects_bound_response_without_changing_width_or_smps
);

fn mt76_ht20_amsdu_receive_and_unsolicited_ampdu_never_consume_pn() -> TestResult {
    for secured in [false, true] {
        let (mut session, bss) = prepared(6, secured);
        if join(&mut session, &bss, secured) != Ok(42) {
            return TestResult::Fail("HT20 RX join");
        }
        let first = super::amsdu_rx_tests::ethernet(1, 5);
        let second = super::amsdu_rx_tests::ethernet(2, 7);
        for (eth, marker) in [(&first, 3), (&second, 1)] {
            session
                .backend
                .packets
                .push_back(super::amsdu_rx_tests::packet(eth, secured, 1, marker, 7));
        }
        if session.receive_ethernet() != Ok(Some(first))
            || session.receive_ethernet() != Ok(Some(second))
        {
            return TestResult::Fail(
                "negotiated HT20 hardware-deaggregated A-MSDU did not compose",
            );
        }
        let valid = if secured {
            ccmp_packet(2, 0, false)
        } else {
            native_data_packet(true)
        };
        let mut aggregate = valid.clone();
        aggregate[8..12].copy_from_slice(&0u32.to_le_bytes());
        session.backend.packets.push_back(aggregate);
        if session.receive_ethernet() != Ok(None) {
            return TestResult::Fail("unsolicited HT A-MPDU bypassed absent BA/reorder owner");
        }
        session.backend.packets.push_back(valid);
        if session.receive_ethernet().ok().flatten().is_none() {
            return TestResult::Fail("rejected A-MPDU consumed the ordinary frame's PN");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht20",
    mt76_ht20_amsdu_receive_and_unsolicited_ampdu_never_consume_pn
);

fn mt76_ht20_ap_downgrade_and_unsupported_mcs_fail_before_peer_activation() -> TestResult {
    for case in 0..4 {
        let (mut session, mut bss) = prepared(6, false);
        let before = session.backend.frames.len();
        match case {
            0 => session.backend.ht_reply = None,
            1 => session.backend.ht_reply.as_mut().unwrap()[3] |= 8, // reserved AP SMPS2/3 mutation below
            2 => {
                let index = bss.information_elements.len() - 22 + 8;
                bss.information_elements[index] = 1;
            }
            _ => {
                let index = bss.information_elements.len() - 22;
                bss.information_elements[index] = 36;
            }
        }
        if case == 1 {
            session.backend.ht_reply.as_mut().unwrap()[2] = 8;
        }
        if join(&mut session, &bss, false).is_ok()
            || session.ht20_profile.is_some()
            || session
                .ht20_rx
                .as_ref()
                .is_some_and(|receiver| receiver.active)
            || case >= 2 && session.backend.frames.len() != before
        {
            return TestResult::Fail(
                "downgraded/malformed HT AP activated a peer or wrote preflight state",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht20",
    mt76_ht20_ap_downgrade_and_unsupported_mcs_fail_before_peer_activation
);

fn mt76_ht20_rlm_policy_and_cancellation_leave_no_active_receiver() -> TestResult {
    let (mut baseline, bss) = prepared(6, false);
    if join(&mut baseline, &bss, false) != Ok(42) {
        return TestResult::Fail("HT20 RLM baseline");
    }
    let rlm = baseline
        .backend
        .frames
        .iter()
        .position(|(_, frame)| {
            frame.len() == 68
                && frame[34..36] == [2, 0]
                && frame[43] == 7
                && frame[52..56] == [2, 0, 16, 0]
        })
        .unwrap();
    for cancel in [false, true] {
        let (mut session, bss) = prepared(6, false);
        if cancel {
            session.backend.tx_stall_after = Some(rlm + 1);
            {
                let mut future = pin!(session.associate_station(
                    &bss,
                    b"narf",
                    Security::Open,
                    test_permission(),
                    &[]
                ));
                if future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("HT20 RLM did not suspend at native DMA");
                }
            }
        } else {
            session.backend.deny_tx_after = Some(rlm + 1);
            if join(&mut session, &bss, false) != Err(Error::Authority) {
                return TestResult::Fail("HT20 RLM receipt reused a revoked grant");
            }
        }
        if session.ht20_profile.is_some()
            || session
                .ht20_rx
                .as_ref()
                .is_some_and(|receiver| receiver.active)
            || !session.backend.owner.published
            || matches!(session.state, State::Associated { .. })
        {
            return TestResult::Fail(
                "failed/cancelled HT20 RLM activated RX or released uncertain DMA",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht20",
    mt76_ht20_rlm_policy_and_cancellation_leave_no_active_receiver
);

fn addba() -> Vec<u8> {
    let mut frame = vec![0; 33];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&super::amsdu_rx_tests::OWN);
    frame[10..16].copy_from_slice(&super::amsdu_rx_tests::AP);
    frame[16..22].copy_from_slice(&super::amsdu_rx_tests::AP);
    frame[24..].copy_from_slice(&[3, 0, 9, 0x0d, 0x10, 0, 0, 0, 0]); // Unsupported delayed BA.
    let mut packet = descriptor(&frame);
    packet[4] = 1; // Real native AP WCID, distinct from frame-address binding.
    packet
}

fn mt76_ht20_addba_is_bound_bounded_and_explicitly_declined_without_ba_state() -> TestResult {
    let (mut session, bss) = prepared(6, true);
    if join(&mut session, &bss, true) != Ok(42) {
        return TestResult::Fail("HT ADDBA setup");
    }
    let packet = addba();
    for (offset, value) in [(24 + 4, 4), (24 + 10, 4), (24 + 22, 1)] {
        let mut foreign = packet.clone();
        foreign[offset] = value;
        session.backend.packets.push_back(foreign);
    }
    if session.receive_ethernet() != Ok(None) || session.keys_pending() {
        return TestResult::Fail("foreign/fragmented ADDBA queued a reply");
    }
    for _ in 0..8 {
        session.backend.packets.push_back(packet.clone());
    }
    if session.receive_ethernet() != Ok(None) || session.control_pending.len() != 4 {
        return TestResult::Fail("ADDBA refusal queue was not bounded");
    }
    let before = session.backend.frames.len();
    if run(session.service_keys()).is_err()
        || session.keys_pending()
        || session.backend.frames.len() != before + 4
        || !matches!(session.state, State::Associated { .. })
    {
        return TestResult::Fail(
            "retained ADDBA management completion did not preserve the current station",
        );
    }
    for (_, frame) in &session.backend.frames[before..] {
        if frame.len() != 33 || frame[0] != 0xd0 || frame[24..] != [3, 1, 9, 38, 0, 14, 0, 0, 0] {
            return TestResult::Fail(
                "ADDBA response enabled BA/AMSDU or changed dialog/TID/status",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht20",
    mt76_ht20_addba_is_bound_bounded_and_explicitly_declined_without_ba_state
);

fn mt76_ht20_addba_refusal_current_authority_and_cancel_retains_owner() -> TestResult {
    for cancel in [false, true] {
        let (mut session, bss) = prepared(6, false);
        if join(&mut session, &bss, false) != Ok(42) {
            return TestResult::Fail("HT ADDBA ownership setup");
        }
        session.backend.packets.push_back(addba());
        if session.receive_ethernet() != Ok(None) || !session.keys_pending() {
            return TestResult::Fail("bound ADDBA did not schedule retained control work");
        }
        let before = session.backend.frames.len();
        if cancel {
            session.backend.tx_stall = true;
            {
                let mut future = pin!(session.service_keys());
                if future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("ADDBA decline did not await native completion");
                }
            }
        } else {
            session.backend.deny_tx_after = Some(before);
            if run(session.service_keys()) != Err(Error::Authority)
                || session.backend.frames.len() != before
            {
                return TestResult::Fail("ADDBA decline used revoked TX permission");
            }
        }
        if matches!(session.state, State::Associated { .. })
            || !session.backend.owner.published
            || session.start_ethernet(&[0; 14]) != Err(Error::Busy)
        {
            return TestResult::Fail(
                "cancelled/denied ADDBA control work authorized packets or freed DMA",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/ht20",
    mt76_ht20_addba_refusal_current_authority_and_cancel_retains_owner
);
