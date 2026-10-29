//! Recipient BA over the actual native command/control/data/CCMP owner.
use super::*;
use crate::mt7921::association::Security;
const OWN: [u8; 6] = super::amsdu_rx_tests::OWN;
const AP: [u8; 6] = super::amsdu_rx_tests::AP;

fn wrap(frame: &[u8], channel: u8) -> Vec<u8> {
    let mut packet = descriptor(frame);
    packet[4] = 1;
    packet[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
    packet
}
pub(super) fn request_packet(tid: u8, ssn: u16, window: u16, timeout: u16, channel: u8) -> Vec<u8> {
    let mut frame = vec![0; 33];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[24..27].copy_from_slice(&[3, 0, 9]);
    frame[27..29].copy_from_slice(&(2 | u16::from(tid) << 2 | window << 6).to_le_bytes());
    frame[29..31].copy_from_slice(&timeout.to_le_bytes());
    frame[31..33].copy_from_slice(&(ssn << 4).to_le_bytes());
    wrap(&frame, channel)
}
fn bar(tid: u8, ssn: u16) -> Vec<u8> {
    let mut frame = vec![0; 20];
    frame[0] = 0x84;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..18].copy_from_slice(&(4 | u16::from(tid) << 12).to_le_bytes());
    frame[18..20].copy_from_slice(&(ssn << 4).to_le_bytes());
    wrap(&frame, 6)
}
fn delba(tid: u8) -> Vec<u8> {
    let mut frame = vec![0; 30];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[24..26].copy_from_slice(&[3, 2]);
    frame[26..28].copy_from_slice(&(0x0800 | u16::from(tid) << 12).to_le_bytes());
    frame[28..30].copy_from_slice(&39u16.to_le_bytes());
    wrap(&frame, 6)
}
fn data(tid: u8, sequence: u16, pn: Option<u64>, value: u8) -> Vec<u8> {
    data_on(6, tid, sequence, pn, value)
}
pub(super) fn data_on(channel: u8, tid: u8, sequence: u16, pn: Option<u64>, value: u8) -> Vec<u8> {
    let ethernet = super::amsdu_rx_tests::ethernet(value, 3);
    let mut frame = vec![0; 26];
    frame[..2].copy_from_slice(&[0x88, if pn.is_some() { 0x42 } else { 2 }]);
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
    frame[24] = tid;
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    frame.extend_from_slice(&ethernet[12..]);
    let prefix = if pn.is_some() { 40 } else { 24 };
    let mut packet = vec![0; prefix];
    packet[..4].copy_from_slice(&((2u32 << 27) | (prefix + frame.len()) as u32).to_le_bytes());
    let r1: u32 = 1 | if pn.is_some() {
        (4 << 16) | (1 << 11)
    } else {
        0
    };
    packet[4..8].copy_from_slice(&r1.to_le_bytes());
    packet[8..12].copy_from_slice(&(u32::from(tid) << 16).to_le_bytes()); // AMPDU; native TID.
    packet[12..16].copy_from_slice(&(u32::from(channel) << 8).to_le_bytes());
    if let Some(pn) = pn {
        packet[24..30].copy_from_slice(&pn.to_le_bytes()[..6]);
    }
    packet.extend_from_slice(&frame);
    packet
}
fn joined(channel: u8, wide: bool, secured: bool) -> Result<Session<Model>, &'static str> {
    let (mut session, bss) = super::ht20_tests::prepared(channel, secured);
    let permission = if wide {
        super::ht40_tests::permission40(channel, channel + 4)
    } else {
        test_permission_for(channel)
    };
    let security = if secured {
        Security::Wpa2Psk { psk: [0x55; 32] }
    } else {
        Security::Open
    };
    run(session.associate_station(&bss, b"narf", security, permission, &[]))
        .map_err(|_| "recipient BA genuine HT station")?;
    Ok(session)
}
fn establish(
    session: &mut Session<Model>,
    tid: u8,
    ssn: u16,
    timeout: u16,
) -> Result<(), &'static str> {
    establish_window(session, tid, ssn, timeout, 32)
}
pub(super) fn establish_window(
    session: &mut Session<Model>,
    tid: u8,
    ssn: u16,
    timeout: u16,
    window: u16,
) -> Result<(), &'static str> {
    let State::Associated { channel, .. } = session.state else {
        return Err("BA needs current association");
    };
    session
        .backend
        .packets
        .push_back(request_packet(tid, ssn, window, timeout, channel));
    if session.receive_ethernet() != Ok(None)
        || !session.keys_pending()
        || session.rx_ba.active(tid)
    {
        return Err("ADDBA request published premature RX agreement");
    }
    run(session.service_keys()).map_err(|_| "native BA setup receipts/response")?;
    if !session.rx_ba.active(tid) {
        return Err("terminal BA response did not activate recipient");
    }
    Ok(())
}
/// An oversize ADDBA is refused with INVALID_QOS_PARAM (38) and an
/// immediate-policy response, with no WTBL/STA_REC_BA programming.
pub(super) fn decline_oversize(
    session: &mut Session<Model>,
    tid: u8,
    window: u16,
) -> Result<(), &'static str> {
    let State::Associated { channel, .. } = session.state else {
        return Err("oversize ADDBA needs current association");
    };
    session
        .backend
        .packets
        .push_back(request_packet(tid, 10, window, 0, channel));
    consume(session, "declined oversize ADDBA delivered data")?;
    let before = session.backend.frames.len();
    run(session.service_keys()).map_err(|_| "oversize ADDBA decline")?;
    let frames = &session.backend.frames[before..];
    if session.rx_ba.active(tid)
        || frames.len() != 1
        || frames[0].1.get(24..29) != Some(&[3, 1, 9, 38, 0][..])
        || frames[0].1[29] != (2 | tid << 2)
    {
        return Err("oversize ADDBA was not refused with INVALID_QOS_PARAM and no programming");
    }
    Ok(())
}
fn expected(value: u8) -> Option<Vec<u8>> {
    Some(super::amsdu_rx_tests::ethernet(value, 3))
}
fn consume(session: &mut Session<Model>, message: &'static str) -> Result<(), &'static str> {
    if session.receive_ethernet() == Ok(None) {
        Ok(())
    } else {
        Err(message)
    }
}

fn wire() -> Result<(), &'static str> {
    for channel in [6, 36] {
        for wide in [false, true] {
            for secured in [false, true] {
                let mut session = joined(channel, wide, secured)?;
                let start = session.backend.frames.len();
                establish(&mut session, 3, 4094, 0)?;
                let frames = &session.backend.frames[start..];
                // Literal native ABI, not an expected value made by the new encoder.
                let wtbl = [
                    0, 1, 1, 0, 1, 0, 0, 0, 13, 0, 40, 0, 1, 2, 1, 0, 0, 0, 0, 0, 8, 0, 28, 0, 3,
                    2, 0, 0, 0, 0, 0, 0, 32, 0, 2, 1, 2, 3, 4, 5, 3, 0, 1, 0, 0, 0, 0, 0,
                ];
                let station = [
                    0, 1, 1, 0, 1, 0, 0, 0, 6, 0, 12, 0, 3, 2, 0, 8, 254, 15, 32, 0,
                ];
                if frames.len() != 3
                    || frames[0].1.get(48..) != Some(wtbl.as_slice())
                    || frames[1].1.get(48..) != Some(station.as_slice())
                    || frames[2].1.get(24..) != Some(&[3, 1, 9, 0, 0, 14, 8, 0, 0][..])
                {
                    return Err("WTBL recipient/reset/window -> STA BA -> no-nested-AMSDU response native wire/order");
                }
            }
        }
    }
    Ok(())
}
fn mt76_rx_ba_native_recipient_receipts_response_and_ht20_ht40_profiles() -> TestResult {
    wire().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_ba",
    mt76_rx_ba_native_recipient_receipts_response_and_ht20_ht40_profiles
);

fn reorder() -> Result<(), &'static str> {
    for secured in [false, true] {
        let mut session = joined(6, false, secured)?;
        establish(&mut session, 3, 4094, 0)?;
        let pn = |n| secured.then_some(n);
        for (seq, counter, value) in [(4095, 11, 11), (0, 12, 12)] {
            session
                .backend
                .packets
                .push_back(data(3, seq, pn(counter), value));
        }
        if session.receive_ethernet() != Ok(None) {
            return Err("out-of-order BA committed/delivered before head");
        }
        session.backend.packets.push_back(data(3, 4094, pn(10), 10));
        for value in [10, 11, 12] {
            if session.receive_ethernet() != Ok(expected(value)) {
                return Err("12-bit wrap reorder or post-reorder PN order failed");
            }
        }
        let mut wrong_wcid = data(3, 1, pn(13), 90);
        wrong_wcid[4] = 2;
        let mut wrong_tid = data(3, 1, pn(13), 91);
        wrong_tid[10] = 4;
        let mut bad_integrity = data(3, 1, pn(13), 92);
        bad_integrity[7] |= 2;
        for packet in [
            data(3, 4095, pn(11), 94),
            data(3, 4093, pn(99), 95),
            wrong_wcid,
            wrong_tid,
            bad_integrity,
        ] {
            session.backend.packets.push_back(packet);
        }
        for marker in [3, 1] {
            let mut nested = super::amsdu_rx_tests::packet(
                &super::amsdu_rx_tests::ethernet(93, 3),
                secured,
                13,
                marker,
                1,
            );
            nested[4] |= 1;
            nested[8..12].copy_from_slice(&(3u32 << 16).to_le_bytes());
            nested[if secured { 64 } else { 48 }] |= 3;
            session.backend.packets.push_back(nested);
        }
        if session.receive_ethernet() != Ok(None) {
            return Err("replay/old SN/native identity/nested aggregate crossed BA owner");
        }
        session.backend.packets.push_back(data(3, 1, pn(13), 13));
        if session.receive_ethernet() != Ok(expected(13)) {
            return Err("rejected BA packet consumed sequence or pairwise PN");
        }
        // A non-A-MPDU A-MSDU on the same TID remains supported, but its
        // single PN must wait behind the earlier MPDU's sequence number.
        for marker in [3, 1] {
            let mut aggregate = super::amsdu_rx_tests::packet(
                &super::amsdu_rx_tests::ethernet(15, 3),
                secured,
                15,
                marker,
                3,
            );
            aggregate[4] |= 1;
            aggregate[8..12].copy_from_slice(&((1u32 << 30) | (3 << 16)).to_le_bytes());
            aggregate[if secured { 64 } else { 48 }] |= 3;
            session.backend.packets.push_back(aggregate);
        }
        consume(
            &mut session,
            "A-MSDU bypassed its BA TID's sequence/PN owner",
        )?;
        session.backend.packets.push_back(data(3, 2, pn(14), 14));
        for value in [14, 15, 15] {
            if session.receive_ethernet() != Ok(expected(value)) {
                return Err("ordered BA plus ordinary A-MSDU changed atomic PN delivery");
            }
        }
    }
    Ok(())
}
fn mt76_rx_ba_wrap_reorder_peer_tid_integrity_and_replay_are_composed() -> TestResult {
    reorder().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_ba",
    mt76_rx_ba_wrap_reorder_peer_tid_integrity_and_replay_are_composed
);

fn bars_and_timeout() -> Result<(), &'static str> {
    let mut session = joined(6, true, true)?;
    establish(&mut session, 5, 100, 0)?;
    for (seq, pn) in [(102, 12), (104, 14)] {
        session
            .backend
            .packets
            .push_back(data(5, seq, Some(pn), pn as u8));
    }
    if session.receive_ethernet() != Ok(None) {
        return Err("BA gap did not hold MPDUs");
    }
    let mut foreign = bar(5, 102);
    foreign[34] ^= 4;
    session.backend.packets.push_back(foreign);
    if session.receive_ethernet() != Ok(None) {
        return Err("foreign BAR released a current peer window");
    }
    session.backend.packets.push_back(bar(5, 102));
    if session.receive_ethernet() != Ok(expected(12)) {
        return Err("compressed BAR did not release in sequence");
    }
    session
        .backend
        .ticks
        .set(session.backend.ticks.get() + 41_000_000);
    if session.receive_ethernet() != Ok(expected(14)) {
        return Err("source VI reorder-hole timer stranded a frame");
    }
    session
        .backend
        .packets
        .push_back(data(5, 103, Some(13), 13));
    if session.receive_ethernet() != Ok(None) {
        return Err("timeout released PN/SN was replayable");
    }
    session
        .backend
        .packets
        .push_back(data(5, 200, Some(30), 30));
    if session.receive_ethernet() != Ok(None) {
        return Err("far-window jump delivered across a new gap");
    }
    session.backend.packets.push_back(bar(5, 201));
    if session.receive_ethernet() != Ok(expected(30)) {
        return Err("bounded far-window advance/BAR lost packet");
    }
    let mut wrapped = joined(6, false, true)?;
    establish(&mut wrapped, 5, 4000, 0)?;
    wrapped.backend.packets.push_back(data(5, 31, Some(1), 1));
    if wrapped.receive_ethernet() != Ok(None) {
        return Err("wrapped far-window jump bypassed its gap");
    }
    wrapped.backend.packets.push_back(bar(5, 32));
    if wrapped.receive_ethernet() != Ok(expected(1)) {
        return Err("12-bit far-window subtraction did not wrap safely");
    }
    Ok(())
}
fn mt76_rx_ba_compressed_bar_hole_timeout_and_far_window_advance() -> TestResult {
    bars_and_timeout().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_ba",
    mt76_rx_ba_compressed_bar_hole_timeout_and_far_window_advance
);

fn duplicates_and_declines() -> Result<(), &'static str> {
    let mut session = joined(6, false, false)?;
    establish(&mut session, 0, 7, 0)?;
    session.backend.packets.push_back(data(0, 8, None, 8));
    if session.receive_ethernet() != Ok(None) {
        return Err("duplicate agreement gap fixture");
    }
    let before = session.backend.frames.len();
    session
        .backend
        .packets
        .push_back(request_packet(0, 7, 32, 0, 6));
    if session.receive_ethernet() != Ok(None) {
        return Err("repeat ADDBA unexpectedly delivered data");
    }
    run(session.service_keys()).map_err(|_| "repeat ADDBA response")?;
    if session.backend.frames.len() != before + 1 {
        return Err("repeat ADDBA reset native sequence/PN records");
    }
    for _ in 0..8 {
        session
            .backend
            .packets
            .push_back(request_packet(0, 7, 32, 0, 6));
    }
    consume(&mut session, "repeat BA flood unexpectedly delivered data")?;
    if !session.control_pending.is_empty() {
        return Err("response backpressure changed a duplicate accepted agreement into a decline");
    }
    let before = session.backend.frames.len();
    run(session.service_keys()).map_err(|_| "bounded repeated BA response flood")?;
    if session.backend.frames.len() != before + 4 {
        return Err("repeated BA response queue escaped its bound");
    }
    session.backend.packets.push_back(data(0, 7, None, 7));
    for n in [7, 8] {
        if session.receive_ethernet() != Ok(expected(n)) {
            return Err("repeat ADDBA destroyed the original reorder window");
        }
    }
    for case in 0..4 {
        let mut packet = request_packet(if case == 0 { 8 } else { 0 }, 10, 64, 0, 6);
        if case == 1 {
            packet[24 + 27] &= !2;
        } // delayed BA
        if case == 2 {
            packet[24 + 31] |= 1;
        } // fragmented SSN
          // case3 is an incompatible active-TID renegotiation.
        session.backend.packets.push_back(packet);
    }
    if session.receive_ethernet() != Ok(None) || session.control_pending.len() != 4 {
        return Err("unsupported ADDBA was unbounded or admitted");
    }
    run(session.service_keys()).map_err(|_| "bounded unsupported BA responses")?;
    if !session.rx_ba.active(0) || session.rx_ba.active(8) {
        return Err("declines replaced a live TID or fabricated unsupported TID");
    }
    Ok(())
}
fn mt76_rx_ba_duplicate_admission_preserves_window_and_unsupported_requests_decline() -> TestResult
{
    duplicates_and_declines().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_ba",
    mt76_rx_ba_duplicate_admission_preserves_window_and_unsupported_requests_decline
);

fn arbitrary_windows() -> Result<(), &'static str> {
    for secured in [false, true] {
        for requested in [0, 1, 3, 5, 31, 33, 48, 63, 64, 65, 127] {
            if requested > 64 {
                // agg-rx.c:351: a non-HE peer's buf_size above
                // IEEE80211_MAX_AMPDU_BUF_HT is declined, never clamped.
                let mut session = joined(6, false, secured)?;
                decline_oversize(&mut session, 3, requested)?;
                run(session.disassociate_station())
                    .map_err(|_| "oversize ADDBA native teardown")?;
                continue;
            }
            let window = if requested == 0 { 64 } else { requested };
            let mut session = joined(6, false, secured)?;
            let before = session.backend.frames.len();
            establish_window(&mut session, 3, 4090, 0, requested)?;
            let frames = &session.backend.frames[before..];
            if frames.len() != 3
                || frames[0].1.get(80..82) != Some(window.to_le_bytes().as_slice())
                || frames[1].1.get(66..68) != Some(window.to_le_bytes().as_slice())
            {
                return Err("native recipient window was rounded or not written to both records");
            }
            if window == 64 && frames[2].1.get(24..) != Some(&[3, 1, 9, 0, 0, 14, 16, 0, 0][..])
                || window == 3 && frames[2].1.get(24..) != Some(&[3, 1, 9, 0, 0, 206, 0, 0, 0][..])
            {
                return Err("literal64/non-power-of-two ADDBA response");
            }
            // Fill every non-head position in reverse order across the
            // native12-bit wrap. Distinct SNs must never alias a slot even
            // when the window does not divide4096.
            // This is a sub-millisecond burst, not63 separate millisecond
            // scheduling intervals that legitimately expire the100ms hole.
            session.backend.tick_step_ns = 1_000;
            for offset in (1..window).rev() {
                session.backend.packets.push_back(data(
                    3,
                    (4090 + offset) & 4095,
                    secured.then_some(100 + u64::from(offset)),
                    offset as u8,
                ));
                consume(&mut session, "arbitrary window bypassed its actual SSN gap")?;
            }
            session
                .backend
                .packets
                .push_back(data(3, 4090, secured.then_some(100), 0));
            for value in 0..window {
                if session.receive_ethernet() != Ok(expected(value as u8)) {
                    return Err(
                        "arbitrary window SN-wrap reorder/PN lost or misordered a native packet",
                    );
                }
            }
            session
                .backend
                .packets
                .push_back(data(3, 4090, secured.then_some(100), 0));
            consume(
                &mut session,
                "arbitrary window admitted replay after full release",
            )?;
            session.backend.tick_step_ns = 1_000_000;
            run(session.disassociate_station())
                .map_err(|_| "arbitrary RX window native teardown")?;
        }
    }
    Ok(())
}
fn mt76_rx_ba_exact_windows_one_through64_reorder_across_sequence_wrap() -> TestResult {
    arbitrary_windows().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_ba",
    mt76_rx_ba_exact_windows_one_through64_reorder_across_sequence_wrap
);

fn establish_nested(session: &mut Session<Model>, ssn: u16) -> Result<(), &'static str> {
    let before = session.backend.frames.len();
    let mut request = request_packet(3, ssn, 64, 0, 6);
    request[51] |= 1; // Genuine ADDBA A-MSDU support, not an inferred HT bit.
    session.backend.packets.push_back(request);
    consume(session, "nested agreement initial capture")?;
    run(session.service_keys()).map_err(|_| "nested WTBL/STA/response native receipts")?;
    let frames = &session.backend.frames[before..];
    let station = [
        0,
        1,
        1,
        0,
        1,
        0,
        0,
        0,
        6,
        0,
        12,
        0,
        3,
        2,
        1,
        8,
        (ssn & 255) as u8,
        (ssn >> 8) as u8,
        64,
        0,
    ];
    if frames.len() != 3
        || frames[1].1.get(48..) != Some(station.as_slice())
        || frames[2].1.get(24..) != Some(&[3, 1, 9, 0, 0, 15, 16, 0, 0][..])
        || !session.rx_ba.amsdu(3)
    {
        return Err("nested permission absent from actual STA_REC_BA/ADDBA receipt");
    }
    Ok(())
}
fn nested_piece(secured: bool, pn: u64, seq: u16, marker: u8, value: u8) -> Vec<u8> {
    let mut packet = super::amsdu_rx_tests::packet(
        &super::amsdu_rx_tests::ethernet(value, 3),
        secured,
        pn,
        marker,
        seq,
    );
    packet[4] |= 1;
    packet[8..12].copy_from_slice(&(3u32 << 16).to_le_bytes()); // AMPDU, native TID3.
    packet[if secured { 64 } else { 48 }] = 0xe3; // Original A-MSDU/BlockAck/TID3.
    packet
}
fn nested() -> Result<(), &'static str> {
    for secured in [false, true] {
        let mut session = joined(6, false, secured)?;
        establish_nested(&mut session, 4094)?;
        for (marker, value) in [(3, 12), (1, 13)] {
            session
                .backend
                .packets
                .push_back(nested_piece(secured, 12, 0, marker, value));
        }
        consume(
            &mut session,
            "nested complete future MPDU bypassed the negotiated SSN",
        )?;
        session
            .backend
            .packets
            .push_back(data(3, 4095, secured.then_some(11), 11));
        consume(&mut session, "ordinary future MPDU bypassed nested BA gap")?;
        session
            .backend
            .packets
            .push_back(nested_piece(secured, 10, 4094, 3, 9));
        consume(
            &mut session,
            "nested prefix was published before complete native MPDU",
        )?;
        session
            .backend
            .packets
            .push_back(nested_piece(secured, 10, 4094, 1, 10));
        for value in [9, 10, 11, 12, 13] {
            if session.receive_ethernet() != Ok(expected(value)) {
                return Err("nested/ordinary MPDUs lost SN order across wrap or split one PN");
            }
        }
        if secured && session.security.as_ref().unwrap().pairwise[3] != 12 {
            return Err("nested aggregate committed more than one PN per original MPDU");
        }
        for (marker, value) in [(3, 12), (1, 13)] {
            session
                .backend
                .packets
                .push_back(nested_piece(secured, 12, 0, marker, value));
        }
        consume(&mut session, "nested original replay was admitted")?;
        run(session.disassociate_station()).map_err(|_| "nested native retirement")?;
    }
    Ok(())
}
fn mt76_rx_ba_negotiated_nested_amsdu_uses_native_flag_whole_mpdu_and_one_post_reorder_pn(
) -> TestResult {
    nested().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_ba",
    mt76_rx_ba_negotiated_nested_amsdu_uses_native_flag_whole_mpdu_and_one_post_reorder_pn
);

fn nested_failures() -> Result<(), &'static str> {
    for case in 0..7 {
        let mut session = joined(6, false, true)?;
        establish_nested(&mut session, 0)?;
        let first = nested_piece(true, 9, 0, 3, 1);
        session.backend.packets.push_back(first);
        consume(&mut session, "nested bad suffix prefix publication")?;
        let mut last = nested_piece(true, 9, 0, 1, 2);
        match case {
            0 => last[4] = 2,  // Wrong native WCID.
            1 => last[10] = 4, // Native/header TID mismatch.
            2 => last[8..12].copy_from_slice(&((1u32 << 30) | (3 << 16)).to_le_bytes()),
            3 => last[7] |= 2, // Integrity error before native assembly.
            4 => last[88..90].copy_from_slice(&[0x88, 0x8e]), // EAPOL subframe.
            5 => {
                let mut ethernet = super::amsdu_rx_tests::ethernet(2, 5);
                ethernet[12..14].copy_from_slice(&[0x81, 0]);
                ethernet[14..18].copy_from_slice(&[0, 1, 0x88, 0x8e]);
                last = super::amsdu_rx_tests::packet(&ethernet, true, 9, 1, 0);
                last[4] |= 1;
                last[8..12].copy_from_slice(&(3u32 << 16).to_le_bytes());
                last[64] = 0xe3;
            }
            _ => {
                last.pop();
            }
        }
        session.backend.packets.push_back(last);
        consume(
            &mut session,
            "bad nested native suffix exposed an authenticated prefix",
        )?;
        if session.security.as_ref().unwrap().pairwise[3] != 0 {
            return Err("bad nested native suffix committed a replay PN");
        }
        for (marker, value) in [(3, 3), (1, 4)] {
            session
                .backend
                .packets
                .push_back(nested_piece(true, 9, 0, marker, value));
        }
        for value in [3, 4] {
            if session.receive_ethernet() != Ok(expected(value)) {
                return Err("bad nested suffix consumed valid same-PN/SN retry");
            }
        }
    }
    Ok(())
}
fn mt76_rx_ba_nested_native_metadata_bad_tail_and_control_subframe_are_atomic() -> TestResult {
    nested_failures().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_ba",
    mt76_rx_ba_nested_native_metadata_bad_tail_and_control_subframe_are_atomic
);

fn retirement() -> Result<(), &'static str> {
    for timeout in [false, true] {
        let mut session = joined(6, false, true)?;
        establish(&mut session, 0, 1, if timeout { 20 } else { 0 })?;
        session.backend.packets.push_back(data(0, 2, Some(2), 2));
        if session.receive_ethernet() != Ok(None) {
            return Err("retirement pending data fixture");
        }
        if timeout {
            session
                .backend
                .ticks
                .set(session.backend.ticks.get() + 21_000_000);
        } else {
            session.backend.packets.push_back(delba(0));
        }
        if session.receive_ethernet() != Ok(None)
            || session.rx_ba.active(0)
            || !session.keys_pending()
        {
            return Err("DELBA/inactivity did not close host RX before native waits");
        }
        let before = session.backend.frames.len();
        run(session.service_keys()).map_err(|_| "native BA stop receipts")?;
        let f = &session.backend.frames[before..];
        if f.len() != if timeout { 3 } else { 2 }
            || f[0].1.get(80..82) != Some(&[0, 0][..])
            || f[1].1.get(63) != Some(&0)
            || !session.rx_ba.records().is_empty()
        {
            return Err("BA native disable/reset/recipient DELBA order");
        }
        session.backend.packets.push_back(data(0, 1, Some(1), 1));
        if session.receive_ethernet() != Ok(None) {
            return Err("retired BA accepted unsolicited A-MPDU");
        }
    }
    Ok(())
}
fn mt76_rx_ba_delba_and_inactivity_retire_both_native_records() -> TestResult {
    retirement().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_ba",
    mt76_rx_ba_delba_and_inactivity_retire_both_native_records
);

fn rekey() -> Result<(), &'static str> {
    let mut session = joined(6, true, true)?;
    establish(&mut session, 0, 1, 0)?;
    session.backend.packets.push_back(data(0, 2, Some(99), 99));
    if session.receive_ethernet() != Ok(None) {
        return Err("old-key buffered BA packet fixture");
    }
    // The native adapter owns the authentic EAPOL rekey conversation; the
    // shared legacy FakeAp does not generate rekeys in its Authorized phase.
    session.backend.access_point = None;
    session.backend.psk = [0x55; 32];
    session.backend.own_mac = OWN;
    session.backend.ap_mac = AP;
    session.backend.anonce = [0x55; 32];
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x55; 32];
    session
        .backend
        .packets
        .push_back(descriptor(&ap_eapol_frame(OWN, AP, &m1.into_eapol())));
    if session.receive_ethernet() != Ok(None) || !session.keys_pending() {
        return Err("BA rekey EAPOL capture");
    }
    let before = session.backend.frames.len();
    run(session.service_keys()).map_err(|_| "BA retirement before rekey M2")?;
    if session.rx_ba.owns(0) {
        return Err("old key's BA owner crossed rekey M2");
    }
    if session.receive_ethernet() != Ok(None) || !session.keys_pending() {
        return Err("native authenticated rekey M3 capture");
    }
    run(session.service_keys()).map_err(|_| "native rekey key receipts")?;
    let frames = &session.backend.frames[before..];
    let wtbl_disabled = frames
        .iter()
        .position(|(_, f)| {
            f.len() == 96
                && f[34..36] == [3, 0]
                && f[49] == 1
                && f[56..60] == [13, 0, 40, 0]
                && f[68..72] == [8, 0, 28, 0]
                && f[80..82] == [0, 0]
        })
        .ok_or("WTBL BA disable before rekey missing")?;
    let disabled = frames
        .iter()
        .position(|(_, f)| f.len() == 68 && f[56..60] == [6, 0, 12, 0] && f[63] == 0)
        .ok_or("BA disable before rekey missing")?;
    let key = frames
        .iter()
        .position(|(_, f)| {
            f.len() == 100
                && f[34..36] == [3, 0]
                && f[48..68]
                    == [
                        0, 1, 1, 0, 1, 0, 0, 0, 17, 0, 44, 0, 0, 1, 0, 0, 5, 36, 0, 16,
                    ]
        })
        .ok_or("native PTK publication missing")?;
    if wtbl_disabled >= disabled || disabled >= key {
        return Err("new PTK preceded terminal receive BA retirement");
    }
    // M3 repeats the installed GTK (id1, 0x77); a PTK rekey must not
    // reinstall that group key and reset its packet-number replay window.
    if frames.iter().any(|(_, f)| {
        f.len() == 100
            && f[34..36] == [3, 0]
            && f[49] == 19
            && f[56..64] == [17, 0, 44, 0, 0, 1, 0, 0]
    }) {
        return Err("unchanged GTK was reinstalled during PTK rekey");
    }
    establish(&mut session, 0, 50, 0)?;
    session.backend.packets.push_back(data(0, 51, Some(2), 2));
    session.backend.packets.push_back(data(0, 50, Some(1), 1));
    for n in [1, 2] {
        if session.receive_ethernet() != Ok(expected(n)) {
            return Err("new key epoch inherited old buffered PN/window");
        }
    }
    session
        .backend
        .ticks
        .set(session.backend.ticks.get() + 101_000_000);
    if session.receive_ethernet() != Ok(None) {
        return Err("old key packet survived into replacement BA window");
    }
    run(session.recover(OWN)).map_err(|_| "verified BA reset")?;
    if !session.rx_ba.records().is_empty() || !matches!(session.state, State::RadioReady(_)) {
        return Err("verified reset retained old BA records");
    }
    Ok(())
}
fn mt76_rx_ba_rekey_receipts_fence_old_windows_before_ptk_and_reset() -> TestResult {
    rekey().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_ba",
    mt76_rx_ba_rekey_receipts_fence_old_windows_before_ptk_and_reset
);

fn failure() -> Result<(), &'static str> {
    for tag in [13, 6] {
        let mut session = joined(6, false, false)?;
        session.backend.ba_error_tag = Some(tag);
        session
            .backend
            .packets
            .push_back(request_packet(0, 1, 64, 0, 6));
        consume(&mut session, "BA error fixture")?;
        let before = session.backend.frames.len();
        if run(session.service_keys()).is_ok()
            || session.rx_ba.active(0)
            || !matches!(session.state, State::Failed { .. })
            || !session.backend.owner.published
            || session.backend.frames[before..]
                .iter()
                .any(|(_, f)| f.first() == Some(&0xd0))
        {
            return Err("rejected native BA receipt activated/replied or released DMA");
        }
    }
    for publication in 0..=3 {
        let mut session = joined(6, false, false)?;
        session
            .backend
            .packets
            .push_back(request_packet(0, 1, 64, 0, 6));
        consume(&mut session, "BA policy fixture")?;
        session.backend.deny_tx_after = Some(session.backend.frames.len() + publication);
        if run(session.service_keys()) != Err(Error::Authority)
            || session.rx_ba.active(0)
            || !matches!(session.state, State::Failed { .. })
            || !session.backend.owner.published
        {
            return Err("native BA publication/response reused current-policy denial");
        }
    }
    Ok(())
}
fn mt76_rx_ba_rejected_receipts_and_each_current_policy_boundary_fail_closed() -> TestResult {
    failure().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_ba",
    mt76_rx_ba_rejected_receipts_and_each_current_policy_boundary_fail_closed
);

fn cancelled() -> Result<(), &'static str> {
    for boundary in 1..=3 {
        let mut session = joined(6, false, false)?;
        session
            .backend
            .packets
            .push_back(request_packet(0, 1, 64, 0, 6));
        consume(&mut session, "BA cancel fixture")?;
        let before = session.backend.frames.len();
        if boundary < 3 {
            session.backend.tx_stall_after = Some(before + boundary);
        } else {
            session.backend.management_stall_after = Some(before + 3);
        }
        {
            let mut future = pin!(session.service_keys());
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return Err("BA native receipt/response did not suspend for cancellation");
            }
        }
        if session.rx_ba.active(0)
            || !session.rx_ba.owns(0)
            || !matches!(session.state, State::Running(_))
            || session.receive_ethernet() != Err(Error::Busy)
            || !session.backend.owner.published
        {
            return Err(
                "cancelled setup restored a producer or lost uncertain native BA/DMA ownership",
            );
        }
    }
    let mut session = joined(6, false, true)?;
    establish(&mut session, 0, 1, 0)?;
    session.backend.packets.push_back(data(0, 2, Some(2), 2));
    consume(&mut session, "BA teardown cancel packet")?;
    session.backend.tx_stall_after = Some(session.backend.frames.len() + 1);
    {
        let mut future = pin!(session.disassociate_station());
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return Err("BA teardown did not suspend at disable receipt");
        }
    }
    if session.rx_ba.active(0)
        || !session.rx_ba.owns(0)
        || session.station_permission.is_some()
        || session.security.is_some()
        || session.receive_ethernet() != Err(Error::Busy)
        || !session.backend.owner.published
    {
        return Err("cancelled BA teardown retained host authorization or freed live mappings");
    }
    let mut rekey = joined(6, true, true)?;
    establish(&mut rekey, 0, 1, 0)?;
    rekey.backend.packets.push_back(data(0, 2, Some(99), 99));
    consume(&mut rekey, "BA key cancellation packet fixture")?;
    let mut m1 = narf_wireless::eapol::KeyFrame::empty(16);
    m1.key_information = 2 | (1 << 3) | (1 << 7);
    m1.key_length = 16;
    m1.replay_counter = 7;
    m1.key_nonce = [0x55; 32];
    rekey
        .backend
        .packets
        .push_back(descriptor(&ap_eapol_frame(OWN, AP, &m1.into_eapol())));
    consume(&mut rekey, "BA key cancellation EAPOL fixture")?;
    rekey.backend.tx_stall_after = Some(rekey.backend.frames.len() + 1);
    {
        let mut future = pin!(rekey.service_keys());
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return Err("BA key retirement did not suspend at native receipt");
        }
    }
    if rekey.rx_ba.active(0)
        || !rekey.rx_ba.owns(0)
        || rekey.security.is_some()
        || rekey.receive_ethernet() != Err(Error::Busy)
        || !rekey.backend.owner.published
    {
        return Err("cancelled key transition revived queued BA/PN ownership or freed DMA");
    }
    Ok(())
}
fn mt76_rx_ba_setup_response_and_teardown_cancel_retain_native_ownership() -> TestResult {
    cancelled().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_ba",
    mt76_rx_ba_setup_response_and_teardown_cancel_retain_native_ownership
);

/// Set IEEE80211_HT_CAP_DELAY_BA in every HT Capabilities element.
fn with_delayed_ba(elements: &mut [u8]) {
    let mut offset = 0;
    while offset + 2 <= elements.len() {
        let length = usize::from(elements[offset + 1]);
        if elements[offset] == 45 && length >= 2 {
            elements[offset + 3] |= 0x04;
        }
        offset += 2 + length;
    }
}

fn delayed() -> Result<(), &'static str> {
    // agg-rx.c requires HT DELAY_BA *and* the S1G HT_DELAYED_BA capability
    // for a delayed policy; a non-S1G peer is refused with INVALID_QOS_PARAM
    // and an immediate-policy response even when it advertises DELAY_BA.
    for advertise in [false, true] {
        let (mut session, mut bss) = super::ht20_tests::prepared(6, false);
        if advertise {
            with_delayed_ba(&mut bss.information_elements);
            if let Some(reply) = session.backend.ht_reply.as_mut() {
                with_delayed_ba(reply);
            }
        }
        run(session.associate_station(&bss, b"narf", Security::Open, test_permission_for(6), &[]))
            .map_err(|_| "delayed-BA HT station")?;
        let mut packet = request_packet(2, 10, 32, 0, 6);
        packet[24 + 27] &= !2;
        session.backend.packets.push_back(packet);
        consume(&mut session, "declined delayed ADDBA delivered data")?;
        let before = session.backend.frames.len();
        run(session.service_keys()).map_err(|_| "delayed ADDBA decline")?;
        let frames = &session.backend.frames[before..];
        if session.rx_ba.active(2)
            || frames.len() != 1
            || frames[0].1.get(24..29) != Some(&[3, 1, 9, 38, 0][..])
            || frames[0].1[29] != (2 | 2 << 2)
        {
            return Err("delayed ADDBA was not refused with INVALID_QOS_PARAM/immediate policy");
        }
    }
    Ok(())
}
fn mt76_rx_ba_delayed_policy_is_refused_invalid_qos_for_non_s1g_peer() -> TestResult {
    delayed().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/rx_ba",
    mt76_rx_ba_delayed_policy_is_refused_invalid_qos_for_non_s1g_peer
);
