// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

const OWN: [u8; 6] = [2, 4, 6, 8, 10, 12];
const PEER: [u8; 6] = [2, 0, 0, 0, 0, 1];

fn action(body: &[u8]) -> Vec<u8> {
    let mut frame = alloc::vec![0xd0, 0, 0, 0];
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&PEER);
    frame.extend_from_slice(&PEER);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(body);
    frame
}

fn smoke_rtw89_block_ack_addba_delba_bar_codecs() -> TestResult {
    // ADDBA Request: token9, A-MSDU|immediate|TID5|buf32, timeout 500TU, SSN 4000.
    let capab: u16 = 1 | 1 << 1 | 5 << 2 | 32 << 6;
    let mut body = alloc::vec![3, 0, 9];
    body.extend_from_slice(&capab.to_le_bytes());
    body.extend_from_slice(&500u16.to_le_bytes());
    body.extend_from_slice(&(4000u16 << 4).to_le_bytes());
    let request = Request {
        token: 9,
        amsdu: true,
        policy: 1,
        tid: 5,
        buf_size: 32,
        timeout: 500,
        ssn: 4000,
    };
    if parse_action(&action(&body), OWN, PEER) != Some(Action::AddbaRequest(request)) {
        return TestResult::Fail("ADDBA request decode differs");
    }
    // Wrong RA, wrong TA, protected bit or a non-BA category are not ours.
    let mut wrong = action(&body);
    wrong[4] ^= 1;
    let mut spoof = action(&body);
    spoof[10] ^= 1;
    let mut protected = action(&body);
    protected[1] |= 0x40;
    let mut other = action(&body);
    other[24] = 4;
    if [wrong, spoof, protected, other]
        .iter()
        .any(|frame| parse_action(frame, OWN, PEER).is_some())
    {
        return TestResult::Fail("foreign or protected action accepted");
    }
    if parse_action(&action(&[3, 0, 9, 1]), OWN, PEER).is_some() {
        return TestResult::Fail("truncated ADDBA accepted");
    }
    // DELBA: TID3, initiator, reason 39.
    let delba_body = [3u8, 2, 0x00, 0x38, 39, 0];
    if parse_action(&action(&delba_body), OWN, PEER)
        != Some(Action::Delba {
            tid: 3,
            initiator: true,
            reason: 39,
        })
    {
        return TestResult::Fail("DELBA decode differs");
    }
    // Admission: immediate+buf<=64 ok (A-MSDU refused in reply), delayed or
    // oversize -> 38, non-HT -> 37, buf0 -> 64.
    if decide(&request, true) != (STATUS_SUCCESS, 32)
        || decide(
            &Request {
                policy: 0,
                ..request
            },
            true,
        )
        .0 != STATUS_INVALID_QOS_PARAM
        || decide(
            &Request {
                buf_size: 65,
                ..request
            },
            true,
        )
        .0 != STATUS_INVALID_QOS_PARAM
        || decide(&request, false).0 != STATUS_REQUEST_DECLINED
        || decide(
            &Request {
                buf_size: 0,
                ..request
            },
            true,
        ) != (STATUS_SUCCESS, 64)
    {
        return TestResult::Fail("ADDBA admission differs from mac80211");
    }
    let response = addba_response(OWN, PEER, &request, STATUS_SUCCESS, 32);
    if response[..4] != [0xd0, 0, 0, 0]
        || response[4..10] != PEER
        || response[10..16] != OWN
        || response[24..] != [3, 1, 9, 0, 0, 0x16, 0x08, 0xf4, 0x01]
    {
        return TestResult::Fail("ADDBA response encoding differs");
    }
    let teardown = delba(OWN, PEER, 6, REASON_TIMEOUT);
    if teardown[24..] != [3, 2, 0x00, 0x60, 39, 0] {
        return TestResult::Fail("DELBA encoding differs");
    }
    let mut bar_frame = alloc::vec![0x84, 0, 0, 0];
    bar_frame.extend_from_slice(&OWN);
    bar_frame.extend_from_slice(&PEER);
    bar_frame.extend_from_slice(&(0b100u16 | 2 << 12).to_le_bytes());
    bar_frame.extend_from_slice(&(77u16 << 4).to_le_bytes());
    let mut multi = bar_frame.clone();
    multi[16] |= 0b010;
    if bar(&bar_frame, OWN, PEER) != Some((2, 77)) || bar(&multi, OWN, PEER).is_some() {
        return TestResult::Fail("BAR decode differs");
    }
    let mut qos = alloc::vec![0x88, 2, 0, 0];
    qos.extend_from_slice(&OWN);
    qos.extend_from_slice(&PEER);
    qos.extend_from_slice(&PEER);
    qos.extend_from_slice(&(321u16 << 4).to_le_bytes());
    qos.extend_from_slice(&[6, 0]);
    let mut fragment = qos.clone();
    fragment[22] |= 1;
    if qos_sequence(&qos) != Some((6, 321)) || qos_sequence(&fragment).is_some() {
        return TestResult::Fail("QoS sequence extraction differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/block_ack",
    smoke_rtw89_block_ack_addba_delba_bar_codecs
);
