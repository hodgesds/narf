use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
const REMOTE: [u8; 6] = [2, 0, 0, 0, 0, 3];
const GROUP: [u8; 6] = [1, 0, 0x5e, 0, 0, 1];
fn ethernet(da: [u8; 6], protocol: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = da.to_vec();
    frame.extend_from_slice(&REMOTE);
    frame.extend_from_slice(&protocol.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
fn aggregate(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        let len = frame.len() - 14 + 8;
        body.extend_from_slice(&frame[..12]);
        body.extend_from_slice(&(len as u16).to_be_bytes());
        body.extend_from_slice(&RFC1042);
        body.extend_from_slice(&frame[12..]);
        if i + 1 != frames.len() {
            while body.len() % 4 != 0 {
                body.push(0xa5); // Padding bytes are not required to be zero.
            }
        }
    }
    body
}
fn smoke_amsdu_station_decodes_complete_unicast_multicast_and_padding() -> TestResult {
    for (receiver, destinations) in [
        (LOCAL, [LOCAL, LOCAL]),
        (LOCAL, [LOCAL, GROUP]),
        (GROUP, [GROUP, GROUP]),
    ] {
        for length in 0..8 {
            let frames = vec![
                ethernet(destinations[0], 0x800, &vec![0x45; length]),
                ethernet(destinations[1], 0x806, &[1, 2, 3]),
            ];
            let body = aggregate(&frames);
            let original = body.clone();
            if decode(&body, LOCAL, receiver) != Ok(frames) || body != original {
                return TestResult::Fail("complete A-MSDU/padding changed exact Ethernet or input");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/amsdu",
    smoke_amsdu_station_decodes_complete_unicast_multicast_and_padding
);

fn smoke_amsdu_rejects_bad_later_subframe_without_partial_delivery() -> TestResult {
    let frames = vec![
        ethernet(LOCAL, 0x800, &[1]),
        ethernet(LOCAL, 0x806, &[2, 3]),
    ];
    let body = aggregate(&frames);
    let second = 24; //14+8+1 bytes, padded to24.
    for case in 0..9 {
        let mut bad = body.clone();
        match case {
            0 => {
                bad.pop();
            }
            1 => bad[second + 12..second + 14].copy_from_slice(&7u16.to_be_bytes()),
            2 => bad[second + 12..second + 14].copy_from_slice(&1509u16.to_be_bytes()),
            3 => bad[second + 14] ^= 1,
            4 => bad[second..second + 6].fill(0),
            5 => bad[second + 6] |= 1,
            6 => bad[second + 6..second + 12].copy_from_slice(&LOCAL),
            7 => bad[second + 20..second + 22].copy_from_slice(&0x888eu16.to_be_bytes()),
            _ => bad[second + 20..second + 22].copy_from_slice(&0x88c7u16.to_be_bytes()),
        }
        let original = bad.clone();
        if decode(&bad, LOCAL, LOCAL).is_ok() || bad != original {
            return TestResult::Fail("malformed later A-MSDU subframe delivered a prefix");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/amsdu",
    smoke_amsdu_rejects_bad_later_subframe_without_partial_delivery
);

fn smoke_amsdu_rfc1042_injection_and_receiver_aliases_are_rejected() -> TestResult {
    let body = aggregate(&[ethernet(RFC1042, 0x800, &[])]);
    if decode(&body, LOCAL, LOCAL) != Err(Error::Injection) {
        return TestResult::Fail("RFC1042 first-DA aggregation injection admitted");
    }
    let other = [2, 0, 0, 0, 0, 9];
    for (receiver, destination) in [
        (LOCAL, other),
        (GROUP, LOCAL),
        (GROUP, [255; 6]),
        (other, other),
    ] {
        let body = aggregate(&[ethernet(destination, 0x800, &[])]);
        if decode(&body, LOCAL, receiver) != Err(Error::Address) {
            return TestResult::Fail("outer receiver/local or inner DA alias admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/amsdu",
    smoke_amsdu_rfc1042_injection_and_receiver_aliases_are_rejected
);

fn smoke_amsdu_exact_default_ht_size_and_subframe_work_are_bounded() -> TestResult {
    let frames = vec![
        ethernet(LOCAL, 0x800, &vec![1; 1500]),
        ethernet(LOCAL, 0x806, &vec![2; 1500]),
        ethernet(LOCAL, 0x800, &vec![3; 769]),
    ];
    let mut body = aggregate(&frames);
    if body.len() != MAX_BYTES || decode(&body, LOCAL, LOCAL) != Ok(frames) {
        return TestResult::Fail("exact3839-byte HT A-MSDU rejected or changed");
    }
    body.push(0);
    if decode(&body, LOCAL, LOCAL) != Err(Error::Length) {
        return TestResult::Fail("over-limit A-MSDU accepted");
    }
    let smallest = ethernet(LOCAL, 0x800, &[]);
    let frames = vec![smallest; 160];
    let body = aggregate(&frames);
    if body.len() != 3838 || decode(&body, LOCAL, LOCAL) != Ok(frames) {
        return TestResult::Fail("bounded minimum-size A-MSDU subframes rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/amsdu",
    smoke_amsdu_exact_default_ht_size_and_subframe_work_are_bounded
);

fn smoke_amsdu_rejects_trailing_padding_and_all_truncated_extents() -> TestResult {
    let body = aggregate(&[ethernet(LOCAL, 0x800, &[1, 2, 3])]);
    for end in 0..body.len() {
        if decode(&body[..end], LOCAL, LOCAL).is_ok() {
            return TestResult::Fail("truncated subheader/LLC/data accepted");
        }
    }
    for count in 1..=3 {
        let mut padded = body.clone();
        padded.extend_from_slice(&vec![0; count]);
        if decode(&padded, LOCAL, LOCAL).is_ok() {
            return TestResult::Fail("trailing last-subframe padding accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/amsdu",
    smoke_amsdu_rejects_trailing_padding_and_all_truncated_extents
);

fn smoke_amsdu_control_port_tunnel_and_vlan_encapsulation_stay_closed() -> TestResult {
    for protocol in [0, 1500, 0x888e, 0x88c7, 0x80f3, 0x8137] {
        if decode(&aggregate(&[ethernet(LOCAL, protocol, &[])]), LOCAL, LOCAL)
            != Err(Error::Protocol)
        {
            return TestResult::Fail("aggregate admitted length/control/tunnel protocol");
        }
    }
    for outer in [0x8100, 0x88a8] {
        for protocol in [0x888eu16, 0x88c7] {
            let payload = [0, 1, (protocol >> 8) as u8, protocol as u8];
            if decode(
                &aggregate(&[ethernet(LOCAL, outer, &payload)]),
                LOCAL,
                LOCAL,
            ) != Err(Error::Protocol)
            {
                return TestResult::Fail("aggregate VLAN hid private control port");
            }
        }
        let frame = ethernet(LOCAL, outer, &[0, 1, 8, 0, 0x45]);
        if decode(&aggregate(core::slice::from_ref(&frame)), LOCAL, LOCAL) != Ok(vec![frame]) {
            return TestResult::Fail("valid VLAN Ethernet-II aggregate rejected");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/amsdu",
    smoke_amsdu_control_port_tunnel_and_vlan_encapsulation_stay_closed
);
