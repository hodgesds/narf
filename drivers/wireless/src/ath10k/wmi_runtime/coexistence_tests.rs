use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
fn bss(frequency: u16, capability: Option<u16>) -> ScanBss {
    let mut ies = Vec::new();
    if let Some(cap) = capability {
        ies.extend_from_slice(&[45, 26]);
        ies.extend_from_slice(&cap.to_le_bytes());
        ies.extend_from_slice(&[0; 24]);
    }
    ies.extend_from_slice(&[74, 14, 20, 0, 10, 0, 1, 0, 200, 0, 20, 0, 5, 0, 25, 0]);
    ScanBss {
        bssid: [2; 6],
        ssid: b"narf".to_vec(),
        frequency,
        snr: 30,
        capability: 1,
        beacon_interval: 100,
        information_elements: ies,
    }
}
fn smoke_ath10k_coexistence_affected_scan_reports_and_strict_public_action() -> TestResult {
    let available: Vec<u16> = (2412..=2472).step_by(5).collect();
    let own = [4; 6];
    for (primary, secondary, expected) in [(2412, 2432, (2412, 2447)), (2462, 2442, (2427, 2472))] {
        let ap = bss(primary, Some(2));
        let mut state = State::new(&ap, secondary, &available).unwrap().unwrap();
        if state.channels.first().copied() != Some(expected.0)
            || state.channels.last().copied() != Some(expected.1)
            || state.interval != 10_000
        {
            return TestResult::Fail("OBSS affected-range/minimum source interval");
        }
        let center = (primary + secondary) / 2;
        for frequency in &available {
            if state.channels.contains(frequency) != (frequency.abs_diff(center) <= 25) {
                return TestResult::Fail(
                    "OBSS center25 included/center30 excluded source boundary",
                );
            }
        }
        if State::new(&ap, secondary, &[primary]).unwrap().is_some() {
            return TestResult::Fail("partial inventory invented clear OBSS");
        }
        state
            .report(&ScanReport {
                bss: alloc::vec![
                    bss(primary, None),
                    bss(secondary, Some(0x4002)),
                    bss(5180, None)
                ],
                received: 3,
                ignored: 0,
                truncated: false,
            })
            .unwrap();
        let frame = state.frame(own);
        if frame[..2] != [0xd0, 0]
            || frame[4..10] != ap.bssid
            || frame[10..16] != own
            || frame[24..29] != [4, 0, 72, 1, 4]
            || frame.len() != 34
            || frame[29..32] != [73, 3, 0]
            || !state.trigger
            || validate_report(&frame[26..]).is_err()
        {
            return TestResult::Fail("native Public Action width request/intolerant report");
        }
        let mut clean = State::new(&ap, secondary, &available).unwrap().unwrap();
        let mut request = frame.clone();
        request[4..10].copy_from_slice(&own);
        request[10..16].copy_from_slice(&ap.bssid);
        let mut foreign = request.clone();
        foreign[10] ^= 2;
        clean.action(&foreign, own).unwrap();
        if clean.trigger {
            return TestResult::Fail("foreign source triggered native width");
        }
        clean.action(&request, own).unwrap();
        if !clean.trigger {
            return TestResult::Fail("exact AP Public Action lost width trigger");
        }
        for malformed in [
            alloc::vec![72, 0],
            alloc::vec![72, 1, 32],
            alloc::vec![72, 1, 0, 72, 1, 0],
            alloc::vec![72, 1, 0, 73, 3, 0, 1, 1],
            alloc::vec![72, 1, 0, 73, 2, 0, 14],
        ] {
            if validate_report(&malformed).is_ok() {
                return TestResult::Fail("malformed coex IE accepted");
            }
        }
        if clean
            .report(&ScanReport {
                bss: Vec::new(),
                received: 0,
                ignored: 0,
                truncated: true,
            })
            .is_ok()
        {
            return TestResult::Fail("truncated OBSS inventory proved absence");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/coexistence",
    smoke_ath10k_coexistence_affected_scan_reports_and_strict_public_action
);
fn smoke_ath10k_coexistence_native_peer_restart_and_response_types_six_dialects() -> TestResult {
    let permission = crate::ath10k::regulatory::Permission {
        factory: crate::ath10k::regulatory::Factory::from_eeprom(0x64).unwrap(),
        country: *b"US",
        frequency: 2432,
        center: 2432,
        secondary: None,
        width80: false,
        center2: None,
        half_dbm: 34,
        radar: 0,
        hint: None,
    };
    for (d, restart_id, peer_id) in [
        (Dialect::Main, 0x5004, 0x6004),
        (Dialect::TenOne, 0x9014, 0x901f),
        (Dialect::TenTwo, 0x9013, 0x901f),
        (Dialect::TenTwoFour, 0x9013, 0x901f),
        (Dialect::TenFour, 0x9016, 0x9025),
        (Dialect::Tlv, 0x5004, 0x6004),
    ] {
        let wire = wire::Wire::new(d);
        let restart = wire.coexistence_restart(0, &permission, 100, 3).unwrap();
        let word = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        let channel = if d == Dialect::Tlv { 84 } else { 4 };
        let owner = if d == Dialect::Tlv { 8 } else { 28 };
        if word(&restart, 0) != restart_id
            || word(&restart, channel) != 2432
            || word(&restart, channel + 4) != 2432
            || word(&restart, channel + 12) != 0x805
            || word(&restart, owner + 12) != 3
        {
            return TestResult::Fail("real20 restart native geometry/DTIM");
        }
        for (i, packet) in wire.coexistence_peer(0, [2; 6]).unwrap().iter().enumerate() {
            let at = if d == Dialect::Tlv { 8 } else { 4 };
            if word(packet, 0) != peer_id
                || word(packet, at) != 0
                || packet[at + 4..at + 10] != [2; 6]
                || word(packet, at + 12) != if i == 0 { 13 } else { 4 }
                || word(packet, at + 16) != if i == 0 { 5 } else { 0 }
            {
                return TestResult::Fail("native peer PHYMODE/CHWIDTH source words");
            }
        }
        let mut response = alloc::vec![0;16];
        if d == Dialect::Tlv {
            response.splice(..0, ((40u32 << 16) | 16).to_le_bytes());
        }
        let at = usize::from(d == Dialect::Tlv) * 4;
        if wire.coexistence_response(0, &response) != Ok(None) {
            return TestResult::Fail("old START satisfied RESTART");
        }
        wire::put(&mut response, at + 8, 1);
        if wire.coexistence_response(0, &response) != Ok(Some(())) {
            return TestResult::Fail("actual successful RESTART rejected");
        }
        wire::put(&mut response, at, 1);
        if wire.coexistence_response(0, &response) != Ok(None) {
            return TestResult::Fail("foreign VDEV RESTART accepted");
        }
        wire::put(&mut response, at, 0);
        wire::put(&mut response, at + 12, 7);
        if wire.coexistence_response(0, &response) != Err(Error::Firmware(7)) {
            return TestResult::Fail("failed RESTART reopened DATA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/coexistence",
    smoke_ath10k_coexistence_native_peer_restart_and_response_types_six_dialects
);
