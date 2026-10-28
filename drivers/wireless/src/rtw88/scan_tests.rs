// SPDX-License-Identifier: GPL-2.0-or-later
//! Channel1 software-scan plan and native probe descriptor admission.
use super::{
    packet_format::{self, Queue, MAX_MPDU},
    scan::{self, MAX_EXTRA_IES, MAX_SSIDS},
};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::{ScanRequest, WirelessError};

const OWN: [u8; 6] = [2, 4, 6, 8, 10, 12];

fn request(active: bool, ssids: Vec<Vec<u8>>, extra_ies: Vec<u8>) -> ScanRequest {
    ScanRequest {
        ssids,
        frequencies_mhz: vec![2412],
        channels: Vec::new(),
        active,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies,
    }
}

fn smoke_rtw88_scan_plan_matches_software_scan_preq() -> TestResult {
    let passive = scan::plan(&request(false, vec![b"x".to_vec()], Vec::new()), OWN);
    if passive.as_ref().map(|p| (p.dwell_ms, p.probes.len())) != Ok((200, 0)) {
        return TestResult::Fail("rtw88 passive plan changed dwell or transmitted");
    }
    let wildcard = match scan::plan(&request(true, Vec::new(), Vec::new()), OWN) {
        Ok(plan) => plan,
        Err(_) => return TestResult::Fail("rtw88 wildcard active plan refused"),
    };
    let mut expected = vec![0x40, 0, 0, 0];
    expected.extend_from_slice(&[255; 6]);
    expected.extend_from_slice(&OWN);
    expected.extend_from_slice(&[255; 6]);
    expected.extend_from_slice(&[0, 0, 0, 0]);
    expected.extend_from_slice(&[1, 8, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24]);
    expected.extend_from_slice(&[50, 4, 0x30, 0x48, 0x60, 0x6c, 3, 1, 1]);
    if wildcard.probes != vec![expected] {
        return TestResult::Fail("rtw88 wildcard probe request bytes differ");
    }
    let ssids: Vec<Vec<u8>> = (0..MAX_SSIDS).map(|i| vec![b'a' + i; 32]).collect();
    let extra = vec![221, 3, 0x00, 0x10, 0x18];
    match scan::plan(&request(true, ssids.clone(), extra.clone()), OWN) {
        Ok(plan)
            if plan.probes.len() == usize::from(MAX_SSIDS)
                && plan.probes.iter().zip(&ssids).all(|(p, s)| {
                    p[24..26] == [0, 32] && p[26..58] == s[..] && p.ends_with(&extra)
                }) => {}
        _ => return TestResult::Fail("rtw88 directed probes lost an SSID or extra IE"),
    }
    let mut too_many = ssids;
    too_many.push(Vec::new());
    if scan::plan(&request(true, too_many, Vec::new()), OWN) != Err(WirelessError::NotSupported) {
        return TestResult::Fail("rtw88 exceeded RTW_SCAN_MAX_SSIDS");
    }
    // The advertised caller budget exactly fills the native MPDU.
    let mut largest = vec![221, 255, 0, 0x10, 0x18];
    largest.resize(257, 0);
    while largest.len() + 257 <= usize::from(MAX_EXTRA_IES) {
        largest.extend_from_within(..257);
    }
    let rest = usize::from(MAX_EXTRA_IES) - largest.len();
    if rest >= 2 {
        largest.extend_from_slice(&[10, (rest - 2) as u8]);
        largest.resize(usize::from(MAX_EXTRA_IES), 0);
    }
    let full = scan::plan(&request(true, vec![vec![b's'; 32]], largest.clone()), OWN);
    if !full.is_ok_and(|p| p.probes[0].len() <= MAX_MPDU) {
        return TestResult::Fail("rtw88 maximum caller IEs overflowed the native MPDU");
    }
    largest.push(0);
    if scan::plan(&request(true, Vec::new(), largest), OWN) != Err(WirelessError::InvalidArgs) {
        return TestResult::Fail("rtw88 accepted probe IEs beyond the advertised budget");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_scan_plan_matches_software_scan_preq
);

fn smoke_rtw88_scan_plan_rejects_unsupported_and_malformed_requests() -> TestResult {
    let base = || request(true, Vec::new(), Vec::new());
    let cases: [(ScanRequest, WirelessError); 9] = [
        (
            ScanRequest {
                // cfg80211 nl80211_parse_random_mac: mask must keep the group bit.
                random_mac: Some(narf_wireless::scan::ScanRandomMac {
                    addr: [2, 0, 0, 0, 0, 0],
                    mask: [0xfe, 0, 0, 0, 0, 0],
                }),
                ..base()
            },
            WirelessError::NotSupported,
        ),
        (
            ScanRequest {
                colocated_6ghz: true,
                ..base()
            },
            WirelessError::NotSupported,
        ),
        (
            ScanRequest {
                frequencies_mhz: vec![5180],
                ..base()
            },
            WirelessError::NotSupported,
        ),
        (
            request(false, Vec::new(), vec![221, 3, 0, 0x10, 0x18]),
            WirelessError::NotSupported,
        ),
        (
            request(true, Vec::new(), vec![1, 1, 0x82]),
            WirelessError::InvalidArgs,
        ),
        (
            request(true, Vec::new(), vec![3, 1, 6]),
            WirelessError::InvalidArgs,
        ),
        (
            request(true, Vec::new(), vec![221, 2, 0, 0]),
            WirelessError::InvalidArgs,
        ),
        (
            request(true, Vec::new(), vec![45, 26, 0]),
            WirelessError::InvalidArgs,
        ),
        (
            ScanRequest {
                duration_tu: Some(0),
                ..base()
            },
            WirelessError::InvalidArgs,
        ),
    ];
    for (case, expected) in cases {
        if scan::plan(&case, OWN) != Err(expected) {
            return TestResult::Fail("rtw88 scan plan admitted an unsupported request");
        }
    }
    if scan::plan(&base(), [1, 0, 0, 0, 0, 0]) != Err(WirelessError::InvalidArgs) {
        return TestResult::Fail("rtw88 probe used a group source address");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_scan_plan_rejects_unsupported_and_malformed_requests
);

fn smoke_rtw88_probe_request_descriptor_is_broadcast_management() -> TestResult {
    let probe = match scan::plan(&request(true, Vec::new(), Vec::new()), OWN) {
        Ok(mut plan) => plan.probes.remove(0),
        Err(_) => return TestResult::Fail("rtw88 probe plan refused"),
    };
    let Ok((descriptor, queue)) = packet_format::transmit(&probe, OWN, 0, None) else {
        return TestResult::Fail("rtw88 native format refused a software-scan probe");
    };
    let word = |i: usize| {
        u32::from_le_bytes([
            descriptor[i],
            descriptor[i + 1],
            descriptor[i + 2],
            descriptor[i + 3],
        ])
    };
    if queue != Queue::Management
        || word(0) & (1 << 24) == 0
        || (word(4) >> 8) & 31 != 18
        || (word(4) >> 16) & 31 != 8
        || word(8) & (1 << 19) != 0
        || word(16) != 0
    {
        return TestResult::Fail("rtw88 probe descriptor is not BMC/MGMT/CCK1 without report");
    }
    // Directed DA, foreign SA, directed BSSID, retry flag.
    for (offset, value) in [(4, 0x02u8), (10, 0x06), (16, 0x02), (1, 0x08)] {
        let mut altered = probe.clone();
        altered[offset] = value;
        if packet_format::classify(&altered, OWN).is_ok() {
            return TestResult::Fail("rtw88 admitted a directed/foreign/flagged probe");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_probe_request_descriptor_is_broadcast_management
);

/// `randomized_scan_mac`: mac80211 `get_random_mask_addr` keeps the masked
/// base bits, randomizes the rest and uses it as every probe SA.
fn smoke_rtw88_scan_plan_random_mac_address() -> TestResult {
    let random = narf_wireless::scan::ScanRandomMac {
        addr: [0x02, 0x11, 0x22, 0, 0, 0],
        mask: [0xff, 0xff, 0xff, 0, 0, 0],
    };
    let mut seen = Vec::new();
    for _ in 0..4 {
        let Ok(p) = scan::plan(
            &ScanRequest {
                random_mac: Some(random),
                ..request(true, vec![b"x".to_vec(), Vec::new()], Vec::new())
            },
            OWN,
        ) else {
            return TestResult::Fail("random-MAC active plan refused");
        };
        let Some(a) = p.address else {
            return TestResult::Fail("random-MAC active plan has no address");
        };
        if a[..3] != [0x02, 0x11, 0x22] || a == OWN || p.probes.iter().any(|f| f[10..16] != a) {
            return TestResult::Fail("random scan address mask or probe SA");
        }
        seen.push(a);
    }
    if seen.iter().all(|a| *a == seen[0]) {
        return TestResult::Fail("random scan address did not vary");
    }
    let passive = scan::plan(
        &ScanRequest {
            random_mac: Some(random),
            ..request(false, Vec::new(), Vec::new())
        },
        OWN,
    );
    if !passive.is_ok_and(|p| p.address.is_none() && p.probes.is_empty()) {
        return TestResult::Fail("passive random-MAC plan transmitted or bound an address");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/narrow/scan",
    smoke_rtw88_scan_plan_random_mac_address
);
