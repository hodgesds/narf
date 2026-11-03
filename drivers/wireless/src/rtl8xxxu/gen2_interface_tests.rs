//! Gen2 netdev scan-request and candidate-cache regressions (pure inputs).
//! Request admission follows the RTL8188EU `interface::validate_scan`
//! contract (`rtl8xxxu_probe` sets `max_scan_ssids = 1`); the cache bound and
//! replacement follow the RTL8188EU service cache. Nothing here is a
//! hardware receipt.

use alloc::{vec, vec::Vec};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::ScanRequest;

use super::{remember, validate_scan, Entry, CANDIDATES};
use crate::rtl8xxxu::management_runtime::Candidate;
use crate::rtl8xxxu::packet_codec::Mpdu;

const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];

fn request() -> ScanRequest {
    ScanRequest {
        ssids: Vec::new(),
        frequencies_mhz: Vec::new(),
        channels: Vec::new(),
        active: false,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    }
}

fn beacon(ap: [u8; 6]) -> Candidate {
    let mut bytes = vec![0x80, 0, 0, 0];
    bytes.extend_from_slice(&[255; 6]);
    bytes.extend_from_slice(&ap);
    bytes.extend_from_slice(&ap);
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&100u16.to_le_bytes());
    bytes.extend_from_slice(&0x0421u16.to_le_bytes());
    bytes.extend_from_slice(&[
        0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96, 3, 1, 1,
    ]);
    let mpdu = Mpdu {
        native: None,
        wide: None,
        ba: false,
        bytes,
        phy: Vec::new(),
        rate: 0,
        ht: false,
        bandwidth40: false,
        tid: 0,
        decrypted: false,
        timestamp: 0,
    };
    Candidate::from_receive(&mpdu, 1, LOCAL).unwrap()
}

fn smoke_rtl8xxxu_gen2_scan_request_admission() -> TestResult {
    // Default: every granted channel, 200 ms passive dwell.
    match validate_scan(&request()) {
        Ok((channels, 200)) if channels.is_empty() => (),
        _ => return TestResult::Fail("default request"),
    }
    // Frequencies win over channel numbers and are de-duplicated.
    let mut r = request();
    r.frequencies_mhz = vec![2412, 2437, 2412];
    r.channels = vec![13];
    if validate_scan(&r).map(|(c, _)| c) != Ok(vec![1, 6]) {
        return TestResult::Fail("frequency list");
    }
    // Channel 14 / 5 GHz / off-raster frequencies are refused.
    for (channels, frequencies) in [
        (vec![14], vec![]),
        (vec![], vec![5180]),
        (vec![], vec![2413]),
    ] {
        let mut r = request();
        r.channels = channels;
        r.frequencies_mhz = frequencies;
        if validate_scan(&r).is_ok() {
            return TestResult::Fail("unqualified channel admitted");
        }
    }
    // Probe IEs only with an active request; at most one active SSID.
    let mut r = request();
    r.extra_ies = vec![221, 0];
    if validate_scan(&r).is_ok() {
        return TestResult::Fail("passive extra IEs");
    }
    r.active = true;
    if validate_scan(&r).is_err() {
        return TestResult::Fail("active extra IEs");
    }
    r.ssids = vec![b"a".to_vec(), b"b".to_vec()];
    if validate_scan(&r).is_ok() {
        return TestResult::Fail("two active SSIDs");
    }
    // Dwell: TU -> ms rounding up; a mandatory dwell needs a duration.
    let mut r = request();
    r.duration_tu = Some(100);
    if validate_scan(&r).map(|(_, d)| d) != Ok(103) {
        return TestResult::Fail("dwell conversion");
    }
    r.duration_tu = None;
    r.duration_mandatory = true;
    if validate_scan(&r).is_ok() {
        return TestResult::Fail("mandatory without duration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_scan_request_admission
);

fn smoke_rtl8xxxu_gen2_candidate_cache_bound() -> TestResult {
    let mut cache: Vec<Entry> = Vec::new();
    for i in 0..CANDIDATES as u8 {
        remember(
            &mut cache,
            beacon([2, 0, 0, 0, 1, i]),
            100 + u64::from(i),
            1,
        );
    }
    // A repeat replaces in place with the newer stream generation.
    remember(&mut cache, beacon([2, 0, 0, 0, 1, 5]), 500, 2);
    if cache.len() != CANDIDATES
        || !cache.iter().any(|e| {
            e.candidate.bssid() == [2, 0, 0, 0, 1, 5] && e.seen == 500 && e.generation == 2
        })
    {
        return TestResult::Fail("in-place replacement");
    }
    // A new BSS evicts the oldest observation (index 0, seen 100).
    remember(&mut cache, beacon([2, 0, 0, 0, 2, 0]), 600, 2);
    if cache.len() != CANDIDATES
        || cache
            .iter()
            .any(|e| e.candidate.bssid() == [2, 0, 0, 0, 1, 0])
        || !cache
            .iter()
            .any(|e| e.candidate.bssid() == [2, 0, 0, 0, 2, 0])
    {
        return TestResult::Fail("oldest eviction");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/gen2station",
    smoke_rtl8xxxu_gen2_candidate_cache_bound
);
