use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw89_he_htc_rate_reports_and_special_packets() -> TestResult {
    // OUTSRC=2, RA class=1, STS_RPT=0; complete length16, MACID0,
    // HE MCS3 NSS1, 1xLTF+0.8us, 20MHz.
    let mut report = [6, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 3, 0x17, 0, 0];
    if rate_allows(&report) != Some(true) {
        return TestResult::Fail("AX HE MCS3 rate report did not enable +HTC");
    }
    for mcs in 0..=2 {
        report[12] = mcs;
        if rate_allows(&report) != Some(false) {
            return TestResult::Fail("legacy fallback rate enabled +HTC");
        }
    }
    report[12] = 3;
    for mode in [0, 1, 2, 3] {
        report[13] = mode;
        if rate_allows(&report) != Some(mode != 0) {
            return TestResult::Fail("AX rate report mode decoded incorrectly");
        }
    }
    for (index, value) in [(12, 0x13), (12, 12), (13, 0x1b), (14, 1), (4, 15)] {
        let mut bad = report;
        bad[index] = value;
        if rate_allows(&bad) != Some(false) {
            return TestResult::Fail("out-of-profile rate report enabled +HTC");
        }
    }
    report[8] = 1;
    if rate_allows(&report).is_some() {
        return TestResult::Fail("other station's rate report changed +HTC");
    }
    report[8] = 0;
    for len in 4..16 {
        if rate_allows(&report[..len]) != Some(false) {
            return TestResult::Fail("truncated rate report did not suppress +HTC");
        }
    }
    report[0] = 2;
    if rate_allows(&report).is_some() {
        return TestResult::Fail("unrelated C2H changed +HTC");
    }

    let mut ethernet = vec![0; 14 + 24 + 8];
    ethernet[12..14].copy_from_slice(&[8, 0]);
    ethernet[14] = 0x46; // IPv4 options: UDP starts after24 octets.
    ethernet[23] = 17;
    ethernet[38..42].copy_from_slice(&[0, 5, 0, 6]);
    if !packet_allows(&ethernet) {
        return TestResult::Fail("ordinary UDP suppressed +HTC");
    }
    for ports in [[0, 67, 0, 68], [0, 68, 0, 67]] {
        ethernet[38..42].copy_from_slice(&ports);
        if packet_allows(&ethernet) {
            return TestResult::Fail("DHCP with IPv4 options received +HTC");
        }
    }
    ethernet[23] = 1;
    if packet_allows(&ethernet) {
        return TestResult::Fail("ICMP received +HTC");
    }
    for protocol in [[8, 6], [0x88, 0x8e]] {
        ethernet[12..14].copy_from_slice(&protocol);
        if packet_allows(&ethernet) {
            return TestResult::Fail("ARP/EAPOL received +HTC");
        }
    }
    for length in 0..14 {
        if packet_allows(&ethernet[..length]) {
            return TestResult::Fail("short Ethernet admitted +HTC");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/htc",
    smoke_rtw89_he_htc_rate_reports_and_special_packets
);
