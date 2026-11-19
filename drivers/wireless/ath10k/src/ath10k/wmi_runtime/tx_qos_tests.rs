use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn ipv4(tos: u8) -> Vec<u8> {
    let mut f = alloc::vec![0u8; 14 + 20];
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    f[14] = 0x45;
    f[15] = tos;
    f
}
/// WMM Parameter IE (BE/BK/VI/VO rows); `acm` sets ACI/AIFSN bit 4 per row.
fn wmm(acm: [bool; 4]) -> Parameters {
    let mut ie = [
        221u8, 24, 0, 0x50, 0xf2, 2, 1, 1, 0, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 94,
        0, 0x62, 0x32, 47, 0,
    ];
    for (row, set) in acm.iter().enumerate() {
        if *set {
            ie[10 + row * 4] |= 0x10;
        }
    }
    Parameters::parse(&ie).unwrap().unwrap()
}

fn smoke_ath10k_tx_qos_classifies_dscp_to_tid() -> TestResult {
    let none = [false; 4];
    // RFC 8325 / cfg80211_classify8021d: EF -> 6, CS6 -> 7, AF21 -> 3,
    // CS1 -> 1 (BK), default -> 0; EAPOL is control-port priority 7.
    for (tos, want) in [
        (0xb8, 6),
        (0xc0, 7),
        (0x48, 3),
        (0x20, 1),
        (0, 0),
        (0x80, 4),
    ] {
        if priority(&ipv4(tos), none) != want {
            return TestResult::Fail("DSCP to 802.1D user priority differs from Linux");
        }
    }
    let mut eapol = alloc::vec![0u8; 18];
    eapol[12..14].copy_from_slice(&[0x88, 0x8e]);
    if priority(&eapol, none) != 7 || priority(&[0; 4], none) != 0 {
        return TestResult::Fail("EAPOL / runt classification differs");
    }
    if admission(&wmm(none)) != none {
        return TestResult::Fail("no-ACM AP must not restrict any AC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/tx_qos",
    smoke_ath10k_tx_qos_classifies_dscp_to_tid
);

fn smoke_ath10k_tx_qos_downgrades_admission_controlled_acs() -> TestResult {
    // VO and VI require admission: voice falls through VI to BE (UP 3).
    let acm = admission(&wmm([false, false, true, true]));
    if acm != [false, false, true, true] {
        return TestResult::Fail("WMM ACM bits not mapped to canonical ACI order");
    }
    if priority(&ipv4(0xb8), acm) != 3 || priority(&ipv4(0x80), acm) != 3 {
        return TestResult::Fail("VO/VI under ACM must downgrade to BE (UP 3)");
    }
    // BE requires admission: BE traffic uses BK (UP 2).
    let acm = admission(&wmm([true, false, false, false]));
    if priority(&ipv4(0), acm) != 2 || priority(&ipv4(0xb8), acm) != 6 {
        return TestResult::Fail("BE under ACM must use BK; unrestricted VO stays");
    }
    // Every AC requires admission: BK is used anyway (wme_downgrade_ac).
    let all = [true; 4];
    if priority(&ipv4(0xc0), all) != 2 || priority(&ipv4(0x20), all) != 1 {
        return TestResult::Fail("BK must be used even when it requires admission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/tx_qos",
    smoke_ath10k_tx_qos_downgrades_admission_controlled_acs
);

fn smoke_ath10k_tx_qos_descriptor_tid_follows_qos_control() -> TestResult {
    let mut frame = alloc::vec![0u8; 26];
    frame[0] = 0x88;
    frame[24] = 0x15; // TID 5 plus EOSP-like upper bits
    if descriptor_tid(&frame) != 5 {
        return TestResult::Fail("HTT TID must come from QoS Control bits 0..3");
    }
    frame[0] = 0x08;
    if descriptor_tid(&frame) != 16 || descriptor_tid(&[0x88; 10]) != 16 {
        return TestResult::Fail("non-QoS or truncated frames use the non-QoS TID");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/tx_qos",
    smoke_ath10k_tx_qos_descriptor_tid_follows_qos_control
);
