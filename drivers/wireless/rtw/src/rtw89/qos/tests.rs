// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn ipv4(tos: u8) -> Vec<u8> {
    let mut f = alloc::vec![0u8; 34];
    f[12] = 0x08;
    f[14] = 0x45;
    f[15] = tos;
    f
}
fn ipv6(tc: u8) -> Vec<u8> {
    let mut f = alloc::vec![0u8; 54];
    f[12] = 0x86;
    f[13] = 0xdd;
    f[14] = 0x60 | tc >> 4;
    f[15] = tc << 4;
    f
}

fn smoke_rtw89_qos_classify_matches_cfg80211_rfc8325() -> TestResult {
    // (DSCP, expected UP) from cfg80211_classify8021d.
    let table: [(u8, u8); 14] = [
        (0, 0),  // DF
        (8, 1),  // CS1
        (10, 0), // AF11
        (16, 0), // CS2
        (18, 3), // AF21
        (24, 4), // CS3
        (26, 4), // AF31
        (32, 4), // CS4
        (34, 4), // AF41
        (40, 5), // CS5
        (44, 6), // VA
        (46, 6), // EF
        (48, 7), // CS6
        (56, 7), // CS7
    ];
    for (dscp, up) in table {
        if classify(&ipv4(dscp << 2 | 3)) != up || classify(&ipv6(dscp << 2 | 1)) != up {
            return TestResult::Fail("DSCP mapping differs from cfg80211_classify8021d");
        }
    }
    let mut arp = alloc::vec![0u8; 42];
    arp[12] = 0x08;
    arp[13] = 0x06;
    let mut mpls = alloc::vec![0u8; 18];
    mpls[12] = 0x88;
    mpls[13] = 0x47;
    mpls[16] = 5 << 1; // TC = 5
    let mut x21 = alloc::vec![0u8; 14];
    x21[12] = 0x89;
    x21[13] = 0x17;
    if classify(&arp) != 0 || classify(&mpls) != 5 || classify(&x21) != 7 || classify(&[0; 8]) != 0
    {
        return TestResult::Fail("non-IP classification differs");
    }
    // Truncated or mislabelled IP headers fall back to best effort.
    let mut bad = ipv4(46 << 2);
    bad[14] = 0x60;
    if classify(&bad) != 0 || classify(&ipv4(0)[..14]) != 0 {
        return TestResult::Fail("malformed IP header classified");
    }
    TestResult::Pass
}

fn smoke_rtw89_qos_ac_downgrade_and_queue_mapping() -> TestResult {
    let acs: [Ac; 8] = core::array::from_fn(|tid| Ac::of(tid as u8));
    use Ac::*;
    if acs
        != [
            BestEffort, Background, Background, BestEffort, Video, Video, Voice, Voice,
        ]
    {
        return TestResult::Fail("ieee802_1d_to_ac differs");
    }
    // ACM on VO and VI: EF downgrades to BE (wme_downgrade_ac chain).
    if downgrade(6, [false, false, true, true]) != 0 {
        return TestResult::Fail("VO/VI ACM downgrade differs");
    }
    if downgrade(6, [false, false, false, true]) != 5 || downgrade(3, [true; 4]) != 2 {
        return TestResult::Fail("partial/all-ACM downgrade differs");
    }
    if downgrade(1, [true; 4]) != 1 || downgrade(4, [false; 4]) != 4 {
        return TestResult::Fail("BK/no-ACM downgrade differs");
    }
    let indicate: Vec<u8> = (0..8).filter(|tid| tid_indicate(*tid)).collect();
    if indicate != [2, 3, 5, 7] {
        return TestResult::Fail("rtw89_core_get_tid_indicate differs");
    }
    if Ac::ORDER.map(Ac::wmm_index) != [3, 2, 0, 1] {
        return TestResult::Fail("strict service order differs");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89/qos",
    smoke_rtw89_qos_classify_matches_cfg80211_rfc8325
);
kernel_test_in!(
    "drivers/wireless/rtw89/qos",
    smoke_rtw89_qos_ac_downgrade_and_queue_mapping
);
