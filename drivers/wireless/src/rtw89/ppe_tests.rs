use super::ppe::parse_assoc_ppe;
use narf_kernel_test::{kernel_test_in, TestResult};

/// EHT PPE fixture, NSS=2, all 5 RUs (layout per `ppe.rs` docs;
/// bytes built by the lane's fixture generator from the
/// `ieee80211.h` field layout, hand-verified bit-by-bit):
/// SSID "abc" + rates, then a HE Capabilities element (ext 35,
/// PHY0 0x0c so 8 MCS/NSS bytes — length 26, no PPE) and an EHT Capabilities element (ext 108,
/// PHY5 0x08 PPE-present, MCS/NSS 6 bytes, PPE header 0x01f1:
/// NSS field 1 = 2 streams, RU bitmap 0b11111).
/// NSS block 0 (decoys): (0,0) (7,7) (1,2) (6,7) (3,3).
/// NSS block 1: RU0 (5,7) -> 3, RU1 (0,5) -> 1, RU2 (7,7) -> 0,
/// RU3 (3,7) -> 3, RU4 (7,6) -> 1.
///
/// Shared with the admission wiring test in
/// `station_8922a_tests` (one source of fixture truth).
pub(super) const IES_E1_EHT_PPE_NSS2: &[u8] = &[
    0x00, 0x03, 0x61, 0x62, 0x63, 0x01, 0x01, 0x82, 0xff, 0x1a, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0x1b, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x81, 0x3f, 0xf2, 0xb7, 0x1e, 0xfd, 0xf7,
    0x1b,
];

/// The EHT Capabilities element of `IES_E1_EHT_PPE_NSS2` alone.
const EHT_E1_ELEM: &[u8] = &[
    0xff, 0x1b, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xf1, 0x81, 0x3f, 0xf2, 0xb7, 0x1e, 0xfd, 0xf7, 0x1b,
];

/// HE PPE fixture, NSS=1, all 4 RUs: HE Capabilities element
/// (ext 35, PHY0 0x04, PHY6 0x80 PPE-present, MCS/NSS 4 bytes,
/// PPE header 0x78: NSS field 0 = 1 stream, RU bitmap 0b1111).
/// Pairs: RU0 (2,7) -> 2, RU1 (0,0) -> 1, RU2 (7,7) -> 0,
/// RU3 (5,7) -> 2; RU4 bit clear -> 1.
/// Shared with the legacy HE admission wiring test.
pub(super) const IES_H1_HE_PPE_NSS1: &[u8] = &[
    0xff, 0x1a, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x1d, 0xf8, 0x7b,
];

/// HE, no PPE field: nominal packet padding 1 (8 us, PHY9 0x40).
const IES_H0_HE_NOMINAL_8US: &[u8] = &[
    0xff, 0x16, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// EHT, no PPE field: common nominal packet padding 2 (16 us,
/// PHY5 0x20), with the HE element the EHT MCS/NSS size needs.
/// EHT element: ext 108, 2 MAC-cap bytes, PHY0..PHY4 zero, PHY5
/// 0x20 (2-byte MAC capabilities, so PHY5 is payload byte 7).
const IES_E0_EHT_COMMON_16US: &[u8] = &[
    0xff, 0x16, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x0f, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// HE PPE companion for the EHT elements above: PHY0 0x0c (so the
/// EHT MCS/NSS map is 6 bytes, matching `EHT_E1_ELEM` /
/// `EHT_TRUNC_ELEM`), 8 HE MCS/NSS bytes, PHY6 PPE-present and the
/// `IES_H1_HE_PPE_NSS1` PPE field (NSS1 pads [2, 1, 0, 2, 1]).
const HE_C_PPE_NSS1: &[u8] = &[
    0xff, 0x1e, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x1d, 0xf8, 0x7b,
];

/// SSID + rates only: no EHT/HE caps.
const IES_NOCAPS: &[u8] = &[0x00, 0x03, 0x61, 0x62, 0x63, 0x01, 0x01, 0x82];

/// EHT PPE-present bit set but the PPE field cut to its 2-byte
/// header (PPET bytes missing); the companion HE element carries
/// no PPE either (nominal pad 0).
const IES_TRUNC_EHT_PPE: &[u8] = &[
    0xff, 0x1a, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x14, 0x6c, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1,
    0x81,
];

/// The truncated EHT element of `IES_TRUNC_EHT_PPE` alone.
const EHT_TRUNC_ELEM: &[u8] = &[
    0xff, 0x14, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xf1, 0x81,
];

fn check(ies: &[u8], nss: u8, want: [u8; 5]) -> TestResult {
    if parse_assoc_ppe(ies, nss) != want {
        return TestResult::Fail("PPE pads mismatch");
    }
    TestResult::Pass
}

/// Run each check in turn, failing on the first mismatch.
fn checks(cases: &[(&[u8], u8, [u8; 5])]) -> TestResult {
    for (ies, nss, want) in cases {
        let result = check(ies, *nss, *want);
        if result != TestResult::Pass {
            return result;
        }
    }
    TestResult::Pass
}

fn smoke_rtw89_ppe_eht_thresholds() -> TestResult {
    // NSS=2 reads the second NSS block; NSS=1 reads the decoy
    // first block — the block selection itself is under test.
    checks(&[
        (IES_E1_EHT_PPE_NSS2, 2, [3, 1, 0, 3, 1]),
        (IES_E1_EHT_PPE_NSS2, 1, [1, 0, 1, 3, 1]),
    ])
}

fn smoke_rtw89_ppe_he_thresholds() -> TestResult {
    check(IES_H1_HE_PPE_NSS1, 1, [2, 1, 0, 2, 1])
}

fn smoke_rtw89_ppe_nominal_pads() -> TestResult {
    checks(&[
        (IES_H0_HE_NOMINAL_8US, 1, [1; 5]),
        (IES_E0_EHT_COMMON_16US, 2, [2; 5]),
    ])
}

fn smoke_rtw89_ppe_no_caps_zero() -> TestResult {
    checks(&[
        (IES_NOCAPS, 2, [0; 5]),
        (&[], 2, [0; 5]),
        (IES_E1_EHT_PPE_NSS2, 0, [0; 5]),
    ])
}

fn smoke_rtw89_ppe_eht_preferred() -> TestResult {
    // Valid HE PPE + valid EHT PPE: the EHT pads win.
    let mut ies = [0u8; 32 + 29];
    ies[..32].copy_from_slice(HE_C_PPE_NSS1);
    ies[32..].copy_from_slice(EHT_E1_ELEM);
    check(&ies, 2, [3, 1, 0, 3, 1])
}

fn smoke_rtw89_ppe_truncated_fail_closed() -> TestResult {
    // Truncated EHT PPE, companion HE with no PPE: zeros.
    let result = check(IES_TRUNC_EHT_PPE, 2, [0; 5]);
    if result != TestResult::Pass {
        return result;
    }
    // Truncated EHT PPE + valid HE PPE: the HE pads are used.
    let mut ies = [0u8; 32 + 22];
    ies[..32].copy_from_slice(HE_C_PPE_NSS1);
    ies[32..].copy_from_slice(EHT_TRUNC_ELEM);
    check(&ies, 1, [2, 1, 0, 2, 1])
}

fn smoke_rtw89_ppe_nss_out_of_range() -> TestResult {
    // The HE PPE field carries one NSS block; NSS=2 has none.
    check(IES_H1_HE_PPE_NSS1, 2, [0; 5])
}

fn smoke_rtw89_ppe_walker_robustness() -> TestResult {
    // An SSID whose payload starts with byte 35 must NOT match
    // as a HE Capabilities element (extension id is only read
    // under element id 255).
    let mut ies = [0u8; 4 + 28];
    ies[..4].copy_from_slice(&[0x00, 0x02, 0x23, 0x00]);
    ies[4..].copy_from_slice(IES_H1_HE_PPE_NSS1);
    let result = check(&ies, 1, [2, 1, 0, 2, 1]);
    if result != TestResult::Pass {
        return result;
    }
    // Unknown extension element (HE Operation, ext 36) skipped.
    let mut ies = [0u8; 4 + 28];
    ies[..4].copy_from_slice(&[0xff, 0x02, 0x24, 0x00]);
    ies[4..].copy_from_slice(IES_H1_HE_PPE_NSS1);
    let result = check(&ies, 1, [2, 1, 0, 2, 1]);
    if result != TestResult::Pass {
        return result;
    }
    // Trailing garbage byte after a valid element is ignored.
    let mut ies = [0u8; 28 + 1];
    ies[..28].copy_from_slice(IES_H1_HE_PPE_NSS1);
    ies[28] = 0xff;
    let result = check(&ies, 1, [2, 1, 0, 2, 1]);
    if result != TestResult::Pass {
        return result;
    }
    // A truncated element before the HE cap ends the walk: the
    // cap is never reached, so the pads stay zero.
    let mut ies = [0u8; 4 + 28];
    ies[..4].copy_from_slice(&[0x01, 0x20, 0x82, 0x84]);
    ies[4..].copy_from_slice(IES_H1_HE_PPE_NSS1);
    check(&ies, 1, [0; 5])
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ppe_eht_thresholds);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ppe_he_thresholds);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ppe_nominal_pads);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ppe_no_caps_zero);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ppe_eht_preferred);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_ppe_truncated_fail_closed
);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ppe_nss_out_of_range);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_ppe_walker_robustness);
