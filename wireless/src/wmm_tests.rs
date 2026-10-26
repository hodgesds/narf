use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
const PARAMETERS: [u8; 26] = [
    221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x8b, 0, 0x62, 0x32, 47, 0, 0x03, 0xa4, 0, 0, 0x42, 0x43, 94,
    0, 0x27, 0xa4, 0, 0,
];
fn wmm_native_literal_rows_and_protocol_policy_separation() -> TestResult {
    let p = match Parameters::parse(&PARAMETERS) {
        Ok(Some(p)) => p,
        _ => return TestResult::Fail("literal WMM Parameter rejected"),
    };
    if p.parameter_set_count != 11
        || !p.uapsd
        || p.ac
            .map(|a| (a.aifsn, a.cw_min(), a.cw_max(), a.txop, a.admission_control))
            != [
                (3, 15, 1023, 0, false),
                (7, 15, 1023, 0, false),
                (2, 7, 15, 94, false),
                (2, 3, 7, 47, false),
            ]
        || Parameters::parse(&INFORMATION) != Ok(None)
    {
        return TestResult::Fail("WMM ACI mapping, source units or AP facts changed");
    }
    let mut zero_acm = PARAMETERS;
    zero_acm[14] |= 16;
    zero_acm[15] = 0xf0;
    if Parameters::parse(&zero_acm).ok().flatten().is_none_or(|p| {
        !p.ac[0].admission_control || p.ac[0].cw_min() != 0 || p.ac[0].cw_max() != 32767
    }) {
        return TestResult::Fail(
            "protocol parser invented BE admission or rejected representable ECW0/15",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/wmm",
    wmm_native_literal_rows_and_protocol_policy_separation
);
fn wmm_native_bounds_duplicates_and_reserved_fields() -> TestResult {
    for end in 1..PARAMETERS.len() {
        if Parameters::parse(&PARAMETERS[..end]).is_ok() {
            return TestResult::Fail("truncated WMM accepted");
        }
    }
    for (offset, value) in [
        (6, 2),
        (7, 2),
        (8, 0x10),
        (9, 1),
        (10, 0xe2),
        (10, 0x61),
        (11, 0x23),
        (22, 3),
    ] {
        let mut bad = PARAMETERS;
        bad[offset] = value;
        if Parameters::parse(&bad).is_ok() {
            return TestResult::Fail("invalid WMM subtype/version/reserved/ACI/ECW accepted");
        }
    }
    let mut duplicate = PARAMETERS.to_vec();
    duplicate.extend_from_slice(&INFORMATION);
    if Parameters::parse(&duplicate) != Err(Error::Duplicate)
        || Parameters::parse(&vec![0; 4097]) != Err(Error::Bounds)
    {
        return TestResult::Fail("WMM singleton/maximum extent bypassed");
    }
    // Other vendor IEs cannot select WMM, including a close but distinct OUI.
    let mut other = PARAMETERS;
    other[4] ^= 1;
    if Parameters::parse(&other) != Ok(None) || Parameters::parse(&[]) != Ok(None) {
        return TestResult::Fail("foreign vendor or absent WMM promoted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/wmm",
    wmm_native_bounds_duplicates_and_reserved_fields
);
