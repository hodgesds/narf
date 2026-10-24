use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
fn flatten(gain: &Gain) -> Vec<i8> {
    let mut result = Vec::new();
    for band in 0..8 {
        for path in 0..2 {
            result.extend_from_slice(&gain.lna[band][path]);
            result.extend_from_slice(&gain.tia[band][path]);
            result.extend_from_slice(&gain.bypass[band][path]);
            result.extend_from_slice(&gain.lna_op1db[band][path]);
            result.extend_from_slice(&gain.tia_op1db[band][path]);
            result.push(gain.rpl20[band][path]);
            result.extend_from_slice(&gain.rpl40[band][path]);
            result.extend_from_slice(&gain.rpl80[band][path]);
            result.extend_from_slice(&gain.rpl160[band][path]);
        }
    }
    result
}
fn smoke_rtw89_b_gain_state_matches_original_linux_signed_callbacks() -> TestResult {
    let gain = Gain::decode(super::super::radio_tables_b::GAIN, 1).unwrap();
    if flatten(&gain) != DEFAULT {
        return TestResult::Fail("real B gain table differs from original Linux state");
    }
    let gain = Gain::decode(SYNTH, 1).unwrap();
    if flatten(&gain) != EXPECTED {
        return TestResult::Fail(
            "packed gain fields/s8 offsets differ from original Linux callbacks",
        );
    }
    for pair in [
        Pair(0x00000200, 0),
        Pair(0x00080000, 0),
        Pair(0, 0),
        Pair(0x000000f9, 0),
        Pair(0x04000000, 0),
    ] {
        if pair.0 == 0 {
            continue;
        }
        if Gain::decode(&[pair], 50).is_ok() {
            return TestResult::Fail("unsupported gain layout/RFE accepted before PHY programming");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_gain_state_matches_original_linux_signed_callbacks
);
