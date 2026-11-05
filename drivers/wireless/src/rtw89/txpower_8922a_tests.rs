// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fixture tests for the 8922A TX-power profile parse.
//! Expected values are computed from the Linux
//! `rtw8922a.c` parse functions by hand, never by
//! calling the parse under test.

use super::txpower_8922a::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw89_txpower_8922a_tssi() -> TestResult {
    let path_a = PathEfuse {
        therm: 0x1A,
        cck_tssi: [0x00, 0x01, 0xFF, 0x80, 0x7F, 0x10],
        bw40_tssi: [0x02, 0x03, 0x04, 0x05, 0x06],
        bw40_1s_tssi_5g: [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        ],
        bw40_1s_tssi_6g: [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
            0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F,
        ],
    };
    let path_b = PathEfuse {
        therm: 0x2B,
        ..PathEfuse::default()
    };
    let profile = TssiProfile::parse([path_a, path_b]);
    // Thermal bytes pass through unchanged.
    if profile.thermal(0) != Some(0x1A) || profile.thermal(1) != Some(0x2B) {
        return TestResult::Fail("txpower tssi thermal");
    }
    // CCK bytes reinterpret bit-preserving as i8:
    // 0xFF -> -1, 0x80 -> -128, 0x7F -> 127.
    if profile.cck(0, 0) != Some(0)
        || profile.cck(0, 1) != Some(1)
        || profile.cck(0, 2) != Some(-1)
        || profile.cck(0, 3) != Some(-128)
        || profile.cck(0, 4) != Some(127)
        || profile.cck(0, 5) != Some(0x10)
    {
        return TestResult::Fail("txpower tssi cck");
    }
    // MCS groups 0..5 are the 2.4 GHz array, 5..19 the
    // 5 GHz array, concatenated in that order.
    if profile.mcs(0, 0) != Some(2)
        || profile.mcs(0, 4) != Some(6)
        || profile.mcs(0, 5) != Some(0x10)
        || profile.mcs(0, 18) != Some(0x1D)
    {
        return TestResult::Fail("txpower tssi mcs concat");
    }
    // 6 GHz groups pass through in order.
    if profile.mcs_6g(0, 0) != Some(0x20) || profile.mcs_6g(0, 31) != Some(0x3F) {
        return TestResult::Fail("txpower tssi 6g");
    }
    // Path B defaults to zero throughout.
    if profile.cck(1, 2) != Some(0) || profile.mcs(1, 10) != Some(0) {
        return TestResult::Fail("txpower tssi path b zero");
    }
    // Out-of-range access is None, never a panic.
    if profile.thermal(2).is_some()
        || profile.cck(0, 6).is_some()
        || profile.mcs(0, 19).is_some()
        || profile.mcs_6g(0, 32).is_some()
    {
        return TestResult::Fail("txpower tssi bounds");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_txpower_8922a_tssi);

fn smoke_rtw89_txpower_8922a_gain() -> TestResult {
    // Enum order: 2G CCK/OFDM, 5G low/mid/high, 6G
    // L0/L1/M0/M1/H0/H1/UH0/UH1. Sign-bit bytes convert
    // via (t ^ 0x7F) + 1 wrapping: 0x80 -> 0, 0x81 -> -1,
    // 0xFF -> -127; plain bytes pass through.
    let raw_a: [u8; GAIN_OFFSETS] = [
        0x00, 0x01, 0x7F, 0x80, 0x81, 0xFF, 0x40, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];
    let raw_b: [u8; GAIN_OFFSETS] = [0x10; GAIN_OFFSETS];
    let profile = GainProfile::parse([raw_a, raw_b]);
    if !profile.offset_valid() {
        return TestResult::Fail("txpower gain mixed valid");
    }
    if profile.offset(0, GAIN_2G_CCK) != Some(0)
        || profile.offset(0, GAIN_2G_OFDM) != Some(1)
        || profile.offset(0, GAIN_5G_LOW) != Some(127)
        || profile.offset(0, GAIN_5G_MID) != Some(0)
        || profile.offset(0, GAIN_5G_HIGH) != Some(-1)
        || profile.offset(0, GAIN_6G_L0) != Some(-127)
        || profile.offset(0, GAIN_6G_L1) != Some(64)
        || profile.offset(0, GAIN_6G_UH1) != Some(7)
    {
        return TestResult::Fail("txpower gain transform");
    }
    if profile.offset(1, GAIN_2G_CCK) != Some(0x10) {
        return TestResult::Fail("txpower gain path b");
    }
    // All-0xFF and all-0x00 mean unprogrammed efuse:
    // invalid in both cases, on either path.
    let all_ff = GainProfile::parse([[0xFF; GAIN_OFFSETS]; PATHS]);
    if all_ff.offset_valid() {
        return TestResult::Fail("txpower gain all-ff valid");
    }
    let all_00 = GainProfile::parse([[0x00; GAIN_OFFSETS]; PATHS]);
    if all_00.offset_valid() {
        return TestResult::Fail("txpower gain all-00 valid");
    }
    // One programmed byte on one path is enough: the
    // validity check is over all paths together.
    let mut one = [[0xFF; GAIN_OFFSETS]; PATHS];
    one[1][GAIN_5G_MID] = 0x20;
    if !GainProfile::parse(one).offset_valid() {
        return TestResult::Fail("txpower gain one byte valid");
    }
    if profile.offset(2, 0).is_some() || profile.offset(0, GAIN_OFFSETS).is_some() {
        return TestResult::Fail("txpower gain bounds");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_txpower_8922a_gain);
