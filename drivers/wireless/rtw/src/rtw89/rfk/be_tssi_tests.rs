use super::super::super::operating_channel_c::Width;
use super::super::super::txpower_8922a::PathEfuse;
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Synthetic TXPWR_TRK element (id 18): bitmap 0xffff, then 36 rows
/// of 30 bytes. All rows are 5 except the 2G rows (row 30 = down
/// 30..59, row 31 = up 0..29), which pin the table walk and the
/// 4-byte reversal.
fn tracking_element() -> [u8; 1088] {
    let mut element = [5u8; 1088];
    element[0] = 0xff;
    element[1] = 0xff;
    element[2] = 0;
    element[3] = 0;
    for (i, slot) in element.iter_mut().skip(8 + 30 * 30).take(30).enumerate() {
        *slot = 30 + i as u8;
    }
    for (i, slot) in element.iter_mut().skip(8 + 31 * 30).take(30).enumerate() {
        *slot = i as u8;
    }
    element
}

fn profile() -> TssiProfile {
    let a = PathEfuse {
        therm: 0x20,
        cck_tssi: [10, 20, 30, 40, 50, 60],
        bw40_tssi: [1, 2, 3, 4, 5],
        bw40_1s_tssi_5g: [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
        bw40_1s_tssi_6g: [
            20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
            42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
        ],
    };
    let b = PathEfuse {
        therm: 0xff,
        cck_tssi: [110, 120, 130, 140, 150, 160],
        bw40_tssi: [101, 102, 103, 104, 105],
        bw40_1s_tssi_5g: [
            106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
        ],
        bw40_1s_tssi_6g: [
            120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136,
            137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151,
        ],
    };
    TssiProfile::parse([a, b])
}

fn smoke_rtw89_be_tssi_h2c_body() -> TestResult {
    let Ok(tracking) = Tracking::parse(&tracking_element()) else {
        return TestResult::Fail("BE TSSI tracking element refused");
    };
    let profile = profile();
    let inputs = Inputs {
        profile: &profile,
        trim: [[0; 8]; 2],
        trim_6g: [[0; 16]; 2],
        tracking: &tracking,
        rfe_type: 0x5a,
        cv: 0,
    };
    // 2.4GHz ch1 20MHz: CCK group 0 (10), OFDM group 0 (1), trim 0.
    let Some(ch1) = Profile::new20(Band::Ghz2, 1) else {
        return TestResult::Fail("2.4GHz ch1 profile refused");
    };
    let body = build(ch1, TssiMode::Normal, &inputs);
    if body[0..2] != [44, 1]
        || body[2] != 0
        || body[3] != 1
        || body[4] != 0
        || body[5] != 0
        || body[6] != 1
        || body[7] != 0
    {
        return TestResult::Fail("BE TSSI header differs from rtw89_h2c_rf_tssi");
    }
    // Path A DE slots: CCK 10, OFDM 1, trim 0, thermal 0x20.
    if body[8] != 0
        || body[10] != 10
        || body[12] != 10
        || body[14] != 10
        || body[16] != 0
        || body[18] != 1
        || body[20] != 1
        || body[22] != 1
        || body[24] != 1
        || body[26] != 1
        || body[28] != 1
        || body[30..38] != [0; 8]
        || body[38] != 0
        || body[40] != 0x20
    {
        return TestResult::Fail("BE TSSI path-A DE slots differ from the efuse fill");
    }
    // Path A thermal table: up ramp 0..29 clamped at 29, down ramp
    // -31..-59 clamped at -59, each 4-byte group byte-reversed.
    if body[42..46] != [3, 2, 1, 0]
        || body[102..106] != [29, 29, 29, 29]
        || body[106..110] != [197, 197, 197, 197]
        || body[166..170] != [225, 224, 223, 222]
    {
        return TestResult::Fail("BE TSSI path-A thermal table differs from the tmeter fill");
    }
    // Path B: CCK 110, OFDM 101, thermal 0xFF -> pg 0x38, zero table.
    if body[9] != 0
        || body[11] != 110
        || body[13] != 110
        || body[15] != 110
        || body[17] != 0
        || body[19] != 101
        || body[21] != 101
        || body[23] != 101
        || body[25] != 101
        || body[27] != 101
        || body[29] != 101
        || body[39] != 0
        || body[41] != 0x38
        || body[170..298] != [0u8; 128]
    {
        return TestResult::Fail("BE TSSI path-B 0xFF-thermal branch differs");
    }
    if body[298] != 0 || body[299] != 0x5a {
        return TestResult::Fail("BE TSSI mode/RFE tail differs");
    }
    // 5GHz 80MHz primary 44 (center 42): OFDM extra group 5 averages
    // MCS 6 and 7 -> 6; CCK group defaults to 0 -> 10.
    let Some(wide) = Profile::new_wide(Band::Ghz5, 44, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile refused");
    };
    let body = build(wide, TssiMode::Scan, &inputs);
    if body[3] != 42
        || body[4] != 2
        || body[5] != 1
        || body[10] != 10
        || body[18] != 6
        || body[28] != 6
        || body[298] != 1
    {
        return TestResult::Fail("BE TSSI 5GHz extra-group average differs");
    }
    // 5GHz subband 1 rows are the constant 5s: table [5; 64, 251; 64].
    if body[42..106] != [5u8; 64] || body[106..170] != [251u8; 64] {
        return TestResult::Fail("BE TSSI 5GHz thermal table differs");
    }
    // 6GHz ch37 20MHz: 6G OFDM group 4 -> MCS 24; 6G trim group 2 -> 0.
    let Some(six) = Profile::new20(Band::Ghz6, 37) else {
        return TestResult::Fail("6GHz ch37 profile refused");
    };
    let body = build(six, TssiMode::Normal, &inputs);
    if body[3] != 37
        || body[4] != 0
        || body[5] != 2
        || body[10] != 10
        || body[18] != 24
        || body[28] != 24
    {
        return TestResult::Fail("BE TSSI 6GHz group differs");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_be_tssi_h2c_body);
