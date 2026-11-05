use super::cctl_g7::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw89_cctl_g7_default() -> TestResult {
    // macid 0x2A, MGQ report off. Hand-computed from the
    // Linux literals (fw.c default builder + fw.h masks):
    // c0 = 0x2A | OP(0x80) = 0xAA; w0 = DATARATE 4;
    // m0 = GENMASK(31,20)|GENMASK(18,0) = 0xFFF7FFFF;
    // w1 = 4 | 0xA0000 | 0x40000000 = 0x400A0004;
    // m1 = all ones; w4 = 0xFFFF0000, m4 = 0xFFFFDFFF;
    // w5 = 0x2AA, m5 = 0xFFFF7FFF; w6 = 0xB000,
    // m6 = 0x80FFFFFF; w7 = 0xB8109, m7 = 0xEFFFEFFF;
    // w14/w15 zero, m14 = all ones, m15 = 0x0FFFFFFF;
    // w2/w3/w8 zero with ALL masks; w9..w13/m9..m13 zero.
    let Ok(table) = build_default(0x2A, false) else {
        return TestResult::Fail("cctl g7 rejects valid macid");
    };
    if table.c0 != 0xAA
        || table.w[0] != 4
        || table.m[0] != 0xFFF7_FFFF
        || table.w[1] != 0x400A_0004
        || table.m[1] != 0xFFFF_FFFF
        || table.w[2] != 0
        || table.m[2] != 0xFFFF_FFFF
        || table.w[3] != 0
        || table.m[3] != 0xFFFF_FFFF
        || table.w[4] != 0xFFFF_0000
        || table.m[4] != 0xFFFF_DFFF
        || table.w[5] != 0x2AA
        || table.m[5] != 0xFFFF_7FFF
        || table.w[6] != 0xB000
        || table.m[6] != 0x80FF_FFFF
        || table.w[7] != 0x000B_8109
        || table.m[7] != 0xEFFF_EFFF
        || table.w[8] != 0
        || table.m[8] != 0xFFFF
        || table.w[14] != 0
        || table.m[14] != 0xFFFF_FFFF
        || table.w[15] != 0
        || table.m[15] != 0x0FFF_FFFF
    {
        return TestResult::Fail("cctl g7 default words");
    }
    for i in 9..14 {
        if table.w[i] != 0 || table.m[i] != 0 {
            return TestResult::Fail("cctl g7 untouched words nonzero");
        }
    }
    // MGQ report enable sets only W0 bit 21.
    let Ok(table) = build_default(0x2A, true) else {
        return TestResult::Fail("cctl g7 mgq rejects valid macid");
    };
    if table.w[0] != (4 | (1 << 21)) || table.c0 != 0xAA {
        return TestResult::Fail("cctl g7 mgq word");
    }
    // MAC ID above the 7-bit field is rejected (Linux would
    // truncate bit 7 into the OP bit).
    if build_default(0x80, false).is_ok() || build_default(0xFFFF, false).is_ok() {
        return TestResult::Fail("cctl g7 accepts out-of-field macid");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_cctl_g7_default);
