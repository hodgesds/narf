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

fn smoke_rtw89_cctl_g7_ampdu() -> TestResult {
    // Bucket edges, hand-computed from the Linux thresholds:
    // <= 0x20 -> 3, <= 0x40 -> 0, <= 0x80 -> 1, <= 0x100 -> 2,
    // <= 0x200 -> 4, <= 0x400 -> 5, above -> 0. w3 = bmap << 12,
    // m3 = GENMASK(14, 12) = 0x7000; c0 = macid | OP(0x80).
    let cases: [(u16, u32); 7] = [
        (0x10, 0x3000),
        (0x21, 0x0000),
        (0x41, 0x1000),
        (0x81, 0x2000),
        (0x101, 0x4000),
        (0x201, 0x5000),
        (0x401, 0x0000),
    ];
    for (agg, w3) in cases {
        let Ok(table) = build_ampdu(0x05, &[agg]) else {
            return TestResult::Fail("cctl g7 ampdu rejects valid macid");
        };
        if table.c0 != 0x85 || table.w[3] != w3 || table.m[3] != 0x7000 {
            return TestResult::Fail("cctl g7 ampdu words");
        }
        for i in 0..16 {
            if i != 3 && (table.w[i] != 0 || table.m[i] != 0) {
                return TestResult::Fail("cctl g7 ampdu touches extra words");
            }
        }
    }
    // Minimum across TIDs, not the first: [0x41, 0x30] -> 0x30 -> 0.
    let Ok(table) = build_ampdu(0x05, &[0x41, 0x30]) else {
        return TestResult::Fail("cctl g7 ampdu min rejects");
    };
    if table.w[3] != 0 || table.m[3] != 0x7000 {
        return TestResult::Fail("cctl g7 ampdu min across TIDs");
    }
    // Empty slice = no active session = agg 0 -> bucket 3.
    let Ok(table) = build_ampdu(0x05, &[]) else {
        return TestResult::Fail("cctl g7 ampdu empty rejects");
    };
    if table.w[3] != 0x3000 {
        return TestResult::Fail("cctl g7 ampdu empty slice bucket");
    }
    if build_ampdu(0x80, &[0x10]).is_ok() {
        return TestResult::Fail("cctl g7 ampdu accepts out-of-field macid");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_cctl_g7_ampdu);

fn smoke_rtw89_cctl_g7_txtime() -> TestResult {
    // Time-only: w3 AMPDU_TIME_SEL (bit 28), w2 MAX_TIME 0xA << 28.
    let Ok(table) = build_txtime(0x05, Some(0xA), None) else {
        return TestResult::Fail("cctl g7 txtime time rejects");
    };
    if table.c0 != 0x85
        || table.w[3] != 0x1000_0000
        || table.m[3] != 0x1000_0000
        || table.w[2] != 0xA000_0000
        || table.m[2] != 0xF000_0000
    {
        return TestResult::Fail("cctl g7 txtime time words");
    }
    // Retry-only: w2 SEL (bit 6) | limit 0x2A; mask SEL | GENMASK(5, 0).
    let Ok(table) = build_txtime(0x05, None, Some(0x2A)) else {
        return TestResult::Fail("cctl g7 txtime retry rejects");
    };
    if table.w[2] != 0x6A || table.m[2] != 0x7F || table.w[3] != 0 || table.m[3] != 0 {
        return TestResult::Fail("cctl g7 txtime retry words");
    }
    // Both gates: masks OR, values OR.
    let Ok(table) = build_txtime(0x05, Some(0xF), Some(0x3F)) else {
        return TestResult::Fail("cctl g7 txtime both rejects");
    };
    if table.w[2] != 0xF000_007F
        || table.m[2] != 0xF000_007F
        || table.w[3] != 0x1000_0000
        || table.m[3] != 0x1000_0000
    {
        return TestResult::Fail("cctl g7 txtime both words");
    }
    // Neither gate: all words zero, only c0 set.
    let Ok(table) = build_txtime(0x05, None, None) else {
        return TestResult::Fail("cctl g7 txtime none rejects");
    };
    if table.w.iter().any(|w| *w != 0) || table.m.iter().any(|m| *m != 0) {
        return TestResult::Fail("cctl g7 txtime none touches words");
    }
    // Out-of-field values rejected, not truncated.
    if build_txtime(0x05, Some(0x10), None).is_ok()
        || build_txtime(0x05, None, Some(0x40)).is_ok()
        || build_txtime(0x80, None, None).is_ok()
    {
        return TestResult::Fail("cctl g7 txtime accepts out-of-field value");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_cctl_g7_txtime);

fn smoke_rtw89_cctl_g7_punctured() -> TestResult {
    // w4 = ~punctured in the 16-bit subchannel field; m4 = field mask.
    let cases: [(u16, u32); 3] = [
        (0x0000, 0xFFFF_0000),
        (0xFFFF, 0x0000_0000),
        (0x00F0, 0xFF0F_0000),
    ];
    for (punctured, w4) in cases {
        let Ok(table) = build_punctured(0x05, punctured) else {
            return TestResult::Fail("cctl g7 punctured rejects");
        };
        if table.c0 != 0x85 || table.w[4] != w4 || table.m[4] != 0xFFFF_0000 {
            return TestResult::Fail("cctl g7 punctured words");
        }
        for i in 0..16 {
            if i != 4 && (table.w[i] != 0 || table.m[i] != 0) {
                return TestResult::Fail("cctl g7 punctured touches extra words");
            }
        }
    }
    if build_punctured(0x80, 0x0000).is_ok() {
        return TestResult::Fail("cctl g7 punctured accepts out-of-field macid");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_cctl_g7_punctured);
