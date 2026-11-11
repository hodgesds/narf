// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852A DIG gain tables (`rtw8852a_phy_dig_table`, rtw8852a.c):
//! `struct rtw89_reg_def` (register, mask) pairs the DIG loop reads via
//! `rtw89_phy_read32_idx` with the PHY_0 stride; the tables carry PHY_0
//! addresses. A is the only AX chip with a `.dig_table` (B/C/51B carry
//! NULL). No consumer yet: the DIG `prepare` in `phy_operating.rs` is
//! B/51B-gated and C has `prepare_c`; an A `prepare_a` that reads these
//! is follow-up work.

/// `rtw89_8852a_lna_gain_g_table` (7 entries).
pub(super) const LNA_GAIN_G: &[(u32, u32)] = &[
    (0x462c, 0x3f000),
    (0x4630, 0x3f),
    (0x4630, 0xfc0000),
    (0x4634, 0xfc0),
    (0x4634, 0x3f000000),
    (0x4638, 0x3f000),
    (0x463c, 0x3f),
];
/// `rtw89_8852a_tia_gain_g_table` (2 entries).
pub(super) const TIA_GAIN_G: &[(u32, u32)] = &[(0x4640, 0xfc0000), (0x4644, 0xfc0)];
/// `rtw89_8852a_lna_gain_a_table` (7 entries).
pub(super) const LNA_GAIN_A: &[(u32, u32)] = &[
    (0x462c, 0xfc0),
    (0x462c, 0x3f000000),
    (0x4630, 0x3f000),
    (0x4634, 0x3f),
    (0x4634, 0xfc0000),
    (0x4638, 0xfc0),
    (0x4638, 0x3f000000),
];
/// `rtw89_8852a_tia_gain_a_table` (2 entries).
pub(super) const TIA_GAIN_A: &[(u32, u32)] = &[(0x4640, 0x3f000), (0x4644, 0x3f)];

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_rtw89_a_dig_gain_tables_match_rtw8852a() -> TestResult {
        if LNA_GAIN_G.len() != 7
            || TIA_GAIN_G.len() != 2
            || LNA_GAIN_A.len() != 7
            || TIA_GAIN_A.len() != 2
        {
            return TestResult::Fail("RTL8852A DIG gain table lengths differ");
        }
        if LNA_GAIN_G
            != [
                (0x462c, 0x3f000),
                (0x4630, 0x3f),
                (0x4630, 0xfc0000),
                (0x4634, 0xfc0),
                (0x4634, 0x3f000000),
                (0x4638, 0x3f000),
                (0x463c, 0x3f),
            ]
            || TIA_GAIN_G != [(0x4640, 0xfc0000), (0x4644, 0xfc0)]
            || LNA_GAIN_A
                != [
                    (0x462c, 0xfc0),
                    (0x462c, 0x3f000000),
                    (0x4630, 0x3f000),
                    (0x4634, 0x3f),
                    (0x4634, 0xfc0000),
                    (0x4638, 0xfc0),
                    (0x4638, 0x3f000000),
                ]
            || TIA_GAIN_A != [(0x4640, 0x3f000), (0x4644, 0x3f)]
        {
            return TestResult::Fail("RTL8852A DIG gain table entries differ");
        }
        // Every mask is a single contiguous GENMASK field.
        for table in [LNA_GAIN_G, TIA_GAIN_G, LNA_GAIN_A, TIA_GAIN_A] {
            for &(_, mask) in table {
                if mask == 0
                    || mask.count_ones() != 32 - mask.leading_zeros() - mask.trailing_zeros()
                {
                    return TestResult::Fail("RTL8852A DIG gain mask is not a GENMASK field");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_a_dig_gain_tables_match_rtw8852a
    );
}
