// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852A DIG gain tables (`rtw8852a_phy_dig_table`, rtw8852a.c):
//! `struct rtw89_reg_def` (register, mask) pairs the DIG loop reads via
//! `rtw89_phy_read32_idx` with the PHY_0 stride; the tables carry PHY_0
//! addresses. A is the only AX chip with a `.dig_table` (B/C/51B carry
//! NULL). Early A cuts read these actual values during DIG initialization.

pub(in crate::rtw89) const RECIPE:&[u8]=b"RTL8852A exact DIG gain init v1; actual corrected cut<=CBV support_igi, IB4628bits11:6 >>2 sign8, PBK4650bits14:10; source four gain tables masked6bit >>2 sign4 +LNA-24/TIA16G12A +8perentry; source reset maxLNA6 TIA1 RXB31 on exact A paired fields before dynamic PD/PAGC init; retained actual read values, no B defaults; cut>CBV no IGI reads/writes; actual A CFO xtal_info direct0280 XO23:17 XI16:10, never B SI5/4";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Gains {
    pub ib_pkpwr: i8,
    pub ib_pbk: u8,
    pub lna_g: [i8; 7],
    pub tia_g: [i8; 2],
    pub lna_a: [i8; 7],
    pub tia_a: [i8; 2],
}
impl Gains {
    /// `rtw89_phy_dig_update_gain_para`, after actual BB tables. The caller
    /// supplies masked reads enclosed by its current original source scopes.
    pub fn read(
        mut read: impl FnMut(u32, u32) -> Result<u32, super::rfk::Error>,
    ) -> Result<Self, super::rfk::Error> {
        let ib_pkpwr = ((read(0x4628, 0xfc0)? >> 2) as u8) as i8;
        let ib_pbk = read(0x4650, 0x7c00)? as u8;
        fn table<const N: usize>(
            read: &mut impl FnMut(u32, u32) -> Result<u32, super::rfk::Error>,
            fields: &[(u32, u32)],
            base: i8,
        ) -> Result<[i8; N], super::rfk::Error> {
            let mut out = [0; N];
            for (i, &(address, mask)) in fields.iter().enumerate() {
                let raw = (read(address, mask)? >> 2) as u8;
                let signed = ((raw << 4) as i8) >> 4;
                out[i] = signed + base + (i as i8) * 8;
            }
            Ok(out)
        }
        Ok(Self {
            ib_pkpwr,
            ib_pbk,
            lna_g: table(&mut read, LNA_GAIN_G, -24)?,
            tia_g: table(&mut read, TIA_GAIN_G, 16)?,
            lna_a: table(&mut read, LNA_GAIN_A, -24)?,
            tia_a: table(&mut read, TIA_GAIN_A, 12)?,
        })
    }
}
/// Source `rtw89_phy_dig_set_igi_cr`: write each path in LNA, TIA, RXB order.
pub(super) const MAX_GAIN_WRITES: &[(u32, u32, u32)] = &[
    (0x4668, 0x0700_0000, 6),
    (0x473c, 0x0700_0000, 6),
    (0x4674, 0x0002_0000, 1),
    (0x4748, 0x0002_0000, 1),
    (0x4658, 0x3e0, 31),
    (0x472c, 0x3e0, 31),
];

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
    fn smoke_rtw8852a_dig_reads_actual_ib_and_signed_gain_fields() -> TestResult {
        let mut reads = alloc::vec::Vec::new();
        let gains = Gains::read(|address, mask| {
            reads.push((address, mask));
            Ok(if (address, mask) == (0x4650, 0x7c00) {
                31
            } else {
                60
            })
        })
        .unwrap();
        if gains.ib_pkpwr != 15
            || gains.ib_pbk != 31
            || gains.lna_g != [-25, -17, -9, -1, 7, 15, 23]
            || gains.lna_a != [-25, -17, -9, -1, 7, 15, 23]
            || gains.tia_g != [15, 23]
            || gains.tia_a != [11, 19]
            || reads.len() != 20
            || reads[..2] != [(0x4628, 0xfc0), (0x4650, 0x7c00)]
        {
            return TestResult::Fail("A actual IB/sign4/gain-base source decode differs");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw8852a_dig_reads_actual_ib_and_signed_gain_fields
    );
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
