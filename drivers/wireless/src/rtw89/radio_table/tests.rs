use super::super::radio_tables_b::{BB, GAIN, NCTL, RF_A, RF_B};
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
fn digest(pairs: &[Pair]) -> u64 {
    let mut hash = 14695981039346656037u64;
    for &Pair(address, data) in pairs {
        for byte in address.to_le_bytes().into_iter().chain(data.to_le_bytes()) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1099511628211);
        }
    }
    hash
}
fn smoke_rtw89_b_phy_pair_selection_matches_original_linux_c() -> TestResult {
    let tables = [BB, GAIN, RF_A, RF_B, NCTL];
    for &(index, rfe, cut, count, expected, rejected) in CASES {
        let result = program(tables[index], rfe, cut);
        if rejected {
            if result.is_ok() {
                return TestResult::Fail("rejected Linux PHY package produced a selected program");
            }
        } else {
            match result {
                Ok(pairs) if pairs.len() == count as usize && digest(&pairs) == expected => {}
                _ => {
                    return TestResult::Fail(
                        "full selected B PHY pair stream differs from original Linux C",
                    )
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_phy_pair_selection_matches_original_linux_c
);
fn smoke_rtw89_phy_table_bad_grammar_is_rejected_before_io() -> TestResult {
    let a = Pair(0xf0010000, 0);
    let yes = Pair(0x80010000, 0);
    let check = Pair(0x40000000, 0);
    let reg = Pair(0x10055, 0x12345);
    let end = Pair(0xb0000000, 0);
    if program(&[a, yes, check, reg, end], 1, 0) != Ok(alloc::vec![reg]) {
        return TestResult::Fail("minimal selected PHY pair branch");
    }
    for table in [
        &[][..],
        &[a, yes][..],
        &[a, check][..],
        &[a, yes, reg, end][..],
        &[a, yes, check, yes, check, end][..],
        &[a, yes, check, Pair(0xa0000000, 0)][..],
        &[a, yes, check, end, end][..],
        &[a, yes, check, reg, a, end][..],
    ] {
        if program(table, 1, 0).is_ok() {
            return TestResult::Fail("malformed PHY table yielded successful partial writes");
        }
    }
    if program(&[a, yes, check, reg, end], 5, 0) != Err(Error::Profile) {
        return TestResult::Fail("unsupported RFE selected another board's PHY table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_phy_table_bad_grammar_is_rejected_before_io
);
