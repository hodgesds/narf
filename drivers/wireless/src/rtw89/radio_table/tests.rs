use super::super::radio_tables_a::{BB as BB_A, NCTL as NCTL_A, RF_A as RF_A_A, RF_B as RF_B_A};
use super::super::radio_tables_b::{BB, GAIN, NCTL, RF_A, RF_B};
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
include!("golden_a.rs");
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
fn smoke_rtw89_b_phy_pair_selection_matches_frozen_references() -> TestResult {
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
                        "full selected B PHY pair stream differs from the frozen reference",
                    )
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_phy_pair_selection_matches_frozen_references
);
fn smoke_rtw89_a_phy_pair_selection_matches_frozen_references() -> TestResult {
    if BB_A.len() != 1267 || RF_A_A.len() != 28869 || RF_B_A.len() != 29126 || NCTL_A.len() != 1036
    {
        return TestResult::Fail("RTL8852A PHY table lengths differ");
    }
    if BB_A[0] != Pair(0xf0ff0001, 0)
        || BB_A[BB_A.len() - 1] != Pair(0xf8, 0x20201013)
        || RF_A_A[0] != Pair(0xf0010000, 0)
        || RF_A_A[1] != Pair(0xf0010001, 1)
        || RF_A_A[RF_A_A.len() - 1] != Pair(0x67, 0x56)
        || RF_B_A[RF_B_A.len() - 1] != Pair(0x67, 0x56)
        || NCTL_A[0] != Pair(0x8000, 0x8)
        || NCTL_A[NCTL_A.len() - 1] != Pair(0x8088, 0x0)
    {
        return TestResult::Fail("RTL8852A PHY table anchors differ");
    }
    let tables = [BB_A, RF_A_A, RF_B_A, NCTL_A];
    for &(index, rfe, cut, count, expected, rejected) in A_CASES {
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
                        "full selected A PHY pair stream differs from the frozen reference",
                    )
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_phy_pair_selection_matches_frozen_references
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
