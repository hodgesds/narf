// SPDX-License-Identifier: GPL-2.0-or-later
//! Authored board/REGDB IEs, with distinguishable inert payloads.
use super::{fetch_board_data_api_n, BoardError};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn ie(out: &mut Vec<u8>, id: u32, payload: &[u8]) {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out.resize(out.len().next_multiple_of(4), 0);
}
fn smoke_ath11k_authored_board_and_regdb_selection_bounds() -> TestResult {
    let mut bytes = b"QCA-ATH11K-BOARD\0".to_vec();
    bytes.resize(20, 0);
    for (kind, payload) in [(0, &[1, 2, 3][..]), (1, &[4, 5][..])] {
        let mut nested = Vec::new();
        ie(&mut nested, 0, b"rust-board");
        ie(&mut nested, 1, payload);
        ie(&mut bytes, kind, &nested);
    }
    for (kind, offset, payload) in [(0, 56, &[1, 2, 3][..]), (1, 96, &[4, 5][..])] {
        if fetch_board_data_api_n(&bytes, b"rust-board", kind, 0, 1) != Ok((offset, payload.len()))
            || &bytes[offset..offset + payload.len()] != payload
            || fetch_board_data_api_n(&bytes, b"rust-boar", kind, 0, 1) != Err(BoardError::NoData)
            || !matches!(
                fetch_board_data_api_n(
                    &bytes[..offset + payload.len() - 1],
                    b"rust-board",
                    kind,
                    0,
                    1
                ),
                Err(BoardError::BadIeLength { .. })
            )
        {
            return TestResult::Fail("ath11k exact identity, BOARD/REGDB kind or declared extent");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_authored_board_and_regdb_selection_bounds
);
