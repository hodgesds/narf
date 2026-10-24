// SPDX-License-Identifier: GPL-2.0-or-later
//! Board identities and IE geometry from installed board-2.bin files.
//! Calibration/REGDB payload is zeroed, so selection proves no board policy.
use super::{fetch_board_data_api_n, BoardError};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

struct MetadataGolden {
    source: &'static str,
    source_sha256: &'static str,
    image_len: usize,
    bytes: &'static [u8],
    fragments: &'static [(usize, usize, usize)],
}
struct BoardSample {
    kind: u32,
    name: &'static str,
    offset: usize,
    len: usize,
}
struct BoardGolden {
    metadata: MetadataGolden,
    samples: &'static [BoardSample],
}
include!("../../../../verification/data/wifi-firmware/qualcomm/ath11k_board.rs");

fn smoke_ath11k_installed_board_metadata_replays() -> TestResult {
    for golden in BOARD_GOLDENS {
        let metadata = &golden.metadata;
        if !metadata.source.starts_with("ath11k/") || metadata.source_sha256.len() != 64 {
            return TestResult::Fail("ath11k board fixture lost source identity");
        }
        let fragments: Vec<_> = metadata
            .fragments
            .iter()
            .map(|&(offset, start, len)| (offset, &metadata.bytes[start..start + len]))
            .collect();
        let bytes =
            match narf_wifi_fixtures::firmware::metadata_replay(metadata.image_len, &fragments) {
                Ok(bytes) => bytes,
                Err(_) => return TestResult::Fail("invalid ath11k board metadata replay"),
            };
        for sample in golden.samples {
            let selected =
                fetch_board_data_api_n(&bytes, sample.name.as_bytes(), sample.kind, 0, 1);
            if selected != Ok((sample.offset, sample.len))
                || bytes[sample.offset..sample.offset + sample.len]
                    .iter()
                    .any(|&byte| byte != 0)
            {
                return TestResult::Fail("ath11k installed board/REGDB selection geometry changed");
            }
            // Exact identity and top-level BOARD/REGDB kind remain independent.
            if fetch_board_data_api_n(&bytes, b"bus=pci,not-in-this-corpus", sample.kind, 0, 1)
                != Err(BoardError::NoData)
            {
                return TestResult::Fail("ath11k accepted an unlisted board identity");
            }
        }
        let sample = &golden.samples[0];
        // Cut inside the selected real calibration extent. Its declared top-
        // level length must fail before any returned range can escape the file.
        if !matches!(
            fetch_board_data_api_n(
                &bytes[..sample.offset + sample.len - 1],
                sample.name.as_bytes(),
                sample.kind,
                0,
                1,
            ),
            Err(BoardError::BadIeLength { .. })
        ) {
            return TestResult::Fail("ath11k admitted a truncated board IE");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_installed_board_metadata_replays
);
