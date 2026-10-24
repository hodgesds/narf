// SPDX-License-Identifier: GPL-2.0-or-later
//! Installed API1 AMSS/M3 files are raw ELF images, not API2 IE containers.
//! Only ELF headers survive; no executable segments are present in replays.
use super::{parse_api_n, FwApi, FwError};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

struct MetadataGolden {
    source: &'static str,
    source_sha256: &'static str,
    image_len: usize,
    bytes: &'static [u8],
    fragments: &'static [(usize, usize, usize)],
}
struct RawGolden {
    metadata: MetadataGolden,
}
include!("../../../../verification/data/wifi-firmware/qualcomm/ath11k_raw.rs");

fn smoke_ath11k_installed_raw_images_are_not_api2() -> TestResult {
    for golden in RAW_GOLDENS {
        let metadata = &golden.metadata;
        if !metadata.source.starts_with("ath11k/") || metadata.source_sha256.len() != 64 {
            return TestResult::Fail("ath11k raw image fixture lost source identity");
        }
        let fragments: Vec<_> = metadata
            .fragments
            .iter()
            .map(|&(offset, start, len)| (offset, &metadata.bytes[start..start + len]))
            .collect();
        let bytes =
            match narf_wifi_fixtures::firmware::metadata_replay(metadata.image_len, &fragments) {
                Ok(bytes) => bytes,
                Err(_) => return TestResult::Fail("invalid ath11k raw metadata replay"),
            };
        if parse_api_n(&bytes) != Err(FwError::BadMagic) {
            return TestResult::Fail("ath11k raw image was admitted as an API2 container");
        }
        let (api, error) = FwApi::pre_init(|_| Ok(bytes));
        if api.api_version != 1
            || error != Some(FwError::BadMagic)
            || api.amss().is_some()
            || api.m3().is_some()
            || !api.file.is_empty()
        {
            return TestResult::Fail("ath11k rejected-container fallback retained API2 image data");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_installed_raw_images_are_not_api2
);
