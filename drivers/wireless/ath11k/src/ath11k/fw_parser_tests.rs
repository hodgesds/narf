// SPDX-License-Identifier: GPL-2.0-or-later
//! Authored noncontainer bytes exercise API2 rejection and API1 fallback.
use super::{parse_api_n, FwApi, FwError};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_ath11k_authored_raw_input_keeps_api1_fallback_empty() -> TestResult {
    let mut raw = vec![0; 64];
    raw[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
    if parse_api_n(&raw) != Err(FwError::BadMagic) {
        return TestResult::Fail("ELF magic was admitted as an ath11k API2 container");
    }
    let (api, error) = FwApi::pre_init(|_| Ok(raw));
    if api.api_version != 1
        || error != Some(FwError::BadMagic)
        || api.amss().is_some()
        || api.m3().is_some()
        || !api.file.is_empty()
    {
        return TestResult::Fail("ath11k malformed-container fallback retained image data");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_authored_raw_input_keeps_api1_fallback_empty
);
