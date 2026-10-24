// SPDX-License-Identifier: GPL-2.0-or-later
//! This real BCM43602 metadata has no optional RAM-size marker and no TRX
//! wrapper. Its sparse replay proves parser behavior, never board admission.
use super::{embedded_ramsize, TrxHeader, FW_RAMSIZE_OFFSET};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

include!("../../../../verification/data/wifi-firmware/broadcom/goldens.rs");

fn smoke_brcmfmac_installed_bcm43602_metadata_replay() -> TestResult {
    if SOURCE != "brcm/brcmfmac43602-pcie.bin" || SOURCE_SHA256.len() != 64 {
        return TestResult::Fail("BCM43602 metadata fixture lost source identity");
    }
    let fragments: Vec<_> = FRAGMENTS
        .iter()
        .map(|&(offset, start, len)| (offset, &METADATA[start..start + len]))
        .collect();
    let bytes = match narf_wifi_fixtures::firmware::metadata_replay(IMAGE_LEN, &fragments) {
        Ok(bytes) => bytes,
        Err(_) => return TestResult::Fail("invalid BCM43602 metadata replay"),
    };
    let reset_vector = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    if reset_vector != RESET_VECTOR_WORD
        || embedded_ramsize(&bytes) != RAMSIZE
        || TrxHeader::parse(&bytes).is_some()
    {
        return TestResult::Fail("BCM43602 observed raw-image/RAM metadata facts changed");
    }
    if embedded_ramsize(&bytes[..FW_RAMSIZE_OFFSET + 7]).is_some()
        || bytes[4..FW_RAMSIZE_OFFSET].iter().any(|&byte| byte != 0)
        || bytes[FW_RAMSIZE_OFFSET + 8..].iter().any(|&byte| byte != 0)
    {
        return TestResult::Fail("BCM43602 replay retained executable payload or short metadata");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_installed_bcm43602_metadata_replay
);
