// SPDX-License-Identifier: GPL-2.0-or-later
//! Structural replays of independently extracted installed firmware metadata.
//! Firmware, OTP and calibration bytes are zeroed; never boot these replays.
use super::{select_board, Error, Image};
use alloc::{string::String, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct MetadataGolden {
    source: &'static str,
    source_sha256: &'static str,
    image_len: usize,
    bytes: &'static [u8],
    fragments: &'static [(usize, usize, usize)],
}
struct ImageGolden {
    metadata: MetadataGolden,
    api: u8,
    features: u64,
    wmi: u32,
    htt: u32,
    image: (usize, usize),
    otp: (usize, usize),
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

include!("../../../../verification/data/wifi-firmware/qualcomm/ath10k_firmware.rs");
include!("../../../../verification/data/wifi-firmware/qualcomm/ath10k_board.rs");

fn replay(golden: &MetadataGolden) -> Result<Vec<u8>, &'static str> {
    if !golden.source.starts_with("ath10k/") || golden.source_sha256.len() != 64 {
        return Err("Qualcomm metadata fixture lost source identity");
    }
    let fragments: Vec<_> = golden
        .fragments
        .iter()
        .map(|&(offset, start, len)| (offset, &golden.bytes[start..start + len]))
        .collect();
    narf_wifi_fixtures::firmware::metadata_replay(golden.image_len, &fragments)
        .map_err(|_| "invalid Qualcomm metadata replay fragments")
}

fn smoke_ath10k_installed_firmware_metadata_replays() -> TestResult {
    for golden in IMAGE_GOLDENS {
        let bytes = match replay(&golden.metadata) {
            Ok(bytes) => bytes,
            Err(message) => return TestResult::Fail(message),
        };
        let parsed = match Image::parse(bytes, golden.api) {
            Ok(parsed) => parsed,
            Err(_) => return TestResult::Fail("installed ath10k firmware metadata rejected"),
        };
        if parsed.api != golden.api
            || parsed.features != golden.features
            || parsed.wmi != golden.wmi
            || parsed.htt != golden.htt
            || parsed.image != (golden.image.0..golden.image.0 + golden.image.1)
            || parsed.otp != Some(golden.otp.0..golden.otp.0 + golden.otp.1)
            || parsed.codeswap.is_some()
        {
            return TestResult::Fail("installed ath10k metadata facts changed");
        }
        if parsed.image().iter().any(|&byte| byte != 0)
            || parsed
                .otp()
                .is_none_or(|otp| otp.iter().any(|&byte| byte != 0))
        {
            return TestResult::Fail("ath10k structural replay retained opaque payload");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k",
    smoke_ath10k_installed_firmware_metadata_replays
);

fn smoke_ath10k_installed_board_metadata_replays() -> TestResult {
    for golden in BOARD_GOLDENS {
        let mut bytes = match replay(&golden.metadata) {
            Ok(bytes) => bytes,
            Err(message) => return TestResult::Fail(message),
        };
        for sample in golden.samples {
            let names = [String::from(sample.name)];
            let selected = match select_board(&bytes, &names, sample.kind == 1) {
                Ok(selected) => selected,
                Err(_) => return TestResult::Fail("installed ath10k board identity not found"),
            };
            if selected.len() != sample.len
                || selected.as_ptr() != bytes[sample.offset..].as_ptr()
                || selected.iter().any(|&byte| byte != 0)
            {
                return TestResult::Fail("ath10k board selection geometry changed");
            }
            let missing = [String::from(sample.name) + ",variant=not-in-this-corpus"];
            if select_board(&bytes, &missing, sample.kind == 1) != Err(Error::BoardNotFound) {
                return TestResult::Fail("ath10k board selection accepted an unlisted identity");
            }
        }
        bytes.pop();
        if select_board(&bytes, &[String::from(golden.samples[0].name)], false)
            != Err(Error::InvalidContainer)
        {
            return TestResult::Fail("ath10k board replay truncation admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k",
    smoke_ath10k_installed_board_metadata_replays
);
