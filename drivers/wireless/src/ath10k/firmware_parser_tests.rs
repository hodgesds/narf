// SPDX-License-Identifier: GPL-2.0-or-later
//! Small authored IE containers; no captured firmware or calibration data.
use super::{select_board, Error, Image};
use alloc::{string::String, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

fn ie(out: &mut Vec<u8>, id: u32, payload: &[u8]) {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out.resize(out.len().next_multiple_of(4), 0);
}
fn image() -> Vec<u8> {
    let mut bytes = b"QCA-ATH10K\0\0".to_vec();
    ie(&mut bytes, 2, &[1, 2]);
    ie(&mut bytes, 3, &[0x11, 0x22, 0x33]);
    ie(&mut bytes, 4, &[0x44, 0x55]);
    ie(&mut bytes, 5, &5u32.to_le_bytes());
    ie(&mut bytes, 6, &2u32.to_le_bytes());
    ie(&mut bytes, 0xffff, &[0x66]);
    bytes
}
fn smoke_ath10k_authored_firmware_api_and_ie_boundaries() -> TestResult {
    let bytes = image();
    for api in 2..=6 {
        let parsed = Image::parse(bytes.clone(), api).unwrap();
        if parsed.api != api
            || parsed.features != 0x201
            || parsed.wmi != 5
            || parsed.htt != 2
            || parsed.image() != [0x11, 0x22, 0x33]
            || parsed.otp() != Some(&[0x44, 0x55][..])
            || parsed.codeswap.is_some()
        {
            return TestResult::Fail("authored ath10k API, flags or IE payload boundaries");
        }
    }
    for end in [0, 10, bytes.len() - 1] {
        if !matches!(
            Image::parse(bytes[..end].to_vec(), 6),
            Err(Error::InvalidContainer)
        ) {
            return TestResult::Fail("truncated ath10k IE container admitted");
        }
    }
    let mut duplicate = bytes.clone();
    ie(&mut duplicate, 3, &[0x77]);
    let mut overrun = bytes;
    overrun[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    for invalid in [duplicate, overrun] {
        if !matches!(Image::parse(invalid, 6), Err(Error::InvalidContainer)) {
            return TestResult::Fail("duplicate image or oversized ath10k IE admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k",
    smoke_ath10k_authored_firmware_api_and_ie_boundaries
);

fn smoke_ath10k_authored_board_identity_and_extended_kind() -> TestResult {
    let mut bytes = b"QCA-ATH10K-BOARD\0".to_vec();
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    for (kind, payload) in [(0, &[1, 2, 3][..]), (1, &[4, 5][..])] {
        let mut nested = Vec::new();
        ie(&mut nested, 0, b"rust-board");
        ie(&mut nested, 1, payload);
        ie(&mut bytes, kind, &nested);
    }
    let names = [String::from("rust-board")];
    if select_board(&bytes, &names, false) != Ok(&[1, 2, 3][..])
        || select_board(&bytes, &names, true) != Ok(&[4, 5][..])
        || select_board(&bytes, &[String::from("rust-boar")], false) != Err(Error::BoardNotFound)
        || select_board(&bytes[..bytes.len() - 1], &names, false) != Err(Error::InvalidContainer)
    {
        return TestResult::Fail("ath10k exact board identity, kind or nested IE bounds");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k",
    smoke_ath10k_authored_board_identity_and_extended_kind
);
