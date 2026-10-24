use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
const OWN: [u8; 6] = [2, 1, 2, 3, 4, 5];
fn frame(length: usize, management: bool) -> Vec<u8> {
    let mut bytes = vec![0; length];
    bytes[..2].copy_from_slice(if management { &[0xb0, 0] } else { &[8, 1] });
    bytes[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    bytes[10..16].copy_from_slice(&OWN);
    bytes[22..24].copy_from_slice(&0x1230u16.to_le_bytes());
    bytes
}
fn smoke_rtw89_b_packet_full_wd_info_matches_extracted_linux_c() -> TestResult {
    for (index, expected) in HEADERS.iter().enumerate() {
        let bytes = frame(if index < 2 { 100 } else { 2304 }, index & 1 != 0);
        let result = transmit(
            &bytes,
            OWN,
            0,
            if index == 3 { 511 } else { index as u16 },
            if index >= 2 {
                0xf_1234_5000
            } else {
                0x1234_5000
            },
            index >= 2,
        );
        if result.as_ref().map(|(bytes, _)| bytes.as_slice()) != Ok(expected.as_slice()) {
            return TestResult::Fail(
                "B full body/info/WP/address-info differs from extracted Linux C",
            );
        }
    }
    if descriptor(0xf_1234_5000) != Ok([64, 0, 0xc0, 0x43, 0, 0x50, 0x34, 0x12]) {
        return TestResult::Fail("B TXBD header-only extent or upper address/LS bits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_packet_full_wd_info_matches_extracted_linux_c
);

fn smoke_rtw89_b_packet_raw_ccmp_extents_and_36bit_limits() -> TestResult {
    let mut bytes = frame(100, false);
    bytes[1] |= 64;
    // Nonzero PN, reserved byte zero, ExtIV set, pairwise key0.
    bytes[24..32].copy_from_slice(&[1, 0, 0, 0x20, 0, 0, 0, 0]);
    let Ok((header, _)) = transmit(&bytes, OWN, 0, 0, 0x1000, false) else {
        return TestResult::Fail("exact non-QoS host CCMP was rejected");
    };
    if header[16..24] != [0; 8] || header[32..36] != [0; 4] || header[3] != 0 {
        return TestResult::Fail("raw CCMP enabled hardware key/IV insertion");
    }
    for index in [0, 1, 22, 26, 27] {
        let mut bad = bytes.clone();
        match index {
            0 => bad[0] = 0x88,
            1 => bad[1] |= 2,
            22 => bad[22] |= 1,
            26 => bad[26] = 1,
            27 => bad[27] &= !0x20,
            _ => unreachable!(),
        }
        if transmit(&bad, OWN, 0, 0, 0x1000, false).is_ok() {
            return TestResult::Fail("raw CCMP accepted optional header or malformed IV");
        }
    }
    for length in [24, 31, 39, 47] {
        if transmit(&bytes[..length], OWN, 0, 0, 0x1000, false).is_ok() {
            return TestResult::Fail("raw CCMP accepted truncated IV/MIC/ciphertext");
        }
    }
    for address in [0, 0x1001, 0x10_0000_0000, DMA_MASK - 3] {
        if transmit(&bytes, OWN, 0, 0, address, false).is_ok() {
            return TestResult::Fail("B packet accepted invalid36-bit complete DMA extent");
        }
    }
    if transmit(&bytes, OWN, 1, 0, 0x1000, false).is_ok()
        || transmit(&bytes, OWN, 0, 512, 0x1000, false).is_ok()
    {
        return TestResult::Fail("packet profile widened MACID or native WD-page identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_packet_raw_ccmp_extents_and_36bit_limits
);
