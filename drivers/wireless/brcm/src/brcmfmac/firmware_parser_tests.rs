// SPDX-License-Identifier: GPL-2.0-or-later
//! Authored raw/TRX and RAM-size marker cases; no device firmware payload.
use super::{embedded_ramsize, TrxHeader, FW_RAMSIZE_OFFSET};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_brcmfmac_authored_raw_trx_and_ram_marker_boundaries() -> TestResult {
    let mut bytes = vec![0; 128];
    if embedded_ramsize(&bytes).is_some() || TrxHeader::parse(&bytes).is_some() {
        return TestResult::Fail("raw test input acquired an absent RAM marker or TRX header");
    }
    bytes[108..112].copy_from_slice(b"RAMS");
    bytes[112..116].copy_from_slice(&0x0008_0000u32.to_le_bytes());
    if embedded_ramsize(&bytes) != Some(0x0008_0000)
        || embedded_ramsize(&bytes[..FW_RAMSIZE_OFFSET + 7]).is_some()
    {
        return TestResult::Fail("RAM marker endianness or short marker extent");
    }
    bytes[108] ^= 1;
    if embedded_ramsize(&bytes).is_some() {
        return TestResult::Fail("damaged RAM marker admitted");
    }
    let trx = [
        0x48, 0x44, 0x52, 0x30, 28, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 1, 0, 2, 0, 28, 0, 0, 0, 40,
        0, 0, 0, 52, 0, 0, 0,
    ];
    let header = TrxHeader::parse(&trx).unwrap();
    if header.length != 28
        || header.crc32 != 0x7856_3412
        || header.flag_version != 0x0002_0001
        || header.offsets != [28, 40, 52]
        || TrxHeader::parse(&trx[..27]).is_some()
    {
        return TestResult::Fail("TRX authored field offsets, endianness or short header");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_authored_raw_trx_and_ram_marker_boundaries
);
