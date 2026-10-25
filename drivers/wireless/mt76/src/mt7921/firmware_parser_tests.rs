//! Authored CONNAC2 headers/tables and inert payloads, entirely in Rust.
use super::{firmware_transport::Firmware, fwdl::*};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

fn patch() -> Vec<u8> {
    let mut bytes = vec![0; 232]; // 96-byte header + 2*64 table + 8 data
    bytes[..16].fill(b'R');
    bytes[16..20].copy_from_slice(b"TEST");
    bytes[20..24].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    bytes[24..28].copy_from_slice(&0x090a_0b0cu32.to_be_bytes());
    bytes[28..30].copy_from_slice(&0x1357u16.to_be_bytes());
    bytes[44..48].copy_from_slice(&2u32.to_be_bytes());
    for (index, offset, len, address) in
        [(0, 224u32, 3u32, 0x1020_3040u32), (1, 227, 5, 0x5060_7080)]
    {
        let at = 96 + index * 64;
        for (field, value) in [2, offset, len, address, len, 0].into_iter().enumerate() {
            bytes[at + field * 4..at + field * 4 + 4].copy_from_slice(&value.to_be_bytes());
        }
    }
    bytes[224..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    bytes
}
fn ram() -> Vec<u8> {
    let mut bytes = vec![0; 124]; // 8 data + 2*40 table + 36-byte trailer
    bytes[..8].copy_from_slice(&[0xa1, 0xa2, 0xa3, 0xa4, 0xb1, 0xb2, 0xb3, 0xb4]);
    for (index, address, feature) in [(0, 0x1122_3344u32, 0), (1, 0x5566_7788, 0x20)] {
        let at = 8 + index * 40;
        bytes[at + 16..at + 20].copy_from_slice(&address.to_le_bytes());
        bytes[at + 20..at + 24].copy_from_slice(&4u32.to_le_bytes());
        bytes[at + 24] = feature;
    }
    bytes[88..93].copy_from_slice(&[0x22, 1, 2, 2, 3]);
    bytes[95..105].copy_from_slice(b"rust-test1");
    bytes[105..120].fill(b'D');
    bytes[120..].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());
    bytes
}
fn smoke_mt7921_authored_patch_endianness_and_section_bounds() -> TestResult {
    let bytes = patch();
    let header = parse_patch_header(&bytes).unwrap();
    let regions: Vec<_> = iter_patch_sections(&bytes, &header)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    if header.build_date != [b'R'; 16]
        || header.platform != *b"TEST"
        || header.hw_sw_ver != 0x1234_5678
        || header.patch_ver != 0x090a_0b0c
        || header.checksum != 0x1357
        || header.n_region != 2
        || regions.len() != 2
        || regions[0].offset != 224
        || regions[0].len != 3
        || regions[0].addr != 0x1020_3040
        || regions[1].offset != 227
        || regions[1].size != 5
        || regions[1].addr != 0x5060_7080
        || parse_patch_header(&bytes[..95]) != Err(FwParseError::TooShort)
        || !matches!(
            iter_patch_sections(&bytes[..223], &header),
            Err(FwParseError::SectionTableOverrun)
        )
    {
        return TestResult::Fail("CONNAC2 patch authored fields, byte order or table extent");
    }
    let mut bad = bytes;
    bad[96..100].copy_from_slice(&3u32.to_be_bytes());
    if iter_patch_sections(&bad, &header).unwrap().next() != Some(Err(FwParseError::BadSectionType))
    {
        return TestResult::Fail("unsupported CONNAC2 patch section kind admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_authored_patch_endianness_and_section_bounds
);

fn smoke_mt7921_authored_ram_trailer_and_region_bounds() -> TestResult {
    let bytes = ram();
    let tail = parse_fw_trailer(&bytes).unwrap();
    let regions: Vec<_> = iter_fw_regions(&bytes, &tail)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    if tail.chip_id != 0x22
        || tail.eco_code != 1
        || tail.n_region != 2
        || tail.format_ver != 2
        || tail.format_flag != 3
        || tail.fw_ver != *b"rust-test1"
        || tail.build_date != [b'D'; 15]
        || tail.crc != 0x89ab_cdef
        || regions.len() != 2
        || regions[0].addr != 0x1122_3344
        || regions[0].len != 4
        || regions[1].addr != 0x5566_7788
        || regions[1].feature_set != 0x20
        || parse_fw_trailer(&bytes[..35]) != Err(FwParseError::TooShort)
        || !matches!(
            iter_fw_regions(&bytes[9..], &tail),
            Err(FwParseError::SectionTableOverrun)
        )
    {
        return TestResult::Fail("CONNAC2 RAM authored fields, byte order or table extent");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_authored_ram_trailer_and_region_bounds
);

fn smoke_mt7921_authored_tables_do_not_substitute_for_missing_payloads() -> TestResult {
    let patch = patch();
    let ram = ram();
    if Firmware::prepare(&patch, &ram).is_err() {
        return TestResult::Fail("complete authored inert CONNAC2 input rejected");
    }
    if Firmware::prepare(&patch[..224], &ram).is_ok()
        || Firmware::prepare(&patch, &ram[8..]).is_ok()
    {
        return TestResult::Fail("CONNAC2 table-only input admitted with missing payload");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_authored_tables_do_not_substitute_for_missing_payloads
);
