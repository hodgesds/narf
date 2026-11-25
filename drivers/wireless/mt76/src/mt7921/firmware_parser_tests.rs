//! Authored CONNAC2 headers/tables and inert payloads, entirely in Rust.
use super::{
    firmware_transport::Firmware,
    fwdl::*,
    pci::firmware_blobs_for,
    regs::{MT7925_FIRMWARE_WM, MT7925_ROM_PATCH, MTK_DEV_MT7925, MTK_DEV_MT7925_ALT},
};
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

/// MT7925 RAM image: same shape as `ram()`, but the trailer `chip_id`
/// byte carries the MT7925 value. `0x25` is the low byte of `0x7925`,
/// by the same convention as the `0x22` byte in `ram()` for MT7922 —
/// a stated convention, NOT verified against a real MT7925 blob (the
/// real-blob value is a hardware-validation item; see the MT7925
/// programme record §5). `Firmware::prepare` does not gate on the
/// trailer `chip_id` byte, so the 7925 value must be accepted exactly
/// like the 7922 one.
fn ram_mt7925() -> Vec<u8> {
    let mut bytes = ram();
    bytes[88] = 0x25;
    bytes
}

fn smoke_mt7925_authored_ram_trailer_accepted_by_prepare() -> TestResult {
    // Both 7925 DIDs resolve to the MT7925 patch/RAM pair (upstream
    // `mt792x.h:51,59`: `MT7925_FIRMWARE_WM` / `MT7925_ROM_PATCH`).
    // That pair is the input `Firmware::open` hands to `prepare`;
    // the names are re-checked here so this test pins the whole
    // 7925-blob-pair → CONNAC2-parser route, not just the trailer.
    for &did in [MTK_DEV_MT7925, MTK_DEV_MT7925_ALT].iter() {
        let (p, r) = firmware_blobs_for(did);
        if p != MT7925_ROM_PATCH || r != MT7925_FIRMWARE_WM {
            return TestResult::Fail("MT7925 firmware blob names drift");
        }
    }
    let bytes = ram_mt7925();
    let tail = parse_fw_trailer(&bytes).unwrap();
    if tail.chip_id != 0x25
        || tail.eco_code != 1
        || tail.n_region != 2
        || tail.format_ver != 2
        || tail.format_flag != 3
    {
        return TestResult::Fail("MT7925 trailer fields differ from the authored fixture");
    }
    // The chip-agnostic CONNAC2 parsers accept a 7925 trailer: upstream
    // `mt792x_load_firmware` (`mt792x_core.c:1097`) calls
    // `mt76_connac2_load_patch` (:1117) and `mt76_connac2_load_ram`
    // (:1134) for 7925, and there is no `mt76_connac3_patch_hdr` /
    // `mt76_connac3_fw_trailer` — the CONNAC3 loaders are 7928-gated.
    if Firmware::prepare(&patch(), &bytes).is_err() {
        return TestResult::Fail("7925-trailer CONNAC2 input rejected by Firmware::prepare");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7925_authored_ram_trailer_accepted_by_prepare
);
