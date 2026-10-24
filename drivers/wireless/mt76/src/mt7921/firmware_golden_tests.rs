//! Metadata slices extracted independently from pinned local MediaTek images.
//! No executable or CLC bytes are present and these fixtures never reach a
//! registry/device. Table decode and image acceptance are separate boundaries.

use super::{firmware_transport::Firmware, fwdl::*};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

struct PatchGolden {
    source: &'static str,
    source_sha256: &'static str,
    image_len: usize,
    metadata: &'static [u8],
    header: Connac2PatchHdr,
    regions: &'static [Connac2PatchSection],
}

struct RamGolden {
    source: &'static str,
    source_sha256: &'static str,
    image_len: usize,
    metadata: &'static [u8],
    trailer: Connac2FwTrailer,
    regions: &'static [Connac2FwRegion],
}

include!("../../../../../verification/data/wifi-firmware/mediatek/goldens.rs");

fn smoke_mt7921_real_patch_metadata_slices() -> TestResult {
    for golden in PATCH_GOLDENS {
        if !golden.source.ends_with(".bin") || golden.source_sha256.len() != 64 {
            return TestResult::Fail("patch fixture lost complete source identity");
        }
        let header = match parse_patch_header(golden.metadata) {
            Ok(header) if header == golden.header => header,
            _ => return TestResult::Fail("real patch header facts changed"),
        };
        let regions: Result<Vec<_>, _> = iter_patch_sections(golden.metadata, &header)
            .expect("captured patch table fits")
            .collect();
        if regions.as_deref() != Ok(golden.regions) {
            return TestResult::Fail("real patch address/length/key-mode facts changed");
        }
        if golden
            .regions
            .iter()
            .any(|region| region.offset as usize + region.len as usize > golden.image_len)
        {
            return TestResult::Fail("captured patch spans exceed original source size");
        }
        if !matches!(
            parse_patch_header(&golden.metadata[..95]),
            Err(FwParseError::TooShort)
        ) || !matches!(
            iter_patch_sections(&golden.metadata[..golden.metadata.len() - 1], &header),
            Err(FwParseError::SectionTableOverrun)
        ) {
            return TestResult::Fail("truncated real patch metadata was accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_real_patch_metadata_slices
);

fn smoke_mt7921_real_ram_metadata_slices() -> TestResult {
    for golden in RAM_GOLDENS {
        if !golden.source.ends_with(".bin") || golden.source_sha256.len() != 64 {
            return TestResult::Fail("RAM fixture lost complete source identity");
        }
        let trailer = match parse_fw_trailer(golden.metadata) {
            Ok(trailer) if trailer == golden.trailer => trailer,
            _ => return TestResult::Fail("real RAM trailer version/date/CRC facts changed"),
        };
        let regions: Result<Vec<_>, _> = iter_fw_regions(golden.metadata, &trailer)
            .expect("captured RAM table fits")
            .collect();
        if regions.as_deref() != Ok(golden.regions) {
            return TestResult::Fail("real RAM address/length/feature/CLC facts changed");
        }
        let payload_len: usize = golden
            .regions
            .iter()
            .map(|region| region.len as usize)
            .sum();
        if payload_len > golden.image_len - golden.metadata.len() {
            return TestResult::Fail("captured RAM spans exceed original source size");
        }
        if !matches!(
            parse_fw_trailer(&golden.metadata[..35]),
            Err(FwParseError::TooShort)
        ) || !matches!(
            iter_fw_regions(&golden.metadata[1..], &trailer),
            Err(FwParseError::SectionTableOverrun)
        ) {
            return TestResult::Fail("truncated real RAM metadata was accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_real_ram_metadata_slices
);

fn smoke_mt7921_real_metadata_is_not_loadable_firmware() -> TestResult {
    for (patch, ram) in PATCH_GOLDENS.iter().zip(RAM_GOLDENS) {
        let patch_replay =
            narf_wifi_fixtures::firmware::metadata_replay(patch.image_len, &[(0, patch.metadata)])
                .expect("patch metadata fits original geometry");
        // The patch has its original geometry but zeroed instruction bytes.
        // The RAM metadata slice still lacks every payload: prepare must reject
        // it instead of mistaking table-only decode for a loadable image.
        if !matches!(
            Firmware::prepare(&patch_replay, ram.metadata),
            Err(super::firmware_transport::Error::InvalidFirmware)
        ) {
            return TestResult::Fail("metadata-only RAM was accepted for download");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    smoke_mt7921_real_metadata_is_not_loadable_firmware
);
