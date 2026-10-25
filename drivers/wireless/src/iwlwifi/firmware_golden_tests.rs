//! Real-image metadata regression tests. These are structural replays with
//! zero-filled executable payloads, never firmware accepted for device loading.
//! The independent extractor and complete source hashes live with the facts.

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Golden {
    source: &'static str,
    source_sha256: &'static str,
    image_len: usize,
    metadata: &'static [u8],
    fragments: &'static [(usize, usize, usize)],
    version: u32,
    build: u32,
    human: &'static str,
    num_cpu: u32,
    fw_version: [u32; 3],
    capabilities: [u32; 8],
    api_changes: [u32; 8],
    calibration: [u32; 2],
    phy_config: u32,
    commands: &'static [u8],
    iml_len: usize,
    pnvm_len: usize,
    sections: &'static [(u32, u32, usize)],
}

include!("../../../../verification/data/wifi-firmware/intel/goldens.rs");

fn replay(golden: &Golden) -> Vec<u8> {
    let fragments: Vec<_> = golden
        .fragments
        .iter()
        .map(|&(offset, start, len)| (offset, &golden.metadata[start..start + len]))
        .collect();
    narf_wifi_fixtures::firmware::metadata_replay(golden.image_len, &fragments)
        .expect("pinned metadata fragments are in bounds and nonoverlapping")
}

/// Test-only metadata replay for consumers checking actual API77 negotiation.
/// Opaque section bytes remain zero and must never enter a device loader.
pub(super) fn api77_replay() -> Vec<u8> {
    replay(
        GOLDENS
            .iter()
            .find(|golden| golden.source == "iwlwifi-cc-a0-77.ucode")
            .expect("pinned API77 metadata is present"),
    )
}

/// Sc c103's recorded command table, decoded by the production image parser.
/// The replay contains no executable bytes and is never passed to start().
pub(super) fn sc103_commands() -> Vec<u8> {
    let bytes = replay(
        GOLDENS
            .iter()
            .find(|golden| golden.source == "iwlwifi-sc-a0-wh-b0-c103.ucode")
            .expect("pinned Sc c103 metadata is present"),
    );
    parse_ucode(&bytes).unwrap().api.commands.to_vec()
}

fn smoke_iwlwifi_real_metadata_structural_replays() -> TestResult {
    for golden in GOLDENS {
        if !golden.source.ends_with(".ucode") || golden.source_sha256.len() != 64 {
            return TestResult::Fail("metadata fixture lost complete source identity");
        }
        let bytes = replay(golden);
        let parsed = match parse_ucode(&bytes) {
            Ok(parsed) => parsed,
            Err(_) => {
                return TestResult::Fail("pinned real-image metadata failed structural decode")
            }
        };
        let [major, minor, api] = golden.fw_version;
        if parsed.header.version != golden.version
            || parsed.header.build != golden.build
            || parsed.header.human_readable != golden.human
            || parsed.num_of_cpu != golden.num_cpu
            || parsed.fw_version != Some((major, minor, api))
        {
            return TestResult::Fail("real-image firmware header/version facts changed");
        }
        if parsed.api.capabilities != golden.capabilities
            || parsed.api.api_changes != golden.api_changes
            || parsed.api.calibration != golden.calibration
            || parsed.api.phy_config != golden.phy_config
            || parsed.api.commands != golden.commands
            || parsed.api.iml.map_or(0, <[u8]>::len) != golden.iml_len
            || parsed.api.pnvm.map_or(0, <[u8]>::len) != golden.pnvm_len
        {
            return TestResult::Fail("real-image API/capability metadata changed");
        }
        for (tags, sections) in [
            (&[19, 24][..], &parsed.rt_sections),
            (&[20, 25], &parsed.init_sections),
        ] {
            let expected: Vec<_> = golden
                .sections
                .iter()
                .filter(|(tag, _, _)| tags.contains(tag))
                .map(|&(_, destination, len)| (destination, len))
                .collect();
            let actual: Vec<_> = sections
                .iter()
                .map(|section| (section.dest_offset, section.payload.len()))
                .collect();
            if actual != expected {
                return TestResult::Fail("real-image section order/address/length facts changed");
            }
            if sections
                .iter()
                .any(|section| section.payload.iter().any(|&byte| byte != 0))
            {
                return TestResult::Fail("structural replay unexpectedly contains section payload");
            }
        }
        for (index, entry) in golden.commands.chunks_exact(4).enumerate() {
            // Real API 77/89/100 images contain duplicate group/opcode
            // records with different versions. Linux fw/img.c and our lookup
            // select the first record; preserve both raw records above.
            if golden.commands[..index * 4]
                .chunks_exact(4)
                .any(|prior| prior[..2] == entry[..2])
            {
                continue;
            }
            if parsed.api.versions(entry[1], entry[0]) != Some((entry[2], entry[3])) {
                return TestResult::Fail("real command/notification version lookup changed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi",
    smoke_iwlwifi_real_metadata_structural_replays
);

fn smoke_iwlwifi_real_metadata_truncation_rejected() -> TestResult {
    for golden in GOLDENS {
        let bytes = replay(golden);
        if !matches!(parse_ucode(&bytes[..87]), Err(ParseError::TooShort))
            || !matches!(
                parse_ucode(&bytes[..bytes.len() - 1]),
                Err(ParseError::TruncatedTlv { .. })
            )
        {
            return TestResult::Fail("truncated real-image metadata replay was accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi",
    smoke_iwlwifi_real_metadata_truncation_rejected
);
