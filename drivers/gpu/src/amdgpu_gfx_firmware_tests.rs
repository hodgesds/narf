use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

pub(crate) fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn container(source: Source) -> Vec<u8> {
    let mut bytes = vec![0; 512];
    let (header, version, ip) = match source {
        Source::Sdma => (48, 1, 0x20005),
        Source::Rlc => (244, 0x40002, 0x3000a),
        Source::Vcn => (32, 1, 3),
        Source::Dmcub => (40, 1, 3),
        _ => (44, 1, 0x3000a),
    };
    for (field, value) in [
        (0, 512),
        (4, header),
        (8, version),
        (12, ip),
        (16, 74),
        (20, 16),
        (24, 256),
    ] {
        put(&mut bytes, field, value);
    }
    bytes[256..272].fill(0x88);
    if source == Source::Rlc {
        for (index, field) in [
            204, 212, 220, 228, 236, 116, 132, 148, 156, 164, 72, 80, 88, 96,
        ]
        .into_iter()
        .enumerate()
        {
            let start = 272 + index * 4;
            put(&mut bytes, field, 4);
            put(&mut bytes, field + 4, start as u32);
            bytes[start..start + 4].fill(index as u8 + 1);
        }
    } else if matches!(source, Source::Vcn | Source::Dmcub) {
        bytes.truncate(272);
        put(&mut bytes, 0, 272);
        if source == Source::Dmcub {
            put(&mut bytes, 32, 12);
            put(&mut bytes, 36, 4);
        }
    } else {
        let field = if source == Source::Sdma { 40 } else { 36 };
        put(&mut bytes, field, 3);
        put(&mut bytes, field + 4, 1);
        bytes[268..272].fill(0xee);
    }
    bytes
}
fn navi22_cp_sdma_container_bounds_and_mec_split() -> TestResult {
    for source in Source::ORDER
        .into_iter()
        .filter(|s| !matches!(s, Source::Rlc | Source::Vcn | Source::Dmcub))
    {
        let bytes = container(source);
        let image = Image::parse(source, &bytes).unwrap();
        let payload = image.payloads().next().unwrap();
        let expected = if matches!(source, Source::Mec | Source::Mec2) {
            12
        } else {
            16
        };
        if payload.bytes() != &bytes[256..256 + expected]
            || image.version() != 74
            || image.payloads().count() != 1
        {
            return TestResult::Fail("wrong payload/JT split or version");
        }
        for len in 0..bytes.len() {
            if Image::parse(source, &bytes[..len]).is_ok() {
                return TestResult::Fail("truncated container accepted");
            }
        }
        let jt = if source == Source::Sdma { 40 } else { 36 };
        for (field, value) in [
            (0, 0),
            (4, 32),
            (8, 0x10001),
            (12, 0x30009),
            (20, 0),
            (20, u32::MAX),
            (24, 32),
            (24, 255),
            (24, u32::MAX),
            (jt, u32::MAX),
            (jt + 4, u32::MAX),
        ] {
            let mut bad = bytes.clone();
            put(&mut bad, field, value);
            if Image::parse(source, &bad).is_ok() {
                return TestResult::Fail("malformed header/payload/JT accepted");
            }
        }
        if matches!(source, Source::Mec | Source::Mec2) {
            for (field, value) in [(36, 0), (36, 2), (40, 0), (40, 4)] {
                let mut bad = bytes.clone();
                put(&mut bad, field, value);
                if Image::parse(source, &bad).is_ok() {
                    return TestResult::Fail("non-tail/empty MEC JT accepted");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx-firmware",
    navi22_cp_sdma_container_bounds_and_mec_split
);

fn navi22_rlc_file_offsets_and_linux_upload_order() -> TestResult {
    let bytes = container(Source::Rlc);
    let image = Image::parse(Source::Rlc, &bytes).unwrap();
    let payloads: Vec<_> = image.payloads().collect();
    if payloads
        .iter()
        .map(|p| p.firmware_type())
        .collect::<Vec<_>>()
        != [27, 28, 29, 65, 66, 22, 20, 21, 26, 48, 8]
    {
        return TestResult::Fail("RLC order/types wrong or metadata was selected as firmware");
    }
    for (index, payload) in payloads.iter().take(10).enumerate() {
        if payload.bytes() != [index as u8 + 1; 4] {
            return TestResult::Fail("RLC offset treated as payload-relative");
        }
    }
    if payloads.last().unwrap().bytes() != [0x88; 16] {
        return TestResult::Fail("RLC_G not last");
    }
    for (minor, header) in [(2, 172), (3, 204)] {
        let mut bytes = bytes.clone();
        put(&mut bytes, 4, header);
        put(&mut bytes, 8, (minor << 16) | 2);
        if minor == 3 {
            for (field, offset) in [(180, 400), (196, 404)] {
                put(&mut bytes, field, 4);
                put(&mut bytes, field + 4, offset);
            }
        }
        let image = Image::parse(Source::Rlc, &bytes).unwrap();
        let kinds: Vec<_> = image.payloads().map(|p| p.firmware_type()).collect();
        let expected = if minor == 2 {
            &[22, 20, 21, 26, 48, 8][..]
        } else {
            &[22, 20, 21, 26, 48, 25, 7, 8][..]
        };
        if kinds != expected {
            return TestResult::Fail("RLC revision selected wrong extensions");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx-firmware",
    navi22_rlc_file_offsets_and_linux_upload_order
);

fn navi22_rlc_rejects_overlap_header_and_descriptor_errors() -> TestResult {
    let bytes = container(Source::Rlc);
    for len in 0..bytes.len() {
        if Image::parse(Source::Rlc, &bytes[..len]).is_ok() {
            return TestResult::Fail("truncated RLC accepted");
        }
    }
    for field in [
        20, 72, 80, 88, 96, 116, 132, 148, 156, 164, 204, 212, 220, 228, 236,
    ] {
        // Main descriptor uses size at 20 and offset at 24, like the others.
        for (bad_field, value) in [
            (field, u32::MAX),
            (field, 3),
            (field + 4, 4),
            (field + 4, u32::MAX),
            (field + 4, 255),
            (field + 4, 256),
        ] {
            if field == 20 && value == 256 {
                continue;
            }
            let mut bad = bytes.clone();
            put(&mut bad, bad_field, value);
            if Image::parse(Source::Rlc, &bad).is_ok() {
                return TestResult::Fail("overlapping or unbounded RLC descriptor accepted");
            }
        }
    }
    for (field, value) in [
        (4, 172),
        (8, 0x50002),
        (8, 0x10002),
        (12, 0x4000a),
        (180, 4),
        (196, 4),
        (184, u32::MAX),
        (200, u32::MAX),
        (20, 0),
        (0, 0),
    ] {
        let mut bad = bytes.clone();
        put(&mut bad, field, value);
        if Image::parse(Source::Rlc, &bad).is_ok() {
            return TestResult::Fail("unsupported RLC header/unused P/V accepted");
        }
    }
    // Real images have empty metadata ranges pointing at a valid boundary.
    let mut empty = bytes;
    for field in [72, 80, 88, 96, 204, 212, 220, 228, 236] {
        put(&mut empty, field, 0);
    }
    if Image::parse(Source::Rlc, &empty)
        .unwrap()
        .payloads()
        .count()
        != 6
    {
        return TestResult::Fail("empty optional RLC ranges mishandled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx-firmware",
    navi22_rlc_rejects_overlap_header_and_descriptor_errors
);

fn navi22_media_firmware_bounds_and_signed_instruction_selection() -> TestResult {
    for (source, kind, size) in [(Source::Vcn, 13, 16), (Source::Dmcub, 51, 12)] {
        let bytes = container(source);
        let image = Image::parse(source, &bytes).unwrap();
        let payload = image.payloads().next().unwrap();
        if image.payloads().count() != 1
            || payload.firmware_type() != kind
            || payload.bytes() != &bytes[256..256 + size]
        {
            return TestResult::Fail("media firmware included header/BSS or wrong PSP type");
        }
        for len in 0..bytes.len() {
            if Image::parse(source, &bytes[..len]).is_ok() {
                return TestResult::Fail("truncated media firmware accepted");
            }
        }
        for (field, value) in [
            (0, 0),
            (4, 44),
            (8, 2),
            (12, 4),
            (20, 0),
            (20, 12),
            (20, u32::MAX),
            (24, 0),
            (24, 255),
            (24, u32::MAX),
        ] {
            let mut bad = bytes.clone();
            put(&mut bad, field, value);
            if Image::parse(source, &bad).is_ok() {
                return TestResult::Fail("invalid media descriptor accepted");
            }
        }
        if source == Source::Dmcub {
            for (field, value) in [
                (32, 0),
                (32, 13),
                (32, 20),
                (32, u32::MAX),
                (36, 0),
                (36, u32::MAX),
            ] {
                let mut bad = bytes.clone();
                put(&mut bad, field, value);
                if Image::parse(source, &bad).is_ok() {
                    return TestResult::Fail("bad DMCUB instruction/BSS split accepted");
                }
            }
            // Current Navy Flounder format combines all data in instructions.
            let mut combined = bytes;
            put(&mut combined, 32, 16);
            put(&mut combined, 36, 0);
            if Image::parse(source, &combined)
                .unwrap()
                .payloads()
                .next()
                .unwrap()
                .bytes()
                .len()
                != 16
            {
                return TestResult::Fail("combined DMCUB layout refused");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx-firmware",
    navi22_media_firmware_bounds_and_signed_instruction_selection
);
