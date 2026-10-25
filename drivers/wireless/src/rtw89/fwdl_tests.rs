//! Independent Linux packed-layout fixtures plus adversarial owned preparation.
//! Frozen Linux fw.h layout reference: AX v0 header32/section16, v1 header48/section16;
//! MFW header16/entry16. Fixtures use literal offsets, not parser constants.
use super::fw::FwError;
use super::fwdl::{parse_auto, select_image, FwSection};
use super::mac::ChipId;
use super::prepared::{self, Files};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[allow(dead_code)]
mod firmware_metadata {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../verification/data/wifi-firmware/realtek/metadata.rs"
    ));
}

fn smoke_rtw89_raw_source_metadata_parser_goldens() -> TestResult {
    // Source hashes belong to complete originals. Only TOCs, headers and
    // security-pool geometry survive in these zero-payload parser replays.
    // They never enter prepared::load, the firmware registry or hardware.
    let source_hashes = include_str!("firmware_fixture_sha256.json");
    let mut images = 0;
    let mut formatted_pools = 0;
    for source in firmware_metadata::AX {
        let provenance = alloc::format!("\"/lib/firmware/{}\": \"{}\"", source.name, source.sha256);
        if !source_hashes.contains(&provenance) {
            return TestResult::Fail("AX original-source SHA256 provenance changed");
        }
        let mut bytes =
            match narf_wifi_fixtures::firmware::metadata_replay(source.length, source.fragments) {
                Ok(bytes) => bytes,
                Err(_) => return TestResult::Fail("AX metadata replay geometry"),
            };
        for image in source.images {
            images += 1;
            let body = &bytes[image.offset..image.offset + image.length];
            let mut sections = output();
            let header = match parse_auto(body, &mut sections) {
                Ok(header) => header,
                Err(_) => return TestResult::Fail("AX raw-source image layout rejected"),
            };
            if header.version != image.version
                || header.fw_major != image.major
                || header.fw_minor != image.minor
                || usize::from(header.section_num) != image.sections.len()
                || header.hdr_len != image.header_length
                || header.dynamic_hdr != image.dynamic
                || header.part_size != 2020
            {
                return TestResult::Fail("AX independently extracted image header facts");
            }
            for (index, expected) in image.sections.iter().enumerate() {
                let actual = sections[index];
                if actual.kind != expected.kind
                    || actual.dladdr != expected.address
                    || actual.len != expected.length
                    || actual.chksum != expected.checksum
                    || actual.redl != expected.redownload
                    || actual.payload_off != expected.offset
                {
                    return TestResult::Fail("AX independently extracted section geometry");
                }
                let expected_pool = expected.pool.as_ref().map(|pool| {
                    formatted_pools += usize::from(pool.bitmap);
                    super::fwdl::SignaturePool {
                        offset: pool.offset,
                        len: pool.length,
                        signatures_offset: pool.signatures_offset,
                        signature_len: pool.signature_length,
                        signature_count: pool.signature_count,
                        bitmap: pool.bitmap,
                    }
                });
                if header.signature_pools[index] != expected_pool {
                    return TestResult::Fail("AX independently extracted signature-pool geometry");
                }
            }
            // Check header and final section/pool truncations without replacing
            // caller metadata on failure; executable byte values play no role.
            for end in [0, 31, image.header_length - 1, body.len() - 1] {
                let mut untouched = output();
                if parse_auto(&body[..end], &mut untouched).is_ok() || untouched != output() {
                    return TestResult::Fail("AX truncated source geometry mutated output");
                }
            }
        }
        // Probe every physical-cut value and supported outer suit type. The
        // expected nearest non-manufacturing CV comes from the original TOC.
        for cut in 0..=15 {
            for kind in [1, 3, 5, 64, 65] {
                let expected = source
                    .images
                    .iter()
                    .filter(|image| image.kind == kind && !image.manufacturing && image.cut <= cut)
                    .max_by_key(|image| image.cut);
                match (select_image(&bytes, cut, kind), expected) {
                    (Ok(selected), Some(image))
                        if selected.len() == image.length
                            && selected.as_ptr() as usize - bytes.as_ptr() as usize
                                == image.offset => {}
                    (Err(FwError::ImageMissing), None) => {}
                    _ => return TestResult::Fail("AX raw-source TOC cut/suit selection differs"),
                }
            }
        }
        // Even an unselected entry may not overlap its own table.
        bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
        if !matches!(select_image(&bytes, 15, 1), Err(FwError::BadFormat)) {
            return TestResult::Fail("AX malformed source TOC extent admitted");
        }
    }
    if images != 46 || formatted_pools != 6 {
        return TestResult::Fail("AX raw-source fixture coverage changed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_raw_source_metadata_parser_goldens
);

fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn output() -> [FwSection; 10] {
    [FwSection {
        kind: 7,
        dladdr: 9,
        len: 11,
        chksum: false,
        redl: false,
        payload_off: 13,
    }; 10]
}
fn image(version: u8, count: usize, dynamic: usize) -> Vec<u8> {
    let base = if version == 0 { 32 } else { 48 };
    let fixed = base + count * 16;
    let header = fixed + dynamic;
    let mut bytes = vec![0; header + count * 17];
    put(&mut bytes, 12, u32::from(version) << 24);
    put(&mut bytes, 24, (count as u32) << 8);
    put(&mut bytes, 28, 0x321); // AX ignores firmware's advertised part size.
    if dynamic != 0 {
        let at = if version == 0 { 12 } else { 20 };
        let old = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        put(&mut bytes, at, old | (header as u32) << 16);
        put(&mut bytes, 28, 0x10321);
        put(&mut bytes, fixed, dynamic as u32);
    }
    for index in 0..count {
        let at = base + index * 16;
        put(&mut bytes, at, 0x0010_0000 + index as u32 * 0x100);
        put(&mut bytes, at + 4, 0x3100_0009); // type1 + checksum + re-download.
        bytes[header + index * 17..header + (index + 1) * 17].fill(index as u8);
    }
    bytes
}

fn smoke_rtw89_checked_layouts_and_transactional_output() -> TestResult {
    for version in [0, 1] {
        for count in 1..=10 {
            for dynamic in [0, 8] {
                let bytes = image(version, count, dynamic);
                let mut sections = output();
                let header = match parse_auto(&bytes, &mut sections) {
                    Ok(h) => h,
                    Err(_) => return TestResult::Fail("valid packed AX image"),
                };
                let length = (if version == 0 { 32 } else { 48 }) + 16 * count + dynamic;
                if header.hdr_len != length || header.part_size != 2020 || header.version != version
                {
                    return TestResult::Fail("independent packed header geometry");
                }
                for (index, section) in sections[..count].iter().enumerate() {
                    if section.kind != 1
                        || section.len != 17
                        || !section.chksum
                        || !section.redl
                        || section.payload_off != length + index * 17
                    {
                        return TestResult::Fail("four-bit type / checksum / exact extent");
                    }
                }
                for end in 0..bytes.len() {
                    let mut untouched = output();
                    if parse_auto(&bytes[..end], &mut untouched).is_ok() || untouched != output() {
                        return TestResult::Fail("truncation changed caller metadata");
                    }
                }
                let mut trailing = bytes;
                trailing.push(0);
                if parse_auto(&trailing, &mut sections).is_ok() {
                    return TestResult::Fail("unaccounted file suffix");
                }
            }
        }
    }
    let mut unknown = image(0, 1, 0);
    put(&mut unknown, 12, 2 << 24);
    if !matches!(
        parse_auto(&unknown, &mut output()),
        Err(FwError::UnsupportedFormat)
    ) {
        return TestResult::Fail("future version admitted");
    }
    let mut backward = image(0, 1, 8);
    put(&mut backward, 12, 32 << 16);
    if parse_auto(&backward, &mut output()).is_ok() {
        return TestResult::Fail("dynamic header overlaps section table");
    }
    let mut mismatch = image(1, 1, 8);
    put(&mut mismatch, 64, 9);
    if parse_auto(&mismatch, &mut output()).is_ok() {
        return TestResult::Fail("dynamic self-length ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_checked_layouts_and_transactional_output
);

fn security_image(version: u8, formatted: bool) -> Vec<u8> {
    let base = if version == 0 { 32 } else { 48 };
    let payload = base + 16;
    let pool = payload + 960;
    let mut bytes = vec![
        0;
        pool + if formatted {
            32 + 264 + 2 * 512
        } else {
            2 * 512
        }
    ];
    put(&mut bytes, 12, u32::from(version) << 24);
    put(&mut bytes, 24, 1 << 8);
    put(&mut bytes, base, 0x0010_0000);
    put(&mut bytes, base + 4, 9 << 24 | 960);
    put(&mut bytes, base + 8, if formatted { 255 } else { 2 });
    if formatted {
        bytes[pool..pool + 8].copy_from_slice(b"MSSKPOOL");
        put(&mut bytes, pool + 8, 32);
        put(&mut bytes, pool + 12, 296);
        bytes[pool + 16] = 1; // eight default key-map bytes.
        bytes[pool + 21] = 2; // device types.
        bytes[pool + 22..pool + 24].copy_from_slice(&2u16.to_le_bytes());
        bytes[pool + 24..pool + 26].copy_from_slice(&32u16.to_le_bytes());
        bytes[pool + 26..pool + 28].copy_from_slice(&32u16.to_le_bytes());
    }
    bytes
}
fn smoke_rtw89_signature_pool_extents() -> TestResult {
    for version in [0, 1] {
        for formatted in [false, true] {
            let bytes = security_image(version, formatted);
            let mut sections = output();
            let header = match parse_auto(&bytes, &mut sections) {
                Ok(h) => h,
                Err(_) => return TestResult::Fail("bounded MSSC pool"),
            };
            let Some(pool) = header.signature_pools[0] else {
                return TestResult::Fail("missing pool metadata");
            };
            let start = if version == 0 { 48 } else { 64 };
            if sections[0].len != 960
                || pool.offset != start + 960
                || pool.signature_count != 2
                || pool.signature_len != 512
                || pool.bitmap != formatted
                || pool.offset + pool.len != bytes.len()
            {
                return TestResult::Fail("signature storage mixed into section DMA");
            }
            for removed in [1, 511, 512, 1024] {
                let mut untouched = output();
                if parse_auto(&bytes[..bytes.len() - removed], &mut untouched).is_ok()
                    || untouched != output()
                {
                    return TestResult::Fail("truncated signature pool admitted");
                }
            }
        }
    }
    let mut dsp = security_image(1, false);
    put(&mut dsp, 24, (1 << 8) | (1 << 24));
    dsp.extend_from_slice(&[0; 16]);
    let header = match parse_auto(&dsp, &mut output()) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("v1 DSP signature checksums"),
    };
    if header.signature_pools[0].unwrap().signature_len != 520 {
        return TestResult::Fail("DSP stride");
    }
    let one = security_image(1, true);
    let mut duplicate = one[..48].to_vec();
    put(&mut duplicate, 24, 2 << 8);
    duplicate.extend_from_slice(&one[48..64]);
    duplicate.extend_from_slice(&one[48..64]);
    duplicate.extend_from_slice(&one[64..]);
    duplicate.extend_from_slice(&one[64..]);
    let mut files = ModelFiles {
        responses: vec![Ok(duplicate)],
        names: Vec::new(),
    };
    let prepared = match prepared::load(&mut files, ChipId::Rtl8852C, 0) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("multiple pools must parse with bounded extents"),
    };
    if !matches!(prepared.unsecured_header(), Err(FwError::UnsupportedFormat)) {
        return TestResult::Fail("unimplemented security descriptor compaction admitted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_signature_pool_extents);

fn mfw(images: &[(u8, u8, bool, Vec<u8>)]) -> Vec<u8> {
    let table = 16 + 16 * images.len();
    let mut bytes = vec![0; table];
    bytes[0] = 255;
    bytes[1] = images.len() as u8;
    for (index, (cut, kind, mp, image)) in images.iter().enumerate() {
        let at = 16 + 16 * index;
        bytes[at] = *cut;
        bytes[at + 1] = *kind;
        bytes[at + 2] = u8::from(*mp);
        let start = bytes.len();
        put(&mut bytes, at + 4, start as u32);
        put(&mut bytes, at + 8, image.len() as u32);
        bytes.extend_from_slice(image);
    }
    bytes
}
fn smoke_rtw89_mfw_physical_cut_selection() -> TestResult {
    let bytes = mfw(&[
        (0, 1, false, vec![0; 4]),
        (2, 1, false, vec![2; 4]),
        (1, 1, false, vec![1; 4]),
        (2, 1, true, vec![9; 4]),
    ]);
    if select_image(&bytes, 1, 1) != Ok(&[1; 4][..])
        || select_image(&bytes, 3, 1) != Ok(&[2; 4][..])
        || !matches!(select_image(&bytes, 3, 5), Err(FwError::ImageMissing))
    {
        return TestResult::Fail("nearest non-MP physical cut");
    }
    let mut ambiguous = bytes.clone();
    ambiguous[16 + 3 * 16 + 2] = 0;
    if select_image(&ambiguous, 3, 1).is_ok() {
        return TestResult::Fail("ambiguous cut admitted");
    }
    let mut invalid_other = bytes;
    put(&mut invalid_other, 16 + 3 * 16 + 4, 0);
    if select_image(&invalid_other, 1, 1).is_ok() {
        return TestResult::Fail("nonselected entry overlaps TOC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_mfw_physical_cut_selection
);

struct ModelFiles {
    responses: Vec<Result<Vec<u8>, FwError>>,
    names: Vec<&'static str>,
}
impl Files for ModelFiles {
    fn load(&mut self, name: &'static str) -> Result<Vec<u8>, FwError> {
        self.names.push(name);
        if self.responses.is_empty() {
            return Err(FwError::BlobMissing);
        }
        self.responses.remove(0)
    }
}
fn smoke_rtw89_owned_firmware_and_fallback() -> TestResult {
    let plain = image(0, 1, 8);
    let file = mfw(&[(0, 1, false, image(0, 1, 0)), (0, 5, false, plain.clone())]);
    let mut files = ModelFiles {
        responses: vec![Err(FwError::BlobMissing), Ok(file)],
        names: Vec::new(),
    };
    let prepared = match prepared::load(&mut files, ChipId::Rtl8852B, 1) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("owned CE selection"),
    };
    if files.names != ["rtw89/rtw8852b_fw-2.bin", "rtw89/rtw8852b_fw-1.bin"]
        || prepared.image() != plain
        || prepared.name() != files.names[1]
        || prepared.payload(0) != Some(&[0; 17][..])
        || prepared.payload(1).is_some()
    {
        return TestResult::Fail("image owner / path priority / CE preference");
    }
    let header = match prepared.unsecured_header() {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("header preparation"),
    };
    if header.len() != 48
        || header[28..32] != [0xe4, 7, 1, 0]
        || prepared.header().hdr_len != 56
        || prepared.image() != plain
    {
        return TestResult::Fail(
            "download header must exclude dynamic extension and preserve owner",
        );
    }
    for error in [FwError::Authority, FwError::BadFormat, FwError::NoMemory] {
        let mut files = ModelFiles {
            responses: vec![Err(error), Ok(image(0, 1, 0))],
            names: Vec::new(),
        };
        if !matches!(prepared::load(&mut files, ChipId::Rtl8852A, 0), Err(e) if e == error)
            || files.names.len() != 1
        {
            return TestResult::Fail("invalid/untrusted file silently downgraded");
        }
    }
    let mut files = ModelFiles {
        responses: vec![Ok(vec![0; 32]), Ok(image(0, 1, 0))],
        names: Vec::new(),
    };
    if prepared::load(&mut files, ChipId::Rtl8852A, 0).is_ok() || files.names.len() != 1 {
        return TestResult::Fail("invalid image bypassed");
    }
    let mut files = ModelFiles {
        responses: vec![Ok(image(0, 1, 0))],
        names: Vec::new(),
    };
    if prepared::load(&mut files, ChipId::Rtl8922A, 0).is_ok() || !files.names.is_empty() {
        return TestResult::Fail("BE admitted through AX loader");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_owned_firmware_and_fallback
);
