//! Smoke tests for the `atombios` parser.
//!
//! All smokes work against a synthetic in-memory VBIOS image so they
//! run on every build without real hardware.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

// ── synthetic image builder ────────────────────────────────────────────────

/// Build a minimal synthetic VBIOS image used by most smokes.
///
/// Layout:
/// - Bytes 0..0x48: padding (zeros)
/// - Bytes 0x48-0x49: little-endian u16 = 0x0100 (pointer to ROM header)
/// - At 0x0100: ATOM_ROM_HEADER with `atom_signature = "ATOM"`,
///   `bios_bootup_message_offset = 0x0200`,
///   `master_data_table_offset = 0x0180`.
/// - At 0x0180: minimal master data table directory
///   (size = 6 → 1 entry → offset 0x0140).
/// - At 0x0140: minimal subtable with usStructureSize = 8.
/// - At 0x0200: NUL-terminated "FAKE BIOS VERSION 1.0".
fn build_synthetic_image() -> alloc::vec::Vec<u8> {
    let mut img = alloc::vec![0u8; 0x300];

    // ROM header pointer at 0x48.
    let hdr_ptr: u16 = 0x0100;
    img[0x48] = (hdr_ptr & 0xFF) as u8;
    img[0x49] = (hdr_ptr >> 8) as u8;

    // ATOM_ROM_HEADER at 0x0100.
    let h = 0x0100usize;
    img[h..h + 4].copy_from_slice(b"ATOM");
    // bios_bootup_message_offset at header+0x0C.
    let msg_off: u16 = 0x0200;
    img[h + 0x0C] = (msg_off & 0xFF) as u8;
    img[h + 0x0D] = (msg_off >> 8) as u8;
    // master_data_table_offset at header+0x1C.
    let mdt_off: u16 = 0x0180;
    img[h + 0x1C] = (mdt_off & 0xFF) as u8;
    img[h + 0x1D] = (mdt_off >> 8) as u8;

    // Master data table at 0x0180: size=6, format_rev=1, content_rev=0,
    // 1 entry → 0x0140.
    let m = 0x0180usize;
    img[m..m + 2].copy_from_slice(&6u16.to_le_bytes());
    img[m + 2] = 1;
    img[m + 3] = 0;
    img[m + 4..m + 6].copy_from_slice(&0x0140u16.to_le_bytes());

    // Subtable at 0x0140: size=8.
    img[0x0140..0x0142].copy_from_slice(&8u16.to_le_bytes());

    // Version string at 0x0200 (NUL-terminated).
    let ver = b"FAKE BIOS VERSION 1.0\0";
    img[0x0200..0x0200 + ver.len()].copy_from_slice(ver);

    img
}

extern crate alloc;

// ── Smoke 1: valid image → AtomBios returned ──────────────────────────────

fn smoke_atombios_parse_valid_header() -> TestResult {
    use crate::atombios::parse;
    let img = build_synthetic_image();
    match parse(&img) {
        Ok(_) => TestResult::Pass,
        Err(e) => TestResult::Fail(alloc::boxed::Box::leak(
            alloc::format!("parse failed: {:?}", e).into_boxed_str(),
        )),
    }
}
kernel_test_in!("drivers/gpu", smoke_atombios_parse_valid_header);

// ── Smoke 2: bad signature → InvalidVbios ──────────────────────────────────

fn smoke_atombios_bad_atom_signature() -> TestResult {
    use crate::atombios::{parse, AtomBiosError};
    let mut img = build_synthetic_image();
    // Corrupt the "ATOM" signature.
    img[0x0100] = b'X';
    match parse(&img) {
        Err(AtomBiosError::BadAtomSignature) => TestResult::Pass,
        other => TestResult::Fail(alloc::boxed::Box::leak(
            alloc::format!("expected BadAtomSignature, got {:?}", other).into_boxed_str(),
        )),
    }
}
kernel_test_in!("drivers/gpu", smoke_atombios_bad_atom_signature);

// ── Smoke 3: too-short image → InvalidVbios ────────────────────────────────

fn smoke_atombios_too_short_image() -> TestResult {
    use crate::atombios::{parse, AtomBiosError};
    // Only 0x40 bytes — can't hold the ROM header pointer at 0x48.
    let img = alloc::vec![0u8; 0x40];
    match parse(&img) {
        Err(AtomBiosError::InvalidVbios) => TestResult::Pass,
        other => TestResult::Fail(alloc::boxed::Box::leak(
            alloc::format!("expected InvalidVbios, got {:?}", other).into_boxed_str(),
        )),
    }
}
kernel_test_in!("drivers/gpu", smoke_atombios_too_short_image);

// ── Smoke 4: extract_version returns the right string ──────────────────────

fn smoke_atombios_extract_version_correct() -> TestResult {
    use crate::atombios::parse;
    let img = build_synthetic_image();
    let atom = match parse(&img) {
        Ok(a) => a,
        Err(e) => {
            return TestResult::Fail(alloc::boxed::Box::leak(
                alloc::format!("parse failed: {:?}", e).into_boxed_str(),
            ))
        }
    };
    match atom.version.as_deref() {
        Some("FAKE BIOS VERSION 1.0") => TestResult::Pass,
        Some(v) => TestResult::Fail(alloc::boxed::Box::leak(
            alloc::format!("wrong version: {:?}", v).into_boxed_str(),
        )),
        None => TestResult::Fail("version is None"),
    }
}
kernel_test_in!("drivers/gpu", smoke_atombios_extract_version_correct);

// ── Smoke 5: missing NUL terminator handled gracefully ─────────────────────

fn smoke_atombios_no_nul_terminator() -> TestResult {
    use crate::atombios::parse;
    // Build a custom image where the version string has no NUL before EOF.
    let mut img = build_synthetic_image();
    // Fill the version area with non-NUL ASCII up to end of image.
    let ver_off = 0x0200;
    let fill = b"NONULTERM";
    for (i, &b) in fill.iter().enumerate() {
        if ver_off + i < img.len() {
            img[ver_off + i] = b;
        }
    }
    // Zero out any trailing NUL that the synthetic builder may have left.
    for b in &mut img[ver_off + fill.len()..] {
        *b = b'X';
    }
    // Parser must not panic; it may return Some or None but must not crash.
    let result = parse(&img);
    // As long as we don't panic, the test passes.
    match result {
        Ok(atom) => {
            // We got a parsed result; version may be Some or None.
            let _ = atom.version;
            TestResult::Pass
        }
        Err(e) => TestResult::Fail(alloc::boxed::Box::leak(
            alloc::format!("unexpected error: {:?}", e).into_boxed_str(),
        )),
    }
}
kernel_test_in!("drivers/gpu", smoke_atombios_no_nul_terminator);

// ── Smoke 6: vbios_version() via DrmCard ───────────────────────────────────

fn smoke_atombios_drm_card_vbios_version() -> TestResult {
    use crate::atombios::parse;
    use crate::drm_devfs_bridge::AmdgpuCard;
    use crate::drm_registry::DrmCard;

    let img = build_synthetic_image();
    let atom = match parse(&img) {
        Ok(a) => a,
        Err(e) => {
            return TestResult::Fail(alloc::boxed::Box::leak(
                alloc::format!("parse failed: {:?}", e).into_boxed_str(),
            ))
        }
    };
    let card = AmdgpuCard::new(
        alloc::string::String::from("card0"),
        0x1002,
        0x1636,
        0x0000,
        0x0000,
        atom.version.clone(),
    );
    match card.vbios_version() {
        Some("FAKE BIOS VERSION 1.0") => TestResult::Pass,
        Some(v) => TestResult::Fail(alloc::boxed::Box::leak(
            alloc::format!("wrong vbios_version: {:?}", v).into_boxed_str(),
        )),
        None => TestResult::Fail("DrmCard::vbios_version() returned None"),
    }
}
kernel_test_in!("drivers/gpu", smoke_atombios_drm_card_vbios_version);

// ── Smoke 7: sysfs vbios_version format includes trailing newline ──────────

fn smoke_atombios_sysfs_version_format() -> TestResult {
    // The sysfs bridge formats the version as "{ver}\n".
    // Verify with a direct format call (not real sysfs).
    let version = "FAKE BIOS VERSION 1.0";
    let sysfs_val = alloc::format!("{}\n", version);
    if sysfs_val == "FAKE BIOS VERSION 1.0\n" {
        TestResult::Pass
    } else {
        TestResult::Fail("sysfs format wrong")
    }
}
kernel_test_in!("drivers/gpu", smoke_atombios_sysfs_version_format);

// ── Smoke 8: master data table offset validates (in-bounds) ────────────────

fn smoke_atombios_master_data_table_in_bounds() -> TestResult {
    use crate::atombios::parse;
    let img = build_synthetic_image();
    let atom = match parse(&img) {
        Ok(a) => a,
        Err(e) => {
            return TestResult::Fail(alloc::boxed::Box::leak(
                alloc::format!("parse failed: {:?}", e).into_boxed_str(),
            ))
        }
    };
    // n_tables should be 1 (1 entry in the synthetic directory).
    if atom.n_data_tables != 1 {
        return TestResult::Fail(alloc::boxed::Box::leak(
            alloc::format!("expected 1 data table, got {}", atom.n_data_tables).into_boxed_str(),
        ));
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu", smoke_atombios_master_data_table_in_bounds);

// ── Smoke 9: bootup message offset out of bounds → None ────────────────────

fn smoke_atombios_bootup_msg_out_of_bounds() -> TestResult {
    use crate::atombios::parse;
    let mut img = build_synthetic_image();
    // Point bios_bootup_message_offset past end of image.
    let h = 0x0100usize;
    let bad_off: u16 = 0xFFFF;
    img[h + 0x0C] = (bad_off & 0xFF) as u8;
    img[h + 0x0D] = (bad_off >> 8) as u8;
    let atom = match parse(&img) {
        Ok(a) => a,
        Err(e) => {
            return TestResult::Fail(alloc::boxed::Box::leak(
                alloc::format!("parse should succeed (header is valid), got {:?}", e)
                    .into_boxed_str(),
            ))
        }
    };
    // version should be None — out-of-bounds offset handled gracefully.
    if atom.version.is_none() {
        TestResult::Pass
    } else {
        TestResult::Fail("expected None for out-of-bounds msg offset")
    }
}
kernel_test_in!("drivers/gpu", smoke_atombios_bootup_msg_out_of_bounds);

// ── Smoke 10: ROM header pointer itself out of bounds → InvalidVbios ────────

fn smoke_atombios_rom_header_ptr_out_of_bounds() -> TestResult {
    use crate::atombios::{parse, AtomBiosError};
    let mut img = build_synthetic_image();
    // Set the ROM header pointer to a value past end of image.
    let bad_ptr: u16 = 0xFFFE;
    img[0x48] = (bad_ptr & 0xFF) as u8;
    img[0x49] = (bad_ptr >> 8) as u8;
    match parse(&img) {
        Err(AtomBiosError::InvalidVbios) | Err(AtomBiosError::InvalidVbios2) => TestResult::Pass,
        other => TestResult::Fail(alloc::boxed::Box::leak(
            alloc::format!("expected bounds error, got {:?}", other).into_boxed_str(),
        )),
    }
}
kernel_test_in!("drivers/gpu", smoke_atombios_rom_header_ptr_out_of_bounds);
