//! Smoke tests for narf-edid.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;

use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{compute_checksum, Block, DisplayDescriptor, EdidError, EDID_BLOCK_SIZE, EDID_HEADER};

/// Build a valid 128-byte EDID block with the supplied fields and
/// recompute the checksum.
fn make_block(fill: impl FnOnce(&mut [u8; 128])) -> [u8; 128] {
    let mut b = [0u8; 128];
    b[0..8].copy_from_slice(&EDID_HEADER);
    fill(&mut b);
    b[127] = compute_checksum(&b);
    b
}

fn smoke_edid_header_magic_required() -> TestResult {
    let mut b = [0u8; EDID_BLOCK_SIZE];
    b[127] = compute_checksum(&b);
    match Block::parse(&b) {
        Err(EdidError::BadHeader) => TestResult::Pass,
        _ => TestResult::Fail("missing header magic must be rejected"),
    }
}
kernel_test_in!("edid", smoke_edid_header_magic_required);

fn smoke_edid_checksum_required() -> TestResult {
    let mut b = make_block(|_| {});
    b[127] = b[127].wrapping_add(1); // tamper checksum
    match Block::parse(&b) {
        Err(EdidError::BadChecksum) => TestResult::Pass,
        _ => TestResult::Fail("bad checksum must be rejected"),
    }
}
kernel_test_in!("edid", smoke_edid_checksum_required);

fn smoke_edid_manufacturer_id_decodes_pnp_5bit_compressed() -> TestResult {
    // "DEL" = 0b00100 0b00101 0b01100 → 0x10AC big-endian.
    let b = make_block(|b| {
        b[8] = 0x10;
        b[9] = 0xAC;
        b[18] = 1;
        b[19] = 4;
    });
    let blk = Block::parse(&b).expect("parse");
    if blk.manufacturer_id != ['D', 'E', 'L'] {
        return TestResult::Fail("PNP ID 5-bit decode should produce 'DEL'");
    }
    TestResult::Pass
}
kernel_test_in!(
    "edid",
    smoke_edid_manufacturer_id_decodes_pnp_5bit_compressed
);

fn smoke_edid_manufacture_year_offsets_from_1990() -> TestResult {
    let b = make_block(|b| {
        // PNP "AAA" valid.
        b[8] = 0x04;
        b[9] = 0x21;
        b[16] = 12; // week
        b[17] = 35; // year offset → 2025
        b[18] = 1;
        b[19] = 4;
    });
    let blk = Block::parse(&b).expect("parse");
    if blk.manufacture_year != 2025 {
        return TestResult::Fail("year offset 35 should decode to 2025");
    }
    if blk.manufacture_week != 12 {
        return TestResult::Fail("week field should pass through");
    }
    TestResult::Pass
}
kernel_test_in!("edid", smoke_edid_manufacture_year_offsets_from_1990);

fn smoke_edid_detailed_timing_decodes_1080p_60() -> TestResult {
    // Synthesise a DTD for 1920x1080 @ 60 Hz with a plausible
    // pixel clock (148.5 MHz). Per §3.10.2 the pixel clock is
    // stored in 10 kHz units, and the H/V active/blanking are
    // packed via low byte + high nibble.
    //
    //   pixel_clock = 14850 (= 148.5 MHz).
    //   h_active = 1920, h_blanking = 280  (h_total 2200)
    //   v_active = 1080, v_blanking = 45   (v_total 1125)
    let mut dtd = [0u8; 18];
    let pixel_clock_10khz: u16 = 14_850;
    dtd[0] = (pixel_clock_10khz & 0xFF) as u8;
    dtd[1] = (pixel_clock_10khz >> 8) as u8;
    let h_active = 1920u16;
    let h_blank = 280u16;
    dtd[2] = (h_active & 0xFF) as u8;
    dtd[3] = (h_blank & 0xFF) as u8;
    dtd[4] = (((h_active >> 8) & 0xF) << 4) as u8 | ((h_blank >> 8) & 0xF) as u8;
    let v_active = 1080u16;
    let v_blank = 45u16;
    dtd[5] = (v_active & 0xFF) as u8;
    dtd[6] = (v_blank & 0xFF) as u8;
    dtd[7] = (((v_active >> 8) & 0xF) << 4) as u8 | ((v_blank >> 8) & 0xF) as u8;
    // Sync offsets / widths (set arbitrarily — we don't check them).
    dtd[8] = 88;
    dtd[9] = 44;
    dtd[10] = 0x44;
    dtd[11] = 0x00;
    // Image size (mm) — set to zero, we don't check.
    dtd[14] = 0;
    // Sync polarity flags: digital separate (4..5 = 0b11), HSync+, VSync+.
    dtd[17] = 0x18 | 0x06;

    let b = make_block(|b| {
        b[8] = 0x04;
        b[9] = 0x21;
        b[18] = 1;
        b[19] = 4;
        b[54..72].copy_from_slice(&dtd);
    });
    let blk = Block::parse(&b).expect("parse");
    let dt = blk
        .preferred_mode()
        .expect("DTD-0 should be a Detailed Timing");
    if dt.h_active != 1920 {
        return TestResult::Fail("H active should decode to 1920");
    }
    if dt.v_active != 1080 {
        return TestResult::Fail("V active should decode to 1080");
    }
    if dt.pixel_clock_khz != 148_500 {
        return TestResult::Fail("pixel clock should decode to 148_500 kHz");
    }
    // Refresh rate: 148_500_000 / (2200 × 1125) ≈ 60_000 mHz.
    let r = dt.refresh_mhz();
    if !(59_500..=60_500).contains(&r) {
        return TestResult::Fail("refresh rate should be ~60 Hz");
    }
    TestResult::Pass
}
kernel_test_in!("edid", smoke_edid_detailed_timing_decodes_1080p_60);

fn smoke_edid_monitor_name_descriptor() -> TestResult {
    // DTD slot containing a Monitor Name descriptor.
    let mut desc = [0u8; 18];
    desc[0] = 0;
    desc[1] = 0;
    desc[2] = 0;
    desc[3] = 0xFC; // Monitor Name
    desc[4] = 0;
    let name = b"narf monitor\n";
    desc[5..5 + name.len()].copy_from_slice(name);
    let b = make_block(|b| {
        b[8] = 0x04;
        b[9] = 0x21;
        b[18] = 1;
        b[19] = 4;
        b[54..72].copy_from_slice(&desc);
    });
    let blk = Block::parse(&b).expect("parse");
    let n = blk.monitor_name().expect("name");
    if n != "narf monitor" {
        return TestResult::Fail("monitor name decode wrong");
    }
    // Descriptor surfaced as DisplayDescriptor variant too.
    let mut found = false;
    for d in &blk.display_descriptors {
        if let DisplayDescriptor::MonitorName(s) = d {
            if s == "narf monitor" {
                found = true;
            }
        }
    }
    if !found {
        return TestResult::Fail("MonitorName not in display_descriptors");
    }
    TestResult::Pass
}
kernel_test_in!("edid", smoke_edid_monitor_name_descriptor);

fn smoke_edid_compute_checksum_round_trip() -> TestResult {
    let mut bytes: Vec<u8> = (0..127u8).collect();
    bytes.push(0); // checksum slot to be computed
    bytes[127] = compute_checksum(&bytes);
    let sum = bytes.iter().fold(0u32, |acc, b| acc + *b as u32);
    if sum & 0xFF != 0 {
        return TestResult::Fail("checksummed block should sum to 0 mod 256");
    }
    TestResult::Pass
}
kernel_test_in!("edid", smoke_edid_compute_checksum_round_trip);
