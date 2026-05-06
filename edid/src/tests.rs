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

// ── CTA-861 extension-block smokes ─────────────────────────────────

fn make_cta_block(fill: impl FnOnce(&mut [u8; 128])) -> [u8; 128] {
    let mut b = [0u8; 128];
    b[0] = crate::cta861::CTA_TAG;
    b[1] = 3; // revision
    fill(&mut b);
    b[127] = compute_checksum(&b);
    b
}

fn smoke_cta_extension_tag_required() -> TestResult {
    let mut b = [0u8; 128];
    // wrong tag
    b[0] = 0x40;
    b[127] = compute_checksum(&b);
    match crate::cta861::CtaExtension::parse(&b) {
        Err(EdidError::BadHeader) => TestResult::Pass,
        _ => TestResult::Fail("non-0x02 tag must be rejected"),
    }
}
kernel_test_in!("edid/cta861", smoke_cta_extension_tag_required);

fn smoke_cta_caps_decode() -> TestResult {
    use crate::cta861::{CtaCaps, CtaExtension};
    let b = make_cta_block(|b| {
        b[2] = 4; // dtd_offset = 4 → empty DBC, no DTDs
        b[3] = 0xC0 | 1; // UNDERSCAN | BASIC_AUDIO + 1 native DTD count
    });
    let ext = CtaExtension::parse(&b).expect("parse");
    if !ext.caps.contains(CtaCaps::UNDERSCAN) {
        return TestResult::Fail("UNDERSCAN flag should be set");
    }
    if !ext.caps.contains(CtaCaps::BASIC_AUDIO) {
        return TestResult::Fail("BASIC_AUDIO flag should be set");
    }
    if ext.native_dtd_count != 1 {
        return TestResult::Fail("native dtd count low nibble = 1");
    }
    TestResult::Pass
}
kernel_test_in!("edid/cta861", smoke_cta_caps_decode);

fn smoke_cta_video_data_block_lists_vics() -> TestResult {
    use crate::cta861::{CtaExtension, DataBlock};
    // Place a VDB (tag 2) with three SVDs at offset 4. Header byte =
    // (2<<5) | 3 = 0x43. SVDs: 16 (1080p60, native), 4 (720p60), 1 (640x480).
    let b = make_cta_block(|b| {
        b[2] = 8; // dtd_offset: 4 + (1 header + 3 payload) = 8
        b[3] = 0;
        b[4] = (2 << 5) | 3; // tag=2 (Video), len=3
        b[5] = 0x80 | 16; // VIC 16 native
        b[6] = 4;
        b[7] = 1;
    });
    let ext = CtaExtension::parse(&b).expect("parse");
    assert_eq!(ext.data_blocks.len(), 1);
    match &ext.data_blocks[0] {
        DataBlock::Video(svds) => {
            if svds.len() != 3 {
                return TestResult::Fail("expected 3 SVDs");
            }
            if svds[0].vic != 16 || !svds[0].native {
                return TestResult::Fail("first SVD should be VIC 16, native");
            }
            if svds[1].vic != 4 || svds[1].native {
                return TestResult::Fail("second SVD wrong");
            }
        }
        _ => return TestResult::Fail("expected Video data block"),
    }
    TestResult::Pass
}
kernel_test_in!("edid/cta861", smoke_cta_video_data_block_lists_vics);

fn smoke_cta_audio_data_block_decodes_lpcm() -> TestResult {
    use crate::cta861::{CtaExtension, DataBlock};
    // ADB (tag 1) with one 3-byte SAD: format=1 (LPCM), max_ch=2-1=1,
    // sample rates bitmap = 0x07 (32/44.1/48 kHz), bit-depths = 0x01 (16-bit).
    //   byte 0: (format << 3) | (chan-1) = (1<<3) | 1 = 0x09
    let b = make_cta_block(|b| {
        b[2] = 8; // dtd_offset = 4 + 1 header + 3 = 8
        b[3] = 0;
        b[4] = (1 << 5) | 3; // tag=1 (Audio), len=3
        b[5] = 0x09;
        b[6] = 0x07;
        b[7] = 0x01;
    });
    let ext = CtaExtension::parse(&b).expect("parse");
    match &ext.data_blocks[0] {
        DataBlock::Audio(sads) => {
            if sads.len() != 1 {
                return TestResult::Fail("expected 1 SAD");
            }
            if sads[0].format != 1 {
                return TestResult::Fail("LPCM format = 1");
            }
            if sads[0].max_channels != 2 {
                return TestResult::Fail("max_channels = 2 (encoded as ch-1)");
            }
            if sads[0].sample_rates != 0x07 {
                return TestResult::Fail("sample-rates bitmap should round-trip");
            }
        }
        _ => return TestResult::Fail("expected Audio data block"),
    }
    TestResult::Pass
}
kernel_test_in!("edid/cta861", smoke_cta_audio_data_block_decodes_lpcm);

fn smoke_cta_hdmi_vsdb_extracts_phys_addr() -> TestResult {
    use crate::cta861::{CtaExtension, HDMI_LICENSING_OUI};
    // VSDB (tag 3), payload: OUI=0x000C03 (LE: 03 0C 00) + phys_addr 0x1000.
    let b = make_cta_block(|b| {
        b[2] = 10; // dtd_offset = 4 + 1 header + 5 payload = 10
        b[3] = 0;
        b[4] = (3 << 5) | 5; // tag=3, len=5
        b[5] = HDMI_LICENSING_OUI[0];
        b[6] = HDMI_LICENSING_OUI[1];
        b[7] = HDMI_LICENSING_OUI[2];
        b[8] = 0x10; // phys addr hi
        b[9] = 0x00; // phys addr lo
    });
    let ext = CtaExtension::parse(&b).expect("parse");
    let v = ext.hdmi_vsdb().expect("HDMI VSDB present");
    if v.cec_phys_addr != 0x1000 {
        return TestResult::Fail("CEC phys addr should round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("edid/cta861", smoke_cta_hdmi_vsdb_extracts_phys_addr);

fn smoke_cta_extended_tag_block() -> TestResult {
    use crate::cta861::{CtaExtension, DataBlock};
    // Extended-tag block (tag 7). Length 2 = ext-tag byte + 1 payload byte.
    let b = make_cta_block(|b| {
        b[2] = 7; // dtd_offset
        b[3] = 0;
        b[4] = (7 << 5) | 2; // tag=7, len=2
        b[5] = 0x06; // extended tag = HDR Static Metadata Data Block
        b[6] = 0xAA; // payload byte
    });
    let ext = CtaExtension::parse(&b).expect("parse");
    match &ext.data_blocks[0] {
        DataBlock::Extended { ext_tag, payload } => {
            if *ext_tag != 0x06 {
                return TestResult::Fail("extended tag byte mismatch");
            }
            if payload != &[0xAA] {
                return TestResult::Fail("extended block payload mismatch");
            }
        }
        _ => return TestResult::Fail("expected Extended data block"),
    }
    TestResult::Pass
}
kernel_test_in!("edid/cta861", smoke_cta_extended_tag_block);

fn smoke_cta_speaker_allocation_block() -> TestResult {
    use crate::cta861::{CtaExtension, DataBlock, SpeakerAllocation};
    let b = make_cta_block(|b| {
        b[2] = 8; // dtd_offset
        b[3] = 0;
        b[4] = (4 << 5) | 3; // tag=4 (Speaker), len=3
        b[5] = SpeakerAllocation::FL_FR | SpeakerAllocation::LFE | SpeakerAllocation::FC;
        b[6] = 0;
        b[7] = 0;
    });
    let ext = CtaExtension::parse(&b).expect("parse");
    match &ext.data_blocks[0] {
        DataBlock::Speaker(s) => {
            if s.0 & SpeakerAllocation::FC == 0 {
                return TestResult::Fail("FC bit should be present");
            }
        }
        _ => return TestResult::Fail("expected Speaker data block"),
    }
    TestResult::Pass
}
kernel_test_in!("edid/cta861", smoke_cta_speaker_allocation_block);

// ── HDMI CEC smokes ────────────────────────────────────────────────

fn smoke_cec_header_byte_packs_initiator_and_destination() -> TestResult {
    use crate::cec::{Frame, LogicalAddress, OPCODE_STANDBY};
    let f = Frame::new(LogicalAddress::PlaybackDevice1.as_u8(), 0xF, OPCODE_STANDBY);
    if f.header() != 0x4F {
        return TestResult::Fail("header byte should be (init<<4) | dest");
    }
    TestResult::Pass
}
kernel_test_in!("edid/cec", smoke_cec_header_byte_packs_initiator_and_destination);

fn smoke_cec_polling_message_is_header_only() -> TestResult {
    use crate::cec::Frame;
    let f = Frame::polling(4);
    let bytes = f.encode();
    if bytes.len() != 1 {
        return TestResult::Fail("polling message must be header-only");
    }
    let back = Frame::decode(&bytes).expect("decode polling");
    if !back.is_polling() {
        return TestResult::Fail("decode should preserve polling shape");
    }
    if back.initiator != 4 || back.destination != 4 {
        return TestResult::Fail("polling pings the address you want to claim");
    }
    TestResult::Pass
}
kernel_test_in!("edid/cec", smoke_cec_polling_message_is_header_only);

fn smoke_cec_active_source_carries_phys_addr_be() -> TestResult {
    use crate::cec::{active_source, Frame, OPCODE_ACTIVE_SOURCE, CEC_BROADCAST};
    let f = active_source(4, 0x1234);
    let bytes = f.encode();
    // header (0x4F) | opcode (0x82) | phys hi | phys lo
    if bytes.len() != 4 {
        return TestResult::Fail("active source = 4 bytes");
    }
    if bytes[0] != 0x4F {
        return TestResult::Fail("Active Source must broadcast → header low nibble = 0xF");
    }
    if bytes[1] != OPCODE_ACTIVE_SOURCE {
        return TestResult::Fail("opcode mismatch");
    }
    if bytes[2] != 0x12 || bytes[3] != 0x34 {
        return TestResult::Fail("phys-addr must be big-endian on the wire");
    }
    let back = Frame::decode(&bytes).expect("decode");
    if back.destination != CEC_BROADCAST {
        return TestResult::Fail("decoded destination != broadcast");
    }
    TestResult::Pass
}
kernel_test_in!("edid/cec", smoke_cec_active_source_carries_phys_addr_be);

fn smoke_cec_set_osd_name_truncates_to_14() -> TestResult {
    use crate::cec::set_osd_name;
    let f = set_osd_name(4, 0, "Long enough name to truncate");
    if f.operands.len() != 14 {
        return TestResult::Fail("Set OSD Name operands cap at 14 bytes (16 - header - opcode)");
    }
    if &f.operands[..14] != b"Long enough na" {
        return TestResult::Fail("truncation should keep the prefix");
    }
    TestResult::Pass
}
kernel_test_in!("edid/cec", smoke_cec_set_osd_name_truncates_to_14);

fn smoke_cec_feature_abort_layout() -> TestResult {
    use crate::cec::{feature_abort, OPCODE_FEATURE_ABORT};
    let f = feature_abort(4, 0, 0x44, 0x00);
    let bytes = f.encode();
    if bytes[1] != OPCODE_FEATURE_ABORT {
        return TestResult::Fail("opcode 0x00 expected");
    }
    if bytes[2] != 0x44 {
        return TestResult::Fail("first operand is the rejected opcode");
    }
    if bytes[3] != 0x00 {
        return TestResult::Fail("second operand is the reason byte");
    }
    TestResult::Pass
}
kernel_test_in!("edid/cec", smoke_cec_feature_abort_layout);

fn smoke_cec_report_physical_address_layout() -> TestResult {
    use crate::cec::{report_physical_address, OPCODE_REPORT_PHYSICAL_ADDRESS, CEC_BROADCAST};
    let f = report_physical_address(4, 0x2000, 4);
    let bytes = f.encode();
    if (bytes[0] & 0x0F) != CEC_BROADCAST {
        return TestResult::Fail("Report Phys Addr must broadcast");
    }
    if bytes[1] != OPCODE_REPORT_PHYSICAL_ADDRESS {
        return TestResult::Fail("opcode 0x84 expected");
    }
    if bytes[2] != 0x20 || bytes[3] != 0x00 {
        return TestResult::Fail("phys addr operands wrong");
    }
    if bytes[4] != 4 {
        return TestResult::Fail("device-type byte must be present");
    }
    TestResult::Pass
}
kernel_test_in!("edid/cec", smoke_cec_report_physical_address_layout);

fn smoke_cec_decode_rejects_oversize_frame() -> TestResult {
    use crate::cec::{CecError, Frame};
    let buf = [0u8; 17];
    match Frame::decode(&buf) {
        Err(CecError::TooLong) => TestResult::Pass,
        _ => TestResult::Fail(">16 byte frame must be rejected"),
    }
}
kernel_test_in!("edid/cec", smoke_cec_decode_rejects_oversize_frame);

// ── DisplayID 2.0 smokes ───────────────────────────────────────────

fn smoke_displayid_rejects_v1() -> TestResult {
    use crate::displayid::{DisplayIdError, Section};
    // version/revision byte = 0x12 (DisplayID 1.2) — must be rejected.
    let buf = [0x12u8, 0, 2, 0, 0];
    match Section::parse(&buf) {
        Err(DisplayIdError::NotV2) => TestResult::Pass,
        _ => TestResult::Fail("DisplayID 1.x must be rejected"),
    }
}
kernel_test_in!("edid/displayid", smoke_displayid_rejects_v1);

fn smoke_displayid_checksum_required() -> TestResult {
    use crate::displayid::{compute_checksum, DisplayIdError, Section};
    let mut buf = alloc::vec![0x20u8, 0, 2, 0]; // empty section
    buf.push(compute_checksum(&buf));
    buf[4] = buf[4].wrapping_add(1); // tamper
    match Section::parse(&buf) {
        Err(DisplayIdError::BadChecksum) => TestResult::Pass,
        _ => TestResult::Fail("bad checksum must be rejected"),
    }
}
kernel_test_in!("edid/displayid", smoke_displayid_checksum_required);

fn smoke_displayid_type_vii_decodes_4k60() -> TestResult {
    use crate::displayid::{compute_checksum, DataBlock, Section, DB_TYPE_VII_TIMING};
    // Build a Type VII block carrying one 20-byte timing for
    // 3840x2160@60Hz with 533.25 MHz pixel clock (CTA VIC 97).
    //   pixel_clock = 533250 kHz → encoded = 533249 LE 24-bit
    //   h_active = 3840 → encoded 3839
    //   h_blank  = 560 → encoded 559
    //   h_front_porch = 176, sync positive → high bit set
    //   h_sync_width = 88 → encoded 87
    //   v_active = 2160 → encoded 2159
    //   v_blank = 90 → encoded 89
    //   v_front_porch = 8 → encoded 7, sync positive
    //   v_sync_width = 10 → encoded 9
    let pix = 533_250u32 - 1;
    let mut t = [0u8; 20];
    t[0] = (pix & 0xFF) as u8;
    t[1] = ((pix >> 8) & 0xFF) as u8;
    t[2] = ((pix >> 16) & 0xFF) as u8;
    t[3] = 0; // flags
    let h_active = 3839u16;
    t[4..6].copy_from_slice(&h_active.to_le_bytes());
    let h_blank = 559u16;
    t[6..8].copy_from_slice(&h_blank.to_le_bytes());
    let h_fp = 175u16 | 0x8000;
    t[8..10].copy_from_slice(&h_fp.to_le_bytes());
    let h_sw = 87u16;
    t[10..12].copy_from_slice(&h_sw.to_le_bytes());
    let v_active = 2159u16;
    t[12..14].copy_from_slice(&v_active.to_le_bytes());
    let v_blank = 89u16;
    t[14..16].copy_from_slice(&v_blank.to_le_bytes());
    let v_fp = 7u16 | 0x8000;
    t[16..18].copy_from_slice(&v_fp.to_le_bytes());
    t[18] = 9;
    t[19] = 0;

    // Build the section: header (4) + DB header (3) + 20-byte payload + checksum.
    let mut section = alloc::vec![0x20u8, 23, crate::displayid::USECASE_GENERIC_DISPLAY, 0];
    section.push(DB_TYPE_VII_TIMING);
    section.push(0); // revision
    section.push(20); // length
    section.extend_from_slice(&t);
    section.push(compute_checksum(&section));

    let s = Section::parse(&section).expect("parse");
    let pref = s.preferred_type_vii().expect("Type VII present");
    if pref.h_active != 3840 || pref.v_active != 2160 {
        return TestResult::Fail("4K active size should round-trip");
    }
    if pref.pixel_clock_khz != 533_250 {
        return TestResult::Fail("pixel clock should round-trip to 533_250");
    }
    if !pref.h_sync_positive || !pref.v_sync_positive {
        return TestResult::Fail("sync polarity bits lost");
    }
    let r = pref.refresh_mhz();
    if !(59_500..=60_500).contains(&r) {
        return TestResult::Fail("refresh should be ~60 Hz");
    }
    // The data block should also surface as a TypeVIITiming variant.
    let mut found_type_vii = false;
    for b in &s.data_blocks {
        if matches!(b, DataBlock::TypeVIITiming(_)) {
            found_type_vii = true;
        }
    }
    if !found_type_vii {
        return TestResult::Fail("Type VII data block missing from collection");
    }
    TestResult::Pass
}
kernel_test_in!("edid/displayid", smoke_displayid_type_vii_decodes_4k60);

fn smoke_displayid_unknown_block_kept_opaque() -> TestResult {
    use crate::displayid::{compute_checksum, DataBlock, Section};
    // Container ID block (tag 0x0C) — we don't decode it yet. Should
    // surface as Other { tag: 0x0C }.
    let mut section = alloc::vec![0x20u8, 7, 0x02, 0]; // header
    section.push(0x0C); // tag
    section.push(0); // revision
    section.push(4); // length
    section.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    section.push(compute_checksum(&section));
    let s = Section::parse(&section).expect("parse");
    if s.data_blocks.len() != 1 {
        return TestResult::Fail("expected 1 data block");
    }
    match &s.data_blocks[0] {
        DataBlock::Other { tag, payload, .. } => {
            if *tag != 0x0C || payload != &[0xAA, 0xBB, 0xCC, 0xDD] {
                return TestResult::Fail("opaque block payload mismatch");
            }
        }
        _ => return TestResult::Fail("unknown tag should land in Other"),
    }
    TestResult::Pass
}
kernel_test_in!("edid/displayid", smoke_displayid_unknown_block_kept_opaque);
