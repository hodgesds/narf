//! Per-crate smoke tests for `narf-graphics`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"graphics"`.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_graphics_pixel_format() -> TestResult {
    use crate::Pixel32;
    if Pixel32::BLACK.raw() != 0xFF00_0000 {
        return TestResult::Fail("BLACK");
    }
    if Pixel32::WHITE.raw() != 0xFFFF_FFFF {
        return TestResult::Fail("WHITE");
    }
    if Pixel32::RED.raw() != 0xFFFF_0000 {
        return TestResult::Fail("RED");
    }
    if Pixel32::GREEN.raw() != 0xFF00_FF00 {
        return TestResult::Fail("GREEN");
    }
    if Pixel32::BLUE.raw() != 0xFF00_00FF {
        return TestResult::Fail("BLUE");
    }
    let p = Pixel32::rgb(0x12, 0x34, 0x56);
    if p.raw() != 0xFF12_3456 {
        return TestResult::Fail("rgb pack");
    }
    TestResult::Pass
}
kernel_test_in!("graphics", smoke_graphics_pixel_format);

fn smoke_graphics_clear_and_fill_rect() -> TestResult {
    use crate::{Framebuffer, Pixel32};
    use alloc::vec;
    // Build a small in-memory framebuffer (8×4) backed by a heap Vec.
    let mut buf = vec![0u32; 32];
    let ptr = buf.as_mut_ptr();
    // SAFETY: backing store outlives the Framebuffer borrow.
    let mut fb = unsafe { Framebuffer::new(ptr, 8, 4, 8) };
    fb.clear(Pixel32::WHITE);
    if !buf.iter().all(|&p| p == Pixel32::WHITE.raw()) {
        return TestResult::Fail("clear didn't paint every pixel");
    }
    fb.fill_rect(2, 1, 4, 2, Pixel32::RED);
    // Inside-rect pixels should be RED, outside should still be WHITE.
    for y in 0..4 {
        for x in 0..8 {
            let p = buf[y * 8 + x];
            let inside = (2..6).contains(&x) && (1..3).contains(&y);
            let want = if inside {
                Pixel32::RED.raw()
            } else {
                Pixel32::WHITE.raw()
            };
            if p != want {
                return TestResult::Fail("fill_rect pixel mismatch");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("graphics", smoke_graphics_clear_and_fill_rect);

fn smoke_graphics_kind_default_domain() -> TestResult {
    use narf_drivers::BoundKind;
    if BoundKind::Graphics.default_domain() != 7 {
        return TestResult::Fail("Graphics domain != 7");
    }
    TestResult::Pass
}
kernel_test_in!("graphics", smoke_graphics_kind_default_domain);

fn smoke_graphics_font_glyph_lookup() -> TestResult {
    use crate::font8x8;
    // Space is a printable code → empty glyph (all zero bytes).
    let space = font8x8::lookup(b' ');
    if !space.iter().all(|&b| b == 0) {
        return TestResult::Fail("space glyph not blank");
    }
    // Non-printable → also empty.
    let nul = font8x8::lookup(0);
    if !nul.iter().all(|&b| b == 0) {
        return TestResult::Fail("non-printable glyph not blank");
    }
    // 'A' has a non-blank glyph in our font.
    let a = font8x8::lookup(b'A');
    if a.iter().all(|&b| b == 0) {
        return TestResult::Fail("A glyph empty");
    }
    // 'A' should have its leftmost-pixel-of-row pattern be a triangle peak.
    // Just verify the top row has the 0x18 pattern (a centred 2-pixel cap).
    if a[0] != 0b00011000 {
        return TestResult::Fail("A glyph top row drifted");
    }
    TestResult::Pass
}
kernel_test_in!("graphics", smoke_graphics_font_glyph_lookup);

fn smoke_cursor_move_clamps_to_bounds() -> TestResult {
    use crate::{Cursor, Pixel32};
    let mut c = Cursor::new(0, 0, Pixel32::WHITE);
    // Move past right edge — should clamp.
    c.move_relative(1000, 0, 100, 100);
    if c.x != 99 || c.y != 0 {
        return TestResult::Fail("right-clamp wrong");
    }
    // Move past bottom — clamp.
    c.move_relative(0, 1000, 100, 100);
    if c.y != 99 {
        return TestResult::Fail("bottom-clamp wrong");
    }
    // Negative — clamp to 0.
    c.move_relative(-1000, -1000, 100, 100);
    if c.x != 0 || c.y != 0 {
        return TestResult::Fail("zero-clamp wrong");
    }
    TestResult::Pass
}
kernel_test_in!("graphics", smoke_cursor_move_clamps_to_bounds);

fn smoke_cursor_draw_at_paints_arrow_tip() -> TestResult {
    use crate::{Cursor, Framebuffer, Pixel32};
    use alloc::vec;
    // 16x16 in-memory FB. Cursor at (0,0) — top-left pixel of arrow
    // is bit 7 of the first sprite row (0b10000000), so pixel (0,0)
    // is FG.
    let mut buf = vec![0u32; 16 * 16];
    let ptr = buf.as_mut_ptr();
    // SAFETY: backing buffer outlives the borrow.
    let mut fb = unsafe { Framebuffer::new(ptr, 16, 16, 16) };
    let mut c = Cursor::new(0, 0, Pixel32::WHITE);
    c.draw_at(&mut fb);
    if buf[0] != Pixel32::WHITE.raw() {
        return TestResult::Fail("arrow tip pixel not painted");
    }
    if c.draw_count != 1 {
        return TestResult::Fail("draw_count not bumped");
    }
    // Second column of the first row — sprite row is 0b10000000,
    // bit 6 = 0 → pixel left untouched (still 0).
    if buf[1] != 0 {
        return TestResult::Fail("transparent pixel got painted");
    }
    TestResult::Pass
}
kernel_test_in!("graphics", smoke_cursor_draw_at_paints_arrow_tip);

fn smoke_splash_render_with_no_console_returns_false() -> TestResult {
    use crate::{render_splash, BootInfo};
    // Reset the global FB console so render() returns false.
    crate::console::__reset_for_test();
    let info = BootInfo {
        arch: "x86_64",
        version: "test",
        cpu_count: 1,
        numa_nodes: 1,
        bound_drivers: 0,
        backend: "pks",
    };
    if render_splash(&info) {
        return TestResult::Fail("render returned true with no console");
    }
    TestResult::Pass
}
kernel_test_in!(
    "graphics",
    smoke_splash_render_with_no_console_returns_false
);

fn smoke_splash_render_with_console_paints() -> TestResult {
    use crate::{render_splash, BootInfo, FbConsole, Framebuffer, Pixel32};
    use alloc::vec;
    let mut buf = vec![0u32; 64 * 48];
    let ptr = buf.as_mut_ptr();
    // SAFETY: backing buffer outlives the borrow.
    let fb = unsafe { Framebuffer::new(ptr, 64, 48, 64) };
    let con = FbConsole::new(fb, Pixel32::WHITE, Pixel32::BLACK);
    crate::install_fb_console(con);
    let info = BootInfo {
        arch: "x86_64",
        version: "0.0.0",
        cpu_count: 2,
        numa_nodes: 1,
        bound_drivers: 8,
        backend: "pks",
    };
    let painted = render_splash(&info);
    // Cleanup.
    crate::console::__reset_for_test();
    if !painted {
        return TestResult::Fail("render returned false with console installed");
    }
    // Title bar should have written non-zero pixels in the first row.
    if buf.iter().take(64).all(|&p| p == 0) {
        return TestResult::Fail("title bar didn't paint");
    }
    TestResult::Pass
}
kernel_test_in!("graphics", smoke_splash_render_with_console_paints);

fn smoke_edid_parses_known_block() -> TestResult {
    use crate::edid::{Edid, EdidError};
    let mut blob = [0u8; 128];
    blob[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    // Manufacturer "NRF" — N=14, R=18, F=6.
    let mfr_raw: u16 = ((14u16) << 10) | ((18u16) << 5) | 6;
    blob[8] = (mfr_raw >> 8) as u8;
    blob[9] = mfr_raw as u8;
    blob[10..12].copy_from_slice(&0x1234u16.to_le_bytes());
    blob[16] = 30; // week
    blob[17] = 30; // year = 1990 + 30 = 2020
    blob[18] = 1;
    blob[19] = 4;
    // Detailed timing #1 at offset 0x36: 1920x1080 @ 148.5 MHz.
    blob[0x36..0x38].copy_from_slice(&14850u16.to_le_bytes());
    let h_active: u16 = 1920;
    let h_blanking: u16 = 280;
    blob[0x38] = (h_active & 0xFF) as u8;
    blob[0x39] = (h_blanking & 0xFF) as u8;
    blob[0x3A] = (((h_active >> 8) << 4) as u8) | ((h_blanking >> 8) & 0x0F) as u8;
    let v_active: u16 = 1080;
    let v_blanking: u16 = 45;
    blob[0x3B] = (v_active & 0xFF) as u8;
    blob[0x3C] = (v_blanking & 0xFF) as u8;
    blob[0x3D] = (((v_active >> 8) << 4) as u8) | ((v_blanking >> 8) & 0x0F) as u8;
    blob[0x3E] = 88;
    blob[0x3F] = 44;
    blob[0x40] = (4u8 << 4) | 5;
    blob[0x41] = 0;
    let s: u8 = blob[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    blob[127] = 0u8.wrapping_sub(s);

    let parsed = match Edid::parse(&blob) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("Edid::parse rejected synthetic block"),
    };
    if parsed.manufacturer() != *b"NRF" {
        return TestResult::Fail("manufacturer mis-decoded");
    }
    if parsed.product_code() != 0x1234 {
        return TestResult::Fail("product_code mis-decoded");
    }
    if parsed.manufacture_year() != 2020 {
        return TestResult::Fail("manufacture_year mis-decoded");
    }
    let timing = match parsed.preferred_timing() {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("preferred_timing rejected"),
    };
    if timing.h_active != 1920 || timing.v_active != 1080 {
        return TestResult::Fail("active resolution mis-decoded");
    }
    if timing.pixel_clock_khz != 148_500 {
        return TestResult::Fail("pixel clock mis-decoded");
    }
    let r = timing.refresh_hz();
    if !(58..=62).contains(&r) {
        return TestResult::Fail("refresh rate not ~60 Hz");
    }
    let mut bad = blob;
    bad[127] ^= 0xFF;
    match Edid::parse(&bad) {
        Err(EdidError::BadChecksum) => TestResult::Pass,
        _ => TestResult::Fail("checksum corruption not surfaced"),
    }
}
kernel_test_in!("graphics", smoke_edid_parses_known_block);

// ── DisplayPort AUX / DPCD smokes ──────────────────────────────────

fn smoke_dp_aux_native_write_command_byte_layout() -> TestResult {
    use crate::dp_aux::{build_native_write, AUX_CMD_NATIVE_WRITE};
    let req = build_native_write(0x12345, &[0xDE, 0xAD]).expect("build");
    // byte 0: cmd<<4 | (addr>>16)&0xF = 0x80 | 0x01 = 0x81
    if req[0] != ((AUX_CMD_NATIVE_WRITE << 4) | 0x01) {
        return TestResult::Fail("command byte should pack cmd nibble + addr[19:16]");
    }
    if req[1] != 0x23 || req[2] != 0x45 {
        return TestResult::Fail("address LE bytes wrong");
    }
    if req[3] != 1 {
        return TestResult::Fail("length field is len-1");
    }
    if &req[4..] != &[0xDE, 0xAD] {
        return TestResult::Fail("write payload must follow length");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dp-aux", smoke_dp_aux_native_write_command_byte_layout);

fn smoke_dp_aux_native_read_request_layout() -> TestResult {
    use crate::dp_aux::{build_native_read, AUX_CMD_NATIVE_READ};
    let req = build_native_read(0x00000, 16).expect("build");
    if req[0] != (AUX_CMD_NATIVE_READ << 4) {
        return TestResult::Fail("native read cmd nibble = 0x9");
    }
    if req[3] != 15 {
        return TestResult::Fail("16-byte read encodes length=15 (length-1)");
    }
    if req.len() != 4 {
        return TestResult::Fail("native read = 4-byte request");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dp-aux", smoke_dp_aux_native_read_request_layout);

fn smoke_dp_aux_rejects_oversize_payload() -> TestResult {
    use crate::dp_aux::{build_native_write, AuxError};
    let bytes = [0u8; 17];
    match build_native_write(0, &bytes) {
        Err(AuxError::BadLength) => TestResult::Pass,
        _ => TestResult::Fail(">16-byte payload must be rejected"),
    }
}
kernel_test_in!("graphics/dp-aux", smoke_dp_aux_rejects_oversize_payload);

fn smoke_dp_aux_rejects_oversize_address() -> TestResult {
    use crate::dp_aux::{build_native_read, AuxError};
    match build_native_read(0x10_0000, 1) {
        Err(AuxError::BadAddress) => TestResult::Pass,
        _ => TestResult::Fail("addr > 20 bits must be rejected"),
    }
}
kernel_test_in!("graphics/dp-aux", smoke_dp_aux_rejects_oversize_address);

fn smoke_dp_aux_reply_byte_decode() -> TestResult {
    use crate::dp_aux::{parse_reply_byte, AUX_REPLY_ACK, AUX_REPLY_DEFER};
    let (code, _) = parse_reply_byte(AUX_REPLY_ACK << 4);
    if code != AUX_REPLY_ACK {
        return TestResult::Fail("ACK reply nibble mismatch");
    }
    let (code, _) = parse_reply_byte(AUX_REPLY_DEFER << 4);
    if code != AUX_REPLY_DEFER {
        return TestResult::Fail("DEFER reply nibble mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dp-aux", smoke_dp_aux_reply_byte_decode);

fn smoke_dpcd_link_rate_constants() -> TestResult {
    use crate::dp_aux::link_rate;
    // DPCD encodes link rate as bw / 0.27 GHz → integer multipliers.
    if link_rate::RBR != 0x06 {
        return TestResult::Fail("RBR (1.62 Gbps) = 6");
    }
    if link_rate::HBR != 0x0A {
        return TestResult::Fail("HBR (2.7 Gbps) = 10");
    }
    if link_rate::HBR2 != 0x14 {
        return TestResult::Fail("HBR2 (5.4 Gbps) = 20");
    }
    if link_rate::HBR3 != 0x1E {
        return TestResult::Fail("HBR3 (8.1 Gbps) = 30");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dp-aux", smoke_dpcd_link_rate_constants);

fn smoke_dpcd_lane_status_all_trained_helper() -> TestResult {
    use crate::dp_aux::lane_status;
    // For two lanes packed in one byte, "all done" means
    // CR_DONE | CHANNEL_EQ_DONE | SYMBOL_LOCKED in each nibble.
    let byte: u8 = (lane_status::CR_DONE | lane_status::CHANNEL_EQ_DONE | lane_status::SYMBOL_LOCKED)
        | ((lane_status::CR_DONE | lane_status::CHANNEL_EQ_DONE | lane_status::SYMBOL_LOCKED) << 4);
    if byte != lane_status::ALL_LANES_TRAINED {
        return TestResult::Fail("ALL_LANES_TRAINED helper should match the packed mask");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dp-aux", smoke_dpcd_lane_status_all_trained_helper);

fn smoke_dp_aux_i2c_read_mot_for_edid_drain() -> TestResult {
    use crate::dp_aux::{build_i2c_read_mot, AUX_CMD_I2C_READ_MOT};
    // EDID DDC slave address is 0x50.
    let req = build_i2c_read_mot(0x50, 16).expect("build");
    if req[0] != (AUX_CMD_I2C_READ_MOT << 4) {
        return TestResult::Fail("I2C-Read-MOT nibble = 0x5");
    }
    if req[2] != 0x50 {
        return TestResult::Fail("EDID slave address goes in low byte of address");
    }
    if req[3] != 15 {
        return TestResult::Fail("16-byte chunk encodes length-1");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dp-aux", smoke_dp_aux_i2c_read_mot_for_edid_drain);

// ── DSC PPS smokes ─────────────────────────────────────────────────

fn smoke_dsc_pps_size_constant() -> TestResult {
    if crate::dsc::DSC_PPS_SIZE != 128 {
        return TestResult::Fail("DSC PPS is 128 bytes per §3.4");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dsc", smoke_dsc_pps_size_constant);

fn smoke_dsc_pps_round_trip_4k_8bpc_at_8bpp() -> TestResult {
    use crate::dsc::Pps;
    let p = Pps {
        dsc_version_major: 1,
        dsc_version_minor: 2,
        pps_identifier: 0,
        bits_per_component: 8,
        linebuf_depth: 9,
        bits_per_pixel: 8 * 16, // 8.0 bpp encoded as 128
        pic_height: 2160,
        pic_width: 3840,
        slice_height: 108,
        slice_width: 1920,
        chunk_size: 1920,
        initial_xmit_delay: 512,
        initial_dec_delay: 526,
        initial_scale_value: 32,
        scale_increment_interval: 113,
        scale_decrement_interval: 1024,
        first_line_bpg_offset: 12,
        nfl_bpg_offset: 1024,
        slice_bpg_offset: 1024,
        initial_offset: 6144,
        final_offset: 4336,
        flatness_min_qp: 7,
        flatness_max_qp: 16,
        rc_model_size: 8192,
        rc_buf_thresh: [
            14, 28, 42, 56, 70, 84, 98, 105, 112, 119, 121, 123, 125, 126,
        ],
        rc_range_parameters: [
            crate::dsc::pack_range_parameter(0, 4, 0),
            crate::dsc::pack_range_parameter(0, 6, 0),
            crate::dsc::pack_range_parameter(0, 8, 1),
            crate::dsc::pack_range_parameter(2, 9, 1),
            crate::dsc::pack_range_parameter(4, 9, 2),
            crate::dsc::pack_range_parameter(6, 9, 2),
            crate::dsc::pack_range_parameter(8, 9, 3),
            crate::dsc::pack_range_parameter(8, 10, 3),
            crate::dsc::pack_range_parameter(10, 11, 3),
            crate::dsc::pack_range_parameter(10, 12, 4),
            crate::dsc::pack_range_parameter(12, 14, 4),
            crate::dsc::pack_range_parameter(12, 14, 6),
            crate::dsc::pack_range_parameter(13, 15, 8),
            crate::dsc::pack_range_parameter(15, 15, 12),
            crate::dsc::pack_range_parameter(15, 16, 14),
        ],
    };
    let buf = p.encode();
    let back = Pps::parse(&buf).expect("parse");
    if back != p {
        return TestResult::Fail("PPS round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dsc", smoke_dsc_pps_round_trip_4k_8bpc_at_8bpp);

fn smoke_dsc_bpp_fractional_split() -> TestResult {
    use crate::dsc::Pps;
    let mut p = Pps::default();
    p.dsc_version_major = 1;
    p.bits_per_pixel = 8 * 16 + 5; // 8.3125 bpp
    if p.bpp_integer_part() != 8 {
        return TestResult::Fail("integer part = high 12 bits / 16");
    }
    if p.bpp_fractional_sixteenths() != 5 {
        return TestResult::Fail("fractional part = low 4 bits");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dsc", smoke_dsc_bpp_fractional_split);

fn smoke_dsc_pack_range_parameter_layout() -> TestResult {
    use crate::dsc::pack_range_parameter;
    // bpg_offset = 4 → bits 15..11 = 4 << 11
    // max_qp = 9 → bits 10..6 = 9 << 6
    // min_qp = 2 → bits 5..0 = 2
    let v = pack_range_parameter(4, 9, 2);
    if (v >> 11) & 0x1F != 4 {
        return TestResult::Fail("bpg_offset at bits 15..11");
    }
    if (v >> 6) & 0x1F != 9 {
        return TestResult::Fail("max_qp at bits 10..6");
    }
    if v & 0x1F != 2 {
        return TestResult::Fail("min_qp at bits 5..0");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dsc", smoke_dsc_pack_range_parameter_layout);

fn smoke_dsc_pps_rejects_zero_version() -> TestResult {
    use crate::dsc::{DscError, Pps};
    let buf = [0u8; 128];
    match Pps::parse(&buf) {
        Err(DscError::BadVersion) => TestResult::Pass,
        _ => TestResult::Fail("DSC version 0 must be rejected"),
    }
}
kernel_test_in!("graphics/dsc", smoke_dsc_pps_rejects_zero_version);

// ── PSR / Adaptive-Sync DPCD smokes ────────────────────────────────

fn smoke_dp_psr_dpcd_addresses() -> TestResult {
    use crate::dp_psr::{DPCD_PSR_CONFIGURATION, DPCD_PSR_STATUS, DPCD_PSR_SUPPORT};
    if DPCD_PSR_SUPPORT != 0x70 {
        return TestResult::Fail("PSR_SUPPORT lives at 0x070");
    }
    if DPCD_PSR_CONFIGURATION != 0x170 {
        return TestResult::Fail("PSR_CONFIGURATION lives at 0x170");
    }
    if DPCD_PSR_STATUS != 0x2007 {
        return TestResult::Fail("PSR_STATUS lives at 0x2007");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dp-psr", smoke_dp_psr_dpcd_addresses);

fn smoke_dp_psr_caps_decode_setup_time() -> TestResult {
    use crate::dp_psr::PsrCaps;
    // Setup time index = 4 (110 µs), deep-sleep on exit = 1.
    let b = (4u8 << 5) | 0x10;
    let c = PsrCaps::decode(b);
    if c.setup_time_index != 4 {
        return TestResult::Fail("setup time index field at bits 7..5");
    }
    if !c.deep_sleep_on_exit {
        return TestResult::Fail("deep-sleep bit lost");
    }
    if c.setup_time() != 110 {
        return TestResult::Fail("setup-time index 4 = 110 µs");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dp-psr", smoke_dp_psr_caps_decode_setup_time);

fn smoke_dp_psr_state_constants() -> TestResult {
    use crate::dp_psr::{
        PSR_STATE_ACTIVE_NO_FRAME, PSR_STATE_INACTIVE, PSR_STATE_INTERNAL_ERROR,
    };
    if PSR_STATE_INACTIVE != 0 {
        return TestResult::Fail("PSR state 0 = inactive");
    }
    if PSR_STATE_ACTIVE_NO_FRAME != 3 {
        return TestResult::Fail("PSR state 3 = active no frame");
    }
    if PSR_STATE_INTERNAL_ERROR != 7 {
        return TestResult::Fail("PSR state 7 = internal error");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dp-psr", smoke_dp_psr_state_constants);

fn smoke_dp_psr2_caps_constants() -> TestResult {
    use crate::dp_psr::{DPCD_PSR2_CAPS, PSR2_CAP_SU, PSR2_CAP_SU_GRANULARITY_REQUIRED};
    if DPCD_PSR2_CAPS != 0x2030 {
        return TestResult::Fail("PSR2_CAPS lives at 0x2030 per eDP 1.5");
    }
    if PSR2_CAP_SU != 1 {
        return TestResult::Fail("Selective Update bit at bit 0");
    }
    if PSR2_CAP_SU_GRANULARITY_REQUIRED != 2 {
        return TestResult::Fail("granularity-required at bit 1");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dp-psr", smoke_dp_psr2_caps_constants);

fn smoke_dp_adaptive_sync_dpcd() -> TestResult {
    use crate::dp_psr::{
        ADAPTIVE_SYNC_CAP_SUPPORT, DPCD_ADAPTIVE_SYNC_CAPABILITY,
        DPCD_DOWN_STREAM_PORT_PRESENT_MSA_TIMING_PAR_IGNORED,
    };
    if DPCD_DOWN_STREAM_PORT_PRESENT_MSA_TIMING_PAR_IGNORED != 0x40 {
        return TestResult::Fail("MSA-VSYNC-IGNORE bit at DPCD 0x05[6]");
    }
    if DPCD_ADAPTIVE_SYNC_CAPABILITY != 0x7001 {
        return TestResult::Fail("Adaptive-Sync capability lives at 0x7001");
    }
    if ADAPTIVE_SYNC_CAP_SUPPORT != 1 {
        return TestResult::Fail("support bit at bit 0");
    }
    TestResult::Pass
}
kernel_test_in!("graphics/dp-psr", smoke_dp_adaptive_sync_dpcd);
