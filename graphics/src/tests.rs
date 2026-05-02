//! Per-crate smoke tests for `narf-graphics`.
//!
//! Tests register via `narf_kernel_test::kernel_test_in!` so the
//! runner groups output under `"graphics"`.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_graphics_pixel_format() -> TestResult {
    use crate::Pixel32;
    if Pixel32::BLACK.raw()  != 0xFF00_0000 { return TestResult::Fail("BLACK"); }
    if Pixel32::WHITE.raw()  != 0xFFFF_FFFF { return TestResult::Fail("WHITE"); }
    if Pixel32::RED.raw()    != 0xFFFF_0000 { return TestResult::Fail("RED"); }
    if Pixel32::GREEN.raw()  != 0xFF00_FF00 { return TestResult::Fail("GREEN"); }
    if Pixel32::BLUE.raw()   != 0xFF00_00FF { return TestResult::Fail("BLUE"); }
    let p = Pixel32::rgb(0x12, 0x34, 0x56);
    if p.raw() != 0xFF12_3456 { return TestResult::Fail("rgb pack"); }
    TestResult::Pass
}
kernel_test_in!("graphics", smoke_graphics_pixel_format);

fn smoke_graphics_clear_and_fill_rect() -> TestResult {
    use alloc::vec;
    use crate::{Framebuffer, Pixel32};
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
            let want = if inside { Pixel32::RED.raw() } else { Pixel32::WHITE.raw() };
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
    use alloc::vec;
    use crate::{Cursor, Framebuffer, Pixel32};
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
        arch: "x86_64", version: "test",
        cpu_count: 1, numa_nodes: 1, bound_drivers: 0, backend: "pks",
    };
    if render_splash(&info) {
        return TestResult::Fail("render returned true with no console");
    }
    TestResult::Pass
}
kernel_test_in!("graphics", smoke_splash_render_with_no_console_returns_false);

fn smoke_splash_render_with_console_paints() -> TestResult {
    use alloc::vec;
    use crate::{render_splash, BootInfo, FbConsole, Framebuffer, Pixel32};
    let mut buf = vec![0u32; 64 * 48];
    let ptr = buf.as_mut_ptr();
    // SAFETY: backing buffer outlives the borrow.
    let fb = unsafe { Framebuffer::new(ptr, 64, 48, 64) };
    let con = FbConsole::new(fb, Pixel32::WHITE, Pixel32::BLACK);
    crate::install_fb_console(con);
    let info = BootInfo {
        arch: "x86_64", version: "0.0.0",
        cpu_count: 2, numa_nodes: 1, bound_drivers: 8, backend: "pks",
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
        Ok(e)  => e,
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
        Ok(t)  => t,
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
