//! Synthetic EDID generation for NARF's synthesised DRM connectors.
//!
//! NARF's virtio-gpu / bochs connectors are software constructs with no
//! physical monitor behind them, so there is no real EDID to read from an
//! I2C/DDC line. Real compositors (kwin, mutter, weston) read the connector's
//! `EDID` blob property to learn the display's identity, physical size and
//! preferred timing; without it kwin logs `Could not find edid for connector`
//! and falls back to guessed DPI/scale. This module builds a minimal but
//! structurally valid EDID 1.4 block describing the connector's active mode so
//! that surface reads back a well-formed display.
//!
//! Layout follows VESA E-EDID 1.4 (see `edid/src/lib.rs` for the field map and
//! `graphics/src/edid.rs` for the parser this must satisfy).

extern crate alloc;

/// One EDID block is 128 bytes.
pub const EDID_BLOCK_SIZE: usize = 128;

/// Encode a 3-letter PnP manufacturer id into the two big-endian bytes at
/// offset 8. Each letter is 5 bits, `A`=1..=`Z`=26, MSB unused.
const fn pnp_id(a: u8, b: u8, c: u8) -> [u8; 2] {
    let v: u16 =
        (((a - b'A' + 1) as u16) << 10) | (((b - b'A' + 1) as u16) << 5) | ((c - b'A' + 1) as u16);
    [(v >> 8) as u8, (v & 0xFF) as u8]
}

/// Millimetres for `px` pixels at an assumed ~96 DPI (25.4 mm/inch).
fn px_to_mm(px: u32) -> u32 {
    (px * 254 + 480) / 960
}

/// Build an 18-byte Detailed Timing Descriptor for `width`×`height`@`refresh`.
///
/// Blanking is a fixed, plausible envelope rather than a full CVT/GTF
/// derivation: the compositor takes the exact modeline from GETCONNECTOR's
/// mode list, so the DTD only needs to decode back to the same active
/// resolution and a self-consistent pixel clock (and carry the physical size).
fn detailed_timing(width: u32, height: u32, refresh: u32) -> [u8; 18] {
    let mut d = [0u8; 18];

    // Fixed blanking envelope (matches common 4:3/16:9 desktop timings well
    // enough for a synthetic panel).
    let hblank: u32 = 160;
    let vblank: u32 = 40;
    let hfront: u32 = 24; // hsync offset (front porch)
    let hsyncw: u32 = 136; // hsync pulse width
    let vfront: u32 = 3; // vsync offset
    let vsyncw: u32 = 6; // vsync pulse width

    let htotal = width + hblank;
    let vtotal = height + vblank;
    // Pixel clock in 10 kHz units (EDID field granularity), self-consistent
    // with the blanking above: clk = htotal * vtotal * refresh.
    let clk_10khz = (htotal as u64 * vtotal as u64 * refresh as u64 / 10_000) as u16;
    d[0] = (clk_10khz & 0xFF) as u8;
    d[1] = (clk_10khz >> 8) as u8;

    d[2] = (width & 0xFF) as u8;
    d[3] = (hblank & 0xFF) as u8;
    d[4] = ((((width >> 8) & 0xF) << 4) | ((hblank >> 8) & 0xF)) as u8;

    d[5] = (height & 0xFF) as u8;
    d[6] = (vblank & 0xFF) as u8;
    d[7] = ((((height >> 8) & 0xF) << 4) | ((vblank >> 8) & 0xF)) as u8;

    d[8] = (hfront & 0xFF) as u8;
    d[9] = (hsyncw & 0xFF) as u8;
    d[10] = (((vfront & 0xF) << 4) | (vsyncw & 0xF)) as u8;
    d[11] = ((((hfront >> 8) & 0x3) << 6)
        | (((hsyncw >> 8) & 0x3) << 4)
        | (((vfront >> 4) & 0x3) << 2)
        | ((vsyncw >> 4) & 0x3)) as u8;

    let hmm = px_to_mm(width);
    let vmm = px_to_mm(height);
    d[12] = (hmm & 0xFF) as u8;
    d[13] = (vmm & 0xFF) as u8;
    d[14] = ((((hmm >> 8) & 0xF) << 4) | ((vmm >> 8) & 0xF)) as u8;

    // d[15]/d[16] borders = 0.
    // Flags: digital separate sync, positive vsync + hsync.
    d[17] = 0x1E;
    d
}

/// Fill an 18-byte display descriptor of `tag` with ASCII `text` (padded with
/// spaces, LF-terminated per VESA when it fits) — used for the monitor name.
fn text_descriptor(tag: u8, text: &str) -> [u8; 18] {
    let mut d = [0u8; 18];
    // 00 00 00 <tag> 00 then up to 13 bytes of text.
    d[3] = tag;
    let bytes = text.as_bytes();
    let n = core::cmp::min(bytes.len(), 13);
    d[5..5 + n].copy_from_slice(&bytes[..n]);
    if n < 13 {
        d[5 + n] = 0x0A; // LF terminator
        for b in d.iter_mut().skip(5 + n + 1) {
            *b = 0x20; // space pad
        }
    }
    d
}

/// Build a valid 128-byte EDID 1.4 block for a synthetic connector running at
/// `width`×`height`@`refresh_hz`. The preferred (first) detailed timing encodes
/// the active mode and physical size; the remaining descriptors carry a monitor
/// name and are otherwise unused.
pub fn synth_edid(width: u32, height: u32, refresh_hz: u32) -> [u8; EDID_BLOCK_SIZE] {
    let mut e = [0u8; EDID_BLOCK_SIZE];

    // Header.
    e[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    // Manufacturer "NRF", product 1, serial 0.
    e[8..10].copy_from_slice(&pnp_id(b'N', b'R', b'F'));
    e[10..12].copy_from_slice(&1u16.to_le_bytes());
    // Manufacture week 0, year 2022 (byte = year - 1990 = 32).
    e[16] = 0;
    e[17] = 32;
    // EDID version 1.4.
    e[18] = 1;
    e[19] = 4;

    // Basic display parameters: digital input, 8 bpc, undefined interface.
    e[20] = 0xA0;
    // Physical size in cm (rounded from the active resolution at ~96 DPI).
    e[21] = ((px_to_mm(width) + 5) / 10) as u8;
    e[22] = ((px_to_mm(height) + 5) / 10) as u8;
    // Display gamma 2.2 → (2.2 * 100) - 100 = 120 = 0x78.
    e[23] = 0x78;
    // Feature support: preferred timing is the native/preferred mode (bit 1).
    e[24] = 0x02;

    // Chromaticity — canonical sRGB primaries (bytes 25..=34).
    e[25..35].copy_from_slice(&[0xEE, 0x91, 0xA3, 0x54, 0x4C, 0x99, 0x26, 0x0F, 0x50, 0x54]);

    // Established + standard timings unused (35..=37 zero; 38..=53 = 0x01 pad).
    for b in e.iter_mut().take(54).skip(38) {
        *b = 0x01;
    }

    // Four 18-byte descriptors at 54, 72, 90, 108.
    e[54..72].copy_from_slice(&detailed_timing(width, height, refresh_hz));
    e[72..90].copy_from_slice(&text_descriptor(0xFC, "NARF Display")); // monitor name
                                                                       // Descriptors 3 and 4: dummy (tag 0x10) so parsers skip them cleanly.
    e[90..108].copy_from_slice(&text_descriptor(0x10, ""));
    e[108..126].copy_from_slice(&text_descriptor(0x10, ""));

    // No extension blocks.
    e[126] = 0;
    // Checksum: the 128 bytes must sum to 0 mod 256.
    let sum = e[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    e[127] = 0u8.wrapping_sub(sum);
    e
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_synth_edid_is_well_formed() -> TestResult {
        let e = synth_edid(1024, 768, 60);
        if e[0..8] != [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00] {
            return TestResult::Fail("EDID header mismatch");
        }
        if e[18] != 1 || e[19] != 4 {
            return TestResult::Fail("EDID version != 1.4");
        }
        // Whole-block checksum must be zero mod 256.
        let sum = e.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        if sum != 0 {
            return TestResult::Fail("EDID checksum nonzero");
        }
        // First detailed timing must decode to the requested active resolution.
        let d = &e[54..72];
        let hactive = (d[2] as u32) | (((d[4] >> 4) as u32) << 8);
        let vactive = (d[5] as u32) | (((d[7] >> 4) as u32) << 8);
        if hactive != 1024 || vactive != 768 {
            return TestResult::Fail("preferred DTD active resolution mismatch");
        }
        // Pixel clock must be non-zero (a zero-clock DTD is "unused").
        if d[0] == 0 && d[1] == 0 {
            return TestResult::Fail("preferred DTD has a zero pixel clock");
        }
        TestResult::Pass
    }

    fn smoke_synth_edid_parses_via_graphics() -> TestResult {
        // The generated block must satisfy the in-tree parser.
        let e = synth_edid(1920, 1080, 60);
        match narf_graphics::edid::Edid::parse(&e) {
            Ok(parsed) => match parsed.preferred_timing() {
                Ok(t) if t.h_active == 1920 && t.v_active == 1080 => TestResult::Pass,
                Ok(_) => TestResult::Fail("parser read wrong preferred timing"),
                Err(_) => TestResult::Fail("parser found no preferred timing"),
            },
            Err(_) => TestResult::Fail("graphics EDID parser rejected the synthetic block"),
        }
    }

    kernel_test_in!("drivers/gpu/edid_gen", smoke_synth_edid_is_well_formed);
    kernel_test_in!("drivers/gpu/edid_gen", smoke_synth_edid_parses_via_graphics);
}
