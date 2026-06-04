//! VESA E-EDID 1.4 parser — clean-room.
//!
//! Reference: VESA Enhanced Extended Display Identification Data
//! Standard, Release A, Revision 2 (2006-09-22). Public document.
//! Section numbers below (`§3.x`) refer to that spec.
//!
//! ## Scope
//!
//! Parses the base 128-byte EDID block; ignores extension blocks
//! (CTA-861 video data blocks, DisplayID, …). The fields covered
//! are sufficient for picking a scanout mode from a panel
//! identified via DDC (the I2C side-band on every modern DP /
//! HDMI / DVI link):
//!
//! - Manufacturer ID (`§3.4.1`) — 3-letter code from the EDID
//!   manufacturer-id encoding.
//! - Product code + serial number (`§3.4.2`).
//! - Manufacture week + year (`§3.4.3`).
//! - Display dimensions in centimetres (`§3.6.1`).
//! - The first **detailed timing descriptor** at offset `0x36`
//!   (`§3.10`) — by spec the "preferred timing", i.e. the panel's
//!   native resolution at native refresh.
//!
//! ## What we don't parse (yet)
//!
//! - Established timings I/II/III bitmaps (`§3.8`).
//! - Standard timings (`§3.9`).
//! - Color characteristics (`§3.7`).
//! - Extension blocks past byte 128.
//!
//! Stage-3 callers (an amdgpu modeset path that wants to drive a
//! detected panel at its native rate) only need the preferred
//! timing — which is the first detailed-timing descriptor — so
//! the rest stays for later.

use core::fmt;

/// Errors surfaced by the EDID parser.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EdidError {
    /// Block isn't 128 bytes (the only size we accept).
    BadLength,
    /// First 8 bytes weren't `00 FF FF FF FF FF FF 00`.
    BadHeader,
    /// Sum of all 128 bytes wasn't zero (mod 256).
    BadChecksum,
    /// First detailed-timing descriptor's pixel-clock field was
    /// zero — the spec uses that to mark the slot as a generic
    /// descriptor (display name, range limits, …) rather than a
    /// timing.
    NoPreferredTiming,
}

/// Parsed EDID block. Borrows the source slice; convert to owned
/// fields with `Edid::owned()` if you need the data to outlive
/// the source.
#[derive(Copy, Clone)]
pub struct Edid<'a> {
    raw: &'a [u8],
}

impl<'a> fmt::Debug for Edid<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mfr = self.manufacturer();
        f.debug_struct("Edid")
            .field("manufacturer", &core::str::from_utf8(&mfr).unwrap_or("???"))
            .field("product", &self.product_code())
            .field("week", &self.manufacture_week())
            .field("year", &self.manufacture_year())
            .finish()
    }
}

const EDID_HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// Detailed-timing descriptor decoded from offset `0x36` of the
/// EDID block. All fields in pixels / lines / kHz; the spec's
/// `(byte_lo, high_nibble << 8)` packing is unpacked here.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DetailedTiming {
    /// Pixel clock in kHz. Multiplied up from the EDID's 10 kHz
    /// units so consumers don't have to remember.
    pub pixel_clock_khz: u32,
    /// Active horizontal pixels.
    pub h_active: u16,
    /// Horizontal blanking pixels.
    pub h_blanking: u16,
    /// Active vertical lines.
    pub v_active: u16,
    /// Vertical blanking lines.
    pub v_blanking: u16,
    /// Horizontal front porch (pixels).
    pub h_sync_offset: u16,
    /// Horizontal sync pulse width (pixels).
    pub h_sync_width: u16,
    /// Vertical front porch (lines).
    pub v_sync_offset: u16,
    /// Vertical sync pulse width (lines).
    pub v_sync_width: u16,
    /// Horizontal sync polarity (true = positive).
    pub h_sync_positive: bool,
    /// Vertical sync polarity (true = positive).
    pub v_sync_positive: bool,
}

impl DetailedTiming {
    /// Approximate refresh rate in Hz, computed from
    /// `pixel_clock / (h_total * v_total)`.
    pub fn refresh_hz(self) -> u32 {
        let h_total = self.h_active as u32 + self.h_blanking as u32;
        let v_total = self.v_active as u32 + self.v_blanking as u32;
        if h_total == 0 || v_total == 0 {
            return 0;
        }
        // pixel_clock_khz = pixels per ms; we want Hz.
        // hz = (pixel_clock_khz * 1000) / (h_total * v_total)
        ((self.pixel_clock_khz as u64 * 1000) / (h_total as u64 * v_total as u64)) as u32
    }
}

impl<'a> Edid<'a> {
    /// Parse + validate a 128-byte EDID block.
    pub fn parse(raw: &'a [u8]) -> Result<Self, EdidError> {
        if raw.len() != 128 {
            return Err(EdidError::BadLength);
        }
        if raw[..8] != EDID_HEADER {
            return Err(EdidError::BadHeader);
        }
        // Checksum: bytes 0..128 sum to 0 (mod 256).
        let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        if sum != 0 {
            return Err(EdidError::BadChecksum);
        }
        Ok(Self { raw })
    }

    /// Manufacturer ID — 3 ASCII letters per `§3.4.1` (compressed
    /// 5-bit encoding in bytes 8-9).
    pub fn manufacturer(&self) -> [u8; 3] {
        let raw = u16::from_be_bytes([self.raw[8], self.raw[9]]);
        let a = ((raw >> 10) & 0x1F) as u8 + b'A' - 1;
        let b = ((raw >> 5) & 0x1F) as u8 + b'A' - 1;
        let c = ((raw) & 0x1F) as u8 + b'A' - 1;
        [a, b, c]
    }

    /// Vendor-assigned product code (bytes 10-11, little-endian).
    pub fn product_code(&self) -> u16 {
        u16::from_le_bytes([self.raw[10], self.raw[11]])
    }

    /// Vendor-assigned serial number (bytes 12-15, little-endian).
    pub fn serial_number(&self) -> u32 {
        u32::from_le_bytes([self.raw[12], self.raw[13], self.raw[14], self.raw[15]])
    }

    /// Manufacture week (1..=53). Byte 16. `0xFF` means "model
    /// year encoding" rather than week — we surface the raw value.
    pub fn manufacture_week(&self) -> u8 {
        self.raw[16]
    }

    /// Manufacture year. Byte 17 + 1990.
    pub fn manufacture_year(&self) -> u32 {
        1990 + self.raw[17] as u32
    }

    /// EDID structure version (byte 18).
    pub fn version_major(&self) -> u8 {
        self.raw[18]
    }
    /// EDID structure revision (byte 19).
    pub fn version_minor(&self) -> u8 {
        self.raw[19]
    }

    /// First detailed-timing descriptor at `0x36`. By spec, the
    /// "preferred timing" — typically the panel's native mode.
    pub fn preferred_timing(&self) -> Result<DetailedTiming, EdidError> {
        let d = &self.raw[0x36..0x36 + 18];
        let pixel_clock_10khz = u16::from_le_bytes([d[0], d[1]]) as u32;
        if pixel_clock_10khz == 0 {
            return Err(EdidError::NoPreferredTiming);
        }
        let pixel_clock_khz = pixel_clock_10khz * 10;
        // Bytes 2..5: low 8 bits of h_active / h_blanking +
        // high 4-bit nibbles in byte 4.
        let h_active = ((d[4] as u16 & 0xF0) << 4) | d[2] as u16;
        let h_blanking = ((d[4] as u16 & 0x0F) << 8) | d[3] as u16;
        // Bytes 5..8: same shape for vertical.
        let v_active = ((d[7] as u16 & 0xF0) << 4) | d[5] as u16;
        let v_blanking = ((d[7] as u16 & 0x0F) << 8) | d[6] as u16;
        // Bytes 8..11: sync offset / width (h + v) packed.
        let h_sync_offset = ((d[11] as u16 & 0xC0) << 2) | d[8] as u16;
        let h_sync_width = ((d[11] as u16 & 0x30) << 4) | d[9] as u16;
        let v_sync_offset = ((d[11] as u16 & 0x0C) << 2) | ((d[10] as u16 & 0xF0) >> 4);
        let v_sync_width = ((d[11] as u16 & 0x03) << 4) | (d[10] as u16 & 0x0F);
        // Byte 17 contains flags. If bits [4:3] are 0b11 (digital separate),
        // bit 2 is V sync (1 = positive) and bit 1 is H sync (1 = positive).
        // We assume digital separate for modern panels.
        let h_sync_positive = (d[17] & (1 << 1)) != 0;
        let v_sync_positive = (d[17] & (1 << 2)) != 0;

        Ok(DetailedTiming {
            pixel_clock_khz,
            h_active,
            h_blanking,
            v_active,
            v_blanking,
            h_sync_offset,
            h_sync_width,
            v_sync_offset,
            v_sync_width,
            h_sync_positive,
            v_sync_positive,
        })
    }

    /// Display dimensions in millimetres (bytes 21-22 in cm; we
    /// scale up). Returns `(width_mm, height_mm)`. `(0, 0)` when
    /// the panel didn't supply physical dimensions.
    pub fn dimensions_mm(&self) -> (u16, u16) {
        (self.raw[21] as u16 * 10, self.raw[22] as u16 * 10)
    }
}
