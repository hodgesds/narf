//! narf-edid — VESA E-EDID 1.4 parser (clean-room).
//!
//! References (public-only):
//! - VESA Enhanced EDID Standard, Release A Revision 2 (Sep 2006).
//! - VESA DDC Standard 1.0 (the I²C transport).
//! - Microsoft PNP ID registry (manufacturer 3-char codes).
//!
//! No GPL Linux source consulted.
//!
//! ## EDID 1.4 block layout (128 bytes)
//!
//! ```text
//!   0..8    Header magic: 00 FF FF FF FF FF FF 00
//!   8..10   Manufacturer ID (3-char compressed PNP code, BE)
//!   10..12  Product Code (LE)
//!   12..16  Serial Number (LE)
//!   16      Week of Manufacture (1..54, or 0xFF = "Year is the model year")
//!   17      Year of Manufacture (offset from 1990)
//!   18      EDID Version (e.g. 1)
//!   19      EDID Revision (e.g. 4)
//!   20      Video Input Definition (bit 7: 1=digital)
//!   21      Max Horizontal Image Size (cm, 0=undefined)
//!   22      Max Vertical Image Size (cm, 0=undefined)
//!   23      Display Gamma (raw = (gamma * 100) - 100, 0xFF = stored in DI-EXT)
//!   24      Supported Features bitmap
//!   25..35  Color Characteristics (chromaticity coordinates)
//!   35..38  Established Timings I, II, Manufacturer-Reserved
//!   38..54  Standard Timings (8 × 2 bytes)
//!   54..126 Detailed Timing / Display Descriptors (4 × 18 bytes)
//!   126     Extension Block Count
//!   127     Checksum (sum of all 128 bytes mod 256 == 0)
//! ```

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

mod tests;

use alloc::string::String;
use alloc::vec::Vec;

/// E-EDID block size.
pub const EDID_BLOCK_SIZE: usize = 128;

/// Header magic (§3.4).
pub const EDID_HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// Errors from EDID parsing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EdidError {
    /// Block isn't 128 bytes.
    BadLength,
    /// Header magic doesn't match.
    BadHeader,
    /// Checksum byte 127 doesn't bring the block sum to a multiple of 256.
    BadChecksum,
}

/// One Detailed Timing Descriptor (DTD), 18 bytes, decoded
/// (§3.10.2). DTDs whose first two bytes (pixel clock) are zero
/// are *Display Descriptors* and decode separately.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DetailedTiming {
    /// Pixel clock in kHz (raw stored as 10 kHz units; we multiply
    /// out for ergonomic readers).
    pub pixel_clock_khz: u32,
    pub h_active: u16,
    pub h_blanking: u16,
    pub v_active: u16,
    pub v_blanking: u16,
    pub h_sync_offset: u16,
    pub h_sync_width: u16,
    pub v_sync_offset: u8,
    pub v_sync_width: u8,
    pub h_image_mm: u16,
    pub v_image_mm: u16,
    pub interlaced: bool,
    pub h_sync_positive: bool,
    pub v_sync_positive: bool,
}

impl DetailedTiming {
    fn parse(buf: &[u8; 18]) -> Self {
        let pixel_clock_10khz = u16::from_le_bytes([buf[0], buf[1]]) as u32;
        let h_active = ((buf[4] as u16 & 0xF0) << 4) | (buf[2] as u16);
        let h_blanking = ((buf[4] as u16 & 0x0F) << 8) | (buf[3] as u16);
        let v_active = ((buf[7] as u16 & 0xF0) << 4) | (buf[5] as u16);
        let v_blanking = ((buf[7] as u16 & 0x0F) << 8) | (buf[6] as u16);
        let h_sync_offset = ((buf[11] as u16 & 0xC0) << 2) | (buf[8] as u16);
        let h_sync_width = ((buf[11] as u16 & 0x30) << 4) | (buf[9] as u16);
        let v_sync_offset = ((buf[11] >> 2) & 0x0C) | ((buf[10] >> 4) & 0x0F);
        let v_sync_width = ((buf[11] << 2) & 0x30) | (buf[10] & 0x0F);
        let h_image_mm = ((buf[14] as u16 & 0xF0) << 4) | (buf[12] as u16);
        let v_image_mm = ((buf[14] as u16 & 0x0F) << 8) | (buf[13] as u16);
        let flags = buf[17];
        let interlaced = flags & 0x80 != 0;
        // Sync polarity: bits 1 (HSync) and 2 (VSync), but only if
        // signal type is digital separate (bits 4..5 == 0b11).
        let h_sync_positive = flags & 0x02 != 0;
        let v_sync_positive = flags & 0x04 != 0;
        Self {
            pixel_clock_khz: pixel_clock_10khz * 10,
            h_active,
            h_blanking,
            v_active,
            v_blanking,
            h_sync_offset,
            h_sync_width,
            v_sync_offset,
            v_sync_width,
            h_image_mm,
            v_image_mm,
            interlaced,
            h_sync_positive,
            v_sync_positive,
        }
    }

    /// Convenience: refresh rate in millihertz, computed from the
    /// pixel clock and the total H/V (active + blanking).
    pub fn refresh_mhz(self) -> u32 {
        let h_total = self.h_active as u64 + self.h_blanking as u64;
        let v_total = self.v_active as u64 + self.v_blanking as u64;
        if h_total == 0 || v_total == 0 {
            return 0;
        }
        let pixels = h_total * v_total;
        // pixel_clock_khz × 1_000_000 / pixels = refresh in mHz.
        ((self.pixel_clock_khz as u64) * 1_000_000 / pixels) as u32
    }
}

/// Display descriptor — appears in the same 18-byte slots as DTDs,
/// distinguished by the first two bytes being zero (§3.10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisplayDescriptor {
    /// 0xFC — Monitor Name (ASCII, terminated by 0x0A or padded with 0x20).
    MonitorName(String),
    /// 0xFD — Range Limits.
    RangeLimits {
        min_v_rate: u8,
        max_v_rate: u8,
        min_h_rate: u8,
        max_h_rate: u8,
        max_pixel_clock_mhz: u8,
    },
    /// 0xFE — Unspecified text.
    UnspecifiedText(String),
    /// 0xFF — Display Product Serial Number (ASCII).
    SerialNumber(String),
    /// Anything else — opaque.
    Unknown(u8),
}

fn parse_text(buf: &[u8]) -> String {
    let mut s = String::new();
    for b in buf {
        if *b == 0x0A {
            break;
        }
        if *b == 0x20 || (*b >= 0x21 && *b <= 0x7E) {
            s.push(*b as char);
        }
    }
    while s.ends_with(' ') {
        s.pop();
    }
    s
}

/// Decoded EDID 1.4 block (128 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// 3-character compressed PNP code (e.g. "DEL" for Dell, "SAM" for Samsung).
    pub manufacturer_id: [char; 3],
    pub product_code: u16,
    pub serial_number: u32,
    /// 1..=54 = ISO week, 0xFF = "year is the model year".
    pub manufacture_week: u8,
    /// Calendar year (the spec stores it as offset from 1990).
    pub manufacture_year: u16,
    pub edid_version: u8,
    pub edid_revision: u8,
    pub digital_input: bool,
    pub max_h_image_cm: u8,
    pub max_v_image_cm: u8,
    pub gamma_x100: Option<u16>,
    pub features: u8,
    pub established_timings_1: u8,
    pub established_timings_2: u8,
    /// 8 standard timing entries (raw 2-byte form per §3.9). 0x0101
    /// means "unused".
    pub standard_timings: [(u8, u8); 8],
    /// Up to 4 detailed timing descriptors. Slots that hold display
    /// descriptors land in `display_descriptors` instead.
    pub detailed_timings: Vec<DetailedTiming>,
    pub display_descriptors: Vec<DisplayDescriptor>,
    pub extension_count: u8,
}

impl Block {
    /// Parse a 128-byte EDID block.
    pub fn parse(buf: &[u8]) -> Result<Self, EdidError> {
        if buf.len() != EDID_BLOCK_SIZE {
            return Err(EdidError::BadLength);
        }
        if buf[0..8] != EDID_HEADER {
            return Err(EdidError::BadHeader);
        }
        let sum = buf.iter().fold(0u32, |acc, b| acc.wrapping_add(*b as u32));
        if sum & 0xFF != 0 {
            return Err(EdidError::BadChecksum);
        }

        // Manufacturer ID — 3 5-bit chars in big-endian 16-bit field;
        // 'A' = 1, 'B' = 2, ... 'Z' = 26.
        let raw = u16::from_be_bytes([buf[8], buf[9]]);
        let c1 = ((raw >> 10) & 0x1F) as u8;
        let c2 = ((raw >> 5) & 0x1F) as u8;
        let c3 = (raw & 0x1F) as u8;
        let manufacturer_id = [
            char::from(b'A' - 1 + c1),
            char::from(b'A' - 1 + c2),
            char::from(b'A' - 1 + c3),
        ];

        let product_code = u16::from_le_bytes([buf[10], buf[11]]);
        let serial_number = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let manufacture_week = buf[16];
        let manufacture_year = 1990u16 + buf[17] as u16;
        let edid_version = buf[18];
        let edid_revision = buf[19];
        let digital_input = (buf[20] & 0x80) != 0;
        let max_h_image_cm = buf[21];
        let max_v_image_cm = buf[22];
        let gamma_x100 = if buf[23] == 0xFF {
            None
        } else {
            Some(buf[23] as u16 + 100)
        };
        let features = buf[24];
        let established_timings_1 = buf[35];
        let established_timings_2 = buf[36];
        let mut standard_timings = [(0u8, 0u8); 8];
        for i in 0..8 {
            standard_timings[i] = (buf[38 + 2 * i], buf[39 + 2 * i]);
        }

        let mut detailed_timings = Vec::new();
        let mut display_descriptors = Vec::new();
        for i in 0..4 {
            let off = 54 + 18 * i;
            let slice: [u8; 18] = buf[off..off + 18].try_into().expect("len");
            // Display Descriptors have the first two bytes zero.
            if slice[0] == 0 && slice[1] == 0 {
                let kind = slice[3];
                let body = &slice[5..18];
                let desc = match kind {
                    0xFC => DisplayDescriptor::MonitorName(parse_text(body)),
                    0xFD => DisplayDescriptor::RangeLimits {
                        min_v_rate: body[0],
                        max_v_rate: body[1],
                        min_h_rate: body[2],
                        max_h_rate: body[3],
                        max_pixel_clock_mhz: body[4],
                    },
                    0xFE => DisplayDescriptor::UnspecifiedText(parse_text(body)),
                    0xFF => DisplayDescriptor::SerialNumber(parse_text(body)),
                    other => DisplayDescriptor::Unknown(other),
                };
                display_descriptors.push(desc);
            } else {
                detailed_timings.push(DetailedTiming::parse(&slice));
            }
        }

        let extension_count = buf[126];

        Ok(Self {
            manufacturer_id,
            product_code,
            serial_number,
            manufacture_week,
            manufacture_year,
            edid_version,
            edid_revision,
            digital_input,
            max_h_image_cm,
            max_v_image_cm,
            gamma_x100,
            features,
            established_timings_1,
            established_timings_2,
            standard_timings,
            detailed_timings,
            display_descriptors,
            extension_count,
        })
    }

    /// First Monitor Name display descriptor, if present.
    pub fn monitor_name(&self) -> Option<&str> {
        for d in &self.display_descriptors {
            if let DisplayDescriptor::MonitorName(s) = d {
                return Some(s.as_str());
            }
        }
        None
    }

    /// Native resolution from the first Detailed Timing Descriptor
    /// (DTD-0 is conventionally the preferred / native mode per
    /// §3.10.1).
    pub fn preferred_mode(&self) -> Option<DetailedTiming> {
        self.detailed_timings.first().copied()
    }
}

/// Compute the EDID checksum byte for the first 127 bytes — the
/// checksum slot at offset 127 must be set to this so the block
/// sum is a multiple of 256.
pub fn compute_checksum(first_127_bytes: &[u8]) -> u8 {
    let sum = first_127_bytes
        .iter()
        .take(127)
        .fold(0u32, |acc, b| acc.wrapping_add(*b as u32));
    ((256 - (sum & 0xFF)) & 0xFF) as u8
}
