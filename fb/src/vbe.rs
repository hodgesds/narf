//! VESA BIOS Extensions (VBE) handoff decoder.
//!
//! ## Sources (public only)
//!
//! - **VESA BIOS Extension (VBE) Core Functions Standard, Version
//!   3.0**, Sept 16, 1998 (VESA). Public.
//!   <https://glenwing.github.io/docs/VBE-3.0.pdf>
//!   - §4.1 (`VbeInfoBlock` — 256 bytes)
//!   - §4.2 (`ModeInfoBlock` — 256 bytes)
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is
//!
//! Pure decoder for the two VBE 3.0 structs a legacy (non-UEFI)
//! BIOS bootloader hands off after running INT 10h AX=4F00 / 4F01.
//! GRUB and Limine record both blocks verbatim into their boot
//! protocols; the kernel decodes them to recover framebuffer
//! geometry. We do not invoke INT 10h ourselves — we're in 64-bit
//! mode by the time we run.
//!
//! `ModeInfoBlock::to_framebuffer` produces the same unified
//! `Framebuffer` shape `gop` exports, so display drivers don't
//! care which path the bootloader took.

extern crate alloc;

use crate::gop::{Framebuffer, PixelBitmask, PixelFormat};

/// `ModeAttributes` bits (VBE 3.0 §4.2).
pub mod mode_attr {
    pub const HW_SUPPORTED: u16 = 1 << 0;
    pub const TTY_OUTPUT: u16 = 1 << 2;
    pub const COLOR: u16 = 1 << 3;
    pub const GRAPHICS: u16 = 1 << 4;
    pub const NON_VGA: u16 = 1 << 5;
    pub const NO_VGA_BANK_MODE: u16 = 1 << 6;
    /// Bit 7 set means LFB (Linear Framebuffer) is available — a
    /// hard requirement for the kernel since we can't switch to
    /// the BIOS bank-switched window mode.
    pub const LFB_AVAILABLE: u16 = 1 << 7;
}

/// `MemoryModel` byte (VBE 3.0 §4.2 offset 0x1B).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MemoryModel {
    Text = 0x00,
    Cga = 0x01,
    Hercules = 0x02,
    Planar = 0x03,
    PackedPixel = 0x04,
    NonChain4_256 = 0x05,
    /// Direct-color RGB framebuffer (the only kernel-relevant
    /// model — every modern board reports this for any non-text
    /// mode).
    DirectColor = 0x06,
    Yuv = 0x07,
    Other = 0xFF,
}

impl MemoryModel {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Text,
            0x01 => Self::Cga,
            0x02 => Self::Hercules,
            0x03 => Self::Planar,
            0x04 => Self::PackedPixel,
            0x05 => Self::NonChain4_256,
            0x06 => Self::DirectColor,
            0x07 => Self::Yuv,
            _ => Self::Other,
        }
    }
}

/// Decoded `ModeInfoBlock` — VBE 3.0 §4.2. We expose the kernel-
/// relevant subset (geometry + LFB pointer + color masks); the
/// 256-byte block has more legacy fields but they describe planar
/// / banked modes a 64-bit kernel can't run.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ModeInfoBlock {
    pub mode_attributes: u16,
    pub bytes_per_scan_line: u16,
    pub x_resolution: u16,
    pub y_resolution: u16,
    pub bits_per_pixel: u8,
    pub memory_model: MemoryModel,
    pub red_mask_size: u8,
    pub red_field_position: u8,
    pub green_mask_size: u8,
    pub green_field_position: u8,
    pub blue_mask_size: u8,
    pub blue_field_position: u8,
    pub reserved_mask_size: u8,
    pub reserved_field_position: u8,
    /// Linear Framebuffer Address — physical pointer (32-bit on
    /// VBE; high bits are zero on systems whose framebuffer fits
    /// below 4 GiB). Bootloaders that want to use a 64-bit address
    /// extend via the VBE/PM protocol; we accept the 32-bit form
    /// the spec defines.
    pub phys_base_ptr: u32,
}

impl Default for MemoryModel {
    fn default() -> Self {
        Self::Other
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VbeError {
    Short,
    NoLinearFramebuffer,
    NotDirectColor,
}

impl ModeInfoBlock {
    /// Decode 256 bytes laid out per VBE 3.0 §4.2. Caller can pass
    /// the full 256-byte block or a shorter slice ≥ 0x32; we only
    /// touch fields the kernel needs.
    pub fn decode(buf: &[u8]) -> Result<Self, VbeError> {
        if buf.len() < 0x32 {
            return Err(VbeError::Short);
        }
        Ok(Self {
            mode_attributes: u16::from_le_bytes([buf[0x00], buf[0x01]]),
            bytes_per_scan_line: u16::from_le_bytes([buf[0x10], buf[0x11]]),
            x_resolution: u16::from_le_bytes([buf[0x12], buf[0x13]]),
            y_resolution: u16::from_le_bytes([buf[0x14], buf[0x15]]),
            bits_per_pixel: buf[0x19],
            memory_model: MemoryModel::from_byte(buf[0x1B]),
            red_mask_size: buf[0x1F],
            red_field_position: buf[0x20],
            green_mask_size: buf[0x21],
            green_field_position: buf[0x22],
            blue_mask_size: buf[0x23],
            blue_field_position: buf[0x24],
            reserved_mask_size: buf[0x25],
            reserved_field_position: buf[0x26],
            phys_base_ptr: u32::from_le_bytes([buf[0x28], buf[0x29], buf[0x2A], buf[0x2B]]),
        })
    }

    /// Build a [`Framebuffer`] from this block. Returns
    /// `NoLinearFramebuffer` if the LFB attribute bit is clear and
    /// `NotDirectColor` if the memory model is anything other than
    /// `DirectColor` (kernel can't drive planar / banked modes).
    pub fn to_framebuffer(&self) -> Result<Framebuffer, VbeError> {
        if self.mode_attributes & mode_attr::LFB_AVAILABLE == 0 {
            return Err(VbeError::NoLinearFramebuffer);
        }
        if self.memory_model != MemoryModel::DirectColor {
            return Err(VbeError::NotDirectColor);
        }
        // VBE color masks are size + position; convert to GOP-style
        // 32-bit channel masks for downstream uniformity.
        let mask = |size: u8, pos: u8| -> u32 {
            let bits = if size == 0 || size > 32 {
                0
            } else if size == 32 {
                0xFFFF_FFFF
            } else {
                (1u32 << size) - 1
            };
            bits << (pos as u32)
        };
        let pixel_information = PixelBitmask {
            red: mask(self.red_mask_size, self.red_field_position),
            green: mask(self.green_mask_size, self.green_field_position),
            blue: mask(self.blue_mask_size, self.blue_field_position),
            reserved: mask(self.reserved_mask_size, self.reserved_field_position),
        };
        let bytes_per_pixel = ((self.bits_per_pixel + 7) / 8) as u32;
        Ok(Framebuffer {
            base: self.phys_base_ptr as u64,
            size: (self.bytes_per_scan_line as u64) * (self.y_resolution as u64),
            width: self.x_resolution as u32,
            height: self.y_resolution as u32,
            stride_bytes: self.bytes_per_scan_line as u32,
            bytes_per_pixel,
            pixel_format: PixelFormat::BitMask,
            pixel_information,
        })
    }
}
