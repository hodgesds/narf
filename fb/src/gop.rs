//! UEFI Graphics Output Protocol (GOP) handoff decoder.
//!
//! ## Sources (public only)
//!
//! - **UEFI Specification, Version 2.10**, August 2022. §12.9
//!   "Graphics Output Protocol".
//!   <https://uefi.org/specs/UEFI/2.10/>
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is
//!
//! Pure decoder for the two structs every UEFI bootloader hands to
//! the kernel when it leaves the firmware GOP active:
//!
//! - `EFI_GRAPHICS_OUTPUT_MODE_INFORMATION` (36 bytes) — pixel
//!   layout + dimensions + stride.
//! - `EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE` (variable) — mode info
//!   pointer + framebuffer base + size.
//!
//! The kernel doesn't *call* GOP at runtime (firmware is gone by
//! the time we're up); it just consumes the snapshot the boot
//! loader recorded. Limine, GRUB, systemd-boot and bare-metal U-Boot
//! all expose these fields with identical wire formats.

extern crate alloc;

/// GOP pixel format codes (§12.9 enum `EFI_GRAPHICS_PIXEL_FORMAT`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    /// `R8 G8 B8 X8` little-endian. The default for QEMU OVMF +
    /// most x86 firmwares.
    RgbReserved8 = 0,
    /// `B8 G8 R8 X8` little-endian. Some Apple / vendor firmwares.
    BgrReserved8 = 1,
    /// Custom layout — bit masks live in `PixelInformation`.
    BitMask = 2,
    /// Framebuffer not directly addressable; only `Blt()` works.
    /// Treat as "no framebuffer mapped" for kernel purposes.
    BltOnly = 3,
    /// Reserved / unknown.
    Other = 0xFFFF_FFFF,
}

impl PixelFormat {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::RgbReserved8,
            1 => Self::BgrReserved8,
            2 => Self::BitMask,
            3 => Self::BltOnly,
            _ => Self::Other,
        }
    }
}

/// `EFI_PIXEL_BITMASK` (§12.9). Channel masks for `BitMask` format.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PixelBitmask {
    pub red: u32,
    pub green: u32,
    pub blue: u32,
    pub reserved: u32,
}

/// Decoded `EFI_GRAPHICS_OUTPUT_MODE_INFORMATION` (36 bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ModeInformation {
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: PixelFormat,
    pub pixel_information: PixelBitmask,
    /// Stride in *pixels* (not bytes) — caller multiplies by the
    /// bytes-per-pixel for the active format.
    pub pixels_per_scan_line: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GopError {
    Short,
    /// Framebuffer base is 0 — UEFI returned a `BltOnly` mode but
    /// the loader still recorded a framebuffer pointer. Caller
    /// should treat as "no scanout".
    NoFramebuffer,
}

impl ModeInformation {
    /// Decode 36 bytes laid out per UEFI 2.10 §12.9.
    pub fn decode(buf: &[u8]) -> Result<Self, GopError> {
        if buf.len() < 36 {
            return Err(GopError::Short);
        }
        Ok(Self {
            version: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            horizontal_resolution: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            vertical_resolution: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            pixel_format: PixelFormat::from_u32(u32::from_le_bytes([
                buf[12], buf[13], buf[14], buf[15],
            ])),
            pixel_information: PixelBitmask {
                red: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
                green: u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]),
                blue: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
                reserved: u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]),
            },
            pixels_per_scan_line: u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
        })
    }

    /// Bytes-per-pixel implied by `pixel_format`.
    pub fn bytes_per_pixel(&self) -> u32 {
        match self.pixel_format {
            PixelFormat::RgbReserved8 | PixelFormat::BgrReserved8 => 4,
            PixelFormat::BitMask => {
                let mask = self.pixel_information.red
                    | self.pixel_information.green
                    | self.pixel_information.blue
                    | self.pixel_information.reserved;
                if mask <= 0xFFFF {
                    2
                } else if mask <= 0xFF_FFFF {
                    3
                } else {
                    4
                }
            }
            _ => 0,
        }
    }

    /// Stride in bytes.
    pub fn stride_bytes(&self) -> u32 {
        self.pixels_per_scan_line * self.bytes_per_pixel()
    }
}

/// Bootloader-recorded snapshot of the GOP `Mode` struct. We only
/// keep the kernel-visible fields — the live `Info` pointer, max
/// mode count, and current mode index are firmware-only state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProtocolMode {
    pub framebuffer_base: u64,
    pub framebuffer_size: u64,
    pub mode: ModeInformation,
}

impl ProtocolMode {
    /// Build a unified `Framebuffer` descriptor.
    pub fn to_framebuffer(self) -> Result<crate::gop::Framebuffer, GopError> {
        if self.framebuffer_base == 0
            || matches!(self.mode.pixel_format, PixelFormat::BltOnly | PixelFormat::Other)
        {
            return Err(GopError::NoFramebuffer);
        }
        Ok(Framebuffer {
            base: self.framebuffer_base,
            size: self.framebuffer_size,
            width: self.mode.horizontal_resolution,
            height: self.mode.vertical_resolution,
            stride_bytes: self.mode.stride_bytes(),
            bytes_per_pixel: self.mode.bytes_per_pixel(),
            pixel_format: self.mode.pixel_format,
            pixel_information: self.mode.pixel_information,
        })
    }
}

/// Unified framebuffer descriptor. The same shape consumed by the
/// VBE decoder so callers can build a single scanout out of either
/// handoff.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Framebuffer {
    pub base: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub stride_bytes: u32,
    pub bytes_per_pixel: u32,
    pub pixel_format: PixelFormat,
    pub pixel_information: PixelBitmask,
}
