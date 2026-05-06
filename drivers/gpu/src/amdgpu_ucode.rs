//! AMDGPU GFX firmware ucode header parser — clean-room.
//!
//! Reference: AMD `amdgpu_ucode.h` (MIT-licensed shape; the GPL
//! Linux driver consumes it but the header itself is non-GPL and
//! shipped with public header drops). The on-the-wire structure
//! is documented in the AMD GPU Open firmware-blob notes.
//!
//! ## Layout
//!
//! Every AMD GFX / SDMA / RLC / SMU / PSP firmware blob ships
//! with a 256-byte header followed by the binary payload.
//! Common-header layout (offsets in bytes, all little-endian):
//!
//! ```text
//! +0x00   uCodeStartByte                    u32 — payload offset
//! +0x04   uCodeSize                         u32 — payload bytes
//! +0x08   uCodeVersion                      u32
//! +0x0C   uCodeFeatureVersion               u32
//! +0x10   uCodeJtVersion                    u32
//! +0x14   uCodeJtBytes                      u32
//! +0x18   uCodeImageBytes                   u32
//! +0x1C   uCodeRtimeBytes                   u32
//! ```
//!
//! Firmware blobs additionally start with a 4-byte magic
//! `0x012345AB` so the kernel can sanity-check the image before
//! handing it to the device. The PSP firmware-load handshake
//! (see `amdgpu::AmdGpu::load_firmware`) reads `uCodeStartByte`
//! + `uCodeSize` to know where the payload starts and how many
//! bytes to DMA into the GPU.
//!
//! ## Scope
//!
//! Stage-5: parse + validate the common header. Per-firmware-
//! type extensions (e.g. SMC microcode footers, RLC autoload
//! offset tables) live in dedicated walkers as the bring-up
//! paths need them.

use core::fmt;

/// The 4-byte magic at offset 0 of every AMD GFX firmware blob.
pub const UCODE_MAGIC: u32 = 0x012345AB;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UcodeError {
    /// Blob shorter than the 256-byte common header.
    Truncated,
    /// Magic `0x012345AB` missing from offset 0.
    BadMagic,
    /// `uCodeStartByte + uCodeSize` overflows the blob length.
    PayloadOutOfBounds,
}

/// Decoded common header fields. Field names mirror the AMD
/// header (camelCase preserved as snake_case for Rust).
#[derive(Copy, Clone)]
pub struct UcodeHeader {
    pub start_offset: u32,
    pub payload_size: u32,
    pub version: u32,
    pub feature_version: u32,
    pub jt_version: u32,
    pub jt_bytes: u32,
    pub image_bytes: u32,
    pub rtime_bytes: u32,
}

impl fmt::Debug for UcodeHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UcodeHeader")
            .field("start_offset", &self.start_offset)
            .field("payload_size", &self.payload_size)
            .field("version", &self.version)
            .field("feature_version", &self.feature_version)
            .finish_non_exhaustive()
    }
}

/// Parse + validate the common header from a firmware blob.
/// `blob` is the raw bytes of the firmware file (the payload of
/// a `narf-firmware::BlobView` after trailer-stripping).
pub fn parse(blob: &[u8]) -> Result<UcodeHeader, UcodeError> {
    if blob.len() < 256 {
        return Err(UcodeError::Truncated);
    }
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if magic != UCODE_MAGIC {
        return Err(UcodeError::BadMagic);
    }

    let read_u32 = |o: usize| u32::from_le_bytes([blob[o], blob[o + 1], blob[o + 2], blob[o + 3]]);
    let header_start = 4; // magic is bytes [0..4); the common header
                          // starts at offset 4 per AMD's layout.
    let start_offset = read_u32(header_start);
    let payload_size = read_u32(header_start + 4);
    let version = read_u32(header_start + 8);
    let feature_version = read_u32(header_start + 12);
    let jt_version = read_u32(header_start + 16);
    let jt_bytes = read_u32(header_start + 20);
    let image_bytes = read_u32(header_start + 24);
    let rtime_bytes = read_u32(header_start + 28);

    let end = (start_offset as u64) + (payload_size as u64);
    if end > blob.len() as u64 {
        return Err(UcodeError::PayloadOutOfBounds);
    }

    Ok(UcodeHeader {
        start_offset,
        payload_size,
        version,
        feature_version,
        jt_version,
        jt_bytes,
        image_bytes,
        rtime_bytes,
    })
}

/// Borrow the firmware payload (offset `start_offset`, length
/// `payload_size`) as a `&[u8]`. The PSP DMA stages this slice;
/// the rest of the blob (header + jump table + image-table
/// metadata) stays kernel-side.
pub fn payload<'a>(blob: &'a [u8], header: &UcodeHeader) -> &'a [u8] {
    let start = header.start_offset as usize;
    let len = header.payload_size as usize;
    &blob[start..start + len]
}
