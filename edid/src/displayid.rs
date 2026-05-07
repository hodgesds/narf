//! VESA DisplayID 2.0 — extension/standalone block parser (clean-room).
//!
//! References (public-only):
//! - VESA DisplayID Standard, Version 2.0, Errata B (Aug 2017).
//!   §2 Section structure, §3.4 Data Block header, §4 Product
//!   Identification, §4.4 Type VII Detailed Timing Data Block,
//!   Annex A (data-block tag codes).
//!   <https://vesa.org/vesa-standards/>
//! - VESA E-EDID 1.4 — base block carries `extension_count` at offset
//!   126; each subsequent 128-byte block has tag 0x70 if it is a
//!   DisplayID extension block.
//!   <https://vesa.org/vesa-standards/>
//!
//! No GPL Linux source consulted.
//!
//! ## Section structure (§2)
//!
//! A DisplayID section is a variable-length envelope that itself sits
//! inside a fixed 128-byte EDID extension block (when carried as
//! such) or stands alone:
//!
//! ```text
//!   byte 0   Version & Revision (e.g. 0x20 = DisplayID 2.0)
//!   byte 1   Section payload size in bytes (= byte 4 of block + 5)
//!   byte 2   Primary use-case (Annex A.1, e.g. 1 = Television)
//!   byte 3   Number of extensions that follow (informational)
//!   byte 4..(4 + size)   Data Block Collection
//!   byte (4 + size)      Checksum (sum mod 256 ≡ 0 over entire section)
//! ```
//!
//! ## Data-block header (§3.4)
//!
//! Every DBC entry has a 3-byte header:
//!
//! ```text
//!   byte 0   Tag code (Annex A.2)
//!   byte 1   Revision (semantic-version-of-this-block-tag)
//!   byte 2   Number of payload bytes that follow
//!   byte 3..(3 + N)   Payload
//! ```
//!
//! Tag codes (selected; Annex A.2):
//!   - 0x00  Product Identification (§4.1)
//!   - 0x02  Display Parameters (§4.3)
//!   - 0x03  Color Characteristics (§4.7)
//!   - 0x07  Type VII Detailed Timing (§4.4) — 20-byte timings
//!   - 0x0C  Container ID
//!   - 0x12  Tiled Display Topology
//!   - 0x7F  Vendor-specific

use alloc::vec::Vec;

/// EDID extension-block tag for DisplayID (E-EDID 1.4 §3.10).
pub const DISPLAYID_EDID_EXT_TAG: u8 = 0x70;

// Use-case codes (§4 product-identification "primary use case").
pub const USECASE_EXTENSION: u8 = 0x00;
pub const USECASE_TEST_STRUCTURE: u8 = 0x01;
pub const USECASE_GENERIC_DISPLAY: u8 = 0x02;
pub const USECASE_TELEVISION: u8 = 0x03;
pub const USECASE_DESKTOP_PRODUCTIVITY: u8 = 0x04;
pub const USECASE_DESKTOP_GAMING: u8 = 0x05;
pub const USECASE_PRESENTATION: u8 = 0x06;
pub const USECASE_HEAD_MOUNTED_VR: u8 = 0x07;
pub const USECASE_HEAD_MOUNTED_AR: u8 = 0x08;

// Data-block tag codes (Annex A.2).
pub const DB_PRODUCT_ID: u8 = 0x00;
pub const DB_DISPLAY_PARAMS: u8 = 0x02;
pub const DB_COLOR_CHARS: u8 = 0x03;
pub const DB_TYPE_VII_TIMING: u8 = 0x07;
pub const DB_CONTAINER_ID: u8 = 0x0C;
pub const DB_TILED_TOPOLOGY: u8 = 0x12;
pub const DB_VENDOR_SPECIFIC: u8 = 0x7F;

/// Errors from DisplayID parsing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DisplayIdError {
    /// Buffer too short for the section header.
    Short,
    /// `version_revision` byte's upper nibble isn't 2 (DisplayID 2.x).
    NotV2,
    /// Section size points past the end of the buffer.
    Truncated,
    /// Section checksum mismatch.
    BadChecksum,
}

/// One Type VII Detailed Timing payload (§4.4, 20 bytes).
///
/// ```text
///   bytes 0..3   Pixel clock - 1, in units of 1 kHz, LE
///   byte 4       Flags (interlaced, 3D-stereo, etc.)
///   bytes 5..6   H Active - 1
///   bytes 7..8   H Blank - 1
///   bytes 9..10  H Front Porch - 1 (high bit = sync polarity for HSync)
///   bytes 11..12 H Sync Width - 1
///   bytes 13..14 V Active - 1
///   bytes 15..16 V Blank - 1
///   bytes 17..18 V Front Porch - 1 (high bit = sync polarity for VSync)
///   byte 19      V Sync Width - 1
/// ```
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TypeVIITiming {
    /// Pixel clock in kHz.
    pub pixel_clock_khz: u32,
    pub interlaced: bool,
    pub h_active: u32,
    pub h_blank: u32,
    pub h_front_porch: u32,
    pub h_sync_width: u32,
    pub h_sync_positive: bool,
    pub v_active: u32,
    pub v_blank: u32,
    pub v_front_porch: u32,
    pub v_sync_width: u32,
    pub v_sync_positive: bool,
}

impl TypeVIITiming {
    pub fn parse(buf: &[u8; 20]) -> Self {
        let pixel_clock_khz = ((buf[0] as u32)
            | ((buf[1] as u32) << 8)
            | ((buf[2] as u32) << 16))
            + 1;
        let flags = buf[3];
        let interlaced = (flags & 0x10) != 0;
        let h_active = u16::from_le_bytes([buf[4], buf[5]]) as u32 + 1;
        let h_blank = u16::from_le_bytes([buf[6], buf[7]]) as u32 + 1;
        let h_front_porch_raw = u16::from_le_bytes([buf[8], buf[9]]);
        let h_sync_positive = (h_front_porch_raw & 0x8000) != 0;
        let h_front_porch = (h_front_porch_raw & 0x7FFF) as u32 + 1;
        let h_sync_width = u16::from_le_bytes([buf[10], buf[11]]) as u32 + 1;
        let v_active = u16::from_le_bytes([buf[12], buf[13]]) as u32 + 1;
        let v_blank = u16::from_le_bytes([buf[14], buf[15]]) as u32 + 1;
        let v_front_porch_raw = u16::from_le_bytes([buf[16], buf[17]]);
        let v_sync_positive = (v_front_porch_raw & 0x8000) != 0;
        let v_front_porch = (v_front_porch_raw & 0x7FFF) as u32 + 1;
        let v_sync_width = (buf[18]) as u32 + 1;
        let _trailer = buf[19];
        Self {
            pixel_clock_khz,
            interlaced,
            h_active,
            h_blank,
            h_front_porch,
            h_sync_width,
            h_sync_positive,
            v_active,
            v_blank,
            v_front_porch,
            v_sync_width,
            v_sync_positive,
        }
    }

    /// Refresh rate in millihertz computed from pixel clock and totals.
    pub fn refresh_mhz(self) -> u32 {
        let h_total = self.h_active + self.h_blank;
        let v_total = self.v_active + self.v_blank;
        if h_total == 0 || v_total == 0 {
            return 0;
        }
        ((self.pixel_clock_khz as u64) * 1_000_000 / (h_total as u64 * v_total as u64)) as u32
    }
}

/// One Data Block in the DBC, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataBlock {
    /// Type VII Detailed Timings — variable count of 20-byte payloads.
    TypeVIITiming(Vec<TypeVIITiming>),
    /// Anything we don't decode yet.
    Other {
        tag: u8,
        revision: u8,
        payload: Vec<u8>,
    },
}

/// Decoded DisplayID 2.0 section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// Combined version/revision byte (0x20 = DisplayID 2.0).
    pub version_revision: u8,
    pub primary_use_case: u8,
    pub data_blocks: Vec<DataBlock>,
}

impl Section {
    /// Parse a DisplayID 2.0 section. Accepts either the standalone
    /// section bytes or the inner section of an EDID extension block
    /// (the EDID extension block tag 0x70 is consumed by the caller).
    pub fn parse(buf: &[u8]) -> Result<Self, DisplayIdError> {
        if buf.len() < 5 {
            return Err(DisplayIdError::Short);
        }
        let version_revision = buf[0];
        if (version_revision >> 4) != 2 {
            return Err(DisplayIdError::NotV2);
        }
        let payload_size = buf[1] as usize;
        let primary_use_case = buf[2];
        let _ext_count = buf[3];

        let total = 5 + payload_size;
        if buf.len() < total {
            return Err(DisplayIdError::Truncated);
        }
        let sum = buf[..total]
            .iter()
            .fold(0u32, |acc, b| acc.wrapping_add(*b as u32));
        if sum & 0xFF != 0 {
            return Err(DisplayIdError::BadChecksum);
        }

        let mut p = 4;
        let end = 4 + payload_size;
        let mut data_blocks = Vec::new();
        while p + 3 <= end {
            let tag = buf[p];
            // A run of 0x00 padding terminates the DBC list — but
            // 0x00 is also "Product Identification". Disambiguate by
            // requiring the length byte to be non-zero for a valid
            // block; if the length is zero the block is empty, which
            // the spec allows for some tags but in practice means
            // "tail padding".
            let revision = buf[p + 1];
            let len = buf[p + 2] as usize;
            if tag == 0 && len == 0 {
                break;
            }
            if p + 3 + len > end {
                break;
            }
            let payload = &buf[p + 3..p + 3 + len];
            let block = match tag {
                DB_TYPE_VII_TIMING => {
                    let mut timings = Vec::new();
                    for chunk in payload.chunks_exact(20) {
                        let arr: [u8; 20] = chunk.try_into().expect("len 20");
                        timings.push(TypeVIITiming::parse(&arr));
                    }
                    DataBlock::TypeVIITiming(timings)
                }
                _ => DataBlock::Other {
                    tag,
                    revision,
                    payload: payload.to_vec(),
                },
            };
            data_blocks.push(block);
            p += 3 + len;
        }

        Ok(Self {
            version_revision,
            primary_use_case,
            data_blocks,
        })
    }

    /// First Type VII timing across all blocks, if any.
    pub fn preferred_type_vii(&self) -> Option<TypeVIITiming> {
        for b in &self.data_blocks {
            if let DataBlock::TypeVIITiming(ts) = b {
                if let Some(t) = ts.first() {
                    return Some(*t);
                }
            }
        }
        None
    }
}

/// Compute the DisplayID checksum byte for a section whose first
/// `payload_size + 4` bytes are filled in: the trailing slot must be
/// set to this so the section sum is a multiple of 256.
pub fn compute_checksum(first_bytes: &[u8]) -> u8 {
    let sum = first_bytes
        .iter()
        .fold(0u32, |acc, b| acc.wrapping_add(*b as u32));
    ((256 - (sum & 0xFF)) & 0xFF) as u8
}
