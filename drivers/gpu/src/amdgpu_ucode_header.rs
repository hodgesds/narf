//! AMDGPU firmware-blob header parsing.
//!
//! Linux's amdgpu firmware blobs (the `_pfp.bin`, `_me.bin`,
//! `_mec.bin`, ... files under `/lib/firmware/amdgpu/`) all
//! start with `struct common_firmware_header` (32 bytes),
//! followed by an IP-specific tail. The tail layout is what
//! tells the driver:
//!
//! - For GFX9 MEC: the offset + size of the jump-table region
//!   within the same file. Linux's amdgpu loads MEC1 + MEC1_JT
//!   as **two distinct UCODE IDs** through PSP — same blob,
//!   different sub-ranges, two separate `LOAD_IP_FW` calls.
//! - For other IPs: feature versions and per-IP metadata the
//!   driver needs but PSP doesn't directly consume.
//!
//! This module parses both the common header and the GFX v1.0
//! variant (used by GFX9 — Renoir/Cezanne/Lucienne/Barcelo).
//! Newer GFX revisions (GFX10+) use different header variants;
//! parsers for those are follow-ups when those chips' loader
//! paths are wired.
//!
//! Reference: `drivers/gpu/drm/amd/amdgpu/amdgpu_ucode.h` in
//! Linux 6.10+. The structures are public ABI between the
//! firmware-build pipeline (AMD-internal) and the driver, so
//! the layout is byte-stable.

#![allow(dead_code)]

extern crate alloc;

use core::fmt;

/// Common 32-byte header at the start of every amdgpu firmware
/// blob (post-Vega). Layout is **little-endian on disk** — the
/// fields below are byte offsets relative to the start of the
/// file.
///
/// | offset | size | field |
/// |--------|------|-------|
/// | 0      | 4    | size_bytes — total blob size |
/// | 4      | 4    | header_size_bytes — sizeof(common header) (always 32 here) |
/// | 8      | 2    | header_version_major |
/// | 10     | 2    | header_version_minor |
/// | 12     | 2    | ip_version_major |
/// | 14     | 2    | ip_version_minor |
/// | 16     | 4    | ucode_version |
/// | 20     | 4    | ucode_size_bytes — payload size |
/// | 24     | 4    | ucode_array_offset_bytes — payload start |
/// | 28     | 4    | crc32 |
#[derive(Copy, Clone, Debug, Default)]
pub struct CommonHeader {
    pub size_bytes: u32,
    pub header_size_bytes: u32,
    pub header_version_major: u16,
    pub header_version_minor: u16,
    pub ip_version_major: u16,
    pub ip_version_minor: u16,
    pub ucode_version: u32,
    pub ucode_size_bytes: u32,
    pub ucode_array_offset_bytes: u32,
    pub crc32: u32,
}

/// Size of the on-disk `common_firmware_header` struct.
pub const COMMON_HEADER_BYTES: usize = 32;

/// GFX firmware header version 1.0 (GFX9 — Renoir / Cezanne /
/// Lucienne / Barcelo). Adds 12 bytes of GFX-specific metadata
/// after the common header.
///
/// | offset | size | field |
/// |--------|------|-------|
/// | 0..32  | 32   | common header |
/// | 32     | 4    | ucode_feature_version |
/// | 36     | 4    | jt_offset — jump table offset in **dwords** from start of UCODE |
/// | 40     | 4    | jt_size   — jump table size in **dwords** |
#[derive(Copy, Clone, Debug, Default)]
pub struct GfxHeaderV10 {
    pub common: CommonHeader,
    pub ucode_feature_version: u32,
    /// JT offset in **32-bit dwords** from the start of the
    /// ucode region (NOT from the start of the file). Multiply
    /// by 4 to get a byte offset, then add
    /// `common.ucode_array_offset_bytes` to get a file-relative
    /// byte offset.
    pub jt_offset: u32,
    /// JT size in dwords (multiply by 4 for bytes).
    pub jt_size: u32,
}

/// Size of the on-disk `gfx_firmware_header_v1_0` struct.
pub const GFX_HEADER_V10_BYTES: usize = COMMON_HEADER_BYTES + 12;

#[derive(Copy, Clone, Debug)]
pub enum HeaderParseError {
    /// Blob shorter than the smallest header.
    TooShort {
        needed: usize,
        actual: usize,
    },
    /// `header_size_bytes` field doesn't match what we expect for
    /// the variant being parsed.
    BadHeaderSize {
        declared: u32,
        expected: usize,
    },
    /// `ucode_array_offset_bytes` points outside the blob.
    UcodeOffsetOutOfRange {
        offset: u32,
        blob_len: usize,
    },
    /// jt_offset + jt_size would overrun the payload (GFX1.0
    /// only).
    JtOutOfRange {
        jt_byte_offset: usize,
        jt_byte_size: usize,
        ucode_byte_size: usize,
    },
}

impl fmt::Display for HeaderParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderParseError::TooShort { needed, actual } => write!(
                f,
                "blob too short: needed {} bytes for header, got {}",
                needed, actual
            ),
            HeaderParseError::BadHeaderSize { declared, expected } => write!(
                f,
                "header_size_bytes mismatch: declared {}, expected {}",
                declared, expected
            ),
            HeaderParseError::UcodeOffsetOutOfRange { offset, blob_len } => write!(
                f,
                "ucode_array_offset_bytes ({}) past end of blob ({})",
                offset, blob_len
            ),
            HeaderParseError::JtOutOfRange {
                jt_byte_offset,
                jt_byte_size,
                ucode_byte_size,
            } => write!(
                f,
                "JT range {}..{} overruns ucode payload of {} bytes",
                jt_byte_offset,
                jt_byte_offset + jt_byte_size,
                ucode_byte_size
            ),
        }
    }
}

#[inline]
fn rd_u16(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap())
}

#[inline]
fn rd_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}

/// Parse the common header at the start of any amdgpu firmware
/// blob.
pub fn parse_common(bytes: &[u8]) -> Result<CommonHeader, HeaderParseError> {
    if bytes.len() < COMMON_HEADER_BYTES {
        return Err(HeaderParseError::TooShort {
            needed: COMMON_HEADER_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(CommonHeader {
        size_bytes: rd_u32(bytes, 0),
        header_size_bytes: rd_u32(bytes, 4),
        header_version_major: rd_u16(bytes, 8),
        header_version_minor: rd_u16(bytes, 10),
        ip_version_major: rd_u16(bytes, 12),
        ip_version_minor: rd_u16(bytes, 14),
        ucode_version: rd_u32(bytes, 16),
        ucode_size_bytes: rd_u32(bytes, 20),
        ucode_array_offset_bytes: rd_u32(bytes, 24),
        crc32: rd_u32(bytes, 28),
    })
}

/// Parse the GFX header v1.0 (GFX9). Validates that the
/// jump-table range fits within the ucode payload.
pub fn parse_gfx_v10(bytes: &[u8]) -> Result<GfxHeaderV10, HeaderParseError> {
    if bytes.len() < GFX_HEADER_V10_BYTES {
        return Err(HeaderParseError::TooShort {
            needed: GFX_HEADER_V10_BYTES,
            actual: bytes.len(),
        });
    }
    let common = parse_common(bytes)?;
    let ucode_feature_version = rd_u32(bytes, 32);
    let jt_offset = rd_u32(bytes, 36);
    let jt_size = rd_u32(bytes, 40);

    // Validate ucode offset is in range.
    let ucode_off = common.ucode_array_offset_bytes as usize;
    if ucode_off > bytes.len() {
        return Err(HeaderParseError::UcodeOffsetOutOfRange {
            offset: common.ucode_array_offset_bytes,
            blob_len: bytes.len(),
        });
    }

    // Validate JT range. jt_offset / jt_size are in dwords →
    // multiply by 4 for byte ranges. ucode_size_bytes is the
    // ceiling.
    let jt_byte_offset = (jt_offset as usize).saturating_mul(4);
    let jt_byte_size = (jt_size as usize).saturating_mul(4);
    let ucode_size = common.ucode_size_bytes as usize;
    if jt_byte_offset.saturating_add(jt_byte_size) > ucode_size {
        return Err(HeaderParseError::JtOutOfRange {
            jt_byte_offset,
            jt_byte_size,
            ucode_byte_size: ucode_size,
        });
    }

    Ok(GfxHeaderV10 {
        common,
        ucode_feature_version,
        jt_offset,
        jt_size,
    })
}

/// Locate the jump-table sub-region within a GFX9 MEC firmware
/// blob. The result is a (host_phys, byte_count) pair — the host
/// can construct a separate PSP `LOAD_IP_FW` for this range to
/// register `CP_MEC1_JT` (a distinct UCODE_ID from the main
/// `CP_MEC1`).
///
/// Returns `Ok(None)` when `jt_size == 0` (some MEC blobs don't
/// carry a JT). Otherwise the offset is **file-relative bytes**
/// — caller adds the firmware-blob base phys to get the JT phys.
pub fn locate_mec1_jt(bytes: &[u8]) -> Result<Option<JtView>, HeaderParseError> {
    let hdr = parse_gfx_v10(bytes)?;
    if hdr.jt_size == 0 {
        return Ok(None);
    }
    let ucode_base = hdr.common.ucode_array_offset_bytes as usize;
    let jt_file_offset = ucode_base + (hdr.jt_offset as usize) * 4;
    let jt_bytes = (hdr.jt_size as usize) * 4;
    Ok(Some(JtView {
        file_offset: jt_file_offset,
        bytes: jt_bytes,
    }))
}

/// Where the jump-table sub-region lives within the firmware
/// blob's payload bytes. File-relative.
#[derive(Copy, Clone, Debug)]
pub struct JtView {
    /// Byte offset from the start of the firmware blob (NOT the
    /// start of the ucode payload).
    pub file_offset: usize,
    pub bytes: usize,
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Helper: build a synthetic GFX v1.0 firmware blob with
    /// the given JT offset/size (in dwords) and a ucode payload
    /// of `ucode_bytes` bytes starting at offset 64.
    fn build_gfx_v10_blob(
        jt_offset_dwords: u32,
        jt_size_dwords: u32,
        ucode_bytes: u32,
    ) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; 64 + ucode_bytes as usize];
        // Common header.
        buf[0..4].copy_from_slice(&(buf.len() as u32).to_le_bytes()); // size_bytes
        buf[4..8].copy_from_slice(&(COMMON_HEADER_BYTES as u32).to_le_bytes());
        buf[8..10].copy_from_slice(&1u16.to_le_bytes()); // header_version_major
        buf[10..12].copy_from_slice(&0u16.to_le_bytes()); // header_version_minor
        buf[12..14].copy_from_slice(&9u16.to_le_bytes()); // ip_version_major (GFX9)
        buf[14..16].copy_from_slice(&0u16.to_le_bytes()); // ip_version_minor
        buf[16..20].copy_from_slice(&0xC0DE_F00Du32.to_le_bytes()); // ucode_version
        buf[20..24].copy_from_slice(&ucode_bytes.to_le_bytes()); // ucode_size_bytes
        buf[24..28].copy_from_slice(&64u32.to_le_bytes()); // ucode_array_offset_bytes
        buf[28..32].copy_from_slice(&0u32.to_le_bytes()); // crc32 (unchecked)
        // GFX1.0-specific tail.
        buf[32..36].copy_from_slice(&7u32.to_le_bytes()); // feature version
        buf[36..40].copy_from_slice(&jt_offset_dwords.to_le_bytes());
        buf[40..44].copy_from_slice(&jt_size_dwords.to_le_bytes());
        // Padding 44..64 stays zero — header_size_bytes = 32 but
        // many blobs round the actual on-disk header to 64 for
        // alignment; the parser only reads 44 so the gap is fine.
        buf
    }

    fn smoke_amdgpu_common_header_round_trip() -> TestResult {
        let blob = build_gfx_v10_blob(0x100, 0x40, 0x1000);
        let hdr = parse_common(&blob).expect("common header parse");
        if hdr.header_version_major != 1 {
            return TestResult::Fail("header_version_major wrong");
        }
        if hdr.ip_version_major != 9 {
            return TestResult::Fail("ip_version_major wrong (expected GFX9)");
        }
        if hdr.ucode_version != 0xC0DE_F00D {
            return TestResult::Fail("ucode_version wrong");
        }
        if hdr.ucode_size_bytes != 0x1000 {
            return TestResult::Fail("ucode_size_bytes wrong");
        }
        if hdr.ucode_array_offset_bytes != 64 {
            return TestResult::Fail("ucode_array_offset_bytes wrong");
        }
        TestResult::Pass
    }

    fn smoke_amdgpu_common_header_too_short() -> TestResult {
        let buf = alloc::vec![0u8; 16];
        match parse_common(&buf) {
            Err(HeaderParseError::TooShort { needed: 32, actual: 16 }) => TestResult::Pass,
            _ => TestResult::Fail("expected TooShort"),
        }
    }

    fn smoke_amdgpu_gfx_v10_jt_offset_round_trip() -> TestResult {
        let blob = build_gfx_v10_blob(0x100, 0x40, 0x1000);
        let hdr = parse_gfx_v10(&blob).expect("gfx v1.0 parse");
        if hdr.jt_offset != 0x100 || hdr.jt_size != 0x40 {
            return TestResult::Fail("jt fields wrong");
        }
        if hdr.ucode_feature_version != 7 {
            return TestResult::Fail("ucode_feature_version wrong");
        }
        TestResult::Pass
    }

    fn smoke_amdgpu_gfx_v10_jt_overrun_rejected() -> TestResult {
        // Ucode payload is 0x1000 bytes; JT at offset 0xF0 dwords
        // (= 0x3C0 bytes) of size 0x400 dwords (= 0x1000 bytes)
        // would extend to byte 0x13C0 — past the 0x1000 payload.
        let blob = build_gfx_v10_blob(0xF0, 0x400, 0x1000);
        match parse_gfx_v10(&blob) {
            Err(HeaderParseError::JtOutOfRange { .. }) => TestResult::Pass,
            _ => TestResult::Fail("expected JtOutOfRange"),
        }
    }

    fn smoke_amdgpu_locate_mec1_jt_returns_file_offset() -> TestResult {
        // JT at dword offset 0x100 (= 0x400 bytes into ucode),
        // size 0x40 dwords (= 0x100 bytes). ucode_array_offset
        // = 64. So file_offset should be 64 + 0x400 = 0x440.
        let blob = build_gfx_v10_blob(0x100, 0x40, 0x1000);
        let jt = locate_mec1_jt(&blob).expect("locate ok").expect("Some(JtView)");
        if jt.file_offset != 0x440 {
            return TestResult::Fail("JT file_offset wrong");
        }
        if jt.bytes != 0x100 {
            return TestResult::Fail("JT bytes wrong");
        }
        TestResult::Pass
    }

    fn smoke_amdgpu_locate_mec1_jt_none_when_size_zero() -> TestResult {
        let blob = build_gfx_v10_blob(0, 0, 0x1000);
        match locate_mec1_jt(&blob) {
            Ok(None) => TestResult::Pass,
            _ => TestResult::Fail("expected None for jt_size = 0"),
        }
    }

    kernel_test_in!(
        "drivers/gpu/amdgpu_ucode_header",
        smoke_amdgpu_common_header_round_trip
    );
    kernel_test_in!(
        "drivers/gpu/amdgpu_ucode_header",
        smoke_amdgpu_common_header_too_short
    );
    kernel_test_in!(
        "drivers/gpu/amdgpu_ucode_header",
        smoke_amdgpu_gfx_v10_jt_offset_round_trip
    );
    kernel_test_in!(
        "drivers/gpu/amdgpu_ucode_header",
        smoke_amdgpu_gfx_v10_jt_overrun_rejected
    );
    kernel_test_in!(
        "drivers/gpu/amdgpu_ucode_header",
        smoke_amdgpu_locate_mec1_jt_returns_file_offset
    );
    kernel_test_in!(
        "drivers/gpu/amdgpu_ucode_header",
        smoke_amdgpu_locate_mec1_jt_none_when_size_zero
    );
}
