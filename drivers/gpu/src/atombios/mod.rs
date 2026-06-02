//! ATOMBIOS VBIOS parser — ATOM_ROM_HEADER + version string extraction.
//!
//! Parses the AMD ATOMBIOS image format used by every modern AMD GPU
//! (Vega / RDNA / Phoenix). Provides:
//!
//! - [`AtomBios`] — parsed VBIOS descriptor with version string.
//! - [`parse`] — top-level entry point; validates and parses a VBIOS
//!   image byte slice.
//!
//! ## VBIOS image layout
//!
//! ```text
//! +0x00 ..0x47    padding / PCI legacy ROM header (varies)
//! +0x48-0x49      u16 (LE) → offset of ATOM_ROM_HEADER within image
//!
//! ATOM_ROM_HEADER (at the pointer above):
//! +0x00  "ATOM"                  4-byte ASCII signature
//! +0x0C  bios_bootup_message_offset  u16 → NUL-terminated version string
//! +0x1A  master_command_table_offset u16 → command table directory
//! +0x1C  master_data_table_offset    u16 → data table directory
//! ...
//! ```
//!
//! ## Scope
//!
//! This module covers:
//! - ROM header signature validation.
//! - Master data table directory parsing (count + per-id offset lookup).
//! - VBIOS version string extraction from `bios_bootup_message_offset`.
//!
//! **Deferred**: PowerPlay table parsing, voltage/thermal limits, DDC/EDID
//! extraction from VBIOS, command table interpreter.
//!
//! ## Linux references
//!
//! - `linux/drivers/gpu/drm/amd/include/atombios.h` — struct definitions.
//! - `linux/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c` lines 73-100
//!   — `amdgpu_atombios_get_bios_version`.
//! - `linux/drivers/gpu/drm/amd/amdgpu/atom.c` lines 267-308
//!   — `atom_parse` (table directory location).

extern crate alloc;

use alloc::string::String;

pub mod header;
pub mod tables;
pub mod version;

#[cfg(feature = "kernel-test")]
mod tests;

use header::HeaderError;
use tables::TableDirError;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors from [`parse`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AtomBiosError {
    /// Image is too short (< 0x4A bytes) to read the ROM header pointer.
    InvalidVbios,
    /// ROM header pointer is out of bounds (points past the image end).
    InvalidVbios2,
    /// The 4-byte ATOM signature at the ROM header offset is not "ATOM".
    BadAtomSignature,
    /// Master data table directory is out of bounds or malformed.
    BadDataTableDir,
}

impl core::fmt::Display for AtomBiosError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AtomBiosError::InvalidVbios => write!(f, "VBIOS image too short"),
            AtomBiosError::InvalidVbios2 => write!(f, "ROM header pointer out of bounds"),
            AtomBiosError::BadAtomSignature => write!(f, "invalid ATOM signature"),
            AtomBiosError::BadDataTableDir => write!(f, "master data table directory error"),
        }
    }
}

impl From<HeaderError> for AtomBiosError {
    fn from(e: HeaderError) -> Self {
        match e {
            HeaderError::InvalidVbios => AtomBiosError::InvalidVbios,
            HeaderError::InvalidVbios2 => AtomBiosError::InvalidVbios2,
            HeaderError::BadAtomSignature => AtomBiosError::BadAtomSignature,
        }
    }
}

impl From<TableDirError> for AtomBiosError {
    fn from(_: TableDirError) -> Self {
        AtomBiosError::BadDataTableDir
    }
}

// ── Parsed result ───────────────────────────────────────────────────────────

/// Parsed ATOMBIOS descriptor.
///
/// Produced by [`parse`]; owned by the caller (all strings are heap-allocated
/// in NARF's `extern crate alloc` environment).
#[derive(Clone, Debug)]
pub struct AtomBios {
    /// VBIOS version string from `bios_bootup_message_offset`, or `None`
    /// when the offset is absent / out of bounds / non-UTF-8.
    ///
    /// Real AMD strings look like:
    /// `"BK-AMD ATOMBIOSBK-AMD VER015.040.000.000.014546"`.
    pub version: Option<String>,

    /// Number of entries in the master data table directory.
    /// 0 when the master data table offset in the ROM header is 0 or
    /// out of bounds (the directory parse degrades gracefully).
    pub n_data_tables: u16,

    /// Format revision from the master data table common header.
    pub data_table_format_rev: u8,

    /// Content revision from the master data table common header.
    pub data_table_content_rev: u8,
}

// ── Top-level parse ─────────────────────────────────────────────────────────

/// Parse a VBIOS image and return an [`AtomBios`] descriptor.
///
/// Validates the ROM header signature, extracts the version string, and
/// catalogues the master data table directory. Hard failures (signature
/// mismatch, image too short) return `Err`; soft failures (version string
/// out of bounds, absent master data table) degrade to `None` / 0 fields.
///
/// # Errors
///
/// - [`AtomBiosError::InvalidVbios`] — image shorter than 0x4A bytes.
/// - [`AtomBiosError::InvalidVbios2`] — ROM header pointer out of bounds.
/// - [`AtomBiosError::BadAtomSignature`] — "ATOM" not present at header.
/// - [`AtomBiosError::BadDataTableDir`] — master data table directory
///   is structurally invalid (size < 4 or extends past image end).
///   Note: a zero `master_data_table_offset` is treated as *absent* (not an
///   error), yielding `n_data_tables = 0`.
pub fn parse(image: &[u8]) -> Result<AtomBios, AtomBiosError> {
    // 1. Parse and validate the ROM header.
    let hdr = header::parse_rom_header(image)?;

    // 2. Extract the version string (soft failure → None).
    let ver = version::extract_version(image, &hdr);

    // 3. Parse the master data table directory. A zero offset is
    //    valid (absent) — degrade gracefully. A non-zero but
    //    structurally invalid offset is a hard error.
    let (n_data_tables, fmt_rev, content_rev) =
        if hdr.master_data_table_offset == 0 {
            (0u16, 0u8, 0u8)
        } else {
            match tables::MasterDataTable::parse(image, &hdr) {
                Ok(dir) => (dir.n_tables, dir.format_revision, dir.content_revision),
                Err(e) => return Err(AtomBiosError::from(e)),
            }
        };

    Ok(AtomBios {
        version: ver,
        n_data_tables,
        data_table_format_rev: fmt_rev,
        data_table_content_rev: content_rev,
    })
}
