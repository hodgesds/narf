//! Master Data Table directory.
//!
//! The master data table directory lives at the offset given by
//! `AtomRomHeader::master_data_table_offset`. Its layout is:
//!
//! ```text
//! ATOM_MASTER_DATA_TABLE:
//! +0x00  usStructureSize  u16   — total size in bytes
//! +0x02  ucTableFormatRevision u8
//! +0x03  ucTableContentRevision u8
//! +0x04  u16[N]           — per-table-id offsets (BIOS-image-relative)
//! ```
//!
//! `N = (usStructureSize - 4) / 2`. A zero entry means the table is absent.
//!
//! ## Linux references
//!
//! - `linux/drivers/gpu/drm/amd/include/atombios.h`
//!   `ATOM_MASTER_LIST_OF_DATA_TABLES` (lines ~1100-1200) —
//!   defines the per-index table IDs (e.g., `FirmwareInfo = 0`,
//!   `ASIC_ProfilingInfo = 1`, …).
//! - `linux/drivers/gpu/drm/amd/amdgpu/atom.c::atom_parse`
//!   (lines 267-308) — how Linux locates the master data table.

use super::header::AtomRomHeader;

/// Errors from master data table parsing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TableDirError {
    /// The `master_data_table_offset` in the ROM header is 0 or
    /// points past the end of the image.
    OutOfBounds,
    /// The `usStructureSize` field in the master data table is < 4
    /// (must hold at least the common header) or extends past the image.
    BadStructureSize,
}

/// Parsed view of the master data table directory.
///
/// Borrows from the VBIOS image slice for its lifetime; individual
/// table offsets are resolved via `table_offset`.
#[derive(Copy, Clone, Debug)]
pub struct MasterDataTable<'a> {
    image: &'a [u8],
    /// Byte offset of this table directory within `image`.
    dir_off: usize,
    /// Number of table entries.
    pub n_tables: u16,
    /// Format revision (byte 2 of the common header).
    pub format_revision: u8,
    /// Content revision (byte 3 of the common header).
    pub content_revision: u8,
}

impl<'a> MasterDataTable<'a> {
    /// Locate and parse the master data table described by `header`.
    ///
    /// Returns `Err(OutOfBounds)` when `header.master_data_table_offset`
    /// is zero or points past the image end.
    /// Returns `Err(BadStructureSize)` when the size field is malformed.
    pub fn parse(image: &'a [u8], header: &AtomRomHeader) -> Result<Self, TableDirError> {
        let dir_off = header.master_data_table_offset as usize;
        if dir_off == 0 || dir_off + 4 > image.len() {
            return Err(TableDirError::OutOfBounds);
        }
        let struct_size = u16::from_le_bytes([image[dir_off], image[dir_off + 1]]) as usize;
        if struct_size < 4 || dir_off + struct_size > image.len() {
            return Err(TableDirError::BadStructureSize);
        }
        let format_revision = image[dir_off + 2];
        let content_revision = image[dir_off + 3];
        let n_tables = ((struct_size - 4) / 2) as u16;
        Ok(Self {
            image,
            dir_off,
            n_tables,
            format_revision,
            content_revision,
        })
    }

    /// Return the VBIOS-image-relative offset for `table_id`, or
    /// `None` when the id is out of range or the stored offset is 0
    /// (table absent in this image).
    ///
    /// The offset is a u16 stored little-endian in the directory
    /// array starting at `dir_off + 4`.
    pub fn table_offset(&self, table_id: u16) -> Option<u16> {
        if table_id >= self.n_tables {
            return None;
        }
        let entry_off = self.dir_off + 4 + (table_id as usize) * 2;
        if entry_off + 2 > self.image.len() {
            return None;
        }
        let off = u16::from_le_bytes([self.image[entry_off], self.image[entry_off + 1]]);
        if off == 0 {
            None
        } else {
            Some(off)
        }
    }

    /// Return a byte slice covering the payload of `table_id`, starting
    /// from the `ATOM_COMMON_TABLE_HEADER` (first 2 bytes =
    /// `usStructureSize`). Returns `None` on any bounds failure.
    pub fn table_slice(&self, table_id: u16) -> Option<&'a [u8]> {
        let off = self.table_offset(table_id)? as usize;
        if off + 2 > self.image.len() {
            return None;
        }
        let len = u16::from_le_bytes([self.image[off], self.image[off + 1]]) as usize;
        if len < 4 || off + len > self.image.len() {
            return None;
        }
        Some(&self.image[off..off + len])
    }
}
