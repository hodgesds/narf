//! RLC (Run-Level Controller) firmware-blob walker — clean-room.
//!
//! Reference: AMD `amdgpu_ucode.h` (MIT-licensed shape) +
//! the public AMD GFX firmware-loading notes. The RLC firmware
//! is the piece of GFX microcode that orchestrates power-gating
//! + the GFX clock-state machine; it ships with extra metadata
//!   past the common ucode header (jump table, save-restore-list
//!   offsets, autoload offset table).
//!
//! ## Common header
//!
//! Every RLC blob starts with the same 256-byte common header
//! `amdgpu_ucode::parse` already decodes (magic + start_offset +
//! payload_size + version + …). The RLC variant additionally
//! places a per-section subheader at offset 4 + 32 = 36 within
//! the common header:
//!
//! ```text
//! +0x24   ulSavedAndRestoredListSrciOffset      u32
//! +0x28   ulSavedAndRestoredListSrciSize        u32
//! +0x2C   ulIndirectStartOffset                 u32
//! +0x30   ulIndirectSize                        u32
//! +0x34   ulRegSpaceListSize                    u32
//! +0x38   ulFwAtmCachedJumpTableSize            u32
//! +0x3C   ulSavedAndRestoredListGpmOffset       u32
//! +0x40   ulSavedAndRestoredListGpmSize         u32
//! +0x44   ulSavedAndRestoredListSrlcOffset      u32
//! +0x48   ulSavedAndRestoredListSrlcSize        u32
//! +0x4C   ulSavedAndRestoredListSrlgOffset      u32
//! +0x50   ulSavedAndRestoredListSrlgSize        u32
//! +0x54   ulRegListIndirectSize                 u32
//! +0x58   ulRlcAutoloadOffsetTableOffset        u32
//! +0x5C   ulRlcAutoloadOffsetTableSize          u32
//! ```
//!
//! ## RLC autoload offset table
//!
//! The `ulRlcAutoloadOffsetTable*` field pair points at a list
//! of `(firmware-id, blob-offset, blob-size)` tuples that tell
//! the RLC autoload sequencer which firmware blob to fetch from
//! VRAM at each step. Each entry is 12 bytes:
//!
//! ```text
//! +0x00   firmware_id     u32
//! +0x04   offset          u32  (VRAM byte offset)
//! +0x08   size            u32  (bytes)
//! ```
//!
//! Stage-8 ships the header decoder + an iterator over the
//! autoload table entries.

use core::fmt;

use crate::amdgpu_ucode::{UcodeError, UcodeHeader, UCODE_MAGIC};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RlcError {
    /// Common header bad / truncated.
    Header(UcodeError),
    /// Autoload-table offset/size pair points past blob length.
    AutoloadOutOfBounds,
}

impl From<UcodeError> for RlcError {
    fn from(e: UcodeError) -> Self {
        RlcError::Header(e)
    }
}

/// RLC-specific extension fields past the common header.
#[derive(Copy, Clone)]
pub struct RlcHeader {
    pub common: UcodeHeader,
    pub saved_restored_list_srci_offset: u32,
    pub saved_restored_list_srci_size: u32,
    pub indirect_start_offset: u32,
    pub indirect_size: u32,
    pub reg_space_list_size: u32,
    pub fw_atm_cached_jump_table_size: u32,
    pub saved_restored_list_gpm_offset: u32,
    pub saved_restored_list_gpm_size: u32,
    pub saved_restored_list_srlc_offset: u32,
    pub saved_restored_list_srlc_size: u32,
    pub saved_restored_list_srlg_offset: u32,
    pub saved_restored_list_srlg_size: u32,
    pub reg_list_indirect_size: u32,
    pub autoload_offset_table_offset: u32,
    pub autoload_offset_table_size: u32,
}

impl fmt::Debug for RlcHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RlcHeader")
            .field("common", &self.common)
            .field(
                "autoload",
                &(
                    self.autoload_offset_table_offset,
                    self.autoload_offset_table_size,
                ),
            )
            .finish_non_exhaustive()
    }
}

/// One entry in the RLC autoload offset table.
#[derive(Copy, Clone)]
pub struct AutoloadEntry {
    pub firmware_id: u32,
    pub offset: u32,
    pub size: u32,
}

impl fmt::Debug for AutoloadEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutoloadEntry")
            .field("fw_id", &self.firmware_id)
            .field("offset", &self.offset)
            .field("size", &self.size)
            .finish()
    }
}

/// Parse the common ucode header + the RLC extension fields.
pub fn parse(blob: &[u8]) -> Result<RlcHeader, RlcError> {
    let common = crate::amdgpu_ucode::parse(blob)?;
    if blob.len() < 0x60 {
        return Err(RlcError::Header(UcodeError::Truncated));
    }
    let read_u32 = |o: usize| u32::from_le_bytes([blob[o], blob[o + 1], blob[o + 2], blob[o + 3]]);
    Ok(RlcHeader {
        common,
        saved_restored_list_srci_offset: read_u32(0x24),
        saved_restored_list_srci_size: read_u32(0x28),
        indirect_start_offset: read_u32(0x2C),
        indirect_size: read_u32(0x30),
        reg_space_list_size: read_u32(0x34),
        fw_atm_cached_jump_table_size: read_u32(0x38),
        saved_restored_list_gpm_offset: read_u32(0x3C),
        saved_restored_list_gpm_size: read_u32(0x40),
        saved_restored_list_srlc_offset: read_u32(0x44),
        saved_restored_list_srlc_size: read_u32(0x48),
        saved_restored_list_srlg_offset: read_u32(0x4C),
        saved_restored_list_srlg_size: read_u32(0x50),
        reg_list_indirect_size: read_u32(0x54),
        autoload_offset_table_offset: read_u32(0x58),
        autoload_offset_table_size: read_u32(0x5C),
    })
}

/// Iterate the RLC autoload offset table. Each entry says
/// "firmware id `N` lives at `offset` for `size` bytes within
/// the per-board RLC payload"; the autoload sequencer fetches
/// each in order.
///
/// `blob` is the full firmware bytes; `header` was returned by
/// `parse`. Returns an iterator that yields one
/// `AutoloadEntry` per 12-byte slot.
pub fn autoload_iter<'a>(
    blob: &'a [u8],
    header: &RlcHeader,
) -> Result<impl Iterator<Item = AutoloadEntry> + 'a, RlcError> {
    let off = header.autoload_offset_table_offset as usize;
    let sz = header.autoload_offset_table_size as usize;
    if off == 0 || sz == 0 || off + sz > blob.len() {
        return Err(RlcError::AutoloadOutOfBounds);
    }
    let n = sz / 12;
    Ok((0..n).map(move |i| {
        let entry_off = off + i * 12;
        let read_u32 =
            |o: usize| u32::from_le_bytes([blob[o], blob[o + 1], blob[o + 2], blob[o + 3]]);
        AutoloadEntry {
            firmware_id: read_u32(entry_off),
            offset: read_u32(entry_off + 4),
            size: read_u32(entry_off + 8),
        }
    }))
}

/// Quick sanity check: blob's first 4 bytes are the standard
/// `0x012345AB` ucode magic AND the common header parses.
pub fn looks_like_rlc(blob: &[u8]) -> bool {
    if blob.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    magic == UCODE_MAGIC && parse(blob).is_ok()
}
