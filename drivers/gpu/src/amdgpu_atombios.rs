//! Bounded ATOM data/command directories, using the common ROM-header
//! decoder. Offsets follow Linux `atom.h` and AMD `atombios.h`:
//! PCI ROM 55 AA, u16 header pointer at 0x48, signature at header+4,
//! u16 command/data directory pointers at header+0x1e/+0x20.
use crate::atombios::header::{parse_rom_header, HeaderError};
use core::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AtomError {
    /// Image too short to even check the ROM signature.
    Truncated,
    /// `0x55 0xAA` ROM signature missing — not a PCI option ROM.
    NotPciRom,
    /// `"ATOM"` marker missing — PCI ROM but not from AMD.
    NotAtombios,
    /// Master data-table pointer points past the end of the image.
    BadTablePointer,
    /// Per-table id is out of range for the indexed array.
    UnknownTableId,
}

/// One ATOMBIOS image, viewed as `(slice, parsed-master-pointers)`.
/// Borrows from the source; convert via methods below.
#[derive(Copy, Clone)]
pub struct Atombios<'a> {
    image: &'a [u8],
    /// Offset of the master data table within `image`.
    data_master_off: u32,
    /// Number of 16-bit per-table entries in the data master.
    n_tables: u16,
    /// Offset of the master command table within `image`.
    cmd_master_off: u32,
    /// Number of 16-bit per-table entries in the command master.
    n_cmd_tables: u16,
}

/// `ATOM_CT_WS_PTR` / `ATOM_CT_PS_PTR` / `ATOM_CT_PS_MASK` / `ATOM_CT_CODE_PTR`
/// from `atom.h:59-63`. The working-scratch byte is at 4, the parameter byte
/// at 5 with only its low seven bits counting, and the bytecode starts at 6.
pub const ATOM_CT_WS_PTR: usize = 4;
pub const ATOM_CT_PS_PTR: usize = 5;
pub const ATOM_CT_PS_MASK: u8 = 0x7F;
pub const ATOM_CT_CODE_PTR: usize = 6;

impl<'a> fmt::Debug for Atombios<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Atombios")
            .field("size", &self.image.len())
            .field("data_master_off", &self.data_master_off)
            .field("n_tables", &self.n_tables)
            .finish()
    }
}

impl<'a> Atombios<'a> {
    /// Parse the BIOS image: validate signatures, locate the
    /// master data table, decode its header.
    pub fn parse(image: &'a [u8]) -> Result<Self, AtomError> {
        if image.len() < 0x4a {
            return Err(AtomError::Truncated);
        }
        if image[..2] != [0x55, 0xaa] {
            return Err(AtomError::NotPciRom);
        }
        let header = parse_rom_header(image).map_err(|e| match e {
            HeaderError::BadAtomSignature => AtomError::NotAtombios,
            _ => AtomError::BadTablePointer,
        })?;
        let data_off = header.master_data_table_offset as u32;
        let cmd_off = header.master_command_table_offset as u32;
        let n_tables = directory_count(image, data_off)?;
        let n_cmd_tables = directory_count(image, cmd_off)?;

        Ok(Self {
            image,
            data_master_off: data_off,
            n_tables,
            cmd_master_off: cmd_off,
            n_cmd_tables,
        })
    }

    /// Number of indexable data tables.
    pub fn data_table_count(&self) -> u16 {
        self.n_tables
    }

    /// Offset of `table_id`'s payload within the BIOS image, or
    /// `Err(UnknownTableId)` when the id is out of range. The
    /// stored pointer is a 16-bit BIOS-relative offset — we
    /// extend it to u32 for callers.
    ///
    pub fn data_table_offset(&self, table_id: u16) -> Result<u32, AtomError> {
        if table_id >= self.n_tables {
            return Err(AtomError::UnknownTableId);
        }
        let off = self.data_master_off as usize + 4 + (table_id as usize) * 2;
        let p = u16::from_le_bytes([self.image[off], self.image[off + 1]]) as u32;
        if p == 0 || p as usize >= self.image.len() {
            return Err(AtomError::BadTablePointer);
        }
        Ok(p)
    }

    /// Borrow a slice covering `table_id`'s payload, starting at
    /// the table header. Length is read from the header's
    /// `usStructureSize` (first 2 bytes of the table).
    pub fn data_table(&self, table_id: u16) -> Result<&'a [u8], AtomError> {
        let off = self.data_table_offset(table_id)? as usize;
        if off + 2 > self.image.len() {
            return Err(AtomError::BadTablePointer);
        }
        let len = u16::from_le_bytes([self.image[off], self.image[off + 1]]) as usize;
        if len < 4 || off + len > self.image.len() {
            return Err(AtomError::BadTablePointer);
        }
        Ok(&self.image[off..off + len])
    }

    // ── Command-table directory ─────────────────────────────────────

    /// Number of indexable command tables. `0` when the BIOS
    /// image doesn't ship a command-table master directory.
    pub fn cmd_table_count(&self) -> u16 {
        self.n_cmd_tables
    }

    /// Offset of `table_id`'s command-table payload within the
    /// BIOS image. Symmetric to `data_table_offset`.
    pub fn cmd_table_offset(&self, table_id: u16) -> Result<u32, AtomError> {
        if self.n_cmd_tables == 0 {
            return Err(AtomError::UnknownTableId);
        }
        if table_id >= self.n_cmd_tables {
            return Err(AtomError::UnknownTableId);
        }
        let off = self.cmd_master_off as usize + 4 + (table_id as usize) * 2;
        let p = u16::from_le_bytes([self.image[off], self.image[off + 1]]) as u32;
        if p == 0 || p as usize >= self.image.len() {
            return Err(AtomError::BadTablePointer);
        }
        Ok(p)
    }

    /// Borrow the bytes of `table_id`'s command-table payload.
    /// Each command table starts with an `ATOM_COMMON_TABLE_HEADER`
    /// (4 bytes) followed by the AtomBIOS bytecode for that
    /// command. Stage-8 doesn't include the bytecode interpreter
    /// — drivers reach into the offset themselves and either
    /// dispatch to a hand-written replacement or run the
    /// bytecode in a future Stage-9+ interpreter.
    pub fn cmd_table(&self, table_id: u16) -> Result<&'a [u8], AtomError> {
        let off = self.cmd_table_offset(table_id)? as usize;
        if off + 2 > self.image.len() {
            return Err(AtomError::BadTablePointer);
        }
        let len = u16::from_le_bytes([self.image[off], self.image[off + 1]]) as usize;
        if len < 6 || off + len > self.image.len() {
            return Err(AtomError::BadTablePointer);
        }
        Ok(&self.image[off..off + len])
    }

    /// Strip the `ATOM_COMMON_TABLE_HEADER` (4 bytes) + the
    /// per-table prelude (ws/ps bytes at `ATOM_CT_WS_PTR`,
    /// `ATOM_CT_PS_PTR` = offsets 4, 5) and return the raw
    /// bytecode body starting at `ATOM_CT_CODE_PTR` (= +6).
    ///
    /// This is what `amdgpu_atom_vm::execute_bytes` consumes.
    /// Convenience helper so callers don't open-code the header
    /// skip per Linux `atom.c::amdgpu_atom_execute_table_locked`
    /// (lines 1232-1235).
    pub fn cmd_table_body(&self, table_id: u16) -> Result<&'a [u8], AtomError> {
        self.cmd_table_body_and_ps(table_id).map(|(body, _)| body)
    }

    /// The bytecode body plus the parameter size the table's own header
    /// declares, in dwords.
    ///
    /// `ATOM_CT_PS_PTR` is offset 5 and `ATOM_CT_PS_MASK` is 0x7F — the top
    /// bit of that byte is not part of the size. `atom.c:1255` divides by four
    /// to get `ectx.ps_shift`, which `atom.c:650` adds to the parameter
    /// pointer when a table calls another. Returning the body alone leaves the
    /// VM no way to compute it, so these travel together.
    pub fn cmd_table_body_and_ps(&self, table_id: u16) -> Result<(&'a [u8], usize), AtomError> {
        let full = self.cmd_table(table_id)?;
        if full.len() < 6 {
            return Err(AtomError::BadTablePointer);
        }
        let ps_bytes = (full[5] & ATOM_CT_PS_MASK) as usize;
        Ok((&full[6..], ps_bytes / 4))
    }
}

fn directory_count(image: &[u8], offset: u32) -> Result<u16, AtomError> {
    let off = offset as usize;
    if off == 0 {
        return Ok(0);
    }
    let header = image.get(off..off + 4).ok_or(AtomError::BadTablePointer)?;
    let size = u16::from_le_bytes([header[0], header[1]]) as usize;
    if size < 4 || size % 2 != 0 || off + size > image.len() {
        return Err(AtomError::BadTablePointer);
    }
    Ok(((size - 4) / 2) as u16)
}
