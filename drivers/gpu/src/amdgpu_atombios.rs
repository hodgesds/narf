//! ATOMBIOS table-directory parser — clean-room.
//!
//! Reference: AMD `AtomBios.h` (Mesa, MIT-licensed; structure
//! definitions are not GPL-encumbered) and the public AMD ATOMBIOS
//! Programming Guide. Section numbers below (`§A.x`) refer to the
//! programming guide.
//!
//! ## Layout
//!
//! Every modern AMD GPU's BIOS image starts with the standard PCI
//! ROM signature `0xAA55` followed by a vendor block whose offset
//! 4 carries the ASCII signature `"ATOM"`. The 32-bit pointer at
//! offset `0x48` from the BIOS base points at the master command
//! table; the pointer at offset `0x4C` points at the master data
//! table. Each master table is itself a header + an array of
//! `usCmdTablePtr` (or `usDataTablePtr`) 16-bit offsets, indexed
//! by table-id.
//!
//! ```text
//! BIOS image (BAR0/2 ROM region or SoC firmware payload):
//! +0x00  0xAA 0x55                  PCI ROM signature
//! +0x02  size in 512-byte blocks
//! +0x04  "ATOM"                     ATOMBIOS marker
//! +0x48  u32  master_cmd_table      (offset within BIOS image)
//! +0x4C  u32  master_data_table     (offset within BIOS image)
//!
//! master_data_table:
//! +0x00  ATOM_COMMON_TABLE_HEADER {
//!          u16 usStructureSize
//!          u8  ucTableFormatRevision
//!          u8  ucTableContentRevision
//!        }
//! +0x04  Array<u16> per-table-id offsets
//! ```
//!
//! ## Stage-3 cut
//!
//! Locates the master tables, decodes `ATOM_COMMON_TABLE_HEADER`,
//! exposes `data_table_offset(table_id)` as a `u32` BIOS-relative
//! offset. Doesn't yet walk individual tables — drivers reach
//! into the offset themselves via the parent BIOS slice. Adding a
//! per-table walker (e.g. for `ATOM_DCN_INIT_DATA` table id 0x14)
//! is mechanical once the layout's documented per `§A`.

use core::fmt;

/// The two ASCII bytes at PCI ROM offset 0/1.
const ROM_SIGNATURE: [u8; 2] = [0xAA, 0x55];
/// ASCII at offset 4 marking an AMD ATOMBIOS image.
const ATOM_MARKER:   &[u8]   = b"ATOM";

/// Offset of the 32-bit pointer to the master data table, per
/// AtomBios.h `OFFSET_TO_POINTER_TO_ATOM_ROM_HEADER`.
const OFFSET_DATA_TABLE_PTR: usize = 0x4C;
/// Offset of the 32-bit pointer to the master command table.
/// Symmetric to the data-table pointer; both live in the
/// `ATOM_ROM_HEADER` block 4 bytes apart.
const OFFSET_CMD_TABLE_PTR: usize = 0x48;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AtomError {
    /// Image too short to even check the ROM signature.
    Truncated,
    /// `0xAA 0x55` ROM signature missing — not a PCI option ROM.
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
        if image.len() < 0x50 { return Err(AtomError::Truncated); }
        if image[0..2] != ROM_SIGNATURE { return Err(AtomError::NotPciRom); }
        if &image[4..8] != ATOM_MARKER  { return Err(AtomError::NotAtombios); }
        let data_off = u32::from_le_bytes([
            image[OFFSET_DATA_TABLE_PTR],
            image[OFFSET_DATA_TABLE_PTR + 1],
            image[OFFSET_DATA_TABLE_PTR + 2],
            image[OFFSET_DATA_TABLE_PTR + 3],
        ]);
        let off = data_off as usize;
        // ATOM_COMMON_TABLE_HEADER is 4 bytes; we need at least
        // the header + one u16 entry.
        if off + 6 > image.len() { return Err(AtomError::BadTablePointer); }
        let struct_size = u16::from_le_bytes([image[off], image[off + 1]]) as usize;
        // Master table is `struct_size` bytes total. Subtract the
        // 4-byte header to get the array byte length, divide by 2
        // for the table count.
        if struct_size < 4 || off + struct_size > image.len() {
            return Err(AtomError::BadTablePointer);
        }
        let n_tables = ((struct_size - 4) / 2) as u16;

        // Command-table master directory — symmetric layout 4
        // bytes lower in the ATOM_ROM_HEADER. May be 0 on images
        // that don't ship command tables (rare; modern Vega+
        // always does).
        let cmd_off = u32::from_le_bytes([
            image[OFFSET_CMD_TABLE_PTR],
            image[OFFSET_CMD_TABLE_PTR + 1],
            image[OFFSET_CMD_TABLE_PTR + 2],
            image[OFFSET_CMD_TABLE_PTR + 3],
        ]);
        let (n_cmd_tables, cmd_off_final) = if cmd_off == 0 {
            (0u16, 0u32)
        } else {
            let coff = cmd_off as usize;
            if coff + 6 > image.len() { return Err(AtomError::BadTablePointer); }
            let csz = u16::from_le_bytes([image[coff], image[coff + 1]]) as usize;
            if csz < 4 || coff + csz > image.len() {
                return Err(AtomError::BadTablePointer);
            }
            (((csz - 4) / 2) as u16, cmd_off)
        };

        Ok(Self {
            image,
            data_master_off: data_off, n_tables,
            cmd_master_off: cmd_off_final, n_cmd_tables,
        })
    }

    /// Number of indexable data tables.
    pub fn data_table_count(&self) -> u16 { self.n_tables }

    /// Offset of `table_id`'s payload within the BIOS image, or
    /// `Err(UnknownTableId)` when the id is out of range. The
    /// stored pointer is a 16-bit BIOS-relative offset — we
    /// extend it to u32 for callers.
    ///
    /// Per AtomBios.h, table 0 in the data master is
    /// `ATOM_DCN_INIT_DATA` (DCN initialization parameters);
    /// drivers usually start there.
    pub fn data_table_offset(&self, table_id: u16) -> Result<u32, AtomError> {
        if table_id >= self.n_tables { return Err(AtomError::UnknownTableId); }
        let off = self.data_master_off as usize
            + 4
            + (table_id as usize) * 2;
        let p = u16::from_le_bytes([self.image[off], self.image[off + 1]]) as u32;
        if p == 0 || p as usize >= self.image.len() {
            return Err(AtomError::BadTablePointer);
        }
        Ok(p)
    }

    /// Borrow a slice covering `table_id`'s payload, starting at
    /// the table header. Length is read from the header's
    /// `usStructureSize` (first 2 bytes of the table).
    pub fn data_table<'b>(&'b self, table_id: u16) -> Result<&'a [u8], AtomError> {
        let off = self.data_table_offset(table_id)? as usize;
        if off + 2 > self.image.len() { return Err(AtomError::BadTablePointer); }
        let len = u16::from_le_bytes([self.image[off], self.image[off + 1]]) as usize;
        if off + len > self.image.len() { return Err(AtomError::BadTablePointer); }
        Ok(&self.image[off..off + len])
    }

    // ── Command-table directory ─────────────────────────────────────

    /// Number of indexable command tables. `0` when the BIOS
    /// image doesn't ship a command-table master directory.
    pub fn cmd_table_count(&self) -> u16 { self.n_cmd_tables }

    /// Offset of `table_id`'s command-table payload within the
    /// BIOS image. Symmetric to `data_table_offset`.
    pub fn cmd_table_offset(&self, table_id: u16) -> Result<u32, AtomError> {
        if self.n_cmd_tables == 0 { return Err(AtomError::UnknownTableId); }
        if table_id >= self.n_cmd_tables { return Err(AtomError::UnknownTableId); }
        let off = self.cmd_master_off as usize
            + 4
            + (table_id as usize) * 2;
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
    pub fn cmd_table<'b>(&'b self, table_id: u16) -> Result<&'a [u8], AtomError> {
        let off = self.cmd_table_offset(table_id)? as usize;
        if off + 2 > self.image.len() { return Err(AtomError::BadTablePointer); }
        let len = u16::from_le_bytes([self.image[off], self.image[off + 1]]) as usize;
        if off + len > self.image.len() { return Err(AtomError::BadTablePointer); }
        Ok(&self.image[off..off + len])
    }
}
