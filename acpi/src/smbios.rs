//! SMBIOS / DMI structure decoder — clean-room.
//!
//! References (public-only):
//! - "SMBIOS Reference Specification, Version 3.6.0" (Mar 2022) —
//!   DMTF DSP0134. Public document.
//!   §5.1 32-bit Entry Point ("_SM_" anchor).
//!   §5.2 64-bit Entry Point ("_SM3_" anchor).
//!   §6.1 Structure Header (type / length / handle).
//!   §7.1 Type 0  BIOS Information.
//!   §7.2 Type 1  System Information.
//!   §7.3 Type 2  Baseboard Information.
//!   §7.5 Type 4  Processor Information.
//!   §7.18 Type 17 Memory Device.
//!
//! No GPL Linux source consulted.
//!
//! ## Entry-point structure (§5)
//!
//! Two flavours coexist; the host walks them through different
//! anchors:
//!
//! ```text
//!   "_SM_"  — 32-bit entry point (legacy BIOS, 31 bytes)
//!   "_SM3_" — 64-bit entry point (UEFI / SMBIOS 3.0+, 24 bytes,
//!             carries a 64-bit physical address of the structure
//!             table that may live above 4 GiB).
//! ```
//!
//! ## Structure layout (§6.1)
//!
//! Each SMBIOS structure begins with a 4-byte header:
//!
//! ```text
//!   byte 0 type      (0..127 = standard, 128..254 = OEM, 255 = end-of-table)
//!   byte 1 length    (formatted-section length, in bytes; ≥ 4)
//!   bytes 2..3 handle (16-bit unique id within this structure table)
//! ```
//!
//! Following the formatted section is a NUL-terminated *string set*
//! ending in a single NUL ("..\0..\0\0").

use alloc::string::String;
use alloc::vec::Vec;

// ── Anchors ────────────────────────────────────────────────────────

pub const ANCHOR_SM2: &[u8; 4] = b"_SM_";
pub const ANCHOR_SM3: &[u8; 5] = b"_SM3_";

// ── Structure types (§6.1, table 4) ────────────────────────────────

pub const TYPE_BIOS_INFO: u8 = 0;
pub const TYPE_SYSTEM_INFO: u8 = 1;
pub const TYPE_BASEBOARD_INFO: u8 = 2;
pub const TYPE_SYSTEM_ENCLOSURE: u8 = 3;
pub const TYPE_PROCESSOR_INFO: u8 = 4;
pub const TYPE_MEMORY_DEVICE: u8 = 17;
pub const TYPE_MEMORY_ARRAY: u8 = 16;
pub const TYPE_END_OF_TABLE: u8 = 127;

// ── Type 17 Memory Device — Memory Type byte (§7.18.2, table 78) ──

pub const MEM_TYPE_DDR: u8 = 0x12;
pub const MEM_TYPE_DDR2: u8 = 0x13;
pub const MEM_TYPE_DDR3: u8 = 0x18;
pub const MEM_TYPE_DDR4: u8 = 0x1A;
pub const MEM_TYPE_DDR5: u8 = 0x22;
pub const MEM_TYPE_LPDDR: u8 = 0x1B;
pub const MEM_TYPE_LPDDR2: u8 = 0x1C;
pub const MEM_TYPE_LPDDR3: u8 = 0x1D;
pub const MEM_TYPE_LPDDR4: u8 = 0x1E;
pub const MEM_TYPE_LPDDR5: u8 = 0x23;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SmbiosError {
    Short,
    /// Anchor signature wasn't found at the start.
    BadAnchor,
    /// Header `length` was < 4 or extended past the buffer.
    BadLength,
    /// Checksum byte didn't bring the entry-point block to zero.
    BadChecksum,
}

// ── Entry points ───────────────────────────────────────────────────

/// 32-bit entry point ("_SM_").
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryPoint32 {
    pub major: u8,
    pub minor: u8,
    /// Byte length of the structure table.
    pub structure_table_length: u16,
    pub structure_table_address: u32,
    pub structure_count: u16,
}

impl EntryPoint32 {
    /// Parse a 32-bit entry-point block. The host found the "_SM_"
    /// anchor and passed the 31-byte block here.
    pub fn parse(buf: &[u8]) -> Result<Self, SmbiosError> {
        if buf.len() < 31 {
            return Err(SmbiosError::Short);
        }
        if &buf[0..4] != ANCHOR_SM2 {
            return Err(SmbiosError::BadAnchor);
        }
        let entry_point_length = buf[5] as usize;
        if entry_point_length > buf.len() || entry_point_length < 31 {
            return Err(SmbiosError::BadLength);
        }
        let sum = buf[..entry_point_length]
            .iter()
            .fold(0u32, |acc, b| acc.wrapping_add(*b as u32));
        if sum & 0xFF != 0 {
            return Err(SmbiosError::BadChecksum);
        }
        Ok(Self {
            major: buf[6],
            minor: buf[7],
            structure_table_length: u16::from_le_bytes([buf[22], buf[23]]),
            structure_table_address: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
            structure_count: u16::from_le_bytes([buf[28], buf[29]]),
        })
    }
}

/// 64-bit entry point ("_SM3_").
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryPoint64 {
    pub major: u8,
    pub minor: u8,
    pub doc_rev: u8,
    /// Maximum size of the structure table (advisory).
    pub structure_table_max_size: u32,
    pub structure_table_address: u64,
}

impl EntryPoint64 {
    pub fn parse(buf: &[u8]) -> Result<Self, SmbiosError> {
        if buf.len() < 24 {
            return Err(SmbiosError::Short);
        }
        if &buf[0..5] != ANCHOR_SM3 {
            return Err(SmbiosError::BadAnchor);
        }
        let entry_point_length = buf[6] as usize;
        if entry_point_length > buf.len() || entry_point_length < 24 {
            return Err(SmbiosError::BadLength);
        }
        let sum = buf[..entry_point_length]
            .iter()
            .fold(0u32, |acc, b| acc.wrapping_add(*b as u32));
        if sum & 0xFF != 0 {
            return Err(SmbiosError::BadChecksum);
        }
        Ok(Self {
            major: buf[7],
            minor: buf[8],
            doc_rev: buf[9],
            structure_table_max_size: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            structure_table_address: u64::from_le_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]),
        })
    }
}

// ── Structure header + iterator ────────────────────────────────────

/// Common 4-byte SMBIOS structure header.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct StructHeader {
    pub typ: u8,
    pub length: u8,
    pub handle: u16,
}

/// Iterate SMBIOS structures in a flat buffer (the structure table
/// loaded from `structure_table_address`). Stops at type 127
/// (end-of-table).
#[derive(Debug)]
pub struct StructIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> StructIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Iterator for StructIter<'a> {
    type Item = (StructHeader, &'a [u8], Vec<String>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 4 > self.buf.len() {
            return None;
        }
        let typ = self.buf[self.pos];
        if typ == TYPE_END_OF_TABLE {
            return None;
        }
        let length = self.buf[self.pos + 1] as usize;
        if length < 4 || self.pos + length > self.buf.len() {
            return None;
        }
        let handle = u16::from_le_bytes([self.buf[self.pos + 2], self.buf[self.pos + 3]]);
        let formatted = &self.buf[self.pos + 4..self.pos + length];
        let mut p = self.pos + length;
        // Walk the string table — sequence of NUL-terminated strings,
        // ending in an extra NUL. If the formatted section is followed
        // immediately by a single NUL, the structure has no strings.
        let mut strings = Vec::new();
        if p < self.buf.len()
            && self.buf[p] == 0
            && (p + 2 > self.buf.len() || self.buf[p + 1] == 0)
        {
            p += 2;
        } else {
            loop {
                if p >= self.buf.len() {
                    return None;
                }
                let start = p;
                while p < self.buf.len() && self.buf[p] != 0 {
                    p += 1;
                }
                if p == self.buf.len() {
                    return None;
                }
                let s = core::str::from_utf8(&self.buf[start..p])
                    .unwrap_or("")
                    .into();
                strings.push(s);
                p += 1; // consume NUL
                if p < self.buf.len() && self.buf[p] == 0 {
                    p += 1;
                    break;
                }
            }
        }
        let header = StructHeader {
            typ,
            length: length as u8,
            handle,
        };
        let result = (header, formatted, strings);
        self.pos = p;
        Some(result)
    }
}

// ── Type 17 Memory Device decoder ──────────────────────────────────

/// Decoded fields of a Type 17 Memory Device structure (§7.18). We
/// surface the SMBIOS 3.x fields modern firmware fills in.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryDevice {
    /// Size in bytes (computed from the 16-bit + 32-bit fields per §7.18.5).
    /// 0 ⇒ slot empty.
    pub size_bytes: u64,
    pub form_factor: u8,
    pub data_width_bits: u16,
    pub total_width_bits: u16,
    /// Raw memory-type byte (one of `MEM_TYPE_*`).
    pub memory_type: u8,
    /// Configured speed in MT/s.
    pub configured_speed_mt_per_s: u16,
    /// Maximum speed in MT/s.
    pub max_speed_mt_per_s: u16,
}

impl MemoryDevice {
    /// Parse the formatted section of a Type 17 structure. The
    /// formatted section's first byte is the *5th* SMBIOS byte (after
    /// type/length/handle), so `formatted[0]` corresponds to
    /// `Physical Memory Array Handle` (§7.18, table 75 row offset 04h).
    pub fn parse(formatted: &[u8]) -> Result<Self, SmbiosError> {
        if formatted.len() < 0x1B {
            return Err(SmbiosError::Short);
        }
        let total_width_bits = u16::from_le_bytes([formatted[0x04], formatted[0x05]]);
        let data_width_bits = u16::from_le_bytes([formatted[0x06], formatted[0x07]]);
        let size_word = u16::from_le_bytes([formatted[0x08], formatted[0x09]]);
        // §7.18.5 size encoding:
        //   0x0000 ⇒ slot empty
        //   0x7FFF ⇒ "see Extended Size" at offset 0x1C..0x20 (32-bit, MB)
        //   else   bit 15: 0=MiB, 1=KiB; low 15 bits = magnitude
        let size_bytes = if size_word == 0 {
            0
        } else if size_word == 0x7FFF {
            if formatted.len() < 0x20 {
                return Err(SmbiosError::Short);
            }
            let extended = u32::from_le_bytes([
                formatted[0x1C],
                formatted[0x1D],
                formatted[0x1E],
                formatted[0x1F],
            ]) as u64;
            extended * 1024 * 1024
        } else {
            let magnitude = (size_word & 0x7FFF) as u64;
            if size_word & 0x8000 != 0 {
                magnitude * 1024
            } else {
                magnitude * 1024 * 1024
            }
        };
        let form_factor = formatted[0x0A];
        let memory_type = formatted[0x0E];
        let configured_speed_mt_per_s =
            u16::from_le_bytes([formatted[0x1B - 4], formatted[0x1B - 3]]);
        let max_speed_mt_per_s = u16::from_le_bytes([formatted[0x11], formatted[0x12]]);
        Ok(Self {
            size_bytes,
            form_factor,
            data_width_bits,
            total_width_bits,
            memory_type,
            configured_speed_mt_per_s,
            max_speed_mt_per_s,
        })
    }
}

// ── Type 1 System Information ──────────────────────────────────────

/// Decoded Type 1 fields. Strings live in the structure's string set
/// — the formatted section carries 1-based indices.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemInfoIndices {
    pub manufacturer_idx: u8,
    pub product_name_idx: u8,
    pub version_idx: u8,
    pub serial_number_idx: u8,
    pub uuid: [u8; 16],
    pub wake_up_type: u8,
    pub sku_number_idx: u8,
    pub family_idx: u8,
}

impl SystemInfoIndices {
    pub fn parse(formatted: &[u8]) -> Result<Self, SmbiosError> {
        if formatted.len() < 23 {
            return Err(SmbiosError::Short);
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&formatted[4..20]);
        Ok(Self {
            manufacturer_idx: formatted[0],
            product_name_idx: formatted[1],
            version_idx: formatted[2],
            serial_number_idx: formatted[3],
            uuid,
            wake_up_type: formatted[20],
            sku_number_idx: formatted[21],
            family_idx: formatted[22],
        })
    }
}

/// Look up an SMBIOS 1-based string index in the structure's string
/// set. Returns `""` for index 0 (the spec's convention for "no
/// string").
pub fn string_at(strings: &[String], idx: u8) -> &str {
    if idx == 0 {
        return "";
    }
    strings
        .get((idx - 1) as usize)
        .map(|s| s.as_str())
        .unwrap_or("")
}
