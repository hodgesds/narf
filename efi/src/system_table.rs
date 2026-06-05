//! `EFI_SYSTEM_TABLE` + `EFI_TABLE_HEADER` decoders — UEFI 2.10 §4.
//!
//! The EFI System Table is the kernel's entry point into firmware
//! data. Bootloaders pass its physical address (often via a ConfigTable
//! handoff or the `boot/` info struct); the kernel decodes the header
//! to find Runtime-Services and ConfigurationTable pointers.

extern crate alloc;
use alloc::vec::Vec;

use crate::variable::Guid;

/// Magic signatures (UEFI 2.10 §4.x) used to identify each table.
pub mod signature {
    pub const SYSTEM_TABLE: u64 = 0x5453_5953_2049_4249; // "IBI SYST"
    pub const BOOT_SERVICES: u64 = 0x5652_4553_544F_4F42; // "BOOT SERV"
    pub const RUNTIME_SERVICES: u64 = 0x5652_4553_4E54_4D52; // "RNTM SERV"
}

/// `EFI_TABLE_HEADER` — 24 bytes, prefixes every UEFI table
/// (System / Boot / Runtime).
///
/// ```text
///   0..8:  Signature  (u64)
///   8..12: Revision   (u32, high u16 = major, low u16 = minor)
///   12..16: HeaderSize (u32)
///   16..20: CRC32     (u32 — over the whole table with this field zero)
///   20..24: Reserved  (u32, must be 0)
///  ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TableHeaderError {
    Short,
    /// Header signature doesn't match the expected value.
    BadSignature,
    /// CRC32 over the table didn't validate.
    BadChecksum,
}

impl TableHeader {
    pub fn decode(buf: &[u8]) -> Result<Self, TableHeaderError> {
        if buf.len() < 24 {
            return Err(TableHeaderError::Short);
        }
        Ok(Self {
            signature: u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            revision: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            header_size: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            crc32: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
        })
    }

    pub fn major_revision(&self) -> u16 {
        (self.revision >> 16) as u16
    }
    pub fn minor_revision(&self) -> u16 {
        (self.revision & 0xFFFF) as u16
    }

    /// Validate the header against an expected signature. Computes
    /// CRC32 over `whole_table` with the CRC field zeroed (per UEFI
    /// 2.10 §4.2.1) and compares.
    pub fn verify(&self, expected_sig: u64, whole_table: &[u8]) -> Result<(), TableHeaderError> {
        if self.signature != expected_sig {
            return Err(TableHeaderError::BadSignature);
        }
        if (self.header_size as usize) > whole_table.len() {
            return Err(TableHeaderError::Short);
        }
        let mut tmp = whole_table[..self.header_size as usize].to_vec();
        // Zero the CRC field at offset 16..20.
        for i in 16..20 {
            tmp[i] = 0;
        }
        let computed = crc32_ieee(&tmp);
        if computed != self.crc32 {
            return Err(TableHeaderError::BadChecksum);
        }
        Ok(())
    }
}

/// `EFI_CONFIGURATION_TABLE` entry — a `(GUID, Pointer)` pair the
/// kernel uses to find ACPI RSDP, SMBIOS, device-tree, etc.
///
/// ```text
///   0..16:  VendorGuid (GUID)
///   16..N:  VendorTable (pointer-sized)
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationTableEntry {
    pub vendor_guid: Guid,
    pub vendor_table: u64,
}

/// Walk a ConfigurationTable array. `entry_size` must be 16
/// (GUID) + pointer-size; pass 24 on 64-bit, 20 on 32-bit.
pub fn decode_configuration_table(
    buf: &[u8],
    n_entries: usize,
    entry_size: usize,
) -> Vec<ConfigurationTableEntry> {
    let mut out = Vec::with_capacity(n_entries);
    for i in 0..n_entries {
        let off = i * entry_size;
        if off + entry_size > buf.len() {
            break;
        }
        let mut g = [0u8; 16];
        g.copy_from_slice(&buf[off..off + 16]);
        let ptr = if entry_size == 24 {
            u64::from_le_bytes([
                buf[off + 16],
                buf[off + 17],
                buf[off + 18],
                buf[off + 19],
                buf[off + 20],
                buf[off + 21],
                buf[off + 22],
                buf[off + 23],
            ])
        } else {
            u32::from_le_bytes([buf[off + 16], buf[off + 17], buf[off + 18], buf[off + 19]]) as u64
        };
        out.push(ConfigurationTableEntry {
            vendor_guid: Guid(g),
            vendor_table: ptr,
        });
    }
    out
}

// ── CRC-32/IEEE (poly 0xEDB88320, init 0xFFFFFFFF, xor-out 0xFFFFFFFF) ──

/// CRC-32 used by UEFI table headers (UEFI 2.10 §4.2.1) — the
/// IEEE 802.3 / ZIP polynomial reflected `0xEDB88320`, init
/// `0xFFFFFFFF`, xor-out `0xFFFFFFFF`.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        let mut c = (crc & 0xFF) ^ b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
        crc = (crc >> 8) ^ c;
    }
    crc ^ 0xFFFF_FFFF
}
