//! FAT (File Allocation Table) management.
//!
//! Based on Microsoft FAT Gen1 Specification (v1.03), pages 15-22.
//! URL: https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf

use super::FatVersion;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FatEntry {
    Free,
    Next(u32),
    Reserved,
    Bad,
    EndOfChain,
}

impl FatVersion {
    pub fn is_end_of_chain(&self, entry: u32) -> bool {
        match self {
            FatVersion::Fat12 => entry >= 0x0FF8,
            FatVersion::Fat16 => entry >= 0xFFF8,
            FatVersion::Fat32 => (entry & 0x0FFFFFFF) >= 0x0FFFFFF8,
        }
    }

    pub fn is_bad_cluster(&self, entry: u32) -> bool {
        match self {
            FatVersion::Fat12 => entry == 0x0FF7,
            FatVersion::Fat16 => entry == 0xFFF7,
            FatVersion::Fat32 => (entry & 0x0FFFFFFF) == 0x0FFFFFF7,
        }
    }

    pub fn is_free_cluster(&self, entry: u32) -> bool {
        match self {
            FatVersion::Fat12 => (entry & 0xFFF) == 0,
            FatVersion::Fat16 => (entry & 0xFFFF) == 0,
            FatVersion::Fat32 => (entry & 0x0FFFFFFF) == 0,
        }
    }
}

pub fn parse_entry(version: FatVersion, offset: usize, buffer: &[u8]) -> FatEntry {
    let val = match version {
        FatVersion::Fat12 => {
            let b1 = buffer[offset] as u32;
            let b2 = buffer[offset + 1] as u32;
            if offset % 3 == 0 {
                b1 | ((b2 & 0x0F) << 8)
            } else {
                (b1 >> 4) | (b2 << 4)
            }
        }
        FatVersion::Fat16 => {
            u16::from_le_bytes([buffer[offset], buffer[offset + 1]]) as u32
        }
        FatVersion::Fat32 => {
            u32::from_le_bytes([buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]]) & 0x0FFFFFFF
        }
    };

    if version.is_free_cluster(val) {
        FatEntry::Free
    } else if version.is_bad_cluster(val) {
        FatEntry::Bad
    } else if version.is_end_of_chain(val) {
        FatEntry::EndOfChain
    } else {
        FatEntry::Next(val)
    }
}

/// Helper to write a FAT entry to raw bytes.
pub fn write_entry(version: FatVersion, offset: usize, buffer: &mut [u8], value: u32) {
    match version {
        FatVersion::Fat12 => {
            let val = value & 0x0FFF;
            let b1 = buffer[offset] as u32;
            let b2 = buffer[offset + 1] as u32;
            if offset % 3 == 0 {
                buffer[offset] = (val & 0xFF) as u8;
                buffer[offset + 1] = ((b2 & 0xF0) | ((val >> 8) & 0x0F)) as u8;
            } else {
                buffer[offset] = ((b1 & 0x0F) | ((val << 4) & 0xF0)) as u8;
                buffer[offset + 1] = ((val >> 4) & 0xFF) as u8;
            }
        }
        FatVersion::Fat16 => {
            let bytes = (value as u16).to_le_bytes();
            buffer[offset] = bytes[0];
            buffer[offset + 1] = bytes[1];
        }
        FatVersion::Fat32 => {
            let existing = u32::from_le_bytes([buffer[offset], buffer[offset+1], buffer[offset+2], buffer[offset+3]]);
            let new_val = (existing & 0xF0000000) | (value & 0x0FFFFFFF);
            let bytes = new_val.to_le_bytes();
            buffer[offset..offset+4].copy_from_slice(&bytes);
        }
    }
}
