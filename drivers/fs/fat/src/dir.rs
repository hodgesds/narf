//! Directory Entry structures.
//!
//! Based on Microsoft FAT Gen1 Specification (v1.03), pages 23-33.
//! URL: https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct DirEntry {
    pub name: [u8; 11],
    pub attr: u8,
    pub nt_res: u8,
    pub crt_time_tehnth: u8,
    pub crt_time: u16,
    pub crt_date: u16,
    pub lst_acc_date: u16,
    pub fst_clus_hi: u16,
    pub wrt_time: u16,
    pub wrt_date: u16,
    pub fst_clus_lo: u16,
    pub file_size: u32,
}

pub mod attr {
    pub const READ_ONLY: u8 = 0x01;
    pub const HIDDEN: u8    = 0x02;
    pub const SYSTEM: u8    = 0x04;
    pub const VOLUME_ID: u8 = 0x08;
    pub const DIRECTORY: u8 = 0x10;
    pub const ARCHIVE: u8   = 0x20;
    pub const LONG_NAME: u8 = READ_ONLY | HIDDEN | SYSTEM | VOLUME_ID;
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct LfnEntry {
    pub ord: u8,
    pub name1: [u16; 5],
    pub attr: u8,
    pub type_res: u8,
    pub chksum: u8,
    pub name2: [u16; 6],
    pub fst_clus_lo: u16, // Must be 0
    pub name3: [u16; 2],
}

impl DirEntry {
    pub fn is_free(&self) -> bool {
        self.name[0] == 0xE5
    }

    pub fn is_end(&self) -> bool {
        self.name[0] == 0x00
    }

    pub fn is_directory(&self) -> bool {
        (self.attr & attr::DIRECTORY) != 0
    }

    pub fn is_lfn(&self) -> bool {
        self.attr == attr::LONG_NAME
    }

    pub fn first_cluster(&self) -> u32 {
        ((self.fst_clus_hi as u32) << 16) | (self.fst_clus_lo as u32)
    }
}

pub const LFN_ENTRY_LAST_MASK: u8 = 0x40;

/// MS-DOS Date (bits 0-4: day, 5-8: month, 9-15: year offset from 1980)
/// MS-DOS Time (bits 0-4: 2-second increments, 5-10: minutes, 11-15: hours)
pub fn to_dos_time(_cycles: u64) -> (u16, u16) {
    // NARF monotonic cycles to UTC/Local time is Stage 4 'time' crate scope.
    // For now, return a fixed value or simple placeholder.
    // Base: 1980-01-01 00:00:00 -> (0x0021, 0x0000)
    (0x0021, 0x0000) 
}

pub fn calculate_checksum(name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in name {
        sum = (((sum & 1) << 7) as u16 + (sum >> 1) as u16 + b as u16) as u8;
    }
    sum
}

impl LfnEntry {
    pub fn extract_name(&self, out: &mut [u16]) -> usize {
        let mut count = 0;
        let name1 = self.name1;
        for &c in &name1 {
            if c == 0 || c == 0xFFFF { return count; }
            out[count] = c;
            count += 1;
        }
        let name2 = self.name2;
        for &c in &name2 {
            if c == 0 || c == 0xFFFF { return count; }
            out[count] = c;
            count += 1;
        }
        let name3 = self.name3;
        for &c in &name3 {
            if c == 0 || c == 0xFFFF { return count; }
            out[count] = c;
            count += 1;
        }
        count
    }
}
