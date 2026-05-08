//! Directory Record structures.
//!
//! Based on ECMA-119 (3rd Edition), Section 9.1.
//! URL: https://www.ecma-international.org/wp-content/uploads/ECMA-119_3rd_edition_december_2017.pdf

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct DirectoryRecord {
    pub length: u8,
    pub extended_attribute_record_length: u8,
    pub extent_location: [u32; 2], // Both-endian
    pub data_length: [u32; 2],     // Both-endian
    pub recording_date_time: [u8; 7],
    pub file_flags: u8,
    pub file_unit_size: u8,
    pub interleave_gap_size: u8,
    pub volume_sequence_number: [u16; 2],
    pub file_identifier_length: u8,
    // File Identifier follow (variable length)
}

pub mod flags {
    pub const HIDDEN: u8      = 1 << 0;
    pub const DIRECTORY: u8   = 1 << 1;
    pub const ASSOCIATED: u8  = 1 << 2;
    pub const RECORD: u8      = 1 << 3;
    pub const PROTECTION: u8  = 1 << 4;
    pub const MULTI_EXTENT: u8 = 1 << 7;
}

impl DirectoryRecord {
    pub fn is_directory(&self) -> bool {
        (self.file_flags & flags::DIRECTORY) != 0
    }
}
