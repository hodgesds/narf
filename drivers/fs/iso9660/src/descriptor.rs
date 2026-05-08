//! Volume Descriptor structures.
//!
//! Based on ECMA-119 (3rd Edition), Section 8.
//! URL: https://www.ecma-international.org/wp-content/uploads/ECMA-119_3rd_edition_december_2017.pdf

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct VolumeDescriptorHeader {
    pub vd_type: u8,
    pub standard_identifier: [u8; 5], // "CD001"
    pub version: u8,
}

pub mod vd_type {
    pub const BOOT_RECORD: u8 = 0;
    pub const PRIMARY: u8     = 1;
    pub const SUPPLEMENTARY: u8 = 2;
    pub const PARTITION: u8   = 3;
    pub const TERMINATOR: u8  = 255;
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct PrimaryVolumeDescriptor {
    pub header: VolumeDescriptorHeader,
    pub reserved1: u8,
    pub system_identifier: [u8; 32],
    pub volume_identifier: [u8; 32],
    pub reserved2: [u8; 8],
    pub volume_space_size: [u32; 2], // Both-endian
    pub reserved3: [u8; 32],
    pub volume_set_size: [u16; 2],
    pub volume_sequence_number: [u16; 2],
    pub logical_block_size: [u16; 2],
    pub path_table_size: [u32; 2],
    pub type_l_path_table_location: u32,
    pub optional_type_l_path_table_location: u32,
    pub type_m_path_table_location: u32,
    pub optional_type_m_path_table_location: u32,
    pub root_directory_record: [u8; 34], // Directory Record for root
    pub volume_set_identifier: [u8; 128],
    pub publisher_identifier: [u8; 128],
    pub data_preparer_identifier: [u8; 128],
    pub application_identifier: [u8; 128],
    pub copyright_file_identifier: [u8; 37],
    pub abstract_file_identifier: [u8; 37],
    pub bibliographic_file_identifier: [u8; 37],
    pub volume_creation_date: [u8; 17],
    pub volume_modification_date: [u8; 17],
    pub volume_expiration_date: [u8; 17],
    pub volume_effective_date: [u8; 17],
    pub file_structure_version: u8,
    pub reserved4: u8,
    pub application_use: [u8; 512],
    pub reserved5: [u8; 653],
}
