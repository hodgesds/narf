//! ISO 9660 Volume Descriptor structures.
//!
//! Clean-room layout per ECMA-119 (3rd edition, December 2017),
//! §8 ("Descriptor for Volumes and Volume Sets") and §9.4 ("Path
//! Table" reference layout). No GPL/LGPL ISO 9660 source consulted.
//!
//! References:
//! - ECMA-119 §8.1 (general volume-descriptor header).
//! - ECMA-119 §8.4 (Primary Volume Descriptor — PVD).
//! - ECMA-119 §8.3 (Volume Descriptor Set Terminator).
//! - OSDev Wiki, "ISO 9660 — Volume Descriptors".
//!   <https://wiki.osdev.org/ISO_9660>

use core::fmt;

/// First-16-byte fixed prefix of every Volume Descriptor (ECMA-119
/// §8.1.1–8.1.3). Recognising this header is enough to walk the VD
/// sequence; only the type byte tells us whether the rest of the
/// 2048-byte sector should be decoded as a PVD, an SVD, etc.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct VolumeDescriptorHeader {
    /// §8.1.1 — descriptor type. See [`vd_type`].
    pub vd_type: u8,
    /// §8.1.2 — must be the ASCII bytes "CD001".
    pub standard_identifier: [u8; 5],
    /// §8.1.3 — version. Always 1 for ECMA-119.
    pub version: u8,
}

impl fmt::Debug for VolumeDescriptorHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.vd_type;
        let v = self.version;
        f.debug_struct("VolumeDescriptorHeader")
            .field("vd_type", &t)
            .field("version", &v)
            .finish()
    }
}

/// Standard-identifier bytes that every valid ISO 9660 VD must
/// start with (ECMA-119 §8.1.2).
pub const STANDARD_IDENTIFIER: [u8; 5] = *b"CD001";

/// Volume-descriptor type byte values (ECMA-119 §8.1.1).
pub mod vd_type {
    /// §8.2 — Boot Record. Skipped; bootable-media support is the
    /// platform's job (El Torito) and lives outside this driver.
    pub const BOOT_RECORD: u8 = 0;
    /// §8.4 — Primary Volume Descriptor. Required, exactly one.
    pub const PRIMARY: u8 = 1;
    /// §8.5 — Supplementary Volume Descriptor (Joliet rides on
    /// this). Detected but not parsed in the first wave.
    pub const SUPPLEMENTARY: u8 = 2;
    /// §8.6 — Volume Partition Descriptor.
    pub const PARTITION: u8 = 3;
    /// §8.3 — Volume Descriptor Set Terminator. Stops the walk.
    pub const TERMINATOR: u8 = 255;
}

/// Primary Volume Descriptor (ECMA-119 §8.4). Layout matches the
/// on-disc bytes verbatim — this struct is only ever populated by
/// `core::ptr::read_unaligned` from a freshly-read sector buffer.
///
/// Both-endian fields (e.g. §8.4.8 "Volume Space Size") are stored
/// as `[u32; 2]` / `[u16; 2]`: index 0 is little-endian, index 1 is
/// big-endian. Both halves carry the same value; the standard
/// requires both to match. We always read the LE half.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct PrimaryVolumeDescriptor {
    pub header: VolumeDescriptorHeader,
    /// §8.4.4 — must be zero.
    pub _unused1: u8,
    /// §8.4.5 — system identifier (a-characters, space-padded).
    pub system_identifier: [u8; 32],
    /// §8.4.6 — volume identifier (d-characters, space-padded).
    pub volume_identifier: [u8; 32],
    /// §8.4.7 — must be zero.
    pub _unused2: [u8; 8],
    /// §8.4.8 — volume space size (both-endian, sectors).
    pub volume_space_size: [u32; 2],
    /// §8.4.9 — must be zero.
    pub _unused3: [u8; 32],
    /// §8.4.10 — volume set size.
    pub volume_set_size: [u16; 2],
    /// §8.4.11 — volume sequence number.
    pub volume_sequence_number: [u16; 2],
    /// §8.4.12 — logical block size (both-endian, bytes).
    pub logical_block_size: [u16; 2],
    /// §8.4.13 — path table size (both-endian, bytes).
    pub path_table_size: [u32; 2],
    /// §8.4.14 — type-L path table location (LE-only).
    pub type_l_path_table_location: u32,
    /// §8.4.15 — optional type-L path table location.
    pub optional_type_l_path_table_location: u32,
    /// §8.4.16 — type-M path table location (BE-only).
    pub type_m_path_table_location: u32,
    /// §8.4.17 — optional type-M path table location.
    pub optional_type_m_path_table_location: u32,
    /// §8.4.18 — root directory record. Embedded 34-byte
    /// `DirectoryRecord` (see [`super::dir`]).
    pub root_directory_record: [u8; 34],
    /// §8.4.19 — volume set identifier.
    pub volume_set_identifier: [u8; 128],
    pub publisher_identifier: [u8; 128],
    pub data_preparer_identifier: [u8; 128],
    pub application_identifier: [u8; 128],
    pub copyright_file_identifier: [u8; 37],
    pub abstract_file_identifier: [u8; 37],
    pub bibliographic_file_identifier: [u8; 37],
    /// §8.4.26 — date/time fields (17-byte ASCII format).
    pub volume_creation_date: [u8; 17],
    pub volume_modification_date: [u8; 17],
    pub volume_expiration_date: [u8; 17],
    pub volume_effective_date: [u8; 17],
    /// §8.4.31 — file structure version. Always 1.
    pub file_structure_version: u8,
    /// §8.4.32 — must be zero.
    pub _unused4: u8,
    /// §8.4.33 — application use (passes through).
    pub application_use: [u8; 512],
    /// §8.4.34 — must be zero (653 bytes of trailing padding so the
    /// PVD spans exactly one logical sector).
    pub _unused5: [u8; 653],
}

impl PrimaryVolumeDescriptor {
    /// Logical block size from the LE half (§8.4.12). ECMA-119
    /// formally permits other sizes, but every disc in practice
    /// reports 2048.
    pub fn logical_block_size_le(&self) -> u16 {
        let arr = self.logical_block_size;
        arr[0]
    }

    /// Volume space size in logical blocks (§8.4.8, LE half).
    pub fn volume_space_size_le(&self) -> u32 {
        let arr = self.volume_space_size;
        arr[0]
    }
}

impl fmt::Debug for PrimaryVolumeDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lbs = self.logical_block_size_le();
        let space = self.volume_space_size_le();
        f.debug_struct("PrimaryVolumeDescriptor")
            .field("logical_block_size", &lbs)
            .field("volume_space_size", &space)
            .finish_non_exhaustive()
    }
}

const _ASSERT_PVD_FITS_SECTOR: () =
    assert!(core::mem::size_of::<PrimaryVolumeDescriptor>() == 2048);
