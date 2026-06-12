//! UDF Descriptor structures — Descriptor Tag, Anchor Volume
//! Descriptor Pointer, Volume Descriptor Sequence members,
//! Logical Volume / Partition / File Set Descriptors.
//!
//! Clean-room layout per ECMA-167 (3rd edition, June 1997). No
//! GPL/LGPL UDF source consulted.
//!
//! References:
//! - ECMA-167 §3/7.2 (Descriptor Tag — the 16-byte prefix every
//!   UDF descriptor begins with).
//! - ECMA-167 §3/7.1 (`extent_ad` — `(length, location)` pair).
//! - ECMA-167 §3/7.7 (`lb_addr` — `(LBN, partition_ref)` pair).
//! - ECMA-167 §3/10.1 (Primary Volume Descriptor).
//! - ECMA-167 §3/10.2 (Anchor Volume Descriptor Pointer).
//! - ECMA-167 §3/10.5 (Partition Descriptor).
//! - ECMA-167 §3/10.6 (Logical Volume Descriptor).
//! - ECMA-167 §3/10.9 (Terminating Descriptor).
//! - ECMA-167 §4/14.1 (File Set Descriptor).
//! - OSTA UDF 2.60 §2.2.3 (recommended AVDP locations).

use core::fmt;

// ── Descriptor Tag ──────────────────────────────────────────────────

/// 16-byte Descriptor Tag — ECMA-167 §3/7.2. Every UDF descriptor
/// begins with one of these.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct DescriptorTag {
    /// §3/7.2.1 — descriptor identifier. See [`tag_id`].
    pub tag_identifier: u16,
    /// §3/7.2.2 — descriptor version. 2 (UDF 1.50–) or 3 (UDF 2.00+).
    pub descriptor_version: u16,
    /// §3/7.2.3 — sum of bytes 0..16 of the tag, EXCLUDING this byte
    /// (offset 4), modulo 256.
    pub tag_checksum: u8,
    /// §3/7.2.4 — must be zero.
    pub _reserved: u8,
    /// §3/7.2.5 — tag serial number.
    pub tag_serial_number: u16,
    /// §3/7.2.6 — CRC-CCITT over the descriptor body
    /// (`descriptor_crc_length` bytes starting just after the tag).
    pub descriptor_crc: u16,
    /// §3/7.2.7 — number of body bytes covered by `descriptor_crc`.
    pub descriptor_crc_length: u16,
    /// §3/7.2.8 — sector number containing this descriptor (LSN).
    pub tag_location: u32,
}

const _ASSERT_DESCRIPTOR_TAG_SIZE: () = assert!(core::mem::size_of::<DescriptorTag>() == 16);

impl fmt::Debug for DescriptorTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id = self.tag_identifier;
        let ver = self.descriptor_version;
        let cs = self.tag_checksum;
        let crc = self.descriptor_crc;
        let crc_len = self.descriptor_crc_length;
        let loc = self.tag_location;
        f.debug_struct("DescriptorTag")
            .field("tag_identifier", &id)
            .field("descriptor_version", &ver)
            .field("tag_checksum", &cs)
            .field("descriptor_crc", &crc)
            .field("descriptor_crc_length", &crc_len)
            .field("tag_location", &loc)
            .finish()
    }
}

/// Compute the Descriptor Tag checksum (ECMA-167 §3/7.2.3) — sum of
/// the first 16 bytes of the tag, EXCLUDING byte 4 (the checksum
/// byte itself), modulo 256.
#[inline]
pub fn tag_checksum(tag_bytes: &[u8; 16]) -> u8 {
    let mut s: u32 = 0;
    for (i, b) in tag_bytes.iter().enumerate() {
        if i == 4 {
            continue;
        }
        s = s.wrapping_add(*b as u32);
    }
    (s & 0xFF) as u8
}

/// CRC-CCITT polynomial 0x1021 (ECMA-167 §3/7.2.6 references the
/// polynomial used here). Implemented bytewise; the descriptor
/// bodies we cover with this driver are small (a few hundred bytes
/// at most), so a table is unnecessary.
pub fn crc_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// TagIdentifier values used by this driver (ECMA-167 §3/7.2.1).
pub mod tag_id {
    /// §3/10.1 — Primary Volume Descriptor.
    pub const PRIMARY_VOLUME_DESCRIPTOR: u16 = 1;
    /// §3/10.2 — Anchor Volume Descriptor Pointer.
    pub const ANCHOR_VOLUME_DESCRIPTOR_POINTER: u16 = 2;
    /// §3/10.3 — Volume Descriptor Pointer (continuation).
    pub const VOLUME_DESCRIPTOR_POINTER: u16 = 3;
    /// §3/10.4 — Implementation Use Volume Descriptor.
    pub const IMPLEMENTATION_USE_VD: u16 = 4;
    /// §3/10.5 — Partition Descriptor.
    pub const PARTITION_DESCRIPTOR: u16 = 5;
    /// §3/10.6 — Logical Volume Descriptor.
    pub const LOGICAL_VOLUME_DESCRIPTOR: u16 = 6;
    /// §3/10.8 — Unallocated Space Descriptor.
    pub const UNALLOCATED_SPACE_DESCRIPTOR: u16 = 7;
    /// §3/10.9 — Terminating Descriptor.
    pub const TERMINATING_DESCRIPTOR: u16 = 8;
    /// §3/10.10 — Logical Volume Integrity Descriptor.
    pub const LOGICAL_VOLUME_INTEGRITY_DESCRIPTOR: u16 = 9;
    /// §4/14.1 — File Set Descriptor.
    pub const FILE_SET_DESCRIPTOR: u16 = 256;
    /// §4/14.4 — File Identifier Descriptor.
    pub const FILE_IDENTIFIER_DESCRIPTOR: u16 = 257;
    /// §4/14.6 — Allocation Extent Descriptor.
    pub const ALLOCATION_EXTENT_DESCRIPTOR: u16 = 258;
    /// §4/14.6 — Indirect Entry.
    pub const INDIRECT_ENTRY: u16 = 259;
    /// §4/14.7 — Terminal Entry.
    pub const TERMINAL_ENTRY: u16 = 260;
    /// §4/14.9 — File Entry.
    pub const FILE_ENTRY: u16 = 261;
    /// §4/14.17 — Extended File Entry.
    pub const EXTENDED_FILE_ENTRY: u16 = 266;
}

/// Decode a Descriptor Tag from a byte buffer at `offset`.
///
/// # Panics
/// Debug-asserts that `offset + 16 <= buf.len()`.
#[inline]
pub fn read_descriptor_tag(buf: &[u8], offset: usize) -> DescriptorTag {
    debug_assert!(offset + core::mem::size_of::<DescriptorTag>() <= buf.len());
    // SAFETY: `DescriptorTag` is `#[repr(C, packed)]` and 16 bytes,
    // matching ECMA-167 §3/7.2 exactly. The caller has bounded
    // `offset` and the buffer is a freshly-read sector copy we own.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe { core::ptr::read_unaligned(buf.as_ptr().add(offset) as *const DescriptorTag) }
}

// ── extent_ad / lb_addr ─────────────────────────────────────────────

/// `extent_ad` — ECMA-167 §3/7.1. Used in the AVDP and several other
/// descriptors that reference a contiguous run of sectors.
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct ExtentAd {
    /// Length of the extent in BYTES.
    pub extent_length: u32,
    /// Logical sector number of the first sector of the extent.
    pub extent_location: u32,
}

const _ASSERT_EXTENT_AD_SIZE: () = assert!(core::mem::size_of::<ExtentAd>() == 8);

impl fmt::Debug for ExtentAd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.extent_length;
        let loc = self.extent_location;
        f.debug_struct("ExtentAd")
            .field("extent_length", &len)
            .field("extent_location", &loc)
            .finish()
    }
}

/// `lb_addr` — ECMA-167 §3/7.7. `(LBN, partition_ref)` pair used by
/// every File-Entry-pointing reference (long_ad, ParentICBLocation,
/// FSD root_directory_icb, …).
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct LbAddr {
    /// Logical block number within the partition referenced by
    /// `partition_reference_number`.
    pub logical_block_number: u32,
    /// Index into the LVD's partition map array.
    pub partition_reference_number: u16,
}

const _ASSERT_LB_ADDR_SIZE: () = assert!(core::mem::size_of::<LbAddr>() == 6);

impl fmt::Debug for LbAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lbn = self.logical_block_number;
        let part = self.partition_reference_number;
        f.debug_struct("LbAddr")
            .field("logical_block_number", &lbn)
            .field("partition_reference_number", &part)
            .finish()
    }
}

// ── Anchor Volume Descriptor Pointer ────────────────────────────────

/// Anchor Volume Descriptor Pointer (ECMA-167 §3/10.2). Locates the
/// Main + Reserve VDS extents. Sector 256 is the canonical position
/// (OSTA UDF 2.60 §2.2.3).
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct AnchorVolumeDescriptorPointer {
    pub tag: DescriptorTag,
    /// §3/10.2.2 — Main VDS extent.
    pub main_vds: ExtentAd,
    /// §3/10.2.3 — Reserve (mirror) VDS extent.
    pub reserve_vds: ExtentAd,
    /// §3/10.2.4 — reserved (480 bytes of zeros to round the AVDP
    /// to one logical sector).
    pub _reserved: [u8; 480],
}

const _ASSERT_AVDP_FITS_SECTOR: () =
    assert!(core::mem::size_of::<AnchorVolumeDescriptorPointer>() == 512);

impl fmt::Debug for AnchorVolumeDescriptorPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnchorVolumeDescriptorPointer")
            .field("tag", &self.tag)
            .field("main_vds", &self.main_vds)
            .field("reserve_vds", &self.reserve_vds)
            .finish()
    }
}

/// Decode an AVDP from a sector buffer (offset 0).
#[inline]
pub fn read_anchor(buf: &[u8]) -> AnchorVolumeDescriptorPointer {
    debug_assert!(buf.len() >= core::mem::size_of::<AnchorVolumeDescriptorPointer>());
    // SAFETY: `AnchorVolumeDescriptorPointer` is `#[repr(C, packed)]`
    // with the 512-byte layout matching ECMA-167 §3/10.2.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const AnchorVolumeDescriptorPointer) }
}

// ── Partition Descriptor ────────────────────────────────────────────

/// Partition Descriptor (ECMA-167 §3/10.5). Names the on-disc start
/// and length of one partition. The driver only uses the
/// `partition_starting_location` and `partition_length` fields; the
/// rest are decoded into a single byte slab so we can keep the layout
/// honest without naming each field.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct PartitionDescriptor {
    pub tag: DescriptorTag,
    /// §3/10.5.2 — volume descriptor sequence number.
    pub volume_descriptor_sequence_number: u32,
    /// §3/10.5.3 — partition flags.
    pub partition_flags: u16,
    /// §3/10.5.4 — partition number.
    pub partition_number: u16,
    /// §3/10.5.5 — partition contents (`+NSR02` etc.).
    pub partition_contents: [u8; 32],
    /// §3/10.5.6 — partition contents use (128 bytes).
    pub partition_contents_use: [u8; 128],
    /// §3/10.5.7 — access type.
    pub access_type: u32,
    /// §3/10.5.8 — partition starting location (LSN).
    pub partition_starting_location: u32,
    /// §3/10.5.9 — partition length (sectors).
    pub partition_length: u32,
    /// §3/10.5.10 — implementation identifier (32 bytes).
    pub implementation_identifier: [u8; 32],
    /// §3/10.5.11 — implementation use (128 bytes).
    pub implementation_use: [u8; 128],
    /// §3/10.5.12 — reserved (156 bytes — pads to 512).
    pub _reserved: [u8; 156],
}

const _ASSERT_PARTITION_FITS_SECTOR_HALF: () =
    assert!(core::mem::size_of::<PartitionDescriptor>() == 512);

impl fmt::Debug for PartitionDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let starting = self.partition_starting_location;
        let length = self.partition_length;
        let number = self.partition_number;
        f.debug_struct("PartitionDescriptor")
            .field("partition_number", &number)
            .field("partition_starting_location", &starting)
            .field("partition_length", &length)
            .finish_non_exhaustive()
    }
}

/// Decode a Partition Descriptor from a sector buffer at `offset`.
#[inline]
pub fn read_partition(buf: &[u8], offset: usize) -> PartitionDescriptor {
    debug_assert!(offset + core::mem::size_of::<PartitionDescriptor>() <= buf.len());
    // SAFETY: `PartitionDescriptor` is `#[repr(C, packed)]`,
    // 512 bytes, matching ECMA-167 §3/10.5.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe { core::ptr::read_unaligned(buf.as_ptr().add(offset) as *const PartitionDescriptor) }
}

// ── Logical Volume Descriptor ───────────────────────────────────────

/// Fixed prefix of the Logical Volume Descriptor (ECMA-167 §3/10.6).
///
/// The full LVD is variable-length: a 440-byte fixed header followed
/// by `map_table_length` bytes of partition-map entries (each map
/// entry has a 2-byte type + 2-byte length header). We expose the
/// fixed prefix here and decode the partition maps in `volume.rs`.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct LogicalVolumeDescriptorHeader {
    pub tag: DescriptorTag,
    /// §3/10.6.2 — VDS sequence number.
    pub volume_descriptor_sequence_number: u32,
    /// §3/10.6.3 — descriptor character set.
    pub descriptor_character_set: [u8; 64],
    /// §3/10.6.4 — logical volume identifier (CS0).
    pub logical_volume_identifier: [u8; 128],
    /// §3/10.6.5 — logical block size (bytes).
    pub logical_block_size: u32,
    /// §3/10.6.6 — domain identifier (32 bytes; OSTA UDF spec ID).
    pub domain_identifier: [u8; 32],
    /// §3/10.6.7 — logical-volume contents use. For UDF this is a
    /// `long_ad` (16 bytes) pointing at the File Set Descriptor.
    pub logical_volume_contents_use: [u8; 16],
    /// §3/10.6.8 — map table length (bytes occupied by partition
    /// maps after this header).
    pub map_table_length: u32,
    /// §3/10.6.9 — number of partition maps.
    pub number_of_partition_maps: u32,
    /// §3/10.6.10 — implementation identifier.
    pub implementation_identifier: [u8; 32],
    /// §3/10.6.11 — implementation use.
    pub implementation_use: [u8; 128],
    /// §3/10.6.12 — integrity sequence extent.
    pub integrity_sequence_extent: ExtentAd,
}

const _ASSERT_LVD_HEADER_SIZE: () =
    assert!(core::mem::size_of::<LogicalVolumeDescriptorHeader>() == 440);

impl fmt::Debug for LogicalVolumeDescriptorHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lbs = self.logical_block_size;
        let n_maps = self.number_of_partition_maps;
        let map_len = self.map_table_length;
        f.debug_struct("LogicalVolumeDescriptorHeader")
            .field("logical_block_size", &lbs)
            .field("number_of_partition_maps", &n_maps)
            .field("map_table_length", &map_len)
            .finish_non_exhaustive()
    }
}

/// Decode the LVD fixed prefix from a sector buffer at `offset`.
#[inline]
pub fn read_lvd_header(buf: &[u8], offset: usize) -> LogicalVolumeDescriptorHeader {
    debug_assert!(offset + core::mem::size_of::<LogicalVolumeDescriptorHeader>() <= buf.len());
    // SAFETY: the type is `#[repr(C, packed)]` with the 440-byte
    // layout from ECMA-167 §3/10.6.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        core::ptr::read_unaligned(buf.as_ptr().add(offset) as *const LogicalVolumeDescriptorHeader)
    }
}

// ── File Set Descriptor ─────────────────────────────────────────────

/// File Set Descriptor (ECMA-167 §4/14.1). Lives in the partition's
/// data area; the LVD's `logical_volume_contents_use` long_ad
/// points at it. Carries the root directory's ICB.
///
/// The fixed length is 512 bytes; we expose only the bytes we need.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct FileSetDescriptor {
    pub tag: DescriptorTag,
    /// §4/14.1.2 — recording date and time (12 bytes).
    pub recording_date_time: [u8; 12],
    /// §4/14.1.3 — interchange level.
    pub interchange_level: u16,
    /// §4/14.1.4 — maximum interchange level.
    pub max_interchange_level: u16,
    /// §4/14.1.5 — character set list.
    pub character_set_list: u32,
    /// §4/14.1.6 — maximum character set list.
    pub max_character_set_list: u32,
    /// §4/14.1.7 — file set number.
    pub file_set_number: u32,
    /// §4/14.1.8 — file set descriptor number.
    pub file_set_descriptor_number: u32,
    /// §4/14.1.9 — logical volume identifier character set.
    pub logical_volume_identifier_character_set: [u8; 64],
    /// §4/14.1.10 — logical volume identifier.
    pub logical_volume_identifier: [u8; 128],
    /// §4/14.1.11 — file set character set.
    pub file_set_character_set: [u8; 64],
    /// §4/14.1.12 — file set identifier.
    pub file_set_identifier: [u8; 32],
    /// §4/14.1.13 — copyright file identifier.
    pub copyright_file_identifier: [u8; 32],
    /// §4/14.1.14 — abstract file identifier.
    pub abstract_file_identifier: [u8; 32],
    /// §4/14.1.15 — root directory ICB (long_ad — 16 bytes).
    pub root_directory_icb: [u8; 16],
    /// §4/14.1.16 — domain identifier (32 bytes).
    pub domain_identifier: [u8; 32],
    /// §4/14.1.17 — next extent (long_ad — 16 bytes).
    pub next_extent: [u8; 16],
    /// §4/14.1.18 — system stream directory ICB (long_ad).
    pub system_stream_directory_icb: [u8; 16],
    /// §4/14.1.19 — reserved (32 bytes — pads to 512).
    pub _reserved: [u8; 32],
}

const _ASSERT_FSD_SIZE: () = assert!(core::mem::size_of::<FileSetDescriptor>() == 512);

impl fmt::Debug for FileSetDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSetDescriptor")
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

/// Decode a File Set Descriptor from a sector buffer at `offset`.
#[inline]
pub fn read_file_set(buf: &[u8], offset: usize) -> FileSetDescriptor {
    debug_assert!(offset + core::mem::size_of::<FileSetDescriptor>() <= buf.len());
    // SAFETY: `FileSetDescriptor` is `#[repr(C, packed)]` with the
    // 512-byte ECMA-167 §4/14.1 layout.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe { core::ptr::read_unaligned(buf.as_ptr().add(offset) as *const FileSetDescriptor) }
}
