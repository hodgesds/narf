//! UDF Information Control Block (ICB) — File Entry / Extended File
//! Entry decode and the icb_tag flags / file-type byte recognition
//! the directory walk depends on.
//!
//! Clean-room layout per ECMA-167 (3rd edition, June 1997). No
//! GPL/LGPL UDF source consulted.
//!
//! References:
//! - ECMA-167 §4/14.6 (icb_tag — the 20-byte ICB tag block that
//!   sits right after the Descriptor Tag in every File / Extended
//!   File Entry).
//! - ECMA-167 §4/14.6.6 (FileType byte — values used here:
//!   4 = directory, 5 = regular file, 10 = symlink).
//! - ECMA-167 §4/14.9 (File Entry — the regular ICB form, 176 bytes
//!   of fixed header followed by L_EA + L_AD bytes of extended
//!   attributes + allocation descriptors).
//! - ECMA-167 §4/14.17 (Extended File Entry — like File Entry but
//!   with an extra 40 bytes of fields between the existing fields
//!   and the AD area; the offsets we need shift accordingly).
//! - ECMA-167 §4/14.14 (Allocation Descriptors — short_ad / long_ad
//!   / ext_ad).

use core::fmt;

use super::descriptor::LbAddr;

// ── icb_tag ─────────────────────────────────────────────────────────

/// `icb_tag` — ECMA-167 §4/14.6. The 20-byte block that follows the
/// Descriptor Tag in every (Extended) File Entry.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct IcbTag {
    /// §4/14.6.1 — count of direct entries recorded prior to this
    /// one.
    pub prior_recorded_number_of_direct_entries: u32,
    /// §4/14.6.2 — strategy type (4 = "default"; 4096 = OSTA UDF
    /// "VAT").
    pub strategy_type: u16,
    /// §4/14.6.3 — strategy parameter (2 bytes — strategy-specific).
    pub strategy_parameter: u16,
    /// §4/14.6.4 — number of entries in this ICB hierarchy.
    pub number_of_entries: u16,
    /// §4/14.6.5 — reserved (one byte of zero).
    pub _reserved: u8,
    /// §4/14.6.6 — file type. See [`file_type`].
    pub file_type: u8,
    /// §4/14.6.7 — parent ICB location (`lb_addr` — 6 bytes).
    pub parent_icb_location: LbAddr,
    /// §4/14.6.8 — flags. See [`flags`].
    pub flags: u16,
}

const _ASSERT_ICB_TAG_SIZE: () = assert!(core::mem::size_of::<IcbTag>() == 20);

impl fmt::Debug for IcbTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let st = self.strategy_type;
        let ne = self.number_of_entries;
        let ft = self.file_type;
        let fl = self.flags;
        f.debug_struct("IcbTag")
            .field("strategy_type", &st)
            .field("number_of_entries", &ne)
            .field("file_type", &ft)
            .field("flags", &fl)
            .finish()
    }
}

/// FileType byte values (ECMA-167 §4/14.6.6) used by this driver.
pub mod file_type {
    /// §4/14.6.6 — Unallocated (the entry is not yet a file).
    pub const UNALLOCATED: u8 = 0;
    /// §4/14.6.6 — Directory.
    pub const DIRECTORY: u8 = 4;
    /// §4/14.6.6 — Regular file (sequence of bytes).
    pub const REGULAR_FILE: u8 = 5;
    /// §4/14.6.6 — Block special device file.
    pub const BLOCK_SPECIAL: u8 = 6;
    /// §4/14.6.6 — Character special device file.
    pub const CHAR_SPECIAL: u8 = 7;
    /// §4/14.6.6 — Extended attributes.
    pub const EXTENDED_ATTRIBUTES: u8 = 8;
    /// §4/14.6.6 — Symbolic link.
    pub const SYMBOLIC_LINK: u8 = 10;
    /// §4/14.6.6 — Stream directory.
    pub const STREAM_DIRECTORY: u8 = 13;
}

/// `icb_tag.flags` bits (ECMA-167 §4/14.6.8). Only the bits we
/// actually use during file-data extent decode are named; the
/// remainder are bookkeeping fields the read-only path can ignore.
pub mod flags {
    /// §4/14.6.8 — bits 0-2 select the allocation-descriptor format:
    ///   0 = short_ad   (8 bytes per descriptor)
    ///   1 = long_ad    (16 bytes per descriptor — the default this
    ///                   driver uses).
    ///   2 = ext_ad     (20 bytes per descriptor)
    ///   3 = data is embedded directly in the AD area (no extents).
    pub const ALLOC_DESC_TYPE_MASK: u16 = 0b111;
    pub const ALLOC_TYPE_SHORT: u16 = 0;
    pub const ALLOC_TYPE_LONG: u16 = 1;
    pub const ALLOC_TYPE_EXT: u16 = 2;
    pub const ALLOC_TYPE_EMBEDDED: u16 = 3;
}

impl IcbTag {
    /// True iff this ICB describes a directory.
    #[inline]
    pub fn is_directory(&self) -> bool {
        self.file_type == file_type::DIRECTORY
    }

    /// Allocation-descriptor format (low 3 bits of `flags`).
    #[inline]
    pub fn alloc_type(&self) -> u16 {
        let f = self.flags;
        f & flags::ALLOC_DESC_TYPE_MASK
    }
}

/// Decode an icb_tag from a buffer at `offset`.
#[inline]
pub fn read_icb_tag(buf: &[u8], offset: usize) -> IcbTag {
    debug_assert!(offset + core::mem::size_of::<IcbTag>() <= buf.len());
    // SAFETY: `IcbTag` is `#[repr(C, packed)]`, 20 bytes, ECMA-167
    // §4/14.6.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe { core::ptr::read_unaligned(buf.as_ptr().add(offset) as *const IcbTag) }
}

// ── File Entry / Extended File Entry — the shared offsets we need ──

/// File-Entry-shape offsets used by this driver.
///
/// We don't decode the full 176-byte File Entry (or 216-byte
/// Extended File Entry) into a struct — most of the fields are
/// metadata the read-only walk doesn't care about. Instead we name
/// the offsets we look up: `information_length`, the L_EA + L_AD
/// pair, and the AD area starting position.
///
/// Layouts (ECMA-167 §4/14.9 + §4/14.17):
///
/// ```text
///   File Entry (tag 261):
///      0  16   Descriptor Tag
///     16  20   icb_tag
///     36   4   Uid
///     40   4   Gid
///     44   4   Permissions
///     48   2   FileLinkCount
///     50   1   RecordFormat
///     51   1   RecordDisplayAttributes
///     52   4   RecordLength
///     56   8   InformationLength
///     64   8   LogicalBlocksRecorded
///     72  12   AccessTime
///     84  12   ModificationTime
///     96  12   AttributeTime
///    108   4   Checkpoint
///    112  16   ExtendedAttributeICB (long_ad)
///    128  32   ImplementationIdentifier
///    160   8   UniqueId
///    168   4   LengthOfExtendedAttributes (L_EA)
///    172   4   LengthOfAllocationDescriptors (L_AD)
///    176     Extended Attributes (L_EA bytes)
///    176+L_EA Allocation Descriptors (L_AD bytes)
///
///   Extended File Entry (tag 266) — adds CreationTime (12 B),
///   ObjectSize (8 B), StreamDirectoryICB (16 B), reserved (4 B)
///   between the original ModificationTime block (84..96) and the
///   later fields, shifting every later field by +40 bytes.
/// ```
pub mod fe_offset {
    pub const TAG_END: usize = 16;
    /// Common to both shapes — icb_tag spans 16..36.
    pub const ICB_TAG_END: usize = 36;

    /// Plain File Entry offsets (ECMA-167 §4/14.9).
    pub mod file_entry {
        pub const INFORMATION_LENGTH: usize = 56;
        pub const L_EA: usize = 168;
        pub const L_AD: usize = 172;
        pub const FIXED_HEADER_LEN: usize = 176;
    }

    /// Extended File Entry offsets (ECMA-167 §4/14.17). The added
    /// 40 bytes split into a 12-byte CreationTime, an 8-byte
    /// ObjectSize, a 16-byte StreamDirectoryICB, and 4 bytes of
    /// reserved/UniqueID-shift, but the only offsets the driver
    /// reads are these three + InformationLength which stays put.
    pub mod extended_file_entry {
        // InformationLength stays at the same offset (56) per
        // §4/14.17.6.
        pub const INFORMATION_LENGTH: usize = 56;
        pub const L_EA: usize = 208;
        pub const L_AD: usize = 212;
        pub const FIXED_HEADER_LEN: usize = 216;
    }
}

/// Read the File Entry / Extended File Entry's `InformationLength`
/// field (ECMA-167 §4/14.9.10 / §4/14.17.6) — the file body's byte
/// length. Same offset (56) in both shapes.
#[inline]
pub fn information_length(entry: &[u8]) -> u64 {
    debug_assert!(entry.len() >= fe_offset::file_entry::INFORMATION_LENGTH + 8);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(
        &entry[fe_offset::file_entry::INFORMATION_LENGTH
            ..fe_offset::file_entry::INFORMATION_LENGTH + 8],
    );
    u64::from_le_bytes(bytes)
}

/// Decoded layout pointers for the extended-attribute / allocation-
/// descriptor area of a (Extended) File Entry. Returned by
/// [`decode_entry_layout`].
#[derive(Copy, Clone, Debug, Default)]
pub struct EntryLayout {
    /// Tag identifier — 261 (File Entry) or 266 (Extended File
    /// Entry).
    pub tag_identifier: u16,
    /// File type byte from the icb_tag (e.g. 4 = dir, 5 = file).
    pub file_type: u8,
    /// Allocation descriptor format (0 = short_ad, 1 = long_ad,
    /// 2 = ext_ad, 3 = embedded).
    pub alloc_type: u16,
    /// File body length in bytes.
    pub information_length: u64,
    /// Byte offset within the entry where the AD area starts
    /// (= fixed-header length + L_EA).
    pub ad_area_offset: usize,
    /// AD area length in bytes (L_AD).
    pub ad_area_length: usize,
}

/// Walk a freshly-read (Extended) File Entry buffer and return the
/// decoded layout pointers + the body length. The buffer must
/// include the descriptor tag at offset 0; the caller knows the
/// tag's identifier from a prior `read_descriptor_tag` call.
pub fn decode_entry_layout(entry: &[u8]) -> Option<EntryLayout> {
    if entry.len() < fe_offset::file_entry::FIXED_HEADER_LEN {
        return None;
    }
    let tag = super::descriptor::read_descriptor_tag(entry, 0);
    let id = tag.tag_identifier;

    let icb_tag = read_icb_tag(entry, fe_offset::TAG_END);
    let info_len = information_length(entry);

    let (l_ea_off, l_ad_off, fixed_len) = match id {
        super::descriptor::tag_id::FILE_ENTRY => (
            fe_offset::file_entry::L_EA,
            fe_offset::file_entry::L_AD,
            fe_offset::file_entry::FIXED_HEADER_LEN,
        ),
        super::descriptor::tag_id::EXTENDED_FILE_ENTRY => {
            if entry.len() < fe_offset::extended_file_entry::FIXED_HEADER_LEN {
                return None;
            }
            (
                fe_offset::extended_file_entry::L_EA,
                fe_offset::extended_file_entry::L_AD,
                fe_offset::extended_file_entry::FIXED_HEADER_LEN,
            )
        }
        _ => return None,
    };

    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&entry[l_ea_off..l_ea_off + 4]);
    let l_ea = u32::from_le_bytes(bytes) as usize;
    bytes.copy_from_slice(&entry[l_ad_off..l_ad_off + 4]);
    let l_ad = u32::from_le_bytes(bytes) as usize;

    let ad_area_offset = fixed_len.checked_add(l_ea)?;
    if ad_area_offset.checked_add(l_ad)? > entry.len() {
        return None;
    }

    Some(EntryLayout {
        tag_identifier: id,
        file_type: icb_tag.file_type,
        alloc_type: icb_tag.alloc_type(),
        information_length: info_len,
        ad_area_offset,
        ad_area_length: l_ad,
    })
}

// ── Allocation Descriptors ──────────────────────────────────────────

/// `short_ad` (ECMA-167 §4/14.14.1) — 8 bytes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ShortAd {
    /// `extent_length` in bytes. The high two bits encode the extent
    /// type ([`ad_type`]); the low 30 bits are the actual length.
    pub extent_length_raw: u32,
    /// Logical block number within the partition implied by the
    /// containing ICB.
    pub extent_position: u32,
}

impl ShortAd {
    #[inline]
    pub fn extent_type(&self) -> u32 {
        self.extent_length_raw >> 30
    }
    #[inline]
    pub fn extent_length(&self) -> u32 {
        self.extent_length_raw & 0x3FFF_FFFF
    }
}

/// `long_ad` (ECMA-167 §4/14.14.2) — 16 bytes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LongAd {
    /// `extent_length` in bytes (high 2 bits = type, low 30 = len).
    pub extent_length_raw: u32,
    /// Logical block number.
    pub extent_lbn: u32,
    /// Partition reference number (index into the LVD's map array).
    pub partition_ref: u16,
    /// Implementation Use / AD UseFlags (6 bytes — opaque to the
    /// read path).
    pub implementation_use: [u8; 6],
}

impl LongAd {
    #[inline]
    pub fn extent_type(&self) -> u32 {
        self.extent_length_raw >> 30
    }
    #[inline]
    pub fn extent_length(&self) -> u32 {
        self.extent_length_raw & 0x3FFF_FFFF
    }
}

/// Extent-type values for the high 2 bits of `extent_length` in any
/// Allocation Descriptor (ECMA-167 §4/14.14).
pub mod ad_type {
    /// Recorded and allocated.
    pub const RECORDED: u32 = 0;
    /// Allocated but not yet recorded.
    pub const NOT_RECORDED_BUT_ALLOCATED: u32 = 1;
    /// Not allocated.
    pub const NOT_ALLOCATED: u32 = 2;
    /// Pointer to next allocation extent (continuation).
    pub const NEXT_EXTENT: u32 = 3;
}

/// Decode a short_ad from a buffer at `offset`.
#[inline]
pub fn read_short_ad(buf: &[u8], offset: usize) -> ShortAd {
    debug_assert!(offset + 8 <= buf.len());
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&buf[offset..offset + 4]);
    let extent_length_raw = u32::from_le_bytes(tmp);
    tmp.copy_from_slice(&buf[offset + 4..offset + 8]);
    let extent_position = u32::from_le_bytes(tmp);
    ShortAd {
        extent_length_raw,
        extent_position,
    }
}

/// Decode a long_ad from a buffer at `offset`.
#[inline]
pub fn read_long_ad(buf: &[u8], offset: usize) -> LongAd {
    debug_assert!(offset + 16 <= buf.len());
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&buf[offset..offset + 4]);
    let extent_length_raw = u32::from_le_bytes(tmp);
    tmp.copy_from_slice(&buf[offset + 4..offset + 8]);
    let extent_lbn = u32::from_le_bytes(tmp);
    let mut t2 = [0u8; 2];
    t2.copy_from_slice(&buf[offset + 8..offset + 10]);
    let partition_ref = u16::from_le_bytes(t2);
    let mut iu = [0u8; 6];
    iu.copy_from_slice(&buf[offset + 10..offset + 16]);
    LongAd {
        extent_length_raw,
        extent_lbn,
        partition_ref,
        implementation_use: iu,
    }
}
