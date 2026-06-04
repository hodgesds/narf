//! ISO 9660 Directory Record structures.
//!
//! Clean-room layout per ECMA-119 (3rd edition, December 2017),
//! §9.1 ("Directory Record"). No GPL/LGPL ISO 9660 source consulted.
//!
//! References:
//! - ECMA-119 §9.1 (Directory Record fields and ordering).
//! - ECMA-119 §9.1.5 (File Flags bitfield).
//! - ECMA-119 §9.1.11 (File Identifier — name + ';' + version).
//! - OSDev Wiki, "ISO 9660 — Directory Entry".
//!   <https://wiki.osdev.org/ISO_9660>

use core::fmt;

/// Fixed 33-byte prefix of every directory record (ECMA-119 §9.1.1
/// through §9.1.10). The trailing File Identifier (§9.1.11) is
/// variable-length and not part of this struct; its length is in
/// [`DirectoryRecord::file_identifier_length`] and the identifier
/// bytes follow immediately after this struct in the on-disc layout.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct DirectoryRecord {
    /// §9.1.1 — total record length (header + identifier + padding).
    /// 0 marks "no more records in this logical sector"; ECMA-119
    /// guarantees a record never crosses a sector boundary.
    pub length: u8,
    /// §9.1.2 — extended attribute record length.
    pub extended_attribute_record_length: u8,
    /// §9.1.3 — extent location (both-endian, LBA).
    pub extent_location: [u32; 2],
    /// §9.1.4 — data length (both-endian, bytes).
    pub data_length: [u32; 2],
    /// §9.1.5 — recording date/time (7-byte binary).
    pub recording_date_time: [u8; 7],
    /// §9.1.6 — file flags. See [`flags`].
    pub file_flags: u8,
    /// §9.1.7 — file unit size (interleaved files).
    pub file_unit_size: u8,
    /// §9.1.8 — interleave gap size.
    pub interleave_gap_size: u8,
    /// §9.1.9 — volume sequence number (both-endian).
    pub volume_sequence_number: [u16; 2],
    /// §9.1.10 — file identifier length in bytes.
    pub file_identifier_length: u8,
}

const _ASSERT_DIR_HEADER_SIZE: () = assert!(core::mem::size_of::<DirectoryRecord>() == 33);

/// File-flag bits (ECMA-119 §9.1.5). Stored in
/// [`DirectoryRecord::file_flags`].
pub mod flags {
    /// Hidden from "normal" directory listings.
    pub const HIDDEN: u8 = 1 << 0;
    /// This record describes a directory.
    pub const DIRECTORY: u8 = 1 << 1;
    /// Associated file (e.g. resource fork).
    pub const ASSOCIATED: u8 = 1 << 2;
    /// Record contents follow Extended Attribute Record format.
    pub const RECORD: u8 = 1 << 3;
    /// File is access-protected.
    pub const PROTECTION: u8 = 1 << 4;
    /// Final extent of a multi-extent file. Bit 7 set on every
    /// extent except the last; bit 7 clear marks the last extent.
    pub const MULTI_EXTENT: u8 = 1 << 7;
}

impl DirectoryRecord {
    /// True iff [`flags::DIRECTORY`] is set in `file_flags`.
    #[inline]
    pub fn is_directory(&self) -> bool {
        (self.file_flags & flags::DIRECTORY) != 0
    }

    /// Extent location (LBA) — LE half of the both-endian field.
    #[inline]
    pub fn extent_lba_le(&self) -> u32 {
        let arr = self.extent_location;
        arr[0]
    }

    /// Data length (bytes) — LE half of the both-endian field.
    #[inline]
    pub fn data_length_le(&self) -> u32 {
        let arr = self.data_length;
        arr[0]
    }
}

impl fmt::Debug for DirectoryRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.length;
        let ff = self.file_flags;
        let fid_len = self.file_identifier_length;
        let lba = self.extent_lba_le();
        let dl = self.data_length_le();
        f.debug_struct("DirectoryRecord")
            .field("length", &len)
            .field("file_flags", &ff)
            .field("file_identifier_length", &fid_len)
            .field("extent_lba", &lba)
            .field("data_length", &dl)
            .finish()
    }
}

/// Read a directory record header (the fixed 33-byte prefix) out
/// of a sector buffer at `offset`. The caller is responsible for
/// bounds-checking the slice (record headers are 33 bytes; ECMA-119
/// guarantees they don't straddle sector boundaries).
///
/// # Panics
/// Debug-asserts that `offset + 33 <= buf.len()`.
#[inline]
pub fn read_directory_record(buf: &[u8], offset: usize) -> DirectoryRecord {
    debug_assert!(offset + core::mem::size_of::<DirectoryRecord>() <= buf.len());
    // SAFETY: `DirectoryRecord` is `#[repr(C, packed)]` with a 33-
    // byte layout that exactly matches ECMA-119 §9.1.1–§9.1.10. The
    // buffer is a freshly-read sector copy we own and the caller has
    // bounded `offset`.
    unsafe { core::ptr::read_unaligned(buf.as_ptr().add(offset) as *const DirectoryRecord) }
}
