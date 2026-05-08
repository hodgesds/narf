//! exFAT 32-byte directory entries.
//!
//! Clean-room. exFAT directories are streams of 32-byte entries, but
//! unlike FAT each logical "file" is a *group* of entries: a primary
//! File Directory Entry (type 0x85) followed by its Stream Extension
//! Entry (type 0xC0) and one or more File Name Entries (type 0xC1).
//! Other primary types (Allocation Bitmap 0x81, Up-case Table 0x82,
//! Volume Label 0x83) sit alone in the root directory.
//!
//! References:
//! - exFAT file system specification (Microsoft, 2019),
//!   §6.1 EntryType byte (high bit = InUse, next = Critical, etc.).
//!   §7.1 Allocation Bitmap Directory Entry (type 0x81).
//!   §7.2 Up-case Table Directory Entry (type 0x82).
//!   §7.3 Volume Label Directory Entry (type 0x83).
//!   §7.4 File Directory Entry (type 0x85).
//!   §7.6 Stream Extension Directory Entry (type 0xC0).
//!     §7.6.5 GeneralSecondaryFlags — bit 0 AllocationPossible,
//!       bit 1 NoFatChain (data is contiguous).
//!   §7.7 File Name Directory Entry (type 0xC1) — 15 UTF-16 chars
//!       per slot.
//!   <https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification>

/// Size of every exFAT directory entry, in bytes (§6 — fixed).
pub const DIR_ENTRY_SIZE: usize = 32;

/// EntryType byte values (§6.1 + §7.x). The high bit (`0x80`)
/// indicates "InUse"; clearing it tombstones the slot.
pub mod entry_type {
    /// §7.1 Allocation Bitmap.
    pub const ALLOCATION_BITMAP: u8 = 0x81;
    /// §7.2 Up-case Table.
    pub const UPCASE_TABLE: u8 = 0x82;
    /// §7.3 Volume Label (may be absent if no label is set).
    pub const VOLUME_LABEL: u8 = 0x83;
    /// §7.4 File / directory primary entry.
    pub const FILE: u8 = 0x85;
    /// §7.6 Stream Extension secondary entry.
    pub const STREAM_EXTENSION: u8 = 0xC0;
    /// §7.7 File Name secondary entry.
    pub const FILE_NAME: u8 = 0xC1;

    /// §6.1 — TypeImportance bit. We don't dispatch on it but the
    /// helpers below check the high "InUse" bit (`0x80`) which the
    /// spec defines as the "EntryType is non-zero" rule.
    pub const IN_USE_MASK: u8 = 0x80;

    /// §6 — value `0x00` terminates the directory chain. Anything
    /// else with the high bit clear is a tombstoned (deleted) slot
    /// that scanners must skip.
    pub const END_OF_DIRECTORY: u8 = 0x00;
}

/// FileAttributes bits (§7.4.4).
pub mod file_attr {
    pub const READ_ONLY: u16 = 0x0001;
    pub const HIDDEN: u16    = 0x0002;
    pub const SYSTEM: u16    = 0x0004;
    pub const DIRECTORY: u16 = 0x0010;
    pub const ARCHIVE: u16   = 0x0020;
}

/// GeneralSecondaryFlags bits inside the Stream Extension entry
/// (§7.6.5). `NO_FAT_CHAIN` means the FAT is bypassed entirely and
/// the data is one contiguous run of `data_length` bytes.
pub mod stream_flags {
    pub const ALLOCATION_POSSIBLE: u8 = 0x01;
    pub const NO_FAT_CHAIN: u8        = 0x02;
}

/// §7.4 File Directory Entry (type 0x85). Primary entry; describes
/// attributes + timestamps. The "SecondaryCount" field counts the
/// 0xC0/0xC1 follow-on entries that complete the file's record.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct FileDirectoryEntry {
    pub entry_type: u8,
    /// §7.4.2 — count of secondary entries (1 stream + N filename).
    pub secondary_count: u8,
    /// §7.4.3 — set checksum over all 32-byte entries in the group
    /// (we don't verify on read; flagged TODO for write).
    pub set_checksum: u16,
    pub file_attributes: u16,
    pub reserved1: u16,
    pub create_timestamp: u32,
    pub last_modified_timestamp: u32,
    pub last_accessed_timestamp: u32,
    pub create_10ms_increment: u8,
    pub last_modified_10ms_increment: u8,
    pub create_utc_offset: u8,
    pub last_modified_utc_offset: u8,
    pub last_accessed_utc_offset: u8,
    pub reserved2: [u8; 7],
}

/// §7.6 Stream Extension Directory Entry (type 0xC0). Always
/// follows the 0x85 primary; carries the name length, name hash,
/// allocation flags, first cluster, and data length.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct StreamExtensionEntry {
    pub entry_type: u8,
    /// §7.6.5 — see `stream_flags`.
    pub general_secondary_flags: u8,
    pub reserved1: u8,
    /// §7.6.7 — character count of the file name (UTF-16 units).
    pub name_length: u8,
    /// §7.6.8 — hash of the up-cased UTF-16 name; used to skip
    /// full name comparison on lookup.
    pub name_hash: u16,
    pub reserved2: u16,
    /// §7.6.9 — valid data length (≤ DataLength).
    pub valid_data_length: u64,
    pub reserved3: u32,
    /// §7.6.11 — first cluster of the file's data.
    pub first_cluster: u32,
    /// §7.6.12 — total allocated length, in bytes.
    pub data_length: u64,
}

/// §7.7 File Name Directory Entry (type 0xC1). Carries up to 15
/// UTF-16 code units of the file name; multiple slots concatenate.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct FileNameEntry {
    pub entry_type: u8,
    pub general_secondary_flags: u8,
    /// §7.7.3 — 15 UTF-16 code units of name fragment.
    pub file_name: [u16; 15],
}

/// §7.1 Allocation Bitmap Directory Entry (type 0x81). The bitmap
/// stream itself lives in the cluster heap starting at
/// `first_cluster`; one bit per cluster.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AllocationBitmapEntry {
    pub entry_type: u8,
    /// §7.1.2 — bit 0 selects FAT 0 vs FAT 1 (TexFAT). For non-
    /// TexFAT volumes (NumberOfFats == 1) this byte is 0.
    pub bitmap_flags: u8,
    pub reserved: [u8; 18],
    pub first_cluster: u32,
    pub data_length: u64,
}

/// §7.2 Up-case Table Directory Entry (type 0x82). The table
/// itself lives in the cluster heap starting at `first_cluster`;
/// it's an array of u16 (input-char → upper-cased-char), at most
/// 0x10000 entries.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct UpcaseTableEntry {
    pub entry_type: u8,
    pub reserved1: [u8; 3],
    /// §7.2.3 — table_checksum, computed over the bytes of the
    /// up-case table per §7.2.3. We load and use the table; the
    /// CRC verification is a TODO for write-path landing.
    pub table_checksum: u32,
    pub reserved2: [u8; 12],
    pub first_cluster: u32,
    pub data_length: u64,
}

// ── Spec §6 helpers — entry-type classification ─────────────────────

/// True iff the slot is the end-of-directory sentinel (§6: byte 0
/// equal to `0x00` terminates the directory stream entirely).
pub fn is_end_of_directory(entry_type: u8) -> bool {
    entry_type == entry_type::END_OF_DIRECTORY
}

/// True iff the slot is in use (high bit of EntryType set, §6.1).
/// A cleared high bit on a non-zero type means a tombstoned entry
/// — skip without terminating the scan.
pub fn is_in_use(entry_type: u8) -> bool {
    (entry_type & entry_type::IN_USE_MASK) != 0
}

// ── Spec §7.6.8 — name hash ─────────────────────────────────────────

/// Compute the §7.6.8 NameHash over an up-cased UTF-16 name. The
/// hash hashes the *little-endian byte image* of the up-cased
/// UTF-16 name, two bytes at a time. Used as a fast-reject filter
/// before full comparison during lookup.
pub fn name_hash(upcased_utf16: &[u16]) -> u16 {
    let mut hash: u16 = 0;
    for &cu in upcased_utf16 {
        let bytes = cu.to_le_bytes();
        for &b in &bytes {
            // §7.6.8 pseudocode: rotate-right-1 + add.
            hash = ((hash & 1) << 15) | (hash >> 1);
            hash = hash.wrapping_add(b as u16);
        }
    }
    hash
}

// ── Spec §7.7.3 — file-name fragment extraction ─────────────────────

/// Append at most `take` UTF-16 code units from this `0xC1` slot's
/// `file_name` field into `out`. Spec §7.7.3 says the name slots
/// are concatenated in order; trailing positions inside the LAST
/// slot beyond the StreamExtension's `name_length` are ignored.
/// Returns the number of code units appended.
pub fn extract_file_name_fragment(entry: &FileNameEntry, out: &mut [u16], take: usize) -> usize {
    let n = take.min(15).min(out.len());
    let name = entry.file_name;
    out[..n].copy_from_slice(&name[..n]);
    n
}
