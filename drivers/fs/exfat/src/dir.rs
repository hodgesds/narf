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
//!   §7.6.5 GeneralSecondaryFlags — bit 0 AllocationPossible,
//!   bit 1 NoFatChain (data is contiguous).
//!   §7.7 File Name Directory Entry (type 0xC1) — 15 UTF-16 chars
//!   per slot.
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
    pub const HIDDEN: u16 = 0x0002;
    pub const SYSTEM: u16 = 0x0004;
    pub const DIRECTORY: u16 = 0x0010;
    pub const ARCHIVE: u16 = 0x0020;
}

/// GeneralSecondaryFlags bits inside the Stream Extension entry
/// (§7.6.5). `NO_FAT_CHAIN` means the FAT is bypassed entirely and
/// the data is one contiguous run of `data_length` bytes.
pub mod stream_flags {
    pub const ALLOCATION_POSSIBLE: u8 = 0x01;
    pub const NO_FAT_CHAIN: u8 = 0x02;
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

/// Linux `mktime64` (kernel/time/time.c), Gauss's algorithm, including
/// its handling of out-of-range fields: month 0 is the previous December,
/// day 0 the last day of the previous month.
fn mktime64(year0: i64, mon0: i64, day: i64, hour: i64, min: i64, sec: i64) -> i64 {
    let (mut year, mut mon) = (year0, mon0 - 2);
    // 1..12 -> 11,12,1..10: puts Feb last since it has the leap day.
    if mon <= 0 {
        mon += 12;
        year -= 1;
    }
    (((year / 4 - year / 100 + year / 400 + 367 * mon / 12 + day) + year * 365 - 719_499) * 24
        + hour)
        * 60
        * 60
        + min * 60
        + sec
}

/// §7.4.10 UtcOffset bit 7 (`EXFAT_TZ_VALID`): the low 7 bits hold a
/// signed offset from UTC in 15-minute units.
pub const EXFAT_TZ_VALID: u8 = 0x80;

/// An exFAT timestamp (§7.4.8: time in the low 16 bits, date in the high
/// 16), its 10 ms increment and its UTC-offset byte, to wall-clock
/// nanoseconds since the epoch. Exactly Linux's `exfat_get_entry_time`:
/// the date/time fields go through `mktime64` unvalidated, a 10 ms byte
/// of 0..199 adds whole seconds plus centiseconds, and a VALID offset
/// converts the local fields to UTC (`exfat_adjust_tz`: 0x00..0x3F is
/// east of UTC and subtracted, 0x40..0x7F is west and added). Without
/// the valid bit, `tz_offset_min` (`exfat_tz_offset`: the `time_offset=`
/// option, or `-sys_tz.tz_minuteswest` with `sys_tz`) is subtracted.
pub fn exfat_time_to_unix_ns(tz: u8, timestamp: u32, time_cs: u8, tz_offset_min: i64) -> u64 {
    let t = i64::from(timestamp & 0xFFFF);
    let d = i64::from(timestamp >> 16);
    let mut sec = mktime64(
        1980 + (d >> 9),
        (d >> 5) & 0x000F,
        d & 0x001F,
        t >> 11,
        (t >> 5) & 0x003F,
        (t & 0x001F) << 1,
    );
    let mut nsec = 0u64;
    if time_cs != 0 {
        sec += i64::from(time_cs / 100);
        nsec = u64::from(time_cs % 100) * 10_000_000;
    }
    if tz & EXFAT_TZ_VALID != 0 {
        let off = i64::from(tz & !EXFAT_TZ_VALID);
        if off <= 0x3F {
            sec -= off * 15 * 60;
        } else {
            sec += (0x80 - off) * 15 * 60;
        }
    } else {
        sec -= tz_offset_min * 60;
    }
    if sec < 0 {
        return 0;
    }
    sec as u64 * 1_000_000_000 + nsec
}

/// An exFAT inode's times as Linux's `exfat_find` + `exfat_fill_inode`
/// build them: mtime from LastModified (with its 10 ms increment and
/// offset), ctime = mtime, atime from LastAccessed (no 10 ms field exists
/// for it). Nanoseconds since the epoch.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct ExfatTimes {
    pub atime_ns: u64,
    pub mtime_ns: u64,
}

impl ExfatTimes {
    pub fn from_entry(e: &FileDirectoryEntry, tz_offset_min: i64) -> Self {
        Self {
            mtime_ns: exfat_time_to_unix_ns(
                e.last_modified_utc_offset,
                e.last_modified_timestamp,
                e.last_modified_10ms_increment,
                tz_offset_min,
            ),
            atime_ns: exfat_time_to_unix_ns(
                e.last_accessed_utc_offset,
                e.last_accessed_timestamp,
                0,
                tz_offset_min,
            ),
        }
    }

    /// The root directory has no file entry; Linux's `exfat_read_root`
    /// stamps the mount time (`simple_inode_init_ts`, truncated to the
    /// 10 ms `s_time_gran`) and rounds atime down to 2 seconds
    /// (`exfat_truncate_inode_atime`).
    pub fn root_at(now_ns: u64) -> Self {
        const NS: u64 = 1_000_000_000;
        let mtime_ns = now_ns - now_ns % 10_000_000;
        let secs = mtime_ns / NS;
        Self {
            mtime_ns,
            atime_ns: (secs - secs % 2) * NS,
        }
    }
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

// ── Spec §6.3.3 — SetChecksum over a directory-entry group ─────────

/// Compute the §6.3.3 SetChecksum over the byte image of a primary
/// FileDirectoryEntry plus every secondary entry. The two bytes at
/// offsets 2 and 3 of the primary entry (the checksum field
/// itself) are skipped — they're written back after the checksum
/// is computed.
///
/// Algorithm (§6.3.3):
///   for byte_index in 0..len:
///     if byte_index in {2, 3}: continue
///     checksum = ((checksum & 1) << 15) | (checksum >> 1) + byte
pub fn set_checksum(group: &[u8]) -> u16 {
    let mut sum: u16 = 0;
    for (i, &b) in group.iter().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }
        sum = ((sum & 1) << 15)
            .wrapping_add(sum >> 1)
            .wrapping_add(b as u16);
    }
    sum
}

/// Re-compute the SetChecksum on `group` and write it back into the
/// primary entry's bytes 2..4 (little-endian). Used by both
/// verification (paired with `verify_set_checksum`) and write
/// (computing a fresh checksum after editing a group).
pub fn finalize_set_checksum(group: &mut [u8]) {
    let cs = set_checksum(group);
    group[2..4].copy_from_slice(&cs.to_le_bytes());
}

/// Verify that the SetChecksum in `group[2..4]` matches the
/// recomputation. Returns `true` iff valid.
pub fn verify_set_checksum(group: &[u8]) -> bool {
    if group.len() < 4 {
        return false;
    }
    let stored = u16::from_le_bytes([group[2], group[3]]);
    set_checksum(group) == stored
}

/// Re-compute and write back the SetChecksum for a directory-entry
/// group that has been modified. Equivalent to [`finalize_set_checksum`];
/// exposed under this name so dir-mutation callers have a clearly
/// named entry point for "I've changed a secondary entry, now fix up
/// the primary's checksum field."
///
/// Per MS exFAT spec §6.3.2 / §7.4.3 the checksum is stored at
/// bytes 2..4 (little-endian) of the first (primary) entry.
///
/// # Panics
/// Panics if `set.len() < 4` — the minimum size for a group with a
/// primary entry is 32 bytes (one entry), but the caller must supply
/// at least 4 bytes for the checksum field to exist.
pub fn recompute_set_checksum(set: &mut [u8]) {
    finalize_set_checksum(set);
}
