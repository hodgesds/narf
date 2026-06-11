//! exFAT File Allocation Table codec.
//!
//! Clean-room. exFAT entries are flat 32-bit values (unlike FAT12's
//! 12-bit pack and FAT16's 16-bit values); the spec defines a small
//! set of magic sentinels for free / bad / EOC. Note: when a stream
//! extension entry sets the `NoFatChain` flag (§7.6.5), the FAT is
//! not consulted at all and the data is one contiguous extent of
//! `data_length` bytes starting at `first_cluster` — that path lives
//! in `node.rs`.
//!
//! References:
//! - exFAT file system specification (Microsoft, 2019),
//!   §3.3 "File Allocation Table" — entry size, sentinels.
//!   EOC      : `0xFFFFFFFF` (§3.3 final value of any active chain).
//!   Bad      : `0xFFFFFFF7`.
//!   Free     : `0x00000000`.
//!   Reserved : index 0 holds `0xFFFFFFF8 | MediaType` per §3.3,
//!   index 1 holds `0xFFFFFFFF`.
//!   <https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification>

/// FAT entry sentinels per §3.3, exposed as raw u32 so the write
/// path can encode them directly.
pub const FAT_FREE: u32 = 0x0000_0000;
pub const FAT_END_OF_CHAIN: u32 = 0xFFFF_FFFF;
pub const FAT_BAD_CLUSTER: u32 = 0xFFFF_FFF7;

/// Decoded meaning of one 32-bit FAT entry.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FatEntry {
    /// `0x00000000` — slot is unallocated.
    Free,
    /// Any value in `[2, ClusterCount + 1]` — pointer to the next
    /// cluster in the chain.
    Next(u32),
    /// `0xFFFFFFF7` — bad cluster, do not allocate.
    Bad,
    /// `0xFFFFFFFF` — terminal sentinel of an allocated chain.
    EndOfChain,
    /// Any other reserved sentinel (e.g. media type at index 0).
    Reserved(u32),
}

/// Decode the FAT entry that lives at byte offset `byte_offset`
/// inside a sector buffer just read from disk. Caller bounds the
/// offset to `lbs - 4`. exFAT FAT entries are little-endian u32s.
pub fn parse_entry(buffer: &[u8], byte_offset: usize) -> FatEntry {
    let v = u32::from_le_bytes([
        buffer[byte_offset],
        buffer[byte_offset + 1],
        buffer[byte_offset + 2],
        buffer[byte_offset + 3],
    ]);
    classify(v)
}

/// Convert a raw u32 entry value to the typed `FatEntry`. Pulled
/// out so the test suite can exercise the classifier without
/// allocating a buffer.
pub fn classify(v: u32) -> FatEntry {
    match v {
        0 => FatEntry::Free,
        0xFFFF_FFFF => FatEntry::EndOfChain,
        0xFFFF_FFF7 => FatEntry::Bad,
        // Anything ≥ 0xFFFF_FFF8 (other than EOC / Bad) is reserved
        // territory per §3.3 — surface explicitly so callers can
        // notice a corrupt FAT.
        x if x >= 0xFFFF_FFF8 => FatEntry::Reserved(x),
        x => FatEntry::Next(x),
    }
}

/// Compute the (sector, byte-in-sector) where a given cluster's
/// FAT entry lives, given the on-disk FatOffset (§3.1.6) and the
/// volume's bytes-per-sector. exFAT FAT entries are 4 bytes each.
pub fn entry_location(
    fat_offset_sectors: u32,
    bytes_per_sector: u32,
    cluster: u32,
) -> (u64, usize) {
    let fat_byte_offset = (cluster as u64) * 4;
    let sector = fat_offset_sectors as u64 + fat_byte_offset / bytes_per_sector as u64;
    let byte_in_sector = (fat_byte_offset % bytes_per_sector as u64) as usize;
    (sector, byte_in_sector)
}
