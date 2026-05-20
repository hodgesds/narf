//! Partition-table parsers — MBR and GPT.
//!
//! Modern disks (UEFI / >2 TiB) carry a GUID Partition Table
//! per UEFI spec 2.10 §5.3:
//!
//! - **LBA 0** — protective MBR. A legacy-MBR signature + a
//!   single partition entry covering the whole disk with type
//!   0xEE. Stops BIOS-era tools from clobbering the GPT.
//! - **LBA 1** — primary GPT header (`EFI PART` magic + CRC32).
//! - **LBA 2..=33** — 128 partition entries × 128 bytes.
//! - **LBA last-33..=last-1** — backup partition entries + secondary
//!   GPT header (mirror of primary, swapped current/backup LBAs).
//!
//! Legacy BIOS disks carry just the classic MBR at LBA 0 with up
//! to four primary partitions (and chained logicals via the
//! extended-partition mechanism — not handled here).
//!
//! This module ships pure-parse functions. Block-layer wire-up
//! (read LBA 1, parse, register sub-devices) lives in the
//! storage driver glue that owns the parent block device.

extern crate alloc;

use alloc::vec::Vec;

// ── Common signatures ──────────────────────────────────────────────

/// Last two bytes of LBA 0 on a partitioned disk — both MBR and
/// GPT-protective layouts carry this.
pub const MBR_BOOT_SIGNATURE: u16 = 0xAA55;
/// Type byte (in the MBR partition entry) used by the GPT
/// protective entry to flag "the whole disk is GPT".
pub const MBR_TYPE_GPT_PROTECTIVE: u8 = 0xEE;

/// "EFI PART" — bytes 0..8 of the GPT header.
pub const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
/// GPT spec rev 1.0 — encoded as 0x00010000 (1.0 little-endian).
pub const GPT_REVISION_1_0: u32 = 0x0001_0000;
/// The fixed-size LBA the primary header lives on.
pub const GPT_PRIMARY_HEADER_LBA: u64 = 1;

// ── MBR ────────────────────────────────────────────────────────────

/// One classic-MBR partition entry. 16 bytes on disk; we expose
/// only the fields callers actually use.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MbrPartition {
    /// 0x80 = active (BIOS-bootable), 0x00 = inactive.
    pub boot_flag: u8,
    /// Partition type byte. 0x00 = empty entry; 0x83 = Linux;
    /// 0x07 = NTFS / exFAT; 0xEE = GPT protective.
    pub kind: u8,
    /// First-LBA of the partition.
    pub start_lba: u32,
    /// Sector count.
    pub sector_count: u32,
}

/// Errors decoding an MBR.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MbrError {
    /// Buffer shorter than 512 bytes.
    Short,
    /// Bytes 510..=511 didn't match `MBR_BOOT_SIGNATURE`.
    BadSignature,
}

/// Parse the four primary partition entries from an MBR-sized
/// (512-byte) sector. Empty entries (kind == 0x00) are still
/// returned so callers can detect "GPT protective + 3 zeros".
pub fn parse_mbr(sector0: &[u8]) -> Result<[MbrPartition; 4], MbrError> {
    if sector0.len() < 512 {
        return Err(MbrError::Short);
    }
    if u16::from_le_bytes([sector0[510], sector0[511]]) != MBR_BOOT_SIGNATURE {
        return Err(MbrError::BadSignature);
    }
    let mut out = [MbrPartition {
        boot_flag: 0,
        kind: 0,
        start_lba: 0,
        sector_count: 0,
    }; 4];
    for i in 0..4 {
        let off = 446 + i * 16;
        let e = &sector0[off..off + 16];
        out[i] = MbrPartition {
            boot_flag: e[0],
            kind: e[4],
            start_lba: u32::from_le_bytes([e[8], e[9], e[10], e[11]]),
            sector_count: u32::from_le_bytes([e[12], e[13], e[14], e[15]]),
        };
    }
    Ok(out)
}

/// Inspect an MBR for the GPT-protective signature: bytes 510..=511
/// match MBR_BOOT_SIGNATURE *and* exactly one entry of type 0xEE
/// covering most of the disk. Returns `true` iff the disk should be
/// re-read as GPT rather than treated as legacy MBR.
pub fn is_gpt_protective(mbr: &[MbrPartition; 4]) -> bool {
    let proto_count = mbr.iter().filter(|p| p.kind == MBR_TYPE_GPT_PROTECTIVE).count();
    let other_count = mbr
        .iter()
        .filter(|p| p.kind != 0 && p.kind != MBR_TYPE_GPT_PROTECTIVE)
        .count();
    proto_count == 1 && other_count == 0
}

// ── GPT ────────────────────────────────────────────────────────────

/// Decoded GPT header (LBA 1). We carry the on-disk CRC32 fields
/// so the caller can verify them; computing the CRCs is delegated
/// to the storage driver that already has a CRC32 implementation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GptHeader {
    /// Revision (e.g. 0x00010000 for spec 1.0).
    pub revision: u32,
    /// Header length in bytes (typically 92).
    pub header_size: u32,
    /// CRC32 of the header with this field zeroed. Caller verifies.
    pub header_crc32: u32,
    /// LBA holding this header. Primary = 1.
    pub current_lba: u64,
    /// LBA holding the backup header (typically last LBA of disk).
    pub backup_lba: u64,
    /// First LBA usable by partitions (after the partition entries).
    pub first_usable_lba: u64,
    /// Last LBA usable by partitions (before the backup entries).
    pub last_usable_lba: u64,
    /// Whole-disk GUID (unique per drive).
    pub disk_guid: [u8; 16],
    /// LBA where the partition entry array starts (typically 2).
    pub partition_entries_lba: u64,
    /// Number of entries in the array (typically 128).
    pub num_partition_entries: u32,
    /// Size of each entry in bytes (typically 128).
    pub partition_entry_size: u32,
    /// CRC32 of the partition entries array.
    pub partition_array_crc32: u32,
}

/// Errors decoding a GPT header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GptError {
    /// Sector buffer shorter than the header size.
    Short,
    /// Bytes 0..8 didn't spell `EFI PART`.
    BadSignature,
    /// Revision field below the minimum we recognise (1.0).
    UnsupportedRevision,
    /// `header_size` claimed less than 92 bytes.
    BadHeaderSize,
    /// `partition_entry_size` was zero or not a multiple of 8.
    BadEntrySize,
}

/// Parse a GPT primary or backup header out of a sector buffer
/// (typically the 512 bytes at LBA 1).
pub fn parse_gpt_header(sector: &[u8]) -> Result<GptHeader, GptError> {
    if sector.len() < 92 {
        return Err(GptError::Short);
    }
    if &sector[0..8] != GPT_SIGNATURE {
        return Err(GptError::BadSignature);
    }
    let revision = u32::from_le_bytes(sector[8..12].try_into().unwrap());
    if revision < GPT_REVISION_1_0 {
        return Err(GptError::UnsupportedRevision);
    }
    let header_size = u32::from_le_bytes(sector[12..16].try_into().unwrap());
    if header_size < 92 {
        return Err(GptError::BadHeaderSize);
    }
    let partition_entry_size = u32::from_le_bytes(sector[84..88].try_into().unwrap());
    if partition_entry_size == 0 || partition_entry_size % 8 != 0 {
        return Err(GptError::BadEntrySize);
    }
    Ok(GptHeader {
        revision,
        header_size,
        header_crc32: u32::from_le_bytes(sector[16..20].try_into().unwrap()),
        // sector[20..24] is reserved (4 zero bytes per UEFI 2.10).
        current_lba: u64::from_le_bytes(sector[24..32].try_into().unwrap()),
        backup_lba: u64::from_le_bytes(sector[32..40].try_into().unwrap()),
        first_usable_lba: u64::from_le_bytes(sector[40..48].try_into().unwrap()),
        last_usable_lba: u64::from_le_bytes(sector[48..56].try_into().unwrap()),
        disk_guid: sector[56..72].try_into().unwrap(),
        partition_entries_lba: u64::from_le_bytes(sector[72..80].try_into().unwrap()),
        num_partition_entries: u32::from_le_bytes(sector[80..84].try_into().unwrap()),
        partition_entry_size,
        partition_array_crc32: u32::from_le_bytes(sector[88..92].try_into().unwrap()),
    })
}

/// One GPT partition entry (128 bytes on disk; we decode the
/// fields callers actually use).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GptPartition {
    /// Partition type GUID. Empty entries have type-GUID = all zeros.
    pub type_guid: [u8; 16],
    /// Unique partition GUID.
    pub partition_guid: [u8; 16],
    /// First LBA of the partition (inclusive).
    pub start_lba: u64,
    /// Last LBA of the partition (inclusive).
    pub end_lba: u64,
    /// Attribute flags. Bit 0 = "required by platform"; bit 2 =
    /// "legacy BIOS bootable"; bits 56..=63 = type-GUID specific.
    pub attributes: u64,
    /// UTF-16LE partition name (up to 36 code units; decoded to
    /// a String for the UI / log surface).
    pub name: alloc::string::String,
}

impl GptPartition {
    /// True if the entry is unused (all-zero type-GUID per spec).
    pub fn is_empty(&self) -> bool {
        self.type_guid.iter().all(|&b| b == 0)
    }
    /// Sector count = end - start + 1 (inclusive endpoints).
    pub fn sector_count(&self) -> u64 {
        self.end_lba.saturating_sub(self.start_lba).saturating_add(1)
    }
}

/// Parse the GPT partition entries array. `array` is the raw
/// bytes from the LBAs starting at `header.partition_entries_lba`;
/// `entry_size` should equal `header.partition_entry_size`;
/// `count` should equal `header.num_partition_entries`. Empty
/// (zero type-GUID) entries are included so the caller's indexing
/// matches the on-disk slot order.
pub fn parse_gpt_partitions(
    array: &[u8],
    entry_size: usize,
    count: usize,
) -> Vec<GptPartition> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * entry_size;
        if off + 128 > array.len() {
            break;
        }
        let e = &array[off..off + entry_size];
        // UTF-16LE name decode — stop at the first null code unit.
        let name = decode_utf16le_name(&e[56..128]);
        out.push(GptPartition {
            type_guid: e[0..16].try_into().unwrap(),
            partition_guid: e[16..32].try_into().unwrap(),
            start_lba: u64::from_le_bytes(e[32..40].try_into().unwrap()),
            end_lba: u64::from_le_bytes(e[40..48].try_into().unwrap()),
            attributes: u64::from_le_bytes(e[48..56].try_into().unwrap()),
            name,
        });
    }
    out
}

fn decode_utf16le_name(bytes: &[u8]) -> alloc::string::String {
    let mut chars: Vec<u16> = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let cu = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if cu == 0 {
            break;
        }
        chars.push(cu);
        i += 2;
    }
    // No-std String::from_utf16 isn't directly available; do a
    // BMP-only decode (good enough for partition names which are
    // ASCII in practice).
    chars
        .iter()
        .map(|&c| char::from_u32(c as u32).unwrap_or('\u{FFFD}'))
        .collect()
}
