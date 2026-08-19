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

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::registry::{
    register_block_device, register_block_device_with_meta, BlockDeviceSync, PartitionMetadata,
};
use crate::BlockIoError;

/// Best-effort filesystem UUID discovery used for `/dev/disk/by-uuid`.
///
/// This intentionally reads only immutable identification bytes while the
/// partition scanner is already registering the child device. It is not a
/// filesystem probe: the owning filesystem driver still validates and mounts
/// the complete format later. FAT serials use Linux's eight-hex-digit form
/// with a dash after four digits; ext UUIDs use their standard byte-order
/// representation.
fn discover_fs_uuid(dev: &dyn BlockDeviceSync) -> Option<String> {
    let lba_bytes = dev.lba_size() as usize;
    if lba_bytes < 512 {
        return None;
    }

    let mut boot = alloc::vec![0u8; lba_bytes];
    if dev.read(0, 1, &mut boot).is_ok() {
        let fat_serial_offset = if boot.get(82..90) == Some(b"FAT32   ".as_slice()) {
            Some(67)
        } else if boot.get(54..62) == Some(b"FAT12   ".as_slice())
            || boot.get(54..62) == Some(b"FAT16   ".as_slice())
        {
            Some(39)
        } else {
            None
        };
        if let Some(offset) = fat_serial_offset {
            let serial = u32::from_le_bytes(boot[offset..offset + 4].try_into().ok()?);
            return Some(format!("{:04X}-{:04X}", serial >> 16, serial & 0xffff));
        }
    }

    // An ext superblock starts at byte 1024 and its UUID at +0x68. Read only
    // the first few logical blocks needed to cover both the magic and UUID.
    let required: usize = 1024 + 0x68 + 16;
    let blocks = required.div_ceil(lba_bytes);
    if blocks == 0 || blocks > u16::MAX as usize {
        return None;
    }
    let mut bytes = alloc::vec![0u8; blocks * lba_bytes];
    if dev.read(0, blocks as u16, &mut bytes).is_err()
        || bytes.get(1024 + 0x38..1024 + 0x3a) != Some(&[0x53, 0xef][..])
    {
        return None;
    }
    let uuid = &bytes[1024 + 0x68..1024 + 0x68 + 16];
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
        uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    ))
}

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
    for (i, slot) in out.iter_mut().enumerate() {
        let off = 446 + i * 16;
        let e = &sector0[off..off + 16];
        *slot = MbrPartition {
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
    let proto_count = mbr
        .iter()
        .filter(|p| p.kind == MBR_TYPE_GPT_PROTECTIVE)
        .count();
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
        self.end_lba
            .saturating_sub(self.start_lba)
            .saturating_add(1)
    }
}

/// Parse the GPT partition entries array. `array` is the raw
/// bytes from the LBAs starting at `header.partition_entries_lba`;
/// `entry_size` should equal `header.partition_entry_size`;
/// `count` should equal `header.num_partition_entries`. Empty
/// (zero type-GUID) entries are included so the caller's indexing
/// matches the on-disk slot order.
pub fn parse_gpt_partitions(array: &[u8], entry_size: usize, count: usize) -> Vec<GptPartition> {
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

/// Format a 16-byte GPT GUID as canonical 8-4-4-4-12 hex. Per UEFI
/// spec §A: the first 8 bytes are the little-endian
/// Data1/Data2/Data3 fields; the last 8 are stored big-endian.
fn format_guid(guid: &[u8; 16]) -> alloc::string::String {
    use core::fmt::Write as _;
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    let mut s = alloc::string::String::with_capacity(36);
    let _ = write!(s, "{:08X}-{:04X}-{:04X}-", d1, d2, d3);
    let _ = write!(s, "{:02X}{:02X}-", guid[8], guid[9]);
    for b in &guid[10..16] {
        let _ = write!(s, "{:02X}", b);
    }
    s
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

// ── PartitionBlockDevice + registration helper ─────────────────────
//
// A partition is just a contiguous LBA window onto a parent
// block device. `PartitionBlockDevice` adds the LBA-offset
// translation + bounds check; `scan_and_register_partitions`
// reads LBA 0 / LBA 1 of a parent and registers a child
// `BlockDeviceSync` for each non-empty entry.

/// A sub-block-device that wraps a parent `BlockDeviceSync` plus
/// a (start_lba, sector_count) window. read/write translate the
/// caller-supplied LBA into parent coordinates and bounds-check
/// against the window end.
pub struct PartitionBlockDevice {
    parent: Arc<dyn BlockDeviceSync>,
    /// Start LBA on the parent device.
    start_lba: u64,
    /// Length of the partition in LBAs.
    sector_count: u64,
}

impl PartitionBlockDevice {
    /// Wrap `parent[start_lba .. start_lba + sector_count]` as a
    /// new block device.
    pub fn new(parent: Arc<dyn BlockDeviceSync>, start_lba: u64, sector_count: u64) -> Self {
        Self {
            parent,
            start_lba,
            sector_count,
        }
    }
}

impl core::fmt::Debug for PartitionBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PartitionBlockDevice")
            .field("start_lba", &self.start_lba)
            .field("sector_count", &self.sector_count)
            .finish_non_exhaustive()
    }
}

impl BlockDeviceSync for PartitionBlockDevice {
    fn lba_size(&self) -> u32 {
        self.parent.lba_size()
    }
    fn capacity(&self) -> u64 {
        self.sector_count
    }
    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        let n = n_blocks as u64;
        if lba.checked_add(n).is_none_or(|end| end > self.sector_count) {
            return Err(BlockIoError::OutOfRange);
        }
        let abs = self.start_lba + lba;
        self.parent.read(abs, n_blocks, out)
    }
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
        let n = n_blocks as u64;
        if lba.checked_add(n).is_none_or(|end| end > self.sector_count) {
            return Err(BlockIoError::OutOfRange);
        }
        let abs = self.start_lba + lba;
        self.parent.write(abs, n_blocks, data)
    }
}

/// Errors during partition scanning.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ScanError {
    /// LBA 0 read failed.
    Mbr(BlockIoError),
    /// LBA 1 read failed.
    Gpt(BlockIoError),
    /// Partition entry array read failed.
    EntriesRead(BlockIoError),
    /// LBA 0 didn't have the MBR signature.
    MbrSignature(MbrError),
    /// GPT header didn't parse.
    GptHeader(GptError),
}

/// Outcome of [`scan_and_register_partitions`] — diagnostic
/// surface for the boot log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanReport {
    /// Names registered against the block registry (e.g.
    /// `["nvme0p1", "nvme0p2"]`).
    pub registered: Vec<String>,
    /// True iff the disk was GPT (vs legacy MBR).
    pub is_gpt: bool,
}

/// Scan a parent block device for partitions and register each
/// as a child device under the registry, naming them
/// `{parent_name}p{n}` (1-indexed, matching Linux convention).
///
/// The names are heap-allocated then `Box::leak`'d so they
/// satisfy the registry's `&'static str` interface. Partitions
/// live for the kernel's lifetime; the leak is bounded by the
/// 128-entry GPT cap.
pub fn scan_and_register_partitions(
    parent: Arc<dyn BlockDeviceSync>,
    parent_name: &str,
) -> Result<ScanReport, ScanError> {
    let lba_bytes = parent.lba_size() as usize;
    // Read LBA 0.
    let mut sector0 = alloc::vec![0u8; lba_bytes];
    parent.read(0, 1, &mut sector0).map_err(ScanError::Mbr)?;
    let mbr = parse_mbr(&sector0).map_err(ScanError::MbrSignature)?;
    let mut registered = Vec::new();

    if is_gpt_protective(&mbr) {
        // GPT path: read LBA 1 (primary header), parse, then read
        // entries array starting at header.partition_entries_lba.
        let mut sector1 = alloc::vec![0u8; lba_bytes];
        parent.read(1, 1, &mut sector1).map_err(ScanError::Gpt)?;
        let header = parse_gpt_header(&sector1).map_err(ScanError::GptHeader)?;

        // Compute how many LBAs the entries array occupies.
        let array_bytes =
            header.num_partition_entries as usize * header.partition_entry_size as usize;
        let array_lbas = array_bytes.div_ceil(lba_bytes) as u16;
        let mut array = alloc::vec![0u8; array_lbas as usize * lba_bytes];
        parent
            .read(header.partition_entries_lba, array_lbas, &mut array)
            .map_err(ScanError::EntriesRead)?;

        let entries = parse_gpt_partitions(
            &array[..array_bytes],
            header.partition_entry_size as usize,
            header.num_partition_entries as usize,
        );
        for (idx, p) in entries.iter().enumerate() {
            if p.is_empty() {
                continue;
            }
            let name = format!("{}p{}", parent_name, idx + 1);
            let static_name: &'static str = Box::leak(name.clone().into_boxed_str());
            let sub = Arc::new(PartitionBlockDevice::new(
                parent.clone(),
                p.start_lba,
                p.sector_count(),
            )) as Arc<dyn BlockDeviceSync>;
            // Attach GPT metadata so root=PARTLABEL=… /
            // root=PARTUUID=… selectors match here.
            let meta = PartitionMetadata {
                gpt_type_guid: format_guid(&p.type_guid),
                partlabel: p.name.clone(),
                partuuid: format_guid(&p.partition_guid),
                fs_uuid: discover_fs_uuid(sub.as_ref()).unwrap_or_default(),
            };
            register_block_device_with_meta(static_name, sub, Some(meta));
            registered.push(name);
        }
        Ok(ScanReport {
            registered,
            is_gpt: true,
        })
    } else {
        // Legacy MBR path.
        for (idx, p) in mbr.iter().enumerate() {
            if p.kind == 0 || p.sector_count == 0 {
                continue;
            }
            let name = format!("{}p{}", parent_name, idx + 1);
            let static_name: &'static str = Box::leak(name.clone().into_boxed_str());
            let sub = Arc::new(PartitionBlockDevice::new(
                parent.clone(),
                p.start_lba as u64,
                p.sector_count as u64,
            )) as Arc<dyn BlockDeviceSync>;
            register_block_device(static_name, sub);
            registered.push(name);
        }
        Ok(ScanReport {
            registered,
            is_gpt: false,
        })
    }
}
