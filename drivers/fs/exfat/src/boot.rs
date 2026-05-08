//! exFAT Main Boot Sector — sector 0 of an exFAT volume.
//!
//! Clean-room. Every field offset, the literal `EXFAT   ` filesystem
//! signature, and the cluster-shift derivation come from Microsoft's
//! 2019 exFAT specification. No GPL/LGPL source consulted.
//!
//! References:
//! - exFAT file system specification (Microsoft, 2019),
//!   §3.1 "Main Boot Sector" — overall layout & field semantics.
//!   §3.1.2 FileSystemName  ("EXFAT   ", 8 bytes, offset 3).
//!   §3.1.3 MustBeZero      (53 bytes at offset 11 — must all be 0).
//!   §3.1.4 PartitionOffset (8 bytes, offset 64).
//!   §3.1.5 VolumeLength    (sectors).
//!   §3.1.6 FatOffset       (sector index of FAT).
//!   §3.1.7 FatLength       (sectors).
//!   §3.1.8 ClusterHeapOffset (sector index of cluster heap).
//!   §3.1.9 ClusterCount.
//!   §3.1.10 FirstClusterOfRootDirectory.
//!   §3.1.13 BytesPerSectorShift (5..=12 → 32..=4096 bytes).
//!   §3.1.14 SectorsPerClusterShift (0..=25-Bps → ≤32 MiB cluster).
//!   §3.1.15 NumberOfFats (1 or 2; TexFAT not in scope).
//!   <https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification>

/// On-disk Main Boot Sector — first 120 bytes of sector 0.
///
/// `#[repr(C, packed)]` because every offset is fixed by §3.1; we
/// `read_unaligned` from a heap-owned sector buffer, so no alignment
/// guarantees on the source.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ExfatBootSector {
    /// §3.1.1 — JumpBoot, 3 bytes (typically `0xEB 0x76 0x90`).
    pub jump_boot: [u8; 3],
    /// §3.1.2 — FileSystemName, exactly the 8 bytes `EXFAT   `.
    pub filesystem_name: [u8; 8],
    /// §3.1.3 — MustBeZero, 53 bytes (all zero — distinguishes
    /// exFAT from FAT12/16/32 where these bytes hold BPB fields).
    pub must_be_zero: [u8; 53],
    /// §3.1.4 — PartitionOffset, sector offset of the partition
    /// from the start of the containing media (informational).
    pub partition_offset: u64,
    /// §3.1.5 — VolumeLength, total sectors in the volume.
    pub volume_length: u64,
    /// §3.1.6 — FatOffset, sector index of the first FAT.
    pub fat_offset: u32,
    /// §3.1.7 — FatLength, sectors per FAT.
    pub fat_length: u32,
    /// §3.1.8 — ClusterHeapOffset, sector index of the cluster heap.
    pub cluster_heap_offset: u32,
    /// §3.1.9 — ClusterCount, number of clusters in the heap.
    pub cluster_count: u32,
    /// §3.1.10 — FirstClusterOfRootDirectory.
    pub first_cluster_of_root_directory: u32,
    /// §3.1.11 — VolumeSerialNumber.
    pub volume_serial_number: u32,
    /// §3.1.12 — FileSystemRevision (major in high byte).
    pub filesystem_revision: u16,
    /// §3.1.13 — VolumeFlags (bit 0 ActiveFat, bit 1 VolumeDirty,
    /// bit 2 MediaFailure, bit 3 ClearToZero).
    pub volume_flags: u16,
    /// §3.1.13 — BytesPerSectorShift (5..=12).
    pub bytes_per_sector_shift: u8,
    /// §3.1.14 — SectorsPerClusterShift (0..=(25 − Bps)).
    pub sectors_per_cluster_shift: u8,
    /// §3.1.15 — NumberOfFats (1 normally, 2 only for TexFAT).
    pub number_of_fats: u8,
    /// §3.1.16 — DriveSelect (BIOS INT 13h drive number).
    pub drive_select: u8,
    /// §3.1.17 — PercentInUse (0..=100, or 0xFF if unknown).
    pub percent_in_use: u8,
    /// §3.1 — Reserved, 7 bytes after PercentInUse.
    pub reserved: [u8; 7],
    // BootCode + BootSignature occupy the remainder of the sector
    // (§3.1.18 / §3.1.19) but we don't need them for mount; the
    // signature `0xAA55` lives at offset 510 and we check the bytes
    // directly out of the raw sector buffer.
}

/// Literal value of `FileSystemName` (§3.1.2) — exactly these 8 bytes.
pub const EXFAT_SIGNATURE: &[u8; 8] = b"EXFAT   ";

/// Trailing 16-bit signature at sector offset 510 (§3.1.19).
pub const BOOT_SIGNATURE: u16 = 0xAA55;

impl ExfatBootSector {
    /// Bytes per sector — §3.1.13 says the on-disk field is the
    /// `log2(BytesPerSector)`, with the spec-required range [5,12].
    pub fn bytes_per_sector(&self) -> u32 {
        1u32 << self.bytes_per_sector_shift
    }

    /// Sectors per cluster — §3.1.14 stores `log2(SectorsPerCluster)`.
    pub fn sectors_per_cluster(&self) -> u32 {
        1u32 << self.sectors_per_cluster_shift
    }

    /// Bytes per cluster — derived from the two shift fields per
    /// §3.1.13 + §3.1.14. The spec caps the product at 32 MiB.
    pub fn bytes_per_cluster(&self) -> u32 {
        1u32 << (self.bytes_per_sector_shift + self.sectors_per_cluster_shift)
    }

    /// True iff the boot sector's FileSystemName field (§3.1.2) is
    /// the exact literal `EXFAT   `. Any deviation → not an exFAT
    /// volume; refuse the mount.
    pub fn has_exfat_signature(&self) -> bool {
        self.filesystem_name == *EXFAT_SIGNATURE
    }

    /// Sanity-check the shift fields against the bounds the spec
    /// dictates (§3.1.13 + §3.1.14). Out-of-range values would let
    /// later math wrap or produce nonsense LBAs; refuse the mount
    /// rather than dereference garbage.
    pub fn shifts_in_range(&self) -> bool {
        let bps = self.bytes_per_sector_shift;
        let spc = self.sectors_per_cluster_shift;
        (5..=12).contains(&bps) && (bps + spc) <= 25
    }
}
