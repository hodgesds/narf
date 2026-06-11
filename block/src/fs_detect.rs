//! Filesystem-type autodetection from on-disk superblock.
//!
//! Read the first few logical blocks of a block device and pattern-
//! match against known superblock signatures. Returns
//! `Option<FsType>` so the caller can pick the right filesystem
//! driver to attempt a mount with.
//!
//! Detection only — no driver instantiation. The block device is
//! borrowed; we read a handful of sectors and let go.
//!
//! Supported probes:
//!
//! - **ext2/3/4** — 16-bit magic `0xEF53` at byte 1080 (LBA 2 + 56
//!   for 512-byte LBAs; LBA 1 + 56 for 1024-byte LBAs). Subdivision
//!   into ext2 vs ext3 vs ext4 needs the feature_incompat flags
//!   we don't decode here — the caller picks the most-capable
//!   driver and lets it reject if the FS uses features it can't
//!   handle.
//! - **FAT12/16/32** — BPB at LBA 0. The "valid BPB" test mirrors
//!   the Microsoft FAT spec §3: bytes_per_sec is one of
//!   {512, 1024, 2048, 4096}, sec_per_clus is a power of two,
//!   num_fats is in {1, 2}, signature 0xAA55 at offset 510.
//! - **exFAT** — ASCII "EXFAT   " at offset 3 of LBA 0.
//! - **ISO 9660** — ASCII "CD001" at LBA 16 offset 1.
//! - **squashfs** — magic 0x73717368 ("hsqs" LE) at LBA 0 offset 0.
//! - **btrfs** — ASCII "_BHRfS_M" at byte 65600 (LBA 128 + 64 for
//!   512-byte LBAs).
//!
//! Unknown FS / unreadable device → `None`. Caller falls through
//! to the next partition or to a "no root FS" diagnostic.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;

use crate::registry::{BlockDeviceSync, BlockIoError};

/// Identified on-disk filesystem type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FsType {
    /// ext2 / ext3 / ext4 (distinguished by feature_incompat flags
    /// the driver inspects — autodetection just says "ext family").
    Ext,
    /// FAT12, FAT16, or FAT32 (distinguished by cluster count
    /// inside the driver per the Microsoft FAT spec §3).
    Fat,
    /// exFAT (Microsoft's flash-optimised FAT successor).
    ExFat,
    /// ISO 9660 (Rock Ridge / Joliet handled by the driver).
    Iso9660,
    /// SquashFS read-only compressed filesystem.
    SquashFs,
    /// btrfs.
    Btrfs,
}

impl FsType {
    /// Canonical name suitable for diagnostic logs / `mount -t` style
    /// callers.
    pub fn name(&self) -> &'static str {
        match self {
            FsType::Ext => "ext",
            FsType::Fat => "fat",
            FsType::ExFat => "exfat",
            FsType::Iso9660 => "iso9660",
            FsType::SquashFs => "squashfs",
            FsType::Btrfs => "btrfs",
        }
    }
}

/// Errors during detection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DetectError {
    /// Underlying block read failed.
    Io(BlockIoError),
    /// Device LBA size isn't supported (we expect 512, 1024, 2048, 4096).
    UnsupportedLbaSize(u32),
}

impl From<BlockIoError> for DetectError {
    fn from(e: BlockIoError) -> Self {
        DetectError::Io(e)
    }
}

/// Probe the device's superblocks and return the first match.
/// Order of probes is least → most expensive (LBA 0 reads cover
/// FAT / exFAT / squashfs; LBA 2-3 covers ext; LBA 16 covers
/// ISO9660; LBA 128 covers btrfs). The function returns at the
/// first hit so cheap matches don't pay for the deeper reads.
pub fn detect_filesystem(dev: &Arc<dyn BlockDeviceSync>) -> Result<Option<FsType>, DetectError> {
    let lba_size = dev.lba_size();
    if !matches!(lba_size, 512 | 1024 | 2048 | 4096) {
        return Err(DetectError::UnsupportedLbaSize(lba_size));
    }
    let mut lba0 = vec![0u8; lba_size as usize];
    dev.read(0, 1, &mut lba0)?;

    // LBA-0 probes first.
    if is_squashfs(&lba0) {
        return Ok(Some(FsType::SquashFs));
    }
    if is_exfat(&lba0) {
        return Ok(Some(FsType::ExFat));
    }
    if is_fat(&lba0) {
        return Ok(Some(FsType::Fat));
    }

    // ext: superblock at byte 1024. Read enough LBAs to cover it.
    let ext_byte_offset = 1024usize;
    let ext_magic_byte = ext_byte_offset + 56;
    let ext_first_lba = (ext_byte_offset / lba_size as usize) as u64;
    let ext_last_byte = ext_magic_byte + 2; // need 2 bytes for the magic
    let ext_lba_count = ext_last_byte.div_ceil(lba_size as usize) - ext_first_lba as usize;
    let mut ext_buf = vec![0u8; ext_lba_count * lba_size as usize];
    if dev
        .read(ext_first_lba, ext_lba_count as u16, &mut ext_buf)
        .is_ok()
    {
        let in_buf_off = ext_magic_byte - ext_first_lba as usize * lba_size as usize;
        if in_buf_off + 2 <= ext_buf.len() {
            let magic = u16::from_le_bytes([ext_buf[in_buf_off], ext_buf[in_buf_off + 1]]);
            if magic == 0xEF53 {
                return Ok(Some(FsType::Ext));
            }
        }
    }

    // ISO 9660: "CD001" at LBA 16 offset 1. Always 2048-byte LBAs
    // logically; for 512-byte block devices it lives at LBA 64.
    let iso_byte = 16 * 2048 + 1;
    let iso_lba = (iso_byte / lba_size as usize) as u64;
    let mut iso_buf = vec![0u8; lba_size as usize];
    if dev.capacity() > iso_lba && dev.read(iso_lba, 1, &mut iso_buf).is_ok() {
        let in_buf = iso_byte - iso_lba as usize * lba_size as usize;
        if in_buf + 5 <= iso_buf.len() && &iso_buf[in_buf..in_buf + 5] == b"CD001" {
            return Ok(Some(FsType::Iso9660));
        }
    }

    // btrfs: "_BHRfS_M" at byte 65600.
    let btrfs_byte = 65536 + 64;
    let btrfs_lba = (btrfs_byte / lba_size as usize) as u64;
    if dev.capacity() > btrfs_lba {
        let mut btrfs_buf = vec![0u8; lba_size as usize];
        if dev.read(btrfs_lba, 1, &mut btrfs_buf).is_ok() {
            let in_buf = btrfs_byte - btrfs_lba as usize * lba_size as usize;
            if in_buf + 8 <= btrfs_buf.len() && &btrfs_buf[in_buf..in_buf + 8] == b"_BHRfS_M" {
                return Ok(Some(FsType::Btrfs));
            }
        }
    }

    Ok(None)
}

// ── Per-FS magic-pattern helpers ───────────────────────────────────

fn is_squashfs(lba0: &[u8]) -> bool {
    // 'hsqs' little-endian = 0x73717368.
    lba0.len() >= 4 && lba0[0] == 0x68 && lba0[1] == 0x73 && lba0[2] == 0x71 && lba0[3] == 0x73
}

fn is_exfat(lba0: &[u8]) -> bool {
    // OEM name "EXFAT   " (8 bytes) at offset 3 of the boot sector.
    lba0.len() >= 11 && &lba0[3..11] == b"EXFAT   "
}

fn is_fat(lba0: &[u8]) -> bool {
    // Sanity-check a BPB. False positives are possible (the BPB
    // shares the boot sector with the MBR for unpartitioned disks),
    // so we err on the side of strictness:
    //   - bytes_per_sec (offset 11) ∈ {512, 1024, 2048, 4096}
    //   - sec_per_clus (offset 13) is a power of two, 1..=128
    //   - num_fats (offset 16) ∈ {1, 2}
    //   - signature at 510..512 == 0xAA55
    if lba0.len() < 512 {
        return false;
    }
    if u16::from_le_bytes([lba0[510], lba0[511]]) != 0xAA55 {
        return false;
    }
    let bytes_per_sec = u16::from_le_bytes([lba0[11], lba0[12]]);
    if !matches!(bytes_per_sec, 512 | 1024 | 2048 | 4096) {
        return false;
    }
    let sec_per_clus = lba0[13];
    if sec_per_clus == 0 || sec_per_clus & (sec_per_clus - 1) != 0 || sec_per_clus > 128 {
        return false;
    }
    let num_fats = lba0[16];
    if !matches!(num_fats, 1 | 2) {
        return false;
    }
    true
}
