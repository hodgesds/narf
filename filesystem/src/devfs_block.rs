//! Block-device nodes for `/dev/`.
//!
//! # Design
//!
//! `BlockFile` wraps a `Arc<dyn BlockDeviceSync>` and implements
//! `FileOps`, translating byte-range reads/writes into LBA-aligned
//! I/O calls on the underlying driver.  Alignment is the caller's
//! responsibility: the `BlockDeviceSync` trait takes LBA addresses
//! and exact-multiple-of-lba_size byte slices, so `BlockFile` performs
//! a read-modify-write (RMW) for any partial first or last block.
//!
//! This is the same strategy used by `blkdev_direct_IO` (Linux
//! `fs/block_dev.c`) and `blk_rq_map_user` for unaligned transfers.
//! Linux reference: `fs/block_dev.c:blkdev_read_iter` /
//! `blkdev_write_iter` (v6.9) and the generic block helpers in
//! `block/bio.c`.
//!
//! # Permission model
//!
//! Block-device nodes default to mode `0o060660` (block-device type
//! bits | owner-rw | group-rw, world-none).  Owners are (0, 6) —
//! root:disk, matching the Linux convention (`udev` sets this at
//! hotplug time; we do it statically).
//!
//! `posix_access_ok` is the gate (see `filesystem/src/lib.rs`):
//! - UID 0 (root) always gets RW.
//! - GID 6 (disk) members get RW.
//! - Everyone else gets no access.
//!
//! The caller (`sys_open` in `userspace/src/handlers.rs`) is
//! responsible for running `posix_access_ok` before handing the
//! `Arc<dyn FileOps>` to user space.  `BlockFile` itself does NOT
//! re-check — it trusts the kernel open path.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::{registry::BlockDeviceSync, BlockError};

use crate::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

// ── BlockFile ─────────────────────────────────────────────────────────

/// A file node backed by a `BlockDeviceSync` device.
///
/// `start_lba` and `lba_count` bound the accessible range so the same
/// type works for whole disks AND partitions (the partition scanner
/// registers `nvme0p1` as a `BlockDeviceSync` whose own capacity
/// already reflects its partition bounds; callers may also set
/// `start_lba=0, lba_count=dev.capacity()` for whole-disk access).
pub struct BlockFile {
    pub dev: Arc<dyn BlockDeviceSync>,
    /// First accessible LBA (0 for whole-disk).
    pub start_lba: u64,
    /// Number of accessible LBAs.
    pub lba_count: u64,
    /// LBA size in bytes (512 typical, 4096 for NVMe 4Kn).
    pub block_size: u32,
    /// Low-9-bit POSIX permission word.  Default: 0o660 (root:disk).
    pub perms: u16,
    /// Linux device number (`st_rdev`). Registry-backed disks use block
    /// extended major 259 and a stable enumeration minor.
    pub rdev: u64,
}

impl core::fmt::Debug for BlockFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlockFile")
            .field("start_lba", &self.start_lba)
            .field("lba_count", &self.lba_count)
            .field("block_size", &self.block_size)
            .field("perms", &self.perms)
            .field("rdev", &self.rdev)
            .finish_non_exhaustive()
    }
}

impl BlockFile {
    /// Construct from a registered block device.
    pub fn from_dev(dev: Arc<dyn BlockDeviceSync>) -> Self {
        let block_size = dev.lba_size();
        let lba_count = dev.capacity();
        BlockFile {
            dev,
            start_lba: 0,
            lba_count,
            block_size,
            perms: 0o660,
            rdev: 0,
        }
    }

    /// Total byte capacity.
    #[inline]
    fn byte_capacity(&self) -> u64 {
        self.lba_count.saturating_mul(self.block_size as u64)
    }

    /// Map `BlockIoError` → `FsError`.
    #[inline]
    fn map_io(e: narf_block::registry::BlockIoError) -> FsError {
        use narf_block::registry::BlockIoError;
        match e {
            BlockIoError::OutOfRange => FsError::Io(BlockError::InvalidRange),
            BlockIoError::BufferTooSmall => FsError::Io(BlockError::InvalidRange),
            BlockIoError::DriverError => FsError::Io(BlockError::IOError),
            BlockIoError::DeviceRemoved => FsError::Io(BlockError::DeviceRemoved),
        }
    }

    /// Read `len` bytes starting at byte `offset` into `dst`.
    ///
    /// Handles:
    /// - aligned reads (fast path: no partial-block slicing)
    /// - unaligned start (partial first block via RMW read)
    /// - unaligned end (partial last block via RMW read)
    /// - multi-block spans
    fn read_sync(&self, offset: u64, dst: &mut [u8]) -> Result<usize, FsError> {
        let bs = self.block_size as u64;
        let capacity = self.byte_capacity();

        if offset >= capacity {
            return Ok(0); // EOF
        }

        // Clamp to available bytes.
        let avail = capacity - offset;
        let len = (dst.len() as u64).min(avail) as usize;
        if len == 0 {
            return Ok(0);
        }
        let dst = &mut dst[..len];

        // LBA of the first byte and byte-offset within that LBA.
        let first_lba_rel = offset / bs;
        let intra_first = (offset % bs) as usize;
        // LBA of the last byte (inclusive).
        let last_lba_rel = (offset + len as u64 - 1) / bs;
        // Count of LBAs to read.
        let n_lbas = (last_lba_rel - first_lba_rel + 1) as usize;

        // Absolute LBAs on the device.
        let abs_first_lba = self.start_lba + first_lba_rel;

        // Allocate a staging buffer exactly covering the needed LBAs.
        let stage_len = n_lbas * self.block_size as usize;
        let mut stage: Vec<u8> = alloc::vec![0u8; stage_len];

        let n_lbas_u16 = n_lbas as u16; // registry trait takes u16
        self.dev
            .read(abs_first_lba, n_lbas_u16, &mut stage)
            .map_err(Self::map_io)?;

        // Copy the slice the caller actually asked for.
        dst.copy_from_slice(&stage[intra_first..intra_first + len]);
        Ok(len)
    }

    /// Write `src` at byte `offset`.
    ///
    /// - Full-block writes go straight through (no read needed).
    /// - Partial first block: read the existing LBA, splice `src`,
    ///   write back.
    /// - Partial last block: same RMW if it's a different LBA from
    ///   the first.
    ///
    /// Linux analogy: `blkdev_write_iter` → `submit_bio` with
    /// partial-page handling in `__block_write_begin` (fs/buffer.c).
    fn write_sync(&self, offset: u64, src: &[u8]) -> Result<usize, FsError> {
        if src.is_empty() {
            return Ok(0);
        }
        let bs = self.block_size as u64;
        let capacity = self.byte_capacity();

        if offset >= capacity {
            return Err(FsError::Io(BlockError::InvalidRange));
        }
        // Clamp write length to device capacity.
        let avail = (capacity - offset) as usize;
        let len = src.len().min(avail);
        let src = &src[..len];

        let first_lba_rel = offset / bs;
        let intra_first = (offset % bs) as usize;
        let last_lba_rel = (offset + len as u64 - 1) / bs;
        let n_lbas = (last_lba_rel - first_lba_rel + 1) as usize;
        let abs_first_lba = self.start_lba + first_lba_rel;

        let stage_len = n_lbas * self.block_size as usize;
        let mut stage: Vec<u8> = alloc::vec![0u8; stage_len];

        // If the write is unaligned at start OR doesn't cover the
        // entire staging range, we must pre-read to preserve
        // surrounding bytes (RMW).
        let needs_rmw = intra_first != 0 || len < stage_len;
        if needs_rmw {
            self.dev
                .read(abs_first_lba, n_lbas as u16, &mut stage)
                .map_err(Self::map_io)?;
        }

        // Splice the caller's data into the staging buffer.
        stage[intra_first..intra_first + len].copy_from_slice(src);

        self.dev
            .write(abs_first_lba, n_lbas as u16, &stage)
            .map_err(Self::map_io)?;

        Ok(len)
    }
}

impl FileOps for BlockFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let result = self.read_sync(offset, buf);
        Box::pin(async move { result })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let result = self.write_sync(offset, buf);
        Box::pin(async move { result })
    }

    fn stat(&self) -> Stat {
        let size = self.byte_capacity();
        let bs = self.block_size as u64;
        let blocks = size.div_ceil(bs);
        Stat {
            size,
            blocks,
            // 0o060000 = block-device file type bits (S_IFBLK).
            // Combined with perms (0o660 default) → 0o060660.
            mode: Mode {
                file_type: FileType::Block,
                perms: self.perms,
            },
            mtime_cycles: 0,
        }
    }

    fn owners(&self) -> (u32, u32) {
        // root:disk (UID 0, GID 6) — matches Linux block-device
        // udev default (see udev rules in
        // /usr/lib/udev/rules.d/50-udev-default.rules).
        (0, 6)
    }

    fn rdev(&self) -> u64 {
        self.rdev
    }

    fn ino(&self) -> u64 {
        0xd002_0000_0000_0000 | self.rdev.wrapping_add(1)
    }

    fn poll_readiness(&self) -> u32 {
        // Block devices are always immediately ready for I/O from
        // the VFS perspective; the underlying driver may block
        // internally but that happens inside read_sync/write_sync.
        crate::POLL_IN | crate::POLL_OUT
    }
}

// ── lookup helper ─────────────────────────────────────────────────────

/// Attempt to resolve `name` as a registered block device, returning
/// a `BlockFile` if found.
///
/// Called from `DevDir::lookup` after the static table misses.
pub fn lookup_block_file(name: &str) -> Option<Arc<dyn FileOps>> {
    narf_block::find_block_device_indexed(name).map(|(minor, dev)| {
        let mut file = BlockFile::from_dev(dev);
        file.rdev = crate::devfs::linux_makedev(259, minor as u32);
        Arc::new(file) as Arc<dyn FileOps>
    })
}

/// All registered block devices as `(name, FileType::Block)` pairs.
///
/// Called from `DevDir::enumerate` after the static entries.
pub fn enumerate_block_devices() -> Vec<(alloc::string::String, FileType)> {
    narf_block::block_devices()
        .into_iter()
        .map(|r| (alloc::string::String::from(r.name), FileType::Block))
        .collect()
}

// ── /dev/disk/by-{label,partuuid} directories ────────────────────────

use crate::{DirEntry, DirOps};

/// `/dev/disk/` — a virtual directory with three subdirectories:
/// `by-label`, `by-uuid` (fs-uuid, unused for now, always empty),
/// and `by-partuuid`.
pub struct DevDiskDir;

impl core::fmt::Debug for DevDiskDir {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DevDiskDir")
    }
}

impl DirOps for DevDiskDir {
    fn ino(&self) -> u64 {
        10
    }
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let _ = name;
        None // all children are directories
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        match name {
            "by-label" => Some(Arc::new(DevDiskByLabel) as Arc<dyn DirOps>),
            "by-uuid" => Some(Arc::new(DevDiskByUuid) as Arc<dyn DirOps>),
            "by-partuuid" => Some(Arc::new(DevDiskByPartUuid) as Arc<dyn DirOps>),
            _ => None,
        }
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> crate::FsFuture<'a, Arc<dyn DirOps>> {
        let r = self.lookup_dir(name).ok_or(FsError::NotFound);
        Box::pin(async move { r })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        const ENTRIES: &[DirEntry] = &[
            DirEntry {
                name: "by-label",
                file_type: FileType::Dir,
            },
            DirEntry {
                name: "by-uuid",
                file_type: FileType::Dir,
            },
            DirEntry {
                name: "by-partuuid",
                file_type: FileType::Dir,
            },
        ];
        Box::new(ENTRIES.iter().copied())
    }
}

// ── by-label ─────────────────────────────────────────────────────────

/// `/dev/disk/by-label/` — lookup by GPT `partition_name` field.
pub struct DevDiskByLabel;

impl core::fmt::Debug for DevDiskByLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DevDiskByLabel")
    }
}

impl DirOps for DevDiskByLabel {
    fn ino(&self) -> u64 {
        11
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        narf_block::block_devices()
            .into_iter()
            .find(|r| {
                r.partition
                    .as_ref()
                    .map(|p| p.partlabel == name)
                    .unwrap_or(false)
            })
            .map(|r| crate::devfs::symlink_file(name, alloc::format!("../../{}", r.name)))
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Dynamic names can't satisfy `&'static str`; return empty
        // and rely on `enumerate()` for readdir.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(alloc::string::String, FileType)> {
        narf_block::block_devices()
            .into_iter()
            .filter_map(|r| {
                r.partition.and_then(|p| {
                    if p.partlabel.is_empty() {
                        None
                    } else {
                        Some(p.partlabel)
                    }
                })
            })
            .skip(cursor)
            .take(max)
            .map(|label| (label, FileType::Symlink))
            .collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> crate::FsFuture<'a, Vec<(alloc::string::String, FileType)>> {
        let v = self.enumerate(cursor, max);
        Box::pin(async move { Ok(v) })
    }
}

// ── by-uuid ───────────────────────────────────────────────────────────

/// `/dev/disk/by-uuid/` — filesystem UUID.
///
/// The block registry's `PartitionMetadata` carries `partuuid` (GPT
/// partition GUID) but not an FS-level UUID (that lives inside the
/// filesystem superblock, which the partition scanner doesn't read).
/// This directory is therefore always empty in NARF v1; the entry
/// exists so tooling that checks for its presence doesn't error.
pub struct DevDiskByUuid;

impl core::fmt::Debug for DevDiskByUuid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DevDiskByUuid")
    }
}

impl DirOps for DevDiskByUuid {
    fn ino(&self) -> u64 {
        12
    }
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }
}

// ── by-partuuid ───────────────────────────────────────────────────────

/// `/dev/disk/by-partuuid/` — lookup by GPT partition GUID.
pub struct DevDiskByPartUuid;

impl core::fmt::Debug for DevDiskByPartUuid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DevDiskByPartUuid")
    }
}

impl DirOps for DevDiskByPartUuid {
    fn ino(&self) -> u64 {
        13
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        narf_block::block_devices()
            .into_iter()
            .find(|r| {
                r.partition
                    .as_ref()
                    .map(|p| p.partuuid == name)
                    .unwrap_or(false)
            })
            .map(|r| crate::devfs::symlink_file(name, alloc::format!("../../{}", r.name)))
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(alloc::string::String, FileType)> {
        narf_block::block_devices()
            .into_iter()
            .filter_map(|r| {
                r.partition.and_then(|p| {
                    if p.partuuid.is_empty() {
                        None
                    } else {
                        Some(p.partuuid)
                    }
                })
            })
            .skip(cursor)
            .take(max)
            .map(|uuid| (uuid, FileType::Symlink))
            .collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> crate::FsFuture<'a, Vec<(alloc::string::String, FileType)>> {
        let v = self.enumerate(cursor, max);
        Box::pin(async move { Ok(v) })
    }
}
