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
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::{registry::BlockDeviceSync, BlockError};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

// ── persistent owner/mode overlay ─────────────────────────────────────
//
// A `BlockFile` is synthesised FRESH on every `/dev/<name>` lookup
// (`lookup_block_file`), so per-node attribute state can't live in the
// `BlockFile` struct — it would evaporate at the next lookup. udev's coldplug
// chowns/chmods each disk node (`root:disk 0660`, and distro-specific gids such
// as CachyOS's `gid=993`), and the new owner/mode MUST survive to the next
// `stat`, or the node keeps its default ownership and the chown/chmod "does
// nothing". Linux devtmpfs persists these on the real inode; NARF has no
// persistent inode here, so mirror the memfs per-node owner/mode model in a
// name-keyed overlay that outlives the transient node. Keyed by the block
// registry name, which is unique and stable across lookups.

/// Default block-node ownership: root:disk (uid 0, gid 6), matching the Linux
/// `50-udev-default.rules` convention before udev applies distro overrides.
const DEFAULT_UID: u32 = 0;
const DEFAULT_GID: u32 = 6;

#[derive(Copy, Clone)]
struct BlockNodeAttr {
    uid: u32,
    gid: u32,
    perms: u16,
}

static BLOCK_NODE_ATTRS: IrqSafeSpinLock<BTreeMap<String, BlockNodeAttr>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// Persisted owners for `name`, if a chown/chmod has ever touched it.
fn block_attr_owners(name: &str) -> Option<(u32, u32)> {
    BLOCK_NODE_ATTRS.lock().get(name).map(|a| (a.uid, a.gid))
}

/// Persisted permission bits for `name`, if a chown/chmod has ever touched it.
fn block_attr_perms(name: &str) -> Option<u16> {
    BLOCK_NODE_ATTRS.lock().get(name).map(|a| a.perms)
}

/// Persist new owners for `name`, preserving any previously-set mode bits.
/// `default_perms` seeds the entry the first time it is created.
fn block_attr_set_owners(name: &str, uid: u32, gid: u32, default_perms: u16) {
    let mut map = BLOCK_NODE_ATTRS.lock();
    let entry = map.entry(String::from(name)).or_insert(BlockNodeAttr {
        uid: DEFAULT_UID,
        gid: DEFAULT_GID,
        perms: default_perms & 0o7777,
    });
    entry.uid = uid;
    entry.gid = gid;
}

/// Persist new permission bits for `name`, preserving any previously-set owner.
fn block_attr_set_perms(name: &str, perms: u16) {
    let mut map = BLOCK_NODE_ATTRS.lock();
    let entry = map.entry(String::from(name)).or_insert(BlockNodeAttr {
        uid: DEFAULT_UID,
        gid: DEFAULT_GID,
        perms: 0,
    });
    entry.perms = perms & 0o7777;
}

/// Drop all persisted block-node attributes (test isolation).
#[doc(hidden)]
pub fn __reset_block_attrs_for_test() {
    BLOCK_NODE_ATTRS.lock().clear();
}

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
    /// Block-registry name (e.g. `"sata0"`, `"vblk0p2"`), the key under which
    /// chown/chmod persist in `BLOCK_NODE_ATTRS`. `None` for directly-
    /// constructed nodes (unit tests) that have no persistent `/dev` identity.
    pub name: Option<String>,
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
            name: None,
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
        // A persisted chmod (udev coldplug) overrides the default 0o660.
        let perms = self
            .name
            .as_deref()
            .and_then(block_attr_perms)
            .unwrap_or(self.perms);
        Stat {
            size,
            blocks,
            // 0o060000 = block-device file type bits (S_IFBLK).
            // Combined with perms (0o660 default) → 0o060660.
            mode: Mode {
                file_type: FileType::Block,
                perms,
            },
            mtime_cycles: 0,
        }
    }

    fn owners(&self) -> (u32, u32) {
        // Default root:disk (UID 0, GID 6) — matches Linux block-device udev
        // default (see /usr/lib/udev/rules.d/50-udev-default.rules) — unless a
        // chown has persisted a different owner for this node.
        self.name
            .as_deref()
            .and_then(block_attr_owners)
            .unwrap_or((DEFAULT_UID, DEFAULT_GID))
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        // Persist under the registry name so the new owner survives the next
        // `/dev/<name>` lookup (which builds a brand-new `BlockFile`). A node
        // with no persistent identity (direct construction) can't store this.
        let result = match self.name.as_deref() {
            Some(name) => {
                block_attr_set_owners(name, uid, gid, self.perms);
                Ok(())
            }
            None => Err(FsError::Unsupported),
        };
        Box::pin(async move { result })
    }

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        let result = match self.name.as_deref() {
            Some(name) => {
                block_attr_set_perms(name, perms);
                Ok(())
            }
            None => Err(FsError::Unsupported),
        };
        Box::pin(async move { result })
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
        // Carry the registry name so chown/chmod persist across lookups.
        file.name = Some(String::from(name));
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

// ── writable symlink overlays for /dev/disk/by-* ──────────────────────
//
// The `by-uuid` / `by-partuuid` / `by-label` directories synthesise their
// entries from block-registry partition metadata, so they are re-created fresh
// on every `lookup_dir` and hold no writable state of their own. But udev's
// coldplug computes the FILESYSTEM uuid/label (by probing partition contents,
// which the partition scanner never does) and creates the canonical
// `/dev/disk/by-uuid/<fs-uuid> -> ../../<dev>` symlink itself. Without a
// writable backing, that `symlinkat` fails and `udevadm settle` never
// completes. Give each directory a global symlink overlay (reusing the
// devtmpfs dynamic-node machinery) that outlives the transient dir object, so
// udev-created aliases persist, resolve on lookup, and appear in readdir
// alongside the synthesised entries.
static BY_UUID_LINKS: IrqSafeSpinLock<crate::devfs::DynamicMap> =
    IrqSafeSpinLock::new(BTreeMap::new());
static BY_PARTUUID_LINKS: IrqSafeSpinLock<crate::devfs::DynamicMap> =
    IrqSafeSpinLock::new(BTreeMap::new());
static BY_LABEL_LINKS: IrqSafeSpinLock<crate::devfs::DynamicMap> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// Drop all udev-created by-* symlinks (test isolation).
#[doc(hidden)]
pub fn __reset_disk_links_for_test() {
    BY_UUID_LINKS.lock().clear();
    BY_PARTUUID_LINKS.lock().clear();
    BY_LABEL_LINKS.lock().clear();
}

/// Create a udev symlink in a by-* overlay. `generated_exists` guards against
/// shadowing/duplicating a synthesised (partition-derived) entry, which
/// `symlink(2)` reports as `EEXIST` just like a re-create of an overlay entry.
fn disk_symlink<'a>(
    overlay: &'static IrqSafeSpinLock<crate::devfs::DynamicMap>,
    generated_exists: bool,
    name: &'a str,
    target: &'a str,
) -> FsFuture<'a, Arc<dyn FileOps>> {
    let result = if generated_exists {
        Err(FsError::Busy)
    } else {
        crate::devfs::dynamic_symlink(overlay, name, target)
    };
    Box::pin(async move { result })
}

/// `enumerate` for a by-* dir: the synthesised entries followed by any
/// udev-created overlay symlinks, then paginated by `cursor`/`max`.
fn disk_enumerate(
    mut generated: Vec<(String, FileType)>,
    overlay: &IrqSafeSpinLock<crate::devfs::DynamicMap>,
    cursor: usize,
    max: usize,
) -> Vec<(String, FileType)> {
    generated.extend(crate::devfs::dynamic_enumerate(overlay));
    generated.into_iter().skip(cursor).take(max).collect()
}

/// `/dev/disk/` — a virtual directory with three subdirectories:
/// `by-label`, `by-uuid` (filesystem UUID), and `by-partuuid`.
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
            // Then any udev-created label alias.
            .or_else(|| crate::devfs::dynamic_lookup_file(&BY_LABEL_LINKS, name))
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        let generated_exists = self.lookup_generated(name);
        disk_symlink(&BY_LABEL_LINKS, generated_exists, name, target)
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        let result = crate::devfs::dynamic_unlink(&BY_LABEL_LINKS, name);
        Box::pin(async move { result })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Dynamic names can't satisfy `&'static str`; return empty
        // and rely on `enumerate()` for readdir.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(alloc::string::String, FileType)> {
        let generated = narf_block::block_devices()
            .into_iter()
            .filter_map(|r| {
                r.partition.and_then(|p| {
                    if p.partlabel.is_empty() {
                        None
                    } else {
                        Some((p.partlabel, FileType::Symlink))
                    }
                })
            })
            .collect();
        disk_enumerate(generated, &BY_LABEL_LINKS, cursor, max)
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

impl DevDiskByLabel {
    /// Whether a synthesised (partition-derived) label entry named `name`
    /// exists — the shadow guard for `symlink`.
    fn lookup_generated(&self, name: &str) -> bool {
        narf_block::block_devices().into_iter().any(|r| {
            r.partition
                .as_ref()
                .map(|p| p.partlabel == name)
                .unwrap_or(false)
        })
    }
}

// ── by-uuid ───────────────────────────────────────────────────────────

/// `/dev/disk/by-uuid/` — filesystem UUID.
///
/// Synthesised from each partition's filesystem UUID, plus any
/// udev-created aliases in the writable overlay.
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
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        narf_block::block_devices()
            .into_iter()
            .find(|r| {
                r.partition
                    .as_ref()
                    .map(|p| !p.fs_uuid.is_empty() && p.fs_uuid.eq_ignore_ascii_case(name))
                    .unwrap_or(false)
            })
            .map(|r| crate::devfs::symlink_file(name, alloc::format!("../../{}", r.name)))
            // Then any udev-created uuid alias.
            .or_else(|| crate::devfs::dynamic_lookup_file(&BY_UUID_LINKS, name))
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        let generated_exists = self.lookup_generated(name);
        disk_symlink(&BY_UUID_LINKS, generated_exists, name, target)
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        let result = crate::devfs::dynamic_unlink(&BY_UUID_LINKS, name);
        Box::pin(async move { result })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(alloc::string::String, FileType)> {
        let generated = narf_block::block_devices()
            .into_iter()
            .filter_map(|r| {
                r.partition.and_then(|p| {
                    if p.fs_uuid.is_empty() {
                        None
                    } else {
                        Some((p.fs_uuid, FileType::Symlink))
                    }
                })
            })
            .collect();
        disk_enumerate(generated, &BY_UUID_LINKS, cursor, max)
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

impl DevDiskByUuid {
    /// Whether a synthesised (partition-derived) uuid entry named `name`
    /// exists — the shadow guard for `symlink`.
    fn lookup_generated(&self, name: &str) -> bool {
        narf_block::block_devices().into_iter().any(|r| {
            r.partition
                .as_ref()
                .map(|p| !p.fs_uuid.is_empty() && p.fs_uuid.eq_ignore_ascii_case(name))
                .unwrap_or(false)
        })
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
            // Then any udev-created partuuid alias.
            .or_else(|| crate::devfs::dynamic_lookup_file(&BY_PARTUUID_LINKS, name))
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        let generated_exists = self.lookup_generated(name);
        disk_symlink(&BY_PARTUUID_LINKS, generated_exists, name, target)
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        let result = crate::devfs::dynamic_unlink(&BY_PARTUUID_LINKS, name);
        Box::pin(async move { result })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(alloc::string::String, FileType)> {
        let generated = narf_block::block_devices()
            .into_iter()
            .filter_map(|r| {
                r.partition.and_then(|p| {
                    if p.partuuid.is_empty() {
                        None
                    } else {
                        Some((p.partuuid, FileType::Symlink))
                    }
                })
            })
            .collect();
        disk_enumerate(generated, &BY_PARTUUID_LINKS, cursor, max)
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

impl DevDiskByPartUuid {
    /// Whether a synthesised (partition-derived) partuuid entry named `name`
    /// exists — the shadow guard for `symlink`.
    fn lookup_generated(&self, name: &str) -> bool {
        narf_block::block_devices().into_iter().any(|r| {
            r.partition
                .as_ref()
                .map(|p| p.partuuid == name)
                .unwrap_or(false)
        })
    }
}
