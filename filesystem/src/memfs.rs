//! `MemFs` — an in-memory read/write filesystem with hierarchy.
//!
//! Stage-4 surface for exercising the mutable [`DirOps`] paths
//! (`unlink`, `create`, `mkdir`, `rmdir`, `rename`, `symlink`).
//! Designed for the `/tmp` mount in the validate harness — small
//! files, nested directories, no persistence. Concurrency: a single
//! `IrqSafeSpinLock` per directory over the entry map; mutations are
//! serialised through it. The validate harness is single-threaded so
//! this is uncontended.
//!
//! Layout: each directory owns a `BTreeMap<String, Entry>` of refcounted
//! files, directories, links, FIFOs, and special nodes. `MemFile` carries a
//! sparse page map behind an IRQ-safe lock, so concurrent readers/writers see
//! a consistent logical length and contents without sparse truncates allocating
//! physical storage. `MemSymlink` stores its target as an immutable `String`
//! and exposes the bytes via `FileOps::read`; writes return
//! `ReadOnly`. `unlink` removes the entry from the parent map but
//! keeps the file's `Arc` alive for any outstanding fd holders —
//! the bytes go away when the last fd drops, matching POSIX
//! semantics. `rmdir` rejects non-empty directories (POSIX
//! EEXIST→`Busy`).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, FsStat, Mode, Stat,
};

const PAGE_SIZE: u64 = 4096;
const SECTORS_PER_PAGE: u64 = PAGE_SIZE / 512;

/// Linux tmpfs mount configuration.
///
/// Limits use 4-KiB pages/inodes. `None` is Linux's explicit unlimited value
/// (`size=0`, `nr_blocks=0`, or `nr_inodes=0`). The ordinary default is half
/// of allocator-managed RAM, matching `shmem_default_max_blocks()` and
/// `shmem_default_max_inodes()` in Linux `mm/shmem.c`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TmpFsOptions {
    pub max_blocks: Option<u64>,
    pub max_inodes: Option<u64>,
    pub root_mode: u16,
    pub root_uid: u32,
    pub root_gid: u32,
    pub noswap: bool,
    pub inode64: bool,
}

impl TmpFsOptions {
    pub fn defaults(total_pages: u64, uid: u32, gid: u32) -> Self {
        let half = total_pages / 2;
        Self {
            max_blocks: (half != 0).then_some(half),
            max_inodes: (half != 0).then_some(half),
            root_mode: 0o1777,
            root_uid: uid,
            root_gid: gid,
            // NARF has no swap-backed shmem path. All tmpfs mounts therefore
            // have Linux's noswap behavior even when the option is omitted.
            noswap: true,
            inode64: true,
        }
    }

    /// Parse Linux's tmpfs mount options against an explicit RAM-page total.
    /// The explicit total keeps unit/kernel tests deterministic; mounted
    /// instances use NARF's live frame total through [`TmpFs::from_options`].
    pub fn parse(options: &str, total_pages: u64, uid: u32, gid: u32) -> Result<Self, FsError> {
        let mut parsed = Self::defaults(total_pages, uid, gid);
        apply_tmpfs_options(&mut parsed, options, total_pages)?;
        Ok(parsed)
    }
}

/// Linux ramfs accepts `mode=` and historically ignores every other mount
/// option. It has no block or inode limits and cannot be resized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RamFsOptions {
    pub root_mode: u16,
    pub root_uid: u32,
    pub root_gid: u32,
}

impl RamFsOptions {
    pub fn parse(options: &str, uid: u32, gid: u32) -> Result<Self, FsError> {
        let mut parsed = Self {
            root_mode: 0o755,
            root_uid: uid,
            root_gid: gid,
        };
        for raw in options.split(',').filter(|part| !part.is_empty()) {
            let (key, value) = raw.split_once('=').unwrap_or((raw, ""));
            if key == "mode" {
                parsed.root_mode = parse_octal_mode(value)?;
            }
            // Linux ramfs intentionally ignores unknown parameters for
            // compatibility with its historical tmpfs-fallback role.
        }
        Ok(parsed)
    }
}

fn parse_octal_mode(value: &str) -> Result<u16, FsError> {
    let value = value.strip_prefix("0o").unwrap_or(value);
    let mode = u16::from_str_radix(value, 8).map_err(|_| FsError::InvalidData)?;
    (mode <= 0o7777).then_some(mode).ok_or(FsError::InvalidData)
}

fn parse_u64(value: &str) -> Result<u64, FsError> {
    value.parse::<u64>().map_err(|_| FsError::InvalidData)
}

fn parse_memparse(value: &str) -> Result<u64, FsError> {
    if value.is_empty() {
        return Err(FsError::InvalidData);
    }
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let base = parse_u64(&value[..split])?;
    let suffix = &value[split..];
    let power = match suffix {
        "" => 0,
        "k" | "K" | "kB" | "KB" => 1,
        "m" | "M" | "mB" | "MB" => 2,
        "g" | "G" | "gB" | "GB" => 3,
        "t" | "T" | "tB" | "TB" => 4,
        "p" | "P" | "pB" | "PB" => 5,
        "e" | "E" | "eB" | "EB" => 6,
        _ => return Err(FsError::InvalidData),
    };
    let mut scaled = base;
    for _ in 0..power {
        scaled = scaled.checked_mul(1024).ok_or(FsError::InvalidData)?;
    }
    Ok(scaled)
}

fn apply_tmpfs_options(
    parsed: &mut TmpFsOptions,
    options: &str,
    total_pages: u64,
) -> Result<(), FsError> {
    for raw in options.split(',').filter(|part| !part.is_empty()) {
        let (key, value) = raw.split_once('=').unwrap_or((raw, ""));
        match key {
            "size" => {
                let blocks = if let Some(percent) = value.strip_suffix('%') {
                    let percent = parse_u64(percent)?;
                    if percent > 100 {
                        return Err(FsError::InvalidData);
                    }
                    total_pages
                        .checked_mul(percent)
                        .ok_or(FsError::InvalidData)?
                        / 100
                } else {
                    parse_memparse(value)?.div_ceil(PAGE_SIZE)
                };
                parsed.max_blocks = (blocks != 0).then_some(blocks);
            }
            "nr_blocks" => {
                let blocks = parse_memparse(value)?;
                parsed.max_blocks = (blocks != 0).then_some(blocks);
            }
            "nr_inodes" => {
                let inodes = parse_memparse(value)?;
                parsed.max_inodes = (inodes != 0).then_some(inodes);
            }
            "mode" => parsed.root_mode = parse_octal_mode(value)?,
            "uid" => {
                parsed.root_uid = value.parse::<u32>().map_err(|_| FsError::InvalidData)?;
            }
            "gid" => {
                parsed.root_gid = value.parse::<u32>().map_err(|_| FsError::InvalidData)?;
            }
            "noswap" if value.is_empty() => parsed.noswap = true,
            "inode64" if value.is_empty() => parsed.inode64 = true,
            "inode32" if value.is_empty() => parsed.inode64 = false,
            // NARF advertises THP as disabled. Accepting another policy would
            // make the mount option lie about allocation behavior.
            "huge" if value == "never" => {}
            // Heap allocation follows the caller/default policy. These two
            // spellings therefore describe existing behavior; node-list
            // policies require page-backed tmpfs and are rejected.
            "mpol" if value == "default" || value == "local" => {}
            _ => return Err(FsError::InvalidData),
        }
    }
    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MemFsKind {
    Generic,
    Tmpfs,
    Ramfs,
}

#[derive(Debug)]
struct SuperState {
    max_blocks: Option<u64>,
    used_blocks: u64,
    max_inodes: Option<u64>,
    used_inodes: u64,
}

#[derive(Debug)]
struct MemSuper {
    kind: MemFsKind,
    state: IrqSafeSpinLock<SuperState>,
}

impl MemSuper {
    fn new(kind: MemFsKind, max_blocks: Option<u64>, max_inodes: Option<u64>) -> Arc<Self> {
        Arc::new(Self {
            kind,
            state: IrqSafeSpinLock::new(SuperState {
                max_blocks,
                used_blocks: 0,
                max_inodes,
                used_inodes: 0,
            }),
        })
    }

    fn reserve_blocks(&self, blocks: u64) -> Result<(), FsError> {
        let mut state = self.state.lock();
        let new = state
            .used_blocks
            .checked_add(blocks)
            .ok_or(FsError::NoSpace)?;
        if state.max_blocks.is_some_and(|limit| new > limit) {
            return Err(FsError::NoSpace);
        }
        state.used_blocks = new;
        Ok(())
    }

    fn release_blocks(&self, blocks: u64) {
        let mut state = self.state.lock();
        state.used_blocks = state.used_blocks.saturating_sub(blocks);
    }

    fn reserve_inode(self: &Arc<Self>) -> Result<InodeLease, FsError> {
        let mut state = self.state.lock();
        let new = state.used_inodes.checked_add(1).ok_or(FsError::NoSpace)?;
        if state.max_inodes.is_some_and(|limit| new > limit) {
            return Err(FsError::NoSpace);
        }
        state.used_inodes = new;
        Ok(InodeLease {
            superblock: Arc::clone(self),
        })
    }

    fn statfs(&self) -> FsStat {
        let state = self.state.lock();
        let (blocks, blocks_free) = match state.max_blocks {
            Some(max) => (max, max.saturating_sub(state.used_blocks)),
            None => (0, 0),
        };
        let (files, files_free) = match state.max_inodes {
            Some(max) => (max, max.saturating_sub(state.used_inodes)),
            None => (0, 0),
        };
        FsStat {
            blocks,
            blocks_free,
            blocks_available: blocks_free,
            files,
            files_free,
            block_size: PAGE_SIZE as u32,
            name_len: 255,
            fragment_size: PAGE_SIZE as u32,
        }
    }

    fn reconfigure_tmpfs(&self, options: &str, total_pages: u64) -> Result<(), FsError> {
        if self.kind != MemFsKind::Tmpfs {
            return Err(FsError::Unsupported);
        }
        let mut requested_blocks = None;
        let mut requested_inodes = None;
        for raw in options.split(',').filter(|part| !part.is_empty()) {
            let (key, value) = raw.split_once('=').unwrap_or((raw, ""));
            match key {
                "size" => {
                    let blocks = if let Some(percent) = value.strip_suffix('%') {
                        let percent = parse_u64(percent)?;
                        if percent > 100 {
                            return Err(FsError::InvalidData);
                        }
                        total_pages
                            .checked_mul(percent)
                            .ok_or(FsError::InvalidData)?
                            / 100
                    } else {
                        parse_memparse(value)?.div_ceil(PAGE_SIZE)
                    };
                    requested_blocks = Some((blocks != 0).then_some(blocks));
                }
                "nr_blocks" => {
                    let blocks = parse_memparse(value)?;
                    requested_blocks = Some((blocks != 0).then_some(blocks));
                }
                "nr_inodes" => {
                    let inodes = parse_memparse(value)?;
                    requested_inodes = Some((inodes != 0).then_some(inodes));
                }
                // Linux ignores root metadata on remount. The remaining
                // accepted initial-only policies are validated here too.
                "mode" => {
                    let _ = parse_octal_mode(value)?;
                }
                "uid" | "gid" => {
                    let _ = value.parse::<u32>().map_err(|_| FsError::InvalidData)?;
                }
                "noswap" | "inode64" | "inode32" if value.is_empty() => {}
                "huge" if value == "never" => {}
                "mpol" if value == "default" || value == "local" => {}
                _ => return Err(FsError::InvalidData),
            }
        }
        let mut state = self.state.lock();
        if let Some(new) = requested_blocks {
            if state.max_blocks.is_none() && new.is_some() {
                return Err(FsError::InvalidData);
            }
            if new.is_some_and(|limit| state.used_blocks > limit) {
                return Err(FsError::NoSpace);
            }
            state.max_blocks = new;
        }
        if let Some(new) = requested_inodes {
            if state.max_inodes.is_none() && new.is_some() {
                return Err(FsError::InvalidData);
            }
            if new.is_some_and(|limit| state.used_inodes > limit) {
                return Err(FsError::NoSpace);
            }
            state.max_inodes = new;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct InodeLease {
    superblock: Arc<MemSuper>,
}

impl Drop for InodeLease {
    fn drop(&mut self) {
        let mut state = self.superblock.state.lock();
        state.used_inodes = state.used_inodes.saturating_sub(1);
    }
}

/// Default permission bits for a freshly minted `MemFile`: 0o666
/// (rw-rw-rw-), owned by root (0, 0). This preserves the historical
/// "root-can-do-anything, everyone has rw" behaviour so DAC enforcement
/// only bites when a file is explicitly minted with tighter perms.
const DEFAULT_PERMS: u16 = 0o666;

/// Monotonic inode allocator for in-memory nodes. Every `MemFile` /
/// `MemDir` / `MemSymlink` claims a unique, stable `st_ino` at
/// construction so distinct nodes never alias. This is load-bearing for
/// more than musl's DSO dedup: systemd's `rm_rf` refuses to descend when
/// a directory and its parent share `(st_dev, st_ino)` (its "you've hit a
/// filesystem root" guard). Previously every tmpfs node reported `ino 0`
/// (the size-0/mtime-0 synthetic fallback for directories), so every
/// `mkdir`-created temp subdir looked like `/` and systemd aborted with
/// "Attempted to remove entire root file system". The base is deliberately
/// high because NARF reports `st_dev = 0` for every mount, so a low base
/// would collide with ext2's small inode numbers (root = 2).
static NEXT_INO: AtomicU64 = AtomicU64::new(0x1000_0000);

/// Claim the next unique in-memory inode number.
fn alloc_ino() -> u64 {
    NEXT_INO.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Default)]
struct FileData {
    len: u64,
    pages: BTreeMap<u64, Box<[u8]>>,
}

impl FileData {
    fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        if offset >= self.len {
            return 0;
        }
        let available = self.len - offset;
        let count = core::cmp::min(buf.len() as u64, available) as usize;
        buf[..count].fill(0);
        let mut copied = 0;
        while copied < count {
            let absolute = offset + copied as u64;
            let index = absolute / PAGE_SIZE;
            let within = (absolute % PAGE_SIZE) as usize;
            let chunk = core::cmp::min(count - copied, PAGE_SIZE as usize - within);
            if let Some(page) = self.pages.get(&index) {
                buf[copied..copied + chunk].copy_from_slice(&page[within..within + chunk]);
            }
            copied += chunk;
        }
        count
    }

    fn missing_pages(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let end = offset
            .checked_add(len as u64)
            .and_then(|value| value.checked_sub(1))
            .ok_or(FsError::NoSpace)?;
        let first = offset / PAGE_SIZE;
        let last = end / PAGE_SIZE;
        Ok((first..=last)
            .filter(|index| !self.pages.contains_key(index))
            .collect())
    }

    fn remove_pages_from(&mut self, first: u64) -> u64 {
        let old = core::mem::take(&mut self.pages);
        let mut removed = 0;
        for (index, page) in old {
            if index >= first {
                removed += 1;
            } else {
                self.pages.insert(index, page);
            }
        }
        removed
    }
}

/// In-memory file: a sparse, page-indexed byte buffer behind a lock, plus
/// per-node DAC metadata (low-9 permission bits + owner uid/gid).
struct MemFile {
    /// Unique, stable inode number (see [`NEXT_INO`]). Immutable after
    /// construction — a plain `u64`, not an atomic, per the per-node
    /// heap-cost note on the metadata fields below.
    ino: u64,
    data: IrqSafeSpinLock<FileData>,
    _inode_lease: InodeLease,
    /// DAC metadata as lock-free atomics — kept deliberately small: a
    /// MemFs node is created for every file in the kernel-test suite, so
    /// three spinlocks here (vs three `AtomicU32`) measurably grew the
    /// suite's heap footprint and tipped its margin. `perms` holds the
    /// low-9 rwxrwxrwx bits; `uid`/`gid` the owner. Relaxed ordering is
    /// fine — this is independent metadata, not a synchronisation point.
    perms: AtomicU32,
    uid: AtomicU32,
    gid: AtomicU32,
    /// Modification time as wall-clock nanoseconds since the epoch; 0 =
    /// "never stamped" (stat then reports mtime_cycles 0, the pre-mtime
    /// behavior). One more 8-byte atomic per node — deliberately NOT a
    /// lock, per the heap-margin note above. Stamped by `write` and set
    /// explicitly through `FileOps::set_times` (utimensat/utime/utimes).
    mtime_ns: AtomicU64,
    /// True when this node is a bound AF_UNIX socket (created by `bind()`
    /// on a pathname address). `stat`/`enumerate` then report S_IFSOCK so
    /// `stat`/`[ -S ]`/`ls -l`/`unlink` on the socket path behave like
    /// Linux (a pathname socket is a real filesystem inode). Immutable
    /// after creation — a plain `bool`, not an atomic, to stay off the
    /// per-node heap-cost path the atomics above were chosen for.
    sock: bool,
    xattrs: IrqSafeSpinLock<BTreeMap<String, Vec<u8>>>,
}

impl MemFile {
    /// Mint a `MemFile` with default perms (0o666) and owner (0, 0).
    fn new(superblock: &Arc<MemSuper>, bytes: &[u8]) -> Result<Self, FsError> {
        let inode_lease = superblock.reserve_inode()?;
        let file = MemFile {
            ino: alloc_ino(),
            data: IrqSafeSpinLock::new(FileData::default()),
            _inode_lease: inode_lease,
            perms: AtomicU32::new(DEFAULT_PERMS as u32),
            uid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            mtime_ns: AtomicU64::new(0),
            sock: false,
            xattrs: IrqSafeSpinLock::new(BTreeMap::new()),
        };
        if !bytes.is_empty() {
            file.write_inner(0, bytes)?;
        }
        Ok(file)
    }

    /// Mint a `MemFile` with explicit perms + owner. Used to seed files
    /// that must enforce a real DAC boundary (e.g. /etc/shadow 0600).
    fn with_perms_owner(bytes: Vec<u8>, perms: u16, uid: u32, gid: u32) -> Self {
        let superblock = MemSuper::new(MemFsKind::Generic, None, None);
        let file = MemFile {
            ino: alloc_ino(),
            data: IrqSafeSpinLock::new(FileData::default()),
            _inode_lease: superblock
                .reserve_inode()
                .expect("unlimited memfs inode reservation"),
            perms: AtomicU32::new((perms & 0o7777) as u32),
            uid: AtomicU32::new(uid),
            gid: AtomicU32::new(gid),
            mtime_ns: AtomicU64::new(0),
            sock: false,
            xattrs: IrqSafeSpinLock::new(BTreeMap::new()),
        };
        file.write_inner(0, &bytes)
            .expect("unlimited memfs seed write");
        file
    }

    /// Mint a pathname-AF_UNIX-socket node (S_IFSOCK) with the given perms.
    fn new_socket(superblock: &Arc<MemSuper>, perms: u16) -> Result<Self, FsError> {
        Ok(MemFile {
            ino: alloc_ino(),
            data: IrqSafeSpinLock::new(FileData::default()),
            _inode_lease: superblock.reserve_inode()?,
            perms: AtomicU32::new((perms & 0o7777) as u32),
            uid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            mtime_ns: AtomicU64::new(0),
            sock: true,
            xattrs: IrqSafeSpinLock::new(BTreeMap::new()),
        })
    }

    /// Stamp mtime = wall-now. Called on every successful write so
    /// `make`-style newer-than comparisons see fresh build outputs as
    /// newer than their sources.
    fn touch_mtime_now(&self) {
        let w = narf_time::now_wall();
        let ns = (w.secs.max(0) as u64).saturating_mul(1_000_000_000) + w.nanos as u64;
        self.mtime_ns.store(ns, Ordering::Relaxed);
    }

    fn alloc_zero_page() -> Result<Box<[u8]>, FsError> {
        let mut page = Vec::new();
        page.try_reserve_exact(PAGE_SIZE as usize)
            .map_err(|_| FsError::NoSpace)?;
        page.resize(PAGE_SIZE as usize, 0);
        Ok(page.into_boxed_slice())
    }

    fn write_inner(&self, offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(FsError::NoSpace)?;
        let mut data = self.data.lock();
        let missing = data.missing_pages(offset, buf.len())?;
        let count = missing.len() as u64;
        self._inode_lease.superblock.reserve_blocks(count)?;
        let mut allocated = Vec::new();
        if allocated.try_reserve_exact(missing.len()).is_err() {
            self._inode_lease.superblock.release_blocks(count);
            return Err(FsError::NoSpace);
        }
        for index in missing {
            match Self::alloc_zero_page() {
                Ok(page) => allocated.push((index, page)),
                Err(error) => {
                    self._inode_lease.superblock.release_blocks(count);
                    return Err(error);
                }
            }
        }
        for (index, page) in allocated {
            data.pages.insert(index, page);
        }
        let mut copied = 0;
        while copied < buf.len() {
            let absolute = offset + copied as u64;
            let index = absolute / PAGE_SIZE;
            let within = (absolute % PAGE_SIZE) as usize;
            let chunk = core::cmp::min(buf.len() - copied, PAGE_SIZE as usize - within);
            let page = data
                .pages
                .get_mut(&index)
                .expect("write reserved every missing page");
            page[within..within + chunk].copy_from_slice(&buf[copied..copied + chunk]);
            copied += chunk;
        }
        data.len = core::cmp::max(data.len, end);
        drop(data);
        self.touch_mtime_now();
        Ok(buf.len())
    }

    fn punch_hole(&self, offset: u64, len: u64) -> Result<(), FsError> {
        let end = offset.checked_add(len).ok_or(FsError::InvalidData)?;
        let mut data = self.data.lock();
        let indexes: Vec<u64> = data
            .pages
            .range((offset / PAGE_SIZE)..end.div_ceil(PAGE_SIZE))
            .map(|(&index, _)| index)
            .collect();
        let mut released = 0;
        for index in indexes {
            let page_start = index * PAGE_SIZE;
            let page_end = page_start + PAGE_SIZE;
            if offset <= page_start && end >= page_end {
                data.pages.remove(&index);
                released += 1;
            } else if let Some(page) = data.pages.get_mut(&index) {
                let start = offset.saturating_sub(page_start) as usize;
                let stop = core::cmp::min(end.saturating_sub(page_start), PAGE_SIZE) as usize;
                if start < stop {
                    page[start..stop].fill(0);
                }
            }
        }
        drop(data);
        self._inode_lease.superblock.release_blocks(released);
        Ok(())
    }
}

impl Drop for MemFile {
    fn drop(&mut self) {
        let blocks = self.data.lock().pages.len() as u64;
        self._inode_lease.superblock.release_blocks(blocks);
    }
}

/// Mint a fresh empty in-memory file outside any directory. The
/// returned `FileOps` handle owns the storage; dropping the last
/// reference frees the bytes. Used by `sys_memfd_create` so an
/// anonymous fd can back a real `MemFile` without occupying a
/// VFS path.
pub fn new_anon_file() -> Arc<dyn FileOps> {
    let superblock = MemSuper::new(MemFsKind::Generic, None, None);
    Arc::new(MemFile::new(&superblock, &[]).expect("unlimited anonymous memfile"))
}

/// Mint a standalone in-memory file with explicit DAC metadata (initial
/// contents + low-9 perm bits + owner uid/gid). The returned `FileOps`
/// handle enforces those perms via `stat()`/`owners()`. Used by the DAC
/// kernel tests to construct a 0600 root-owned file (or a 0o666 world-rw
/// file) without going through a mounted FS.
pub fn new_file_with_perms_owner(
    bytes: Vec<u8>,
    perms: u16,
    uid: u32,
    gid: u32,
) -> Arc<dyn FileOps> {
    Arc::new(MemFile::with_perms_owner(bytes, perms, uid, gid))
}

impl fmt::Debug for MemFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemFile")
            .field("len", &self.data.lock().len)
            .finish_non_exhaustive()
    }
}

impl FileOps for MemFile {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(self.data.lock().read(offset, buf)) })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { self.write_inner(offset, buf) })
    }

    fn set_times(&self, _atime_ns: Option<u64>, mtime_ns: Option<u64>) -> Result<(), FsError> {
        // atime is accepted and dropped (NARF tracks no access times —
        // the relatime spirit); mtime round-trips through `stat`.
        if let Some(ns) = mtime_ns {
            self.mtime_ns.store(ns, Ordering::Relaxed);
        }
        Ok(())
    }

    fn stat(&self) -> Stat {
        let data = self.data.lock();
        Stat {
            size: data.len,
            blocks: data.pages.len() as u64 * SECTORS_PER_PAGE,
            mode: Mode {
                file_type: if self.sock {
                    FileType::Socket
                } else {
                    FileType::File
                },
                perms: (self.perms.load(Ordering::Relaxed) & 0o7777) as u16,
            },
            // Report wall-ns as cycles so the stat ABI's cycles→ns
            // conversion (`stat_linux`: `cycles_to_ns(mtime_cycles)`)
            // hands userspace back the exact epoch-ns that utimensat /
            // the last write stored — the tar -x / cp -p / make
            // round-trip. 0 (never stamped) stays 0.
            //
            // `ns_to_cycles` is the exact inverse of the `cycles_to_ns`
            // the stat path applies, so the round-trip is lossless. The
            // old pair was `* cycles_per_ns()` here and `/ cycles_per_ns()`
            // there — self-cancelling ONLY because both were the same
            // truncated integer, which stopped being true the moment
            // either side moved to the calibrated scale.
            mtime_cycles: narf_time::ns_to_cycles(self.mtime_ns.load(Ordering::Relaxed)),
        }
    }

    fn owners(&self) -> (u32, u32) {
        (
            self.uid.load(Ordering::Relaxed),
            self.gid.load(Ordering::Relaxed),
        )
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.uid.store(uid, Ordering::Relaxed);
            self.gid.store(gid, Ordering::Relaxed);
            self.perms.fetch_and(!0o6000, Ordering::Relaxed);
            Ok(())
        })
    }

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.perms.store((perms & 0o7777) as u32, Ordering::Relaxed);
            Ok(())
        })
    }

    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut data = self.data.lock();
            if len < data.len {
                let first_removed = len.div_ceil(PAGE_SIZE);
                let released = data.remove_pages_from(first_removed);
                if len % PAGE_SIZE != 0 {
                    if let Some(page) = data.pages.get_mut(&(len / PAGE_SIZE)) {
                        page[(len % PAGE_SIZE) as usize..].fill(0);
                    }
                }
                self._inode_lease.superblock.release_blocks(released);
            }
            // Extending a tmpfs file creates a hole. No page/block is charged
            // until a write or fallocate materialises it.
            data.len = len;
            drop(data);
            self.touch_mtime_now();
            Ok(())
        })
    }

    fn set_xattr<'a>(&'a self, name: &'a str, value: &'a [u8], flags: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            if !(name.starts_with("user.")
                || name.starts_with("trusted.")
                || name.starts_with("security."))
                || name.len() > 255
            {
                return Err(FsError::InvalidData);
            }
            const XATTR_CREATE: u32 = 1;
            const XATTR_REPLACE: u32 = 2;
            if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 || flags == XATTR_CREATE | XATTR_REPLACE
            {
                return Err(FsError::InvalidData);
            }
            let mut attrs = self.xattrs.lock();
            let exists = attrs.contains_key(name);
            if flags == XATTR_CREATE && exists {
                return Err(FsError::Busy);
            }
            if flags == XATTR_REPLACE && !exists {
                return Err(FsError::NotFound);
            }
            attrs.insert(name.to_string(), value.to_vec());
            Ok(())
        })
    }

    fn get_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.xattrs
                .lock()
                .get(name)
                .cloned()
                .ok_or(FsError::NotFound)
        })
    }

    fn list_xattr<'a>(&'a self) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let attrs = self.xattrs.lock();
            let mut list = Vec::new();
            for name in attrs.keys() {
                list.extend_from_slice(name.as_bytes());
                list.push(0);
            }
            Ok(list)
        })
    }

    fn remove_xattr<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.xattrs
                .lock()
                .remove(name)
                .map(|_| ())
                .ok_or(FsError::NotFound)
        })
    }

    fn fallocate<'a>(&'a self, mode: u32, offset: u64, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            const KEEP_SIZE: u32 = 0x01;
            const PUNCH_HOLE: u32 = 0x02;
            const ZERO_RANGE: u32 = 0x10;
            if len == 0 || mode & !(KEEP_SIZE | PUNCH_HOLE | ZERO_RANGE) != 0 {
                return Err(FsError::Unsupported);
            }
            if mode & PUNCH_HOLE != 0 {
                if mode != PUNCH_HOLE | KEEP_SIZE {
                    return Err(FsError::Unsupported);
                }
                return self.punch_hole(offset, len);
            }
            let end = offset.checked_add(len).ok_or(FsError::NoSpace)?;
            let chunk = [0u8; PAGE_SIZE as usize];
            let old_len = self.data.lock().len;
            let mut position = offset;
            while position < end {
                let within = position % PAGE_SIZE;
                let count = core::cmp::min(PAGE_SIZE - within, end - position) as usize;
                if mode & ZERO_RANGE != 0
                    || !self.data.lock().pages.contains_key(&(position / PAGE_SIZE))
                {
                    self.write_inner(position, &chunk[..count])?;
                }
                position += count as u64;
            }
            let mut data = self.data.lock();
            data.len = if mode & KEEP_SIZE != 0 {
                old_len
            } else {
                core::cmp::max(old_len, end)
            };
            Ok(())
        })
    }

    fn seek<'a>(&'a self, offset: u64, whence: u32) -> FsFuture<'a, u64> {
        Box::pin(async move {
            const SEEK_DATA: u32 = 3;
            const SEEK_HOLE: u32 = 4;
            let data = self.data.lock();
            if offset >= data.len {
                return Err(FsError::NoSpace);
            }
            let page_index = offset / PAGE_SIZE;
            match whence {
                SEEK_DATA => {
                    if data.pages.contains_key(&page_index) {
                        Ok(offset)
                    } else {
                        data.pages
                            .range((page_index + 1)..)
                            .next()
                            .map(|(&index, _)| index * PAGE_SIZE)
                            .filter(|&position| position < data.len)
                            .ok_or(FsError::NoSpace)
                    }
                }
                SEEK_HOLE => {
                    if !data.pages.contains_key(&page_index) {
                        return Ok(offset);
                    }
                    let mut index = page_index + 1;
                    while data.pages.contains_key(&index) {
                        index += 1;
                    }
                    Ok(core::cmp::min(index * PAGE_SIZE, data.len))
                }
                _ => Err(FsError::Unsupported),
            }
        })
    }
}

/// In-memory symlink: an immutable target path. The target is stored
/// verbatim and exposed to readers via `FileOps::read`; writes return
/// `ReadOnly` (POSIX symlink targets are immutable — `symlink(2)`
/// creates and `readlink(2)` reads, but there is no `writelink(2)`).
struct MemSymlink {
    /// Unique, stable inode number (see [`NEXT_INO`]).
    ino: u64,
    target: String,
    _inode_lease: InodeLease,
    uid: AtomicU32,
    gid: AtomicU32,
}

impl fmt::Debug for MemSymlink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemSymlink")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl FileOps for MemSymlink {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let bytes = self.target.as_bytes();
            let off = offset as usize;
            if off >= bytes.len() {
                return Ok(0);
            }
            let n = core::cmp::min(buf.len(), bytes.len() - off);
            buf[..n].copy_from_slice(&bytes[off..off + n]);
            Ok(n)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.target.len() as u64,
            blocks: 1,
            mode: Mode {
                file_type: FileType::Symlink,
                perms: 0o777,
            },
            mtime_cycles: 0,
        }
    }

    fn owners(&self) -> (u32, u32) {
        (
            self.uid.load(Ordering::Relaxed),
            self.gid.load(Ordering::Relaxed),
        )
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.uid.store(uid, Ordering::Relaxed);
            self.gid.store(gid, Ordering::Relaxed);
            Ok(())
        })
    }
}

struct MemSpecial {
    ino: u64,
    file_type: FileType,
    rdev: u64,
    _inode_lease: InodeLease,
    perms: AtomicU32,
    uid: AtomicU32,
    gid: AtomicU32,
}

impl fmt::Debug for MemSpecial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemSpecial")
            .field("ino", &self.ino)
            .field("file_type", &self.file_type)
            .field("rdev", &self.rdev)
            .finish()
    }
}

impl FileOps for MemSpecial {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: self.file_type,
                perms: (self.perms.load(Ordering::Relaxed) & 0o7777) as u16,
            },
            mtime_cycles: 0,
        }
    }

    fn owners(&self) -> (u32, u32) {
        (
            self.uid.load(Ordering::Relaxed),
            self.gid.load(Ordering::Relaxed),
        )
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.uid.store(uid, Ordering::Relaxed);
            self.gid.store(gid, Ordering::Relaxed);
            self.perms.fetch_and(!0o6000, Ordering::Relaxed);
            Ok(())
        })
    }

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.perms.store((perms & 0o7777) as u32, Ordering::Relaxed);
            Ok(())
        })
    }

    fn rdev(&self) -> u64 {
        self.rdev
    }
}

/// A named FIFO plus its tmpfs/ramfs inode reservation. Open descriptions
/// retain this wrapper, so unlink cannot release inode quota prematurely.
struct MemFifo {
    node: Arc<crate::fifo::FifoNode>,
    _inode_lease: InodeLease,
}

impl FileOps for MemFifo {
    fn ino(&self) -> u64 {
        self.node.ino()
    }

    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        self.node.read(offset, buf)
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        self.node.write(offset, buf)
    }

    fn stat(&self) -> Stat {
        self.node.stat()
    }

    fn owners(&self) -> (u32, u32) {
        self.node.owners()
    }

    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        self.node.set_owners(uid, gid)
    }

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        self.node.set_perms(perms)
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn fifo_shared(&self) -> Option<Arc<crate::fifo::FifoShared>> {
        self.node.fifo_shared()
    }
}

/// One directory entry. The discriminant carries either an `Arc`-
/// owned file, an `Arc`-owned subdirectory, an `Arc`-owned symlink,
/// an externally-minted node filed in via `link_node` (the O_TMPFILE
/// materialisation target), or an `Arc`-owned named-pipe (FIFO) node;
/// all kinds drop their underlying storage when the last reference
/// disappears.
enum Entry {
    File(Arc<MemFile>),
    Dir(Arc<MemDir>),
    Symlink(Arc<MemSymlink>),
    Special(Arc<MemSpecial>),
    /// A file node minted outside this directory and later filed into it
    /// by `DirOps::link_node` — the materialisation target of an
    /// `O_TMPFILE` fd's `linkat(AT_EMPTY_PATH)`. Held as a trait object
    /// so the fd and the name alias the exact same inode (a write through
    /// either is visible via the other). Its file type comes from
    /// `stat()` rather than a discriminant.
    Node(Arc<dyn FileOps>),
    /// A named pipe. The `FifoNode` owns the shared pipe buffer; every
    /// `open()` of this entry resolves to the same node (and thus the same
    /// buffer), so all openers rendezvous — see `crate::fifo`.
    Fifo(Arc<MemFifo>),
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Arc<dyn FileOps>` isn't `Debug`, so a derive can't cover the
        // `Node` arm; render each variant by name.
        match self {
            Entry::File(file) => f.debug_tuple("File").field(file).finish(),
            Entry::Dir(dir) => f.debug_tuple("Dir").field(dir).finish(),
            Entry::Symlink(link) => f.debug_tuple("Symlink").field(link).finish(),
            Entry::Special(node) => f.debug_tuple("Special").field(node).finish(),
            Entry::Node(_) => f.debug_tuple("Node").finish(),
            Entry::Fifo(_) => f.debug_tuple("Fifo").finish(),
        }
    }
}

/// A directory node: owns the `BTreeMap` of children behind a lock.
/// `MemDir` is the unit of recursion — both the root and every
/// subdirectory created via `mkdir` are `MemDir`s.
struct MemDir {
    /// Unique, stable inode number (see [`NEXT_INO`]). Distinguishes a
    /// directory from its parent so systemd's `rm_rf` root-guard doesn't
    /// mistake a `mkdir`-created temp dir for the filesystem root.
    ino: u64,
    superblock: Arc<MemSuper>,
    _inode_lease: InodeLease,
    entries: IrqSafeSpinLock<BTreeMap<String, Entry>>,
    /// Directory permission bits (low 12). Defaults to 0o777; `chmod(2)`
    /// on the directory updates it so `stat` reflects the real mode —
    /// dbus/systemd require `XDG_RUNTIME_DIR` to not be group/other-
    /// writable, so `chmod 0700` on a tmpfs dir must actually take.
    perms: AtomicU32,
    uid: AtomicU32,
    gid: AtomicU32,
}

impl fmt::Debug for MemDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemDir")
            .field("entries", &self.entries.lock().len())
            .finish_non_exhaustive()
    }
}

impl MemDir {
    fn contains_dir(&self, needle: *const MemDir) -> bool {
        if core::ptr::eq(self, needle) {
            return true;
        }
        let children: Vec<Arc<MemDir>> = self
            .entries
            .lock()
            .values()
            .filter_map(|entry| match entry {
                Entry::Dir(dir) => Some(Arc::clone(dir)),
                _ => None,
            })
            .collect();
        children.iter().any(|dir| dir.contains_dir(needle))
    }

    fn validate_replacement(source: &Entry, destination: &Entry) -> Result<(), FsError> {
        match (source, destination) {
            (Entry::Dir(_), Entry::Dir(dir)) if !dir.entries.lock().is_empty() => {
                Err(FsError::Busy)
            }
            (Entry::Dir(_), Entry::Dir(_)) => Ok(()),
            (Entry::Dir(_), _) | (_, Entry::Dir(_)) => Err(FsError::InvalidPath),
            _ => Ok(()),
        }
    }

    fn rename_entry(
        &self,
        old_name: &str,
        destination: &MemDir,
        new_name: &str,
        flags: u32,
    ) -> Result<(), FsError> {
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;
        if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) != 0
            || flags == RENAME_NOREPLACE | RENAME_EXCHANGE
        {
            return Err(FsError::Unsupported);
        }
        if !Arc::ptr_eq(&self.superblock, &destination.superblock) {
            return Err(FsError::InvalidPath);
        }
        if core::ptr::eq(self, destination) && old_name == new_name {
            return self
                .entries
                .lock()
                .contains_key(old_name)
                .then_some(())
                .ok_or(FsError::NotFound);
        }

        let moving_dir = self
            .entries
            .lock()
            .get(old_name)
            .and_then(|entry| match entry {
                Entry::Dir(dir) => Some(Arc::clone(dir)),
                _ => None,
            });
        if moving_dir
            .as_ref()
            .is_some_and(|dir| dir.contains_dir(destination as *const MemDir))
        {
            return Err(FsError::InvalidPath);
        }

        if core::ptr::eq(self, destination) {
            let mut entries = self.entries.lock();
            if flags == RENAME_EXCHANGE {
                let old = entries.remove(old_name).ok_or(FsError::NotFound)?;
                let new = match entries.remove(new_name) {
                    Some(new) => new,
                    None => {
                        entries.insert(old_name.to_string(), old);
                        return Err(FsError::NotFound);
                    }
                };
                entries.insert(old_name.to_string(), new);
                entries.insert(new_name.to_string(), old);
                return Ok(());
            }
            if flags == RENAME_NOREPLACE && entries.contains_key(new_name) {
                return Err(FsError::Busy);
            }
            let source = entries.remove(old_name).ok_or(FsError::NotFound)?;
            if let Some(target) = entries.get(new_name) {
                if let Err(error) = Self::validate_replacement(&source, target) {
                    entries.insert(old_name.to_string(), source);
                    return Err(error);
                }
            }
            entries.insert(new_name.to_string(), source);
            return Ok(());
        }

        let self_first = (self as *const Self as usize) < (destination as *const Self as usize);
        let (mut first, mut second) = if self_first {
            (self.entries.lock(), destination.entries.lock())
        } else {
            (destination.entries.lock(), self.entries.lock())
        };
        let (source_entries, destination_entries) = if self_first {
            (&mut first, &mut second)
        } else {
            (&mut second, &mut first)
        };
        if flags == RENAME_EXCHANGE {
            let old = source_entries.remove(old_name).ok_or(FsError::NotFound)?;
            let new = match destination_entries.remove(new_name) {
                Some(new) => new,
                None => {
                    source_entries.insert(old_name.to_string(), old);
                    return Err(FsError::NotFound);
                }
            };
            source_entries.insert(old_name.to_string(), new);
            destination_entries.insert(new_name.to_string(), old);
            return Ok(());
        }
        if flags == RENAME_NOREPLACE && destination_entries.contains_key(new_name) {
            return Err(FsError::Busy);
        }
        let source = source_entries.remove(old_name).ok_or(FsError::NotFound)?;
        if let Some(target) = destination_entries.get(new_name) {
            if let Err(error) = Self::validate_replacement(&source, target) {
                source_entries.insert(old_name.to_string(), source);
                return Err(error);
            }
        }
        destination_entries.insert(new_name.to_string(), source);
        Ok(())
    }

    fn clone_linkable(entry: &Entry) -> Result<Entry, FsError> {
        match entry {
            Entry::Dir(_) => Err(FsError::InvalidPath),
            Entry::File(file) => Ok(Entry::File(Arc::clone(file))),
            Entry::Symlink(link) => Ok(Entry::Symlink(Arc::clone(link))),
            Entry::Special(node) => Ok(Entry::Special(Arc::clone(node))),
            Entry::Node(node) => Ok(Entry::Node(Arc::clone(node))),
            Entry::Fifo(node) => Ok(Entry::Fifo(Arc::clone(node))),
        }
    }
}

impl DirOps for MemDir {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let g = self.entries.lock();
        match g.get(name)? {
            Entry::File(f) => Some(Arc::clone(f) as Arc<dyn FileOps>),
            Entry::Symlink(s) => Some(Arc::clone(s) as Arc<dyn FileOps>),
            Entry::Special(node) => Some(Arc::clone(node) as Arc<dyn FileOps>),
            Entry::Node(n) => Some(Arc::clone(n)),
            Entry::Fifo(p) => Some(Arc::clone(p) as Arc<dyn FileOps>),
            Entry::Dir(_) => None,
        }
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        let g = self.entries.lock();
        match g.get(name)? {
            Entry::Dir(d) => Some(Arc::clone(d) as Arc<dyn DirOps>),
            Entry::File(_) | Entry::Special(_) | Entry::Node(_) => None,
            // Symlinks are never auto-traversed: `readlink`-style
            // callers want the target bytes via `lookup`, not a
            // resolved DirOps. Path resolution that wants to follow
            // a symlink chain must do so explicitly.
            Entry::Symlink(_) => None,
            // A FIFO is a file, not a directory — never descendable.
            Entry::Fifo(_) => None,
        }
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { self.lookup_dir(name).ok_or(FsError::NotFound) })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // `DirEntry::name` is `&'static str`; we can't synthesise
        // that from our `String` keys without leaking. The kernel's
        // readdir path uses `enumerate()` (overridden below) which
        // returns owned `(String, FileType)` pairs instead.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let g = self.entries.lock();
        g.iter()
            .skip(cursor)
            .take(max)
            .map(|(name, entry)| {
                let ft = match entry {
                    Entry::File(f) if f.sock => FileType::Socket,
                    Entry::File(_) => FileType::File,
                    Entry::Dir(_) => FileType::Dir,
                    Entry::Symlink(_) => FileType::Symlink,
                    Entry::Special(node) => node.file_type,
                    // A linked-in node reports whatever type it stats as
                    // (an O_TMPFILE materialisation is a regular file).
                    Entry::Node(n) => n.stat().mode.file_type,
                    Entry::Fifo(_) => FileType::Fifo,
                };
                (name.clone(), ft)
            })
            .collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move { Ok(self.enumerate(cursor, max)) })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            match g.get(name) {
                None => Err(FsError::NotFound),
                Some(Entry::Dir(_)) => Err(FsError::InvalidPath),
                Some(Entry::File(_))
                | Some(Entry::Symlink(_))
                | Some(Entry::Special(_))
                | Some(Entry::Node(_))
                | Some(Entry::Fifo(_)) => {
                    g.remove(name);
                    Ok(())
                }
            }
        })
    }

    fn create<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            let f = Arc::new(MemFile::new(&self.superblock, &[])?);
            g.insert(name.to_string(), Entry::File(Arc::clone(&f)));
            Ok(f as Arc<dyn FileOps>)
        })
    }

    /// Create an S_IFSOCK node — the filesystem inode Linux materialises
    /// when a pathname AF_UNIX socket is `bind()`-ed. Makes the bound path
    /// `stat`/`[ -S ]`/`ls`/`unlink`-visible (wayland, dbus, and shells all
    /// probe the socket path this way). Connection routing still goes
    /// through the socket layer's LISTENERS registry; this node is the
    /// filesystem-visible marker.
    fn create_socket<'a>(&'a self, name: &'a str, perms: u16) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            let f = Arc::new(MemFile::new_socket(&self.superblock, perms)?);
            g.insert(name.to_string(), Entry::File(Arc::clone(&f)));
            Ok(f as Arc<dyn FileOps>)
        })
    }

    /// Materialise a special node. Only `FileType::Fifo` is honoured on
    /// tmpfs — `mkfifo`/`mknod(S_IFIFO)` on `/run`, `/tmp`, `/etc`. The FIFO
    /// node owns a fresh shared pipe buffer; every later `open()` of this
    /// path resolves to the same node (`lookup` above), so all openers
    /// rendezvous on that one buffer. Device / block nodes aren't backed by
    /// tmpfs (return `Unsupported` so the syscall layer falls back to a
    /// plain file, matching the pre-FIFO behaviour); the `rdev` argument is
    /// unused for a FIFO.
    fn mknod<'a>(
        &'a self,
        name: &'a str,
        file_type: FileType,
        rdev: u64,
    ) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            if !matches!(
                file_type,
                FileType::Fifo | FileType::Special | FileType::Block
            ) {
                return Err(FsError::Unsupported);
            }
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            if file_type == FileType::Fifo {
                let fifo = Arc::new(MemFifo {
                    node: Arc::new(crate::fifo::FifoNode::new(alloc_ino(), DEFAULT_PERMS)),
                    _inode_lease: self.superblock.reserve_inode()?,
                });
                g.insert(name.to_string(), Entry::Fifo(Arc::clone(&fifo)));
                Ok(fifo as Arc<dyn FileOps>)
            } else {
                let node = Arc::new(MemSpecial {
                    ino: alloc_ino(),
                    file_type,
                    rdev,
                    _inode_lease: self.superblock.reserve_inode()?,
                    perms: AtomicU32::new(DEFAULT_PERMS as u32),
                    uid: AtomicU32::new(0),
                    gid: AtomicU32::new(0),
                });
                g.insert(name.to_string(), Entry::Special(Arc::clone(&node)));
                Ok(node as Arc<dyn FileOps>)
            }
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            let d = Arc::new(MemDir {
                ino: alloc_ino(),
                superblock: Arc::clone(&self.superblock),
                _inode_lease: self.superblock.reserve_inode()?,
                entries: IrqSafeSpinLock::new(BTreeMap::new()),
                perms: AtomicU32::new(0o755),
                uid: AtomicU32::new(self.uid.load(Ordering::Relaxed)),
                gid: AtomicU32::new(self.gid.load(Ordering::Relaxed)),
            });
            g.insert(name.to_string(), Entry::Dir(Arc::clone(&d)));
            Ok(d as Arc<dyn DirOps>)
        })
    }

    fn dir_mode(&self) -> u16 {
        (self.perms.load(Ordering::Relaxed) & 0o7777) as u16
    }

    fn set_dir_mode(&self, perms: u16) {
        self.perms.store((perms & 0o7777) as u32, Ordering::Relaxed);
    }

    fn dir_owners(&self) -> (u32, u32) {
        (
            self.uid.load(Ordering::Relaxed),
            self.gid.load(Ordering::Relaxed),
        )
    }

    fn set_dir_owners(&self, uid: u32, gid: u32) {
        self.uid.store(uid, Ordering::Relaxed);
        self.gid.store(gid, Ordering::Relaxed);
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            match g.get(name) {
                None => Err(FsError::NotFound),
                Some(Entry::File(_)) | Some(Entry::Special(_)) | Some(Entry::Node(_)) => {
                    Err(FsError::InvalidPath)
                }
                Some(Entry::Symlink(_)) => Err(FsError::InvalidPath),
                Some(Entry::Fifo(_)) => Err(FsError::InvalidPath),
                Some(Entry::Dir(d)) => {
                    if !d.entries.lock().is_empty() {
                        return Err(FsError::Busy);
                    }
                    g.remove(name);
                    Ok(())
                }
            }
        })
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            let s = Arc::new(MemSymlink {
                ino: alloc_ino(),
                target: target.to_string(),
                _inode_lease: self.superblock.reserve_inode()?,
                uid: AtomicU32::new(self.uid.load(Ordering::Relaxed)),
                gid: AtomicU32::new(self.gid.load(Ordering::Relaxed)),
            });
            g.insert(name.to_string(), Entry::Symlink(Arc::clone(&s)));
            Ok(s as Arc<dyn FileOps>)
        })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move { self.rename_entry(old_name, self, new_name, 0) })
    }

    fn rename_to<'a>(
        &'a self,
        old_name: &'a str,
        new_dir: &'a dyn DirOps,
        new_name: &'a str,
        flags: u32,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let destination = new_dir
                .as_any()
                .and_then(|value| value.downcast_ref::<MemDir>())
                .ok_or(FsError::InvalidPath)?;
            self.rename_entry(old_name, destination, new_name, flags)
        })
    }

    fn link<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            // link(2) NEVER replaces an existing destination — EEXIST
            // (unlike rename's atomic-replace contract above).
            if g.contains_key(new_name) {
                return Err(FsError::Busy);
            }
            // Cloning the Arc IS the hard link: both names now alias the
            // one backing node, so a write through either is visible via
            // the other, and the node lives until the last name (or open
            // fd) drops it — exactly the inode refcount model. A symlink
            // entry links the symlink itself (linkat(2) default without
            // AT_SYMLINK_FOLLOW). Directories can't be hard-linked
            // (Linux: EPERM).
            let aliased = Self::clone_linkable(g.get(old_name).ok_or(FsError::NotFound)?)?;
            g.insert(new_name.to_string(), aliased);
            Ok(())
        })
    }

    fn link_to<'a>(
        &'a self,
        old_name: &'a str,
        new_dir: &'a dyn DirOps,
        new_name: &'a str,
    ) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let destination = new_dir
                .as_any()
                .and_then(|value| value.downcast_ref::<MemDir>())
                .ok_or(FsError::InvalidPath)?;
            if !Arc::ptr_eq(&self.superblock, &destination.superblock) {
                return Err(FsError::InvalidPath);
            }
            let self_first = core::ptr::eq(self, destination)
                || (self as *const Self as usize) < (destination as *const Self as usize);
            let mut first = if self_first {
                self.entries.lock()
            } else {
                destination.entries.lock()
            };
            if core::ptr::eq(self, destination) {
                if first.contains_key(new_name) {
                    return Err(FsError::Busy);
                }
                let linked = Self::clone_linkable(first.get(old_name).ok_or(FsError::NotFound)?)?;
                first.insert(new_name.to_string(), linked);
                return Ok(());
            }
            let mut second = if self_first {
                destination.entries.lock()
            } else {
                self.entries.lock()
            };
            let (source, target) = if self_first {
                (&mut first, &mut second)
            } else {
                (&mut second, &mut first)
            };
            if target.contains_key(new_name) {
                return Err(FsError::Busy);
            }
            let linked = Self::clone_linkable(source.get(old_name).ok_or(FsError::NotFound)?)?;
            target.insert(new_name.to_string(), linked);
            Ok(())
        })
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }

    fn link_node<'a>(&'a self, name: &'a str, node: Arc<dyn FileOps>) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            // linkat NEVER replaces an existing name (like `link` above).
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            // Store the passed trait object verbatim: the caller's
            // O_TMPFILE fd and this new name now alias the one inode, so
            // the bytes already written through the fd are visible under
            // the name the instant it appears.
            g.insert(name.to_string(), Entry::Node(node));
            Ok(())
        })
    }

    fn tmpfile<'a>(&'a self, mode: u32) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            let file = Arc::new(MemFile::new(&self.superblock, &[])?);
            file.perms.store(mode & 0o7777, Ordering::Relaxed);
            Ok(file as Arc<dyn FileOps>)
        })
    }

    fn supports_tmpfile(&self) -> bool {
        true
    }
}

/// Mutable in-memory FS. Mount-time seeding is supported via
/// [`MemFs::with_seeds`] so the validate harness can mount
/// `/tmp` already populated with a few files for unlink/read probes.
pub struct MemFs {
    name: &'static str,
    root: Arc<MemDir>,
    superblock: Arc<MemSuper>,
}

impl fmt::Debug for MemFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemFs")
            .field("name", &self.name)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl MemFs {
    fn configured(
        name: &'static str,
        kind: MemFsKind,
        max_blocks: Option<u64>,
        max_inodes: Option<u64>,
        root_mode: u16,
        root_uid: u32,
        root_gid: u32,
    ) -> Result<Self, FsError> {
        let superblock = MemSuper::new(kind, max_blocks, max_inodes);
        let root = Arc::new(MemDir {
            ino: alloc_ino(),
            superblock: Arc::clone(&superblock),
            _inode_lease: superblock.reserve_inode()?,
            entries: IrqSafeSpinLock::new(BTreeMap::new()),
            perms: AtomicU32::new(root_mode as u32),
            uid: AtomicU32::new(root_uid),
            gid: AtomicU32::new(root_gid),
        });
        Ok(Self {
            name,
            root,
            superblock,
        })
    }

    /// Empty FS.
    pub fn new(name: &'static str) -> Self {
        Self::configured(name, MemFsKind::Generic, None, None, 0o755, 0, 0)
            .expect("unlimited MemFs root inode")
    }

    /// Construct with pre-seeded files at the root. Each `(name,
    /// contents)` pair becomes a regular file at the FS's root with
    /// `contents` bytes. Names must not contain `/`.
    pub fn with_seeds(name: &'static str, seeds: &[(&str, &[u8])]) -> Self {
        let fs = Self::new(name);
        {
            let mut g = fs.root.entries.lock();
            for (n, c) in seeds {
                let f =
                    Arc::new(MemFile::new(&fs.superblock, c).expect("unlimited MemFs seed inode"));
                g.insert((*n).to_string(), Entry::File(f));
            }
        }
        fs
    }

    /// Diagnostic: number of root-level entries currently in the FS.
    /// Subdirectory contents are not counted recursively.
    pub fn file_count(&self) -> usize {
        self.root.entries.lock().len()
    }

    /// Apply explicit DAC metadata (perms + owner) to a root-level file
    /// previously seeded via [`MemFs::with_seeds`]. Returns `true` if a
    /// regular file with `name` was found and updated, `false` otherwise
    /// (missing, or the entry is a dir/symlink). Used by boot-init to
    /// turn /etc/shadow into a real 0600 root-owned secret. Only the
    /// low-9 perm bits are stored.
    pub fn set_file_perms_owner(&self, name: &str, perms: u16, uid: u32, gid: u32) -> bool {
        let g = self.root.entries.lock();
        match g.get(name) {
            Some(Entry::File(f)) => {
                f.perms.store((perms & 0o7777) as u32, Ordering::Relaxed);
                f.uid.store(uid, Ordering::Relaxed);
                f.gid.store(gid, Ordering::Relaxed);
                true
            }
            _ => false,
        }
    }
}

impl FsInstance for MemFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::clone(&self.root) as Arc<dyn DirOps>
    }
    fn name(&self) -> &str {
        self.name
    }

    fn statfs<'a>(&'a self) -> FsFuture<'a, FsStat> {
        Box::pin(async move { Ok(self.superblock.statfs()) })
    }
}

/// Linux tmpfs: sparse page-backed files with per-mount block/inode limits,
/// mount-root metadata, and live statfs accounting.
pub struct TmpFs {
    inner: MemFs,
    total_pages: u64,
}

impl fmt::Debug for TmpFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TmpFs")
            .field("inner", &self.inner)
            .field("total_pages", &self.total_pages)
            .finish()
    }
}

impl TmpFs {
    pub fn from_options(options: &str, uid: u32, gid: u32) -> Result<Self, FsError> {
        Self::from_options_with_total(options, narf_memory::frame::stats().total as u64, uid, gid)
    }

    pub fn from_options_with_total(
        options: &str,
        total_pages: u64,
        uid: u32,
        gid: u32,
    ) -> Result<Self, FsError> {
        let parsed = TmpFsOptions::parse(options, total_pages, uid, gid)?;
        let inner = MemFs::configured(
            "tmpfs",
            MemFsKind::Tmpfs,
            parsed.max_blocks,
            parsed.max_inodes,
            parsed.root_mode,
            parsed.root_uid,
            parsed.root_gid,
        )?;
        Ok(Self { inner, total_pages })
    }
}

impl FsInstance for TmpFs {
    fn root(&self) -> Arc<dyn DirOps> {
        self.inner.root()
    }

    fn name(&self) -> &str {
        "tmpfs"
    }

    fn statfs<'a>(&'a self) -> FsFuture<'a, FsStat> {
        self.inner.statfs()
    }

    fn reconfigure(&self, options: &str) -> Result<(), FsError> {
        self.inner
            .superblock
            .reconfigure_tmpfs(options, self.total_pages)
    }
}

/// Linux ramfs: the same POSIX in-memory inode/data behavior as tmpfs but
/// deliberately unlimited, unswappable, and non-resizable.
pub struct RamFs {
    inner: MemFs,
}

impl fmt::Debug for RamFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RamFs").field("inner", &self.inner).finish()
    }
}

impl RamFs {
    pub fn from_options(options: &str, uid: u32, gid: u32) -> Result<Self, FsError> {
        let parsed = RamFsOptions::parse(options, uid, gid)?;
        Ok(Self {
            inner: MemFs::configured(
                "ramfs",
                MemFsKind::Ramfs,
                None,
                None,
                parsed.root_mode,
                parsed.root_uid,
                parsed.root_gid,
            )?,
        })
    }
}

impl FsInstance for RamFs {
    fn root(&self) -> Arc<dyn DirOps> {
        self.inner.root()
    }

    fn name(&self) -> &str {
        "ramfs"
    }

    fn statfs<'a>(&'a self) -> FsFuture<'a, FsStat> {
        self.inner.statfs()
    }
}
