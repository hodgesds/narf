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
//! Layout: each directory owns a `BTreeMap<String, Entry>` where
//! `Entry` is `File(Arc<MemFile>)`, `Dir(Arc<MemDir>)`, or
//! `Symlink(Arc<MemSymlink>)`. `MemFile` carries a `Mutex<Vec<u8>>`
//! so concurrent writers / readers see a consistent length+contents
//! tuple. `MemSymlink` stores its target as an immutable `String`
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
use core::fmt;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat};

/// Default permission bits for a freshly minted `MemFile`: 0o666
/// (rw-rw-rw-), owned by root (0, 0). This preserves the historical
/// "root-can-do-anything, everyone has rw" behaviour so DAC enforcement
/// only bites when a file is explicitly minted with tighter perms.
const DEFAULT_PERMS: u16 = 0o666;

/// In-memory file: a length-tracked byte buffer behind a lock, plus
/// per-node DAC metadata (low-9 permission bits + owner uid/gid).
struct MemFile {
    bytes: IrqSafeSpinLock<Vec<u8>>,
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
}

impl MemFile {
    /// Mint a `MemFile` with default perms (0o666) and owner (0, 0).
    fn new(bytes: Vec<u8>) -> Self {
        MemFile {
            bytes: IrqSafeSpinLock::new(bytes),
            perms: AtomicU32::new(DEFAULT_PERMS as u32),
            uid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            mtime_ns: AtomicU64::new(0),
            sock: false,
        }
    }

    /// Mint a `MemFile` with explicit perms + owner. Used to seed files
    /// that must enforce a real DAC boundary (e.g. /etc/shadow 0600).
    fn with_perms_owner(bytes: Vec<u8>, perms: u16, uid: u32, gid: u32) -> Self {
        MemFile {
            bytes: IrqSafeSpinLock::new(bytes),
            perms: AtomicU32::new((perms & 0o777) as u32),
            uid: AtomicU32::new(uid),
            gid: AtomicU32::new(gid),
            mtime_ns: AtomicU64::new(0),
            sock: false,
        }
    }

    /// Mint a pathname-AF_UNIX-socket node (S_IFSOCK) with the given perms.
    fn new_socket(perms: u16) -> Self {
        MemFile {
            bytes: IrqSafeSpinLock::new(Vec::new()),
            perms: AtomicU32::new((perms & 0o777) as u32),
            uid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            mtime_ns: AtomicU64::new(0),
            sock: true,
        }
    }

    /// Stamp mtime = wall-now. Called on every successful write so
    /// `make`-style newer-than comparisons see fresh build outputs as
    /// newer than their sources.
    fn touch_mtime_now(&self) {
        let w = narf_time::now_wall();
        let ns = (w.secs.max(0) as u64).saturating_mul(1_000_000_000) + w.nanos as u64;
        self.mtime_ns.store(ns, Ordering::Relaxed);
    }
}

/// Mint a fresh empty in-memory file outside any directory. The
/// returned `FileOps` handle owns the storage; dropping the last
/// reference frees the bytes. Used by `sys_memfd_create` so an
/// anonymous fd can back a real `MemFile` without occupying a
/// VFS path.
pub fn new_anon_file() -> Arc<dyn FileOps> {
    Arc::new(MemFile::new(Vec::new()))
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
            .field("len", &self.bytes.lock().len())
            .finish_non_exhaustive()
    }
}

impl FileOps for MemFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let g = self.bytes.lock();
            let off = offset as usize;
            if off >= g.len() {
                return Ok(0);
            }
            let n = core::cmp::min(buf.len(), g.len() - off);
            buf[..n].copy_from_slice(&g[off..off + n]);
            Ok(n)
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            {
                let mut g = self.bytes.lock();
                let off = offset as usize;
                // Grow the buffer to fit the write — POSIX semantics for
                // a write past EOF on a regular file.
                if off + buf.len() > g.len() {
                    g.resize(off + buf.len(), 0);
                }
                g[off..off + buf.len()].copy_from_slice(buf);
            }
            self.touch_mtime_now();
            Ok(buf.len())
        })
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
        let g = self.bytes.lock();
        Stat {
            size: g.len() as u64,
            blocks: (g.len() as u64).div_ceil(512),
            mode: Mode {
                file_type: if self.sock {
                    FileType::Socket
                } else {
                    FileType::File
                },
                perms: (self.perms.load(Ordering::Relaxed) & 0o777) as u16,
            },
            // Report wall-ns as cycles so the stat ABI's cycles→ns
            // division (`stat_linux`: mtime_cycles / cycles_per_ns)
            // hands userspace back the exact epoch-ns that utimensat /
            // the last write stored — the tar -x / cp -p / make
            // round-trip. 0 (never stamped) stays 0.
            mtime_cycles: self
                .mtime_ns
                .load(Ordering::Relaxed)
                .saturating_mul(narf_time::cycles_per_ns().max(1) as u64),
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

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // Persist only the low-9 rwxrwxrwx bits.
            self.perms.store((perms & 0o777) as u32, Ordering::Relaxed);
            Ok(())
        })
    }

    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            // Cap at usize::MAX so a 64-bit pathologically large `len`
            // doesn't underflow into a tiny resize on 32-bit hosts. NARF
            // user mode is 64-bit on every supported target, but Stage-5
            // host-side test runners may differ.
            let new_len = len as usize;
            let mut g = self.bytes.lock();
            g.resize(new_len, 0);
            Ok(())
        })
    }
}

/// In-memory symlink: an immutable target path. The target is stored
/// verbatim and exposed to readers via `FileOps::read`; writes return
/// `ReadOnly` (POSIX symlink targets are immutable — `symlink(2)`
/// creates and `readlink(2)` reads, but there is no `writelink(2)`).
struct MemSymlink {
    target: String,
}

impl fmt::Debug for MemSymlink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemSymlink")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl FileOps for MemSymlink {
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
}

/// One directory entry. The discriminant carries either an `Arc`-
/// owned file, an `Arc`-owned subdirectory, or an `Arc`-owned
/// symlink; all kinds drop their underlying storage when the last
/// reference disappears.
#[derive(Debug)]
enum Entry {
    File(Arc<MemFile>),
    Dir(Arc<MemDir>),
    Symlink(Arc<MemSymlink>),
}

/// A directory node: owns the `BTreeMap` of children behind a lock.
/// `MemDir` is the unit of recursion — both the root and every
/// subdirectory created via `mkdir` are `MemDir`s.
struct MemDir {
    entries: IrqSafeSpinLock<BTreeMap<String, Entry>>,
    /// Directory permission bits (low 12). Defaults to 0o777; `chmod(2)`
    /// on the directory updates it so `stat` reflects the real mode —
    /// dbus/systemd require `XDG_RUNTIME_DIR` to not be group/other-
    /// writable, so `chmod 0700` on a tmpfs dir must actually take.
    perms: AtomicU32,
}

impl fmt::Debug for MemDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemDir")
            .field("entries", &self.entries.lock().len())
            .finish_non_exhaustive()
    }
}

impl DirOps for MemDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let g = self.entries.lock();
        match g.get(name)? {
            Entry::File(f) => Some(Arc::clone(f) as Arc<dyn FileOps>),
            Entry::Symlink(s) => Some(Arc::clone(s) as Arc<dyn FileOps>),
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
            Entry::File(_) => None,
            // Symlinks are never auto-traversed: `readlink`-style
            // callers want the target bytes via `lookup`, not a
            // resolved DirOps. Path resolution that wants to follow
            // a symlink chain must do so explicitly.
            Entry::Symlink(_) => None,
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
                Some(Entry::File(_)) | Some(Entry::Symlink(_)) => {
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
            let f = Arc::new(MemFile::new(Vec::new()));
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
            let f = Arc::new(MemFile::new_socket(perms));
            g.insert(name.to_string(), Entry::File(Arc::clone(&f)));
            Ok(f as Arc<dyn FileOps>)
        })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            if g.contains_key(name) {
                return Err(FsError::Busy);
            }
            let d = Arc::new(MemDir {
                entries: IrqSafeSpinLock::new(BTreeMap::new()),
                perms: AtomicU32::new(0o755),
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

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            match g.get(name) {
                None => Err(FsError::NotFound),
                Some(Entry::File(_)) => Err(FsError::InvalidPath),
                Some(Entry::Symlink(_)) => Err(FsError::InvalidPath),
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
                target: target.to_string(),
            });
            g.insert(name.to_string(), Entry::Symlink(Arc::clone(&s)));
            Ok(s as Arc<dyn FileOps>)
        })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let mut g = self.entries.lock();
            let entry = match g.remove(old_name) {
                Some(e) => e,
                None => return Err(FsError::NotFound),
            };
            // POSIX rename(2) ATOMICALLY REPLACES an existing destination —
            // that is the whole point of the write-temp-then-rename atomic-
            // save idiom (Qt QSaveFile, KConfig, most config/cache writers).
            // The old code rejected an existing `new_name` with EBUSY, so
            // every REWRITE of an existing file failed (KDE reported it as
            // "Disk full?"). `insert` overwrites whatever was there.
            g.insert(new_name.to_string(), entry);
            Ok(())
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
            let aliased = match g.get(old_name) {
                None => return Err(FsError::NotFound),
                Some(Entry::Dir(_)) => return Err(FsError::InvalidPath),
                Some(Entry::File(f)) => Entry::File(Arc::clone(f)),
                Some(Entry::Symlink(s)) => Entry::Symlink(Arc::clone(s)),
            };
            g.insert(new_name.to_string(), aliased);
            Ok(())
        })
    }
}

/// Mutable in-memory FS. Mount-time seeding is supported via
/// [`MemFs::with_seeds`] so the validate harness can mount
/// `/tmp` already populated with a few files for unlink/read probes.
pub struct MemFs {
    name: &'static str,
    root: Arc<MemDir>,
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
    /// Empty FS.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            root: Arc::new(MemDir {
                entries: IrqSafeSpinLock::new(BTreeMap::new()),
                perms: AtomicU32::new(0o755),
            }),
        }
    }

    /// Construct with pre-seeded files at the root. Each `(name,
    /// contents)` pair becomes a regular file at the FS's root with
    /// `contents` bytes. Names must not contain `/`.
    pub fn with_seeds(name: &'static str, seeds: &[(&str, &[u8])]) -> Self {
        let fs = Self::new(name);
        {
            let mut g = fs.root.entries.lock();
            for (n, c) in seeds {
                let f = Arc::new(MemFile::new(c.to_vec()));
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
                f.perms.store((perms & 0o777) as u32, Ordering::Relaxed);
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
}
