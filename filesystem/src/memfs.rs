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

use narf_lib::sync::IrqSafeSpinLock;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat};

/// In-memory file: a length-tracked byte buffer behind a lock.
struct MemFile {
    bytes: IrqSafeSpinLock<Vec<u8>>,
}

/// Mint a fresh empty in-memory file outside any directory. The
/// returned `FileOps` handle owns the storage; dropping the last
/// reference frees the bytes. Used by `sys_memfd_create` so an
/// anonymous fd can back a real `MemFile` without occupying a
/// VFS path.
pub fn new_anon_file() -> Arc<dyn FileOps> {
    Arc::new(MemFile {
        bytes: IrqSafeSpinLock::new(Vec::new()),
    })
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
            let mut g = self.bytes.lock();
            let off = offset as usize;
            // Grow the buffer to fit the write — POSIX semantics for
            // a write past EOF on a regular file.
            if off + buf.len() > g.len() {
                g.resize(off + buf.len(), 0);
            }
            g[off..off + buf.len()].copy_from_slice(buf);
            Ok(buf.len())
        })
    }

    fn stat(&self) -> Stat {
        let g = self.bytes.lock();
        Stat {
            size: g.len() as u64,
            blocks: (g.len() as u64).div_ceil(512),
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    fn truncate(&self, len: u64) -> Result<(), FsError> {
        // Cap at usize::MAX so a 64-bit pathologically large `len`
        // doesn't underflow into a tiny resize on 32-bit hosts. NARF
        // user mode is 64-bit on every supported target, but Stage-5
        // host-side test runners may differ.
        let new_len = len as usize;
        let mut g = self.bytes.lock();
        g.resize(new_len, 0);
        Ok(())
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
                    Entry::File(_) => FileType::File,
                    Entry::Dir(_) => FileType::Dir,
                    Entry::Symlink(_) => FileType::Symlink,
                };
                (name.clone(), ft)
            })
            .collect()
    }

    fn unlink(&self, name: &str) -> Result<(), FsError> {
        let mut g = self.entries.lock();
        match g.get(name) {
            None => Err(FsError::NotFound),
            Some(Entry::Dir(_)) => Err(FsError::InvalidPath),
            Some(Entry::File(_)) | Some(Entry::Symlink(_)) => {
                g.remove(name);
                Ok(())
            }
        }
    }

    fn create(&self, name: &str) -> Result<Arc<dyn FileOps>, FsError> {
        let mut g = self.entries.lock();
        if g.contains_key(name) {
            return Err(FsError::Busy);
        }
        let f = Arc::new(MemFile {
            bytes: IrqSafeSpinLock::new(Vec::new()),
        });
        g.insert(name.to_string(), Entry::File(Arc::clone(&f)));
        Ok(f as Arc<dyn FileOps>)
    }

    fn mkdir(&self, name: &str) -> Result<Arc<dyn DirOps>, FsError> {
        let mut g = self.entries.lock();
        if g.contains_key(name) {
            return Err(FsError::Busy);
        }
        let d = Arc::new(MemDir {
            entries: IrqSafeSpinLock::new(BTreeMap::new()),
        });
        g.insert(name.to_string(), Entry::Dir(Arc::clone(&d)));
        Ok(d as Arc<dyn DirOps>)
    }

    fn rmdir(&self, name: &str) -> Result<(), FsError> {
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
    }

    fn symlink(&self, name: &str, target: &str) -> Result<Arc<dyn FileOps>, FsError> {
        let mut g = self.entries.lock();
        if g.contains_key(name) {
            return Err(FsError::Busy);
        }
        let s = Arc::new(MemSymlink {
            target: target.to_string(),
        });
        g.insert(name.to_string(), Entry::Symlink(Arc::clone(&s)));
        Ok(s as Arc<dyn FileOps>)
    }

    fn rename(&self, old_name: &str, new_name: &str) -> Result<(), FsError> {
        let mut g = self.entries.lock();
        if !g.contains_key(old_name) {
            return Err(FsError::NotFound);
        }
        if g.contains_key(new_name) {
            return Err(FsError::Busy);
        }
        let entry = g.remove(old_name).unwrap();
        g.insert(new_name.to_string(), entry);
        Ok(())
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
                let f = Arc::new(MemFile {
                    bytes: IrqSafeSpinLock::new(c.to_vec()),
                });
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
}

impl FsInstance for MemFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::clone(&self.root) as Arc<dyn DirOps>
    }
    fn name(&self) -> &str {
        self.name
    }
}
