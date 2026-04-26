//! `MemFs` — an in-memory read/write filesystem.
//!
//! Stage-4 surface for exercising the mutable [`DirOps`] paths
//! (`unlink`, `create`, eventually `mkdir`/`rmdir`/`rename`). Designed
//! for the `/tmp` mount in the validate harness — small files, single
//! flat directory, no persistence. Concurrency: a single
//! `IrqSafeSpinLock` over the file map; writes are serialised through
//! it. The validate harness is single-threaded so this is uncontended.
//!
//! Layout: `BTreeMap<String, Arc<MemFile>>`. Each `MemFile` carries a
//! `Mutex<Vec<u8>>` so concurrent writers / readers see a consistent
//! length+contents tuple. `unlink` removes the entry from the map but
//! keeps the file's `Arc` alive for any outstanding fd holders — the
//! bytes go away when the last fd drops, matching POSIX semantics.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    DirEntry, DirOps, FileOps, FsError, FsFuture, FsInstance, Mode, Stat,
};

/// In-memory file: a length-tracked byte buffer behind a lock.
struct MemFile {
    bytes: IrqSafeSpinLock<Vec<u8>>,
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
            size:         g.len() as u64,
            blocks:       (g.len() as u64).div_ceil(512),
            mode:         Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
}

/// Mutable in-memory FS. Mount-time seeding is supported via
/// [`MemFs::with_seeds`] so the validate harness can mount
/// `/tmp` already populated with a few files for unlink/read probes.
pub struct MemFs {
    name:  &'static str,
    files: Arc<IrqSafeSpinLock<BTreeMap<String, Arc<MemFile>>>>,
}

impl fmt::Debug for MemFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemFs")
            .field("name", &self.name)
            .field("files", &self.files.lock().len())
            .finish_non_exhaustive()
    }
}

impl MemFs {
    /// Empty FS.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            files: Arc::new(IrqSafeSpinLock::new(BTreeMap::new())),
        }
    }

    /// Construct with pre-seeded files. Each `(name, contents)` pair
    /// becomes a regular file at `name` with `contents` bytes. Names
    /// must not contain `/`.
    pub fn with_seeds(name: &'static str, seeds: &[(&str, &[u8])]) -> Self {
        let fs = Self::new(name);
        {
            let mut g = fs.files.lock();
            for (n, c) in seeds {
                g.insert(
                    (*n).to_string(),
                    Arc::new(MemFile {
                        bytes: IrqSafeSpinLock::new(c.to_vec()),
                    }),
                );
            }
        }
        fs
    }
}

impl FsInstance for MemFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(MemFsRoot { files: Arc::clone(&self.files) })
    }
    fn name(&self) -> &str { self.name }
}

#[derive(Debug)]
struct MemFsRoot {
    files: Arc<IrqSafeSpinLock<BTreeMap<String, Arc<MemFile>>>>,
}

impl DirOps for MemFsRoot {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let g = self.files.lock();
        g.get(name)
            .map(|f| Arc::clone(f) as Arc<dyn FileOps>)
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // DirEntry::name is &'static — we can't synthesise that from
        // String keys. Stage-4 widens DirEntry to owned String; until
        // then iter() returns empty for the mutable FS. Callers that
        // need contents probe via lookup() against known names.
        Box::new(core::iter::empty())
    }

    fn unlink(&self, name: &str) -> Result<(), FsError> {
        let mut g = self.files.lock();
        if g.remove(name).is_some() {
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }

    fn create(&self, name: &str) -> Result<Arc<dyn FileOps>, FsError> {
        let mut g = self.files.lock();
        if g.contains_key(name) {
            return Err(FsError::Busy);
        }
        let f = Arc::new(MemFile {
            bytes: IrqSafeSpinLock::new(Vec::new()),
        });
        g.insert(name.to_string(), Arc::clone(&f));
        Ok(f as Arc<dyn FileOps>)
    }
}

impl MemFs {
    /// Diagnostic: number of files currently in the FS. Reads under
    /// the lock so the result is consistent with concurrent unlinks.
    pub fn file_count(&self) -> usize {
        self.files.lock().len()
    }
}
