//! `DevFs` — minimal `/dev/null` + `/dev/zero` virtual filesystem.
//!
//! Real C programs reach for these almost universally — discarding
//! debug output via `> /dev/null`, zero-filling buffers via `dd
//! if=/dev/zero`, etc. Without them user programs that mention the
//! paths in a never-taken branch still need them to *exist* (or
//! the open call surfaces a NotFound that the caller doesn't
//! distinguish from a real failure).
//!
//! Layout: a single `DevFs::new()` returns an `FsInstance` whose
//! root holds two read-only special files.
//!
//! Semantics:
//!   - `/dev/null`: read returns 0 (immediate EOF); write returns
//!     the requested length (bytes silently discarded).
//!   - `/dev/zero`: read fills the user buffer with zeros and
//!     returns the requested length; write discards.
//!
//! Stat reports `FileType::Special` so `S_ISCHR(...)` consumers see
//! the right shape.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat,
};

/// `/dev/null` — read = EOF, write = discard.
struct DevNull;

impl FileOps for DevNull {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        Box::pin(async move { Ok(len) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size:         0,
            blocks:       0,
            mode:         Mode { file_type: FileType::Special, perms: 0o666 },
            mtime_cycles: 0,
        }
    }
}

/// `/dev/zero` — read = zero-fill the buffer, write = discard.
struct DevZero;

impl FileOps for DevZero {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        // Zero-fill happens here so the future body owns the slice
        // mutation; the async-block move keeps `buf` borrowed for
        // the future's lifetime.
        for slot in buf.iter_mut() { *slot = 0; }
        Box::pin(async move { Ok(len) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        Box::pin(async move { Ok(len) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size:         0,
            blocks:       0,
            mode:         Mode { file_type: FileType::Special, perms: 0o666 },
            mtime_cycles: 0,
        }
    }
}

/// `DevFs` root directory — exposes `null` and `zero` as fixed
/// children. No mutation surface (the trait defaults return
/// `Unsupported` on every override-able method).
struct DevDir;

impl DirOps for DevDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        match name {
            "null" => Some(Arc::new(DevNull) as Arc<dyn FileOps>),
            "zero" => Some(Arc::new(DevZero) as Arc<dyn FileOps>),
            _      => None,
        }
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Names are `&'static str` literals — fine for DirEntry.
        const ENTRIES: &[DirEntry] = &[
            DirEntry { name: "null", file_type: FileType::Special },
            DirEntry { name: "zero", file_type: FileType::Special },
        ];
        Box::new(ENTRIES.iter().copied())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let entries = [
            ("null", FileType::Special),
            ("zero", FileType::Special),
        ];
        entries.iter()
            .skip(cursor)
            .take(max)
            .map(|(n, t)| ((*n).into(), *t))
            .collect()
    }
}

/// Mountable handle. `DevFs::new()` returns one suitable for
/// `registry().mount("/dev", DevFs::new())`.
#[derive(Debug)]
pub struct DevFs {
    name: String,
}

impl DevFs {
    pub fn new() -> Self {
        Self { name: "devfs".into() }
    }
}

impl Default for DevFs {
    fn default() -> Self { Self::new() }
}

impl FsInstance for DevFs {
    fn root(&self) -> Arc<dyn DirOps> { Arc::new(DevDir) }
    fn name(&self) -> &str { &self.name }
}
