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

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat};

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
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }
}

/// `/dev/random` and `/dev/urandom` — read = fill with PRNG bytes,
/// write = discard. NARF doesn't distinguish blocking-vs-non-
/// blocking RNG today (no entropy pool), so both entries map to
/// the same backing.
///
/// Backing: a Park-Miller minimal-standard LCG seeded lazily on
/// first read from `narf_time::now_cycles()`. Matches the same
/// non-cryptographic guarantee `crypto::per_task_rng()` documents.
struct DevRandom;

use core::sync::atomic::{AtomicU64, Ordering};
static RANDOM_STATE: AtomicU64 = AtomicU64::new(0);

fn next_random_u32() -> u32 {
    let mut s = RANDOM_STATE.load(Ordering::Relaxed);
    if s == 0 {
        let cy = narf_time::now_cycles();
        s = (cy ^ 0x9E37_79B9_7F4A_7C15).wrapping_mul(0xC2B2_AE3D_27D4_EB4F) & 0x7FFF_FFFF;
        if s == 0 {
            s = 1;
        }
    }
    s = (s.wrapping_mul(48271)) % 0x7FFF_FFFF;
    RANDOM_STATE.store(s, Ordering::Relaxed);
    s as u32
}

impl FileOps for DevRandom {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        // Fill the user buffer in 4-byte chunks, plus tail bytes.
        let mut i = 0usize;
        while i + 4 <= len {
            let v = next_random_u32();
            buf[i] = (v & 0xFF) as u8;
            buf[i + 1] = ((v >> 8) & 0xFF) as u8;
            buf[i + 2] = ((v >> 16) & 0xFF) as u8;
            buf[i + 3] = ((v >> 24) & 0xFF) as u8;
            i += 4;
        }
        if i < len {
            let v = next_random_u32();
            let mut shift = 0u32;
            while i < len {
                buf[i] = ((v >> shift) & 0xFF) as u8;
                i += 1;
                shift += 8;
            }
        }
        Box::pin(async move { Ok(len) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        Box::pin(async move { Ok(len) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o666,
            },
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
        for slot in buf.iter_mut() {
            *slot = 0;
        }
        Box::pin(async move { Ok(len) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        Box::pin(async move { Ok(len) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o666,
            },
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
            "random" => Some(Arc::new(DevRandom) as Arc<dyn FileOps>),
            "urandom" => Some(Arc::new(DevRandom) as Arc<dyn FileOps>),
            _ => None,
        }
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            self.lookup(name).ok_or(FsError::NotFound)
        })
    }

    fn lookup_dir_async<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move {
            // DevFs root has no subdirectories.
            Err(FsError::NotFound)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Names are `&'static str` literals — fine for DirEntry.
        const ENTRIES: &[DirEntry] = &[
            DirEntry {
                name: "null",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "zero",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "random",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "urandom",
                file_type: FileType::Special,
            },
        ];
        Box::new(ENTRIES.iter().copied())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let entries = [
            ("null", FileType::Special),
            ("zero", FileType::Special),
            ("random", FileType::Special),
            ("urandom", FileType::Special),
        ];
        entries
            .iter()
            .skip(cursor)
            .take(max)
            .map(|(n, t)| ((*n).into(), *t))
            .collect()
    }

    fn enumerate_async<'a>(&'a self, cursor: usize, max: usize) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move {
            Ok(self.enumerate(cursor, max))
        })
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
        Self {
            name: "devfs".into(),
        }
    }
}

impl Default for DevFs {
    fn default() -> Self {
        Self::new()
    }
}

impl FsInstance for DevFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(DevDir)
    }
    fn name(&self) -> &str {
        &self.name
    }
}

/// Boot helper: mount DevFs at `/dev` if no FS is already mounted
/// there. Idempotent — re-running silently no-ops on `Busy`.
/// Use during kernel init to give every user task /dev/null,
/// /dev/zero, /dev/random, /dev/urandom out of the box.
pub fn mount_default() {
    let auth = crate::bootstrap_mount_authority();
    let _ = crate::registry().mount(&auth, "/dev", DevFs::new());
}
