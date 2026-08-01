//! Miscellaneous `/dev` nodes: `/dev/full`.
//!
//! Linux ref: `drivers/char/mem.c full_read` / `full_write`.
//!
//! ## `/dev/full`
//!
//! - `read()` fills the buffer with zeros (same behaviour as `/dev/zero`).
//! - `write()` always returns `FsError::NoSpace` (ENOSPC), signalling that
//!   the device has no room.
//!
//! This is useful for testing applications' error-handling paths: write to
//! `/dev/full` to simulate a disk-full condition without actually filling a
//! disk.
//!
//! ## Deferred
//!
//! - `/dev/loop0..7` — file-backed loopback block devices.  These require
//!   the `block/` loopback driver which is not yet implemented.
//! - `/dev/fuse` — userspace filesystem channel.  Requires the FUSE transport
//!   layer (`filesystem/src/fuse.rs` carries the protocol types but the
//!   channel device node is deferred until a full FUSE daemon is available).

use alloc::boxed::Box;

use crate::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

/// `/dev/full` — read returns zeros; write returns ENOSPC.
///
/// Linux ref: `drivers/char/mem.c full_read` (returns zeros, like
///   `/dev/zero`) and `full_write` (returns -ENOSPC).
#[derive(Debug)]
pub struct DevFull;

impl FileOps for DevFull {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        for slot in buf.iter_mut() {
            *slot = 0;
        }
        Box::pin(async move { Ok(len) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::NoSpace) })
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

    fn rdev(&self) -> u64 {
        crate::devfs::linux_makedev(1, 7)
    }

    fn ino(&self) -> u64 {
        0xd001_0000_0000_0000 | self.rdev().wrapping_add(1)
    }
}
