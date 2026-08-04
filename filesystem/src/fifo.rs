//! Named pipes (FIFOs, `S_IFIFO`).
//!
//! A FIFO is a filesystem inode ([`FifoNode`]) that owns ONE shared byte
//! ring ([`FifoShared`]). Every `open()` of the FIFO's path resolves — via
//! the filesystem's `lookup` — to the same `FifoNode`, so all openers
//! rendezvous on the same buffer keyed by node identity. `sys_open` reads
//! the node's `fifo_shared()` and installs a per-open [`FifoHandle`] that
//! carries the access direction (O_RDONLY / O_WRONLY / O_RDWR) and the
//! peer-open counting; the bare node is never installed as an fd.
//!
//! The ring + blocking model reuses the anonymous-pipe design in the
//! userspace crate's `pipe` module: a `VecDeque<u8>` behind an
//! `IrqSafeSpinLock`, with EOF and SIGPIPE derived from OPEN COUNTS rather
//! than per-half `Arc`-drop flags — a FIFO is opened many times through one
//! shared node, so the reader-count / writer-count are the correct signals:
//!
//! * a reader reads 0 (EOF) once the buffer is empty AND `writers == 0`;
//! * a write with `readers == 0` yields [`FsError::BrokenPipe`], which the
//!   syscall layer turns into SIGPIPE + `-EPIPE`.
//!
//! Blocking on `read()`/`write()` is driven the same way anonymous pipes
//! are: `read_should_block()` reports "empty but not at EOF", and the
//! syscall layer parks + re-executes. The open-time peer rendezvous
//! (O_RDONLY blocks until a writer appears, and vice versa) lives in
//! `sys_open`, which must release every filesystem/fd-table lock before it
//! parks — a FIFO open holding a lock across the wait would wedge the
//! kernel.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_ERR, POLL_HUP, POLL_IN, POLL_OUT,
};

/// FIFO ring capacity, matching the anonymous-pipe buffer and Linux's
/// default pipe size (`include/linux/pipe_fs_i.h`: 16 pages × 4 KiB —
/// FIFOs use the same `pipe_inode_info` as anonymous pipes).
const FIFO_BUF_BYTES: usize = 65536;

/// POSIX `PIPE_BUF` (Linux `include/linux/limits.h`): writes of at most
/// this many bytes are atomic — `fs/pipe.c::pipe_write` writes nothing
/// rather than splitting them across a partial buffer.
const PIPE_BUF: usize = 4096;

/// The shared, mutable state of a named pipe: the byte queue plus live
/// reader/writer OPEN counts. Both counts are the per-open population of
/// [`FifoHandle`]s currently referencing this FIFO, incremented when a
/// handle is built (at `open`) and decremented on the handle's `Drop` (at
/// `close`). EOF is `queue empty && writers == 0`; a write with
/// `readers == 0` is a broken pipe.
#[derive(Debug)]
pub struct FifoShared {
    queue: IrqSafeSpinLock<VecDeque<u8>>,
    /// Number of read-capable handles currently open (O_RDONLY + O_RDWR).
    readers: AtomicU32,
    /// Number of write-capable handles currently open (O_WRONLY + O_RDWR).
    writers: AtomicU32,
}

impl FifoShared {
    fn new() -> Self {
        FifoShared {
            queue: IrqSafeSpinLock::new(VecDeque::with_capacity(FIFO_BUF_BYTES)),
            readers: AtomicU32::new(0),
            writers: AtomicU32::new(0),
        }
    }

    /// Live count of write-capable openers — a reader at an empty buffer
    /// is at EOF exactly when this is 0.
    pub fn writer_count(&self) -> u32 {
        self.writers.load(Ordering::Acquire)
    }

    /// Live count of read-capable openers — a writer with 0 readers hits a
    /// broken pipe (SIGPIPE / EPIPE).
    pub fn reader_count(&self) -> u32 {
        self.readers.load(Ordering::Acquire)
    }
}

/// A named-pipe inode. Stored in a directory like any other node; its
/// `FileOps::stat` reports [`FileType::Fifo`] and `fifo_shared()` hands
/// back the shared buffer so `open` can build a directional handle. The
/// node's own `read`/`write` are never the hot path (openers get a
/// [`FifoHandle`]) but are defined for completeness: reading the bare node
/// returns EOF, writing it is a broken pipe.
pub struct FifoNode {
    ino: u64,
    shared: Arc<FifoShared>,
    perms: AtomicU32,
    uid: AtomicU32,
    gid: AtomicU32,
}

impl core::fmt::Debug for FifoNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FifoNode")
            .field("ino", &self.ino)
            .finish_non_exhaustive()
    }
}

impl FifoNode {
    /// Mint a fresh FIFO inode with the given inode number and permission
    /// bits, owned by root (0, 0). The shared buffer starts empty with no
    /// openers.
    pub fn new(ino: u64, perms: u16) -> Self {
        FifoNode {
            ino,
            shared: Arc::new(FifoShared::new()),
            perms: AtomicU32::new((perms & 0o777) as u32),
            uid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
        }
    }

    /// The FIFO's permission bits — read by the per-open handle's `stat`
    /// so `chmod` on the path is reflected through either surface.
    fn perms(&self) -> u16 {
        (self.perms.load(Ordering::Relaxed) & 0o777) as u16
    }
}

impl FileOps for FifoNode {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // The bare node isn't a directional endpoint; a raw read reports EOF.
        Box::pin(async move { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::BrokenPipe) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Fifo,
                perms: self.perms(),
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

    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.perms.store((perms & 0o777) as u32, Ordering::Relaxed);
            Ok(())
        })
    }

    fn is_stream(&self) -> bool {
        true
    }

    fn fifo_shared(&self) -> Option<Arc<FifoShared>> {
        Some(Arc::clone(&self.shared))
    }
}

/// A single `open()` of a FIFO. Carries the shared buffer plus the access
/// direction; increments the matching open count(s) at construction and
/// decrements them on `Drop` (fd close). Read/write/poll route through the
/// shared ring, with EOF and broken-pipe keyed on the peer counts.
pub struct FifoHandle {
    shared: Arc<FifoShared>,
    /// Retains a named VFS inode after unlink until this open description
    /// closes. Anonymous/test handles leave this empty.
    _inode_owner: Option<Arc<dyn FileOps>>,
    ino: u64,
    perms: u16,
    uid: u32,
    gid: u32,
    can_read: bool,
    can_write: bool,
}

impl core::fmt::Debug for FifoHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FifoHandle")
            .field("can_read", &self.can_read)
            .field("can_write", &self.can_write)
            .finish_non_exhaustive()
    }
}

impl FifoHandle {
    /// Build a per-open handle for `shared`, bumping the reader/writer open
    /// counts to match the requested direction. `ino`/`perms`/`uid`/`gid` are
    /// copied from the node so `stat`/`fstat` on the handle reports the FIFO's
    /// identity, mode, and owner. The corresponding count is dropped in `Drop`.
    pub fn open(
        shared: Arc<FifoShared>,
        ino: u64,
        perms: u16,
        uid: u32,
        gid: u32,
        can_read: bool,
        can_write: bool,
    ) -> Self {
        Self::open_inner(shared, None, ino, perms, uid, gid, can_read, can_write)
    }

    /// Open a named FIFO and retain the filesystem node that owns its inode.
    #[allow(clippy::too_many_arguments)]
    pub fn open_owned(
        shared: Arc<FifoShared>,
        inode_owner: Arc<dyn FileOps>,
        ino: u64,
        perms: u16,
        uid: u32,
        gid: u32,
        can_read: bool,
        can_write: bool,
    ) -> Self {
        Self::open_inner(
            shared,
            Some(inode_owner),
            ino,
            perms,
            uid,
            gid,
            can_read,
            can_write,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_inner(
        shared: Arc<FifoShared>,
        inode_owner: Option<Arc<dyn FileOps>>,
        ino: u64,
        perms: u16,
        uid: u32,
        gid: u32,
        can_read: bool,
        can_write: bool,
    ) -> Self {
        if can_read {
            shared.readers.fetch_add(1, Ordering::AcqRel);
        }
        if can_write {
            shared.writers.fetch_add(1, Ordering::AcqRel);
        }
        FifoHandle {
            shared,
            _inode_owner: inode_owner,
            ino,
            perms,
            uid,
            gid,
            can_read,
            can_write,
        }
    }

    /// The shared buffer this handle is attached to — used by the open-time
    /// peer rendezvous in `sys_open` to poll the peer counts.
    pub fn shared(&self) -> &Arc<FifoShared> {
        &self.shared
    }
}

impl Drop for FifoHandle {
    fn drop(&mut self) {
        // Releasing the last write-capable handle flips the reader to EOF;
        // releasing the last read-capable handle makes further writes a
        // broken pipe.
        if self.can_read {
            self.shared.readers.fetch_sub(1, Ordering::AcqRel);
        }
        if self.can_write {
            self.shared.writers.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl FileOps for FifoHandle {
    fn ino(&self) -> u64 {
        self.ino
    }

    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if !self.can_read {
                // Reading a write-only FIFO handle: EBADF on Linux
                // (`fs/read_write.c::vfs_read`, FMODE_READ check). The old
                // Ok(0) masqueraded as a clean EOF.
                return Err(FsError::BadFd);
            }
            let mut q = self.shared.queue.lock();
            let avail = q.len();
            if avail == 0 {
                // Empty: EOF only once every writer has closed. Otherwise a
                // 0-byte read means "try again" and the syscall layer parks
                // (see `read_should_block`).
                return Ok(0);
            }
            let n = core::cmp::min(buf.len(), avail);
            for slot in buf.iter_mut().take(n) {
                // pop_front cannot fail: avail > 0 above.
                *slot = q.pop_front().unwrap();
            }
            Ok(n)
        })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if !self.can_write {
                // Writing a read-only FIFO handle: EBADF on Linux
                // (`fs/read_write.c::vfs_write`, FMODE_WRITE check). The old
                // BrokenPipe here additionally raised a bogus SIGPIPE —
                // Linux never reaches the pipe op for a wrong-mode fd.
                return Err(FsError::BadFd);
            }
            // No readers left: broken pipe. The syscall layer raises SIGPIPE
            // and returns -EPIPE.
            if self.shared.readers.load(Ordering::Acquire) == 0 {
                return Err(FsError::BrokenPipe);
            }
            let mut q = self.shared.queue.lock();
            let room = FIFO_BUF_BYTES.saturating_sub(q.len());
            // POSIX PIPE_BUF atomicity (`fs/pipe.c::pipe_write`): a write of
            // ≤ PIPE_BUF bytes is all-or-nothing; the 0-progress result makes
            // the syscall layer park (blocking) or EAGAIN (O_NONBLOCK).
            if buf.len() <= PIPE_BUF && room < buf.len() {
                return Ok(0);
            }
            let n = core::cmp::min(buf.len(), room);
            for &b in buf.iter().take(n) {
                q.push_back(b);
            }
            Ok(n)
        })
    }

    fn stat(&self) -> Stat {
        // st_size on a FIFO is 0 on Linux (pipefs never updates i_size);
        // FIONREAD is the way to count queued bytes.
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Fifo,
                perms: self.perms,
            },
            mtime_cycles: 0,
        }
    }

    fn owners(&self) -> (u32, u32) {
        (self.uid, self.gid)
    }

    fn poll_readiness(&self) -> u32 {
        // `fs/pipe.c::pipe_poll`: read side gets EPOLLIN only while data is
        // queued and EPOLLHUP once the writers are gone (both may be set);
        // write side gets EPOLLOUT while there is room and EPOLLERR once
        // the readers are gone.
        let mut mask = 0;
        let q = self.shared.queue.lock();
        if self.can_read {
            if !q.is_empty() {
                mask |= POLL_IN;
            }
            if self.shared.writers.load(Ordering::Acquire) == 0 {
                mask |= POLL_HUP;
            }
        }
        if self.can_write {
            if q.len() < FIFO_BUF_BYTES {
                mask |= POLL_OUT;
            }
            if self.shared.readers.load(Ordering::Acquire) == 0 {
                mask |= POLL_ERR;
            }
        }
        mask
    }

    fn read_should_block(&self) -> bool {
        // Block (retry) only while readable-but-not-EOF: the queue is empty
        // AND a writer is still open. A write-only handle never blocks a read
        // here (it EOFs immediately above). Keying EOF on
        // (empty && writers == 0) makes a data-arrived race re-read instead of
        // mis-reading a transient 0 as end-of-file — the same discipline the
        // anonymous pipe uses.
        if !self.can_read {
            return false;
        }
        let q = self.shared.queue.lock();
        !(q.is_empty() && self.shared.writers.load(Ordering::Acquire) == 0)
    }

    fn write_should_block(&self) -> bool {
        // A full-FIFO write that made no progress must PARK the writer while
        // a reader is still open (`fs/pipe.c::pipe_write` waits for room).
        // When the readers are gone, write() returns BrokenPipe instead of
        // 0, so this is only consulted with a live reader.
        self.can_write && self.shared.readers.load(Ordering::Acquire) > 0
    }

    fn is_stream(&self) -> bool {
        // A FIFO is a non-seekable byte stream: reject it as a sendfile(2)
        // source (EINVAL) so consumers fall back to a read()/write() loop,
        // matching the anonymous pipe.
        true
    }

    fn pipe_capacity(&self) -> Option<usize> {
        // `fcntl(F_GETPIPE_SZ)` works on FIFOs exactly as on anonymous
        // pipes (both are `pipe_inode_info` buffers on Linux).
        Some(FIFO_BUF_BYTES)
    }

    fn pipe_peek(&self, max: usize) -> Option<alloc::vec::Vec<u8>> {
        if !self.can_read {
            return None;
        }
        let q = self.shared.queue.lock();
        let n = core::cmp::min(max, q.len());
        Some(q.iter().copied().take(n).collect())
    }

    fn fifo_shared(&self) -> Option<Arc<FifoShared>> {
        Some(Arc::clone(&self.shared))
    }
}
