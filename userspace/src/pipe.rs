//! Anonymous pipe(2) file-ops.
//!
//! Backs a pair of fd-table entries with a shared byte ring buffer.
//! Stage-4 first cut: the read/write futures resolve immediately
//! with a try-style result rather than parking on Pending — the test
//! harness has no scheduler-driven progress, so a blocking pipe
//! would deadlock. Real consumers loop on a 0-byte read until either
//! data arrives or the writer side has closed; once a real polling
//! executor is wired in, the futures here can grow waker registration
//! without breaking the existing call-sites.
//!
//! Why not `narf-ipc::Ring<u8, N>`? `Ring`'s `Producer`/`Consumer`
//! halves are `!Sync`, but `FileOps: Send + Sync` — and the same
//! pipe-half is shared between parent and child after a future
//! `fork`. A plain `IrqSafeSpinLock<VecDeque<u8>>` keeps the lock
//! discipline uniform with the rest of the userspace crate (every
//! per-task table here is `IrqSafeSpinLock`-protected) and avoids
//! pulling a third sync primitive into the dep graph.
//!
//! Closure semantics: the read-side `FileOps::read` returns 0 (EOF)
//! when the buffer is empty AND the writer side has been dropped;
//! a 0-byte read with the writer still alive means "try again later"
//! (POSIX would return EAGAIN here for a non-blocking fd). The
//! writer side never EOFs; `write` on a closed reader returns
//! `FsError::BrokenPipe`, which the Linux syscall layer translates to
//! SIGPIPE plus `EPIPE`.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_filesystem::{FileOps, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

/// Pipe ring capacity. Matches Linux's default pipe buffer
/// (`include/linux/pipe_fs_i.h`: 16 pages × 4 KiB = 65536), which is
/// what `fcntl(F_GETPIPE_SZ)` reports on a fresh pipe.
const PIPE_BUF_BYTES: usize = 65536;

/// POSIX `PIPE_BUF` (Linux `include/linux/limits.h`): writes of at most
/// this many bytes are ATOMIC — `fs/pipe.c::pipe_write` refuses to split
/// them across a partial buffer ("We must still wake up any pending
/// writers... but only do an atomic write if buf is small enough"), so a
/// short-on-room write of ≤ PIPE_BUF bytes writes NOTHING and blocks
/// (or EAGAINs for O_NONBLOCK) until the whole payload fits.
const PIPE_BUF: usize = 4096;

/// Linux `FIONREAD` / `TIOCINQ`: write the immediately readable byte
/// count as an `int` through the ioctl argument pointer.
const FIONREAD: u32 = 0x541B;

/// Shared mutable state between the read+write halves: the byte
/// queue plus a "writer dropped" flag. The `closed_*` flags let
/// either half observe the peer-side close from the read/write
/// future without holding the queue lock.
#[derive(Debug)]
struct PipeShared {
    queue: IrqSafeSpinLock<VecDeque<u8>>,
    /// Set when the write half is dropped. The read half observes
    /// this to flip empty-read from "try again" to EOF.
    writer_closed: AtomicBool,
    /// Set when the read half is dropped. The write half observes
    /// this and reports `BrokenPipe` to the syscall layer.
    reader_closed: AtomicBool,
    readable_token: AtomicU64,
    writable_token: AtomicU64,
    /// Durable readiness cell shared by both halves — the migration target
    /// that replaces the two edge tokens + the `notify(0)` herd with a fused
    /// arm/set per-fd wake (see `narf_lib::readiness`). One cell carries the
    /// union of both views: POLL_IN (queue non-empty), POLL_OUT (room), POLL_HUP
    /// (writer gone), POLL_ERR (reader gone). The read fd arms POLL_IN|POLL_HUP,
    /// the write fd arms POLL_OUT|POLL_ERR (the poll/epoll layer folds ERR|HUP
    /// into every arm interest), and `set` wakes each waiter on its own bits.
    readiness: narf_lib::readiness::Readiness,
}

impl PipeShared {
    /// Recompute the durable readiness cell from the current queue occupancy and
    /// the peer-close flags, publishing the transition. POLL_IN (queue
    /// non-empty), POLL_OUT (room below capacity), POLL_HUP (writer gone),
    /// POLL_ERR (reader gone) — exactly the union of `PipeRead::poll_readiness`
    /// and `PipeWrite::poll_readiness`. `set` bumps its edge sequence and wakes
    /// armed waiters only on a rising edge, all under one lock (drop-free), so a
    /// concurrent `arm` can never miss this transition. Called after every
    /// write/read/close that changes state; the legacy edge tokens + `notify`
    /// stay belt-and-suspenders during the migration.
    fn sync_readiness(&self) {
        let len = self.queue.lock().len();
        let writer_closed = self.writer_closed.load(Ordering::Acquire);
        let reader_closed = self.reader_closed.load(Ordering::Acquire);
        let mut add = 0u32;
        let mut clear = 0u32;
        if len > 0 {
            add |= narf_filesystem::POLL_IN;
        } else {
            clear |= narf_filesystem::POLL_IN;
        }
        if len < PIPE_BUF_BYTES {
            add |= narf_filesystem::POLL_OUT;
        } else {
            clear |= narf_filesystem::POLL_OUT;
        }
        if writer_closed {
            add |= narf_filesystem::POLL_HUP;
        } else {
            clear |= narf_filesystem::POLL_HUP;
        }
        if reader_closed {
            add |= narf_filesystem::POLL_ERR;
        } else {
            clear |= narf_filesystem::POLL_ERR;
        }
        self.readiness.set(add, clear);
    }
}

/// Read end of a pipe.
pub struct PipeRead {
    shared: Arc<PipeShared>,
}

/// Write end of a pipe.
pub struct PipeWrite {
    shared: Arc<PipeShared>,
}

/// Result classes needed by the read-end `vmsplice(2)` transaction.  The
/// user-copy errno is kept intact so the syscall layer can distinguish an
/// invalid range (`EINVAL`) from an inaccessible one (`EFAULT`).
pub(crate) enum VmspliceDrainError {
    WouldBlock,
    User(u64),
}

impl core::fmt::Debug for PipeRead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PipeRead").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for PipeWrite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PipeWrite").finish_non_exhaustive()
    }
}

/// Allocate a new pipe pair. Both halves share a single
/// `Arc<PipeShared>`; dropping either flips the corresponding
/// `*_closed` flag for the peer to observe.
pub fn pipe_pair() -> (Arc<PipeRead>, Arc<PipeWrite>) {
    let shared = Arc::new(PipeShared {
        queue: IrqSafeSpinLock::new(VecDeque::with_capacity(PIPE_BUF_BYTES)),
        writer_closed: AtomicBool::new(false),
        reader_closed: AtomicBool::new(false),
        readable_token: AtomicU64::new(0),
        writable_token: AtomicU64::new(0),
        // Fresh pipe: empty (not readable), has room (writable), both ends open.
        readiness: narf_lib::readiness::Readiness::new(narf_filesystem::POLL_OUT),
    });
    (
        Arc::new(PipeRead {
            shared: shared.clone(),
        }),
        Arc::new(PipeWrite { shared }),
    )
}

impl PipeRead {
    /// Copy the current pipe prefix to `dst`, consuming it only after the
    /// guarded user copy succeeds.  Keeping the queue lock across the copy is
    /// deliberate: another reader must not consume or reorder the prefix
    /// between observation and commit.  A failed copy leaves every byte in
    /// the pipe, matching Linux's pipe-to-user splice actor.
    pub(crate) fn vmsplice_to_user(
        &self,
        dst: u64,
        max: usize,
    ) -> Result<usize, VmspliceDrainError> {
        crate::handlers::validate_user_range(dst, max).map_err(VmspliceDrainError::User)?;

        // Allocate before disabling IRQs on the queue lock.  A pipe can never
        // supply more than its fixed capacity, even if the iovec is larger.
        let mut staging = alloc::vec::Vec::with_capacity(core::cmp::min(max, PIPE_BUF_BYTES));
        let mut q = self.shared.queue.lock();
        let avail = q.len();
        if avail == 0 {
            return if self.shared.writer_closed.load(Ordering::Acquire) {
                Ok(0)
            } else {
                Err(VmspliceDrainError::WouldBlock)
            };
        }
        let n = core::cmp::min(max, avail);
        staging.extend(q.iter().copied().take(n));

        // SAFETY: validate_user_range accepted the entire destination above;
        // the guarded copy converts a racing unmap/protection change to an
        // error.  The queue is still untouched on that error path.
        unsafe { crate::handlers::copy_to_user(dst, &staging) }
            .map_err(VmspliceDrainError::User)?;
        q.drain(..n);
        let became_writable = avail == PIPE_BUF_BYTES;
        drop(q);

        if became_writable {
            self.shared.writable_token.fetch_add(1, Ordering::Release);
        }
        self.shared.sync_readiness();
        narf_net::readiness::notify(0);
        Ok(n)
    }
}

impl Drop for PipeRead {
    fn drop(&mut self) {
        // The fd-table holds an `Arc<dyn FileOps>` per slot, so this
        // Drop only fires when the *last* `Arc<PipeRead>` (across
        // every dup'd fd in every task) goes away — at that point
        // there are no readers left and the writer should observe
        // EOF on its side.
        self.shared.reader_closed.store(true, Ordering::Release);
        self.shared.writable_token.fetch_add(1, Ordering::Release);
        // Latch POLL_ERR into the durable cell (store THEN sync so it observes
        // reader_closed=true) — wakes a writer parked on POLL_OUT|POLL_ERR, even
        // one blocked on a full pipe where no POLL_OUT edge ever comes.
        self.shared.sync_readiness();
        narf_net::readiness::notify(0);
    }
}

impl Drop for PipeWrite {
    fn drop(&mut self) {
        // Same Arc-counted reasoning as PipeRead::drop — only flips
        // when every writer fd has been closed.
        self.shared.writer_closed.store(true, Ordering::Release);
        self.shared.readable_token.fetch_add(1, Ordering::Release);
        // Latch POLL_HUP into the durable cell (store THEN sync so it observes
        // writer_closed=true) — wakes a reader parked on POLL_IN|POLL_HUP so it
        // runs read()→0=EOF instead of hanging on the lost-wake backstop.
        self.shared.sync_readiness();
        narf_net::readiness::notify(0);
    }
}

impl FileOps for PipeRead {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let mut q = self.shared.queue.lock();
            let avail = q.len();
            if avail == 0 {
                // Empty: "writer still open" is would-block, "writer gone" is
                // a real EOF. Linux `fs/pipe.c::pipe_read` makes exactly this
                // split (-EAGAIN vs 0).
                //
                // Deciding it HERE, under the same lock that observed the
                // empty queue, is what makes it race-free. The previous
                // arrangement returned Ok(0) and made the syscall layer
                // re-classify it in a separate lock acquisition, so a writer
                // landing in between could turn arrived data into a spurious
                // EOF. One atomic decision removes the ambiguity.
                return if self.shared.writer_closed.load(Ordering::Acquire) {
                    Ok(0)
                } else {
                    Err(narf_filesystem::FsError::WouldBlock)
                };
            }
            let n = core::cmp::min(buf.len(), avail);
            // Bulk drain: `VecDeque::drain` copies the front `n` bytes in as
            // few `memcpy`s as the ring's two contiguous slices allow, instead
            // of `n` individual `pop_front`s — the byte-at-a-time loop dominated
            // large pipe/splice transfers.
            for (slot, byte) in buf.iter_mut().zip(q.drain(..n)) {
                *slot = byte;
            }
            let became_writable = avail == PIPE_BUF_BYTES && n != 0;
            drop(q);
            if became_writable {
                self.shared.writable_token.fetch_add(1, Ordering::Release);
            }
            if n != 0 {
                // Draining can clear POLL_IN (queue now empty) and set POLL_OUT
                // (room freed); republish so a writer parked on this pipe's
                // readiness cell wakes, and bump the global notify generation so
                // a writer parked via `park_reexecute_on_io` (armed on that
                // generation, not the cell) re-runs instead of sleeping out its
                // deadline.
                self.shared.sync_readiness();
                narf_net::readiness::notify(0);
            }
            Ok(n)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        // Writing the read end: Linux fails this with EBADF from the
        // FMODE_WRITE check in `fs/read_write.c::vfs_write` — the pipe
        // read end is opened O_RDONLY. Returning Ok(0) here (the old
        // behaviour) made writers loop forever on a fd that can never
        // make progress.
        Box::pin(async move { Err(narf_filesystem::FsError::BadFd) })
    }

    fn stat(&self) -> Stat {
        // An anonymous pipe fstats as a FIFO: `fs/pipe.c::create_pipe_files`
        // creates the pipefs inode with `S_IFIFO | S_IRUSR | S_IWUSR`, and
        // pipefs never updates i_size, so st_size is always 0 (FIONREAD is
        // the sanctioned way to count queued bytes). Reporting S_IFREG here
        // was not cosmetic: GNU coreutils ≥ 9 `cat` switches to its
        // copy_file_range path when `S_ISREG(fstat(stdin))` holds, which on
        // a pipe stdin turned every `cat < pipe > file` into an instant
        // zero-byte "EOF" (the Fedora xkbcomp keymap-capture failure).
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: narf_filesystem::FileType::Fifo,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, narf_filesystem::FsError> {
        if cmd != FIONREAD {
            return Err(narf_filesystem::FsError::Unsupported);
        }
        let bytes = (self.shared.queue.lock().len() as i32).to_le_bytes();
        // SAFETY: `copy_to_user` validates the destination through the SMAP
        // window; FIONREAD writes one Linux `int`.
        if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
            return Err(narf_filesystem::FsError::InvalidData);
        }
        Ok(0)
    }

    fn poll_readiness(&self) -> u32 {
        // `fs/pipe.c::pipe_poll`, read side: EPOLLIN only while data is
        // queued; EPOLLHUP once the last writer is gone (both may be set —
        // an EOF'd pipe with residual data reports EPOLLIN | EPOLLHUP).
        // The old mask granted a bare POLLIN for "empty + writer gone",
        // hiding the hangup from callers that branch on POLLHUP. poll(2)/
        // select(2)/epoll all deliver HUP regardless of the requested
        // event set, so an EOF still terminates a POLLIN wait.
        let mut mask = 0;
        let q = self.shared.queue.lock();
        if !q.is_empty() {
            mask |= narf_filesystem::POLL_IN;
        }
        if self.shared.writer_closed.load(Ordering::Acquire) {
            mask |= narf_filesystem::POLL_HUP;
        }
        mask
    }

    fn readiness_notifies(&self) -> bool {
        true
    }

    fn poll_edge_token(&self) -> (u64, u64) {
        (self.shared.readable_token.load(Ordering::Acquire), 0)
    }

    fn readiness(&self) -> Option<&narf_lib::readiness::Readiness> {
        // The shared cell reaches both halves; a read fd's poller arms it with
        // POLL_IN|POLL_HUP (the poll/epoll layer folds HUP in), and a peer write
        // or close fires exactly this waiter. Reachable directly through the Arc
        // field, so the default `arm_readiness`/`disarm_readiness` suffice — no
        // override, unlike the lock-guarded AF_UNIX ring.
        Some(&self.shared.readiness)
    }

    fn is_stream(&self) -> bool {
        // A pipe is a non-seekable byte stream: reject it as a `sendfile(2)`
        // source (EINVAL) so busybox `cat` (which sendfiles pipe→file) falls
        // back to a read()/write() loop. The sendfile fast path's copy core
        // treats a transient empty read on a still-open pipe as EOF, silently
        // truncating to 0 bytes; the read() loop parks correctly instead.
        true
    }

    fn pipe_peek(&self, max: usize) -> Option<alloc::vec::Vec<u8>> {
        let q = self.shared.queue.lock();
        let n = core::cmp::min(max, q.len());
        // Copy the front `n` bytes without consuming them — tee(2)
        // duplicates pipe data, leaving the source readable.
        Some(q.iter().copied().take(n).collect())
    }

    fn pipe_capacity(&self) -> Option<usize> {
        Some(PIPE_BUF_BYTES)
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

impl FileOps for PipeWrite {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Reading the write end: EBADF on Linux (`fs/read_write.c::vfs_read`
        // FMODE_READ check — the pipe write end is opened O_WRONLY). The
        // old Ok(0) here masqueraded as a clean EOF.
        Box::pin(async move { Err(narf_filesystem::FsError::BadFd) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            // The syscall layer turns this into SIGPIPE plus -EPIPE.
            if self.shared.reader_closed.load(Ordering::Acquire) {
                return Err(narf_filesystem::FsError::BrokenPipe);
            }
            let mut q = self.shared.queue.lock();
            let was_empty = q.is_empty();
            let room = PIPE_BUF_BYTES.saturating_sub(q.len());
            // POSIX PIPE_BUF atomicity (`fs/pipe.c::pipe_write`): a write of
            // ≤ PIPE_BUF bytes is all-or-nothing — if it doesn't fit in the
            // free space, write NOTHING. The 0-progress result makes the
            // syscall layer park a blocking writer (re-executing until the
            // reader drains room) or return EAGAIN for O_NONBLOCK, exactly
            // Linux's split. Larger writes may land a partial prefix.
            if buf.len() <= PIPE_BUF && room < buf.len() {
                return Ok(0);
            }
            let n = core::cmp::min(buf.len(), room);
            // Bulk enqueue: `extend` appends the whole prefix in one pass
            // (amortised memcpy into the ring), replacing `n` individual
            // `push_back`s that dominated large pipe/vmsplice writes.
            q.extend(buf[..n].iter().copied());
            drop(q);
            if n != 0 {
                if was_empty {
                    self.shared.readable_token.fetch_add(1, Ordering::Release);
                }
                // Data added sets POLL_IN (and clears POLL_OUT if now full);
                // republish so a reader parked on this pipe wakes.
                self.shared.sync_readiness();
                narf_net::readiness::notify(0);
            }
            Ok(n)
        })
    }

    fn stat(&self) -> Stat {
        // Same shape as the read end: S_IFIFO, zero size — see
        // `PipeRead::stat` (fs/pipe.c::create_pipe_files).
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: narf_filesystem::FileType::Fifo,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, narf_filesystem::FsError> {
        if cmd != FIONREAD {
            return Err(narf_filesystem::FsError::Unsupported);
        }
        let bytes = (self.shared.queue.lock().len() as i32).to_le_bytes();
        // Linux accepts FIONREAD on either pipe end and reports the shared
        // unread-byte count.
        // SAFETY: `copy_to_user` validates the destination through the SMAP
        // window; FIONREAD writes one Linux `int`.
        if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
            return Err(narf_filesystem::FsError::InvalidData);
        }
        Ok(0)
    }

    fn poll_readiness(&self) -> u32 {
        // `fs/pipe.c::pipe_poll`, write side: EPOLLOUT while the buffer has
        // room; EPOLLERR once the last reader is gone. The old mask granted
        // POLLOUT on reader-close (instead of POLLERR), so a poller never
        // saw the error condition Linux reports.
        let mut mask = 0;
        let q = self.shared.queue.lock();
        if q.len() < PIPE_BUF_BYTES {
            mask |= narf_filesystem::POLL_OUT;
        }
        if self.shared.reader_closed.load(Ordering::Acquire) {
            mask |= narf_filesystem::POLL_ERR;
        }
        mask
    }

    fn readiness_notifies(&self) -> bool {
        true
    }

    fn poll_edge_token(&self) -> (u64, u64) {
        (0, self.shared.writable_token.load(Ordering::Acquire))
    }

    fn readiness(&self) -> Option<&narf_lib::readiness::Readiness> {
        // Same shared cell as the read half; a write fd's poller arms it with
        // POLL_OUT|POLL_ERR (the poll/epoll layer folds ERR in), so a peer read
        // (room frees) or a reader close (POLL_ERR) fires exactly this waiter.
        Some(&self.shared.readiness)
    }

    fn write_should_block(&self) -> bool {
        // A full-pipe write returns 0; block the writer (POSIX blocking write
        // waits for room) as long as a reader is still open. When the reader
        // has closed, write() returns BrokenPipe rather than 0, so this is
        // only consulted while the reader is present.
        !self.shared.reader_closed.load(Ordering::Acquire)
    }

    fn is_stream(&self) -> bool {
        // Same non-seekable-stream marker as the read end: `lseek(2)` on
        // either pipe end is ESPIPE (pipefifo_fops has no .llseek).
        true
    }

    fn pipe_capacity(&self) -> Option<usize> {
        Some(PIPE_BUF_BYTES)
    }
}
