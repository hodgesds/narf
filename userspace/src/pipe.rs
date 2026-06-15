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
//! writer side never EOFs; `write` on a closed reader silently
//! drops bytes (POSIX SIGPIPE / EPIPE is a follow-up).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_filesystem::{FileOps, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

/// Pipe ring capacity. Matches a single 4 KiB user page so a future
/// kernel-only Stage-5 zero-copy revision can drop the VecDeque for
/// a fixed-array-backed scheme without renumbering callers.
const PIPE_BUF_BYTES: usize = 4096;

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
    /// this to discard further writes silently (Stage-4 simplification
    /// — POSIX would surface SIGPIPE / EPIPE; deferred).
    reader_closed: AtomicBool,
}

/// Read end of a pipe.
pub struct PipeRead {
    shared: Arc<PipeShared>,
}

/// Write end of a pipe.
pub struct PipeWrite {
    shared: Arc<PipeShared>,
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
    });
    (
        Arc::new(PipeRead {
            shared: shared.clone(),
        }),
        Arc::new(PipeWrite { shared }),
    )
}

impl Drop for PipeRead {
    fn drop(&mut self) {
        // The fd-table holds an `Arc<dyn FileOps>` per slot, so this
        // Drop only fires when the *last* `Arc<PipeRead>` (across
        // every dup'd fd in every task) goes away — at that point
        // there are no readers left and the writer should observe
        // EOF on its side.
        self.shared.reader_closed.store(true, Ordering::Release);
    }
}

impl Drop for PipeWrite {
    fn drop(&mut self) {
        // Same Arc-counted reasoning as PipeRead::drop — only flips
        // when every writer fd has been closed.
        self.shared.writer_closed.store(true, Ordering::Release);
    }
}

impl FileOps for PipeRead {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let mut q = self.shared.queue.lock();
            let avail = q.len();
            if avail == 0 {
                // Empty: distinguish "writer still open" (try again)
                // from "writer gone" (EOF). Both surface as Ok(0)
                // today; the harness's reader loops at most once
                // here, and the test cases drive write-before-read
                // so the buffer is non-empty by the time read fires.
                return Ok(0);
            }
            let n = core::cmp::min(buf.len(), avail);
            for slot in buf.iter_mut().take(n) {
                // VecDeque::pop_front cannot fail: avail > 0 above.
                *slot = q.pop_front().unwrap();
            }
            Ok(n)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        // Reading from the write fd / writing to the read fd is a
        // POSIX EBADF; we surface a 0-byte write so callers loop
        // forever — Stage-4 doesn't have an errno-on-the-wire path.
        Box::pin(async move { Ok(0) })
    }

    fn stat(&self) -> Stat {
        // `mode` is "named pipe" in POSIX (S_IFIFO = 0o010000); we
        // don't carry the bit through `Mode` yet so report the
        // FILE_RW shape — callers that care use `fstat` for size.
        Stat {
            size: self.shared.queue.lock().len() as u64,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    fn poll_readiness(&self) -> u32 {
        let mut mask = 0;
        let q = self.shared.queue.lock();
        if !q.is_empty() || self.shared.writer_closed.load(Ordering::Acquire) {
            mask |= narf_filesystem::POLL_IN;
        }
        mask
    }

    fn read_should_block(&self) -> bool {
        // Block (retry the read) unless we are TRULY at EOF: the queue is empty
        // AND the writer has gone. Reporting "don't block" merely because the
        // queue is non-empty would drop data: sys_read calls read() and this
        // check under *separate* lock acquisitions, so if a writer on another
        // CPU pushes bytes in between, read() already returned 0 — and treating
        // that 0 as EOF (instead of re-reading) loses the bytes. Keying EOF on
        // (empty AND writer_closed) makes a data-arrived race re-read instead.
        let q = self.shared.queue.lock();
        !(q.is_empty() && self.shared.writer_closed.load(Ordering::Acquire))
    }

    fn pipe_peek(&self, max: usize) -> Option<alloc::vec::Vec<u8>> {
        let q = self.shared.queue.lock();
        let n = core::cmp::min(max, q.len());
        // Copy the front `n` bytes without consuming them — tee(2)
        // duplicates pipe data, leaving the source readable.
        Some(q.iter().copied().take(n).collect())
    }
}

impl FileOps for PipeWrite {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            // Drop on a closed reader: silently discard. Stage-5
            // adds SIGPIPE delivery + an EPIPE return path.
            if self.shared.reader_closed.load(Ordering::Acquire) {
                return Ok(buf.len());
            }
            let mut q = self.shared.queue.lock();
            let room = PIPE_BUF_BYTES.saturating_sub(q.len());
            let n = core::cmp::min(buf.len(), room);
            for &b in buf.iter().take(n) {
                q.push_back(b);
            }
            Ok(n)
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.shared.queue.lock().len() as u64,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    fn poll_readiness(&self) -> u32 {
        let mut mask = 0;
        let q = self.shared.queue.lock();
        if q.len() < PIPE_BUF_BYTES || self.shared.reader_closed.load(Ordering::Acquire) {
            mask |= narf_filesystem::POLL_OUT;
        }
        mask
    }
}
