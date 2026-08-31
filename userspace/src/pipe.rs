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
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

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

/// Linux `PIPE_DEF_BUFFERS` (`include/linux/pipe_fs_i.h`): a fresh pipe holds
/// at most 16 `struct pipe_buffer`s. `pipe_full()` compares the BUFFER count
/// against this limit, not a byte count:
///
///     return pipe_occupancy(head, tail) >= limit;
///
/// so sixteen one-byte packets fill a 64 KiB pipe. That only matters in packet
/// mode: ordinary writes merge into the tail buffer, so a byte-stream pipe
/// never accumulates buffers and only ever hits the byte limit.
const PIPE_MAX_FRAMES: usize = 16;

/// One queued `struct pipe_buffer`'s framing metadata.
#[derive(Debug)]
struct PipeFrame {
    len: usize,
    /// `PIPE_BUF_FLAG_PACKET` — set by `pipe_write` when the writing file has
    /// O_DIRECT (`fs/pipe.c::is_packetized`). A packet is one record: a read
    /// never returns more than one, and never returns part of one and keeps
    /// the rest.
    packet: bool,
}

/// The pipe's buffer list: a flat byte queue with the write boundaries laid
/// over it. `frames` covers `bytes` exactly — the frame lengths always sum to
/// `bytes.len()`.
///
/// Linux keeps a ring of `struct pipe_buffer`, each owning a page. Flattening
/// the payload and carrying only the boundaries keeps every existing
/// byte-stream path (splice, tee, FIONREAD, poll) working on one contiguous
/// queue while still answering the only question packet mode asks: where does
/// this record end?
///
/// The merge rule below is what makes that safe. Consecutive non-packet writes
/// coalesce into a single frame, so a pipe that never sees O_DIRECT holds at
/// most one frame and every query here degenerates to the byte arithmetic it
/// replaced. Linux instead merges only up to a page boundary
/// (`offset + chars <= PAGE_SIZE`), but that limit is invisible to a
/// non-packet reader — `pipe_read` walks buffers without reporting where one
/// ended — so coalescing further changes nothing a caller can observe.
#[derive(Debug)]
struct PipeBufs {
    bytes: VecDeque<u8>,
    frames: VecDeque<PipeFrame>,
}

impl PipeBufs {
    fn new() -> Self {
        Self {
            bytes: VecDeque::with_capacity(PIPE_BUF_BYTES),
            frames: VecDeque::new(),
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Would `pipe_full()` stop a writer here? Either limit can bind: bytes
    /// for a stream pipe, buffers for a packet pipe.
    fn is_full(&self) -> bool {
        self.bytes.len() >= PIPE_BUF_BYTES || self.frames.len() >= PIPE_MAX_FRAMES
    }

    /// Bytes a write of this kind can still deposit.
    ///
    /// A non-packet write that can merge into the tail buffer needs no new
    /// buffer, so it is bounded by bytes alone — which is why a stream pipe
    /// never notices `PIPE_MAX_FRAMES`. A packet write always needs a fresh
    /// buffer per page, so it is bounded by both.
    fn room(&self, packet: bool) -> usize {
        let byte_room = PIPE_BUF_BYTES.saturating_sub(self.bytes.len());
        let free_frames = PIPE_MAX_FRAMES.saturating_sub(self.frames.len());
        if packet {
            core::cmp::min(byte_room, free_frames.saturating_mul(PIPE_BUF))
        } else if self.frames.back().is_some_and(|frame| !frame.packet) || free_frames > 0 {
            byte_room
        } else {
            0
        }
    }

    /// Record a frame boundary for `len` bytes already appended to `bytes`.
    fn push_frame(&mut self, len: usize, packet: bool) {
        if len == 0 {
            return;
        }
        match self.frames.back_mut() {
            Some(tail) if !packet && !tail.packet => tail.len += len,
            _ => self.frames.push_back(PipeFrame { len, packet }),
        }
    }

    fn push(&mut self, data: &[u8], packet: bool) {
        if data.is_empty() {
            return;
        }
        self.bytes.extend(data.iter().copied());
        if packet {
            // `pipe_write` copies at most one page into each buffer
            // (`copy_page_from_iter(page, 0, PAGE_SIZE, from)`) and loops, so a
            // packet write larger than a page arrives as SEVERAL packets — not
            // one oversized record. A reader that assumed otherwise would treat
            // the split as a lost boundary.
            for chunk in data.chunks(PIPE_BUF) {
                self.push_frame(chunk.len(), true);
            }
        } else {
            self.push_frame(data.len(), false);
        }
    }

    /// What a read of `max` bytes takes: `(copied, consumed)`.
    ///
    /// `fs/pipe.c::pipe_read` walks buffers until the request is satisfied, but
    /// stops at the first packet buffer and drops whatever is left in it:
    ///
    ///     if (chars > total_len) {
    ///             ...
    ///             chars = total_len;
    ///     }
    ///     ...
    ///     /* Was it a packet buffer? Clean up and exit */
    ///     if (buf->flags & PIPE_BUF_FLAG_PACKET) {
    ///             total_len = chars;
    ///             buf->len = 0;
    ///     }
    ///
    /// `buf->len = 0` retires the whole buffer however little was copied, and
    /// `total_len = chars` ends the read. That is why the two counts differ: a
    /// short read of a packet returns the truncated prefix and DISCARDS the
    /// remainder. Reporting `consumed` separately is what lets each read path
    /// perform that discard without folding it into the byte count it returns
    /// to the caller — conflating them would report bytes that were never
    /// copied.
    ///
    /// `PIPE_BUF_FLAG_WHOLE` (the -ENOBUFS "entire buffer or error" rule) is a
    /// watch-queue flag, not a packet one; O_DIRECT truncates rather than
    /// failing, so it is deliberately not modelled here.
    fn read_span(&self, max: usize) -> (usize, usize) {
        let mut copied = 0;
        let mut consumed = 0;
        let mut left = max;
        for frame in self.frames.iter() {
            if left == 0 {
                break;
            }
            let take = core::cmp::min(left, frame.len);
            copied += take;
            left -= take;
            if frame.packet {
                consumed += frame.len;
                break;
            }
            consumed += take;
        }
        (copied, consumed)
    }

    /// Drop `consumed` bytes from the front, keeping `frames` covering `bytes`.
    fn commit(&mut self, consumed: usize) {
        self.bytes.drain(..consumed);
        self.retire_frames(consumed);
    }

    /// The frame half of [`Self::commit`], for callers that already moved the
    /// bytes out of `bytes` themselves.
    fn retire_frames(&mut self, consumed: usize) {
        let mut left = consumed;
        while left > 0 {
            let Some(front) = self.frames.front_mut() else {
                break;
            };
            if front.len > left {
                front.len -= left;
                break;
            }
            left -= front.len;
            self.frames.pop_front();
        }
    }

    /// Duplicate up to `max` bytes into `dst` WITHOUT consuming them, carrying
    /// each frame's packet flag — the tee(2) counterpart of
    /// [`Self::move_prefix_to`].
    ///
    /// `fs/splice.c::link_pipe` copies whole `struct pipe_buffer`s and keeps
    /// their flags:
    ///
    ///     *obuf = *ibuf;
    ///     obuf->flags &= ~PIPE_BUF_FLAG_GIFT;
    ///     obuf->flags &= ~PIPE_BUF_FLAG_CAN_MERGE;
    ///     if (obuf->len > len)
    ///             obuf->len = len;
    ///
    /// so PIPE_BUF_FLAG_PACKET survives a tee and the destination reads back
    /// the same records the source holds. The final buffer may be TRUNCATED to
    /// the caller's remaining length and still keeps its flag — a short tee of
    /// a packet yields a shorter packet, not a stream fragment.
    ///
    /// Its loop stops on `pipe_full(o_head, o_tail, opipe->max_usage)`, a
    /// buffer-count test, which is what `dst.room` reproduces.
    ///
    /// The one flag not modelled is CAN_MERGE: Linux clears it so a later
    /// write on the destination cannot extend a teed buffer, whereas
    /// [`Self::push_frame`] will merge into it. That is unobservable to a
    /// reader — non-packet boundaries are invisible to `pipe_read` — and it
    /// only shifts the destination's buffer COUNT, which already diverges
    /// because this queue merges past the page boundary Linux stops at.
    /// Modelling half of the merge rule would make that divergence less
    /// predictable, not more.
    fn copy_prefix_to(&self, dst: &mut PipeBufs, max: usize) -> usize {
        let mut copied = 0;
        // Byte offset of the current frame within `bytes`. `VecDeque::range`
        // seeks in O(1), so this stays linear in the bytes actually copied.
        let mut offset = 0;
        for frame in self.frames.iter() {
            if copied >= max {
                break;
            }
            let room = dst.room(frame.packet);
            let n = core::cmp::min(core::cmp::min(max - copied, frame.len), room);
            if n == 0 {
                break;
            }
            dst.bytes
                .extend(self.bytes.range(offset..offset + n).copied());
            dst.push_frame(n, frame.packet);
            copied += n;
            if n < frame.len {
                // Truncated tail buffer — nothing after it can be copied.
                break;
            }
            offset += frame.len;
        }
        copied
    }

    /// Move up to `max` bytes into `dst`, carrying each frame's packet flag.
    ///
    /// `fs/splice.c` moves whole `struct pipe_buffer`s between pipes rather
    /// than bytes, so the flags travel with the payload and a packet is never
    /// split across the transfer. Hence the all-or-nothing step for a packet
    /// frame: a destination without room for the whole record stops the move
    /// instead of tearing it. A trailing NON-packet frame may still move
    /// partially, because its boundary is invisible to any reader.
    fn move_prefix_to(&mut self, dst: &mut PipeBufs, max: usize) -> usize {
        let mut moved = 0;
        while moved < max {
            let Some(&PipeFrame { len, packet }) = self.frames.front() else {
                break;
            };
            let room = dst.room(packet);
            if room == 0 {
                break;
            }
            let n = if packet {
                if len > core::cmp::min(max - moved, room) {
                    break;
                }
                len
            } else {
                core::cmp::min(core::cmp::min(max - moved, room), len)
            };
            if n == 0 {
                break;
            }
            // Deque-to-deque move: no staging buffer, so nothing is allocated
            // while the two queue locks are held.
            dst.bytes.extend(self.bytes.drain(..n));
            dst.push_frame(n, packet);
            self.retire_frames(n);
            moved += n;
        }
        moved
    }
}

/// Shared mutable state between the read+write halves: the byte
/// queue plus a "writer dropped" flag. The `closed_*` flags let
/// either half observe the peer-side close from the read/write
/// future without holding the queue lock.
#[derive(Debug)]
struct PipeShared {
    queue: IrqSafeSpinLock<PipeBufs>,
    /// Set when the write half is dropped. The read half observes
    /// this to flip empty-read from "try again" to EOF.
    writer_closed: AtomicBool,
    /// Set when the read half is dropped. The write half observes
    /// this and reports `BrokenPipe` to the syscall layer.
    reader_closed: AtomicBool,
    /// Durable readiness cell shared by both halves — the SOLE readiness
    /// mechanism (there is no edge token). One cell carries the union of both
    /// views: POLL_IN (queue non-empty), POLL_OUT (room), POLL_HUP (writer gone),
    /// POLL_ERR (reader gone). The read fd arms POLL_IN|POLL_HUP, the write fd
    /// arms POLL_OUT|POLL_ERR (the poll/epoll layer folds ERR|HUP into every arm
    /// interest); `set` wakes each waiter on its own rising bits, and `notify`
    /// (see [`PipeShared::sync_readiness`]) fires the wait-queue for the changed
    /// direction so an EPOLLET consumer re-fires even at the same level.
    readiness: narf_lib::readiness::Readiness,
}

impl PipeShared {
    /// Recompute the durable readiness cell from the current queue occupancy and
    /// the peer-close flags, publishing the transition. POLL_IN (queue
    /// non-empty), POLL_OUT (room below capacity), POLL_HUP (writer gone),
    /// POLL_ERR (reader gone) — exactly the union of `PipeRead::poll_readiness`
    /// and `PipeWrite::poll_readiness`. `set` bumps its edge sequence and wakes
    /// armed waiters only on a rising edge, all under one lock (drop-free), so a
    /// concurrent `arm` can never miss this transition. `notify(event & add)`
    /// then fires the wait-queue for the just-changed direction UNCONDITIONALLY
    /// so an EPOLLET consumer re-fires even at the same level. `event` is the
    /// direction the caller changed: POLL_IN on a write, POLL_OUT on a read.
    /// Called after every write/read/close that changes state.
    fn sync_readiness(&self, event: u32) {
        let (len, full) = {
            let q = self.queue.lock();
            (q.len(), q.is_full())
        };
        let writer_closed = self.writer_closed.load(Ordering::Acquire);
        let reader_closed = self.reader_closed.load(Ordering::Acquire);
        let mut add = 0u32;
        let mut clear = 0u32;
        if len > 0 {
            add |= narf_filesystem::POLL_IN;
        } else {
            clear |= narf_filesystem::POLL_IN;
        }
        // Room is a buffer question as well as a byte one — a packet pipe
        // holding 16 short records is full at a few dozen bytes, and reporting
        // POLL_OUT there would spin a writer that can never make progress.
        if !full {
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
        // Fire the wait-queue for the caller's direction (plus any peer-close bit
        // that just latched, so a close reliably wakes the peer), masked to what
        // is actually ready.
        self.readiness
            .notify((event | narf_filesystem::POLL_HUP | narf_filesystem::POLL_ERR) & add);
    }
}

/// Read end of a pipe.
pub struct PipeRead {
    shared: Arc<PipeShared>,
}

/// Write end of a pipe.
pub struct PipeWrite {
    shared: Arc<PipeShared>,
    /// `filp->f_flags & O_DIRECT`, consulted per write by
    /// `fs/pipe.c::is_packetized`. Linux keeps it on the open file
    /// description, which is exactly the lifetime of this object: `pipe2`
    /// gives O_DIRECT to the WRITE file only
    /// (`O_WRONLY | (flags & (O_NONBLOCK | O_DIRECT))` in
    /// `create_pipe_files`, while the read file gets only O_NONBLOCK), every
    /// `dup` shares it, and `fcntl(F_SETFL)` can flip it for later writes.
    packetized: AtomicBool,
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
    pipe_pair_flags(false)
}

/// Allocate a pipe pair whose write end is in packet mode when `packetized`
/// (`pipe2(O_DIRECT)`).
pub fn pipe_pair_flags(packetized: bool) -> (Arc<PipeRead>, Arc<PipeWrite>) {
    let shared = Arc::new(PipeShared {
        queue: IrqSafeSpinLock::new(PipeBufs::new()),
        writer_closed: AtomicBool::new(false),
        reader_closed: AtomicBool::new(false),
        // Fresh pipe: empty (not readable), has room (writable), both ends open.
        readiness: narf_lib::readiness::Readiness::new(narf_filesystem::POLL_OUT),
    });
    (
        Arc::new(PipeRead {
            shared: shared.clone(),
        }),
        Arc::new(PipeWrite {
            shared,
            packetized: AtomicBool::new(packetized),
        }),
    )
}

impl PipeWrite {
    /// Mirror `fcntl(F_SETFL, O_DIRECT)` onto the pipe. Linux re-reads
    /// `filp->f_flags` on every `pipe_write`, so toggling O_DIRECT changes the
    /// framing of subsequent writes without disturbing records already queued.
    pub(crate) fn set_packetized(&self, packetized: bool) {
        self.packetized.store(packetized, Ordering::Release);
    }
}

impl PipeRead {
    /// Move a pipe prefix into a non-pipe sink and consume only the prefix the
    /// sink accepted. The source queue stays locked across one non-blocking
    /// sink poll, making the observation+commit indivisible with respect to
    /// other readers. The caller must not park or await while that poll runs.
    /// Pipe to pipe uses [`Self::splice_to_pipe`] instead so two queue locks are
    /// always acquired in address order.
    pub(crate) fn splice_to_sink(
        &self,
        max: usize,
        write: impl FnOnce(&[u8]) -> Result<usize, narf_filesystem::FsError>,
    ) -> Result<usize, narf_filesystem::FsError> {
        // Reserve before disabling IRQs in the queue lock. `max` is capped by
        // the syscall copy core's 64-KiB chunk size.
        let mut staging = Vec::with_capacity(core::cmp::min(max, PIPE_BUF_BYTES));
        let mut q = self.shared.queue.lock();
        let avail = q.len();
        if avail == 0 {
            return if self.shared.writer_closed.load(Ordering::Acquire) {
                Ok(0)
            } else {
                Err(narf_filesystem::FsError::WouldBlock)
            };
        }
        // `splice_from_pipe` hands the actor ONE buffer at a time, so the
        // offered span stops at a packet boundary of its own accord.
        let (n, _) = q.read_span(core::cmp::min(max, avail));
        staging.extend(q.bytes.iter().copied().take(n));
        let written = write(&staging)?;
        if written > n {
            return Err(narf_filesystem::FsError::InvalidData);
        }
        // No packet discard here: a short actor write advances the buffer
        // (`buf->offset += ret; buf->len -= ret;`) and leaves the remainder
        // queued. Only `pipe_read` retires a partially-copied packet.
        q.commit(written);
        drop(q);

        if written != 0 {
            self.shared.sync_readiness(narf_filesystem::POLL_OUT);
            narf_net::readiness::notify(0);
        }
        Ok(written)
    }

    /// Move bytes directly between two pipe queues. Locking both queues in
    /// stable address order prevents opposing concurrent splices from
    /// deadlocking, while consuming exactly the number appended prevents a
    /// partially full destination from dropping the source tail.
    pub(crate) fn splice_to_pipe(
        &self,
        dst: &PipeWrite,
        max: usize,
    ) -> Result<usize, narf_filesystem::FsError> {
        if Arc::ptr_eq(&self.shared, &dst.shared) {
            return Err(narf_filesystem::FsError::InvalidData);
        }
        if dst.shared.reader_closed.load(Ordering::Acquire) {
            return Err(narf_filesystem::FsError::BrokenPipe);
        }

        let src_addr = Arc::as_ptr(&self.shared) as usize;
        let dst_addr = Arc::as_ptr(&dst.shared) as usize;
        let (moved, _, _) = if src_addr < dst_addr {
            let mut src = self.shared.queue.lock();
            let mut dstq = dst.shared.queue.lock();
            move_pipe_prefix(
                &mut src,
                &mut dstq,
                max,
                self.shared.writer_closed.load(Ordering::Acquire),
            )?
        } else {
            let mut dstq = dst.shared.queue.lock();
            let mut src = self.shared.queue.lock();
            move_pipe_prefix(
                &mut src,
                &mut dstq,
                max,
                self.shared.writer_closed.load(Ordering::Acquire),
            )?
        };

        if moved != 0 {
            self.shared.sync_readiness(narf_filesystem::POLL_OUT);
            dst.shared.sync_readiness(narf_filesystem::POLL_IN);
            narf_net::readiness::notify(0);
        }
        Ok(moved)
    }

    /// Duplicate a prefix into another pipe without consuming it — tee(2).
    ///
    /// Locking both queues in stable address order is the same ABBA guard
    /// `fs/splice.c::link_pipe` documents ("two different processes could
    /// deadlock (one doing tee from A -> B, the other from B -> A)") and that
    /// [`Self::splice_to_pipe`] already uses.
    pub(crate) fn tee_to(
        &self,
        dst: &PipeWrite,
        max: usize,
    ) -> Result<usize, narf_filesystem::FsError> {
        if Arc::ptr_eq(&self.shared, &dst.shared) {
            // `if (!ipipe || !opipe || ipipe == opipe) return -EINVAL;`
            return Err(narf_filesystem::FsError::InvalidData);
        }
        if dst.shared.reader_closed.load(Ordering::Acquire) {
            // `if (!opipe->readers) { send_sig(SIGPIPE, ...); ret = -EPIPE; }`
            return Err(narf_filesystem::FsError::BrokenPipe);
        }
        let writer_closed = self.shared.writer_closed.load(Ordering::Acquire);
        let src_addr = Arc::as_ptr(&self.shared) as usize;
        let dst_addr = Arc::as_ptr(&dst.shared) as usize;
        let (copied, _) = if src_addr < dst_addr {
            let src = self.shared.queue.lock();
            let mut dstq = dst.shared.queue.lock();
            copy_pipe_prefix(&src, &mut dstq, max, writer_closed)?
        } else {
            let mut dstq = dst.shared.queue.lock();
            let src = self.shared.queue.lock();
            copy_pipe_prefix(&src, &mut dstq, max, writer_closed)?
        };

        if copied != 0 {
            // Only the destination changed: tee leaves the source queue intact,
            // so the source's readiness is unchanged and must not be
            // republished as an edge.
            dst.shared.sync_readiness(narf_filesystem::POLL_IN);
            narf_net::readiness::notify(0);
        }
        Ok(copied)
    }

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
        // `discard_packets: false` — vmsplice drains through the splice actor
        // (`pipe_to_user`), which advances a partially-copied buffer instead of
        // retiring it. The packet discard belongs to `pipe_read` alone.
        self.drain_to_user(max, false, |bytes| {
            // SAFETY: validate_user_range accepted the complete destination;
            // guarded copy catches a racing unmap/protection change.
            unsafe { crate::handlers::copy_to_user(dst, bytes) }
        })
    }

    /// Transactional pipe read used by read/readv/vmsplice: copy a stable
    /// prefix through `copy`, and consume it only after the complete guarded
    /// user-copy succeeds. The byte queue does not preserve Linux pipe_buffer
    /// boundaries, so this selected prefix is one logical buffer: a fault in a
    /// later iovec retains even an earlier copied fragment rather than wrongly
    /// consuming part of the currently faulting buffer.
    pub(crate) fn read_to_user(
        &self,
        max: usize,
        copy: impl FnOnce(&[u8]) -> Result<(), u64>,
    ) -> Result<usize, VmspliceDrainError> {
        self.drain_to_user(max, true, copy)
    }

    /// [`Self::read_to_user`] with the packet-retire rule made explicit:
    /// `discard_packets` is read(2)'s `buf->len = 0`, which drops the tail of a
    /// packet too large for the caller's buffer. Splice actors clear it.
    fn drain_to_user(
        &self,
        max: usize,
        discard_packets: bool,
        copy: impl FnOnce(&[u8]) -> Result<(), u64>,
    ) -> Result<usize, VmspliceDrainError> {
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
        let (n, packet_consumed) = q.read_span(max);
        staging.extend(q.bytes.iter().copied().take(n));

        copy(&staging).map_err(VmspliceDrainError::User)?;
        q.commit(if discard_packets { packet_consumed } else { n });
        drop(q);

        self.shared.sync_readiness(narf_filesystem::POLL_OUT);
        narf_net::readiness::notify(0);
        Ok(n)
    }
}

fn copy_pipe_prefix(
    src: &PipeBufs,
    dst: &mut PipeBufs,
    max: usize,
    writer_closed: bool,
) -> Result<(usize, bool), narf_filesystem::FsError> {
    if src.is_empty() {
        // `ipipe_prep`: an empty source is end-of-stream only once the last
        // writer is gone; otherwise the caller waits or takes -EAGAIN.
        return if writer_closed {
            Ok((0, dst.is_empty()))
        } else {
            Err(narf_filesystem::FsError::WouldBlock)
        };
    }
    let dst_was_empty = dst.is_empty();
    let copied = src.copy_prefix_to(dst, max);
    if copied == 0 {
        // The destination could not take even the head buffer.
        return Err(narf_filesystem::FsError::WouldBlock);
    }
    Ok((copied, dst_was_empty))
}

fn move_pipe_prefix(
    src: &mut PipeBufs,
    dst: &mut PipeBufs,
    max: usize,
    writer_closed: bool,
) -> Result<(usize, bool, bool), narf_filesystem::FsError> {
    if src.is_empty() {
        return if writer_closed {
            Ok((0, false, dst.is_empty()))
        } else {
            Err(narf_filesystem::FsError::WouldBlock)
        };
    }
    let src_was_full = src.is_full();
    let dst_was_empty = dst.is_empty();
    let n = src.move_prefix_to(dst, max);
    if n == 0 {
        // The destination could not take even the head frame — full, or short
        // of room for a whole packet. Either way the caller must retry.
        return Err(narf_filesystem::FsError::WouldBlock);
    }
    Ok((n, src_was_full, dst_was_empty))
}

impl Drop for PipeRead {
    fn drop(&mut self) {
        // The fd-table holds an `Arc<dyn FileOps>` per slot, so this
        // Drop only fires when the *last* `Arc<PipeRead>` (across
        // every dup'd fd in every task) goes away — at that point
        // there are no readers left and the writer should observe
        // EOF on its side.
        self.shared.reader_closed.store(true, Ordering::Release);
        // Latch POLL_ERR into the durable cell (store THEN sync so it observes
        // reader_closed=true) — wakes a writer parked on POLL_OUT|POLL_ERR, even
        // one blocked on a full pipe where no POLL_OUT edge ever comes.
        self.shared.sync_readiness(narf_filesystem::POLL_OUT);
        narf_net::readiness::notify(0);
    }
}

impl Drop for PipeWrite {
    fn drop(&mut self) {
        // Same Arc-counted reasoning as PipeRead::drop — only flips
        // when every writer fd has been closed.
        self.shared.writer_closed.store(true, Ordering::Release);
        // Latch POLL_HUP into the durable cell (store THEN sync so it observes
        // writer_closed=true) — wakes a reader parked on POLL_IN|POLL_HUP so it
        // runs read()→0=EOF instead of hanging on the lost-wake backstop.
        self.shared.sync_readiness(narf_filesystem::POLL_IN);
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
            let (n, consumed) = q.read_span(buf.len());
            // Bulk drain: `VecDeque::drain` copies the front bytes in as few
            // `memcpy`s as the ring's two contiguous slices allow, instead of
            // individual `pop_front`s — the byte-at-a-time loop dominated large
            // pipe/splice transfers. `Drain` removes its whole range on drop
            // even though `take(n)` stops copying early, which IS the packet
            // discard: `consumed` bytes leave the pipe, `n` reach the caller.
            for (slot, byte) in buf.iter_mut().zip(q.bytes.drain(..consumed).take(n)) {
                *slot = byte;
            }
            q.retire_frames(consumed);
            drop(q);
            if n != 0 {
                // Draining can clear POLL_IN (queue now empty) and set POLL_OUT
                // (room freed); republish so a writer parked on this pipe's
                // readiness cell wakes, and bump the global notify generation so
                // a writer parked via `park_reexecute_on_io` (armed on that
                // generation, not the cell) re-runs instead of sleeping out its
                // deadline.
                self.shared.sync_readiness(narf_filesystem::POLL_OUT);
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
        // Copy the front bytes without consuming them — tee(2) duplicates pipe
        // data, leaving the source readable. `read_span` bounds the copy to one
        // record, matching `fs/splice.c::tee` duplicating whole buffers.
        //
        // LINUX-GAP: tee/splice into another pipe carry the payload but not the
        // PACKET flag, because this interface hands the destination a plain
        // byte slice that its own write path re-frames. Linux copies the
        // `pipe_buffer` flags across, so a teed packet stays a packet on the
        // far side; here it takes the destination's framing. One call still
        // copies at most one packet, so the records are not run together —
        // only the flag that marks them as records is lost.
        let (n, _) = q.read_span(max);
        Some(q.bytes.iter().copied().take(n).collect())
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
            // `is_packetized(filp)` is re-read per write, so a mid-stream
            // F_SETFL takes effect from the next write onward.
            let packet = self.packetized.load(Ordering::Acquire);
            let room = q.room(packet);
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
            // Bulk enqueue: `push` appends the whole prefix in one pass
            // (amortised memcpy into the ring), replacing `n` individual
            // `push_back`s that dominated large pipe/vmsplice writes, and
            // records the frame boundary this write establishes.
            q.push(&buf[..n], packet);
            drop(q);
            if n != 0 {
                // Data added sets POLL_IN (and clears POLL_OUT if now full);
                // republish so a reader parked on this pipe wakes.
                self.shared.sync_readiness(narf_filesystem::POLL_IN);
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
        if !q.is_full() {
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

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        // `fcntl(F_SETFL, O_DIRECT)` downcasts through this to retarget packet
        // mode; without it the flag would be recorded in the fd's status flags
        // and never reach the write path.
        Some(self)
    }
}
