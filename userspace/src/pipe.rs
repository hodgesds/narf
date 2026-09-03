//! Anonymous pipe(2) file-ops.
//!
//! Backs a pair of fd-table entries with a shared byte ring buffer.
//! The file-op futures expose try-style results; the syscall layer parks a
//! blocking caller on the shared durable readiness cell and re-executes the
//! syscall when its peer changes the pipe state.
//!
//! Why not `narf-ipc::Ring<u8, N>`? `Ring`'s `Producer`/`Consumer`
//! halves are `!Sync`, but `FileOps: Send + Sync` — and the same
//! pipe-half is shared between parent and child after a future
//! `fork`. The shared queue therefore uses an IRQ-safe lock.
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
const PIPE_DEFAULT_BYTES: usize = 65_536;

/// Linux's default `/proc/sys/fs/pipe-max-size`. NARF has no root user or
/// `CAP_SYS_RESOURCE` override, so an attempt to grow beyond this ceiling is
/// the unprivileged Linux `EPERM` case.
const PIPE_MAX_BYTES: usize = 1_048_576;

/// POSIX `PIPE_BUF` (Linux `include/linux/limits.h`): writes of at most
/// this many bytes are ATOMIC — `fs/pipe.c::pipe_write` refuses to split
/// them across a partial buffer ("We must still wake up any pending
/// writers... but only do an atomic write if buf is small enough"), so a
/// short-on-room write of ≤ PIPE_BUF bytes writes NOTHING and blocks
/// (or EAGAINs for O_NONBLOCK) until the whole payload fits.
const PIPE_BUF: usize = 4096;
/// Stack staging cutoff for an atomic pipe write/read. This matches Linux's
/// page-sized PIPE_BUF and stress-ng's transfer size, avoiding heap allocation
/// while keeping the transactional user-copy buffer tightly bounded.
pub(crate) const PIPE_FAST_BYTES: usize = PIPE_BUF;

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

/// Fixed-capacity byte ring backing a pipe. Unlike `VecDeque<u8>`, this exposes
/// the one or two contiguous writable regions at the tail, allowing guarded
/// user copies to land directly in pipe storage before the new length is
/// committed.
#[derive(Debug)]
struct PipeBytes {
    storage: Box<[u8]>,
    head: usize,
    len: usize,
}

impl PipeBytes {
    fn new() -> Self {
        Self {
            storage: alloc::vec![0; PIPE_DEFAULT_BYTES].into_boxed_slice(),
            head: 0,
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn capacity(&self) -> usize {
        self.storage.len()
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn prefix_slices(&self, n: usize) -> (&[u8], &[u8]) {
        debug_assert!(n <= self.len);
        let first = core::cmp::min(n, self.capacity() - self.head);
        (
            &self.storage[self.head..self.head + first],
            &self.storage[..n - first],
        )
    }

    fn spare_slices_mut(&mut self, n: usize) -> (&mut [u8], &mut [u8]) {
        let capacity = self.capacity();
        debug_assert!(n <= capacity - self.len);
        let tail = (self.head + self.len) % capacity;
        let first = core::cmp::min(n, capacity - tail);
        let (before, after) = self.storage.split_at_mut(tail);
        (&mut after[..first], &mut before[..n - first])
    }

    fn commit_write(&mut self, n: usize) {
        debug_assert!(n <= self.capacity() - self.len);
        self.len += n;
    }

    fn push(&mut self, data: &[u8]) {
        let n = data.len();
        {
            let (first, wrapped) = self.spare_slices_mut(n);
            let split = first.len();
            first.copy_from_slice(&data[..split]);
            wrapped.copy_from_slice(&data[split..]);
        }
        self.commit_write(n);
    }

    fn copy_out(&self, offset: usize, dst: &mut [u8]) {
        debug_assert!(offset + dst.len() <= self.len);
        let len = dst.len();
        let capacity = self.capacity();
        let start = (self.head + offset) % capacity;
        let first = core::cmp::min(len, capacity - start);
        dst[..first].copy_from_slice(&self.storage[start..start + first]);
        dst[first..].copy_from_slice(&self.storage[..len - first]);
    }

    fn consume(&mut self, n: usize) {
        debug_assert!(n <= self.len);
        self.head = (self.head + n) % self.capacity();
        self.len -= n;
        if self.len == 0 {
            self.head = 0;
        }
    }

    /// Replace the backing ring while preserving its logical byte order.
    /// The caller preallocates `storage` before taking the pipe's IRQ-safe
    /// queue lock and verifies that the live prefix fits.
    fn replace_storage(&mut self, mut storage: Box<[u8]>) {
        debug_assert!(storage.len() >= self.len);
        let (front, wrapped) = self.prefix_slices(self.len);
        storage[..front.len()].copy_from_slice(front);
        storage[front.len()..self.len].copy_from_slice(wrapped);
        self.storage = storage;
        self.head = 0;
    }
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
    bytes: PipeBytes,
    frames: VecDeque<PipeFrame>,
}

impl PipeBufs {
    fn new() -> Self {
        Self {
            bytes: PipeBytes::new(),
            frames: VecDeque::new(),
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    fn max_frames(&self) -> usize {
        self.capacity() / PIPE_BUF
    }

    /// Conservative Linux pipe-buffer occupancy for resize admission. Packet
    /// frames consume one slot each; coalesced stream frames account for every
    /// page they span even though their boundaries are invisible to readers.
    fn occupied_frames(&self) -> usize {
        self.frames
            .iter()
            .map(|frame| frame.len.div_ceil(PIPE_BUF))
            .sum()
    }

    /// Would `pipe_full()` stop a writer here? Either limit can bind: bytes
    /// for a stream pipe, buffers for a packet pipe.
    fn is_full(&self) -> bool {
        self.bytes.len() >= self.capacity() || self.frames.len() >= self.max_frames()
    }

    /// Bytes a write of this kind can still deposit.
    ///
    /// A non-packet write that can merge into the tail buffer needs no new
    /// buffer, so it is bounded by bytes alone — which is why a stream pipe
    /// never notices the frame limit. A packet write always needs a fresh
    /// buffer per page, so it is bounded by both.
    fn room(&self, packet: bool) -> usize {
        let byte_room = self.capacity().saturating_sub(self.bytes.len());
        let free_frames = self.max_frames().saturating_sub(self.frames.len());
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
        self.bytes.push(data);
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
        self.bytes.consume(consumed);
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
            let mut scratch = [0u8; PIPE_BUF];
            let mut done = 0;
            while done < n {
                let chunk = core::cmp::min(PIPE_BUF, n - done);
                self.bytes.copy_out(offset + done, &mut scratch[..chunk]);
                dst.bytes.push(&scratch[..chunk]);
                done += chunk;
            }
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
            let mut scratch = [0u8; PIPE_BUF];
            let mut done = 0;
            while done < n {
                let chunk = core::cmp::min(PIPE_BUF, n - done);
                self.bytes.copy_out(done, &mut scratch[..chunk]);
                dst.bytes.push(&scratch[..chunk]);
                done += chunk;
            }
            self.bytes.consume(n);
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
    /// Linux `pipe_inode_info::poll_usage`: once a persistent poll/epoll
    /// registration exists, same-level I/O events must continue firing.
    poll_usage: AtomicBool,
}

impl PipeShared {
    fn capacity(&self) -> usize {
        self.queue.lock().capacity()
    }

    /// Linux `pipe_set_size` semantics for an unprivileged caller. Sizes are
    /// rounded to a page-sized power of two, values above 2 GiB are EINVAL,
    /// growth above the system ceiling is EPERM, a shrink below live buffer
    /// occupancy is EBUSY, and backing-allocation failure is ENOMEM.
    fn set_capacity(&self, arg: u32) -> Result<usize, u64> {
        if arg > (1u32 << 31) {
            return Err(22); // EINVAL
        }
        let requested = (arg as usize).max(PIPE_BUF).next_power_of_two();
        if requested > PIPE_MAX_BYTES {
            return Err(1); // EPERM: no CAP_SYS_RESOURCE/root bypass in NARF
        }
        if requested == self.capacity() {
            return Ok(requested);
        }

        // Allocate before disabling IRQs through the queue lock. `try_reserve`
        // preserves Linux's recoverable ENOMEM rather than turning pressure
        // into an allocator panic.
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(requested)
            .map_err(|_| 12u64)?; // ENOMEM
        replacement.resize(requested, 0);
        let replacement = replacement.into_boxed_slice();

        let mut q = self.queue.lock();
        let requested_frames = requested / PIPE_BUF;
        if q.len() > requested || q.occupied_frames() > requested_frames {
            return Err(16); // EBUSY
        }
        if q.capacity() != requested {
            q.bytes.replace_storage(replacement);
        }
        let len = q.len();
        let full = q.is_full();
        drop(q);
        // Growing a full pipe makes POLLOUT rise and must wake a blocked writer.
        self.sync_readiness_state(narf_filesystem::POLL_OUT, len, full);
        Ok(requested)
    }

    /// Recompute the durable readiness cell from the current queue occupancy and
    /// the peer-close flags, publishing the transition. POLL_IN (queue
    /// non-empty), POLL_OUT (room below capacity), POLL_HUP (writer gone),
    /// POLL_ERR (reader gone) — exactly the union of `PipeRead::poll_readiness`
    /// and `PipeWrite::poll_readiness`. `set_event` bumps its edge sequence and
    /// wakes armed waiters under one lock (drop-free), so a concurrent `arm`
    /// cannot miss the transition. Once poll/epoll has registered persistently,
    /// the event argument also fires same-level events, matching Linux's
    /// `pipe->poll_usage` gate without a second exclusive wake. `event` is the
    /// direction the caller changed: POLL_IN on a write, POLL_OUT on a read.
    fn sync_readiness(&self, event: u32) {
        let (len, full) = {
            let q = self.queue.lock();
            (q.len(), q.is_full())
        };
        self.sync_readiness_state(event, len, full);
    }

    #[inline]
    fn sync_readiness_state(&self, event: u32, len: usize, full: bool) {
        self.sync_readiness_state_with_policy(event, len, full, false);
    }

    #[inline]
    fn sync_readiness_state_all(&self, event: u32, len: usize, full: bool) {
        self.sync_readiness_state_with_policy(event, len, full, true);
    }

    #[inline]
    fn sync_readiness_state_with_policy(&self, event: u32, len: usize, full: bool, wake_all: bool) {
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
        if wake_all {
            self.readiness.set_wake_all(add, clear);
        } else {
            // Fire one wait-queue event for the caller's direction. Folding it
            // into the level update avoids selecting two exclusive blockers
            // when the same operation also creates a rising edge.
            let notify = if self.poll_usage.load(Ordering::Acquire) {
                (event | narf_filesystem::POLL_HUP | narf_filesystem::POLL_ERR) & add
            } else {
                0
            };
            self.readiness.set_event(add, clear, notify);
        }
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
        poll_usage: AtomicBool::new(false),
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

    pub(crate) fn set_capacity(&self, arg: u32) -> Result<usize, u64> {
        self.shared.set_capacity(arg)
    }

    /// Linux-shaped `write(2)` path. Reader/room checks precede user access,
    /// and writes larger than `PIPE_BUF` are copied and committed one page at
    /// a time. Thus a closed reader wins over a bad source (`EPIPE`), a full
    /// nonblocking pipe wins over it (`EAGAIN` in the syscall layer), a fault
    /// before progress is `EFAULT`, and a fault after progress returns the
    /// committed short count just like `fs/pipe.c::anon_pipe_write`.
    pub(crate) fn write_from_user(
        &self,
        src_uptr: u64,
        len: usize,
    ) -> Result<Result<usize, narf_filesystem::FsError>, u64> {
        if self.shared.reader_closed.load(Ordering::Acquire) {
            return Ok(Err(narf_filesystem::FsError::BrokenPipe));
        }
        let mut q = self.shared.queue.lock();
        // Pipe endpoint closure is serialized by this same lock, mirroring
        // Linux's pipe->mutex around both pipe_release and pipe_write.
        if self.shared.reader_closed.load(Ordering::Acquire) {
            return Ok(Err(narf_filesystem::FsError::BrokenPipe));
        }
        let packet = self.packetized.load(Ordering::Acquire);
        let room = q.room(packet);
        if len <= PIPE_BUF && room < len {
            return Ok(Ok(0));
        }
        let target = core::cmp::min(len, room);
        if target == 0 {
            return Ok(Ok(0));
        }
        let was_empty = q.is_empty();
        let mut written = 0usize;
        let mut first_error = None;
        while written < target {
            let chunk = core::cmp::min(PIPE_BUF, target - written);
            let copy_result = {
                let (first, wrapped) = q.bytes.spare_slices_mut(chunk);
                let split = first.len();
                // SAFETY: the syscall layer validated the complete range.
                // Logical pipe length is committed only after every guarded
                // copy making up this Linux-sized pipe buffer succeeds.
                let first_result =
                    unsafe { crate::handlers::copy_from_user(first, src_uptr + written as u64) };
                if first_result.is_ok() && !wrapped.is_empty() {
                    // SAFETY: continuation of the same validated user range.
                    unsafe {
                        crate::handlers::copy_from_user(
                            wrapped,
                            src_uptr + written as u64 + split as u64,
                        )
                    }
                } else {
                    first_result
                }
            };
            if let Err(errno) = copy_result {
                first_error = Some(errno);
                break;
            }
            q.bytes.commit_write(chunk);
            q.push_frame(chunk, packet);
            written += chunk;
        }
        let new_len = q.len();
        let new_full = q.is_full();
        drop(q);
        if written != 0 && (was_empty || new_full || self.shared.poll_usage.load(Ordering::Acquire))
        {
            self.shared
                .sync_readiness_state(narf_filesystem::POLL_IN, new_len, new_full);
        }
        if written == 0 {
            if let Some(errno) = first_error {
                return Err(errno);
            }
        }
        Ok(Ok(written))
    }

    fn try_write(&self, buf: &[u8]) -> Result<usize, narf_filesystem::FsError> {
        // The syscall layer turns this into SIGPIPE plus -EPIPE.
        if self.shared.reader_closed.load(Ordering::Acquire) {
            return Err(narf_filesystem::FsError::BrokenPipe);
        }
        let mut q = self.shared.queue.lock();
        // PipeRead::drop publishes closure while holding this lock. Recheck
        // after acquiring it so a writer that lost that race returns EPIPE
        // instead of appending bytes after the final reader disappeared.
        if self.shared.reader_closed.load(Ordering::Acquire) {
            return Err(narf_filesystem::FsError::BrokenPipe);
        }
        let packet = self.packetized.load(Ordering::Acquire);
        let room = q.room(packet);
        if buf.len() <= PIPE_BUF && room < buf.len() {
            return Ok(0);
        }
        let n = core::cmp::min(buf.len(), room);
        let was_empty = q.is_empty();
        q.push(&buf[..n], packet);
        let new_len = q.len();
        let new_full = q.is_full();
        drop(q);
        if n != 0 && (was_empty || new_full || self.shared.poll_usage.load(Ordering::Acquire)) {
            self.shared
                .sync_readiness_state(narf_filesystem::POLL_IN, new_len, new_full);
            narf_net::readiness::bump_generation();
        }
        Ok(n)
    }
}

impl PipeRead {
    pub(crate) fn set_capacity(&self, arg: u32) -> Result<usize, u64> {
        self.shared.set_capacity(arg)
    }

    /// Linux-shaped `read(2)` path: copy the stable queue prefix directly to
    /// user memory and advance the pipe one page-sized buffer at a time. A
    /// fault before progress is `EFAULT`; a fault after a committed buffer
    /// returns the short count, matching `fs/pipe.c::anon_pipe_read`.
    pub(crate) fn read_direct_to_user(
        &self,
        dst: u64,
        max: usize,
    ) -> Result<usize, VmspliceDrainError> {
        let mut q = self.shared.queue.lock();
        if q.is_empty() {
            return if self.shared.writer_closed.load(Ordering::Acquire) {
                Ok(0)
            } else {
                Err(VmspliceDrainError::WouldBlock)
            };
        }
        let was_full = q.is_full();
        let mut copied = 0usize;
        let mut first_error = None;
        while copied < max && !q.is_empty() {
            let packet = q.frames.front().is_some_and(|frame| frame.packet);
            let (n, consumed) = q.read_span(core::cmp::min(PIPE_BUF, max - copied));
            if n == 0 {
                break;
            }
            let copy_result = {
                let (front, wrapped) = q.bytes.prefix_slices(n);
                let first = front.len();
                // SAFETY: read(2) validated the complete destination before
                // reaching this path; the guarded copy catches a racing
                // mapping change.
                let first_result =
                    unsafe { crate::handlers::copy_to_user(dst + copied as u64, &front[..first]) };
                if first_result.is_ok() && first != n {
                    // SAFETY: continuation of the same validated destination.
                    unsafe {
                        crate::handlers::copy_to_user(
                            dst + copied as u64 + first as u64,
                            &wrapped[..n - first],
                        )
                    }
                } else {
                    first_result
                }
            };
            if let Err(errno) = copy_result {
                first_error = Some(errno);
                break;
            }
            q.commit(consumed);
            copied += n;
            if packet {
                break;
            }
        }
        let new_len = q.len();
        let new_full = q.is_full();
        drop(q);
        if copied != 0
            && (was_full || new_len == 0 || self.shared.poll_usage.load(Ordering::Acquire))
        {
            self.shared
                .sync_readiness_state(narf_filesystem::POLL_OUT, new_len, new_full);
        }
        if copied == 0 {
            if let Some(errno) = first_error {
                return Err(VmspliceDrainError::User(errno));
            }
        }
        Ok(copied)
    }

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
        let mut staging = Vec::with_capacity(core::cmp::min(max, self.shared.capacity()));
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
        staging.resize(n, 0);
        q.bytes.copy_out(0, &mut staging);
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
            narf_net::readiness::bump_generation();
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
            if dst.shared.reader_closed.load(Ordering::Acquire) {
                return Err(narf_filesystem::FsError::BrokenPipe);
            }
            move_pipe_prefix(
                &mut src,
                &mut dstq,
                max,
                self.shared.writer_closed.load(Ordering::Acquire),
            )?
        } else {
            let mut dstq = dst.shared.queue.lock();
            let mut src = self.shared.queue.lock();
            if dst.shared.reader_closed.load(Ordering::Acquire) {
                return Err(narf_filesystem::FsError::BrokenPipe);
            }
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
            narf_net::readiness::bump_generation();
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
            if dst.shared.reader_closed.load(Ordering::Acquire) {
                return Err(narf_filesystem::FsError::BrokenPipe);
            }
            copy_pipe_prefix(&src, &mut dstq, max, writer_closed)?
        } else {
            let mut dstq = dst.shared.queue.lock();
            let src = self.shared.queue.lock();
            if dst.shared.reader_closed.load(Ordering::Acquire) {
                return Err(narf_filesystem::FsError::BrokenPipe);
            }
            copy_pipe_prefix(&src, &mut dstq, max, writer_closed)?
        };

        if copied != 0 {
            // Only the destination changed: tee leaves the source queue intact,
            // so the source's readiness is unchanged and must not be
            // republished as an edge.
            dst.shared.sync_readiness(narf_filesystem::POLL_IN);
            narf_net::readiness::bump_generation();
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
        if max <= PIPE_FAST_BYTES {
            let mut staging = [0u8; PIPE_FAST_BYTES];
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
            let (front, wrapped) = q.bytes.prefix_slices(n);
            let first = front.len();
            staging[..first].copy_from_slice(&front[..first]);
            staging[first..n].copy_from_slice(&wrapped[..n - first]);
            copy(&staging[..n]).map_err(VmspliceDrainError::User)?;
            q.commit(if discard_packets { packet_consumed } else { n });
            drop(q);
            self.shared.sync_readiness(narf_filesystem::POLL_OUT);
            narf_net::readiness::bump_generation();
            return Ok(n);
        }

        // Allocate before disabling IRQs on the queue lock. A pipe can never
        // supply more than its current capacity, even if the iovec is larger.
        let mut staging =
            alloc::vec::Vec::with_capacity(core::cmp::min(max, self.shared.capacity()));
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
        staging.resize(n, 0);
        q.bytes.copy_out(0, &mut staging);

        copy(&staging).map_err(VmspliceDrainError::User)?;
        q.commit(if discard_packets { packet_consumed } else { n });
        drop(q);

        self.shared.sync_readiness(narf_filesystem::POLL_OUT);
        narf_net::readiness::bump_generation();
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
        let q = self.shared.queue.lock();
        self.shared.reader_closed.store(true, Ordering::Release);
        let len = q.len();
        let full = q.is_full();
        drop(q);
        // Latch POLL_ERR into the durable cell after publishing closure — wakes
        // a writer parked on POLL_OUT|POLL_ERR, even on a full pipe.
        self.shared
            .sync_readiness_state_all(narf_filesystem::POLL_OUT, len, full);
        narf_net::readiness::bump_generation();
    }
}

impl Drop for PipeWrite {
    fn drop(&mut self) {
        // Same Arc-counted reasoning as PipeRead::drop — only flips
        // when every writer fd has been closed.
        let q = self.shared.queue.lock();
        self.shared.writer_closed.store(true, Ordering::Release);
        let len = q.len();
        let full = q.is_full();
        drop(q);
        // Latch POLL_HUP into the durable cell after publishing closure — wakes
        // a reader parked on POLL_IN|POLL_HUP so it runs read()→0=EOF.
        self.shared
            .sync_readiness_state_all(narf_filesystem::POLL_IN, len, full);
        narf_net::readiness::bump_generation();
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
            q.bytes.copy_out(0, &mut buf[..n]);
            q.bytes.consume(consumed);
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
                narf_net::readiness::bump_generation();
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

    fn arm_readiness_exclusive(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        Some(
            self.shared
                .readiness
                .arm_exclusive(task_id, interest, waker),
        )
    }

    fn arm_readiness_persistent(
        &self,
        id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<u32> {
        self.shared.poll_usage.store(true, Ordering::Release);
        Some(self.shared.readiness.arm_persistent(id, interest, waker))
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
        let mut bytes = alloc::vec![0; n];
        q.bytes.copy_out(0, &mut bytes);
        Some(bytes)
    }

    fn pipe_capacity(&self) -> Option<usize> {
        Some(self.shared.capacity())
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
        Box::pin(async move { self.try_write(buf) })
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

    fn arm_readiness_exclusive(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        Some(
            self.shared
                .readiness
                .arm_exclusive(task_id, interest, waker),
        )
    }

    fn arm_readiness_persistent(
        &self,
        id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<u32> {
        self.shared.poll_usage.store(true, Ordering::Release);
        Some(self.shared.readiness.arm_persistent(id, interest, waker))
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
        Some(self.shared.capacity())
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        // `fcntl(F_SETFL, O_DIRECT)` downcasts through this to retarget packet
        // mode; without it the flag would be recorded in the fd's status flags
        // and never reach the write path.
        Some(self)
    }
}
