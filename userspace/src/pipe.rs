//! Anonymous pipe(2) file-ops.
//!
//! Backs a pair of fd-table entries with a shared ring of page buffers.
//! The file-op futures expose try-style results; the syscall layer parks a
//! blocking caller on the shared durable readiness cell and re-executes the
//! syscall when its peer changes the pipe state.
//!
//! Why not `narf-ipc::Ring<u8, N>`? `Ring`'s `Producer`/`Consumer`
//! halves are `!Sync`, but `FileOps: Send + Sync` — and the same
//! pipe-half is shared between parent and child after `fork`. A per-pipe
//! sleepable mutex serializes payload ownership; a short publication lock
//! serializes readiness updates without covering payload copies or I/O.
//!
//! Closure semantics: the read-side `FileOps::read` returns 0 (EOF)
//! when the buffer is empty AND the writer side has been dropped;
//! a 0-byte read with the writer still alive means "try again later"
//! (POSIX would return EAGAIN here for a non-blocking fd). The
//! writer side never EOFs; `write` on a closed reader returns
//! `FsError::BrokenPipe`, which the Linux syscall layer translates to
//! SIGPIPE plus `EPIPE`.

use crate::errno::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_filesystem::{FileOps, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

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

use narf_filesystem::{pipe_buffer::PipeBufs, pipe_queue as queue};

fn lock_queue(queue: &queue::Queue) -> queue::Guard<'_> {
    crate::handlers::poll_blocking(queue.lock_async())
        .expect("pipe mutex acquisition requires a runnable task context")
}

enum Endpoint<'a> {
    Read(&'a PipeRead),
    Write(&'a PipeWrite),
    Named(&'a narf_filesystem::fifo::FifoHandle),
}

impl<'a> Endpoint<'a> {
    fn from_file(ops: &'a dyn FileOps) -> Option<Self> {
        let any = ops.as_any()?;
        if let Some(read) = any.downcast_ref::<PipeRead>() {
            return Some(Self::Read(read));
        }
        if let Some(write) = any.downcast_ref::<PipeWrite>() {
            return Some(Self::Write(write));
        }
        any.downcast_ref::<narf_filesystem::fifo::FifoHandle>()
            .map(Self::Named)
    }
    fn queue(&self) -> &queue::Queue {
        match self {
            Self::Read(read) => &read.shared.queue,
            Self::Write(write) => &write.shared.queue,
            Self::Named(fifo) => fifo.shared().queue(),
        }
    }
    fn writer_closed(&self) -> bool {
        match self {
            Self::Read(read) => read.shared.writer_closed.load(Ordering::Acquire),
            Self::Write(write) => write.shared.writer_closed.load(Ordering::Acquire),
            Self::Named(fifo) => fifo.shared().writer_count() == 0,
        }
    }
    fn reader_closed(&self) -> bool {
        match self {
            Self::Read(read) => read.shared.reader_closed.load(Ordering::Acquire),
            Self::Write(write) => write.shared.reader_closed.load(Ordering::Acquire),
            Self::Named(fifo) => fifo.shared().reader_count() == 0,
        }
    }
    fn notify(&self, event: u32, transferred: usize) {
        match self {
            Self::Read(read) => {
                read.shared
                    .sync_readiness_after_transfer(event, 0, false, transferred)
            }
            Self::Write(write) => {
                write
                    .shared
                    .sync_readiness_after_transfer(event, 0, false, transferred)
            }
            Self::Named(fifo) => fifo.shared().notify_transfer(event, transferred),
        }
    }
    fn packetized(&self) -> bool {
        match self {
            Self::Read(_) => false,
            Self::Write(write) => write.packetized.load(Ordering::Acquire),
            Self::Named(fifo) => fifo.packetized(),
        }
    }
}

/// One transactional iterator write, including capacity/fault distinction for
/// a blocking syscall which must retain its accepted prefix while sleeping.
pub(crate) fn write_from_iter(
    ops: &dyn FileOps,
    len: usize,
    copy: impl FnMut(usize, &mut [u8]) -> Result<(), u64>,
) -> Result<(usize, bool), u64> {
    let output = Endpoint::from_file(ops).ok_or(EBADF as u64)?;
    let mut q = lock_queue(output.queue());
    if output.reader_closed() {
        return Err(EPIPE as u64);
    }
    let n = q.write_with(len, output.packetized(), copy)?;
    let full = q.is_full();
    drop(q);
    if n != 0 {
        output.notify(narf_filesystem::POLL_IN, n);
    }
    Ok((n, full))
}

pub(crate) fn read_to_iter(
    ops: &dyn FileOps,
    len: usize,
    discard_packets: bool,
    mut copy: impl FnMut(usize, *const u8, usize) -> Result<(), u64>,
) -> Result<usize, u64> {
    let input = Endpoint::from_file(ops).ok_or(EBADF as u64)?;
    let mut q = lock_queue(input.queue());
    if q.is_empty() {
        return if input.writer_closed() {
            Ok(0)
        } else {
            Err(EAGAIN as u64)
        };
    }
    let mut total = 0;
    while total < len && !q.is_empty() {
        let (buffer_len, packet) = q.front_info().unwrap();
        let n = buffer_len.min(len - total);
        if let Err(errno) = q.with_front_raw(n, |ptr, count| copy(total, ptr, count)) {
            if total == 0 {
                return Err(errno);
            }
            break;
        }
        q.commit(if packet && discard_packets {
            buffer_len
        } else {
            n
        });
        total += n;
        if packet && discard_packets {
            break;
        }
    }
    drop(q);
    if total != 0 {
        input.notify(narf_filesystem::POLL_OUT, total);
    }
    Ok(total)
}

/// All anonymous/named combinations use the same ordered two-queue operation.
pub(crate) fn transfer(
    input: &dyn FileOps,
    output: &dyn FileOps,
    max: usize,
    duplicate: bool,
) -> Option<Result<usize, narf_filesystem::FsError>> {
    use narf_filesystem::FsError;
    let input = Endpoint::from_file(input)?;
    let output = Endpoint::from_file(output)?;
    let source = input.queue();
    let destination = output.queue();
    if core::ptr::eq(source, destination) {
        return Some(Err(FsError::InvalidData));
    }
    let (mut src, mut dst) = if (source as *const _ as usize) < (destination as *const _ as usize) {
        let src = lock_queue(source);
        (src, lock_queue(destination))
    } else {
        let dst = lock_queue(destination);
        (lock_queue(source), dst)
    };
    if src.is_empty() && !input.writer_closed() {
        return Some(Err(FsError::WouldBlock));
    }
    if output.reader_closed() {
        return Some(Err(FsError::BrokenPipe));
    }
    if dst.is_full() {
        return Some(Err(FsError::WouldBlock));
    }
    let n = if duplicate {
        src.copy_prefix_to(&mut dst, max)
    } else {
        src.move_prefix_to(&mut dst, max)
    };
    drop(dst);
    drop(src);
    if n != 0 {
        if !duplicate {
            input.notify(narf_filesystem::POLL_OUT, n);
        }
        output.notify(narf_filesystem::POLL_IN, n);
    }
    Some(Ok(n))
}

pub(crate) fn resize(ops: &dyn FileOps, arg: u32) -> Option<Result<usize, u64>> {
    let endpoint = Endpoint::from_file(ops)?;
    Some((|| {
        if arg > 1u32 << 31 {
            return Err(EINVAL as u64);
        }
        let requested = (arg as usize).max(PIPE_BUF).next_power_of_two();
        if requested > narf_filesystem::procfs::sys_fs::pipe_max_size() as usize {
            return Err(EPERM as u64);
        }
        lock_queue(endpoint.queue()).resize(requested / PIPE_BUF)?;
        endpoint.notify(narf_filesystem::POLL_OUT, PIPE_BUF);
        Ok(requested)
    })())
}

pub(crate) fn is_pipe(ops: &dyn FileOps) -> bool {
    Endpoint::from_file(ops).is_some()
}

pub(crate) fn vmsplice_into(
    ops: &dyn FileOps,
    address_space: Option<&narf_memory::AddressSpace>,
    base: u64,
    len: usize,
) -> Result<Result<usize, narf_filesystem::FsError>, u64> {
    let endpoint = Endpoint::from_file(ops).ok_or(EBADF as u64)?;
    let mut q = lock_queue(endpoint.queue());
    if endpoint.reader_closed() {
        return Ok(Err(narf_filesystem::FsError::BrokenPipe));
    }
    #[cfg(feature = "kernel-test")]
    if crate::handlers::kernel_buf_scope::active() {
        let n = q.write_unmerged(len, |offset, dst| {
            // SAFETY: explicitly scoped kernel-test scratch buffers only.
            unsafe { crate::handlers::copy_from_user(dst, base + offset as u64) }
        })?;
        drop(q);
        if n != 0 {
            endpoint.notify(narf_filesystem::POLL_IN, n);
        }
        return Ok(Ok(n));
    }
    let address_space = address_space.ok_or(EFAULT as u64)?;
    let mut total = 0;
    while total < len && !q.is_full() {
        let address = base + total as u64;
        let offset = (address & 4095) as usize;
        let count = (len - total).min(4096 - offset);
        let result = (|| {
            // Fault in the page before looking up and retaining its current
            // backing under the memory subsystem's ownership lock. A racing
            // unmap is revalidated by pin_user_page, never by stale metadata.
            let mut probe = [0u8];
            // SAFETY: the complete iovec passed access_ok; guarded touch may
            // return EFAULT after a concurrent protection/mapping change.
            unsafe { crate::handlers::copy_from_user(&mut probe, address) }?;
            let pin = address_space
                .pin_user_page(narf_memory::VirtAddr::new(address))
                .ok_or(EFAULT as u64)?;
            q.push_pinned(pin, offset, count)
        })();
        if let Err(errno) = result {
            if total == 0 {
                return Err(errno);
            }
            break;
        }
        total += count;
    }
    drop(q);
    if total != 0 {
        endpoint.notify(narf_filesystem::POLL_IN, total);
    }
    Ok(Ok(total))
}

pub(crate) fn splice_to_sink(
    input: &dyn FileOps,
    max: usize,
    mut write: impl FnMut(&[u8]) -> Result<usize, narf_filesystem::FsError>,
) -> Result<usize, narf_filesystem::FsError> {
    use narf_filesystem::FsError;
    let input = Endpoint::from_file(input).ok_or(FsError::InvalidData)?;
    let mut q = lock_queue(input.queue());
    if q.is_empty() {
        return if input.writer_closed() {
            Ok(0)
        } else {
            Err(FsError::WouldBlock)
        };
    }
    let mut total = 0;
    while total < max && !q.is_empty() {
        let offered = q.front_len(max - total);
        let n = match q.with_front(offered, &mut write) {
            Ok(n) if n <= offered => n,
            Ok(_) if total == 0 => return Err(FsError::InvalidData),
            Err(error) if total == 0 => return Err(error),
            _ => break,
        };
        q.commit(n);
        total += n;
        if n < offered {
            break;
        }
    }
    drop(q);
    if total != 0 {
        input.notify(narf_filesystem::POLL_OUT, total);
    }
    Ok(total)
}

/// Retain native file pages, or read a buffered provider directly into fresh
/// nonmergeable pipe pages (Linux's copy_splice_read fallback).
pub(crate) fn splice_from_source(
    input: &dyn FileOps,
    offset: u64,
    output: &dyn FileOps,
    max: usize,
) -> Result<usize, narf_filesystem::FsError> {
    use narf_filesystem::FsError;
    let output = Endpoint::from_file(output).ok_or(FsError::InvalidData)?;
    let mut q = lock_queue(output.queue());
    if output.reader_closed() {
        return Err(FsError::BrokenPipe);
    }
    if q.is_full() {
        return Err(FsError::WouldBlock);
    }
    let mut total = 0;
    while total < max && !q.is_full() {
        let result = match input.splice_read_page(offset + total as u64, max - total) {
            Ok(Some(page)) if page.byte_len() <= max - total => {
                q.push_file_page(page).map_err(|_| FsError::OutOfMemory)
            }
            Ok(Some(_)) => Err(FsError::InvalidData),
            Ok(None) => break,
            Err(FsError::Unsupported) => {
                let mut actor_error = None;
                let result = q.fill_from(max - total, |within, bytes| {
                    crate::handlers::poll_blocking(
                        input.read(offset + total as u64 + within as u64, bytes),
                    )
                    .unwrap_or(Err(FsError::WouldBlock))
                    .map_err(|error| {
                        actor_error = Some(error);
                        5
                    })
                });
                result.map_err(|errno| {
                    actor_error.unwrap_or(if errno == 12 {
                        FsError::OutOfMemory
                    } else {
                        FsError::InvalidData
                    })
                })
            }
            Err(error) => Err(error),
        };
        match result {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(error) if total == 0 => return Err(error),
            Err(_) => break,
        }
    }
    drop(q);
    if total != 0 {
        output.notify(narf_filesystem::POLL_IN, total);
    }
    Ok(total)
}

/// Shared mutable state between the read+write halves: the byte
/// queue plus a "writer dropped" flag. The `closed_*` flags let
/// either half observe the peer-side close from the read/write
/// future without holding the queue lock.
#[derive(Debug)]
struct PipeShared {
    /// The pipe's pipefs inode, shared by both ends (`create_pipe_files`
    /// makes one inode and two files on it): both ends fstat to the same
    /// `(st_dev, st_ino)`, distinct from every other pipe.
    id: narf_filesystem::inode_id::InodeId,
    queue: queue::Queue,
    publish: IrqSafeSpinLock<()>,
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
    /// (see [`PipeShared::sync_readiness_after_transfer`]) fires the wait-queue for the changed
    /// direction so an EPOLLET consumer re-fires even at the same level.
    readiness: narf_lib::readiness::Readiness,
    /// Readiness publication is lazy. An untouched pipe has no possible
    /// waiter, so taking the readiness spinlock on every empty/full edge only
    /// maintains state nobody can observe. The first readiness accessor sets
    /// this while holding `publish`, publishes a current snapshot, and leaves it
    /// set forever; subsequent queue mutations then maintain and wake the
    /// durable cell normally.
    readiness_active: AtomicBool,
    /// Linux `pipe_inode_info::poll_usage`: once a persistent poll/epoll
    /// registration exists, same-level I/O events must continue firing.
    poll_usage: AtomicBool,
}

impl PipeShared {
    fn capacity(&self) -> usize {
        self.queue.capacity()
    }

    /// Start maintaining the durable readiness cell on first use. Taking the
    /// publication lock orders activation against transfer/close publication.
    /// Earlier completed mutations are included in the atomic queue snapshot;
    /// a mutation completing later sees the active flag and republishes.
    fn activate_readiness(&self) {
        if self.readiness_active.load(Ordering::Acquire) {
            return;
        }
        let _publish = self.publish.lock();
        if !self.readiness_active.swap(true, Ordering::AcqRel) {
            let (len, full) = self.queue.snapshot();
            self.publish_readiness_state_with_policy(0, len, full, false, true);
        }
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
    /// Keep direct handoff for token-sized traffic. Page-sized and bulk pipe
    /// traffic still gets an exact-waiter wake, but lets the running endpoint
    /// fill or drain the ring before it naturally blocks.
    #[inline]
    fn sync_readiness_after_transfer(
        &self,
        event: u32,
        len: usize,
        full: bool,
        transferred: usize,
    ) {
        self.sync_readiness_state_with_policy(event, len, full, false, transferred < PIPE_BUF);
    }

    #[inline]
    fn sync_readiness_state_all(&self, event: u32, len: usize, full: bool) {
        self.sync_readiness_state_with_policy(event, len, full, true, false);
    }

    #[inline]
    fn sync_readiness_state_with_policy(
        &self,
        event: u32,
        _len: usize,
        _full: bool,
        wake_all: bool,
        urgent_handoff: bool,
    ) {
        if !self.readiness_active.load(Ordering::Acquire) {
            return;
        }
        // Re-sample under the publication lock so a delayed older writer
        // cannot overwrite a newer state or a final-close notification.
        let _publish = self.publish.lock();
        let (len, full) = self.queue.snapshot();
        self.publish_readiness_state_with_policy(event, len, full, wake_all, urgent_handoff);
    }

    fn publish_readiness_state_with_policy(
        &self,
        event: u32,
        len: usize,
        full: bool,
        wake_all: bool,
        urgent_handoff: bool,
    ) {
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
            let continuation = if event == 0 {
                0
            } else {
                (narf_filesystem::POLL_IN | narf_filesystem::POLL_OUT) & !event
            };
            let selected = self.readiness.set_event_with_continuation(
                add,
                clear,
                notify,
                continuation,
                |task_id, waker| {
                    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                    if urgent_handoff {
                        narf_scheduler::wake_urgent_task(waker, task_id);
                    } else {
                        waker.wake_by_ref();
                    }
                    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                    waker.wake_by_ref();
                },
            );
            // Linux uses `wake_up_interruptible_sync_poll` (WF_SYNC) for pipe
            // reader/writer wakeups: the consumer should run promptly and
            // generate/free the next token. For a token-sized transfer, pass
            // only the exact exclusive blocker selected above into the
            // scheduler's revalidated handoff hint. Page-sized/bulk transfers
            // keep the ordinary targeted wake so the running endpoint can
            // batch. Plain poll/epoll observers never take this path.
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            if urgent_handoff {
                if let Some(task_id) = selected {
                    narf_scheduler::stackful::note_urgent_wake_preempt(task_id);
                }
            }
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
        id: narf_filesystem::inode_id::PseudoFs::Pipe.new_inode(),
        queue: queue::Queue::new(PipeBufs::new()),
        publish: IrqSafeSpinLock::new(()),
        writer_closed: AtomicBool::new(false),
        reader_closed: AtomicBool::new(false),
        // Fresh pipe: empty (not readable), has room (writable), both ends open.
        readiness: narf_lib::readiness::Readiness::new(narf_filesystem::POLL_OUT),
        readiness_active: AtomicBool::new(false),
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
        let packet = self.packetized.load(Ordering::Acquire);
        self.copy_from_user_into_pipe(src_uptr, len, packet)
    }

    fn copy_from_user_into_pipe(
        &self,
        src_uptr: u64,
        len: usize,
        packet: bool,
    ) -> Result<Result<usize, narf_filesystem::FsError>, u64> {
        if self.shared.reader_closed.load(Ordering::Acquire) {
            return Ok(Err(narf_filesystem::FsError::BrokenPipe));
        }
        let mut q = lock_queue(&self.shared.queue);
        // Recheck the durable close flag after waiting for the payload mutex.
        // A later close may linearize after this write's peer check.
        if self.shared.reader_closed.load(Ordering::Acquire) {
            return Ok(Err(narf_filesystem::FsError::BrokenPipe));
        }
        let was_empty = q.is_empty();
        let written = q.write_with(len, packet, |offset, dst| {
            // SAFETY: guarded user copy; the buffer is published only after
            // the complete page fragment has been copied successfully.
            unsafe { crate::handlers::copy_from_user(dst, src_uptr + offset as u64) }
        })?;
        let new_len = q.len();
        let new_full = q.is_full();
        drop(q);
        if written != 0 && (was_empty || new_full || self.shared.poll_usage.load(Ordering::Acquire))
        {
            self.shared.sync_readiness_after_transfer(
                narf_filesystem::POLL_IN,
                new_len,
                new_full,
                written,
            );
        }
        Ok(Ok(written))
    }

    async fn try_write(&self, buf: &[u8]) -> Result<usize, narf_filesystem::FsError> {
        // The syscall layer turns this into SIGPIPE plus -EPIPE.
        if self.shared.reader_closed.load(Ordering::Acquire) {
            return Err(narf_filesystem::FsError::BrokenPipe);
        }
        let mut q = self.shared.queue.lock_async().await;
        // Close does not need the payload mutex. Recheck its durable flag
        // after acquiring the mutex, before accepting any bytes.
        if self.shared.reader_closed.load(Ordering::Acquire) {
            return Err(narf_filesystem::FsError::BrokenPipe);
        }
        let packet = self.packetized.load(Ordering::Acquire);
        let was_empty = q.is_empty();
        let n = q
            .write_with(buf.len(), packet, |offset, dst| {
                dst.copy_from_slice(&buf[offset..offset + dst.len()]);
                Ok(())
            })
            .map_err(|_| narf_filesystem::FsError::OutOfMemory)?;
        let new_len = q.len();
        let new_full = q.is_full();
        drop(q);
        if n != 0 && (was_empty || new_full || self.shared.poll_usage.load(Ordering::Acquire)) {
            self.shared.sync_readiness_after_transfer(
                narf_filesystem::POLL_IN,
                new_len,
                new_full,
                n,
            );
            narf_net::readiness::bump_generation();
        }
        Ok(n)
    }
}

impl PipeRead {
    pub(crate) fn shares_pipe_with(&self, write: &PipeWrite) -> bool {
        Arc::ptr_eq(&self.shared, &write.shared)
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
        self.copy_direct_to_user(dst, max, true)
    }

    /// Copy a pipe prefix directly into user memory, committing one
    /// Linux-sized pipe buffer after each successful guarded copy.
    ///
    /// `discard_packets` selects read(2)'s packet-tail discard. Splice actors
    /// pass false: Linux advances a partially copied pipe buffer and leaves its
    /// tail queued, even when the buffer carries `PIPE_BUF_FLAG_PACKET`.
    fn copy_direct_to_user(
        &self,
        dst: u64,
        max: usize,
        discard_packets: bool,
    ) -> Result<usize, VmspliceDrainError> {
        let mut copied = 0usize;
        self.drain_to_user(max, discard_packets, |bytes| {
            // SAFETY: caller validated the range; guarded copy handles a
            // protection change while the immutable page is retained.
            unsafe { crate::handlers::copy_to_user(dst + copied as u64, bytes) }?;
            copied += bytes.len();
            Ok(())
        })
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
        // sys_vmsplice imported and validated the complete destination before
        // pipe lookup, preserving Linux's errno order. The direct copies still
        // catch a racing unmap before committing the affected pipe buffer.
        read_to_iter(self, max, false, |offset, src, len| {
            // SAFETY: the pipe retains this source; vmsplice imported dst.
            unsafe { crate::handlers::copy_raw_to_user(dst + offset as u64, src, len) }
        })
        .map_err(|errno| {
            if errno == EAGAIN as u64 {
                VmspliceDrainError::WouldBlock
            } else {
                VmspliceDrainError::User(errno)
            }
        })
    }

    /// Transactional pipe read used by read/readv/vmsplice: copy a stable
    /// prefix through `copy`, and consume it only after the complete guarded
    /// user-copy succeeds for each page buffer. A fault in a later iovec
    /// retains the currently faulting buffer; earlier complete buffers remain
    /// consumed and are reported as partial progress.
    pub(crate) fn read_to_user(
        &self,
        max: usize,
        copy: impl FnMut(&[u8]) -> Result<(), u64>,
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
        mut copy: impl FnMut(&[u8]) -> Result<(), u64>,
    ) -> Result<usize, VmspliceDrainError> {
        let mut q = lock_queue(&self.shared.queue);
        if q.is_empty() {
            return if self.shared.writer_closed.load(Ordering::Acquire) {
                Ok(0)
            } else {
                Err(VmspliceDrainError::WouldBlock)
            };
        }
        let was_full = q.is_full();
        let mut copied = 0;
        while copied < max && !q.is_empty() {
            let packet = q.front_info().unwrap().1;
            let n = q.front_len(max - copied);
            if let Err(errno) = q.with_front(n, &mut copy) {
                if copied == 0 {
                    return Err(VmspliceDrainError::User(errno));
                }
                break;
            }
            let consumed = if discard_packets && packet {
                q.front_info().unwrap().0
            } else {
                n
            };
            q.commit(consumed);
            copied += n;
            if discard_packets && packet {
                break;
            }
        }
        let new_len = q.len();
        let new_full = q.is_full();
        drop(q);
        if copied != 0
            && (was_full || new_len == 0 || self.shared.poll_usage.load(Ordering::Acquire))
        {
            self.shared.sync_readiness_after_transfer(
                narf_filesystem::POLL_OUT,
                new_len,
                new_full,
                copied,
            );
        }
        Ok(copied)
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
        let (len, full) = self.shared.queue.snapshot();
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
        self.shared.writer_closed.store(true, Ordering::Release);
        let (len, full) = self.shared.queue.snapshot();
        // Latch POLL_HUP into the durable cell after publishing closure — wakes
        // a reader parked on POLL_IN|POLL_HUP so it runs read()→0=EOF.
        self.shared
            .sync_readiness_state_all(narf_filesystem::POLL_IN, len, full);
        narf_net::readiness::bump_generation();
    }
}

impl FileOps for PipeRead {
    fn ino(&self) -> u64 {
        self.shared.id.ino
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::InodeAttrs {
            dev: self.shared.id.dev,
            ..Default::default()
        }
    }

    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let mut q = self.shared.queue.lock_async().await;
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
            q.copy_out(0, &mut buf[..n]);
            q.commit(consumed);
            drop(q);
            if n != 0 {
                // Draining can clear POLL_IN (queue now empty) and set POLL_OUT
                // (room freed); republish so a writer parked on this pipe's
                // readiness cell wakes, and bump the global notify generation so
                // a writer parked via `park_reexecute_on_io` (armed on that
                // generation, not the cell) re-runs instead of sleeping out its
                // deadline.
                self.shared
                    .sync_readiness_after_transfer(narf_filesystem::POLL_OUT, 0, false, n);
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
        let bytes = (self.shared.queue.snapshot().0 as i32).to_le_bytes();
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
        if self.shared.queue.snapshot().0 != 0 {
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
        // or close fires exactly this waiter. Its first observer reconciles the
        // lazily-maintained cell before returning it.
        self.shared.activate_readiness();
        Some(&self.shared.readiness)
    }

    fn arm_readiness(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        // A plain poll()/select waiter — not just epoll's persistent arm — must
        // mark the pipe poll-observed. Otherwise the write side skips
        // `sync_readiness` on a non-edge write (see `copy_from_user_into_pipe`,
        // gated on `was_empty || new_full || poll_usage`) and never republishes
        // POLL_IN/POLL_OUT to this parked waiter. That is the fish fd_monitor
        // self-pipe hang: fish parks in poll() on the notify read end while only
        // its iothread writes it, so without this the wake is lost and fish
        // stalls at startup until a SIGINT (Ctrl-C) breaks the poll.
        self.shared.poll_usage.store(true, Ordering::Release);
        self.shared.activate_readiness();
        Some(self.shared.readiness.arm(task_id, interest, waker))
    }

    fn arm_readiness_exclusive(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        // See `arm_readiness`: a plain poll()/select waiter must mark the pipe
        // poll-observed so the write side does not skip `sync_readiness` and lose
        // this parked waiter's wake.
        self.shared.poll_usage.store(true, Ordering::Release);
        self.shared.activate_readiness();
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
        self.shared.activate_readiness();
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
        let q = lock_queue(&self.shared.queue);
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
        q.copy_out(0, &mut bytes);
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
    fn ino(&self) -> u64 {
        self.shared.id.ino
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::InodeAttrs {
            dev: self.shared.id.dev,
            ..Default::default()
        }
    }

    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Reading the write end: EBADF on Linux (`fs/read_write.c::vfs_read`
        // FMODE_READ check — the pipe write end is opened O_WRONLY). The
        // old Ok(0) here masqueraded as a clean EOF.
        Box::pin(async move { Err(narf_filesystem::FsError::BadFd) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { self.try_write(buf).await })
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
        let bytes = (self.shared.queue.snapshot().0 as i32).to_le_bytes();
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
        if !self.shared.queue.snapshot().1 {
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
        self.shared.activate_readiness();
        Some(&self.shared.readiness)
    }

    fn arm_readiness(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        // A plain poll()/select waiter — not just epoll's persistent arm — must
        // mark the pipe poll-observed. Otherwise the write side skips
        // `sync_readiness` on a non-edge write (see `copy_from_user_into_pipe`,
        // gated on `was_empty || new_full || poll_usage`) and never republishes
        // POLL_IN/POLL_OUT to this parked waiter. That is the fish fd_monitor
        // self-pipe hang: fish parks in poll() on the notify read end while only
        // its iothread writes it, so without this the wake is lost and fish
        // stalls at startup until a SIGINT (Ctrl-C) breaks the poll.
        self.shared.poll_usage.store(true, Ordering::Release);
        self.shared.activate_readiness();
        Some(self.shared.readiness.arm(task_id, interest, waker))
    }

    fn arm_readiness_exclusive(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        // See `arm_readiness`: a plain poll()/select waiter must mark the pipe
        // poll-observed so the write side does not skip `sync_readiness` and lose
        // this parked waiter's wake.
        self.shared.poll_usage.store(true, Ordering::Release);
        self.shared.activate_readiness();
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
        self.shared.activate_readiness();
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
