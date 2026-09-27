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
//! are: reads return [`FsError::WouldBlock`] for an empty live stream, and
//! the syscall layer parks + re-executes. The open-time peer rendezvous
//! (O_RDONLY blocks until a writer appears, and vice versa) lives in
//! `sys_open`, which must release every filesystem/fd-table lock before it
//! parks — a FIFO open holding a lock across the wait would wedge the
//! kernel.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::{Poll, Waker};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_ERR, POLL_HUP, POLL_IN, POLL_OUT,
};

/// Presence bit in each directional open-rendezvous readiness cell.
const PEER_PRESENT: u32 = 1;

/// Result classes for a named FIFO's transactional vmsplice-to-user drain.
/// User-copy errno is kept intact for the Linux syscall layer.
#[derive(Debug)]
pub enum VmspliceDrainError {
    WouldBlock,
    User(u64),
    BadFd,
}

/// Result classes for the named-FIFO direct user-copy write path.  Keeping
/// readiness and peer failures distinct from a guarded-copy failure lets the
/// syscall layer preserve Linux's EAGAIN/EPIPE-before-EFAULT ordering.
#[derive(Debug)]
pub enum FifoWriteError {
    WouldBlock,
    User(u64),
    BadFd,
    BrokenPipe,
}

/// The shared, mutable state of a named pipe: the byte queue plus live
/// reader/writer OPEN counts. Both counts are the per-open population of
/// [`FifoHandle`]s currently referencing this FIFO, incremented when a
/// handle is built (at `open`) and decremented on the handle's `Drop` (at
/// `close`). EOF is `queue empty && writers == 0`; a write with
/// `readers == 0` is a broken pipe.
#[derive(Debug)]
pub struct FifoShared {
    queue: crate::pipe_queue::Queue,
    /// Serializes opener-count transitions and publication of the derived
    /// readiness levels. Without this, two open/close paths can snapshot in
    /// one order and publish in the opposite order, leaving a stale peer level.
    publish: IrqSafeSpinLock<()>,
    /// Number of read-capable handles currently open (O_RDONLY + O_RDWR).
    readers: AtomicU32,
    /// Number of write-capable handles currently open (O_WRONLY + O_RDWR).
    writers: AtomicU32,
    /// Combined readiness for every directional handle on this FIFO. Waiters
    /// arm only the bits their handle can consume, so one shared cell mirrors
    /// Linux's one wait-queue pair per pipe inode without a global wake scan.
    readiness: narf_lib::readiness::Readiness,
    /// Direction-specific presence cells for blocking-open rendezvous. A
    /// separate cell per direction gives each waiter an independent edge
    /// sequence, so an open+close that completes before it runs is durable.
    reader_presence: narf_lib::readiness::Readiness,
    writer_presence: narf_lib::readiness::Readiness,
}

impl FifoShared {
    /// Common pipe-buffer queue, also used by cross-pipe splice/tee.
    pub fn queue(&self) -> &crate::pipe_queue::Queue {
        &self.queue
    }

    /// Publish a completed transfer after releasing the payload mutex.
    pub fn notify_transfer(&self, event: u32, transferred: usize) {
        let _publish = self.publish.lock();
        self.sync_readiness_locked(event, false, transferred != 0 && transferred < 4096);
    }

    /// Shared unread byte count for FIONREAD on either open direction.
    pub fn unread_bytes(&self) -> usize {
        self.queue.snapshot().0
    }

    fn new() -> Self {
        FifoShared {
            queue: crate::pipe_queue::Queue::new(crate::pipe_buffer::PipeBufs::new()),
            publish: IrqSafeSpinLock::new(()),
            readers: AtomicU32::new(0),
            writers: AtomicU32::new(0),
            readiness: narf_lib::readiness::Readiness::new(POLL_OUT | POLL_HUP | POLL_ERR),
            reader_presence: narf_lib::readiness::Readiness::new(0),
            writer_presence: narf_lib::readiness::Readiness::new(0),
        }
    }

    /// Publish levels while `publish` is held. Open/close use this form so the
    /// count transition and its derived presence edge are one ordered action.
    fn sync_readiness_locked(&self, event: u32, wake_all: bool, urgent_handoff: bool) {
        let (len, full) = self.queue.snapshot();
        let mut mask = 0;
        if len != 0 {
            mask |= POLL_IN;
        }
        if !full {
            mask |= POLL_OUT;
        }
        if self.writers.load(Ordering::Acquire) == 0 {
            mask |= POLL_HUP;
        }
        if self.readers.load(Ordering::Acquire) == 0 {
            mask |= POLL_ERR;
        }
        let clear = (POLL_IN | POLL_OUT | POLL_HUP | POLL_ERR) & !mask;
        if wake_all {
            self.readiness.set_wake_all(mask, clear);
        } else {
            let continuation = if event == 0 {
                0
            } else {
                (POLL_IN | POLL_OUT) & !event
            };
            let selected = self.readiness.set_event_with_continuation(
                mask,
                clear,
                event,
                continuation,
                |task_id, waker| {
                    if urgent_handoff {
                        narf_scheduler::wake_urgent_task(waker, task_id);
                    } else {
                        waker.wake_by_ref();
                    }
                },
            );
            if urgent_handoff {
                if let Some(task_id) = selected {
                    narf_scheduler::stackful::note_urgent_wake_preempt(task_id);
                }
            }
        }
        let readers = self.readers.load(Ordering::Acquire);
        let writers = self.writers.load(Ordering::Acquire);
        self.reader_presence.set(
            if readers != 0 { PEER_PRESENT } else { 0 },
            if readers == 0 { PEER_PRESENT } else { 0 },
        );
        self.writer_presence.set(
            if writers != 0 { PEER_PRESENT } else { 0 },
            if writers == 0 { PEER_PRESENT } else { 0 },
        );
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
    packetized: AtomicBool,
    /// Counterpart-presence edge observed before this handle published its own
    /// direction. A changed edge completes a blocking open even if the peer
    /// opened and closed before this task was scheduled.
    peer_seq_at_open: u64,
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
        let publish = shared.publish.lock();
        let peer_seq_at_open = if can_read && !can_write {
            shared.writer_presence.seq()
        } else if can_write && !can_read {
            shared.reader_presence.seq()
        } else {
            0
        };
        if can_read {
            shared.readers.fetch_add(1, Ordering::AcqRel);
        }
        if can_write {
            shared.writers.fetch_add(1, Ordering::AcqRel);
        }
        shared.sync_readiness_locked(0, true, false);
        drop(publish);
        FifoHandle {
            shared,
            _inode_owner: inode_owner,
            ino,
            perms,
            uid,
            gid,
            can_read,
            can_write,
            packetized: AtomicBool::new(false),
            peer_seq_at_open,
        }
    }

    /// The shared buffer this handle is attached to — used by the open-time
    /// peer rendezvous in `sys_open` to poll the peer counts.
    pub fn shared(&self) -> &Arc<FifoShared> {
        &self.shared
    }

    fn peer_cell(&self) -> Option<&narf_lib::readiness::Readiness> {
        if self.can_read && !self.can_write {
            Some(&self.shared.writer_presence)
        } else if self.can_write && !self.can_read {
            Some(&self.shared.reader_presence)
        } else {
            None
        }
    }

    /// Whether a blocking single-direction open has observed its counterpart,
    /// either as a current level or as a transient open+close edge.
    pub fn peer_ready_or_seen(&self) -> bool {
        self.peer_cell().is_none_or(|cell| {
            cell.mask() & PEER_PRESENT != 0 || cell.seq() != self.peer_seq_at_open
        })
    }

    /// Atomically arm a blocking-open waiter on counterpart presence. The
    /// post-arm edge recheck closes a transient peer race that level alone
    /// cannot represent.
    pub fn arm_peer(&self, task_id: u64, waker: &Waker) -> Poll<()> {
        let Some(cell) = self.peer_cell() else {
            return Poll::Ready(());
        };
        if self.peer_ready_or_seen() {
            return Poll::Ready(());
        }
        match cell.arm(task_id, PEER_PRESENT, waker) {
            Poll::Ready(_) => Poll::Ready(()),
            Poll::Pending if cell.seq() != self.peer_seq_at_open => {
                cell.disarm(task_id);
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }

    pub fn disarm_peer(&self, task_id: u64) {
        if let Some(cell) = self.peer_cell() {
            cell.disarm(task_id);
        }
    }

    /// Copy the current FIFO prefix through `copy`, consuming it only after
    /// that complete user-copy transaction succeeds.
    ///
    /// Linux's `pipe_to_user` actor advances/removes a pipe buffer only after
    /// `copy_page_to_iter` reports the requested length. Holding the queue lock
    /// across the callback gives named FIFOs the same observe/copy/commit
    /// semantics: an inaccessible or concurrently unmapped destination leaves
    /// every byte queued, while another reader cannot reorder the prefix. This
    /// FIFO stores bytes rather than per-write pipe_buffer boundaries, so the
    /// selected prefix is conservatively one logical buffer and commits
    /// all-or-none across a vector copy.
    pub async fn vmsplice_to_user(
        &self,
        max: usize,
        copy: impl FnMut(&[u8]) -> Result<(), u64>,
    ) -> Result<usize, VmspliceDrainError> {
        self.drain_to_user(max, false, copy).await
    }

    pub async fn read_to_user(
        &self,
        max: usize,
        copy: impl FnMut(&[u8]) -> Result<(), u64>,
    ) -> Result<usize, VmspliceDrainError> {
        self.drain_to_user(max, true, copy).await
    }

    async fn drain_to_user(
        &self,
        max: usize,
        discard_packets: bool,
        mut copy: impl FnMut(&[u8]) -> Result<(), u64>,
    ) -> Result<usize, VmspliceDrainError> {
        if !self.can_read {
            return Err(VmspliceDrainError::BadFd);
        }

        let mut q = self.shared.queue.lock_async().await;
        let avail = q.len();
        if avail == 0 {
            return if self.shared.writers.load(Ordering::Acquire) == 0 {
                Ok(0)
            } else {
                Err(VmspliceDrainError::WouldBlock)
            };
        }
        let mut n = 0;
        while n < max && !q.is_empty() {
            let packet = q.front_info().unwrap().1;
            let count = q.front_len(max - n);
            if let Err(errno) = q.with_front(count, &mut copy) {
                if n == 0 {
                    return Err(VmspliceDrainError::User(errno));
                }
                break;
            }
            let consumed = if packet && discard_packets {
                q.front_info().unwrap().0
            } else {
                count
            };
            q.commit(consumed);
            n += count;
            if packet && discard_packets {
                break;
            }
        }
        drop(q);
        if n != 0 {
            self.shared.notify_transfer(POLL_OUT, n);
        }
        Ok(n)
    }

    /// Copy from userspace into this FIFO only after peer/fullness checks.
    ///
    /// Linux's `anon_pipe_write` takes the pipe mutex, checks readers and
    /// available buffer slots, and only then calls `copy_page_from_iter`.
    /// Reserving initialized deque space before invoking `copy` gives the
    /// named FIFO the same ordering without a heap allocation or boxed async
    /// future on the syscall hot path. A failed copy truncates the reservation,
    /// leaving the queue unchanged.
    pub async fn write_from_user(
        &self,
        max: usize,
        mut copy: impl FnMut(&mut [u8]) -> Result<(), u64>,
    ) -> Result<usize, FifoWriteError> {
        if !self.can_write {
            return Err(FifoWriteError::BadFd);
        }

        let mut q = self.shared.queue.lock_async().await;
        if self.shared.readers.load(Ordering::Acquire) == 0 {
            return Err(FifoWriteError::BrokenPipe);
        }
        let n = q
            .write_with(max, self.packetized.load(Ordering::Acquire), |_, dst| {
                copy(dst)
            })
            .map_err(FifoWriteError::User)?;
        drop(q);
        if n == 0 && max != 0 {
            return Err(FifoWriteError::WouldBlock);
        }
        self.shared.notify_transfer(POLL_IN, n);
        Ok(n)
    }

    pub fn set_packetized(&self, packetized: bool) {
        self.packetized.store(packetized, Ordering::Release);
    }

    fn arm_data(
        &self,
        task_id: u64,
        interest: u32,
        waker: &Waker,
        exclusive: bool,
    ) -> Option<Poll<u32>> {
        // The shared cell is the union of both endpoint views.  Restrict the
        // interest to bits this open description can actually observe, or a
        // read-only fd polling POLLOUT (for example) would spin on the shared
        // buffer's write readiness.
        let mut local_interest = 0;
        if self.can_read {
            local_interest |= interest & (POLL_IN | POLL_HUP);
        }
        if self.can_write {
            local_interest |= interest & (POLL_OUT | POLL_ERR);
        }

        let suppress_initial_hup = self.can_read
            && !self.can_write
            && self.shared.writers.load(Ordering::Acquire) == 0
            && self.shared.writer_presence.seq() == self.peer_seq_at_open;
        let first_interest = if suppress_initial_hup {
            local_interest & !POLL_HUP
        } else {
            local_interest
        };

        let arm = |bits| {
            if exclusive {
                self.shared.readiness.arm_exclusive(task_id, bits, waker)
            } else {
                self.shared.readiness.arm(task_id, bits, waker)
            }
        };
        let first = arm(first_interest);
        if first.is_ready() || !suppress_initial_hup {
            self.disarm_peer(task_id);
            return Some(first);
        }

        // A writer appearing is not itself POLLIN, but it changes whether a
        // later writer close is a visible HUP.  Arm the presence edge after
        // the data cell, then re-arm the data cell with HUP enabled if that
        // edge already raced us.  The two register-then-check operations make
        // both writer-open and writer-open+close races lossless.
        match self.arm_peer(task_id, waker) {
            Poll::Pending => Some(Poll::Pending),
            Poll::Ready(()) => {
                self.shared.readiness.disarm(task_id);
                Some(arm(local_interest))
            }
        }
    }

    pub fn packetized(&self) -> bool {
        self.packetized.load(Ordering::Acquire)
    }

    /// Linux suppresses `POLLHUP` on a read-only FIFO opened with no writer
    /// until that particular open description has observed a writer.  Without
    /// this per-open edge check, `poll(POLLIN)` returns immediately on a fresh
    /// nonblocking reader, which can make the reader close before a writer gets
    /// scheduled to complete the rendezvous.
    fn read_hangup_visible(&self) -> bool {
        self.can_read
            && self.shared.writers.load(Ordering::Acquire) == 0
            && self.shared.writer_presence.seq() != self.peer_seq_at_open
    }
}

impl Drop for FifoHandle {
    fn drop(&mut self) {
        // Releasing the last write-capable handle flips the reader to EOF;
        // releasing the last read-capable handle makes further writes a
        // broken pipe.
        let publish = self.shared.publish.lock();
        if self.can_read {
            self.shared.readers.fetch_sub(1, Ordering::AcqRel);
        }
        if self.can_write {
            self.shared.writers.fetch_sub(1, Ordering::AcqRel);
        }
        if self.shared.reader_count() == 0 && self.shared.writer_count() == 0 {
            // No live handle can still be executing an operation: its borrow
            // would retain an open description and therefore an opener count.
            // Reset before another open passes the publication lock.
            self.shared
                .queue
                .try_lock()
                .expect("last FIFO handle owns no active I/O")
                .reset();
        }
        self.shared.sync_readiness_locked(0, true, false);
        drop(publish);
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
            let mut q = self.shared.queue.lock_async().await;
            let avail = q.len();
            if avail == 0 {
                // Empty: EOF only once every writer has closed; otherwise
                // would-block. Linux `fs/pipe.c::pipe_read` splits these as
                // 0 vs -EAGAIN. Decided under the SAME lock that saw the
                // empty queue, so a writer arriving concurrently cannot be
                // mistaken for end-of-file.
                return if self.shared.writers.load(Ordering::Acquire) == 0 {
                    Ok(0)
                } else {
                    Err(FsError::WouldBlock)
                };
            }
            let (n, consumed) = q.read_span(buf.len());
            q.copy_out(0, &mut buf[..n]);
            q.commit(consumed);
            drop(q);
            self.shared.notify_transfer(POLL_OUT, n);
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
            let mut q = self.shared.queue.lock_async().await;
            let n = q
                .write_with(
                    buf.len(),
                    self.packetized.load(Ordering::Acquire),
                    |offset, dst| {
                        dst.copy_from_slice(&buf[offset..offset + dst.len()]);
                        Ok(())
                    },
                )
                .map_err(|_| FsError::OutOfMemory)?;
            drop(q);
            if n != 0 {
                self.shared.notify_transfer(POLL_IN, n);
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
        let (len, full) = self.shared.queue.snapshot();
        if self.can_read {
            if len != 0 {
                mask |= POLL_IN;
            }
            if self.read_hangup_visible() {
                mask |= POLL_HUP;
            }
        }
        if self.can_write {
            if !full {
                mask |= POLL_OUT;
            }
            if self.shared.readers.load(Ordering::Acquire) == 0 {
                mask |= POLL_ERR;
            }
        }
        mask
    }

    fn readiness_notifies(&self) -> bool {
        true
    }

    fn readiness(&self) -> Option<&narf_lib::readiness::Readiness> {
        Some(&self.shared.readiness)
    }

    fn arm_readiness(&self, task_id: u64, interest: u32, waker: &Waker) -> Option<Poll<u32>> {
        self.arm_data(task_id, interest, waker, false)
    }

    fn arm_readiness_exclusive(
        &self,
        task_id: u64,
        interest: u32,
        waker: &Waker,
    ) -> Option<Poll<u32>> {
        self.arm_data(task_id, interest, waker, true)
    }

    fn disarm_readiness(&self, task_id: u64) -> bool {
        self.shared.readiness.disarm(task_id);
        self.disarm_peer(task_id);
        true
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
        Some(self.shared.queue.capacity())
    }

    fn pipe_peek(&self, max: usize) -> Option<alloc::vec::Vec<u8>> {
        if !self.can_read {
            return None;
        }
        let q = self.shared.queue.try_lock()?;
        let (n, _) = q.read_span(max);
        let mut bytes = alloc::vec![0; n];
        q.copy_out(0, &mut bytes);
        Some(bytes)
    }

    fn fifo_shared(&self) -> Option<Arc<FifoShared>> {
        Some(Arc::clone(&self.shared))
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}
