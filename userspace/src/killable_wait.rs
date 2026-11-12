//! Filesystem waits a fatal signal can end — Linux `TASK_KILLABLE`.
//!
//! A syscall handler runs in trap context and drives a filesystem future
//! with [`crate::handlers::poll_blocking`]: `Pending` parks the task until
//! the future's own waker fires. Nothing else ends that park, so a future
//! that never completes left the task impossible to remove — SIGKILL set
//! its pending bit, woke it, and the park went straight back to sleep.
//!
//! Linux sleeps in `TASK_KILLABLE` on the waits a dying task has no reason
//! to finish: `filemap_read` → `filemap_update_page` →
//! `folio_put_wait_locked(folio, TASK_KILLABLE)`, `folio_lock_killable`,
//! `__folio_lock_or_retry` under `FAULT_FLAG_KILLABLE`, `iterate_dir`'s
//! `down_read_killable(&inode->i_rwsem)`, `generic_perform_write`'s
//! `fatal_signal_pending(current)` test and `balance_dirty_pages`. Those
//! return `-EINTR`/`VM_FAULT_RETRY` and the task dies on its way out of the
//! kernel. Waits that must not be abandoned — a transaction commit
//! (`btrfs_commit_transaction` → `wait_event`), `i_rwsem` taken for a
//! namespace change — stay uninterruptible there and stay on
//! `poll_blocking` here.
//!
//! What NARF cannot do is unwind the operation the way Linux returns from a
//! killable sleep. A filesystem future that has been polled may own a
//! device's shared DMA scratch buffer with a request in flight
//! (`drivers/fs/btrfs` `read_exact_from`/`write_exact_to` hold the volume's
//! `io` mutex across `device.submit().await`), the btrfs operation lock, or
//! a half-staged batch. Dropping it there would release the scratch buffer
//! under the device and abandon the operation mid-edit. So a killed wait
//! never drops its future: the future owns everything it touches
//! (`Arc<dyn FileOps>`, its buffer) and is handed to the scheduler to run to
//! its own terminal completion while the task goes on to die. That is the
//! one shape that is safe for every filesystem, which is why every wait in
//! this module takes an owned, `'static` future.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use narf_filesystem::{DirOps, FileOps, FileType, FsError, ReadOptions};

/// An operation that owns everything it borrows from.
pub(crate) type OwnedWait<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// A killed operation on its way to the scheduler.
pub(crate) type Detached = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// The wait ended because the task has a fatal signal pending. The operation
/// is still running; its result will never be seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Killed;

/// What a killable filesystem wait reports: `Err(Killed)`, or what
/// `poll_blocking` would have — `None` when there was no executor to park on.
pub(crate) type Waited<T> = Result<Option<Result<T, FsError>>, Killed>;

/// Linux `fatal_signal_pending(task)`.
fn fatal_signal_pending(task: u64) -> bool {
    crate::handlers::task_fatal_signal_pending(task)
}

fn detach_to_scheduler(op: Detached) {
    #[cfg(feature = "kernel-test")]
    {
        let hook = tests::DETACH_HOOK.load(core::sync::atomic::Ordering::Acquire);
        if hook != 0 {
            // SAFETY: the only non-zero values stored are `fn(Detached)`
            // pointers, by `tests::DetachFixture`.
            let hook: fn(Detached) = unsafe { core::mem::transmute(hook) };
            return hook(op);
        }
    }
    narf_scheduler::spawn(op);
}

fn discard<T>(_: T) {}

/// One owned operation, waited for killably.
///
/// The operation is polled before anything else, so an operation that
/// completes at once (a page-cache hit) costs no signal bookkeeping. Only a
/// `Pending` poll arms this task's signal waker and then tests for a fatal
/// signal — in that order, so a SIGKILL raised after the test finds the
/// waker.
pub(crate) struct KillableWait<T: Send + 'static> {
    task: u64,
    op: Option<OwnedWait<T>>,
    /// The operation returned `Pending` at least once: it may hold a lock or
    /// have I/O in flight, and must reach its own completion.
    started: bool,
    armed: bool,
    killed: bool,
    detach: fn(Detached),
    /// Runs on the result of a killed operation, in the scheduler task that
    /// finished it: whatever the waiter would have done that other tasks
    /// depend on.
    finish: fn(T),
}

impl<T: Send + 'static> KillableWait<T> {
    pub(crate) fn new(task: u64, op: OwnedWait<T>) -> Self {
        Self {
            task,
            op: Some(op),
            started: false,
            armed: false,
            killed: false,
            detach: detach_to_scheduler,
            finish: discard::<T>,
        }
    }

    #[cfg(feature = "kernel-test")]
    pub(crate) fn finish_with(mut self, finish: fn(T)) -> Self {
        self.finish = finish;
        self
    }

    #[cfg(feature = "kernel-test")]
    fn detach_with(mut self, detach: fn(Detached)) -> Self {
        self.detach = detach;
        self
    }
}

impl<T: Send + 'static> Future for KillableWait<T> {
    type Output = Result<T, Killed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let op = match this.op.as_mut() {
            Some(op) if !this.killed => op,
            // Polled again after it resolved. `poll_blocking` returns on the
            // first `Ready`, so this is not reached; a killed operation must
            // in any case not be polled from here again.
            _ => return Poll::Ready(Err(Killed)),
        };
        match op.as_mut().poll(cx) {
            Poll::Ready(value) => {
                this.op = None;
                Poll::Ready(Ok(value))
            }
            Poll::Pending => {
                this.started = true;
                crate::handlers::register_signal_waker(this.task, cx.waker().clone());
                this.armed = true;
                if fatal_signal_pending(this.task) {
                    this.killed = true;
                    Poll::Ready(Err(Killed))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl<T: Send + 'static> Drop for KillableWait<T> {
    fn drop(&mut self) {
        if self.armed {
            crate::handlers::drop_signal_waker(self.task);
        }
        let Some(op) = self.op.take() else {
            return;
        };
        if self.killed && self.started {
            // Runs after `poll` returned, with no registry or driver lock
            // held. The scheduler task's first poll installs its own waker
            // in whatever the operation is waiting on.
            let finish = self.finish;
            (self.detach)(Box::pin(async move { finish(op.await) }));
        }
        // Not killed: the caller gave up for a reason of its own (no
        // executor to park on), exactly as `poll_blocking` always has.
    }
}

/// Drive `wait` with `poll_io_to_completion` (`io`) or `poll_blocking`.
///
/// Every function between a syscall handler and here is `#[track_caller]`,
/// so a task parked in one of these waits is named in `/proc/<pid>/stack`
/// by the handler line that started it, not by this module.
#[track_caller]
fn wait_with<T: Send + 'static>(wait: KillableWait<T>, io: bool) -> Result<Option<T>, Killed> {
    let outcome = if io {
        crate::handlers::poll_io_to_completion(wait)
    } else {
        crate::handlers::poll_blocking(wait)
    };
    match outcome {
        Some(Ok(value)) => Ok(Some(value)),
        Some(Err(Killed)) => Err(Killed),
        None => Ok(None),
    }
}

/// [`crate::handlers::poll_blocking`] that a fatal signal ends. `Ok(None)`
/// is `poll_blocking`'s `None`: there was no executor to park on.
#[track_caller]
pub(crate) fn wait<T: Send + 'static>(op: OwnedWait<T>) -> Result<Option<T>, Killed> {
    let wait = KillableWait::new(crate::handlers::current_task_id(), op);
    wait_with(wait, false)
}

/// [`crate::handlers::poll_io_to_completion`] that a fatal signal ends.
#[track_caller]
pub(crate) fn wait_io<T: Send + 'static>(op: OwnedWait<T>) -> Result<Option<T>, Killed> {
    let wait = KillableWait::new(crate::handlers::current_task_id(), op);
    wait_with(wait, true)
}

/// Whether `ops` is stored file data: a regular file of an on-disk or
/// in-memory filesystem.
///
/// Only those are waited for killably. A pipe, socket, FIFO, device or
/// event descriptor has no position: a read that finished after its reader
/// died would consume bytes or an event meant for the next reader, a write
/// would deliver a dead writer's bytes, and the operation's `Arc` would hold
/// the object open past the process's last close. Those block through their
/// readiness parks, which signals already end; one whose read future itself
/// pends keeps the uninterruptible wait it had.
///
/// File type cannot tell the two apart — an inotify descriptor and the
/// pollable procfs files are `FileType::File` too. [`FileOps::can_poll`]
/// can: only plain file data answers `false` (Linux: a file with no
/// `->poll`), which is the class `filemap_read` and `generic_perform_write`
/// serve.
fn stores_file_data(ops: &dyn FileOps) -> bool {
    !ops.is_stream() && !ops.can_poll()
}

/// `read(2)`-family read into `staging[..want]` — `filemap_read`'s killable
/// page wait. The buffer travels with the operation and comes back with its
/// result; after `Err(Killed)` (and after `Ok(None)`) it is gone and
/// `staging` is empty.
///
/// Anything but stored file data ([`stores_file_data`]) is read as before.
///
/// Stored file data is read through the file's cached `MAP_SHARED` pages:
/// a store made through a mapping and not written back yet is part of what
/// `read(2)` returns, as it is on Linux, where both use one folio.
#[track_caller]
pub(crate) fn read(
    ops: &Arc<dyn FileOps>,
    offset: u64,
    staging: &mut Vec<u8>,
    want: usize,
    options: ReadOptions,
) -> Waited<usize> {
    // Before the filesystem read: see `mapped_file::overlay_dirty`.
    let epoch = crate::mapped_file::read_epoch();
    if !stores_file_data(ops.as_ref()) {
        let want = want.min(staging.len());
        let outcome = crate::handlers::poll_blocking(ops.read_with_options(
            offset,
            &mut staging[..want],
            options,
        ));
        // A file may be mappable without saying it is plain stored data.
        if let (Some(Ok(read)), false) = (&outcome, ops.is_stream()) {
            let read = (*read).min(want);
            crate::mapped_file::overlay_dirty(ops, offset, &mut staging[..read], epoch);
        }
        return Ok(outcome);
    }
    let file = ops.clone();
    let mut buffer = core::mem::take(staging);
    let want = want.min(buffer.len());
    let done = wait(Box::pin(async move {
        let result = file
            .read_with_options(offset, &mut buffer[..want], options)
            .await;
        (result, buffer)
    }))?;
    Ok(done.map(|(result, buffer)| {
        *staging = buffer;
        if let Ok(read) = result {
            let read = read.min(staging.len());
            crate::mapped_file::overlay_dirty(ops, offset, &mut staging[..read], epoch);
        }
        result
    }))
}

/// `write(2)`-family write of `payload` — `generic_perform_write`'s
/// `fatal_signal_pending` test, and the reservation and writeback-throttle
/// sleeps under it (`btrfs` `wait_reserve_ticket`, `balance_dirty_pages`),
/// which are `TASK_KILLABLE`, and the wait for the file's writeback lock. A
/// killed write is not cut short: it completes in the background, whole,
/// cache report included, as if the signal had arrived just after it.
/// `payload` comes back with the result; after `Err(Killed)` and `Ok(None)`
/// it is empty.
///
/// The live `MAP_SHARED` pages of the file are told of the bytes here
/// ([`crate::mapped_file::write_and_note`]); callers do not report them
/// again.
///
/// Anything but stored file data ([`stores_file_data`]) is not waited for
/// killably.
#[track_caller]
pub(crate) fn write(ops: &Arc<dyn FileOps>, offset: u64, payload: &mut Vec<u8>) -> Waited<usize> {
    let bytes = core::mem::take(payload);
    let op = crate::mapped_file::write_and_note(ops.clone(), offset, bytes);
    if !stores_file_data(ops.as_ref()) {
        return Ok(crate::handlers::poll_blocking(op).map(|(result, bytes)| {
            *payload = bytes;
            result
        }));
    }
    let wait = KillableWait::new(crate::handlers::current_task_id(), Box::pin(op));
    let done = wait_with(wait, false)?;
    Ok(done.map(|(result, bytes)| {
        *payload = bytes;
        result
    }))
}

/// `getdents64` batch — `iterate_dir`'s `down_read_killable(&inode->i_rwsem)`.
#[track_caller]
pub(crate) fn enumerate(
    dir: &Arc<dyn DirOps>,
    cursor: usize,
    max: usize,
) -> Waited<Vec<(String, FileType)>> {
    let dir = dir.clone();
    wait(Box::pin(
        async move { dir.enumerate_async(cursor, max).await },
    ))
}

/// A durability wait — `fsync`/`fdatasync` (`ops.fsync`), `syncfs`
/// (`ops.syncfs`) or `sync` — that a fatal signal ends.
///
/// Linux does not sleep killably here: `btrfs_sync_file` takes the inode
/// lock and waits for its transaction to commit uninterruptibly. What makes
/// that tolerable there is that the wait is short; here the commit queues
/// behind every other operation on the volume, and a killed task sat in that
/// queue for minutes before it could exit. Ending the wait changes nothing
/// anyone can observe: a sync has no result but its return value, and the
/// task that would read it is dying. So a task that already has SIGKILL
/// pending does not start one at all, and one that is killed while it waits
/// leaves the operation — which may already hold the volume's operation lock
/// or have a commit in flight — to finish in the background, as a killed
/// write does.
#[track_caller]
fn durability(op: OwnedWait<Result<(), FsError>>) -> Waited<()> {
    if fatal_signal_pending(crate::handlers::current_task_id()) {
        return Err(Killed);
    }
    wait(op)
}

/// `fsync(2)`/`fdatasync(2)`'s filesystem commit. See [`durability`].
#[track_caller]
pub(crate) fn fsync(ops: &Arc<dyn FileOps>, data_only: bool) -> Waited<()> {
    let file = ops.clone();
    durability(Box::pin(async move { file.fsync(data_only).await }))
}

/// `syncfs(2)`'s filesystem commit. See [`durability`].
#[track_caller]
pub(crate) fn syncfs(ops: &Arc<dyn FileOps>) -> Waited<()> {
    let file = ops.clone();
    durability(Box::pin(async move { file.syncfs().await }))
}

/// `sync(2)`: every mounted filesystem, then every disk. See
/// [`durability`].
#[track_caller]
pub(crate) fn sync_all() -> Result<Option<narf_filesystem::sync_all::SyncReport>, Killed> {
    if fatal_signal_pending(crate::handlers::current_task_id()) {
        return Err(Killed);
    }
    wait(Box::pin(narf_filesystem::sync_all::sync_all()))
}

/// A file page fault's cache fill — `filemap_fault` →
/// `__folio_lock_or_retry` with `FAULT_FLAG_KILLABLE`. The frame it resolves
/// to is the file's own cache page, so a fill that finishes after its
/// faulting task died leaves nothing to release.
#[track_caller]
pub(crate) fn mmap_fault(ops: &Arc<dyn FileOps>, offset: u64) -> Waited<u64> {
    let file = ops.clone();
    wait_io(Box::pin(async move { file.mmap_fault_async(offset).await }))
}

/// A fresh frame an operation is filling. Whoever ends up with the guard
/// decides the frame's fate: the faulting task takes the frame out, a killed
/// fill drops the guard in the scheduler and the frame goes back.
pub(crate) struct FilledFrame(Option<narf_memory::PhysAddr>);

impl FilledFrame {
    pub(crate) fn take(mut self) -> narf_memory::PhysAddr {
        self.0.take().expect("frame present until taken")
    }
}

impl Drop for FilledFrame {
    fn drop(&mut self) {
        if let Some(frame) = self.0.take() {
            #[cfg(feature = "kernel-test")]
            tests::FRAMES_RELEASED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            narf_memory::free_frame(narf_memory::PhysFrame::new(frame));
        }
    }
}

/// Read one page of `ops` at `offset` into the fresh, zeroed, exclusively
/// owned `frame` — the private-copy and generic-fallback fault fill. The
/// frame belongs to the fill from here on: it is returned on success and
/// freed on a read error, on `Ok(None)` and when the fill outlives a killed
/// task.
#[track_caller]
pub(crate) fn fill_frame(
    ops: &Arc<dyn FileOps>,
    offset: u64,
    frame: narf_memory::PhysAddr,
    want: usize,
) -> Waited<narf_memory::PhysAddr> {
    let file = ops.clone();
    let guard = FilledFrame(Some(frame));
    let want = want.min(4096);
    let done = wait_io(Box::pin(async move {
        let mut filled = 0usize;
        while filled < want {
            // SAFETY: the guard owns `frame` exclusively until it is taken
            // or dropped, the frame is direct-mapped, and `want <= 4096`.
            // The slice is rebuilt per read so no raw pointer lives across
            // an await.
            let dst = unsafe {
                core::slice::from_raw_parts_mut(
                    frame.kernel_mut_ptr::<u8>().add(filled),
                    want - filled,
                )
            };
            match file.read(offset + filled as u64, dst).await {
                Ok(0) => break,
                Ok(n) => filled += n.min(want - filled),
                Err(error) => return Err(error),
            }
        }
        Ok(guard)
    }))?;
    Ok(done.map(|result| result.map(FilledFrame::take)))
}

#[cfg(feature = "kernel-test")]
#[path = "killable_wait_tests.rs"]
mod tests;
