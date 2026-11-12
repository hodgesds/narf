//! The running transaction's door: operations join it side by side, a
//! commit closes it.
//!
//! Linux's `btrfs_start_transaction` joins the running transaction
//! (`num_writers += 1`) unless a commit has started closing it
//! (`TRANS_STATE_COMMIT_START`), in which case the new writer waits for
//! that commit; `btrfs_commit_transaction` stops new joins and waits for
//! `num_writers` to reach zero. [`TxnGate`] is that shape as an async
//! reader-writer lock with writer preference:
//!
//! - [`TxnGate::join`] — an operation's read-to-stage span. Any number at
//!   once; a new one waits while a commit is waiting or running, so a stream
//!   of operations cannot hold a commit off for ever.
//! - [`TxnGate::close`] — a commit, or anything else that must see no
//!   operation in flight. One at a time, in arrival order, once every
//!   joined operation has left.
//!
//! The lock order the filesystem keeps: an inode's or directory's lock is
//! always taken *before* joining, never while joined (Linux takes
//! `inode_lock` before `btrfs_start_transaction`). An operation joined here
//! therefore never waits for anything a commit waiting on it could hold.

use alloc::collections::VecDeque;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use narf_lib::sync::IrqSafeSpinLock;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// The calling task (0 when the kernel cannot say, as on the host harness,
/// whose operations all run in one thread).
fn task() -> u64 {
    narf_filesystem::killable::current_task()
}

#[derive(Default)]
struct State {
    /// Operations joined.
    joined: usize,
    /// Joins per task, so code deep in an operation can tell whether the
    /// task running it is joined ([`TxnGate::joined_by_current`]).
    owners: alloc::vec::Vec<(u64, usize)>,
    /// A close is held, and by which task.
    closed: bool,
    closer: u64,
    /// Closes waiting, in arrival order: they go before any new join.
    closers: VecDeque<u64>,
    /// Every parked future, to wake when the state changes.
    wakers: VecDeque<(u64, Waker)>,
}

impl State {
    fn park(&mut self, id: u64, waker: &Waker) {
        match self.wakers.iter_mut().find(|(w, _)| *w == id) {
            Some((_, w)) if w.will_wake(waker) => {}
            Some((_, w)) => *w = waker.clone(),
            None => self.wakers.push_back((id, waker.clone())),
        }
    }

    fn unpark(&mut self, id: u64) {
        self.wakers.retain(|(w, _)| *w != id);
    }

    fn own(&mut self, task: u64) {
        self.joined += 1;
        match self.owners.iter_mut().find(|(t, _)| *t == task) {
            Some((_, n)) => *n += 1,
            None => self.owners.push((task, 1)),
        }
    }

    fn disown(&mut self, task: u64) {
        self.joined = self.joined.saturating_sub(1);
        if let Some(at) = self.owners.iter().position(|(t, _)| *t == task) {
            self.owners[at].1 -= 1;
            if self.owners[at].1 == 0 {
                self.owners.swap_remove(at);
            }
        }
    }

    fn take_wakers(&mut self) -> VecDeque<(u64, Waker)> {
        core::mem::take(&mut self.wakers)
    }
}

/// See the module documentation.
pub(crate) struct TxnGate {
    state: IrqSafeSpinLock<State>,
}

impl core::fmt::Debug for TxnGate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state = self.state.lock();
        f.debug_struct("TxnGate")
            .field("joined", &state.joined)
            .field("closed", &state.closed)
            .field("closers", &state.closers.len())
            .finish()
    }
}

impl TxnGate {
    pub(crate) fn new() -> Self {
        Self {
            state: IrqSafeSpinLock::new(State::default()),
        }
    }

    /// Join the running transaction for one operation's read-to-stage span.
    pub(crate) fn join(&self) -> JoinFuture<'_> {
        JoinFuture {
            gate: self,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Close the transaction: wait for every joined operation to leave and
    /// keep new ones out until the guard drops.
    pub(crate) fn close(&self) -> CloseFuture<'_> {
        CloseFuture {
            gate: self,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            queued: false,
        }
    }

    /// Whether the calling task holds the close. Where the kernel cannot
    /// name the task (the host harness, one thread), whether any close is
    /// held: nothing joined runs while one is.
    pub(crate) fn closed_by_current(&self) -> bool {
        let state = self.state.lock();
        let me = task();
        state.closed && (me == 0 || state.closer == me)
    }

    /// Whether the calling task is joined. Where the kernel cannot name the
    /// task, whether any operation is.
    pub(crate) fn joined_by_current(&self) -> bool {
        let state = self.state.lock();
        match task() {
            0 => state.joined > 0,
            me => state.owners.iter().any(|(t, _)| *t == me),
        }
    }

    fn wake_all(&self) {
        let wakers = self.state.lock().take_wakers();
        for (_, waker) in wakers {
            waker.wake();
        }
    }

    /// Count one join back in at once, even past a waiting or held close:
    /// only for [`Upgrade`]'s cancellation, which leaves again right after.
    fn force_join(&self, task: u64) {
        self.state.lock().own(task);
    }

    /// Leave without a guard ([`Upgrade`]).
    fn leave(&self, task: u64) {
        {
            let mut state = self.state.lock();
            state.disown(task);
            if state.joined != 0 {
                return;
            }
        }
        self.wake_all();
    }
}

/// [`TxnGate::join`].
pub(crate) struct JoinFuture<'a> {
    gate: &'a TxnGate,
    id: u64,
}

impl<'a> Future for JoinFuture<'a> {
    type Output = Joined<'a>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Joined<'a>> {
        let this = self.get_mut();
        let mut state = this.gate.state.lock();
        if !state.closed && state.closers.is_empty() {
            let me = task();
            state.own(me);
            state.unpark(this.id);
            return Poll::Ready(Joined {
                gate: this.gate,
                task: me,
            });
        }
        state.park(this.id, cx.waker());
        Poll::Pending
    }
}

impl Drop for JoinFuture<'_> {
    fn drop(&mut self) {
        self.gate.state.lock().unpark(self.id);
    }
}

/// One operation joined to the running transaction.
pub(crate) struct Joined<'a> {
    gate: &'a TxnGate,
    task: u64,
}

impl Drop for Joined<'_> {
    fn drop(&mut self) {
        self.gate.leave(self.task);
    }
}

/// [`TxnGate::close`].
pub(crate) struct CloseFuture<'a> {
    gate: &'a TxnGate,
    id: u64,
    queued: bool,
}

impl<'a> Future for CloseFuture<'a> {
    type Output = Closed<'a>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Closed<'a>> {
        let this = self.get_mut();
        let mut state = this.gate.state.lock();
        if !this.queued {
            state.closers.push_back(this.id);
            this.queued = true;
        }
        if !state.closed && state.joined == 0 && state.closers.front() == Some(&this.id) {
            state.closers.pop_front();
            state.closed = true;
            state.closer = task();
            state.unpark(this.id);
            this.queued = false;
            return Poll::Ready(Closed { gate: this.gate });
        }
        state.park(this.id, cx.waker());
        Poll::Pending
    }
}

impl Drop for CloseFuture<'_> {
    fn drop(&mut self) {
        let front = {
            let mut state = self.gate.state.lock();
            state.unpark(self.id);
            if !self.queued {
                return;
            }
            let front = state.closers.front() == Some(&self.id);
            state.closers.retain(|&c| c != self.id);
            front
        };
        // The next closer, or the joins held back behind this one, may go.
        if front {
            self.gate.wake_all();
        }
    }
}

/// The transaction closed: no operation is joined, none can join.
pub(crate) struct Closed<'a> {
    gate: &'a TxnGate,
}

impl Drop for Closed<'_> {
    fn drop(&mut self) {
        {
            let mut state = self.gate.state.lock();
            state.closed = false;
            state.closer = 0;
        }
        self.gate.wake_all();
    }
}

/// A joined operation stepping out to close the transaction itself (a
/// commit it needs, a chunk it must allocate) and back in: Linux's
/// `btrfs_commit_transaction` called with a handle, which waits for every
/// other writer and lets none join meanwhile. The caller's own join is
/// handed in, not held, so the count stays right if the caller's future is
/// dropped half-way: `Drop` counts the join back before the caller's guard
/// counts it out.
pub(crate) struct Upgrade<'a> {
    gate: &'a TxnGate,
    task: u64,
    out: bool,
}

impl<'a> Upgrade<'a> {
    /// Step out of the join the caller holds.
    pub(crate) fn step_out(gate: &'a TxnGate) -> Self {
        let task = task();
        gate.leave(task);
        Upgrade {
            gate,
            task,
            out: true,
        }
    }

    /// Join again, waiting behind any close.
    pub(crate) async fn step_in(mut self) {
        core::mem::forget(self.gate.join().await);
        self.out = false;
    }
}

impl Drop for Upgrade<'_> {
    fn drop(&mut self) {
        if self.out {
            self.gate.force_join(self.task);
        }
    }
}
