//! `Subscriber<T>` — per-consumer cursor handle. Async `next()`
//! parks until the producer publishes; `try_next()` is the
//! non-blocking equivalent. On overflow the next call returns
//! `Err(RecvError::Gapped { skipped })` and the cursor is fast-
//! forwarded so subsequent reads succeed.

use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use narf_capabilities::{Cap, Invoke};

use crate::cap::Subscriber as SubscriberCap;
use crate::engine::{CursorEntry, Ring, SeqNum, TryRecvOk};
use crate::payload::{Arena, ArenaHandle, Event};

/// Per-subscriber cursored read handle. `Send`-able but `!Sync` —
/// the cursor is a single-drainer invariant.
pub struct Subscriber<T: Event> {
    cap: Cap<SubscriberCap, Invoke>,
    ring: Arc<Ring<T>>,
    arena: Option<Arc<Arena>>,
    cursor: Arc<CursorEntry>,
}

// Subscriber is single-task drain. Marker `!Sync` enforced via the
// raw-pointer in PhantomData would require a `_no_sync` field; we
// instead document the requirement and the consumer side honours it.
impl<T: Event> core::fmt::Debug for Subscriber<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Subscriber").finish_non_exhaustive()
    }
}

/// Errors from `next` / `try_next`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecvError {
    /// One or more events were overwritten before this subscriber
    /// drained them; cursor has been fast-forwarded.
    Gapped { skipped: u64 },
    /// Publisher cap was revoked.
    Closed,
    /// This subscriber's cap was revoked.
    CapRevoked,
}

impl<T: Event> Subscriber<T> {
    pub(crate) fn new(
        cap: Cap<SubscriberCap, Invoke>,
        ring: Arc<Ring<T>>,
        arena: Option<Arc<Arena>>,
        cursor: Arc<CursorEntry>,
    ) -> Self {
        Self {
            cap,
            ring,
            arena,
            cursor,
        }
    }

    /// Non-blocking poll. `Ok(None)` = ring empty (try again later
    /// or `.await` the future).
    pub fn try_next(&mut self) -> Result<Option<(SeqNum, T)>, RecvError> {
        if self.cap.check_live().is_err() {
            self.ring.detach_cursor(&self.cursor);
            return Err(RecvError::CapRevoked);
        }
        match self.ring.try_recv(&self.cursor) {
            TryRecvOk::Empty => Ok(None),
            TryRecvOk::Got { seq, val } => Ok(Some((seq, val))),
            TryRecvOk::Gapped { skipped } => Err(RecvError::Gapped { skipped }),
            TryRecvOk::Closed => Err(RecvError::Closed),
            TryRecvOk::Revoked => Err(RecvError::CapRevoked),
        }
    }

    /// Async receive. Parks via the cursor's waker slot; the
    /// publisher wakes on every `publish`.
    pub fn next(&mut self) -> SubscriberRecv<'_, T> {
        SubscriberRecv { sub: self }
    }

    /// Copy `len` bytes referenced by `handle` from the topic's arena
    /// into `out`. Returns the number of bytes copied. `None` =
    /// arena slot has been recycled; the handle is stale.
    pub fn read_arena(&self, handle: ArenaHandle, out: &mut [u8]) -> Option<usize> {
        let arena = self.arena.as_ref()?;
        arena.read(handle, out)
    }

    /// Test helper: expose the cap slot so smokes can simulate
    /// revocation via `narf_capabilities::object_table::bump_epoch`.
    #[doc(hidden)]
    pub fn cap_slot_for_test(&self) -> narf_capabilities::CapSlot {
        self.cap.slot()
    }
}

impl<T: Event> Drop for Subscriber<T> {
    fn drop(&mut self) {
        self.ring.detach_cursor(&self.cursor);
    }
}

/// Future returned by `Subscriber::next`.
pub struct SubscriberRecv<'s, T: Event> {
    sub: &'s mut Subscriber<T>,
}

impl<'s, T: Event> core::fmt::Debug for SubscriberRecv<'s, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SubscriberRecv").finish_non_exhaustive()
    }
}

impl<'s, T: Event> Future for SubscriberRecv<'s, T> {
    type Output = Result<(SeqNum, T), RecvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.sub.cap.check_live().is_err() {
            this.sub.ring.detach_cursor(&this.sub.cursor);
            return Poll::Ready(Err(RecvError::CapRevoked));
        }
        match this.sub.ring.try_recv(&this.sub.cursor) {
            TryRecvOk::Got { seq, val } => Poll::Ready(Ok((seq, val))),
            TryRecvOk::Gapped { skipped } => Poll::Ready(Err(RecvError::Gapped { skipped })),
            TryRecvOk::Closed => Poll::Ready(Err(RecvError::Closed)),
            TryRecvOk::Revoked => Poll::Ready(Err(RecvError::CapRevoked)),
            TryRecvOk::Empty => {
                this.sub.ring.park(&this.sub.cursor, cx.waker());
                // Re-check after parking — producer may have published
                // in the window between try_recv and park.
                match this.sub.ring.try_recv(&this.sub.cursor) {
                    TryRecvOk::Got { seq, val } => Poll::Ready(Ok((seq, val))),
                    TryRecvOk::Gapped { skipped } => {
                        Poll::Ready(Err(RecvError::Gapped { skipped }))
                    }
                    TryRecvOk::Closed => Poll::Ready(Err(RecvError::Closed)),
                    TryRecvOk::Revoked => Poll::Ready(Err(RecvError::CapRevoked)),
                    TryRecvOk::Empty => Poll::Pending,
                }
            }
        }
    }
}
