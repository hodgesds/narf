//! Wait for the owner of a same-page demand fault (Linux folio wait).
//!
//! The region lock serializes claim retirement with waiter registration.
//! Publication, cancellation and VMA removal all retire through DemandClaims,
//! so each wakes the exact ticket's waiters. A replacement claim cannot keep
//! an old waiter asleep. No backing, allocation or AS lock is held while the
//! caller parks. Like Readiness, wakers must support IRQ-safe wake_by_ref.
//!
//! Waiters are entries linked into hashed wait queues, as Linux links an
//! on-stack `wait_page_queue` into `folio_wait_table`: each [`DemandPageWait`]
//! carries its own entry, so the table has buckets but no capacity, and
//! registering never allocates.

use super::{AddressSpace, AddressSpaceError};
use core::cell::UnsafeCell;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use narf_lib::intrusive::{IntrusiveList, Node};
use narf_lib::sync::IrqSafeSpinLock;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static WAIT_HOOK: AtomicUsize = AtomicUsize::new(0);

pub(super) fn new_id() -> u64 {
    NEXT_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("demand wait identity exhausted")
}

/// Drive the borrowed wait to completion, parking only from a valid task
/// context and returning an error on a fatal signal or inability to park.
pub type DemandPageWaitHook = for<'a> fn(DemandPageWait<'a>) -> Result<(), AddressSpaceError>;

pub fn install_demand_page_wait_hook(hook: DemandPageWaitHook) {
    WAIT_HOOK.store(hook as usize, Ordering::Release);
}

/// Linux `PAGE_WAIT_TABLE_SIZE`: wait-queue heads hashed by page. Only the
/// hash spread depends on it; each bucket links any number of waiters.
const WAIT_BUCKETS: usize = 256;

struct Waiter {
    claims: u64,
    page: u64,
    ticket: u64,
    /// Read and replaced only under the entry's bucket lock.
    waker: UnsafeCell<Option<Waker>>,
}

static BUCKETS: [IrqSafeSpinLock<IntrusiveList<Waiter>>; WAIT_BUCKETS] =
    [const { IrqSafeSpinLock::new(IntrusiveList::new()) }; WAIT_BUCKETS];

fn bucket_of(claims: u64, page: u64) -> usize {
    let key = claims.rotate_left(32) ^ (page >> 12);
    (key.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 56) as usize & (WAIT_BUCKETS - 1)
}

/// Called with the owning region lock held, after retiring the ticket.
/// Wake by reference only: the scheduler waker is atomic/IRQ-safe, and the
/// waiter keeps its entry linked until it resumes or abandons this wait.
pub(super) fn notify(claims: u64, page: u64, ticket: u64) {
    if ACTIVE.load(Ordering::Acquire) == 0 {
        return;
    }
    let queue = BUCKETS[bucket_of(claims, page)].lock();
    let mut cursor = queue.front();
    while let Some(entry) = cursor {
        // SAFETY: `entry` is linked into this queue, whose lock is held;
        // its owner unlinks it under the same lock before the storage goes.
        cursor = unsafe { queue.next(entry) };
        // SAFETY: as above.
        let waiter = unsafe { &entry.as_ref().value };
        if waiter.claims == claims && waiter.page == page && waiter.ticket == ticket {
            // SAFETY: the waker cell is accessed only under this bucket lock.
            if let Some(waker) = unsafe { &*waiter.waker.get() } {
                waker.wake_by_ref();
            }
        }
    }
}

/// Borrowed, allocation-free wait. Poll with an IRQ-safe scheduler waker;
/// do not poll or drop while holding an address-space lock. Once polled it
/// stays pinned: its wait-queue entry is linked until it is dropped.
pub struct DemandPageWait<'a> {
    space: &'a AddressSpace,
    page: u64,
    ticket: u64,
    /// Bucket the entry is linked into, while registered.
    registration: Option<usize>,
    entry: Node<Waiter>,
}

impl fmt::Debug for DemandPageWait<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DemandPageWait")
            .field("page", &self.page)
            .field("ticket", &self.ticket)
            .field("registered", &self.registration.is_some())
            .finish()
    }
}

impl<'a> DemandPageWait<'a> {
    pub(super) fn new(space: &'a AddressSpace, page: u64, ticket: u64) -> Self {
        Self {
            space,
            page,
            ticket,
            registration: None,
            entry: Node::new(Waiter {
                claims: 0,
                page,
                ticket,
                waker: UnsafeCell::new(None),
            }),
        }
    }

    /// Unlink the queue entry of a wait whose task was dropped while parked
    /// on it — the `detach` of a scheduler stack-wait record, since such a
    /// task never resumes to drop the wait itself.
    ///
    /// # Safety
    /// `wait` points at a live, pinned `DemandPageWait` whose owning task is
    /// no longer running and never will be.
    pub unsafe fn detach_raw(wait: *const ()) {
        // SAFETY: the caller's contract; `unregister` touches only the
        // entry and its bucket, never the borrowed address space.
        unsafe { (*wait.cast_mut().cast::<DemandPageWait<'static>>()).unregister() };
    }

    /// Unlink the entry, if linked. The waker is dropped after the bucket
    /// lock: its final reference can deallocate.
    fn unregister(&mut self) {
        let Some(bucket) = self.registration.take() else {
            return;
        };
        let old = {
            let queue = BUCKETS[bucket].lock();
            // SAFETY: `registration` says the entry is linked into exactly
            // this bucket's queue, whose lock is held.
            unsafe { queue.unlink(NonNull::from(&self.entry)) };
            self.entry.value.waker.get_mut().take()
        };
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
        drop(old);
    }
}

impl Drop for DemandPageWait<'_> {
    fn drop(&mut self) {
        self.unregister();
    }
}

impl Future for DemandPageWait<'_> {
    type Output = Result<(), AddressSpaceError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: nothing is moved out of `self`; the entry is linked only
        // while `self` is pinned, and `Drop` unlinks it.
        let this = unsafe { self.get_unchecked_mut() };
        // Clone before the region lock; even a foreign test waker cannot
        // allocate there. Replaced references also drop after that lock.
        let waker = cx.waker().clone();
        let regions = this.space.regions.lock();
        let claims = &regions.demand_pages;
        if claims.get(this.page) != Some(this.ticket) {
            drop(regions);
            this.unregister();
            return Poll::Ready(Ok(()));
        }
        if let Some(bucket) = this.registration {
            let old = {
                let _queue = BUCKETS[bucket].lock();
                // SAFETY: the waker cell is accessed only under this lock.
                unsafe { (*this.entry.value.waker.get()).replace(waker) }
            };
            drop(regions);
            drop(old);
            return Poll::Pending;
        }
        this.entry.value.claims = claims.wait_id;
        *this.entry.value.waker.get_mut() = Some(waker);
        let bucket = bucket_of(claims.wait_id, this.page);
        {
            let queue = BUCKETS[bucket].lock();
            // SAFETY: `self` is pinned (see above) and stays so until `Drop`
            // unlinks the entry under this bucket's lock.
            queue.push_back(unsafe { Pin::new_unchecked(&mut this.entry) });
        }
        ACTIVE.fetch_add(1, Ordering::AcqRel);
        this.registration = Some(bucket);
        // Claim check and registration are one region-lock transaction:
        // retirement either preceded the check or will see this waiter.
        Poll::Pending
    }
}

pub(super) fn wait(space: &AddressSpace, page: u64, ticket: u64) -> Result<(), AddressSpaceError> {
    let raw = WAIT_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        // Never report a still-unmapped instruction as resolved without a
        // waiter installed (early boot/test callers cannot sleep).
        return Err(AddressSpaceError::NotImplemented);
    }
    // SAFETY: only DemandPageWaitHook function pointers are installed above.
    let hook: DemandPageWaitHook = unsafe { core::mem::transmute(raw) };
    hook(DemandPageWait::new(space, page, ticket))
}

#[cfg(feature = "kernel-test")]
#[path = "demand_wait_tests.rs"]
mod tests;
