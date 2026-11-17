//! Wait for the owner of a same-page demand fault (Linux folio wait).
//!
//! The region lock serializes claim retirement with waiter registration.
//! Publication, cancellation and VMA removal all retire through DemandClaims,
//! so each wakes the exact ticket's waiters. A replacement claim cannot keep
//! an old waiter asleep. No backing, allocation or AS lock is held while the
//! caller parks. Like Readiness, wakers must support IRQ-safe wake_by_ref.

use super::{AddressSpace, AddressSpaceError};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use narf_lib::sync::IrqSafeSpinLock;

/// At least the scheduler's user-task admission limit (asserted by its caller).
pub const MAX_DEMAND_WAITERS: usize = 1024;
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

struct Waiter {
    claims: u64,
    page: u64,
    ticket: u64,
    waker: Waker,
}

struct Slot {
    // Skip unrelated slots without taking their locks during retirement.
    claims: AtomicU64,
    waiter: IrqSafeSpinLock<Option<Waiter>>,
}

static WAITERS: [Slot; MAX_DEMAND_WAITERS] = [const {
    Slot {
        claims: AtomicU64::new(0),
        waiter: IrqSafeSpinLock::new(None),
    }
}; MAX_DEMAND_WAITERS];

#[derive(Debug)]
struct Registration(usize);

impl Drop for Registration {
    fn drop(&mut self) {
        let slot = &WAITERS[self.0];
        let old = {
            let mut entry = slot.waiter.lock();
            slot.claims.store(0, Ordering::Release);
            entry.take()
        };
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
        // A waker's final reference can deallocate; drop outside all locks.
        drop(old);
    }
}

/// Called with the owning region lock held, after retiring the ticket.
/// Wake by reference only: the scheduler waker is atomic/IRQ-safe, and the
/// waiter keeps its reference until it resumes or abandons this wait.
pub(super) fn notify(claims: u64, page: u64, ticket: u64) {
    if ACTIVE.load(Ordering::Acquire) == 0 {
        return;
    }
    for slot in &WAITERS {
        if slot.claims.load(Ordering::Acquire) != claims {
            continue;
        }
        let entry = slot.waiter.lock();
        if let Some(waiter) = entry.as_ref() {
            if waiter.claims == claims && waiter.page == page && waiter.ticket == ticket {
                waiter.waker.wake_by_ref();
            }
        }
    }
}

/// Borrowed, allocation-free wait. Poll with an IRQ-safe scheduler waker;
/// do not poll or drop while holding an address-space lock.
#[derive(Debug)]
pub struct DemandPageWait<'a> {
    space: &'a AddressSpace,
    page: u64,
    ticket: u64,
    registration: Option<Registration>,
}

impl<'a> DemandPageWait<'a> {
    pub(super) fn new(space: &'a AddressSpace, page: u64, ticket: u64) -> Self {
        Self {
            space,
            page,
            ticket,
            registration: None,
        }
    }
}

impl Future for DemandPageWait<'_> {
    type Output = Result<(), AddressSpaceError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Clone before the region lock; even a foreign test waker cannot
        // allocate there. Replaced references also drop after that lock.
        let waker = cx.waker().clone();
        let regions = this.space.regions.lock();
        let claims = &regions.demand_pages;
        if claims.get(this.page) != Some(this.ticket) {
            drop(regions);
            drop(this.registration.take());
            return Poll::Ready(Ok(()));
        }
        if let Some(registration) = &this.registration {
            let old = {
                let mut entry = WAITERS[registration.0].waiter.lock();
                core::mem::replace(
                    &mut entry.as_mut().expect("live demand waiter").waker,
                    waker,
                )
            };
            drop(regions);
            drop(old);
            return Poll::Pending;
        }
        for (index, slot) in WAITERS.iter().enumerate() {
            let mut entry = slot.waiter.lock();
            if entry.is_some() {
                continue;
            }
            *entry = Some(Waiter {
                claims: claims.wait_id,
                page: this.page,
                ticket: this.ticket,
                waker,
            });
            ACTIVE.fetch_add(1, Ordering::AcqRel);
            slot.claims.store(claims.wait_id, Ordering::Release);
            this.registration = Some(Registration(index));
            // Claim check and registration are one region-lock transaction:
            // retirement either preceded the check or will see this waiter.
            return Poll::Pending;
        }
        Poll::Ready(Err(AddressSpaceError::AllocationFailed))
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
