//! Allocation-free backpressure for anonymous user demand faults.
//!
//! `memory` reports reserve pressure only after retiring its page claim and
//! dropping allocator/address-space locks. A stackful fault handler can then
//! install its existing executor waker here and switch out until kswapd makes
//! (or finishes attempting) progress. The table is deliberately fixed: a page
//! fault must never grow a collection or allocate while handling a trap.

use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Waker;

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, AddressSpaceError, VirtAddr};

/// One slot for every user task the scheduler can admit. Consequently every
/// live stackful user fault can park; `Full` remains a fail-safe for broken
/// admission/accounting rather than an expected pressure behavior.
const MAX_RECLAIM_WAITERS: usize = narf_scheduler::MAX_USER_TASKS;

static RECLAIM_GENERATION: AtomicU64 = AtomicU64::new(0);
static RECLAIM_WAITERS: [IrqSafeSpinLock<Option<Waker>>; MAX_RECLAIM_WAITERS] =
    [const { IrqSafeSpinLock::new(None) }; MAX_RECLAIM_WAITERS];

struct Registration {
    slot: usize,
}

impl Drop for Registration {
    fn drop(&mut self) {
        *RECLAIM_WAITERS[self.slot].lock() = None;
    }
}

enum RegisterResult {
    /// A reclaim completion raced registration; retry without sleeping.
    RetryNow,
    /// The waiter is durably visible to every later completion.
    Armed(Registration),
    /// Fixed capacity is full; fail without allocating or busy-waiting.
    Full,
}

fn register_waiter(observed: u64, waker: Waker) -> RegisterResult {
    let mut waker = Some(waker);
    for (slot_index, slot) in RECLAIM_WAITERS.iter().enumerate() {
        let mut entry = slot.lock();
        if entry.is_some() {
            continue;
        }
        *entry = waker.take();
        drop(entry);

        let registration = Registration { slot: slot_index };
        // SeqCst makes the classic prepare-to-wait ordering explicit: either
        // this load follows kswapd's generation bump and observes it, or the
        // bump follows this load and kswapd's subsequent scan observes the
        // installed slot. There is no scan-before-install + stale-load gap.
        if RECLAIM_GENERATION.load(Ordering::SeqCst) != observed {
            drop(registration);
            return RegisterResult::RetryNow;
        }
        return RegisterResult::Armed(registration);
    }
    RegisterResult::Full
}

/// Current completion generation, sampled before an allocation attempt.
#[inline]
fn generation() -> u64 {
    RECLAIM_GENERATION.load(Ordering::SeqCst)
}

/// Publish reclaim completion/progress and wake every currently registered
/// fault waiter. Called only by kswapd task context, never by a trap.
///
/// Slots are cloned but deliberately not removed here. Their owners remove
/// them after resume, so a newly registering waiter can never reuse a slot
/// while an older owner is still capable of clearing it (ABA).
#[cfg_attr(
    any(feature = "boot-smoke", feature = "idt-selftest"),
    allow(dead_code)
)]
pub(crate) fn notify_reclaim_progress() {
    RECLAIM_GENERATION.fetch_add(1, Ordering::SeqCst);
    for slot in &RECLAIM_WAITERS {
        let waker = slot.lock().clone();
        if let Some(waker) = waker {
            // Do not invoke scheduler wake code while holding a waiter lock.
            waker.wake();
        }
    }
}

/// Park the current stackful task until reclaim advances. `false` is the safe
/// fallback outside stackful execution or when the fixed waiter table is full.
fn park_until_reclaim(observed: u64) -> bool {
    let Some(waker) = narf_scheduler::stackful::current_stackful_waker() else {
        return false;
    };
    match register_waiter(observed, waker) {
        RegisterResult::RetryNow => true,
        RegisterResult::Full => false,
        RegisterResult::Armed(registration) => {
            // The allocation path already cancelled its demand ticket and
            // returned through every address-space/allocator lock. The active
            // mempolicy slot is also cleared by `try_demand_page` below.
            // SAFETY: current_stackful_waker proved a live stackful task on
            // this CPU; yielding from its kernel trap continuation is the same
            // scheduler boundary used by blocking syscalls.
            unsafe { narf_scheduler::stackful::yield_current_stackful() };
            drop(registration);
            true
        }
    }
}

fn try_demand_page(aspace: &AddressSpace, vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
    narf_userspace::publish_mempolicy_for_fault(vaddr.as_u64());
    // SAFETY: callers are the architecture page-fault/data-abort paths with
    // the faulting task's address-space root active and the kernel RAM mapping
    // live. This helper changes only retry/parking around the existing call.
    let result = unsafe { aspace.demand_alloc_page(vaddr) };
    narf_userspace::clear_mempolicy_for_fault();
    result
}

fn retry_once_after_pressure(
    mut attempt: impl FnMut() -> Result<(), AddressSpaceError>,
    mut wait: impl FnMut() -> bool,
    may_wait: bool,
) -> Result<(), AddressSpaceError> {
    let first = attempt();
    if first != Err(AddressSpaceError::ReclaimPressure) || !may_wait || !wait() {
        return first;
    }
    attempt()
}

/// Resolve one demand fault, parking only for anonymous reserve pressure and
/// retrying at most once. No-stackful/full-table/zero-progress paths all
/// terminate after the original or second allocation result; none busy-yield.
pub(crate) fn demand_page(aspace: &AddressSpace, vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
    let observed = generation();
    retry_once_after_pressure(
        || try_demand_page(aspace, vaddr),
        || park_until_reclaim(observed),
        true,
    )
}

/// Resolve one demand fault without entering the reclaim wait path.
///
/// Guarded kernel uaccess owns architecture-local probe state (and x86 SMAP's
/// AC window), so it cannot context-switch on reserve pressure. A successful
/// allocation still heals the fault; `ReclaimPressure` is returned unchanged
/// so the trap can consume the probe and surface `EFAULT` to the syscall.
pub(crate) fn demand_page_no_wait(
    aspace: &AddressSpace,
    vaddr: VirtAddr,
) -> Result<(), AddressSpaceError> {
    retry_once_after_pressure(
        || try_demand_page(aspace, vaddr),
        || unreachable!("no-wait demand fault entered reclaim parking"),
        false,
    )
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{RawWaker, RawWakerVTable};
    use narf_kernel_test::{kernel_test_in, TestResult};

    static WAKES: AtomicUsize = AtomicUsize::new(0);

    unsafe fn clone_raw(data: *const ()) -> RawWaker {
        RawWaker::new(data, &TEST_VTABLE)
    }
    unsafe fn wake_raw(_data: *const ()) {
        WAKES.fetch_add(1, Ordering::Relaxed);
    }
    unsafe fn wake_by_ref_raw(_data: *const ()) {
        WAKES.fetch_add(1, Ordering::Relaxed);
    }
    unsafe fn drop_raw(_data: *const ()) {}

    static TEST_VTABLE: RawWakerVTable =
        RawWakerVTable::new(clone_raw, wake_raw, wake_by_ref_raw, drop_raw);

    fn counting_waker() -> Waker {
        // SAFETY: TEST_VTABLE never dereferences the inert data pointer and
        // owns no resource requiring destruction.
        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &TEST_VTABLE)) }
    }

    fn smoke_reclaim_wait_registration_is_lost_wake_free() -> TestResult {
        WAKES.store(0, Ordering::Relaxed);
        let observed = generation();
        let registration = match register_waiter(observed, counting_waker()) {
            RegisterResult::Armed(registration) => registration,
            _ => return TestResult::Fail("fixed reclaim waiter could not register"),
        };
        notify_reclaim_progress();
        if WAKES.load(Ordering::Relaxed) != 1 {
            drop(registration);
            return TestResult::Fail("reclaim progress did not wake an armed fault waiter");
        }
        drop(registration);

        // Completion before prepare-to-wait must force an immediate retry,
        // not leave a waker installed for a cycle that already ended.
        let stale = generation();
        notify_reclaim_progress();
        match register_waiter(stale, counting_waker()) {
            RegisterResult::RetryNow => TestResult::Pass,
            RegisterResult::Armed(registration) => {
                drop(registration);
                TestResult::Fail("stale generation armed a sleeping waiter")
            }
            RegisterResult::Full => TestResult::Fail("waiter table unexpectedly full"),
        }
    }
    kernel_test_in!("frame", smoke_reclaim_wait_registration_is_lost_wake_free);

    fn smoke_reclaim_wait_retry_is_bounded() -> TestResult {
        let mut attempts = 0usize;
        let result = retry_once_after_pressure(
            || {
                attempts += 1;
                Err(AddressSpaceError::ReclaimPressure)
            },
            || true,
            true,
        );
        if result != Err(AddressSpaceError::ReclaimPressure) || attempts != 2 {
            return TestResult::Fail("zero-progress pressure did not stop after one retry");
        }

        let mut nonpressure_attempts = 0usize;
        let mut waited = false;
        let result = retry_once_after_pressure(
            || {
                nonpressure_attempts += 1;
                Err(AddressSpaceError::Unmapped)
            },
            || {
                waited = true;
                true
            },
            true,
        );
        if result != Err(AddressSpaceError::Unmapped) || nonpressure_attempts != 1 || waited {
            return TestResult::Fail("a genuine unmapped fault entered reclaim backpressure");
        }
        TestResult::Pass
    }
    kernel_test_in!("frame", smoke_reclaim_wait_retry_is_bounded);

    fn smoke_reclaim_no_wait_never_parks_or_retries() -> TestResult {
        let mut attempts = 0usize;
        let mut waited = false;
        let result = retry_once_after_pressure(
            || {
                attempts += 1;
                Err(AddressSpaceError::ReclaimPressure)
            },
            || {
                waited = true;
                true
            },
            false,
        );
        if result == Err(AddressSpaceError::ReclaimPressure) && attempts == 1 && !waited {
            TestResult::Pass
        } else {
            TestResult::Fail("guarded-uaccess pressure waited or retried")
        }
    }
    kernel_test_in!("frame", smoke_reclaim_no_wait_never_parks_or_retries);
}
