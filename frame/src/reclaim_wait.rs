//! Allocation-free backpressure for anonymous user demand faults.
//!
//! `memory` reports reserve pressure only after retiring its page claim and
//! dropping allocator/address-space locks. A stackful fault handler can then
//! install its existing executor waker here and switch out until kswapd makes
//! (or finishes attempting) progress. The table is deliberately fixed: a page
//! fault must never grow a collection or allocate while handling a trap.

use core::sync::atomic::{AtomicU32, Ordering};
use core::task::Waker;

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::reclaim::ReclaimTicket;
use narf_memory::{AddressSpace, AddressSpaceError, VirtAddr, FRAME_MAX_NUMA_NODES};

/// One slot for every user task the scheduler can admit. Consequently every
/// live stackful user fault can park; `Full` remains a fail-safe for broken
/// admission/accounting rather than an expected pressure behavior.
const MAX_RECLAIM_WAITERS: usize = narf_scheduler::MAX_USER_TASKS;

static RECLAIM_COMPLETED: [AtomicU32; FRAME_MAX_NUMA_NODES] =
    [const { AtomicU32::new(0) }; FRAME_MAX_NUMA_NODES];

/// Linux bounds consecutive reclaim failures at `MAX_RECLAIM_RETRIES` before
/// entering its OOM path. NARF's reclaim/OOM work runs in kswapd rather than
/// inline, so each iteration below waits for one exact completed cycle.
const MAX_RECLAIM_RETRIES: usize = 16;

struct Waiter {
    ticket: ReclaimTicket,
    waker: Waker,
}

static RECLAIM_WAITERS: [IrqSafeSpinLock<Option<Waiter>>; MAX_RECLAIM_WAITERS] =
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

/// Sequence arithmetic over request IDs 1..=2^30-1. At most 2^29 requests
/// may be outstanding on one node, vastly beyond the fixed waiter capacity.
fn sequence_reached(completed: u32, target: u32) -> bool {
    const MODULUS: u32 = 0x3fff_ffff;
    const HALF_RANGE: u32 = MODULUS / 2;
    if completed == 0 || target == 0 {
        return false;
    }
    let completed = completed - 1;
    let target = target - 1;
    let distance = completed.wrapping_add(MODULUS).wrapping_sub(target) % MODULUS;
    distance <= HALF_RANGE
}

/// Whether a live fault waiter owns any request coalesced into `ticket`'s
/// cycle. User-fault OOM authority expires when this becomes false, so a late
/// kswapd pass cannot kill an unrelated process after the original allocator
/// failure was handled or its task exited.
#[allow(dead_code)] // kswapd is compiled out of several test-only frame images.
pub(crate) fn has_waiter_for(ticket: ReclaimTicket) -> bool {
    RECLAIM_WAITERS.iter().any(|slot| {
        slot.lock().as_ref().is_some_and(|waiter| {
            waiter.ticket.node == ticket.node
                && sequence_reached(ticket.sequence, waiter.ticket.sequence)
        })
    })
}

fn ticket_completed(ticket: ReclaimTicket) -> bool {
    RECLAIM_COMPLETED.get(ticket.node).is_some_and(|completed| {
        sequence_reached(completed.load(Ordering::SeqCst), ticket.sequence)
    })
}

fn register_waiter(ticket: ReclaimTicket, waker: Waker) -> RegisterResult {
    let mut waiter = Some(Waiter { ticket, waker });
    for (slot_index, slot) in RECLAIM_WAITERS.iter().enumerate() {
        let mut entry = slot.lock();
        if entry.is_some() {
            continue;
        }
        *entry = waiter.take();
        drop(entry);

        let registration = Registration { slot: slot_index };
        // SeqCst makes the classic prepare-to-wait ordering explicit: either
        // this load follows completion of the exact request and observes it,
        // or completion follows this load and kswapd's subsequent scan sees
        // the installed slot. There is no scan-before-install + stale-load
        // gap, and an unrelated older cycle cannot satisfy this ticket.
        if ticket_completed(ticket) {
            drop(registration);
            return RegisterResult::RetryNow;
        }
        return RegisterResult::Armed(registration);
    }
    RegisterResult::Full
}

/// Publish completion of one bounded reclaim/OOM balancing cycle and wake
/// fault waiters whose requests were consumed by that cycle. Gross
/// page-eviction progress and unrelated background cycles are deliberately
/// not published: neither proves that this fault's request has completed.
/// Called only by the matching node's kswapd task context, never by a trap.
///
/// Slots are cloned but deliberately not removed here. Their owners remove
/// them after resume, so a newly registering waiter can never reuse a slot
/// while an older owner is still capable of clearing it (ABA).
#[cfg_attr(
    any(feature = "boot-smoke", feature = "idt-selftest"),
    allow(dead_code)
)]
pub(crate) fn notify_reclaim_progress(ticket: ReclaimTicket) {
    let Some(completed) = RECLAIM_COMPLETED.get(ticket.node) else {
        return;
    };
    completed.store(ticket.sequence, Ordering::SeqCst);
    for slot in &RECLAIM_WAITERS {
        let waker = slot.lock().as_ref().and_then(|waiter| {
            (waiter.ticket.node == ticket.node
                && sequence_reached(ticket.sequence, waiter.ticket.sequence))
            .then(|| waiter.waker.clone())
        });
        if let Some(waker) = waker {
            // Do not invoke scheduler wake code while holding a waiter lock.
            waker.wake();
        }
    }
}

/// Park the current stackful task until reclaim advances. `false` is the safe
/// fallback outside stackful execution or when the fixed waiter table is full.
fn park_until_reclaim(ticket: ReclaimTicket) -> bool {
    let Some(waker) = narf_scheduler::stackful::current_stackful_waker() else {
        return false;
    };
    match register_waiter(ticket, waker) {
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

fn retry_after_pressure(
    mut attempt: impl FnMut() -> Result<(), AddressSpaceError>,
    mut wait: impl FnMut(ReclaimTicket) -> bool,
    may_wait: bool,
) -> Result<(), AddressSpaceError> {
    let mut result = attempt();
    if !may_wait {
        return result;
    }

    for _ in 0..MAX_RECLAIM_RETRIES {
        let Err(AddressSpaceError::ReclaimPressure(ticket)) = result else {
            return result;
        };
        if !wait(ticket) {
            return result;
        }
        result = attempt();
    }
    result
}

/// Resolve one demand fault, parking only for anonymous reserve pressure and
/// retrying after completed reclaim cycles with Linux's bounded retry count.
/// No-stackful/full-table paths terminate immediately; none busy-yield.
pub(crate) fn demand_page(aspace: &AddressSpace, vaddr: VirtAddr) -> Result<(), AddressSpaceError> {
    retry_after_pressure(|| try_demand_page(aspace, vaddr), park_until_reclaim, true)
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
    retry_after_pressure(
        || try_demand_page(aspace, vaddr),
        |_| unreachable!("no-wait demand fault entered reclaim parking"),
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

    fn next_ticket(node: usize) -> ReclaimTicket {
        let current = RECLAIM_COMPLETED[node].load(Ordering::Relaxed);
        ReclaimTicket {
            node,
            sequence: if current == 0x3fff_ffff {
                1
            } else {
                current + 1
            },
        }
    }

    fn smoke_reclaim_wait_registration_is_lost_wake_free() -> TestResult {
        const NODE: usize = FRAME_MAX_NUMA_NODES - 1;
        WAKES.store(0, Ordering::Relaxed);
        let ticket = next_ticket(NODE);
        let registration = match register_waiter(ticket, counting_waker()) {
            RegisterResult::Armed(registration) => registration,
            _ => return TestResult::Fail("fixed reclaim waiter could not register"),
        };
        // An overlapping cycle on another node cannot satisfy this request.
        notify_reclaim_progress(next_ticket(NODE - 1));
        if WAKES.load(Ordering::Relaxed) != 0 {
            drop(registration);
            return TestResult::Fail("unrelated reclaim completion woke a waiter");
        }
        notify_reclaim_progress(ticket);
        if WAKES.load(Ordering::Relaxed) != 1 {
            drop(registration);
            return TestResult::Fail("reclaim progress did not wake an armed fault waiter");
        }
        drop(registration);

        // Completion before prepare-to-wait must force an immediate retry,
        // not leave a waker installed for a cycle that already ended.
        let completed = next_ticket(NODE);
        notify_reclaim_progress(completed);
        match register_waiter(completed, counting_waker()) {
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
        let ticket = ReclaimTicket {
            node: 0,
            sequence: 1,
        };
        let mut attempts = 0usize;
        let mut waits = 0usize;
        let result = retry_after_pressure(
            || {
                attempts += 1;
                Err(AddressSpaceError::ReclaimPressure(ticket))
            },
            |_| {
                waits += 1;
                true
            },
            true,
        );
        if result != Err(AddressSpaceError::ReclaimPressure(ticket))
            || attempts != MAX_RECLAIM_RETRIES + 1
            || waits != MAX_RECLAIM_RETRIES
        {
            return TestResult::Fail("zero-progress pressure exceeded the Linux retry bound");
        }

        let mut nonpressure_attempts = 0usize;
        let mut waited = false;
        let result = retry_after_pressure(
            || {
                nonpressure_attempts += 1;
                Err(AddressSpaceError::Unmapped)
            },
            |_| {
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
        let ticket = ReclaimTicket {
            node: 0,
            sequence: 1,
        };
        let mut attempts = 0usize;
        let mut waited = false;
        let result = retry_after_pressure(
            || {
                attempts += 1;
                Err(AddressSpaceError::ReclaimPressure(ticket))
            },
            |_| {
                waited = true;
                true
            },
            false,
        );
        if result == Err(AddressSpaceError::ReclaimPressure(ticket)) && attempts == 1 && !waited {
            TestResult::Pass
        } else {
            TestResult::Fail("guarded-uaccess pressure waited or retried")
        }
    }
    kernel_test_in!("frame", smoke_reclaim_no_wait_never_parks_or_retries);
}
