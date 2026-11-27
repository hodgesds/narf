//! Allocation-free backpressure for anonymous user demand faults.
//!
//! `memory` reports reserve pressure only after retiring its page claim and
//! dropping allocator/address-space locks. A stackful fault handler can then
//! install its existing executor waker here and switch out until kswapd makes
//! (or finishes attempting) progress. A page fault must never grow a
//! collection or allocate while handling a trap, so each waiting fault links
//! an entry from its own kernel stack into its node's wait queue, as Linux's
//! `reclaim_throttle` sleeps on `pgdat->reclaim_wait` with an on-stack entry:
//! the queue has no capacity, and every fault the scheduler admitted can park.

use core::cell::{Cell, UnsafeCell};
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::Waker;

use narf_lib::intrusive::{IntrusiveList, Node};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::reclaim::ReclaimTicket;
use narf_memory::{AddressSpace, AddressSpaceError, VirtAddr, FRAME_MAX_NUMA_NODES};

static RECLAIM_COMPLETED: [AtomicU32; FRAME_MAX_NUMA_NODES] =
    [const { AtomicU32::new(0) }; FRAME_MAX_NUMA_NODES];

/// Linux bounds consecutive reclaim failures at `MAX_RECLAIM_RETRIES` before
/// entering its OOM path. NARF's reclaim/OOM work runs in kswapd rather than
/// inline, so each iteration below waits for one exact completed cycle.
const MAX_RECLAIM_RETRIES: usize = 16;

/// Wakers a completion takes out of a queue per pass. They are woken after
/// the queue lock drops; the pass repeats until no matching entry is left
/// unwoken, so this bounds lock hold time, not the number of waiters.
const WAKE_BATCH: usize = 16;

struct Waiter {
    ticket: ReclaimTicket,
    /// Read only under the node queue lock.
    waker: UnsafeCell<Option<Waker>>,
    /// The completed sequence whose pass last took this entry's waker, so a
    /// completion that wakes in batches visits each entry once.
    woken_for: Cell<u32>,
}

/// Per-node queues of parked faults.
static RECLAIM_WAITERS: [IrqSafeSpinLock<IntrusiveList<Waiter>>; FRAME_MAX_NUMA_NODES] =
    [const { IrqSafeSpinLock::new(IntrusiveList::new()) }; FRAME_MAX_NUMA_NODES];

/// One fault's wait-queue entry, pinned on the faulting task's own kernel
/// stack (its frame survives the switch-out).
struct ReclaimWaiter {
    entry: Node<Waiter>,
    /// The node queue the entry is linked into, while linked.
    linked: Cell<Option<usize>>,
}

impl ReclaimWaiter {
    fn new(ticket: ReclaimTicket, waker: Waker) -> Self {
        Self {
            entry: Node::new(Waiter {
                ticket,
                waker: UnsafeCell::new(Some(waker)),
                woken_for: Cell::new(0),
            }),
            linked: Cell::new(None),
        }
    }

    /// Unlink the entry, if linked; its waker drops after the queue lock.
    fn unlink(&self) {
        let Some(node) = self.linked.take() else {
            return;
        };
        let waker = {
            let queue = RECLAIM_WAITERS[node].lock();
            // SAFETY: `linked` says the entry is in exactly this queue, whose
            // lock is held.
            unsafe { queue.unlink(NonNull::from(&self.entry)) };
            // SAFETY: unlinked under the lock; nothing else reaches the cell.
            unsafe { (*self.entry.value.waker.get()).take() }
        };
        drop(waker);
    }

    /// `StackWait` detach for a task dropped while parked here.
    ///
    /// # Safety
    /// `waiter` points at a live, pinned `ReclaimWaiter` whose task no longer
    /// runs.
    unsafe fn detach_raw(waiter: *const ()) {
        // SAFETY: the caller's contract.
        unsafe { (*waiter.cast::<ReclaimWaiter>()).unlink() };
    }
}

/// Owns a linked entry; dropping it unlinks the entry.
struct Registration<'a> {
    waiter: Pin<&'a ReclaimWaiter>,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        self.waiter.unlink();
    }
}

enum RegisterResult<'a> {
    /// A reclaim completion raced registration; retry without sleeping.
    RetryNow,
    /// The waiter is durably visible to every later completion.
    Armed(Registration<'a>),
}

/// Sequence arithmetic over request IDs 1..=2^30-1. At most 2^29 requests
/// may be outstanding on one node, vastly beyond any number of waiters.
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
    let Some(queue) = RECLAIM_WAITERS.get(ticket.node) else {
        return false;
    };
    let queue = queue.lock();
    let mut cursor = queue.front();
    while let Some(entry) = cursor {
        // SAFETY: linked into this queue, whose lock is held; owners unlink
        // under the same lock before their stack frame goes.
        let waiter = unsafe { &entry.as_ref().value };
        if sequence_reached(ticket.sequence, waiter.ticket.sequence) {
            return true;
        }
        // SAFETY: as above.
        cursor = unsafe { queue.next(entry) };
    }
    false
}

fn ticket_completed(ticket: ReclaimTicket) -> bool {
    RECLAIM_COMPLETED.get(ticket.node).is_some_and(|completed| {
        sequence_reached(completed.load(Ordering::SeqCst), ticket.sequence)
    })
}

/// Link `waiter` into the queue of its ticket's node.
fn register_waiter(mut waiter: Pin<&mut ReclaimWaiter>) -> RegisterResult<'_> {
    let ticket = waiter.entry.value.ticket;
    let node = ticket.node;
    {
        let queue = RECLAIM_WAITERS[node].lock();
        // SAFETY: a structural pin projection — `entry` is never moved out —
        // and `Registration` (or the stack-wait detach) unlinks it under this
        // lock before its storage goes.
        queue.push_back(unsafe { waiter.as_mut().map_unchecked_mut(|w| &mut w.entry) });
        waiter.linked.set(Some(node));
    }
    let registration = Registration {
        waiter: waiter.into_ref(),
    };
    // SeqCst makes the classic prepare-to-wait ordering explicit: either
    // this load follows completion of the exact request and observes it,
    // or completion follows this load and kswapd's subsequent scan sees
    // the linked entry. There is no scan-before-link + stale-load gap, and
    // an unrelated older cycle cannot satisfy this ticket.
    if ticket_completed(ticket) {
        drop(registration);
        return RegisterResult::RetryNow;
    }
    RegisterResult::Armed(registration)
}

/// Publish completion of one bounded reclaim/OOM balancing cycle and wake
/// fault waiters whose requests were consumed by that cycle. Gross
/// page-eviction progress and unrelated background cycles are deliberately
/// not published: neither proves that this fault's request has completed.
/// Called only by the matching node's kswapd task context, never by a trap.
///
/// Entries are left linked here. Their owners unlink them after resume, so
/// an entry is never reused while an older owner could still unlink it.
#[cfg_attr(
    any(feature = "boot-smoke", feature = "idt-selftest"),
    allow(dead_code)
)]
pub(crate) fn notify_reclaim_progress(ticket: ReclaimTicket) {
    let (Some(completed), Some(queue)) = (
        RECLAIM_COMPLETED.get(ticket.node),
        RECLAIM_WAITERS.get(ticket.node),
    ) else {
        return;
    };
    completed.store(ticket.sequence, Ordering::SeqCst);
    loop {
        let mut batch: [Option<Waker>; WAKE_BATCH] = [const { None }; WAKE_BATCH];
        let mut taken = 0;
        let mut more = false;
        {
            let queue = queue.lock();
            let mut cursor = queue.front();
            while let Some(entry) = cursor {
                // SAFETY: linked into this queue, whose lock is held.
                let waiter = unsafe { &entry.as_ref().value };
                // SAFETY: as above.
                cursor = unsafe { queue.next(entry) };
                if waiter.woken_for.get() == ticket.sequence
                    || !sequence_reached(ticket.sequence, waiter.ticket.sequence)
                {
                    continue;
                }
                if taken == WAKE_BATCH {
                    more = true;
                    break;
                }
                waiter.woken_for.set(ticket.sequence);
                // SAFETY: the waker cell is read only under this lock.
                batch[taken] = unsafe { (*waiter.waker.get()).clone() };
                taken += 1;
            }
        }
        // Do not invoke scheduler wake code while holding a waiter lock.
        for waker in batch.iter_mut().take(taken).filter_map(Option::take) {
            waker.wake();
        }
        if !more {
            return;
        }
    }
}

/// Park the current stackful task until reclaim advances. `false` is the safe
/// fallback outside stackful execution.
fn park_until_reclaim(ticket: ReclaimTicket) -> bool {
    let Some(waker) = narf_scheduler::stackful::current_stackful_waker() else {
        return false;
    };
    if ticket.node >= FRAME_MAX_NUMA_NODES {
        return false;
    }
    let mut waiter = core::pin::pin!(ReclaimWaiter::new(ticket, waker));
    let registered = register_waiter(waiter.as_mut());
    match registered {
        RegisterResult::RetryNow => true,
        RegisterResult::Armed(registration) => {
            // SAFETY: `detach_raw` unlinks exactly this pinned entry and does
            // not block; the scheduler calls it only once this task has
            // stopped for good, while its stack (and so `waiter`) is mapped.
            let stack_wait = core::pin::pin!(unsafe {
                narf_scheduler::stackful::StackWait::new(
                    core::ptr::from_ref(registration.waiter.get_ref()).cast(),
                    ReclaimWaiter::detach_raw,
                )
            });
            let record = narf_scheduler::stackful::record_stack_wait(stack_wait.as_ref());
            // The allocation path already cancelled its demand ticket and
            // returned through every address-space/allocator lock. The active
            // mempolicy slot is also cleared by `try_demand_page` below.
            // SAFETY: current_stackful_waker proved a live stackful task on
            // this CPU; yielding from its kernel trap continuation is the same
            // scheduler boundary used by blocking syscalls.
            unsafe { narf_scheduler::stackful::yield_current_stackful() };
            drop(record);
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
    mut fatal_signal_pending: impl FnMut() -> bool,
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
        // A fatal signal (notably SIGKILL from stress-ng's timeout/OOM parent)
        // must break a task out of reclaim backpressure. The signal path kicks
        // the scheduler slot, so `yield_current_stackful` below resumes, but a
        // standard signal is coalesced and therefore provides only that ONE
        // wake. Retrying and parking on a fresh ticket here strands the task
        // until kswapd happens to complete every remaining retry.
        if fatal_signal_pending() || !wait(ticket) || fatal_signal_pending() {
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
    retry_after_pressure(
        || try_demand_page(aspace, vaddr),
        park_until_reclaim,
        narf_userspace::handlers::current_task_fatal_signal_pending,
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
    retry_after_pressure(
        || try_demand_page(aspace, vaddr),
        |_| unreachable!("no-wait demand fault entered reclaim parking"),
        || false,
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
        let mut waiter = core::pin::pin!(ReclaimWaiter::new(ticket, counting_waker()));
        let registration = match register_waiter(waiter.as_mut()) {
            RegisterResult::Armed(registration) => registration,
            RegisterResult::RetryNow => {
                return TestResult::Fail("reclaim waiter could not register")
            }
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
        let mut late = core::pin::pin!(ReclaimWaiter::new(completed, counting_waker()));
        match register_waiter(late.as_mut()) {
            RegisterResult::RetryNow => {}
            RegisterResult::Armed(registration) => {
                drop(registration);
                return TestResult::Fail("stale generation armed a sleeping waiter");
            }
        }
        if late.linked.get().is_some() {
            return TestResult::Fail("a retried waiter stayed linked");
        }
        TestResult::Pass
    }
    kernel_test_in!("frame", smoke_reclaim_wait_registration_is_lost_wake_free);

    /// More fault waiters than the old fixed table held (one slot per task
    /// the scheduler could admit) all park on one reclaim cycle and all wake
    /// when it completes. Linux parks a reclaim-throttled task on a wait
    /// queue (`reclaim_throttle` → `pgdat->reclaim_wait`), which has no
    /// capacity; with task admission sized from RAM neither may this.
    fn smoke_reclaim_wait_has_no_waiter_capacity() -> TestResult {
        const NODE: usize = FRAME_MAX_NUMA_NODES - 1;
        const WAITERS: usize = 1100;
        WAKES.store(0, Ordering::Relaxed);
        let ticket = next_ticket(NODE);
        let mut waiters = (0..WAITERS)
            .map(|_| alloc::boxed::Box::pin(ReclaimWaiter::new(ticket, counting_waker())))
            .collect::<alloc::vec::Vec<_>>();
        let mut registrations = alloc::vec::Vec::with_capacity(WAITERS);
        for waiter in waiters.iter_mut() {
            match register_waiter(waiter.as_mut()) {
                RegisterResult::Armed(registration) => registrations.push(registration),
                RegisterResult::RetryNow => {
                    drop(registrations);
                    return TestResult::Fail("an unfinished reclaim cycle forced a retry");
                }
            }
        }
        notify_reclaim_progress(ticket);
        let woken = WAKES.load(Ordering::Relaxed);
        // Entries stay linked until their owners resume; publishing the same
        // completed sequence again must not wake any of them twice.
        notify_reclaim_progress(ticket);
        let rewoken = WAKES.load(Ordering::Relaxed) - woken;
        let any_waiter = has_waiter_for(ticket);
        drop(registrations);
        if woken != WAITERS {
            return TestResult::Fail("reclaim progress did not wake every waiter");
        }
        if rewoken != 0 {
            return TestResult::Fail("one completion woke an entry twice");
        }
        if !any_waiter || has_waiter_for(ticket) {
            return TestResult::Fail("has_waiter_for did not track the linked waiters");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "frame/reclaim_wait",
        smoke_reclaim_wait_has_no_waiter_capacity
    );

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
            || false,
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
            || false,
            true,
        );
        if result != Err(AddressSpaceError::Unmapped) || nonpressure_attempts != 1 || waited {
            return TestResult::Fail("a genuine unmapped fault entered reclaim backpressure");
        }
        TestResult::Pass
    }
    kernel_test_in!("frame", smoke_reclaim_wait_retry_is_bounded);

    fn smoke_reclaim_wait_fatal_signal_aborts_after_single_wake() -> TestResult {
        let ticket = ReclaimTicket {
            node: 0,
            sequence: 1,
        };
        let fatal = core::cell::Cell::new(false);
        let mut attempts = 0usize;
        let mut waits = 0usize;
        let result = retry_after_pressure(
            || {
                attempts += 1;
                Err(AddressSpaceError::ReclaimPressure(ticket))
            },
            |_| {
                waits += 1;
                // Model SIGKILL waking the parked stackful continuation.
                fatal.set(true);
                true
            },
            || fatal.get(),
            true,
        );
        if result == Err(AddressSpaceError::ReclaimPressure(ticket)) && attempts == 1 && waits == 1
        {
            TestResult::Pass
        } else {
            TestResult::Fail("fatal signal retried reclaim after its one wake")
        }
    }
    kernel_test_in!(
        "frame",
        smoke_reclaim_wait_fatal_signal_aborts_after_single_wake
    );

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
            || false,
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
