use super::*;
use crate::address_space::{DemandPageClaim, Region, RegionPerms};
use crate::{PhysAddr, VirtAddr};
use alloc::sync::Arc;
use alloc::task::Wake;
use narf_kernel_test::{kernel_test_in, TestResult};

const BASE: u64 = 0x0000_0084_0000_0000;

#[derive(Default)]
struct Count(AtomicUsize);
impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn region() -> Region {
    Region {
        base: VirtAddr::new(BASE),
        len: 4096 * (super::super::INLINE_DEMAND_CLAIMS as u64 + 2),
        perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::FILE_DEMAND,
        phys: alloc::vec![].into(),
    }
}

fn claim(space: &AddressSpace, page: u64) -> u64 {
    match space.claim_demand_page(page, |_, _| Ok(())).unwrap() {
        DemandPageClaim::Owner { ticket, .. } => ticket,
        _ => panic!("test page already claimed"),
    }
}

fn smoke_demand_wait_blocks_until_exact_owner_retires() -> TestResult {
    let space = AddressSpace::empty();
    let other = AddressSpace::empty();
    space.map_region(region()).unwrap();
    other.map_region(region()).unwrap();
    let ticket = claim(&space, BASE);
    let other_ticket = claim(&other, BASE);
    let neighbor = claim(&space, BASE + 4096);
    let count = Arc::new(Count::default());
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    let mut wait = core::pin::pin!(DemandPageWait::new(&space, BASE, ticket));
    for _ in 0..16 {
        assert!(wait.as_mut().poll(&mut cx).is_pending());
    }
    other.cancel_demand_page(BASE, other_ticket);
    space.cancel_demand_page(BASE + 4096, neighbor);
    assert_eq!(count.0.load(Ordering::Relaxed), 0);
    space.cancel_demand_page(BASE, ticket);
    assert_eq!(count.0.load(Ordering::Relaxed), 1);
    // A new owner at the same VA cannot extend the old ticket's wait.
    let replacement = claim(&space, BASE);
    assert_eq!(wait.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
    space.cancel_demand_page(BASE, replacement);
    assert_eq!(count.0.load(Ordering::Relaxed), 1);
    TestResult::Pass
}
kernel_test_in!(
    "memory/demand_wait",
    smoke_demand_wait_blocks_until_exact_owner_retires
);

fn smoke_demand_wait_completion_before_registration() -> TestResult {
    let space = AddressSpace::empty();
    space.map_region(region()).unwrap();
    let ticket = claim(&space, BASE);
    let mut wait = core::pin::pin!(DemandPageWait::new(&space, BASE, ticket));
    space.cancel_demand_page(BASE, ticket);
    let count = Arc::new(Count::default());
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    assert_eq!(wait.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
    assert_eq!(count.0.load(Ordering::Relaxed), 0);
    assert!(wait.registration.is_none());
    TestResult::Pass
}
kernel_test_in!(
    "memory/demand_wait",
    smoke_demand_wait_completion_before_registration
);

fn smoke_demand_wait_unmap_wakes_inline_overflow_and_all_peers() -> TestResult {
    let space = AddressSpace::empty();
    space.map_region(region()).unwrap();
    let mut tickets = alloc::vec::Vec::new();
    for page in 0..=super::super::INLINE_DEMAND_CLAIMS {
        tickets.push(claim(&space, BASE + page as u64 * 4096));
    }
    let count = Arc::new(Count::default());
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    let mut waits = alloc::vec::Vec::new();
    for index in [0, 0, 0, super::super::INLINE_DEMAND_CLAIMS] {
        let mut wait = alloc::boxed::Box::pin(DemandPageWait::new(
            &space,
            BASE + index as u64 * 4096,
            tickets[index],
        ));
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        waits.push(wait);
    }
    // Dropping one waiter (e.g. SIGKILL) removes only its registration.
    waits.pop();
    space.unmap_region(VirtAddr::new(BASE)).unwrap();
    assert_eq!(count.0.load(Ordering::Relaxed), 3);
    space.map_region(region()).unwrap();
    for wait in &mut waits {
        assert_eq!(wait.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
    }
    // Also exercise an actual waiter on the overflow claim's cancellation.
    for (page, ticket) in tickets.iter_mut().enumerate() {
        *ticket = claim(&space, BASE + page as u64 * 4096);
    }
    let index = super::super::INLINE_DEMAND_CLAIMS;
    let mut overflow = core::pin::pin!(DemandPageWait::new(
        &space,
        BASE + index as u64 * 4096,
        tickets[index]
    ));
    assert!(overflow.as_mut().poll(&mut cx).is_pending());
    space.unmap_region(VirtAddr::new(BASE)).unwrap();
    assert_eq!(count.0.load(Ordering::Relaxed), 4);
    assert_eq!(overflow.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
    TestResult::Pass
}
kernel_test_in!(
    "memory/demand_wait",
    smoke_demand_wait_unmap_wakes_inline_overflow_and_all_peers
);

fn smoke_demand_wait_publish_and_install_failure_wake() -> TestResult {
    for fail in [true, false] {
        let space = AddressSpace::empty();
        space.map_region(region()).unwrap();
        let ticket = claim(&space, BASE);
        let count = Arc::new(Count::default());
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut wait = core::pin::pin!(DemandPageWait::new(&space, BASE, ticket));
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        // Synthetic backing: removed before AS destruction, never freed.
        let phys = PhysAddr::new(0x34_000);
        crate::rmap::try_prepare_owner_slots(phys, 1).unwrap();
        let result = space.finish_demand_page(BASE, ticket, phys, |_, _| {
            if fail {
                Err(AddressSpaceError::NotImplemented)
            } else {
                Ok(())
            }
        });
        if fail {
            crate::rmap::release_reserved_owner_slots(phys, 1);
            assert_eq!(result, Err(AddressSpaceError::NotImplemented));
        } else {
            crate::rmap::remove(phys, space.root, VirtAddr::new(BASE));
            space.regions.lock().remove(BASE);
            assert_eq!(result, Ok(true));
        }
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        assert_eq!(wait.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/demand_wait",
    smoke_demand_wait_publish_and_install_failure_wake
);

fn smoke_demand_wait_real_fault_enters_unlocked_wait() -> TestResult {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn complete_owner(wait: DemandPageWait<'_>) -> Result<(), AddressSpaceError> {
        let mut wait = core::pin::pin!(wait);
        CALLS.fetch_add(1, Ordering::Relaxed);
        assert!(
            wait.space.regions.try_lock().is_some(),
            "fault held region lock across wait"
        );
        let count = Arc::new(Count::default());
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        wait.space.cancel_demand_page(wait.page, wait.ticket);
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        assert_eq!(wait.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
        Ok(())
    }
    struct Restore(usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            WAIT_HOOK.store(self.0, Ordering::Release);
        }
    }
    let _restore = Restore(WAIT_HOOK.swap(
        complete_owner as DemandPageWaitHook as usize,
        Ordering::AcqRel,
    ));
    // SAFETY: allocator and kernel mapping are live; this unpublished mm has
    // no running user, like a stopped tracee's remote-page fault.
    let space = unsafe { AddressSpace::new_for_user() }.unwrap();
    space.map_region(region()).unwrap();
    claim(&space, BASE);
    CALLS.store(0, Ordering::Relaxed);
    assert_eq!(
        // SAFETY: valid, exclusively-owned stopped mm. The pending page never
        // installs a leaf; the hook retires the peer claim instead.
        unsafe { space.demand_alloc_page(VirtAddr::new(BASE)) },
        Ok(())
    );
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    let ticket = claim(&space, BASE);
    WAIT_HOOK.store(0, Ordering::Release);
    assert_eq!(
        // SAFETY: same valid stopped mm; no waiter means explicit failure.
        unsafe { space.demand_alloc_page(VirtAddr::new(BASE)) },
        Err(AddressSpaceError::NotImplemented)
    );
    space.cancel_demand_page(BASE, ticket);
    TestResult::Pass
}
kernel_test_in!(
    "memory/demand_wait",
    smoke_demand_wait_real_fault_enters_unlocked_wait
);

fn smoke_demand_wait_replacement_waker() -> TestResult {
    const PEERS: usize = 3;
    let space = AddressSpace::empty();
    space.map_region(region()).unwrap();
    let ticket = claim(&space, BASE);
    let old = Arc::new(Count::default());
    let new = Arc::new(Count::default());
    let old_waker = Waker::from(old.clone());
    let new_waker = Waker::from(new.clone());
    let mut cx = Context::from_waker(&old_waker);
    let mut waits = alloc::vec::Vec::with_capacity(PEERS);
    for _ in 0..PEERS {
        let mut wait = alloc::boxed::Box::pin(DemandPageWait::new(&space, BASE, ticket));
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        waits.push(wait);
    }
    // A re-poll with another waker replaces it in place: one entry, the
    // newest waker.
    let mut extra = core::pin::pin!(DemandPageWait::new(&space, BASE, ticket));
    assert!(extra.as_mut().poll(&mut cx).is_pending());
    assert!(extra
        .as_mut()
        .poll(&mut Context::from_waker(&new_waker))
        .is_pending());
    space.cancel_demand_page(BASE, ticket);
    assert_eq!(old.0.load(Ordering::Relaxed), PEERS);
    assert_eq!(new.0.load(Ordering::Relaxed), 1);
    drop(waits);
    assert_eq!(extra.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
    assert_eq!(ACTIVE.load(Ordering::Acquire), 0);
    TestResult::Pass
}
kernel_test_in!("memory/demand_wait", smoke_demand_wait_replacement_waker);

/// More waiters than the old fixed table held (one slot per task the
/// scheduler could admit) all park on one owner, and all wake when it
/// retires. Linux's folio wait queues link on-stack entries and have no
/// capacity; with task admission sized from RAM neither may this.
fn smoke_demand_wait_has_no_waiter_capacity() -> TestResult {
    const WAITERS: usize = 1100;
    let space = AddressSpace::empty();
    space.map_region(region()).unwrap();
    let ticket = claim(&space, BASE);
    let count = Arc::new(Count::default());
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    let mut waits = alloc::vec::Vec::with_capacity(WAITERS);
    for _ in 0..WAITERS {
        let mut wait = alloc::boxed::Box::pin(DemandPageWait::new(&space, BASE, ticket));
        if !wait.as_mut().poll(&mut cx).is_pending() {
            drop(waits);
            space.cancel_demand_page(BASE, ticket);
            return TestResult::Fail("a demand-page waiter past 1024 could not park");
        }
        waits.push(wait);
    }
    space.cancel_demand_page(BASE, ticket);
    let woken = count.0.load(Ordering::Relaxed);
    let resolved = waits
        .iter_mut()
        .all(|wait| wait.as_mut().poll(&mut cx) == Poll::Ready(Ok(())));
    drop(waits);
    if woken != WAITERS {
        return TestResult::Fail("retiring the owner did not wake every waiter");
    }
    if !resolved {
        return TestResult::Fail("a woken waiter did not see its owner retired");
    }
    if ACTIVE.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("a dropped waiter stayed registered");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/demand_wait",
    smoke_demand_wait_has_no_waiter_capacity
);
