use super::*;
use alloc::boxed::Box;
use alloc::task::Wake;
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

struct WakeCount(AtomicU32);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
fn new_card() -> u32 {
    let iface = Arc::new(crate::drm_devfs_bridge::BochsCard::new(alloc::format!(
        "card{}",
        crate::drm_registry::count()
    )));
    let card = crate::drm::card::Card::new("test", "placement liveness fixture", (1, 0, 0));
    crate::drm_registry::register_drm_card_with_state(iface, card)
}

fn placement_loss_wakes_all_clients_and_cancelled_waiters_disarm() -> TestResult {
    let card = new_card();
    let Some(held) = try_placement(card) else {
        return TestResult::Fail("placement guard");
    };
    let ready = &placement_state(card).unwrap().ready;
    let count = Arc::new(WakeCount(AtomicU32::new(0)));
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    let mut a = Box::pin(lock_placement_live(card));
    let mut b = Box::pin(lock_placement_live(card));
    let mut cancelled = Box::pin(lock_placement_live(card));
    if !a.as_mut().poll(&mut cx).is_pending()
        || !b.as_mut().poll(&mut cx).is_pending()
        || !cancelled.as_mut().poll(&mut cx).is_pending()
        || ready.waiter_count() != 3
    {
        return TestResult::Fail("client waiters did not arm");
    }
    drop(cancelled);
    if ready.waiter_count() != 2 {
        return TestResult::Fail("cancelled client kept a loss waiter");
    }
    mark_placement_lost(card);
    if count.0.load(Ordering::Relaxed) != 2
        || !matches!(
            a.as_mut().poll(&mut cx),
            Poll::Ready(Err(FsError::NoDevice))
        )
        || !matches!(
            b.as_mut().poll(&mut cx),
            Poll::Ready(Err(FsError::NoDevice))
        )
        || ready.waiter_count() != 0
    {
        return TestResult::Fail("terminal loss did not wake/refuse every queued client");
    }
    // New clients must not wait for the quarantined guard to drop. A card
    // which used to share its mutex shard remains independently usable.
    if !matches!(
        Box::pin(lock_placement_live(card)).as_mut().poll(&mut cx),
        Poll::Ready(Err(FsError::NoDevice))
    ) || try_placement_live(card).err() != Some(FsError::NoDevice)
        || ensure_placement_live(card + 16).is_err()
        || try_placement_live(card + 16).ok().flatten().is_none()
        || try_placement(card).is_some()
    {
        return TestResult::Fail("lost device admitted a new client or poisoned its shard");
    }
    drop(held);
    if !matches!(
        narf_scheduler::block_on_spin(lock_placement_live(card)),
        Err(FsError::NoDevice)
    ) {
        return TestResult::Fail("releasing reset exclusion resurrected a lost device");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    placement_loss_wakes_all_clients_and_cancelled_waiters_disarm
);

fn placement_live_admission_preserves_temporary_contention() -> TestResult {
    let card = new_card();
    let held = narf_scheduler::block_on_spin(lock_placement(card));
    let ready = &placement_state(card).unwrap().ready;
    let mut request = Box::pin(prepare_scanout(card, Vec::new()));
    let mut cx = Context::from_waker(Waker::noop());
    if !request.as_mut().poll(&mut cx).is_pending() || ready.waiter_count() != 1 {
        return TestResult::Fail("temporary contention failed instead of parking");
    }
    drop(held);
    let Ok(prepared) = narf_scheduler::block_on_spin(request) else {
        return TestResult::Fail("temporary suspend/recovery marked card lost");
    };
    if ready.waiter_count() != 0 || try_placement(card).is_some() {
        return TestResult::Fail("successful admission lost guard or retained waiter");
    }
    drop(prepared);
    if try_placement_live(card).ok().flatten().is_none() {
        return TestResult::Fail("temporary admission did not release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    placement_live_admission_preserves_temporary_contention
);
