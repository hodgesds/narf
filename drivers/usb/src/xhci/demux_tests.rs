//! Demux routing against the live controller: events are injected
//! through the same routing the interrupt handler and every ring poller
//! use after popping an event off the ring.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn transfer(slot: u8, dci: u8, pointer: u64, code: u8) -> [u32; 4] {
    [
        pointer as u32,
        (pointer >> 32) as u32,
        u32::from(code) << 24,
        TRB_TYPE_TRANSFER_EVENT << TRB_TYPE_SHIFT | u32::from(dci) << 16 | u32::from(slot) << 24,
    ]
}

/// A slot no device occupies on the first controller.
fn idle_slot() -> Option<(Arc<Xhci>, u8)> {
    let c = first_controller()?;
    let slot = c.max_slots();
    c.device_generation(slot).is_none().then_some((c, slot))
}

/// A stray EP0 Transfer Event — one no control receipt claims, such as
/// a late event for a completed or cancelled TD — is dropped, as Linux
/// `handle_tx_event` drops an event matching no TD. Nothing ever takes
/// EP0 events from the shared queue, so a queued one stayed until slot
/// reclaim and kept `has_pending_transfer_events` true: the
/// supervisor's inter-cycle wait could never park. Interrupt-IN events
/// still queue for their pumps.
fn smoke_xhci_stray_ep0_event_lets_supervisor_wait_park() -> TestResult {
    let Some((c, slot)) = idle_slot() else {
        return TestResult::Skip("no controller with an idle slot");
    };
    let stray = transfer(slot, 1, 0x7000, 1);
    let report = transfer(slot, 3, 0x7100, 13);
    if unowned_transfer_route(&stray) != EventRoute::Drop
        || unowned_transfer_route(&report) != EventRoute::Queue
    {
        return TestResult::Fail("unowned Transfer Event routes changed");
    }
    c.__test_route_event(stray);
    let stray_queued = c.__test_queued_transfer_events(slot);
    c.__test_route_event(report);
    let report_queued = c.__test_queued_transfer_events(slot);
    c.purge_slot_events(slot);
    if stray_queued != 0 {
        return TestResult::Fail("stray EP0 event stayed queued; the supervisor wait never parks");
    }
    if report_queued != 1 {
        return TestResult::Fail("interrupt-IN report was not queued for its pump");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci/demux",
    smoke_xhci_stray_ep0_event_lets_supervisor_wait_park
);

struct Count(core::sync::atomic::AtomicUsize);
impl alloc::task::Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

/// Reclaiming a slot (`purge_slot_events`) drops its endpoint
/// completion wakers with its events: left registered, they would be
/// woken by the next occupant of the slot's completions, and keep a
/// dead owner alive.
fn smoke_xhci_slot_reclaim_drops_endpoint_wakers() -> TestResult {
    let Some((c, slot)) = idle_slot() else {
        return TestResult::Skip("no controller with an idle slot");
    };
    let woken = Arc::new(Count(core::sync::atomic::AtomicUsize::new(0)));
    let waker = core::task::Waker::from(woken.clone());
    c.set_endpoint_waker(slot, 3, &waker);
    c.set_endpoint_waker(slot, 4, &waker);
    if c.__test_endpoint_wakers(slot) != 2 {
        c.clear_endpoint_waker(slot, 3);
        c.clear_endpoint_waker(slot, 4);
        return TestResult::Fail("endpoint wakers did not register");
    }
    c.purge_slot_events(slot);
    let left = c.__test_endpoint_wakers(slot);
    c.clear_endpoint_waker(slot, 3);
    c.clear_endpoint_waker(slot, 4);
    if left != 0 {
        return TestResult::Fail("slot reclaim left its endpoint wakers registered");
    }
    // The next occupant's completion wakes nobody.
    c.__test_route_event(transfer(slot, 3, 0x7200, 13));
    c.purge_slot_events(slot);
    if woken.0.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("a reclaimed slot's waker was woken by a later completion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci/demux",
    smoke_xhci_slot_reclaim_drops_endpoint_wakers
);
