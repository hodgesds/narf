//! What wakes a parked supervisor, on the live controller: the events a
//! controller posts are routed exactly as the demux routes them after
//! popping them off the event ring, and the supervisor's wait must end
//! because of the event — with no timer armed while it waited. Linux's
//! `hub_wq` runs from `hub_irq` (a hub's status-change URB completing),
//! from `xhci_hub_status_data`/`usb_hcd_poll_rh_status` after a Port
//! Status Change Event, and HID input arrives by `hid_irq_in`.
use super::*;
use crate::supervisor_wait::{park, Woke};
use alloc::task::Wake;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::AtomicUsize;
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Count(AtomicUsize);
impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

fn transfer(slot: u8, dci: u8, code: u8) -> [u32; 4] {
    [
        0x7400,
        0,
        u32::from(code) << 24,
        TRB_TYPE_TRANSFER_EVENT << TRB_TYPE_SHIFT | u32::from(dci) << 16 | u32::from(slot) << 24,
    ]
}

fn port_status_change(port: u8) -> [u32; 4] {
    [
        u32::from(port) << 24,
        0,
        1 << 24,
        TRB_TYPE_PORT_STATUS_CHANGE << TRB_TYPE_SHIFT,
    ]
}

/// A slot no device occupies on the first controller.
fn idle_slot() -> Option<(Arc<Xhci>, u8)> {
    let c = first_controller()?;
    let slot = c.max_slots();
    c.device_generation(slot).is_none().then_some((c, slot))
}

/// Park a supervisor wait on `c` with no deadline, `inject` an event,
/// and require that the event — not a timer — woke it and ended it.
fn event_wakes_parked_supervisor(c: &Xhci, inject: impl FnOnce()) -> Result<(), &'static str> {
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    // Another source may kick the live controller between the snapshot
    // and the first poll; take a fresh snapshot until the wait parks.
    let mut parked = None;
    for _ in 0..8 {
        let mut wait = park(c, c.supervisor_kicks(), None);
        if Pin::new(&mut wait).poll(&mut cx).is_pending() {
            parked = Some(wait);
            break;
        }
    }
    let Some(mut wait) = parked else {
        return Err("the supervisor wait never parked");
    };
    if wait.timer_armed() {
        return Err("the parked supervisor armed a timer instead of waiting for its event");
    }
    let woken = count.0.load(Ordering::Acquire);
    inject();
    if count.0.load(Ordering::Acquire) == woken {
        return Err("the event did not wake the parked supervisor");
    }
    match Pin::new(&mut wait).poll(&mut cx) {
        Poll::Ready(Woke::Kick) => Ok(()),
        _ => Err("the woken supervisor wait did not end on its next poll"),
    }
}

/// A Port Status Change Event on a root port wakes the controller's
/// parked supervisor within one poll.
fn smoke_usb_port_status_change_wakes_parked_supervisor() -> TestResult {
    let Some(c) = first_controller() else {
        return TestResult::Skip("no xHCI controller");
    };
    let before = c.port_status_events();
    if let Err(why) =
        event_wakes_parked_supervisor(&c, || c.__test_route_event(port_status_change(1)))
    {
        return TestResult::Fail(why);
    }
    if c.port_status_events() == before {
        return TestResult::Fail("the Port Status Change Event was not counted for its controller");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/supervisor",
    smoke_usb_port_status_change_wakes_parked_supervisor
);

/// The completion of a hub's status-change interrupt-IN transfer (a
/// downstream port changed: `hub_irq`) wakes the parked supervisor.
fn smoke_usb_hub_status_completion_wakes_parked_supervisor() -> TestResult {
    let Some((c, slot)) = idle_slot() else {
        return TestResult::Skip("no controller with an idle slot");
    };
    // The status-change endpoint is the hub interface's first endpoint,
    // EP1 IN (DCI 3); one byte reports port 2 changed.
    let result = event_wakes_parked_supervisor(&c, || c.__test_route_event(transfer(slot, 3, 13)));
    c.purge_slot_events(slot);
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/usb/supervisor",
    smoke_usb_hub_status_completion_wakes_parked_supervisor
);

/// A HID interrupt-IN completion wakes the parked supervisor with no
/// timer, and its pump takes the report at once (`hid_irq_in`): input
/// needs no periodic poll. The device is absent, so the report decodes
/// to nothing; what matters is that the completion reached the pump.
fn smoke_usb_hid_completion_reaches_pump_without_timer() -> TestResult {
    let Some((c, slot)) = idle_slot() else {
        return TestResult::Skip("no controller with an idle slot");
    };
    if c.id() != 0 {
        return TestResult::Skip("the keyboard fixture binds on controller 0");
    }
    crate::hid::__push_keyboard_for_test(crate::hid::BootKeyboard::from_configured_endpoint(
        slot,
        0,
        3,
        None,
        narf_input::evdev::InputId::new(narf_input::evdev::bus::USB, 0, 0, 0),
    ));
    let woke = event_wakes_parked_supervisor(&c, || c.__test_route_event(transfer(slot, 3, 13)));
    let queued = c.__test_queued_transfer_events(slot);
    let _ = crate::hid::pump_all(&c);
    let left = c.__test_queued_transfer_events(slot);
    let _ = crate::hid::detach_boot_keyboard(0, slot);
    c.purge_slot_events(slot);
    if let Err(why) = woke {
        return TestResult::Fail(why);
    }
    if queued != 1 || left != 0 {
        return TestResult::Fail("the woken HID pump did not take the completed report");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/supervisor",
    smoke_usb_hid_completion_reaches_pump_without_timer
);
