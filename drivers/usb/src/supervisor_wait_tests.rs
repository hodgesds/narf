//! The supervisor's wait is event-driven, as Linux's `hub_wq` is: it
//! runs only when kicked (a hub status-change completion, a port status
//! change, an explicit `kick_hub_wq`), and arms a timer only for a
//! deadline of its own. The fake source models a controller that is never
//! kicked unless the test kicks it.
use super::*;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::sync::atomic::AtomicUsize;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

struct Quiet {
    kicks: AtomicU64,
    waiter: IrqSafeSpinLock<Option<Waker>>,
}

impl Quiet {
    fn new() -> Self {
        Self {
            kicks: AtomicU64::new(0),
            waiter: IrqSafeSpinLock::new(None),
        }
    }
    fn kick(&self) {
        self.kicks.fetch_add(1, Ordering::SeqCst);
        let waker = self.waiter.lock().clone();
        if let Some(w) = waker {
            w.wake();
        }
    }
}

impl KickSource for Quiet {
    fn kicks(&self) -> u64 {
        self.kicks.load(Ordering::SeqCst)
    }
    fn arm(&self, _id: u64, waker: &Waker, seen: u64) -> bool {
        *self.waiter.lock() = Some(waker.clone());
        self.kicks() != seen
    }
    fn disarm(&self, _id: u64) {
        self.waiter.lock().take();
    }
}

struct Count(AtomicUsize);
impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

fn counting() -> (Arc<Count>, Waker) {
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    (count, waker)
}

/// A supervisor with nothing to wait out — no idle window running, every
/// source able to interrupt — parks with no timer, and over a second with
/// no event nothing wakes it, so the executor never polls it again.
/// Today's wait sleeps 8 ms on the wheel every cycle instead (four of
/// them on CPU0, one per controller: ~400 expiries a second).
fn smoke_usb_idle_supervisor_parks_without_timer() -> TestResult {
    let deadline = next_deadline(narf_time::monotonic_ns(), &Needs::default());
    if deadline.is_some() {
        return TestResult::Fail("an idle supervisor armed a timer (the 8 ms fallback)");
    }
    let source = Quiet::new();
    let (count, waker) = counting();
    let mut cx = Context::from_waker(&waker);
    let mut wait = park(&source, source.kicks(), deadline);
    if Pin::new(&mut wait).poll(&mut cx).is_ready() {
        return TestResult::Fail("an idle wait ended without a kick");
    }
    if wait.timer_armed() {
        return TestResult::Fail("an idle wait armed a timer");
    }
    let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(1_000));
    if count.0.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("an idle wait was woken without a kick");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/supervisor",
    smoke_usb_idle_supervisor_parks_without_timer
);

/// A kick wakes the parked supervisor at once, and the wait ends on that
/// next poll — no timer is involved.
fn smoke_usb_supervisor_kick_ends_wait_on_next_poll() -> TestResult {
    let source = Quiet::new();
    let (count, waker) = counting();
    let mut cx = Context::from_waker(&waker);
    let mut wait = park(&source, source.kicks(), None);
    if Pin::new(&mut wait).poll(&mut cx).is_ready() {
        return TestResult::Fail("a wait ended before its kick");
    }
    if wait.timer_armed() {
        return TestResult::Fail("a wait for a kick armed a timer");
    }
    source.kick();
    if count.0.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("a kick did not wake the parked supervisor");
    }
    match Pin::new(&mut wait).poll(&mut cx) {
        Poll::Ready(Woke::Kick) => TestResult::Pass,
        _ => TestResult::Fail("the woken wait did not end on its next poll"),
    }
}
kernel_test_in!(
    "drivers/usb/supervisor",
    smoke_usb_supervisor_kick_ends_wait_on_next_poll
);

/// The deadlines the supervisor does wait out fire exactly: the wait's
/// deadline is the supervisor's own (here an idle window ending in 5 s),
/// and a 20 ms deadline (a debounce window) ends the wait at 20 ms, not
/// at the next 8 ms tick before it.
fn smoke_usb_supervisor_deadline_fires_on_time() -> TestResult {
    let now = narf_time::monotonic_ns();
    let needs = Needs {
        idle_suspend_at_ns: Some(now + 5_000_000_000),
        ..Needs::default()
    };
    let Some(deadline) = next_deadline(now, &needs) else {
        return TestResult::Fail("the supervisor's own deadline armed no timer");
    };
    let left_ms = narf_time::wall::cycles_to_ns(deadline.remaining_cycles()) / 1_000_000;
    if !(4_990..=5_000).contains(&left_ms) {
        return TestResult::Fail("the wait's deadline is not the supervisor's own deadline");
    }
    let source = Quiet::new();
    let start = narf_time::monotonic_ns();
    let woke = narf_scheduler::block_on_spin(park(
        &source,
        source.kicks(),
        Some(narf_time::Deadline::after_ms(20)),
    ));
    let took_ms = narf_time::monotonic_ns().saturating_sub(start) / 1_000_000;
    if woke != Woke::Deadline || !(20..=40).contains(&took_ms) {
        return TestResult::Fail("a 20 ms deadline did not end the wait on time");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/supervisor",
    smoke_usb_supervisor_deadline_fires_on_time
);
