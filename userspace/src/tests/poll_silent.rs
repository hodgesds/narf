//! A blocking poll/select sleeps on its files' wait queues: no periodic
//! rescan timer exists for any provider that has a wake source. The one
//! exception is a provider that declares `FileOps::poll_requires_rescan`
//! (polled hardware without an interrupt), whose bounded rescan is kept for
//! that file only.
use super::*;
use crate::poll::{
    arm_readiness_cells, arm_then_scan, poll_wake_deadline, ArmedScan, PollFd, UNNOTIFIED_RESCAN_NS,
};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::{RawWaker, RawWakerVTable, Waker};

const TASK: u64 = 0xFACE_A091;
const NOW: u64 = 1_000_000_000;

struct Fixture {
    _task: Arc<crate::task::Task>,
}
impl Fixture {
    fn new() -> Self {
        crate::fd::__test_reset();
        Self {
            _task: crate::task::Task::new_registered(TASK, TASK),
        }
    }
    fn install(&self, ops: Arc<dyn narf_filesystem::FileOps>) -> PollFd {
        let fd = crate::fd::install(
            TASK,
            crate::fd::FdEntry {
                ops,
                offset: 0,
                flags: 0,
                status_flags: 0,
            },
        )
        .expect("install poll fixture fd");
        PollFd {
            fd: fd as i32,
            events: narf_filesystem::POLL_IN as u16,
            revents: 0,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        crate::task::release_task(TASK);
        crate::fd::__test_reset();
    }
}

/// A waker that counts its wakes in a static, so a test can observe a
/// producer's wake reaching a queued poller.
static WAKES: AtomicU32 = AtomicU32::new(0);
fn counting_waker() -> Waker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    unsafe fn wake(_: *const ()) {
        WAKES.fetch_add(1, Ordering::SeqCst);
    }
    unsafe fn drop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake, drop);
    // SAFETY: the vtable functions ignore the null data pointer.
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
}

/// The serial console (`ttyS0`) is interrupt-fed: its poller queues on the
/// console input wait queue, an input byte wakes it, and an infinite poll
/// arms no timer. This was the fixture for the old 10 ms "silent recheck".
fn serial_console_poll_is_event_driven() -> TestResult {
    let fixture = Fixture::new();
    let serial = narf_filesystem::devfs::console_tty_node(narf_filesystem::TTY_ID_SERIAL0)
        .expect("serial tty fixture");
    let fds = [fixture.install(serial.clone())];
    let waker = counting_waker();
    let arms = arm_readiness_cells(TASK, &fds, &waker);
    if !arms.all_armed || arms.needs_rescan {
        serial.disarm_readiness(TASK);
        return TestResult::Fail("serial console poll is not on a wait queue");
    }
    if poll_wake_deadline(TASK, &fds, u64::MAX, NOW, arms) != u64::MAX {
        serial.disarm_readiness(TASK);
        return TestResult::Fail("infinite serial console poll armed a timer");
    }
    let before = WAKES.load(Ordering::SeqCst);
    let pushed = narf_input::push_global(narf_input::InputEvent::AsciiByte(b'q'));
    let woke = WAKES.load(Ordering::SeqCst) != before;
    serial.disarm_readiness(TASK);
    if pushed {
        // Leave the shared console ring as we found it.
        let _ = narf_input::pop_ascii_byte();
    }
    if pushed && !woke {
        return TestResult::Fail("a serial input byte did not wake the queued poller");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/poll/silent", serial_console_poll_is_event_driven);

#[derive(Debug)]
struct Provider {
    cell: Option<narf_lib::readiness::Readiness>,
    rescan: bool,
    deadline: Option<u64>,
}
impl narf_filesystem::FileOps for Provider {
    fn read<'a>(&'a self, _: u64, _: &'a mut [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::WouldBlock) })
    }
    fn write<'a>(&'a self, _: u64, b: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async move { Ok(b.len()) })
    }
    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
    fn poll_readiness(&self) -> u32 {
        narf_filesystem::POLL_OUT
    }
    fn readiness(&self) -> Option<&narf_lib::readiness::Readiness> {
        self.cell.as_ref()
    }
    fn poll_requires_rescan(&self) -> bool {
        self.rescan
    }
    fn poll_deadline(&self) -> Option<u64> {
        self.deadline
    }
}

/// Neither a durable provider nor a constant one (no cell, but nothing can
/// change its readiness) arms a periodic timer; only a declared no-wake
/// provider does.
fn only_unnotified_providers_keep_a_rescan() -> TestResult {
    let fixture = Fixture::new();
    for cell in [false, true] {
        let fds = [fixture.install(Arc::new(Provider {
            cell: cell.then(|| narf_lib::readiness::Readiness::new(0)),
            rescan: false,
            deadline: None,
        }))];
        let arms = arm_readiness_cells(TASK, &fds, Waker::noop());
        if poll_wake_deadline(TASK, &fds, u64::MAX, NOW, arms) != u64::MAX
            || poll_wake_deadline(TASK, &fds, NOW + 60_000_000_000, NOW, arms)
                != NOW + 60_000_000_000
        {
            return TestResult::Fail("a provider with a wake source acquired a periodic rescan");
        }
    }
    let fds = [PollFd {
        fd: -1,
        events: 1,
        revents: 0,
    }];
    let arms = arm_readiness_cells(TASK, &fds, Waker::noop());
    if poll_wake_deadline(TASK, &fds, u64::MAX, NOW, arms) != u64::MAX {
        return TestResult::Fail("negative-only poll acquired a polling deadline");
    }
    let fds = [fixture.install(Arc::new(Provider {
        cell: None,
        rescan: true,
        deadline: None,
    }))];
    let arms = arm_readiness_cells(TASK, &fds, Waker::noop());
    let wake = poll_wake_deadline(TASK, &fds, u64::MAX, NOW, arms);
    if wake <= NOW || wake > NOW + UNNOTIFIED_RESCAN_NS {
        return TestResult::Fail("a provider with no wake source lost its bounded rescan");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/poll/silent",
    only_unnotified_providers_keep_a_rescan
);

fn mixed_poll_preserves_timer_and_unnotified_deadlines() -> TestResult {
    let fixture = Fixture::new();
    let unnotified = fixture.install(Arc::new(Provider {
        cell: None,
        rescan: true,
        deadline: None,
    }));
    let cell = fixture.install(Arc::new(Provider {
        cell: Some(narf_lib::readiness::Readiness::new(0)),
        rescan: false,
        deadline: None,
    }));
    let timer = fixture.install(Arc::new(Provider {
        cell: None,
        rescan: false,
        deadline: Some(NOW + 5_000_000),
    }));
    let fds = [unnotified, cell];
    let arms = arm_readiness_cells(TASK, &fds, Waker::noop());
    if poll_wake_deadline(TASK, &fds, u64::MAX, NOW, arms) != NOW + UNNOTIFIED_RESCAN_NS {
        return TestResult::Fail("a mixed poll stranded its unnotified descriptor");
    }
    let fds = [unnotified, cell, timer];
    let arms = arm_readiness_cells(TASK, &fds, Waker::noop());
    if poll_wake_deadline(TASK, &fds, u64::MAX, NOW, arms) != NOW + 5_000_000
        || poll_wake_deadline(TASK, &fds, NOW + 1_000_000, NOW, arms) != NOW + 1_000_000
    {
        return TestResult::Fail("poll rescan delayed an earlier timer or application timeout");
    }
    let fds = [cell, timer];
    let arms = arm_readiness_cells(TASK, &fds, Waker::noop());
    if poll_wake_deadline(TASK, &fds, u64::MAX, NOW, arms) != NOW + 5_000_000 {
        return TestResult::Fail("a timer-only clamp grew a rescan");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/poll/silent",
    mixed_poll_preserves_timer_and_unnotified_deadlines
);

/// A wait-queue provider (Linux `->poll` = `poll_wait` + compute) whose
/// producer publishes and wakes in the window between poll's first scan and
/// its registration. The wake finds an empty queue; only a scan AFTER the
/// registration sees the event. Before `arm_then_scan`, poll trusted the
/// arm's own answer, parked, and lost this event.
#[derive(Debug)]
struct RacingQueue {
    queue: narf_lib::readiness::WaitQueue,
    published: AtomicBool,
}
impl narf_filesystem::FileOps for RacingQueue {
    fn read<'a>(&'a self, _: u64, _: &'a mut [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::WouldBlock) })
    }
    fn write<'a>(&'a self, _: u64, b: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async move { Ok(b.len()) })
    }
    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
    fn poll_readiness(&self) -> u32 {
        if self.published.load(Ordering::Acquire) {
            narf_filesystem::POLL_IN
        } else {
            0
        }
    }
    fn arm_readiness(
        &self,
        id: u64,
        interest: u32,
        waker: &Waker,
    ) -> Option<core::task::Poll<u32>> {
        // The producer runs on another CPU right now: publish, then wake a
        // queue this poller has not joined yet.
        self.published.store(true, Ordering::Release);
        self.queue.wake(narf_filesystem::POLL_IN);
        // Register with no recompute (the caller's scan is the recompute).
        Some(self.queue.arm(id, interest, waker, || 0))
    }
    fn disarm_readiness(&self, id: u64) -> bool {
        self.queue.disarm(id);
        true
    }
}

fn poll_rechecks_after_registering() -> TestResult {
    let fixture = Fixture::new();
    let racing = Arc::new(RacingQueue {
        queue: narf_lib::readiness::WaitQueue::new(),
        published: AtomicBool::new(false),
    });
    let mut fds = [fixture.install(racing.clone())];
    // First scan: nothing ready, as `poll_common` saw before arming.
    if crate::poll::poll_scan(TASK, &mut fds) != 0 {
        return TestResult::Fail("fixture ready before the race");
    }
    match arm_then_scan(TASK, &mut fds, Waker::noop()) {
        ArmedScan::Ready(1) => {}
        ArmedScan::Ready(_) => return TestResult::Fail("wrong ready count after the race"),
        ArmedScan::Park(_) => {
            racing.queue.disarm(TASK);
            return TestResult::Fail(
                "poll parked on an event published between its scan and its registration",
            );
        }
    }
    if fds[0].revents != narf_filesystem::POLL_IN as u16 {
        return TestResult::Fail("post-registration scan did not report POLLIN");
    }
    if racing.queue.waiter_count() != 0 {
        return TestResult::Fail("a ready poll left its registration queued");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/poll/silent", poll_rechecks_after_registering);
