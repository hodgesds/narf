//! A poll/select wait on a silent provider must have a bounded recheck even
//! when the application requested an infinite wait. No network notification
//! or busy loop is available to rescue the serial tty in this fixture.
use super::*;
use crate::poll::{arm_readiness_cells, poll_wake_deadline, PollFd};
use core::task::Waker;

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

fn silent_serial_poll_has_bounded_recheck() -> TestResult {
    let fixture = Fixture::new();
    let serial = narf_filesystem::devfs::console_tty_node(narf_filesystem::TTY_ID_SERIAL0)
        .expect("serial tty fixture");
    let fds = [fixture.install(serial)];
    let arms = arm_readiness_cells(TASK, &fds, Waker::noop());
    let wake = poll_wake_deadline(TASK, &fds, u64::MAX, NOW, arms);
    if wake <= NOW || wake > NOW + 10_000_000 {
        return TestResult::Fail("infinite serial poll has no prompt scheduler recheck");
    }
    // A short caller timeout wins; a long timeout is a retry deadline,
    // not permission to leave input pending until that timeout expires.
    if poll_wake_deadline(TASK, &fds, NOW + 5_000_000, NOW, arms) != NOW + 5_000_000
        || poll_wake_deadline(TASK, &fds, NOW + 60_000_000_000, NOW, arms) > NOW + 10_000_000
    {
        return TestResult::Fail(
            "serial poll wake ignores the short deadline or sleeps out a long one",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/poll/silent",
    silent_serial_poll_has_bounded_recheck
);

#[derive(Debug)]
struct Provider {
    cell: Option<narf_lib::readiness::Readiness>,
    notifies: bool,
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
    fn readiness_notifies(&self) -> bool {
        self.notifies
    }
    fn poll_deadline(&self) -> Option<u64> {
        self.deadline
    }
}

fn notifying_poll_sets_keep_event_driven_waits() -> TestResult {
    let fixture = Fixture::new();
    for cell in [false, true] {
        let fds = [fixture.install(Arc::new(Provider {
            cell: cell.then(|| narf_lib::readiness::Readiness::new(0)),
            notifies: !cell,
            deadline: None,
        }))];
        let arms = arm_readiness_cells(TASK, &fds, Waker::noop());
        if poll_wake_deadline(TASK, &fds, u64::MAX, NOW, arms) != u64::MAX
            || poll_wake_deadline(TASK, &fds, NOW + 60_000_000_000, NOW, arms)
                != NOW + 60_000_000_000
        {
            return TestResult::Fail("a durable/notifying poll acquired a periodic recheck");
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
    TestResult::Pass
}
kernel_test_in!(
    "userspace/poll/silent",
    notifying_poll_sets_keep_event_driven_waits
);

fn mixed_poll_preserves_timer_and_silent_source_deadlines() -> TestResult {
    let fixture = Fixture::new();
    let silent = fixture.install(Arc::new(Provider {
        cell: None,
        notifies: false,
        deadline: None,
    }));
    let cell = fixture.install(Arc::new(Provider {
        cell: Some(narf_lib::readiness::Readiness::new(0)),
        notifies: false,
        deadline: None,
    }));
    let timer = fixture.install(Arc::new(Provider {
        cell: None,
        notifies: false,
        deadline: Some(NOW + 5_000_000),
    }));
    let fds = [silent, cell];
    let arms = arm_readiness_cells(TASK, &fds, Waker::noop());
    if poll_wake_deadline(TASK, &fds, u64::MAX, NOW, arms) != NOW + 10_000_000 {
        return TestResult::Fail("a mixed poll stranded its silent descriptor");
    }
    let fds = [silent, cell, timer];
    let arms = arm_readiness_cells(TASK, &fds, Waker::noop());
    if poll_wake_deadline(TASK, &fds, u64::MAX, NOW, arms) != NOW + 5_000_000
        || poll_wake_deadline(TASK, &fds, NOW + 1_000_000, NOW, arms) != NOW + 1_000_000
    {
        return TestResult::Fail("poll recheck delayed an earlier timer or application timeout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/poll/silent",
    mixed_poll_preserves_timer_and_silent_source_deadlines
);
