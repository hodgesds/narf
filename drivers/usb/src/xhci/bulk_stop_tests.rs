use super::super::{
    bulk_owner::{self, Direction, Endpoint, State},
    event_wait,
};
use super::*;
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::{
    future::Future,
    task::{Context as TaskContext, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestError {
    Stop(Error),
    Hardware,
}
impl From<Error> for TestError {
    fn from(e: Error) -> Self {
        Self::Stop(e)
    }
}
struct Model {
    state: State,
    context: Context,
    ops: Vec<[u32; 4]>,
    queue: VecDeque<[u32; 4]>,
    enq: usize,
    cycle: u32,
    pause: usize,
    fail: usize,
    bad_pointer: bool,
    commits: usize,
}
struct Fake(IrqSafeSpinLock<Model>);
impl Fake {
    fn new(enq: usize, cycle: u32) -> (Self, Token) {
        let mut state = State::new();
        let token = state
            .begin(
                Endpoint {
                    generation: 9,
                    slot: 2,
                    dci: 3,
                },
                Direction::In,
                4096,
                || 0x1000,
            )
            .unwrap();
        (
            Self(IrqSafeSpinLock::new(Model {
                state,
                context: Context {
                    state: 1,
                    dequeue: 0x1001,
                },
                ops: Vec::new(),
                queue: VecDeque::new(),
                enq,
                cycle,
                pause: 0,
                fail: 0,
                bad_pointer: false,
                commits: 0,
            })),
            token,
        )
    }
}
impl Bus for Fake {
    type Error = TestError;
    fn claim(&self, token: &Token) -> Result<Plan, TestError> {
        let mut m = self.0.lock();
        let id = m
            .state
            .begin_stop(9, token)
            .map_err(|_| TestError::Hardware)?;
        Ok(Plan::new(id, 0x1000, 64, m.enq, m.cycle)?)
    }
    async fn command(&self, words: [u32; 4]) -> Result<(), TestError> {
        let pause = {
            let mut m = self.0.lock();
            m.ops.push(words);
            let phase = m.ops.len();
            if m.fail == phase {
                return Err(TestError::Hardware);
            }
            if words[3] >> 10 & 63 == 15 {
                m.context.state = 3;
                let fse = [0x1010, 0, 27u32 << 24, 32 << 10 | 2 << 24 | 3 << 16];
                if !m.state.record(fse) {
                    event_wait::enqueue(&mut m.queue, fse);
                }
            } else {
                m.context.dequeue = u64::from(words[0]) | u64::from(words[1]) << 32;
                if m.bad_pointer {
                    m.context.dequeue ^= 16;
                }
            }
            m.pause == phase
        };
        if pause {
            core::future::pending::<()>().await;
        }
        Ok(())
    }
    fn context(&self, _: &Plan) -> Result<Context, TestError> {
        Ok(self.0.lock().context)
    }
    fn purge_events(&self, _: &Plan) -> Result<(), TestError> {
        self.0.lock().queue.clear();
        Ok(())
    }
    fn commit(&self, p: Plan) -> Result<(), TestError> {
        let mut m = self.0.lock();
        m.state
            .finish_stop(p.identity)
            .map_err(|_| TestError::Hardware)?;
        m.enq = p.enqueue;
        m.cycle = p.cycle;
        m.commits += 1;
        Ok(())
    }
}
fn smoke_usb_bulk_stop_exact_commands_and_successor_quarantine() -> TestResult {
    let (bus, token) = Fake::new(1, 1);
    if narf_scheduler::block_on(run(&bus, &token)).is_err() {
        return TestResult::Fail("Stop+SetDequeue failed");
    }
    let m = bus.0.lock();
    if m.ops
        != [
            [0, 0, 0, 15 << 10 | 2 << 24 | 3 << 16],
            [0x1011, 0, 0, 16 << 10 | 2 << 24 | 3 << 16],
        ]
        || m.state.active()
        || !m.queue.is_empty()
        || m.commits != 1
    {
        return TestResult::Fail(
            "successor FSE escaped quarantine or exact command sequence wrong",
        );
    }
    if m.state.validate(9, &token) != Err(bulk_owner::Error::Stale) {
        return TestResult::Fail("cancelled receipt remained valid");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/bulk_stop",
    smoke_usb_bulk_stop_exact_commands_and_successor_quarantine
);
fn smoke_usb_bulk_stop_link_cycle_canonicalization() -> TestResult {
    for cycle in [0, 1] {
        let (bus, token) = Fake::new(63, cycle);
        narf_scheduler::block_on(run(&bus, &token)).unwrap();
        let m = bus.0.lock();
        if m.enq != 0 || m.cycle != cycle ^ 1 || m.ops[1][0] != 0x1000 | cycle ^ 1 {
            return TestResult::Fail("SetDequeue target/cycle pointed at stale Link boundary");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/bulk_stop",
    smoke_usb_bulk_stop_link_cycle_canonicalization
);
fn smoke_usb_bulk_stop_cancellation_after_each_command_retains_claim() -> TestResult {
    for phase in 1..=2 {
        let (bus, token) = Fake::new(1, 1);
        bus.0.lock().pause = phase;
        {
            let mut future = Box::pin(run(&bus, &token));
            if !matches!(
                future
                    .as_mut()
                    .poll(&mut TaskContext::from_waker(Waker::noop())),
                Poll::Pending
            ) {
                return TestResult::Fail(
                    "actual stop/setdeq publication did not precede pending future",
                );
            }
        }
        let mut m = bus.0.lock();
        let before = m.ops.len();
        if m.commits != 0
            || !m.state.active()
            || m.state.validate(9, &token) != Err(bulk_owner::Error::Busy)
        {
            return TestResult::Fail("dropped stop released retained TD/page");
        }
        let mut published = false;
        if m.state
            .begin(
                Endpoint {
                    generation: 9,
                    slot: 2,
                    dci: 3,
                },
                Direction::In,
                4096,
                || {
                    published = true;
                    0x1010
                },
            )
            .is_ok()
            || published
            || m.ops.len() != before
        {
            return TestResult::Fail("cancelled stop allowed scratch/ring reuse");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/bulk_stop",
    smoke_usb_bulk_stop_cancellation_after_each_command_retains_claim
);
fn smoke_usb_bulk_stop_error_or_bad_context_never_commits() -> TestResult {
    for phase in 0..=2 {
        let (bus, token) = Fake::new(1, 1);
        {
            let mut m = bus.0.lock();
            m.fail = phase;
            m.bad_pointer = phase == 0;
        }
        if narf_scheduler::block_on(run(&bus, &token)).is_ok() {
            return TestResult::Fail("failed stop/setdeq/context reported success");
        }
        let m = bus.0.lock();
        if !m.state.active()
            || m.commits != 0
            || m.state.validate(9, &token) != Err(bulk_owner::Error::Busy)
        {
            return TestResult::Fail("failed reclamation released DMA claim");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/bulk_stop",
    smoke_usb_bulk_stop_error_or_bad_context_never_commits
);
