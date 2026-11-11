//! Fixture tests for the EP0 timeout-cancellation coordinator. The fake
//! bus models what the coordinator can observe of a controller: the EP0
//! output-context state/dequeue, command completion codes, and the
//! Transfer Events a Stop Endpoint forces. The MMIO side reuses the
//! command/await machinery the live QEMU gates already exercise.
use super::super::{bulk_owner::ControlState, bulk_owner::Error as OwnerError, event_wait};
use super::*;
use alloc::{collections::VecDeque, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

const SLOT: u8 = 5;
const GENERATION: u64 = 42;
const RING: u64 = 0x1000;
const SETUP: u64 = RING;
const DATA: u64 = RING + 16;
const STATUS: u64 = RING + 32;
/// Enqueue cursor after the three-TRB TD, producer cycle 1.
const ENQUEUE: usize = 3;
const TARGET: u64 = (RING + 48) | 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestError {
    Cancel(Error),
    Owner(OwnerError),
    Hardware,
}
impl From<Error> for TestError {
    fn from(error: Error) -> Self {
        Self::Cancel(error)
    }
}

fn transfer(pointer: u64, code: u8) -> event_wait::Event {
    [
        pointer as u32,
        (pointer >> 32) as u32,
        u32::from(code) << 24,
        32 << 10 | 1 << 16 | u32::from(SLOT) << 24,
    ]
}

struct Model {
    control: ControlState,
    context: Context,
    ops: Vec<[u32; 4]>,
    queue: VecDeque<event_wait::Event>,
    enq: usize,
    cycle: u32,
    /// The endpoint halts on a late error before Stop Endpoint executes.
    halts_before_stop: bool,
    /// 1-based command index that fails at the transport level.
    fail: usize,
    commits: usize,
}
struct Fake(IrqSafeSpinLock<Model>);
impl Fake {
    /// A published Setup/Data/Status TD that never completed.
    fn timed_out(state: u8) -> Self {
        let mut control = ControlState::new();
        control.begin(GENERATION, GENERATION).unwrap();
        control.expect_setup(SETUP).unwrap();
        control.expect(DATA).unwrap();
        control.expect(STATUS).unwrap();
        Self(IrqSafeSpinLock::new(Model {
            control,
            context: Context {
                state,
                dequeue: SETUP | 1,
            },
            ops: Vec::new(),
            queue: VecDeque::new(),
            enq: ENQUEUE,
            cycle: 1,
            halts_before_stop: false,
            fail: 0,
            commits: 0,
        }))
    }
    fn deliver(model: &mut Model, event: event_wait::Event) {
        if !model.control.record(SLOT, event) {
            event_wait::enqueue(&mut model.queue, event);
        }
    }
}
impl Bus for Fake {
    type Error = TestError;
    fn claim(&self) -> Result<Plan, TestError> {
        let mut m = self.0.lock();
        m.control
            .begin_cancel(GENERATION, GENERATION)
            .map_err(TestError::Owner)?;
        Ok(Plan {
            slot: SLOT,
            generation: GENERATION,
            target: (RING + m.enq as u64 * 16) | u64::from(m.cycle),
            enqueue: m.enq,
            cycle: m.cycle,
        })
    }
    async fn command(&self, words: [u32; 4]) -> Result<u8, TestError> {
        let mut m = self.0.lock();
        m.ops.push(words);
        if m.fail == m.ops.len() {
            return Err(TestError::Hardware);
        }
        match words[3] >> 10 & 63 {
            15 if m.halts_before_stop => {
                // xHCI 1.2 §4.6.9: Stop Endpoint on a Halted endpoint
                // fails with Context State Error. The halting Transfer
                // Event names the Setup TRB.
                m.context.state = 2;
                Self::deliver(&mut m, transfer(SETUP, 4));
                Ok(19)
            }
            15 => {
                m.context.state = 3;
                // Forced events: Stopped (26) on the TD's own TRB, and
                // Stopped - Length Invalid (27) at a pointer no latch
                // names. Neither may reach the lossy shared queue.
                Self::deliver(&mut m, transfer(DATA, 26));
                Self::deliver(&mut m, transfer(RING + 48, 27));
                Ok(1)
            }
            14 => {
                m.context.state = 3;
                Ok(1)
            }
            _ => {
                m.context.dequeue = u64::from(words[0]) | u64::from(words[1]) << 32;
                Ok(1)
            }
        }
    }
    fn context(&self, _: &Plan) -> Result<Context, TestError> {
        Ok(self.0.lock().context)
    }
    fn commit(&self, plan: Plan) -> Result<(), TestError> {
        let mut m = self.0.lock();
        m.queue.clear();
        m.control.force_reset();
        m.enq = plan.enqueue;
        m.cycle = plan.cycle;
        m.commits += 1;
        Ok(())
    }
}

fn words(kind: u32, dequeue: u64) -> [u32; 4] {
    [
        dequeue as u32,
        (dequeue >> 32) as u32,
        0,
        kind << 10 | u32::from(SLOT) << 24 | 1 << 16,
    ]
}

/// Defect 3: after a control stage wait expires, Stop Endpoint + Set TR
/// Dequeue Pointer retire the TD, the EP0 claim is released, and the next
/// control transfer is accepted (`begin` + its three TRB receipts).
fn smoke_xhci_control_timeout_cancel_releases_ep0() -> TestResult {
    let bus = Fake::timed_out(1);
    {
        // The stage wait itself: nothing ever arrives, the deadline fires.
        let mut m = bus.0.lock();
        let waited =
            event_wait::poll_batch(|| m.control.take_matching(&mut |_| true), || false, || true);
        if waited != Err(event_wait::PollError::TimedOut) {
            return TestResult::Fail("silent control TD did not time out");
        }
        if m.control.begin(GENERATION, GENERATION) != Err(OwnerError::Busy) {
            return TestResult::Fail("timed-out TD did not hold the EP0 claim");
        }
    }
    if narf_scheduler::block_on(run(&bus)) != Ok(()) {
        return TestResult::Fail("EP0 Stop+SetDequeue cancellation failed");
    }
    let mut m = bus.0.lock();
    if m.ops != [words(15, 0), words(16, TARGET)] {
        return TestResult::Fail("cancel did not issue exactly Stop Endpoint + Set TR Dequeue");
    }
    if !m.queue.is_empty() || m.commits != 1 || m.enq != ENQUEUE || m.cycle != 1 {
        return TestResult::Fail("forced EP0 events escaped quarantine or cursor not committed");
    }
    if m.control.active() {
        return TestResult::Fail("EP0 claim still busy after cancellation");
    }
    // The following transfer is accepted and owns fresh receipts.
    if m.control.begin(GENERATION, GENERATION) != Ok(())
        || m.control.expect_setup(RING + 48) != Ok(())
        || m.control.expect(RING + 64) != Ok(())
        || m.control.expect(RING + 80) != Ok(())
    {
        return TestResult::Fail("control transfer after a cancelled timeout was refused");
    }
    // A late event for the cancelled TD cannot satisfy the new transfer.
    if m.control.record(SLOT, transfer(DATA, 1)) {
        return TestResult::Fail("cancelled TD's late event latched into the next transfer");
    }
    let status = transfer(RING + 80, 1);
    let data = transfer(RING + 64, 1);
    if !m.control.record(SLOT, data)
        || !m.control.record(SLOT, status)
        || m.control.take_matching(&mut |event| *event == data) != Ok(Some(data))
        || m.control.take_matching(&mut |event| *event == status) != Ok(Some(status))
        || m.control.complete(GENERATION, GENERATION) != Ok(())
    {
        return TestResult::Fail("control transfer after a cancelled timeout did not complete");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_control_timeout_cancel_releases_ep0
);

/// A TD that timed out because its error event was lost leaves EP0
/// Halted: Stop Endpoint would fail, so the coordinator goes straight to
/// Reset Endpoint (Linux `xhci_handle_halted_endpoint`).
fn smoke_xhci_control_cancel_resets_halted_ep0() -> TestResult {
    let bus = Fake::timed_out(2);
    if narf_scheduler::block_on(run(&bus)) != Ok(()) {
        return TestResult::Fail("halted EP0 cancellation failed");
    }
    {
        let m = bus.0.lock();
        if m.ops != [words(14, 0), words(16, TARGET)] || m.control.active() {
            return TestResult::Fail("halted EP0 was not recovered by Reset + Set TR Dequeue");
        }
    }
    // The endpoint halts between the readback and Stop Endpoint: the
    // command reports Context State Error and the readback routes to
    // Reset Endpoint (Linux `xhci_handle_cmd_stop_ep`).
    let bus = Fake::timed_out(1);
    bus.0.lock().halts_before_stop = true;
    if narf_scheduler::block_on(run(&bus)) != Ok(()) {
        return TestResult::Fail("Stop/halt race cancellation failed");
    }
    let m = bus.0.lock();
    if m.ops != [words(15, 0), words(14, 0), words(16, TARGET)]
        || m.control.active()
        || !m.queue.is_empty()
    {
        return TestResult::Fail("Context State Error on Stop did not fall back to Reset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_control_cancel_resets_halted_ep0
);

/// A cancellation that cannot prove the endpoint stopped keeps the claim
/// closed and the quarantine up: a possibly-live ring is never reopened.
fn smoke_xhci_control_cancel_failure_retains_claim() -> TestResult {
    for fail in [1, 2] {
        let bus = Fake::timed_out(1);
        bus.0.lock().fail = fail;
        if narf_scheduler::block_on(run(&bus)) != Err(TestError::Hardware) {
            return TestResult::Fail("failed cancel command was not reported");
        }
        let mut m = bus.0.lock();
        if !m.control.active()
            || m.commits != 0
            || m.control.begin(GENERATION, GENERATION) != Err(OwnerError::Busy)
            || !m.control.record(SLOT, transfer(RING + 96, 1))
            || m.control.take_matching(&mut |_| true) != Ok(None)
        {
            return TestResult::Fail("failed cancellation reopened EP0");
        }
    }
    // An endpoint that is neither Running, Halted nor Stopped is refused.
    let bus = Fake::timed_out(0);
    if narf_scheduler::block_on(run(&bus)) != Err(TestError::Cancel(Error::State)) {
        return TestResult::Fail("disabled EP0 context was accepted");
    }
    let m = bus.0.lock();
    if !m.ops.is_empty() || !m.control.active() {
        return TestResult::Fail("cancel published a command against a disabled endpoint");
    }
    // An idle pipe has nothing to cancel and publishes nothing.
    let mut idle = ControlState::new();
    if idle.begin_cancel(GENERATION, GENERATION) != Err(OwnerError::Stale) || idle.active() {
        return TestResult::Fail("idle EP0 accepted a cancellation claim");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_control_cancel_failure_retains_claim
);
