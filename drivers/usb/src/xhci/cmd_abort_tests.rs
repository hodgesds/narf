//! Fixture tests for the command-ring abort (Linux
//! `xhci_handle_command_timeout` / `xhci_abort_cmd_ring` /
//! `xhci_handle_stopped_cmd_ring`). The fake executes its command ring
//! in order from the dequeue pointer, as an xHC does, so a command it
//! cannot finish — an Address Device whose SET_ADDRESS a hung device
//! never acknowledges — blocks every command queued behind it. The
//! receipts are the production `Commands`, fed the completions the fake
//! posts.
use super::super::completion::{Commands, Conflict};
use super::super::event_wait;
use super::*;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU64, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

const RING: u64 = 0x8000;
const ENTRIES: usize = 8;
const ENABLE_SLOT: u32 = 9;
const ADDRESS_DEVICE: u32 = 11;
const CONFIGURE_ENDPOINT: u32 = 12;
/// Slot the modelled Enable Slot hands out.
const NEW_SLOT: u8 = 3;

fn pointer(entry: usize) -> u64 {
    RING + entry as u64 * 16
}

fn completion(pointer: u64, code: u8, slot: u8) -> [u32; 4] {
    [
        pointer as u32,
        (pointer >> 32) as u32,
        u32::from(code) << 24,
        33 << 10 | u32::from(slot) << 24,
    ]
}

struct Model {
    commands: Commands,
    /// Command TRB type per ring entry, as the controller would fetch it.
    trbs: [u32; ENTRIES],
    slots: [u8; ENTRIES],
    enqueue: usize,
    dequeue: usize,
    /// CRCR.CRR.
    running: bool,
    /// Ring entry the controller cannot complete.
    stuck: Option<usize>,
    /// The controller ignores CRCR.CA (its abort never stops the ring).
    deaf: bool,
    events: VecDeque<[u32; 4]>,
    aborts: usize,
    noops: usize,
    fatal: usize,
}

struct Fake {
    model: IrqSafeSpinLock<Model>,
    clock_ms: AtomicU64,
}

impl Fake {
    fn new(stuck: Option<usize>) -> Self {
        Self {
            model: IrqSafeSpinLock::new(Model {
                commands: Commands::new(ENTRIES),
                trbs: [0; ENTRIES],
                slots: [0; ENTRIES],
                enqueue: 0,
                dequeue: 0,
                running: false,
                stuck,
                deaf: false,
                events: VecDeque::new(),
                aborts: 0,
                noops: 0,
                fatal: 0,
            }),
            clock_ms: AtomicU64::new(0),
        }
    }

    /// Publish a command at the enqueue pointer and ring the doorbell.
    fn submit(&self, kind: u32, slot: u8) -> u64 {
        let mut m = self.model.lock();
        let entry = m.enqueue;
        m.commands.reserve(entry, pointer(entry), slot).unwrap();
        m.trbs[entry] = kind;
        m.slots[entry] = slot;
        m.enqueue += 1;
        Self::execute(&mut m);
        pointer(entry)
    }

    /// The controller after a doorbell: run commands in ring order until
    /// the ring is empty or a command cannot finish.
    fn execute(m: &mut Model) {
        m.running = true;
        while m.dequeue < m.enqueue {
            let entry = m.dequeue;
            let kind = m.trbs[entry];
            if m.stuck == Some(entry) && kind != TRB_NO_OP_COMMAND {
                return;
            }
            let slot = match kind {
                TRB_NO_OP_COMMAND => 0,
                ENABLE_SLOT => NEW_SLOT,
                _ => m.slots[entry],
            };
            m.events.push_back(completion(pointer(entry), 1, slot));
            m.dequeue += 1;
        }
    }

    /// The demux: hand every posted completion to the receipts.
    fn deliver(m: &mut Model) {
        while let Some(event) = m.events.pop_front() {
            m.commands.record(event);
        }
    }
}

impl Bus for Fake {
    fn ring_running(&self) -> bool {
        self.model.lock().running
    }
    fn write_abort(&self) {
        let mut m = self.model.lock();
        m.aborts += 1;
        if m.deaf || !m.running {
            return;
        }
        // xHCI 1.2 §4.6.1.2: the executing command completes with
        // Command Aborted, then Command Ring Stopped names the dequeue
        // pointer and CRR clears.
        if m.dequeue < m.enqueue {
            let entry = m.dequeue;
            m.events
                .push_back(completion(pointer(entry), CC_COMMAND_ABORTED, 0));
            m.dequeue += 1;
        }
        let dequeue = m.dequeue;
        m.events
            .push_back(completion(pointer(dequeue), CC_COMMAND_RING_STOPPED, 0));
        m.running = false;
    }
    fn take_ring_stopped(&self) -> bool {
        let mut m = self.model.lock();
        Self::deliver(&mut m);
        m.commands.take_ring_stopped()
    }
    fn noop_abandoned(&self) -> usize {
        let mut m = self.model.lock();
        let entries = m.commands.abandoned_entries();
        for &entry in &entries {
            m.trbs[entry] = TRB_NO_OP_COMMAND;
        }
        m.noops += entries.len();
        entries.len()
    }
    fn restart(&self) {
        let mut m = self.model.lock();
        if m.commands.active() {
            Self::execute(&mut m);
        }
    }
    fn fatal(&self) {
        self.model.lock().fatal += 1;
    }
    fn now_ms(&self) -> u64 {
        self.clock_ms.load(Ordering::Acquire)
    }
    async fn pause(&self) {
        self.clock_ms.fetch_add(1, Ordering::AcqRel);
    }
}

/// A hung device: its Address Device never completes and two commands
/// queue behind it — a Configure Endpoint whose waiter also gives up and
/// a live Enable Slot. Both timed-out entries stay reserved (the
/// controller may still fetch them); the abort stops the ring, the
/// abandoned Configure Endpoint becomes a No Op, the ring restarts and
/// the Enable Slot completes. Every entry is released afterwards.
fn smoke_xhci_command_timeout_aborts_ring_and_restarts() -> TestResult {
    let bus = Fake::new(Some(0));
    let address = bus.submit(ADDRESS_DEVICE, 4);
    let configure = bus.submit(CONFIGURE_ENDPOINT, 4);
    let enable = bus.submit(ENABLE_SLOT, 0);
    let take_enable = |m: &mut Model| {
        m.commands
            .take_matching(&mut |event| event_wait::command_pointer_matches(event, enable))
    };
    {
        let mut m = bus.model.lock();
        Fake::deliver(&mut m);
        if take_enable(&mut m) != Ok(None) {
            return TestResult::Fail("a command completed behind a stuck one");
        }
        // Both waiters time out (250 ms) and give their receipts up.
        if !m.commands.retire_pointer(address) || !m.commands.retire_pointer(configure) {
            return TestResult::Fail("timed-out receipts were not abandoned");
        }
        if m.commands.reserve(0, address, 4) != Err(Conflict) {
            return TestResult::Fail("timed-out entry was reusable while the controller held it");
        }
    }
    let outcome = narf_scheduler::block_on(handle_timeout(&bus, ADDRESS_DEVICE));
    let mut m = bus.model.lock();
    if outcome != Outcome::Restarted || m.aborts != 1 || m.fatal != 0 {
        return TestResult::Fail("command timeout did not abort the command ring");
    }
    if m.noops != 1 || m.trbs[1] != TRB_NO_OP_COMMAND {
        return TestResult::Fail("abandoned queued command was not turned into a No Op");
    }
    Fake::deliver(&mut m);
    match take_enable(&mut m) {
        Ok(Some(event)) if (event[2] >> 24) as u8 == 1 && (event[3] >> 24) as u8 == NEW_SLOT => {}
        _ => return TestResult::Fail("Enable Slot behind the aborted command did not complete"),
    }
    if m.commands.active()
        || m.commands.reserve(0, address, 4) != Ok(())
        || m.commands.reserve(1, configure, 4) != Ok(())
    {
        return TestResult::Fail("aborted and No Op entries were not released");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci/cmd_abort",
    smoke_xhci_command_timeout_aborts_ring_and_restarts
);

/// A Stop Endpoint that never completes is controller-fatal (Linux
/// "xHCI host not responding to stop endpoint command": `xhci_halt` +
/// `xhci_hc_died`): recovery is requested and the ring is not aborted.
fn smoke_xhci_stop_endpoint_timeout_is_controller_fatal() -> TestResult {
    let bus = Fake::new(Some(0));
    let stop = bus.submit(TRB_STOP_ENDPOINT, 4);
    bus.model.lock().commands.retire_pointer(stop);
    let outcome = narf_scheduler::block_on(handle_timeout(&bus, TRB_STOP_ENDPOINT));
    let m = bus.model.lock();
    if outcome != Outcome::Fatal || m.fatal != 1 || m.aborts != 0 {
        return TestResult::Fail("Stop Endpoint timeout did not request controller recovery");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci/cmd_abort",
    smoke_xhci_stop_endpoint_timeout_is_controller_fatal
);

/// An abort that never clears CRR is a dead controller (Linux "Abort
/// failed to stop command ring"): bounded by the 5 s handshake, then
/// recovery is requested.
fn smoke_xhci_abort_that_never_stops_requests_recovery() -> TestResult {
    let bus = Fake::new(Some(0));
    bus.model.lock().deaf = true;
    let address = bus.submit(ADDRESS_DEVICE, 4);
    bus.model.lock().commands.retire_pointer(address);
    let outcome = narf_scheduler::block_on(handle_timeout(&bus, ADDRESS_DEVICE));
    let m = bus.model.lock();
    if outcome != Outcome::Fatal || m.fatal != 1 || m.aborts != 1 {
        return TestResult::Fail("a ring that ignored the abort did not request recovery");
    }
    if bus.now_ms() < ABORT_HANDSHAKE_MS || bus.now_ms() > ABORT_HANDSHAKE_MS + 1 {
        return TestResult::Fail("the abort handshake was not bounded at 5 s");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci/cmd_abort",
    smoke_xhci_abort_that_never_stops_requests_recovery
);
