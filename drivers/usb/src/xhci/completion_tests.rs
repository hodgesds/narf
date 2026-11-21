use super::super::{
    bulk_owner::{ControlState, Direction, Endpoint, Error, State},
    event_wait,
};
use super::*;
use alloc::collections::VecDeque;
use narf_kernel_test::{kernel_test_in, TestResult};

fn transfer(slot: u8, dci: u8, pointer: u64, code: u8, residue: u32) -> Event {
    [
        pointer as u32,
        (pointer >> 32) as u32,
        u32::from(code) << 24 | residue,
        32 << 10 | u32::from(dci) << 16 | u32::from(slot) << 24,
    ]
}
fn command(pointer: u64) -> Event {
    [
        pointer as u32,
        (pointer >> 32) as u32,
        1 << 24,
        33 << 10 | 5 << 24,
    ]
}

fn smoke_xhci_owned_bulk_completion_survives_isr_queue_overflow() -> TestResult {
    let mut owner = State::new();
    let token = owner
        .begin(
            Endpoint {
                generation: 42,
                slot: 5,
                dci: 3,
            },
            Direction::In,
            512,
            || 0x1000,
        )
        .unwrap();
    let target = transfer(5, 3, 0x1000, 13, 12);
    let mut queue = VecDeque::new();
    let mut overflowed = 0;
    // Route a whole ISR burst, with no waiter polls between the completions.
    // Each exact owner record runs before the production shared queue policy.
    for index in 0..257 {
        let event = if index == 0 {
            target
        } else {
            transfer(6, 3, 0x2000 + index * 16, 1, 0)
        };
        if !owner.record(event) {
            overflowed += usize::from(event_wait::enqueue(&mut queue, event));
        }
    }
    if queue.len() != event_wait::QUEUE_DEPTH || overflowed == 0 {
        return TestResult::Fail("bulk latch regression did not overflow the shared queue");
    }
    let event = owner.take_matching(&mut |event| token.matches(event));
    if event != Ok(Some(target)) || owner.complete(42, &token, &target, |_| ()) != Ok(Some(500)) {
        return TestResult::Fail("exact bulk terminal event was lost under ISR pressure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_owned_bulk_completion_survives_isr_queue_overflow
);

fn smoke_xhci_ep0_pair_and_command_survive_isr_queue_overflow() -> TestResult {
    let mut control = ControlState::new();
    control.begin(42, 42).unwrap();
    control.expect(0x1000).unwrap();
    control.expect(0x1010).unwrap();
    let data = transfer(5, 1, 0x1000, 13, 4);
    let status = transfer(5, 1, 0x1010, 1, 0);
    let mut commands = Commands::new(8);
    commands.reserve(0, 0x3000, 5).unwrap();
    let command = command(0x3000);
    let mut queue = VecDeque::new();
    for event in [data, status, command] {
        if !(control.record(5, event) || commands.record(event)) {
            return TestResult::Fail("active control/command receipt did not retain own event");
        }
    }
    for index in 0..256 {
        let event = transfer(6, 1, 0x8000 + index * 16, 1, 0);
        if !(control.record(5, event) || commands.record(event)) {
            event_wait::enqueue(&mut queue, event);
        }
    }
    if queue.len() != event_wait::QUEUE_DEPTH
        || control.take_matching(&mut |event| *event == status) != Ok(Some(status))
        || control.take_matching(&mut |event| *event == data) != Ok(Some(data))
        || control.complete(42, 42) != Ok(())
        || commands.take_matching(&mut |event| *event == command) != Ok(Some(command))
        || commands.active()
    {
        return TestResult::Fail("EP0 Data/Status or command was evicted by ISR peers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_ep0_pair_and_command_survive_isr_queue_overflow
);

fn smoke_xhci_owned_completion_duplicates_and_conflicts() -> TestResult {
    let target = transfer(5, 3, 0x1000, 1, 0);
    let mut latch = Latch::new();
    latch.record(target);
    let mut duplicate = target;
    duplicate[3] ^= 1; // Event-ring cycle isn't part of TD identity/result.
    latch.record(duplicate);
    if latch.take_matching(&mut |_| true) != Ok(Some(target))
        || latch.take_matching(&mut |_| true) != Ok(None)
    {
        return TestResult::Fail("identical terminal event was not idempotent");
    }
    let mut owner = State::new();
    let token = owner
        .begin(
            Endpoint {
                generation: 42,
                slot: 5,
                dci: 3,
            },
            Direction::In,
            512,
            || 0x1000,
        )
        .unwrap();
    if !owner.record(target) {
        return TestResult::Fail("own event not retained");
    }
    let mut conflict = target;
    conflict[2] = 6 << 24;
    owner.record(conflict);
    if owner.take_matching(&mut |event| token.matches(event)) != Err(Error::Malformed)
        || !owner.active()
        || owner.complete(42, &token, &target, |_| panic!("conflicted DMA copy"))
            != Err(Error::Malformed)
        || !matches!(
            owner.begin(
                Endpoint {
                    generation: 42,
                    slot: 5,
                    dci: 3
                },
                Direction::In,
                512,
                || panic!("conflicted reuse")
            ),
            Err(Error::Busy)
        )
    {
        return TestResult::Fail("conflicting terminal events reopened DMA ownership");
    }
    let mut commands = Commands::new(1);
    commands.reserve(0, 0x3000, 5).unwrap();
    let good = command(0x3000);
    let mut bad = good;
    bad[2] = 5 << 24;
    commands.record(good);
    commands.record(bad);
    if commands.take_matching(&mut |_| true) != Err(Conflict)
        || commands.reserve(0, 0x4000, 5) != Err(Conflict)
        || !commands.active()
    {
        return TestResult::Fail("conflicting command completion reused ring receipt");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_owned_completion_duplicates_and_conflicts
);

fn smoke_xhci_command_receipt_precedes_publication_and_reuse() -> TestResult {
    let mut commands = Commands::new(1);
    commands.reserve(0, 0x3000, 5).unwrap();
    if commands.reserve(0, 0x3000, 5) != Err(Conflict) {
        return TestResult::Fail("pending command ring entry was overwritten");
    }
    let mut wrong = command(0x3000);
    wrong[3] ^= 1 << 24;
    if commands.record(wrong) || commands.record(command(0x3010)) {
        return TestResult::Fail("foreign command latched into owned receipt");
    }
    let good = command(0x3000);
    commands.record(good);
    commands.record(good);
    if commands.take_matching(&mut |_| true) != Ok(Some(good))
        || commands.active()
        || commands.reserve(0, 0x3000, 5) != Ok(())
    {
        return TestResult::Fail("terminal command did not release receipt exactly once");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_command_receipt_precedes_publication_and_reuse
);

/// `Commands::clear` (controller recovery) drops every retained
/// receipt: nothing stays active, and a recycled ring entry can be
/// reserved again — the stale receipt must not alias its pointer.
fn smoke_xhci_command_receipts_clear_for_recovery() -> TestResult {
    let mut commands = Commands::new(4);
    if commands.reserve(0, 0x3000, 5) != Ok(()) || !commands.active() {
        return TestResult::Fail("receipt did not reserve");
    }
    commands.clear();
    if commands.active() {
        return TestResult::Fail("clear left an active receipt");
    }
    if commands.reserve(0, 0x3000, 5) != Ok(()) || !commands.active() {
        return TestResult::Fail("cleared entry did not reserve again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_command_receipts_clear_for_recovery
);

fn completion(pointer: u64, code: u8, slot: u8) -> Event {
    [
        pointer as u32,
        (pointer >> 32) as u32,
        u32::from(code) << 24,
        33 << 10 | u32::from(slot) << 24,
    ]
}

/// #884: a timed-out waiter abandons its receipt. The command TRB is
/// still on the ring and the controller executes the ring in order, so
/// the entry stays reserved — never reused while the controller may
/// still fetch it — until the controller's completion for it arrives
/// (here Command Aborted after a ring abort, or the No Op it was turned
/// into), which is swallowed and releases the entry. A full small ring
/// then turns over again.
fn smoke_xhci_command_receipt_retires_on_timeout() -> TestResult {
    let mut commands = Commands::new(2);
    if commands.reserve(0, 0x3000, 5) != Ok(()) || !commands.active() {
        return TestResult::Fail("receipt did not reserve");
    }
    if !commands.retire_pointer(0x3000) {
        return TestResult::Fail("timeout did not abandon the receipt");
    }
    if commands.reserve(0, 0x3000, 5) != Err(Conflict) || !commands.active() {
        return TestResult::Fail("abandoned entry was reusable before the controller dequeued it");
    }
    if commands.abandoned_entries() != [0] {
        return TestResult::Fail("abandoned entry not reported for the ring abort");
    }
    // Retiring twice, an unknown pointer, or a consumed receipt is a
    // no-op — never drops a live receipt.
    if commands.retire_pointer(0x3000) || commands.retire_pointer(0x9999) {
        return TestResult::Fail("retire claimed an abandoned or unknown pointer");
    }
    // Command Aborted (slot 0) for the abandoned TRB releases it.
    if !commands.record(completion(0x3000, 25, 0)) || commands.active() {
        return TestResult::Fail("aborted completion did not release the abandoned entry");
    }
    if commands.reserve(0, 0x3000, 5) != Ok(()) {
        return TestResult::Fail("released entry did not reserve again");
    }
    commands.reserve(1, 0x3010, 5).unwrap();
    commands.record(command(0x3010));
    if commands.take_matching(&mut |_| true) != Ok(Some(command(0x3010))) {
        return TestResult::Fail("consumed receipt did not release");
    }
    if commands.retire_pointer(0x3010) {
        return TestResult::Fail("retire dropped an already-consumed receipt");
    }
    // Commands execute in ring order: a completion for a later command
    // releases an abandoned earlier one whose own completion was lost.
    commands.reserve(1, 0x3010, 5).unwrap();
    commands.retire_pointer(0x3000);
    commands.record(command(0x3010));
    if commands.reserve(0, 0x3000, 5) != Ok(()) {
        return TestResult::Fail("an executed abandoned command kept its entry after a lost CCE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_command_receipt_retires_on_timeout
);

/// #884: a CCE that arrives after its waiter timed out is swallowed at
/// the demux instead of landing in the lossy command-event queue, and
/// no waiter can take it. Once it released the entry, the next command
/// on that entry latches its own CCE normally.
fn smoke_xhci_late_cce_after_retire_is_swallowed() -> TestResult {
    let mut commands = Commands::new(1);
    commands.reserve(0, 0x3000, 5).unwrap();
    if !commands.retire_pointer(0x3000) {
        return TestResult::Fail("retire did not abandon the receipt");
    }
    if commands.take_matching(&mut |_| true) != Ok(None) {
        return TestResult::Fail("an abandoned receipt was takeable");
    }
    if !commands.record(command(0x3000)) {
        return TestResult::Fail("late CCE was not swallowed after retire");
    }
    if commands.active() || commands.take_matching(&mut |_| true) != Ok(None) {
        return TestResult::Fail("swallowed CCE left a receipt behind");
    }
    if commands.reserve(0, 0x3000, 5) != Ok(()) {
        return TestResult::Fail("released entry did not reserve again");
    }
    commands.record(command(0x3000));
    if commands.take_matching(&mut |_| true) != Ok(Some(command(0x3000))) {
        return TestResult::Fail("re-reserved entry swallowed its own CCE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_late_cce_after_retire_is_swallowed
);

/// A Command Ring Stopped completion (code 24) names the ring's dequeue
/// pointer — the next command to execute — and completes nothing
/// (Linux `handle_cmd_completion`). It must not latch into the receipt
/// of the live command at that pointer; it is reported to the abort
/// instead, and that command's real completion still arrives.
fn smoke_xhci_command_ring_stopped_completes_no_command() -> TestResult {
    let mut commands = Commands::new(2);
    commands.reserve(0, 0x3000, 0).unwrap();
    if !commands.record(completion(0x3000, 24, 0)) {
        return TestResult::Fail("Command Ring Stopped reached the lossy queue");
    }
    if commands.take_matching(&mut |_| true) != Ok(None) {
        return TestResult::Fail(
            "Command Ring Stopped completed the command at the dequeue pointer",
        );
    }
    if !commands.take_ring_stopped() || commands.take_ring_stopped() {
        return TestResult::Fail("Command Ring Stopped was not reported exactly once");
    }
    let done = completion(0x3000, 1, 3);
    commands.record(done);
    if commands.take_matching(&mut |_| true) != Ok(Some(done)) {
        return TestResult::Fail("the command's own completion was lost after the stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_command_ring_stopped_completes_no_command
);

/// Recovery must drop abandoned receipts along with the live ones:
/// ring pointers repeat after the cursors restart at zero, and a stale
/// abandoned receipt would swallow the recycled entry's own completion.
fn smoke_xhci_clear_drops_retired_pointers() -> TestResult {
    let mut commands = Commands::new(1);
    commands.reserve(0, 0x3000, 5).unwrap();
    commands.retire_pointer(0x3000);
    commands.clear();
    if commands.reserve(0, 0x3000, 5) != Ok(()) {
        return TestResult::Fail("cleared entry did not reserve again");
    }
    commands.record(command(0x3000));
    if commands.take_matching(&mut |_| true) != Ok(Some(command(0x3000))) {
        return TestResult::Fail("stale tombstone swallowed a post-recovery CCE");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_clear_drops_retired_pointers);
