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
