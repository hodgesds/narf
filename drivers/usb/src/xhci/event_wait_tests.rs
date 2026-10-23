use super::*;
use alloc::collections::VecDeque;
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Source {
    queued: [VecDeque<Event>; 2],
    hardware: VecDeque<Event>,
    demuxed: usize,
    overflowed: usize,
}
impl Source {
    fn new() -> Self {
        Self {
            queued: [VecDeque::new(), VecDeque::new()],
            hardware: VecDeque::new(),
            demuxed: 0,
            overflowed: 0,
        }
    }
    fn take(&mut self, target: Event) -> Option<Event> {
        for queue in &mut self.queued {
            if let Some(event) = take_matching(queue, &mut |event| *event == target) {
                return Some(event);
            }
        }
        None
    }
    fn push(&mut self, event: Event) {
        let class = usize::from(event[3] & (0x3f << 10) == 32 << 10);
        self.overflowed += usize::from(enqueue(&mut self.queued[class], event));
    }
    fn demux(&mut self) -> bool {
        let Some(event) = self.hardware.pop_front() else {
            return false;
        };
        self.demuxed += 1;
        self.push(event);
        true
    }
}
fn completion(kind: u32, identity: u32) -> Event {
    [identity * 16, 0, 1 << 24, kind << 10 | 5 << 24]
}

fn smoke_xhci_waiter_matches_before_peer_queue_pressure() -> TestResult {
    for kind in [32, 33] {
        let target = completion(kind, 1000);
        let source = RefCell::new(Source::new());
        {
            let mut source = source.borrow_mut();
            // Start with the actual 64-entry policy already at capacity.
            for peer in 0..QUEUE_DEPTH {
                source.push(completion(kind, peer as u32));
            }
            source.hardware.push_back(target);
            for peer in 0..(QUEUE_DEPTH * 3) {
                source
                    .hardware
                    .push_back(completion(kind, peer as u32 + 2000));
            }
        }
        let result = poll_batch(
            || Ok::<_, ()>(source.borrow_mut().take(target)),
            || source.borrow_mut().demux(),
            || false,
        );
        let source = source.borrow();
        if result != Ok(Some(target))
            || source.demuxed != 1
            || source.overflowed != 1
            || source.hardware.len() != QUEUE_DEPTH * 3
        {
            return TestResult::Fail("USB waiter drained peers past its own completion");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_waiter_matches_before_peer_queue_pressure
);

fn smoke_xhci_waiter_continuous_producer_yields_and_checks_deadline() -> TestResult {
    let source = RefCell::new(Source::new());
    let target = completion(33, 1000);
    let polls = Cell::new(0usize);
    let expired = Cell::new(false);
    let demux = || {
        polls.set(polls.get() + 1);
        source.borrow_mut().push(completion(33, polls.get() as u32));
        true // Hardware never runs out of unrelated events.
    };
    let result = poll_batch(
        || Ok::<_, ()>(source.borrow_mut().take(target)),
        demux,
        || expired.get(),
    );
    if result != Ok(None) || polls.get() != DRAIN_BUDGET {
        return TestResult::Fail("continuous USB events prevented bounded executor return");
    }
    let result = poll_batch(
        || Ok::<_, ()>(source.borrow_mut().take(target)),
        || {
            polls.set(polls.get() + 1);
            source.borrow_mut().push(completion(33, polls.get() as u32));
            if polls.get() == DRAIN_BUDGET + 5 {
                expired.set(true);
            }
            true
        },
        || expired.get(),
    );
    if result != Err(PollError::TimedOut) || polls.get() != DRAIN_BUDGET + 5 {
        return TestResult::Fail("continuous USB events starved the waiter deadline");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_waiter_continuous_producer_yields_and_checks_deadline
);

fn smoke_xhci_waiter_preserves_peers_and_final_batch_completion() -> TestResult {
    let source = RefCell::new(Source::new());
    let target = completion(32, 1000);
    let peer = completion(33, 42);
    {
        let mut source = source.borrow_mut();
        source.push(peer);
        for index in 0..DRAIN_BUDGET - 1 {
            source.hardware.push_back(completion(32, index as u32));
        }
        source.hardware.push_back(target);
    }
    let result = poll_batch(
        || Ok::<_, ()>(source.borrow_mut().take(target)),
        || source.borrow_mut().demux(),
        || false,
    );
    if result != Ok(Some(target))
        || source.borrow().demuxed != DRAIN_BUDGET
        || source.borrow_mut().take(peer) != Some(peer)
    {
        return TestResult::Fail("last batch completion/other waiter's event was lost");
    }
    source.borrow_mut().push(target);
    let result = poll_batch(
        || Ok::<_, ()>(source.borrow_mut().take(target)),
        || panic!("queued completion must precede new hardware polling"),
        || true,
    );
    if result != Ok(Some(target)) {
        return TestResult::Fail("already queued terminal event was hidden by timeout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_waiter_preserves_peers_and_final_batch_completion
);
