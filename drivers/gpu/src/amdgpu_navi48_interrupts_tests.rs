use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn event(seq: u32) -> ih::Event {
    ih::Event {
        ih_ring: (seq % 2) as u8,
        vector: ih::Vector::decode([0x0000b50a, seq, 0, 0, seq, 0, 0, 0]),
    }
}
fn navi48_interrupt_history_is_bounded_ordered_and_retains_fault_diagnostics() -> TestResult {
    let mut h = History::new();
    assert!(h.pop().is_empty());
    let fault = ih::Event {
        ih_ring: 1,
        vector: ih::Vector::decode([0x8100000a, 1, 0, 3, 0xdead, 0xbeef, 0, 0]),
    };
    h.push(fault);
    for seq in 0..80 {
        h.push(event(seq));
    }
    assert_eq!(h.received, 81);
    assert_eq!(h.evicted, 17);
    assert_eq!(h.vm_faults, 1);
    assert_eq!(h.last_fault, Some(fault));
    let first = h.pop();
    assert!(first.pending);
    for (i, v) in first.events().enumerate() {
        assert_eq!(*v, event(i as u32 + 16));
    }
    let second = h.pop();
    assert!(!second.pending);
    for (i, v) in second.events().enumerate() {
        assert_eq!(*v, event(i as u32 + 48));
    }
    assert!(h.pop().is_empty());
    assert_eq!(h.last_fault, Some(fault));
    for seq in 80..83 {
        h.push(event(seq));
    }
    for (i, v) in h.pop().events().enumerate() {
        assert_eq!(*v, event(i as u32 + 80));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_interrupt_history_is_bounded_ordered_and_retains_fault_diagnostics
);

fn navi48_irq_wait_snapshot_precedes_draining_and_cancellation_cleans_waker() -> TestResult {
    use core::{
        future::Future,
        task::{Context, Waker},
    };
    let vector = narf_interrupts::vector::alloc().unwrap();
    {
        let wait = narf_interrupts::wait_for_irq(vector);
        // Arrival during hardware draining, before first future poll.
        narf_interrupts::on_irq(vector);
        let mut wait = core::pin::pin!(wait);
        assert!(wait
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready());
    }
    {
        let mut wait = core::pin::pin!(narf_interrupts::wait_for_irq(vector));
        assert!(wait
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert_eq!(narf_interrupts::dispatch::wakers_len(vector), 1);
    }
    assert_eq!(narf_interrupts::dispatch::wakers_len(vector), 0);
    narf_interrupts::vector::free(vector).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_irq_wait_snapshot_precedes_draining_and_cancellation_cleans_waker
);

fn navi48_eop_counters_match_only_owned_vmid_pasid_me_pipe_queue() -> TestResult {
    let mut h = History::new();
    for ring in 0..=255u8 {
        let mut e = event(0);
        e.vector.ring = ring;
        // Payload is not a kernel queue identity; accept a zero doorbell.
        e.vector.data[0] = 0;
        h.push(e);
    }
    assert_eq!(h.kernel_eop, [2, 2]); // bit 7 is reserved, as in Linux.
    for case in 0..4 {
        let mut e = event(0);
        match case {
            0 => e.vector.client = 0x12,
            1 => e.vector.source = 180,
            2 => e.vector.vmid = 1,
            _ => e.vector.pasid = 1,
        }
        h.push(e);
    }
    while !h.pop().is_empty() {}
    assert_eq!(h.kernel_eop, [2, 2]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_eop_counters_match_only_owned_vmid_pasid_me_pipe_queue
);

fn navi48_eop_observation_rejects_partial_history_duplicates_faults_and_route_changes() -> TestResult
{
    let s = Sample {
        pipe: 0,
        count: 5,
        cpu: 7,
        vector: Some(0x60),
    };
    assert_eq!(s.observed(6, Some(0x60), 8, false, 0), Ok(true));
    assert_eq!(s.observed(6, Some(0x60), 8, true, 0), Ok(false));
    assert_eq!(s.observed(6, Some(0x60), 7, false, 0), Ok(false));
    assert_eq!(s.observed(5, Some(0x60), 8, false, 0), Ok(false));
    assert_eq!(
        s.observed(7, Some(0x60), 8, false, 0),
        Err(ih::Error::Protocol)
    );
    assert_eq!(
        s.observed(6, Some(0x60), 8, false, 1),
        Err(ih::Error::Protocol)
    );
    assert_eq!(
        s.observed(6, Some(0x61), 8, false, 0),
        Err(ih::Error::Protocol)
    );
    assert_eq!(s.observed(6, None, 8, false, 0), Err(ih::Error::Protocol));
    assert_eq!(
        Sample { vector: None, ..s }.observed(6, None, 7, false, 0),
        Ok(true)
    );
    assert_eq!(
        Sample {
            count: u64::MAX,
            ..s
        }
        .observed(0, s.vector, 8, false, 0),
        Err(ih::Error::Invalid)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    navi48_eop_observation_rejects_partial_history_duplicates_faults_and_route_changes
);
