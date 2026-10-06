//! Per-device request gate: mutual exclusion for a device's shared
//! request scratch WITHOUT masking interrupts while waiting.
//!
//! The synchronous virtio paths used to serialise on a global
//! `IrqSafeSpinLock<Option<Device>>`, holding it across submit +
//! busy-poll. That masks interrupts on the waiting CPU for the whole
//! hardware round-trip and makes every other CPU spin on the same lock,
//! also interrupts-masked — starving timers and RCU, and livelocking
//! under load (see the virtio-blk fix this generalises,
//! `blk_pci::ReqGate`).
//!
//! A `ReqGate` lives ON the device it protects, so two devices never
//! contend, and it is spun on with plain atomics so timer ticks, RCU
//! quiescent states and the sleep pumps keep running while a CPU waits
//! its turn. The device's own virtqueue lock still provides ring mutual
//! exclusion and is released between completion polls; this gate only
//! has to cover the per-device request scratch and any submit sequences
//! that must not interleave.

use core::sync::atomic::{AtomicBool, Ordering};

/// RAII holder for a device's request gate. See module docs.
pub(crate) struct ReqGate<'a>(&'a AtomicBool);

impl<'a> ReqGate<'a> {
    /// Spin until the gate is ours. Interrupts keep their
    /// caller-supplied state — the whole point.
    pub(crate) fn acquire(flag: &'a AtomicBool) -> ReqGate<'a> {
        loop {
            // Short plain spin first: the gate covers only a submit sequence,
            // so it is usually released within a few iterations.
            for _ in 0..64 {
                if flag
                    .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return ReqGate(flag);
                }
                core::hint::spin_loop();
            }
            // Still contended: the holder is blocked on its (up to two-second)
            // device round-trip and may be a descheduled stackful task homed
            // on THIS CPU. A non-yielding spin starves it and DEADLOCKS at low
            // core counts — at SMP=1 the GPU/snd/mem flush gate never releases.
            // Yield to the executor so the holder runs, completes, and drops
            // the gate; fall back to a plain spin when there is no stackful
            // task to yield (early boot / IRQ context). Same shape as the
            // virtio-blk gate (`blk_pci::ReqGate`, task #34) that this module
            // generalises — the yield was the missing half of that fix.
            if !narf_scheduler::cooperative_yield() {
                // Can't yield (IRQs masked, or no stackful task): drain pending
                // TLB shootdowns / membarrier work while spinning. A holder
                // that shoots down while this waiter cannot ack would otherwise
                // wait forever on the waiter, and the waiter on the gate.
                narf_lib::sync::service_masked_spin();
                core::hint::spin_loop();
            }
        }
    }
}

impl Drop for ReqGate<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// A gate waiter that cannot yield — interrupts masked — must keep servicing
/// pending TLB shootdowns while it spins. It did not: a desktop VM wedged with
/// one CPU spinning here (IF=0) on the GPU gate while the gate's holder, on
/// another CPU, waited forever in `shoot_request_mask` for this CPU's ack.
///
/// The test holds the gate and installs a spin-wait hook that releases it, so
/// `acquire` can only return by servicing the hook while it spins. (Without
/// the fix it spins forever, so the fail-before shape is a hang, not a
/// failure.)
fn smoke_virtio_req_gate_services_shootdowns_while_masked() -> narf_kernel_test::TestResult {
    use core::sync::atomic::AtomicUsize;
    use narf_kernel_test::TestResult;
    static FLAG: AtomicBool = AtomicBool::new(false);
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn release_hook() {
        CALLS.fetch_add(1, Ordering::Relaxed);
        FLAG.store(false, Ordering::Release);
    }
    CALLS.store(0, Ordering::Relaxed);
    FLAG.store(true, Ordering::Release);
    let previous = narf_lib::sync::__test_swap_lock_spin_hook(Some(release_hook));
    narf_lib::sync::without_interrupts(|| drop(ReqGate::acquire(&FLAG)));
    let _ = narf_lib::sync::__test_swap_lock_spin_hook(previous);
    FLAG.store(false, Ordering::Release);
    if CALLS.load(Ordering::Relaxed) == 0 {
        return TestResult::Fail("a masked gate waiter did not service pending shootdowns");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!(
    "drivers/virtio/req_gate",
    smoke_virtio_req_gate_services_shootdowns_while_masked
);
