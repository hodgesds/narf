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
