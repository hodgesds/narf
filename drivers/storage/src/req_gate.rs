//! Per-device request gate for synchronous storage I/O.
//!
//! The synchronous block paths used to take a driver's global
//! `CONTROLLER: IrqSafeSpinLock<Option<...>>` and hold it across the
//! whole device round-trip — submit, then busy-poll for completion
//! (30 s budget for AHCI, up to seconds of aggregate PIO for SDHCI).
//! `IrqSafeSpinLock` masks interrupts, so the waiting CPU ran with
//! interrupts masked for a hardware transfer, and every other CPU
//! doing I/O spun on the same lock, also interrupts-masked. Under a
//! filesystem workload that starves timers and RCU and livelocks the
//! machine: the stall watchdog caught three CPUs `SPIN-NOT-POLLING`
//! on the equivalent virtio-blk lock with work queued on every ready
//! queue, and adding vCPUs made it worse because it is a thundering
//! herd rather than a race.
//!
//! The fix (mirroring `drivers/virtio/src/blk_pci.rs`): the global
//! lock is taken only long enough to read the installed device's
//! address, and mutual exclusion for the actual transfer moves to a
//! per-device `AtomicBool` spun on WITHOUT masking interrupts, so
//! timer ticks, RCU quiescent states and the sleep pumps keep running
//! on a CPU waiting its turn.

use core::sync::atomic::{AtomicBool, Ordering};

/// RAII holder for a device's request gate. See the module docs for
/// why this replaces holding the controller spinlock across I/O.
pub(crate) struct ReqGate<'a>(&'a AtomicBool);

impl<'a> ReqGate<'a> {
    /// Spin until the gate is ours. Interrupts keep their
    /// caller-supplied state — the whole point — so timer ticks, RCU
    /// quiescent states and the sleep pumps continue to run on this
    /// CPU while we wait.
    pub(crate) fn acquire(flag: &'a AtomicBool) -> ReqGate<'a> {
        while flag
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        ReqGate(flag)
    }
}

impl Drop for ReqGate<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
