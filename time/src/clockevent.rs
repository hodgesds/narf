//! Periodic tick-source abstraction.
//!
//! Currently the kernel hardcodes the LAPIC timer as its only
//! periodic IRQ source. On hardware where the LAPIC timer is broken
//! (Phoenix HawkPoint1 / certain Renoir SKUs: LVT_TIMER programs
//! correctly per readback, but IRQs at the timer vector never reach
//! the trap handler), the kernel wedges: `fire_due` never runs, the
//! timer wheel never wakes, every kernel async task that uses
//! `sleep_cycles` parks indefinitely after one poll.
//!
//! This module decouples "wheel needs a periodic tick" from "LAPIC
//! timer is the only way to get one." Backends (LAPIC, HPET periodic
//! mode, eventually PIT / ACPI PM Timer) implement the [`ClockEvent`]
//! trait and call [`register`] at boot. [`select_primary`] picks the
//! first working backend (Phase 2 adds verification); the selected
//! backend's vector is published via [`TICK_VECTOR`] so the trap
//! dispatcher knows which IRQ counts as "tick" and invokes
//! [`on_tick`] to advance the wheel.
//!
//! Linux's equivalent infrastructure is `kernel/time/clockevents.c` +
//! `tick_broadcast.c` (per-CPU clockevents + broadcast for CPUs whose
//! local timer stops in deep C-states). Phase 6 of the bring-up plan
//! lands per-CPU + broadcast on top of this trait.

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// A periodic tick source. The kernel arms one of these at boot
/// to drive the timer wheel + scheduler preemption.
pub trait ClockEvent: Sync + Send {
    /// Human-readable name (`"lapic"`, `"hpet"`, ...). Surfaced
    /// on the FB status panel + boot log.
    fn name(&self) -> &'static str;

    /// True iff the device is present + this CPU can arm it.
    /// Called once per backend before arming; cheap (no MMIO
    /// writes, only capability probes).
    fn supported(&self) -> bool;

    /// Arm to fire `hz` Hz, delivering IRQs to IDT vector
    /// `vector`. The backend programs its own IRQ routing
    /// (LAPIC LVT_TIMER, HPET TN_CONF + IOAPIC route, etc.).
    ///
    /// # Safety
    /// CPL=0, exclusive access to the backend's MMIO/MSRs for
    /// the duration of the call.
    unsafe fn arm_periodic(&self, hz: u32, vector: u8) -> Result<(), ClockEventError>;

    /// Disarm (mask the LVT entry / disable the comparator /
    /// stop the divider, depending on backend).
    ///
    /// # Safety
    /// Same as `arm_periodic`.
    unsafe fn disarm(&self);

    /// Monotonic count of ticks observed by the backend's ISR.
    /// Used by `probe_fires` to verify the device is actually
    /// delivering. Surfaced on the panel as the per-source
    /// liveness signal.
    fn tick_count(&self) -> u64;

    /// Coarsest-grained period this device can produce, in
    /// nanoseconds. Lower-resolution backends (PIT at 18.2 Hz =
    /// 54.9 ms) are deprioritised by `select_primary` against
    /// higher-resolution ones (LAPIC at <1 µs).
    fn resolution_ns(&self) -> u64;
}

/// Why arming failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ClockEventError {
    /// Backend reported `supported() == false`.
    NotSupported,
    /// Requested frequency too high / too low for this backend.
    InvalidFrequency,
    /// MMIO / MSR write didn't take effect (BIOS lock, partial
    /// hardware init, etc.).
    HardwareError,
    /// Backend needs an IRQ vector but vector::alloc / IOAPIC
    /// route failed.
    NoFreeIrq,
}

/// Max simultaneously-registered backends. Today we have at
/// most LAPIC + HPET; PIT + ACPI-PM bring this to 4. Bump if
/// more land.
const MAX_BACKENDS: usize = 4;

/// Registry of all registered backends. Sized fixed-array so we
/// don't need heap allocation at boot.
static REGISTRY: IrqSafeSpinLock<[Option<&'static dyn ClockEvent>; MAX_BACKENDS]> =
    IrqSafeSpinLock::new([const { None }; MAX_BACKENDS]);

/// 1-based index into REGISTRY of the selected primary backend
/// (`0` = none selected). 1-based so the all-zero default is
/// "no selection yet."
static PRIMARY_IDX: AtomicUsize = AtomicUsize::new(0);

/// IDT vector the primary backend is programmed to deliver on.
/// 0 = no primary selected. The trap dispatcher checks this:
/// any frame.vector == TICK_VECTOR calls into [`on_tick`].
pub static TICK_VECTOR: AtomicU8 = AtomicU8::new(0);

/// Register a backend. Idempotent on the same pointer (no-op if
/// already present). Panics if MAX_BACKENDS is exceeded — that's
/// a build-config bug, not a runtime error.
pub fn register(dev: &'static dyn ClockEvent) {
    let mut slots = REGISTRY.lock();
    // Dedup by name to avoid double-registration on test reruns.
    for slot in slots.iter() {
        if let Some(existing) = slot {
            if existing.name() == dev.name() {
                return;
            }
        }
    }
    for slot in slots.iter_mut() {
        if slot.is_none() {
            *slot = Some(dev);
            return;
        }
    }
    panic!(
        "clockevent::register: MAX_BACKENDS={} exceeded; bump and rebuild",
        MAX_BACKENDS
    );
}

/// Pick a working backend and arm it. Iterates registered
/// backends in registration order, calls `arm_periodic`, and
/// (in Phase 2) verifies it actually delivers ticks before
/// committing. Phase 1: picks the first `supported()` backend
/// whose arm succeeds, without verification.
///
/// On success: publishes TICK_VECTOR + PRIMARY_IDX, returns
/// the selected device. On failure (no backend worked): returns
/// None and leaves the kernel without a periodic tick — the
/// trap-handler fail-safe (`fire_due` on every IRQ) is the
/// fallback in that case.
pub fn select_primary(hz: u32, vector: u8) -> Option<&'static dyn ClockEvent> {
    let snapshot: [Option<&'static dyn ClockEvent>; MAX_BACKENDS] = *REGISTRY.lock();
    for (idx, slot) in snapshot.iter().enumerate() {
        let Some(dev) = slot else { continue; };
        if !dev.supported() {
            continue;
        }
        // SAFETY: select_primary runs once at boot from BSP; no
        // other agent is touching backend MMIO.
        let arm_res = unsafe { dev.arm_periodic(hz, vector) };
        if arm_res.is_err() {
            continue;
        }
        if !probe_fires(*dev) {
            // SAFETY: same.
            unsafe { dev.disarm(); }
            continue;
        }
        PRIMARY_IDX.store(idx + 1, Ordering::Release);
        TICK_VECTOR.store(vector, Ordering::Release);
        return Some(*dev);
    }
    None
}

/// Return the currently-selected primary backend, if any.
pub fn primary() -> Option<&'static dyn ClockEvent> {
    let idx = PRIMARY_IDX.load(Ordering::Acquire);
    if idx == 0 {
        return None;
    }
    REGISTRY.lock()[idx - 1]
}

/// Central tick handler invoked from the trap dispatcher when an
/// IRQ matching [`TICK_VECTOR`] fires. Advances the timer wheel
/// — the backend's own ISR already incremented its `tick_count`.
///
/// Called with IF=0 (trap context) and the backend's per-vector
/// dispatch lock NOT held; safe to call from any IRQ handler.
#[inline]
pub fn on_tick() {
    let now = crate::now_cycles();
    let _ = crate::timer_wheel::fire_due(now);
}

/// Verification probe (Phase 2). Phase 1 stub returns `true`
/// always — no real verification, just "the arm call returned
/// Ok." Phase 2 will arm, spin ~50ms via TSC, check tick_count
/// grew, and return true iff it did.
#[inline]
fn probe_fires(_dev: &dyn ClockEvent) -> bool {
    true
}

#[doc(hidden)]
pub fn __reset_for_test() {
    let mut slots = REGISTRY.lock();
    for slot in slots.iter_mut() {
        *slot = None;
    }
    PRIMARY_IDX.store(0, Ordering::Release);
    TICK_VECTOR.store(0, Ordering::Release);
}
