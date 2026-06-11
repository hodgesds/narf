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

use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Whether a clockevent device fires once per CPU (LAPIC) or
/// globally (HPET, PIT, ACPI PM Timer). Drives the tick-broadcast
/// machinery: per-CPU devices auto-tick their own CPU; shared
/// devices iterate the broadcast mask and IPI listed CPUs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ClockEventKind {
    /// One instance per CPU; each CPU's own local timer fires its
    /// own IRQ. Selected device is implicitly "for this CPU" only.
    /// LAPIC timer is the canonical example.
    PerCpu,
    /// One physical device; can only generate one tick stream at
    /// a time. Used as a tick-broadcast source — when a CPU's
    /// per-CPU clockevent is broken or stops in deep C-states,
    /// register that CPU into the broadcast mask and the shared
    /// device IPIs it on every tick. HPET / PIT / ACPI PM-Timer
    /// are the canonical examples.
    Shared,
}

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

    /// Per-CPU or shared. Drives the tick-broadcast machinery.
    /// Default `Shared` — most non-LAPIC tick sources are global.
    fn kind(&self) -> ClockEventKind {
        ClockEventKind::Shared
    }
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
    for existing in slots.iter().flatten() {
        if existing.name() == dev.name() {
            return;
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
    use core::fmt::Write as _;
    let snapshot: [Option<&'static dyn ClockEvent>; MAX_BACKENDS] = *REGISTRY.lock();
    for (idx, slot) in snapshot.iter().enumerate() {
        let Some(dev) = slot else {
            continue;
        };
        if !dev.supported() {
            let _ = writeln!(
                narf_console::Writer,
                "  clockevent: '{}' unsupported (skipped)",
                dev.name()
            );
            continue;
        }
        // SAFETY: select_primary runs once at boot from BSP; no
        // other agent is touching backend MMIO.
        let arm_res = unsafe { dev.arm_periodic(hz, vector) };
        if let Err(e) = arm_res {
            let _ = writeln!(
                narf_console::Writer,
                "  clockevent: '{}' arm_periodic failed: {:?}",
                dev.name(),
                e
            );
            continue;
        }
        let baseline = dev.tick_count();
        if !probe_fires(*dev) {
            let after = dev.tick_count();
            let _ = writeln!(
                narf_console::Writer,
                "  clockevent: '{}' armed but probe fired 0 ticks (was {}, now {}) — IRQ not delivered",
                dev.name(),
                baseline,
                after
            );
            // SAFETY: same.
            unsafe {
                dev.disarm();
            }
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
/// For a `Shared` clockevent, also drives the broadcast machinery:
/// iterates [`BROADCAST_MASK`] and invokes the broadcast sender
/// hook (installed via [`set_broadcast_sender`]) to deliver an
/// IPI at [`TICK_VECTOR`] to each registered CPU. This is how
/// CPUs whose per-CPU LAPIC timer is broken (or stopped in deep
/// C-states) still get scheduler / wheel ticks.
///
/// Called with IF=0 (trap context) and the backend's per-vector
/// dispatch lock NOT held; safe to call from any IRQ handler.
#[inline]
pub fn on_tick() {
    let now = crate::now_cycles();
    let _ = crate::timer_wheel::fire_due(now);
    // Broadcast to CPUs in BROADCAST_MASK if a sender's installed.
    // No-op until SMP wires `set_broadcast_sender` + per-CPU
    // registration. Single-CPU NARF: mask is always 0, no-op.
    let mask = BROADCAST_MASK.load(Ordering::Acquire);
    if mask != 0 {
        let sender = BROADCAST_SENDER.load(Ordering::Acquire);
        if sender != 0 {
            let vector = TICK_VECTOR.load(Ordering::Acquire);
            // SAFETY: sender was installed via set_broadcast_sender
            // which takes a real `BroadcastSender` (fn-pointer
            // typed). The transmute reverses that.
            let f: BroadcastSender = unsafe { core::mem::transmute(sender) };
            f(mask, vector);
        }
    }
}

/// Function signature for the broadcast IPI sender. Takes the
/// CPU mask (bit N = CPU N) and the vector to deliver. Backend-
/// specific implementation: on x86_64 x2APIC, iterates set bits,
/// composes ICR for each, writes APIC_ICR_MSR.
pub type BroadcastSender = fn(cpu_mask: u64, vector: u8);

/// Storage for the broadcast IPI sender's fn-pointer-as-usize.
/// 0 = not installed. Set via [`set_broadcast_sender`] from the
/// platform init code that has access to APIC ICR writes.
static BROADCAST_SENDER: AtomicUsize = AtomicUsize::new(0);

/// CPU mask of cores that depend on tick broadcast (their own
/// per-CPU clockevent is unreliable or unselected). Each set bit
/// receives an IPI at [`TICK_VECTOR`] on every shared-clockevent
/// tick. Bit N = CPU N. Up to 64 CPUs in this initial design;
/// upsize to AtomicBitset for >64 once that's a concern.
pub static BROADCAST_MASK: AtomicU64 = AtomicU64::new(0);

/// Install the per-arch broadcast IPI sender. Called once at
/// boot from the arch-specific init path (currently
/// `narf_interrupts::x86_64::apic::init_bsp`'s tail when x2APIC
/// is up).
pub fn set_broadcast_sender(f: BroadcastSender) {
    BROADCAST_SENDER.store(f as usize, Ordering::Release);
}

/// Register CPU `n` as needing tick broadcast. Idempotent.
/// Future: called by per-CPU init when its local clockevent's
/// probe fails OR when it enters a sleep state that stops its
/// LAPIC timer.
pub fn broadcast_register(cpu: u8) {
    BROADCAST_MASK.fetch_or(1u64 << (cpu as u32 & 63), Ordering::Release);
}

/// Unregister CPU `n` from broadcast. Called when its local
/// clockevent is restored / re-armed.
pub fn broadcast_unregister(cpu: u8) {
    BROADCAST_MASK.fetch_and(!(1u64 << (cpu as u32 & 63)), Ordering::Release);
}

/// Verification probe. Arms the device, spins ~50 ms via TSC,
/// returns true iff the device's `tick_count` grew. Distinguishes
/// "arm_periodic returned Ok but IRQs aren't actually delivered"
/// (Phoenix HawkPoint1 LAPIC case) from "arm worked and ticks
/// arrive."
///
/// The probe runs with IRQs ENABLED — that's the whole point.
/// `arm_periodic` must have already programmed the device, and
/// the caller (boot path) is expected to call this AFTER
/// `enable_interrupts`. If the probe is called before IF is set,
/// no ticks deliver and the device fails the probe even when
/// it's actually working — caller is responsible for ordering.
///
/// 50 ms at the target 100 Hz tick rate = 5 ticks expected. We
/// require at least 1 tick to call it a pass — generous enough
/// for slower probes / lower-Hz arms.
fn probe_fires(dev: &dyn ClockEvent) -> bool {
    let baseline = dev.tick_count();
    // 50 ms TSC busy-wait. cpns may be uncalibrated at this point
    // in boot — use a conservative cycle count that gives at
    // least 25 ms on any plausible CPU (≥2 GHz worst case;
    // slower CPUs wait longer, which is also fine for a probe).
    let cpns = crate::wall::cycles_per_ns().max(1) as u64;
    let probe_cycles = 50_000_000u64.saturating_mul(cpns);
    let start = crate::now_cycles();
    while crate::now_cycles().wrapping_sub(start) < probe_cycles {
        core::hint::spin_loop();
        if dev.tick_count() > baseline {
            return true;
        }
    }
    dev.tick_count() > baseline
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
