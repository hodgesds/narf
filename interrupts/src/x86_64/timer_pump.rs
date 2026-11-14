//! x86 hrtimer clockevent pump.
//!
//! Bridges the per-CPU `narf_time::hrtimer` bases to the selected
//! clockevent (`tick_program_event`). Reliable LAPIC TSC-deadline is the
//! primary path; HPET comparator 0 remains the fallback when the
//! selected LAPIC is not a reliable one-shot source. At boot the
//! fallback allocates one IDT vector + one IOAPIC redirection. This
//! is the contrast with
//! [`crate::x86_64::hpet_oneshot`], which leaks a fresh vector on
//! every arm and is fine for one-shot calibration use but would
//! exhaust the 240-slot IDT bitmap if we used it as the executor's
//! sleep backbone.
//!
//! The handler runs from the synchronous-handler hook in
//! [`crate::dispatch::on_irq`]:
//!
//!   1. Disarm + clear HPET status latch (level-triggered line).
//!   2. Expire every CPU's due hrtimers (HPET is one global comparator
//!      with no per-CPU deadline, so it is the broadcast expiry).
//!   3. Re-arm HPET to the earliest remaining event of any CPU.
//!
//! `enter_irq`/`exit_irq` bracketing happens in `dispatch::on_irq`
//! around the synchronous handler call.
//!
//! Spec: `interrupts/specification/spec.md` (§8 — async-IRQ
//! surface; this is the implementation backing `time/`'s sleep
//! futures). HPET register layout: see
//! `time/src/hpet.rs` module header.

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_acpi::ioapic;

/// Why [`init`] failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TimerPumpInitError {
    /// HPET wasn't initialised — `narf_time::hpet::init` never ran
    /// or returned `Err`.
    HpetMissing,
    /// HPET reports zero comparators (impossible per spec but
    /// handled defensively).
    NoComparators,
    /// Comparator 0's `Tn_INT_ROUTE_CAP` mask had no GSI in the
    /// safe range (>= 16, to clear the legacy ISA block).
    NoSafeGsi,
    /// `vector::alloc` returned exhausted.
    NoVector,
    /// IOAPIC programming failed — usually because no MADT-known
    /// IOAPIC owns the chosen GSI.
    IoapicRoutingFailed,
    /// MADT enumerated no LAPIC, so we have no CPU to route to.
    NoLocalApic,
    /// `init` was called twice.
    AlreadyInitialised,
}

#[derive(Debug)]
struct PumpState {
    initialised: AtomicBool,
    /// IDT vector we allocated; cached so the handler stays installed.
    vector: AtomicU8,
    /// GSI we routed through the IOAPIC.
    gsi: AtomicU8,
    /// LAPIC id we route to (always BSP for this pass).
    dest_apic: AtomicU8,
}

static STATE: PumpState = PumpState {
    initialised: AtomicBool::new(false),
    vector: AtomicU8::new(0),
    gsi: AtomicU8::new(0),
    dest_apic: AtomicU8::new(0),
};

/// Whether wheel arms also need the HPET fallback. A working TSC-deadline
/// clockevent already targets the same absolute deadline; programming HPET as
/// well causes two interrupts and several intercepted MMIO accesses per
/// deadline under KVM. Default to `true` until [`init`] has positively
/// identified the reliable LAPIC primary.
static USE_HPET_FALLBACK: AtomicBool = AtomicBool::new(true);

/// Pick a GSI in `mask`. Tries the high range first (>= `min_gsi`,
/// typically 16, to stay out of legacy ISA territory), then falls
/// back to lower GSIs skipping the well-known legacy allocations
/// (0 = PIT cascade, 1 = i8042 kbd, 2 = legacy PIC cascade,
/// 8 = RTC, 13 = FPU). On QEMU the HPET timer 0 route_cap often
/// only advertises low GSIs (4-7) — without this fallback
/// `timer_pump` init returns NoSafeGsi and async sleeps fall back
/// to busy-poll.
fn pick_gsi(mask: u32, min_gsi: u8) -> Option<u8> {
    for g in min_gsi..32 {
        if mask & (1u32 << g) != 0 {
            return Some(g);
        }
    }
    // Fallback: scan low GSIs skipping the well-known legacy
    // assignments. GSI 0 = legacy PIT, GSI 1 = i8042 kbd, GSI 8 =
    // RTC, GSI 13 = FPU. GSI 2 (historically PIC cascade / re-
    // routed PIT) is allowed because we never enable the PIT for
    // timekeeping — modern systems run HPET / LAPIC timer there.
    // On QEMU, HPET timer 0 route_cap is exactly 0x4 (GSI 2 only),
    // so without this allowance timer_pump init returns NoSafeGsi
    // and async sleep_cycles falls back to busy-poll.
    const LEGACY_RESERVED: u32 = (1 << 0) | (1 << 1) | (1 << 8) | (1 << 13);
    (0u8..16).find(|&g| mask & (1u32 << g) != 0 && LEGACY_RESERVED & (1u32 << g) == 0)
}

/// Convert a TSC-cycle delta to HPET ticks using the calibrated
/// ratios. Truncates toward zero — for an arming a one-tick
/// undershoot is fine (the wheel would just fire-due on the next
/// poll and re-arm one tick later).
fn cycles_delta_to_hpet_ticks(cycles: u64) -> u64 {
    let cps = narf_time::ns_to_cycles(1_000_000_000);
    let hpet_hz = narf_time::hpet::frequency_hz();
    if cps == 0 || hpet_hz == 0 {
        return 0;
    }
    ((cycles as u128) * (hpet_hz as u128) / (cps as u128)) as u64
}

/// Translate a deadline expressed in monotonic TSC cycles to an
/// absolute HPET counter target.
fn deadline_cycles_to_hpet_target(deadline_cycles: u64) -> u64 {
    let now_cycles = narf_time::now_cycles();
    let now_hpet = narf_time::hpet::read_counter();
    if deadline_cycles <= now_cycles {
        // Already past — fire ASAP. Add 1 so the comparator
        // doesn't read as exactly equal to `now` and miss.
        return now_hpet.wrapping_add(1);
    }
    let delta_hpet = cycles_delta_to_hpet_ticks(deadline_cycles - now_cycles);
    now_hpet.wrapping_add(delta_hpet.max(1))
}

/// Hrtimer clockevent programmer (`tick_program_event`) for THIS CPU's
/// base. Called from an hrtimer enqueue or expiry with IRQs disabled.
fn wheel_arm(deadline_cycles: u64) {
    // Primary: this CPU's LAPIC TSC-deadline one-shot (reliable under KVM,
    // where the HPET one-shot IRQ isn't promptly delivered). Unconditional —
    // must run even before the HPET pump's STATE.initialised is set.
    crate::x86_64::apic::arm_hrtimer_event(deadline_cycles);
    // Secondary: HPET one-shot only when the selected primary is not reliable
    // TSC-deadline. The clockevent probe is the authority here: preserving an
    // always-on HPET duplicate after LAPIC passed merely delivers the same
    // deadline twice.
    if !STATE.initialised.load(Ordering::Acquire) || !USE_HPET_FALLBACK.load(Ordering::Acquire) {
        return;
    }
    // One comparator serves every CPU: arm it for the earliest event of
    // any base, never a later local one that would hide an earlier remote.
    let Some(earliest) = narf_time::hrtimer::next_event_cycles_any() else {
        return;
    };
    arm_hpet(earliest.min(deadline_cycles));
}

fn arm_hpet(deadline_cycles: u64) {
    let gsi = STATE.gsi.load(Ordering::Relaxed);
    let mut target = deadline_cycles_to_hpet_target(deadline_cycles);
    // Linux `clockevents_program_event` → `clockevents_program_min_delta`:
    // when the device reports -ETIME (the counter reached the comparator
    // before it was armed — on real HPETs every MMIO access costs about a
    // microsecond, and a match only fires on equality), re-arm at the
    // minimum delta from now, growing it until the arm holds. Without this a
    // near or past deadline left the comparator behind the counter and the
    // broadcast silent until some later arm.
    let mut delta = narf_time::hpet::MIN_PROG_TICKS;
    for _ in 0..10 {
        // SAFETY: HPET window initialised at boot (init() checked); GSI is
        // the one we registered against the IOAPIC; comparator 0 is the one
        // we routed.
        match unsafe { narf_time::hpet::arm_oneshot_checked(0, gsi, target) } {
            Err(narf_time::hpet::ArmError::Expired) => {
                target = narf_time::hpet::read_counter().wrapping_add(delta);
                delta = delta.saturating_mul(2);
            }
            _ => return,
        }
    }
}

/// Synchronous IRQ handler installed against our IDT vector.
fn pump_irq() {
    if !STATE.initialised.load(Ordering::Acquire) {
        return;
    }
    // Clear the HPET status latch + comparator enable. The wheel
    // walk may immediately re-arm; arm_oneshot writes a fresh
    // enable bit, so disarming first is safe.
    // SAFETY: HPET singleton alive post-init.
    unsafe {
        let _ = narf_time::hpet::disarm(0);
    }
    // Broadcast expiry: every CPU's due hard timers run here (their
    // callbacks wake by reference and never free); due soft timers are raised
    // on their own CPU. O(1) stack.
    let next = narf_time::hrtimer::hrtimer_run_all_bases();
    if next != narf_time::hrtimer::KTIME_MAX && USE_HPET_FALLBACK.load(Ordering::Acquire) {
        arm_hpet(narf_time::hrtimer::ns_to_deadline_cycles(next));
    }
}

/// Initialise the timer pump. Must be called once at boot after:
///   - `narf_time::hpet::init` succeeded.
///   - `narf_interrupts::x86_64::init_bsp` ran (x2APIC + IDT live).
///   - ACPI MADT walk populated `narf_acpi::ioapic` and
///     `narf_acpi::apic_id_at`.
///
/// On success, installs the hrtimer clockevent programmer so future
/// `SleepUntil` registrations program HPET automatically.
pub fn init() -> Result<(), TimerPumpInitError> {
    if STATE
        .initialised
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(TimerPumpInitError::AlreadyInitialised);
    }

    // Roll-back closure: clear `initialised` so a follow-up call
    // can retry. We can't `?` because the manual rollback path is
    // load-bearing.
    let bail = |err: TimerPumpInitError| -> TimerPumpInitError {
        STATE.initialised.store(false, Ordering::Release);
        err
    };

    if !narf_time::hpet::is_present() {
        return Err(bail(TimerPumpInitError::HpetMissing));
    }
    if narf_time::hpet::num_comparators() == 0 {
        return Err(bail(TimerPumpInitError::NoComparators));
    }

    let dest_apic = match narf_acpi::apic_id_of_cpu(0) {
        Some(id) if id <= 0xFF => id as u8,
        _ => return Err(bail(TimerPumpInitError::NoLocalApic)),
    };

    let route_cap = narf_time::hpet::timer_route_cap(0);
    let gsi = match pick_gsi(route_cap, 16) {
        Some(g) => g,
        None => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  timer_pump: HPET timer 0 route_cap = {:#010x} \
                 (no usable GSI found)",
                route_cap,
            );
            return Err(bail(TimerPumpInitError::NoSafeGsi));
        }
    };

    let vector = match crate::vector::alloc() {
        Ok(v) => v,
        Err(_) => return Err(bail(TimerPumpInitError::NoVector)),
    };
    crate::install_handler(vector, pump_irq);

    // SAFETY: vector freshly allocated, handler installed above.
    let routed = unsafe {
        ioapic::route_gsi_to_vector(
            gsi as u32,
            vector,
            dest_apic,
            ioapic::POLARITY_HIGH | ioapic::TRIGGER_LEVEL,
        )
    };
    if !routed {
        let _ = crate::vector::free(vector);
        return Err(bail(TimerPumpInitError::IoapicRoutingFailed));
    }

    STATE.vector.store(vector, Ordering::Release);
    STATE.gsi.store(gsi, Ordering::Release);
    STATE.dest_apic.store(dest_apic, Ordering::Release);

    // Linux-style single clockevent ownership: once the boot probe selected a
    // reliable LAPIC one-shot, it alone drives wheel deadlines. Retain HPET for
    // a failed LAPIC probe, an HPET primary, or the unreliable legacy LAPIC
    // InitialCount mode.
    // A periodic-only LAPIC (InitialCount mode, no TSC-deadline) ticks
    // reliably but cannot fire at an arbitrary deadline: HPET is then the
    // one-shot broadcast device for precise hrtimer events (Linux
    // tick-broadcast with HPET).
    let oneshot_lapic = narf_time::clockevent::primary()
        .is_some_and(|dev| dev.name() == "lapic" && dev.can_stop_idle_tick());
    USE_HPET_FALLBACK.store(!oneshot_lapic, Ordering::Release);

    // Install the wheel callback last — it's the gate that lets
    // future `register` calls actually program HPET. Anything
    // installed before this point would race against an
    // unconfigured pump.
    narf_time::hrtimer::set_arm_callback(wheel_arm);

    // Timers queued before init: arm now so they don't sit untriggered.
    if let Some(d) = narf_time::hrtimer::next_event_cycles_local() {
        wheel_arm(d);
    }
    Ok(())
}

/// `true` once [`init`] has completed successfully.
#[inline]
pub fn is_initialised() -> bool {
    STATE.initialised.load(Ordering::Acquire)
}

/// Diagnostic: `true` when wheel deadlines are duplicated onto HPET because
/// no reliable LAPIC TSC-deadline primary was selected.
pub fn uses_hpet_fallback() -> bool {
    USE_HPET_FALLBACK.load(Ordering::Acquire)
}

#[doc(hidden)]
pub fn __vector_for_test() -> u8 {
    STATE.vector.load(Ordering::Acquire)
}
