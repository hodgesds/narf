//! HPET periodic-mode `ClockEvent` backend.
//!
//! Wires HPET periodic-mode arming (`narf_time::hpet::arm_periodic`)
//! + IDT vector allocation + IOAPIC routing into a [`ClockEvent`]
//! implementation. Used as a fallback tick source when the LAPIC
//! timer is broken on a given platform (Phoenix HawkPoint1 / Renoir
//! confirmed: LVT_TIMER programs correctly per readback, but the
//! IRQ never reaches the trap handler).
//!
//! The HPET delivers an IRQ at a per-timer-block-selectable GSI.
//! We pick a comparator that supports periodic mode (HPET spec
//! guarantees timer 0; others may), pick a free GSI from its
//! `Tn_INT_ROUTE_CAP` mask in the safe range (≥ 16, avoiding ISA
//! IRQ block 0..15), allocate an IDT vector via `vector::alloc`,
//! install our ISR, route GSI→vector via IOAPIC, then call
//! `hpet::arm_periodic`.
//!
//! Tick counter incremented in the ISR. `clockevent::on_tick`
//! invoked to advance the timer wheel.

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

/// Total HPET-clockevent IRQ deliveries observed by our ISR.
static HPET_TICKS: AtomicU64 = AtomicU64::new(0);

/// Allocated IDT vector for our HPET periodic tick, or 0 if
/// `arm_periodic` hasn't successfully completed.
static HPET_TICK_VECTOR: AtomicU8 = AtomicU8::new(0);

/// Comparator index armed in periodic mode. Stored so the ISR
/// can clear the level-status latch for THIS comparator.
static HPET_COMPARATOR: AtomicU8 = AtomicU8::new(0xFF);

/// ISR for HPET periodic ticks. Increments tick counter, clears
/// the level-mode status latch (HPET spec §3.2.3), calls
/// `clockevent::on_tick` to advance the wheel.
fn hpet_tick_isr() {
    HPET_TICKS.fetch_add(1, Ordering::Relaxed);
    // Clear status latch for our comparator. Level-triggered
    // HPET timers latch the interrupt until SW writes 1 to the
    // bit in REG_INT_STS; without this the IOAPIC line stays
    // asserted and we don't get re-armed IRQs.
    let n = HPET_COMPARATOR.load(Ordering::Acquire);
    if n != 0xFF {
        // SAFETY: HPET MMIO live, n was set during successful arm.
        unsafe {
            let _ = narf_time::hpet::clear_status(n);
        }
    }
    narf_time::clockevent::on_tick();
}

/// The HPET ClockEvent backend.
#[derive(Debug)]
pub struct HpetClockEvent;

/// Global singleton for registration with the clockevent registry.
pub static HPET_CLOCKEVENT: HpetClockEvent = HpetClockEvent;

impl narf_time::clockevent::ClockEvent for HpetClockEvent {
    fn name(&self) -> &'static str {
        "hpet"
    }

    fn supported(&self) -> bool {
        if !narf_time::hpet::is_present() {
            return false;
        }
        // Need at least one comparator with periodic capability.
        for n in 0..narf_time::hpet::num_comparators() {
            if narf_time::hpet::comparator_supports_periodic(n) {
                return true;
            }
        }
        false
    }

    unsafe fn arm_periodic(
        &self,
        hz: u32,
        vector: u8,
    ) -> Result<(), narf_time::clockevent::ClockEventError> {
        use narf_time::clockevent::ClockEventError;

        if hz == 0 || hz > 10_000 {
            return Err(ClockEventError::InvalidFrequency);
        }
        let hpet_hz = narf_time::hpet::frequency_hz();
        if hpet_hz == 0 {
            return Err(ClockEventError::HardwareError);
        }
        let period_ticks = hpet_hz / (hz as u64);
        if period_ticks == 0 {
            return Err(ClockEventError::InvalidFrequency);
        }

        // Pick the lowest-numbered comparator that (a) is NOT
        // comparator 0 — reserved for `timer_pump`'s oneshot wheel
        // arming, (b) supports periodic mode, and (c) has a safe
        // GSI (>=16, outside the legacy ISA block) in its route
        // cap. If a chipset only has comparator 0 (some QEMU
        // models), this backend's probe fails and the caller
        // moves on to the next clockevent.
        let num = narf_time::hpet::num_comparators();
        let mut chosen: Option<(u8, u8)> = None;
        for n in 1..num {
            if !narf_time::hpet::comparator_supports_periodic(n) {
                continue;
            }
            let route_cap = narf_time::hpet::timer_route_cap(n);
            // Prefer high GSIs to avoid colliding with ISA IRQs.
            for gsi in (16u8..32).chain(0u8..16) {
                if route_cap & (1u32 << gsi) != 0 {
                    chosen = Some((n, gsi));
                    break;
                }
            }
            if chosen.is_some() {
                break;
            }
        }
        let (n, gsi) = chosen.ok_or(ClockEventError::NotSupported)?;

        // Install ISR at the requested vector. We use the
        // caller-supplied `vector` directly (the central
        // `select_primary` allocates one and passes it in).
        crate::install_handler(vector, hpet_tick_isr);

        // Program the IOAPIC redirection: GSI → vector. HPET
        // delivers level-triggered active-high by default in
        // periodic mode; configure to match.
        let flags = narf_acpi::ioapic::POLARITY_HIGH
            | narf_acpi::ioapic::TRIGGER_LEVEL;
        // SAFETY: vector + handler installed above; IOAPIC code
        // upholds its own preconditions.
        let routed = unsafe {
            narf_acpi::ioapic::route_gsi_to_vector(gsi as u32, vector, 0, flags)
        };
        if !routed {
            return Err(ClockEventError::NoFreeIrq);
        }

        HPET_COMPARATOR.store(n, Ordering::Release);
        HPET_TICK_VECTOR.store(vector, Ordering::Release);

        // SAFETY: caller upholds CPL=0; IDT vector + IOAPIC route
        // installed; HPET MMIO is live (supported() confirmed).
        match unsafe { narf_time::hpet::arm_periodic(n, gsi, period_ticks) } {
            Ok(()) => Ok(()),
            Err(_) => {
                HPET_COMPARATOR.store(0xFF, Ordering::Release);
                HPET_TICK_VECTOR.store(0, Ordering::Release);
                Err(ClockEventError::HardwareError)
            }
        }
    }

    unsafe fn disarm(&self) {
        let n = HPET_COMPARATOR.load(Ordering::Acquire);
        if n == 0xFF {
            return;
        }
        // SAFETY: caller upholds CPL=0; HPET MMIO live.
        unsafe {
            let _ = narf_time::hpet::disarm(n);
        }
        HPET_COMPARATOR.store(0xFF, Ordering::Release);
        HPET_TICK_VECTOR.store(0, Ordering::Release);
    }

    fn tick_count(&self) -> u64 {
        HPET_TICKS.load(Ordering::Relaxed)
    }

    fn resolution_ns(&self) -> u64 {
        let hz = narf_time::hpet::frequency_hz();
        if hz == 0 {
            return u64::MAX;
        }
        // 1 second in nanoseconds / Hz = ns per tick.
        1_000_000_000 / hz
    }
}
