//! HPET-driven one-shot wakeup integration.
//!
//! Wires together three pieces of platform plumbing so callers can
//! ask "fire `handler` at HPET tick `deadline`" without re-doing
//! the IDT-vector / IOAPIC dance themselves:
//!
//!   1. [`narf_time::hpet::arm_oneshot`] — programs the per-timer
//!      comparator block (Intel HPET spec rev 1.0a §2.3.5/§2.3.6).
//!   2. [`crate::vector::alloc`] + [`crate::install_handler`] —
//!      reserves an IDT vector and installs the synchronous ISR.
//!   3. [`narf_acpi::ioapic::route_gsi_to_vector`] — programs the
//!      MADT-discovered IOAPIC's redirection table to deliver the
//!      HPET line to the chosen vector.
//!
//! Spec: Intel **"IA-PC HPET (High Precision Event Timers)
//! Specification"** rev 1.0a, October 2004, document 309216-001:
//! <https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/software-developers-hpet-spec-1-0a.pdf>
//! §2.3 (per-timer registers) + §3.2.3 (general interrupt status,
//! the level-mode latch we clear on every (re)arm).
//!
//! Stage cut: comparator 0 only. Multi-comparator scheduling +
//! sleep-wheel integration come later — once a single-deadline
//! sleep_cycles + executor-side `halt_until_irq` handshake are
//! solid we can grow to a per-comparator allocator.

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

/// Why an [`arm_oneshot`] call failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpetOneshotError {
    /// HPET wasn't initialised — `narf_time::hpet::init` never ran
    /// or returned an error.
    HpetMissing,
    /// HPET is present but reports zero comparators (impossible per
    /// spec but defensively handled).
    NoComparators,
    /// Comparator 0's `Tn_INT_ROUTE_CAP` had no acceptable GSI in
    /// the safe range (>= 16, to avoid the legacy ISA IRQ block).
    NoSafeGsi,
    /// `narf_interrupts::vector::alloc` returned exhausted.
    NoVector,
    /// IOAPIC programming failed — typically because no MADT-known
    /// IOAPIC owns the chosen GSI.
    IoapicRoutingFailed,
    /// MADT didn't enumerate any local APIC, so we have no
    /// destination CPU id to route to.
    NoLocalApic,
    /// Internal: comparator 0 is already armed by an earlier caller
    /// that hasn't released it. The Stage-cut API is single-slot.
    AlreadyArmed,
}

/// Per-vector state needed by the IRQ stub (it only knows its own
/// vector index, not the comparator number). Filled in by
/// [`arm_oneshot`] before unmasking the IOAPIC line.
struct ArmState {
    /// Comparator index to clear on IRQ. We only use 0 in this pass
    /// but the field keeps the IRQ stub generic.
    comparator: AtomicU8,
    /// User handler. Accessed via `usize` because `fn()` is not
    /// `Atomic`-compatible directly; the IRQ stub round-trips
    /// through `transmute` after a non-zero load.
    handler: AtomicU32,
    handler_high: AtomicU32,
    /// `true` once [`arm_oneshot`] has fully wired comparator +
    /// IOAPIC + dispatch; the IRQ stub returns early until then to
    /// stay safe against an early-firing line.
    armed: AtomicBool,
}

impl ArmState {
    const fn new() -> Self {
        Self {
            comparator: AtomicU8::new(0),
            handler: AtomicU32::new(0),
            handler_high: AtomicU32::new(0),
            armed: AtomicBool::new(false),
        }
    }
}

/// Single global slot — comparator 0 only this pass.
static SLOT0: ArmState = ArmState::new();

/// Stub IRQ handler installed via `install_handler`. Reads the
/// per-slot user handler, clears the HPET level latch, then dispatches.
///
/// Runs from the synchronous-handler hook in `dispatch::on_irq`,
/// before the LAPIC EOI in the trap path. The HPET status latch
/// must be cleared first — IOAPIC-level lines re-assert until the
/// source clears, so an EOI without a status clear would re-fire
/// the line immediately.
fn slot0_irq() {
    if !SLOT0.armed.load(Ordering::Acquire) {
        return;
    }
    let comp = SLOT0.comparator.load(Ordering::Relaxed);
    // Clear the level-mode latch + disable the comparator (one-shot
    // semantics: a single delivery, then the user re-arms if they
    // want another). Order matters: disarm before invoking the user
    // handler so a user that re-arms inside the handler doesn't
    // race the disarm.
    // SAFETY: HPET singleton is initialised (we wouldn't have armed
    // otherwise) and `comp` is the index we programmed.
    unsafe {
        let _ = narf_time::hpet::disarm(comp);
    }
    SLOT0.armed.store(false, Ordering::Release);

    let lo = SLOT0.handler.load(Ordering::Acquire) as usize;
    let hi = SLOT0.handler_high.load(Ordering::Acquire) as usize;
    let raw = lo | (hi << 32);
    if raw != 0 {
        // SAFETY: `raw` was stored from a `fn() as usize`; the
        // round-trip back to `fn()` is sound when non-zero.
        let f: fn() = unsafe { core::mem::transmute(raw) };
        f();
    }
}

/// Pick the first GSI from a `Tn_INT_ROUTE_CAP` mask that is
///  - in `mask`, and
///  - >= `min_gsi` (default 16 — keeps us out of the legacy ISA
///    block where SCI / IRQ 0..15 may already live).
///
/// Returns `None` if the mask is empty or only carries low GSIs.
fn pick_gsi(mask: u32, min_gsi: u8) -> Option<u8> {
    for g in min_gsi..32 {
        if mask & (1u32 << g) != 0 {
            return Some(g);
        }
    }
    None
}

/// Program HPET comparator 0 to deliver `handler` at HPET tick
/// `deadline_ticks`. Allocates an IDT vector + IOAPIC redirection
/// on first call; subsequent calls re-use the existing vector +
/// just reprogram the comparator.
///
/// `deadline_ticks` is in raw HPET ticks (use
/// [`narf_time::hpet::read_counter`] + a tick-based offset). Pass
/// a deadline already in the past to fire the IRQ as soon as the
/// HPET notices (typically within one main-counter tick).
///
/// # Safety
/// Caller asserts:
///   - HPET is initialised (`narf_time::hpet::init` succeeded).
///   - x2APIC + IOAPIC programming infrastructure is live (BSP has
///     run `narf_interrupts::x86_64::init_bsp` and ACPI MADT walk).
///   - `handler` is safe to invoke from IRQ context (no allocation,
///     no scheduler entry, etc.).
pub unsafe fn arm_oneshot(deadline_ticks: u64, handler: fn()) -> Result<(), HpetOneshotError> {
    use narf_acpi::ioapic;

    // Fast structural validation so we error out before mutating
    // any global state.
    if !narf_time::hpet::is_present() {
        return Err(HpetOneshotError::HpetMissing);
    }
    if narf_time::hpet::num_comparators() == 0 {
        return Err(HpetOneshotError::NoComparators);
    }

    // Try to claim slot 0. Only one in-flight one-shot at a time
    // for this pass — multi-deadline scheduling lands in a future
    // change.
    if SLOT0
        .armed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(HpetOneshotError::AlreadyArmed);
    }

    // Stash handler + comparator before unmasking. Must be set
    // before `narf_time::hpet::arm_oneshot` flips `Tn_INT_ENB_CNF`
    // because the line could fire as soon as that bit is set.
    let raw = handler as usize;
    SLOT0.handler.store((raw & 0xFFFF_FFFF) as u32, Ordering::Release);
    SLOT0
        .handler_high
        .store(((raw >> 32) & 0xFFFF_FFFF) as u32, Ordering::Release);
    SLOT0.comparator.store(0, Ordering::Release);

    // Allocate an IDT vector + install the synchronous ISR. Fresh
    // allocation each arm is fine — vectors are cheap (240-slot
    // bitmap) and freeing on disarm is awkward when a late IRQ
    // could still land. A future change can cache the vector across
    // arms.
    let vector = match crate::vector::alloc() {
        Ok(v) => v,
        Err(_) => {
            // Roll back the slot claim so the next caller can try.
            SLOT0.armed.store(false, Ordering::Release);
            return Err(HpetOneshotError::NoVector);
        }
    };
    crate::install_handler(vector, slot0_irq);

    // Pick the destination CPU. Use the BSP — apic_id_at(0). Local
    // APIC IDs > 255 require either x2APIC IOAPIC redirection or
    // an interrupt remapping unit; both are out of scope for this
    // pass. Reject CPUs we can't address through the legacy
    // 8-bit dest field.
    let dest_apic = match narf_acpi::apic_id_at(0) {
        Some(id) if id <= 0xFF => id as u8,
        Some(_) => {
            SLOT0.armed.store(false, Ordering::Release);
            let _ = crate::vector::free(vector);
            return Err(HpetOneshotError::NoLocalApic);
        }
        None => {
            SLOT0.armed.store(false, Ordering::Release);
            let _ = crate::vector::free(vector);
            return Err(HpetOneshotError::NoLocalApic);
        }
    };

    // Pick a GSI from the comparator's route-cap. Skip low GSIs
    // (<16) so we stay clear of the legacy ISA block — anything
    // in 0..16 is plausibly already routed by ACPI MADT
    // ISA-overrides (PIT, RTC, keyboard, COM, SCI, etc.).
    let route_cap = narf_time::hpet::timer_route_cap(0);
    let gsi = match pick_gsi(route_cap, 16) {
        Some(g) => g,
        None => {
            SLOT0.armed.store(false, Ordering::Release);
            let _ = crate::vector::free(vector);
            return Err(HpetOneshotError::NoSafeGsi);
        }
    };

    // Route the line through the IOAPIC. HPET drives the line
    // level-active-high in level mode (HPET spec §2.3.5; ACPI
    // doesn't define an MADT override for HPET so this is the
    // hardware default).
    // SAFETY: vector freshly allocated; handler installed above;
    // dest_apic from a checksummed MADT entry.
    let routed = unsafe {
        ioapic::route_gsi_to_vector(
            gsi as u32,
            vector,
            dest_apic,
            ioapic::POLARITY_HIGH | ioapic::TRIGGER_LEVEL,
        )
    };
    if !routed {
        SLOT0.armed.store(false, Ordering::Release);
        let _ = crate::vector::free(vector);
        return Err(HpetOneshotError::IoapicRoutingFailed);
    }

    // Finally, program the comparator. The HPET-side arm sequence
    // (clear status latch → write comparator → enable interrupt)
    // is encapsulated in `narf_time::hpet::arm_oneshot_comparator`.
    // SAFETY: HPET window is live (is_present check above); the
    // IDT vector + IOAPIC redirection are now in place so a
    // delivery is safe to take.
    let r = unsafe { narf_time::hpet::arm_oneshot(0, gsi, deadline_ticks) };
    if r.is_err() {
        SLOT0.armed.store(false, Ordering::Release);
        // Mask the IOAPIC line we just unmasked so a stray IRQ
        // can't land at the now-released vector.
        // SAFETY: vector + handler still installed; mask alone is
        // a no-side-effect op.
        let _ = unsafe {
            ioapic::route_gsi_to_vector(
                gsi as u32,
                vector,
                dest_apic,
                ioapic::POLARITY_HIGH | ioapic::TRIGGER_LEVEL | ioapic::MASKED,
            )
        };
        let _ = crate::vector::free(vector);
        return Err(HpetOneshotError::IoapicRoutingFailed);
    }
    Ok(())
}

/// Test surface for the GSI-picker mask logic — exposed as a
/// doc-hidden helper so the smoke in `interrupts/src/tests.rs` can
/// validate the algorithm without needing a live HPET.
#[doc(hidden)]
pub fn __pick_gsi_for_test(mask: u32, min_gsi: u8) -> Option<u8> {
    pick_gsi(mask, min_gsi)
}
