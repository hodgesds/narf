//! ACPI Thermal Zone driver — composition shim.
//!
//! Spec: ACPI 6.5 §11 (Thermal Management).
//!   <https://uefi.org/specs/ACPI/>
//!
//! Zone modelling lives in exactly one place: `narf_power::acpi_thermal`
//! owns enumeration (ThermalZone nodes ∪ `PNP0C0F`, deduplicated), the
//! full trip-point table (`_CRT`/`_HOT`/`_PSV`/`_AC0..=_AC9`/`_TC1`/
//! `_TC2`) and trip classification. This module used to carry a second,
//! divergent zone walk (its own `_CRT`/`_PSV` reads, invented fallbacks,
//! one poll task per zone); that duplicate is retired (#910).
//!
//! What remains here is the platform-side composition:
//!   1. register every ACPI zone with the generic `narf_power::thermal`
//!      registry via the ACPI layer's bridge
//!      (`register_with_generic_registry`), and
//!   2. run the single `_TMP` poll task that feeds the registry through
//!      the bridge's `sample_all()`.
//!
//! The generic registry itself is created earlier — power's
//! `thermal-registry` initcall at Stage::PostCore (#907) — so by the
//! time this Stage::Subsys initcall runs, registration cannot hit
//! `NotInitialised` in a correctly ordered boot. Registration failures
//! are logged by the bridge, never swallowed.

extern crate alloc;

use core::fmt::Write;

use narf_power::acpi_thermal::{register_with_generic_registry, sample_all};
use narf_power::bootstrap_thermal_authority;

/// `_TMP` poll interval, in cycles as passed to
/// `narf_time::sleep_cycles`. Matches the interval the retired
/// per-zone poll tasks used (nominal 5 s).
const POLL_CYCLES: u64 = 5_000_000_000;

pub fn init() {
    let cap = bootstrap_thermal_authority();

    // The bridge applies the canonical warn/crit mapping
    // (crit ← _CRT|_HOT, warn ← _PSV|_AC0) and skips sensorless
    // zones; per-zone failures are logged inside it.
    let registered = register_with_generic_registry(&cap);
    let _ = writeln!(
        narf_console::Writer,
        "  acpi-thermal: {} zone(s) registered with the thermal registry",
        registered
    );
    if registered == 0 {
        // No usable zones (or a repeat call — the bridge is
        // idempotent). Don't spawn a poll task with nothing to sample.
        return;
    }

    // One poll task for every bridged zone (the bridge keeps the
    // path → registry-id map). Stackful: ACPI _TMP evaluation can be
    // expensive on real silicon; preemption-capped.
    narf_scheduler::spawn_stackful(async move {
        loop {
            sample_all();

            // Poll every 5 seconds (standard ACPI interval).
            narf_time::sleep_cycles(POLL_CYCLES).await;
        }
    });
}
