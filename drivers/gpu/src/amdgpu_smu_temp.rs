//! SMU temperature provider for the power service (#1186, #914 remainder).
//!
//! `LaptopStateSnapshot.gpu_temp_mc` ("GPU package temperature, per SMU")
//! had no production provider: the only SMU temperature surface was a
//! decode on a metrics-table snapshot (`amdgpu_smu::parse_metrics`,
//! exercised only from tests), with no live handle and no provider
//! registration. The telemetry owners close that gap — each
//! refreshes PMFW metrics on a one-second cadence through the retained
//! SMU owner and publishes the last sample (`amdgpu_navi22_power` for
//! SMU11/Navi22, `amdgpu_navi48_power` for SMU14/Navi48,
//! `amdgpu_smu_apu_telemetry` for SMU 12/13 Renoir/Phoenix APUs, the
//! same cached table Linux serves sysfs reads from). This module reads
//! the last published **edge** temperature from those owners and
//! registers it as the power service's `gpu_temp_mc` provider.
//!
//! Edge (`temp1`, `METRICS_TEMPERATURE_EDGE`) is the package sensor
//! the snapshot field is documented for — the same choice the hwmon
//! surface makes for `temp1_input`; hotspot (`temp2`, junction) is
//! the thermal-trip sensor, not the package temperature. The value
//! flows through unchanged: the discrete telemetry `Metrics` already
//! carry milli-degrees Celsius, so no rescaling happens here; the
//! APU sample arrives in centi-Celsius and its
//! `edge_temperature_milli_c()` accessor converts (centi-C × 10).
//!
//! A machine with no telemetry owner publishing a sample yields
//! `None` — the field stays unknown rather than reporting a
//! fabricated zero (the hwmon class rule). That still includes
//! APU-only machines (Renoir/Phoenix, SMU 12/13) until the APU owner
//! is attached: the owner exists (`amdgpu_smu_apu_telemetry`) and
//! this module already reads its last published sample, but no APU
//! platform singleton exists to retain the owner and spawn its 1 s
//! monitor, so no live APU sample is published yet; the attach is
//! the remaining #1698 remainder.

use alloc::sync::Arc;

use narf_power::bootstrap_power_authority;
use narf_power::service::{register_state_providers, StateProviders};

use crate::amdgpu_navi22_power::Snapshot as Navi22Snapshot;
use crate::amdgpu_navi48_power::Snapshot as Navi48Snapshot;
use crate::amdgpu_smu_apu_telemetry::ApuSnapshot;

/// Edge temperature in milli-degrees Celsius from one generation's
/// last published snapshot. `None` when the owner never published,
/// or its last sample is absent (owner started, no refresh yet).
fn edge_from_navi22(snapshot: Option<Navi22Snapshot>) -> Option<i32> {
    snapshot
        .and_then(|s| s.telemetry)
        .map(|t| t.metrics.edge_milli)
}

/// Edge temperature in milli-degrees Celsius from one generation's
/// last published snapshot. `None` when the owner never published,
/// or its last sample is absent (owner started, no refresh yet).
fn edge_from_navi48(snapshot: Option<Navi48Snapshot>) -> Option<i32> {
    snapshot
        .and_then(|s| s.telemetry)
        .map(|t| t.metrics.edge_milli)
}

/// Edge temperature in milli-degrees Celsius from the APU owner's
/// last published snapshot. `None` when the owner never published,
/// or its last sample is absent (owner started, no refresh yet).
fn edge_from_apu(snapshot: Option<ApuSnapshot>) -> Option<i32> {
    snapshot.and_then(|s| s.edge_temperature_milli_c())
}

/// First live edge reading across the telemetry owners, in
/// milli-degrees Celsius. Navi22 is consulted first, then Navi48,
/// then the APU owner; a snapshot without telemetry does not shadow
/// a live reading from another owner. `None` when no owner has a
/// sample.
pub(crate) fn gpu_temp_mc_from(
    navi22: Option<Navi22Snapshot>,
    navi48: Option<Navi48Snapshot>,
    apu: Option<ApuSnapshot>,
) -> Option<i32> {
    edge_from_navi22(navi22)
        .or_else(|| edge_from_navi48(navi48))
        .or_else(|| edge_from_apu(apu))
}

/// Current GPU package temperature in milli-degrees Celsius, read
/// live from the last published telemetry sample: the Navi22 (SMU11),
/// Navi48 (SMU14), or APU (SMU 12/13) owner's edge temperature.
/// `None` when no owner has published a sample.
pub fn gpu_temp_mc() -> Option<i32> {
    gpu_temp_mc_from(
        crate::amdgpu_navi22_power::snapshot(),
        crate::amdgpu_navi48_power::snapshot(),
        crate::amdgpu_smu_apu_telemetry::snapshot(),
    )
}

/// Register the GPU temperature provider with the power service.
/// The merge semantics of `register_state_providers` make this
/// order-independent against the platform composition and the
/// hwmon CPU registration: it fills only `gpu_temp_mc` and leaves
/// every other field untouched.
pub fn register_gpu_temp_provider() {
    let cap = bootstrap_power_authority();
    let providers = StateProviders {
        ac_adapter: None,
        lid: None,
        battery: None,
        cpu_temp_mc: None,
        gpu_temp_mc: Some(Arc::new(gpu_temp_mc)),
    };
    let _ = register_state_providers(&cap, providers);
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_smu_temp_tests.rs"]
mod tests;
