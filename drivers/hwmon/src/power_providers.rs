//! Power-service snapshot temperature provider (#914).
//!
//! `narf_power::service` fuses a `LaptopStateSnapshot` from
//! registered providers; the platform composition registers the
//! battery / AC / lid providers but leaves the temperature fields
//! unset, so the snapshot's temperatures were never produced in
//! the running system. The CPU temperature source lives here —
//! this crate owns the sensor registry — because the dependency
//! cannot run the other way: `narf-drivers-hwmon` already depends
//! on `narf-drivers-platform`, so platform code cannot call into
//! this crate.
//!
//! The provider resolves the reading live on every snapshot: the
//! k10temp `Tdie` sensor is the source the snapshot field is
//! documented for (`cpu_tdie_mc`, per k10temp); Intel coretemp's
//! package sensor is the fallback on machines with that driver
//! instead. A machine with neither driver probed yields `None` —
//! the field stays unknown rather than reporting a fabricated
//! zero (the hwmon class rule: a failed read renders as absent,
//! never as a made-up value).

use alloc::sync::Arc;

use narf_power::bootstrap_power_authority;
use narf_power::service::{register_state_providers, StateProviders};

use crate::registry;

/// Current CPU package temperature in milli-degrees Celsius, read
/// live from the hwmon registry: k10temp `Tdie` first, coretemp
/// `Tpackage` as the fallback. `None` when no CPU temperature
/// driver has probed (or its read fails).
pub fn cpu_temp_mc() -> Option<i32> {
    let devices = registry::devices();
    for dev in &devices {
        if dev.name() == "k10temp" {
            if let Some(t) = dev.read_temp("Tdie") {
                return Some(t);
            }
        }
    }
    for dev in &devices {
        if dev.name() == "coretemp" {
            if let Some(t) = dev.read_temp("Tpackage") {
                return Some(t);
            }
        }
    }
    None
}

/// Register the CPU temperature provider with the power service.
/// The merge semantics of `register_state_providers` make this
/// order-independent against the platform composition: it fills
/// only `cpu_temp_mc` and leaves every other field untouched.
///
/// `gpu_temp_mc` deliberately stays unset: the amdgpu SMU
/// temperature exists only as a decode of a metrics-table
/// snapshot with no live in-kernel handle and no production
/// reader, so there is no honest reading to publish yet — that
/// half of #914 remains open until the GPU telemetry is
/// published through a live handle.
pub fn register_temp_providers() {
    let cap = bootstrap_power_authority();
    let providers = StateProviders {
        ac_adapter: None,
        lid: None,
        battery: None,
        cpu_temp_mc: Some(Arc::new(cpu_temp_mc)),
        gpu_temp_mc: None,
    };
    let _ = register_state_providers(&cap, providers);
}
