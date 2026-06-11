//! Unified laptop power-state snapshot.
//!
//! Fuses the per-source state models added through the laptop
//! bring-up round into a single observable snapshot that the UI
//! (status bar, battery indicator) and diagnostics tooling can
//! read in one call.
//!
//! Each field reads through whatever subsystem owns the source
//! of truth; this module just aggregates. State is read-only
//! from here — writes (e.g. set backlight) go through the
//! per-source surface (e.g. AmdGpu::set_backlight).

extern crate alloc;

use narf_acpi::ac_adapter::AcAdapterState;
use narf_acpi::battery::{BatteryInfo, BatteryState};
use narf_acpi::lid::LidState;

/// What the host knows about the laptop's power + thermal state
/// at one moment. All fields are `Option<_>` so the snapshot is
/// usable on systems that don't expose every source (e.g., desktop
/// SKUs without a battery / lid).
#[derive(Clone, Debug, Default)]
pub struct LaptopStateSnapshot {
    /// AC adapter (wall-power) plug state.
    pub ac_adapter: Option<AcAdapterState>,
    /// Lid switch position.
    pub lid: Option<LidState>,
    /// Power-button presses observed since the last drain by the
    /// power service. Useful for the UI to debounce.
    pub power_button_presses: u8,
    /// Sleep-button presses since last drain.
    pub sleep_button_presses: u8,
    /// CPU package Tdie in milli-degrees Celsius (per k10temp).
    pub cpu_tdie_mc: Option<i32>,
    /// GPU package temperature in m°C (per SMU).
    pub gpu_temp_mc: Option<i32>,
    /// Battery info (static, from _BIF).
    pub battery_info: Option<BatteryInfo>,
    /// Battery state (dynamic, from _BST).
    pub battery_state: Option<BatteryState>,
}

impl LaptopStateSnapshot {
    /// "Battery is running low and AC isn't connected" — used by
    /// the power service to fire the critical-low warning.
    pub fn is_running_low_on_battery(&self) -> bool {
        let on_battery = matches!(self.ac_adapter, Some(AcAdapterState::Offline) | None);
        let critical = self.battery_state.as_ref().is_some_and(|s| s.is_critical());
        on_battery && critical
    }

    /// True iff any thermal sensor reports above `threshold_mc` —
    /// the throttle subsystem polls this every few hundred ms.
    pub fn any_temp_above(&self, threshold_mc: i32) -> bool {
        let cpu_hot = self.cpu_tdie_mc.is_some_and(|t| t > threshold_mc);
        let gpu_hot = self.gpu_temp_mc.is_some_and(|t| t > threshold_mc);
        cpu_hot || gpu_hot
    }

    /// "Lid is shut" — the power service uses this to gate
    /// suspend-on-close policy.
    pub fn lid_is_closed(&self) -> bool {
        matches!(self.lid, Some(LidState::Closed))
    }

    /// Battery percent remaining, fused from info + state. None
    /// when either isn't known yet.
    pub fn battery_percent(&self) -> Option<u8> {
        let info = self.battery_info.as_ref()?;
        let state = self.battery_state.as_ref()?;
        state.percent_remaining(info)
    }
}
