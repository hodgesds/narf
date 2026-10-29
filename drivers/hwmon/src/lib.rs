//! Hardware monitoring drivers for NARF.
//!
//! Provides the [`HwmonDevice`] trait and concrete drivers for:
//! - [`k10temp`] — AMD Family 17h/19h CPU (Zen2 + Zen4) temperature
//! - [`coretemp`] — Intel per-core thermal status via MSR 0x19C/0x1A2
//! - [`nct6775`] — Nuvoton NCT6775/6776/6779/6791-6798 Super-I/O
//! - [`dell_smm`] — Dell SMM/i8042 fan + temp interface (Dell laptops)
//!
//! Linux references:
//! - `drivers/hwmon/k10temp.c`    (Clemens Ladisch + Jean Delvare)
//! - `drivers/hwmon/coretemp.c`   (Rudolf Marek et al.)
//! - `drivers/hwmon/nct6775_core.c` (Guenter Roeck)
//!
//! ## Temperature units
//!
//! All `read_temp` values are in **millidegrees Celsius** (mC), matching
//! the Linux hwmon convention (`/sys/class/hwmon/hwmonN/tempM_input`).
//! `read_fan` is in RPM. `read_voltage` is in millivolts.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod applesmc;
pub mod cooling;
pub mod coretemp;
pub mod dell_smm;
pub mod it87;
pub mod jc42;
pub mod k10temp;
pub mod nct6775;
pub mod power_providers;
pub mod registry;
pub mod sysfs_bridge;

mod tests;

/// Shared hwmon device trait. Every hardware-monitoring driver exposes
/// temperatures, fan speeds, and voltages through this interface.
///
/// Label strings are driver-defined, e.g. `"Tdie"`, `"fan1"`, `"in0"`.
/// Drivers that do not support a measurement class always return `None`.
pub trait HwmonDevice: core::fmt::Debug {
    /// Short driver / chip name, e.g. `"k10temp"` or `"nct6775"`.
    fn name(&self) -> &str;

    /// Read a temperature sensor by label. Returns millidegrees Celsius,
    /// or `None` if the label is unknown or the read fails.
    fn read_temp(&self, label: &str) -> Option<i32>;

    /// Read a fan tachometer by label. Returns RPM, or `None`.
    fn read_fan(&self, label: &str) -> Option<u32>;

    /// Read a voltage input by label. Returns millivolts, or `None`.
    fn read_voltage(&self, label: &str) -> Option<i32>;

    /// Set a fan PWM output level (0–255). Returns `false` if the label
    /// is not a controllable fan or the chip does not support fan control.
    ///
    /// `label` is a fan channel label from [`HwmonDevice::list_labels`]
    /// (e.g. `"fan1"`); `level` is a PWM duty in 0–255. Drivers whose
    /// hardware takes discrete levels instead of a duty (Dell SMM fan
    /// tiers) scale the duty internally — the 0–255 contract holds at
    /// this surface regardless of the hardware's native units.
    fn set_fan(&self, label: &str, level: u8) -> bool;

    /// The device's real high (`max`) and critical (`crit`) temperature
    /// limits for `label`, in millidegrees Celsius, as the hardware
    /// itself reports them — a Tjmax MSR, a programmed limit register,
    /// and so on. Either component is `None` when the hardware exposes
    /// no such limit for the label.
    ///
    /// The sysfs bridge publishes `temp<n>_max` / `temp<n>_crit` only
    /// for components that return `Some` (#909): thresholds are never
    /// invented constants. The default reports no limits.
    fn temp_limits(&self, _label: &str) -> (Option<i32>, Option<i32>) {
        (None, None)
    }

    /// Read back the current PWM duty (0–255) of a fan channel, by the
    /// same label [`HwmonDevice::set_fan`] takes. Returns `None` if the
    /// channel is not controllable or the read fails. Default: `None`.
    fn read_pwm(&self, _label: &str) -> Option<u8> {
        None
    }

    /// Whether the fan channel named by `label` (a label from
    /// [`HwmonDevice::list_labels`], e.g. `"fan1"`) can be driven via
    /// [`HwmonDevice::set_fan`]. The sysfs bridge publishes a writable
    /// `pwm<n>` attribute — and the thermal composition registers a
    /// cooling device — only for channels that return `true`, so a
    /// published control always has a real driver behind it.
    /// Default: `false`.
    fn supports_fan_control(&self, _label: &str) -> bool {
        false
    }

    /// List all sensor labels exposed by this device. The returned slice
    /// references static strings owned by the driver; no allocation.
    fn list_labels(&self) -> alloc::vec::Vec<&str>;
}

/// Stage::Subsys initcalls for hardware-monitoring crate.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "hwmon-k10temp", || {
        k10temp::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "hwmon-nct6775", || {
        nct6775::register_isa_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "hwmon-it87", || {
        it87::register_isa_driver();
        InitResult::Ok
    });
    narf_init::register(
        Stage::Subsys,
        "hwmon-coretemp",
        coretemp::register_msr_driver,
    );
    narf_init::register(Stage::Subsys, "hwmon-applesmc", || {
        #[cfg(target_arch = "x86_64")]
        applesmc::register_smc_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "hwmon-dell-smm", || {
        #[cfg(target_arch = "x86_64")]
        dell_smm::register_smm_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "hwmon-jc42", || {
        jc42::register_initcalls();
        InitResult::Ok
    });
    // Stage::Late: sysfs bridge runs after all Stage::Subsys driver probes.
    narf_init::register(Stage::Late, "hwmon-sysfs-bridge", || {
        sysfs_bridge::populate_hwmon_class();
        InitResult::Ok
    });
    // Stage::Late: hand every controllable hwmon fan to the thermal
    // governor as a cooling device (see `cooling`). Runs after the
    // bridge registration above; the thermal registry itself is
    // initialised at Stage::PostCore, so it is live by now.
    narf_init::register(Stage::Late, "hwmon-cooling", || {
        cooling::register_hwmon_cooling_devices();
        InitResult::Ok
    });
    // Stage::Late: publish the CPU temperature into the power
    // service's fused snapshot (#914). The provider reads this
    // crate's registry live at snapshot time, so driver probe
    // order does not matter.
    narf_init::register(Stage::Late, "hwmon-power-providers", || {
        power_providers::register_temp_providers();
        InitResult::Ok
    });
}
