//! Hardware monitoring drivers for NARF.
//!
//! Provides the [`HwmonDevice`] trait and concrete drivers for:
//! - [`k10temp`] — AMD Family 17h/19h CPU (Zen2 + Zen4) temperature / voltage
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
pub mod coretemp;
pub mod dell_smm;
pub mod it87;
pub mod jc42;
pub mod k10temp;
pub mod nct6775;
pub mod registry;
#[cfg(feature = "linux-compat")]
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
    fn set_fan(&self, label: &str, level: u8) -> bool;

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
    narf_init::register(Stage::Subsys, "hwmon-coretemp", || {
        #[cfg(target_arch = "x86_64")]
        coretemp::register_msr_driver();
        InitResult::Ok
    });
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
    #[cfg(feature = "linux-compat")]
    narf_init::register(Stage::Late, "hwmon-sysfs-bridge", || {
        sysfs_bridge::populate_hwmon_class();
        InitResult::Ok
    });
}
