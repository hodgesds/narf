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

    /// Whether, and how, the temperature channel `label` publishes
    /// `temp<n>_<attr>` — Linux's `hwmon_ops.is_visible` (0 / 0444 /
    /// 0644). `None` means the attribute does not exist for this
    /// channel. The sysfs bridge publishes exactly the attributes this
    /// returns `Some` for, so a threshold or alarm is only ever the
    /// hardware's own (#909). The default publishes none.
    fn temp_attr_mode(&self, _label: &str, _attr: TempAttr) -> Option<AttrMode> {
        None
    }

    /// Read `temp<n>_<attr>`: millidegrees Celsius for the limits, 0 or
    /// 1 for the alarms and `enable` (Linux `hwmon_ops.read`). `None`
    /// when the read fails.
    fn read_temp_attr(&self, _label: &str, _attr: TempAttr) -> Option<i64> {
        None
    }

    /// Write `temp<n>_<attr>` (Linux `hwmon_ops.write`). Only called for
    /// attributes [`HwmonDevice::temp_attr_mode`] reports
    /// [`AttrMode::ReadWrite`]; the value is what `kstrtol` parsed.
    fn write_temp_attr(
        &self,
        _label: &str,
        _attr: TempAttr,
        _value: i64,
    ) -> Result<(), HwmonError> {
        Err(HwmonError::InvalidValue)
    }

    /// Whether `temp<n>_label` is published for `label` (Linux:
    /// `HWMON_T_LABEL` in the channel's config). Default: yes.
    fn temp_label_visible(&self, _label: &str) -> bool {
        true
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

/// A temperature-channel attribute beside `temp<n>_input` and
/// `temp<n>_label`, named by its Linux hwmon suffix
/// (`Documentation/hwmon/sysfs-interface.rst`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TempAttr {
    /// `temp<n>_enable`: 1 enabled, 0 disabled.
    Enable,
    /// `temp<n>_lcrit`: low critical limit, millidegrees.
    Lcrit,
    /// `temp<n>_min`: low limit, millidegrees.
    Min,
    /// `temp<n>_max`: high limit, millidegrees.
    Max,
    /// `temp<n>_crit`: high critical limit, millidegrees.
    Crit,
    /// `temp<n>_lcrit_alarm`.
    LcritAlarm,
    /// `temp<n>_min_alarm`.
    MinAlarm,
    /// `temp<n>_max_alarm`.
    MaxAlarm,
    /// `temp<n>_crit_alarm`.
    CritAlarm,
}

impl TempAttr {
    /// Every attribute, in Linux's `hwmon_temp_attr_templates` order.
    pub const ALL: [Self; 9] = [
        Self::Enable,
        Self::Lcrit,
        Self::Min,
        Self::Max,
        Self::Crit,
        Self::LcritAlarm,
        Self::MinAlarm,
        Self::MaxAlarm,
        Self::CritAlarm,
    ];

    /// The sysfs suffix after `temp<n>_`.
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Enable => "enable",
            Self::Lcrit => "lcrit",
            Self::Min => "min",
            Self::Max => "max",
            Self::Crit => "crit",
            Self::LcritAlarm => "lcrit_alarm",
            Self::MinAlarm => "min_alarm",
            Self::MaxAlarm => "max_alarm",
            Self::CritAlarm => "crit_alarm",
        }
    }
}

/// How a published attribute may be accessed (Linux `is_visible`'s
/// 0444 / 0644).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AttrMode {
    ReadOnly,
    ReadWrite,
}

/// Why a hwmon attribute write failed. Each variant is the errno the
/// Linux driver's `write` returns, so the bridge can hand it back to
/// `write(2)` unchanged.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HwmonError {
    /// The value is not one the attribute accepts (`-EINVAL`).
    InvalidValue,
    /// The device did not answer (`-ENXIO`).
    NoResponse,
    /// The bus transaction timed out (`-ETIMEDOUT`).
    Timeout,
    /// The bus is owned elsewhere (`-EBUSY`).
    Busy,
    /// Arbitration was lost; retrying may succeed (`-EAGAIN`).
    Again,
    /// Any other transfer failure (`-EIO`).
    Io,
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
