//! Thermal composition — hand controllable hwmon fan channels to the
//! `narf_power::thermal` active-cooling governor as cooling devices.
//!
//! Before this module, [`crate::HwmonDevice::set_fan`] had no
//! production caller anywhere in the tree (#909): the drivers could
//! drive fan PWM, but nothing in the running kernel ever asked them
//! to. The governor in `power/` drives every registered
//! [`CoolingDevice`] with a 0–255 level — exactly the duty contract
//! `set_fan` documents — so each hwmon fan channel whose driver
//! reports [`crate::HwmonDevice::supports_fan_control`] is registered
//! here at `Stage::Late` (after all driver probes, alongside the
//! sysfs bridge population). The userspace path to the same drivers
//! is the writable `pwm<n>` sysfs attribute (see `sysfs_bridge`).

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use core::fmt::Write as _;

use narf_console::Writer;
use narf_power::bootstrap_thermal_authority;
use narf_power::thermal::{register_cooling_device, CoolingDevice};

use crate::HwmonDevice;

/// A [`CoolingDevice`] backed by one controllable hwmon fan channel.
///
/// `set_level` forwards the governor's 0–255 level straight to
/// [`HwmonDevice::set_fan`] for the channel's label; the bool result
/// is dropped because the `CoolingDevice` surface is infallible (a
/// channel that stops answering simply stops cooling — the governor
/// has no error channel, matching `drivers/platform`'s `AcpiFan`).
#[derive(Debug)]
pub struct HwmonCoolingDevice {
    dev: Arc<dyn HwmonDevice + Send + Sync>,
    label: String,
}

impl HwmonCoolingDevice {
    /// Wrap the fan channel `label` of `dev` as a cooling device.
    pub fn new(dev: Arc<dyn HwmonDevice + Send + Sync>, label: &str) -> Self {
        Self {
            dev,
            label: String::from(label),
        }
    }
}

impl CoolingDevice for HwmonCoolingDevice {
    fn name(&self) -> &'static str {
        // Role name, like `AcpiFan`'s "acpi-fan": the per-device
        // identity (chip + channel) is in the `Debug` representation.
        "hwmon-fan"
    }

    fn set_level(&self, level: u8) {
        let _ = self.dev.set_fan(&self.label, level);
    }
}

/// Register every controllable hwmon fan channel as a thermal
/// cooling device.
///
/// Called from the `hwmon-cooling` `Stage::Late` initcall. The
/// thermal registry is initialised at `Stage::PostCore`, so
/// registration can only fail if that bring-up did not happen; each
/// failure is logged with its device and channel (never silently
/// swallowed — the #907 rule the platform fan driver follows), and
/// the final count is reported either way.
pub fn register_hwmon_cooling_devices() {
    let cap = bootstrap_thermal_authority();
    let mut registered: u32 = 0;
    for dev in crate::registry::devices() {
        for label in dev.list_labels() {
            if !dev.supports_fan_control(label) {
                continue;
            }
            let cooling = Arc::new(HwmonCoolingDevice::new(dev.clone(), label));
            match register_cooling_device(&cap, cooling) {
                Ok(()) => registered += 1,
                Err(e) => {
                    let _ = writeln!(
                        Writer,
                        "  hwmon: cooling registration failed for {}/{}: {:?}",
                        dev.name(),
                        label,
                        e
                    );
                }
            }
        }
    }
    let _ = writeln!(
        Writer,
        "  hwmon: {} fan channel(s) registered as thermal cooling devices",
        registered
    );
}
