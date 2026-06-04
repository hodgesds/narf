//! Global hwmon device registry.
//!
//! Two parallel registries:
//!
//! 1. [`REGISTRY`] — lightweight `RegisteredSensor` snapshots for early
//!    diagnostics (name / description / bus_loc).  Drivers push here during
//!    `Stage::Subsys` probe.
//!
//! 2. [`DEVICE_REGISTRY`] — live `Arc<dyn HwmonDevice>` objects.  Drivers
//!    push here alongside the snapshot so the sysfs bridge (Stage::Late)
//!    can manufacture `AttrShow` closures that call through to live hardware.
//!
//! Thread-safety: registration happens at Stage::Subsys (single-threaded
//! kernel init), reads can occur from any context after that.
//! `IrqSafeSpinLock<Vec<_>>` is the simplest correct approach; the
//! vectors are small (< 16 entries on a typical laptop).

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

/// Maximum number of sensor label strings per device kept in the
/// compact registry snapshot. Full label lists are returned via
/// `HwmonDevice::list_labels()`.
pub const MAX_LABELS_PER_DEVICE: usize = 32;

/// A static snapshot of a registered hwmon device.
#[derive(Debug)]
pub struct RegisteredSensor {
    /// Driver / chip name, e.g. `"k10temp"`.
    pub name: &'static str,
    /// Human-readable chip description.
    pub description: &'static str,
    /// PCI/ISA bus location, if applicable.
    pub bus_loc: &'static str,
}

static REGISTRY: IrqSafeSpinLock<Vec<RegisteredSensor>> = IrqSafeSpinLock::new(Vec::new());

static DEVICE_REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn crate::HwmonDevice + Send + Sync>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register a hwmon device snapshot. Called from driver probe paths.
pub fn register(sensor: RegisteredSensor) {
    REGISTRY.lock().push(sensor);
}

/// Register a live hwmon device object. Called from driver probe paths
/// alongside `register()` so the sysfs bridge can attach `AttrShow`
/// closures that call through to the driver.
pub fn register_device(dev: Arc<dyn crate::HwmonDevice + Send + Sync>) {
    DEVICE_REGISTRY.lock().push(dev);
}

/// Returns a snapshot of all registered hwmon devices. The returned
/// `Vec` is owned by the caller; the registry lock is held only
/// for the duration of the clone.
pub fn sensors() -> Vec<RegisteredSensor> {
    // RegisteredSensor contains only &'static strs, which are Copy.
    // We cannot derive Copy (Vec doesn't implement it), but we can
    // reconstruct the entries manually.
    let g = REGISTRY.lock();
    g.iter()
        .map(|s| RegisteredSensor {
            name: s.name,
            description: s.description,
            bus_loc: s.bus_loc,
        })
        .collect()
}

/// Returns clones of all live device Arcs.
///
/// The registry lock is held only for the duration of the clone.
/// Used by the sysfs bridge (Stage::Late) to build `AttrShow` closures.
pub fn devices() -> Vec<Arc<dyn crate::HwmonDevice + Send + Sync>> {
    DEVICE_REGISTRY.lock().clone()
}

/// Number of registered device snapshots.
pub fn count() -> usize {
    REGISTRY.lock().len()
}

/// Number of registered live device objects.
pub fn device_count() -> usize {
    DEVICE_REGISTRY.lock().len()
}

/// Clear both device registries. TEST USE ONLY.
#[doc(hidden)]
pub fn __reset_devices_for_test() {
    REGISTRY.lock().clear();
    DEVICE_REGISTRY.lock().clear();
}
