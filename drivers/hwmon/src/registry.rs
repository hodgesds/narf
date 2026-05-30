//! Global hwmon device registry.
//!
//! Drivers call [`register`] during their probe path to publish a
//! [`RegisteredSensor`] entry.  Userspace / diagnostics call
//! [`sensors`] to iterate them.
//!
//! Thread-safety: registration happens at Stage::Subsys (single-
//! threaded kernel init), reads can occur from any context after that.
//! An `IrqSafeSpinLock<Vec<_>>` is the simplest correct approach; the
//! vector is small (< 16 entries on a typical laptop).

extern crate alloc;

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

static REGISTRY: IrqSafeSpinLock<Vec<RegisteredSensor>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register a hwmon device. Called from driver probe paths.
pub fn register(sensor: RegisteredSensor) {
    REGISTRY.lock().push(sensor);
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

/// Number of registered devices.
pub fn count() -> usize {
    REGISTRY.lock().len()
}
