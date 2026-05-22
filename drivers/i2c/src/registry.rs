//! Process-global registry of I2C buses, keyed by controller name.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

use crate::I2cBus;

static BUSES: IrqSafeSpinLock<Vec<Arc<dyn I2cBus>>> = IrqSafeSpinLock::new(Vec::new());

/// Lock-free snapshot of the registered-bus count. Updated whenever
/// `register_unique` adds an entry. status::paint / other diagnostics
/// read this WITHOUT taking the registry lock so a driver mid-probe
/// (holding BUSES via register_unique) doesn't block the diagnostic
/// path on `IrqSafeSpinLock`-induced IF=0 spin.
pub static REGISTERED_COUNT: AtomicU32 = AtomicU32::new(0);

/// Register a bus. If another bus with the same `name()` is already
/// present, the new one is rejected and the existing one returned —
/// re-running discovery against already-probed hardware is a no-op.
pub fn register_unique(bus: Arc<dyn I2cBus>) -> Arc<dyn I2cBus> {
    let mut g = BUSES.lock();
    let name = bus.name();
    if let Some(existing) = g.iter().find(|b| b.name() == name) {
        return existing.clone();
    }
    g.push(bus.clone());
    REGISTERED_COUNT.store(g.len() as u32, Ordering::Release);
    bus
}

/// Snapshot of every registered bus.
pub fn list() -> Vec<Arc<dyn I2cBus>> {
    BUSES.lock().clone()
}

/// Look up a bus by its registered name (the ACPI path of the
/// controller, in the AMD FCH case).
pub fn find(name: &str) -> Option<Arc<dyn I2cBus>> {
    BUSES.lock().iter().find(|b| b.name() == name).cloned()
}

/// Number of registered buses.
pub fn count() -> usize {
    BUSES.lock().len()
}

/// Test-only: drop every registered bus so each smoke starts from a
/// clean registry. Hermetic isolation between tests.
#[doc(hidden)]
pub fn __reset_for_test() {
    BUSES.lock().clear();
    REGISTERED_COUNT.store(0, Ordering::Release);
}

/// Test-only: register without the duplicate-name check (used by
/// smokes that want to confirm uniqueness behaviour).
#[doc(hidden)]
pub fn __push_for_test(bus: Arc<dyn I2cBus>) {
    let mut g = BUSES.lock();
    g.push(bus);
    REGISTERED_COUNT.store(g.len() as u32, Ordering::Release);
}

// Suppress "unused" warnings for `String` when no callers materialise
// in this crate's no-default-features build.
#[allow(dead_code)]
fn _force_string_use(_: String) {}
