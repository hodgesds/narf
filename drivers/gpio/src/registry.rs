//! Process-global registry of GPIO controllers, keyed by name.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

use crate::GpioController;

static CTRLS: IrqSafeSpinLock<Vec<Arc<dyn GpioController>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Lock-free snapshot of the registered-controller count. Read by
/// diagnostics without taking the CTRLS lock.
pub static REGISTERED_COUNT: AtomicU32 = AtomicU32::new(0);

/// Register a controller. If another controller with the same `name()`
/// is already present, the new one is rejected and the existing one
/// returned.
pub fn register_unique(c: Arc<dyn GpioController>) -> Arc<dyn GpioController> {
    let mut g = CTRLS.lock();
    let name = c.name();
    if let Some(existing) = g.iter().find(|x| x.name() == name) {
        return existing.clone();
    }
    g.push(c.clone());
    REGISTERED_COUNT.store(g.len() as u32, Ordering::Release);
    c
}

pub fn list() -> Vec<Arc<dyn GpioController>> {
    CTRLS.lock().clone()
}

/// Look up by ACPI path / registered name.
pub fn find(name: &str) -> Option<Arc<dyn GpioController>> {
    CTRLS.lock().iter().find(|c| c.name() == name).cloned()
}

pub fn count() -> usize {
    CTRLS.lock().len()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    CTRLS.lock().clear();
    REGISTERED_COUNT.store(0, Ordering::Release);
}
