//! Process-global registry of GPIO controllers, keyed by name.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

use crate::GpioController;

static CTRLS: IrqSafeSpinLock<Vec<Arc<dyn GpioController>>> = IrqSafeSpinLock::new(Vec::new());

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

/// Snapshot the current registry contents. Pairs with
/// `__restore_for_test`: the synthetic smokes in `tests` isolate
/// themselves by resetting, but a bare reset wipes the boot-time
/// DT bindings (the PL061 at 0x0903_0000) before the live DT
/// smoke reads the registry — the registry check then fails
/// while the probe's BOUND record still reports INTID 39.
/// Snapshotting before the reset and restoring after keeps
/// isolation without destroying live bindings.
#[doc(hidden)]
pub fn __snapshot_for_test() -> Vec<Arc<dyn GpioController>> {
    CTRLS.lock().clone()
}

/// Restore a snapshot taken by `__snapshot_for_test`, replacing
/// the current contents. Refreshes the lock-free count.
#[doc(hidden)]
pub fn __restore_for_test(entries: Vec<Arc<dyn GpioController>>) {
    let mut g = CTRLS.lock();
    *g = entries;
    REGISTERED_COUNT.store(g.len() as u32, Ordering::Release);
}
