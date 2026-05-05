use super::*;
use narf_lib::sync::IrqSafeSpinLock;
use alloc::vec::Vec;
use alloc::sync::Arc;

static REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn I3cBus>>> = IrqSafeSpinLock::new(Vec::new());

pub fn register(bus: Arc<dyn I3cBus>) {
    REGISTRY.lock().push(bus);
}

pub fn list() -> Vec<Arc<dyn I3cBus>> {
    REGISTRY.lock().clone()
}
