use super::*;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

static REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn I3cBus>>> = IrqSafeSpinLock::new(Vec::new());

pub fn register(bus: Arc<dyn I3cBus>) {
    REGISTRY.lock().push(bus);
}

pub fn list() -> Vec<Arc<dyn I3cBus>> {
    REGISTRY.lock().clone()
}
