//! Type-C connector global registry.
//!
//! Separate from `class::REGISTRY` (which stores `Arc<dyn ExtconDevice>`)
//! so that the sysfs bridge can access `TypecConnector`-specific fields
//! (orientation, power/data roles, alt modes) without a downcast.
//!
//! Linux analogue: the list of `typec_port` objects maintained by
//! `drivers/usb/typec/class.c` (`typec_register_port()` / the
//! `typec_port_list` hidden inside the class).

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::typec::TypecConnector;

/// All registered Type-C connector instances.
///
/// Linux analogue: the per-class device list maintained by the
/// driver model under `struct class typec_class` in
/// `drivers/usb/typec/class.c`.
pub static TYPEC_REGISTRY: IrqSafeSpinLock<Vec<Arc<TypecConnector>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register a `TypecConnector`, making it visible to the sysfs bridge
/// and any future in-kernel consumers.
///
/// Callers typically also call `crate::class::register(conn.clone())`
/// if they want the connector to appear in the extcon registry as well.
///
/// Linux analogue: `typec_register_port()` (class.c).
pub fn typec_register(conn: Arc<TypecConnector>) {
    TYPEC_REGISTRY.lock().push(conn);
}

/// Return the number of registered Type-C connectors.
pub fn typec_count() -> usize {
    TYPEC_REGISTRY.lock().len()
}
