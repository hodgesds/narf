//! Extcon class — `ExtconDevice` trait + global registry.
//!
//! Linux ref: `drivers/extcon/extcon.c`:
//! - `extcon_dev_register()` → [`register`]
//! - `extcon_get_state()` → [`ExtconDevice::cable_state`]
//! - `extcon_register_notifier()` → [`ExtconDevice::subscribe`]
//!
//! Design differences from Linux:
//! - No sysfs; NARF has no VFS yet.  Cable state is polled via the
//!   trait + pushed via the subscriber interface.
//! - The registry is a global `IrqSafeSpinLock<Vec<Arc<dyn
//!   ExtconDevice>>>` rather than a kernel-linked list.
//! - Subscribers are `Arc<dyn ExtconEventSink>` objects stored per
//!   device; no blocking notifiers.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::cable::Cable;

// ── Event sink (subscriber) ────────────────────────────────────────

/// Callback interface for cable-state changes.
///
/// Called from whatever context updates the connector's cable state.
/// Implementations must be fast and non-blocking (no alloc, no
/// sleeping, no lock hierarchy violations).
pub trait ExtconEventSink: Send + Sync {
    /// Called when `cable`'s attached state changes to `attached`.
    fn on_cable_change(&self, device: &str, cable: Cable, attached: bool);
}

// ── ExtconDevice trait ─────────────────────────────────────────────

/// An external connector device.
///
/// Implemented by platform connectors, USB-C ports, audio-jack
/// detection circuits, etc.
///
/// Linux analogue: `struct extcon_dev` + the `extcon_get_state` /
/// `extcon_update_state` public API in `drivers/extcon/extcon.c`.
pub trait ExtconDevice: Send + Sync {
    /// Stable name for diagnostics, e.g. `"extcon0"` or
    /// `"typec-port0"`.
    fn name(&self) -> &str;

    /// The cables this device can ever report. Static; doesn't
    /// change after registration. Corresponds to
    /// `extcon_dev::supported_cable[]` (Linux extcon.c line ~134).
    fn supported_cables(&self) -> &[Cable];

    /// Current attachment state for `cable`. Returns `false` for
    /// cables not in `supported_cables()`.
    fn cable_state(&self, cable: Cable) -> bool;

    /// Register a subscriber. The extcon device calls
    /// `sink.on_cable_change(…)` whenever a cable's state changes.
    fn subscribe(&self, sink: Arc<dyn ExtconEventSink>);
}

// ── Global registry ────────────────────────────────────────────────

/// All registered extcon devices.
///
/// Linux analogue: `extcon_dev_list` (a kernel-linked list in
/// `drivers/extcon/extcon.c`).
pub static REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn ExtconDevice>>> = IrqSafeSpinLock::new(Vec::new());

/// Register an extcon device, making it visible to the rest of the
/// kernel.
///
/// Linux analogue: `extcon_dev_register()` (extcon.c).
pub fn register(dev: Arc<dyn ExtconDevice>) {
    REGISTRY.lock().push(dev);
}

/// Look up an extcon device by name. Returns `None` if no device
/// with that name is registered.
pub fn lookup(name: &str) -> Option<Arc<dyn ExtconDevice>> {
    REGISTRY.lock().iter().find(|d| d.name() == name).cloned()
}

/// Return the number of registered extcon devices.
pub fn device_count() -> usize {
    REGISTRY.lock().len()
}
