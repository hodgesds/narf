//! Watchdog device class: trait + global registry.
//!
//! Mirrors the Linux watchdog class registry shape
//! (`drivers/watchdog/watchdog_dev.c`): devices register once under
//! a unique name and the subsystem dispatches operations through
//! the trait. There is no arbitration here (unlike backlight's
//! panel owner): a machine has at most one watchdog block, and a
//! second registration under the same name replaces the first,
//! matching the backlight registry's idempotency assumption.

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;

use narf_lib::sync::IrqSafeSpinLock;

/// Errors a watchdog operation can return.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WatchdogError {
    /// The requested timeout is outside the device's tick range
    /// (below the minimum tick, above the maximum tick, or outside
    /// the WDDT count bounds when those bound the range).
    InvalidTimeout,
    /// No watchdog device is registered under the requested name.
    NotPresent,
}

/// Live status snapshot of a watchdog device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WatchdogStatus {
    /// True when the timer is running (halt bit clear).
    pub armed: bool,
    /// True when the first-timeout (TIMEOUT) status bit is latched.
    pub timed_out: bool,
    /// True when the second-timeout (SECOND_TO_STS) status bit is
    /// latched: the timer expired twice without a reload in between.
    pub second_timeout: bool,
    /// Approximate seconds left on the current countdown
    /// (current count x 0.6s, truncated). Zero when disarmed.
    pub timeleft_secs: u32,
    /// True when this driver cannot control the platform's
    /// NO_REBOOT bit (see the iTCO module docs): expiry then
    /// follows firmware's reboot policy rather than the driver's.
    pub no_reboot_control: bool,
}

/// Trait implemented by every watchdog device that registers with
/// the subsystem.
///
/// Implementations must be `Send + Sync` so the static registry can
/// hold them behind an `Arc`.
pub trait WatchdogDevice: Send + Sync + Debug {
    /// Device name, e.g. `"watchdog0"`.
    fn name(&self) -> &str;

    /// Arm (or re-arm) the watchdog with a `secs` timeout. The
    /// timer starts counting down immediately; it must be petted
    /// before expiry or the platform takes its expiry action.
    fn set_timeout(&self, secs: u32) -> Result<(), WatchdogError>;

    /// Reload the timer to its programmed timeout ("pet" / keepalive).
    /// Harmless when disarmed.
    fn pet(&self);

    /// Halt the timer. The device stays registered; a later
    /// `set_timeout` re-arms it.
    fn stop(&self);

    /// Current status snapshot.
    fn status(&self) -> WatchdogStatus;
}

static WATCHDOG_DEVS: IrqSafeSpinLock<Vec<Arc<dyn WatchdogDevice>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register a watchdog device. The name must be unique; duplicate
/// names silently replace the previous entry.
pub fn register_watchdog(dev: Arc<dyn WatchdogDevice>) {
    let name: String = dev.name().to_owned();
    let mut g = WATCHDOG_DEVS.lock();
    if let Some(slot) = g.iter_mut().find(|d| d.name() == name) {
        *slot = dev;
    } else {
        g.push(dev);
    }
}

/// Unregister a watchdog device by name.
pub fn unregister_watchdog(name: &str) {
    WATCHDOG_DEVS.lock().retain(|d| d.name() != name);
}

/// Return a snapshot of all registered watchdog devices.
pub fn watchdog_devices() -> Vec<Arc<dyn WatchdogDevice>> {
    WATCHDOG_DEVS.lock().clone()
}

/// Find a device by name.
pub fn watchdog_device(name: &str) -> Option<Arc<dyn WatchdogDevice>> {
    WATCHDOG_DEVS
        .lock()
        .iter()
        .find(|d| d.name() == name)
        .cloned()
}

/// Test helper: drain the registry.
#[doc(hidden)]
pub fn __reset_for_test() {
    WATCHDOG_DEVS.lock().clear();
}
