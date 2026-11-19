//! Hooks the USB Bluetooth driver (`narf-drivers-bluetooth-btusb`) installs.
//!
//! btusb used to live in this crate, and the host stack called into it at
//! two points: the attach cascade (async bind of an addressed device) and the
//! supervisor's per-cycle remote-wakeup watch. btusb now depends on this
//! crate, so those two calls go through hook slots it fills at boot. With no
//! hook installed (btusb not built in, or built as a `.ko`), the cascade falls
//! through to the class registry — where a loadable btusb's
//! `narf_register_usb_driver` match is offered the device — and the wake
//! watch does nothing.
//!
//! Each slot holds a kernel-resident function for the kernel's lifetime; a
//! hook never points into unloadable module text.

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::xhci::Xhci;

/// Future returned by a Bluetooth hook, borrowing the controller (and the
/// configuration descriptor, for the binder).
pub type HookFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Attach-cascade binder: `(controller, slot, vid, pid, config descriptor,
/// hub context)` → `true` when it bound the device. Runs at btusb's historic
/// position in the cascade (after CDC-ECM, before the fingerprint matchers).
pub type BluetoothBinder =
    for<'a> fn(&'a Xhci, u8, u16, u16, &'a [u8], Option<(u8, u8)>) -> HookFuture<'a, bool>;

/// Supervisor wake watch: resume a parked controller's port on an observed
/// remote-wakeup edge. Runs once per supervisor cycle, before the pumps.
pub type BluetoothWakeWatch = for<'a> fn(&'a Xhci) -> HookFuture<'a, ()>;

static BINDER: AtomicUsize = AtomicUsize::new(0);
static WAKE_WATCH: AtomicUsize = AtomicUsize::new(0);

/// Install the attach-cascade binder. Idempotent.
pub fn set_binder(binder: BluetoothBinder) {
    BINDER.store(binder as usize, Ordering::Release);
}

/// Install the supervisor wake watch. Idempotent.
pub fn set_wake_watch(watch: BluetoothWakeWatch) {
    WAKE_WATCH.store(watch as usize, Ordering::Release);
}

/// Run the installed binder; `false` when none is installed.
pub(crate) async fn bind(
    xhci: &Xhci,
    slot_id: u8,
    vendor_id: u16,
    product_id: u16,
    cfg: &[u8],
    hub_port: Option<(u8, u8)>,
) -> bool {
    let raw = BINDER.load(Ordering::Acquire);
    if raw == 0 {
        return false;
    }
    // SAFETY: only `set_binder` stores here, and it stores a `BluetoothBinder`.
    let binder: BluetoothBinder = unsafe { core::mem::transmute(raw) };
    binder(xhci, slot_id, vendor_id, product_id, cfg, hub_port).await
}

/// Run the installed wake watch, if any.
pub(crate) async fn wake_watch(xhci: &Xhci) {
    let raw = WAKE_WATCH.load(Ordering::Acquire);
    if raw == 0 {
        return;
    }
    // SAFETY: only `set_wake_watch` stores here, and it stores a
    // `BluetoothWakeWatch`.
    let watch: BluetoothWakeWatch = unsafe { core::mem::transmute(raw) };
    watch(xhci).await;
}

/// Whether btusb installed its binder (diagnostics and smokes).
pub fn binder_installed() -> bool {
    BINDER.load(Ordering::Acquire) != 0
}
