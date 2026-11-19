//! USB Bluetooth HCI controller driver (btusb) — dual-build (built-in or `.ko`).
//!
//! The driver body compiles only for the built-in build: [`btusb`] (endpoint
//! discovery, HCI transport over bulk/interrupt/isochronous endpoints,
//! suspend/resume, detach) and the per-vendor setup in `btusb_intel`,
//! `btusb_rtl`, `btusb_bcm`, `btusb_mtk` and `btusb_qca`. It reaches the USB
//! host stack through `narf-drivers-usb`'s public modules, and the host stack
//! reaches it only through the `bluetooth_hooks` slots installed by
//! [`register_initcalls`].
//!
//! The `module` build registers the Bluetooth interface match through the
//! `narf_register_usb_driver` KSYMTAB export (registration-only until a USB
//! transfer datapath is exported). Without the built-in binder the attach
//! cascade offers Bluetooth devices to the class registry, which is where the
//! `.ko`'s match sees them.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

// The driver reaches the USB host stack through `crate::…` paths.
#[cfg(feature = "builtin")]
#[allow(unused_imports)]
use narf_drivers_usb::{attach, class_registry, control, device, xhci};

#[cfg(feature = "builtin")]
pub mod btusb;
#[cfg(feature = "builtin")]
mod btusb_bcm;
#[cfg(feature = "builtin")]
mod btusb_intel;
#[cfg(feature = "builtin")]
mod btusb_mtk;
#[cfg(feature = "builtin")]
mod btusb_qca;
#[cfg(feature = "builtin")]
mod btusb_rtl;

#[cfg(feature = "kernel-test")]
mod btusb_tests;

narf_driver! {
    name: "btusb",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "USB Bluetooth HCI controller",
        target_domain: "net",
    },
    register: do_register,
}

/// Built-in: the class-registry entry that gives detach a path to
/// `detach_btusb_slot` (#890), and the idle-suspend hook.
#[cfg(feature = "builtin")]
fn do_register() {
    btusb::register_initcalls();
    btusb::register();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}

#[cfg(feature = "builtin")]
fn bind_hook<'a>(
    xhci: &'a xhci::Xhci,
    slot_id: u8,
    vendor_id: u16,
    product_id: u16,
    cfg: &'a [u8],
    hub_port: Option<(u8, u8)>,
) -> narf_drivers_usb::bluetooth_hooks::HookFuture<'a, bool> {
    alloc::boxed::Box::pin(async move {
        btusb::try_bind_btusb_already_addressed(xhci, slot_id, vendor_id, product_id, cfg, hub_port)
            .await
            .is_ok()
    })
}

#[cfg(feature = "builtin")]
fn wake_watch_hook(xhci: &xhci::Xhci) -> narf_drivers_usb::bluetooth_hooks::HookFuture<'_, ()> {
    alloc::boxed::Box::pin(btusb::wake_suspended_ports(xhci))
}

/// Install the USB stack's Bluetooth hooks and register btusb's Stage::Subsys
/// initcalls. Called by `frame` beside `narf_drivers_usb::register_initcalls`.
/// The hooks are installed immediately, not from an initcall: they only
/// publish kernel-resident functions, and must be in place before the USB
/// supervisor's first attach pass.
#[cfg(feature = "builtin")]
pub fn register_initcalls() {
    narf_drivers_usb::bluetooth_hooks::set_binder(bind_hook);
    narf_drivers_usb::bluetooth_hooks::set_wake_watch(wake_watch_hook);
    narf_init::register(narf_init::Stage::Subsys, "usb-btusb", || {
        register();
        narf_init::InitResult::Ok
    });
}

/// Loadable-module registration path (registration-only; `-ENOSYS` probe).
/// Links only the `narf_register_usb_driver` KSYMTAB import.
#[cfg(feature = "module")]
mod module_probe {
    /// `usb_device_id` match flags (`narf_bus::module_usb`).
    const MATCH_INT_CLASS: u16 = 1 << 1;
    const MATCH_INT_SUBCLASS: u16 = 1 << 2;
    const MATCH_INT_PROTOCOL: u16 = 1 << 3;
    /// `btusb::BTUSB_CLASS_MATCH`: Wireless Controller / RF / Bluetooth.
    const USB_CLASS_WIRELESS: u8 = 0xE0;
    const USB_SUBCLASS_RF: u8 = 0x01;
    const USB_PROTOCOL_BLUETOOTH: u8 = 0x01;
    const NAME: &[u8] = b"btusb-module";

    unsafe extern "C" {
        fn narf_register_usb_driver(
            name: *const u8,
            name_len: usize,
            match_flags: u16,
            vendor: u16,
            product: u16,
            class: u8,
            subclass: u8,
            protocol: u8,
            probe: usize,
        ) -> i32;
    }

    extern "C" fn probe_c(_dev_token: u64, _reserved: u64) -> i32 {
        // -ENOSYS: no USB transfer datapath is exported to modules yet.
        -38
    }

    pub fn register() {
        // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn.
        // The loader unregisters the match before unmapping this image.
        unsafe {
            narf_register_usb_driver(
                NAME.as_ptr(),
                NAME.len(),
                MATCH_INT_CLASS | MATCH_INT_SUBCLASS | MATCH_INT_PROTOCOL,
                0,
                0,
                USB_CLASS_WIRELESS,
                USB_SUBCLASS_RF,
                USB_PROTOCOL_BLUETOOTH,
                probe_c as usize,
            );
        }
    }
}
