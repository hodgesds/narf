//! narf-drivers-usb-storage — USB mass storage over Bulk-Only Transport,
//! dual-build.
//!
//! The built-in build is the wire codec alone ([`codec`]); the built-in
//! binder lives in `narf-drivers-usb::msc`. The `module` build is
//! `usb-storage.ko`: a loadable BOT driver that moves SCSI commands with the
//! `narf_usb_*` exports and publishes the stick as a module-backed disk
//! with `narf_blk_*`. See `drivers/usb/ftdi` for the USB dual-build pattern.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

pub mod codec;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "usb_storage",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "USB mass storage (Bulk-Only Transport, SCSI)",
        target_domain: "block",
        required_caps: "BusDevice:Write,BlockDevice:Write",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
