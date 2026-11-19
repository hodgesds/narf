//! FTDI USB-serial driver — dual-build.
//!
//! * [`codec`] — the FTDI wire codec (request codes, baud divisors, modem
//!   control encoding, bulk-IN status framing). Compiled in both builds: the
//!   built-in driver in `narf-drivers-usb` (`serial::ftdi`) re-exports it.
//! * `module_probe` — the `.ko` (`feature = "module"`): a working driver that
//!   brings the chip up and moves serial data using only the USB datapath
//!   KSYMTAB exports (`narf_usb_*`), publishing `/dev/ttyUSB<N>`.
//!
//! In the built-in build [`register`] does nothing: the FTDI binding there
//! is the USB stack's serial cascade, which needs no registration call.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

pub mod codec;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "ftdi_sio",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "FTDI FT232/FT-X/FT232H USB-serial",
        target_domain: "input",
        required_caps: "BusDevice:Write",
    },
    register: do_register,
}

/// Built-in: the serial cascade in `narf-drivers-usb` binds FTDI parts.
#[cfg(feature = "builtin")]
fn do_register() {}

/// Module: register the FTDI matches against the datapath driver.
#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
