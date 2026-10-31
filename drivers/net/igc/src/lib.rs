//! Intel I225/I226 2.5GbE NIC — dual-build (built-in or loadable `.ko`).
//!
//! See `narf-drivers-net-e1000` for the reference pattern. The real driver in
//! [`igc`] compiles only for the built-in build; the `module` build registers
//! through the device C ABI and shares reset, PHY and queue programming.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

#[cfg(feature = "builtin")]
pub use narf_drivers_net_core::*;

#[cfg(feature = "builtin")]
pub mod igc;

#[cfg(feature = "builtin")]
mod counters;
#[cfg_attr(feature = "module", allow(dead_code))]
mod hardware;
#[cfg(feature = "builtin")]
mod merge;
#[cfg(feature = "builtin")]
mod packet;
#[cfg_attr(feature = "module", allow(dead_code))]
mod protocol;
#[cfg(feature = "builtin")]
mod ptp;
#[cfg(feature = "builtin")]
mod queue;
#[cfg(feature = "builtin")]
mod tests;
#[cfg(feature = "builtin")]
mod traffic;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "igc",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Intel I225/I226 2.5GbE NIC",
        target_domain: "net",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    igc::register_pci_driver();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
