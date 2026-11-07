//! Aquantia/Marvell AQC1xx (Atlantic) NIC family — dual-build.
//!
//! AQC113 first (`hw_atl2` generation in Linux's atlantic driver):
//! probe + firmware-boot handshake + TX/RX rings + publication +
//! carrier. The older AQC100/107/108/109/111/112 (`hw_atl` B1) and
//! legacy D-series (`hw_atl` A0/B0) generations use a different
//! register backend and are a remainder — see `aqc113.rs`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

#[cfg(feature = "builtin")]
pub use narf_drivers_net_core::*;

#[cfg(feature = "builtin")]
pub mod aqc113;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "aqc1xx",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Aquantia/Marvell AQC113 (Atlantic) NIC family",
        target_domain: "net",
    },
    register: do_register,
}

/// Register every driver in the family. The facade calls this once from its
/// `Stage::Subsys` initcall.
#[cfg(feature = "builtin")]
fn do_register() {
    aqc113::register_pci_driver();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
