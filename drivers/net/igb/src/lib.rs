//! Intel I210 / I211 / 82576 / I350 1GbE NIC — dual-build (built-in or loadable `.ko`).
//!
//! Shares `narf-drivers-net-igc`'s advanced-descriptor datapath (advanced
//! one-buffer RX, advanced TX data/context descriptors, SRRCTL ADV_ONEBUF, the
//! `0x1500` extended-interrupt block). The functional delta vs igc is the igb
//! reset's per-queue `TXDCTL`/`RXDCTL` ENABLE handshake.
//!
//! The real driver in [`igb`] compiles only for the built-in build; the
//! `module` build registers through the `narf_register_pci_driver` KSYMTAB
//! export (registration-only until the device datapath ABI lands).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

#[cfg(feature = "builtin")]
pub use narf_drivers_net_core::*;

#[cfg(feature = "builtin")]
pub mod igb;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "igb",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Intel I210/I211/82576/I350 1GbE NIC",
        target_domain: "net",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    igb::register_pci_driver();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
