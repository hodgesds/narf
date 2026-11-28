//! Mellanox ConnectX-3 (MT27500 / MT27520) NIC — dual-build (built-in or
//! loadable `.ko`).
//!
//! ConnectX-3 is a different device generation from ConnectX-4/5/6: it speaks
//! the legacy *Hardware Command Register* (HCR) firmware interface and the
//! `mlx4` context-memory (ICM) model, not the ConnectX-4+ host command queue
//! that the sibling [`narf-drivers-net-mlx5`] crate implements. The two share
//! no wire formats, so ConnectX-3 lives in its own crate.
//!
//! The built-in and module builds share the HCR, ICM, queue and packet
//! engines. Modules use device-scoped KABI grants and a polled single-port
//! datapath. See drivers/net/specification/mlx4.md for validation limits.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[path = "../../module_platform.rs"]
pub(crate) mod platform;

extern crate alloc;

#[cfg(feature = "builtin")]
pub use narf_drivers_net_core::*;

pub mod mlx4;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "mlx4",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Mellanox ConnectX-3 NIC",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write,DmaBuffer:Write",
    },
    register: do_register => i32,
}

#[cfg(feature = "builtin")]
fn do_register() -> i32 {
    mlx4::register_pci_driver();
    0
}

#[cfg(feature = "module")]
fn do_register() -> i32 {
    module_probe::register()
}

#[cfg(all(test, feature = "module"))]
extern crate std;
#[cfg(all(test, feature = "module"))]
#[path = "../../module_test_support.rs"]
mod module_test_support;
#[cfg(all(test, feature = "module"))]
mod module_tests;
