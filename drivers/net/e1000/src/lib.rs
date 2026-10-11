//! Intel 8254x/8257x (e1000/e1000e) NIC driver — dual-build.
//!
//! One source, two builds (see this crate's `Cargo.toml`):
//!   * `builtin` — the real driver in [`e1000`], registered from the kernel's
//!     Stage::Subsys initcall via the facade.
//!   * `module` — a relocatable `.ko` whose [`register`] registers the driver
//!     through the `narf_register_pci_driver` KSYMTAB export. The loader picks
//!     its runtime isolation frame; the bus call gate re-enters that frame for
//!     every callback. The module path resets the device, programs persistent
//!     copy-mode RX/TX rings, registers an Ethernet interface, and drives it
//!     from task-context IRQ/poller callbacks.
//!
//! The [`narf_driver!`] macro generates the shared `register()` entry and, for
//! the `module` build, the `narf_module_init` entry point, `.modinfo` lines and
//! panic handler.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

// The driver body and the module registration path reference the shared NIC
// trait surface through `crate::…`; re-export it so `crate::HwNic`,
// `crate::NicModel`, … resolve inside `e1000.rs`.
#[cfg(feature = "builtin")]
extern crate alloc;

#[cfg(feature = "builtin")]
pub use narf_drivers_net_core::*;

/// Compile-time placement for the in-kernel build. Unlike a `.ko`'s effective
/// domain, this value is part of the kernel image and cannot be changed by a
/// module-load parameter.
#[cfg(feature = "builtin")]
pub(crate) const BUILTIN_DOMAIN: narf_lib::id::DomainId = narf_lib::id::DomainId::DRIVER_0;

/// The real driver. Compiled only for the built-in build — its probe maps
/// BARs, programs DMA rings and MSI-X, and registers with the net stack, all
/// through kernel crates that a `.ko` cannot link.
#[cfg(feature = "builtin")]
pub mod e1000;

/// The loadable-module registration + C-ABI datapath. Compiled only for the
/// `.ko` build.
#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "e1000",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Intel 8254x/8257x (e1000/e1000e) NIC",
        target_domain: "net",
        required_caps: "DmaBuffer:Write,BusDevice:Write,NetIface:Write",
    },
    register: do_register,
}

/// Built-in registration: the real driver's full PCI id table + probe.
#[cfg(feature = "builtin")]
fn do_register() {
    e1000::register_pci_driver();
}

/// Module registration: the primary e1000 id, bound to the C-ABI thunk.
#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
