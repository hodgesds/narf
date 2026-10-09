//! Realtek r8169 / RTL8125 / RTL8126 / RTL8127 NIC family — dual-build.
//!
//! The family is a dependency chain (`rtl8127` → `rtl8126` → `rtl8125` →
//! `r8169`) sharing the `rtl_phy` helpers, so it lives in one crate; the
//! inter-driver references resolve as in-crate `crate::rtl8126::…` paths. Each
//! driver still registers its own PCI matches. See `narf-drivers-net-e1000`
//! for the dual-build pattern.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

#[cfg(feature = "builtin")]
pub use narf_drivers_net_core::*;

#[cfg(feature = "builtin")]
pub mod r8169;
#[cfg(feature = "builtin")]
pub mod rtl8125;
#[cfg(feature = "builtin")]
pub mod rtl8126;
#[cfg(feature = "builtin")]
pub mod rtl8127;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "realtek",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Realtek r8169/RTL8125/RTL8126/RTL8127 NIC family",
        target_domain: "net",
    },
    register: do_register,
}

/// Register every driver in the family. The facade calls this once from its
/// `Stage::Subsys` initcall (replacing the four per-driver initcalls).
#[cfg(feature = "builtin")]
fn do_register() {
    r8169::register_pci_driver();
    rtl8125::register_pci_driver();
    rtl8126::register_pci_driver();
    rtl8127::register_pci_driver();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}

/// The RTL8127 late PHY-firmware pass. Kept out of [`register`] because it must
/// run after the firmware registry is populated; the facade registers it in
/// `Stage::Late` (see `narf_drivers_net::register_late_firmware_initcalls`).
#[cfg(feature = "builtin")]
pub fn configure_rtl8127_phy_late() {
    rtl8127::configure_phy_late();
}
