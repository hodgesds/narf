//! MediaTek CONNAC2 Wi-Fi (MT7921 / MT7922 / MT7961 / MT7920) — dual-build
//! (built-in or loadable `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/mt7921/` module. See
//! `drivers/net/i40e/` for the reference dual-build shape and `PLAN.md` at the
//! worktree root for the promotion rationale.
//!
//! The real driver in [`mt7921`] (L1 remap, MCU framing, WFDMA rings, firmware
//! download, the [`iface`] `WirelessNetIface` scaffold) compiles only for the
//! built-in build. The `module` build registers through the
//! `narf_register_pci_driver` KSYMTAB export (registration-only until the
//! wireless datapath ABI lands).
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates no MediaTek Wi-Fi PCIe device, so chip-id read, firmware
//! download, and association cannot run here. Validation includes dual builds,
//! command fixtures, native descriptor models and retained station/reset
//! ownership tests on both architectures. These do not establish RF acceptance.

#![no_std]
#![allow(dead_code)]

#[cfg(feature = "builtin")]
extern crate alloc;

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
pub mod mt7921;

#[cfg(feature = "builtin")]
pub mod iface;

#[cfg(feature = "module")]
mod module_probe;

// Re-export the key driver surface so the facade (and tests in other crates)
// can reach it through the crate root, mirroring the pre-promotion module.
#[cfg(feature = "builtin")]
pub use iface::Mt76Iface;
#[cfg(feature = "builtin")]
pub use mt7921::{
    firmware_blobs_for, l1_remap, name_for, probe, Mt7921Device, ProbeError, ALL_DEV_IDS,
    ITTIM_VENDOR, MTK_DEV_MT7920, MTK_DEV_MT7921, MTK_DEV_MT7921_ALT, MTK_DEV_MT7922,
    MTK_DEV_MT7961, MTK_VENDOR,
};

narf_driver! {
    name: "mt76",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "MediaTek CONNAC2 Wi-Fi (MT7921/MT7922/MT7961/MT7920)",
        target_domain: "net",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    mt7921::register();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}

// The `narf_driver!` macro above generates the public `register()` entry point
// (it calls `do_register`). The `narf-drivers-wireless` facade invokes
// `mt76::register()` from its `Stage::Subsys` initcall.
