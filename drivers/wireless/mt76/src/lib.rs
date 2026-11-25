//! MediaTek CONNAC2 Wi-Fi (MT7921 / MT7922 / MT7961 / MT7920) — dual-build
//! (built-in or loadable `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/mt7921/` module. See
//! `drivers/net/i40e/` for the reference dual-build shape and `PLAN.md` at the
//! worktree root for the promotion rationale.
//!
//! One source tree, two builds. The driver in [`mt7921`] (L1 remap, WFDMA
//! rings, MCU framing, firmware download, the station join with its in-driver
//! WPA2/WPA3 supplicant, the packet path) reaches the kernel only through
//! [`platform`]: the kernel's crates built in, `narf-module-rt` and the KABI
//! in the `.ko` (the `drivers/wireless/ath11k` precedent).
//!
//! - Built in, [`iface`] is the full `WirelessNetIface` netdev (station, AP,
//!   P2P, monitor, WoW, system PM), and the private copy-mode family host
//!   ([`module_protocol`], `module_host`) stays registered for loadable
//!   frontends built against it.
//! - As a module, `mt7921::pci_kabi` binds the function over the KABI and
//!   `iface_module` publishes the station netdev and wiphy through the netif
//!   bridge and the generic `WIFI` family host (version 2).
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates no MediaTek Wi-Fi PCIe device, so chip-id read, firmware
//! download, and association cannot run here. Validation includes dual builds,
//! command fixtures, native descriptor models and retained station/reset
//! ownership tests on both architectures. These do not establish RF acceptance.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

use narf_driver_macros::narf_driver;

pub mod module_protocol;

#[cfg(feature = "builtin")]
mod module_host;

/// Kernel services under one name in both builds.
pub mod platform;

/// The driver. One source tree in both builds.
pub mod mt7921;

#[cfg(feature = "builtin")]
pub mod iface;

/// Station helpers both netdevs share (scan plans, join resolution).
pub(crate) mod iface_station;

/// The station netdev and wiphy of the module build.
#[cfg(feature = "module")]
pub mod iface_module;

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
        required_caps: "BusDevice:Write,NetIface:Write,DmaBuffer:Write,Firmware:Read",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    module_host::register();
    mt7921::register();
}

/// The built-in registration without the PCI binding (`mt76-module-only` in
/// `narf-drivers-wireless`): `mt76.ko` owns the CONNAC2 PCI ids, and only the
/// private copy-mode family host is registered.
#[cfg(feature = "builtin")]
pub fn register_host_only() {
    module_host::register();
}

/// `mt76.debug=1` (or the load argument `debug=1`): the routine firmware and
/// station traces the built-in driver prints under `mt76.dyndbg=+p`
/// ([`mt7921::debug`]), declared so the loader applies it before init.
#[cfg(feature = "module")]
#[used]
#[link_section = ".narf_kparams"]
static KPARAMS: [u8; 7] = *b"debug=\n";

#[cfg(feature = "module")]
#[unsafe(no_mangle)]
pub extern "C" fn narf_module_exit() {
    mt7921::pci::exit();
}

#[cfg(feature = "module")]
fn do_register() {
    mt7921::pci::register();
}

// The `narf_driver!` macro above generates the public `register()` entry point
// (it calls `do_register`). The `narf-drivers-wireless` facade invokes
// `mt76::register()` from its `Stage::Subsys` initcall.
