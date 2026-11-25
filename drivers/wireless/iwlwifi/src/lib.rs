//! Intel iwlwifi PCIe Wi-Fi (AX200 / AX201 / AX210 / AX211 / BE200) —
//! dual-build (built-in or loadable `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/iwlwifi/` module. See
//! `drivers/wireless/mt76/` and `drivers/net/tg3/` for the reference dual-build
//! shape.
//!
//! The driver in [`iwlwifi`] (PCIe gen2/gen3 transport, firmware TLV parsing
//! and the filename ladder, the MLD station control/data path) is one source
//! tree in both builds. Built in, all of it runs. The `module` build compiles
//! the identity, firmware, transport and station layers kernel-free and runs
//! them inside the `.ko` for every id of the built-in table over
//! `narf-module-rt` and the KABI ([`iwlwifi::module`]): firmware boot, the
//! Gen3 MLD and Gen2 MVM configuration, scan, association with the in-driver
//! WPA2/WPA3 supplicant and the data path, with one `wlan%d` netdev and wiphy
//! through the netif bridge and the `WIFI` family host. AP/P2P, scheduled
//! scan, MLO, WoWLAN and BIOS SAR/PPAG stay built in.
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates no Intel Wi-Fi PCIe device, so chip-id read, firmware
//! download and association cannot run here. Validation is dual builds, TLV
//! fixtures, chip-table completeness and the gated control-plane tests on both
//! architectures. These do not establish RF acceptance.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

use narf_driver_macros::narf_driver;

// Shared, driver-agnostic helpers live in `narf-drivers-wireless-core`.
// Re-exported at the crate root so the inner driver's `crate::firmware_asset`
// and `crate::future_heap` references resolve unchanged after promotion.
#[cfg(feature = "module")]
pub(crate) use iwlwifi::module::firmware_asset;
/// `future_heap` is pure (no kernel crate), so the module build compiles the
/// same file.
#[cfg(feature = "module")]
#[path = "../../core/src/future_heap.rs"]
pub(crate) mod future_heap;
#[cfg(feature = "builtin")]
pub(crate) use narf_drivers_wireless_core::{firmware_asset, future_heap};

/// The driver. Built in, every layer; as a module, the kernel-free subset
/// plus [`iwlwifi::module`] (see the crate docs).
pub mod iwlwifi;

narf_driver! {
    name: "iwlwifi",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Intel iwlwifi PCIe Wi-Fi (AX200/AX201/AX210/AX211/BE200)",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write,DmaBuffer:Write,Firmware:Read",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    iwlwifi::register();
}

#[cfg(feature = "module")]
fn do_register() {
    iwlwifi::module::register();
}
