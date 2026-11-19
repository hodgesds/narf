//! Intel iwlwifi PCIe Wi-Fi (AX200 / AX201 / AX210 / AX211 / BE200) —
//! dual-build (built-in or loadable `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/iwlwifi/` module. See
//! `drivers/wireless/mt76/` and `drivers/net/tg3/` for the reference dual-build
//! shape.
//!
//! The real driver in [`iwlwifi`] (PCIe gen2/gen3 transport, firmware TLV
//! parsing and the filename ladder, the MLD station control/data path)
//! compiles only for the built-in build. The `module` build registers the
//! Intel PCI ids through the `narf_register_pci_driver` KSYMTAB export; its
//! probe thunk returns `-ENOSYS` because the Wi-Fi device datapath ABI is not
//! yet exported, matching the net `.ko`s (registration-only proof).
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates no Intel Wi-Fi PCIe device, so chip-id read, firmware
//! download and association cannot run here. Validation is dual builds, TLV
//! fixtures, chip-table completeness and the gated control-plane tests on both
//! architectures. These do not establish RF acceptance.

#![no_std]
#![allow(dead_code)]

#[cfg(feature = "builtin")]
extern crate alloc;

use narf_driver_macros::narf_driver;

// Shared, driver-agnostic helpers live in `narf-drivers-wireless-core`.
// Re-exported at the crate root so the inner driver's `crate::firmware_asset`
// and `crate::future_heap` references resolve unchanged after promotion.
#[cfg(feature = "builtin")]
pub(crate) use narf_drivers_wireless_core::{firmware_asset, future_heap};

#[cfg(feature = "builtin")]
pub mod iwlwifi;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "iwlwifi",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Intel iwlwifi PCIe Wi-Fi (AX200/AX201/AX210/AX211/BE200)",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    iwlwifi::register();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
