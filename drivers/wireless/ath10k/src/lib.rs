//! Qualcomm Atheros ath10k PCIe Wi-Fi — dual-build (built-in or loadable
//! `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/ath10k/` module. The shared
//! Qualcomm/Atheros code it used (`qualcomm_pci`, `qualcomm_regulatory`, the
//! `classify8021d` QoS helper, SMBIOS board id, WMI NLO types) now lives in
//! `narf-drivers-wireless-ath-core`; see `drivers/wireless/iwlwifi/` for the
//! reference dual-build shape.
//!
//! The real driver in [`ath10k`] compiles only for the built-in build. The
//! `module` build registers the QCA PCI ids through the
//! `narf_register_pci_driver` KSYMTAB export; its probe thunk returns
//! `-ENOSYS` (registration-only proof), matching the net and iwlwifi `.ko`s.
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates no Atheros Wi-Fi PCIe device, so chip bring-up and
//! association cannot run here. Validation is dual builds, fixtures and the
//! gated station tests on both architectures; these do not establish RF
//! acceptance.

#![no_std]
#![allow(dead_code)]

#[cfg(feature = "builtin")]
extern crate alloc;

use narf_driver_macros::narf_driver;

// Shared firmware-asset helper lives in `narf-drivers-wireless-core`.
// Re-exported at the crate root so the inner driver's `crate::firmware_asset`
// references resolve unchanged after promotion.
#[cfg(feature = "builtin")]
pub(crate) use narf_drivers_wireless_core::firmware_asset;

#[cfg(feature = "builtin")]
pub mod ath10k;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "ath10k",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Qualcomm Atheros ath10k PCIe Wi-Fi",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    ath10k::register();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
