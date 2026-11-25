//! Qualcomm Atheros ath10k PCIe Wi-Fi — dual-build (built-in or loadable
//! `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/ath10k/` module. The shared
//! Qualcomm/Atheros code it used (`qualcomm_pci`, `qualcomm_regulatory`, the
//! `classify8021d` QoS helper, SMBIOS board id, WMI NLO types) now lives in
//! `narf-drivers-wireless-ath-core`; see `drivers/wireless/iwlwifi/` for the
//! reference dual-build shape.
//!
//! One driver source tree in both builds. Built in, [`ath10k`] binds every
//! QCA988X/9887/6174/6164/99X0/9888/9984/9377 PCI id through `narf-bus`. The
//! `module` build is the same driver running inside the `.ko`: it registers
//! the same ids through `narf_register_pci_driver` and drives the card
//! through the KABI (BAR access, PCI command, plain MSI, ASPM, mapped DMA,
//! firmware), with its station netdev and wiphy published through the netif
//! bridge and the `WIFI` family host. Kernel services come from
//! [`ath10k::platform`].
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates no Atheros Wi-Fi PCIe device, so chip bring-up and
//! association cannot run here. Validation is dual builds, fixtures and the
//! gated station tests on both architectures; these do not establish RF
//! acceptance.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

use narf_driver_macros::narf_driver;

// Shared firmware-asset helper lives in `narf-drivers-wireless-core`.
// Re-exported at the crate root so the inner driver's `crate::firmware_asset`
// references resolve unchanged after promotion.
#[cfg(feature = "builtin")]
pub(crate) use narf_drivers_wireless_core::firmware_asset;

/// The driver. One source tree in both builds: kernel services come from
/// [`ath10k::platform`], which is the kernel's crates built in and
/// `narf-module-rt` + the KABI in the `.ko`.
pub mod ath10k;

narf_driver! {
    name: "ath10k",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Qualcomm Atheros ath10k PCIe Wi-Fi",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write,DmaBuffer:Write,Firmware:Read",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    ath10k::register();
}

#[cfg(feature = "module")]
fn do_register() {
    ath10k::register_module();
}
