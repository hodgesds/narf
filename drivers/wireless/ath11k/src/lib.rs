//! Qualcomm ath11k Wi-Fi 6 — dual-build (built-in or loadable `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/ath11k/` module. The shared
//! Qualcomm/Atheros code it uses lives in `narf-drivers-wireless-ath-core`; see
//! `drivers/wireless/ath10k/` and `drivers/wireless/iwlwifi/` for the reference
//! dual-build shape.
//!
//! ath11k is multi-bus: built in, the driver in [`ath11k`] binds
//! QCA6390/WCN6855/QCN9074 over PCIe and IPQ8074/6018/5018 + WCN6750 over
//! AHB/Devicetree. The `module` build is the same driver running inside the
//! `.ko` for WCN6855 over PCIe: it registers the PCI id through
//! `narf_register_pci_driver` and drives the card through the KABI (BAR
//! access, plain MSI, mapped DMA, firmware), with its netdev and wiphy
//! published through the netif bridge and the `WIFI` family host.
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates no Qualcomm Wi-Fi device (PCIe or AHB), so bring-up and
//! association cannot run here. Validation is dual builds, fixtures and the
//! gated tests on both architectures; these do not establish RF acceptance.

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
/// [`ath11k::platform`], which is the kernel's crates built in and
/// `narf-module-rt` + the KABI in the `.ko`.
pub mod ath11k;

narf_driver! {
    name: "ath11k",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Qualcomm ath11k Wi-Fi 6 (PCIe + IPQ AHB)",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write,DmaBuffer:Write,Firmware:Read",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    ath11k::register();
}

/// The autoconnect bring-up aid's `ath11k.ssid=` / `ath11k.psk=` /
/// `ath11k.passphrase=` / `ath11k.scan=` ([`ath11k::autoconnect`]), declared
/// so the loader applies them from the kernel command line (and the load's
/// own arguments) before init. Empty = not given.
#[cfg(feature = "module")]
#[used]
#[link_section = ".narf_kparams"]
static KPARAMS: [u8; 29] = *b"ssid=\npsk=\npassphrase=\nscan=\n";

#[cfg(feature = "module")]
fn do_register() {
    ath11k::register_module();
}
