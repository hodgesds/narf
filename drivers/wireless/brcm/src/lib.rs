//! Broadcom / Infineon FullMAC Wi-Fi family — dual-build (built-in or loadable
//! `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/{brcmfmac,cyw43439}/`
//! modules into one family crate. The two drivers are a deeply intertwined
//! Broadcom FullMAC pair: cyw43439 reuses brcmfmac's chip/event/provision/vif/
//! ap code and brcmfmac reuses cyw43439's fullmac/station/runtime, a
//! bidirectional dependency that cannot be split across crates — so they share
//! a crate (inner module paths `brcmfmac`/`cyw43439` preserved).
//!
//! Built in, [`brcmfmac`] binds the Broadcom PCIe FullMAC ids and
//! [`cyw43439`] the CYW43439 SDIO/gSPI functions. The `module` build is the
//! brcmfmac PCIe driver running inside the `.ko` (module name `brcm`): it
//! registers the Broadcom PCIe ids through `narf_register_pci_driver` and
//! drives the card through the KABI (config window, BAR0/BAR2, plain MSI,
//! mapped DMA, signed firmware), with the shared FullMAC station
//! ([`cyw43439::station`]) and its netdev/wiphy published through the netif
//! bridge and the `WIFI` family host. Kernel services come from
//! [`platform`]. CYW43439 is built-in only: no SDIO I/O KABI exists.
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates neither a Broadcom PCIe Wi-Fi device nor a CYW43439 SDIO
//! card, so chip bring-up and association cannot run here. Validation is dual
//! builds, fixtures and the gated station/AP tests on both architectures;
//! these do not establish RF acceptance.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

use narf_driver_macros::narf_driver;

// Shared, driver-agnostic helpers live in `narf-drivers-wireless-core`.
// Re-exported at the crate root so the inner drivers' `crate::future_heap`
// references resolve unchanged after promotion. The module build carries its
// own copy (the wireless-core crate is kernel-resident).
#[cfg(feature = "builtin")]
pub(crate) use narf_drivers_wireless_core::future_heap;
#[cfg(feature = "module")]
mod future_heap;

/// Kernel services under one name in both builds: the kernel's crates built
/// in, `narf-module-rt` + the KABI in the `.ko`.
pub mod platform;

pub mod brcmfmac;

/// CYW43439 and the shared FullMAC station. The module build carries only
/// the bus-independent station, event, IOCTL and runtime layers the PCIe
/// path drives.
pub mod cyw43439;

narf_driver! {
    name: "brcm",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Broadcom/Infineon FullMAC Wi-Fi (brcmfmac PCIe + CYW43439 SDIO)",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write,DmaBuffer:Write,Firmware:Read",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    brcmfmac::register();
    cyw43439::register();
}

/// The autoconnect bring-up aid's `brcm.ssid=` / `brcm.psk=` /
/// `brcm.passphrase=` ([`cyw43439::interface_module`]), declared so the loader
/// applies them from the kernel command line (and the load's own arguments)
/// before init. Empty = not given.
#[cfg(feature = "module")]
#[used]
#[link_section = ".narf_kparams"]
static KPARAMS: [u8; 23] = *b"ssid=\npsk=\npassphrase=\n";

#[cfg(feature = "module")]
fn do_register() {
    brcmfmac::register_module();
}
