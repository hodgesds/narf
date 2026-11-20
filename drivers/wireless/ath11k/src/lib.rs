//! Qualcomm ath11k Wi-Fi 6 — dual-build (built-in or loadable `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/ath11k/` module. The shared
//! Qualcomm/Atheros code it uses lives in `narf-drivers-wireless-ath-core`; see
//! `drivers/wireless/ath10k/` and `drivers/wireless/iwlwifi/` for the reference
//! dual-build shape.
//!
//! ath11k is multi-bus: the real driver in [`ath11k`] binds QCA6390/WCN6855/
//! QCN9074 over PCIe and IPQ8074/6018/5018 + WCN6750 over AHB/Devicetree. The
//! `module` build registers BOTH — the PCI ids through `narf_register_pci_driver`
//! and the AHB DT compatibles through `narf_register_dt_driver` — with a probe
//! thunk that returns `-ENOSYS` (registration-only proof).
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates no Qualcomm Wi-Fi device (PCIe or AHB), so bring-up and
//! association cannot run here. Validation is dual builds, fixtures and the
//! gated tests on both architectures; these do not establish RF acceptance.

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
pub mod ath11k;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "ath11k",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Qualcomm ath11k Wi-Fi 6 (PCIe + IPQ AHB)",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    ath11k::register();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
