//! iwlwifi as a loadable module (`iwlwifi.ko`).
//!
//! The driver's identity, firmware, PCIe transport and station layers are the
//! same source in both builds. What a `.ko` cannot link — the kernel crates —
//! [`kernel`] provides under the same names over `narf-module-rt` and the
//! KABI. What differs in shape, not just in name, lives here:
//!
//! - [`pci`] — the PCI binding: identity, the per-family profile and its
//!   firmware, the driver's [`super::runtime::Hardware`];
//! - [`netdev`] — the Gen3 (Ty/So/Ma/Bz/Sc) station: `Device`'s station
//!   subset over the same `Hardware` and `connection::Connection`;
//! - [`mvm_netdev`] — the Gen2 (AX200/AX201) station: `mvm_device`'s station
//!   subset over the same `mvm_boot::Owner`;
//!   both publish one `wlan%d` netdev and wiphy through the netif bridge and
//!   the `WIFI` family host (version 2): scan, association with the
//!   in-driver supplicant, the data path, link loss;
//! - [`firmware_asset`] — firmware with its verified signer and digest;
//! - [`regulatory`] — the kernel's regulatory domain (`narf_wireless_regdomain`);
//! - [`absent`] — the roles the module does not carry, as uninhabited types.
//!
//! Scope is every id of the built-in table. Built in only: AP/P2P/monitor,
//! scheduled scan, MLO further links, roaming, WoWLAN/D3 and system PM, and
//! BIOS SAR/PPAG.

pub(crate) mod absent;
pub mod kernel;
pub(crate) mod mvm_netdev;
pub(crate) mod netdev;
pub(crate) mod pci;
pub(crate) mod regulatory;

use core::sync::atomic::{AtomicU64, Ordering};
use narf_module_rt::exec::Executor;

/// The module's executor: every driver future runs here, driven by the 1 ms
/// device poller and by each MSI-X vector callback.
pub static EXEC: Executor = Executor::new();

/// The probed device's token; 0 until probe.
static DEVICE: AtomicU64 = AtomicU64::new(0);

/// Record the probed device (the token every device export takes).
pub(crate) fn set_device(dev: u64) {
    DEVICE.store(dev, Ordering::Release);
}

/// The probed device's token.
pub(crate) fn device() -> u64 {
    DEVICE.load(Ordering::Acquire)
}

/// `narf_module_init`: install the kernel DRBG as the protocol code's entropy
/// source, then register the PCI ids. The rest happens in probe.
pub fn register() {
    pci::install_entropy();
    pci::register_pci_driver();
}

/// The firmware loader, under the name the driver uses (`crate::firmware_asset`).
pub mod firmware_asset;
