//! iwlwifi as a loadable module (`iwlwifi.ko`).
//!
//! The driver's identity, firmware, PCIe transport and station layers are the
//! same source in both builds. What a `.ko` cannot link — the kernel crates —
//! [`kernel`] provides under the same names over `narf-module-rt` and the
//! KABI. What differs in shape, not just in name, lives here:
//!
//! - [`pci`] — the PCI binding: identity, the Sc profile, firmware, the
//!   driver's [`super::runtime::Hardware`] boot to ALIVE, NVM and the
//!   runtime configuration commands;
//! - [`netdev`] — the station (`Device`'s station subset over the same
//!   `Hardware` and `connection::Connection`): one `wlan%d` netdev and wiphy
//!   through the netif bridge and the `WIFI` family host (version 2), scan,
//!   association with the in-driver supplicant, the data path, link loss;
//! - [`regulatory`] — the kernel's regulatory domain, read through the host;
//! - [`absent`] — the roles the module does not carry, as uninhabited types.
//!
//! Scope is the Sc MAC (BE20x/BE21x): the profile the built-in driver's MLD
//! station path targets, and the one seen on silicon (MS-03 `8086:e340`).
//! Built in only: AP/P2P/monitor, scheduled scan, MLO further links,
//! roaming, WoWLAN and system PM, BIOS SAR/PPAG, and the Gen2/Ty/So/Ma/Bz
//! profiles.

pub(crate) mod absent;
pub mod kernel;
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

/// The firmware loader, under the name the transport's source binding uses
/// (`crate::firmware_asset`).
pub mod firmware_asset {
    use alloc::vec::Vec;

    /// One loaded firmware file. Built in, an `Asset` also carries the
    /// revocable registry capability the transport re-checks on every
    /// operation; a module's firmware authority is its manifest `Firmware`
    /// cap, checked by the kernel at `narf_firmware_open`, so the bytes are
    /// the whole asset.
    #[derive(Debug)]
    pub struct Asset {
        pub bytes: Vec<u8>,
    }

    impl Asset {
        /// Built in: the registry capability still names these bytes.
        /// Module: always (the bytes are a private copy).
        pub fn current(&self) -> bool {
            true
        }
    }
}
