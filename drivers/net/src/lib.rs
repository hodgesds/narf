//! narf-drivers-net — hardware NIC drivers skeleton.
//!
//! Spec: `drivers/net/specification/spec.md` (Stage-4 primary).
//! The real drivers (e1000 / igb / ixgbe / mlx5) each need:
//!
//! - PCIe-device claim + BAR0/2 MMIO mapping.
//! - DMA-ring setup (RX descriptors + TX descriptors).
//! - MSI-X vector binding per RX / TX queue.
//! - Link-state change interrupt handling.
//! - Feature negotiation (TSO, checksum offload, RSS).
//!
//! What lands here at this Stage-4 skeleton pass:
//!
//! - `NicModel` enum of supported chipsets.
//! - `NicCaps` feature-bitmap mirroring the `BlockFeature` pattern.
//! - `NicDescriptor` — a single RX/TX descriptor shape that all
//!   drivers can produce.
//! - `HwNic` trait for per-chipset drivers to implement; the
//!   surface matches `narf_net::Interface` (name/mac/mtu/link_up/
//!   rx_ring/tx_ring) so the net registry can consume
//!   chipset-specific drivers uniformly.
//!
//! No actual driver body — the first real driver (e1000, simplest
//! of the modern line) lands when the BAR mapping + MSI-X binding
//! integration with `bus/` is complete.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod atheros;
pub mod bnxt;
pub mod cxgb4;
pub mod e1000;
pub mod enic;
pub mod forcedeth;
pub mod i40e;
pub mod igc;
pub mod ixgbe;
pub mod mlx5;
pub mod r8169;
pub mod rtl8125;
pub mod rtl8126;
pub mod rtl8127;
pub mod rtl8139;
pub mod tg3;
pub mod vmxnet3;

// Per-driver smoke tests register against `narf-kernel-test` and
// land in the same `narf.tests` ELF section as the rest of the
// suite. Kept in its own module so a future `cfg(test_in_tree)`
// or feature gate can drop them from production binaries.
mod tests;

// The driver-agnostic surface (HwNic + NicModel/NicCaps/NicDescriptor/NicError)
// and the Realtek PHY helpers now live in `narf-drivers-net-core`; re-export
// them so `narf_drivers_net::HwNic`, `crate::NicModel`, `crate::rtl_phy`, …
// keep resolving for the driver modules and external callers alike.
pub use narf_drivers_net_core::*;

/// Register the late PHY-firmware pass.
///
/// Kept out of [`register_initcalls`] because it must run after the
/// firmware registry has been populated, and `Stage::Late` initcalls
/// run in registration order — this crate registers before
/// `narf-firmware` does. `bare_main` calls this after
/// `narf_firmware::register_initcalls()`, which is what puts it after
/// the initramfs and rootfs firmware scans.
pub fn register_late_firmware_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Late, "rtl8127-phy-firmware", || {
        rtl8127::configure_phy_late();
        InitResult::Ok
    });
}

/// Stage::Subsys initcalls for this driver crate.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "cxgb4", || {
        cxgb4::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "e1000", || {
        e1000::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "i40e", || {
        i40e::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "r8169", || {
        r8169::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "rtl8125", || {
        rtl8125::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "rtl8126", || {
        rtl8126::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "rtl8127", || {
        rtl8127::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "mlx5", || {
        mlx5::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "ixgbe", || {
        ixgbe::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "igc", || {
        igc::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "rtl8139", || {
        rtl8139::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "atheros", || {
        atheros::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "tg3", || {
        tg3::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "vmxnet3", || {
        vmxnet3::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "forcedeth", || {
        forcedeth::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "bnxt", || {
        bnxt::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "enic", || {
        enic::register_pci_driver();
        InitResult::Ok
    });
}
