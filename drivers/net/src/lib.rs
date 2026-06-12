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
pub mod cxgb4;
pub mod e1000;
pub mod forcedeth;
pub mod i40e;
pub mod igc;
pub mod ixgbe;
pub mod mlx5;
pub mod r8169;
pub mod rtl8125;
pub mod rtl8126;
pub mod rtl8139;
pub mod rtl_phy;
pub mod tg3;
pub mod vmxnet3;

// Per-driver smoke tests register against `narf-kernel-test` and
// land in the same `narf.tests` ELF section as the rest of the
// suite. Kept in its own module so a future `cfg(test_in_tree)`
// or feature gate can drop them from production binaries.
mod tests;

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
}

/// Chipset families the Stage-4 driver set targets.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicModel {
    /// Intel 8254x / 8257x — "e1000" / "e1000e".
    IntelE1000,
    /// Intel 82575-onwards Gigabit — "igb".
    IntelIgb,
    /// Intel 82599 / X540 10-GbE — "ixgbe".
    IntelIxgbe,
    /// Mellanox ConnectX-4 / 5 / 6 — "mlx5_core".
    MellanoxMlx5,
    /// Realtek RTL8139 — legacy smoke target.
    RealtekRtl8139,
    /// Realtek RTL8168 / RTL8111 — modern PCIe Gigabit family.
    RealtekRtl8168,
    /// Atheros / Attansic L1c / L2c Gigabit.
    AtherosAtl1c,
    /// Nvidia nForce MAC — "forcedeth".
    NvidiaForcedeth,
    /// Broadcom Tigon3 — "tg3".
    BroadcomTg3,
}

impl NicModel {
    /// PCI vendor/device id pair that identifies this chipset. Only
    /// the first entry of the family is returned; full cross-version
    /// coverage lives in each driver's probe table.
    pub const fn primary_pci_id(self) -> (u16, u16) {
        match self {
            NicModel::IntelE1000 => (0x8086, 0x100E),
            NicModel::IntelIgb => (0x8086, 0x10C9),
            NicModel::IntelIxgbe => (0x8086, 0x10B6),
            NicModel::MellanoxMlx5 => (0x15B3, 0x1013),
            NicModel::RealtekRtl8139 => (0x10EC, 0x8139),
            NicModel::RealtekRtl8168 => (0x10EC, 0x8168),
            NicModel::AtherosAtl1c => (0x1969, 0x1063),
            NicModel::NvidiaForcedeth => (0x10DE, 0x0372),
            NicModel::BroadcomTg3 => (0x14E4, 0x1644),
        }
    }
}

/// NIC feature bitmap. Bits mirror features the net stack cares
/// about on the fast path.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NicCaps(pub u32);

impl NicCaps {
    pub const NONE: NicCaps = NicCaps(0);
    pub const TX_CSUM: NicCaps = NicCaps(1 << 0);
    pub const RX_CSUM: NicCaps = NicCaps(1 << 1);
    pub const TSO: NicCaps = NicCaps(1 << 2);
    pub const LRO: NicCaps = NicCaps(1 << 3);
    pub const RSS: NicCaps = NicCaps(1 << 4);
    pub const MULTICAST_HASH: NicCaps = NicCaps(1 << 5);
    pub const VLAN_TAGGING: NicCaps = NicCaps(1 << 6);
    pub const PROMISC: NicCaps = NicCaps(1 << 7);

    #[inline]
    pub const fn contains(self, o: NicCaps) -> bool {
        self.0 & o.0 == o.0
    }
}

impl core::ops::BitOr for NicCaps {
    type Output = NicCaps;
    fn bitor(self, rhs: NicCaps) -> Self {
        NicCaps(self.0 | rhs.0)
    }
}

/// A single RX/TX descriptor. Direction-agnostic — `dir` disambiguates.
#[derive(Copy, Clone, Debug)]
pub struct NicDescriptor {
    pub dir: narf_net::Direction,
    pub buffer: u64, // physical address
    pub len: u32,
    /// Driver-specific completion bits mirrored here for generic
    /// completion-ring consumers.
    pub flags: u16,
}

use narf_ipc::{Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, RX_RING_N, TX_RING_N};

/// Per-chipset driver trait. `name` / `mac` / `mtu` / `link_up`
/// cover the `narf_net::Interface` surface; `model` / `caps` /
/// `ring_capacity` are Stage-4 introspection used by test harnesses
/// and the driver framework.
pub trait HwNic: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn mac(&self) -> [u8; 6];
    fn mtu(&self) -> u32;
    fn link_up(&self) -> bool;
    fn model(&self) -> NicModel;
    fn caps(&self) -> NicCaps;
    fn ring_capacity(&self) -> usize;

    /// RX consumer half.
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>;
    /// TX producer half.
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicError {
    BarMapFailed,
    NoMemory,
    /// Frame outside [1, 1518].
    FrameTooLong,
    /// `transmit` couldn't find a free TX descriptor.
    TxRingFull,
    /// `transmit` polled too long for OWN to clear.
    TxTimeout,
    /// MSI-X table couldn't be brought up.
    MsixSetup,
    /// Generic or catch-all error.
    Other(&'static str),
}
