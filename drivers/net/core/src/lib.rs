//! Shared surface for NARF NIC drivers.
//!
//! The driver-agnostic half of `narf-drivers-net`: the [`HwNic`] trait and the
//! types it is defined over ([`NicModel`], [`NicCaps`], [`NicDescriptor`],
//! [`NicError`]), plus the Realtek PHY helpers in [`rtl_phy`]. Per-driver
//! crates depend on this crate for the trait surface rather than on the
//! `narf-drivers-net` facade, which depends on *them* — so there is no cycle.
//!
//! The `narf-drivers-net` facade re-exports everything here, so existing
//! `narf_drivers_net::HwNic` users are unaffected by the split.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

pub mod rtl_phy;

use narf_ipc::{Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, RX_RING_N, TX_RING_N};

/// Chipset families the Stage-4 driver set targets.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicModel {
    /// Intel 8254x / 8257x — "e1000" / "e1000e".
    IntelE1000,
    /// Intel 82575-onwards Gigabit — "igb".
    IntelIgb,
    /// Intel 82599 / X540 10-GbE — "ixgbe".
    IntelIxgbe,
    /// Intel X710 / XL710 / XXV710 — "i40e".
    IntelI40e,
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
            NicModel::IntelI40e => (0x8086, 0x1572),
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

    // ── Multi-queue + RSS (first-class; single-queue by default) ─────
    // Mirrors `narf_net::Interface`; defaults keep single-queue drivers
    // unchanged. A multi-queue driver overrides these and the shared NAPI
    // helper (`narf_net::napi`) + RSS core (`narf_net::rss`) drive per-queue
    // pollers and flow steering off them.

    /// Number of RX queues the device exposes. 1 ⇒ no multi-queue.
    fn num_rx_queues(&self) -> u16 {
        1
    }
    /// Number of TX queues. 1 ⇒ no multi-queue.
    fn num_tx_queues(&self) -> u16 {
        1
    }
    /// RSS configuration (Toeplitz key + indirection table) for a multi-queue
    /// device; `None` when single-queue.
    fn rss(&self) -> Option<narf_net::rss::RssConfig> {
        None
    }
    /// Preferred CPU / IRQ binding for queue `q`. Default: boot CPU, no vector.
    fn queue_affinity(&self, _q: u16) -> narf_net::rss::QueueAffinity {
        narf_net::rss::QueueAffinity::default()
    }
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
