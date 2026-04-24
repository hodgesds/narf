//! Bus-address types.
//!
//! A `BusAddr` is the opaque key used by the registry to name a device.
//! Spec: `bus/` §3.1 `DeviceLocation`. PCIe devices carry the four
//! segment/bus/device/function coordinates; MMIO (virtio-mmio on
//! aarch64, platform devices generally) carries a single physical
//! base address.

use core::fmt;

use narf_memory::PhysAddr;

/// PCIe ECAM coordinates. Segment is part of the addressing space in
/// PCIe to name the PCI domain; `segment=0` is the only value QEMU
/// ever exposes but the field is kept so the on-the-wire key matches
/// real hardware.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct PcieAddr {
    pub segment:  u16,
    pub bus:      u8,
    pub device:   u8,
    pub function: u8,
}

impl PcieAddr {
    #[inline]
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self { segment, bus, device, function }
    }

    /// ECAM offset for this B/D/F relative to the segment's ECAM base.
    /// PCIe spec: `(bus << 20) | (device << 15) | (function << 12)`.
    #[inline]
    pub const fn ecam_offset(self) -> u64 {
        ((self.bus as u64) << 20)
            | ((self.device as u64) << 15)
            | ((self.function as u64) << 12)
    }
}

impl fmt::Debug for PcieAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04x}:{:02x}:{:02x}.{}",
            self.segment, self.bus, self.device, self.function)
    }
}

/// A canonical address for anything the bus crate discovered. Used as
/// the registry key. Two devices never share a `BusAddr`.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum BusAddr {
    /// PCIe device at the given segment/bus/device/function.
    Pcie(PcieAddr),
    /// MMIO / platform device at a physical base address. For
    /// virtio-mmio on aarch64 this is the node's first `reg` cell.
    Mmio(PhysAddr),
}

impl fmt::Debug for BusAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BusAddr::Pcie(a)  => write!(f, "pcie:{:?}", a),
            BusAddr::Mmio(p)  => write!(f, "mmio:{:#x}", p.raw()),
        }
    }
}
