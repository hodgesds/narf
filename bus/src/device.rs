//! Device descriptor.
//!
//! Spec: `bus/` §3.1 `DeviceInfo`. Simplified for Stage 2/3-side-track:
//! the canonical registry entry is a `BusDevice` that names the
//! device, its location, and enough identification for drivers to
//! decide whether they care (vendor/device/class for PCIe; compatible
//! string + optional magic for MMIO). BAR sizing, MSI-X capability
//! layout, IOMMU group, and NUMA node are future work.

use core::fmt;

use crate::addr::{BusAddr, PcieAddr};
use narf_memory::PhysAddr;

/// Identification fields common across transports. PCIe populates all
/// five; MMIO virtio populates `vendor`/`device` from the transport's
/// own registers (magic + device id) with `class` left at 0 and
/// `subsystem_vendor`/`subsystem_id` left at 0.
///
/// Subsystem IDs come from the PCI type-0 header at offsets 0x2C
/// (Subsystem Vendor ID) and 0x2E (Subsystem ID) per PCI 3.0 §6.2.4.
/// Linux reads them in `drivers/pci/probe.c::pci_read_bases` (called
/// by `pci_setup_device`) and stores as `dev->subsystem_vendor` /
/// `dev->subsystem_device`.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct DeviceId {
    pub vendor: u16,
    pub device: u16,
    pub class: u32,
    /// PCI Subsystem Vendor ID (cfg offset 0x2C). 0 for non-PCIe transports.
    pub subsystem_vendor: u16,
    /// PCI Subsystem ID (cfg offset 0x2E). 0 for non-PCIe transports.
    pub subsystem_id: u16,
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeviceId({:04x}:{:04x}, class={:06x}, subsys={:04x}:{:04x})",
            self.vendor, self.device, self.class,
            self.subsystem_vendor, self.subsystem_id
        )
    }
}

/// Transport-specific extras. Kept small — a driver that needs the
/// full BAR layout asks the registry for its `BusDeviceHandle` and
/// pulls it out there (Wave 2 cap work).
#[derive(Copy, Clone)]
pub enum BusKind {
    /// PCIe function. ECAM window base lets drivers build their own
    /// cfg-space accessor after `claim()` — the bus crate holds the
    /// only mapping today and simply exposes its base.
    Pcie {
        addr: PcieAddr,
        /// Physical address of this function's 4-KiB cfg window.
        cfg_phys: PhysAddr,
    },
    /// Memory-mapped virtio transport. `device_id` mirrors the value
    /// pulled from the VIRTIO_MMIO_DEVICE_ID register (0 = invalid /
    /// empty slot, reported here only when non-zero).
    VirtioMmio {
        base: PhysAddr,
        /// Size of the VIRTIO_MMIO register window (typically 0x200).
        len: u64,
        /// VIRTIO_MMIO device ID (DeviceId register, offset 0x08).
        device_id: u32,
    },
}

impl fmt::Debug for BusKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BusKind::Pcie { addr, cfg_phys } => f
                .debug_struct("Pcie")
                .field("addr", addr)
                .field("cfg_phys", cfg_phys)
                .finish(),
            BusKind::VirtioMmio {
                base,
                len,
                device_id,
            } => f
                .debug_struct("VirtioMmio")
                .field("base", base)
                .field("len", len)
                .field("device_id", device_id)
                .finish(),
        }
    }
}

/// A discovered device. Immutable post-enumeration.
#[derive(Copy, Clone)]
pub struct BusDevice {
    pub addr: BusAddr,
    pub id: DeviceId,
    pub kind: BusKind,
}

impl fmt::Debug for BusDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BusDevice")
            .field("addr", &self.addr)
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish()
    }
}
