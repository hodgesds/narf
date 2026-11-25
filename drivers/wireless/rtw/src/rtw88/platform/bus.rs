//! `narf_bus` for the module: the PCI types, uninhabited.
//!
//! The module build carries no PCI function (the rtw88 PCIe ids are
//! registration-only), yet code shared with the USB path names PCI types in
//! the signatures of PCI-only branches. Making those types uninhabited lets
//! the shared code build unchanged while the compiler proves every PCI-only
//! branch unreachable: a `BusDevice` or `MmioRegion` can never exist here.

/// A bus address. No value exists in the module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusAddr {}

/// Vendor/device id of a bus device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceId {
    pub vendor: u16,
    pub device: u16,
}

/// An enumerated bus device. Uninhabited (its address is).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusDevice {
    pub addr: BusAddr,
    pub id: DeviceId,
}

/// The per-device authority object.
#[derive(Debug)]
pub enum BusDeviceCap {}

/// A mapped BAR. No value exists in the module.
#[derive(Debug)]
pub enum MmioRegion {}

impl MmioRegion {
    /// # Safety
    /// Unreachable: no `MmioRegion` exists in the module.
    pub unsafe fn read8(&self, _offset: u64) -> u8 {
        match *self {}
    }
    /// # Safety
    /// Unreachable: no `MmioRegion` exists in the module.
    pub unsafe fn read16(&self, _offset: u64) -> u16 {
        match *self {}
    }
    /// # Safety
    /// Unreachable: no `MmioRegion` exists in the module.
    pub unsafe fn read32(&self, _offset: u64) -> u32 {
        match *self {}
    }
    /// # Safety
    /// Unreachable: no `MmioRegion` exists in the module.
    pub unsafe fn write8(&self, _offset: u64, _value: u8) {
        match *self {}
    }
    /// # Safety
    /// Unreachable: no `MmioRegion` exists in the module.
    pub unsafe fn write16(&self, _offset: u64, _value: u16) {
        match *self {}
    }
    /// # Safety
    /// Unreachable: no `MmioRegion` exists in the module.
    pub unsafe fn write32(&self, _offset: u64, _value: u32) {
        match *self {}
    }
}

/// PCI configuration space, unreachable in the module.
pub mod pci {
    use super::{BusDevice, BusDeviceCap};
    use crate::rtw88::platform::narf_capabilities::{Cap, Write};

    /// Configuration access error.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PciError {}

    /// Command register bits.
    pub mod cmd {
        pub const MEM_SPACE: u16 = 1 << 1;
        pub const BUS_MASTER: u16 = 1 << 2;
        pub const INTX_DISABLE: u16 = 1 << 10;
    }

    pub fn read_config32(
        _cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
        _offset: u16,
    ) -> Result<u32, PciError> {
        match device.addr {}
    }

    pub fn read_command(
        _cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u16, PciError> {
        match device.addr {}
    }
}
