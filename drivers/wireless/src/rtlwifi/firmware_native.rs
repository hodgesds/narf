//! Retained rtlwifi PCI authority for RTL8188EE MMIO firmware writes.
use super::firmware_transport::{Error, Io};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

pub struct PciIo {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    registers: MmioRegion,
}
impl core::fmt::Debug for PciIo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RtlwifiPciFirmwareIo")
            .field("address", &self.device.addr)
            .finish_non_exhaustive()
    }
}
impl PciIo {
    /// Caller owns the exact live BAR2 control region exclusively. No other
    /// firmware/register path may run concurrently with the retained owner.
    pub(super) unsafe fn new(
        device: BusDevice,
        cap: Cap<BusDeviceCap, Write>,
        registers: MmioRegion,
    ) -> Self {
        Self {
            device,
            cap,
            registers,
        }
    }
    fn access<T>(&self, reg: u16, width: usize, operation: impl FnOnce() -> T) -> Result<T, Error> {
        // The PCI command check and actual MMIO execute in the same live
        // capability operation; returning a raw register handle is forbidden.
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check(reg, width)?;
            Ok(operation())
        })
        .map_err(|_| Error::Access)?
    }
    fn check(&self, reg: u16, width: usize) -> Result<(), Error> {
        let cmd =
            narf_bus::pci::read_command(&self.cap, &self.device).map_err(|_| Error::Access)?;
        if cmd & (narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER)
            != narf_bus::pci::cmd::MEM_SPACE
            || u64::try_from(width)
                .ok()
                .and_then(|n| u64::from(reg).checked_add(n))
                .is_none_or(|end| end > self.registers.len)
        {
            return Err(Error::Access);
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl Io for PciIo {
    fn read8(&self, reg: u16) -> Result<u8, Error> {
        // SAFETY: access checks live authority, parked DMA and complete byte extent.
        self.access(reg, 1, || unsafe { self.registers.read8(u64::from(reg)) })
    }
    fn read32(&self, reg: u16) -> Result<u32, Error> {
        if reg & 3 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: aligned dword extent checked inside the live invocation.
        self.access(reg, 4, || unsafe { self.registers.read32(u64::from(reg)) })
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), Error> {
        // SAFETY: access checks live authority, parked DMA and complete byte extent.
        self.access(reg, 1, || unsafe {
            self.registers.write8(u64::from(reg), value)
        })
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), Error> {
        if reg & 3 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: aligned dword extent checked inside the live invocation.
        self.access(reg, 4, || unsafe {
            self.registers.write32(u64::from(reg), value)
        })
    }
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), Error> {
        self.access(reg, bytes.len(), || {
            for (i, byte) in bytes.iter().enumerate() {
                // SAFETY: complete byte slice was bounded inside this CapOp.
                unsafe { self.registers.write8(u64::from(reg) + i as u64, *byte) };
            }
        })
    }
}
