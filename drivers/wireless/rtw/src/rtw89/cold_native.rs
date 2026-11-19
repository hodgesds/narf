// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Actual parked PCI function and one owned capability-scoped cold backend.
use super::{
    factory::Source,
    mac::{self, ChipId},
    pcie::Interface,
    pcie_native,
    power::{Error, Io},
    power_native::NativeIo,
};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
#[derive(Debug)]
pub(super) struct Owned {
    pub io: NativeIo,
    pub device: BusDevice,
    pub authority: Cap<BusDeviceCap, Write>,
}
impl Owned {
    /// # Safety
    /// Caller holds the singleton function exclusively and has independently
    /// fenced inherited DMA. PCI parking below does not establish that fence.
    /// No diagnostic owner, IRQ, reset or other BAR producer may coexist.
    pub unsafe fn claim(
        device: BusDevice,
        authority: Cap<BusDeviceCap, Write>,
    ) -> Result<Self, Error> {
        authority.check_live().map_err(|_| Error::Access)?;
        let chip = ChipId::from_pci_did(device.id.device).ok_or(Error::Unsupported)?;
        if device.id.vendor != 0x10ec
            || chip == ChipId::Rtl8922A
            || narf_io::iommu::mode() == narf_io::iommu::IommuMode::PerDomain
        {
            return Err(Error::Unsupported);
        }
        crate::rtw88::pci_park::invoke(&authority, || {
            crate::rtw88::pci_park::park(&device, &authority)
        })
        .map_err(|_| Error::Access)?
        .map_err(|_| Error::Access)?;
        let region = crate::rtw88::pci_park::map_bar_control(&device, &authority, 2)
            .map_err(|_| Error::Access)?;
        let required = if matches!(chip, ChipId::Rtl8852A | ChipId::Rtl8852C) {
            0x40004
        } else {
            0x10000
        };
        if region.len < required {
            return Err(Error::Unsupported);
        }
        let version = crate::rtw88::pci_park::invoke(&authority, || {
            // SAFETY: the just-mapped owned Device BAR covers the full SYS_CFG1
            // word; actual current capability invocation encloses the read.
            unsafe { region.read32(mac::R_AX_SYS_CFG1) }
        })
        .map_err(|_| Error::Access)?;
        if version == u32::MAX {
            return Err(Error::Gone);
        }
        let cut = ((version & mac::B_AX_CHIP_VER_MASK) >> mac::B_AX_CHIP_VER_SHIFT) as u8;
        // SAFETY: same exclusively owned Device BAR and verified PCI parking.
        let io = unsafe { NativeIo::new(region, authority, chip, cut) }?;
        Ok(Self {
            io,
            device,
            authority,
        })
    }
    fn access(&mut self) -> pcie_native::Native<'_> {
        pcie_native::Native {
            io: &mut self.io,
            device: &self.device,
            authority: &self.authority,
        }
    }
}
impl Source for Owned {
    fn profile(&self) -> (ChipId, u8) {
        self.io.profile()
    }
    async fn physical(&mut self, start: u16, output: &mut [u8]) -> Result<(), Error> {
        self.io.read_physical(start, output).await
    }
}
impl Interface for Owned {
    async fn config_read8(&mut self, a: u16) -> Result<u8, Error> {
        self.access().config_read8(a).await
    }
    async fn config_read16(&mut self, a: u16) -> Result<u16, Error> {
        self.access().config_read16(a).await
    }
    async fn config_read32(&mut self, a: u16) -> Result<u32, Error> {
        self.access().config_read32(a).await
    }
    async fn config_write8(&mut self, a: u16, v: u8) -> Result<(), Error> {
        self.access().config_write8(a, v).await
    }
    async fn config_write16(&mut self, a: u16, v: u16) -> Result<(), Error> {
        self.access().config_write16(a, v).await
    }
    async fn phy_read(&mut self, g: super::phy_access::Generation, a: u8) -> Result<u16, Error> {
        self.io.read_phy(g, a).await
    }
    async fn phy_write(
        &mut self,
        g: super::phy_access::Generation,
        a: u8,
        v: u16,
    ) -> Result<(), Error> {
        self.io.write_phy(g, a, v).await
    }
}
impl Io for Owned {
    fn read8(&mut self, a: u32) -> Result<u8, Error> {
        self.io.read8(a)
    }
    fn read16(&mut self, a: u32) -> Result<u16, Error> {
        self.io.read16(a)
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.io.read32(a)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), Error> {
        self.io.write8(a, v)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), Error> {
        self.io.write16(a, v)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.io.write32(a, v)
    }
    fn now_us(&self) -> u64 {
        self.io.now_us()
    }
    async fn delay_us(&mut self, us: u64) {
        self.io.delay_us(us).await
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        self.io.read_ecv().await
    }
}
