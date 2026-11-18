// SPDX-License-Identifier: GPL-2.0-or-later
//! Mounted below firmware_native: current original PCI restrictive AE park.
use super::*;
pub(super) struct ParkIo<'a>(pub(super) &'a PciIo);
impl ParkIo<'_> {
    fn access<T>(
        &self,
        reg: u16,
        width: usize,
        f: impl FnOnce(&MmioRegion) -> T,
    ) -> Result<T, Error> {
        self.0.access(reg, width, || {
            self.0.check_identity()?;
            Ok(f(&self.0.registers))
        })?
    }
}
#[async_trait::async_trait]
impl Io for ParkIo<'_> {
    fn read8(&self, r: u16) -> Result<u8, Error> {
        // SAFETY: exact original BAR, bounded extent and current PCI identity
        // are checked inside the SAME capability operation as each access.
        self.access(r, 1, |m| unsafe { m.read8(u64::from(r)) })
    }
    fn read16(&self, r: u16) -> Result<u16, Error> {
        if r & 1 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: aligned word in the original BAR; access checks its full
        // extent and current PCI identity inside the same capability operation.
        self.access(r, 2, |m| unsafe { m.read16(u64::from(r)) })
    }
    fn read32(&self, r: u16) -> Result<u32, Error> {
        if r & 3 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: aligned dword in the original BAR; access checks its full
        // extent and current PCI identity inside the same capability operation.
        self.access(r, 4, |m| unsafe { m.read32(u64::from(r)) })
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), Error> {
        // SAFETY: access checks this byte's original BAR extent and current
        // PCI identity inside the same capability operation as the write.
        self.access(r, 1, |m| unsafe { m.write8(u64::from(r), v) })
    }
    fn write16(&self, _r: u16, _v: u16) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), Error> {
        if r & 3 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: aligned dword in the original BAR; access checks its full
        // extent and current PCI identity inside the same capability operation.
        self.access(r, 4, |m| unsafe { m.write32(u64::from(r), v) })
    }
    fn write_bytes(&self, _r: u16, _b: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}
impl PciIo {
    pub(in crate::rtlwifi) fn restrict_ae_packets(&self) -> Result<(), Error> {
        if self.device.id.device != super::super::rtl8723ae::DEV_ID {
            return Err(Error::Unsupported);
        }
        let io = ParkIo(self);
        let result = super::super::rtl8723ae::park::close(&io, || {
            // This narrow operation disables BME only; no command path may
            // enable it or mint replacement MMIO/reset/DMA-idle authority.
            crate::rtw88::pci_park::invoke(&self.cap, || {
                self.check_identity()?;
                narf_bus::pci::clear_command(
                    &self.cap,
                    &self.device,
                    narf_bus::pci::cmd::BUS_MASTER,
                )
                .map_err(|_| Error::Access)?;
                let command = narf_bus::pci::read_command(&self.cap, &self.device)
                    .map_err(|_| Error::Access)?;
                if command == u16::MAX {
                    return Err(Error::Gone);
                }
                if command & narf_bus::pci::cmd::BUS_MASTER != 0 {
                    return Err(Error::Gate);
                }
                Ok(())
            })
            .map_err(|_| Error::Access)?
        });
        // IRQ delivery is independent of the MAC/BME attempt. Existing MSI
        // withdrawal quarantines the vector when its current write is denied.
        let irq = crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check_identity()?;
            let _ = self.deliver(false);
            if self.msi.lock().is_some() || self.quarantined.load(Ordering::Acquire) {
                return Err(Error::Gate);
            }
            Ok(())
        })
        .map_err(|_| Error::Access)
        .and_then(core::convert::identity);
        // NASR3 may have committed endpoint states before a wait was
        // cancelled or its source revoked. Terminal park serializes against
        // that same scalar effect gate and independently withdraws only this
        // original endpoint's optional states under CURRENT PCI authority.
        // This permits no new link state and proves neither RF nor DMA stop.
        let link = self.disable_aspm();
        result.and(irq).and(link)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "park_native_tests.rs"]
mod tests;
