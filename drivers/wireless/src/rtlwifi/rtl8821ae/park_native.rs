// SPDX-License-Identifier: GPL-2.0-or-later
//! Mounted below firmware_native; only current original PCI may restrict8821.
use super::*;
impl PciIo {
    pub(in crate::rtlwifi) fn restrict_8821_packets(&self) -> Result<(), Error> {
        if self.device.id.device != super::super::regs::RTL_DEV_8821AE {
            return Err(Error::Unsupported);
        }
        // Reuse only the scalar PCI adapter, not AE's register recipe.
        let io = super::ae_park::ParkIo(self);
        let result = super::super::rtl8821ae::park::close(&io, || {
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
        let irq = crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check_identity()?;
            let _ = self.deliver(false);
            if self.msi.lock().is_some() || self.quarantined.load(Ordering::Acquire) {
                return Err(Error::Gate);
            }
            Ok(())
        })
        .map_err(|_| Error::Access)?;
        result.and(irq)
    }
}
