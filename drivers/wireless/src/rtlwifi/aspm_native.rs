// SPDX-License-Identifier: GPL-2.0-or-later
//! Endpoint-only ASPM following the actual enabled upstream platform policy.
//! The shared bridge and common-clock configuration remain platform-owned.
use super::super::aspm;
use super::*;
use narf_capabilities::Read;
impl aspm::Port for PciIo {
    fn write16(&self, register: u16, value: u16) -> Result<(), Error> {
        if register & 1 != 0 {
            return Err(Error::Access);
        }
        // SAFETY: the exact complete aligned word is enclosed by the
        // current function's native PCI capability operation.
        self.access(register, 2, || unsafe {
            self.registers.write16(u64::from(register), value)
        })
    }
}
impl PciIo {
    fn aspm_policy(&self, enabled: bool) -> Result<Option<u16>, Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check(0, 1)?;
            self.check_identity()?;
            let read = self.cap.derive::<Read>().map_err(|_| Error::Access)?;
            let status = match narf_bus::pci_express::read_status(&read, &self.device) {
                Ok(status) => status,
                Err(narf_bus::pci_express::PcieCapError::NotExpress) => return Ok(None),
                Err(_) => return Err(Error::Access),
            };
            if !enabled {
                return Ok(Some(0));
            }
            let known = narf_bus::pci::upstream_bridge(&self.device).is_some_and(|parent| {
                matches!(parent.id.vendor, 0x8086 | 0x1002 | 0x1022 | 0x1039)
            });
            if !known {
                return Ok(Some(0));
            }
            let parent = narf_bus::pci_express::parent_link_control(&read, &self.device)
                .map_err(|_| Error::Access)?;
            Ok(Some(aspm::policy(status.link_caps, parent, enabled)))
        })
        .map_err(|_| Error::Access)?
    }
    fn aspm_control(&self, desired: u16) -> Result<(), Error> {
        crate::rtw88::pci_park::invoke(&self.cap, || {
            self.check(0, 1)?;
            self.check_identity()?;
            // SAFETY: bounded standard capability discovery over this exact
            // retained function's validated live configuration window.
            let offset = unsafe {
                narf_bus::pci_cap::find_cap(&self.device, narf_bus::pci_express::PCIE_CAP_ID)
            }
            .map_err(|_| Error::Access)?
            .ok_or(Error::Unsupported)?;
            if offset > 0xec {
                return Err(Error::Access);
            }
            let control_offset = offset as u16 + 0x10;
            let current = narf_bus::pci::read_config32(&self.cap, &self.device, control_offset)
                .map_err(|_| Error::Access)? as u16;
            if current == u16::MAX {
                return Err(Error::Gone);
            }
            if current & aspm::CONTROL_MASK == desired {
                return Ok(());
            }
            narf_bus::pci_express::clear_and_set_link_control(
                &self.cap,
                &self.device,
                aspm::CONTROL_MASK,
                desired,
            )
            .map_err(|_| Error::Access)?;
            let after = narf_bus::pci::read_config32(&self.cap, &self.device, control_offset)
                .map_err(|_| Error::Access)? as u16;
            if after & aspm::CONTROL_MASK != desired
                || after & !aspm::CONTROL_MASK != current & !aspm::CONTROL_MASK
            {
                return Err(Error::Gate);
            }
            Ok(())
        })
        .map_err(|_| Error::Access)?
    }
    pub(in crate::rtlwifi) fn disable_aspm(&self) -> Result<(), Error> {
        match self.aspm_policy(false)? {
            Some(_) => self.aspm_control(0),
            None => Ok(()),
        }
    }
    /// Linux keeps the link's power policy after the NIC is disabled.
    /// Only this same function's actually completed internal preparation
    /// can be reused here; a fresh control port has no such receipt.
    pub(in crate::rtlwifi) async fn idle_aspm(&self, enabled: bool) -> Result<(), Error> {
        if !self.aspm_prepared.load(Ordering::Acquire) {
            return Ok(());
        }
        aspm::configure(self, enabled).await
    }
    pub(in crate::rtlwifi) async fn prepare_aspm(&self, enabled: bool) -> Result<(), Error> {
        aspm::configure(self, enabled).await
    }
}
impl aspm::PolicyPort for PciIo {
    fn desired(&self, enabled: bool) -> Result<Option<u16>, Error> {
        self.aspm_policy(enabled)
    }
    fn control(&self, desired: u16) -> Result<(), Error> {
        self.aspm_control(desired)
    }
    fn prepared(&self) -> &AtomicBool {
        &self.aspm_prepared
    }
}
#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_rtl8188ee_aspm_revoked_native_pci_cap_never_accesses_config_or_bar() -> TestResult {
        let address = narf_bus::PcieAddr::new(0xfffe, 0xfc, 0x1c, 0);
        let device = BusDevice {
            addr: narf_bus::BusAddr::Pcie(address),
            id: narf_bus::DeviceId {
                vendor: 0x10ec,
                device: 0x8179,
                class: 0x028000,
                subsystem_vendor: 0x10ec,
                subsystem_id: 0xffff,
            },
            kind: narf_bus::BusKind::Pcie {
                addr: address,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        };
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        cap.revoke();
        let registers = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0x2000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        // SAFETY: deliberately revoked inert authority. The actual native
        // wrapper must return before touching the invalid config/BAR windows.
        let io = unsafe { PciIo::new(device, cap, registers) };
        if narf_scheduler::block_on_spin(io.prepare_aspm(true)) != Err(Error::Access) {
            return TestResult::Fail("EE revoked native ASPM authority reached PCI/MMIO");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtlwifi/aspm",
        smoke_rtl8188ee_aspm_revoked_native_pci_cap_never_accesses_config_or_bar
    );
}
