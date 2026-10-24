// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Current-capability byte configuration/PHY adapter for the retained owner.
use super::{
    pcie::Interface,
    phy_access::Generation,
    power::{Error, Io},
    power_native::NativeIo,
};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};

pub(super) struct Native<'a> {
    pub io: &'a mut NativeIo,
    pub device: &'a BusDevice,
    pub authority: &'a Cap<BusDeviceCap, Write>,
}
impl Native<'_> {
    fn config<T>(&self, address: u16, operation: impl FnOnce(*mut u8) -> T) -> Result<T, Error> {
        self.config_width(address, 1, operation)
    }
    fn config_width<T>(
        &self,
        address: u16,
        width: u16,
        operation: impl FnOnce(*mut u8) -> T,
    ) -> Result<T, Error> {
        crate::rtw88::pci_park::invoke(self.authority, || {
            if address & (width - 1) != 0 || u32::from(address) + u32::from(width) > 4096 {
                return Err(Error::Access);
            }
            let narf_bus::BusKind::Pcie { cfg_phys, .. } = self.device.kind else {
                return Err(Error::Unsupported);
            };
            let pointer =
                narf_bus::ecam::ptr_for(cfg_phys, u64::from(address)).ok_or(Error::Access)?;
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            let value = operation(pointer);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            Ok(value)
        })
        .map_err(|_| Error::Access)?
    }
}
impl Interface for Native<'_> {
    async fn config_read8(&mut self, address: u16) -> Result<u8, Error> {
        let result = self.config(address, |pointer| {
            // SAFETY: exact byte inside the mapped same-function ECAM window;
            // the operation executes within current device-capability invocation.
            unsafe { core::ptr::read_volatile(pointer) }
        });
        match result {
            Ok(value) => Ok(value),
            Err(_) => self.io.read_dbi(address).await,
        }
    }
    async fn config_write8(&mut self, address: u16, value: u8) -> Result<(), Error> {
        let result = self.config(address, |pointer| {
            // SAFETY: current exclusive authority and checked ECAM byte extent.
            // A byte write avoids touching adjacent RW1C/configuration fields.
            unsafe {
                core::ptr::write_volatile(pointer, value);
            }
        });
        match result {
            Ok(()) => Ok(()),
            Err(_) => self.io.write_dbi(address, value).await,
        }
    }
    async fn config_read16(&mut self, address: u16) -> Result<u16, Error> {
        self.config_width(address, 2, |pointer| {
            // SAFETY: complete aligned same-function ECAM word in current invocation.
            u16::from_le(unsafe { core::ptr::read_volatile(pointer.cast::<u16>()) })
        })
    }
    async fn config_read32(&mut self, address: u16) -> Result<u32, Error> {
        self.config_width(address, 4, |pointer| {
            // SAFETY: complete aligned same-function ECAM dword in current invocation.
            u32::from_le(unsafe { core::ptr::read_volatile(pointer.cast::<u32>()) })
        })
    }
    async fn config_write16(&mut self, address: u16, value: u16) -> Result<(), Error> {
        self.config_width(address, 2, |pointer| {
            // SAFETY: exact aligned control word; adjacent RW1C status is untouched.
            unsafe {
                core::ptr::write_volatile(pointer.cast::<u16>(), value.to_le());
            }
        })
    }
    async fn phy_read(&mut self, generation: Generation, address: u8) -> Result<u16, Error> {
        self.io.read_phy(generation, address).await
    }
    async fn phy_write(
        &mut self,
        generation: Generation,
        address: u8,
        value: u16,
    ) -> Result<(), Error> {
        self.io.write_phy(generation, address, value).await
    }
}
impl Io for Native<'_> {
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
        self.io.delay_us(us).await;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        self.io.read_ecv().await
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use crate::rtw89::{mac::ChipId, pcie::Pcie};
    use alloc::vec;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use narf_capabilities::{object_table, CapKind, CapSlot, Rights};
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn ready<F: Future>(future: F) -> Option<F::Output> {
        let mut f = pin!(future);
        match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(r) => Some(r),
            Poll::Pending => None,
        }
    }
    fn smoke_rtw89_native_pcie_policy_requires_current_authority() -> TestResult {
        let mut words = vec![0u32; 16384];
        let (index, generation) = object_table::register(CapKind::BusDevice);
        // SAFETY: fresh test object with exact BusDevice/Write type and rights.
        let authority = unsafe {
            Cap::<BusDeviceCap, Write>::mint(CapSlot::new(
                generation,
                index,
                Write::BITS,
                CapKind::BusDevice as u32,
            ))
        };
        let address = narf_bus::PcieAddr::new(0, 0, 7, 0);
        let device = BusDevice {
            addr: narf_bus::BusAddr::Pcie(address),
            id: narf_bus::DeviceId {
                vendor: 0x10ec,
                device: 0xc852,
                class: 0x028000,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: narf_bus::BusKind::Pcie {
                addr: address,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        };
        let region = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: words.as_mut_ptr() as u64,
            len: 65536,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        // SAFETY: exclusively owned aligned model BAR remains live throughout.
        let mut io = unsafe { NativeIo::new(region, authority, ChipId::Rtl8852C, 0) }.unwrap();
        let mut access = Native {
            io: &mut io,
            device: &device,
            authority: &authority,
        };
        let mut owner = Pcie::default();
        // SAFETY: inert C direct-RAC model needs no ECAM/config transaction;
        // no physical function, DMA engine, reset or concurrent producer exists.
        if ready(unsafe { owner.prepare(&mut access, ChipId::Rtl8852C, 0, true) }) != Some(Ok(())) {
            return TestResult::Fail("native direct-RAC PCIe pre-init");
        }
        let before = words.clone();
        authority.revoke();
        let mut owner = Pcie::default();
        // SAFETY: revocation must reject before any same-model register access.
        if ready(unsafe { owner.prepare(&mut access, ChipId::Rtl8852C, 0, true) })
            != Some(Err(Error::Access))
            || words != before
        {
            return TestResult::Fail("revoked PCIe owner touched BAR");
        }
        let mut basic = super::super::pci_basic::Basic::default();
        // SAFETY: the revoked model must reject before direct RAC or ECAM access.
        if ready(unsafe { basic.prepare(&mut access, ChipId::Rtl8852C) })
            != Some(Err(Error::Access))
            || basic.state() != super::super::pci_basic::State::Preparing
            || words != before
        {
            return TestResult::Fail("revoked PCI basic configuration touched hardware");
        }
        let mut called = false;
        if access
            .config(0x719, |_| {
                called = true;
            })
            .is_ok()
            || called
            || words != before
        {
            return TestResult::Fail("revoked byte configuration accessed ECAM");
        }
        for (address, width) in [(1, 2), (4095, 2), (4094, 4)] {
            let mut called = false;
            if access
                .config_width(address, width, |_| {
                    called = true;
                })
                .is_ok()
                || called
            {
                return TestResult::Fail("invalid native config width reached ECAM");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_native_pcie_policy_requires_current_authority
    );
}
