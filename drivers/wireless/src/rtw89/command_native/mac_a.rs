// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Fresh N5AM scope around every actual A post-WCPU MAC access.

use super::*;
use crate::rtw89::{
    mac_a_policy::{Board, Qualification},
    mac_runtime, power, radio_assets,
};
use alloc::sync::Arc;

struct Port<'a> {
    io: &'a mut NativeIo,
    grant: &'a Qualification,
    error: Option<power::Error>,
}
struct RxPort<'a> {
    io: Port<'a>,
    device: &'a narf_bus::BusDevice,
    authority: &'a narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
}
impl RxPort<'_> {
    fn config<T>(
        &mut self,
        address: u16,
        width: u16,
        operation: impl FnOnce(*mut u8) -> T,
    ) -> Result<T, power::Error> {
        if let Some(error) = self.io.error {
            return Err(error);
        }
        let grant = self.io.grant;
        let io = &mut *self.io.io;
        let device = self.device;
        let authority = self.authority;
        grant.with_current(|| {
            crate::rtw89::pcie_native::Native {
                io,
                device,
                authority,
            }
            .config_width(address, width, operation)
        })
    }
}
impl power::Io for RxPort<'_> {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.io.read8(a)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.io.read16(a)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.io.read32(a)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.io.write8(a, v)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.io.write16(a, v)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.io.write32(a, v)
    }
    fn now_us(&self) -> u64 {
        self.io.now_us()
    }
    async fn delay_us(&mut self, us: u64) {
        self.io.delay_us(us).await;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl crate::rtw89::pcie::Interface for RxPort<'_> {
    async fn config_read8(&mut self, a: u16) -> Result<u8, power::Error> {
        self.config(a, 1, |p| {
            // SAFETY: exact original mapped ECAM byte enclosed by both grants.
            unsafe { core::ptr::read_volatile(p) }
        })
    }
    async fn config_read16(&mut self, a: u16) -> Result<u16, power::Error> {
        self.config(a, 2, |p| {
            // SAFETY: actual checked aligned same-function ECAM word/current scopes.
            u16::from_le(unsafe { core::ptr::read_volatile(p.cast::<u16>()) })
        })
    }
    async fn config_read32(&mut self, a: u16) -> Result<u32, power::Error> {
        self.config(a, 4, |p| {
            // SAFETY: actual checked aligned same-function ECAM dword/current scopes.
            u32::from_le(unsafe { core::ptr::read_volatile(p.cast::<u32>()) })
        })
    }
    async fn config_write8(&mut self, _: u16, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn phy_read(
        &mut self,
        _: crate::rtw89::phy_access::Generation,
        _: u8,
    ) -> Result<u16, power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn phy_write(
        &mut self,
        _: crate::rtw89::phy_access::Generation,
        _: u8,
        _: u16,
    ) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Port<'_> {
    fn access<T>(
        &mut self,
        operation: impl FnOnce(&mut NativeIo) -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        self.grant.with_current(|| operation(self.io))
    }
}
impl power::Io for Port<'_> {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.access(|io| io.read8(a))
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.access(|io| io.read16(a))
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access(|io| io.read32(a))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.access(|io| io.write8(a, v))
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.access(|io| io.write16(a, v))
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access(|io| io.write32(a, v))
    }
    fn now_us(&self) -> u64 {
        self.io.now_us()
    }
    async fn delay_us(&mut self, us: u64) {
        if let Err(error) = self.grant.current() {
            self.error = Some(error);
            return;
        }
        self.io.delay_us(us).await;
        if let Err(error) = self.grant.current() {
            self.error = Some(error);
        }
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Native {
    pub(super) fn mac_access<T>(
        &mut self,
        operation: impl FnOnce(&mut NativeIo) -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        if self.chip != ChipId::Rtl8852A {
            return operation(&mut self.io);
        }
        let grant = self.mac_a.clone().ok_or(power::Error::Unsupported)?;
        grant.with_current(|| operation(&mut self.io))
    }
    pub(super) async unsafe fn prepare_receive_a(
        &mut self,
        mac: &mac_runtime::Mac,
    ) -> Result<(), crate::rtw89::rx_dma::Error> {
        if self.state != State::Active
            || self.chip != ChipId::Rtl8852A
            || mac.state() != mac_runtime::State::Ready
            || self.identity().is_none()
        {
            return Err(power::Error::Terminal.into());
        }
        let grant = self.mac_a.clone().ok_or(power::Error::Unsupported)?;
        grant.current()?;
        let command = grant.with_current(|| self.command().map_err(|_| power::Error::Access))?;
        if command & (narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE)
            != narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE
        {
            return Err(power::Error::Access.into());
        }
        let mut io = RxPort {
            io: Port {
                io: &mut self.io,
                grant: &grant,
                error: None,
            },
            device: &self.device,
            authority: &self.authority,
        };
        // SAFETY: actual original A MAC receipt, retained current signed/Bus
        // port and exact source AX/LTR geometry; outer Attempt retains maps.
        unsafe { self.receive.prepare_for(&mut io, ChipId::Rtl8852A, 64) }.await?;
        grant.current()?;
        Ok(())
    }
    pub(in crate::rtw89) fn secure_policy_a(
        &self,
        assets: &radio_assets::Assets,
    ) -> Result<crate::rtw89::mac_a_policy::SecurePolicy, power::Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            if self.chip != ChipId::Rtl8852A
                || self.state != State::Unpublished
                || self
                    .factory
                    .as_ref()
                    .and_then(|f| f.identity())
                    .is_none_or(|id| !id.fuses().enabled())
            {
                return Err(power::Error::Unsupported);
            }
            let board = Board::new(
                self.lifecycle,
                self.factory.as_ref().ok_or(power::Error::Unsupported)?,
                self.device.id,
                assets,
            )
            .map_err(|_| power::Error::Access)?;
            let policy = crate::rtw89::mac_a_policy::SecurePolicy::load(board)
                .map_err(|_| power::Error::Access)?;
            if !policy.matches(board) {
                return Err(power::Error::Access);
            }
            policy.current()?;
            Ok(policy)
        })
        .map_err(|_| power::Error::Access)?
    }
    pub(in crate::rtw89) fn preflight_mac_a(
        &self,
        assets: &radio_assets::Assets,
    ) -> Result<Qualification, power::Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            if self.state != State::Active
                || self.chip != ChipId::Rtl8852A
                || self.mac_a.is_some()
                || self.receive.state() != crate::rtw89::rx_dma::State::New
                || self.radio_started
            {
                return Err(power::Error::Terminal);
            }
            let board = Board::new(
                self.lifecycle,
                self.factory.as_ref().ok_or(power::Error::Unsupported)?,
                self.device.id,
                assets,
            )
            .map_err(|_| power::Error::Access)?;
            Qualification::load(board).map_err(|_| power::Error::Access)
        })
        .map_err(|_| power::Error::Access)?
    }
    /// # Safety
    /// Same original startup/function after Running firmware, drained CH12;
    /// no packet/IRQ/radio/reset/PM producer. Outer Attempt terminalizes on
    /// failure/drop and retains all original maps and scheduler ownership.
    pub(in crate::rtw89) async unsafe fn prepare_mac_a(
        &mut self,
        mac: &mut mac_runtime::Mac,
        assets: &radio_assets::Assets,
        grant: Qualification,
    ) -> Result<(), power::Error> {
        if self.state != State::Active
            || self.chip != ChipId::Rtl8852A
            || self.mac_a.is_some()
            || mac.state() != mac_runtime::State::New
            || self.radio_started
            || self.receive.state() != crate::rtw89::rx_dma::State::New
        {
            return Err(power::Error::Terminal);
        }
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let board = Board::new(self.lifecycle, factory, self.device.id, assets)
            .map_err(|_| power::Error::Access)?;
        if !grant.matches(board) {
            return Err(power::Error::Access);
        }
        grant.current()?;
        let grant = Arc::new(grant);
        self.mac_a = Some(grant.clone()); // before the first new MAC effect
        let command = grant.with_current(|| self.command().map_err(|_| power::Error::Access))?;
        if command & (narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE)
            != narf_bus::pci::cmd::BUS_MASTER | narf_bus::pci::cmd::MEM_SPACE
        {
            return Err(power::Error::Access);
        }
        let start = self.io.now_us();
        loop {
            grant.with_current(|| self.poll().map_err(|_| power::Error::Access))?;
            if self.queue.pending() == 0 {
                break;
            }
            if self.io.now_us().saturating_sub(start) >= 400_000 {
                return Err(power::Error::Timeout);
            }
            grant.current()?;
            self.io.delay_us(50).await;
            grant.current()?;
        }
        let factory = self.factory.as_ref().ok_or(power::Error::Unsupported)?;
        let mut io = Port {
            io: &mut self.io,
            grant: &grant,
            error: None,
        };
        // SAFETY: the exact A source config and current signed/Bus Port above;
        // same original Mac owner is never reconstructed after uncertainty.
        unsafe { mac.prepare(&mut io, factory) }.await?;
        grant.current()
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mac_a_tests.rs"]
mod tests;
