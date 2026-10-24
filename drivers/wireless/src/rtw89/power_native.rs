// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Capability-scoped AX register and asynchronous DDV backend.
use super::{
    mac::ChipId,
    power::{Error, Io},
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

/// Exclusively owned BAR; the cold boot owner must keep PCI DMA parked.
#[derive(Debug)]
pub struct NativeIo {
    region: MmioRegion,
    authority: Cap<BusDeviceCap, Write>,
    chip: ChipId,
    cut: u8,
    ddv: crate::rtw89::ddv::Ddv,
    phy: super::phy_access::Access,
}
impl NativeIo {
    /// # Safety
    /// Caller exclusively owns the Device-mapped BAR and configuration for the
    /// capability's device; no concurrent firmware, reset or EFUSE access.
    pub unsafe fn new(
        region: MmioRegion,
        authority: Cap<BusDeviceCap, Write>,
        chip: ChipId,
        cut: u8,
    ) -> Result<Self, Error> {
        if region.len < 0x10000 || chip == ChipId::Rtl8922A || cut > 15 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            region,
            authority,
            chip,
            cut,
            ddv: crate::rtw89::ddv::Ddv::default(),
            phy: super::phy_access::Access::default(),
        })
    }
    pub(super) fn profile(&self) -> (ChipId, u8) {
        (self.chip, self.cut)
    }
    /// Actual AX PHY adds0x10000; B path-B's last direct RF dword is1f3fc.
    /// The MAC-sized minimum BAR receipt alone never authorizes RF access.
    pub(super) fn b_phy_window(&self) -> Result<(), Error> {
        if self.chip != ChipId::Rtl8852B {
            return Err(Error::Unsupported);
        }
        self.checked(0x1f3fc, 4, |_, _| ())
    }
    fn checked<T>(
        &self,
        address: u32,
        width: u32,
        operation: impl FnOnce(&MmioRegion, u64) -> T,
    ) -> Result<T, Error> {
        crate::rtw88::pci_park::invoke(&self.authority, || {
            let offset = u64::from(address);
            if address & (width - 1) != 0
                || offset
                    .checked_add(u64::from(width))
                    .is_none_or(|end| end > self.region.len)
            {
                return Err(Error::Access);
            }
            Ok(operation(&self.region, offset))
        })
        .map_err(|_| Error::Access)?
    }
    /// Serialized PCIe PHY/DBI access. A failed/cancelled transaction leaves
    /// this native owner terminal for all PHY/DBI operations. An independent
    /// verified device reset must precede a replacement NativeIo owner.
    pub async fn read_phy(
        &mut self,
        generation: super::phy_access::Generation,
        address: u8,
    ) -> Result<u16, Error> {
        let mut state = core::mem::replace(&mut self.phy, super::phy_access::Access::terminal());
        let chip = self.chip;
        let result = state.read_phy(self, chip, generation, address).await;
        self.phy = state;
        result
    }
    pub async fn write_phy(
        &mut self,
        generation: super::phy_access::Generation,
        address: u8,
        value: u16,
    ) -> Result<(), Error> {
        let mut state = core::mem::replace(&mut self.phy, super::phy_access::Access::terminal());
        let chip = self.chip;
        let result = state
            .write_phy(self, chip, generation, address, value)
            .await;
        self.phy = state;
        result
    }
    pub async fn modify_phy(
        &mut self,
        generation: super::phy_access::Generation,
        address: u8,
        mask: u16,
        value: u16,
    ) -> Result<(), Error> {
        let mut state = core::mem::replace(&mut self.phy, super::phy_access::Access::terminal());
        let chip = self.chip;
        let result = state
            .modify_phy(self, chip, generation, address, mask, value)
            .await;
        self.phy = state;
        result
    }
    pub async fn read_dbi(&mut self, address: u16) -> Result<u8, Error> {
        let mut state = core::mem::replace(&mut self.phy, super::phy_access::Access::terminal());
        let chip = self.chip;
        let result = state.read_dbi(self, chip, address).await;
        self.phy = state;
        result
    }
    pub async fn write_dbi(&mut self, address: u16, value: u8) -> Result<(), Error> {
        let mut state = core::mem::replace(&mut self.phy, super::phy_access::Access::terminal());
        let chip = self.chip;
        let result = state.write_dbi(self, chip, address, value).await;
        self.phy = state;
        result
    }
    /// AX DDV physical bytes, including ECV0x5ea and secure selection0x5ec.
    /// Cancellation keeps DDV terminal and permanently refuses another read;
    /// a verified chip power/reset owner must precede any later reclamation.
    pub async fn read_physical(&mut self, start: u16, output: &mut [u8]) -> Result<(), Error> {
        // Replacing before await keeps the native owner closed even if the
        // future (and its temporary DDV state) is dropped mid-operation.
        let mut state = core::mem::replace(&mut self.ddv, crate::rtw89::ddv::Ddv::terminal());
        let chip = self.chip;
        let cut = self.cut;
        let result = state.read(self, chip, cut, start, output).await;
        self.ddv = state;
        result
    }
    /// Read actual physical secure selection, preserving DDV's retained failure
    /// state. No erased or disabled-boot default is supplied on access failure.
    pub async fn secure_fuses(
        &mut self,
    ) -> Result<super::secure::Fuses, super::download_plan::Error> {
        let mut bytes = [0; 2];
        self.read_physical(0x5ec, &mut bytes)
            .await
            .map_err(|_| super::download_plan::Error::Firmware(super::fw::FwError::Authority))?;
        Ok(super::secure::Fuses::decode(self.chip, bytes[0], bytes[1])?)
    }
}
impl Io for NativeIo {
    fn read8(&mut self, address: u32) -> Result<u8, Error> {
        self.checked(address, 1, |r, a| {
            // SAFETY: checked live invocation, Device extent and byte alignment.
            unsafe { r.read8(a) }
        })
    }
    fn read16(&mut self, address: u32) -> Result<u16, Error> {
        self.checked(address, 2, |r, a| {
            // SAFETY: complete word extent and natural alignment inside invocation.
            unsafe { r.read16(a) }
        })
    }
    fn read32(&mut self, address: u32) -> Result<u32, Error> {
        self.checked(address, 4, |r, a| {
            // SAFETY: complete dword extent/alignment; exclusive current authority.
            unsafe { r.read32(a) }
        })
    }
    fn write8(&mut self, address: u32, value: u8) -> Result<(), Error> {
        self.checked(address, 1, |r, a| {
            // SAFETY: current exclusive authority and complete checked byte extent.
            unsafe { r.write8(a, value) }
        })
    }
    fn write16(&mut self, address: u32, value: u16) -> Result<(), Error> {
        self.checked(address, 2, |r, a| {
            // SAFETY: current authority, complete word extent and natural alignment.
            unsafe { r.write16(a, value) }
        })
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), Error> {
        self.checked(address, 4, |r, a| {
            // SAFETY: checked current authority plus dword extent/alignment.
            unsafe { r.write32(a, value) }
        })
    }
    fn now_us(&self) -> u64 {
        narf_time::wall::monotonic_ns() / 1000
    }
    async fn delay_us(&mut self, us: u64) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(us.saturating_mul(1000))).await;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        let mut byte = [0];
        self.read_physical(0x5ea, &mut byte).await?;
        let cut = byte[0] >> 4;
        if cut == 15 {
            Ok(None)
        } else {
            self.cut = cut;
            Ok(Some(cut))
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::vec;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_rtw89_native_power_authority_and_bounds() -> TestResult {
        let mut words = vec![0u32; 16384];
        words[0] = 0x1122_aabb;
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        // An aligned, owned register-memory model stays live for every access.
        let mut io = NativeIo {
            region: MmioRegion {
                phys: narf_memory::PhysAddr::new(0),
                virt: words.as_mut_ptr() as u64,
                len: 0x10000,
                kind: narf_bus::BarKind::Mmio32 {
                    prefetchable: false,
                },
            },
            authority: cap,
            chip: ChipId::Rtl8852B,
            cut: 0,
            ddv: crate::rtw89::ddv::Ddv::default(),
            phy: super::super::phy_access::Access::default(),
        };
        if io.read8(0) != Ok(0xbb)
            || io.read16(0) != Ok(0xaabb)
            || io.read32(0) != Ok(0x1122_aabb)
            || io.read32(1) != Err(Error::Access)
            || io.read16(0xffff) != Err(Error::Access)
            || io.write32(0x10000, 1) != Err(Error::Access)
        {
            return TestResult::Fail("native register extent/alignment");
        }
        if io.write8(4, 0x55).is_err()
            || io.write16(6, 0x6677).is_err()
            || io.write32(8, 0x8899_aabb).is_err()
            || words[1] != 0x6677_0055
            || words[2] != 0x8899_aabb
        {
            return TestResult::Fail("native register widths");
        }
        cap.revoke();
        if io.read8(0) != Err(Error::Access)
            || io.read16(0) != Err(Error::Access)
            || io.read32(0) != Err(Error::Access)
            || io.write8(0, 0).is_ok()
            || io.write16(0, 0).is_ok()
            || io.write32(0, 0).is_ok()
            || words[0] != 0x1122_aabb
        {
            return TestResult::Fail("revoked current authority reached native MMIO");
        }
        let mut byte = [0xa5];
        let result = {
            let mut future = pin!(io.read_physical(0x5ea, &mut byte));
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
        };
        if result != Poll::Ready(Err(Error::Access)) || byte != [0xa5] || !io.ddv.is_terminal() {
            return TestResult::Fail("revoked EFUSE ownership was not retained");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_native_power_authority_and_bounds
    );
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "phy_access/native_tests.rs"]
mod phy_tests;
