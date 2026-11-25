// SPDX-License-Identifier: GPL-2.0-or-later
//! Original native AR9003 ANI transport. The source latch encloses every
//! actual access; only this serialized owner bypasses its changing ANI
//! receipt. All fixed power/clock/RFkill/PCI receipts remain required.
use super::*;
#[cfg(feature = "module")]
use crate::ath9k::platform::compat::narf_time;
use crate::ath9k::{ar9003::ani, periodic::Io};
pub(super) struct Unchecked<'a> {
    pub(super) native: &'a Native,
}
impl Io for Unchecked<'_> {
    fn read(&self, r: u64) -> Result<u32, Error> {
        self.native.extent(r)?;
        // SAFETY: private receipt reader used only inside the outer current
        // original P/A/PCI scope; this checks the complete aligned dword.
        Ok(unsafe { self.native.bar.read32(r) })
    }
    fn write(&self, _: u64, _: u32) -> Result<(), Error> {
        Err(Error::Access)
    }
    fn now_us(&self) -> u64 {
        narf_time::monotonic_ns() / 1000
    }
    fn delay_us(&self, _: u64) {}
}
struct Raw<'a> {
    native: &'a Native,
}
impl Raw<'_> {
    fn current<T>(&self, action: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.native.manual.current(true, || {
            self.native.raw_invoke(|| {
                self.native
                    .physical_readback(self.native.active.load(Ordering::Acquire), false)?;
                action()
            })
        })
    }
}
impl Io for Raw<'_> {
    fn read(&self, r: u64) -> Result<u32, Error> {
        self.current(|| {
            Unchecked {
                native: self.native,
            }
            .read(r)
        })
    }
    fn write(&self, r: u64, v: u32) -> Result<(), Error> {
        self.current(|| {
            self.native.extent(r)?;
            // SAFETY: actual original current P/A/PCI invocation and dword.
            unsafe { self.native.bar.write32(r, v) };
            Ok(())
        })
    }
    fn now_us(&self) -> u64 {
        narf_time::monotonic_ns() / 1000
    }
    fn delay_us(&self, _: u64) {}
}
impl Native {
    /// One optional P lookup of the actual original calibrated generation,
    /// before packet effects. Only NotFound preserves the ordinary A scope.
    pub(in crate::ath9k) fn ar9003_bind_ani(&self) -> Result<(), Error> {
        let Calibrated::Ar9300 {
            grant,
            permission,
            report,
            ..
        } = &self.calibrated
        else {
            return Err(Error::State);
        };
        if !matches!(self.device.id.device, 0x0032 | 0x0034 | 0x0036) {
            return Ok(());
        }
        if self.active.load(Ordering::Acquire)
            || self.manual.retained()
            || self.ps_bound.load(Ordering::Acquire)
        {
            return Err(Error::State);
        }
        let raw = Raw { native: self };
        let ini = grant
            .invoke(|| {
                ani::Settings::read(&raw, self.device.id.device)
                    .map_err(|_| identity::BringUpError::BadState)
            })
            .map_err(|_| Error::Access)?;
        // InstalledPower is a packed receipt, so retain the original Plan
        // from the calibrated constructor rather than reconstructing it.
        let base = ani::Base::new(
            grant.clone(),
            *permission,
            report,
            self.ar9003_plan.as_deref().ok_or(Error::State)?,
            ini,
        )?;
        self.ani_request
            .set(alloc::boxed::Box::new(base.request()))
            .map_err(|_| Error::State)?;
        let Some(source) = ani::Grant::optional(base)? else {
            return Ok(());
        };
        self.manual.install_ani(source.clone())?;
        let result = self.manual.current(true, || {
            let owner = ani::Owner::begin(
                &raw,
                self.device.id.device,
                report.rx_chainmask,
                source.ini(),
            )?;
            *self.ani_expected.lock() = Some(owner.settings());
            *self.ani.lock() = Some(alloc::boxed::Box::new(owner));
            Ok(())
        });
        if result.is_err() {
            self.manual.fail();
        }
        result
    }
    pub(in crate::ath9k) fn ar9003_ani_request(&self) -> Option<ani::Request> {
        self.ani_request
            .get()
            .map(|request| request.as_ref().clone())
    }
    pub(super) fn ar9003_ani_service(&self, eligible: bool) -> Result<(), Error> {
        if !self.manual.ani_bound() {
            return Ok(());
        }
        self.access(self.active.load(Ordering::Acquire), || Ok(()))?;
        if !eligible {
            return Ok(());
        }
        let result = self.manual.current(true, || {
            let mut slot = self.ani.lock();
            let owner = slot.as_mut().ok_or(Error::State)?;
            owner.service(&Raw { native: self })?;
            *self.ani_expected.lock() = Some(owner.settings());
            Ok(())
        });
        if result.is_err() {
            self.manual.fail();
        }
        result
    }
    pub(super) fn ar9003_ani_beacon(&self, rssi: i8) {
        if let Some(owner) = self.ani.lock().as_mut() {
            owner.beacon(rssi);
        }
    }
    pub(super) fn ar9003_ani_epoch(&self) {
        if let Some(owner) = self.ani.lock().as_mut() {
            owner.epoch();
        }
    }
}
