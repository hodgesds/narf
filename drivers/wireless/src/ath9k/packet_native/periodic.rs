// SPDX-License-Identifier: GPL-2.0-or-later
//! Same-native current P binding and raw bounded calibration operations.
//! No slot lock survives a capability invocation or actual MMIO callback.
use super::*;
use crate::ath9k::periodic::{self, Grant, Live};
use alloc::sync::Arc;
#[derive(Default)]
pub(super) struct Slot {
    source: Option<Arc<Grant>>,
    bound: bool,
    live: Option<Live>,
    failed: bool,
}
impl Native {
    pub(super) fn has_periodic(&self) -> bool {
        self.periodic.lock().bound
    }
    pub(super) fn periodic_source(&self) -> Option<Arc<Grant>> {
        let retained = { self.periodic.lock().source.clone() };
        if retained.is_some() {
            return retained;
        }
        let source = periodic::Source::Registered.load(self.ht_grant()?).ok()?;
        let mut slot = self.periodic.lock();
        Some(slot.source.get_or_insert(source).clone())
    }
    pub(super) fn periodic_begin(&self, source: &Arc<Grant>) -> Result<(), Error> {
        if self.ps_bound.load(Ordering::Acquire)
            || self
                .periodic_source()
                .is_none_or(|current| !Arc::ptr_eq(&current, source))
            || !source.for_base(&self.ht_grant().ok_or(Error::Access)?)
        {
            return Err(Error::State);
        }
        source.check()?;
        self.access(self.active.load(Ordering::Acquire), || Ok(()))?;
        let mut slot = self.periodic.lock();
        if slot.bound || slot.failed {
            return Err(Error::State);
        }
        // No ordinary access is possible until initialization supplies the
        // actual initial live receipt. The raw worker retains the current P.
        slot.bound = true;
        Ok(())
    }
    pub(super) fn periodic_snapshot(&self) -> Result<Option<(Arc<Grant>, Live)>, Error> {
        let slot = self.periodic.lock();
        if !slot.bound {
            return Ok(None);
        }
        if slot.failed {
            return Err(Error::Access);
        }
        Ok(Some((
            slot.source.clone().ok_or(Error::Access)?,
            slot.live.ok_or(Error::State)?,
        )))
    }
    fn periodic_raw_source(&self) -> Result<Arc<Grant>, Error> {
        let slot = self.periodic.lock();
        if !slot.bound || slot.failed {
            return Err(Error::Access);
        }
        slot.source.clone().ok_or(Error::Access)
    }
    pub(super) fn periodic_limit(&self) -> i16 {
        let ba = { self.ba.lock().clone() };
        let tx = { self.tx_ba.lock().clone() };
        let qos = { self.qos.lock().clone() };
        let mut ceiling = i16::MAX;
        if let Some(source) = ba {
            ceiling = ceiling.min(source.signed_ceiling());
        }
        if let Some(source) = tx {
            ceiling = ceiling.min(source.signed_ceiling());
        }
        if let Some(source) = qos {
            ceiling = ceiling.min(source.signed_ceiling());
        }
        ceiling
    }
    fn periodic_invoke<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        let source = self.periodic_raw_source()?;
        let ceiling = self.periodic_limit();
        self.invoke(|| {
            self.invoke_packet_sources(|| {
                source.invoke_under(ceiling, || {
                    self.physical_readback(self.active.load(Ordering::Acquire), true)?;
                    operation()
                })
            })
        })
    }
    pub(super) fn periodic_report(
        &self,
    ) -> Result<
        (
            crate::ath9k::calibration::Report,
            Option<crate::ath9k::calibration::wide::WideReport>,
        ),
        Error,
    > {
        self.periodic_invoke(|| {
            Ok((
                self.report,
                match &self.powers {
                    Some(InstalledPower::Forty(actual)) => Some(*actual),
                    _ => None,
                },
            ))
        })
    }
    pub(super) fn periodic_read_raw(&self, register: u64) -> Result<u32, Error> {
        self.periodic_invoke(|| {
            self.extent(register)?;
            // SAFETY: full aligned BAR extent in actual current P+PCI source.
            let value = unsafe { self.bar.read32(register) };
            if value == u32::MAX {
                self.extent(0x4020)?;
                // SAFETY: same current PCI invocation, checked silicon ID.
                if unsafe { self.bar.read32(0x4020) } == u32::MAX {
                    return Err(Error::Access);
                }
            }
            Ok(value)
        })
    }
    pub(super) fn periodic_write_raw(&self, register: u64, value: u32) -> Result<(), Error> {
        self.periodic_invoke(|| {
            self.extent(register)?;
            // SAFETY: only the retained serialized periodic continuation uses
            // this path; ordinary native access is blocked during mutation.
            unsafe {
                self.bar.write32(register, value);
            }
            Ok(())
        })
    }
    pub(super) fn install_periodic(&self, live: Live) -> Result<(), Error> {
        let previous = { self.periodic.lock().live };
        let raw = Raw { native: self };
        self.periodic_invoke(|| live.install_after(previous, &raw))?;
        let mut slot = self.periodic.lock();
        if slot.failed || slot.live != previous {
            return Err(Error::State);
        }
        slot.live = Some(live);
        Ok(())
    }
    pub(super) fn fail_periodic(&self) {
        self.periodic.lock().failed = true;
    }
}
pub(super) struct Raw<'a> {
    pub native: &'a Native,
}
impl periodic::Io for Raw<'_> {
    fn read(&self, register: u64) -> Result<u32, Error> {
        self.native.periodic_read_raw(register)
    }
    fn write(&self, register: u64, value: u32) -> Result<(), Error> {
        self.native.periodic_write_raw(register, value)
    }
    fn now_us(&self) -> u64 {
        self.native.now_us()
    }
    fn delay_us(&self, us: u64) {
        self.native.delay_us(us);
    }
}
