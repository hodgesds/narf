// SPDX-License-Identifier: GPL-2.0-or-later
//! The MCI power programmer runs inside actual retained record CapOps.
//! Its raw transport rechecks PCI/current host authority per access, while
//! the normal packet path checks the last completely verified rate table.
use super::*;
use crate::ath9k::ar9003::btcoex::concurrent::Raw;
#[cfg(feature = "module")]
use crate::ath9k::platform::compat::narf_bus;

struct Registers<'a>(&'a Native, bool);
impl Registers<'_> {
    fn current<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        let native = self.0;
        let action = || {
            if (native.command()? & narf_bus::pci::cmd::BUS_MASTER != 0)
                != native.active.load(Ordering::Acquire)
            {
                return Err(Error::Access);
            }
            let domain = crate::ath9k::platform::regdb::snapshot().ok_or(Error::Access)?;
            if !native.calibrated.permitted(&domain) {
                return Err(Error::Access);
            }
            if let Calibrated::Ar9300 {
                rf_kill: Some(kill),
                ..
            } = &native.calibrated
            {
                native.extent(0x404c)?;
                // SAFETY: current PCI invocation, checked full input dword.
                let value = unsafe { native.bar.read32(0x404c) };
                if value == u32::MAX || (value & (1 << kill.gpio) != 0) == kill.polarity {
                    return Err(Error::Access);
                }
            }
            native.extent(0x7044)?;
            // SAFETY: current retained PCI invocation and checked full dword.
            if unsafe { native.bar.read32(0x7044) } & 15 != 2 {
                return Err(Error::State);
            }
            operation()
        };
        if self.1 {
            native.manual.current(false, || native.raw_invoke(action))
        } else {
            native.invoke(action)
        }
    }
}
impl Raw for Registers<'_> {
    fn read(&self, register: u64) -> Result<u32, Error> {
        self.current(|| {
            self.0.extent(register)?;
            // SAFETY: checked complete BAR dword within current PCI invocation.
            Ok(unsafe { self.0.bar.read32(register) })
        })
    }
    fn write(&self, register: u64, value: u32) -> Result<(), Error> {
        self.current(|| {
            self.0.extent(register)?;
            // SAFETY: checked complete BAR dword in the exclusive retained
            // current PCI invocation, enclosed by the real record CapOp.
            unsafe { self.0.bar.write32(register, value) };
            Ok(())
        })
    }
}

impl Native {
    pub(super) fn mci_power_transition(&self, enabled: bool) -> Result<bool, Error> {
        if self.manual.mci_facts().is_some() {
            return Err(Error::State);
        }
        let Some(power) = self.mci_power.as_ref() else {
            return Ok(false);
        };
        let Calibrated::Ar9300 { grant, .. } = &self.calibrated else {
            return Err(Error::State);
        };
        // This includes the current synth, rate table, host policy, source,
        // RFkill, transport and original packet-child fences. No transition
        // bypass is reachable until this ordinary admission succeeded.
        grant
            .invoke(|| {
                Ok((|| {
                    self.access(self.active.load(Ordering::Acquire), || Ok(()))?;
                    power
                        .lock()
                        .transition(&Registers(self, false), grant, enabled)?;
                    Ok(true)
                })())
            })
            .map_err(|_| Error::Access)?
    }

    /// The real same-channel reset/calibration restored the base program.
    /// This is the sole recovery from an uncertain transition and is only
    /// reachable with retained DMA parked and BME proven off by the owner.
    pub(in crate::ath9k) fn ar9300_reset_coex_power(
        &self,
        plan: &crate::ath9k::ar9003::power::Plan,
    ) -> Result<(), Error> {
        if self.manual.retained() {
            return Err(Error::State);
        }
        let Some(power) = self.mci_power.as_ref() else {
            return Ok(());
        };
        if self.active.load(Ordering::Acquire) {
            return Err(Error::State);
        }
        let Calibrated::Ar9300 { grant, .. } = &self.calibrated else {
            return Err(Error::State);
        };
        power.lock().reset(&Registers(self, false), grant, plan)
    }
    /// Restore actual immutable source powers under N65D/N65A before the
    /// serialized MCI owner withdraws priorities. This is no flag reset.
    pub(in crate::ath9k) fn ar9565_manual_restore_power(&self) -> Result<(), Error> {
        if self.device.id.device != 0x0036
            || self.active.load(Ordering::Acquire)
            || self.manual.mci_facts().is_none()
        {
            return Err(Error::State);
        }
        let Calibrated::Ar9300 { grant, .. } = &self.calibrated else {
            return Err(Error::State);
        };
        let power = self.mci_power.as_ref().ok_or(Error::State)?;
        self.manual.current(false, || {
            power
                .lock()
                .transition(&Registers(self, true), grant, false)?;
            self.raw_invoke(|| self.physical_readback(false, false))
        })
    }
}

#[cfg(feature = "kernel-test")]
#[path = "coex/tests.rs"]
mod tests;
