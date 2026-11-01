// SPDX-License-Identifier: GPL-2.0-or-later
//! Device-side RTC/clock behavior over actual register state. Uses the same
//! source power transition implementation as Native; never returns a fake
//! sleep/wake receipt to the driver.
use super::*;
use crate::ath9k::ps::hardware::Raw;
pub(super) struct RawModel<'a> {
    pub model: &'a Model,
    pub source: &'a crate::ath9k::ps::Grant,
}
impl Raw for RawModel<'_> {
    fn read(&self, register: u64) -> Result<u32, Error> {
        self.source.invoke(|| {
            self.model.access()?;
            Ok(*self.model.registers.borrow().get(&register).unwrap_or(&0))
        })
    }
    fn write(&self, register: u64, value: u32) -> Result<(), Error> {
        self.source.invoke(|| {
            self.model.access()?;
            self.model.ps_trace.borrow_mut().push((register, value));
            if self.model.ignore.get() == Some(register) {
                return Ok(());
            }
            self.model.registers.borrow_mut().insert(register, value);
            if register == 0x704c {
                if value & 1 != 0 {
                    self.model.registers.borrow_mut().insert(0x7044, 2);
                } else if value == 2 {
                    self.model.registers.borrow_mut().insert(0x7044, 4);
                }
            }
            Ok(())
        })
    }
    fn delay(&self, us: u64) {
        self.model.now.set(self.model.now.get() + us);
    }
    fn wait(&self, register: u64, mask: u32, expected: u32, budget_us: u64) -> Result<(), Error> {
        if self.read(register)? & mask == expected {
            Ok(())
        } else {
            self.delay(budget_us);
            Err(Error::Timeout)
        }
    }
}
impl Model {
    pub(super) fn power_awake(&self) -> Result<(), Error> {
        if !self.ps_bound.get() {
            return Ok(());
        }
        if self.ps_failed.get() {
            return Err(Error::Access);
        }
        let source = self.ps.borrow().clone().ok_or(Error::Access)?;
        source.check()?;
        let raw = RawModel {
            model: self,
            source: &source,
        };
        if self.ps_sleeping.get() {
            if let Err(error) = crate::ath9k::ps::hardware::awake(&raw) {
                self.ps_failed.set(true);
                return Err(error);
            }
            self.ps_sleeping.set(false);
        } else if raw.read(0x7044)? & 15 != 2 {
            self.ps_failed.set(true);
            return Err(Error::State);
        }
        Ok(())
    }
}
impl Model {
    /// Actual device-side timer cause: RTC WakeOnInterrupt, secondary cause
    /// and RAC report, followed by the installed signal if one exists.
    pub(in crate::ath9k) fn fire_tim(&self) {
        let mut registers = self.registers.borrow_mut();
        let cause = registers.get(&0x80).copied().unwrap_or(0) | 0x10000000;
        registers.insert(0x80, cause);
        registers.insert(0xc0, cause);
        registers.insert(0xd8, 0x10);
        registers.insert(0x4038, 2);
        if registers.get(&0x704c).is_some_and(|value| value & 2 != 0) {
            registers.insert(0x7044, 2);
        }
        drop(registers);
        if let Some(signal) = self.signal.borrow().clone() {
            signal.raise();
        }
    }
}
