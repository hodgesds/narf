// SPDX-License-Identifier: GPL-2.0-or-later
//! Device register behavior for real native calibration fixtures. Emulates
//! actual busy/completion bits and measurement registers, never a driver-side
//! coefficient/NF/native ticket receipt. All algorithms run production code.
use super::*;
use crate::ath9k::periodic::{self, Context as PeriodicContext, Io};
#[derive(Default)]
pub(in crate::ath9k) struct State {
    pub source: Option<Arc<periodic::Grant>>,
    pub bound: Option<Arc<periodic::Grant>>,
    pub live: Option<periodic::Live>,
    pub failed: bool,
    pub hold_cal: bool,
    pub hold_nf: bool,
    pub hold_nf_load: bool,
    pub delay_jump: u64,
    pub cal_ready: Option<u64>,
    pub nf_ready: Option<(u64, bool)>,
    pub trace: Vec<(u64, u32)>,
}
pub(super) struct Raw<'a>(pub &'a Model);
impl Model {
    fn periodic_limit(&self) -> i16 {
        let mut limit = i16::MAX;
        if let Some(source) = self.ba.borrow().as_ref() {
            limit = limit.min(source.signed_ceiling());
        }
        if let Some(source) = self.tx_ba.borrow().as_ref() {
            limit = limit.min(source.signed_ceiling());
        }
        if let Some(source) = self.qos.borrow().as_ref() {
            limit = limit.min(source.signed_ceiling());
        }
        limit
    }
    pub(super) fn periodic_model_invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        let source = {
            let state = self.periodic.borrow();
            if state.failed {
                return Err(Error::Access);
            }
            let source = state.bound.clone().ok_or(Error::State)?;
            if state
                .source
                .as_ref()
                .is_none_or(|cached| !Arc::ptr_eq(cached, &source))
            {
                return Err(Error::Access);
            }
            source
        };
        let base = { self.ht.borrow().clone().ok_or(Error::State)? };
        if !source.for_base(&base) || self.ps_bound.get() || !self.allowed.get() {
            return Err(Error::Access);
        }
        let ba = { self.ba.borrow().clone() };
        let tx = { self.tx_ba.borrow().clone() };
        let qos = { self.qos.borrow().clone() };
        let physical = base.clone();
        let operation = || {
            source.invoke_under(self.periodic_limit(), || {
                self.access()?;
                physical.periodic_physical(|register| {
                    Ok(self.registers.borrow().get(&register).copied().unwrap_or(0))
                })?;
                if self.registers.borrow().get(&0x7044).copied() != Some(2) {
                    return Err(Error::State);
                }
                operation()
            })
        };
        let operation = || {
            if let Some(source) = ba {
                source.invoke(operation)
            } else {
                base.invoke(operation)
            }
        };
        let operation = || {
            if let Some(source) = tx {
                source.invoke(operation)
            } else {
                operation()
            }
        };
        if let Some(source) = qos {
            source.invoke(operation)
        } else {
            operation()
        }
    }
    pub(super) fn bind_periodic_model(&self, source: &Arc<periodic::Grant>) -> Result<(), Error> {
        let base = { self.ht.borrow().clone().ok_or(Error::State)? };
        source.check()?;
        if !source.for_base(&base) || self.ps_bound.get() {
            return Err(Error::State);
        }
        let mut state = self.periodic.borrow_mut();
        if state.failed
            || state.bound.is_some()
            || state
                .source
                .as_ref()
                .is_none_or(|cached| !Arc::ptr_eq(cached, source))
        {
            return Err(Error::State);
        }
        state.bound = Some(source.clone());
        Ok(())
    }
    pub(super) fn periodic_model_current(&self) -> Result<bool, Error> {
        let (bound, live) = {
            let state = self.periodic.borrow();
            (state.bound.is_some(), state.live)
        };
        if !bound {
            return Ok(false);
        }
        self.periodic_model_invoke(|| {
            live.ok_or(Error::State)?.readback(&Raw(self))?;
            Ok(true)
        })
    }
    pub(super) fn with_periodic<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        let (bound, live) = {
            let state = self.periodic.borrow();
            (state.bound.is_some(), state.live)
        };
        if !bound {
            return operation();
        }
        self.periodic_model_invoke(|| {
            live.ok_or(Error::State)?.readback(&Raw(self))?;
            operation()
        })
    }
    pub(super) fn install_periodic_model(&self, live: periodic::Live) -> Result<(), Error> {
        let previous = { self.periodic.borrow().live };
        self.periodic_model_invoke(|| live.install_after(previous, &Raw(self)))?;
        let mut state = self.periodic.borrow_mut();
        if state.failed || state.live != previous {
            return Err(Error::State);
        }
        state.live = Some(live);
        Ok(())
    }
    pub(super) fn periodic_model_read(&self, register: u64) -> Result<u32, Error> {
        self.periodic_model_invoke(|| {
            let (cal, nf, hold_cal, hold_nf, hold_load) = {
                let state = self.periodic.borrow();
                (
                    state.cal_ready,
                    state.nf_ready,
                    state.hold_cal,
                    state.hold_nf,
                    state.hold_nf_load,
                )
            };
            if register == 0x9920 && !hold_cal && cal.is_some_and(|time| self.now.get() >= time) {
                let current = self.registers.borrow().get(&0x9920).copied().unwrap_or(0);
                self.registers
                    .borrow_mut()
                    .insert(0x9920, current & !0x10000);
                self.periodic.borrow_mut().cal_ready = None;
            }
            if register == 0x9860 && !hold_nf {
                if let Some((_, loading)) = nf
                    .filter(|(time, loading)| self.now.get() >= *time && (!*loading || !hold_load))
                {
                    let current = self.registers.borrow().get(&0x9860).copied().unwrap_or(0);
                    self.registers.borrow_mut().insert(0x9860, current & !2);
                    if !loading {
                        for (reg, shift, raw) in [(0x9864, 20, -115i32), (0x99bc, 16, -117)] {
                            let current = self.registers.borrow().get(&reg).copied().unwrap_or(0);
                            self.registers.borrow_mut().insert(
                                reg,
                                (current & !(511 << shift)) | ((raw as u32 & 511) << shift),
                            );
                        }
                    }
                    self.periodic.borrow_mut().nf_ready = None;
                }
            }
            let value = self.registers.borrow().get(&register).copied().unwrap_or(0);
            if (0x8088..=0x8098).contains(&register) {
                self.registers.borrow_mut().insert(register, 0);
            }
            Ok(value)
        })
    }
    pub(super) fn periodic_model_write(&self, register: u64, value: u32) -> Result<(), Error> {
        self.periodic_model_invoke(|| {
            self.periodic.borrow_mut().trace.push((register, value));
            if self.ignore.get() == Some(register) {
                return Ok(());
            }
            let previous = self
                .registers
                .borrow_mut()
                .insert(register, value)
                .unwrap_or(0);
            if register == 0x9920 {
                if value & 0x10000 != 0 && previous & 0x10000 == 0 {
                    self.periodic.borrow_mut().cal_ready = Some(self.now.get() + 100);
                } else if value & 0x10000 == 0 {
                    self.periodic.borrow_mut().cal_ready = None;
                }
            }
            if register == 0x9860 && value & 2 != 0 && previous & 2 == 0 {
                self.periodic.borrow_mut().nf_ready =
                    Some((self.now.get() + 100, value & 0x28000 == 0));
            }
            Ok(())
        })
    }
}
impl Io for Raw<'_> {
    fn read(&self, register: u64) -> Result<u32, Error> {
        self.0.periodic_model_read(register)
    }
    fn write(&self, register: u64, value: u32) -> Result<(), Error> {
        self.0.periodic_model_write(register, value)
    }
    fn now_us(&self) -> u64 {
        self.0.now.get()
    }
    fn delay_us(&self, us: u64) {
        self.0.now.set(self.0.now.get() + us);
    }
}
impl PeriodicContext for Raw<'_> {
    fn publish(&self, live: periodic::Live) -> Result<(), Error> {
        self.0.install_periodic_model(live)
    }
    fn failed(&self) {
        self.0.periodic.borrow_mut().failed = true;
    }
}
