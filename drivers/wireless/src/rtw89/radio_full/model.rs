//! One current-epoch device register model through every real radio component.
//! IQK and TSSI/DPK use the same owned BB/RF Vec backings, never stage receipts.
use super::super::*;
use crate::rtw89::{iqk, tssi};
use alloc::vec::Vec;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, Write};
use power::Io;

pub(super) struct Model {
    pub(super) base: tssi::tests::Model,
    iqk: Option<iqk::tests::Model>,
    pub(super) operations: usize,
    pub(super) admissions: usize,
    pub(super) fail: Option<usize>,
    pub(super) deny: Option<usize>,
    pub(super) hold_delay: Option<u64>,
    pub(super) starts: Vec<rfk::Kind>,
    pub(super) ends: Vec<rfk::Kind>,
    pub(super) pauses: usize,
    pub(super) resumes: usize,
    pub(super) paused: bool,
    pub(super) lock_stuck: bool,
    failed: bool,
    synth_written: bool,
    lpf_busy: u8,
}
fn rf_error(error: rfk::Error) -> power::Error {
    match error {
        rfk::Error::Register(error) => error,
        _ => power::Error::Access,
    }
}
fn ready<T>(future: impl Future<Output = Result<T, rfk::Error>>) -> Result<T, power::Error> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result.map_err(rf_error),
        Poll::Pending => Err(power::Error::Access),
    }
}
impl Model {
    pub(super) fn new() -> Self {
        let mut base = tssi::tests::Model::new(0);
        base.words[0x1010 / 4] = 1 << 8 | 1 << 16 | 1 << 19;
        Self {
            base,
            iqk: None,
            operations: 0,
            admissions: 0,
            fail: None,
            deny: None,
            hold_delay: None,
            starts: Vec::new(),
            ends: Vec::new(),
            pauses: 0,
            resumes: 0,
            paused: false,
            lock_stuck: false,
            failed: false,
            synth_written: false,
            lpf_busy: 0,
        }
    }
    pub(super) fn authority(&self) -> Cap<BusDeviceCap, Write> {
        self.base.authority
    }
    pub(super) fn backings(&self) -> (usize, [usize; 2]) {
        assert!(self.iqk.is_none());
        (
            self.base.words.as_ptr() as usize,
            core::array::from_fn(|i| self.base.rf[i].as_ptr() as usize),
        )
    }
    fn operation<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, power::Error>,
    ) -> Result<T, power::Error> {
        let authority = self.authority();
        crate::rtw88::pci_park::invoke(&authority, || {
            let index = self.operations;
            self.operations += 1;
            if self.failed || self.fail == Some(index) {
                self.failed = true;
                return Err(power::Error::Access);
            }
            operation(self)
        })
        .map_err(|_| power::Error::Access)?
    }
    fn admit_current(&mut self) -> Result<(), rfk::Error> {
        let index = self.admissions;
        self.admissions += 1;
        if self.failed || self.deny == Some(index) {
            self.failed = true;
            return Err(rfk::Error::Policy);
        }
        crate::rtw88::pci_park::invoke(&self.authority(), || ()).map_err(|_| rfk::Error::Policy)
    }
}
impl Io for Model {
    fn read8(&mut self, address: u32) -> Result<u8, power::Error> {
        self.operation(|model| model.base.read8(address))
    }
    fn read16(&mut self, address: u32) -> Result<u16, power::Error> {
        self.operation(|model| model.base.read16(address))
    }
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        self.operation(|model| {
            if let Some(iqk) = &mut model.iqk {
                rfk::Interface::admit(iqk).map_err(rf_error)?;
                iqk.read32(address)
            } else {
                model.base.read32(address)
            }
        })
    }
    fn write8(&mut self, address: u32, value: u8) -> Result<(), power::Error> {
        self.operation(|model| model.base.write8(address, value))
    }
    fn write16(&mut self, address: u32, value: u16) -> Result<(), power::Error> {
        self.operation(|model| model.base.write16(address, value))
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.operation(|model| {
            if let Some(iqk) = &mut model.iqk {
                rfk::Interface::admit(iqk).map_err(rf_error)?;
                iqk.write32(address, value)
            } else {
                model.base.write32(address, value)
            }
        })
    }
    fn now_us(&self) -> u64 {
        self.iqk.as_ref().map_or(self.base.now, Io::now_us)
    }
    async fn delay_us(&mut self, us: u64) {
        if self.hold_delay == Some(us) {
            core::future::pending::<()>().await;
        }
        let result = self.operation(|model| {
            if let Some(iqk) = &mut model.iqk {
                rfk::Interface::admit(iqk).map_err(rf_error)?;
                let mut future = pin!(iqk.delay_us(us));
                match future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                {
                    Poll::Ready(()) => Ok(()),
                    Poll::Pending => Err(power::Error::Access),
                }
            } else {
                let mut future = pin!(model.base.delay_us(us));
                match future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                {
                    Poll::Ready(()) => Ok(()),
                    Poll::Pending => Err(power::Error::Access),
                }
            }
        });
        if result.is_err() {
            self.failed = true;
        }
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl channel_bb::Interface for Model {
    fn admit(&mut self) -> Result<(), channel_bb::Error> {
        self.admit_current().map_err(|_| channel_bb::Error::Policy)
    }
}
impl rfk::Interface for Model {
    fn admit(&mut self) -> Result<(), rfk::Error> {
        self.admit_current()
    }
    async fn rf_read(&mut self, path: u8, address: u32, mask: u32) -> Result<u32, rfk::Error> {
        Ok(self.operation(|model| {
            if let Some(iqk) = &mut model.iqk {
                rfk::Interface::admit(iqk).map_err(rf_error)?;
                ready(rfk::Interface::rf_read(iqk, path, address, mask))
            } else {
                if model.base.kind.is_none() && address == 0xc5 && mask == 0x8000 {
                    return Ok(u32::from(model.synth_written && !model.lock_stuck));
                }
                if model.base.kind.is_none() && address == 0xb7 && mask == 0x100 {
                    let busy = model.lpf_busy != 0;
                    model.lpf_busy = model.lpf_busy.saturating_sub(1);
                    return Ok(u32::from(busy));
                }
                ready(rfk::Interface::rf_read(
                    &mut model.base,
                    path,
                    address,
                    mask,
                ))
            }
        })?)
    }
    async fn rf_write(
        &mut self,
        path: u8,
        address: u32,
        mask: u32,
        value: u32,
    ) -> Result<(), rfk::Error> {
        self.operation(|model| {
            if let Some(iqk) = &mut model.iqk {
                rfk::Interface::admit(iqk).map_err(rf_error)?;
                ready(rfk::Interface::rf_write(iqk, path, address, mask, value))
            } else {
                ready(rfk::Interface::rf_write(
                    &mut model.base,
                    path,
                    address,
                    mask,
                    value,
                ))?;
                if model.base.kind.is_none() && path == 0 && address == 0x18 {
                    model.synth_written = true;
                    model.lpf_busy = 1;
                }
                Ok(())
            }
        })?;
        Ok(())
    }
    async fn begin(&mut self, kind: rfk::Kind) -> Result<(), rfk::Error> {
        self.admit_current()?;
        self.operation(|model| {
            if kind == rfk::Kind::Iqk {
                if model.iqk.is_some() || model.base.kind.is_some() {
                    return Err(power::Error::Terminal);
                }
                let words = core::mem::take(&mut model.base.words);
                let rf = core::mem::take(&mut model.base.rf);
                model.iqk = Some(
                    iqk::tests::Model::with_registers(words, rf, model.base.now)
                        .map_err(rf_error)?,
                );
                model.base.kind = Some(kind);
            }
            if let Some(iqk) = &mut model.iqk {
                rfk::Interface::admit(iqk).map_err(rf_error)?;
                ready(rfk::Interface::begin(iqk, kind))?;
            } else {
                ready(rfk::Interface::begin(&mut model.base, kind))?;
            }
            model.starts.push(kind);
            Ok(())
        })?;
        Ok(())
    }
    async fn end(&mut self, kind: rfk::Kind) -> Result<(), rfk::Error> {
        self.admit_current()?;
        self.operation(|model| {
            if let Some(iqk) = &mut model.iqk {
                rfk::Interface::admit(iqk).map_err(rf_error)?;
                ready(rfk::Interface::end(iqk, kind))?;
                if kind == rfk::Kind::Iqk {
                    let (words, rf, now) = model
                        .iqk
                        .take()
                        .ok_or(power::Error::Access)?
                        .into_registers();
                    model.base.words = words;
                    model.base.rf = rf;
                    model.base.now = now;
                    model.base.kind = None;
                }
            } else {
                ready(rfk::Interface::end(&mut model.base, kind))?;
            }
            model.ends.push(kind);
            Ok(())
        })?;
        Ok(())
    }
    async fn pause(&mut self) -> Result<u32, rfk::Error> {
        self.admit_current()?;
        Ok(self.operation(|model| {
            if model.paused {
                return Err(power::Error::Terminal);
            }
            let saved = if let Some(iqk) = &mut model.iqk {
                rfk::Interface::admit(iqk).map_err(rf_error)?;
                ready(rfk::Interface::pause(iqk))?
            } else {
                ready(rfk::Interface::pause(&mut model.base))?
            };
            model.paused = true;
            model.pauses += 1;
            Ok(saved)
        })?)
    }
    async fn resume(&mut self, saved: u32) -> Result<(), rfk::Error> {
        self.admit_current()?;
        self.operation(|model| {
            if !model.paused || saved != 0x11223344 {
                return Err(power::Error::Terminal);
            }
            if let Some(iqk) = &mut model.iqk {
                rfk::Interface::admit(iqk).map_err(rf_error)?;
                ready(rfk::Interface::resume(iqk, saved))?;
            } else {
                ready(rfk::Interface::resume(&mut model.base, saved))?;
            }
            model.paused = false;
            model.resumes += 1;
            Ok(())
        })?;
        Ok(())
    }
}
