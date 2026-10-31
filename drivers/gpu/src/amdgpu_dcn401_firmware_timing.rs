//! Borrow the serialized firmware transport for a timing operation. The
//! register owner and its parked displays return even when a future is dropped.
use super::*;
use core::ops::{Deref, DerefMut};

pub(super) trait TimingTransport {
    async fn drr(&mut self, otg: u8, timing: drr::DrrTiming) -> Result<(), Error>;
}
impl TimingTransport for crate::amdgpu_dmub_navi48::Dmub {
    async fn drr(&mut self, otg: u8, timing: drr::DrrTiming) -> Result<(), Error> {
        self.fams2_drr_update(otg, Some(timing.totals), timing.mid)
            .await
            .map_err(Error::Firmware)
    }
}

#[derive(Debug)]
pub(super) struct Spare {
    status: Box<Status>,
    displays: Box<Displays>,
}
impl Spare {
    pub(super) fn new() -> Self {
        Self {
            status: Box::new(Status::new()),
            displays: Displays::new(),
        }
    }
}

pub(super) struct FirmwareIo<'a, I: Io, T: TimingTransport> {
    pub(super) io: &'a mut I,
    transport: &'a mut T,
}
impl<I: Io, T: TimingTransport> Io for FirmwareIo<'_, I, T> {
    fn read(&mut self, at: u64) -> u32 {
        self.io.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.io.write(at, value);
    }
    async fn vupdate(&mut self, pipe: u8, enable: bool) -> Result<(), Error> {
        self.io.vupdate(pipe, enable).await
    }
    fn firmware_timing(&self) -> bool {
        true
    }
    async fn drr_update(&mut self, otg: u8, timing: drr::DrrTiming) -> Result<(), Error> {
        self.transport.drr(otg, timing).await
    }
    #[cfg(feature = "kernel-test")]
    fn pause_wait(&self) -> bool {
        self.io.pause_wait()
    }
    #[cfg(feature = "kernel-test")]
    fn wait_poll_limit(&self) -> Option<u32> {
        self.io.wait_poll_limit()
    }
}

pub(super) struct Loan<'a, I: Io, T: TimingTransport> {
    engine: Option<Engine<FirmwareIo<'a, I, T>>>,
    status: &'a mut Box<Status>,
    displays: &'a mut Box<Displays>,
    spare: &'a mut Option<Spare>,
}
impl<'a, I: Io, T: TimingTransport> Loan<'a, I, T> {
    pub(super) fn new(
        engine: &'a mut Engine<I>,
        spare: &'a mut Option<Spare>,
        transport: &'a mut T,
    ) -> Result<Self, Error> {
        let scratch = spare.take().ok_or(Error::Busy)?;
        Ok(Self {
            engine: Some(Engine {
                io: FirmwareIo {
                    io: &mut engine.io,
                    transport,
                },
                authority: engine.authority,
                layout: engine.layout,
                status: core::mem::replace(&mut engine.status, scratch.status),
                displays: core::mem::replace(&mut engine.displays, scratch.displays),
            }),
            status: &mut engine.status,
            displays: &mut engine.displays,
            spare,
        })
    }
}
impl<'a, I: Io, T: TimingTransport> Deref for Loan<'a, I, T> {
    type Target = Engine<FirmwareIo<'a, I, T>>;
    fn deref(&self) -> &Self::Target {
        self.engine.as_ref().unwrap()
    }
}
impl<I: Io, T: TimingTransport> DerefMut for Loan<'_, I, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.engine.as_mut().unwrap()
    }
}
impl<I: Io, T: TimingTransport> Drop for Loan<'_, I, T> {
    fn drop(&mut self) {
        let mut engine = self.engine.take().unwrap();
        core::mem::swap(self.status, &mut engine.status);
        core::mem::swap(self.displays, &mut engine.displays);
        *self.spare = Some(Spare {
            status: engine.status,
            displays: engine.displays,
        });
    }
}

impl<'a> Loan<'a, Mmio, crate::amdgpu_dmub_navi48::Dmub> {
    pub(super) fn native(
        engine: &'a mut Engine<Mmio>,
        spare: &'a mut Option<Spare>,
        dmub: &'a mut crate::amdgpu_dmub_navi48::Dmub,
    ) -> Result<Self, Error> {
        if !dmub.matches_display(engine.io.0, engine.layout.base) {
            return Err(Error::Invalid);
        }
        Self::new(engine, spare, dmub)
    }
}
