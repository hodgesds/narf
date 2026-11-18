// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! One-shot original-owner inactive BE packet preflight. No packet activation
//! receipt is made here: source BE MLME completion is a separate prerequisite.
use super::{
    be_packet_qualification::{Ordinary, Response},
    be_qualification::Facts,
    checked_fwdl_8922a::{self as checked, packet},
    cold_8922a::{self as cold, Regs as _},
    native_radio_be, power,
    prepared_8922a::checked::CheckedPrepared,
};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
#[path = "native_packet_be_mlme.rs"]
mod mlme;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Busy,
    MissingMeasurement,
    Inactive,
    MlmeConfiguredClosed,
}
#[derive(Default)]
pub(super) struct Program {
    state: State,
    qualification: Option<Ordinary>,
    response: Option<Response>,
    controller: super::be_mlme::Controller,
    source: Option<([u8; 6], super::rfk::be_features::Features)>,
}
pub(super) struct Sources<'a> {
    pub(super) device: narf_bus::DeviceId,
    pub(super) factory: &'a super::efuse_be::checked::Snapshot,
    pub(super) chip: super::mac_pre_init_8922a::HalChipVer,
    pub(super) assets: &'a super::radio_assets::Assets,
    pub(super) features: super::rfk::be_features::Features,
}
impl Program {
    pub(super) fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// These actual source facts/Radio/CheckedPrepared/BAR/current PCI belong
    /// to the SAME original supervisor. It retains this Program before calling
    /// and cannot replace/retry it after missing input, failure or cancellation.
    #[allow(clippy::too_many_arguments)]
    pub(super) unsafe fn prepare(
        &mut self,
        prepared: &mut CheckedPrepared,
        radio: &native_radio_be::Radio,
        region: &MmioRegion,
        cap: &Cap<BusDeviceCap, Write>,
        cancel: &AtomicBool,
        sources: Sources<'_>,
    ) -> Result<bool, power::Error> {
        if self.state != State::New {
            return Err(power::Error::Terminal);
        }
        self.state = State::Busy;
        // SAFETY: same actual original closed radio/PCI owner; snapshot
        // source-preserved response words BEFORE the first N22O lookup.
        self.response = Some(unsafe { Response::observe(radio, region, cap, cancel) }?);
        let own = sources.factory.factory.mac;
        self.source = Some((own, sources.features));
        let facts = Facts {
            device: sources.device,
            factory: sources.factory,
            chip: sources.chip,
            assets: sources.assets,
            features: sources.features,
            phycap: prepared.phycap().ok_or(power::Error::Terminal)?,
        };
        self.qualification = Ordinary::load(
            &facts,
            self.response.as_ref().ok_or(power::Error::Terminal)?,
        )
        .map_err(|_| power::Error::Access)?;
        let Some(grant) = self.qualification.as_ref() else {
            self.state = State::MissingMeasurement;
            return Ok(false);
        };
        // The exact N22W source owner is still current, and the fresh N22O
        // record is independently required. Neither metadata alone grants RF.
        let result = radio.with_packet_preflight(|| {
            // SAFETY: actual same-function original source composition above;
            // this adapter supports inactive reads only and refuses start.
            let mut io = unsafe {
                Preflight::new(
                    region,
                    cap,
                    cancel,
                    grant,
                    self.response.ok_or(power::Error::Terminal)?,
                )
            };
            prepared
                .packet_preflight(&mut io, own)
                .map_err(|_| power::Error::Access)
        });
        result?;
        self.state = State::Inactive;
        Ok(true)
    }
    /// # Safety
    /// Same actual original supervisor/checked source objects as prepare.
    /// This configures the retained source no-link controller only; packet
    /// gates, ordinary HCI and public Station service remain closed.
    pub(super) async unsafe fn initialize(
        &mut self,
        prepared: &mut CheckedPrepared,
        radio: &native_radio_be::Radio,
        region: &MmioRegion,
        cap: &Cap<BusDeviceCap, Write>,
        cancel: &AtomicBool,
    ) -> Result<(), power::Error> {
        if self.state != State::Inactive {
            return Err(power::Error::Terminal);
        }
        radio.with_packet_preflight(|| Ok::<_, power::Error>(()))?;
        self.state = State::Busy;
        let (own, features) = self.source.ok_or(power::Error::Terminal)?;
        let grant = self.qualification.as_ref().ok_or(power::Error::Terminal)?;
        let response = self.response.ok_or(power::Error::Terminal)?;
        // SAFETY: exact same retained original closed source and distinct
        // current N22O grant; Native exposes only the source MLME surface.
        let mut io =
            unsafe { mlme::Native::new(prepared, region, cap, cancel, grant, response, radio) };
        // SAFETY: the adapter borrows this same original inactive owner and
        // rechecks Radio/N22W, N22O and PCI at each register/CH12 effect. Busy
        // was retained before awaiting, so error/drop cannot retry or replace
        // the controller, rings or sole new no-link port.
        let result = unsafe { self.controller.initialize(&mut io, own, features) }.await;
        if result.is_err() {
            io.poison();
            return result;
        }
        self.state = State::MlmeConfiguredClosed;
        Ok(())
    }
}
struct Preflight<'a> {
    inner: checked::Native<'a>,
    grant: &'a Ordinary,
    cancel: &'a AtomicBool,
    fault: bool,
    region: &'a MmioRegion,
    cap: &'a Cap<BusDeviceCap, Write>,
    response: Response,
}
#[cfg(any(test, feature = "kernel-test"))]
pub(super) unsafe fn fixture_preflight<'a>(
    region: &'a MmioRegion,
    cap: &'a Cap<BusDeviceCap, Write>,
    cancel: &'a AtomicBool,
    grant: &'a Ordinary,
) -> impl packet::Port + 'a {
    // SAFETY: caller supplies the original retained inert native owner/BAR.
    unsafe { Preflight::new(region, cap, cancel, grant, Response::fixture()) }
}
impl<'a> Preflight<'a> {
    unsafe fn new(
        region: &'a MmioRegion,
        cap: &'a Cap<BusDeviceCap, Write>,
        cancel: &'a AtomicBool,
        grant: &'a Ordinary,
        response: Response,
    ) -> Self {
        Self {
            // SAFETY: caller retains the original checked owner, complete
            // live BAR and matching PCI cap without a competing producer.
            // scope additionally invokes N22O/PCI around every native access;
            // this adapter cannot write registers or open packet gates.
            inner: unsafe { checked::Native::new(region, cap) }.cancel_with(cancel),
            grant,
            cancel,
            fault: false,
            region,
            cap,
            response,
        }
    }
    fn scope<T, E: From<power::Error>>(
        &mut self,
        op: impl FnOnce(&mut checked::Native<'a>) -> Result<T, E>,
    ) -> Result<T, E> {
        if self.fault || self.cancel.load(Ordering::Acquire) {
            return Err(power::Error::Access.into());
        }
        let grant = self.grant;
        let result = grant.with_current(|| {
            crate::rtw88::pci_park::invoke(self.cap, || {
                super::be_packet_qualification::closed(self.region)?;
                self.response.check(self.region)?;
                let value = op(&mut self.inner)?;
                self.inner.current()?;
                super::be_packet_qualification::closed(self.region)?;
                self.response.check(self.region)?;
                grant.with_current(|| Ok(value))
            })
            .map_err(|_| E::from(power::Error::Access))?
        });
        if result.is_err() {
            self.fault = true;
        }
        result
    }
}
impl cold::Regs for Preflight<'_> {
    fn binding(&self) -> cold::Binding {
        self.inner.binding()
    }
    fn current(&mut self) -> Result<(), power::Error> {
        self.scope(|io| io.current())
    }
    fn dma_memory<T>(
        &mut self,
        op: impl FnOnce() -> Result<T, checked::Error>,
    ) -> Result<T, checked::Error> {
        self.scope(|io| io.dma_memory(op))
    }
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.scope(|io| io.read8(a))
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.scope(|io| io.read16(a))
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.scope(|io| io.read32(a))
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        self.fault = true;
        Err(power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        self.fault = true;
        Err(power::Error::Access)
    }
    fn write32(&mut self, _: u32, _: u32) -> Result<(), power::Error> {
        self.fault = true;
        Err(power::Error::Access)
    }
    fn poll32(&mut self, a: u32, mask: u32, value: u32, us: u64) -> Result<(), power::Error> {
        let mut error = None;
        let done = narf_scheduler::responsive_spin_until(
            || match self.read32(a) {
                Ok(word) => word & mask == value,
                Err(e) => {
                    error = Some(e);
                    true
                }
            },
            narf_time::Deadline::after_us(us),
        );
        if let Some(e) = error {
            Err(e)
        } else if done {
            Ok(())
        } else {
            self.fault = true;
            Err(power::Error::Timeout)
        }
    }
    fn delay_us(&mut self, us: u64) -> Result<(), power::Error> {
        self.scope(|io| io.delay_us(us))
    }
}
// SAFETY: exact actual original Native implements every retained DMA/read
// operation, enclosed by the distinct current packet grant before/after.
// This inactive adapter refuses all writes/start/peer operations; it cannot
// manufacture missing BE MLME or ordinary packet publication receipts.
unsafe impl packet::Port for Preflight<'_> {
    fn packet_current(&mut self, phase: packet::Phase) -> Result<(), power::Error> {
        if phase != packet::Phase::Inactive {
            return Err(power::Error::Unsupported);
        }
        self.current()?;
        for (at, mask, value) in [
            (0x24, 0x1f00001f, 0x1f000000),
            (0x84, 0x03030300, 0x02010000),
            (0x10000, 0x30000000, 0),
            (0xb010, 0x80007fff, 0x80006fff),
            (0xb000, 0xb0, 0x30),
        ] {
            let seen = self.read32(at)?;
            if seen == u32::MAX || seen & mask != value {
                self.fault = true;
                return Err(power::Error::Access);
            }
        }
        self.current()
    }
    fn peer_current(&mut self, _: &[u8], _: u8) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn start_packets(&mut self) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn stop_packets(&mut self) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
}
