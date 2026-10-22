//! DCN401 VUPDATE_NO_LOCK interrupt source ownership. The independent IH
//! service alone enables, acknowledges and masks these OTG register bits.
//! Linux irq_service_dcn401.c vupdate_no_lock_int_entry and generic set/ack.
use crate::{
    amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_ih7 as ih, amdgpu_navi48_sources as src,
    amdgpu_psp_ring::bank, amdgpu_rdna4::PipePool,
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const STATUS: u64 = 0x1b88;
const ENABLE: u32 = 1 << 12;
const ACK: u32 = 1 << 16;
// Other event-clear strobes in the shared register must not be replayed by
// an RMW of our enable/ACK fields (VSTARTUP, VUPDATE, VREADY).
const ALL_ACK: u32 = (1 << 4) | (1 << 10) | ACK | (1 << 22);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Status {
    /// Armed sources by pipe index, not physical OTG instance.
    pub enabled: u8,
    /// Includes a partially enabled source until masking was read back.
    pub owned: u8,
    pub failed: Option<ih::Error>,
    pub acknowledgements: u64,
    pub stale: u64,
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    base: u64,
    pool: PipePool,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, ih::Error> {
        crate::amdgpu_navi48_firmware::Target::resolve(gpu).map_err(|_| ih::Error::Unsupported)?;
        Ok(Self {
            base: bank(gpu, ip::HW_ID_DCN, &[(4, 0, 1), (4, 1, 0)], 2, 0x1d08)
                .map_err(|_| ih::Error::Unsupported)?,
            pool: crate::amdgpu_rdna4::pipe_pool(),
        })
    }
    fn at(self, pipe: u8) -> u64 {
        self.base + (STATUS + u64::from(self.pool.hw(pipe)) * 0x80) * 4
    }
}
trait Io {
    fn read(&mut self, at: u64) -> u32;
    fn write(&mut self, at: u64, value: u32);
}
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: discovery bounds the permanent GPU BAR and physical OTG.
        unsafe { self.0.read32(at) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: SERVICE alone owns these interrupt enable/ACK fields.
        unsafe { self.0.write32(at, value) }
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn checked(value: u32) -> Result<u32, ih::Error> {
    if value == u32::MAX {
        Err(ih::Error::DeviceGone)
    } else {
        Ok(value)
    }
}
struct Engine<I> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    status: Status,
    initialized: bool,
    stopped: bool,
}
impl<I: Io> Engine<I> {
    fn new(io: I, authority: Cap<BusDeviceCap, Write>, layout: Layout) -> Self {
        Self {
            io,
            authority,
            layout,
            status: Status {
                enabled: 0,
                owned: 0,
                failed: None,
                acknowledgements: 0,
                stale: 0,
            },
            initialized: false,
            stopped: false,
        }
    }
    fn access<T>(
        &mut self,
        f: impl FnOnce(&mut I) -> Result<T, ih::Error>,
    ) -> Result<T, ih::Error> {
        let value = self
            .authority
            .invoke(Op(|| f(&mut self.io)))
            .map_err(|_| ih::Error::Revoked)?;
        self.authority
            .invoke(Op(|| ()))
            .map_err(|_| ih::Error::Revoked)?;
        value
    }
    fn fail<T>(&mut self, result: Result<T, ih::Error>) -> Result<T, ih::Error> {
        if let Err(e) = result {
            self.status.failed = Some(e);
        }
        result
    }
    /// Claim cold inherited bits while the retained service exists, before
    /// CPU interrupt delivery. No fused OTG is ever sampled.
    fn initialize(&mut self) -> Result<(), ih::Error> {
        if self.initialized || self.stopped {
            return Err(ih::Error::Busy);
        }
        self.status.owned = self.layout.pool.all();
        for p in self.layout.pool.pipes() {
            self.mask(p)?;
        }
        self.initialized = true;
        Ok(())
    }
    fn valid(&self, pipe: u8) -> Result<(), ih::Error> {
        if pipe >= self.layout.pool.count() {
            Err(ih::Error::Invalid)
        } else {
            Ok(())
        }
    }
    fn enable(&mut self, pipe: u8) -> Result<(), ih::Error> {
        self.valid(pipe)?;
        if !self.initialized || self.stopped || self.status.failed.is_some() {
            return Err(ih::Error::Busy);
        }
        let bit = 1 << pipe;
        let at = self.layout.at(pipe);
        if self.status.enabled & bit != 0 {
            let result = self.access(|io| {
                if checked(io.read(at))? & ENABLE != 0 {
                    Ok(())
                } else {
                    Err(ih::Error::Readback)
                }
            });
            return self.fail(result);
        }
        // Retain intent before either ACK or enable: a partial failure must
        // still be masked before timing clocks can become inaccessible.
        self.status.owned |= bit;
        let result = self.access(|io| {
            let value = checked(io.read(at))?;
            io.write(at, (value & !(ENABLE | ALL_ACK)) | ACK);
            if checked(io.read(at))? & ENABLE != 0 {
                return Err(ih::Error::Readback);
            }
            let value = checked(io.read(at))?;
            io.write(at, (value & !ALL_ACK) | ENABLE);
            if checked(io.read(at))? & ENABLE == 0 {
                return Err(ih::Error::Readback);
            }
            Ok(())
        });
        self.fail(result)?;
        self.status.enabled |= bit;
        Ok(())
    }
    /// A successful readback retires ownership. A failed mask keeps it, so
    /// no caller can turn off clocks based on an attempted write alone.
    fn mask(&mut self, pipe: u8) -> Result<(), ih::Error> {
        self.valid(pipe)?;
        let bit = 1 << pipe;
        if self.status.owned & bit == 0 {
            return Ok(());
        }
        let at = self.layout.at(pipe);
        let result = self.access(|io| {
            let value = checked(io.read(at))?;
            io.write(at, (value & !(ENABLE | ALL_ACK)) | ACK);
            if checked(io.read(at))? & ENABLE != 0 {
                return Err(ih::Error::Readback);
            }
            Ok(())
        });
        self.fail(result)?;
        self.status.enabled &= !bit;
        self.status.owned &= !bit;
        Ok(())
    }
    fn stop(&mut self) -> Result<(), ih::Error> {
        self.stopped = true;
        let mut error = None;
        for p in self.layout.pool.pipes() {
            if let Err(e) = self.mask(p) {
                error.get_or_insert(e);
            }
        }
        error.map_or(Ok(()), Err)
    }
    /// True means dispatch may run. Late retired-source IVs never read a
    /// possibly clock-gated OTG or wake a new LFC generation. Fused events
    /// remain dispatch diagnostics (its pool mapping wakes nobody).
    fn handle(&mut self, event: ih::Event) -> Result<bool, ih::Error> {
        let src::Class::Display(src::Display::Vupdate(inst)) = src::classify(&event) else {
            return Ok(true);
        };
        let Some(pipe) = self.layout.pool.pipe(inst) else {
            return Ok(true);
        };
        if self.status.enabled & (1 << pipe) == 0 {
            self.status.stale = self.status.stale.saturating_add(1);
            return Ok(false);
        }
        if self.status.failed.is_some() || self.stopped {
            return Err(ih::Error::Busy);
        }
        let at = self.layout.at(pipe);
        let result = self.access(|io| {
            let value = checked(io.read(at))?;
            if value & ENABLE == 0 {
                return Err(ih::Error::Readback);
            }
            io.write(at, (value & !ALL_ACK) | ACK);
            if checked(io.read(at))? & ENABLE == 0 {
                return Err(ih::Error::Readback);
            }
            Ok(())
        });
        self.fail(result)?;
        self.status.acknowledgements = self.status.acknowledgements.saturating_add(1);
        Ok(true)
    }
}
pub(crate) struct Monitor(Engine<Mmio>);
impl core::fmt::Debug for Monitor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Vupdate").field(&self.0.status).finish()
    }
}
impl Monitor {
    pub(crate) fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Option<Self> {
        Some(Self(Engine::new(
            Mmio(gpu.regs),
            authority,
            Layout::resolve(gpu).ok()?,
        )))
    }
    pub(super) fn initialize(&mut self) -> Result<(), ih::Error> {
        self.0.initialize()
    }
    pub(super) fn enabled(&self, pipe: u8) -> bool {
        self.0.status.enabled & (1 << pipe) != 0
    }
    pub(super) fn enable(&mut self, pipe: u8) -> Result<(), ih::Error> {
        self.0.enable(pipe)
    }
    pub(super) fn mask(&mut self, pipe: u8) -> Result<(), ih::Error> {
        self.0.mask(pipe)
    }
    pub(super) fn stop(&mut self) -> Result<(), ih::Error> {
        self.0.stop()
    }
    pub(super) fn retired(&self) -> bool {
        self.0.status.owned == 0
    }
    pub(super) fn handle(&mut self, event: ih::Event) -> Result<bool, ih::Error> {
        self.0.handle(event)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_vupdate_tests.rs"]
mod tests;
