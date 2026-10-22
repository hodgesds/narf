//! Owned SMU14 THM/MP1 interrupt registers. Linux smu_v14_0_set_irq_state
//! and smu_v14_0_irq_process, using thm_14_0_2 and mp_14_0_2 headers.
use super::Limits;
use crate::{
    amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_ih7 as ih, amdgpu_navi48_sources as src,
    amdgpu_psp_ring::bank,
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const THERM_ENA: u32 = 0xa;
const THERM_CTRL: u32 = 0xb;
const MP_INT: u32 = 0x141;
const MP_CTRL: u32 = 0x142;
const INTH_MASK: u32 = 1 << 24;
const INTL_MASK: u32 = 1 << 25;
const TRIGGER_MASK: u32 = 1 << 26;
const IH_ENABLE: u32 = 1 << 28;
const CREDIT: u32 = 7 << 29;
const CLEAR: u32 = 0x38;
const MP_MASK: u32 = 1;
const MP_ACK: u32 = 1 << 8;
const MP_VALID: u32 = 1 << 8;
const SMU_TO_DRIVER: u8 = 0xfe;
const FAN_ABNORMAL: u32 = 8;
const FAN_RECOVERY: u32 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Revoked,
    DeviceGone,
    Readback,
    Busy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Armed,
    Stopped,
    Failed(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub high_c: u8,
    pub high: u64,
    pub low: u64,
    pub smu: u64,
    pub fan_abnormal: bool,
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    thm: u64,
    mp: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        crate::amdgpu_navi48_firmware::Target::resolve(gpu).map_err(|_| Error::Unsupported)?;
        let versions = crate::amdgpu_rdna4::MP_VERSIONS;
        Ok(Self {
            thm: bank(gpu, ip::HW_ID_THM, versions, 0, THERM_CTRL)
                .map_err(|_| Error::Unsupported)?,
            mp: bank(gpu, ip::HW_ID_MP1, versions, 1, MP_CTRL).map_err(|_| Error::Unsupported)?,
        })
    }
}
trait Io {
    fn read(&mut self, at: u64) -> u32;
    fn write(&mut self, at: u64, value: u32);
}
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: Layout bounded these discovery-based registers to this permanent BAR.
        unsafe { core::ptr::read_volatile((self.0.virt + at) as *const u32) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: the service exclusively owns these thermal interrupt controls.
        unsafe { core::ptr::write_volatile((self.0.virt + at) as *mut u32, value) }
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn checked(v: u32) -> Result<u32, Error> {
    if v == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(v)
    }
}
struct Engine<I> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    limits: Limits,
    status: Status,
}
impl<I: Io> Engine<I> {
    fn new(io: I, authority: Cap<BusDeviceCap, Write>, layout: Layout, limits: Limits) -> Self {
        Self {
            io,
            authority,
            layout,
            limits,
            status: Status {
                state: State::Prepared,
                high_c: limits.software_shutdown_c.min(255) as u8,
                high: 0,
                low: 0,
                smu: 0,
                fan_abnormal: false,
            },
        }
    }
    fn access<T>(
        &mut self,
        f: impl FnOnce(&mut I, Layout) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let result = self
            .authority
            .invoke(Op(|| f(&mut self.io, self.layout)))
            .map_err(|_| Error::Revoked)?;
        self.authority
            .invoke(Op(|| ()))
            .map_err(|_| Error::Revoked)?;
        result
    }
    fn arm(&mut self) -> Result<(), Error> {
        if self.status.state != State::Prepared {
            return Err(Error::Busy);
        }
        let high = u32::from(self.status.high_c);
        let result = self.access(|io, l| {
            let old = checked(io.read(l.thm + u64::from(THERM_CTRL) * 4))?;
            let control = (old & !(0xffff | INTH_MASK | INTL_MASK | TRIGGER_MASK | CREDIT))
                | high
                | IH_ENABLE
                | 5 << 29;
            io.write(l.thm + u64::from(THERM_CTRL) * 4, control);
            if checked(io.read(l.thm + u64::from(THERM_CTRL) * 4))? != control {
                return Err(Error::Readback);
            }
            io.write(l.thm + u64::from(THERM_ENA) * 4, CLEAR);
            let sw = checked(io.read(l.mp + u64::from(MP_INT) * 4))?;
            io.write(
                l.mp + u64::from(MP_INT) * 4,
                (sw & !(0xff | MP_VALID)) | u32::from(SMU_TO_DRIVER),
            );
            let control = checked(io.read(l.mp + u64::from(MP_CTRL) * 4))? & !MP_MASK;
            io.write(l.mp + u64::from(MP_CTRL) * 4, control);
            if checked(io.read(l.mp + u64::from(MP_CTRL) * 4))? & MP_MASK != 0 {
                return Err(Error::Readback);
            }
            Ok(())
        });
        self.status.state = result.map_or_else(State::Failed, |()| State::Armed);
        result
    }
    fn stop(&mut self) -> Result<(), Error> {
        if matches!(self.status.state, State::Prepared | State::Stopped) {
            self.status.state = State::Stopped;
            return Ok(());
        }
        let result = self.access(|io, l| {
            let control =
                checked(io.read(l.thm + u64::from(THERM_CTRL) * 4))? | INTH_MASK | INTL_MASK;
            io.write(l.thm + u64::from(THERM_CTRL) * 4, control);
            io.write(l.thm + u64::from(THERM_ENA) * 4, 0);
            let control = checked(io.read(l.mp + u64::from(MP_CTRL) * 4))? | MP_MASK;
            io.write(l.mp + u64::from(MP_CTRL) * 4, control);
            Ok(())
        });
        self.status.state = result.map_or_else(State::Failed, |()| State::Stopped);
        result
    }
    /// Capture exact known sources. Only MP1 source0xfe is acknowledged;
    /// THM has no per-vector ACK in smu_v14_0_irq_process.
    fn handle(&mut self, event: ih::Event) -> Result<bool, Error> {
        if self.status.state != State::Armed {
            return Ok(false);
        }
        let v = event.vector;
        if v.client == src::CLIENT_THM {
            match v.source {
                0 => {
                    self.status.high = self.status.high.saturating_add(1);
                    return Ok(true);
                }
                1 => self.status.low = self.status.low.saturating_add(1),
                _ => {}
            }
            return Ok(false);
        }
        if v.client != src::CLIENT_MP1 || v.source != SMU_TO_DRIVER {
            return Ok(false);
        }
        self.status.smu = self.status.smu.saturating_add(1);
        let context = v.data[0];
        let high = match context {
            FAN_ABNORMAL => Some(
                (i32::from(self.limits.software_shutdown_c)
                    + i32::from(self.limits.software_shutdown_offset_c))
                .clamp(0, 255) as u8,
            ),
            FAN_RECOVERY => Some(self.limits.software_shutdown_c.min(255) as u8),
            _ => None,
        };
        let result = self.access(|io, l| {
            let ctrl = checked(io.read(l.mp + u64::from(MP_CTRL) * 4))?;
            io.write(l.mp + u64::from(MP_CTRL) * 4, ctrl | MP_ACK);
            if let Some(high) = high {
                let ctrl = checked(io.read(l.thm + u64::from(THERM_CTRL) * 4))?;
                io.write(
                    l.thm + u64::from(THERM_CTRL) * 4,
                    (ctrl & !(0xff | TRIGGER_MASK)) | u32::from(high),
                );
            }
            Ok(())
        });
        if let Err(e) = result {
            self.status.state = State::Failed(e);
            return Err(e);
        }
        if let Some(high) = high {
            self.status.high_c = high;
            self.status.fan_abnormal = context == FAN_ABNORMAL;
        }
        Ok(false)
    }
}
pub(crate) struct Monitor(Engine<Mmio>);
impl core::fmt::Debug for Monitor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Thermal").field(&self.0.status).finish()
    }
}
impl Monitor {
    /// Construction does no I/O. The retained IH service must own the
    /// monitor before arming, and stop it before dropping its GPU epoch.
    pub(crate) fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        limits: Option<Limits>,
    ) -> Option<Self> {
        let limits = limits.filter(|l| l.software_shutdown_c != 0)?;
        let layout = Layout::resolve(gpu).ok()?;
        Some(Self(Engine::new(Mmio(gpu.regs), authority, layout, limits)))
    }
    pub(crate) fn arm(&mut self) -> Result<(), Error> {
        self.0.arm()
    }
    pub(crate) fn stop(&mut self) -> Result<(), Error> {
        self.0.stop()
    }
    pub(crate) fn handle(&mut self, event: ih::Event) -> Result<bool, Error> {
        self.0.handle(event)
    }
    pub(crate) fn threshold(&self) -> u16 {
        self.0.limits.software_shutdown_c
    }
    pub(crate) fn status(&self) -> Status {
        self.0.status
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_thermal_tests.rs"]
mod tests;
