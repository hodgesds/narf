//! Native Navi48 pixel/DPP dividers. Register layout: dcn_4_1_0 headers;
//! sequencing: Linux dcn401_dccg.c and dce_clock_source.c. All consumers must
//! be retired. This prepares clocks; it does not enable a stream or HDMI PLL.
use crate::{amdgpu::AmdGpu, amdgpu_dcn401_clk as clocks, amdgpu_discovery as ip};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const GATE3: u64 = 0x5a;
const DENTIST: u64 = 0x64;
const DTB_P: u64 = 0x68;
const GATE5: u64 = 0x69;
const PIXEL_DIV: u64 = 0x6f;
const PIXEL: u64 = 0x80;
const DPP_PARAM: u64 = 0x99;
const DPP_ENABLE: u64 = 0xa8;
// Native absolute DWORD addresses from dcn401_clk_mgr.c. Read-only.
const PLL: u64 = 0x16e37 * 4;
const DPREF: u64 = 0x16e6f * 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Revoked,
    DeviceGone,
    Readback(u64),
    Timeout,
    Clocks(clocks::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Applying,
    Applied,
    Failed(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TmdsDivider {
    By2,
    By4,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelClock {
    Disabled,
    DisplayPort {
        pixel_hz: u64,
    },
    HdmiFrl {
        pixel_hz: u64,
    },
    /// Select the divider and disable DP DTO. The link owner must separately
    /// program the HDMI PLL before enabling TMDS transmission.
    Tmds {
        divider: TmdsDivider,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub pipe: u8,
    pub dpp_khz: u32,
    pub pixel: PixelClock,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Applied {
    pub request: Request,
    pub global: clocks::Applied,
    pub dpp_phase: u8,
    /// Raw DPREFCLK snapshot for DP, acknowledged DTBCLK for FRL; zero for
    /// disabled/TMDS. Matches DCN401's pixel DTO path, not audio SS correction.
    pub reference_hz: u32,
    pub integer: u8,
    pub phase: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    /// Historical successful programming, each tagged with its global clocks.
    /// Failed/in-flight operations must never be treated as a usable pipe.
    pub pipes: [Option<Applied>; 4],
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    base: u64,
    dio: u64,
    idle: [(u64, u32); 31],
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        let display = clocks::Layout::resolve(gpu).map_err(Error::Clocks)?;
        if gpu.regs.len < DPREF + 4 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            base: crate::amdgpu_psp_ring::bank(
                gpu,
                ip::HW_ID_DCN,
                &[(4, 0, 1), (4, 1, 0)],
                1,
                DPP_ENABLE as u32,
            )
            .map_err(|_| Error::Unsupported)?,
            dio: crate::amdgpu_psp_ring::bank(
                gpu,
                ip::HW_ID_DCN,
                &[(4, 0, 1), (4, 1, 0)],
                2,
                GATE3 as u32,
            )
            .map_err(|_| Error::Unsupported)?,
            idle: display.idle_registers(),
        })
    }
    fn reg(self, index: u64) -> u64 {
        self.base + index * 4
    }
}
trait Io {
    fn read(&mut self, at: u64) -> u32;
    fn write(&mut self, at: u64, value: u32);
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: discovery plus absolute PLL bounds checked by the constructor;
        // each access invokes live authority, owner excludes PM/modeset/reset.
        unsafe { self.0.read32(at) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: exclusively owned DCCG bank, bounded by Layout::resolve.
        unsafe { self.0.write32(at, value) };
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
fn dpref_hz(pll: u32, did: u32) -> Result<u32, Error> {
    checked(pll)?;
    checked(did)?;
    let divider = match did {
        8..=63 => did,
        64..=95 => 64 + 2 * (did - 64),
        96..=125 => 128 + 4 * (did - 96),
        126 => 248,
        127 => 512,
        _ => return Err(Error::Invalid),
    };
    // Linux's native PLL has a 100 MHz reference and 9.16 FbMult. SpineDiv
    // is not part of its VCO calculation. Do not invent fallback frequencies.
    let vco_khz = u64::from(pll & 0x1ff) * 100_000 + u64::from(pll >> 16) * 100_000 / 65536;
    let khz = 4 * vco_khz / u64::from(divider);
    let hz = u32::try_from(khz * 1000).map_err(|_| Error::Invalid)?;
    if hz == 0 {
        return Err(Error::Invalid);
    }
    Ok(hz)
}
impl Request {
    fn validate(self, global: clocks::Applied) -> Result<(), Error> {
        if self.pipe >= 4 || self.dpp_khz > global.dpp_khz {
            return Err(Error::Invalid);
        }
        if (self.pixel == PixelClock::Disabled) != (self.dpp_khz == 0) {
            return Err(Error::Invalid);
        }
        if matches!(
            self.pixel,
            PixelClock::DisplayPort { pixel_hz: 0 } | PixelClock::HdmiFrl { pixel_hz: 0 }
        ) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn plan(self, global: clocks::Applied, reference_hz: u32) -> Result<Applied, Error> {
        self.validate(global)?;
        let dpp_phase = if self.dpp_khz == 0 {
            0
        } else {
            (255 * u64::from(self.dpp_khz)).div_ceil(u64::from(global.dpp_khz)) as u8
        };
        let (integer, phase) = match self.pixel {
            PixelClock::DisplayPort { pixel_hz } | PixelClock::HdmiFrl { pixel_hz } => {
                if reference_hz == 0 {
                    return Err(Error::Invalid);
                }
                let integer = pixel_hz / u64::from(reference_hz);
                if integer > 15 {
                    return Err(Error::Invalid);
                }
                (integer as u8, (pixel_hz % u64::from(reference_hz)) as u32)
            }
            _ => (0, 0),
        };
        Ok(Applied {
            request: self,
            global,
            dpp_phase,
            reference_hz,
            integer,
            phase,
        })
    }
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    status: Status,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)?
    }
    fn read(&mut self, at: u64) -> Result<u32, Error> {
        self.access(|io| checked(io.read(at)))
    }
    fn update(&mut self, index: u64, mask: u32, value: u32) -> Result<(), Error> {
        self.update_at(self.layout.reg(index), mask, value)
    }
    fn update_at(&mut self, at: u64, mask: u32, value: u32) -> Result<(), Error> {
        // Check authority again between writes and readback so revocation
        // cannot be hidden by a successful posted-write flush.
        self.access(|io| {
            let old = checked(io.read(at))?;
            io.write(at, (old & !mask) | (value & mask));
            Ok(())
        })?;
        if self.read(at)? & mask != value & mask {
            return Err(Error::Readback(at));
        }
        Ok(())
    }
    fn idle(&mut self) -> Result<(), Error> {
        for (at, mask) in self.layout.idle {
            if self.read(at)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    async fn tmds_divider(&mut self, pipe: u8, divider: TmdsDivider) -> Result<(), Error> {
        let mask = 1 << (5 * pipe);
        let value = if divider == TmdsDivider::By4 { mask } else { 0 };
        if self.read(self.layout.reg(PIXEL_DIV))? & mask == value {
            return Ok(());
        }
        self.update(PIXEL_DIV, mask, value)?;
        // Native DIG FIFO workaround: retrigger the current dentist value,
        // then await DISPCLK change completion (50 us, 100 ms bound).
        let at = self.layout.reg(DENTIST);
        self.access(|io| {
            let old = checked(io.read(at))?;
            io.write(at, old);
            Ok(())
        })?;
        let deadline = narf_time::Deadline::after_ms(100);
        loop {
            if self.read(at)? & (1 << 19) != 0 {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant()).await;
        }
    }
    async fn program(&mut self, plan: Applied) -> Result<(), Error> {
        let pipe = plan.request.pipe;
        let pixel = PIXEL + 4 * u64::from(pipe);
        if plan.dpp_phase != 0 {
            self.update(
                DPP_PARAM + u64::from(pipe),
                u32::MAX,
                u32::from(plan.dpp_phase) | 0xff << 16,
            )?;
        }
        let enable = 1 << (3 * pipe);
        self.update(
            DPP_ENABLE,
            enable,
            if plan.dpp_phase != 0 { enable } else { 0 },
        )?;
        match plan.request.pixel {
            PixelClock::DisplayPort { .. } | PixelClock::HdmiFrl { .. } => {
                self.update(GATE5, 1 << pipe, 1 << pipe)?;
                let gates = (3 << (8 + 2 * pipe)) | (3 << (20 + 2 * pipe));
                // GATE3 lives in DCN bank 2, unlike GATE5 and the DTOs.
                self.update_at(self.layout.dio + GATE3 * 4, gates, gates)?;
                let source = if matches!(plan.request.pixel, PixelClock::HdmiFrl { .. }) {
                    6
                } else {
                    4
                };
                self.update(DTB_P, 7 << (3 * pipe), source << (3 * pipe))?;
                self.update(pixel + 1, u32::MAX, plan.phase)?;
                self.update(pixel + 2, u32::MAX, plan.reference_hz)?;
                self.update(
                    PIXEL_DIV,
                    15 << (5 * pipe + 1),
                    u32::from(plan.integer) << (5 * pipe + 1),
                )?;
                self.update(pixel, 0x1010, 0x1010)?;
            }
            PixelClock::Tmds { divider } => {
                self.update(pixel, 0x1010, 0)?;
                self.tmds_divider(pipe, divider).await?;
            }
            PixelClock::Disabled => {
                self.update(pixel, 0x1010, 0)?;
                // Park DTBCLK_P on REFCLK without changing its remembered mux.
                self.update(DTB_P, 4 << (3 * pipe), 0)?;
            }
        }
        Ok(())
    }
    async fn prepare(
        &mut self,
        request: Request,
        global: clocks::Applied,
    ) -> Result<Applied, Error> {
        if !matches!(self.status.state, State::Ready | State::Applied) {
            return Err(Error::Busy);
        }
        request.validate(global)?;
        self.idle()?;
        let reference = match request.pixel {
            PixelClock::DisplayPort { .. } => dpref_hz(self.read(PLL)?, self.read(DPREF)?)?,
            PixelClock::HdmiFrl { .. } => global.dtb_khz.checked_mul(1000).ok_or(Error::Invalid)?,
            _ => 0,
        };
        let plan = request.plan(global, reference)?;
        self.status.state = State::Applying;
        let result = self.program(plan).await;
        self.status.state = match result {
            Ok(()) => State::Applied,
            Err(e) => State::Failed(e),
        };
        result?;
        self.status.pipes[usize::from(request.pipe)] = Some(plan);
        Ok(plan)
    }
}
#[derive(Debug)]
pub struct Dccg(Engine<Mmio>);
impl Dccg {
    /// # Safety
    /// Exclusively own this GPU's DCCG, display consumers and PM/reset for the
    /// owner's lifetime. Mapping is permanent. Retain uncertain transitions;
    /// do not enable any stream without matching current global/pipe clocks.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        authority.invoke(Op(|| ())).map_err(|_| Error::Revoked)?;
        Ok(Self(Engine {
            io: Mmio(gpu.regs),
            authority,
            layout,
            status: Status {
                state: State::Ready,
                pipes: [None; 4],
            },
        }))
    }
    pub fn status(&self) -> Status {
        self.0.status
    }
    /// Program a retired pipe against current acknowledged global clocks.
    /// Every consumer must be idle; partial failure/cancellation blocks replay.
    pub async fn prepare(
        &mut self,
        clocks: &mut clocks::ClockManager,
        request: Request,
    ) -> Result<Applied, Error> {
        let global = clocks.pipe_clocks(self.0.io.0).map_err(Error::Clocks)?;
        self.0.prepare(request, global).await
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_dccg_tests.rs"]
mod tests;
