//! Native DCN401 timing preparation and retirement. Register layout comes
//! from dcn_4_1_0; sequencing from Linux dcn401_optc.c/dcn10_optc.c.
//! Progressive RGB, fixed refresh and one OPP per OTG only. Internal black
//! timing can run with fetchers stopped; surface/link scanout needs its owners.
use crate::{
    amdgpu::AmdGpu, amdgpu_dcn401_clk as clocks, amdgpu_dcn401_dccg as dccg,
    amdgpu_discovery as ip, amdgpu_dml::Timing,
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[path = "amdgpu_dcn401_opp.rs"]
mod opp;
pub use opp::{BlankApplied, BlankRequest, BlankRunning, ColorDepth};
#[path = "amdgpu_dcn401_fetch.rs"]
mod fetch;
pub use fetch::PlanesRetired;
#[path = "amdgpu_dcn401_stream.rs"]
mod stream;
pub use stream::{DpBlanked, DpEncoderRetired, DpStream};
#[path = "amdgpu_dcn401_link.rs"]
mod link;
pub use link::DpSstDisabled;
#[path = "amdgpu_dcn401_hpo_link.rs"]
mod hpo_link;
pub use hpo_link::{HpoDpDisabled, HpoLinkRetired};
#[path = "amdgpu_dcn401_hdmi.rs"]
mod hdmi;
pub use hdmi::HdmiTmdsRetired;
#[path = "amdgpu_dcn401_tmds_timing.rs"]
mod tmds_timing;
pub use tmds_timing::TmdsTimingRetired;

const H_TOTAL: u64 = 0x1b2a;
const H_BLANK: u64 = 0x1b2b;
const H_SYNC: u64 = 0x1b2c;
const H_POL: u64 = 0x1b2d;
const H_TIMING: u64 = 0x1b2e;
const V_TOTAL: u64 = 0x1b2f;
const V_MIN: u64 = 0x1b30;
const V_MAX: u64 = 0x1b31;
const V_CONTROL: u64 = 0x1b33;
const V_BLANK: u64 = 0x1b38;
const V_SYNC: u64 = 0x1b39;
const V_POL: u64 = 0x1b3a;
const CONTROL: u64 = 0x1b43;
const INTERLACE: u64 = 0x1b45;
const CLOCK: u64 = 0x1b84;
const STARTUP: u64 = 0x1b85;
const UPDATE: u64 = 0x1b86;
const READY: u64 = 0x1b87;
const LOCK: u64 = 0x1b89;
const PSTATE: u64 = 0x1b9f;
const SOURCE: u64 = 0x1acb;
const FORMAT: u64 = 0x1acc;
const INPUT_CLOCK: u64 = 0x1ad0;
const MEMORY: u64 = 0x1ad1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Revoked,
    DeviceGone,
    Readback(u64),
    Timeout(u64),
    Clocks(clocks::Error),
    PipeClocks(dccg::Error),
    Firmware(crate::amdgpu_dmub_navi48::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Preparing(u8),
    Prepared,
    PreparingBlank(u8),
    BlankPrepared,
    StartingBlank(u8),
    RunningBlank(u8),
    BlankingDp(DpStream),
    DpBlanked,
    RetiringDpEncoder(DpStream),
    DpEncoderRetired,
    DisablingDpSst(u8),
    DpSstDisabled,
    RetiringHpoLink(u8),
    HpoLinkRetired,
    DisablingHpoDp(u8),
    HpoDpDisabled,
    RetiringHdmiTmds(u8),
    HdmiTmdsRetired,
    RetiringTmdsTiming(u8),
    TmdsTimingRetired,
    RetiringPlanes,
    PlanesRetired,
    Retiring(u8),
    Retired,
    Failed(Error),
}
impl State {
    pub(crate) fn reusable(self) -> bool {
        matches!(
            self,
            Self::Ready
                | Self::Prepared
                | Self::BlankPrepared
                | Self::Retired
                | Self::PlanesRetired
                | Self::DpBlanked
                | Self::DpEncoderRetired
                | Self::DpSstDisabled
                | Self::HpoLinkRetired
                | Self::HpoDpDisabled
                | Self::HdmiTmdsRetired
                | Self::TmdsTimingRetired
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    DisplayPort,
    HpoDisplayPort,
    Tmds,
    HdmiFrl,
}
impl Signal {
    fn control(self) -> u32 {
        match self {
            Self::DisplayPort => 0x1000,
            Self::HpoDisplayPort => 0x201000,
            Self::Tmds => 0,
            // Native FRL shares HPO mux 2 with DP; mux 1 is reserved.
            Self::HdmiFrl => 0x200000,
        }
    }
}
/// Caller-supplied bandwidth/DLG results. Field validation is not a proof
/// that a mode can fetch its surfaces within these windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalSync {
    pub vstartup: u32,
    pub vupdate_offset: u32,
    pub vupdate_width: u32,
    pub vready_offset: u32,
    pub pstate_keepout: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub pipe: u8,
    pub timing: Timing,
    pub sync: GlobalSync,
    pub signal: Signal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Applied {
    pub request: Request,
    pub clock: dccg::Applied,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    /// Historical programming, not permission to start scanout. A clock
    /// change invalidates the recorded snapshot; failure/cancellation is sticky.
    pub pipes: [Option<Applied>; 4],
    /// Staged OPP/FMT programming; never a proof of active blanking.
    pub blanks: [Option<BlankApplied>; 4],
    /// Historical internal blank completion, valid only in RunningBlank.
    /// Does not prove link output or authorize scanout allocation reuse.
    pub running_blank: Option<BlankRunning>,
    /// Historical fetch-stop evidence. Never grants allocation reuse or proves
    /// retirement of GPUVM, writeback, or other GPU engines.
    pub planes_retired: Option<PlanesRetired>,
    /// Historical DP video blanking only; never PHY, timing or memory retirement.
    pub dp_blanked: Option<DpBlanked>,
    /// Historical stream-encoder shutdown only; PHYs and memory stay retained.
    pub dp_encoder_retired: Option<DpEncoderRetired>,
    /// Historical legacy DP firmware-disable/backend-off evidence only.
    /// Does not prove analog PHY power gating, sink or memory retirement.
    pub dp_sst_disabled: Option<DpSstDisabled>,
    /// Historical HPO digital-link stop only; PHY and its root clock remain owned.
    pub hpo_link_retired: Option<HpoLinkRetired>,
    /// Historical lane-disable/TX-clock/root-route evidence, not analog power gating.
    pub hpo_dp_disabled: Option<HpoDpDisabled>,
    /// Historical TMDS frontend stop only; backend/PHY/OTG remain owned.
    pub hdmi_tmds_retired: Option<HdmiTmdsRetired>,
    /// Historical timing/input clock-off only; all PHYs and memory stay retained.
    pub tmds_timing_retired: Option<TmdsTimingRetired>,
    /// Timing retirement only. Does not prove HUBP/VM or surface retirement.
    pub retired: u8,
}
#[derive(Clone, Copy, Debug)]
struct Plan {
    request: Request,
    h_blank: u32,
    v_blank: u32,
    vtg: u32,
}
impl Plan {
    fn registers(self) -> [(u64, u32, u32); 16] {
        let Request {
            timing: t,
            sync: s,
            signal,
            ..
        } = self.request;
        [
            (H_TOTAL, 0x7fff, t.h_total - 1),
            (H_SYNC, 0x7fff7fff, t.h_sync_width << 16),
            (H_BLANK, 0x7fff7fff, self.h_blank),
            (H_POL, 1, u32::from(!t.h_sync_positive)),
            (V_TOTAL, 0x7fff, t.v_total - 1),
            (V_MIN, 0x7fff, t.v_total - 1),
            (V_MAX, 0x7fff, t.v_total - 1),
            (V_SYNC, 0x7fff7fff, t.v_sync_width << 16),
            (V_BLANK, 0x7fff7fff, self.v_blank),
            (V_POL, 1, u32::from(!t.v_sync_positive)),
            (INTERLACE, 1, 0),
            (CONTROL, 0x303000, signal.control()),
            (STARTUP, 0x3ff, s.vstartup),
            (UPDATE, 0x3ffffff, s.vupdate_offset | s.vupdate_width << 16),
            (READY, 0xffff, s.vready_offset),
            (PSTATE, 0x7fff, s.pstate_keepout),
        ]
    }
    fn h_divider(self) -> u32 {
        ((self.request.timing.h_total
            | self.request.timing.h_sync_width
            | self.h_blank
            | (self.h_blank >> 16))
            & 1)
            << 8
    }
}
impl Request {
    fn plan(self) -> Result<Plan, Error> {
        let t = self.timing;
        let s = self.sync;
        if self.pipe >= 4
            || t.pixel_clock_khz == 0
            || t.h_active == 0
            || t.v_active == 0
            || t.h_total > 32768
            || t.v_total > 32768
            || t.h_sync_width < 4
            || t.v_sync_width == 0
            || t.v_front_porch == 0
            || s.vstartup == 0
            || s.vstartup > 0x3ff
            || s.vstartup >= t.v_total
            || s.vupdate_offset > 0xffff
            || s.vupdate_width > 0x3ff
            || s.vready_offset > 0xffff
            || s.pstate_keepout > 0x7fff
        {
            return Err(Error::Invalid);
        }
        let blank = |total: u32, active: u32, front: u32, sync: u32, min: u32| {
            let width = total.checked_sub(active).ok_or(Error::Invalid)?;
            let start = total.checked_sub(front).ok_or(Error::Invalid)?;
            let end = start.checked_sub(active).ok_or(Error::Invalid)?;
            if width < min || start > 0x7fff || end < sync {
                return Err(Error::Invalid);
            }
            Ok((start, end))
        };
        let (hs, he) = blank(t.h_total, t.h_active, t.h_front_porch, t.h_sync_width, 32)?;
        let (vs, ve) = blank(t.v_total, t.v_active, t.v_front_porch, t.v_sync_width, 3)?;
        Ok(Plan {
            request: self,
            h_blank: hs | he << 16,
            v_blank: vs | ve << 16,
            vtg: vs << 16 | s.vstartup.saturating_sub(ve + 1),
        })
    }
    fn validate_clock(self, clock: dccg::Applied) -> Result<(), Error> {
        let hz = u64::from(self.timing.pixel_clock_khz) * 1000;
        let signal_matches = match (self.signal, clock.request.pixel) {
            (
                Signal::DisplayPort | Signal::HpoDisplayPort,
                dccg::PixelClock::DisplayPort { pixel_hz },
            )
            | (Signal::HdmiFrl, dccg::PixelClock::HdmiFrl { pixel_hz }) => pixel_hz == hz,
            (Signal::Tmds, dccg::PixelClock::Tmds { .. }) => true,
            _ => false,
        };
        if !signal_matches
            || clock.request.pipe != self.pipe
            || self.timing.pixel_clock_khz > clock.global.display_khz
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    base: u64,
    mpc_base: u64,
    link_clock: u64,
    idle: [(u64, u32); clocks::IDLE_REG_COUNT],
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        let display = clocks::Layout::resolve(gpu).map_err(Error::Clocks)?;
        let base = crate::amdgpu_psp_ring::bank(
            gpu,
            ip::HW_ID_DCN,
            &[(4, 0, 1), (4, 1, 0)],
            2,
            0x3947, // includes all six native SAT status rows on HPO link 3
        )
        .map_err(|_| Error::Unsupported)?;
        Ok(Self {
            base,
            link_clock: display.hpo_link_clock(),
            mpc_base: crate::amdgpu_psp_ring::bank(
                gpu,
                ip::HW_ID_DCN,
                &[(4, 0, 1), (4, 1, 0)],
                3,
                0xe59, // MPC and four independent HPO stream-to-link mappers
            )
            .map_err(|_| Error::Unsupported)?,
            idle: display.idle_registers(),
        })
    }
    fn otg(self, pipe: u8, reg: u64) -> u64 {
        self.base + (reg + u64::from(pipe) * 0x80) * 4
    }
    fn odm(self, pipe: u8, reg: u64) -> u64 {
        self.base + (reg + u64::from(pipe) * 0x10) * 4
    }
    fn vtg(self, pipe: u8) -> u64 {
        self.base + (0x530 + u64::from(pipe)) * 4
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
        // SAFETY: bounded discovery, permanent mapping and serialized owner.
        unsafe { self.0.read32(at) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: same bounds/ownership; caller invokes live write authority.
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
    fn update(&mut self, at: u64, mask: u32, value: u32) -> Result<(), Error> {
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
    fn preflight(&mut self, pipe: u8, retire: bool) -> Result<(), Error> {
        if !(self.status.state.reusable()
            || retire && self.status.state == State::RunningBlank(pipe))
        {
            return Err(Error::Busy);
        }
        if pipe >= 4 {
            return Err(Error::Invalid);
        }
        let l = self.layout;
        for (at, mask) in l.idle {
            let timing = (0..4).any(|p| at == l.otg(p, CONTROL) || at == l.otg(p, CLOCK));
            if !(retire && timing) && self.read(at)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        // Never steal an inherited master-update transaction or program an
        // OTG held in soft reset. FAMS/firmware writers are excluded by ownership.
        if self.read(l.otg(pipe, LOCK))? & 0x101 != 0 || self.read(l.otg(pipe, CLOCK))? & 0x10 != 0
        {
            return Err(Error::Busy);
        }
        Ok(())
    }
    async fn wait(&mut self, at: u64, mask: u32, value: u32, us: u64) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_us(us);
        loop {
            if self.read(at)? & mask == value {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout(at));
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(1).as_instant()).await;
        }
    }
    async fn program(&mut self, plan: Plan) -> Result<(), Error> {
        let l = self.layout;
        let pipe = plan.request.pipe;
        let odm = |r| l.odm(pipe, r);
        let otg = |r| l.otg(pipe, r);
        self.update(odm(INPUT_CLOCK), 3, 3)?;
        self.wait(odm(INPUT_CLOCK), 4, 4, 1000).await?;
        self.update(otg(CLOCK), 3, 3)?;
        self.wait(otg(CLOCK), 0x100, 0x100, 1000).await?;
        self.update(l.vtg(pipe), 0x80000000, 0)?;
        // Native ODM bypass: no legacy segment-width programming. One OPP,
        // all unused segments disconnected, no ODM combining memory.
        self.update(odm(SOURCE), u32::MAX, 0xfff00000 | u32::from(pipe) << 16)?;
        // Native HW may select divide-by-two automatically only if every
        // horizontal boundary is even. Odd timings require manual no-divide.
        self.update(otg(H_TIMING), 0x103, plan.h_divider())?;
        self.update(odm(MEMORY), 0xffff, 0)?;
        // Fixed refresh; clear inherited DRR selectors before setting equal
        // total/min/max. No DMUB FAMS delegation is active under this owner.
        self.update(otg(V_CONTROL), 0xffff0013, 0)?;
        for (r, mask, value) in plan.registers() {
            self.update(otg(r), mask, value)?;
        }
        self.update(l.vtg(pipe), 0x7fff7fff, plan.vtg)?;
        self.update(odm(FORMAT), 0x33, 0)?; // RGB, DSC disabled
        Ok(())
    }
    async fn prepare(&mut self, request: Request, clock: dccg::Applied) -> Result<Applied, Error> {
        let plan = request.plan()?;
        request.validate_clock(clock)?;
        self.preflight(request.pipe, false)?;
        self.status.state = State::Preparing(request.pipe);
        match self.program(plan).await {
            Ok(()) => {
                let applied = Applied { request, clock };
                self.status.pipes[usize::from(request.pipe)] = Some(applied);
                self.status.blanks[usize::from(request.pipe)] = None;
                self.status.retired &= !(1 << request.pipe);
                self.status.state = State::Prepared;
                Ok(applied)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    async fn disable(&mut self, pipe: u8) -> Result<(), Error> {
        let l = self.layout;
        self.update(l.odm(pipe, SOURCE), 0xffff0003, 0xffff0000)?;
        self.update(l.odm(pipe, MEMORY), 0xffff, 0)?;
        self.update(l.otg(pipe, CONTROL), 1, 0)?;
        self.update(l.vtg(pipe), 0x80000000, 0)?;
        self.wait(l.otg(pipe, CONTROL), 0x10001, 0, 150_000).await?;
        self.wait(l.otg(pipe, CLOCK), 0x10000, 0, 150_000).await
    }
    async fn retire(&mut self, pipe: u8) -> Result<(), Error> {
        self.preflight(pipe, true)?;
        self.status.state = State::Retiring(pipe);
        match self.disable(pipe).await {
            Ok(()) => {
                self.status.pipes[usize::from(pipe)] = None;
                self.status.blanks[usize::from(pipe)] = None;
                self.status.running_blank = None;
                self.status.retired |= 1 << pipe;
                self.status.state = State::Retired;
                Ok(())
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
#[derive(Debug)]
pub struct Otg(Engine<Mmio>);
impl Otg {
    /// # Safety
    /// Retain permanent mappings and exclusive display/PM/reset ownership.
    /// Exclude firmware/FAMS and concurrent timing or clock writers. Retain
    /// this owner after partial failure/cancellation until independent reset.
    /// Construction only validates metadata and live authority; it writes nothing.
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
                blanks: [None; 4],
                running_blank: None,
                planes_retired: None,
                dp_blanked: None,
                dp_encoder_retired: None,
                dp_sst_disabled: None,
                hpo_link_retired: None,
                hpo_dp_disabled: None,
                hdmi_tmds_retired: None,
                tmds_timing_retired: None,
                retired: 0,
            },
        }))
    }
    pub fn status(&self) -> Status {
        self.0.status
    }
    /// Prepare disabled fixed-refresh RGB timing against matching current
    /// clocks. No OPP/plane/PHY setup, bandwidth proof or scanout enable.
    pub async fn prepare(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        request: Request,
    ) -> Result<Applied, Error> {
        request.plan()?;
        if !self.0.status.state.reusable() {
            return Err(Error::Busy);
        }
        let clock = dccg
            .timing_clock(self.0.io.0, clocks, request.pipe)
            .map_err(Error::PipeClocks)?;
        self.0.prepare(request, clock).await
    }
    /// Retire one inherited or prepared timing generator after every display
    /// stream/link clock is stopped. Leaves clocks on for later reprogramming.
    /// # Safety
    /// Stop CPU scanout writers and retain all associated surfaces, page
    /// tables, HUBP and OPP resources. Timing retirement does not prove memory
    /// fetch retirement and must never authorize freeing/reusing those resources.
    pub async unsafe fn retire(&mut self, pipe: u8) -> Result<(), Error> {
        self.0.retire(pipe).await
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_otg_tests.rs"]
mod tests;
