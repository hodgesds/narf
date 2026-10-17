//! Navi22 DAL display clocks. Protocol and offsets: Linux dcn30_clk_mgr_smu_msg.c,
//! dalsmc.h, dcn30_clk_mgr.h and dcn20_clk_mgr.c. This is neither the Phoenix
//! VBIOSSMC mailbox nor the GFX PPSMC mailbox. No firmware table DMA is needed.
use crate::{
    amdgpu::AmdGpu, amdgpu_dcn_clk::Error, amdgpu_dcn_dccg::Dccg, amdgpu_dcn_profile::Profile,
};
use core::future::Future;
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

const MESSAGE: u32 = 0x28a;
const ARGUMENT: u32 = 0x273;
const RESPONSE: u32 = 0x274;
// CLK_REG_LIST_DCN3 selects CLK02, not CLK00 or Navi10's CLK3 bank.
const PLL: u32 = 0x17010;
const GET_VERSION: u32 = 2;
const GET_INTERFACE: u32 = 3;
const GET_HEADER: u32 = 4;
const HARD_MIN: u32 = 9;
const DPM_BY_INDEX: u32 = 0xb;
const DEEP_SLEEP_MIN: u32 = 0xd;
const DISPLAYS: u32 = 0xe;
const DF_CSTATE_ALLOW: u32 = 0x10;
/// `DALSMC_MSG_BacoAudioD3PME`.
const BACO_AUDIO_D3_PME: u32 = 0x11;
const LEVELS: usize = 16;

/// PPCLK ids in the DAL interface (MHz). PIXCLK supplies the global DPP clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Clock {
    Soc = 1,
    Memory = 2,
    Fabric = 3,
    Dcf = 8,
    Display = 9,
    Pixel = 10,
    Phy = 11,
}
const CLOCKS: [Clock; 7] = [
    Clock::Soc,
    Clock::Memory,
    Clock::Fabric,
    Clock::Dcf,
    Clock::Display,
    Clock::Pixel,
    Clock::Phy,
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Range {
    mhz: [u16; LEVELS],
    count: u8,
    pub fine_grained: bool,
}
impl Range {
    pub fn mhz(&self) -> &[u16] {
        &self.mhz[..usize::from(self.count)]
    }
    pub fn max_khz(&self) -> u32 {
        u32::from(*self.mhz().last().unwrap_or(&0)) * 1000
    }
    pub fn min_khz(&self) -> u32 {
        u32::from(*self.mhz().first().unwrap_or(&0)) * 1000
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Levels {
    ranges: [Range; 7],
    pub firmware: u32,
    pub interface: u32,
    pub vco_khz: u32,
}
impl Levels {
    pub fn range(&self, clock: Clock) -> &Range {
        &self.ranges[CLOCKS.iter().position(|c| *c == clock).unwrap()]
    }
    /// Highest representable DISP/DPP clocks within the board limits. The
    /// divider is rounded toward a lower frequency here, never above the SKU.
    pub fn ceiling(&self, clock: Clock) -> Result<u32, Error> {
        if !matches!(clock, Clock::Display | Clock::Pixel) {
            return Err(Error::Invalid);
        }
        let max = self.range(clock).max_khz();
        (8..=127)
            .map(|did| frequency(self.vco_khz, did))
            .find(|&khz| khz <= max)
            .filter(|&khz| khz >= self.range(clock).min_khz())
            .ok_or(Error::Invalid)
    }
    pub fn plan(&self, display_khz: u32, pixel_khz: u32, dcf_khz: u32) -> Result<Plan, Error> {
        let (display_did, display_khz) = self.quantize(Clock::Display, display_khz)?;
        let (pixel_did, pixel_khz) = self.quantize(Clock::Pixel, pixel_khz)?;
        if dcf_khz == 0 || dcf_khz > self.range(Clock::Dcf).max_khz() {
            return Err(Error::Invalid);
        }
        Ok(Plan {
            display_khz,
            pixel_khz,
            dcf_khz: dcf_khz.max(self.range(Clock::Dcf).min_khz()),
            display_did,
            pixel_did,
            vco_khz: self.vco_khz,
        })
    }
    fn quantize(&self, clock: Clock, khz: u32) -> Result<(u8, u32), Error> {
        if khz == 0 {
            return Err(Error::Invalid);
        }
        let range = self.range(clock);
        let requested = khz.max(range.min_khz());
        (8..=127)
            .rev()
            .map(|did| (did, frequency(self.vco_khz, did)))
            .find(|&(_, value)| value >= requested && value <= range.max_khz())
            .ok_or(Error::Invalid)
    }
}
/// An immutable, board-bounded DENTIST plan. Frequencies are those the divider
/// actually provides; use them in DML, rather than the unrounded request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub display_khz: u32,
    pub pixel_khz: u32,
    pub dcf_khz: u32,
    display_did: u8,
    pixel_did: u8,
    vco_khz: u32,
}
fn divider(did: u8) -> u32 {
    match did {
        8..=63 => u32::from(did),
        64..=95 => 64 + 2 * u32::from(did - 64),
        96..=125 => 128 + 4 * u32::from(did - 96),
        126 => 248,
        127 => 512,
        _ => 0,
    }
}
fn frequency(vco: u32, did: u8) -> u32 {
    (u64::from(vco) * 4 / u64::from(divider(did))) as u32
}
fn vco(pll: u32) -> Result<u32, Error> {
    if pll == u32::MAX {
        return Err(Error::DeviceGone);
    }
    // FbMult is an integer in bits 8:0 plus a /65536 fraction in bits 31:16.
    let khz = (u64::from(pll & 0x1ff) * 100_000 + u64::from(pll >> 16) * 100_000 / 65536) as u32;
    if !(600_000..=6_000_000).contains(&khz) {
        return Err(Error::Invalid);
    }
    Ok(khz)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Dormant,
    InFlight,
    Ready,
    Configured,
    Failed,
}
trait Io: Send {
    fn read(&mut self, reg: u32) -> u32;
    fn write(&mut self, reg: u32, value: u32);
    fn idle(&mut self) -> Result<(), Error>;
}
#[derive(Debug)]
struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
    mp1: u64,
    dcn: u64,
}
impl Io for Mmio {
    fn read(&mut self, reg: u32) -> u32 {
        let offset = if reg == PLL {
            u64::from(reg) * 4
        } else {
            self.mp1 + u64::from(reg) * 4
        };
        // SAFETY: constructor bounds the PLL and exact MP1 aperture.
        unsafe { self.regs.read32(offset) }
    }
    fn write(&mut self, reg: u32, value: u32) {
        // SAFETY: only the three owned DAL mailbox registers are written.
        unsafe { self.regs.write32(self.mp1 + u64::from(reg) * 4, value) };
    }
    fn idle(&mut self) -> Result<(), Error> {
        for i in 0..6 {
            for (reg, mask) in [
                (0x1b41 + i * 0x80, 1),
                (0x1b86 + i * 0x80, 1 << 16),
                (0x210c + i * 0x100, 1 | 1 << 16),
            ] {
                // SAFETY: all six OTGs and DIGs are bounded in the constructor.
                let value = unsafe { self.regs.read32(self.dcn + reg * 4) };
                if value == u32::MAX {
                    return Err(Error::DeviceGone);
                }
                if value & mask != 0 {
                    return Err(Error::Busy);
                }
            }
        }
        Ok(())
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
trait Dentist: Send {
    fn program(&mut self, disp: u8, dpp: u8) -> impl Future<Output = Result<(), Error>> + Send;
}
impl Dentist for Dccg {
    async fn program(&mut self, disp: u8, dpp: u8) -> Result<(), Error> {
        self.navi22_dentist(disp, dpp).await
    }
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    state: State,
    levels: Option<Levels>,
    applied: Option<Plan>,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    async fn settled(&mut self) -> Result<u32, Error> {
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            let value = self.access(|io| io.read(RESPONSE))?;
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
            if value != 0 {
                return Ok(value);
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(10).as_instant()).await;
        }
    }
    async fn command(&mut self, msg: u32, arg: u32) -> Result<u32, Error> {
        self.settled().await?;
        self.access(|io| {
            io.write(RESPONSE, 0);
            io.write(ARGUMENT, arg);
            io.write(MESSAGE, msg);
        })?;
        let response = self.settled().await?;
        if response != 1 {
            return Err(Error::Rejected(response));
        }
        let result = self.access(|io| io.read(ARGUMENT))?;
        if result == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok(result)
    }
    async fn start(
        &mut self,
        power: impl Future<Output = Result<(), Error>>,
    ) -> Result<Levels, Error> {
        if self.state != State::Dormant {
            return Err(Error::Busy);
        }
        self.access(|io| io.idle())??;
        self.state = State::InFlight;
        let result = async {
            power.await?;
            self.start_inner().await
        }
        .await;
        self.state = if result.is_ok() {
            State::Ready
        } else {
            State::Failed
        };
        if let Ok(levels) = result {
            self.levels = Some(levels);
        }
        result
    }
    /// A DAL query whose rejection Linux ignores (dcn30_smu_send_msg_with_param
    /// leaves the response 0): a rejected message reads as 0, while timeouts,
    /// device loss and revocation still fail.
    async fn query_lenient(&mut self, msg: u32, arg: u32) -> Result<u32, Error> {
        match self.command(msg, arg).await {
            Err(Error::Rejected(_)) => Ok(0),
            other => other,
        }
    }
    /// `dcn3_init_clocks`: only the SMU version query decides `smu_present`;
    /// the driver-interface and message-header checks are logged ("do we
    /// fail if these fail? ... do we not care to check?"), and
    /// `dcn3_init_single_clock` records whatever levels PMFW reports (a
    /// failed query is 0 levels). Unusable ranges are refused later, by the
    /// clock plan, rather than here.
    async fn start_inner(&mut self) -> Result<Levels, Error> {
        let vco_khz = vco(self.access(|io| io.read(PLL))?)?;
        let firmware = self.command(GET_VERSION, 0).await?;
        // Driver-table versions differ between Navy and Sienna. We record
        // this diagnostic but use only the version-1 scalar DAL protocol.
        let interface = self.query_lenient(GET_INTERFACE, 0).await?;
        let header = self.query_lenient(GET_HEADER, 0).await?;
        if header != 1 {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 DAL msg header version {header} (driver 1), if {interface:#x}"
            );
        }
        let mut ranges = [Range::default(); 7];
        for (range, clock) in ranges.iter_mut().zip(CLOCKS) {
            let features = self
                .query_lenient(DPM_BY_INDEX, (clock as u32) << 16 | 0xff)
                .await?;
            range.fine_grained = features & 1 << 31 != 0;
            // clk_table holds at most LEVELS entries; never index past it.
            range.count = if range.fine_grained {
                2
            } else {
                (features as u8).min(LEVELS as u8)
            };
            for index in 0..usize::from(range.count) {
                let value = self
                    .query_lenient(DPM_BY_INDEX, (clock as u32) << 16 | index as u32)
                    .await?
                    & 0xffff;
                range.mhz[index] = value as u16;
            }
        }
        Ok(Levels {
            ranges,
            firmware,
            interface,
            vco_khz,
        })
    }
    async fn floor(&mut self, clock: Clock, khz: u32) -> Result<(), Error> {
        let mhz = khz.div_ceil(1000);
        if mhz == 0 || mhz > u32::from(u16::MAX) {
            return Err(Error::Invalid);
        }
        let applied = self.command(HARD_MIN, (clock as u32) << 16 | mhz).await?;
        if applied < mhz
            || applied > self.levels.ok_or(Error::Invalid)?.range(clock).max_khz() / 1000
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    async fn prepare(&mut self, plan: Plan, dentist: &mut impl Dentist) -> Result<(), Error> {
        if !matches!(self.state, State::Ready | State::Configured) {
            return Err(Error::Busy);
        }
        let levels = self.levels.ok_or(Error::Invalid)?;
        // Revalidate public frequency fields, provenance and both divider ids.
        if levels.plan(plan.display_khz, plan.pixel_khz, plan.dcf_khz)? != plan {
            return Err(Error::Invalid);
        }
        self.access(|io| io.idle())??;
        self.state = State::InFlight;
        let result = async {
            // The first native path pins memory/fabric/SOC at their upper
            // board states. It does not enable p-state switching or deep sleep.
            self.command(DISPLAYS, 1).await?;
            self.command(DF_CSTATE_ALLOW, 0).await?;
            for clock in [Clock::Memory, Clock::Fabric, Clock::Soc] {
                self.floor(clock, levels.range(clock).max_khz()).await?;
            }
            self.floor(Clock::Dcf, plan.dcf_khz).await?;
            self.command(DEEP_SLEEP_MIN, plan.dcf_khz.div_ceil(1000))
                .await?;
            self.floor(Clock::Pixel, plan.pixel_khz).await?;
            self.floor(Clock::Display, plan.display_khz).await?;
            // Check again after firmware waits, and before touching DENTIST.
            self.access(|io| io.idle())??;
            dentist.program(plan.display_did, plan.pixel_did).await?;
            Ok(())
        }
        .await;
        self.state = if result.is_ok() {
            State::Configured
        } else {
            State::Failed
        };
        if result.is_ok() {
            self.applied = Some(plan);
        }
        result
    }
}

/// Exclusive DAL mailbox owner. Retains incomplete operations after future
/// cancellation; a failed or cancelled transaction requires a GPU restart.
#[derive(Debug)]
pub struct ClockManager {
    engine: Engine<Mmio>,
    dccg: Dccg,
}
impl ClockManager {
    /// # Safety
    /// Caller exclusively owns this Navi22 GPU, its DAL mailbox, DCCG and
    /// reset controls, with permanent mappings and matching PCI authority.
    /// The SMU passed to `start` must own this same physical GPU, with its board
    /// power policy running. No other owner may enable a stream concurrently.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        if Profile::resolve(gpu)? != Profile::Navi22 {
            return Err(Error::Unsupported);
        }
        let mp1 = crate::amdgpu_smu_navi22::mp1_bank(gpu).map_err(|_| Error::Unsupported)?;
        if gpu.regs.len < u64::from(PLL + 1) * 4 {
            return Err(Error::Invalid);
        }
        let dcn = Profile::Navi22.bank(gpu, 2, 0x260c)?;
        // SAFETY: DCCG is retained here; no second divider owner is exposed.
        let dccg = unsafe { Dccg::new(gpu, authority)? };
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                    mp1,
                    dcn,
                },
                authority,
                state: State::Dormant,
                levels: None,
                applied: None,
            },
            dccg,
        })
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub fn levels(&self) -> Option<Levels> {
        self.engine.levels
    }
    pub fn applied(&self) -> Option<Plan> {
        self.engine.applied
    }
    pub async fn start(
        &mut self,
        smu: &mut crate::amdgpu_smu_navi22::Smu,
    ) -> Result<Levels, Error> {
        // SAFETY: start_with checks every OTG and stream before polling it;
        // exclusive GPU ownership prevents new users.
        self.start_with(unsafe { display_power(smu) }).await
    }
    /// [`ClockManager::start`] with the SMU display-power step supplied by the
    /// caller (the retained SMU owner, or a model of it).
    pub async fn start_with(
        &mut self,
        power: impl Future<Output = Result<(), Error>>,
    ) -> Result<Levels, Error> {
        self.engine.start(power).await
    }
    /// Configure a single-display mode with all six OTGs and DIG streams idle.
    /// The SMU display/memory DPM policy must have been enabled by the retained
    /// Navi22 SMU owner. Floors remain pinned on failure; no rollback guesses.
    pub async fn prepare(&mut self, plan: Plan) -> Result<(), Error> {
        self.engine.prepare(plan, &mut self.dccg).await?;
        self.dccg.set_reference_dppclk(plan.pixel_khz);
        Ok(())
    }
    /// `dcn30_notify_link_rate_change`: the PHYCLK hard minimum for a DP link
    /// at `khz` (link rate code x 27 MHz).
    pub async fn phy_floor(&mut self, khz: u32) -> Result<(), Error> {
        if self.engine.state != State::Configured {
            return Err(Error::Busy);
        }
        self.engine.floor(Clock::Phy, khz).await
    }
    pub fn pipe_clock(&mut self, pipe: u8, khz: u32) -> Result<(), Error> {
        if self.engine.state != State::Configured {
            return Err(Error::Busy);
        }
        self.dccg.update_dpp_dto(pipe, khz)
    }
}
/// `dcn3_enable_pme_wa`: wake the Azalia from D3 before its endpoint is
/// touched. Linux ignores the result (`dcn30_smu_send_msg_with_param`'s
/// response is not checked there); so does this.
impl crate::amdgpu_dcn30_audio::AzaliaWake for ClockManager {
    async fn wake_azalia(&mut self) {
        let _ = self.engine.command(BACO_AUDIO_D3_PME, 0).await;
    }
}

/// `smu_v11_0` display power through the retained SMU owner, with its errors
/// in this module's terms.
///
/// # Safety
/// As `Smu::enable_display_power`: poll it only as the future handed to
/// [`ClockManager::start_with`], which checks every OTG and stream idle first.
pub(crate) async unsafe fn display_power(
    smu: &mut crate::amdgpu_smu_navi22::Smu,
) -> Result<(), Error> {
    // SAFETY: forwarded contract.
    unsafe { smu.enable_display_power().await }.map_err(|error| match error {
        crate::amdgpu_smu_navi22::Error::Revoked => Error::Revoked,
        crate::amdgpu_smu_navi22::Error::Busy => Error::Busy,
        crate::amdgpu_smu_navi22::Error::Timeout => Error::Timeout,
        crate::amdgpu_smu_navi22::Error::DeviceGone => Error::DeviceGone,
        crate::amdgpu_smu_navi22::Error::Rejected(status) => Error::Rejected(status),
        _ => Error::Unsupported,
    })
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn30_clk_tests.rs"]
mod tests;
