//! Navi48 DAL display clocks, following Linux dcn401_clk_mgr{,_smu_msg}.c,
//! dcn401_smu14_driver_if.h and dalsmc.h. This mailbox is separate from PPSMC.
//! Requires retired display consumers; no active-mode clock transitions yet.
use crate::{
    amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_psp_ring::bank, amdgpu_smu_navi48 as smu,
};
use core::future::Future;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const MESSAGE: u32 = 0x8a; // MP1 C2PMSG74, base index 1
const ARGUMENT: u32 = 0x73; // C2PMSG51
const RESPONSE: u32 = 0x74; // C2PMSG52
const LEVEL_COUNT: usize = 8;
pub(crate) const IDLE_REG_COUNT: usize = 75;
pub(crate) const FRL_IDLE: [(u64, u32); 5] = [
    (0x8d3, 0x1111),   // stream clock request and three clock-on witnesses
    (0x8d6, 0x100011), // ramp FIFO enable/reset request and reset-done
    (0x8df, 0x111),    // tribyte enable/reset request and reset-done
    (0x95b, 0x11),     // digital link enable/reset
    (0x95c, 3),        // link clock request/ON
];
pub(crate) fn backend_clock_mask(instance: u8) -> u32 {
    // Only DIG0 exposes the HDCP clock-on witness in DCN4.1.0.
    0x2810 | if instance == 0 { 0x1000 } else { 0 }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Revoked,
    DeviceGone,
    Timeout,
    Rejected(u32),
    Interface(u32),
    HardMinTimeout(Clock),
    Frequency(Clock, u32),
    Power(smu::Error),
    /// The display owner's DPP DTO update inside a live clock update failed.
    Dto,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Starting,
    Ready,
    Applying,
    Applied,
    Failed(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Clock {
    Soc = 1,
    Memory = 2,
    Fabric = 3,
    Display = 6,
    Dpp = 7,
    Dcf = 9,
    Dtb = 10,
}
const CLOCKS: [Clock; 7] = [
    Clock::Soc,
    Clock::Memory,
    Clock::Fabric,
    Clock::Display,
    Clock::Dpp,
    Clock::Dcf,
    Clock::Dtb,
];
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Range {
    mhz: [u16; LEVEL_COUNT],
    count: u8,
    pub fine_grained: bool,
    /// Original DPM feature word, including auto/sweep/forced flags.
    pub flags: u32,
    /// PMFW `GetDcModeMaxDpmFreq` below the table maximum, or zero.
    pub dc_limit_mhz: u16,
}
impl Range {
    /// The raw PMFW DPM table, before any DC-mode limit.
    pub fn mhz(&self) -> &[u16] {
        &self.mhz[..usize::from(self.count)]
    }
    pub fn min_khz(&self) -> u32 {
        u32::from(*self.mhz().first().unwrap_or(&0)) * 1000
    }
    /// Highest usable frequency. Like Linux DCN401 (`use_clock_dc_limits`),
    /// a DC-mode maximum caps the table; floors never request above it.
    pub fn max_khz(&self) -> u32 {
        let table = u32::from(*self.mhz().last().unwrap_or(&0));
        let limit = u32::from(self.dc_limit_mhz);
        if limit != 0 && limit < table {
            limit.max(u32::from(*self.mhz().first().unwrap_or(&0))) * 1000
        } else {
            table * 1000
        }
    }
    fn request(&self, khz: u32) -> Result<u32, Error> {
        if khz == 0 || khz > self.max_khz() {
            return Err(Error::Invalid);
        }
        Ok(khz.max(self.min_khz()))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Levels {
    ranges: [Range; 7],
    /// DALSMC `GetNumUmcChannels`: 16-bit memory channels behind the UMCs.
    pub umc_channels: u32,
    pub firmware: u32,
    pub interface: u32,
    pub header: u32,
}
impl Levels {
    /// Fine-grained `[min, max]` MHz per clock in `CLOCKS` order, for models.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn fine_grained(mhz: [[u16; 2]; 7], umc_channels: u32) -> Self {
        let mut ranges = [Range::default(); 7];
        for (range, [min, max]) in ranges.iter_mut().zip(mhz) {
            range.mhz[..2].copy_from_slice(&[min, max]);
            range.count = 2;
            range.fine_grained = true;
        }
        Self {
            ranges,
            umc_channels,
            firmware: 1,
            interface: 1,
            header: 1,
        }
    }
    pub fn range(&self, clock: Clock) -> &Range {
        &self.ranges[CLOCKS.iter().position(|&c| c == clock).unwrap()]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub displays: u8,
    pub display_khz: u32,
    pub dpp_khz: u32,
    pub dtb_khz: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Applied {
    pub request: Request,
    /// Actual DISP/DPP/DTB rates returned by PMFW, in kHz (not MHz).
    pub display_khz: u32,
    pub dpp_khz: u32,
    pub dtb_khz: u32,
    /// Acknowledged requested floors, not measurements of instantaneous clocks.
    pub dcf_floor_khz: u32,
    pub memory_floor_khz: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub levels: Option<Levels>,
    pub applied: Option<Applied>,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Layout {
    mp1: u64,
    dccg: u64,
    dio: u64,
    hpo: u64,
    /// The display resource pool: a fused pipe's OTG is no idle witness.
    pool: crate::amdgpu_rdna4::PipePool,
}
impl Layout {
    pub(crate) fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if crate::amdgpu_rdna4::Rdna4Chip::of(gpu).is_none() {
            return Err(Error::Unsupported);
        }
        bank(gpu, ip::HW_ID_GC, crate::amdgpu_rdna4::GC_VERSIONS, 0, 0)
            .map_err(|_| Error::Unsupported)?;
        let mp1 = bank(
            gpu,
            ip::HW_ID_MP1,
            crate::amdgpu_rdna4::MP_VERSIONS,
            1,
            MESSAGE,
        )
        .map_err(|_| Error::Unsupported)?;
        // Linux DAL uses absolute DWORD addresses 0x1628a/0x16273/0x16274.
        // Require discovery to agree rather than borrowing another MP1 bank.
        if mp1 != 0x16200 * 4 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            mp1,
            dccg: bank(gpu, ip::HW_ID_DCN, &[(4, 0, 1), (4, 1, 0)], 1, 0x66)
                .map_err(|_| Error::Unsupported)?,
            dio: bank(gpu, ip::HW_ID_DCN, &[(4, 0, 1), (4, 1, 0)], 2, 0x3931)
                .map_err(|_| Error::Unsupported)?,
            hpo: bank(gpu, ip::HW_ID_DCN, &[(4, 0, 1), (4, 1, 0)], 3, 0x95c)
                .map_err(|_| Error::Unsupported)?,
            pool: crate::amdgpu_rdna4::pipe_pool(),
        })
    }
    pub(crate) fn hpo_link_clock(self) -> u64 {
        self.dccg + 0x66 * 4
    }
    pub(crate) fn idle_registers(self) -> [(u64, u32); IDLE_REG_COUNT] {
        let mut regs = [(0, 0); IDLE_REG_COUNT];
        for i in 0..4 {
            for (j, (reg, stride, mask)) in [
                (0x1b43, 0x80, 0x10001),  // OTG_MASTER_EN/current master state
                (0x1b84, 0x80, 0x10000),  // OTG_BUSY
                (0x20bd, 0x124, 1),       // DIG_BE_ENABLE (HDMI and legacy DP)
                (0x2122, 0x124, 0x10001), // DP stream enable/status
                (0x3685, 0xd4, 0x101),    // HPO DP video enable/status
                (0x367b, 0xd4, 1),        // HPO DP SDP enable
                (0x369f, 0xd4, 0x11),     // HPO DP link clock request/ON
                (0x2094, 0x124, 0x2c10),  // DIO frontend clock request/ON
                (0x2095, 0x124, 1),       // DIO frontend enabled
                (0x209b, 0x124, 1),       // DIO pixel FIFO enabled
                (0x3623, 0xd4, 0x11111),  // HPO stream clock request/ON
                (0x365d, 0xd4, 1),        // HPO SYM32 encoder enabled
                (0x20bb, 0x124, backend_clock_mask(i as u8)), // backend clocks
                (0x36b4, 0xd4, 3),        // HPO DPHY enable/reset
                (0x36b5, 0xd4, 0x1f1003), // HPO DPHY status and pending transactions
                (0x2943, 0xd8, 0x3c3c3c3c), // RDPCS lane clock/data/handshake activity
                (0x2931, 0xd8, 0x6f0),    // RDPCS lane and TX clock request/ON
            ]
            .into_iter()
            .enumerate()
            {
                regs[i * 17 + j] = (self.dio + (reg + i as u64 * stride) * 4, mask);
            }
            // The OTG witnesses (the first two) of a fused pipe: Linux never
            // reads a fused timing generator. Every consumer skips mask 0.
            if self.pool.pipe(i as u8).is_none() {
                regs[i * 17] = (0, 0);
                regs[i * 17 + 1] = (0, 0);
            }
        }
        // The single FRL stream lives in DCN bank 3, unlike HPO DP's bank 2.
        for (i, (reg, mask)) in FRL_IDLE.into_iter().enumerate() {
            regs[68 + i] = (self.hpo + reg * 4, mask);
        }
        regs[73] = (self.hpo_link_clock(), 0x8888);
        regs[74] = (self.dio + 0x4a * 4, 1); // PHY-derived FRL character-clock root
        regs
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
        // SAFETY: discovery bounds every register; each batch invokes current
        // PCI authority and the retained owner excludes other clock/reset users.
        unsafe { self.0.read32(at) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: only the three bounded, exclusively owned DAL registers.
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
async fn delay() {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
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
    fn idle(&mut self) -> Result<(), Error> {
        self.idle_except(&|_| false)
    }
    /// `idle`, leaving the registers `held` claims to their display owner.
    fn idle_except(&mut self, held: &dyn Fn(u64) -> bool) -> Result<(), Error> {
        let regs = self.layout.idle_registers();
        self.access(|io| {
            for (at, mask) in regs {
                if mask != 0 && !held(at) && checked(io.read(at))? & mask != 0 {
                    return Err(Error::Busy);
                }
            }
            Ok(())
        })
    }
    async fn settled(&mut self, deadline: narf_time::Deadline) -> Result<u32, Error> {
        let at = self.layout.mp1 + u64::from(RESPONSE) * 4;
        loop {
            let value = self.access(|io| checked(io.read(at)))?;
            if value != 0 {
                return Ok(value);
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay().await;
        }
    }
    async fn command_until(
        &mut self,
        message: u32,
        parameter: u32,
        deadline: narf_time::Deadline,
    ) -> Result<u32, Error> {
        let ready = self.settled(deadline).await?;
        if ready != 1 {
            return Err(Error::Rejected(ready));
        }
        if deadline.expired() {
            return Err(Error::Timeout);
        }
        let base = self.layout.mp1;
        self.access(|io| {
            io.write(base + u64::from(RESPONSE) * 4, 0);
            io.write(base + u64::from(ARGUMENT) * 4, parameter);
            io.write(base + u64::from(MESSAGE) * 4, message);
            Ok(())
        })?;
        let result = self.settled(deadline).await?;
        if result != 1 {
            return Err(Error::Rejected(result));
        }
        self.access(|io| checked(io.read(base + u64::from(ARGUMENT) * 4)))
    }
    async fn command(&mut self, message: u32, parameter: u32) -> Result<u32, Error> {
        self.command_until(message, parameter, narf_time::Deadline::after_ms(2000))
            .await
    }
    async fn start(
        &mut self,
        power: impl Future<Output = Result<smu::PowerStatus, smu::Error>>,
    ) -> Result<Levels, Error> {
        if self.status.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.idle()?; // Do not even poll the power future while inherited scanout lives.
        self.status.state = State::Starting;
        let result = async {
            power.await.map_err(Error::Power)?;
            self.query().await
        }
        .await;
        match result {
            Ok(levels) => {
                self.status.state = State::Ready;
                self.status.levels = Some(levels);
            }
            Err(e) => self.status.state = State::Failed(e),
        }
        result
    }
    async fn query(&mut self) -> Result<Levels, Error> {
        let firmware = self.command(2, 0).await?;
        if firmware == 0 {
            return Err(Error::Invalid);
        }
        let interface = self.command(3, 0).await?;
        if interface != 1 {
            return Err(Error::Interface(interface));
        }
        let header = self.command(4, 0).await?;
        if header != 1 {
            return Err(Error::Interface(header));
        }
        let mut ranges = [Range::default(); 7];
        for (i, clock) in CLOCKS.into_iter().enumerate() {
            let flags = self.command(0xb, (clock as u32) << 16 | 0xff).await?;
            let fine_grained = flags & (1 << 31) != 0;
            let count = if fine_grained {
                2
            } else {
                (flags & 0xff) as usize
            };
            if count == 0
                || count
                    > if clock == Clock::Memory {
                        6
                    } else {
                        LEVEL_COUNT
                    }
            {
                return Err(Error::Invalid);
            }
            let mut range = Range {
                count: count as u8,
                fine_grained,
                flags,
                ..Range::default()
            };
            for index in 0..count {
                let mhz = self
                    .command(0xb, (clock as u32) << 16 | index as u32)
                    .await?
                    & 0xffff;
                if mhz == 0 || (index > 0 && mhz < u32::from(range.mhz[index - 1])) {
                    return Err(Error::Invalid);
                }
                range.mhz[index] = mhz as u16;
            }
            ranges[i] = range;
        }
        // Linux reads these DC-mode maxima and treats one equal to the table
        // maximum as no limit. FCLK and DPPCLK have none on DCN401.
        for (i, clock) in CLOCKS.into_iter().enumerate() {
            if !matches!(
                clock,
                Clock::Dcf | Clock::Soc | Clock::Dtb | Clock::Display | Clock::Memory
            ) {
                continue;
            }
            let mhz = self.command(0xc, (clock as u32) << 16).await? & 0xffff;
            let range = &mut ranges[i];
            if mhz != 0 && mhz < range.max_khz() / 1000 {
                range.dc_limit_mhz = mhz as u16;
            }
        }
        // Linux falls back to VBIOS when PMFW reports none; every bandwidth
        // limit scales with this count, so an unknown count is refused.
        let umc_channels = self.command(0x1c, 0).await?;
        if umc_channels == 0 || umc_channels > 64 {
            return Err(Error::Invalid);
        }
        Ok(Levels {
            umc_channels,
            ranges,
            firmware,
            interface,
            header,
        })
    }
    async fn hard_min(&mut self, clock: Clock, khz: u32) -> Result<u32, Error> {
        let range = *self.status.levels.ok_or(Error::Invalid)?.range(clock);
        // Linux treats a single level as a fixed clock, with no DPM request.
        // The advertised fixed rate already satisfies every admitted request.
        if range.count == 1 {
            return if khz <= range.min_khz() {
                Ok(range.min_khz())
            } else {
                Err(Error::Invalid)
            };
        }
        let mhz = khz.div_ceil(1000);
        if mhz == 0 || mhz > u32::from(u16::MAX) {
            return Err(Error::Invalid);
        }
        let actual = self.command(9, (clock as u32) << 16 | mhz).await?;
        // Mailbox OK only accepts the request. ReturnHardMinStatus acknowledges
        // that this specific PPCLK floor has actually taken effect.
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            let bits = self.command_until(0x15, 0, deadline).await.map_err(|e| {
                if e == Error::Timeout {
                    Error::HardMinTimeout(clock)
                } else {
                    e
                }
            })?;
            if bits & (1 << clock as u32) != 0 {
                break;
            }
            if deadline.expired() {
                return Err(Error::HardMinTimeout(clock));
            }
            delay().await;
        }
        if matches!(clock, Clock::Display | Clock::Dpp | Clock::Dtb) {
            let max = range.max_khz();
            if actual < khz || actual > max {
                return Err(Error::Frequency(clock, actual));
            }
        }
        Ok(actual)
    }
    async fn prepare(&mut self, request: Request) -> Result<Applied, Error> {
        if !matches!(self.status.state, State::Ready | State::Applied) {
            return Err(Error::Busy);
        }
        let levels = self.status.levels.ok_or(Error::Invalid)?;
        if !(1..=4).contains(&request.displays) {
            return Err(Error::Invalid);
        }
        let display = levels.range(Clock::Display).request(request.display_khz)?;
        let dpp = levels.range(Clock::Dpp).request(request.dpp_khz)?;
        let dtb = levels.range(Clock::Dtb).request(request.dtb_khz)?;
        self.idle()?;
        self.status.state = State::Applying;
        let result = async {
            self.command(0xe, u32::from(request.displays)).await?;
            let dcf = levels.range(Clock::Dcf).max_khz();
            let memory = levels.range(Clock::Memory).max_khz();
            self.hard_min(Clock::Dcf, dcf).await?;
            self.hard_min(Clock::Memory, memory).await?;
            if levels.range(Clock::Memory).count > 1 {
                self.command(0x1a, 0).await?; // no UCLK switching during scanout
            }
            // FCLK follows DCFCLK on DCN401; Linux explicitly avoids issuing
            // SetFclkSwitchAllow or an independent FCLK floor on this ASIC.
            let display_khz = self.hard_min(Clock::Display, display).await?;
            let dpp_khz = self.hard_min(Clock::Dpp, dpp).await?;
            let dtb_khz = self.hard_min(Clock::Dtb, dtb).await?;
            Ok(Applied {
                request,
                display_khz,
                dpp_khz,
                dtb_khz,
                dcf_floor_khz: dcf,
                memory_floor_khz: memory,
            })
        }
        .await;
        match result {
            Ok(applied) => {
                self.status.applied = Some(applied);
                self.status.state = State::Applied;
            }
            Err(e) => self.status.state = State::Failed(e),
        }
        result
    }
    /// dcn401_update_clocks while displays run: the bandwidth sequence's
    /// display count (prepare only), then the display sequence. A clock
    /// changes when `should_set_clock`: it rises, or `safe_to_lower` and it
    /// falls. DTBCLK first, then DISPCLK; a lowered DPPCLK (the DPP DTOs'
    /// reference) has its DTOs raised for the new reference before the
    /// reference falls and set again for the actual one after, a raised one
    /// is raised before its DTOs are updated (`dto`, given the reference in
    /// kHz). DENTIST is PMFW's on DCN401. Every consumer register other
    /// than `held` must be idle.
    async fn update_live(
        &mut self,
        request: Request,
        safe_to_lower: bool,
        held: &(dyn Fn(u64) -> bool + Sync),
        dto: &mut (dyn FnMut(u32) -> Result<(), Error> + Send),
    ) -> Result<Applied, Error> {
        if self.status.state != State::Applied {
            return Err(Error::Busy);
        }
        let levels = self.status.levels.ok_or(Error::Invalid)?;
        let current = self.status.applied.ok_or(Error::Invalid)?;
        if !(1..=4).contains(&request.displays) {
            return Err(Error::Invalid);
        }
        let display = levels.range(Clock::Display).request(request.display_khz)?;
        let dpp = levels.range(Clock::Dpp).request(request.dpp_khz)?;
        let dtb = levels.range(Clock::Dtb).request(request.dtb_khz)?;
        self.idle_except(held)?;
        let set = |new: u32, cur: u32| (safe_to_lower && new < cur) || new > cur;
        let mut next = current;
        self.status.state = State::Applying;
        let result = async {
            // CLK_MGR401_UPDATE_NUM_DISPLAYS: sent in prepare while any
            // display stays on.
            if !safe_to_lower {
                self.command(0xe, u32::from(request.displays)).await?;
                next.request.displays = request.displays;
            }
            if set(dtb, current.request.dtb_khz) {
                next.dtb_khz = self.hard_min(Clock::Dtb, dtb).await?;
                next.request.dtb_khz = dtb;
            }
            let update_dpp = set(dpp, current.request.dpp_khz);
            let lowered = update_dpp && dpp < current.request.dpp_khz;
            if set(display, current.request.display_khz) {
                next.display_khz = self.hard_min(Clock::Display, display).await?;
                next.request.display_khz = display;
            }
            if lowered {
                // Increase the DTOs before lowering their reference.
                dto(dpp)?;
                next.dpp_khz = self.hard_min(Clock::Dpp, dpp).await?;
                next.request.dpp_khz = dpp;
                dto(next.dpp_khz)?;
            } else {
                // Raise the reference before updating the DTOs.
                if update_dpp {
                    next.dpp_khz = self.hard_min(Clock::Dpp, dpp).await?;
                    next.request.dpp_khz = dpp;
                }
                dto(next.dpp_khz)?;
            }
            Ok(next)
        }
        .await;
        match result {
            Ok(applied) => {
                self.status.applied = Some(applied);
                self.status.state = State::Applied;
            }
            Err(e) => self.status.state = State::Failed(e),
        }
        result
    }
}
#[derive(Debug)]
pub struct ClockManager(Engine<Mmio>);
impl ClockManager {
    /// # Safety
    /// Own this physical Navi48's DAL mailbox, all display streams/pipes, SMU
    /// and reset/PM transitions exclusively, with permanent register mappings.
    /// Retain this owner after any in-flight failure or cancelled operation.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        authority.invoke(Op(|| ())).map_err(|_| Error::Revoked)?;
        Ok(Self(Engine {
            io: Mmio(gpu.regs),
            authority,
            layout,
            status: Status {
                state: State::Prepared,
                levels: None,
                applied: None,
            },
        }))
    }
    pub fn status(&self) -> Status {
        self.0.status
    }
    /// Only the matching retained DCCG owner may consume these references.
    /// Historical success after a failed/in-flight transition is insufficient.
    pub(crate) fn pipe_clocks(&mut self, regs: MmioRegion) -> Result<Applied, Error> {
        self.pipe_clocks_except(regs, &|_| false)
    }
    /// `pipe_clocks` while other displays of the same display owner run:
    /// `held` names their consumer registers, which that owner verifies.
    pub(crate) fn pipe_clocks_except(
        &mut self,
        regs: MmioRegion,
        held: &dyn Fn(u64) -> bool,
    ) -> Result<Applied, Error> {
        let applied = self.retained_pipe_clocks(regs)?;
        self.0.idle_except(held)?;
        Ok(applied)
    }
    /// Read-only reference for an exclusive display owner with live consumers.
    /// Does not grant clock programming or replace that owner's consumer checks.
    pub(crate) fn retained_pipe_clocks(&mut self, regs: MmioRegion) -> Result<Applied, Error> {
        if regs.phys != self.0.io.0.phys || regs.len != self.0.io.0.len {
            return Err(Error::Invalid);
        }
        if self.0.status.state != State::Applied {
            return Err(Error::Busy);
        }
        self.0.access(|_| Ok(()))?;
        self.0.status.applied.ok_or(Error::Invalid)
    }
    /// # Safety
    /// Matching protected SMU power is ready; all GPU engines are idle and
    /// display consumers retired. Install floors before enabling any stream.
    pub async unsafe fn start(&mut self, smu: &mut smu::Smu) -> Result<Levels, Error> {
        self.0
            .start(async {
                // SAFETY: same physical owner; Engine::start checked all display
                // consumers before polling, and caller excludes live engine work.
                unsafe { smu.enable_display_power().await }
            })
            .await
    }
    /// Set floors with every stream/pipe retired. Refuses inherited display
    /// activity before writes; failures retain partial floors without rollback.
    pub async fn prepare(&mut self, request: Request) -> Result<Applied, Error> {
        self.0.prepare(request).await
    }
    /// Move the floors to `request` while the display owner's displays run
    /// (their consumer registers `held`), in dcn401_update_clocks order:
    /// prepare_bandwidth (`safe_to_lower` false) only raises clocks,
    /// optimize_bandwidth (true) also lowers them. `dto` updates the DPP
    /// DTOs against the DPPCLK reference it is given, at the points Linux
    /// does. Failure or cancellation leaves the owner failed.
    pub(crate) async fn update_live(
        &mut self,
        regs: MmioRegion,
        request: Request,
        safe_to_lower: bool,
        held: &(dyn Fn(u64) -> bool + Sync),
        dto: &mut (dyn FnMut(u32) -> Result<(), Error> + Send),
    ) -> Result<Applied, Error> {
        if regs.phys != self.0.io.0.phys || regs.len != self.0.io.0.len {
            return Err(Error::Invalid);
        }
        self.0.update_live(request, safe_to_lower, held, dto).await
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_clk_tests.rs"]
mod tests;
