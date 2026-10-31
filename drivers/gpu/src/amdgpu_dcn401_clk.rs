//! RDNA4 DAL display clocks, following Linux dcn401_clk_mgr{,_smu_msg}.c,
//! dcn401_smu14_driver_if.h and dalsmc.h. This mailbox is separate from PPSMC.
//! Startup/release require retired consumers; live updates retain the display
//! owner's explicit consumer and DPP DTO coordination.
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
    /// The configuration's deep-sleep DCFCLK (DPMM's deepsleep_dcfclk_khz):
    /// PMFW's SetMinDeepSleepDcfclk floor. Zero leaves it as it is.
    pub deep_sleep_dcfclk_khz: u32,
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
    /// The active UCLK floor: the highest level while UCLK switching is
    /// disallowed, else the configuration's DPMM UCLK.
    pub memory_floor_khz: u32,
    /// SetUclkPstateAllow(1) is in force: PMFW may switch UCLK between the
    /// floor and its maximum while displays run.
    pub uclk_pstate: bool,
}

/// The memory and fabric part of DC's `dc_clocks` that dcn401_update_clocks'
/// bandwidth sequence programs (bw_ctx.bw.dcn.clk as
/// dml21_copy_clocks_to_dc_state fills it from DML21), in kHz.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bandwidth {
    /// p_state_change_support (DML's uclk_pstate_supported).
    pub uclk_pstate: bool,
    /// fclk_p_state_change_support.
    pub fclk_pstate: bool,
    /// dramclk_khz / idle_dramclk_khz: DPMM's active and idle UCLK.
    pub dramclk_khz: u32,
    pub idle_dramclk_khz: u32,
    /// fclk_khz / idle_fclk_khz.
    pub fclk_khz: u32,
    pub idle_fclk_khz: u32,
    /// dcfclk_deep_sleep_khz.
    pub deep_sleep_dcfclk_khz: u32,
}

impl Bandwidth {
    /// dcn401_init_clocks: P-state support set, every clock zero.
    const INIT: Self = Self {
        uclk_pstate: true,
        fclk_pstate: false,
        dramclk_khz: 0,
        idle_dramclk_khz: 0,
        fclk_khz: 0,
        idle_fclk_khz: 0,
        deep_sleep_dcfclk_khz: 0,
    };
    /// A configuration without UCLK or FCLK P-state support: both at the
    /// highest level. `deep_sleep_dcfclk_khz` is left to the caller.
    pub fn pinned(levels: &Levels) -> Self {
        let uclk = levels.range(Clock::Memory).max_khz();
        let fclk = levels.range(Clock::Fabric).max_khz();
        Self {
            uclk_pstate: false,
            fclk_pstate: false,
            dramclk_khz: uclk,
            idle_dramclk_khz: uclk,
            fclk_khz: fclk,
            idle_fclk_khz: fclk,
            deep_sleep_dcfclk_khz: 0,
        }
    }
}

/// khz_to_mhz_ceil.
fn mhz_ceil(khz: u32) -> u32 {
    khz.div_ceil(1000)
}
/// should_set_clock.
fn should_set(safe_to_lower: bool, new: u32, cur: u32) -> bool {
    (safe_to_lower && new < cur) || new > cur
}
/// should_update_pstate_support: support is gained only when lowering
/// clocks is safe, and lost only before programming.
fn should_update_pstate(safe_to_lower: bool, new: bool, cur: bool) -> bool {
    cur != new && ((new && safe_to_lower) || (!new && !safe_to_lower))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub levels: Option<Levels>,
    pub applied: Option<Applied>,
    /// What the bandwidth sequence last programmed (clk_mgr's `clks`).
    pub bandwidth: Bandwidth,
    /// DAL messages PMFW refused or timed out whose result Linux ignores.
    pub ignored: Ignored,
    /// All three watermark-table messages completed without an ignored reply.
    pub watermarks_ready: bool,
    /// The runtime admission replay completed (only with State::Applied).
    /// Subsequent bandwidth/sleep commands require real acknowledgements.
    pub dynamic_power: bool,
    /// Acknowledged SetCabForUclkPstate reservation, retained on failure.
    pub cab_ways: u8,
}
impl Status {
    /// Whether PMFW may switch UCLK under running displays: a bandwidth
    /// sequence this owner ran since its first `prepare` allowed it. Before
    /// that nothing was programmed (`Bandwidth::INIT`'s P-state support is
    /// dcn401_init_clocks' software state, not something PMFW was told), so
    /// a configuration change has nothing to pin, as Linux's first
    /// prepare_bandwidth has nothing to fail on.
    pub fn uclk_switching(&self) -> bool {
        self.applied.is_some() && self.bandwidth.uclk_pstate
    }
}
/// The bandwidth sequence's, NumOfDisplays' and the watermark notify's DAL
/// messages are dcn401_smu_* helpers whose result dcn401's clock manager
/// never reads: PMFW's refusal of a sent message (or an unacknowledged
/// ActiveUclkFclk/IdleUclkFclk/UCLK floor) is logged and counted here, and
/// the sequence goes on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ignored {
    pub count: u32,
    /// The last one: its message and why.
    pub last: Option<(u32, Error)>,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Layout {
    mp1: u64,
    dccg: u64,
    dio: u64,
    hpo: u64,
    /// The display resource pool: a fused pipe's OTG is no idle witness.
    pool: crate::amdgpu_rdna4::PipePool,
    /// The die, for dcn401_is_ppclk_idle_dpm_enabled's PMFW versions.
    chip: Option<crate::amdgpu_rdna4::Rdna4Chip>,
}
impl Layout {
    pub(crate) fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        let chip = crate::amdgpu_rdna4::Rdna4Chip::of(gpu);
        if chip.is_none() {
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
            chip,
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
    /// Read-driven register models can use a bounded number of cooperative
    /// polls instead of a wall-clock deadline. Real MMIO always uses time.
    #[cfg(feature = "kernel-test")]
    fn wait_poll_limit(&self) -> Option<u32> {
        None
    }
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
    /// Only an ignored-result message that we actually sent may leave an
    /// unanswered transaction reusable. Linux waits, then replaces it on the
    /// next send; an unknown inherited busy mailbox must still fail closed.
    unanswered_ignored: bool,
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
    async fn reserve_cab(&mut self, ways: u8) -> Result<(), Error> {
        if ways > 16 {
            return Err(Error::Invalid);
        }
        if self.status.state != State::Applied
            || !self.status.dynamic_power
            || self.status.bandwidth.uclk_pstate
        {
            return Err(Error::Busy);
        }
        self.access(|_| Ok(()))?;
        if ways == self.status.cab_ways {
            return Ok(());
        }
        self.status.state = State::Applying;
        match self
            .command(0x12, u32::from(ways) << 1 | u32::from(ways != 0))
            .await
        {
            Ok(_) => {
                self.status.cab_ways = ways;
                self.status.state = State::Applied;
                Ok(())
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    async fn settled(&mut self, deadline: narf_time::Deadline) -> Result<u32, Error> {
        let at = self.layout.mp1 + u64::from(RESPONSE) * 4;
        #[cfg(feature = "kernel-test")]
        let mut polls = self.io.wait_poll_limit();
        loop {
            let value = self.access(|io| checked(io.read(at)))?;
            if value != 0 {
                return Ok(value);
            }
            #[cfg(feature = "kernel-test")]
            if let Some(left) = &mut polls {
                if *left == 0 {
                    return Err(Error::Timeout);
                }
                *left -= 1;
                narf_scheduler::yield_now().await;
                continue;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay().await;
        }
    }
    async fn send_until(
        &mut self,
        message: u32,
        parameter: u32,
        deadline: narf_time::Deadline,
    ) -> Result<(), Error> {
        // dcn401_smu_send_msg_with_param only waits for a nonzero response
        // (whatever an earlier message, this owner's or not, left there, a
        // refusal included) and then sends. Linux also sends after a timeout.
        // Permit that only for a known unanswered ignored-result transaction,
        // never an inherited busy mailbox or an interrupted required result.
        match self.settled(deadline).await {
            Ok(_) if !deadline.expired() => {}
            Ok(_) | Err(Error::Timeout) if self.unanswered_ignored => {}
            Ok(_) => return Err(Error::Timeout),
            Err(e) => return Err(e),
        }
        let base = self.layout.mp1;
        self.access(|io| {
            io.write(base + u64::from(RESPONSE) * 4, 0);
            io.write(base + u64::from(ARGUMENT) * 4, parameter);
            io.write(base + u64::from(MESSAGE) * 4, message);
            Ok(())
        })?;
        self.unanswered_ignored = false;
        Ok(())
    }
    async fn response_until(&mut self, deadline: narf_time::Deadline) -> Result<u32, Error> {
        let result = self.settled(deadline).await?;
        if result != 1 {
            return Err(Error::Rejected(result));
        }
        let at = self.layout.mp1 + u64::from(ARGUMENT) * 4;
        self.access(|io| checked(io.read(at)))
    }
    async fn command_until(
        &mut self,
        message: u32,
        parameter: u32,
        deadline: narf_time::Deadline,
    ) -> Result<u32, Error> {
        self.send_until(message, parameter, deadline).await?;
        self.response_until(deadline).await
    }
    async fn command(&mut self, message: u32, parameter: u32) -> Result<u32, Error> {
        self.send_until(message, parameter, narf_time::Deadline::after_ms(2000))
            .await?;
        self.response_until(narf_time::Deadline::after_ms(2000))
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
        #[cfg(feature = "kernel-test")]
        let mut polls = self.io.wait_poll_limit();
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
            #[cfg(feature = "kernel-test")]
            if let Some(left) = &mut polls {
                if *left == 0 {
                    return Err(Error::HardMinTimeout(clock));
                }
                *left -= 1;
                narf_scheduler::yield_now().await;
                continue;
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
    /// dcn401_is_ppclk_idle_dpm_enabled for both UCLK and FCLK, with their
    /// DPM (more than one level): PMFW then takes separate active and idle
    /// UCLK/FCLK floors (ActiveUclkFclk, IdleUclkFclk) instead of a UCLK
    /// hard minimum.
    fn idle_dpm(&self, levels: &Levels) -> bool {
        let dpm = |c: Clock| levels.range(c).count > 1;
        dpm(Clock::Memory)
            && dpm(Clock::Fabric)
            && self
                .layout
                .chip
                .is_some_and(|chip| levels.firmware >= chip.idle_dpm_min_smu())
    }
    /// dcn401_smu_send_msg_with_param where the caller ignores the result:
    /// PMFW's refusal of the sent message is recorded (`Status::ignored`)
    /// and logged, as is a post-write timeout. The next send may replace that
    /// known unanswered transaction after its bounded readiness wait, as in
    /// Linux. A pre-write failure and revoked/removed authority still fail;
    /// an unsent message is never counted as ignored.
    async fn optional_result(
        &mut self,
        message: u32,
        parameter: u32,
    ) -> Result<Result<u32, Error>, Error> {
        self.send_until(message, parameter, narf_time::Deadline::after_ms(2000))
            .await?;
        match self
            .response_until(narf_time::Deadline::after_ms(2000))
            .await
        {
            Ok(value) => Ok(Ok(value)),
            Err(e @ (Error::Rejected(_) | Error::Timeout)) => {
                self.unanswered_ignored = e == Error::Timeout;
                Ok(Err(e))
            }
            Err(e) => Err(e),
        }
    }
    async fn command_ignored(&mut self, message: u32, parameter: u32) -> Result<(), Error> {
        if self.status.dynamic_power {
            return self.command(message, parameter).await.map(|_| ());
        }
        if let Err(e) = self.optional_result(message, parameter).await? {
            self.ignore(message, e);
        }
        Ok(())
    }
    fn ignore(&mut self, message: u32, error: Error) {
        let i = &mut self.status.ignored;
        i.count = i.count.saturating_add(1);
        i.last = Some((message, error));
        let _ = core::fmt::Write::write_fmt(
            &mut narf_console::Writer,
            format_args!("amdgpu: dcn401 DAL message {message:#x} not honoured: {error:?}\n"),
        );
    }
    /// dcn401_smu_wait_hard_min_status after a floor whose result Linux
    /// ignores: ReturnHardMinStatus until `clock` is acknowledged, for at
    /// most one second (a refused status reads as no bits); no
    /// acknowledgement is recorded and logged as ignored.
    async fn hard_min_settled_ignored(&mut self, message: u32, clock: Clock) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(1000);
        #[cfg(feature = "kernel-test")]
        let mut polls = self.io.wait_poll_limit();
        loop {
            let bits = match if self.status.dynamic_power {
                Ok(self.command_until(0x15, 0, deadline).await.map_err(|e| {
                    if e == Error::Timeout {
                        Error::HardMinTimeout(clock)
                    } else {
                        e
                    }
                })?)
            } else {
                self.optional_result(0x15, 0).await?
            } {
                Ok(bits) => bits,
                Err(Error::Timeout) => {
                    // The result of the floor's acknowledgement is unread by
                    // the clock manager as well. A status request was sent:
                    // keep that fact so the following void step can proceed.
                    self.ignore(message, Error::HardMinTimeout(clock));
                    return Ok(());
                }
                Err(Error::Rejected(_)) => 0,
                Err(e) => return Err(e),
            };
            if bits & (1 << clock as u32) != 0 {
                return Ok(());
            }
            #[cfg(feature = "kernel-test")]
            if let Some(left) = &mut polls {
                if *left == 0 {
                    if self.status.dynamic_power {
                        return Err(Error::HardMinTimeout(clock));
                    }
                    self.ignore(message, Error::HardMinTimeout(clock));
                    return Ok(());
                }
                *left -= 1;
                narf_scheduler::yield_now().await;
                continue;
            }
            if deadline.expired() {
                if self.status.dynamic_power {
                    return Err(Error::HardMinTimeout(clock));
                }
                self.ignore(message, Error::HardMinTimeout(clock));
                return Ok(());
            }
            delay().await;
        }
    }
    /// The UCLK/FCLK and deep-sleep DCFCLK steps of
    /// dcn401_build_update_bandwidth_clocks_sequence towards `new`, from
    /// the last programmed `status.bandwidth` (`planes`: the configuration
    /// scans planes out). With no firmware-assisted method in use, FAMS
    /// (SetAlwaysWaitDmcubResp, IndicateDrrStatus) and the SubVP/CAB
    /// steps never run. Returns what is now programmed and the active UCLK
    /// floor in kHz; `status.bandwidth` is the caller's to store.
    async fn bandwidth(
        &mut self,
        new: Bandwidth,
        safe_to_lower: bool,
        planes: bool,
    ) -> Result<(Bandwidth, u32), Error> {
        let levels = self.status.levels.ok_or(Error::Invalid)?;
        let dpm = |c: Clock| levels.range(c).count > 1;
        let idle_dpm = self.idle_dpm(&levels);
        let cur = self.status.bandwidth;
        let mut next = cur;
        let mut active_uclk = mhz_ceil(cur.dramclk_khz);
        let mut active_fclk = mhz_ceil(cur.fclk_khz);
        let mut idle_uclk = mhz_ceil(cur.idle_dramclk_khz);
        let mut idle_fclk = mhz_ceil(cur.idle_fclk_khz);
        let (mut uclk_active, mut uclk_idle) = (false, false);
        let (mut fclk_active, mut fclk_idle) = (false, false);
        // FCLK P-state support: DCN401 has no FCLK switch message.
        let fclk = (new.fclk_pstate && (!self.status.dynamic_power || idle_dpm)) || !planes;
        if should_update_pstate(safe_to_lower, fclk, cur.fclk_pstate) {
            next.fclk_pstate = fclk;
            fclk_active = true;
            fclk_idle = true;
        }
        if !next.fclk_pstate && dpm(Clock::Fabric) {
            active_fclk = levels.range(Clock::Fabric).max_khz() / 1000;
            idle_fclk = active_fclk;
        }
        // CLK_MGR401_UPDATE_DEEP_SLEEP_DCFCLK (zero: no plan says it, except
        // for a configuration without planes, whose DML21 minimum is zero).
        if (new.deep_sleep_dcfclk_khz != 0 || !planes)
            && should_set(
                safe_to_lower,
                new.deep_sleep_dcfclk_khz,
                cur.deep_sleep_dcfclk_khz,
            )
        {
            next.deep_sleep_dcfclk_khz = new.deep_sleep_dcfclk_khz;
            if dpm(Clock::Dcf) {
                self.command_ignored(0xd, mhz_ceil(next.deep_sleep_dcfclk_khz))
                    .await?;
            }
        }
        // UCLK P-state support: allowed before the new floors, disallowed
        // after them.
        let uclk = new.uclk_pstate || !planes;
        let disallow = !uclk && should_update_pstate(safe_to_lower, uclk, cur.uclk_pstate);
        if should_update_pstate(safe_to_lower, uclk, cur.uclk_pstate) {
            next.uclk_pstate = uclk;
            uclk_active = true;
            uclk_idle = true;
            if next.uclk_pstate && dpm(Clock::Memory) {
                self.command_ignored(0x1a, 1).await?;
            }
        }
        if !next.uclk_pstate && dpm(Clock::Memory) {
            active_uclk = levels.range(Clock::Memory).max_khz() / 1000;
            idle_uclk = active_uclk;
        }
        if should_set(safe_to_lower, new.dramclk_khz, cur.dramclk_khz) {
            next.dramclk_khz = new.dramclk_khz;
            if next.uclk_pstate {
                uclk_active = true;
                active_uclk = mhz_ceil(next.dramclk_khz);
            }
        }
        if should_set(safe_to_lower, new.idle_dramclk_khz, cur.idle_dramclk_khz) {
            next.idle_dramclk_khz = new.idle_dramclk_khz;
            if next.uclk_pstate {
                uclk_idle = true;
                idle_uclk = mhz_ceil(next.idle_dramclk_khz);
            }
        }
        if should_set(safe_to_lower, new.fclk_khz, cur.fclk_khz) {
            next.fclk_khz = new.fclk_khz;
            if next.fclk_pstate {
                fclk_active = true;
                active_fclk = mhz_ceil(next.fclk_khz);
            }
        }
        if should_set(safe_to_lower, new.idle_fclk_khz, cur.idle_fclk_khz) {
            next.idle_fclk_khz = new.idle_fclk_khz;
            if next.fclk_pstate {
                fclk_idle = true;
                idle_fclk = mhz_ceil(next.idle_fclk_khz);
            }
        }
        let pair = |uclk: u32, fclk: u32| -> Result<u32, Error> {
            if uclk > u32::from(u16::MAX) || fclk > u32::from(u16::MAX) {
                return Err(Error::Invalid);
            }
            Ok(fclk << 16 | uclk)
        };
        // CLK_MGR401_UPDATE_ACTIVE_HARDMINS / _IDLE_HARDMINS, each waiting
        // for the UCLK floor's acknowledgement.
        if (uclk_active || fclk_active) && idle_dpm {
            self.command_ignored(0x18, pair(active_uclk, active_fclk)?)
                .await?;
            self.hard_min_settled_ignored(0x18, Clock::Memory).await?;
        }
        if (uclk_idle || fclk_idle) && idle_dpm {
            self.command_ignored(0x19, pair(idle_uclk, idle_fclk)?)
                .await?;
            self.hard_min_settled_ignored(0x19, Clock::Memory).await?;
        }
        if uclk_active || uclk_idle {
            // CLK_MGR401_UPDATE_HARDMIN_PPCLK for UCLK, its response unread.
            if !idle_dpm && dpm(Clock::Memory) {
                if active_uclk == 0 || active_uclk > u32::from(u16::MAX) {
                    return Err(Error::Invalid);
                }
                self.command_ignored(9, (Clock::Memory as u32) << 16 | active_uclk)
                    .await?;
                self.hard_min_settled_ignored(9, Clock::Memory).await?;
            }
            if disallow && dpm(Clock::Memory) {
                self.command_ignored(0x1a, 0).await?;
            }
        }
        let floor = if next.uclk_pstate {
            mhz_ceil(next.dramclk_khz) * 1000
        } else {
            levels.range(Clock::Memory).max_khz()
        };
        if self.status.dynamic_power && planes && !next.fclk_pstate {
            next.fclk_khz = levels.range(Clock::Fabric).max_khz();
            next.idle_fclk_khz = next.fclk_khz;
        }
        Ok((next, floor))
    }
    /// The bandwidth sequence towards `new` while the display owner's
    /// displays run (their consumer registers `held`): prepare_bandwidth
    /// (`safe_to_lower` false) only raises floors and disallows UCLK
    /// switching, optimize_bandwidth (true) lowers them and allows it.
    async fn update_bandwidth(
        &mut self,
        new: Bandwidth,
        safe_to_lower: bool,
        held: &(dyn Fn(u64) -> bool + Sync),
    ) -> Result<Applied, Error> {
        if self.status.state != State::Applied {
            return Err(Error::Busy);
        }
        let current = self.status.applied.ok_or(Error::Invalid)?;
        if self.status.dynamic_power {
            let levels = self.status.levels.ok_or(Error::Invalid)?;
            for (clock, active, idle) in [
                (Clock::Memory, new.dramclk_khz, new.idle_dramclk_khz),
                (Clock::Fabric, new.fclk_khz, new.idle_fclk_khz),
            ] {
                if active == 0 || active > levels.range(clock).max_khz() || idle > active {
                    return Err(Error::Invalid);
                }
            }
            if new.deep_sleep_dcfclk_khz > levels.range(Clock::Dcf).max_khz() {
                return Err(Error::Invalid);
            }
        }
        self.idle_except(held)?;
        self.status.state = State::Applying;
        let result = self.bandwidth(new, safe_to_lower, true).await;
        match result {
            Ok((bandwidth, floor)) => {
                self.status.bandwidth = bandwidth;
                let applied = Applied {
                    memory_floor_khz: floor,
                    uclk_pstate: bandwidth.uclk_pstate,
                    ..current
                };
                self.status.applied = Some(applied);
                self.status.state = State::Applied;
                Ok(applied)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// dcn401_update_clocks in optimize_bandwidth (`safe_to_lower`) once no
    /// stream is left (dc_commit_streams with none, as the last CRTC's
    /// disable and dm_suspend's commit run it), towards the clocks
    /// dml21_init_min_clocks_for_dc_state gives a context without streams:
    /// NumOfDisplays(0) (enter_display_off, sent only when safe to lower),
    /// the DCFCLK hard minimum at its lowest level, then the bandwidth
    /// sequence without planes (UCLK and FCLK P-state support set, as
    /// total_plane_count == 0 forces: the deep-sleep DCFCLK zero, switching
    /// allowed, the active UCLK/FCLK floors at their lowest levels and the
    /// idle ones zero), then the display clock sequence: DTBCLK, DISPCLK,
    /// DPPCLK at their first levels. No DTO update is needed without streams.
    /// The bandwidth results are unread; display rates must be acknowledged.
    /// Every consumer must be retired. Nothing when nothing was applied or
    /// it already ran.
    async fn release(&mut self) -> Result<Applied, Error> {
        let current = match (self.status.state, self.status.applied) {
            (State::Applied, Some(a)) => a,
            (State::Applied, None) => return Err(Error::Invalid),
            _ => return Err(Error::Busy),
        };
        if current.request.displays == 0 {
            return Ok(current);
        }
        let levels = self.status.levels.ok_or(Error::Invalid)?;
        self.idle()?;
        self.status.state = State::Applying;
        let result = async {
            self.command_ignored(0xe, 0).await?;
            let dcf = levels.range(Clock::Dcf);
            if should_set(true, dcf.min_khz(), current.dcf_floor_khz) && dcf.count > 1 {
                let mhz = mhz_ceil(dcf.min_khz());
                self.command_ignored(9, (Clock::Dcf as u32) << 16 | mhz)
                    .await?;
                self.hard_min_settled_ignored(9, Clock::Dcf).await?;
            }
            let memory = levels.range(Clock::Memory);
            let fabric = levels.range(Clock::Fabric);
            if self.status.dynamic_power && !self.idle_dpm(&levels) {
                self.hard_min(Clock::Fabric, fabric.min_khz()).await?;
            }
            let none = Bandwidth {
                uclk_pstate: true,
                fclk_pstate: true,
                dramclk_khz: memory.min_khz(),
                idle_dramclk_khz: 0,
                fclk_khz: fabric.min_khz(),
                idle_fclk_khz: 0,
                deep_sleep_dcfclk_khz: 0,
            };
            let (bandwidth, floor) = self.bandwidth(none, true, false).await?;
            self.status.bandwidth = bandwidth;
            let mut next = current;
            // dcn401_build_update_display_clocks_sequence with dtbclk_en
            // false and dml21_init_min_clocks_for_dc_state's first levels.
            // With every consumer retired the DTO/dentist steps have no live
            // pipe to update. Preserve the actual frequencies PMFW returns.
            for (clock, requested, actual) in [
                (Clock::Dtb, &mut next.request.dtb_khz, &mut next.dtb_khz),
                (
                    Clock::Display,
                    &mut next.request.display_khz,
                    &mut next.display_khz,
                ),
                (Clock::Dpp, &mut next.request.dpp_khz, &mut next.dpp_khz),
            ] {
                let minimum = levels.range(clock).min_khz();
                if should_set(true, minimum, *requested) {
                    *actual = self.hard_min(clock, minimum).await?;
                    *requested = minimum;
                }
            }
            Ok(Applied {
                request: Request {
                    displays: 0,
                    deep_sleep_dcfclk_khz: 0,
                    ..next.request
                },
                dcf_floor_khz: dcf.min_khz().min(current.dcf_floor_khz),
                memory_floor_khz: floor,
                uclk_pstate: bandwidth.uclk_pstate,
                ..next
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
    /// dcn401_notify_wm_ranges: tell PMFW where the WatermarksExternal_t
    /// table is (SetDalDramAddrHigh/Low) and have it read it
    /// (TransferTableDram2Smu, TABLE_WATERMARKS).
    async fn notify_wm_ranges(&mut self, address: u64) -> Result<(), Error> {
        if !matches!(self.status.state, State::Ready | State::Applied) {
            return Err(Error::Busy);
        }
        let previous = self.status.state;
        self.status.watermarks_ready = false;
        self.status.state = State::Applying;
        // dcn401_smu_set_dram_addr_high/low and
        // dcn401_smu_transfer_wm_table_dram_2_smu return nothing. Retain the
        // applying state on cancellation so a partial mailbox is not reused.
        let mut accepted = true;
        let result = async {
            for (message, parameter) in [(5, (address >> 32) as u32), (6, address as u32), (8, 2)] {
                if self.status.dynamic_power {
                    self.command(message, parameter).await?;
                } else if let Err(error) = self.optional_result(message, parameter).await? {
                    accepted = false;
                    self.ignore(message, error);
                }
            }
            Ok(())
        }
        .await;
        self.status.state = match result {
            Ok(()) => previous,
            Err(e) => State::Failed(e),
        };
        self.status.watermarks_ready = result.is_ok() && accepted && !self.unanswered_ignored;
        result
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
            // dcn401_smu_set_num_of_displays: its result is never read.
            self.command_ignored(0xe, u32::from(request.displays))
                .await?;
            let dcf = levels.range(Clock::Dcf).max_khz();
            self.hard_min(Clock::Dcf, dcf).await?;
            // The bandwidth sequence's UCLK and FCLK part for a pinned
            // configuration: both at their highest level and UCLK
            // switching disallowed (prepare_bandwidth before any scanout).
            let pinned = Bandwidth {
                deep_sleep_dcfclk_khz: request.deep_sleep_dcfclk_khz,
                ..Bandwidth::pinned(&levels)
            };
            let (bandwidth, memory) = self.bandwidth(pinned, false, true).await?;
            self.status.bandwidth = bandwidth;
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
                uclk_pstate: bandwidth.uclk_pstate,
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
                self.command_ignored(0xe, u32::from(request.displays))
                    .await?;
                next.request.displays = request.displays;
            }
            // CLK_MGR401_UPDATE_DEEP_SLEEP_DCFCLK (a zero request keeps it).
            let ds = self.status.bandwidth.deep_sleep_dcfclk_khz;
            if request.deep_sleep_dcfclk_khz != 0
                && should_set(safe_to_lower, request.deep_sleep_dcfclk_khz, ds)
            {
                if levels.range(Clock::Dcf).count > 1 {
                    // dcn401_smu_set_min_deep_sleep_dcef_clk returns nothing.
                    self.command_ignored(0xd, mhz_ceil(request.deep_sleep_dcfclk_khz))
                        .await?;
                }
                self.status.bandwidth.deep_sleep_dcfclk_khz = request.deep_sleep_dcfclk_khz;
                next.request.deep_sleep_dcfclk_khz = request.deep_sleep_dcfclk_khz;
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
            unanswered_ignored: false,
            status: Status {
                state: State::Prepared,
                levels: None,
                applied: None,
                bandwidth: Bandwidth::INIT,
                ignored: Ignored::default(),
                watermarks_ready: false,
                dynamic_power: false,
                cab_ways: 0,
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
    /// Reserve/release SubVP cache ways with UCLK switching pinned. A
    /// cancelled request leaves the mailbox owner Applying; no release is
    /// inferred without the firmware acknowledgement.
    pub(crate) async fn reserve_cab(&mut self, regs: MmioRegion, ways: u8) -> Result<(), Error> {
        self.retained_pipe_clocks(regs)?;
        self.0.reserve_cab(ways).await
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
    /// Move the UCLK/FCLK P-state policy and floors (and the deep-sleep
    /// DCFCLK) to `bandwidth` while the display owner's displays run, as
    /// dcn401_update_clocks' bandwidth sequence: `safe_to_lower` false
    /// (prepare_bandwidth) raises and disallows, true (optimize_bandwidth)
    /// lowers and allows. Display clocks are unchanged. Failure or
    /// cancellation leaves the owner failed.
    pub(crate) async fn update_bandwidth(
        &mut self,
        regs: MmioRegion,
        bandwidth: Bandwidth,
        safe_to_lower: bool,
        held: &(dyn Fn(u64) -> bool + Sync),
    ) -> Result<Applied, Error> {
        if regs.phys != self.0.io.0.phys || regs.len != self.0.io.0.len {
            return Err(Error::Invalid);
        }
        self.0
            .update_bandwidth(bandwidth, safe_to_lower, held)
            .await
    }
    /// dcn401_update_clocks' optimize once no stream is left (`Engine::
    /// release`): NumOfDisplays(0), DCFCLK at its lowest level, UCLK
    /// switching allowed with UCLK and FCLK at their lowest, then DTBCLK,
    /// DISPCLK and DPPCLK at their first levels. Every consumer must be
    /// retired. Failure or cancellation leaves the owner unusable.
    pub(crate) async fn release(&mut self, regs: MmioRegion) -> Result<Applied, Error> {
        if regs.phys != self.0.io.0.phys || regs.len != self.0.io.0.len {
            return Err(Error::Invalid);
        }
        self.0.release().await
    }
    /// dcn401_build_wm_range_table as PMFW's `WatermarksExternal_t`: set A
    /// (WATERMARKS_CLOCK_RANGE) and set 1A, the dummy P-state set
    /// (WATERMARKS_DUMMY_PSTATE); sets B and 1B are unused on DCN4.
    pub fn wm_range_table() -> [u8; WM_TABLE_BYTES] {
        let mut t = [0u8; WM_TABLE_BYTES];
        // WatermarkRow[WM_A] = { WmSetting 0, Flags CLOCK_RANGE }, and
        // WatermarkRow[WM_1A] = { WmSetting 2, Flags DUMMY_PSTATE }.
        t[8] = 2;
        t[9] = 1;
        t
    }
    /// Send the watermark range table PMFW reads at `address` (the GPU
    /// address of [`Self::wm_range_table`]'s bytes, written and flushed by
    /// the caller), as dcn401_init_hw does once the clocks are known. Firmware
    /// refusals/timeouts are recorded; authority errors or cancellation leave
    /// the retained owner unusable.
    pub(crate) async fn notify_wm_ranges(
        &mut self,
        regs: MmioRegion,
        address: u64,
    ) -> Result<(), Error> {
        if regs.phys != self.0.io.0.phys || regs.len != self.0.io.0.len {
            return Err(Error::Invalid);
        }
        self.0.notify_wm_ranges(address).await
    }
}

/// sizeof(WatermarksExternal_t).
pub const WM_TABLE_BYTES: usize = 112;
#[path = "amdgpu_dcn401_power.rs"]
mod power;
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_clk_tests.rs"]
mod tests;
