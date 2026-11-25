//! Navi31 / Navi32 (DCN 3.2.0) and Navi33 (DCN 3.2.1) display clock manager.
//! The display clock interface is a mailbox on MP1 that is distinct from the
//! GFX SMU's own message space, and its message ids are the DALSMC set, not
//! PPSMC. Protocol and offsets: Linux `dcn32_clk_mgr_smu_msg.c`, `dalsmc.h`,
//! `dcn32_clk_mgr.c` and `dcn32_smu13_driver_if.h` (SMU 13.0.0).
//!
//! The DALSMC protocol is the same one the DCN 3.0 owner
//! ([`crate::amdgpu_dcn30_clk`]) implements for Navi22, and this module
//! reuses its transport shape (wait for a nonzero response, clear it, write
//! argument then message id, wait for `DALSMC_Result_OK`): the message
//! registers are the same absolute MP1 addresses (MSG 0x1628A, ARG 0x16273,
//! RESP 0x16274) and the wait is the same 10 us x 200000. What differs on
//! 3.2 is the clock set and its limits:
//! - PPCLK ids are SMU 13.0.0's (`dcn32_smu13_driver_if.h`): DISPCLK 8,
//!   DPPCLK 9, DCFCLK 11, DTBCLK 12, SOCCLK 1, UCLK 2, FCLK 3 — not
//!   Navi22's numbering, where DCFCLK is 8 and DISPCLK 9;
//! - DISPCLK and DPPCLK are capped at 1950 MHz, in the DPM table and in the
//!   DC-mode limit (`dcn32_clk_mgr.c`);
//! - the DTBCLK floor is a display-owned floor (`SetHardMinByFreq` on
//!   PPCLK_DTBCLK with the reference DTBCLK), and UCLK gets a hard min as
//!   well as a hard max;
//! - the driver-interface version is 0x18 (`SMU13_DRIVER_IF_VERSION`);
//! - the watermark table is transferred to the SMU
//!   (`TransferTableDram2Smu`, TABLE_WATERMARKS) from a caller-staged DRAM
//!   address — the table contents come from the DML32 watermark
//!   computation, so staging them is the caller's job.
//!
//! The DENTIST VCO is the DML bounding box's
//! `dispclk_dppclk_vco_speed_mhz` (4300 MHz, `dcn3_2_soc`): Linux reads it
//! from CLK0/CLK1_CLK_PLL_REQ (`dcn32_get_vco_frequency_from_reg`), but the
//! FbMult int/frac masks that decode lives in a header the sparse Linux
//! reference tree does not carry, so the register decode is a remainder for
//! silicon validation and the PLL-req register is read only for the
//! device-gone check.
use crate::{
    amdgpu::AmdGpu, amdgpu_dcn32_dccg::Dccg32, amdgpu_dcn_clk::Error, amdgpu_dcn_profile::Profile,
};
use core::future::Future;
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// linux: n/a (mmDAL_MSG_REG 0x1628A, local in dcn32_clk_mgr_smu_msg.c, minus MP1 seg0 0x16000)
const MESSAGE: u32 = 0x28a;
// linux: n/a (mmDAL_ARG_REG 0x16273, local in dcn32_clk_mgr_smu_msg.c, minus MP1 seg0 0x16000)
const ARGUMENT: u32 = 0x273;
// linux: n/a (mmDAL_RESP_REG 0x16274, local in dcn32_clk_mgr_smu_msg.c, minus MP1 seg0 0x16000)
const RESPONSE: u32 = 0x274;
// CLK0_CLK_PLL_REQ, absolute; the FbMult decode is a remainder (see above).
// linux: n/a (mmCLK0_CLK_PLL_REQ 0x17010, absolute, local in dcn32_clk_mgr.c)
const PLL: u32 = 0x17010;
const GET_VERSION: u32 = 2; // linux: DALSMC_MSG_GetSmuVersion
const GET_INTERFACE: u32 = 3; // linux: DALSMC_MSG_GetDriverIfVersion
const GET_HEADER: u32 = 4; // linux: DALSMC_MSG_GetMsgHeaderVersion
const SET_DRAM_ADDR_HIGH: u32 = 5; // linux: DALSMC_MSG_SetDalDramAddrHigh
const SET_DRAM_ADDR_LOW: u32 = 6; // linux: DALSMC_MSG_SetDalDramAddrLow
const TRANSFER_TABLE_DRAM2SMU: u32 = 8; // linux: DALSMC_MSG_TransferTableDram2Smu
const HARD_MIN: u32 = 9; // linux: DALSMC_MSG_SetHardMinByFreq
const HARD_MAX: u32 = 0xa; // linux: DALSMC_MSG_SetHardMaxByFreq
const DPM_BY_INDEX: u32 = 0xb; // linux: DALSMC_MSG_GetDpmFreqByIndex
const DC_MODE_MAX: u32 = 0xc; // linux: DALSMC_MSG_GetDcModeMaxDpmFreq
const DEEP_SLEEP_MIN: u32 = 0xd; // linux: DALSMC_MSG_SetMinDeepSleepDcefclk
const DISPLAYS: u32 = 0xe; // linux: DALSMC_MSG_NumOfDisplays
const SET_FCLK_SWITCH_ALLOW: u32 = 0x11; // linux: DALSMC_MSG_SetFclkSwitchAllow
const RETURN_HARD_MIN_STATUS: u32 = 0x15; // linux: DALSMC_MSG_ReturnHardMinStatus
/// `SMU13_DRIVER_IF_VERSION` for SMU 13.0.0.
const DRIVER_IF_VERSION: u32 = 0x18;
/// `TABLE_WATERMARKS` (`dcn32_smu13_driver_if.h`).
const TABLE_WATERMARKS: u32 = 2;
/// `dcn32_clk_mgr.c`: DISPCLK/DPPCLK are capped at 1950 MHz.
const DISP_DPP_MAX_MHZ: u32 = 1950;
// linux: n/a (NARF table bound; Linux clk_table holds MAX_NUM_DPM_LVL = 8)
const LEVELS: usize = 16;

/// PPCLK ids in the DAL interface, SMU 13.0.0 (`dcn32_smu13_driver_if.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Clock {
    Soc = 1,     // linux: PPCLK_SOCCLK
    Memory = 2,  // linux: PPCLK_UCLK
    Fabric = 3,  // linux: PPCLK_FCLK
    Display = 8, // linux: PPCLK_DISPCLK
    Pixel = 9,   // linux: PPCLK_DPPCLK
    Phy = 10,    // linux: PPCLK_DPREFCLK
    Dcf = 11,    // linux: PPCLK_DCFCLK
    Dtbclk = 12, // linux: PPCLK_DTBCLK
}
const CLOCKS: [Clock; 8] = [
    Clock::Soc,
    Clock::Memory,
    Clock::Fabric,
    Clock::Display,
    Clock::Pixel,
    Clock::Phy,
    Clock::Dcf,
    Clock::Dtbclk,
];
/// `CHECK_HARD_MIN_CLK_*` bits (`dalsmc.h`), for [`ClockManager::hard_min_status`].
impl Clock {
    pub const fn hard_min_bit(self) -> u32 {
        match self {
            Clock::Display => 0x1, // linux: CHECK_HARD_MIN_CLK_DISPCLK
            Clock::Pixel => 0x2,   // linux: CHECK_HARD_MIN_CLK_DPPCLK
            Clock::Phy => 0x4,     // linux: CHECK_HARD_MIN_CLK_DPREFCLK
            Clock::Dcf => 0x8,     // linux: CHECK_HARD_MIN_CLK_DCFCLK
            Clock::Dtbclk => 0x10, // linux: CHECK_HARD_MIN_CLK_DTBCLK
            Clock::Memory => 0x20, // linux: CHECK_HARD_MIN_CLK_UCLK
            Clock::Soc | Clock::Fabric => 0,
        }
    }
}

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
    ranges: [Range; 8],
    /// DC-mode maximum per clock, MHz (`GetDcModeMaxDpmFreq`).
    dc_mode_max_mhz: [u16; 8],
    pub firmware: u32,
    pub interface: u32,
    pub header: u32,
    pub vco_khz: u32,
}
impl Levels {
    pub fn range(&self, clock: Clock) -> &Range {
        &self.ranges[CLOCKS.iter().position(|c| *c == clock).unwrap()]
    }
    /// The DC-mode maximum for `clock`, in kHz (0 when PMFW reported none).
    pub fn dc_mode_max_khz(&self, clock: Clock) -> u32 {
        u32::from(self.dc_mode_max_mhz[CLOCKS.iter().position(|c| *c == clock).unwrap()]) * 1000
    }
    /// Highest representable DISP/DPP clocks within the board limits. The
    /// divider is rounded toward a lower frequency here, never above the SKU.
    pub fn ceiling(&self, clock: Clock) -> Result<u32, Error> {
        if !matches!(clock, Clock::Display | Clock::Pixel) {
            return Err(Error::Invalid);
        }
        let max = self.range(clock).max_khz();
        (8..=127) // linux-lit: 8=DENTIST_BASE_DID_1; 127=DENTIST_MAX_DID
            .map(|did| frequency(self.vco_khz, did))
            .find(|&khz| khz <= max)
            .filter(|&khz| khz >= self.range(clock).min_khz())
            .ok_or(Error::Invalid)
    }
    pub fn plan(
        &self,
        display_khz: u32,
        pixel_khz: u32,
        dcf_khz: u32,
        dtbclk_khz: u32,
    ) -> Result<Plan, Error> {
        let (display_did, display_khz) = self.quantize(Clock::Display, display_khz)?;
        let (pixel_did, pixel_khz) = self.quantize(Clock::Pixel, pixel_khz)?;
        if dcf_khz == 0 || dcf_khz > self.range(Clock::Dcf).max_khz() {
            return Err(Error::Invalid);
        }
        if dtbclk_khz > self.range(Clock::Dtbclk).max_khz() {
            return Err(Error::Invalid);
        }
        Ok(Plan {
            display_khz,
            pixel_khz,
            dcf_khz: dcf_khz.max(self.range(Clock::Dcf).min_khz()),
            dtbclk_khz,
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
        (8..=127) // linux-lit: 8=DENTIST_BASE_DID_1; 127=DENTIST_MAX_DID
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
    pub dtbclk_khz: u32,
    display_did: u8,
    pixel_did: u8,
    vco_khz: u32,
}
fn divider(did: u8) -> u32 {
    match did {
        8..=63 => u32::from(did), // linux-lit: 8=DENTIST_BASE_DID_1; 63=DENTIST_BASE_DID_2 - 1
        // linux-lit: 64=DENTIST_BASE_DID_2; 95=DENTIST_BASE_DID_3 - 1
        // linux-lit: 2=DENTIST_DIVIDER_RANGE_2_STEP
        64..=95 => 64 + 2 * u32::from(did - 64),
        // linux-lit: 96=DENTIST_BASE_DID_3; 125=DENTIST_BASE_DID_4 - 1
        // linux-lit: 128=DENTIST_DIVIDER_RANGE_3_START; 4=DENTIST_DIVIDER_RANGE_3_STEP
        96..=125 => 128 + 4 * u32::from(did - 96),
        126 => 248, // linux-lit: 126=DENTIST_BASE_DID_4; 248=DENTIST_DIVIDER_RANGE_4_START
        // linux-lit: 127=DENTIST_MAX_DID
        // linux-lit: 512=DENTIST_DIVIDER_RANGE_4_START + DENTIST_DIVIDER_RANGE_4_STEP
        127 => 512,
        _ => 0,
    }
}
fn frequency(vco: u32, did: u8) -> u32 {
    // linux-lit: 4=DENTIST_DIVIDER_RANGE_SCALE_FACTOR
    (u64::from(vco) * 4 / u64::from(divider(did))) as u32
}
/// `dcn3_2_soc.dispclk_dppclk_vco_speed_mhz`. The PLL-req register is still
/// read: all ones means the device is gone.
fn vco(pll: u32) -> Result<u32, Error> {
    if pll == u32::MAX {
        return Err(Error::DeviceGone);
    }
    Ok(DENTIST_VCO_KHZ)
}
// linux: n/a (dcn3_2_soc.dispclk_dppclk_vco_speed_mhz = 4300.0)
const DENTIST_VCO_KHZ: u32 = 4_300_000;
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
    /// Read-driven register models can use a bounded number of cooperative
    /// polls instead of a wall-clock deadline. Real MMIO always uses time.
    #[cfg(feature = "kernel-test")]
    fn wait_poll_limit(&self) -> Option<u32> {
        None
    }
}
#[derive(Debug)]
struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
    mp1: u64,
    dcn: u64,
    pipes: u8,
    streams: u8,
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
        for i in 0..u64::from(self.pipes) {
            for (reg, mask) in [
                // linux-lit: 0x1b41=regOTG0_OTG_CONTROL
                // linux-lit: 0x80=regOTG1_OTG_CONTROL - regOTG0_OTG_CONTROL
                // linux-lit: 1=OTG0_OTG_CONTROL__OTG_MASTER_EN_MASK
                (0x1b41 + i * 0x80, 1),
                // linux-lit: 0x1b85=regOTG0_OTG_CLOCK_CONTROL
                // linux-lit: 0x80=regOTG1_OTG_CLOCK_CONTROL - regOTG0_OTG_CLOCK_CONTROL
                // linux-lit: 16=OTG0_OTG_CLOCK_CONTROL__OTG_BUSY__SHIFT
                (0x1b85 + i * 0x80, 1 << 16),
            ] {
                // SAFETY: all four OTGs are bounded in the constructor.
                let value = unsafe { self.regs.read32(self.dcn + reg * 4) };
                if value == u32::MAX {
                    return Err(Error::DeviceGone);
                }
                if value & mask != 0 {
                    return Err(Error::Busy);
                }
            }
        }
        for i in 0..u64::from(self.streams) {
            // linux-lit: 0x210c=regDP0_DP_VID_STREAM_CNTL
            // linux-lit: 0x100=regDP1_DP_VID_STREAM_CNTL - regDP0_DP_VID_STREAM_CNTL
            // linux-lit: 1=DP0_DP_VID_STREAM_CNTL__DP_VID_STREAM_ENABLE_MASK
            // linux-lit: 16=DP0_DP_VID_STREAM_CNTL__DP_VID_STREAM_STATUS__SHIFT
            let reg = 0x210c + i * 0x100;
            // SAFETY: all five stream encoders are bounded in the constructor.
            let value = unsafe { self.regs.read32(self.dcn + reg * 4) };
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
            if value & (1 | 1 << 16) != 0 {
                return Err(Error::Busy);
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
impl Dentist for Dccg32 {
    async fn program(&mut self, disp: u8, dpp: u8) -> Result<(), Error> {
        self.dentist32(disp, dpp).await
    }
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    state: State,
    levels: Option<Levels>,
    applied: Option<Plan>,
    /// Shared PHYCLK must cover every active or verified DP link. This
    /// owner conservatively retains its peak until GPU restart.
    phy_floor_mhz: u16,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    async fn settled(&mut self) -> Result<u32, Error> {
        // linux: n/a (dcn32_smu_wait_for_response: 10 us x 200000)
        let deadline = narf_time::Deadline::after_ms(2000);
        #[cfg(feature = "kernel-test")]
        let mut polls = self.io.wait_poll_limit();
        loop {
            let value = self.access(|io| io.read(RESPONSE))?;
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
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
            // linux: n/a (10 us poll, dcn32_smu_send_msg_with_param)
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
        // linux-lit: 1=DALSMC_Result_OK
        if response != 1 {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi31 DAL message {msg:#x} argument {arg:#x} rejected {response:#x}"
            );
            return Err(Error::Rejected(response));
        }
        let result = self.access(|io| io.read(ARGUMENT))?;
        if result == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok(result)
    }
    fn begin_runtime(&mut self) -> Result<State, Error> {
        if !matches!(self.state, State::Ready | State::Configured) {
            return Err(Error::Busy);
        }
        let resume = self.state;
        self.state = State::InFlight;
        Ok(resume)
    }
    async fn runtime_command(&mut self, msg: u32, arg: u32) -> Result<u32, Error> {
        let resume = self.begin_runtime()?;
        let result = self.command(msg, arg).await;
        self.state = match result {
            // A completed refusal leaves no unknown transaction in flight.
            Ok(_) | Err(Error::Rejected(_)) => resume,
            Err(_) => State::Failed,
        };
        result
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
    /// A DAL query whose rejection Linux ignores (dcn32_smu_send_msg_with_param
    /// leaves the response 0): a rejected message reads as 0, while timeouts,
    /// device loss and revocation still fail.
    async fn query_lenient(&mut self, msg: u32, arg: u32) -> Result<u32, Error> {
        match self.command(msg, arg).await {
            Err(Error::Rejected(_)) => Ok(0),
            other => other,
        }
    }
    /// The void notifications in dcn32_update_clocks do not make a refused
    /// display-count or deep-sleep hint a modeset failure. Transport errors
    /// still fail; voltage/bandwidth floors continue to use strict `floor`.
    async fn notify(&mut self, msg: u32, arg: u32) -> Result<(), Error> {
        self.query_lenient(msg, arg).await.map(|_| ())
    }
    /// `dcn32_init_clocks`: only the SMU version query decides `smu_present`;
    /// the driver-interface and message-header checks are recorded, and
    /// `dcn32_init_single_clock` records whatever levels PMFW reports (a
    /// failed query is 0 levels). DISPCLK/DPPCLK entries are capped at 1950
    /// MHz, in the table and in the DC-mode limit. Unusable ranges are
    /// refused later, by the clock plan, rather than here.
    async fn start_inner(&mut self) -> Result<Levels, Error> {
        let vco_khz = vco(self.access(|io| io.read(PLL))?)?;
        let firmware = self.command(GET_VERSION, 0).await?;
        let interface = self.query_lenient(GET_INTERFACE, 0).await?;
        if interface != 0 && interface != DRIVER_IF_VERSION {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi31 DAL driver-if version {interface:#x} (expected {DRIVER_IF_VERSION:#x})"
            );
        }
        let header = self.query_lenient(GET_HEADER, 0).await?;
        let mut ranges = [Range::default(); 8];
        let mut dc_mode_max_mhz = [0u16; 8];
        for (index, (range, clock)) in ranges.iter_mut().zip(CLOCKS).enumerate() {
            let features = self
                .query_lenient(DPM_BY_INDEX, (clock as u32) << 16 | 0xff)
                .await?;
            // linux: n/a (1 << 31 fine-grained flag, literal in dcn32_clk_mgr.c:dcn32_init_single_clock)
            range.fine_grained = features & 1 << 31 != 0;
            // clk_table holds at most LEVELS entries; never index past it.
            range.count = if range.fine_grained {
                2 // linux: n/a (num_levels = 2, literal in dcn32_clk_mgr.c:dcn32_init_single_clock)
            } else {
                (features as u8).min(LEVELS as u8)
            };
            for level in 0..usize::from(range.count) {
                let value = self
                    .query_lenient(DPM_BY_INDEX, (clock as u32) << 16 | level as u32)
                    .await?
                    // linux: n/a (& 0xFFFF, literal in dcn32_clk_mgr.c:dcn32_init_single_clock)
                    & 0xffff;
                range.mhz[level] = value as u16;
            }
            // linux: n/a (dcn32_clk_mgr.c: disp/dpp table entries capped at 1950 MHz)
            if matches!(clock, Clock::Display | Clock::Pixel) {
                for entry in range.mhz.iter_mut() {
                    if *entry > DISP_DPP_MAX_MHZ as u16 {
                        *entry = DISP_DPP_MAX_MHZ as u16;
                    }
                }
            }
            let dc_max = self.query_lenient(DC_MODE_MAX, clock as u32).await? & 0xffff;
            dc_mode_max_mhz[index] = dc_max as u16;
            if matches!(clock, Clock::Display | Clock::Pixel)
                && dc_mode_max_mhz[index] > DISP_DPP_MAX_MHZ as u16
            {
                dc_mode_max_mhz[index] = DISP_DPP_MAX_MHZ as u16;
            }
        }
        Ok(Levels {
            ranges,
            dc_mode_max_mhz,
            firmware,
            interface,
            header,
            vco_khz,
        })
    }
    fn floor_mhz(&self, clock: Clock, khz: u32) -> Result<u32, Error> {
        let levels = self.levels.ok_or(Error::Invalid)?;
        let range = levels.range(clock);
        let min = range.min_khz() / 1000;
        let max = range.max_khz() / 1000;
        if khz == 0 || min == 0 || min > max {
            return Err(Error::Invalid);
        }
        // dcn32_notify_link_rate_change starts at the board's minimum PHYCLK.
        // Clamp lower requests, but never send a floor above the board range.
        let mhz = khz.div_ceil(1000).max(min);
        if mhz > max {
            return Err(Error::Invalid);
        }
        Ok(mhz)
    }
    async fn floor(&mut self, clock: Clock, khz: u32) -> Result<(), Error> {
        let mhz = self.floor_mhz(clock, khz)?;
        let applied = self.command(HARD_MIN, (clock as u32) << 16 | mhz).await?;
        if applied < mhz
            || applied > self.levels.ok_or(Error::Invalid)?.range(clock).max_khz() / 1000
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    async fn runtime_floor(&mut self, clock: Clock, khz: u32) -> Result<(), Error> {
        let mut mhz = self.floor_mhz(clock, khz)?;
        if clock == Clock::Phy {
            // dcn32_notify_link_rate_change takes the maximum across links.
            // We do not release individual link floors on unplug yet.
            mhz = mhz.max(u32::from(self.phy_floor_mhz));
        }
        let resume = self.begin_runtime()?;
        let result = self.floor(clock, mhz * 1000).await;
        if result.is_ok() && clock == Clock::Phy {
            self.phy_floor_mhz = mhz as u16;
        }
        self.state = if result.is_ok() {
            resume
        } else {
            State::Failed
        };
        result
    }
    async fn prepare(&mut self, plan: Plan, dentist: &mut impl Dentist) -> Result<(), Error> {
        self.prepare_displays(plan, dentist, 1).await
    }
    async fn prepare_displays(
        &mut self,
        plan: Plan,
        dentist: &mut impl Dentist,
        displays: u8,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::Ready | State::Configured) {
            return Err(Error::Busy);
        }
        // DCN 3.2 has at most five streams. Count streams, not ODM slices or PHYs.
        if !(1..=5).contains(&displays) {
            return Err(Error::Invalid);
        }
        let levels = self.levels.ok_or(Error::Invalid)?;
        // Revalidate public frequency fields, provenance and both divider ids.
        if levels.plan(
            plan.display_khz,
            plan.pixel_khz,
            plan.dcf_khz,
            plan.dtbclk_khz,
        )? != plan
        {
            return Err(Error::Invalid);
        }
        self.access(|io| io.idle())??;
        self.state = State::InFlight;
        let result = async {
            // dcn32_update_clocks: request only display-owned floors. Pin
            // UCLK at the top board state to disable p-state switching, and
            // floor DTBCLK at the reference the DCCG DTOs divide against.
            self.notify(DISPLAYS, u32::from(displays)).await?;
            self.floor(Clock::Dcf, plan.dcf_khz).await?;
            self.notify(DEEP_SLEEP_MIN, plan.dcf_khz.div_ceil(1000))
                .await?;
            self.floor(Clock::Memory, levels.range(Clock::Memory).max_khz())
                .await?;
            self.floor(Clock::Dtbclk, plan.dtbclk_khz).await?;
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
    dccg: Dccg32,
}
impl ClockManager {
    /// # Safety
    /// Caller exclusively owns this Navi31 GPU, its DAL mailbox, DCCG and
    /// reset controls, with permanent mappings and matching PCI authority.
    /// No other owner may enable a stream concurrently.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        if !profile.is_dcn32() {
            return Err(Error::Unsupported);
        }
        let mp1 = crate::amdgpu_psp_ring::bank(
            gpu,
            crate::amdgpu_discovery::HW_ID_MP1,
            crate::amdgpu_rdna3::MP_VERSIONS,
            0,
            RESPONSE,
        )
        .map_err(|_| Error::Unsupported)?;
        if gpu.regs.len < u64::from(PLL + 1) * 4 {
            return Err(Error::Invalid);
        }
        // linux-lit: 0x260c=regDP5_DP_VID_STREAM_CNTL
        let dcn = profile.bank(gpu, 2, 0x260c)?;
        // SAFETY: DCCG is retained here; no second divider owner is exposed.
        let dccg = unsafe { Dccg32::new(gpu, authority)? };
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                    mp1,
                    dcn,
                    pipes: profile.pipes(),
                    streams: profile.streams(),
                },
                authority,
                state: State::Dormant,
                levels: None,
                applied: None,
                phy_floor_mhz: 0,
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
    pub fn dccg(&mut self) -> &mut Dccg32 {
        &mut self.dccg
    }
    pub async fn start(&mut self) -> Result<Levels, Error> {
        // The Navi31 power owner is the caller: no SMU step is needed here,
        // the DAL mailbox is independent of the GFX SMU message space.
        self.engine.start(core::future::ready(Ok(()))).await
    }
    /// Set a display-owned floor (`SetHardMinByFreq`) while running.
    pub async fn set_floor(&mut self, clock: Clock, khz: u32) -> Result<(), Error> {
        self.engine.runtime_floor(clock, khz).await
    }
    /// Cap a clock (`SetHardMaxByFreq`) while running.
    pub async fn set_ceiling(&mut self, clock: Clock, khz: u32) -> Result<(), Error> {
        let mhz = self.engine.floor_mhz(clock, khz)?;
        self.engine
            .runtime_command(HARD_MAX, (clock as u32) << 16 | mhz)
            .await?;
        Ok(())
    }
    /// `dcn32_smu_set_fclk_switch_allow`: allow or forbid FCLK p-state
    /// switching. `FCLK_SWITCH_ALLOW` is 1, `FCLK_SWITCH_DISALLOW` 0.
    pub async fn set_fclk_switch_allow(&mut self, allow: bool) -> Result<(), Error> {
        self.engine
            .runtime_command(SET_FCLK_SWITCH_ALLOW, u32::from(allow))
            .await?;
        Ok(())
    }
    /// Which clocks currently hold a hard min, as the `CHECK_HARD_MIN_CLK_*`
    /// mask (`ReturnHardMinStatus`).
    pub async fn hard_min_status(&mut self) -> Result<u32, Error> {
        self.engine.runtime_command(RETURN_HARD_MIN_STATUS, 0).await
    }
    /// Stage the watermark table at `dram_addr` and transfer it to the SMU
    /// (`SetDalDramAddrHigh/Low`, then `TransferTableDram2Smu` with
    /// TABLE_WATERMARKS). The caller stages the table contents in VRAM; this
    /// owner only moves the pointer and triggers the transfer.
    pub async fn transfer_watermarks(&mut self, dram_addr: u64) -> Result<(), Error> {
        let resume = self.engine.begin_runtime()?;
        let result = async {
            self.engine
                .command(SET_DRAM_ADDR_HIGH, (dram_addr >> 32) as u32)
                .await?;
            self.engine
                .command(SET_DRAM_ADDR_LOW, dram_addr as u32)
                .await?;
            self.engine
                .command(TRANSFER_TABLE_DRAM2SMU, TABLE_WATERMARKS)
                .await?;
            Ok(())
        }
        .await;
        self.engine.state = if result.is_ok() {
            resume
        } else {
            State::Failed
        };
        result
    }
    pub async fn prepare(&mut self, plan: Plan) -> Result<(), Error> {
        let Self { engine, dccg } = self;
        engine.prepare(plan, dccg).await
    }
}

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Fake {
        values: Vec<u32>,
        writes: Vec<(u32, u32)>,
        gone: bool,
        /// (message id, argument) the fake answers, in order.
        script: Vec<(u32, u32, u32)>,
    }
    impl Fake {
        fn new() -> Self {
            // RESPONSE starts nonzero: Linux's
            // `dcn32_smu_send_msg_with_param` waits for the response
            // register to be ready before the first message, so real
            // hardware always has a nonzero value here, and the DCN 3.0
            // fake models the same initial state (`response: 1`).
            let mut values = vec![0; 0x300];
            values[RESPONSE as usize] = 1;
            Self {
                values,
                writes: Vec::new(),
                gone: false,
                script: Vec::new(),
            }
        }
        /// Answer `msg` with `response` and leave `result` in ARGUMENT.
        fn answer(&mut self, msg: u32, response: u32, result: u32) {
            self.script.push((msg, response, result));
        }
    }
    impl Io for Fake {
        fn wait_poll_limit(&self) -> Option<u32> {
            // The model answers synchronously in write(), so the first poll
            // after the message write already reads the response; sixteen
            // polls is pure margin, and a silent SMU reaches its Timeout by
            // count instead of burning the 2 s deadline under the spin
            // executor (#879).
            Some(16)
        }
        fn read(&mut self, reg: u32) -> u32 {
            if self.gone {
                return u32::MAX;
            }
            if reg == PLL {
                // The PLL-req register lives outside the mailbox window the
                // fake models; 0 means present (not all-ones).
                return 0;
            }
            self.values[reg as usize]
        }
        fn write(&mut self, reg: u32, value: u32) {
            self.writes.push((reg, value));
            self.values[reg as usize] = value;
            if reg == MESSAGE {
                // The SMU answers at once: response in RESPONSE, result in ARGUMENT.
                let (response, result) =
                    match self.script.iter().position(|(msg, _, _)| *msg == value) {
                        Some(at) => {
                            let (_, response, result) = self.script.remove(at);
                            (response, result)
                        }
                        None => (1, 0),
                    };
                self.values[RESPONSE as usize] = response;
                self.values[ARGUMENT as usize] = result;
            }
        }
        fn idle(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }
    fn engine() -> Engine<Fake> {
        Engine {
            io: Fake::new(),
            authority: Cap::bootstrap(),
            state: State::Dormant,
            levels: None,
            applied: None,
            phy_floor_mhz: 0,
        }
    }
    /// A DPM table with two levels per clock: 800 and 1950+ MHz on
    /// DISP/DPP (capped to 1950), 400 and 1564 on DCFCLK.
    fn tabled(mut e: Engine<Fake>) -> Engine<Fake> {
        e.io.answer(GET_VERSION, 1, 0x0d00_0000);
        e.io.answer(GET_INTERFACE, 1, DRIVER_IF_VERSION);
        e.io.answer(GET_HEADER, 1, 1);
        for clock in CLOCKS {
            let (lo, hi) = match clock {
                Clock::Display | Clock::Pixel => (800u32, 2400u32),
                Clock::Dcf => (400, 1564),
                Clock::Dtbclk => (200, 1564),
                _ => (100, 1200),
            };
            e.io.answer(DPM_BY_INDEX, 1, 2);
            e.io.answer(DPM_BY_INDEX, 1, lo);
            e.io.answer(DPM_BY_INDEX, 1, hi);
            e.io.answer(DC_MODE_MAX, 1, hi);
        }
        e
    }

    fn dcn32_clk_start_reads_the_dpm_tables_and_caps_disp() -> TestResult {
        let mut e = tabled(engine());
        // The PLL register reads 0 (not all-ones): the device is present.
        let levels = match narf_scheduler::block_on_spin(e.start(core::future::ready(Ok(())))) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("DCN32 clock start rejected"),
        };
        if levels.firmware != 0x0d00_0000 || levels.interface != DRIVER_IF_VERSION {
            return TestResult::Fail("DCN32 clock versions wrong");
        }
        // DISP/DPP table entries above 1950 MHz are capped, in the table and
        // in the DC-mode limit.
        if levels.range(Clock::Display).max_khz() != 1_950_000
            || levels.range(Clock::Pixel).max_khz() != 1_950_000
            || levels.dc_mode_max_khz(Clock::Display) != 1_950_000
        {
            return TestResult::Fail("DCN32 DISP/DPP cap not applied");
        }
        if levels.range(Clock::Dcf).max_khz() != 1_564_000 || levels.vco_khz != DENTIST_VCO_KHZ {
            return TestResult::Fail("DCN32 DCFCLK table or VCO wrong");
        }
        if e.state != State::Ready {
            return TestResult::Fail("DCN32 clock not Ready after start");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-clk",
        dcn32_clk_start_reads_the_dpm_tables_and_caps_disp
    );

    fn dcn32_clk_plan_quantizes_to_dentist_dividers() -> TestResult {
        let mut e = tabled(engine());
        if narf_scheduler::block_on_spin(e.start(core::future::ready(Ok(())))).is_err() {
            return TestResult::Fail("DCN32 clock start rejected");
        }
        let levels = e.levels.unwrap();
        // 600 MHz DISPCLK against the 4.3 GHz VCO: quantize clamps the
        // request to the 800 MHz table minimum, then takes the first
        // divider output at or above it — DID 21, 4*4300000/21 = 819047 kHz.
        let plan = match levels.plan(600_000, 600_000, 800_000, 500_000) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("DCN32 clock plan rejected"),
        };
        if plan.display_khz != 819_047 {
            return TestResult::Fail("DCN32 clock plan divider wrong");
        }
        if levels.plan(3_000_000, 600_000, 800_000, 500_000).is_ok() {
            return TestResult::Fail("DCN32 clock plan above the cap admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-clk",
        dcn32_clk_plan_quantizes_to_dentist_dividers
    );

    fn dcn32_clk_hard_min_status_bits_are_per_clock() -> TestResult {
        if Clock::Display.hard_min_bit() != 0x1
            || Clock::Pixel.hard_min_bit() != 0x2
            || Clock::Dcf.hard_min_bit() != 0x8
            || Clock::Dtbclk.hard_min_bit() != 0x10
            || Clock::Memory.hard_min_bit() != 0x20
        {
            return TestResult::Fail("DCN32 hard-min status bits wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-clk",
        dcn32_clk_hard_min_status_bits_are_per_clock
    );
}
