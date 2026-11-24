//! DCN314 and DCN315 display clock manager. The display clock interface is a
//! mailbox on MP1 that is distinct from the GFX SMU's own message space, and
//! its message ids are the VBIOSSMC set, not PPSMC.
//!
//! DCN 3.1.4 (Phoenix, SMU 13.0.4/13.0.11) uses C2PMSG_67/83/91 where the
//! power driver uses 66/82/90: `dcn314_smu.c`, `dcn314_clk_mgr.c`,
//! `mp_13_0_4_offset.h`.
//!
//! DCN 3.1.5 (Raphael, SMU 13.0.5) is a different protocol, not a
//! renumbering (`dcn315_smu.c`, `dcn315_clk_mgr.c`, `mp_13_0_5_offset.h`):
//! the parameter and response are C2PMSG_37/38, the message id is written to
//! `MP1_C2PMSG_3` through the SMN index/data pair and read back, `SetDtbClk`
//! is 0x0A rather than 0x17, DPREFCLK is asked of the firmware rather than
//! fixed, and the DPM table has four levels per clock and no WCK ratio.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as discovery,
    amdgpu_smn::{NBIO_VERSIONS as NBIO_VERSIONS_315, PCIE_DATA2},
    amdgpu_vram::{Pool, Reservation},
};
use core::{
    future::Future,
    sync::atomic::{fence, Ordering},
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const MSG: u64 = 0x283; // linux: n/a (DCN 3.1.4 path: MP1_SMN_C2PMSG_67)
const PARAM: u64 = 0x293; // linux: n/a (DCN 3.1.4 path: MP1_SMN_C2PMSG_83)
const RESPONSE: u64 = 0x29b; // linux: n/a (DCN 3.1.4 path: MP1_SMN_C2PMSG_91)

const MSG_TEST: u32 = 0x01; // linux: n/a (DCN 3.1.4 path)
const MSG_GET_VERSION: u32 = 0x02; // linux: n/a (DCN 3.1.4 path)
const MSG_SET_DISPCLK: u32 = 0x04; // linux: n/a (DCN 3.1.4 path)
const MSG_SET_DPPCLK: u32 = 0x06; // linux: n/a (DCN 3.1.4 path)
const MSG_SET_HARD_MIN_DCFCLK: u32 = 0x07; // linux: n/a (DCN 3.1.4 path)
const MSG_SET_MIN_DEEP_SLEEP_DCFCLK: u32 = 0x08; // linux: n/a (DCN 3.1.4 path)
const MSG_SET_DRAM_ADDR_HIGH: u32 = 0x0e; // linux: n/a (DCN 3.1.4 path)
const MSG_SET_DRAM_ADDR_LOW: u32 = 0x0f; // linux: n/a (DCN 3.1.4 path)
const MSG_TRANSFER_TABLE_SMU2DRAM: u32 = 0x10; // linux: n/a (DCN 3.1.4 path)
const MSG_SET_IDLE_OPTIMIZATIONS: u32 = 0x12; // linux: n/a (DCN 3.1.4 path)
const MSG_SET_DTBCLK: u32 = 0x17; // linux: n/a (DCN 3.1.4 path)

// DCN 3.1.5. Linux addresses C2PMSG_37/38 through a hard-coded MP1 base of
// 0x16000 (`MP0_BASE` segment 0 in dcn315_smu.c, `_BASE_IDX 0` in
// mp_13_0_5_offset.h); discovery must agree before the bank is believed.
const PARAM_315: u64 = 0x265; // linux: n/a (DCN 3.1.5 path: regMP1_SMN_C2PMSG_37)
const RESPONSE_315: u64 = 0x266; // linux: n/a (DCN 3.1.5 path: regMP1_SMN_C2PMSG_38)
const MP1_BASE_315: u64 = 0x0001_6000; // linux: n/a (DCN 3.1.5 path: MP0_BASE segment 0)
/// `mmMP1_C2PMSG_3`, an SMN address: written with `IX_REG_SET_SYNC`, which is
/// `WREG32_PCIE` through NBIO's PCIE_INDEX2/DATA2.
const MSG_SMN_315: u32 = 0x03b1_050c; // linux: n/a (DCN 3.1.5 path: mmMP1_C2PMSG_3)
/// `SMU_REGISTER_WRITE_RETRY_COUNT`: a message id that does not read back is
/// written again, two microseconds apart.
const MSG_WRITE_RETRIES: u32 = 5; // linux: n/a (DCN 3.1.5 path)
const MSG_SET_DTBCLK_315: u32 = 0x0a; // linux: n/a (DCN 3.1.5 path)
const MSG_GET_DPREFCLK_315: u32 = 0x13; // linux: n/a (DCN 3.1.5 path)
/// `DpmClocks_315_t`: seven 4-entry arrays, four 12-byte DF p-states, the
/// enabled-level counts and the GFX clock range.
const TABLE_SIZE_315: u64 = 176; // linux: n/a (DCN 3.1.5 path)
const LEVELS_315: usize = 4; // linux: n/a (DCN 3.1.5 path)
/// `UNSUPPORTED_DCFCLK` (`dcn315_clk_mgr.c`): a hard-minimum DCFCLK no level
/// meets, which PMFW takes as "lock p-state".
const UNSUPPORTED_DCFCLK_KHZ: u32 = 10_000_000; // linux: n/a (DCN 3.1.5 path)
/// `dc->debug.min_disp_clk_khz` on both DCN 3.1.4 and 3.1.5: the floor of
/// what is asked of PMFW, though the requested clock is what is recorded.
const MIN_DISPCLK_KHZ: u32 = 100_000; // linux: n/a (DCN 3.1.4/3.1.5 debug_defaults_drv)

const STATUS_BUSY: u32 = 0x00; // linux: n/a (DCN 3.1.4 path)
const STATUS_OK: u32 = 0x01; // linux: n/a (DCN 3.1.4 path)

const TABLE_DPMCLOCKS: u32 = 4; // linux: n/a (DCN 3.1.4 path)
/// `DpmClocks314_t`: six 8-entry clock arrays, voltages, four DF p-states,
/// the enabled-level counts and the GFX clock range.
const TABLE_SIZE: u64 = 304; // linux: n/a (DCN 3.1.4 path)
const LEVELS: usize = 8; // linux: n/a (DCN 3.1.4 path)
const DF_PSTATES: usize = 4; // linux: n/a (DCN 3.1.4 path)

/// DCN314 drives DP reference and DTB from a fixed 600 MHz source
/// (`dcn314_clk_mgr_construct`). When the boot firmware leaves the SPLL
/// spreading, the DP DTO's reference is lowered by half the spread
/// ([`dp_dto_reference_khz`]).
pub const DPREFCLK_KHZ: u32 = 600_000; // linux: n/a (DCN 3.1.4 path)

/// A DPREFCLK downspread of `percentage / divider` percent — Linux's
/// `dprefclk_ss_percentage` and `dprefclk_ss_divider`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spread {
    pub percentage: u32,
    pub divider: u32,
}

/// The reference the DP DTO divides: `dce_adjust_dp_ref_freq_for_ss`, which
/// `dcn314_init_clocks` applies while the SPLL spreads, lowers DPREFCLK by
/// half the downspread so the synthesised pixel clock is right on average.
///
/// Computed bit for bit in Linux's 31.32 fixed point rather than exactly:
/// `dc_fixpt_from_fraction` rounds 0.375 % / 200 up, so the LUT's 0.375 %
/// spread on 600 MHz gives 598 874 kHz where exact arithmetic gives 598 875,
/// and the DTO must match the clock Linux would program.
pub fn dp_dto_reference_khz(dprefclk_khz: u32, spread: Option<Spread>) -> u32 {
    const ONE: u64 = 1 << 32; // linux: n/a (dc_fixpt_one, 31.32 fixed point)
    let Some(spread) = spread.filter(|s| s.divider != 0) else {
        return dprefclk_khz;
    };
    let percent = fixpt_from_fraction(u64::from(spread.percentage), u64::from(spread.divider));
    // dc_fixpt_div_int(x, 200) is dc_fixpt_from_fraction(x.value, 200 << 32).
    // linux-lit: 200=literal divisor in dce_adjust_dp_ref_freq_for_ss
    let half_spread = fixpt_from_fraction(percent, 200 * ONE);
    let Some(factor) = ONE.checked_sub(half_spread) else {
        return dprefclk_khz;
    };
    // dc_fixpt_mul_int by an integer has no fractional cross term, and
    // dc_fixpt_floor drops the fraction.
    ((u128::from(factor) * u128::from(dprefclk_khz)) >> 32) as u32
}

/// `dc_fixpt_from_fraction` for non-negative operands: long division to 32
/// fractional bits, then round the last bit half up.
fn fixpt_from_fraction(numerator: u64, denominator: u64) -> u64 {
    let mut value = numerator / denominator;
    let mut remainder = numerator % denominator;
    for _ in 0..32 {
        remainder <<= 1;
        value <<= 1;
        if remainder >= denominator {
            value |= 1;
            remainder -= denominator;
        }
    }
    value + u64::from(remainder << 1 >= denominator)
}
pub const DTBCLK_KHZ: u32 = 600_000; // linux: n/a (DCN 3.1.4 path)
/// Linux clamps DPPCLK to 100 MHz to keep an eDP panel plus a 4K monitor from
/// underflowing when the global clock drops.
const DPPCLK_FLOOR_KHZ: u32 = 100_000; // linux: n/a (DCN 3.1.4 path)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Allocation,
    Revoked,
    Busy,
    Timeout,
    DeviceGone,
    Rejected(u32),
}
/// Enabled DPM levels as the firmware reports them, in MHz.
/// `display` applies to both DISPCLK and DPPCLK (`NumDispClkLevelsEnabled`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Levels {
    pub dcfclk: [u32; LEVELS],
    pub dispclk: [u32; LEVELS],
    pub dppclk: [u32; LEVELS],
    pub socclk: [u32; LEVELS],
    pub fclk: [u32; DF_PSTATES],
    pub memclk: [u32; DF_PSTATES],
    /// `WCK_RATIO_*` as the firmware reports it: 0 is 1:1, 1 is 1:2, 2 is 1:4.
    pub wck_ratio: [u8; DF_PSTATES],
    pub dcfclk_levels: u8,
    pub display_levels: u8,
    pub socclk_levels: u8,
    pub df_pstates: u8,
    pub min_gfxclk: u32,
    pub max_gfxclk: u32,
}
fn ceiling(values: &[u32], count: u8) -> u32 {
    values[..count as usize].iter().copied().max().unwrap_or(0)
}
impl Levels {
    pub fn max_dispclk_khz(&self) -> u32 {
        ceiling(&self.dispclk, self.display_levels) * 1000
    }
    pub fn max_dppclk_khz(&self) -> u32 {
        ceiling(&self.dppclk, self.display_levels) * 1000
    }
    pub fn max_dcfclk_khz(&self) -> u32 {
        ceiling(&self.dcfclk, self.dcfclk_levels) * 1000
    }
    pub fn max_socclk_khz(&self) -> u32 {
        ceiling(&self.socclk, self.socclk_levels) * 1000
    }
    pub fn max_fclk_khz(&self) -> u32 {
        ceiling(&self.fclk, self.df_pstates) * 1000
    }
    pub fn max_memclk_khz(&self) -> u32 {
        ceiling(&self.memclk, self.df_pstates) * 1000
    }
    /// The DRAM data rate DML wants, in MT/s: twice the memory clock for
    /// double data rate, times the WCK ratio. Taken from the p-state with the
    /// highest resulting rate, which is the one a modeset will run at.
    pub fn max_dram_speed_mts(&self) -> u32 {
        (0..self.df_pstates as usize)
            .map(|index| {
                let ratio = match self.wck_ratio[index] {
                    1 => 2,
                    2 => 4,
                    _ => 1,
                };
                self.memclk[index].saturating_mul(2).saturating_mul(ratio)
            })
            .max()
            .unwrap_or(0)
    }
}
/// The clock state the pipeline requires. DTBCLK is only needed by DP2.0 and
/// DSC paths; this 8b/10b SST path leaves it disabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Clocks {
    pub dispclk_khz: u32,
    pub dppclk_khz: u32,
    pub dcfclk_khz: u32,
    pub deep_sleep_dcfclk_khz: u32,
    pub dtbclk_enabled: bool,
}
/// The two consumers a clock change has to coordinate with. `dpp_dto` programs
/// the DCCG per-DPP dividers; `notify` tells DMCUB what was applied so its own
/// idle and power decisions match. Both are supplied by the caller because
/// neither the DCCG bank nor the firmware mailbox belongs to this module.
pub trait Consumers {
    fn dpp_dto(&mut self, global_dppclk_khz: u32) -> Result<(), Error>;
    fn notify(&mut self, clocks: Clocks) -> impl Future<Output = Result<(), Error>> + Send;
}
/// No DPP pipe is running and no firmware is listening yet.
#[derive(Debug, Default)]
pub struct Unattached;
impl Consumers for Unattached {
    fn dpp_dto(&mut self, _: u32) -> Result<(), Error> {
        Ok(())
    }
    async fn notify(&mut self, _: Clocks) -> Result<(), Error> {
        Ok(())
    }
}

/// Which display mailbox protocol the firmware speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mailbox {
    /// `dcn314_smu.c`: C2PMSG_67 message, 83 parameter, 91 response.
    Dcn314,
    /// `dcn315_smu.c`: C2PMSG_37 parameter, 38 response, message by SMN.
    Dcn315,
}
impl Mailbox {
    fn param(self) -> u64 {
        match self {
            Self::Dcn314 => PARAM,
            Self::Dcn315 => PARAM_315,
        }
    }
    fn response(self) -> u64 {
        match self {
            Self::Dcn314 => RESPONSE,
            Self::Dcn315 => RESPONSE_315,
        }
    }
    fn set_dtbclk(self) -> u32 {
        match self {
            Self::Dcn314 => MSG_SET_DTBCLK,
            Self::Dcn315 => MSG_SET_DTBCLK_315,
        }
    }
    fn table_size(self) -> u64 {
        match self {
            Self::Dcn314 => TABLE_SIZE,
            Self::Dcn315 => TABLE_SIZE_315,
        }
    }
}

trait Io: Send {
    fn read(&mut self, reg: u64) -> u32;
    fn write(&mut self, reg: u64, value: u32);
    /// `RREG32_PCIE` / `WREG32_PCIE`: an SMN register through NBIO's index
    /// and data pair. Only the DCN 3.1.5 mailbox uses it.
    fn read_smn(&mut self, address: u32) -> u32;
    fn write_smn(&mut self, address: u32, value: u32);
    fn read_table(&mut self, offset: u64) -> u32;
    fn write_table(&mut self, offset: u64, value: u32);
    /// Read-driven register models can use a bounded number of cooperative
    /// polls instead of a wall-clock deadline. Real MMIO always uses time.
    #[cfg(feature = "kernel-test")]
    fn wait_poll_limit(&self) -> Option<u32> {
        None
    }
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    mp1: u64,
    /// NBIO bank holding PCIE_INDEX2/DATA2, for the DCN 3.1.5 message write.
    nbio: Option<u64>,
    table: MmioRegion,
}
impl Io for Mmio {
    fn read(&mut self, reg: u64) -> u32 {
        // SAFETY: constructor bounds this MP1 register bank and keeps the map.
        unsafe { self.regs.read32(self.mp1 + reg * 4) }
    }
    fn write(&mut self, reg: u64, value: u32) {
        // SAFETY: same bounds; this is the sole display mailbox client.
        unsafe { self.regs.write32(self.mp1 + reg * 4, value) };
    }
    fn read_smn(&mut self, address: u32) -> u32 {
        let Some(nbio) = self.nbio else {
            return u32::MAX;
        };
        // SAFETY: the constructor bounds the NBIO bank through PCIE_DATA2.
        unsafe { crate::amdgpu_smn::read(&self.regs, nbio, address) }
    }
    fn write_smn(&mut self, address: u32, value: u32) {
        let Some(nbio) = self.nbio else {
            return;
        };
        // SAFETY: as read_smn.
        unsafe { crate::amdgpu_smn::write(&self.regs, nbio, address, value) }
    }
    fn read_table(&mut self, offset: u64) -> u32 {
        // Firmware wrote this through its own path; order the read after the
        // transfer completed. All offsets stay below the reserved TABLE_SIZE.
        fence(Ordering::SeqCst);
        // SAFETY: bounded by the reservation this engine owns.
        unsafe { self.table.read32(offset) }
    }
    fn write_table(&mut self, offset: u64, value: u32) {
        // SAFETY: same owned reservation.
        unsafe { self.table.write32(offset, value) };
        fence(Ordering::SeqCst);
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
async fn delay(ms: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
}
fn mhz_ceil(khz: u32) -> u32 {
    khz.div_ceil(1000)
}
/// Linux `should_set_clock`: raise immediately, lower only when permitted.
fn should_set(safe_to_lower: bool, new: u32, current: u32) -> bool {
    new > current || (safe_to_lower && new < current)
}
fn valid_clock(mhz: u32) -> bool {
    // Linux `is_valid_clock_value`.
    mhz > 1 && mhz < 100_000
}

#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    mailbox: Mailbox,
    table: Reservation,
    clocks: Clocks,
    levels: Option<Levels>,
    /// DPREFCLK: DCN 3.1.4's fixed 600 MHz, or what DCN 3.1.5's firmware
    /// reports in `start` (zero until then, which the DP DTO refuses).
    dprefclk_khz: u32,
    /// `new_clocks->p_state_change_support` for the next request.
    pstate_supported: bool,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    /// Wait for the mailbox to leave BUSY. Linux polls for up to two seconds.
    async fn settled(&mut self) -> Result<u32, Error> {
        let deadline = narf_time::Deadline::after_ms(2000);
        #[cfg(feature = "kernel-test")]
        let mut polls = self.io.wait_poll_limit();
        let response = self.mailbox.response();
        loop {
            let value = self.access(|io| io.read(response))?;
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
            if value != STATUS_BUSY {
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
            delay(1).await;
        }
    }
    async fn send(&mut self, message: u32, param: u32) -> Result<u32, Error> {
        if self.settled().await? == STATUS_BUSY {
            return Err(Error::Busy);
        }
        let (response, param_reg) = (self.mailbox.response(), self.mailbox.param());
        self.access(|io| {
            io.write(response, STATUS_BUSY);
            io.write(param_reg, param);
        })?;
        match self.mailbox {
            Mailbox::Dcn314 => self.access(|io| io.write(MSG, message))?,
            Mailbox::Dcn315 => {
                // dcn315_smu_send_msg_with_param: write the id through SMN
                // and read it back, retrying a write that did not land. A
                // message that never lands leaves the response BUSY, which
                // the wait below reports as a timeout, as Linux's does.
                for attempt in 0..MSG_WRITE_RETRIES {
                    let echoed = self.access(|io| {
                        io.write_smn(MSG_SMN_315, message);
                        io.read_smn(MSG_SMN_315)
                    })?;
                    if echoed == message {
                        break;
                    }
                    if attempt + 1 < MSG_WRITE_RETRIES {
                        narf_time::SleepUntil::new(narf_time::Deadline::after_us(2).as_instant())
                            .await;
                    }
                }
            }
        }
        let result = self.settled().await?;
        if result != STATUS_OK {
            // DCN 3.1.4 leaves the mailbox usable for the next command, as
            // Linux does after a rejection; dcn315_smu.c does not. Either
            // way the firmware's own status is reported, not its parameter.
            if self.mailbox == Mailbox::Dcn314 {
                self.access(|io| io.write(response, STATUS_OK))?;
            }
            return Err(Error::Rejected(result));
        }
        self.access(|io| io.read(param_reg))
    }
    /// Read back the firmware's DPM table. The buffer is zeroed first so a
    /// firmware that writes nothing cannot be mistaken for a valid table.
    async fn read_levels(&mut self) -> Result<Levels, Error> {
        let address = self.table.address();
        let size = self.mailbox.table_size();
        self.table.publish();
        self.access(|io| {
            for offset in (0..size).step_by(4) {
                io.write_table(offset, 0);
            }
        })?;
        self.send(MSG_SET_DRAM_ADDR_HIGH, (address >> 32) as u32)
            .await?;
        self.send(MSG_SET_DRAM_ADDR_LOW, address as u32).await?;
        self.send(MSG_TRANSFER_TABLE_SMU2DRAM, TABLE_DPMCLOCKS)
            .await?;
        let words: [u32; (TABLE_SIZE / 4) as usize] = self.access(|io| {
            let mut words = [0u32; (TABLE_SIZE / 4) as usize];
            for (index, word) in words.iter_mut().take((size / 4) as usize).enumerate() {
                *word = io.read_table(index as u64 * 4);
            }
            words
        })?;
        match self.mailbox {
            Mailbox::Dcn314 => parse(&words),
            Mailbox::Dcn315 => parse_315(&words),
        }
    }
    async fn apply(
        &mut self,
        requested: Clocks,
        safe_to_lower: bool,
        consumers: &mut impl Consumers,
    ) -> Result<Clocks, Error> {
        let levels = self.levels.ok_or(Error::Invalid)?;
        let mut target = requested;
        target.dppclk_khz = target.dppclk_khz.max(DPPCLK_FLOOR_KHZ);
        if target.dispclk_khz > levels.max_dispclk_khz()
            || target.dppclk_khz > levels.max_dppclk_khz()
            || target.dcfclk_khz > levels.max_dcfclk_khz()
            || target.deep_sleep_dcfclk_khz > target.dcfclk_khz
        {
            return Err(Error::Invalid);
        }
        // DTBCLK is enabled before the clocks that depend on it and disabled
        // only once nothing needs it.
        let set_dtbclk = self.mailbox.set_dtbclk();
        if !safe_to_lower && target.dtbclk_enabled && !self.clocks.dtbclk_enabled {
            self.send(set_dtbclk, 1).await?;
            self.clocks.dtbclk_enabled = true;
        }
        if safe_to_lower && !target.dtbclk_enabled && self.clocks.dtbclk_enabled {
            self.send(set_dtbclk, 0).await?;
            self.clocks.dtbclk_enabled = false;
        }
        // dcn315_update_clocks: "Lock pstate by requesting unsupported dcfclk
        // if change is unsupported". DCN 3.1.4's clock manager has no lock.
        if self.mailbox == Mailbox::Dcn315 && !self.pstate_supported {
            target.dcfclk_khz = UNSUPPORTED_DCFCLK_KHZ;
        }
        // A BIOS that left DCFCLK DPM disabled rejects these two; Linux warns
        // and continues, because the boot DCFCLK already satisfies the request.
        if should_set(safe_to_lower, target.dcfclk_khz, self.clocks.dcfclk_khz) {
            match self
                .send(MSG_SET_HARD_MIN_DCFCLK, mhz_ceil(target.dcfclk_khz))
                .await
            {
                Ok(_) => self.clocks.dcfclk_khz = target.dcfclk_khz,
                Err(Error::Rejected(_)) => {}
                Err(error) => return Err(error),
            }
        }
        if should_set(
            safe_to_lower,
            target.deep_sleep_dcfclk_khz,
            self.clocks.deep_sleep_dcfclk_khz,
        ) {
            match self
                .send(
                    MSG_SET_MIN_DEEP_SLEEP_DCFCLK,
                    mhz_ceil(target.deep_sleep_dcfclk_khz),
                )
                .await
            {
                Ok(_) => self.clocks.deep_sleep_dcfclk_khz = target.deep_sleep_dcfclk_khz,
                Err(Error::Rejected(_)) => {}
                Err(error) => return Err(error),
            }
        }
        let lowering = should_set(safe_to_lower, target.dppclk_khz, self.clocks.dppclk_khz)
            && target.dppclk_khz < self.clocks.dppclk_khz;
        let update_dppclk = should_set(safe_to_lower, target.dppclk_khz, self.clocks.dppclk_khz);
        let update_dispclk = should_set(safe_to_lower, target.dispclk_khz, self.clocks.dispclk_khz)
            && target.dispclk_khz > 0;
        if update_dispclk {
            // "Clamp the requested clock to PMFW based on their limit": the
            // floor is what is asked for, the request is what is recorded.
            let asked = target.dispclk_khz.max(MIN_DISPCLK_KHZ);
            self.send(MSG_SET_DISPCLK, mhz_ceil(asked)).await?;
            self.clocks.dispclk_khz = target.dispclk_khz;
        }
        if update_dppclk {
            self.clocks.dppclk_khz = target.dppclk_khz;
        }
        if lowering {
            // Raise the per-DPP dividers before the global clock drops, so no
            // pipe is ever fed a clock above what its divider was set for.
            consumers.dpp_dto(self.clocks.dppclk_khz)?;
            self.send(MSG_SET_DPPCLK, mhz_ceil(self.clocks.dppclk_khz))
                .await?;
        } else {
            if update_dppclk || update_dispclk {
                self.send(MSG_SET_DPPCLK, mhz_ceil(self.clocks.dppclk_khz))
                    .await?;
            }
            consumers.dpp_dto(self.clocks.dppclk_khz)?;
        }
        consumers.notify(self.clocks).await?;
        Ok(self.clocks)
    }
}
fn parse(words: &[u32; (TABLE_SIZE / 4) as usize]) -> Result<Levels, Error> {
    let array = |start: usize| {
        let mut out = [0u32; LEVELS];
        out.copy_from_slice(&words[start..start + LEVELS]);
        out
    };
    let counts = words[72];
    let mut levels = Levels {
        dcfclk: array(0),
        dispclk: array(8),
        dppclk: array(16),
        socclk: array(24),
        fclk: [0; DF_PSTATES],
        memclk: [0; DF_PSTATES],
        wck_ratio: [0; DF_PSTATES],
        dcfclk_levels: counts as u8,
        display_levels: (counts >> 8) as u8,
        socclk_levels: (counts >> 16) as u8,
        df_pstates: words[73] as u8,
        min_gfxclk: words[74],
        max_gfxclk: words[75],
    };
    for index in 0..DF_PSTATES {
        levels.fclk[index] = words[56 + index * 4];
        levels.memclk[index] = words[57 + index * 4];
        // Each 16-byte p-state entry ends with WckRatio and three spare bytes.
        levels.wck_ratio[index] = words[59 + index * 4] as u8;
    }
    checked(levels, LEVELS)
}
/// `DpmClocks_315_t`: DcfClocks, DispClocks, DppClocks, SocClocks, VClocks,
/// DClocks and SocVoltage at four words each, then four `DfPstateTable_t`
/// of FClk/MemClk/Voltage, then the counts. There is no WCK ratio: Linux's
/// `dcn315_clk_mgr_helper_populate_bw_params` sets every entry's to 1.
fn parse_315(words: &[u32; (TABLE_SIZE / 4) as usize]) -> Result<Levels, Error> {
    let array = |start: usize| {
        let mut out = [0u32; LEVELS];
        out[..LEVELS_315].copy_from_slice(&words[start..start + LEVELS_315]);
        out
    };
    let counts = words[40];
    let mut levels = Levels {
        dcfclk: array(0),
        dispclk: array(4),
        dppclk: array(8),
        socclk: array(12),
        fclk: [0; DF_PSTATES],
        memclk: [0; DF_PSTATES],
        wck_ratio: [0; DF_PSTATES],
        dcfclk_levels: counts as u8,
        display_levels: (counts >> 8) as u8,
        socclk_levels: (counts >> 16) as u8,
        df_pstates: words[41] as u8,
        min_gfxclk: words[42],
        max_gfxclk: words[43],
    };
    for index in 0..DF_PSTATES {
        levels.fclk[index] = words[28 + index * 3];
        levels.memclk[index] = words[29 + index * 3];
    }
    checked(levels, LEVELS_315)
}
/// Refuse a table whose enabled counts exceed what its layout holds, or
/// whose enabled clocks are not ones Linux would accept.
fn checked(levels: Levels, max_levels: usize) -> Result<Levels, Error> {
    let enabled = [
        (levels.dcfclk_levels, &levels.dcfclk[..]),
        (levels.display_levels, &levels.dispclk[..]),
        (levels.display_levels, &levels.dppclk[..]),
        (levels.socclk_levels, &levels.socclk[..]),
    ];
    for (count, values) in enabled {
        if count == 0 || count as usize > max_levels {
            return Err(Error::Unsupported);
        }
        if !values[..count as usize].iter().copied().all(valid_clock) {
            return Err(Error::Unsupported);
        }
    }
    if levels.df_pstates == 0 || levels.df_pstates as usize > DF_PSTATES {
        return Err(Error::Unsupported);
    }
    if !levels.fclk[..levels.df_pstates as usize]
        .iter()
        .chain(levels.memclk[..levels.df_pstates as usize].iter())
        .copied()
        .all(valid_clock)
    {
        return Err(Error::Unsupported);
    }
    Ok(levels)
}

/// The sole owner of the DCN314/DCN315 display clock mailbox. This is not the GFX
/// SMU interface: holding it does not grant power-management authority, and a
/// caller must still keep the GFX driver from touching the display messages.
#[derive(Debug)]
pub struct ClockManager(Engine<Mmio>);
impl ClockManager {
    /// # Safety
    /// Caller exclusively owns the MP1 display mailbox (C2PMSG_67/83/91 on
    /// DCN 3.1.4; C2PMSG_37/38 and MP1_C2PMSG_3 on DCN 3.1.5) for this
    /// object's lifetime, holds matching PCI authority and permanent register
    /// and pool mappings, and owns the pool's remaining memory. On DCN 3.1.5
    /// the message goes through NBIO's PCIE_INDEX2/DATA2 pair, which
    /// `amdgpu_smn` serializes against its other users. The table reservation
    /// is published to firmware, so it
    /// must not be reused unless this object is dropped after firmware stops
    /// writing it.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        let (mailbox, mp1, nbio) = if let Ok(mp1) = bank(
            gpu,
            discovery::HW_ID_MP1,
            &[(13, 0, 5)],
            0,
            RESPONSE_315 as u32,
        ) {
            // SMU 13.0.5 is Raphael's, and so is DCN 3.1.5's clock manager
            // (dc_clk_mgr_create picks it by DCN version).
            if crate::amdgpu_dcn_profile::Profile::resolve(gpu)
                != Ok(crate::amdgpu_dcn_profile::Profile::Dcn315)
                || mp1 != MP1_BASE_315 * 4
            {
                return Err(Error::Unsupported);
            }
            let nbio = bank(
                gpu,
                discovery::HW_ID_NBIF,
                NBIO_VERSIONS_315,
                0,
                PCIE_DATA2 as u32,
            )?;
            (Mailbox::Dcn315, mp1, Some(nbio))
        } else {
            // `dcn31_smu.c` is `dcn314_smu.c`: the same C2PMSG_67/83/91
            // registers and VBIOSSMC message IDs. The window differs by MP1
            // version: 13.0.4/13.0.11 put every C2PMSG register on `_BASE_IDX`
            // 1 (`mp_13_0_4_offset.h`), while the generic `psp_v13_0` family
            // — 13.0.0/13.0.2/13.0.5 in the headers, and 13.0.1/13.0.3 by the
            // same driver — puts them on `_BASE_IDX` 0. DPREFCLK is 600 MHz
            // on both (`dcn31_clk_mgr.c`,
            // `clk_mgr->base.dprefclk_khz = 600000`).
            let mp1 = bank(
                gpu,
                discovery::HW_ID_MP1,
                &[(13, 0, 4), (13, 0, 11)],
                1,
                RESPONSE as u32,
            )
            .or_else(|_| {
                bank(
                    gpu,
                    discovery::HW_ID_MP1,
                    &[(13, 0, 1), (13, 0, 3)],
                    0,
                    RESPONSE as u32,
                )
            })?;
            (Mailbox::Dcn314, mp1, None)
        };
        let table = pool
            .reserve(mailbox.table_size())
            .map_err(|_| Error::Allocation)?;
        Ok(Self(Engine {
            io: Mmio {
                regs: gpu.regs,
                mp1,
                nbio,
                table: table.mapping(),
            },
            authority,
            mailbox,
            table,
            clocks: Clocks::default(),
            levels: None,
            dprefclk_khz: match mailbox {
                Mailbox::Dcn314 => DPREFCLK_KHZ,
                Mailbox::Dcn315 => 0,
            },
            pstate_supported: true,
        }))
    }
    /// Verify the mailbox answers and latch the firmware's DPM levels. Until
    /// this succeeds no clock request can be validated, so `update` fails.
    pub async fn start(&mut self) -> Result<Levels, Error> {
        self.0.send(MSG_TEST, 0).await?;
        self.0.send(MSG_GET_VERSION, 0).await?;
        if self.0.mailbox == Mailbox::Dcn315 {
            // dcn315_clk_mgr_construct: DPREFCLK is the firmware's answer, in
            // MHz. A value Linux's clock check would not accept is refused
            // rather than synthesised into every pixel clock.
            let mhz = self.0.send(MSG_GET_DPREFCLK_315, 0).await?;
            if !valid_clock(mhz) {
                return Err(Error::Unsupported);
            }
            self.0.dprefclk_khz = mhz * 1000;
        }
        let levels = self.0.read_levels().await?;
        self.0.levels = Some(levels);
        Ok(levels)
    }
    pub fn levels(&self) -> Option<Levels> {
        self.0.levels
    }
    pub fn clocks(&self) -> Clocks {
        self.0.clocks
    }
    /// The DPREFCLK the DP DTOs synthesise pixel clocks from: DCN 3.1.4's
    /// fixed 600 MHz, or what DCN 3.1.5's firmware reported to `start`
    /// (`dcn315_smu_get_dpref_clk`) — zero before then.
    pub fn dprefclk_khz(&self) -> u32 {
        self.0.dprefclk_khz
    }
    /// Whether the mode being applied can take a DRAM clock change (only in
    /// vactive on DCN 3.1.x). On DCN 3.1.5 an unsupported change locks
    /// p-state on the next `update`; DCN 3.1.4's clock manager ignores it, as
    /// Linux's does.
    pub fn set_pstate_support(&mut self, supported: bool) {
        self.0.pstate_supported = supported;
    }
    /// Apply a clock request in Linux's order. `safe_to_lower` must only be
    /// set when every pipe has already been reprogrammed for the lower clocks.
    /// The returned clocks are what was actually applied.
    pub async fn update(
        &mut self,
        requested: Clocks,
        safe_to_lower: bool,
        consumers: &mut impl Consumers,
    ) -> Result<Clocks, Error> {
        self.0.apply(requested, safe_to_lower, consumers).await
    }
    /// Release the display idle optimizations so the PHY reference clock and
    /// DF requests stay up while a stream is live.
    pub async fn enter_mission_mode(&mut self) -> Result<(), Error> {
        self.0.send(MSG_SET_IDLE_OPTIMIZATIONS, 0).await.map(|_| ())
    }
}
fn bank(
    gpu: &AmdGpu,
    id: u16,
    versions: &[(u8, u8, u8)],
    index: usize,
    last: u32,
) -> Result<u64, Error> {
    crate::amdgpu_psp_ring::bank(gpu, id, versions, index, last).map_err(|_| Error::Unsupported)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn_clk_tests.rs"]
mod tests;
