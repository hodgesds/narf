//! DCN314 display clock manager. The display clock interface is a mailbox on
//! MP1 that is distinct from the GFX SMU's own message space: it uses
//! C2PMSG_67/83/91 where the power driver uses 66/82/90, and its message ids
//! are the VBIOSSMC set, not PPSMC. Message ids, parameter units and the
//! programming order follow Linux `dcn314_smu.c` and `dcn314_clk_mgr.c`;
//! register indices follow `mp_13_0_4_offset.h`.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as discovery,
    amdgpu_vram::{Pool, Reservation},
};
use core::{
    future::Future,
    sync::atomic::{fence, Ordering},
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const MSG: u64 = 0x283; // MP1_SMN_C2PMSG_67
const PARAM: u64 = 0x293; // MP1_SMN_C2PMSG_83
const RESPONSE: u64 = 0x29b; // MP1_SMN_C2PMSG_91

const MSG_TEST: u32 = 0x01;
const MSG_GET_VERSION: u32 = 0x02;
const MSG_SET_DISPCLK: u32 = 0x04;
const MSG_SET_DPPCLK: u32 = 0x06;
const MSG_SET_HARD_MIN_DCFCLK: u32 = 0x07;
const MSG_SET_MIN_DEEP_SLEEP_DCFCLK: u32 = 0x08;
const MSG_SET_DRAM_ADDR_HIGH: u32 = 0x0e;
const MSG_SET_DRAM_ADDR_LOW: u32 = 0x0f;
const MSG_TRANSFER_TABLE_SMU2DRAM: u32 = 0x10;
const MSG_SET_IDLE_OPTIMIZATIONS: u32 = 0x12;
const MSG_SET_DTBCLK: u32 = 0x17;

const STATUS_BUSY: u32 = 0x00;
const STATUS_OK: u32 = 0x01;

const TABLE_DPMCLOCKS: u32 = 4;
/// `DpmClocks314_t`: six 8-entry clock arrays, voltages, four DF p-states,
/// the enabled-level counts and the GFX clock range.
const TABLE_SIZE: u64 = 304;
const LEVELS: usize = 8;
const DF_PSTATES: usize = 4;

/// DCN314 drives DP reference and DTB from a fixed 600 MHz source
/// (`dcn314_clk_mgr_construct`). Spread spectrum would adjust the DP DTO
/// source only; this path does not enable it.
pub const DPREFCLK_KHZ: u32 = 600_000;
pub const DTBCLK_KHZ: u32 = 600_000;
/// Linux clamps DPPCLK to 100 MHz to keep an eDP panel plus a 4K monitor from
/// underflowing when the global clock drops.
const DPPCLK_FLOOR_KHZ: u32 = 100_000;

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

trait Io: Send {
    fn read(&mut self, reg: u64) -> u32;
    fn write(&mut self, reg: u64, value: u32);
    fn read_table(&mut self, offset: u64) -> u32;
    fn write_table(&mut self, offset: u64, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    mp1: u64,
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
    table: Reservation,
    clocks: Clocks,
    levels: Option<Levels>,
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
        loop {
            let value = self.access(|io| io.read(RESPONSE))?;
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
            if value != STATUS_BUSY {
                return Ok(value);
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
        self.access(|io| {
            io.write(RESPONSE, STATUS_BUSY);
            io.write(PARAM, param);
            io.write(MSG, message);
        })?;
        let result = self.settled().await?;
        if result != STATUS_OK {
            // Leave the mailbox usable for the next command, as Linux does
            // after a rejection, then report the firmware's own status.
            self.access(|io| io.write(RESPONSE, STATUS_OK))?;
            return Err(Error::Rejected(result));
        }
        self.access(|io| io.read(PARAM))
    }
    /// Read back the firmware's DPM table. The buffer is zeroed first so a
    /// firmware that writes nothing cannot be mistaken for a valid table.
    async fn read_levels(&mut self) -> Result<Levels, Error> {
        let address = self.table.address();
        self.table.publish();
        self.access(|io| {
            for offset in (0..TABLE_SIZE).step_by(4) {
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
            for (index, word) in words.iter_mut().enumerate() {
                *word = io.read_table(index as u64 * 4);
            }
            words
        })?;
        parse(&words)
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
        if !safe_to_lower && target.dtbclk_enabled && !self.clocks.dtbclk_enabled {
            self.send(MSG_SET_DTBCLK, 1).await?;
            self.clocks.dtbclk_enabled = true;
        }
        if safe_to_lower && !target.dtbclk_enabled && self.clocks.dtbclk_enabled {
            self.send(MSG_SET_DTBCLK, 0).await?;
            self.clocks.dtbclk_enabled = false;
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
            self.send(MSG_SET_DISPCLK, mhz_ceil(target.dispclk_khz))
                .await?;
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
    let enabled = [
        (levels.dcfclk_levels, &levels.dcfclk[..]),
        (levels.display_levels, &levels.dispclk[..]),
        (levels.display_levels, &levels.dppclk[..]),
        (levels.socclk_levels, &levels.socclk[..]),
    ];
    for (count, values) in enabled {
        if count == 0 || count as usize > LEVELS {
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

/// The sole owner of the DCN314 display clock mailbox. This is not the GFX
/// SMU interface: holding it does not grant power-management authority, and a
/// caller must still keep the GFX driver from touching the display messages.
#[derive(Debug)]
pub struct ClockManager(Engine<Mmio>);
impl ClockManager {
    /// # Safety
    /// Caller exclusively owns the MP1 display mailbox (C2PMSG_67/83/91) for
    /// this object's lifetime, holds matching PCI authority and permanent
    /// register and pool mappings, and owns the pool's remaining memory. The
    /// table reservation is published to firmware, so it must not be reused
    /// unless this object is dropped after firmware stops writing it.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        let mp1 = bank(
            gpu,
            discovery::HW_ID_MP1,
            &[(13, 0, 4), (13, 0, 11)],
            1,
            RESPONSE as u32,
        )?;
        let table = pool.reserve(TABLE_SIZE).map_err(|_| Error::Allocation)?;
        Ok(Self(Engine {
            io: Mmio {
                regs: gpu.regs,
                mp1,
                table: table.mapping(),
            },
            authority,
            table,
            clocks: Clocks::default(),
            levels: None,
        }))
    }
    /// Verify the mailbox answers and latch the firmware's DPM levels. Until
    /// this succeeds no clock request can be validated, so `update` fails.
    pub async fn start(&mut self) -> Result<Levels, Error> {
        self.0.send(MSG_TEST, 0).await?;
        self.0.send(MSG_GET_VERSION, 0).await?;
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
