//! DCN 3.1.4 output timing generator (OPTC). Register offsets and field layouts
//! are `dcn_3_1_4_offset.h`/`dcn_3_1_4_sh_mask.h` at DCN base index 2;
//! sequencing follows Linux `dcn10_optc.c::optc1_program_timing`,
//! `optc1_program_global_sync`, `dcn30_optc.c::optc3_set_odm_bypass` and
//! `dcn31_optc.c::optc31_enable_crtc`/`optc31_disable_crtc`.
//!
//! Pixel blanking is not here: from DCN2 onwards a stream is blanked by the
//! OPP's display pattern generator, not by the timing generator, so this module
//! only starts and stops the timing itself.
use crate::{
    amdgpu::AmdGpu, amdgpu_dcn_clk::Error, amdgpu_discovery as discovery, amdgpu_dml::Timing,
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

// OTG instance block, stride 0x80.
const OTG_H_TOTAL: u64 = 0x1b2a;
const OTG_H_BLANK_START_END: u64 = 0x1b2b;
const OTG_H_SYNC_A: u64 = 0x1b2c;
const OTG_H_SYNC_A_CNTL: u64 = 0x1b2d;
const OTG_H_TIMING_CNTL: u64 = 0x1b2e;
const OTG_V_TOTAL: u64 = 0x1b2f;
const OTG_V_TOTAL_MIN: u64 = 0x1b30;
const OTG_V_TOTAL_MAX: u64 = 0x1b31;
const OTG_V_BLANK_START_END: u64 = 0x1b36;
const OTG_V_SYNC_A: u64 = 0x1b37;
const OTG_V_SYNC_A_CNTL: u64 = 0x1b38;
const OTG_CONTROL: u64 = 0x1b41;
const OTG_CLOCK_CONTROL: u64 = 0x1b85;
const OTG_VSTARTUP_PARAM: u64 = 0x1b86;
const OTG_VUPDATE_PARAM: u64 = 0x1b87;
const OTG_VREADY_PARAM: u64 = 0x1b88;
const OTG_STRIDE: u64 = 0x80;
// ODM instance block, stride 0x10.
const OPTC_DATA_SOURCE_SELECT: u64 = 0x1acb;
const OPTC_WIDTH_CONTROL: u64 = 0x1ace;
const OPTC_MEMORY_CONFIG: u64 = 0x1ad0;
const ODM_STRIDE: u64 = 0x10;
// Vertical timing generator, stride 1.
const VTG_CONTROL: u64 = 0x052d;
/// The highest register this module touches, for the bank bound.
const LAST_REG: u32 = (OTG_VREADY_PARAM + 3 * OTG_STRIDE) as u32;
const INSTANCES: u8 = 4;

/// Totals, blank and sync positions are 15-bit; VSTARTUP is 10-bit and the
/// VUPDATE width 10-bit. Programming a mode whose counts do not fit is refused.
const COUNT_BITS: u32 = 15;
const VSTARTUP_BITS: u32 = 10;
const VUPDATE_WIDTH_BITS: u32 = 10;
const OFFSET_BITS: u32 = 16;
/// `OPTC_SEG*_SRC_SEL` parks a segment with all ones.
const SEGMENT_PARKED: u32 = 0xf;

/// The global sync positions the detile buffer needs, in pixels and lines. These
/// come from the mode math, not from the timing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalSync {
    pub v_startup_lines: u32,
    pub v_update_offset_pix: u32,
    pub v_update_width_pix: u32,
    pub v_ready_offset_pix: u32,
}

trait Io: Send {
    fn read(&mut self, reg: u64) -> u32;
    fn write(&mut self, reg: u64, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    base: u64,
}
impl Io for Mmio {
    fn read(&mut self, reg: u64) -> u32 {
        // SAFETY: constructor bounds the DCN bank and retains the mapping.
        unsafe { self.regs.read32(self.base + reg * 4) }
    }
    fn write(&mut self, reg: u64, value: u32) {
        // SAFETY: same bounded bank; this is the sole owner of this OTG.
        unsafe { self.regs.write32(self.base + reg * 4, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn fits(value: u32, bits: u32) -> Result<u32, Error> {
    if value >= 1 << bits {
        return Err(Error::Invalid);
    }
    Ok(value)
}
async fn delay(ms: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Idle,
    Programmed,
    Running,
}

#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    instance: u8,
    state: State,
}
impl<I: Io> Engine<I> {
    fn otg(&self, reg: u64) -> u64 {
        reg + self.instance as u64 * OTG_STRIDE
    }
    fn odm(&self, reg: u64) -> u64 {
        reg + self.instance as u64 * ODM_STRIDE
    }
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        self.access(|io| {
            let old = io.read(reg);
            if old == u32::MAX {
                return Err(Error::DeviceGone);
            }
            io.write(reg, (old & !mask) | (value & mask));
            if io.read(reg) & mask != value & mask {
                return Err(Error::Invalid);
            }
            Ok(())
        })?
    }
    fn set(&mut self, reg: u64, value: u32) -> Result<(), Error> {
        self.access(|io| io.write(reg, value))
    }
    /// `optc1_program_timing` for a progressive DisplayPort stream with one
    /// pixel per container, so no horizontal timing division and no interlace.
    fn program_timing(&mut self, timing: &Timing, sync: &GlobalSync) -> Result<(), Error> {
        if self.state == State::Running {
            // Retiming a live generator would tear; the caller must stop first.
            return Err(Error::Busy);
        }
        // The counters hold one less than the total.
        let h_total = fits(
            timing.h_total.checked_sub(1).ok_or(Error::Invalid)?,
            COUNT_BITS,
        )?;
        let v_total = fits(
            timing.v_total.checked_sub(1).ok_or(Error::Invalid)?,
            COUNT_BITS,
        )?;
        // Blank starts at the end of active plus front porch and ends a whole
        // active region later, counting backwards from the line end.
        let h_blank_start = fits(timing.h_total - timing.h_front_porch, COUNT_BITS)?;
        let h_blank_end = fits(h_blank_start - timing.h_active, COUNT_BITS)?;
        let v_blank_start = fits(timing.v_total - timing.v_front_porch, COUNT_BITS)?;
        let v_blank_end = fits(v_blank_start - timing.v_active, COUNT_BITS)?;
        let h_sync_end = fits(timing.h_sync_width, COUNT_BITS)?;
        let v_sync_end = fits(timing.v_sync_width, COUNT_BITS)?;

        self.set(self.otg(OTG_H_TOTAL), h_total)?;
        // Sync starts at zero and runs for its width.
        self.update(self.otg(OTG_H_SYNC_A), 0x7fff_7fff, h_sync_end << 16)?;
        self.update(
            self.otg(OTG_H_BLANK_START_END),
            0x7fff_7fff,
            h_blank_start | h_blank_end << 16,
        )?;
        // The register field means "negative polarity", so it is the inverse of
        // what the mode declares.
        self.update(
            self.otg(OTG_H_SYNC_A_CNTL),
            1,
            u32::from(!timing.h_sync_positive),
        )?;
        self.set(self.otg(OTG_V_TOTAL), v_total)?;
        // With V_TOTAL_CONTROL off these must still match V_TOTAL, or a
        // variable-refresh range left by firmware would retime the stream.
        self.set(self.otg(OTG_V_TOTAL_MIN), v_total)?;
        self.set(self.otg(OTG_V_TOTAL_MAX), v_total)?;
        self.update(self.otg(OTG_V_SYNC_A), 0x7fff_7fff, v_sync_end << 16)?;
        self.update(
            self.otg(OTG_V_BLANK_START_END),
            0x7fff_7fff,
            v_blank_start | v_blank_end << 16,
        )?;
        self.update(
            self.otg(OTG_V_SYNC_A_CNTL),
            1,
            u32::from(!timing.v_sync_positive),
        )?;
        // Park the vertical timing generator before moving its reference.
        self.update(self.otg_vtg(), 1 << 31, 0)?;
        // DisplayPort starts counting at the first line of the blank, and a
        // progressive stream has no field number.
        self.update(self.otg(OTG_CONTROL), 1 << 12 | 1 << 13, 1 << 12)?;
        self.program_global_sync(sync)?;
        // One OPP segment feeding this OTG: no ODM combine, no memory split,
        // and no horizontal timing division.
        self.set(
            self.odm(OPTC_DATA_SOURCE_SELECT),
            (self.instance as u32) << 16
                | SEGMENT_PARKED << 20
                | SEGMENT_PARKED << 24
                | SEGMENT_PARKED << 28,
        )?;
        self.update(self.otg(OTG_H_TIMING_CNTL), 0x3, 0)?;
        self.set(self.odm(OPTC_MEMORY_CONFIG), 0)?;
        self.update(
            self.odm(OPTC_WIDTH_CONTROL),
            0x1fff,
            fits(timing.h_active, 13)?,
        )?;
        self.state = State::Programmed;
        Ok(())
    }
    fn otg_vtg(&self) -> u64 {
        VTG_CONTROL + self.instance as u64
    }
    /// `optc1_program_global_sync`. A zero VStartup would mean the detile
    /// buffer is never given time to prefetch.
    fn program_global_sync(&mut self, sync: &GlobalSync) -> Result<(), Error> {
        if sync.v_startup_lines == 0 {
            return Err(Error::Invalid);
        }
        self.set(
            self.otg(OTG_VSTARTUP_PARAM),
            fits(sync.v_startup_lines, VSTARTUP_BITS)?,
        )?;
        self.set(
            self.otg(OTG_VUPDATE_PARAM),
            fits(sync.v_update_offset_pix, OFFSET_BITS)?
                | fits(sync.v_update_width_pix, VUPDATE_WIDTH_BITS)? << 16,
        )?;
        self.set(
            self.otg(OTG_VREADY_PARAM),
            fits(sync.v_ready_offset_pix, OFFSET_BITS)?,
        )
    }
    /// `optc31_enable_crtc`: the vertical timing generator goes first, then the
    /// master enable with the request disabled until the blank's first line.
    fn enable(&mut self) -> Result<(), Error> {
        if self.state != State::Programmed {
            return Err(Error::Busy);
        }
        self.update(
            self.odm(OPTC_DATA_SOURCE_SELECT),
            0xf << 16,
            (self.instance as u32) << 16,
        )?;
        self.update(self.otg_vtg(), 1 << 31, 1 << 31)?;
        self.update(self.otg(OTG_CONTROL), 0x301, 2 << 8 | 1)?;
        self.state = State::Running;
        Ok(())
    }
    /// `optc31_disable_crtc`: park every segment, drop the master enable, stop
    /// the vertical timing generator and wait for the block to go idle.
    async fn disable(&mut self) -> Result<(), Error> {
        self.set(
            self.odm(OPTC_DATA_SOURCE_SELECT),
            SEGMENT_PARKED << 16
                | SEGMENT_PARKED << 20
                | SEGMENT_PARKED << 24
                | SEGMENT_PARKED << 28,
        )?;
        self.set(self.odm(OPTC_MEMORY_CONFIG), 0)?;
        self.update(self.otg(OTG_CONTROL), 1, 0)?;
        self.update(self.otg_vtg(), 1 << 31, 0)?;
        let clock_control = self.otg(OTG_CLOCK_CONTROL);
        let deadline = narf_time::Deadline::after_ms(100);
        loop {
            let value = self.access(|io| io.read(clock_control))?;
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
            if value & 1 << 16 == 0 {
                self.state = State::Idle;
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay(1).await;
        }
    }
}

/// One owned DCN314 timing generator. Programming it does not light a panel:
/// the stream still has to be unblanked by the OPP and carried by the stream
/// encoder.
#[derive(Debug)]
pub struct Otg(Engine<Mmio>);
impl Otg {
    /// # Safety
    /// Caller exclusively owns this OTG instance, its ODM segment and its
    /// vertical timing generator for the object's lifetime, holds matching PCI
    /// authority and a permanent register mapping, and must not let another
    /// client retime the same instance.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        instance: u8,
    ) -> Result<Self, Error> {
        if instance >= INSTANCES {
            return Err(Error::Invalid);
        }
        let base =
            crate::amdgpu_psp_ring::bank(gpu, discovery::HW_ID_DCN, &[(3, 1, 4)], 2, LAST_REG)
                .map_err(|_| Error::Unsupported)?;
        Ok(Self(Engine {
            io: Mmio {
                regs: gpu.regs,
                base,
            },
            authority,
            instance,
            state: State::Idle,
        }))
    }
    pub fn state(&self) -> State {
        self.0.state
    }
    pub fn instance(&self) -> u8 {
        self.0.instance
    }
    /// Program the mode and its global sync positions. Refused while running.
    pub fn program_timing(&mut self, timing: &Timing, sync: &GlobalSync) -> Result<(), Error> {
        self.0.program_timing(timing, sync)
    }
    pub fn program_global_sync(&mut self, sync: &GlobalSync) -> Result<(), Error> {
        self.0.program_global_sync(sync)
    }
    pub fn enable(&mut self) -> Result<(), Error> {
        self.0.enable()
    }
    pub async fn disable(&mut self) -> Result<(), Error> {
        self.0.disable().await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn_otg_tests.rs"]
mod tests;
