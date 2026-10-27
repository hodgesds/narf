//! Navi22 DCN3.0 and Phoenix DCN3.1.4 output timing generator (OPTC). Register offsets and field layouts
//! are `dcn_3_1_4_offset.h`/`dcn_3_1_4_sh_mask.h` at DCN base index 2;
//! sequencing follows Linux `dcn10_optc.c::optc1_program_timing`,
//! `optc1_program_global_sync`, `dcn30_optc.c::optc3_set_odm_bypass` and
//! `dcn31_optc.c::optc31_enable_crtc`/`optc31_disable_crtc`.
//!
//! Pixel blanking is not here: from DCN2 onwards a stream is blanked by the
//! OPP's display pattern generator, not by the timing generator, so this module
//! only starts and stops the timing itself.
use crate::{
    amdgpu::AmdGpu, amdgpu_dcn_clk::Error, amdgpu_dcn_profile::Profile, amdgpu_dml::Timing,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// OTG instance block, stride 0x80.
// Profile selects DCN30 or DCN314; shared ids below were compared against
// both Linux offset and mask headers. Generation differences stay explicit.
// linux-ctx: hdr=dcn seg=2
const OTG_H_TOTAL: u64 = 0x1b2a; // linux: mmOTG0_OTG_H_TOTAL
const OTG_H_BLANK_START_END: u64 = 0x1b2b; // linux: mmOTG0_OTG_H_BLANK_START_END
const OTG_H_SYNC_A: u64 = 0x1b2c; // linux: mmOTG0_OTG_H_SYNC_A
const OTG_H_SYNC_A_CNTL: u64 = 0x1b2d; // linux: mmOTG0_OTG_H_SYNC_A_CNTL
const OTG_H_TIMING_CNTL: u64 = 0x1b2e; // linux: mmOTG0_OTG_H_TIMING_CNTL
const OTG_V_TOTAL: u64 = 0x1b2f; // linux: mmOTG0_OTG_V_TOTAL
const OTG_V_TOTAL_MIN: u64 = 0x1b30; // linux: mmOTG0_OTG_V_TOTAL_MIN
const OTG_V_TOTAL_MAX: u64 = 0x1b31; // linux: mmOTG0_OTG_V_TOTAL_MAX
const OTG_V_BLANK_START_END: u64 = 0x1b36; // linux: mmOTG0_OTG_V_BLANK_START_END
const OTG_V_SYNC_A: u64 = 0x1b37; // linux: mmOTG0_OTG_V_SYNC_A
const OTG_V_SYNC_A_CNTL: u64 = 0x1b38; // linux: mmOTG0_OTG_V_SYNC_A_CNTL
const OTG_CONTROL: u64 = 0x1b41; // linux: mmOTG0_OTG_CONTROL
const OTG_INTERLACE_CONTROL: u64 = 0x1b44; // linux: mmOTG0_OTG_INTERLACE_CONTROL
                                           // DCN 3.1.4 offsets; otg() adds 1 on Navi22, giving the DCN30 registers.
const OTG_CLOCK_CONTROL: u64 = 0x1b85; // linux: mmOTG0_OTG_CLOCK_CONTROL - 1
const OTG_VSTARTUP_PARAM: u64 = 0x1b86; // linux: mmOTG0_OTG_VSTARTUP_PARAM - 1
const OTG_VUPDATE_PARAM: u64 = 0x1b87; // linux: mmOTG0_OTG_VUPDATE_PARAM - 1
const OTG_VREADY_PARAM: u64 = 0x1b88; // linux: mmOTG0_OTG_VREADY_PARAM - 1
const OTG_STRIDE: u64 = 0x80; // linux: mmOTG1_OTG_H_TOTAL - mmOTG0_OTG_H_TOTAL
                              // ODM instance block, stride 0x10.
const OPTC_DATA_SOURCE_SELECT: u64 = 0x1acb; // linux: mmODM0_OPTC_DATA_SOURCE_SELECT
const OPTC_WIDTH_CONTROL: u64 = 0x1ace; // linux: mmODM0_OPTC_WIDTH_CONTROL
const OPTC_MEMORY_CONFIG: u64 = 0x1ad0; // linux: mmODM0_OPTC_MEMORY_CONFIG
                                        // linux: mmODM1_OPTC_DATA_SOURCE_SELECT - mmODM0_OPTC_DATA_SOURCE_SELECT
const ODM_STRIDE: u64 = 0x10;
// Vertical timing generator, stride 1.
// linux: n/a (DCN 3.1.4 path; Navi22 uses mmVTG0_CONTROL inline in otg_vtg)
const VTG_CONTROL: u64 = 0x052d;
/// The highest register this module touches, for the bank bound.
#[cfg(feature = "kernel-test")]
// linux: n/a (test-only bank bound)
const LAST_REG: u32 = (OTG_VREADY_PARAM + 3 * OTG_STRIDE) as u32;
/// Totals, blank and sync positions are 15-bit; VSTARTUP is 10-bit and the
/// VUPDATE width 10-bit. Programming a mode whose counts do not fit is refused.
const COUNT_BITS: u32 = 15; // linux: n/a (width of OTG0_OTG_H_TOTAL__OTG_H_TOTAL_MASK 0x7fff)
                            // linux: n/a (width of OTG0_OTG_VSTARTUP_PARAM__VSTARTUP_START_MASK 0x3ff)
const VSTARTUP_BITS: u32 = 10;
// linux: n/a (width of OTG0_OTG_VUPDATE_PARAM__VUPDATE_WIDTH_MASK 0x3ff0000)
const VUPDATE_WIDTH_BITS: u32 = 10;
// linux: n/a (width of OTG0_OTG_VUPDATE_PARAM__VUPDATE_OFFSET_MASK 0xffff)
const OFFSET_BITS: u32 = 16;
/// `OPTC_SEG*_SRC_SEL` parks a segment with all ones.
const SEGMENT_PARKED: u32 = 0xf; // linux: n/a (literal 0xf in dcn30_optc.c:optc3_set_odm_bypass)
/// `ODM0_OPTC_WIDTH_CONTROL__OPTC_SEGMENT_WIDTH_MASK` is 0x00001FFF, so one
/// OPP segment carries at most 8191 active pixels.
///
/// This is the binding limit on a mode's width for this path, and it is
/// narrower than the timing counters: `optc1_validate_timing` bounds h_total
/// and v_total at `OTG_H_TOTAL`'s mask plus one, which [`COUNT_BITS`] already
/// enforces at 32768. The segment is the tighter constraint because
/// `optc1_set_odm_bypass` puts the whole active width into ONE segment —
/// splitting a wider mode needs ODM combine, which this pipeline does not do.
// linux: n/a (width of ODM0_OPTC_WIDTH_CONTROL__OPTC_SEGMENT_WIDTH_MASK, checked below)
const SEGMENT_WIDTH_BITS: u32 = 13;
/// The widest active region one OPP segment can carry, inclusive.
// linux: ODM0_OPTC_WIDTH_CONTROL__OPTC_SEGMENT_WIDTH_MASK
pub const MAX_SEGMENT_WIDTH: u32 = (1 << SEGMENT_WIDTH_BITS) - 1;

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
    regs: crate::amdgpu_reg_window::Window,
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
    profile: Profile,
}
impl<I: Io> Engine<I> {
    fn otg(&self, reg: u64) -> u64 {
        // DCN30 inserts a register before CLOCK_CONTROL, moving the clock
        // and global-sync quartet by one dword. Earlier timing ids match.
        reg + self.instance as u64 * OTG_STRIDE
            + u64::from(self.profile.is_dcn30() && reg >= OTG_CLOCK_CONTROL)
    }
    fn segment_shift(&self) -> u32 {
        if self.profile.is_dcn30() {
            8 // linux: ODM0_OPTC_DATA_SOURCE_SELECT__OPTC_SEG0_SRC_SEL__SHIFT
        } else {
            16 // linux: n/a (DCN 3.1.4 path)
        }
    }
    fn segments(&self, first: u32) -> u32 {
        // linux-lit: 4=ODM0_OPTC_DATA_SOURCE_SELECT__OPTC_SEG1_SRC_SEL__SHIFT - ODM0_OPTC_DATA_SOURCE_SELECT__OPTC_SEG0_SRC_SEL__SHIFT
        // linux-lit: 8=ODM0_OPTC_DATA_SOURCE_SELECT__OPTC_SEG2_SRC_SEL__SHIFT - ODM0_OPTC_DATA_SOURCE_SELECT__OPTC_SEG0_SRC_SEL__SHIFT
        // linux-lit: 12=ODM0_OPTC_DATA_SOURCE_SELECT__OPTC_SEG3_SRC_SEL__SHIFT - ODM0_OPTC_DATA_SOURCE_SELECT__OPTC_SEG0_SRC_SEL__SHIFT
        (first | SEGMENT_PARKED << 4 | SEGMENT_PARKED << 8 | SEGMENT_PARKED << 12)
            << self.segment_shift()
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
        // linux-lit: 0x7fff7fff=OTG0_OTG_H_SYNC_A__OTG_H_SYNC_A_START_MASK | OTG0_OTG_H_SYNC_A__OTG_H_SYNC_A_END_MASK
        // linux-lit: 16=OTG0_OTG_H_SYNC_A__OTG_H_SYNC_A_END__SHIFT
        self.update(self.otg(OTG_H_SYNC_A), 0x7fff_7fff, h_sync_end << 16)?;
        self.update(
            self.otg(OTG_H_BLANK_START_END),
            // linux: OTG0_OTG_H_BLANK_START_END__OTG_H_BLANK_START_MASK | OTG0_OTG_H_BLANK_START_END__OTG_H_BLANK_END_MASK
            0x7fff_7fff,
            // linux-lit: 16=OTG0_OTG_H_BLANK_START_END__OTG_H_BLANK_END__SHIFT
            h_blank_start | h_blank_end << 16,
        )?;
        // The register field means "negative polarity", so it is the inverse of
        // what the mode declares.
        self.update(
            self.otg(OTG_H_SYNC_A_CNTL),
            1, // linux: OTG0_OTG_H_SYNC_A_CNTL__OTG_H_SYNC_A_POL_MASK
            u32::from(!timing.h_sync_positive),
        )?;
        self.set(self.otg(OTG_V_TOTAL), v_total)?;
        // With V_TOTAL_CONTROL off these must still match V_TOTAL, or a
        // variable-refresh range left by firmware would retime the stream.
        self.set(self.otg(OTG_V_TOTAL_MIN), v_total)?;
        self.set(self.otg(OTG_V_TOTAL_MAX), v_total)?;
        // linux-lit: 0x7fff7fff=OTG0_OTG_V_SYNC_A__OTG_V_SYNC_A_START_MASK | OTG0_OTG_V_SYNC_A__OTG_V_SYNC_A_END_MASK
        // linux-lit: 16=OTG0_OTG_V_SYNC_A__OTG_V_SYNC_A_END__SHIFT
        self.update(self.otg(OTG_V_SYNC_A), 0x7fff_7fff, v_sync_end << 16)?;
        self.update(
            self.otg(OTG_V_BLANK_START_END),
            // linux: OTG0_OTG_V_BLANK_START_END__OTG_V_BLANK_START_MASK | OTG0_OTG_V_BLANK_START_END__OTG_V_BLANK_END_MASK
            0x7fff_7fff,
            // linux-lit: 16=OTG0_OTG_V_BLANK_START_END__OTG_V_BLANK_END__SHIFT
            v_blank_start | v_blank_end << 16,
        )?;
        self.update(
            self.otg(OTG_V_SYNC_A_CNTL),
            1, // linux: OTG0_OTG_V_SYNC_A_CNTL__OTG_V_SYNC_A_POL_MASK
            u32::from(!timing.v_sync_positive),
        )?;
        // This owner admits progressive modes only. Firmware may have left
        // the generator in interlace even though the new counters are valid.
        // linux: OTG0_OTG_INTERLACE_CONTROL__OTG_INTERLACE_ENABLE_MASK
        self.update(self.otg(OTG_INTERLACE_CONTROL), 1, 0)?;
        // Park the vertical timing generator before moving its reference.
        self.update(self.otg_vtg(), 1 << 31, 0)?; // linux-lit: 31=VTG0_CONTROL__VTG0_ENABLE__SHIFT
                                                  // DisplayPort starts counting at the first line of the blank, and a
                                                  // progressive stream has no field number.
                                                  // linux-lit: 12=OTG0_OTG_CONTROL__OTG_START_POINT_CNTL__SHIFT
                                                  // linux-lit: 13=OTG0_OTG_CONTROL__OTG_FIELD_NUMBER_CNTL__SHIFT
        self.update(self.otg(OTG_CONTROL), 1 << 12 | 1 << 13, 1 << 12)?;
        self.program_global_sync(sync)?;
        // optc1_program_timing -> optc1_set_vtg_params(program_fp2=true).
        // VTG supplies HUBP's vertical timing in the DCFCLK domain: enabling
        // it alone leaves prefetch aligned to the previous mode (or zero).
        let fp2 = sync.v_startup_lines.saturating_sub(v_blank_end + 1);
        self.update(
            self.otg_vtg(),
            // linux: VTG0_CONTROL__VTG0_FP2_MASK | VTG0_CONTROL__VTG0_VCOUNT_INIT_MASK
            0x7fff_7fff,
            // linux-lit: 16=VTG0_CONTROL__VTG0_VCOUNT_INIT__SHIFT
            v_blank_start << 16 | fits(fp2, COUNT_BITS)?,
        )?;
        // One OPP segment feeding this OTG: no ODM combine, no memory split,
        // and no horizontal timing division.
        self.set(
            self.odm(OPTC_DATA_SOURCE_SELECT),
            self.segments(self.instance as u32),
        )?;
        // linux-lit: 0x3=OTG0_OTG_H_TIMING_CNTL__OTG_H_TIMING_DIV_MODE_MASK
        self.update(self.otg(OTG_H_TIMING_CNTL), 0x3, 0)?;
        self.set(self.odm(OPTC_MEMORY_CONFIG), 0)?;
        self.update(
            self.odm(OPTC_WIDTH_CONTROL),
            0x1fff, // linux: ODM0_OPTC_WIDTH_CONTROL__OPTC_SEGMENT_WIDTH_MASK
            fits(timing.h_active, SEGMENT_WIDTH_BITS)?,
        )?;
        self.state = State::Programmed;
        Ok(())
    }
    /// `optc1_program_timing` with a TMDS signal: start point and field
    /// number zero.
    fn program_tmds_timing(&mut self, timing: &Timing, sync: &GlobalSync) -> Result<(), Error> {
        self.program_timing(timing, sync)?;
        // linux-lit: 12=OTG0_OTG_CONTROL__OTG_START_POINT_CNTL__SHIFT
        // linux-lit: 13=OTG0_OTG_CONTROL__OTG_FIELD_NUMBER_CNTL__SHIFT
        self.update(self.otg(OTG_CONTROL), 1 << 12 | 1 << 13, 0)
    }
    fn otg_vtg(&self) -> u64 {
        let base = if self.profile.is_dcn30() {
            0x0528 // linux: mmVTG0_CONTROL
        } else {
            VTG_CONTROL
        };
        base + self.instance as u64
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
                // linux-lit: 16=OTG0_OTG_VUPDATE_PARAM__VUPDATE_WIDTH__SHIFT
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
        if self.profile.is_dcn30() {
            // link_set_dpms_on -> optc3_set_out_mux(OUT_MUX_DIO).
            // These owners support the DIO HDMI/DP encoders. Select that
            // destination explicitly instead of inheriting firmware routing.
            // linux: OTG0_OTG_CONTROL__OTG_OUT_MUX_MASK
            self.update(self.otg(OTG_CONTROL), 1 << 20, 0)?;
        }
        self.update(
            self.odm(OPTC_DATA_SOURCE_SELECT),
            // linux-lit: 0xf=ODM0_OPTC_DATA_SOURCE_SELECT__OPTC_SEG0_SRC_SEL_MASK >> ODM0_OPTC_DATA_SOURCE_SELECT__OPTC_SEG0_SRC_SEL__SHIFT
            0xf << self.segment_shift(),
            (self.instance as u32) << self.segment_shift(),
        )?;
        // linux-lit: 31=VTG0_CONTROL__VTG0_ENABLE__SHIFT
        self.update(self.otg_vtg(), 1 << 31, 1 << 31)?;
        let disable_point = if self.profile.is_dcn30() {
            3 // linux: n/a (literal in dcn10_optc.c:optc1_enable_crtc, OTG_DISABLE_POINT_CNTL)
        } else {
            2 // linux: n/a (DCN 3.1.4 path)
        };
        // linux-lit: 0x301=OTG0_OTG_CONTROL__OTG_DISABLE_POINT_CNTL_MASK | OTG0_OTG_CONTROL__OTG_MASTER_EN_MASK
        // linux-lit: 8=OTG0_OTG_CONTROL__OTG_DISABLE_POINT_CNTL__SHIFT
        // linux-lit: 1=OTG0_OTG_CONTROL__OTG_MASTER_EN_MASK
        self.update(self.otg(OTG_CONTROL), 0x301, disable_point << 8 | 1)?;
        self.state = State::Running;
        Ok(())
    }
    /// `optc31_disable_crtc`: park every segment, drop the master enable, stop
    /// the vertical timing generator and wait for the block to go idle.
    async fn disable(&mut self) -> Result<(), Error> {
        if self.profile == Profile::Dcn314 {
            self.set(
                self.odm(OPTC_DATA_SOURCE_SELECT),
                self.segments(SEGMENT_PARKED),
            )?;
            self.set(self.odm(OPTC_MEMORY_CONFIG), 0)?;
            self.update(self.otg(OTG_CONTROL), 1, 0)?;
        } else {
            // DCN30 uses optc1_disable_crtc: retire at the first blank line
            // before changing ODM routing, rather than cutting the live mux.
            // linux-lit: 0x301=OTG0_OTG_CONTROL__OTG_DISABLE_POINT_CNTL_MASK | OTG0_OTG_CONTROL__OTG_MASTER_EN_MASK
            // linux-lit: 8=OTG0_OTG_CONTROL__OTG_DISABLE_POINT_CNTL__SHIFT
            self.update(self.otg(OTG_CONTROL), 0x301, 3 << 8)?;
        }
        self.update(self.otg_vtg(), 1 << 31, 0)?; // linux-lit: 31=VTG0_CONTROL__VTG0_ENABLE__SHIFT
        let clock_control = self.otg(OTG_CLOCK_CONTROL);
        let deadline = narf_time::Deadline::after_ms(100);
        loop {
            let value = self.access(|io| io.read(clock_control))?;
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
            // linux-lit: 16=OTG0_OTG_CLOCK_CONTROL__OTG_BUSY__SHIFT
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

/// One owned DCN30/DCN314 timing generator. Programming it does not light a panel:
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
        let profile = Profile::resolve(gpu)?;
        if instance >= profile.pipes() {
            return Err(Error::Invalid);
        }
        let last = OTG_VREADY_PARAM
            + u64::from(profile.is_dcn30())
            + u64::from(profile.pipes() - 1) * OTG_STRIDE;
        let base = profile.bank(gpu, 2, last as u32)?; // linux-lit: 2=mmOTG0_OTG_H_TOTAL_BASE_IDX
                                                       // linux-ctx: reset
        Ok(Self(Engine {
            io: Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                base,
            },
            authority,
            instance,
            state: State::Idle,
            profile,
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
    /// `optc1_program_timing` for a TMDS (HDMI/DVI) signal, which counts
    /// from start point 0 rather than DisplayPort's first blank line.
    pub fn program_tmds_timing(&mut self, timing: &Timing, sync: &GlobalSync) -> Result<(), Error> {
        self.0.program_tmds_timing(timing, sync)
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
