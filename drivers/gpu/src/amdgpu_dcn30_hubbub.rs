//! Navi22 DCN3.0 HUBBUB arbiter: the DCHUB reference clock and the four
//! watermark sets. Sequences follow Linux `dcn30_hubbub.c::hubbub3_program_watermarks`
//! (via `dcn21_hubbub.c::hubbub21_program_{urgent,stutter,pstate}_watermarks`),
//! `dcn10_hubbub.c::hubbub1_allow_self_refresh_control` and
//! `dcn20_hubbub.c::hubbub2_get_dchub_ref_freq`; offsets and masks are
//! `dcn_3_0_0_offset.h` / `dcn_3_0_0_sh_mask.h` at DCN base index 2.
//!
//! Every set A–D receives the same values: the plan is computed at the pinned
//! (highest) clock state, and the DAL clock owner keeps memory and fabric
//! clocks hard-pinned, so the SMU never selects a set computed for a lower
//! clock. Self refresh (stutter) stays forced off until a plan that allows it
//! is validated. Linux masks oversized watermark values into the field; this
//! owner refuses them instead, since a wrapped watermark underflows the pipe.
use crate::{amdgpu::AmdGpu, amdgpu_dcn_profile::Profile, amdgpu_dml30::WatermarkSet};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// linux-ctx: hdr=dcn seg=2
const DF_REQ_OUTSTAND: u64 = 0x0505; // linux: mmDCHUBBUB_ARB_DF_REQ_OUTSTAND
const SAT_LEVEL: u64 = 0x0506; // linux: mmDCHUBBUB_ARB_SAT_LEVEL
const DRAM_STATE_CNTL: u64 = 0x0508; // linux: mmDCHUBBUB_ARB_DRAM_STATE_CNTL
/// `DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A`; each set is five dwords:
/// urgency, trip to memory, SR enter, SR exit, DRAM clock change.
const SET_A: u64 = 0x0509; // linux: mmDCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A
                           // linux: mmDCHUBBUB_ARB_DATA_URGENCY_WATERMARK_B - mmDCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A
const SET_STRIDE: u64 = 5;
const GLOBAL_TIMER_CNTL: u64 = 0x051f; // linux: mmDCHUBBUB_GLOBAL_TIMER_CNTL
/// `DCHUBBUB_ARB_FRAC_URG_BW_NOM_A`; NOM/FLIP pairs per set.
const FRAC_NOM_A: u64 = 0x053f; // linux: mmDCHUBBUB_ARB_FRAC_URG_BW_NOM_A
const LAST_REG: u32 = (FRAC_NOM_A + 7) as u32; // linux: mmDCHUBBUB_ARB_FRAC_URG_BW_FLIP_D
                                               // linux-ctx: reset
                                               // Field masks.
                                               // linux: DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A__DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A_MASK
const URGENCY: u32 = 0x3fff;
// linux: DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A__DCHUBBUB_ARB_VM_ROW_URGENCY_WATERMARK_A__SHIFT
const VM_ROW_URGENCY_SHIFT: u32 = 16;
// linux: DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_A__DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_A_MASK
const TRIP: u32 = 0x3fff;
// linux: DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A__DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A_MASK
const SR: u32 = 0xffff;
// linux: DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A__DCHUBBUB_ARB_VM_ROW_ALLOW_SR_ENTER_WATERMARK_A__SHIFT
const VM_ROW_SR_SHIFT: u32 = 16;
// linux: DCHUBBUB_ARB_FRAC_URG_BW_NOM_A__DCHUBBUB_ARB_FRAC_URG_BW_NOM_A_MASK
const FRAC: u32 = 0x3ff;
// linux: DCHUBBUB_ARB_DF_REQ_OUTSTAND__DCHUBBUB_ARB_MIN_REQ_OUTSTAND_MASK
const MIN_REQ_OUTSTAND: u32 = 0x001f_f000;
// linux: DCHUBBUB_ARB_DRAM_STATE_CNTL__DCHUBBUB_ARB_ALLOW_SELF_REFRESH_FORCE_VALUE_MASK
const SELF_REFRESH_FORCE_VALUE: u32 = 1 << 0;
// linux: DCHUBBUB_ARB_DRAM_STATE_CNTL__DCHUBBUB_ARB_ALLOW_SELF_REFRESH_FORCE_ENABLE_MASK
const SELF_REFRESH_FORCE_ENABLE: u32 = 1 << 1;
// linux: DCHUBBUB_GLOBAL_TIMER_CNTL__DCHUBBUB_GLOBAL_TIMER_REFDIV_MASK
const TIMER_REFDIV: u32 = 0xf;
// linux: DCHUBBUB_GLOBAL_TIMER_CNTL__DCHUBBUB_GLOBAL_TIMER_ENABLE_MASK
const TIMER_ENABLE: u32 = 1 << 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    /// A watermark does not fit its DCN3.0 field.
    Invalid,
    Revoked,
    DeviceGone,
    /// The DCHUB global timer is off or outside 40–60 MHz.
    Timer,
    /// A written register read back different.
    Readback,
}

pub(crate) trait Io: Send {
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
        // SAFETY: same bounded bank; this owner is exclusive.
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

#[derive(Debug)]
pub(crate) struct Engine<I: Io> {
    pub(crate) io: I,
    authority: Cap<BusDeviceCap, Write>,
}
impl<I: Io> Engine<I> {
    pub(crate) fn new_with(io: I, authority: Cap<BusDeviceCap, Write>) -> Self {
        Self { io, authority }
    }
    fn read(&mut self, reg: u64) -> Result<u32, Error> {
        let io = &mut self.io;
        let value = self
            .authority
            .invoke(Op(|| io.read(reg)))
            .map_err(|_| Error::Revoked)?;
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok(value)
    }
    fn write(&mut self, reg: u64, value: u32) -> Result<(), Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| io.write(reg, value)))
            .map_err(|_| Error::Revoked)
    }
    /// `REG_SET` then a masked read-back.
    fn set(&mut self, reg: u64, value: u32, mask: u32) -> Result<(), Error> {
        self.write(reg, value)?;
        if self.read(reg)? & mask != value & mask {
            return Err(Error::Readback);
        }
        Ok(())
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read(reg)?;
        self.set(reg, (old & !mask) | (value & mask), mask)
    }
    /// `hubbub2_get_dchub_ref_freq`, failing closed where Linux asserts.
    pub(crate) fn dchub_refclk_khz(&mut self, dccg_ref_khz: u32) -> Result<u32, Error> {
        let cntl = self.read(GLOBAL_TIMER_CNTL)?;
        if cntl & TIMER_ENABLE == 0 {
            return Err(Error::Timer);
        }
        // linux: n/a (ref_div == 2, literal in dcn20_hubbub.c:hubbub2_get_dchub_ref_freq)
        let khz = if cntl & TIMER_REFDIV == 2 {
            dccg_ref_khz / 2
        } else {
            dccg_ref_khz
        };
        // linux: n/a (40000..60000 kHz, literal in dcn20_hubbub.c:hubbub2_get_dchub_ref_freq)
        if !(40_000..=60_000).contains(&khz) {
            return Err(Error::Timer);
        }
        Ok(khz)
    }
    /// `hubbub3_program_watermarks(safe_to_lower = true)` with stutter off.
    pub(crate) fn program(&mut self, set: &WatermarkSet, refclk_khz: u32) -> Result<(), Error> {
        if set.urgent > URGENCY
            || set.urgent_latency > TRIP
            || set.sr_enter > SR
            || set.sr_exit > SR
            || set.dram_clock_change > SR
            || set.frac_urg_bw_nom > FRAC
            || set.frac_urg_bw_flip > FRAC
            || refclk_khz < 1000
        // linux: n/a (NARF: 1 MHz floor for refclk_mhz)
        {
            return Err(Error::Invalid);
        }
        for index in 0..4 {
            // linux: n/a (watermark sets A..D)
            let base = SET_A + index * SET_STRIDE;
            let both = |value: u32, shift: u32| value | value << shift;
            self.set(
                base,
                both(set.urgent, VM_ROW_URGENCY_SHIFT),
                // linux-lit: 16=DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A__DCHUBBUB_ARB_VM_ROW_URGENCY_WATERMARK_A__SHIFT
                URGENCY | URGENCY << 16,
            )?;
            // linux-lit: 1=mmDCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_A - mmDCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A
            self.set(base + 1, set.urgent_latency, TRIP)?;
            // linux-lit: 2=mmDCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A - mmDCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A
            self.set(base + 2, both(set.sr_enter, VM_ROW_SR_SHIFT), u32::MAX)?;
            // linux-lit: 3=mmDCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_A - mmDCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A
            self.set(base + 3, both(set.sr_exit, VM_ROW_SR_SHIFT), u32::MAX)?;
            self.set(
                // linux-lit: 4=mmDCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_A - mmDCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A
                base + 4,
                both(set.dram_clock_change, VM_ROW_SR_SHIFT),
                u32::MAX,
            )?;
            // linux-lit: 2=mmDCHUBBUB_ARB_FRAC_URG_BW_NOM_B - mmDCHUBBUB_ARB_FRAC_URG_BW_NOM_A
            self.set(FRAC_NOM_A + 2 * index, set.frac_urg_bw_nom, FRAC)?;
            // linux-lit: 2=mmDCHUBBUB_ARB_FRAC_URG_BW_NOM_B - mmDCHUBBUB_ARB_FRAC_URG_BW_NOM_A
            // linux-lit: 1=mmDCHUBBUB_ARB_FRAC_URG_BW_FLIP_A - mmDCHUBBUB_ARB_FRAC_URG_BW_NOM_A
            self.set(FRAC_NOM_A + 2 * index + 1, set.frac_urg_bw_flip, FRAC)?;
        }
        // linux: n/a (60 * refclk_mhz, literal in dcn30_hubbub.c:hubbub3_program_watermarks)
        self.set(SAT_LEVEL, 60 * (refclk_khz / 1000), u32::MAX)?;
        // linux: n/a (0x1FF, literal in dcn30_hubbub.c:hubbub3_program_watermarks)
        // linux-lit: 12=DCHUBBUB_ARB_DF_REQ_OUTSTAND__DCHUBBUB_ARB_MIN_REQ_OUTSTAND__SHIFT
        self.update(DF_REQ_OUTSTAND, MIN_REQ_OUTSTAND, 0x1ff << 12)?;
        // hubbub1_allow_self_refresh_control(false): FORCE_ENABLE=1, VALUE=0.
        self.update(
            DRAM_STATE_CNTL,
            SELF_REFRESH_FORCE_VALUE | SELF_REFRESH_FORCE_ENABLE,
            SELF_REFRESH_FORCE_ENABLE,
        )
    }
}

/// The owned DCN3.0 HUBBUB arbiter.
#[derive(Debug)]
pub struct Hubbub(Engine<Mmio>);
impl Hubbub {
    /// # Safety
    /// Caller exclusively owns the DCHUBBUB arbiter for the object's lifetime
    /// and holds matching PCI authority with a permanent register mapping.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu).map_err(|_| Error::Unsupported)?;
        if !profile.is_dcn30() {
            return Err(Error::Unsupported);
        }
        let base = profile
            .bank(gpu, 2, LAST_REG)
            .map_err(|_| Error::Unsupported)?;
        Ok(Self(Engine::new_with(
            Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                base,
            },
            authority,
        )))
    }
    /// The DCHUB reference every DLG/TTU field and watermark is counted in.
    pub fn dchub_refclk_khz(&mut self, dccg_ref_khz: u32) -> Result<u32, Error> {
        self.0.dchub_refclk_khz(dccg_ref_khz)
    }
    /// Program all four watermark sets and read them back.
    ///
    /// # Safety
    /// No HUBP may be fetching: lowering a watermark under a live pipe can
    /// underflow it (Linux only lowers with `safe_to_lower`).
    pub unsafe fn program(&mut self, set: &WatermarkSet, refclk_khz: u32) -> Result<(), Error> {
        self.0.program(set, refclk_khz)
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Fake {
        regs: Vec<u32>,
        writes: Vec<(u64, u32)>,
        stuck: Option<u64>,
    }
    impl Io for Fake {
        fn read(&mut self, reg: u64) -> u32 {
            self.regs[reg as usize]
        }
        fn write(&mut self, reg: u64, value: u32) {
            self.writes.push((reg, value));
            if self.stuck != Some(reg) {
                self.regs[reg as usize] = value;
            }
        }
    }
    fn engine() -> Engine<Fake> {
        Engine::new_with(
            Fake {
                regs: vec![0; LAST_REG as usize + 1],
                writes: Vec::new(),
                stuck: None,
            },
            Cap::bootstrap(),
        )
    }
    fn set() -> WatermarkSet {
        WatermarkSet {
            urgent: 247,
            urgent_latency: 191,
            sr_enter: 1104,
            sr_exit: 879,
            dram_clock_change: 20447,
            frac_urg_bw_nom: 11,
            frac_urg_bw_flip: 0,
        }
    }

    fn dcn30_hubbub_programs_all_sets_and_forces_stutter_off() -> TestResult {
        let mut e = engine();
        e.io.regs[DF_REQ_OUTSTAND as usize] = 0x1ff;
        if e.program(&set(), 50_000).is_err() {
            return TestResult::Fail("program");
        }
        // Literal ids: DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_D 0x518,
        // ALLOW_DRAM_CLK_CHANGE_WATERMARK_D 0x51c, FRAC_URG_BW_NOM_D 0x545.
        let r = &e.io.regs;
        if r[0x509] != 247 | 247 << 16
            || r[0x518] != r[0x509]
            || r[0x51c] != 20447 | 20447 << 16
            || r[0x50a] != 191
            || r[0x545] != 11
            || r[0x506] != 3000
            || r[0x505] != 0x1ff | 0x1ff << 12
            || r[0x508] & 3 != 2
        {
            return TestResult::Fail("watermark registers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn30-hubbub",
        dcn30_hubbub_programs_all_sets_and_forces_stutter_off
    );

    fn dcn30_hubbub_refuses_oversized_values_timer_and_readback() -> TestResult {
        let mut e = engine();
        let mut big = set();
        big.urgent = 0x4000;
        if e.program(&big, 50_000) != Err(Error::Invalid) || !e.io.writes.is_empty() {
            return TestResult::Fail("oversized urgency wrapped");
        }
        e.io.stuck = Some(0x50e);
        if e.program(&set(), 50_000) != Err(Error::Readback) {
            return TestResult::Fail("readback");
        }
        // hubbub2_get_dchub_ref_freq: REFDIV 2 halves the 100 MHz DCCG ref.
        if e.dchub_refclk_khz(100_000) != Err(Error::Timer) {
            return TestResult::Fail("disabled timer accepted");
        }
        e.io.regs[GLOBAL_TIMER_CNTL as usize] = TIMER_ENABLE | 2;
        if e.dchub_refclk_khz(100_000) != Ok(50_000) {
            return TestResult::Fail("refdiv 2");
        }
        e.io.regs[GLOBAL_TIMER_CNTL as usize] = TIMER_ENABLE | 1;
        if e.dchub_refclk_khz(100_000) != Err(Error::Timer) {
            return TestResult::Fail("100 MHz DCHUB reference accepted");
        }
        e.io.regs[GLOBAL_TIMER_CNTL as usize] = u32::MAX;
        if e.dchub_refclk_khz(100_000) != Err(Error::DeviceGone) {
            return TestResult::Fail("device loss");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn30-hubbub",
        dcn30_hubbub_refuses_oversized_values_timer_and_readback
    );
}
