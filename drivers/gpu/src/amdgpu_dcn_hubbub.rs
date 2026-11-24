//! DCN 3.1.4 / 3.1.5 DCHUBBUB: how the configurable return buffer (CRB) is
//! split between each pipe's detile buffer (DET) and the compressed buffer,
//! and the arbiter's urgency, self-refresh and DRAM-clock-change watermarks.
//!
//! Both DCNs build `hubbub31` (`dcn31_hubbub.c`); the arbiter watermark
//! registers sit at the same offsets in `dcn_3_1_4_offset.h` and
//! `dcn_3_1_5_offset.h`, while the DET/COMPBUF block is 0x11 dwords higher on
//! DCN 3.1.5. Every field mask used here is identical in both `_sh_mask.h`.
//!
//! The split and the watermarks are global: they also serve any pipe the boot
//! firmware left scanning out, which the single-plane mode math does not model.
//! So this module takes the state it finds into account rather than assume it
//! owns the hub — see [`plan`] and [`Mode`].
use crate::{amdgpu::AmdGpu, amdgpu_dcn_clk::Error, amdgpu_dcn_profile::Profile};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// linux-ctx: hdr=dcn seg=2
// The CRB split, DCN 3.1.4 offsets; DCN 3.1.5 adds DCN315_CRB_SHIFT.
const COMPBUF_CTRL: u64 = 0x04ba; // linux: regDCHUBBUB_COMPBUF_CTRL
const DET0_CTRL: u64 = 0x04bb; // linux: regDCHUBBUB_DET0_CTRL
/// `regDCHUBBUB_DET0_CTRL` is 0x4cc and `regDCHUBBUB_COMPBUF_CTRL` 0x4cb in
/// `dcn_3_1_5_offset.h`.
const DCN315_CRB_SHIFT: u64 = 0x11; // linux: n/a (regDCHUBBUB_DET0_CTRL 0x4cc - 0x4bb)
const DET_SIZE: u32 = 0x0000_0007; // linux: DCHUBBUB_DET0_CTRL__DET0_SIZE_MASK
const DET_SIZE_CURRENT: u32 = 0x0000_0700; // linux: DCHUBBUB_DET0_CTRL__DET0_SIZE_CURRENT_MASK
const COMPBUF_SIZE: u32 = 0x0000_001f; // linux: DCHUBBUB_COMPBUF_CTRL__COMPBUF_SIZE_MASK
/// Read only by the register model, which mirrors COMPBUF_SIZE into it.
#[cfg(feature = "kernel-test")]
const COMPBUF_SIZE_CURRENT: u32 = 0x0000_1f00; // linux: DCHUBBUB_COMPBUF_CTRL__COMPBUF_SIZE_CURRENT_MASK
const CONFIG_ERROR: u32 = 0x8000_0000; // linux: DCHUBBUB_COMPBUF_CTRL__CONFIG_ERROR_MASK
/// `DCN31_CRB_SEGMENT_SIZE_KB`.
const SEGMENT_KB: u32 = 64; // linux: n/a (dcn31_hubbub.c DCN31_CRB_SEGMENT_SIZE_KB)

// The arbiter, set A; sets B, C and D follow at SET_STRIDE.
const DRAM_STATE_CNTL: u64 = 0x04fc; // linux: regDCHUBBUB_ARB_DRAM_STATE_CNTL
const SELF_REFRESH_FORCE: u32 = 0x0000_0003; // linux: n/a (ALLOW_SELF_REFRESH_FORCE_VALUE_MASK | _FORCE_ENABLE_MASK)
const URGENCY: u64 = 0x04fd; // linux: regDCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A
const TRIP_TO_MEMORY: u64 = 0x04fe; // linux: regDCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_A
const SR_ENTER: u64 = 0x04ff; // linux: regDCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A
const SR_ENTER_Z8: u64 = 0x0500; // linux: regDCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_Z8_A
const SR_EXIT: u64 = 0x0501; // linux: regDCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_A
const SR_EXIT_Z8: u64 = 0x0502; // linux: regDCHUBBUB_ARB_ALLOW_SR_EXIT_WATERMARK_Z8_A
const DRAM_CLK_CHANGE: u64 = 0x0503; // linux: regDCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_A
const FRAC_URG_BW_NOM: u64 = 0x0504; // linux: regDCHUBBUB_ARB_FRAC_URG_BW_NOM_A
const FRAC_URG_BW_FLIP: u64 = 0x0505; // linux: regDCHUBBUB_ARB_FRAC_URG_BW_FLIP_A
/// `regDCHUBBUB_ARB_DATA_URGENCY_WATERMARK_B` 0x506 against set A's 0x4fd.
const SET_STRIDE: u64 = 9; // linux: n/a (regDCHUBBUB_ARB_DATA_URGENCY_WATERMARK_B - _A)
const SETS: u64 = 4;
const URGENCY_MASK: u32 = 0x3fff; // linux: DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A__DCHUBBUB_ARB_DATA_URGENCY_WATERMARK_A_MASK
const TRIP_MASK: u32 = 0x3fff; // linux: DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_A__DCHUBBUB_ARB_REFCYC_PER_TRIP_TO_MEMORY_A_MASK
const SR_MASK: u32 = 0xffff; // linux: DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A__DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_A_MASK
const SR_Z8_MASK: u32 = 0x000f_ffff; // linux: DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_Z8_A__DCHUBBUB_ARB_ALLOW_SR_ENTER_WATERMARK_Z8_A_MASK
const DRAM_CLK_MASK: u32 = 0xffff; // linux: DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_A__DCHUBBUB_ARB_ALLOW_DRAM_CLK_CHANGE_WATERMARK_A_MASK
const FRAC_MASK: u32 = 0x03ff; // linux: DCHUBBUB_ARB_FRAC_URG_BW_NOM_A__DCHUBBUB_ARB_FRAC_URG_BW_NOM_A_MASK

// Per-pipe OTG master enable, read to find which pipes are already live.
const OTG_CONTROL: u64 = 0x1b41; // linux: mmOTG0_OTG_CONTROL
const OTG_STRIDE: u64 = 0x80; // linux: mmOTG1_OTG_H_TOTAL - mmOTG0_OTG_H_TOTAL
const OTG_MASTER_EN: u32 = 0x1; // linux: OTG0_OTG_CONTROL__OTG_MASTER_EN_MASK
/// The highest DCN register this module touches, for the bank bound.
const LAST_REG: u32 = (OTG_CONTROL + 3 * OTG_STRIDE) as u32;
/// `REG_WAIT(DCHUBBUB_DETn_CTRL, DETn_SIZE_CURRENT, size, 1000, 30)`.
const DET_APPLY_POLLS: u32 = 30;
/// `dcn314_resource.c` `minimum_z8_residency_time`, in µs: a Z8 enter
/// watermark below it is raised to it when the stutter period is shorter.
/// dcn315 sets none.
const DCN314_MIN_Z8_RESIDENCY_US: u32 = 2100; // linux: n/a (dcn314 debug_defaults_drv)

/// `config_return_buffer_size_in_kbytes`: 1792 on DCN 3.1.4, 1024 on 3.1.5,
/// 1280 on DCN 3.2.0 and 3.2.1 (`dcn32_fpu.c` / `dcn321_fpu.c`).
fn crb_kbytes(profile: Profile) -> Option<u32> {
    match profile {
        Profile::Dcn314 => Some(1792),
        Profile::Dcn315 => Some(1024),
        Profile::Dcn320 | Profile::Dcn321 => Some(1280),
        _ => None,
    }
}
fn segments(kbytes: u32) -> u32 {
    kbytes.div_ceil(SEGMENT_KB)
}

/// What one pipe gets out of the CRB, and how the compressed buffer is sized
/// around it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub det_kbytes: u32,
    /// `bw.dcn.compbuf_size_kb`: what is left once every live pipe's DET is
    /// taken out of the CRB.
    pub compbuf_kbytes: u32,
    /// What `dcn20_prepare_bandwidth` shrinks the compressed buffer to before
    /// the DETs change: `min_comp_buffer_size_kbytes` (64 KB) on DCN 3.1.5,
    /// the final size on DCN 3.1.4.
    pub prepare_compbuf_kbytes: u32,
    /// `unbounded_req_mode`: the lone pipe may also use the compressed buffer
    /// as return buffer (`hubp31_set_unbounded_requesting`).
    pub unbounded: bool,
}

/// The DET split Linux's `populate_dml_pipes_from_context` gives this pipe,
/// given the pipes already live (`others`, as DET segments each).
///
/// - Alone (`pipe_cnt == 1`, one non-dual-plane surface at most 5120 wide
///   and, on DCN 3.1.5, below the largest non-ODM pixel rate): 192 KB with
///   unbounded requesting, on both DCNs.
/// - Otherwise: DCN 3.1.4's `DCN3_14_DEFAULT_DET_SIZE` (384 KB);
///   DCN 3.1.5's even split of the CRB less `DCN3_15_MIN_COMPBUF_SIZE_KB`,
///   capped at `DCN3_15_MAX_DET_SIZE` (384 KB).
///
/// Linux would then reprogram every pipe. A live pipe here belongs to the boot
/// firmware, so its DET is kept and this pipe must fit beside it; a split
/// that does not fit is refused rather than taken from a live scanout.
pub(crate) fn plan(
    profile: Profile,
    others: &[u32],
    surface_width: u32,
    pixel_clock_khz: u32,
    max_dispclk_khz: u32,
) -> Result<Plan, Error> {
    let crb = crb_kbytes(profile).ok_or(Error::Unsupported)?;
    let pipe_cnt = others.len() as u32 + 1;
    let det_kbytes = if pipe_cnt == 1 {
        // dcn_get_max_non_odm_pix_rate_100hz: clock_limits[0].dispclk_mhz,
        // which dcn315_update_bw_bounding_box_fpu sets to the DPM maximum,
        // over 1 + dcn_downspread_percent (0.38 %).
        let below_odm = profile != Profile::Dcn315
            || (u64::from(pixel_clock_khz) * 10_038) < u64::from(max_dispclk_khz) * 10_000;
        if surface_width <= 5120 && below_odm {
            192
        } else {
            match profile {
                Profile::Dcn315 => ((crb - 128) / SEGMENT_KB * SEGMENT_KB).min(384),
                _ => 384,
            }
        }
    } else {
        match profile {
            // linux: n/a (DCN3_15_MIN_COMPBUF_SIZE_KB 128, DCN3_15_MAX_DET_SIZE 384)
            Profile::Dcn315 => ((crb - 128) / SEGMENT_KB / pipe_cnt * SEGMENT_KB).min(384),
            _ => 384,
        }
    };
    let unbounded = pipe_cnt == 1 && det_kbytes == 192;
    let taken: u32 = others.iter().sum::<u32>() + segments(det_kbytes);
    let crb_segments = crb / SEGMENT_KB;
    if taken >= crb_segments {
        return Err(Error::Invalid);
    }
    let compbuf_kbytes = (crb_segments - taken) * SEGMENT_KB;
    let prepare_compbuf_kbytes = match profile {
        // linux: n/a (dcn3_15_ip.min_comp_buffer_size_kbytes)
        Profile::Dcn315 => compbuf_kbytes.min(64),
        _ => compbuf_kbytes,
    };
    Ok(Plan {
        det_kbytes,
        compbuf_kbytes,
        prepare_compbuf_kbytes,
        unbounded,
    })
}

/// One arbiter watermark set, in Linux's units (`struct dcn_watermarks`):
/// nanoseconds, and the urgent-bandwidth fractions in thousandths.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Watermarks {
    pub urgent_ns: u32,
    pub urgent_latency_ns: u32,
    pub sr_exit_ns: u32,
    pub sr_enter_plus_exit_ns: u32,
    pub sr_exit_z8_ns: u32,
    pub sr_enter_plus_exit_z8_ns: u32,
    pub pstate_change_ns: u32,
    pub frac_urg_bw_nom: u32,
    pub frac_urg_bw_flip: u32,
}
impl Watermarks {
    /// `dcn31_calculate_wm_and_dlg_fp`'s set A from the mode math, every
    /// microsecond truncated to whole nanoseconds as Linux's `(uint32_t)(x *
    /// 1000)` does. `frac_urg_bw_nom` is `FractionOfUrgentBandwidth` × 1000;
    /// there is no immediate flip, so its flip counterpart is zero.
    ///
    /// LINUX-GAP: DCN 3.1.4 raises the Z8 enter watermark to its 2100 µs
    /// minimum residency only when the stutter period is shorter than that.
    /// The stutter period is not computed here, so the floor always applies:
    /// Z8 is entered less often, never before it can pay off.
    pub(crate) fn from_dml(
        profile: Profile,
        wm: &crate::amdgpu_dml::Watermarks,
        frac_urg_bw_nom: u32,
    ) -> Self {
        let ns = |us: crate::amdgpu_dml::Fx| {
            crate::amdgpu_dml::Fx::int(1000)
                .times(us)
                .floor()
                .clamp(0, u32::MAX as i64) as u32
        };
        let mut sr_enter_plus_exit_z8_ns = ns(wm.z8_stutter_enter_plus_exit_us);
        if profile == Profile::Dcn314 {
            sr_enter_plus_exit_z8_ns =
                sr_enter_plus_exit_z8_ns.max(DCN314_MIN_Z8_RESIDENCY_US * 1000);
        }
        Self {
            urgent_ns: ns(wm.urgent_us),
            urgent_latency_ns: ns(wm.urgent_latency_us),
            sr_exit_ns: ns(wm.stutter_exit_us),
            sr_enter_plus_exit_ns: ns(wm.stutter_enter_plus_exit_us),
            sr_exit_z8_ns: ns(wm.z8_stutter_exit_us),
            sr_enter_plus_exit_z8_ns,
            pstate_change_ns: ns(wm.pstate_change_us),
            frac_urg_bw_nom,
            frac_urg_bw_flip: 0,
        }
    }
}

/// How the arbiter watermarks may move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `program_watermarks(safe_to_lower = false)`: only raise. Linux compares
    /// against its own cache of what it last wrote; nothing here has written
    /// them yet, so the comparison is against what the hardware holds — the
    /// boot firmware's values, which also serve any pipe it left live.
    Raise,
    /// `safe_to_lower = true`: program the computed values exactly and allow
    /// self-refresh (`hubbub1_allow_self_refresh_control`). Only for a pipe
    /// that is the hub's sole user, since the values describe this plane.
    Exact,
}

/// `convert_and_clamp` without the clamp: a value its field cannot hold is
/// refused, because a clamped watermark is the one that underflows.
fn cycles(ns: u32, refclk_mhz: u32, mask: u32) -> Result<u32, Error> {
    let value = u64::from(ns) * u64::from(refclk_mhz) / 1000;
    if value > u64::from(mask) {
        return Err(Error::Invalid);
    }
    Ok(value as u32)
}

trait Io: Send {
    fn read(&mut self, reg: u64) -> u32;
    fn write(&mut self, reg: u64, value: u32);
    /// A model's poll budget; hardware polls for real (`None`).
    fn wait_poll_limit(&self) -> Option<u32> {
        None
    }
}
#[derive(Debug)]
struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
    base: u64,
}
impl Io for Mmio {
    fn read(&mut self, reg: u64) -> u32 {
        // SAFETY: the constructor bounds the DCN bank and keeps the mapping.
        unsafe { self.regs.read32(self.base + reg * 4) }
    }
    fn write(&mut self, reg: u64, value: u32) {
        // SAFETY: same bounded bank; this is the hub's sole owner.
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
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    profile: Profile,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    fn read(&mut self, reg: u64) -> Result<u32, Error> {
        let value = self.access(|io| io.read(reg))?;
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok(value)
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read(reg)?;
        self.access(|io| io.write(reg, (old & !mask) | (value & mask)))
    }
    fn crb(&self, reg: u64) -> u64 {
        reg + if self.profile == Profile::Dcn315 {
            DCN315_CRB_SHIFT
        } else {
            0
        }
    }
    fn det_ctrl(&self, pipe: u8) -> u64 {
        self.crb(DET0_CTRL) + u64::from(pipe)
    }
    fn pipes(&self) -> u8 {
        self.profile.pipes()
    }
    /// Pipes whose timing generator runs, other than `pipe`, with the DET
    /// segments each currently holds.
    fn live_others(&mut self, pipe: u8) -> Result<alloc::vec::Vec<u32>, Error> {
        let mut out = alloc::vec::Vec::new();
        for other in (0..self.pipes()).filter(|p| *p != pipe) {
            let control = self.read(OTG_CONTROL + u64::from(other) * OTG_STRIDE)?;
            if control & OTG_MASTER_EN != 0 {
                let det = self.read(self.det_ctrl(other))?;
                out.try_reserve(1).map_err(|_| Error::Allocation)?;
                out.push((det & DET_SIZE_CURRENT) >> DET_SIZE_CURRENT.trailing_zeros());
            }
        }
        Ok(out)
    }
    /// `dcn31_program_det_size`, refused when the programmed DETs and the
    /// compressed buffer would no longer fit the CRB (Linux asserts).
    fn program_det_size(&mut self, pipe: u8, kbytes: u32) -> Result<(), Error> {
        if pipe >= self.pipes() {
            return Err(Error::Invalid);
        }
        let crb = crb_kbytes(self.profile).ok_or(Error::Unsupported)? / SEGMENT_KB;
        let new = segments(kbytes);
        if new > DET_SIZE {
            return Err(Error::Invalid);
        }
        let mut total = new;
        for other in (0..self.pipes()).filter(|p| *p != pipe) {
            total += self.read(self.det_ctrl(other))? & DET_SIZE;
        }
        total += self.read(self.crb(COMPBUF_CTRL))? & COMPBUF_SIZE;
        if total > crb {
            return Err(Error::Invalid);
        }
        self.update(self.det_ctrl(pipe), DET_SIZE, new)
    }
    /// `dcn31_wait_for_det_apply`: DETn_SIZE_CURRENT follows DETn_SIZE within
    /// 30 ms. Linux only logs a timeout; a DET that never changed is refused.
    async fn wait_for_det_apply(&mut self, pipe: u8) -> Result<(), Error> {
        let reg = self.det_ctrl(pipe);
        let limit = self.io.wait_poll_limit();
        for _ in 0..limit.unwrap_or(DET_APPLY_POLLS) {
            let value = self.read(reg)?;
            if (value & DET_SIZE_CURRENT) >> DET_SIZE_CURRENT.trailing_zeros() == value & DET_SIZE {
                return Ok(());
            }
            if limit.is_some() {
                narf_scheduler::yield_now().await;
            } else {
                narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
            }
        }
        Err(Error::Timeout)
    }
    /// `dcn31_program_compbuf_size`: shrinking is always allowed; growing only
    /// when `safe_to_increase`, after every DET has applied. CONFIG_ERROR
    /// afterwards means the split the hub was given is invalid.
    async fn program_compbuf_size(
        &mut self,
        kbytes: u32,
        safe_to_increase: bool,
    ) -> Result<(), Error> {
        let crb = crb_kbytes(self.profile).ok_or(Error::Unsupported)? / SEGMENT_KB;
        let new = segments(kbytes);
        if new > COMPBUF_SIZE {
            return Err(Error::Invalid);
        }
        let current = self.read(self.crb(COMPBUF_CTRL))? & COMPBUF_SIZE;
        if !safe_to_increase && new > current {
            return Ok(());
        }
        if new > current {
            for pipe in 0..self.pipes() {
                self.wait_for_det_apply(pipe).await?;
            }
        }
        let mut total = new;
        for pipe in 0..self.pipes() {
            total += self.read(self.det_ctrl(pipe))? & DET_SIZE;
        }
        if total > crb {
            return Err(Error::Invalid);
        }
        self.update(self.crb(COMPBUF_CTRL), COMPBUF_SIZE, new)?;
        if self.read(self.crb(COMPBUF_CTRL))? & CONFIG_ERROR != 0 {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    /// `hubbub31_program_watermarks` for sets A–D (Linux copies A into B, C
    /// and D). Every value is checked against its field before anything is
    /// written, so a refused set leaves the arbiter as it was.
    fn program_watermarks(
        &mut self,
        wm: &Watermarks,
        refclk_mhz: u32,
        mode: Mode,
    ) -> Result<(), Error> {
        let fields = [
            (
                URGENCY,
                cycles(wm.urgent_ns, refclk_mhz, URGENCY_MASK)?,
                URGENCY_MASK,
            ),
            (
                TRIP_TO_MEMORY,
                cycles(wm.urgent_latency_ns, refclk_mhz, TRIP_MASK)?,
                TRIP_MASK,
            ),
            (
                SR_ENTER,
                cycles(wm.sr_enter_plus_exit_ns, refclk_mhz, SR_MASK)?,
                SR_MASK,
            ),
            (
                SR_EXIT,
                cycles(wm.sr_exit_ns, refclk_mhz, SR_MASK)?,
                SR_MASK,
            ),
            (
                SR_ENTER_Z8,
                cycles(wm.sr_enter_plus_exit_z8_ns, refclk_mhz, SR_Z8_MASK)?,
                SR_Z8_MASK,
            ),
            (
                SR_EXIT_Z8,
                cycles(wm.sr_exit_z8_ns, refclk_mhz, SR_Z8_MASK)?,
                SR_Z8_MASK,
            ),
            (
                DRAM_CLK_CHANGE,
                cycles(wm.pstate_change_ns, refclk_mhz, DRAM_CLK_MASK)?,
                DRAM_CLK_MASK,
            ),
            (FRAC_URG_BW_NOM, wm.frac_urg_bw_nom, FRAC_MASK),
            (FRAC_URG_BW_FLIP, wm.frac_urg_bw_flip, FRAC_MASK),
        ];
        if fields.iter().any(|&(_, value, mask)| value > mask) {
            return Err(Error::Invalid);
        }
        for set in 0..SETS {
            for &(reg, value, mask) in &fields {
                let reg = reg + set * SET_STRIDE;
                let value = match mode {
                    Mode::Exact => value,
                    Mode::Raise => value.max(self.read(reg)? & mask),
                };
                self.access(|io| io.write(reg, value))?;
            }
        }
        if mode == Mode::Exact {
            // allow_self_refresh_control(!disable_stutter): neither forced.
            self.update(DRAM_STATE_CNTL, SELF_REFRESH_FORCE, 0)?;
        }
        Ok(())
    }
}

/// The DCN 3.1.x hub's CRB split and arbiter. Holding it grants the global
/// arbiter registers, not any pipe: a pipe's own DET is only changed through
/// the pipeline that owns it.
#[derive(Debug)]
pub struct Hubbub(Engine<Mmio>);
impl Hubbub {
    /// # Safety
    /// Caller exclusively owns the DCHUBBUB arbiter and CRB registers for this
    /// object's lifetime, holds matching PCI authority and a permanent register
    /// mapping, and changes only the DET of a pipe it owns.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        crb_kbytes(profile).ok_or(Error::Unsupported)?;
        let base = profile.bank(gpu, 2, LAST_REG)?; // linux-lit: 2=regDCHUBBUB_DET0_CTRL_BASE_IDX
        Ok(Self(Engine {
            io: Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                base,
            },
            authority,
            profile,
        }))
    }
    /// The DET split for `pipe` beside whatever pipes are already live.
    pub fn plan(
        &mut self,
        pipe: u8,
        surface_width: u32,
        pixel_clock_khz: u32,
        max_dispclk_khz: u32,
    ) -> Result<Plan, Error> {
        let others = self.0.live_others(pipe)?;
        plan(
            self.0.profile,
            &others,
            surface_width,
            pixel_clock_khz,
            max_dispclk_khz,
        )
    }
    /// Whether any pipe other than `pipe` is scanning out.
    pub fn others_live(&mut self, pipe: u8) -> Result<bool, Error> {
        Ok(!self.0.live_others(pipe)?.is_empty())
    }
    pub fn program_det_size(&mut self, pipe: u8, kbytes: u32) -> Result<(), Error> {
        self.0.program_det_size(pipe, kbytes)
    }
    pub async fn wait_for_det_apply(&mut self, pipe: u8) -> Result<(), Error> {
        self.0.wait_for_det_apply(pipe).await
    }
    pub async fn program_compbuf_size(
        &mut self,
        kbytes: u32,
        safe_to_increase: bool,
    ) -> Result<(), Error> {
        self.0.program_compbuf_size(kbytes, safe_to_increase).await
    }
    pub fn program_watermarks(
        &mut self,
        wm: &Watermarks,
        refclk_mhz: u32,
        mode: Mode,
    ) -> Result<(), Error> {
        self.0.program_watermarks(wm, refclk_mhz, mode)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn_hubbub_tests.rs"]
mod tests;
