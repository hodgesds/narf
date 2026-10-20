//! DCN401 RGB conversion and scaler preparation. Native references:
//! dpp401_dpp_setup, dpp35 FCNV and dpp3 CM programming, and
//! dpp401_dscl_set_scaler_manual_scale with SPL's scaler data
//! (`amdgpu_dcn401_spl`, `amdgpu_dcn401_dscl`): the scaler bypasses a
//! unity plane (SCALING_444_BYPASS) and scales any other with SPL's
//! polyphase or EASF filters. MPC remains disconnected; no pixels are
//! fetched.
//!
//! Every surface format takes amdgpu_dm's default plane color state: no
//! degamma (in_transfer_func bypass), no bias/scale (FCNV bias 0, scale
//! 1.0) and the unity HDR multiplier. RGB is sRGB (post CSC bypass); a
//! 4:2:0 plane's YCbCr goes through the post CSC with the
//! `dpp_input_csc_matrix` of its COLOR_ENCODING / COLOR_RANGE color space
//! (dpp401_dpp_setup's INPUT_CSC_SELECT_ICSC, dpp3_program_post_csc).
//! FP16 needs nothing more: its values pass through and the output
//! denormalization clamps them, as on Linux without color properties.
use super::*;
use crate::amdgpu_dcn401_dscl as dscl;
use crate::amdgpu_dcn401_spl as spl;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};

const DPP_CLOCK: u64 = 0xcc5;
const RESET: u64 = 0xcc6;
const FORMAT_CONTROL: u64 = 0xcd0;
const DPP_CURSOR: u64 = 0xcf1;
const SCALER_PENDING: u64 = 0xd18;
const SCALER_POWER: u64 = 0xd24;
const SCALER_STATUS: u64 = 0xd25;
const CM_CONTROL: u64 = 0xd67;
const PRE_DEGAM: u64 = 0xced;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DppApplied {
    pub surface: SurfaceApplied,
    pub timing: Applied,
    /// The first segment's line-buffer memory configuration
    /// (dpp401_dscl_find_lb_memory_config on SPL's scaler data).
    pub line_buffer_config: u8,
    /// Each segment's SCL_COEF_RAM_SELECT after its coefficient load, in
    /// segment order; none for a segment that bypasses the scaler.
    pub coef_ram: [Option<bool>; 2],
    /// CNVC, scaler and CM pending bits, respectively. Timing is stopped, so
    /// staged programming may remain pending; zero is not presentation evidence.
    pub pending: u8,
}
impl Layout {
    pub(super) fn dpp(self, pipe: u8, reg: u64) -> u64 {
        self.base + (reg + u64::from(pipe) * 0x16b) * 4
    }
}
/// The CM_POST_CSC_C11_C12..C33_C34 words of a plane in `format`: none
/// for RGB (INPUT_CSC_SELECT_BYPASS), else its color space's
/// dpp_input_csc_matrix packed two coefficients a register, the first low
/// (cm_helper_program_color_matrices).
pub(in crate::amdgpu_dcn401_otg) fn post_csc_words(
    format: SurfaceFormat,
    color: crate::amdgpu_dcn401_otg::YuvColor,
) -> Option<[u32; 6]> {
    if !format.is_video() {
        return None;
    }
    let m = color.matrix();
    Some(core::array::from_fn(|i| {
        u32::from(m[2 * i]) | u32::from(m[2 * i + 1]) << 16
    }))
}
/// CM_POST_CSC_CONTROL and its coefficient set A (CM_POST_CSC_C11_C12).
const POST_CSC: u64 = 0xd68;
const POST_CSC_C11_C12: u64 = 0xd69;
/// The CNVC and CM state of `format`: dpp401_dpp_setup's crossbar and
/// pixel format, and every color block in bypass but a 4:2:0 plane's post
/// CSC: dpp3_program_post_csc loads its color space's matrix into the set
/// not in use (A on a pipe staged from bypass) as
/// cm_helper_program_color_matrices packs it (C11 low, C12 high, ...) and
/// selects it (CM_POST_CSC_MODE 1, INPUT_CSC_SELECT_ICSC).
fn cnvc_cm(a: DppApplied) -> alloc::vec::Vec<(u64, u32, u32)> {
    let format = a.surface.request.format;
    let csc = post_csc_words(format, a.surface.request.surface.color);
    let mut out = alloc::vec![
        // RGB crossbar; EXPANSION_MODE_ZERO = 1; ALPHA_EN unless RGB565.
        (
            FORMAT_CONTROL,
            0x3f033111,
            0x24000001 | u32::from(format.cnvc_alpha()) << 8,
        ),
        // dpp401_dpp_setup's format, no separate alpha plane.
        (0xccf, 0x17f, format.cnvc_pixel_format()),
        (0xcd7, 0x33, 0), // color/luma keying disabled
        (0xcde, 0x11, 0),
        (0xcee, 0x11, 0),     // pre de/re-alpha off
        (PRE_DEGAM, 0x73, 0), // pre-degamma bypass (encoded RGB passes through)
        (0xcd1, 0x7ffff, 0),
        (0xcd2, 0x7ffff, 0),
        (0xcd3, 0x7ffff, 0),
        (0xcd4, 0x7ffff, 0x1f000),
        (0xcd5, 0x7ffff, 0x1f000),
        (0xcd6, 0x7ffff, 0x1f000),
        (CM_CONTROL, 1, 0),
    ];
    if let Some(words) = csc {
        for (i, word) in words.into_iter().enumerate() {
            out.push((POST_CSC_C11_C12 + i as u64, u32::MAX, word));
        }
    }
    out.extend([
        (POST_CSC, 3, u32::from(csc.is_some())), // ICSC for YCbCr, else bypass
        (0xd77, 0xf, 0),                         // gamma correction bypass
        (0xdc5, 3, 0),                           // CM de-alpha off
        (0xd75, 0xffff, 0),
        (0xd76, u32::MAX, 0),
        (0xdc1, 0x7ffff, 0x1f000), // unity HDR multiplier
    ]);
    out
}
/// The scaler writes' final field values, as a readback must find them:
/// each register's last write (the coefficient RAM swap is checked from
/// the applied report).
fn dscl_state(scaler: &spl::Scaler, alpha: bool) -> alloc::vec::Vec<(u64, u32, u32)> {
    let mut out: alloc::vec::Vec<(u64, u32, u32)> = alloc::vec::Vec::new();
    for op in dscl::program(scaler, alpha) {
        if let dscl::Op::Write { reg, mask, value } = op {
            match out.iter_mut().find(|(r, _, _)| *r == reg) {
                Some(have) => {
                    *have = (reg, have.1 | mask, have.2 & !mask | value);
                }
                None => out.push((reg, mask, value)),
            }
        }
    }
    out
}
impl<I: Io> Engine<I> {
    fn dpp_stopped(&mut self, pipe: u8, clocked: bool) -> Result<(), Error> {
        if !self.hubp_powered(pipe)? {
            return Err(Error::Busy);
        }
        let l = self.layout;
        for (r, mask, value) in [
            (DPP_CLOCK, 0x70000010, u32::from(clocked) << 4),
            (RESET, 0x1111, 0),
            (DPP_CURSOR, 0x10001, 0),
            // Native DSCL code manages LUT power, while LB groups use hardware
            // policy. Reject inherited forced/manual LB gating rather than
            // silently replacing that independent policy.
            (SCALER_POWER, 0x13333330, 0),
        ] {
            if self.read(l.dpp(pipe, r))? & mask != value {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    fn dpp_pending(&mut self, pipe: u8) -> Result<u8, Error> {
        let mut pending = 0;
        for (bit, (r, mask)) in [
            (FORMAT_CONTROL, 0x100000),
            (SCALER_PENDING, 1),
            (CM_CONTROL, 0x100),
        ]
        .into_iter()
        .enumerate()
        {
            if self.read(self.layout.dpp(pipe, r))? & mask != 0 {
                pending |= 1 << bit;
            }
        }
        Ok(pending)
    }
    /// Program every segment's DPP; returns each segment's coefficient
    /// RAM selection.
    async fn program_dpp(&mut self, applied: DppApplied) -> Result<[Option<bool>; 2], Error> {
        let mut coef_ram = [None; 2];
        let alpha = applied.surface.request.layout().blend.per_pixel_alpha;
        for (i, (p, scaler)) in applied.surface.request.scalers().enumerate() {
            coef_ram[i] = self.program_segment_dpp(applied, p, &scaler, alpha).await?;
        }
        Ok(coef_ram)
    }
    async fn program_segment_dpp(
        &mut self,
        applied: DppApplied,
        p: u8,
        scaler: &spl::Scaler,
        alpha: bool,
    ) -> Result<Option<bool>, Error> {
        let l = self.layout;
        self.update(l.dpp(p, DPP_CLOCK), 0x10, 0x10)?;
        // Wake the native scaler LUT before its programming.
        self.update(l.dpp(p, SCALER_POWER), 7, 4)?;
        self.wait(l.dpp(p, SCALER_STATUS), 3, 0, 1000).await?;
        self.hubp_tree_stopped(Some(p))?;
        self.dpp_stopped(p, true)?;
        for (r, mask, value) in cnvc_cm(applied) {
            self.update(l.dpp(p, r), mask, value)?;
        }
        let mut coef_ram = None;
        for op in dscl::program(scaler, alpha) {
            match op {
                dscl::Op::Write { reg, mask, value } => self.update(l.dpp(p, reg), mask, value)?,
                dscl::Op::Wait { reg, mask, value } => {
                    self.wait(l.dpp(p, reg), mask, value, 1000).await?;
                    self.hubp_tree_stopped(Some(p))?;
                    self.dpp_stopped(p, true)?;
                }
                dscl::Op::Coefficients {
                    filter_type,
                    taps,
                    filter,
                } => {
                    // dpp401_dscl_set_scaler_filter: select the filter's first
                    // phase and tap pair; the data port auto-increments, so
                    // its writes are not read back.
                    self.update(
                        l.dpp(p, dscl::SCL_COEF_RAM_TAP_SELECT),
                        0x73f03,
                        filter_type << 16,
                    )?;
                    let data = l.dpp(p, dscl::SCL_COEF_RAM_TAP_DATA);
                    self.access(|io| {
                        for word in dscl::coefficient_words(taps, filter) {
                            io.write(data, word);
                        }
                        Ok(())
                    })?;
                }
                dscl::Op::SwapCoefficientRam { chroma } => {
                    // Load into the RAM not in use, then select it.
                    let at = l.dpp(p, dscl::SCL_MODE);
                    let current = self.read(at)? & dscl::COEF_RAM_SELECT_CURRENT != 0;
                    self.update(
                        at,
                        dscl::COEF_RAM_SELECT | dscl::CHROMA_COEF_MODE,
                        u32::from(!current) << 8 | u32::from(chroma) << 16,
                    )?;
                    coef_ram = Some(!current);
                }
            }
        }
        self.update(l.dpp(p, DPP_CLOCK), 0x10, 0)?;
        Ok(coef_ram)
    }
    pub(super) fn verify_dpp(&mut self, applied: DppApplied) -> Result<(), Error> {
        let alpha = applied.surface.request.layout().blend.per_pixel_alpha;
        for (i, (p, scaler)) in applied.surface.request.scalers().enumerate() {
            self.dpp_stopped(p, false)?;
            let coef = applied.coef_ram[i].map(|select| {
                (
                    dscl::SCL_MODE,
                    dscl::COEF_RAM_SELECT,
                    u32::from(select) << 8,
                )
            });
            for (r, mask, value) in cnvc_cm(applied)
                .into_iter()
                .chain(dscl_state(&scaler, alpha))
                .chain(coef)
                .chain([(SCALER_POWER, 7, 4), (SCALER_STATUS, 3, 0)])
            {
                // PRE_DEGAM follows the pipe's color record (bypass when
                // staged; legacy gamma's sRGB once scanout programs it).
                let value = if r == PRE_DEGAM {
                    self.status.colors[usize::from(p)].pre_degam()
                } else {
                    value
                };
                let at = self.layout.dpp(p, r);
                if self.read(at)? & mask != value {
                    return Err(Error::Readback(at));
                }
            }
        }
        Ok(())
    }
    /// Every segment DPP's pending bits, ORed.
    fn segment_dpp_pending(&mut self, surface: SurfaceRequest) -> Result<u8, Error> {
        let mut pending = 0;
        for (p, _, _) in surface.segments() {
            pending |= self.dpp_pending(p)?;
        }
        Ok(pending)
    }
    /// The pipe whose timing and OPP carry `pipe`'s plane: its own for a
    /// display's primary plane, the selected display's for an overlay.
    pub(in crate::amdgpu_dcn401_otg) fn stream_pipe(&self, pipe: u8) -> u8 {
        let own = self
            .status
            .blanks
            .get(usize::from(pipe))
            .is_some_and(Option::is_some);
        if own {
            pipe
        } else {
            self.displays.selected
        }
    }
}
/// Whether `surface` fits the blanked stream `blank` it is to be shown on:
/// a full-frame plane the timing's own size, or a layout on that stream.
pub(in crate::amdgpu_dcn401_otg) fn plane_on_stream(
    surface: SurfaceRequest,
    blank: &BlankApplied,
) -> bool {
    let t = blank.timing.request;
    let fits = match surface.plane {
        None => surface.width == t.timing.h_active && surface.height == t.timing.v_active,
        Some(l) => {
            l.stream_width == t.timing.h_active
                && l.stream_height == t.timing.v_active
                && l.ycbcr420 == blank.request.ycbcr420
        }
    };
    fits && surface.odm == t.odm
}
impl Surfaces {
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_dpp<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        mut owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<DppApplied, Error> {
        let slot = usize::from(pipe);
        let surface = self
            .0
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        if !e.status.state.reusable()
            || e.status.dpps[slot].is_some()
            || e.status.surfaces[slot] != Some(surface.applied)
        {
            return Err(Error::Busy);
        }
        let stream = e.stream_pipe(pipe);
        let blank = e.status.blanks[usize::from(stream)].ok_or(Error::Invalid)?;
        let (clock, config) = owners()?;
        if e.blank_timing(blank.request, clock)? != blank.timing
            || !plane_on_stream(surface.applied.request, &blank)
            || e.status.memory[slot]
                != Some(MemoryApplied {
                    pipe,
                    framebuffer_base: config.fb_base,
                    framebuffer_top: config.fb_top,
                    framebuffer_offset: config.fb_offset,
                    page_table_base: config.root,
                })
        {
            return Err(Error::Invalid);
        }
        let plan = blank.timing.request.plan()?;
        let alpha = surface.applied.request.layout().blend.per_pixel_alpha;
        let (_, first) = surface
            .applied
            .request
            .scalers()
            .next()
            .ok_or(Error::Invalid)?;
        if surface.applied.request.scalers().any(|(_, s)| !s.ok) {
            return Err(Error::Unsupported);
        }
        let mut applied = DppApplied {
            surface: surface.applied,
            timing: blank.timing,
            line_buffer_config: first.lb_memory_config(alpha) as u8,
            coef_ram: [None; 2],
            pending: 0,
        };
        e.hubp_tree_stopped(Some(pipe))?;
        e.verify_surface(surface.applied)?;
        e.verify_memory(pipe, config)?;
        e.verify_blank(blank, plan, false)?;
        for (p, _, _) in surface.applied.request.segments() {
            e.dpp_stopped(p, false)?;
        }
        if e.segment_dpp_pending(surface.applied.request)? != 0 {
            return Err(Error::Busy);
        }
        e.status.state = State::PreparingDpp(pipe);
        // Staging writes the input transfer function's bypass.
        for (p, _, _) in surface.applied.request.segments() {
            e.status.colors[usize::from(p)].pre_degam_srgb = false;
        }
        let result = async {
            applied.coef_ram = e.program_dpp(applied).await?;
            if owners()? != (clock, config) {
                return Err(Error::Busy);
            }
            e.hubp_tree_stopped(Some(pipe))?;
            e.verify_surface(surface.applied)?;
            e.verify_memory(pipe, config)?;
            e.verify_blank(blank, plan, false)?;
            e.verify_dpp(applied)?;
            e.segment_dpp_pending(surface.applied.request)
        }
        .await;
        match result {
            Ok(pending) => {
                applied.pending = pending;
                e.status.dpps[slot] = Some(applied);
                e.status.state = State::DppPrepared;
                Ok(applied)
            }
            Err(err) => {
                e.status.state = State::Failed(err);
                Err(err)
            }
        }
    }
}
impl Otg {
    /// Stage native RGB conversion, scaler and line-buffer setup for a
    /// retained surface of any `SurfaceFormat` on its stream: a display's
    /// primary plane, or an overlay on a free pipe of the selected display.
    /// Fetch, MPC and timing remain stopped.
    /// # Safety
    /// Retain all owners and inherited resources on every outcome. Exclude
    /// firmware/FAMS and concurrent display, hub/VM, clock, reset and power writers.
    pub async unsafe fn prepare_dpp(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
    ) -> Result<DppApplied, Error> {
        let regs = self.0.io.0;
        let (held, layout) = self.0.held();
        let stream = self.0.stream_pipe(pipe);
        self.1
            .prepare_dpp(&mut self.0, pipe, || {
                Ok((
                    dccg.timing_clock_except(regs, clocks, stream, &|at| {
                        held_by_sibling(held, layout, at)
                    })
                    .map_err(Error::PipeClocks)?,
                    gmc.display_context(regs).map_err(Error::Memory)?,
                ))
            })
            .await
    }
}

#[cfg(feature = "kernel-test")]
fn dcn401_dpp_line_buffer_follows_linux() -> narf_kernel_test::TestResult {
    // dpp401_dscl_find_lb_memory_config for an unscaled full-frame line:
    // one vertical tap fits the first memory while a row takes at most
    // 970 entries (5820 pixels), then the second (7740 pixels); per-pixel
    // alpha takes as many entries in the same memories.
    for (width, want) in [
        (1, 1),
        (2910, 1),
        (3840, 1),
        (5820, 1),
        (5821, 2),
        (7740, 2),
        (7741, 0),
        (10290, 0),
    ] {
        for alpha in [false, true] {
            let r = spl::Rect::new(0, 0, width, 64);
            let s = spl::calculate(&spl::Input {
                src: r,
                dst: r,
                clip: r,
                stream_width: width,
                stream_height: 64,
                odm_slice: r,
                rotation: spl::Rotation::R0,
                horizontal_mirror: false,
                alpha,
                video: None,
            });
            assert_eq!(s.lb_memory_config(alpha), want, "width {width}");
        }
    }
    narf_kernel_test::TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "drivers/gpu/dcn401-dpp",
    dcn401_dpp_line_buffer_follows_linux
);
