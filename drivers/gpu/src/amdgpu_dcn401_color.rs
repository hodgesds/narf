//! Native DCN401 CRTC color management on a scanout's DPPs and MPCCs, as
//! amdgpu_dm maps DRM's CRTC properties on DCN 4.0.1 (no plane color, no
//! degamma LUT) and dcn401_program_pipe programs them:
//! - dcn401_program_gamut_remap: the CTM in MPCC_OGAM_GAMUT_REMAP
//!   (mpc401_set_gamut_remap: the coefficient set not in use, then that set
//!   and the coefficient format); both MCM gamut remaps bypassed.
//! - dcn32_set_input_transfer_func: legacy gamma's implicit degamma
//!   (map_crtc_degamma_to_dc_plane's TF_TYPE_PREDEFINED input: BT.709 for
//!   an NV12 plane, sRGB for any other, P010 included, through
//!   dpp3_set_pre_degam's ROM), else bypass; GAMCOR always bypassed
//!   (dpp3_program_gamcor_lut with no PWL), CM enabled.
//!
//! amdgpu_dm exposes no plane color property on DCN 4.0.1 by default: the
//! plane's DEGAMMA/HDR multiplier/CTM/shaper/3D/blend LUTs are
//! AMD_PRIVATE_COLOR only, and its COLOR_PIPELINE (drm_colorop) is offered
//! only to clients that set DRM_CLIENT_CAP_PLANE_COLOR_PIPELINE, which NARF
//! does not implement. Without either, amdgpu_dm_update_plane_color_mgmt
//! leaves the input transfer function bypassed unless the CRTC's legacy
//! gamma asks for the implicit degamma above.
//! - dcn401_set_output_transfer_func -> mpc3_set_output_gamma: GAMMA_LUT's
//!   PWL into the OGAM RAM bank not in use (mpc3_program_luta/b and
//!   mpc3_program_ogam_pwl), then that bank selected; bypass without one.
//!
//! The scanout start programs them under its OTG master lock; a live update
//! takes the same lock, so the double-buffered selections latch together at
//! one VUPDATE, and waits for that latch before reporting.
use super::scanout::Pipe;
use super::*;
use alloc::sync::Arc;

/// CNVC_CFG PRE_DEGAM, CM_CONTROL and CM_GAMCOR_CONTROL (DPP stride 0x16b).
const PRE_DEGAM: u64 = 0xced;
const CM_CONTROL: u64 = 0xd67;
const GAMCOR_CONTROL: u64 = 0xd77;
/// MPCC_MEM_PWR_CTRL (MPCC stride 0x15): MPCC_OGAM_MEM_PWR_DIS and _STATE.
const MPCC_MEM_PWR: u64 = 0xd;
const OGAM_MEM_PWR_DIS: u32 = 4;
const OGAM_MEM_PWR_STATE: u32 = 0x300;
/// The MPCC_OGAM block (stride 0x5e).
const OGAM_CONTROL: u64 = 0x7e;
const OGAM_LUT_INDEX: u64 = 0x7f;
const OGAM_LUT_DATA: u64 = 0x80;
const OGAM_LUT_CONTROL: u64 = 0x81;
/// MPCC_OGAM_RAMA_START_CNTL_B and MPCC_OGAM_RAMB_START_CNTL_B: each bank's
/// START_CNTL_B/G/R, START_SLOPE_CNTL_B/G/R, START_BASE_CNTL_B/G/R,
/// END_CNTL1/2_B, _G, _R, OFFSET_B/G/R, then REGION_0_1..REGION_32_33.
const OGAM_RAMA: u64 = 0x82;
const OGAM_RAMB: u64 = 0xa5;
const RAM_START_SLOPE: u64 = 3;
const RAM_END: u64 = 9;
const RAM_REGIONS: u64 = 0x12;
/// MPCC_GAMUT_REMAP_COEF_FORMAT, _MODE and the C11_C12_A / _B sets.
const GAMUT_COEF_FORMAT: u64 = 0xc8;
const GAMUT_MODE: u64 = 0xc9;
const GAMUT_A: u64 = 0xca;
const GAMUT_B: u64 = 0xd0;
/// MPCC_MCM_FIRST/SECOND_GAMUT_REMAP_MODE (stride 0xb0).
const MCM_FIRST_GAMUT_MODE: u64 = 0x4de;
const MCM_SECOND_GAMUT_MODE: u64 = 0x4ec;

/// The OGAM PWL of a GAMMA_LUT, as cm3_helper_translate_curve_to_hw_format
/// and cm_helper_program_gamcor_xfer_func give its register words. Channel
/// arrays are blue, green, red (the RAM's register order); `lut` holds the
/// red, green and blue LUT_DATA words of every hardware point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OgamProgram {
    /// RAMx_START_CNTL: EXP_REGION_START with START_SEGMENT 0.
    pub start: [u32; 3],
    /// RAMx_START_SLOPE_CNTL: EXP_REGION_START_SLOPE.
    pub start_slope: [u32; 3],
    /// RAMx_END_CNTL1: EXP_REGION_END_BASE.
    pub end_base: [u32; 3],
    /// RAMx_END_CNTL2: EXP_REGION_END_SLOPE and EXP_REGION_END.
    pub end: [u32; 3],
    /// RAMx_REGION_0_1 .. RAMx_REGION_32_33.
    pub regions: [u32; 17],
    pub lut: [alloc::vec::Vec<u32>; 3],
}
/// The CTM as mpc401_set_gamut_remap converts it: the six C11_C12..C33_C34
/// words and S3.12 (else S2.13) coefficients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GamutProgram {
    pub coef: [u32; 6],
    pub s3_12: bool,
}
/// What a display's CRTC color properties program. `Default` is amdgpu_dm's
/// bypass: no gamut remap, no implicit degamma, no regamma.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ColorProgram {
    /// TF_TYPE_PREDEFINED sRGB input (legacy 256-entry gamma): the
    /// PRE_DEGAM sRGB ROM linearizes for the sRGB-based legacy regamma.
    pub pre_degam_srgb: bool,
    pub gamut: Option<GamutProgram>,
    pub ogam: Option<OgamProgram>,
}
/// dpp3_set_pre_degam's choice: the DPP's predefined degamma ROM for a
/// TF_TYPE_PREDEFINED input transfer function, or bypass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PreDegam {
    /// TRANSFER_FUNCTION_LINEAR / UNITY (and any unlisted function).
    #[default]
    Bypass,
    /// TRANSFER_FUNCTION_SRGB: PRE_DEGAM_SELECT 0.
    Srgb,
    /// TRANSFER_FUNCTION_BT709: PRE_DEGAM_SELECT 4.
    Bt709,
}
impl PreDegam {
    /// map_crtc_degamma_to_dc_plane's implicit degamma for a plane in
    /// `format` under legacy gamma: TRANSFER_FUNCTION_BT709 for
    /// SURFACE_PIXEL_FORMAT_VIDEO_420_YCbCr and _YCrCb (amdgpu_dm's NV21
    /// and NV12; "DC doesn't have a transfer function for BT601
    /// specifically"), sRGB for every other format, P010's
    /// VIDEO_420_10bpc_YCrCb included.
    pub const fn implicit(format: SurfaceFormat) -> Self {
        match format {
            SurfaceFormat::Nv12 => Self::Bt709,
            _ => Self::Srgb,
        }
    }
    /// CNVC_CFG PRE_DEGAM (mask 0x73): PRE_DEGAM_MODE 1 with the ROM's
    /// PRE_DEGAM_SELECT, or 0 for bypass (dpp3_set_pre_degam's REG_SET_2).
    pub const fn word(self) -> u32 {
        match self {
            Self::Bypass => 0,
            Self::Srgb => 1,
            Self::Bt709 => 1 | 4 << 4,
        }
    }
}

/// What one pipe's color blocks were last set to: the PRE_DEGAM ROM, the
/// OGAM gamut remap set (1 = A, 2 = B) with its S3.12 format, and the OGAM
/// RAM bank (0 = A, 1 = B). Default is bypass, which every staged DPP and
/// MPC preparation writes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipeColor {
    pub pre_degam: PreDegam,
    pub gamut: Option<(u8, bool)>,
    pub ogam: Option<u8>,
}
impl PipeColor {
    /// PRE_DEGAM (mask 0x73).
    pub(super) fn pre_degam(self) -> u32 {
        self.pre_degam.word()
    }
    /// MPCC_OGAM_CONTROL MODE (mask 3) and SELECT (mask 4).
    pub(super) fn ogam_control(self) -> (u32, u32) {
        match self.ogam {
            Some(bank) => (7, 2 | u32::from(bank) << 2),
            None => (3, 0),
        }
    }
    /// MODE_CURRENT and SELECT_CURRENT (mask 0x380) once latched.
    pub(super) fn ogam_current(self) -> u32 {
        self.ogam.map_or(0, |bank| 2 << 7 | u32::from(bank) << 9)
    }
    /// MPCC_GAMUT_REMAP_MODE (mask 3) and its MODE_CURRENT (mask 0x180).
    pub(super) fn gamut_mode(self) -> u32 {
        self.gamut.map_or(0, |(set, _)| u32::from(set))
    }
}

impl ColorProgram {
    /// What amdgpu_dm makes of a CRTC's committed CTM and GAMMA_LUT blobs on
    /// DCN 4.0.1, where no plane carries color of its own
    /// (amdgpu_dm_update_crtc_color_mgmt, amdgpu_dm_update_plane_color_mgmt):
    /// - a 256-entry GAMMA_LUT is legacy gamma: __set_legacy_tf's sRGB-based
    ///   regamma, its input linearized by the plane's predefined sRGB
    ///   in_transfer_func (cm_is_degamma_srgb), linear or not;
    /// - a 4096-entry one is amdgpu_dm_set_atomic_regamma's distributed
    ///   points (__set_output_tf on a linear base) unless __is_lut_linear,
    ///   which, like no GAMMA_LUT, bypasses the OGAM;
    /// - a CTM is the stream's gamut remap (__drm_ctm_to_dc_matrix,
    ///   enable_remap), whatever its values.
    ///
    /// None for blobs of another size, which the DRM bridge refuses first.
    pub fn from_crtc(ctm: Option<&[u8]>, gamma_lut: Option<&[u8]>) -> Option<Self> {
        use crate::amdgpu_dcn_color as cm;
        let gamut = match ctm {
            Some(blob) => {
                let remap = cm::gamut_remap(&cm::ctm_matrix(&cm::ctm_from_bytes(blob)?));
                Some(GamutProgram {
                    coef: remap.words(),
                    s3_12: remap.s3_12,
                })
            }
            None => None,
        };
        let (pre_degam_srgb, ogam) = match gamma_lut {
            None => (false, None),
            Some(blob) => {
                let lut = cm::DrmColorLut::from_bytes(blob)?;
                let legacy = match lut.len() {
                    cm::MAX_COLOR_LEGACY_LUT_ENTRIES => true,
                    cm::MAX_COLOR_LUT_ENTRIES => false,
                    _ => return None,
                };
                if !legacy && cm::is_lut_linear(&lut) {
                    (false, None)
                } else {
                    let pwl: alloc::boxed::Box<cm::Pwl> = cm::regamma_pwl(&lut)?;
                    (legacy, Some(OgamProgram::from_pwl(&pwl)))
                }
            }
        };
        Some(Self {
            pre_degam_srgb,
            gamut,
            ogam,
        })
    }
}
impl OgamProgram {
    /// The register words cm_helper_program_gamcor_xfer_func and
    /// mpc3_program_ogam_pwl write for `pwl`.
    pub fn from_pwl(pwl: &crate::amdgpu_dcn_color::Pwl) -> Self {
        let regs = pwl.registers();
        let words = |v: &[u32]| v.iter().map(|w| w & 0x3ffff).collect();
        Self {
            start: regs.start_cntl,
            start_slope: regs.start_slope_cntl,
            end_base: regs.end_cntl1,
            end: regs.end_cntl2,
            regions: regs.region,
            lut: [
                words(&pwl.red_reg),
                words(&pwl.green_reg),
                words(&pwl.blue_reg),
            ],
        }
    }
}

impl<I: Io> Engine<I> {
    /// dcn401_program_gamut_remap on pipe `q`'s MPCC: the stream's remap on its
    /// segment's top layer, bypass (`None`) below. Returns the coefficient
    /// set now selected.
    fn program_gamut(
        &mut self,
        q: u8,
        gamut: Option<&GamutProgram>,
    ) -> Result<Option<(u8, bool)>, Error> {
        let l = self.layout;
        // No plane CTM; the second MCM remap is reserved bypass.
        self.update(l.mcm(q, MCM_FIRST_GAMUT_MODE), 3, 0)?;
        self.update(l.mcm(q, MCM_SECOND_GAMUT_MODE), 3, 0)?;
        let Some(g) = gamut else {
            self.update(l.ogam(q, GAMUT_MODE), 3, 0)?;
            return Ok(None);
        };
        // The set in use is not rewritten: A unless A is current.
        let current = (self.read(l.ogam(q, GAMUT_MODE))? >> 7) & 3;
        let set = if current != 1 { 1 } else { 2 };
        let base = if set == 1 { GAMUT_A } else { GAMUT_B };
        for (i, &word) in g.coef.iter().enumerate() {
            self.update(l.ogam(q, base + i as u64), u32::MAX, word)?;
        }
        self.update(l.ogam(q, GAMUT_MODE), 3, set)?;
        self.update(l.ogam(q, GAMUT_COEF_FORMAT), 1, u32::from(g.s3_12))?;
        Ok(Some((set as u8, g.s3_12)))
    }
    /// dcn32_set_input_transfer_func on pipe `q`'s DPP for a plane without its
    /// own color: dpp3_set_pre_degam, then dpp3_program_gamcor_lut(NULL).
    fn program_input_tf(&mut self, q: u8, degam: PreDegam) -> Result<(), Error> {
        let l = self.layout;
        self.update(l.dpp(q, PRE_DEGAM), 0x73, degam.word())?;
        self.update(l.dpp(q, CM_CONTROL), 1, 0)?;
        self.update(l.dpp(q, GAMCOR_CONTROL), 0xf, 0)
    }
    /// mpc3_set_output_gamma on pipe `q`'s MPCC. Returns the RAM bank now selected.
    async fn program_ogam(
        &mut self,
        q: u8,
        ogam: Option<&OgamProgram>,
    ) -> Result<Option<u8>, Error> {
        let l = self.layout;
        let at = |r| l.ogam(q, r);
        let Some(o) = ogam else {
            self.update(at(OGAM_CONTROL), 0xf, 0)?;
            return Ok(None);
        };
        self.update(at(OGAM_CONTROL), 0xf, 2)?;
        // mpc3_get_ogam_current: RAM A or B only when MODE_CURRENT is RAM.
        let control = self.read(at(OGAM_CONTROL))?;
        let current = ((control >> 7) & 3 == 2).then_some((control >> 9) & 1);
        let next: u32 = if current == Some(0) { 1 } else { 0 };
        // mpc3_power_on_ogam_lut: force the memory on, then wait for it.
        let power = l.mpcc(q, MPCC_MEM_PWR);
        self.update(power, OGAM_MEM_PWR_DIS, OGAM_MEM_PWR_DIS)?;
        self.wait(power, OGAM_MEM_PWR_STATE, 0, 100).await?;
        // mpc3_configure_ogam_lut: all channels, host access to `next`.
        self.update(at(OGAM_LUT_CONTROL), 0x47, 7 | next << 6)?;
        self.update(at(OGAM_LUT_INDEX), u32::MAX, 0)?;
        let ram = if next == 0 { OGAM_RAMA } else { OGAM_RAMB };
        // cm_helper_program_gamcor_xfer_func's order.
        for (c, &start) in o.start.iter().enumerate() {
            self.update(at(ram + c as u64), u32::MAX, start)?;
        }
        for (c, &slope) in o.start_slope.iter().enumerate() {
            self.update(at(ram + RAM_START_SLOPE + c as u64), u32::MAX, slope)?;
        }
        // END_CNTL1 then END_CNTL2 of B, G and R (interleaved registers).
        for (c, &base) in o.end_base.iter().enumerate() {
            self.update(at(ram + RAM_END + 2 * c as u64), u32::MAX, base)?;
        }
        for (c, &end) in o.end.iter().enumerate() {
            self.update(at(ram + RAM_END + 2 * c as u64 + 1), u32::MAX, end)?;
        }
        for (i, &region) in o.regions.iter().enumerate() {
            self.update(at(ram + RAM_REGIONS + i as u64), u32::MAX, region)?;
        }
        // mpc3_program_ogam_pwl: one pass when the channels agree, else red,
        // green and blue each under its write mask from index 0.
        let data = at(OGAM_LUT_DATA);
        if o.lut[0] == o.lut[1] && o.lut[1] == o.lut[2] {
            self.lut_words(data, &o.lut[0])?;
        } else {
            for (c, mask) in [4u32, 2, 1].into_iter().enumerate() {
                if c > 0 {
                    self.update(at(OGAM_LUT_INDEX), u32::MAX, 0)?;
                }
                self.update(at(OGAM_LUT_CONTROL), 7, mask)?;
                self.lut_words(data, &o.lut[c])?;
            }
        }
        self.update(at(OGAM_CONTROL), 4, next << 2)?;
        Ok(Some(next as u8))
    }
    /// Back-to-back LUT_DATA writes; the hardware advances the index.
    fn lut_words(&mut self, data: u64, words: &[u32]) -> Result<(), Error> {
        self.access(|io| {
            for &word in words {
                io.write(data, word);
            }
            Ok(())
        })
    }
    /// The input transfer function amdgpu_dm gives the plane HUBP/DPP `q`
    /// fetches under display `pipe`'s CRTC color: the implicit degamma of
    /// its format under legacy gamma (cm_is_degamma_srgb), else bypass.
    fn input_tf(&self, pipe: u8, q: u8) -> PreDegam {
        let legacy = self.displays.color[usize::from(pipe)]
            .as_deref()
            .is_some_and(|c| c.pre_degam_srgb);
        match self.fetched_surface(q) {
            Some(a) if legacy => PreDegam::implicit(a.request.format),
            None if legacy => PreDegam::Srgb,
            _ => PreDegam::Bypass,
        }
    }
    /// Program display `p.pipe`'s requested color on each of its pipes, in
    /// dcn401_program_pipe's order (gamut remap, input then output transfer
    /// function). Every plane takes the input transfer function amdgpu_dm
    /// derives from the CRTC for its format (`input_tf`); the stream's gamut
    /// remap and regamma go on each segment's top MPCC only
    /// (dcn401_program_gamut_remap and dcn401_set_output_transfer_func's
    /// is_top_pipe), the MPCCs below it in bypass. The caller holds the OTG
    /// master lock.
    pub(super) async fn program_color(&mut self, p: Pipe) -> Result<(), Error> {
        let program = self.displays.color[usize::from(p.pipe)].clone();
        let program = program.as_deref();
        for tree in p.trees() {
            let top = tree.last().copied();
            for &q in &tree {
                let stream = program.filter(|_| Some(q) == top);
                let gamut = self.program_gamut(q, stream.and_then(|c| c.gamut.as_ref()))?;
                let pre_degam = self.input_tf(p.pipe, q);
                self.program_input_tf(q, pre_degam)?;
                let ogam = self
                    .program_ogam(q, stream.and_then(|c| c.ogam.as_ref()))
                    .await?;
                self.status.colors[usize::from(q)] = PipeColor {
                    pre_degam,
                    gamut,
                    ogam,
                };
            }
        }
        Ok(())
    }
    /// Pipe `q`'s recorded color selections must hold (staged values are
    /// checked by the DPP and MPC verifiers through the same record).
    pub(super) fn verify_color(&mut self, q: u8) -> Result<(), Error> {
        let l = self.layout;
        let c = self.status.colors[usize::from(q)];
        let (ogam_mask, ogam) = c.ogam_control();
        for (at, mask, value) in [
            (l.dpp(q, PRE_DEGAM), 0x73, c.pre_degam()),
            (l.ogam(q, OGAM_CONTROL), ogam_mask, ogam),
            (l.ogam(q, GAMUT_MODE), 3, c.gamut_mode()),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    /// Make `program` display `pipe`'s CRTC color. Recorded for the next
    /// scanout start; a live scanout is reprogrammed at once under its
    /// lock (amdgpu_dm's non-modeset color update), returning after the
    /// selections latched.
    pub(in crate::amdgpu_dcn401_otg) async fn set_color(
        &mut self,
        pipe: u8,
        program: Option<Arc<ColorProgram>>,
    ) -> Result<(), Error> {
        let slot = usize::from(pipe);
        let unchanged = match (&self.displays.color[slot], &program) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b) || **a == **b,
            (None, None) => true,
            _ => false,
        };
        self.displays.color[slot] = program;
        if self.status.state != State::ScanoutRunning(pipe) || unchanged {
            return Ok(());
        }
        let running = self.status.scanout.ok_or(Error::Invalid)?;
        let blank = self.status.blanks[slot].ok_or(Error::Invalid)?;
        let p = Pipe {
            pipe,
            odm: running.odm,
            mpc: running.mpc,
            address: running.address,
            overlays: running.overlays,
            black: 0x41 | blank.request.depth.dpg() << 12,
            timeout_us: self.frame_timeout_us(pipe, blank)?,
            watch: true,
        };
        self.live_fetch(pipe, running.address)?;
        self.flip_quiet(pipe)?;
        self.status.state = State::UpdatingStream(pipe);
        let result = async {
            self.lock(pipe).await?;
            self.program_color(p).await?;
            self.update(self.layout.otg(pipe, LOCK), 1, 0)?;
            self.drr_trigger(pipe)?;
            self.stream_latched(p).await?;
            for q in p.all_pipes() {
                self.verify_color(q)?;
            }
            self.live_fetch(pipe, running.address)
        }
        .await;
        match result {
            Ok(()) => {
                self.status.state = State::ScanoutRunning(pipe);
                Ok(())
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}

impl Otg {
    /// Set display `pipe`'s CRTC color (`None`: bypass). A live scanout is
    /// reprogrammed at once; otherwise the next scanout start programs it.
    /// A failure on a live scanout leaves `Failed`.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display writers.
    pub async unsafe fn set_color(
        &mut self,
        pipe: u8,
        program: Option<Arc<ColorProgram>>,
    ) -> Result<(), Error> {
        // Display k scans out on pipe k: address that display's records.
        self.0.select_display(pipe)?;
        self.0.set_color(pipe, program).await
    }
    /// The color display `pipe` was last asked for.
    pub fn color(&self, pipe: u8) -> Option<Arc<ColorProgram>> {
        self.0
            .displays
            .color
            .get(usize::from(pipe))
            .cloned()
            .flatten()
    }
    /// New HDR static metadata for display `pipe`'s running stream, which
    /// already sends HDR packets (the stream update amdgpu_dm makes when
    /// metadata changes while HDR stays on): the HDMI DRM InfoFrame (TMDS
    /// generic packet 4 or the FRL encoder's packet 4) or the DP HDR SDP
    /// (DIO or HPO packet 3) rewritten with an immediate update. `Invalid` for a
    /// stream without HDR packets (entering or leaving HDR is a modeset)
    /// or a packet of the other kind; `Busy` without running video.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display writers.
    pub async unsafe fn set_hdr(
        &mut self,
        pipe: u8,
        packet: crate::amdgpu_hdr::InfoPacket,
    ) -> Result<(), Error> {
        self.0.select_display(pipe)?;
        let e = &mut self.0;
        let live = match e.status.state {
            State::ScanoutRunning(p) => p == pipe,
            State::HdmiVideoRunning(s) => e
                .status
                .hdmi_video_running
                .is_some_and(|v| v.link.request.stream == s && v.link.request.pipe == pipe),
            State::DpVideoRunning(s) => e
                .status
                .dp_video_running
                .is_some_and(|v| v.frontend.request.stream == s && v.frontend.request.pipe == pipe),
            State::UhbrVideoRunning(s) => e
                .status
                .uhbr_video_running
                .is_some_and(|v| v.stream == s && v.timing.blank.request.pipe == pipe),
            State::FrlVideoRunning(p) => p == pipe && e.status.frl_video_running.is_some(),
            _ => false,
        };
        if !live {
            return Err(Error::Busy);
        }
        // The DRM InfoFrame's type sits in HB0; the SDP's in HB1.
        let hdmi = packet.hb[0] == 0x87;
        let s = &e.status;
        let tmds = s
            .hdmi_video_running
            .is_some_and(|v| v.link.request.pipe == pipe);
        let frl = s.frl_video_running.is_some_and(|v| v.request.pipe == pipe);
        let dio = s
            .dp_video_running
            .is_some_and(|v| v.frontend.request.pipe == pipe);
        let hpo = s
            .uhbr_video_running
            .is_some_and(|v| v.timing.blank.request.pipe == pipe);
        let result = match (hdmi, tmds, frl, dio, hpo) {
            (true, true, ..) => e.hdmi_update_hdr(packet).await,
            (true, _, true, ..) => e.frl_update_hdr(packet).await,
            (false, _, _, true, _) => e.dp_update_hdr(packet).await,
            (false, .., true) => e.uhbr_update_hdr(packet).await,
            _ => return Err(Error::Invalid),
        };
        if let Err(err) = result {
            if err != Error::Invalid {
                e.status.state = State::Failed(err);
            }
        }
        result
    }
    /// The HDR packet display `pipe`'s running stream sends, if any.
    pub fn hdr(&self, pipe: u8) -> Option<crate::amdgpu_hdr::InfoPacket> {
        let s = self.display_status(pipe)?;
        let hdmi = s
            .hdmi_video_running
            .filter(|v| v.link.request.pipe == pipe)
            .and_then(|v| v.link.request.hdr);
        let dp = s
            .dp_video_running
            .filter(|v| v.frontend.request.pipe == pipe)
            .and_then(|v| v.frontend.request.hdr);
        let frl = s
            .frl_video_running
            .filter(|v| v.request.pipe == pipe)
            .and_then(|v| v.request.hdr);
        let hpo = s
            .uhbr_video_running
            .filter(|v| v.timing.blank.request.pipe == pipe)
            .and_then(|v| v.sdp.hdr);
        hdmi.or(dp).or(frl).or(hpo)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_color_tests.rs"]
mod tests;
