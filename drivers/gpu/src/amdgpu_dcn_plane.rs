//! Navi22 DCN3.0 and Phoenix DCN3.1.4 plane path: the display pipe processor, the multiple-pipe/plane
//! combiner and the output pixel processor. Offsets and fields are
//! `dcn_3_1_4_offset.h`/`dcn_3_1_4_sh_mask.h`; the DPP and OPP banks are DCN base
//! index 2 while the MPC bank is index 3. Sequencing follows Linux
//! `dcn10_dpp_dscl.c`, `dcn30_mpc.c::mpc1_mux_plane` and
//! `dcn20_opp.c::opp2_set_disp_pattern_generator`.
//!
//! Scope is one plane with the scaler and every colour-management stage bypassed
//! and no blending, which is what an unscaled linear RGB scanout needs. A
//! stream is blanked here, by the OPP's pattern generator, rather than at the
//! timing generator.
use crate::{
    amdgpu::AmdGpu, amdgpu_dcn_clk::Error, amdgpu_dcn_profile::Profile, amdgpu_dml::Format,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// DPP block (base index 2), stride 0x16b.
// Profile selects DCN30 or DCN314; shared ids below were compared against
// both Linux offset and mask headers. Generation differences stay explicit.
// linux-ctx: hdr=dcn seg=2
const DPP_CONTROL: u64 = 0x0cc5; // linux: mmDPP_TOP0_DPP_CONTROL
const CNVC_SURFACE_PIXEL_FORMAT: u64 = 0x0ccf; // linux: mmCNVC_CFG0_CNVC_SURFACE_PIXEL_FORMAT
const FORMAT_CONTROL: u64 = 0x0cd0; // linux: mmCNVC_CFG0_FORMAT_CONTROL
const PRE_DEALPHA: u64 = 0x0cde; // linux: mmCNVC_CFG0_PRE_DEALPHA
const PRE_DEGAM: u64 = 0x0ced; // linux: mmCNVC_CFG0_PRE_DEGAM
const PRE_REALPHA: u64 = 0x0cee; // linux: mmCNVC_CFG0_PRE_REALPHA
const CM_CONTROL: u64 = 0x0d20; // linux: mmCM0_CM_CONTROL
const SCL_MODE: u64 = 0x0cfb; // linux: mmDSCL0_SCL_MODE
const DSCL_CONTROL: u64 = 0x0cfd; // linux: mmDSCL0_DSCL_CONTROL
const DSCL_AUTOCAL: u64 = 0x0d0c; // linux: mmDSCL0_DSCL_AUTOCAL
const RECOUT_START: u64 = 0x0d11; // linux: mmDSCL0_RECOUT_START
const RECOUT_SIZE: u64 = 0x0d12; // linux: mmDSCL0_RECOUT_SIZE
const MPC_SIZE: u64 = 0x0d13; // linux: mmDSCL0_MPC_SIZE
const LB_DATA_FORMAT: u64 = 0x0d14; // linux: mmDSCL0_LB_DATA_FORMAT
const LB_MEMORY_CTRL: u64 = 0x0d15; // linux: mmDSCL0_LB_MEMORY_CTRL
const DPP_STRIDE: u64 = 0x16b; // linux: mmDPP_TOP1_DPP_CONTROL - mmDPP_TOP0_DPP_CONTROL
                               // OPP block (base index 2): FMT stride 0x5a, shared by DPG and OPP_PIPE.
const FMT_CONTROL: u64 = 0x1840; // linux: mmFMT0_FMT_CONTROL
const FMT_BIT_DEPTH_CONTROL: u64 = 0x1841; // linux: mmFMT0_FMT_BIT_DEPTH_CONTROL
const DPG_CONTROL: u64 = 0x1854; // linux: mmDPG0_DPG_CONTROL
const DPG_DIMENSIONS: u64 = 0x1856; // linux: mmDPG0_DPG_DIMENSIONS
const DPG_COLOUR_R_CR: u64 = 0x1857; // linux: mmDPG0_DPG_COLOUR_R_CR
const DPG_COLOUR_G_Y: u64 = 0x1858; // linux: mmDPG0_DPG_COLOUR_G_Y
const DPG_COLOUR_B_CB: u64 = 0x1859; // linux: mmDPG0_DPG_COLOUR_B_CB
const OPP_PIPE_CONTROL: u64 = 0x188c; // linux: mmOPP_PIPE0_OPP_PIPE_CONTROL
const OPP_STRIDE: u64 = 0x5a; // linux: mmFMT1_FMT_CONTROL - mmFMT0_FMT_CONTROL
                              // MPC block (base index 3): MPCC stride 0x20, output mux stride 4.
                              // linux-ctx: hdr=dcn seg=3
const MPCC_TOP_SEL: u64 = 0x0000; // linux: mmMPCC0_MPCC_TOP_SEL
const MPCC_BOT_SEL: u64 = 0x0001; // linux: mmMPCC0_MPCC_BOT_SEL
const MPCC_OPP_ID: u64 = 0x0002; // linux: mmMPCC0_MPCC_OPP_ID
const MPCC_CONTROL: u64 = 0x0003; // linux: mmMPCC0_MPCC_CONTROL
const MPCC_STRIDE: u64 = 0x20; // linux: mmMPCC1_MPCC_TOP_SEL - mmMPCC0_MPCC_TOP_SEL
const MPCC_OGAM_CONTROL: u64 = 0x0100; // linux: mmMPCC_OGAM0_MPCC_OGAM_CONTROL
const OGAM_STRIDE: u64 = 0x80; // linux: mmMPCC_OGAM1_MPCC_OGAM_CONTROL - mmMPCC_OGAM0_MPCC_OGAM_CONTROL
const MPC_OUT_MUX: u64 = 0x0580; // linux: mmMPC_OUT0_MUX
const MPC_OUT_STRIDE: u64 = 4; // linux: mmMPC_OUT1_MUX - mmMPC_OUT0_MUX
                               // linux-ctx: hdr=dcn

#[cfg(feature = "kernel-test")]
const DPP_LAST_REG: u32 = (CM_CONTROL + 3 * DPP_STRIDE) as u32; // linux: n/a (test-only bank bound)
#[cfg(feature = "kernel-test")]
// linux: n/a (test-only bank bound)
const OPP_LAST_REG: u32 = (OPP_PIPE_CONTROL + 3 * OPP_STRIDE) as u32;
#[cfg(feature = "kernel-test")]
// linux: n/a (test-only bank bound)
const MPC_LAST_REG: u32 = (MPC_OUT_MUX + 3 * MPC_OUT_STRIDE) as u32;
/// One per pixel pipe; see [`crate::amdgpu_dcn::DCN_PIPES`].
#[cfg(feature = "kernel-test")]
const INSTANCES: u8 = crate::amdgpu_dcn::DCN_PIPES;
/// The widest and tallest region these blocks can describe.
///
/// `DSCL0_RECOUT_SIZE`'s `RECOUT_WIDTH`/`RECOUT_HEIGHT`, `DSCL0_MPC_SIZE`'s
/// `MPC_WIDTH`/`MPC_HEIGHT` and `DPG0_DPG_DIMENSIONS`'s
/// `DPG_ACTIVE_WIDTH`/`DPG_ACTIVE_HEIGHT` are all 14-bit fields (0x00003FFF
/// and 0x3FFF0000), so every dimension this module programs tops out here.
/// `amdgpu_dcn_display::MAX_HEIGHT` is the same bound, checked where the mode
/// is validated; the width is bounded tighter still by the OTG's
/// `OPTC_SEGMENT_WIDTH`, so this is the backstop rather than the gate.
pub(crate) const MAX_DIMENSION: u32 = (1 << 14) - 1; // linux: DSCL0_RECOUT_SIZE__RECOUT_WIDTH_MASK

/// `DSCL_MODE_SCALING_444_BYPASS`: an unscaled RGB plane takes no scaler taps.
/// `DSCL_MODE_SCALING_444_BYPASS` from `enum dscl_mode_sel`
/// (`dcn10_dpp_dscl.c:79-87`).
// linux: n/a (enum dscl_mode_sel in dcn10_dpp.c: DSCL_MODE_SCALING_444_BYPASS = 0)
const SCALER_BYPASS: u32 = 0;
/// `DSCL0_SCL_MODE__DSCL_MODE_MASK` — **three** bits, not two. The enum runs to
/// `DSCL_MODE_DSCL_BYPASS` = 6, so bit 2 is live.
///
/// LINUX-GAP: this was masked 0x3. On a handoff from firmware that left the
/// scaler in mode 4, 5 or 6, clearing only the low two bits would have left
/// mode 4 (`SCALING_420_LUMA_BYPASS`) behind instead of reaching bypass.
const DSCL_MODE: u32 = 0x0000_0007; // linux: DSCL0_SCL_MODE__DSCL_MODE_MASK
/// `MPCC_TOP_SEL`/`MPCC_BOT_SEL` park with all ones.
const MPCC_UNSET: u32 = 0xf; // linux: n/a (literal 0xf in dcn10_mpc.c:mpc1_remove_mpcc)

// `MPCC0_MPCC_CONTROL` fields, from `dcn_3_1_4_sh_mask.h`:
//
//   MPCC_MODE                     0x00000003
//   MPCC_ALPHA_BLND_MODE          0x00000030
//   MPCC_ALPHA_MULTIPLIED_MODE    0x00000040
//   MPCC_BLND_ACTIVE_OVERLAP_ONLY 0x00000080
//   MPCC_BG_BPC                   0x00000700
//   MPCC_GLOBAL_ALPHA             0x00FF0000
//
// LINUX-GAP: the mask was `0xf | 0x3 << 4 | 0x3 << 8` — two bits wider than
// `MPCC_MODE` (reaching reserved bits 3:2) and one bit narrower than
// `MPCC_BG_BPC`. The fields below are the ones `mpc1_update_blending` and
// `mpc1_mux_plane` write, with the values `dcn20_hwseq.c:2960-2990` composes
// for an opaque plane.
const MPCC_MODE: u32 = 0x0000_0003; // linux: MPCC0_MPCC_CONTROL__MPCC_MODE_MASK
                                    // linux: MPCC0_MPCC_CONTROL__MPCC_ALPHA_BLND_MODE_MASK
const MPCC_ALPHA_BLND_MODE: u32 = 0x0000_0030;
// linux: MPCC0_MPCC_CONTROL__MPCC_ALPHA_MULTIPLIED_MODE_MASK
const MPCC_ALPHA_MULTIPLIED_MODE: u32 = 0x0000_0040;
// linux: MPCC0_MPCC_CONTROL__MPCC_BLND_ACTIVE_OVERLAP_ONLY_MASK
const MPCC_BLND_ACTIVE_OVERLAP_ONLY: u32 = 0x0000_0080;
const MPCC_BG_BPC: u32 = 0x0000_0700; // linux: MPCC0_MPCC_CONTROL__MPCC_BG_BPC_MASK
const MPCC_GLOBAL_ALPHA: u32 = 0x00FF_0000; // linux: MPCC0_MPCC_CONTROL__MPCC_GLOBAL_ALPHA_MASK

/// `MPCC_BLEND_MODE_TOP_LAYER_ONLY` from `enum mpcc_blend_mode`
/// (`inc/hw/mpc.h:70-75`): BYPASS 0, TOP_LAYER_PASSTHROUGH 1, TOP_LAYER_ONLY 2,
/// TOP_BOT_BLENDING 3.
///
/// LINUX-GAP: this register was written 0, `MPCC_BLEND_MODE_BYPASS`, under a
/// comment describing opaque passthrough. `mpc1_mux_plane` writes
/// `TOP_LAYER_ONLY` for exactly this case — no bottom layer — and Linux's MPC
/// never writes BYPASS anywhere. A bypassed MPCC does not put the DPP's pixels
/// on the OPP at all.
// linux: n/a (enum mpcc_blend_mode in inc/hw/mpc.h; header not in checker set)
const MPCC_BLEND_MODE_TOP_LAYER_ONLY: u32 = 2;
/// `MPCC_ALPHA_BLEND_MODE_GLOBAL_ALPHA` (`inc/hw/mpc.h`), which
/// `dcn20_hwseq.c` selects for a plane with no per-pixel alpha, paired with
/// `global_alpha = 0xff`.
// linux: n/a (enum mpcc_alpha_blend_mode in inc/hw/mpc.h; header not in checker set)
const MPCC_ALPHA_BLEND_MODE_GLOBAL_ALPHA: u32 = 2;
/// `blnd_cfg.global_alpha = 0xff` — fully opaque.
// linux: n/a (literal in dcn20_hwseq.c:dcn20_update_mpcc, global_alpha)
const MPCC_GLOBAL_ALPHA_OPAQUE: u32 = 0xff;
/// `blnd_cfg.background_color_bpc = 4` (`dcn20_hwseq.c:2985`).
// linux: n/a (literal in dcn20_hwseq.c:dcn20_update_mpcc, background_color_bpc)
const MPCC_BG_BPC_DEFAULT: u32 = 4;

// `FMT0_FMT_CONTROL`:
//
//   FMT_PIXEL_ENCODING            0x00030000
//   FMT_SUBSAMPLING_MODE          0x000C0000
//   FMT_CBCR_BIT_REDUCTION_BYPASS 0x00200000
//
// LINUX-GAP: the mask was `0x7 << 16`, which straddles the first two fields —
// all of `FMT_PIXEL_ENCODING` and only the LOW bit of `FMT_SUBSAMPLING_MODE`.
// `opp1_program_fmt`'s RGB arm clears all three, so an inherited
// `FMT_SUBSAMPLING_MODE` of 2 (what a 4:2:2 or 4:2:0 stream leaves) would have
// survived into an RGB stream.
// linux: FMT0_FMT_CONTROL__FMT_PIXEL_ENCODING_MASK | FMT0_FMT_CONTROL__FMT_SUBSAMPLING_MODE_MASK | FMT0_FMT_CONTROL__FMT_CBCR_BIT_REDUCTION_BYPASS_MASK
const FMT_RGB_FIELDS: u32 = 0x0003_0000 | 0x000C_0000 | 0x0020_0000;
/// `TEST_PATTERN_MODE_HORIZONTALBARS` with both bar colours black, which is how
/// DCN2 onwards paints a blanked stream.
// linux: n/a (enum test_pattern_mode in inc/hw/hw_shared.h; not in checker set)
const DPG_MODE_SOLID: u32 = 4;
/// `TEST_PATTERN_COLOR_FORMAT_BPC_8`.
// linux: n/a (enum test_pattern_color_format in inc/hw/hw_shared.h; not in checker set)
const DPG_BIT_DEPTH_8: u32 = 1;

/// The pixel encoding the output formatter emits. Only uncompressed RGB is
/// modelled; 4:2:2 and 4:2:0 would need the chroma path this port does not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Rgb,
}
impl Encoding {
    fn code(self) -> u32 {
        match self {
            Encoding::Rgb => 0, // linux: n/a (literal in dcn10_opp.c:opp1_set_pixel_encoding)
        }
    }
}
/// `CNVC_SURFACE_PIXEL_FORMAT` uses the same codes as the hub pixel pipe.
fn cnvc_format(format: Format) -> u32 {
    match format {
        Format::Rgb16 => 3,  // linux: n/a (literal in dcn30_dpp.c:dpp3_cnv_setup, RGB565)
        Format::Rgb32 => 8,  // linux: n/a (literal in dcn30_dpp.c:dpp3_cnv_setup, ARGB8888)
        Format::Rgb64 => 26, // linux: n/a (literal in dcn30_dpp.c:dpp3_cnv_setup, ARGB16161616)
    }
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
        // SAFETY: constructor bounds this DCN bank and retains the mapping.
        unsafe { self.regs.read32(self.base + reg * 4) }
    }
    fn write(&mut self, reg: u64, value: u32) {
        // SAFETY: same bounded bank; this is the sole owner of the instance.
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
struct Block<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    instance: u8,
    profile: Profile,
}
impl<I: Io> Block<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    fn set(&mut self, reg: u64, value: u32) -> Result<(), Error> {
        self.access(|io| io.write(reg, value))
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        self.access(|io| {
            let old = io.read(reg);
            if old == u32::MAX {
                return Err(Error::DeviceGone);
            }
            io.write(reg, (old & !mask) | (value & mask));
            Ok(())
        })?
    }
}
impl<I: Io> Block<I> {
    fn dpp(&self, reg: u64) -> u64 {
        reg + self.instance as u64 * DPP_STRIDE
    }
    fn mpcc(&self, reg: u64) -> u64 {
        reg + self.instance as u64 * MPCC_STRIDE
    }
    fn opp(&self, reg: u64) -> u64 {
        reg + self.instance as u64 * OPP_STRIDE
    }
    /// Program the input format and a 1:1 recout. The recout and the combiner
    /// size match the active area because nothing is scaled and nothing is
    /// blended beside it.
    fn dpp_program(&mut self, format: Format, width: u32, height: u32) -> Result<(), Error> {
        if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
            return Err(Error::Invalid);
        }
        let reg = self.dpp(DPP_CONTROL);
        // linux-lit: 4=DPP_TOP0_DPP_CONTROL__DPP_CLOCK_ENABLE__SHIFT
        self.update(reg, 1 << 4, 1 << 4)?;
        let reg = self.dpp(CNVC_SURFACE_PIXEL_FORMAT);
        // No separate alpha surface (RGBE_ALPHA is not an accepted format).
        // linux-lit: 0x17f=CNVC_CFG0_CNVC_SURFACE_PIXEL_FORMAT__CNVC_SURFACE_PIXEL_FORMAT_MASK | CNVC_CFG0_CNVC_SURFACE_PIXEL_FORMAT__CNVC_ALPHA_PLANE_ENABLE_MASK
        self.update(reg, 0x17f, cnvc_format(format))?;
        // dpp3_cnv_setup: zero expansion, R/G/B crossbar 0/1/2, no float,
        // clamp or converter bypass inherited from a previous stream.
        let reg = self.dpp(FORMAT_CONTROL);
        let alpha = u32::from(format != Format::Rgb16) << 8;
        // linux-lit: 0x3f033111=CNVC_CFG0_FORMAT_CONTROL__FORMAT_EXPANSION_MODE_MASK | CNVC_CFG0_FORMAT_CONTROL__FORMAT_CNV16_MASK | CNVC_CFG0_FORMAT_CONTROL__ALPHA_EN_MASK | CNVC_CFG0_FORMAT_CONTROL__CNVC_BYPASS_MASK | CNVC_CFG0_FORMAT_CONTROL__CNVC_BYPASS_MSB_ALIGN_MASK | CNVC_CFG0_FORMAT_CONTROL__CLAMP_POSITIVE_MASK | CNVC_CFG0_FORMAT_CONTROL__CLAMP_POSITIVE_C_MASK | CNVC_CFG0_FORMAT_CONTROL__FORMAT_CROSSBAR_R_MASK | CNVC_CFG0_FORMAT_CONTROL__FORMAT_CROSSBAR_G_MASK | CNVC_CFG0_FORMAT_CONTROL__FORMAT_CROSSBAR_B_MASK
        self.update(reg, 0x3f03_3111, 0x2400_0001 | alpha)?;
        for field in [PRE_DEALPHA, PRE_REALPHA] {
            let reg = self.dpp(field);
            // linux-lit: 0x11=CNVC_CFG0_PRE_DEALPHA__PRE_DEALPHA_EN_MASK | CNVC_CFG0_PRE_DEALPHA__PRE_DEALPHA_ABLND_EN_MASK
            self.update(reg, 0x11, 0)?;
        }
        // CNVC's ROM degamma is before the CM block, so bypass both. This
        // path accepts already encoded RGB pixels and owns no color LUTs.
        let reg = self.dpp(PRE_DEGAM);
        // linux-lit: 0x73=CNVC_CFG0_PRE_DEGAM__PRE_DEGAM_MODE_MASK | CNVC_CFG0_PRE_DEGAM__PRE_DEGAM_SELECT_MASK
        self.update(reg, 0x73, 0)?;
        let reg = self.dpp(CM_CONTROL);
        // linux-lit: 1=CM0_CM_CONTROL__CM_BYPASS_MASK
        self.update(reg, 1, 1)?;
        // dpp1_dscl_set_scaler_manual_scale still initializes autocal,
        // boundary mode and line-buffer storage for SCALING_444_BYPASS.
        // It only skips these for DSCL_BYPASS (the separate FP16 path).
        let reg = self.dpp(DSCL_AUTOCAL);
        // linux-lit: 0x3303=DSCL0_DSCL_AUTOCAL__AUTOCAL_MODE_MASK | DSCL0_DSCL_AUTOCAL__AUTOCAL_NUM_PIPE_MASK | DSCL0_DSCL_AUTOCAL__AUTOCAL_PIPE_ID_MASK
        self.update(reg, 0x3303, 0)?;
        let reg = self.dpp(DSCL_CONTROL);
        self.update(reg, 1, 0)?; // linux-lit: 1=DSCL0_DSCL_CONTROL__SCL_BOUNDARY_MODE_MASK
        let reg = self.dpp(LB_DATA_FORMAT);
        // Opaque RGB: neither alpha nor chroma interleave uses LB storage.
        // linux-lit: 0x11=DSCL0_LB_DATA_FORMAT__INTERLEAVE_EN_MASK | DSCL0_LB_DATA_FORMAT__ALPHA_EN_MASK
        self.update(reg, 0x11, 0)?;
        let reg = self.dpp(LB_MEMORY_CTRL);
        // Linux's use_max_lb RGB choice, MEMORY_CONFIG_0 (all three banks),
        // with the pre-DCN3.2 maximum of 63 partitions. No scaling/taps.
        // linux-lit: 0x3f00=63 << DSCL0_LB_MEMORY_CTRL__LB_MAX_PARTITIONS__SHIFT
        self.set(reg, 0x3f00)?;
        // Bypass the scaler outright rather than programming unity taps.
        let reg = self.dpp(SCL_MODE);
        self.update(reg, DSCL_MODE, SCALER_BYPASS)?;
        let reg = self.dpp(RECOUT_START);
        self.set(reg, 0)?;
        let reg = self.dpp(RECOUT_SIZE);
        // linux-lit: 16=DSCL0_RECOUT_SIZE__RECOUT_HEIGHT__SHIFT
        self.set(reg, width | height << 16)?;
        let reg = self.dpp(MPC_SIZE);
        self.set(reg, width | height << 16) // linux-lit: 16=DSCL0_MPC_SIZE__MPC_HEIGHT__SHIFT
    }
    /// `mpc1_mux_plane`: bind this MPCC to a DPP and an OPP and route the OPP's
    /// output mux to it. Opaque passthrough, no bottom layer.
    fn mpc_mux_plane(&mut self, dpp: u8, opp: u8) -> Result<(), Error> {
        if dpp >= self.profile.pipes() || opp >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        // mpc3_program_ogam(NULL): this passthrough path owns no output
        // gamma LUT. A firmware LUT may still be selected after mpc_init.
        let reg = MPCC_OGAM_CONTROL + u64::from(self.instance) * OGAM_STRIDE;
        self.update(reg, 3, 0)?; // linux-lit: 3=MPCC_OGAM0_MPCC_OGAM_CONTROL__MPCC_OGAM_MODE_MASK
        let reg = self.mpcc(MPCC_TOP_SEL);
        self.update(reg, 0xf, dpp as u32)?; // linux-lit: 0xf=MPCC0_MPCC_TOP_SEL__MPCC_TOP_SEL_MASK
                                            // Nothing below this plane: a stale bottom select would blend against
                                            // another pipe's output.
        let reg = self.mpcc(MPCC_BOT_SEL);
        self.update(reg, 0xf, MPCC_UNSET)?; // linux-lit: 0xf=MPCC0_MPCC_BOT_SEL__MPCC_BOT_SEL_MASK
        let reg = self.mpcc(MPCC_OPP_ID);
        self.update(reg, 0xf, opp as u32)?; // linux-lit: 0xf=MPCC0_MPCC_OPP_ID__MPCC_OPP_ID_MASK
                                            // Top layer only, with the opaque blend configuration
                                            // `dcn20_hwseq.c:2960-2990` composes: global alpha at 0xff, no
                                            // pre-multiplication, not overlap-only, background bpc 4.
        let reg = self.mpcc(MPCC_CONTROL);
        self.update(
            reg,
            MPCC_MODE
                | MPCC_ALPHA_BLND_MODE
                | MPCC_ALPHA_MULTIPLIED_MODE
                | MPCC_BLND_ACTIVE_OVERLAP_ONLY
                | MPCC_BG_BPC
                | MPCC_GLOBAL_ALPHA,
            MPCC_BLEND_MODE_TOP_LAYER_ONLY
                | MPCC_ALPHA_BLEND_MODE_GLOBAL_ALPHA << MPCC_ALPHA_BLND_MODE.trailing_zeros()
                | MPCC_BG_BPC_DEFAULT << MPCC_BG_BPC.trailing_zeros()
                | MPCC_GLOBAL_ALPHA_OPAQUE << MPCC_GLOBAL_ALPHA.trailing_zeros(),
        )?;
        let instance = self.instance as u32;
        let reg = MPC_OUT_MUX + opp as u64 * MPC_OUT_STRIDE;
        self.update(reg, 0xf, instance) // linux-lit: 0xf=MPC_OUT0_MUX__MPC_OUT_MUX_MASK
    }
    fn mpc_release(&mut self, opp: u8) -> Result<(), Error> {
        if opp >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        let reg = MPC_OUT_MUX + opp as u64 * MPC_OUT_STRIDE;
        self.update(reg, 0xf, MPCC_UNSET)?; // linux-lit: 0xf=MPC_OUT0_MUX__MPC_OUT_MUX_MASK
        for reg in [MPCC_TOP_SEL, MPCC_BOT_SEL, MPCC_OPP_ID] {
            let reg = self.mpcc(reg);
            // linux-lit: 0xf=MPCC0_MPCC_TOP_SEL__MPCC_TOP_SEL_MASK
            self.update(reg, 0xf, MPCC_UNSET)?;
        }
        Ok(())
    }
    /// Program the output formatter. Truncation and dithering stay off, so the
    /// formatter passes the plane's depth through untouched.
    fn opp_program(&mut self, encoding: Encoding, width: u32, height: u32) -> Result<(), Error> {
        if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
            return Err(Error::Invalid);
        }
        let reg = self.opp(OPP_PIPE_CONTROL);
        self.update(reg, 1, 1)?; // linux-lit: 1=OPP_PIPE0_OPP_PIPE_CONTROL__OPP_PIPE_CLOCK_EN_MASK
        let reg = self.opp(FMT_CONTROL);
        // linux-lit: 16=FMT0_FMT_CONTROL__FMT_PIXEL_ENCODING__SHIFT
        self.update(reg, FMT_RGB_FIELDS, encoding.code() << 16)?;
        // No truncation, no spatial dither, no frame randomisation.
        let reg = self.opp(FMT_BIT_DEPTH_CONTROL);
        self.set(reg, 0)?;
        // The pattern generator's active area must match the stream, or a
        // blanked stream would paint only part of the screen.
        let reg = self.opp(DPG_DIMENSIONS);
        // linux-lit: 16=DPG0_DPG_DIMENSIONS__DPG_ACTIVE_WIDTH__SHIFT
        self.set(reg, height | width << 16)
    }
    fn opp_set_blank(&mut self, blank: bool) -> Result<(), Error> {
        if blank {
            for colour in [DPG_COLOUR_R_CR, DPG_COLOUR_G_Y, DPG_COLOUR_B_CB] {
                let reg = self.opp(colour);
                self.set(reg, 0)?;
            }
            let reg = self.opp(DPG_CONTROL);
            // linux-lit: 1=DPG0_DPG_CONTROL__DPG_EN_MASK
            // linux-lit: 4=DPG0_DPG_CONTROL__DPG_MODE__SHIFT
            // linux-lit: 12=DPG0_DPG_CONTROL__DPG_BIT_DEPTH__SHIFT
            self.set(reg, 1 | DPG_MODE_SOLID << 4 | DPG_BIT_DEPTH_8 << 12)
        } else {
            // Disabling the generator outright is how DCN2 onwards returns to
            // video, rather than selecting a passthrough pattern.
            let reg = self.opp(DPG_CONTROL);
            self.set(reg, 0)
        }
    }
}

/// One owned display pipe processor, with the scaler bypassed.
#[derive(Debug)]
pub struct Dpp(Block<Mmio>);
impl Dpp {
    /// # Safety
    /// Caller exclusively owns this DPP instance for the object's lifetime and
    /// holds matching PCI authority and a permanent register mapping.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        instance: u8,
    ) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        if instance >= profile.pipes() {
            return Err(Error::Invalid);
        }
        Ok(Self(Block {
            io: Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                base: profile.bank(
                    gpu,
                    2, // linux-lit: 2=mmDPP_TOP0_DPP_CONTROL_BASE_IDX
                    (CM_CONTROL + u64::from(profile.pipes() - 1) * DPP_STRIDE) as u32,
                )?,
            },
            authority,
            instance,
            profile,
        }))
    }
    pub fn program(&mut self, format: Format, width: u32, height: u32) -> Result<(), Error> {
        self.0.dpp_program(format, width, height)
    }
}

/// The multiple-pipe/plane combiner. One MPCC takes one DPP and feeds one OPP,
/// with nothing below it to blend against.
#[derive(Debug)]
pub struct Mpc(Block<Mmio>);
impl Mpc {
    /// # Safety
    /// Caller exclusively owns this MPCC instance and the output mux of the OPP
    /// it feeds, and holds matching PCI authority and a permanent mapping.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        mpcc: u8,
    ) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        if mpcc >= profile.pipes() {
            return Err(Error::Invalid);
        }
        Ok(Self(Block {
            io: Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                base: profile.bank(
                    gpu,
                    3, // linux-lit: 3=mmMPCC0_MPCC_TOP_SEL_BASE_IDX
                    (MPC_OUT_MUX + u64::from(profile.pipes() - 1) * MPC_OUT_STRIDE) as u32,
                )?,
            },
            authority,
            instance: mpcc,
            profile,
        }))
    }
    pub fn mux_plane(&mut self, dpp: u8, opp: u8) -> Result<(), Error> {
        self.0.mpc_mux_plane(dpp, opp)
    }
    /// Park the combiner so neither the DPP nor the OPP is still routed.
    pub fn release(&mut self, opp: u8) -> Result<(), Error> {
        self.0.mpc_release(opp)
    }
}

/// One owned output pixel processor. Its pattern generator is what blanks and
/// unblanks the stream.
#[derive(Debug)]
pub struct Opp {
    block: Block<Mmio>,
    blanked: bool,
}
impl Opp {
    /// # Safety
    /// Caller exclusively owns this OPP instance for the object's lifetime and
    /// holds matching PCI authority and a permanent register mapping.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        instance: u8,
    ) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        if instance >= profile.pipes() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            block: Block {
                io: Mmio {
                    regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                    base: profile.bank(
                        gpu,
                        2, // linux-lit: 2=mmOPP_PIPE0_OPP_PIPE_CONTROL_BASE_IDX
                        // linux-ctx: reset
                        (OPP_PIPE_CONTROL + u64::from(profile.pipes() - 1) * OPP_STRIDE) as u32,
                    )?,
                },
                authority,
                instance,
                profile,
            },
            blanked: true,
        })
    }
    pub fn blanked(&self) -> bool {
        self.blanked
    }
    pub fn program(&mut self, encoding: Encoding, width: u32, height: u32) -> Result<(), Error> {
        self.block.opp_program(encoding, width, height)
    }
    /// Blank the stream by painting the pattern generator black over the whole
    /// active area, or unblank by disabling it so real pixels pass through.
    pub fn set_blank(&mut self, blank: bool) -> Result<(), Error> {
        self.block.opp_set_blank(blank)?;
        self.blanked = blank;
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn_plane_tests.rs"]
mod tests;
