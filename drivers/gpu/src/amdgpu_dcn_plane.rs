//! DCN 3.1.4 plane path: the display pipe processor, the multiple-pipe/plane
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
    amdgpu::AmdGpu, amdgpu_dcn_clk::Error, amdgpu_discovery as discovery, amdgpu_dml::Format,
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

// DPP block (base index 2), stride 0x16b.
/// The DCN versions these offsets describe. The DPP, DSCL, FMT, DPG and OPP
/// ids below are identical on DCN 3.5, but the MPC bank is reorganised:
/// `MPC_OUT_MUX` moves 0x0580→0x03d8 and the per-MPCC stride goes 0x20→0x15
/// (`regMPCC1_MPCC_TOP_SEL` 0x0020 against 0x0015). So this is not one entry
/// short of portable — another generation needs its own MPC ids and stride,
/// selected per version the way `amdgpu_platform::SURFACE_WINDOWS` does it.
const DCN_VERSIONS: &[(u8, u8, u8)] = &[(3, 1, 4)];

const DPP_CONTROL: u64 = 0x0cc5;
const CNVC_SURFACE_PIXEL_FORMAT: u64 = 0x0ccf;
const SCL_MODE: u64 = 0x0cfb;
const RECOUT_START: u64 = 0x0d11;
const RECOUT_SIZE: u64 = 0x0d12;
const MPC_SIZE: u64 = 0x0d13;
const DPP_STRIDE: u64 = 0x16b;
// OPP block (base index 2): FMT stride 0x5a, shared by DPG and OPP_PIPE.
const FMT_CONTROL: u64 = 0x1840;
const FMT_BIT_DEPTH_CONTROL: u64 = 0x1841;
const DPG_CONTROL: u64 = 0x1854;
const DPG_DIMENSIONS: u64 = 0x1856;
const DPG_COLOUR_R_CR: u64 = 0x1857;
const DPG_COLOUR_G_Y: u64 = 0x1858;
const DPG_COLOUR_B_CB: u64 = 0x1859;
const OPP_PIPE_CONTROL: u64 = 0x188c;
const OPP_STRIDE: u64 = 0x5a;
// MPC block (base index 3): MPCC stride 0x20, output mux stride 4.
const MPCC_TOP_SEL: u64 = 0x0000;
const MPCC_BOT_SEL: u64 = 0x0001;
const MPCC_OPP_ID: u64 = 0x0002;
const MPCC_CONTROL: u64 = 0x0003;
const MPCC_STRIDE: u64 = 0x20;
const MPC_OUT_MUX: u64 = 0x0580;
const MPC_OUT_STRIDE: u64 = 4;

const DPP_LAST_REG: u32 = (MPC_SIZE + 3 * DPP_STRIDE) as u32;
const OPP_LAST_REG: u32 = (OPP_PIPE_CONTROL + 3 * OPP_STRIDE) as u32;
const MPC_LAST_REG: u32 = (MPC_OUT_MUX + 3 * MPC_OUT_STRIDE) as u32;
const INSTANCES: u8 = 4;

/// `DSCL_MODE_SCALING_444_BYPASS`: an unscaled RGB plane takes no scaler taps.
/// `DSCL_MODE_SCALING_444_BYPASS` from `enum dscl_mode_sel`
/// (`dcn10_dpp_dscl.c:79-87`).
const SCALER_BYPASS: u32 = 0;
/// `DSCL0_SCL_MODE__DSCL_MODE_MASK` — **three** bits, not two. The enum runs to
/// `DSCL_MODE_DSCL_BYPASS` = 6, so bit 2 is live.
///
/// LINUX-GAP: this was masked 0x3. On a handoff from firmware that left the
/// scaler in mode 4, 5 or 6, clearing only the low two bits would have left
/// mode 4 (`SCALING_420_LUMA_BYPASS`) behind instead of reaching bypass.
const DSCL_MODE: u32 = 0x0000_0007;
/// `MPCC_TOP_SEL`/`MPCC_BOT_SEL` park with all ones.
const MPCC_UNSET: u32 = 0xf;

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
const MPCC_MODE: u32 = 0x0000_0003;
const MPCC_ALPHA_BLND_MODE: u32 = 0x0000_0030;
const MPCC_ALPHA_MULTIPLIED_MODE: u32 = 0x0000_0040;
const MPCC_BLND_ACTIVE_OVERLAP_ONLY: u32 = 0x0000_0080;
const MPCC_BG_BPC: u32 = 0x0000_0700;
const MPCC_GLOBAL_ALPHA: u32 = 0x00FF_0000;

/// `MPCC_BLEND_MODE_TOP_LAYER_ONLY` from `enum mpcc_blend_mode`
/// (`inc/hw/mpc.h:70-75`): BYPASS 0, TOP_LAYER_PASSTHROUGH 1, TOP_LAYER_ONLY 2,
/// TOP_BOT_BLENDING 3.
///
/// LINUX-GAP: this register was written 0, `MPCC_BLEND_MODE_BYPASS`, under a
/// comment describing opaque passthrough. `mpc1_mux_plane` writes
/// `TOP_LAYER_ONLY` for exactly this case — no bottom layer — and Linux's MPC
/// never writes BYPASS anywhere. A bypassed MPCC does not put the DPP's pixels
/// on the OPP at all.
const MPCC_BLEND_MODE_TOP_LAYER_ONLY: u32 = 2;
/// `MPCC_ALPHA_BLEND_MODE_GLOBAL_ALPHA` (`inc/hw/mpc.h`), which
/// `dcn20_hwseq.c` selects for a plane with no per-pixel alpha, paired with
/// `global_alpha = 0xff`.
const MPCC_ALPHA_BLEND_MODE_GLOBAL_ALPHA: u32 = 2;
/// `blnd_cfg.global_alpha = 0xff` — fully opaque.
const MPCC_GLOBAL_ALPHA_OPAQUE: u32 = 0xff;
/// `blnd_cfg.background_color_bpc = 4` (`dcn20_hwseq.c:2985`).
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
const FMT_RGB_FIELDS: u32 = 0x0003_0000 | 0x000C_0000 | 0x0020_0000;
/// `TEST_PATTERN_MODE_HORIZONTALBARS` with both bar colours black, which is how
/// DCN2 onwards paints a blanked stream.
const DPG_MODE_SOLID: u32 = 4;
/// `TEST_PATTERN_COLOR_FORMAT_BPC_8`.
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
            Encoding::Rgb => 0,
        }
    }
}
/// `CNVC_SURFACE_PIXEL_FORMAT` uses the same codes as the hub pixel pipe.
fn cnvc_format(format: Format) -> u32 {
    match format {
        Format::Rgb16 => 3,
        Format::Rgb32 => 8,
        Format::Rgb64 => 26,
    }
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
        if width == 0 || height == 0 || width > 0x3fff || height > 0x3fff {
            return Err(Error::Invalid);
        }
        let reg = self.dpp(DPP_CONTROL);
        self.update(reg, 1 << 4, 1 << 4)?;
        let reg = self.dpp(CNVC_SURFACE_PIXEL_FORMAT);
        self.update(reg, 0x7f, cnvc_format(format))?;
        // Bypass the scaler outright rather than programming unity taps.
        let reg = self.dpp(SCL_MODE);
        self.update(reg, DSCL_MODE, SCALER_BYPASS)?;
        let reg = self.dpp(RECOUT_START);
        self.set(reg, 0)?;
        let reg = self.dpp(RECOUT_SIZE);
        self.set(reg, width | height << 16)?;
        let reg = self.dpp(MPC_SIZE);
        self.set(reg, width | height << 16)
    }
    /// `mpc1_mux_plane`: bind this MPCC to a DPP and an OPP and route the OPP's
    /// output mux to it. Opaque passthrough, no bottom layer.
    fn mpc_mux_plane(&mut self, dpp: u8, opp: u8) -> Result<(), Error> {
        if dpp >= INSTANCES || opp >= INSTANCES {
            return Err(Error::Invalid);
        }
        let reg = self.mpcc(MPCC_TOP_SEL);
        self.update(reg, 0xf, dpp as u32)?;
        // Nothing below this plane: a stale bottom select would blend against
        // another pipe's output.
        let reg = self.mpcc(MPCC_BOT_SEL);
        self.update(reg, 0xf, MPCC_UNSET)?;
        let reg = self.mpcc(MPCC_OPP_ID);
        self.update(reg, 0xf, opp as u32)?;
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
        self.update(reg, 0xf, instance)
    }
    fn mpc_release(&mut self, opp: u8) -> Result<(), Error> {
        if opp >= INSTANCES {
            return Err(Error::Invalid);
        }
        let reg = MPC_OUT_MUX + opp as u64 * MPC_OUT_STRIDE;
        self.update(reg, 0xf, MPCC_UNSET)?;
        for reg in [MPCC_TOP_SEL, MPCC_BOT_SEL, MPCC_OPP_ID] {
            let reg = self.mpcc(reg);
            self.update(reg, 0xf, MPCC_UNSET)?;
        }
        Ok(())
    }
    /// Program the output formatter. Truncation and dithering stay off, so the
    /// formatter passes the plane's depth through untouched.
    fn opp_program(&mut self, encoding: Encoding, width: u32, height: u32) -> Result<(), Error> {
        if width == 0 || height == 0 || width > 0x3fff || height > 0x3fff {
            return Err(Error::Invalid);
        }
        let reg = self.opp(OPP_PIPE_CONTROL);
        self.update(reg, 1, 1)?;
        let reg = self.opp(FMT_CONTROL);
        self.update(reg, FMT_RGB_FIELDS, encoding.code() << 16)?;
        // No truncation, no spatial dither, no frame randomisation.
        let reg = self.opp(FMT_BIT_DEPTH_CONTROL);
        self.set(reg, 0)?;
        // The pattern generator's active area must match the stream, or a
        // blanked stream would paint only part of the screen.
        let reg = self.opp(DPG_DIMENSIONS);
        self.set(reg, height | width << 16)
    }
    fn opp_set_blank(&mut self, blank: bool) -> Result<(), Error> {
        if blank {
            for colour in [DPG_COLOUR_R_CR, DPG_COLOUR_G_Y, DPG_COLOUR_B_CB] {
                let reg = self.opp(colour);
                self.set(reg, 0)?;
            }
            let reg = self.opp(DPG_CONTROL);
            self.set(reg, 1 | DPG_MODE_SOLID << 4 | DPG_BIT_DEPTH_8 << 12)
        } else {
            // Disabling the generator outright is how DCN2 onwards returns to
            // video, rather than selecting a passthrough pattern.
            let reg = self.opp(DPG_CONTROL);
            self.set(reg, 0)
        }
    }
}

fn bank(gpu: &AmdGpu, index: usize, last: u32) -> Result<u64, Error> {
    crate::amdgpu_psp_ring::bank(gpu, discovery::HW_ID_DCN, DCN_VERSIONS, index, last)
        .map_err(|_| Error::Unsupported)
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
        if instance >= INSTANCES {
            return Err(Error::Invalid);
        }
        Ok(Self(Block {
            io: Mmio {
                regs: gpu.regs,
                base: bank(gpu, 2, DPP_LAST_REG)?,
            },
            authority,
            instance,
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
        if mpcc >= INSTANCES {
            return Err(Error::Invalid);
        }
        Ok(Self(Block {
            io: Mmio {
                regs: gpu.regs,
                base: bank(gpu, 3, MPC_LAST_REG)?,
            },
            authority,
            instance: mpcc,
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
        if instance >= INSTANCES {
            return Err(Error::Invalid);
        }
        Ok(Self {
            block: Block {
                io: Mmio {
                    regs: gpu.regs,
                    base: bank(gpu, 2, OPP_LAST_REG)?,
                },
                authority,
                instance,
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
