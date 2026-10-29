//! The pixel-path half of an HDMI stream's output format on DCN3.0, for one
//! pipe (OTG, OPP/FMT/DPG and MPC output `n` = pipe `n`):
//!
//! - `dcn20_program_pipe`'s `opp1_set_dyn_expansion` (YCbCr601, the stream
//!   depth, HDMI) and `opp1_program_fmt` with
//!   `resource_build_bit_depth_reduction_params` (DITHER_OPTION_DEFAULT:
//!   SPATIAL8 at 8 bpc, SPATIAL10 at 10 bpc, none at 12 bpc) and
//!   `build_clamping_params` (CLAMPING_FULL_RANGE), plus
//!   `opp2_program_left_edge_extra_pixel` (0 for the OTG master);
//! - `optc1_program_timing` / `optc3_set_odm_bypass` for 4:2:0's two pixels
//!   per container: OPTC_DATA_FORMAT 2 and OTG_H_TIMING_DIV_MODE by 2;
//! - `dcn20_program_output_csc` → `mpc3_power_on_ogam_lut` and
//!   `mpc3_set_ocsc_default` (`output_csc_matrix` for sRGB, sRGB limited or
//!   YCbCr709, coefficient set A);
//! - `dcn20_blank_pixel_data`'s DPG black (`color_space_to_black_color`,
//!   `opp2_dpg_set_blank_color`).
//!
//! Offsets and masks are `dcn_3_0_0_offset.h` / `_sh_mask.h`: FMT, DPG, OTG
//! and ODM at DCN base index 2, MPC at base index 3. DCN3.0 has no DCCG
//! pixel-rate divider (`dccg3_funcs` has no `set_pixel_rate_div`): 4:2:0's
//! halved TMDS pixel clock is the SetPixelClock target, and MPC output rate
//! control stays disabled (`mpc3_set_out_rate_control`).
use super::{Depth, Error, Format};
use crate::amdgpu_hdr::{DcColorSpace as C, PixelEncoding as E};
use crate::{amdgpu::AmdGpu, amdgpu_dcn_profile::Profile};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// Base index 2. FMT/DPG stride 0x5a, OTG 0x80, ODM 0x10.
// linux-ctx: hdr=dcn seg=2
// linux: mmFMT0_FMT_DYNAMIC_EXP_CNTL
const FMT_DYNAMIC_EXP_CNTL: u64 = 0x183f;
// linux: mmFMT0_FMT_CONTROL
const FMT_CONTROL: u64 = 0x1840;
// linux: mmFMT0_FMT_BIT_DEPTH_CONTROL
const FMT_BIT_DEPTH_CONTROL: u64 = 0x1841;
// linux: mmFMT0_FMT_DITHER_RAND_R_SEED; mmFMT0_FMT_DITHER_RAND_G_SEED; mmFMT0_FMT_DITHER_RAND_B_SEED
const FMT_DITHER_RAND_SEEDS: [u64; 3] = [0x1842, 0x1843, 0x1844];
// linux: mmFMT0_FMT_CLAMP_CNTL
const FMT_CLAMP_CNTL: u64 = 0x1845;
// linux: mmFMT0_FMT_MAP420_MEMORY_CONTROL
const FMT_MAP420_MEMORY_CONTROL: u64 = 0x1847;
// linux: mmFMT0_FMT_422_CONTROL
const FMT_422_CONTROL: u64 = 0x1849;
// linux: mmOPPBUF0_OPPBUF_CONTROL; mmOPPBUF0_OPPBUF_3D_PARAMETERS_0
const OPPBUF_CONTROL: u64 = 0x1884;
const OPPBUF_3D_PARAMETERS_0: u64 = 0x1885;
/// `opp2_dpg_set_blank_color`'s order: B/Cb, G/Y, R/Cr.
// linux: mmDPG0_DPG_COLOUR_B_CB
const DPG_COLOUR_B_CB: u64 = 0x1859;
// linux: mmDPG0_DPG_COLOUR_G_Y
const DPG_COLOUR_G_Y: u64 = 0x1858;
// linux: mmDPG0_DPG_COLOUR_R_CR
const DPG_COLOUR_R_CR: u64 = 0x1857;
// linux: mmFMT1_FMT_CONTROL - mmFMT0_FMT_CONTROL
const FMT_STRIDE: u64 = 0x5a;
// linux: mmODM0_OPTC_DATA_FORMAT_CONTROL
const ODM_OPTC_DATA_FORMAT_CONTROL: u64 = 0x1acc;
// linux: mmODM1_OPTC_DATA_FORMAT_CONTROL - mmODM0_OPTC_DATA_FORMAT_CONTROL
const ODM_STRIDE: u64 = 0x10;
// linux: mmOTG0_OTG_H_TIMING_CNTL
const OTG_H_TIMING_CNTL: u64 = 0x1b2e;
// linux: mmOTG0_OTG_STEREO_CONTROL; mmOTG0_OTG_3D_STRUCTURE_CONTROL
const OTG_STEREO_CONTROL: u64 = 0x1b54;
const OTG_3D_STRUCTURE_CONTROL: u64 = 0x1b83;
// linux: mmOTG1_OTG_H_TIMING_CNTL - mmOTG0_OTG_H_TIMING_CNTL
const OTG_STRIDE: u64 = 0x80;
// linux-ctx: hdr=dcn seg=3
// Base index 3. MPCC stride 0x20, MPC output CSC stride 0xd.
// linux: mmMPCC0_MPCC_MEM_PWR_CTRL
const MPCC_MEM_PWR_CTRL: u64 = 0x000c;
// linux: mmMPCC1_MPCC_MEM_PWR_CTRL - mmMPCC0_MPCC_MEM_PWR_CTRL
const MPCC_STRIDE: u64 = 0x20;
// linux: mmMPC_OUT_CSC_COEF_FORMAT
const MPC_OUT_CSC_COEF_FORMAT: u64 = 0x0598;
// linux: mmMPC_OUT0_CSC_MODE
const MPC_OUT_CSC_MODE: u64 = 0x0599;
// linux: mmMPC_OUT0_CSC_C11_C12_A
const MPC_OUT_CSC_C11_C12_A: u64 = 0x059a;
// linux: mmMPC_OUT1_CSC_MODE - mmMPC_OUT0_CSC_MODE
const MPC_OUT_STRIDE: u64 = 0xd;
// linux-ctx: reset
// linux: mmOTG5_OTG_H_TIMING_CNTL
const LAST_2: u32 = (OTG_3D_STRUCTURE_CONTROL + 5 * OTG_STRIDE) as u32;
// linux: mmMPC_OUT5_CSC_C33_C34_A
const LAST_3: u32 = (MPC_OUT_CSC_C11_C12_A + 5 + 5 * MPC_OUT_STRIDE) as u32;

// linux: FMT0_FMT_DYNAMIC_EXP_CNTL__FMT_DYNAMIC_EXP_EN_MASK
const FMT_DYNAMIC_EXP_EN: u32 = 1 << 0;
// linux: FMT0_FMT_DYNAMIC_EXP_CNTL__FMT_DYNAMIC_EXP_MODE_MASK
const FMT_DYNAMIC_EXP_MODE: u32 = 1 << 4;
// linux: FMT0_FMT_CONTROL__FMT_SPATIAL_DITHER_FRAME_COUNTER_MAX_MASK
const FMT_SPATIAL_DITHER_FRAME_COUNTER_MAX: u32 = 0xf00;
// linux: FMT0_FMT_CONTROL__FMT_SPATIAL_DITHER_FRAME_COUNTER_BIT_SWAP_MASK
const FMT_SPATIAL_DITHER_FRAME_COUNTER_BIT_SWAP: u32 = 0x3000;
// linux: FMT0_FMT_CONTROL__FMT_PIXEL_ENCODING_MASK
const FMT_PIXEL_ENCODING: u32 = 0x3_0000;
// linux: FMT0_FMT_CONTROL__FMT_SUBSAMPLING_MODE_MASK
const FMT_SUBSAMPLING_MODE: u32 = 0xc_0000;
// linux: FMT0_FMT_CONTROL__FMT_CBCR_BIT_REDUCTION_BYPASS_MASK
const FMT_CBCR_BIT_REDUCTION_BYPASS: u32 = 0x20_0000;
// linux: FMT0_FMT_BIT_DEPTH_CONTROL__FMT_TRUNCATE_EN_MASK | FMT0_FMT_BIT_DEPTH_CONTROL__FMT_TRUNCATE_MODE_MASK | FMT0_FMT_BIT_DEPTH_CONTROL__FMT_TRUNCATE_DEPTH_MASK
const FMT_TRUNCATE: u32 = 0x1 | 0x2 | 0x30;
// linux: FMT0_FMT_BIT_DEPTH_CONTROL__FMT_SPATIAL_DITHER_EN_MASK
const FMT_SPATIAL_DITHER_EN: u32 = 1 << 8;
// linux: FMT0_FMT_BIT_DEPTH_CONTROL__FMT_SPATIAL_DITHER_MODE_MASK
const FMT_SPATIAL_DITHER_MODE: u32 = 0x600;
// linux: FMT0_FMT_BIT_DEPTH_CONTROL__FMT_SPATIAL_DITHER_DEPTH_MASK
const FMT_SPATIAL_DITHER_DEPTH: u32 = 0x1800;
// linux: FMT0_FMT_BIT_DEPTH_CONTROL__FMT_FRAME_RANDOM_ENABLE_MASK
const FMT_FRAME_RANDOM_ENABLE: u32 = 1 << 13;
// linux: FMT0_FMT_BIT_DEPTH_CONTROL__FMT_RGB_RANDOM_ENABLE_MASK
const FMT_RGB_RANDOM_ENABLE: u32 = 1 << 14;
// linux: FMT0_FMT_BIT_DEPTH_CONTROL__FMT_HIGHPASS_RANDOM_ENABLE_MASK
const FMT_HIGHPASS_RANDOM_ENABLE: u32 = 1 << 15;
// linux: FMT0_FMT_BIT_DEPTH_CONTROL__FMT_TEMPORAL_DITHER_EN_MASK
const FMT_TEMPORAL_DITHER_EN: u32 = 1 << 16;
// linux: FMT0_FMT_CLAMP_CNTL__FMT_CLAMP_DATA_EN_MASK
const FMT_CLAMP_DATA_EN: u32 = 1 << 0;
// linux: FMT0_FMT_CLAMP_CNTL__FMT_CLAMP_COLOR_FORMAT_MASK
const FMT_CLAMP_COLOR_FORMAT: u32 = 0x7_0000;
// linux: FMT0_FMT_MAP420_MEMORY_CONTROL__FMT_MAP420MEM_PWR_FORCE_MASK
const FMT_MAP420MEM_PWR_FORCE: u32 = 0x3;
// linux: FMT0_FMT_422_CONTROL__FMT_LEFT_EDGE_EXTRA_PIXEL_COUNT_MASK
const FMT_LEFT_EDGE_EXTRA_PIXEL_COUNT: u32 = 1 << 0;
// linux: ODM0_OPTC_DATA_FORMAT_CONTROL__OPTC_DATA_FORMAT_MASK
const OPTC_DATA_FORMAT: u32 = 0x3;
// linux: OTG0_OTG_H_TIMING_CNTL__OTG_H_TIMING_DIV_MODE_MASK
const OTG_H_TIMING_DIV_MODE: u32 = 0x3;
// linux: MPCC0_MPCC_MEM_PWR_CTRL__MPCC_OGAM_MEM_PWR_DIS_MASK
const MPCC_OGAM_MEM_PWR_DIS: u32 = 1 << 2;
// linux: MPCC0_MPCC_MEM_PWR_CTRL__MPCC_OGAM_MEM_PWR_STATE_MASK
const MPCC_OGAM_MEM_PWR_STATE: u32 = 0x300;
/// `MPC_OUTPUT_CSC_COEF_A`.
// linux: MPC_OUTPUT_CSC_COEF_A
const MPC_OCSC_MODE_COEF_A: u32 = 1;
/// `REG_WAIT(MPCC_MEM_PWR_CTRL, MPCC_OGAM_MEM_PWR_STATE, 0, 10, 10)`.
// linux: n/a (REG_WAIT max_try 10, literal in dcn30_mpc.c:mpc3_power_on_ogam_lut)
const MEM_PWR_POLLS: u32 = 10;
// linux: n/a (REG_WAIT delay 10 us, literal in dcn30_mpc.c:mpc3_power_on_ogam_lut)
const MEM_PWR_POLL_US: u64 = 10;

/// `output_csc_matrix` (`dc_hw_sequencer.c`): C11..C34 for
/// COLOR_SPACE_RGB_TYPE, RGB_LIMITED_TYPE and YCBCR709_TYPE.
const CSC_SRGB: [u16; 12] = [0x2000, 0, 0, 0, 0, 0x2000, 0, 0, 0, 0, 0x2000, 0];
const CSC_SRGB_LIMITED: [u16; 12] = [
    0x1b67, 0, 0, 0x201, 0, 0x1b67, 0, 0x201, 0, 0, 0x1b67, 0x201,
];
const CSC_YCBCR709: [u16; 12] = [
    0xe04, 0xf345, 0xfeb7, 0x1004, 0x5d3, 0x1399, 0x1fa, 0x201, 0xfcca, 0xf533, 0xe04, 0x1004,
];

const CSC_YCBCR601: [u16; 12] = [
    0xe04, 0xf444, 0xfdb9, 0x1004, 0x831, 0x1016, 0x320, 0x201, 0xfb45, 0xf6b7, 0xe04, 0x1004,
];
const CSC_YCBCR2020: [u16; 12] = [
    0x1000, 0xf149, 0xfeb7, 0x1004, 0x868, 0x15b2, 0x1e6, 0x201, 0xfb88, 0xf478, 0x1000, 0x1004,
];

/// `color_space_to_black_color`'s (R/Cr, G/Y, B/Cb), 10-bit.
fn black(format: Format) -> [u32; 3] {
    match format.colorspace {
        C::Ycbcr601 | C::Ycbcr709 | C::Ycbcr2020Limited => [0x1f4, 0x40, 0x1f4],
        C::SrgbLimited | C::Rgb2020Limited => [0x40, 0x40, 0x40],
        _ => [0, 0, 0],
    }
}
fn csc(format: Format) -> &'static [u16; 12] {
    match format.colorspace {
        C::Ycbcr601 => &CSC_YCBCR601,
        C::Ycbcr709 => &CSC_YCBCR709,
        C::Ycbcr2020Limited => &CSC_YCBCR2020,
        C::SrgbLimited | C::Rgb2020Limited => &CSC_SRGB_LIMITED,
        _ => &CSC_SRGB,
    }
}

/// Which DCN register bank an offset is relative to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Bank {
    Two,
    Three,
}
pub(crate) trait Io: Send {
    fn read(&mut self, bank: Bank, reg: u64) -> u32;
    fn write(&mut self, bank: Bank, reg: u64, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
    base2: u64,
    base3: u64,
}
impl Io for Mmio {
    fn read(&mut self, bank: Bank, reg: u64) -> u32 {
        let base = if bank == Bank::Two {
            self.base2
        } else {
            self.base3
        };
        // SAFETY: the constructor bounds both banks and retains the mapping.
        unsafe { self.regs.read32(base + reg * 4) }
    }
    fn write(&mut self, bank: Bank, reg: u64, value: u32) {
        let base = if bank == Bank::Two {
            self.base2
        } else {
            self.base3
        };
        // SAFETY: as for read; this owner holds the pipe's output stages.
        unsafe { self.regs.write32(base + reg * 4, value) };
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
    pipe: u8,
}
impl<I: Io> Engine<I> {
    pub(crate) fn new_with(io: I, authority: Cap<BusDeviceCap, Write>, pipe: u8) -> Self {
        Self {
            io,
            authority,
            pipe,
        }
    }
    fn at(&self, reg: u64, stride: u64) -> u64 {
        reg + u64::from(self.pipe) * stride
    }
    fn read(&mut self, bank: Bank, reg: u64) -> Result<u32, Error> {
        let io = &mut self.io;
        let value = self
            .authority
            .invoke(Op(|| io.read(bank, reg)))
            .map_err(|_| Error::Revoked)?;
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok(value)
    }
    fn write(&mut self, bank: Bank, reg: u64, value: u32) -> Result<(), Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| io.write(bank, reg, value)))
            .map_err(|_| Error::Revoked)
    }
    fn update(&mut self, bank: Bank, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read(bank, reg)?;
        self.write(bank, reg, (old & !mask) | (value & mask))
    }
    fn fmt(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        self.update(Bank::Two, self.at(reg, FMT_STRIDE), mask, value)
    }
    /// `opp1_set_dyn_expansion(COLOR_SPACE_YCBCR601, depth, HDMI)` (the OPP's
    /// `dyn_expansion` is never set, so AUTO), then `opp1_program_fmt`.
    pub(crate) fn program_fmt(&mut self, format: Format) -> Result<(), Error> {
        self.fmt(
            FMT_DYNAMIC_EXP_CNTL,
            FMT_DYNAMIC_EXP_EN | FMT_DYNAMIC_EXP_MODE,
            0,
        )?;
        let mode = if format.depth == Depth::Bpc8 {
            FMT_DYNAMIC_EXP_MODE
        } else {
            0
        };
        self.fmt(
            FMT_DYNAMIC_EXP_CNTL,
            FMT_DYNAMIC_EXP_EN | FMT_DYNAMIC_EXP_MODE,
            FMT_DYNAMIC_EXP_EN | mode,
        )?;
        if format.encoding.is_420() {
            self.fmt(FMT_MAP420_MEMORY_CONTROL, FMT_MAP420MEM_PWR_FORCE, 0)?;
        }
        // resource_build_bit_depth_reduction_params, DITHER_OPTION_DEFAULT:
        // SPATIAL8 / SPATIAL10 (spatial depth 1 / 2, high-pass random, RGB
        // random for RGB, no frame random) or DISABLE at 12 bpc; never a
        // truncation.
        let spatial = match format.depth {
            Depth::Bpc8 => Some(1),
            Depth::Bpc10 => Some(2),
            Depth::Bpc12 => None,
        };
        // opp1_set_truncation.
        self.fmt(FMT_BIT_DEPTH_CONTROL, FMT_TRUNCATE, 0)?;
        // opp1_set_spatial_dither: everything off, frame counter for
        // FRAME_RANDOM 0, zero seeds, then the dither itself.
        let dither = FMT_SPATIAL_DITHER_EN
            | FMT_SPATIAL_DITHER_MODE
            | FMT_SPATIAL_DITHER_DEPTH
            | FMT_HIGHPASS_RANDOM_ENABLE
            | FMT_FRAME_RANDOM_ENABLE
            | FMT_RGB_RANDOM_ENABLE;
        self.fmt(FMT_BIT_DEPTH_CONTROL, dither | FMT_TEMPORAL_DITHER_EN, 0)?;
        self.fmt(
            FMT_CONTROL,
            FMT_SPATIAL_DITHER_FRAME_COUNTER_MAX | FMT_SPATIAL_DITHER_FRAME_COUNTER_BIT_SWAP,
            0,
        )?;
        for seed in FMT_DITHER_RAND_SEEDS {
            self.write(Bank::Two, self.at(seed, FMT_STRIDE), 0)?;
        }
        let bits = match spatial {
            Some(depth) => {
                FMT_SPATIAL_DITHER_EN
// linux-lit: 11=FMT0_FMT_BIT_DEPTH_CONTROL__FMT_SPATIAL_DITHER_DEPTH__SHIFT
                    | depth << 11
                    | FMT_HIGHPASS_RANDOM_ENABLE
                    | if format.encoding == E::Rgb { FMT_RGB_RANDOM_ENABLE } else { 0 }
            }
            None => 0,
        };
        self.fmt(FMT_BIT_DEPTH_CONTROL, dither, bits)?;
        // opp1_set_clamping: off, then CLAMPING_FULL_RANGE.
        self.fmt(
            FMT_CLAMP_CNTL,
            FMT_CLAMP_DATA_EN | FMT_CLAMP_COLOR_FORMAT,
            0,
        )?;
        self.fmt(
            FMT_CLAMP_CNTL,
            FMT_CLAMP_DATA_EN | FMT_CLAMP_COLOR_FORMAT,
            FMT_CLAMP_DATA_EN,
        )?;
        // opp1_set_pixel_encoding.
        let encoding = match format.encoding {
            // linux-lit: 16=FMT0_FMT_CONTROL__FMT_PIXEL_ENCODING__SHIFT; 18=FMT0_FMT_CONTROL__FMT_SUBSAMPLING_MODE__SHIFT
            E::Ycbcr422 => 1 << 16 | 2 << 18,
            E::Ycbcr420 => 2 << 16 | 2 << 18 | FMT_CBCR_BIT_REDUCTION_BYPASS,
            E::Rgb | E::Ycbcr444 => 0,
        };
        self.fmt(
            FMT_CONTROL,
            FMT_PIXEL_ENCODING | FMT_SUBSAMPLING_MODE | FMT_CBCR_BIT_REDUCTION_BYPASS,
            encoding,
        )?;
        // opp2_program_left_edge_extra_pixel: the OTG master gets none.
        self.fmt(FMT_422_CONTROL, FMT_LEFT_EDGE_EXTRA_PIXEL_COUNT, 0)
    }
    /// The 4:2:0 half of `optc1_program_timing` / `optc3_set_odm_bypass`:
    /// OPTC_DATA_FORMAT (0 RGB, 2 4:2:0) and the horizontal divide-by-2.
    /// After the timing is programmed, before the OTG starts.
    pub(crate) fn program_otg(&mut self, format: Format) -> Result<(), Error> {
        // dcn10_setup_stereo -> optc1_disable_stereo. The admitted stream
        // is progressive 2D; retire firmware frame packing explicitly.
        self.write(Bank::Two, self.at(OTG_STEREO_CONTROL, OTG_STRIDE), 0)?;
        self.write(Bank::Two, self.at(OTG_3D_STRUCTURE_CONTROL, OTG_STRIDE), 0)?;
        // opp1_program_stereo(false): no stereosync override.
        self.fmt(FMT_CONTROL, 1, 0)?; // linux-lit: 1=FMT0_FMT_CONTROL__FMT_STEREOSYNC_OVERRIDE_MASK
        self.fmt(OPPBUF_CONTROL, 0x3fff, 0)?; // linux-lit: 0x3fff=OPPBUF0_OPPBUF_CONTROL__OPPBUF_ACTIVE_WIDTH_MASK
                                              // linux-lit: 0xfffff=OPPBUF0_OPPBUF_3D_PARAMETERS_0__OPPBUF_3D_VACT_SPACE1_SIZE_MASK | OPPBUF0_OPPBUF_3D_PARAMETERS_0__OPPBUF_3D_VACT_SPACE2_SIZE_MASK
        self.fmt(OPPBUF_3D_PARAMETERS_0, 0x000f_ffff, 0)?;
        let two = u32::from(format.encoding.is_420());
        self.update(
            Bank::Two,
            self.at(ODM_OPTC_DATA_FORMAT_CONTROL, ODM_STRIDE),
            OPTC_DATA_FORMAT,
            two << 1,
        )?;
        self.update(
            Bank::Two,
            self.at(OTG_H_TIMING_CNTL, OTG_STRIDE),
            OTG_H_TIMING_DIV_MODE,
            two,
        )
    }
    /// `dcn20_program_output_csc`: the MPCC's OGAM memory powered
    /// (`mpc3_power_on_ogam_lut`, whose REG_WAIT only logs a timeout), then
    /// `mpc3_set_ocsc_default` with coefficient set A.
    pub(crate) async fn program_ocsc(&mut self, format: Format) -> Result<(), Error> {
        let power = self.at(MPCC_MEM_PWR_CTRL, MPCC_STRIDE);
        self.update(
            Bank::Three,
            power,
            MPCC_OGAM_MEM_PWR_DIS,
            MPCC_OGAM_MEM_PWR_DIS,
        )?;
        let mut on = false;
        for _ in 0..MEM_PWR_POLLS {
            if self.read(Bank::Three, power)? & MPCC_OGAM_MEM_PWR_STATE == 0 {
                on = true;
                break;
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(MEM_PWR_POLL_US).as_instant())
                .await;
        }
        if !on {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 MPCC {} OGAM memory did not power on",
                self.pipe
            );
        }
        self.update(Bank::Three, MPC_OUT_CSC_COEF_FORMAT, 1 << self.pipe, 0)?;
        self.write(
            Bank::Three,
            self.at(MPC_OUT_CSC_MODE, MPC_OUT_STRIDE),
            MPC_OCSC_MODE_COEF_A,
        )?;
        let first = self.at(MPC_OUT_CSC_C11_C12_A, MPC_OUT_STRIDE);
        for (i, pair) in csc(format).chunks_exact(2).enumerate() {
            let value = u32::from(pair[0]) | u32::from(pair[1]) << 16;
            self.write(Bank::Three, first + i as u64, value)?;
        }
        Ok(())
    }
    /// `opp2_dpg_set_blank_color` with the stream's black: both pattern
    /// colours, 16-bit MSB-aligned. After every `Opp::set_blank(true)`.
    pub(crate) fn set_blank_color(&mut self, format: Format) -> Result<(), Error> {
        let [r, g, b] = black(format);
        for (reg, c) in [
            (DPG_COLOUR_B_CB, b),
            (DPG_COLOUR_G_Y, g),
            (DPG_COLOUR_R_CR, r),
        ] {
            // linux-lit: 16=DPG0_DPG_COLOUR_B_CB__DPG_COLOUR1_B_CB__SHIFT
            self.write(Bank::Two, self.at(reg, FMT_STRIDE), (c << 6) << 16 | c << 6)?;
        }
        Ok(())
    }
}

/// The output-format owner of one pipe.
#[derive(Debug)]
pub struct Formatter(Engine<Mmio>);
impl Formatter {
    /// # Safety
    /// Caller exclusively owns pipe `pipe`'s OTG, ODM, OPP/FMT/DPG, MPCC
    /// memory power and MPC output CSC for the object's lifetime, holds
    /// matching PCI authority and a permanent register mapping.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pipe: u8,
    ) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu).map_err(|_| Error::Unsupported)?;
        if !profile.is_dcn30() {
            return Err(Error::Unsupported);
        }
        if pipe >= profile.pipes() {
            return Err(Error::Invalid);
        }
        let bank = |index, last| {
            profile
                .bank(gpu, index, last)
                .map_err(|_| Error::Unsupported)
        };
        Ok(Self(Engine::new_with(
            Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                base2: bank(2, LAST_2)?, // linux-lit: 2=mmFMT0_FMT_CONTROL_BASE_IDX
                base3: bank(3, LAST_3)?, // linux-lit: 3=mmMPC_OUT0_CSC_MODE_BASE_IDX
            },
            authority,
            pipe,
        )))
    }
    pub fn program_fmt(&mut self, format: Format) -> Result<(), Error> {
        self.0.program_fmt(format)
    }
    pub fn program_otg(&mut self, format: Format) -> Result<(), Error> {
        self.0.program_otg(format)
    }
    pub async fn program_ocsc(&mut self, format: Format) -> Result<(), Error> {
        self.0.program_ocsc(format).await
    }
    pub fn set_blank_color(&mut self, format: Format) -> Result<(), Error> {
        self.0.set_blank_color(format)
    }
}
