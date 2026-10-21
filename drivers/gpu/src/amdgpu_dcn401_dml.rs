//! Native DCN4.0.1 scanout admission for up to four pipes: the DML21 mode-support and
//! mode-programming path that Linux runs for Navi48 (`dml2_core_dcn4_calcs.c`,
//! `dml2_dpmm_dcn4.c`, `dml2_mcg_dcn4.c`, `dml2_pmo_dcn4_fams2.c` stutter
//! reservation), reduced to the one configuration the native scanout path
//! implements and evaluated in fixed point.
//!
//! The admitted shape is up to four streams with progressive fixed timing,
//! each with up to four planes in all ([`Plane`]): packed RGB of 2, 4 or 8
//! bytes per pixel (DML's `dml2_444_16`, `dml2_444_32`, `dml2_444_64`) or
//! 4:2:0 video (`dml2_420_8` NV12, `dml2_420_10` P010, luma and chroma
//! surfaces), linear or in a GFX12 2D swizzle (256B, 4KB, 64KB, 256KB),
//! optionally with GFX12 DCC (no metadata plane: the mcache's DRAM overhead
//! and placement), scaled as SPL scales it and scanned horizontally or (a
//! tiled surface rotated 90/270) vertically, in physical VRAM:
//! GPUVM/HostVM, MALL/SubVP, cursor, tdlut, dynamic metadata, writeback and
//! immediate flip are all off; a 4:4:4 DP stream may use DSC. One tiled RGB
//! plane alone on one pipe requests unbounded.
//!
//! ODM is DML's `dml2_odm_mode_auto` with dynamic ODM off (DecideODMMode):
//! a stream takes two, three or four pipes (DPP + OPP each, one DSC each)
//! when its pixel clock exceeds that many less one pipes' downspread-limited
//! DISPCLK maximum, its DSC line is wider than 5760 pixels per DSC or has
//! more than four slices per DSC (three pipes only for twelve slices), or
//! its 4:2:0 line is wider than 4096 pixels per pipe. Each pipe then fetches
//! its segment of the line at its share of the pixel clock;
//! ValidateODMMode's split (3:1 and 4:1 lines divide by four, 3:1 may be
//! uneven without DSC), slice and width limits apply, and a configuration
//! needing more than four pipes in all is rejected. A multi-pipe [`Plan`]
//! carries every pipe's values: they differ only in the DLG blank end.
//!
//! MPC combine follows DML's auto `mpcc_combine_factor` (DC's default): a
//! plane in ODM bypass whose single DPP would need more than the DPPCLK
//! maximum or cannot hold its viewport's swath takes two DPPs, each
//! fetching half the viewport (DCN4's `mpc_combine_limit` is two), for
//! every surface: linear or GFX12-tiled, RGB or 4:2:0 (each DPP half the
//! luma and chroma swath), with or without DCC, scanned horizontally or
//! vertically. A DCC plane whose mcaches its pipes cannot place is split
//! over two DPPs by the mcache phase whatever the factor
//! (pmo_dcn4_fams2_optimize_dcc_mcache), and refused on an ODM stream.
//!
//! The default 320-KiB DET from the staged requestor is a fixed input for
//! every pipe rather than DML's own allocation (four pipes fit the 1280-KiB
//! DET pool exactly). Anything else is rejected, not approximated.
//!
//! Policy mirrors the native clock owner: memory clock switching is disabled
//! for the whole scanout, so DML's UCLK pstate strategies are never searched
//! (the uclk watermark is still computed, never left at zero). Linux's stutter
//! reservation is kept: when the nominal blank is long enough, 54 us of it are
//! budgeted for self-refresh entry and exit if the mode still passes with them.
//!
//! The SoC bounding box is `dml2_socbb_dcn401` with `dcn4_variant_a` QoS and
//! `dml2_dcn401_max_ip_caps`; board clock ranges, the UMC channel count, the
//! DENTIST VCO and the DCHUB reference clock are inputs ([`Soc`]). This is a
//! calculation only: nothing here touches hardware, and a [`Plan`] is not
//! bound to any owner until a caller binds it.
use crate::amdgpu_dcn401_otg::GlobalSync;
use crate::amdgpu_dml::{Fx, Timing};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Inputs that cannot describe a real mode or board.
    Invalid,
    /// A shape outside the admitted configuration, including a stream its
    /// ODM split cannot divide as ValidateODMMode requires.
    Unsupported,
    /// The clock tables cannot supply DML's fabric/DCF state for this UCLK,
    /// or the configuration's SDP bandwidth would make DPMM raise DCFCLK or
    /// FCLK above that state, which this port does not plan at.
    ClockState,
    /// The pixel rate needs more DISPCLK/DPPCLK than the board provides.
    PixelClock,
    /// The swath or pitch does not fit the line/detile buffers.
    Buffer,
    /// Outstanding requests or ROB cannot cover the memory latency.
    Latency,
    /// No prefetch schedule fits the vertical blank.
    Prefetch,
    /// The DET cannot hide urgent latency.
    UrgentLatencyHiding,
    /// Average or urgent return bandwidth is exceeded.
    Bandwidth,
    /// Active latency hiding cannot cover a GDDR6 temperature-read blackout.
    TempRead,
    /// A DLG/TTU value exceeds the range DML asserts for its register field.
    Register,
    /// The streams need more than the four DPP/OPP pipes DCN4.0.1 has
    /// (an ODM stream takes one per segment, an MPC-combined plane two).
    Pipes,
}

/// Board and SoC state the calculation depends on. Every field must come
/// from the installed card, not from a Linux sample bounding box.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Soc {
    /// DALSMC `GetNumUmcChannels`; each channel is 16 bits wide.
    pub umc_channels: u32,
    /// The pinned memory clock (highest UCLK DPM level).
    pub uclk_khz: u32,
    /// Lowest and highest FCLK DPM levels.
    pub fclk_khz: [u32; 2],
    /// Lowest and highest DCFCLK DPM levels.
    pub dcfclk_khz: [u32; 2],
    /// Lowest SOCCLK DPM level.
    pub socclk_khz: u32,
    pub dispclk_max_khz: u32,
    pub dppclk_max_khz: u32,
    /// DENTIST VCO, from which DISPCLK/DPPREFCLK dividers are derived.
    pub dentist_vco_khz: u32,
    /// DCHUB global-timer reference: every DLG/TTU/watermark refcyc unit.
    pub dchub_refclk_khz: u32,
}

/// One unscaled full-frame linear RGB surface on one timing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode {
    pub timing: Timing,
    /// Surface pitch in pixels.
    pub pitch: u32,
    /// Bytes per pixel of the single packed RGB plane: 2 (`dml2_444_16`,
    /// RGB565), 4 (`dml2_444_32`, 8888 and 2101010) or 8 (`dml2_444_64`,
    /// FP16). Every other value is `Error::Invalid`.
    pub bytes_per_pixel: u32,
    /// The stream leaves as YCbCr 4:2:0 (HDMI): two pixels per OTG
    /// container, which adds a line of delay after the scaler.
    pub ycbcr420: bool,
    /// Display Stream Compression of a 4:4:4 DP output, as DC passes it
    /// (timing.dsc: enabled with the slice count and compressed bpp).
    pub dsc: Option<Dsc>,
    /// The stream's planes, bottom (the primary) first, as
    /// populate_dml21_plane_config_from_plane_state describes them. An
    /// empty `planes[0]` is the unscaled full-frame primary of `pitch` and
    /// `bytes_per_pixel`; the overlays follow from `planes[1]` up to the
    /// first `None` (`Mode::plane_list`).
    pub planes: [Option<Plane>; MAX_PLANES],
}

/// Planes (DPP pipes before ODM) every admitted configuration shares.
pub const MAX_PLANES: usize = 4;

/// One plane of a stream as DC passes DML21 a plane state after SPL
/// (populate_dml21_surface_config_from_plane_state,
/// populate_dml21_plane_config_from_plane_state): its surface, SPL's
/// whole-plane viewport (DC hands DML the plane's scaler data as if no ODM
/// split it), the scale ratios and taps, the GFX12 swizzle and DCC, and a
/// 4:2:0 source's chroma plane. Packed (surfaces are at most 16383 pixels,
/// taps at most 8): plans carry every stream's planes and are copied often.
/// `Default` is an empty linear RGB plane, for `..Plane::default()`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Plane {
    pub surface_width: u16,
    pub surface_height: u16,
    /// Surface (luma) pitch in pixels.
    pub pitch: u16,
    pub viewport_width: u16,
    pub viewport_height: u16,
    /// An RGB source's 2, 4 or 8 (`dml2_444_16`, `dml2_444_32`,
    /// `dml2_444_64`); a 4:2:0 source's luma bytes (1 for NV12, 2 for P010).
    pub bytes_per_pixel: u8,
    pub h_taps: u8,
    pub v_taps: u8,
    /// Input over output in units of 2^-19 (SPL's U3.19 ratios, which DC
    /// converts to the doubles DML takes exactly); `Plane::UNITY` is 1:1.
    pub h_ratio: u32,
    pub v_ratio: u32,
    /// The DML source format class.
    pub source: Source,
    /// The surface's GFX12 swizzle (`gfx_addr3_to_dml2_swizzle_mode`).
    pub swizzle: Swizzle,
    /// `surface.dcc.enable`: GFX12 DCC (no metadata plane; DCC rate 2.0).
    pub dcc: bool,
    /// The plane is rotated 90 or 270 degrees: DML scans the surface
    /// vertically (`dml_is_vertical_rotation`).
    pub vertical_scan: bool,
    /// A 4:2:0 source's chroma plane (`surface.plane1` and the scaler's
    /// plane1 values); `None` for RGB, whose chroma values are its luma ones.
    pub chroma: Option<Chroma>,
}

/// `enum dml2_source_format_class` for the formats DC maps native planes
/// to: packed RGB (by `Plane::bytes_per_pixel`), `dml2_420_8` (NV12) and
/// `dml2_420_10` (P010).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Source {
    #[default]
    Rgb,
    Yuv420_8,
    Yuv420_10,
}

/// The GFX12 swizzles DC maps onto `dml2_swizzle_mode`: `dml2_sw_linear`,
/// `dml2_sw_256b_2d`, `dml2_sw_4kb_2d`, `dml2_sw_64kb_2d`,
/// `dml2_sw_256kb_2d` (DC_ADDR3_SW_LINEAR..DC_ADDR3_SW_256KB_2D).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Swizzle {
    #[default]
    Linear,
    S256B2D,
    S4K2D,
    S64K2D,
    S256K2D,
}

impl Swizzle {
    /// dml_get_tile_block_size_bytes.
    pub const fn block_bytes(self) -> u32 {
        match self {
            Self::Linear | Self::S256B2D => 256,
            Self::S4K2D => 4096,
            Self::S64K2D => 65536,
            Self::S256K2D => 262_144,
        }
    }
    /// CalculateBytePerPixelAndBlockSizes' macro tile to 256-byte block
    /// scale (256B_2D keeps the initial 1).
    const fn macro_tile_scale(self) -> u32 {
        match self {
            Self::Linear | Self::S256B2D => 1,
            Self::S4K2D => 4,
            Self::S64K2D => 16,
            Self::S256K2D => 32,
        }
    }
}

/// A 4:2:0 plane's chroma surface (`surface.plane1`: amdgpu_dm's half-size
/// chroma surface and pitches[1] in chroma pixels) and SPL's chroma
/// viewport, ratios and taps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Chroma {
    pub surface_width: u16,
    pub surface_height: u16,
    /// Chroma pitch in chroma pixels.
    pub pitch: u16,
    pub viewport_width: u16,
    pub viewport_height: u16,
    pub h_ratio: u32,
    pub v_ratio: u32,
    pub h_taps: u8,
    pub v_taps: u8,
}

impl Plane {
    pub const UNITY: u32 = 1 << 19;
    /// A pixel extent as a plane field, saturated (validation refuses it).
    pub fn extent(v: u32) -> u16 {
        u16::try_from(v).unwrap_or(u16::MAX)
    }
    /// A byte or tap count as a plane field, saturated likewise.
    pub fn count(v: u32) -> u8 {
        u8::try_from(v).unwrap_or(u8::MAX)
    }
    /// The unscaled full-frame plane of `timing` (a field that does not
    /// fit saturates, which validation then refuses).
    pub fn full(timing: &Timing, pitch: u32, bytes_per_pixel: u32) -> Self {
        Self {
            surface_width: Self::extent(timing.h_active),
            surface_height: Self::extent(timing.v_active),
            pitch: Self::extent(pitch),
            bytes_per_pixel: Self::count(bytes_per_pixel),
            viewport_width: Self::extent(timing.h_active),
            viewport_height: Self::extent(timing.v_active),
            h_ratio: Self::UNITY,
            v_ratio: Self::UNITY,
            h_taps: 1,
            v_taps: 1,
            ..Self::default()
        }
    }
    /// scaler_info.enabled as dml21_translation_helper sets it with SPL: a
    /// ratio other than 1 (luma or chroma), or more than one tap.
    pub fn scaler_enabled(&self) -> bool {
        let c = self.chroma_values();
        self.h_ratio != Self::UNITY
            || self.v_ratio != Self::UNITY
            || self.h_taps > 1
            || self.v_taps > 1
            || c.h_ratio != Self::UNITY
            || c.v_ratio != Self::UNITY
            || c.h_taps > 1
            || c.v_taps > 1
    }
    /// The plane1 values DML takes: the chroma plane's, or an RGB plane's
    /// own luma values.
    pub fn chroma_values(&self) -> Chroma {
        self.chroma.unwrap_or(Chroma {
            surface_width: self.surface_width,
            surface_height: self.surface_height,
            pitch: self.pitch,
            viewport_width: self.viewport_width,
            viewport_height: self.viewport_height,
            h_ratio: self.h_ratio,
            v_ratio: self.v_ratio,
            h_taps: self.h_taps,
            v_taps: self.v_taps,
        })
    }
    /// A two-plane (4:2:0) source (`dml_is_420`).
    pub fn is_420(&self) -> bool {
        self.source != Source::Rgb
    }
}

impl Mode {
    /// One unscaled full-frame plane of `pitch` pixels on `timing`.
    pub fn new(timing: Timing, pitch: u32, bytes_per_pixel: u32) -> Self {
        Self {
            timing,
            pitch,
            bytes_per_pixel,
            ycbcr420: false,
            dsc: None,
            planes: [None; MAX_PLANES],
        }
    }
    /// The planes DML sees, in order: the primary (`planes[0]`, or the
    /// whole unscaled surface of `pitch` and `bytes_per_pixel` when none),
    /// then the overlays up to the first empty slot.
    pub fn plane_list(&self) -> impl Iterator<Item = Plane> + '_ {
        let primary = self.planes[0]
            .unwrap_or_else(|| Plane::full(&self.timing, self.pitch, self.bytes_per_pixel));
        core::iter::once(primary).chain(self.planes[1..].iter().map_while(|p| *p))
    }
}

/// One stream's DSC as DML21 takes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dsc {
    /// Horizontal slices (dsc_cfg.num_slices_h).
    pub slices: u32,
    /// Compressed bits per pixel in 1/16 bpp.
    pub bpp_x16: u32,
}

/// dml2_core_dcn4.c's ip caps: pixels per line one DSC takes, the DSC input
/// depth DML assumes, and DML_MAX_NUM_OF_SLICES_PER_DSC.
const MAX_PIXELS_PER_DSC: u32 = 5760;
const DSC_INPUT_BPC: u32 = 12;
const MAX_SLICES_PER_DSC: u32 = 4;
/// dcn4_soc_bb.h's DSCCLK table; DC never overrides it for DCN401.
const MAX_DSCCLK_KHZ: u32 = 666_667;

/// DML's math_round: floor(x + 0.5) through an int.
fn round_f64(v: f64) -> f64 {
    (v + 0.5) as i32 as f64
}
/// DML's math_ceil2(x, 1): (int)(x + 0.99999).
fn ceil_f64(v: f64) -> f64 {
    (v + 0.99999) as i32 as f64
}

/// dscceComputeDelay for a 4:4:4 (dml2_444) DP output: the DSC encoder's
/// bit-stream construction delay in pixels.
fn dscce_delay(bpc: u32, bpp: f64, slice_width: u32, slices: u32) -> u32 {
    let mut ixd = round_f64(8192.0 / 2.0 / bpp / 1.0) as u32;
    // dml2_444 counts slice width in pixel pairs, as Linux does.
    let swm = slice_width / 2;
    let padding = if swm % 3 != 0 {
        (3 - swm % 3) * (ixd / swm)
    } else {
        0
    };
    if 3.0 * bpp >= f64::from(ixd.div_ceil(3)) * 3.0 && (ixd + padding) % 3 == 1 {
        ixd += 1;
    }
    let ssm_priming = match bpc {
        8 => 83,
        10 => 91,
        12 => 115,
        14 => 123,
        _ => 128,
    };
    let groups = swm.div_ceil(3);
    let padded = 3 * groups - swm;
    let lines_ixd = ixd / swm;
    let groups_ixd = (ixd + padded * lines_ixd).div_ceil(3) + ssm_priming;
    let lines = groups_ixd.div_ceil(groups);
    let additional = u32::from((ixd - lines_ixd * swm) % 3 == 0);
    let group_delay = lines * groups * (slices - 1) + groups_ixd + additional;
    // Six cycles per group for dml2_444; SSM and OBSM pipeline delays.
    (group_delay - 1) * 6 + 3 + 3
}

/// dscComputeDelay for 4:4:4: the DSC wrapper's fixed delay.
const DSC_WRAPPER_DELAY: u32 = 2 + 16 * 3 + 3 + (1 + 4 * 3) + (3 + 3) + (3 + 3 * 3) + 1;

/// DSCDelayRequirement with one DSC per ODM pipe, in pixels: each of the
/// `odm` DSCs encodes its share of the slices, and their delays add.
fn dsc_delay(t: &Timing, dsc: Dsc, odm: u32) -> u32 {
    let bpp = f64::from(dsc.bpp_x16) / 16.0;
    let slice_width = ceil_f64(f64::from(t.h_active) / f64::from(dsc.slices)) as u32;
    let core =
        odm * (dscce_delay(DSC_INPUT_BPC, bpp, slice_width, dsc.slices / odm) + DSC_WRAPPER_DELAY);
    let blank = f64::from(t.h_total - t.h_active);
    let v = (f64::from(core) + blank * ceil_f64(f64::from(core) / f64::from(t.h_active))) as u32;
    let pclk = f64::from(t.pixel_clock_khz) / 1000.0;
    (f64::from(v) * pclk / pclk) as u32
}

/// DecideODMMode for `dml2_odm_mode_auto` (dynamic ODM off): the fewest
/// pipes whose DISPCLK (CalculateRequiredDispclk: the pixel clock over the
/// pipes, at least half of it for an HDMI TMDS 4:2:0 output) fits
/// `dispclk_ss_khz`, else four; at least as many as a DSC line needs at
/// 5760 pixels per DSC or a 4:2:0 line at 4096 pixels per formatter; with
/// DSC, two for more than four slices, three for more than eight, and four
/// for a three-pipe split whose slices are not twelve.
fn decide_odm(mode: &Mode, dispclk_ss_khz: u64) -> u32 {
    let t = &mode.timing;
    let pclk = u64::from(t.pixel_clock_khz);
    let fits = |pipes: u32| pclk <= u64::from(disp_divider(pipes, mode.ycbcr420)) * dispclk_ss_khz;
    let span = |limit: u32| t.h_active.div_ceil(limit).clamp(1, 4);
    let mut odm = (1..=3).find(|&n| fits(n)).unwrap_or(4);
    if mode.dsc.is_some() {
        odm = odm.max(span(MAX_PIXELS_PER_DSC));
    }
    if mode.ycbcr420 {
        odm = odm.max(span(FMT_420_BUFFER_WIDTH));
    }
    if let Some(dsc) = mode.dsc {
        if odm == 1 && dsc.slices > MAX_SLICES_PER_DSC {
            odm = 2;
        }
        if odm == 2 && dsc.slices > 2 * MAX_SLICES_PER_DSC {
            odm = 3;
        }
        if odm == 3 && dsc.slices != 3 * MAX_SLICES_PER_DSC {
            odm = 4;
        }
    }
    odm
}

/// CalculateRequiredDispclk's divisor of the pixel clock for `odm` pipes:
/// the pipe count, but at most two for an HDMI TMDS 4:2:0 output, whose
/// DISPCLK is at least half the pixel clock (`TMDS420MinPixClock`).
fn disp_divider(odm: u32, ycbcr420: bool) -> u32 {
    if ycbcr420 {
        odm.min(2)
    } else {
        odm
    }
}

/// The pipes admission gives a DSC stream of `timing` with `slices`
/// horizontal slices on a board whose highest DISPCLK is
/// `dispclk_max_khz` (DecideODMMode less downspread, as `admit_all` runs
/// it): 1 to 4. DSC policy uses it to keep each segment within one DSC.
pub fn dsc_pipes(timing: &Timing, slices: u32, dispclk_max_khz: u32) -> u32 {
    let mode = Mode {
        timing: *timing,
        pitch: timing.h_active,
        bytes_per_pixel: 4,
        ycbcr420: false,
        dsc: Some(Dsc { slices, bpp_x16: 0 }),
        planes: [None; MAX_PLANES],
    };
    let ss = u64::from(dispclk_max_khz) * 10_000 / DOWNSPREAD_TENTHOUSANDTHS as u64;
    decide_odm(&mode, ss)
}

/// `dsc_pipes` when the native DSCs take the stream's shape: one DSC401
/// per pipe, each image at most 5184 pixels with at most four slices, the
/// slices split evenly between the pipes (twelve on three, as
/// ValidateODMMode requires). `None` otherwise.
pub fn dsc_shape(timing: &Timing, slices: u32, dispclk_max_khz: u32) -> Option<u32> {
    let pipes = dsc_pipes(timing, slices, dispclk_max_khz);
    (slices % pipes == 0
        && slices <= MAX_SLICES_PER_DSC * pipes
        && (pipes != 3 || slices == 3 * MAX_SLICES_PER_DSC)
        && timing.h_active <= DSC401_MAX_IMAGE_WIDTH * pipes)
        .then_some(pipes)
}
/// DSC401's `max_image_width`.
pub const DSC401_MAX_IMAGE_WIDTH: u32 = 5184;

/// Clocks the plan was computed for. DISPCLK, DPPREFCLK and the pipe's DPPCLK
/// are minimums the clock owner must meet; DCFCLK/FCLK/UCLK are DML's own
/// state for this UCLK, below the pinned floors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clocks {
    pub dispclk_khz: u32,
    pub dpprefclk_khz: u32,
    pub dppclk_khz: u32,
    pub deep_sleep_dcfclk_khz: u32,
    pub dcfclk_khz: u32,
    pub fclk_khz: u32,
    pub uclk_khz: u32,
    pub socclk_khz: u32,
}

/// Nonzero HUBP DLG fields. Every VM/PTE/meta/tdlut/flip/cursor field is zero
/// in the admitted shape.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dlg {
    pub refcyc_h_blank_end: u32,
    pub dlg_vblank_end: u32,
    pub min_dst_y_next_start: u32,
    pub refcyc_per_htotal: u32,
    pub refcyc_x_after_scaler: u32,
    pub dst_y_after_scaler: u32,
    pub dst_y_prefetch: u32,
    pub dst_y_per_vm_vblank: u32,
    pub dst_y_per_row_vblank: u32,
    pub ref_freq_to_pix_freq: u32,
    pub vratio_prefetch: u32,
    pub vratio_prefetch_c: u32,
    pub refcyc_per_line_delivery_pre_l: u32,
    pub refcyc_per_line_delivery_l: u32,
    /// A 4:2:0 plane's chroma line delivery (zero for RGB).
    pub refcyc_per_line_delivery_pre_c: u32,
    pub refcyc_per_line_delivery_c: u32,
    pub vready_after_vcount0: bool,
    pub dst_y_delta_drq_limit: u32,
    pub dmdata_dl_delta: u32,
}

/// Nonzero HUBP TTU fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ttu {
    pub qos_level_low_wm: u32,
    pub qos_level_high_wm: u32,
    pub min_ttu_vblank: u32,
    pub qos_level_flip: u32,
    pub refcyc_per_req_delivery_l: u32,
    pub refcyc_per_req_delivery_pre_l: u32,
    /// A 4:2:0 plane's chroma request delivery (zero for RGB).
    pub refcyc_per_req_delivery_c: u32,
    pub refcyc_per_req_delivery_pre_c: u32,
    pub qos_level_fixed_l: u32,
    pub qos_level_fixed_c: u32,
}

/// One surface's `struct dml2_display_plane_rq_regs` (DCHUBP_REQ_SIZE_CONFIG
/// or _C), as rq_dlg_get_rq_reg fills it: log2 sizes less their bias, the
/// swath height in log2 lines. With GPUVM off and no MRQ the group, meta
/// and PTE-row fields are zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RqPlane {
    pub chunk_size: u32,
    pub min_chunk_size: u32,
    pub meta_chunk_size: u32,
    pub min_meta_chunk_size: u32,
    pub dpte_group_size: u32,
    pub mpte_group_size: u32,
    pub swath_height: u32,
    pub pte_row_height_linear: u32,
}

/// `struct dml2_display_rq_regs` for every pipe of a plane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RqRegs {
    /// `rq_regs_l`.
    pub luma: RqPlane,
    /// `rq_regs_c`: Linux fills the chunk sizes even for an RGB plane.
    pub chroma: RqPlane,
    pub drq_expansion_mode: u32,
    pub prq_expansion_mode: u32,
    pub mrq_expansion_mode: u32,
    pub crq_expansion_mode: u32,
    /// The DET's chroma base in KiB (zero for RGB).
    pub plane1_base_address: u32,
    /// Unbounded requesting (one tiled RGB plane on one pipe).
    pub unbounded_request_enabled: bool,
}

/// DCHUBBUB watermark set, in DCHUB reference cycles (fractions in 1/1000).
/// Linux programs the same values into sets A and B.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Watermarks {
    pub urgent: u32,
    pub sr_enter: u32,
    pub sr_exit: u32,
    pub uclk_pstate: u32,
    pub fclk_pstate: u32,
    pub temp_read: u32,
    pub usr: u32,
    pub refcyc_per_trip_to_mem: u32,
    pub refcyc_per_meta_trip_to_mem: u32,
    pub frac_urg_bw_flip: u32,
    pub frac_urg_bw_nom: u32,
    pub frac_urg_bw_mall: u32,
}

/// DCHUBBUB arbiter values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Arbiter {
    pub max_req_outstanding: u32,
    pub min_req_outstanding: u32,
    pub sat_level_us: u32,
    pub compbuf_reserved_space_kbytes: u32,
    /// DML's minimum compressed buffer. The staged requestor keeps the rest of
    /// the CRB as compbuf; with DCC off neither size feeds a calculation.
    pub compbuf_segments: u32,
    pub sdpif_request_rate_limit: u32,
    pub dcfclk_deep_sleep_hysteresis: u32,
    pub pstate_stall_threshold: u32,
    pub hvm_max_qos_commit_threshold: u32,
    pub hvm_min_req_outstand_commit_threshold: u32,
    /// `allow_sdpif_rate_limit_when_cstate_req` (DML's hw_debug5).
    pub allow_sdpif_rate_limit_when_cstate_req: bool,
}

/// A reproducible programming plan for one mode on one board state.
///
/// With `pipes` of 2 to 4 (ODM 2:1, 3:1, 4:1) the stream's one OTG drives
/// that many OPPs, each fed by its own DPP/HUBP reading its segment of the
/// line. Every pipe runs at `clocks.dppclk_khz` with `det_bytes` of DET and
/// the same `ttu` and `dlg`, except that each further pipe's
/// `refcyc_h_blank_end` is its `odm_refcyc_h_blank_end` entry
/// ([`Plan::pipe_dlg`]); Linux DML21 programs no other per-pipe difference
/// (check.sh verifies every register of every further pipe against the
/// first). A plane in ODM bypass may still take two DPPs (MPC combine,
/// [`PlanePlan::dpps`]); both program identical values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub mode: Mode,
    pub soc: Soc,
    pub clocks: Clocks,
    pub sync: GlobalSync,
    /// The first (or only) pipe's DLG.
    pub dlg: Dlg,
    pub ttu: Ttu,
    pub watermarks: Watermarks,
    pub arbiter: Arbiter,
    /// DET of each of the stream's pipes.
    pub det_bytes: u32,
    /// ODM segments (OPPs, and DPPs of each plane) the stream takes: 1 in
    /// ODM bypass, 2 to 4 in ODM 2:1, 3:1 or 4:1 combine. DML's policy
    /// decides it ([`admit_all`]), not the caller.
    pub pipes: u8,
    /// Each further ODM pipe's `refcyc_h_blank_end` (pipes 1 to 3): the
    /// blank end moved by the segments before it. Zero past `pipes`.
    pub odm_refcyc_h_blank_end: [u32; 3],
    /// Vertical blank budgeted for self-refresh entry and exit, if any.
    pub stutter_reserved_us: u32,
    /// Every other mode admitted together with this one, in admission
    /// order (this plan's own, `mode`, belongs at `stream`; `joint_modes`
    /// lists them all). A plan is only valid in that configuration. Plans
    /// are copied often, so the record keeps no second copy of `mode`.
    pub streams: [Option<Mode>; MAX_STREAMS - 1],
    pub stream: u8,
    /// Each of the stream's planes (`Mode::plane_list` order): its own
    /// DPPCLK, DLG, TTU, DET and second ODM pipe's blank end. The fields
    /// above (`clocks.dppclk_khz`, `dlg`, `ttu`, `det_bytes`,
    /// `odm_refcyc_h_blank_end`) are the first plane's.
    pub planes: [Option<PlanePlan>; MAX_PLANES],
}

/// One plane's share of a stream's [`Plan`] (the plane is the plan's
/// `mode.plane_list()` entry): every one of its `dpps` pipes runs at
/// `dppclk_khz` with `det_bytes` and this DLG/TTU, each further ODM pipe
/// with its own blank end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanePlan {
    pub dppclk_khz: u32,
    pub dlg: Dlg,
    pub ttu: Ttu,
    pub det_bytes: u32,
    pub odm_refcyc_h_blank_end: [u32; 3],
    /// DML's NoOfDPP for the plane: its stream's `Plan::pipes` ODM
    /// segments, or 2 in ODM bypass when DML MPC-combines it (each DPP then
    /// scans half the plane's recout, blended in the segment's MPCC tree).
    pub dpps: u8,
    /// Every pipe's DCHUBP request configuration.
    pub rq: RqRegs,
    /// A DCC plane's mcache allocation; `None` without DCC.
    pub mcache: Option<McacheAllocation>,
}
impl PlanePlan {
    /// MPC slices of the plane: its DPPs in ODM bypass, else 1.
    pub fn mpc_slices(&self, odm_pipes: u8) -> u8 {
        if odm_pipes > 1 {
            1
        } else {
            self.dpps
        }
    }
}

/// A DCC plane's `dml2_mcache_surface_allocation` as DML21 leaves it in the
/// plane programming: per surface (luma, chroma) the mcache count, the
/// slice boundaries (the last one the surface width; an admitted plane has
/// at most three slices) and the global mcache ids
/// (dml2_top_mcache_assign_global_mcache_ids, in admission order; the entry
/// after the last wraps to the first), and whether chroma's last slice
/// shares luma's last mcache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct McacheAllocation {
    pub count: [u8; 2],
    pub offsets: [[u16; 3]; 2],
    pub ids: [[u8; 4]; 2],
    pub shared: bool,
}

/// One surface's `dml2_display_mcache_regs` (MCACHEID_REG_READ_1H/2H and
/// the split): the main and MALL-prefetch sets are equal without iMALL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McacheRegs {
    pub id_first: u32,
    pub id_second: u32,
    pub split_location: u32,
}

impl McacheRegs {
    /// reset_mcache_allocations: no mcache and no split.
    pub const UNASSIGNED: Self = Self {
        id_first: 0xf,
        id_second: 0xf,
        split_location: 0xffff,
    };
}

impl McacheAllocation {
    /// dml2_top_soc15_build_mcache_programming for one pipe whose luma
    /// viewport starts at `p0.0` and is `p0.1` wide (and chroma's `p1`, for
    /// a 4:2:0 plane): each surface's first mcache, and the second with the
    /// split before the next boundary when the viewport spans two. `None`
    /// when it spans more (calculate_first_second_splitting fails).
    pub fn pipe_regs(&self, p0: (u32, u32), p1: Option<(u32, u32)>) -> Option<[McacheRegs; 2]> {
        let mut regs = [McacheRegs::UNASSIGNED; 2];
        for (i, vp) in [Some(p0), p1].into_iter().enumerate() {
            let Some((start, width)) = vp else {
                continue;
            };
            let count = usize::from(self.count[i]);
            let offsets = &self.offsets[i][..count.min(3)];
            let (first, second) = first_second_splitting(
                offsets,
                i64::from(start),
                i64::from(start) + i64::from(width) - 1,
            )?;
            regs[i].id_first = u32::from(*self.ids[i].get(first)?);
            if let Some(second) = second {
                regs[i].id_second = u32::from(*self.ids[i].get(second)?);
                regs[i].split_location = u32::from(*self.offsets[i].get(first)?).wrapping_sub(1);
            }
        }
        Some(regs)
    }
}

/// calculate_first_second_splitting with no shift: the slice holding the
/// viewport's first pixel, and the next slice if its last pixel lies there.
fn first_second_splitting(
    boundaries: &[u16],
    start: i64,
    end: i64,
) -> Option<(usize, Option<usize>)> {
    let n = boundaries.len();
    if n <= 1 {
        return Some((0, None));
    }
    let mut left = 0;
    let mut range_start = 0i64;
    while left < n {
        let range_end = i64::from(boundaries[left]) - 1;
        if range_start <= start && start <= range_end {
            break;
        }
        range_start = range_end + 1;
        left += 1;
    }
    let mut range_end = 0xff_ffffi64;
    let mut right = n as i64 - 1;
    while right >= -1 {
        let range_start = if right >= 0 {
            i64::from(boundaries[right as usize])
        } else {
            0
        };
        if range_start <= end && end <= range_end {
            break;
        }
        range_end = range_start - 1;
        right -= 1;
    }
    let right = ((right + 1) as usize) % n;
    if right == left {
        Some((left, None))
    } else if right == (left + 1) % n {
        Some((left, Some(right)))
    } else {
        None
    }
}

/// Streams admitted together at most: one per pipe.
pub const MAX_STREAMS: usize = 4;
/// `max_num_dpp` / `max_num_opp`: pipes every admitted stream shares.
pub const MAX_PIPES: u32 = 4;
/// DCN4's `mpc_combine_limit` (dml2_pmo_dcn4_fams2): at most two DPPs per
/// MPC-combined plane.
const MPC_COMBINE_LIMIT: u32 = 2;

// ── dml2_socbb_dcn401 / dml_dcn4_variant_a_soc_qos_params ──────────────────
const CHANNEL_BYTES: u64 = 2;
const TRANSACTIONS_PER_CLOCK: u64 = 16;
const RETURN_BUS_BYTES: i64 = 64; // == fabric_datapath_to_dcn_data_return_bytes
const MAX_FCLK_FOR_UCLK_KHZ: u64 = 1_250_000;
const DOWNSPREAD_TENTHOUSANDTHS: i64 = 10_038; // dcn_downspread_percent 0.38
const MAX_OUTSTANDING_REQS: i64 = 512;
const MALL_PRESENT: bool = true; // mall_allocated_for_dcn_mbytes = 64
const DRAM_CLK_CHANGE_US: i64 = 400;
const SR_ENTER_PLUS_EXIT_US: i64 = 54;
const SR_EXIT_US: i64 = 41;
/// FAMS2 `max_allow_delay_us`, which Linux still programs as the stall limit.
const MAX_ALLOW_DELAY_US: i64 = 100_000;
/// `{dcfclk, fclk, dram}` derate percents.
const URGENT_ACTIVE: [i64; 3] = [100, 76, 22];
const URGENT_PREFETCH: [i64; 3] = [100, 83, 40];
const AVERAGE_ACTIVE: [i64; 3] = [75, 57, 17];
const AVERAGE_PREFETCH: [i64; 3] = [83, 62, 33];
// dcn4x QoS. The variant-A table has one UCLK entry, so every UCLK uses it.
const DF_QOS_RESPONSE_FCLK: i64 = 300;
const MAX_ROUND_TRIP_FCLK: i64 = 350;
const MALL_OVERHEAD_FCLK: i64 = 50;
const AVG_TRANSPORT_FCLK: i64 = 257;
const URGENT_RAMP_UCLK: i64 = 472;
const TRIP_TO_MEMORY_UCLK: i64 = 827;
const MAX_LATENCY_URGENT_UCLK: i64 = 72;
const AVG_LATENCY_URGENT_UCLK: i64 = 61;
const AVG_LATENCY_NON_URGENT_UCLK: i64 = 118;
const UMC_URGENT_RAMP_MARGIN: i64 = 50;
const UMC_MAX_MARGIN: i64 = 30;
const UMC_AVG_MARGIN: i64 = 20;
const FABRIC_MAX_MARGIN: i64 = 20;
const FABRIC_AVG_MARGIN: i64 = 10;
/// `core_dcn4_g6_temp_read_blackout_table` as (minimum UCLK kHz, us).
const G6_TEMP_READ: [(u32, i64); 8] = [
    (96_000, 23),
    (435_000, 10),
    (521_000, 10),
    (731_000, 8),
    (822_000, 8),
    (962_000, 5),
    (1_069_000, 5),
    (1_187_000, 5),
];

// ── core_dcn4_ip_caps_base patched with dml2_dcn401_max_ip_caps ────────────
const ROB_KBYTES: i64 = 192;
const CONFIG_RETURN_KBYTES: u32 = 1344;
const SEGMENT_KBYTES: u32 = 64;
const PIXEL_CHUNK_KBYTES: i64 = 8;
const MIN_PIXEL_CHUNK_BYTES: u32 = 1024;
const LINE_BUFFER_BITS: i64 = 1_171_920;
const MAX_LINE_BUFFER_LINES: i64 = 32;
const LB_BITS_PER_PIXEL: i64 = 57;
const MAX_LINEAR_SWATH: u32 = 15_360;
const DISPCLK_RAMP_MARGIN_PERCENT: i64 = 1;
/// dppclk_delay_subtotal + cnvc_formatter, then scl (scaler enabled) or
/// scl_lb_only (bypassed).
const DPP_DELAY_CYCLES: i64 = 47 + 28;
const DPP_DELAY_SCL: i64 = 50;
const DPP_DELAY_SCL_LB_ONLY: i64 = 16;
/// max_dchub_pscl_bw_pix_per_clk, max_pscl_lb_bw_pix_per_clk.
const MAX_DCHUB_PSCL_BW: i64 = 4;
const MAX_PSCL_LB_BW: i64 = 2;
/// max_hscl_ratio = max_vscl_ratio, max_hscl_taps = max_vscl_taps.
const MAX_SCL_RATIO: u32 = 6;
const MAX_SCL_TAPS: u32 = 8;
const DISPCLK_DELAY_CYCLES: i64 = 125;
const MAX_INTER_DCN_TILE_REPEATERS: i64 = 8;
const MAX_VSTARTUP: u32 = 1023;
const WORDS_PER_CHANNEL: u32 = 16;
const MAX_VRATIO_PRE: i64 = 8;
const MAX_VRATIO_PRE_OTO: i64 = 4;
const MAX_VRATIO_PRE_EQU: i64 = 6;
/// `__DML2_CALCS_DCFCLK_FACTOR__` 1.15.
const DCFCLK_FACTOR_HUNDREDTHS: i64 = 115;
/// `(83 / max_uclk + 75 / max_fclk) * min_dcfclk` return-latency terms.
const MIN_RETURN_UCLK_CYCLES: i64 = 83;
const MIN_RETURN_FCLK_CYCLES: i64 = 75;

// ── Native policy ──────────────────────────────────────────────────────────
/// The staged requestor's DCN4_01_DEFAULT_DET_SIZE, also DML's nominal DET.
pub const DET_KBYTES: u32 = 320;
/// The full request size (CalculateSwathAndDETConfiguration: 256 bytes
/// unless a halved tiled swath requests 64 or 128), and the extra-latency
/// default.
const REQUEST_BYTES: i64 = 256;
/// Upper bound for any clock input: 10 GHz.
const MAX_CLOCK_KHZ: u32 = 10_000_000;
/// `DML2_MAX_FMT_420_BUFFER_WIDTH`: widest 4:2:0 output line per OPP.
pub(crate) const FMT_420_BUFFER_WIDTH: u32 = 4096;
/// PMO only budgets stutter when the nominal blank is three times its cost.
const MIN_BLANK_STUTTER_FACTOR: i64 = 3;

fn fx(n: i64) -> Fx {
    Fx::int(n)
}
fn q(n: i64, d: i64) -> Fx {
    Fx::ratio(n, d)
}
fn mhz(khz: u64) -> Fx {
    q(khz as i64, 1000)
}
fn percent(p: i64) -> Fx {
    q(p, 100)
}
/// `1 + margin%`.
fn margin(p: i64) -> Fx {
    q(100 + p, 100)
}
/// `math_round`.
fn round(v: Fx) -> i64 {
    v.plus(q(1, 2)).floor()
}
/// `math_floor2(4 * v, 1) / 4` and its ceiling.
fn floor_quarter(v: Fx) -> Fx {
    q(fx(4).times(v).floor(), 4)
}
/// DML's math_ceil2(4 * v, 1) / 4: lib_float_math's (int)(x + 0.99999),
/// so a value within 1e-5 above a quarter line stays on it.
fn ceil_quarter(v: Fx) -> Fx {
    q(fx(4).times(v).plus(q(99_999, 100_000)).floor(), 4)
}
fn ceil_to(v: u64, m: u64) -> u64 {
    v.div_ceil(m) * m
}
fn reg(v: Fx) -> u32 {
    v.floor().clamp(0, u32::MAX as i64) as u32
}

/// Clocks one evaluation runs at, all in MHz (or MB/s).
#[derive(Clone, Copy)]
struct State {
    dcfclk: Fx,
    fclk: Fx,
    uclk: Fx,
    dram_bw: Fx,
}
#[derive(Clone, Copy)]
struct Available {
    /// `[sys_active, svp_prefetch]` x `[sdp, dram]`.
    urgent: [[Fx; 2]; 2],
    average: [[Fx; 2]; 2],
}
fn available(s: State) -> Available {
    let get = |d: [i64; 3]| {
        let sdp = fx(RETURN_BUS_BYTES)
            .times(s.dcfclk)
            .times(percent(d[0]))
            .min(s.fclk.times(fx(RETURN_BUS_BYTES)).times(percent(d[1])));
        [sdp, s.dram_bw.times(percent(d[2]))]
    };
    Available {
        urgent: [get(URGENT_ACTIVE), get(URGENT_PREFETCH)],
        average: [get(AVERAGE_ACTIVE), get(AVERAGE_PREFETCH)],
    }
}

/// Latencies that depend only on the fabric and memory clocks.
#[derive(Clone, Copy)]
struct Latency {
    urgent: Fx,
    trip: Fx,
    max_urgent: Fx,
    df_response: Fx,
    avg_urgent: Fx,
    avg_non_urgent: Fx,
    g6_temp_read: Fx,
}
fn latency(s: State, uclk_khz: u64) -> Latency {
    let f = |cycles: i64| fx(cycles).over(s.fclk);
    let u = |cycles: i64| fx(cycles).over(s.uclk);
    let round_trip = f(MAX_ROUND_TRIP_FCLK).times(margin(FABRIC_MAX_MARGIN));
    let urgent = f(DF_QOS_RESPONSE_FCLK + MALL_OVERHEAD_FCLK)
        .plus(round_trip)
        .plus(u(URGENT_RAMP_UCLK).times(margin(UMC_URGENT_RAMP_MARGIN)));
    let trip = f(MALL_OVERHEAD_FCLK)
        .plus(round_trip)
        .plus(u(TRIP_TO_MEMORY_UCLK).times(margin(UMC_MAX_MARGIN)));
    let avg = |cycles: i64| {
        u(cycles)
            .times(margin(UMC_AVG_MARGIN))
            .plus(f(AVG_TRANSPORT_FCLK))
            .times(margin(FABRIC_AVG_MARGIN))
    };
    let mut blackout = G6_TEMP_READ[0].1;
    for (min_khz, us) in G6_TEMP_READ {
        if uclk_khz < u64::from(min_khz) {
            break;
        }
        blackout = us;
    }
    Latency {
        urgent,
        trip: urgent.max(trip),
        max_urgent: u(MAX_LATENCY_URGENT_UCLK)
            .times(margin(UMC_MAX_MARGIN))
            .plus(f(MALL_OVERHEAD_FCLK))
            .plus(round_trip),
        df_response: f(DF_QOS_RESPONSE_FCLK),
        avg_urgent: avg(AVG_LATENCY_URGENT_UCLK),
        avg_non_urgent: avg(AVG_LATENCY_NON_URGENT_UCLK),
        g6_temp_read: fx(blackout),
    }
}

/// One DET surface of a plane (its luma, or a 4:2:0 plane's chroma), as
/// CalculateBytePerPixelAndBlockSizes, CalculateSwathWidth,
/// CalculateSwathAndDETConfiguration and CalculatePrefetchSourceLines
/// derive it.
#[derive(Clone, Copy)]
struct Surf {
    /// BytePerPixelY/C.
    bpp: u32,
    /// BytePerPixelInDETY/C times three (P010 stores 4/3 and 8/3 bytes).
    det_bpp3: u32,
    /// The request width along the swath: Read256BlockWidth scanning
    /// horizontally, Read256BlockHeight vertically.
    req_w: u32,
    /// SwathWidthSingleDPP and each pipe's SwathWidth, and the
    /// request-rounded swath_width_ub.
    swath_single: u32,
    swath: u32,
    swath_ub: u32,
    /// MaximumSwathHeight, then the SwathHeight the DET takes.
    max_height: u32,
    height: u32,
    /// DETBufferSizeY/C.
    det_bytes: u32,
    request_bytes: u32,
    /// full_swath_bytes and RoundedUpSwathSizeBytes.
    full_swath_bytes: u32,
    rounded_swath_bytes: u32,
    h_ratio: u32,
    v_ratio: u32,
    h_taps: u8,
    v_taps: u8,
    hratio: Fx,
    vratio: Fx,
    /// VInitPreFill, MaxNumSwath and PrefetchSourceLines
    /// (CalculatePrefetchSourceLines, viewport not stationary).
    vinit: u32,
    max_num_swath: u32,
    source_lines: i64,
    /// PSCL_THROUGHPUT(_CHROMA), as Linux's double holds it.
    pscl: f64,
    /// vactive_sw_bw in mode support (from the viewport) and mode
    /// programming (from the swath; the same for luma).
    vactive_bw: Fx,
    vactive_bw_mp: Fx,
}

impl Surf {
    /// CalculatePrefetchSourceLines with no interlace or stationary
    /// viewport: VInitPreFill = floor((VRatio + VTaps + 1) / 2), the
    /// swaths covering it and the partial swath after them.
    fn source_lines(&mut self) {
        let unity = u64::from(Plane::UNITY);
        let vinit = (u64::from(self.v_ratio) + u64::from(self.v_taps + 1) * unity) / (2 * unity);
        let h = u64::from(self.height);
        let max_num = (vinit.saturating_sub(1)).div_ceil(h) + 1;
        let partial = if vinit > 1 {
            ((vinit - 2) % h).max(1)
        } else {
            ((vinit + h - 2) % h).max(1)
        };
        self.vinit = vinit as u32;
        self.max_num_swath = max_num as u32;
        self.source_lines = (max_num * h + partial) as i64;
    }
    /// The whole lines (rounded down to whole swaths) `bytes` of DET hold
    /// of swaths `width` wide.
    fn det_lines(&self, bytes: u64, width: u32) -> u64 {
        let lines = bytes * 3 / (u64::from(self.det_bpp3) * u64::from(width));
        lines / u64::from(self.height) * u64::from(self.height)
    }
}

/// CalculateBytePerPixelAndBlockSizes for a plane: per surface (luma,
/// chroma) BytePerPixel, BytePerPixelInDET (times three), the 256-byte
/// block and the macro tile. An RGB plane's chroma entries are zero.
#[derive(Clone, Copy)]
struct Blocks {
    bpp: [u32; 2],
    det_bpp3: [u32; 2],
    block_w: [u32; 2],
    block_h: [u32; 2],
    tile_w: [u32; 2],
    tile_h: [u32; 2],
}

impl Blocks {
    fn of(p: &Plane) -> Self {
        let b = u32::from(p.bytes_per_pixel).max(1);
        let linear = p.swizzle == Swizzle::Linear;
        let (bpp, det_bpp3, block_h) = match p.source {
            Source::Rgb => (
                [b, 0],
                [3 * b, 0],
                [
                    if linear {
                        1
                    } else if b == 8 {
                        4
                    } else {
                        8
                    },
                    0,
                ],
            ),
            Source::Yuv420_8 => ([1, 2], [3, 6], if linear { [1, 1] } else { [16, 8] }),
            Source::Yuv420_10 => ([2, 4], [4, 8], if linear { [1, 1] } else { [8, 8] }),
        };
        let mut out = Self {
            bpp,
            det_bpp3,
            block_w: [0; 2],
            block_h,
            tile_w: [0; 2],
            tile_h: [0; 2],
        };
        for i in 0..2 {
            if bpp[i] == 0 || block_h[i] == 0 {
                continue;
            }
            out.block_w[i] = 256 / bpp[i] / block_h[i];
            out.tile_h[i] = p.swizzle.macro_tile_scale() * block_h[i];
            out.tile_w[i] = p.swizzle.block_bytes() / bpp[i] / out.tile_h[i];
        }
        out
    }
}

/// dcn4_soc_bb: `mcache_size_bytes`, `mcache_line_size_bytes` (also
/// `mem_word_bytes`).
const MCACHE_BYTES: u32 = 2048;
const MCACHE_LINE_BYTES: u32 = 32;
/// `num_dcc_mcaches`.
const DCC_MCACHES: u32 = 8;

/// One DCC surface's calculate_mcache_row_bytes and calculate_mcache_setting
/// results with GPUVM off and the viewport not stationary: the mcache count,
/// its first two split offsets (a third only matters once admission has
/// already failed) and the DRAM overhead factors.
#[derive(Clone, Copy)]
struct Mcache {
    count: u32,
    offsets: [u32; 2],
    dram_nom: Fx,
    dram_pref: Fx,
    /// lc_comb_mcache (luma's entry): luma and chroma share the last one.
    shared: bool,
}

impl Mcache {
    /// Luma, then a 4:2:0 plane's chroma (`surfs[1]` is ignored for RGB).
    fn of(p: &Plane, b: &Blocks, surfs: [&Surf; 2], channels: u32) -> [Self; 2] {
        let vertical = p.vertical_scan;
        let meta = p.swizzle.block_bytes() as f32 / 256.0 / channels as f32;
        let meta_ub = (ceil_f(f64::from(meta) / f64::from(MCACHE_LINE_BYTES))
            * f64::from(MCACHE_LINE_BYTES)) as u32;
        let c = p.chroma_values();
        let views = [
            (p.viewport_width, p.viewport_height),
            (c.viewport_width, c.viewport_height),
        ];
        let surfaces = if p.is_420() { 2 } else { 1 };
        let mut out = [Self {
            count: 0,
            offsets: [0; 2],
            dram_nom: Fx::ONE,
            dram_pref: Fx::ONE,
            shared: false,
        }; 2];
        let (mut width_ub, mut per_channel) = ([0u32; 2], [0u32; 2]);
        for i in 0..surfaces {
            let (tw, th) = (b.tile_w[i], b.tile_h[i]);
            let (vw, vh) = (u32::from(views[i].0), u32::from(views[i].1));
            // meta_row_width_ub along the access, and the row's bytes per
            // channel.
            let (row_bytes, pc) = if vertical {
                width_ub[i] = ceil_to(u64::from(vh - 1), u64::from(th)) as u32 + th;
                let pc = width_ub[i] / th * meta_ub;
                (u64::from(pc) * u64::from(channels), pc)
            } else {
                width_ub[i] = ceil_to(u64::from(vw - 1), u64::from(tw)) as u32 + tw;
                let rb = u64::from(width_ub[i]) * u64::from(th) * u64::from(surfs[i].bpp) / 256;
                let pc = ceil_f(rb as f64 / f64::from(channels) / f64::from(MCACHE_LINE_BYTES))
                    * f64::from(MCACHE_LINE_BYTES);
                (rb, pc as u32)
            };
            per_channel[i] = pc;
            out[i].count = pc.div_ceil(MCACHE_BYTES);
            out[i].dram_nom = if vertical {
                let m = f64::from(meta);
                fx_f(1.0 + max_f(1.0 / 256.0, f64::from(meta_ub) / (256.0 * m)))
            } else {
                q(257, 256)
            };
            // dcc_dr_oh_pref: an (unsigned) quotient of the row's bytes over
            // the full swath's.
            let whole = row_bytes / u64::from(surfs[i].full_swath_bytes.max(1));
            out[i].dram_pref = if whole == 0 {
                q(257, 256)
            } else {
                fx(1 + whole as i64)
            };
        }
        // Luma/chroma sharing the last mcache (no iMALL): both remainders
        // fit one mcache, luma weighted by its swath-time factor.
        let access = |i: usize| if vertical { b.tile_h[i] } else { b.tile_w[i] };
        let (rem_l, rem_c) = (per_channel[0] % MCACHE_BYTES, per_channel[1] % MCACHE_BYTES);
        let lc_comb = surfaces == 2 && rem_l != 0 && rem_c != 0 && {
            let factor = if vertical {
                f64::from(b.tile_w[1]) / f64::from(b.tile_w[0]) * 2.0
            } else {
                f64::from(b.tile_h[1]) / f64::from(b.tile_h[0]) * 2.0
            };
            (f64::from(rem_l) * factor + f64::from(rem_c)) as u32 <= MCACHE_BYTES
        };
        out[0].shared = lc_comb;
        for (i, m) in out.iter_mut().enumerate().take(surfaces) {
            let a = access(i);
            let avg = width_ub[i] / m.count.max(1);
            for n in 0..m.count.saturating_sub(1).min(2) {
                m.offsets[n as usize] = if lc_comb {
                    (n + 1) * (MCACHE_BYTES / meta_ub) * a
                } else {
                    (n + 1) * avg / a * a
                };
            }
        }
        out
    }
    /// dml2_top_mcache_validate_admissability for a plane on `dpps` pipes
    /// of a stream split `odm` ways: each surface's mcache boundaries no
    /// more than its pipes and at most one within any pipe's share of the
    /// viewport (an ODM segment's source pixels, at most the surface; an
    /// MPC slice's share of the surface width). The viewport is never
    /// stationary, so no shift is searched.
    fn admissible(m: &[Self; 2], p: &Plane, h_active: u32, odm: u32, dpps: u32) -> bool {
        let c = p.chroma_values();
        let widths = [
            p.surface_width,
            if p.is_420() { c.surface_width } else { 0 },
        ];
        let ratios = [p.h_ratio, c.h_ratio];
        for i in 0..2 {
            let mut span = i64::from(widths[i]);
            if odm > 1 {
                let share = ratio_f(ratios[i]) * f64::from(h_active) / f64::from(odm);
                span = span.min(ceil_f(share) as i64);
            } else {
                span /= i64::from(dpps.max(1));
            }
            span += if i == 0 { 12 } else { 6 };
            let boundaries = m[i].count.saturating_sub(1);
            if boundaries > dpps
                || count_in_span(&m[i].offsets[..boundaries.min(2) as usize], span) > 1
            {
                return false;
            }
        }
        true
    }
}

/// count_elements_in_span: the most of the (ascending) offsets that lie
/// within `span` of one another's window start.
fn count_in_span(offsets: &[u32], span: i64) -> u32 {
    if offsets.is_empty() || span == 0 {
        return 1;
    }
    let (mut start_value, mut start, mut greatest) = (0i64, 0usize, 0u32);
    while start < offsets.len() {
        for (i, &o) in offsets.iter().enumerate().skip(start) {
            if i64::from(o) - start_value <= span {
                greatest = greatest.max((i - start + 1) as u32);
            } else {
                break;
            }
        }
        start += 1;
        if start < offsets.len() {
            start_value = i64::from(offsets[start - 1]) + 1;
        }
    }
    greatest
}

/// One plane's quantities that no clock changes, with its stream's.
#[derive(Clone, Copy)]
struct Shape {
    /// The plane's stream: its index among the admitted modes.
    stream: usize,
    t: Timing,
    pclk: Fx,
    line: Fx,
    /// ODM segments of the plane's stream: 1 to 4.
    odm: u32,
    /// The plane's DPPs (DML's NoOfDPP / DPPPerSurface): its stream's ODM
    /// segments, or 2 for an MPC-combined plane in ODM bypass.
    dpps: u32,
    /// DETBufferSizeInKByte of each pipe, in bytes.
    det_bytes: u32,
    vblank: u32,
    ycbcr420: bool,
    /// DSCDelayRequirement in pixels (0 without DSC).
    dsc_delay: u32,
    plane: Plane,
    /// The luma (or RGB) surface, and a 4:2:0 plane's chroma.
    y: Surf,
    c: Option<Surf>,
    /// RequiredDPPCLK (MHz), as Linux's double holds it; whether DPPCLK is
    /// just the pixel clock over the pipes.
    dpp: f64,
    dpp_unit: bool,
    /// The DCC DRAM overhead factors (calculate_mcache_row_bytes:
    /// dcc_dram_bw_nom/pref_overhead_factor, luma then chroma), 1 without
    /// DCC. Only DRAM bandwidth carries them.
    dram_nom: [Fx; 2],
    dram_pref: [Fx; 2],
    /// The DCC mcaches the plane takes (both surfaces, one less when they
    /// share the last); zero without DCC.
    mcaches: u32,
    /// The DCC plane's allocation, its ids still zero.
    mcache: Option<McacheAllocation>,
    /// dml2_top_mcache_validate_admissability's verdict for the plane on
    /// its pipes (true without DCC).
    mcache_fits: bool,
}

/// DPPCLK, DISPCLK and deep-sleep DCFCLK one evaluation runs the pipe at.
#[derive(Clone, Copy)]
struct PipeClocks {
    dpp: Fx,
    disp: Fx,
    deep_sleep: Fx,
    /// The same clocks in whole kHz (DPPCLK, DISPCLK, deep-sleep DCFCLK)
    /// when mode programming runs at DPMM's chosen clocks: the VUpdate and
    /// VReady widths are then rounded up from their exact value, as Linux's
    /// doubles do, rather than from 24-bit fixed point.
    khz: Option<[u32; 3]>,
}

/// Results of one `CalculatePrefetchSchedule` + `CalculateUrgentBurstFactor`.
#[derive(Clone, Copy, Default)]
struct Schedule {
    vstartup: u32,
    vupdate_offset: u32,
    vupdate_width: u32,
    vready_offset: u32,
    t_setup: Fx,
    t_dmdl: Fx,
    dst_x: u32,
    dst_y: u32,
    dst_y_prefetch: Fx,
    /// VRatioPrefetchY/C (C is 1 for RGB: no source lines over Lsw).
    vratio_pre: Fx,
    vratio_pre_c: Fx,
    /// RequiredPrefetchPixelDataBWLuma/Chroma and RequiredPrefetchBWMax.
    prefetch_bw: Fx,
    prefetch_bw_c: Fx,
    prefetch_bw_max: Fx,
    no_time: bool,
}

/// Everything one evaluation at one clock state produces.
#[derive(Clone, Copy)]
struct Evaluation {
    /// Each surface's prefetch schedule, in admission order.
    planes: [Schedule; MAX_PLANES],
    extra: Fx,
    extra_sr: Fx,
    t_calc: Fx,
    t_wait: Fx,
    lat: Latency,
    frac_nom: Fx,
    frac_mall: Fx,
    non_urgent_sdp: Fx,
    /// Urgent SDP bandwidth over every surface (urg_bandwidth_required_flip
    /// with no flip), in MB/s.
    urgent_sdp: Fx,
}

/// DML's math_ceil2(x, 1) for a non-negative double.
fn ceil_f(x: f64) -> f64 {
    let i = x as i64 as f64;
    if i < x {
        i + 1.0
    } else {
        i
    }
}
fn max_f(a: f64, b: f64) -> f64 {
    if a > b {
        a
    } else {
        b
    }
}
fn min_f(a: f64, b: f64) -> f64 {
    if a < b {
        a
    } else {
        b
    }
}
/// A 2^-19 ratio as DML's double.
fn ratio_f(r: u32) -> f64 {
    f64::from(r) / 524_288.0
}
/// A non-negative double as fixed point (truncated to 2^-24).
fn fx_f(v: f64) -> Fx {
    Fx::ratio((v * 16_777_216.0) as i64, 1 << 24)
}

impl Plane {
    /// ScaleRatioAndTapsSupport, SourceFormatPixelAndScanSupport,
    /// ViewportExceedsSurface and PitchSupport: what DML refuses of a
    /// plane on its own. Returns the plane's blocks.
    fn validate(&self) -> Result<Blocks, Error> {
        let taps_ok = |t: u8| (1..=MAX_SCL_TAPS).contains(&u32::from(t));
        let ratio_ok = |r: u32, taps: u8| {
            r != 0 && r <= MAX_SCL_RATIO * Self::UNITY && r <= u32::from(taps) * Self::UNITY
        };
        let scaler_ok = |h_taps: u8, v_taps: u8, h: u32, v: u32| {
            taps_ok(h_taps)
                && taps_ok(v_taps)
                && !(h_taps > 1 && h_taps % 2 == 1)
                && ratio_ok(h, h_taps)
                && ratio_ok(v, v_taps)
        };
        let extent_ok = |w: u16, h: u16, pitch: u16, vw: u16, vh: u16| {
            w != 0
                && h != 0
                && w <= 0x3fff
                && h <= 0x3fff
                && vw != 0
                && vh != 0
                && vw <= w
                && vh <= h
                && pitch >= w
        };
        let bpp_ok = match self.source {
            Source::Rgb => matches!(self.bytes_per_pixel, 2 | 4 | 8),
            Source::Yuv420_8 => self.bytes_per_pixel == 1,
            Source::Yuv420_10 => self.bytes_per_pixel == 2,
        };
        let chroma_ok = match (self.is_420(), self.chroma) {
            (false, None) => true,
            (true, Some(c)) => {
                extent_ok(
                    c.surface_width,
                    c.surface_height,
                    c.pitch,
                    c.viewport_width,
                    c.viewport_height,
                ) && scaler_ok(c.h_taps, c.v_taps, c.h_ratio, c.v_ratio)
            }
            _ => false,
        };
        if !extent_ok(
            self.surface_width,
            self.surface_height,
            self.pitch,
            self.viewport_width,
            self.viewport_height,
        ) || !bpp_ok
            || !scaler_ok(self.h_taps, self.v_taps, self.h_ratio, self.v_ratio)
            || !chroma_ok
            // A 4:2:0 plane always scales its chroma.
            || (self.is_420() && !self.scaler_enabled())
        {
            return Err(Error::Invalid);
        }
        // A linear surface cannot be scanned vertically.
        if self.vertical_scan && self.swizzle == Swizzle::Linear {
            return Err(Error::Unsupported);
        }
        let b = Blocks::of(self);
        let c = self.chroma_values();
        let surfaces = if self.is_420() { 2 } else { 1 };
        for (i, (pitch, width)) in [(self.pitch, self.surface_width), (c.pitch, c.surface_width)]
            .into_iter()
            .take(surfaces)
            .enumerate()
        {
            let (pitch, width) = (u64::from(pitch), u64::from(width));
            if self.swizzle == Swizzle::Linear {
                // A 128-byte-aligned linear pitch changes the request
                // width this omits.
                if pitch * u64::from(b.bpp[i]) % 256 != 0 {
                    return Err(Error::Unsupported);
                }
            } else if ceil_to(pitch.max(width), u64::from(b.tile_w[i])) > pitch {
                // A tiled pitch is whole macro tiles.
                return Err(Error::Invalid);
            }
        }
        Ok(b)
    }
}

impl Shape {
    /// `dispclk_ss_khz` is DML's `max_dispclk_freq_mhz`: the board maximum
    /// less downspread, which decides ODM combine; `channels` the DRAM
    /// channel count calculate_mcache_row_bytes spreads DCC metadata over.
    fn new(
        mode: &Mode,
        plane: Plane,
        stream: usize,
        dispclk_ss_khz: u64,
        channels: u32,
    ) -> Result<Self, Error> {
        let t = mode.timing;
        if t.pixel_clock_khz == 0
            || t.h_active == 0
            || t.v_active == 0
            || t.h_total <= t.h_active
            || t.v_total <= t.v_active
            || t.h_total > 0x8000
            || t.v_total > 0x8000
            || u64::from(t.h_front_porch) + u64::from(t.h_sync_width)
                > u64::from(t.h_total - t.h_active)
            || u64::from(t.v_front_porch) + u64::from(t.v_sync_width)
                > u64::from(t.v_total - t.v_active)
        {
            return Err(Error::Invalid);
        }
        plane.validate()?;
        // DML needs a blank line after VStartup for MIN_DST_Y_NEXT_START.
        if t.v_total - t.v_active < 2
            || t.v_front_porch == 0
            || t.h_active > 0x3fff
            || t.v_active > 0x3fff
        {
            return Err(Error::Unsupported);
        }
        if let Some(dsc) = mode.dsc {
            if dsc.bpp_x16 == 0 {
                return Err(Error::Invalid);
            }
            if mode.ycbcr420 || dsc.slices == 0 {
                return Err(Error::Unsupported);
            }
        }
        // Even a 4:1 split cannot bring DISPCLK under the board maximum.
        if u64::from(t.pixel_clock_khz) > 4 * dispclk_ss_khz {
            return Err(Error::PixelClock);
        }
        let odm = decide_odm(mode, dispclk_ss_khz);
        // ValidateODMMode: DISPCLK within the maximum (an HDMI 4:2:0 output's
        // stays at half the pixel clock however wide the split); each pipe
        // takes an equal share of the line in whole pixel containers (a
        // 3:1 split only with DSC), and OTG_H_TIMING_DIV_MODE's divisor
        // (four for 3:1 and 4:1, which pack four pixels per transfer)
        // divides the line; the formatter's 4:2:0 line buffer per pipe.
        if u64::from(t.pixel_clock_khz)
            > u64::from(disp_divider(odm, mode.ycbcr420)) * dispclk_ss_khz
        {
            return Err(Error::PixelClock);
        }
        let ppc = if mode.ycbcr420 { 2 } else { 1 };
        let symmetric = odm != 3 || mode.dsc.is_some();
        let h_div = match odm {
            3 | 4 => 4,
            2 => 2,
            _ => ppc,
        };
        if (symmetric && t.h_active % (odm * ppc) != 0)
            || t.h_active % h_div != 0
            || (mode.ycbcr420 && t.h_active > odm * FMT_420_BUFFER_WIDTH)
        {
            return Err(Error::Unsupported);
        }
        // With DSC, ValidateODMMode (one DSC per pipe: at most 5760 pixels
        // and four slices each, the slices dividing the line and splitting
        // evenly between the pipes, all twelve on three), the DSC unit/slice
        // checks, and DSCCLKRequiredMoreThanSupported (a third of each
        // pipe's pixels).
        if let Some(dsc) = mode.dsc {
            if dsc.slices > odm * MAX_SLICES_PER_DSC
                || t.h_active > odm * MAX_PIXELS_PER_DSC
                || t.h_active % dsc.slices != 0
                || dsc.slices % odm != 0
                || (odm == 3 && dsc.slices != 3 * MAX_SLICES_PER_DSC)
            {
                return Err(Error::Unsupported);
            }
            if f64::from(t.pixel_clock_khz) / 1000.0 / (3.0 * f64::from(odm)) / 1.0
                > f64::from(MAX_DSCCLK_KHZ) / 1000.0
            {
                return Err(Error::PixelClock);
            }
        }
        Self::with_pipes(mode, plane, stream, odm, odm, channels)
    }
    /// The plane's quantities on `dpps` DPPs of a stream split `odm` ways:
    /// `dpps == odm` for an ODM split, or 2 on one ODM segment for MPC
    /// combine (the viewport halved).
    fn with_pipes(
        mode: &Mode,
        plane: Plane,
        stream: usize,
        odm: u32,
        dpps: u32,
        channels: u32,
    ) -> Result<Self, Error> {
        let t = mode.timing;
        let blocks = plane.validate()?;
        // CalculateSwathWidth: the viewport (its height scanning
        // vertically); with ODM each pipe's share of the line in source
        // pixels (math_round), at most that; with MPC combine half the
        // viewport; a 4:2:0 chroma swath is half the luma one. Each is
        // rounded to whole requests within the surface.
        let vertical = plane.vertical_scan;
        let along = |w: u16, h: u16| u32::from(if vertical { h } else { w });
        let vp = along(plane.viewport_width, plane.viewport_height);
        let swath = if odm > 1 {
            let share = (2 * u64::from(t.h_active) * u64::from(plane.h_ratio)
                + u64::from(odm) * u64::from(Plane::UNITY))
                / (2 * u64::from(odm) * u64::from(Plane::UNITY));
            vp.min(share as u32)
        } else {
            vp / dpps
        };
        let c = plane.chroma_values();
        let ratio = |r: u32| q(i64::from(r), i64::from(Plane::UNITY));
        // vactive_sw_bw: the single-pipe swath's bytes per line time at
        // the vertical ratio.
        let line_bw = |width: u32, bpp: u32, v: u32| {
            q(
                i64::from(width) * i64::from(bpp) * i64::from(t.pixel_clock_khz),
                i64::from(t.h_total) * 1000,
            )
            .times(ratio(v))
        };
        // CalculateSinglePipeDPPCLKAndSCLThroughput, per surface.
        let pscl = |h: f64, h_taps: u8| {
            if h > 1.0 {
                min_f(
                    MAX_DCHUB_PSCL_BW as f64,
                    MAX_PSCL_LB_BW as f64 * h / ceil_f(f64::from(h_taps) / 6.0),
                )
            } else {
                min_f(MAX_DCHUB_PSCL_BW as f64, MAX_PSCL_LB_BW as f64)
            }
        };
        let make = |i: usize,
                    single: u32,
                    swath: u32,
                    surface: (u16, u16),
                    (h_ratio, v_ratio, h_taps, v_taps): (u32, u32, u8, u8),
                    bw: (Fx, Fx)| {
            let (bw_w, bw_h) = (blocks.block_w[i], blocks.block_h[i]);
            let (req_w, extent, max_height) = if vertical {
                (bw_h, surface.1, bw_w)
            } else {
                (bw_w, surface.0, bw_h)
            };
            let r = u64::from(req_w);
            let swath_ub = ceil_to(u64::from(extent), r)
                .min(ceil_to(u64::from(swath).saturating_sub(1), r) + r)
                as u32;
            let mut full =
                u64::from(swath_ub) * u64::from(blocks.det_bpp3[i]) * u64::from(max_height) / 3;
            if plane.source == Source::Yuv420_10 {
                full = ceil_to(full, 256);
            }
            Surf {
                bpp: blocks.bpp[i],
                det_bpp3: blocks.det_bpp3[i],
                req_w,
                swath_single: single,
                swath,
                swath_ub,
                max_height,
                height: max_height,
                det_bytes: 0,
                request_bytes: 256,
                full_swath_bytes: full as u32,
                rounded_swath_bytes: full as u32,
                h_ratio,
                v_ratio,
                h_taps,
                v_taps,
                hratio: ratio(h_ratio),
                vratio: ratio(v_ratio),
                vinit: 0,
                max_num_swath: 0,
                source_lines: 0,
                pscl: pscl(ratio_f(h_ratio), h_taps),
                vactive_bw: bw.0,
                vactive_bw_mp: bw.1,
            }
        };
        let luma_bw = line_bw(vp, blocks.bpp[0], plane.v_ratio);
        let mut y = make(
            0,
            vp,
            swath,
            (plane.surface_width, plane.surface_height),
            (plane.h_ratio, plane.v_ratio, plane.h_taps, plane.v_taps),
            (luma_bw, luma_bw),
        );
        let mut chroma = plane.is_420().then(|| {
            make(
                1,
                vp / 2,
                swath / 2,
                (c.surface_width, c.surface_height),
                (c.h_ratio, c.v_ratio, c.h_taps, c.v_taps),
                (
                    line_bw(
                        along(c.viewport_width, c.viewport_height),
                        blocks.bpp[1],
                        c.v_ratio,
                    ),
                    line_bw(vp / 2, blocks.bpp[1], c.v_ratio),
                ),
            )
        });
        // CalculateSwathAndDETConfiguration: the full swaths if two of them
        // fit half the DET (always for linear), else halved swaths.
        let det = DET_KBYTES * 1024;
        let half = det / 2;
        let full_l = y.full_swath_bytes;
        let full_c = chroma.map_or(0, |s| s.full_swath_bytes);
        let half_request = |bpp: u32| if (bpp == 2) == vertical { 128 } else { 64 };
        let (halve_l, halve_c) = if plane.swizzle == Swizzle::Linear || full_l + full_c <= half {
            (false, false)
        } else if 2 * u64::from(full_l) >= 3 * u64::from(full_c) && full_l / 2 + full_c <= half {
            (true, false)
        } else if 2 * u64::from(full_l) < 3 * u64::from(full_c) && full_l + full_c / 2 <= half {
            (false, true)
        } else {
            (true, true)
        };
        if halve_l {
            y.height = y.max_height / 2;
            y.rounded_swath_bytes = full_l / 2;
            y.request_bytes = half_request(y.bpp);
        }
        if let Some(s) = chroma.as_mut() {
            if halve_c {
                s.height = s.max_height / 2;
                s.rounded_swath_bytes = full_c / 2;
                s.request_bytes = half_request(s.bpp);
            }
            if s.height == 0 {
                s.request_bytes = 0;
            }
        }
        // The DET split between the surfaces.
        match chroma.as_mut() {
            None => y.det_bytes = det,
            Some(s) => {
                if 2 * u64::from(y.rounded_swath_bytes) <= 3 * u64::from(s.rounded_swath_bytes) {
                    y.det_bytes = det / 2;
                } else {
                    y.det_bytes = det * 2 / 3 / 1024 * 1024;
                }
                s.det_bytes = det - y.det_bytes;
            }
        }
        y.source_lines();
        if let Some(s) = chroma.as_mut() {
            s.source_lines();
        }
        // CalculateSinglePipeDPPCLKAndSCLThroughput, then RequiredDPPCLK:
        // the faster of luma and chroma.
        let pixel_mhz = f64::from(t.pixel_clock_khz) / 1000.0;
        let single_dpp = |s: &Surf| {
            let (h, v) = (ratio_f(s.h_ratio), ratio_f(s.v_ratio));
            let vtaps_term = f64::from(s.v_taps / 6) * min_f(1.0, h);
            let mut single = pixel_mhz * max_f(max_f(vtaps_term, h * v / s.pscl), 1.0);
            if (s.h_taps > 6 || s.v_taps > 6) && single < 2.0 * pixel_mhz {
                single = 2.0 * pixel_mhz;
            }
            single
        };
        let single = chroma
            .as_ref()
            .map_or(single_dpp(&y), |s| max_f(single_dpp(&y), single_dpp(s)));
        // calculate_mcache_setting (GPUVM off, viewport not stationary):
        // DCC's DRAM overhead, and the mcaches dml2_top_mcache_validate_
        // admissability must place on the plane's pipes.
        let mut dram_nom = [Fx::ONE; 2];
        let mut dram_pref = [Fx::ONE; 2];
        let mut mcache_count = 0;
        let mut mcache_alloc = None;
        let mut mcache_fits = true;
        if plane.dcc {
            let mcaches = Mcache::of(
                &plane,
                &blocks,
                [&y, chroma.as_ref().unwrap_or(&y)],
                channels,
            );
            for (i, m) in mcaches
                .iter()
                .take(if plane.is_420() { 2 } else { 1 })
                .enumerate()
            {
                dram_nom[i] = m.dram_nom;
                dram_pref[i] = m.dram_pref;
                mcache_count += m.count;
            }
            mcache_count -= u32::from(mcaches[0].shared);
            // core_dcn4_calculate_mcache_allocation: the last boundary is
            // the surface's width. Global ids come with admission.
            let widths = [plane.surface_width, c.surface_width];
            let mut a = McacheAllocation {
                shared: mcaches[0].shared,
                ..McacheAllocation::default()
            };
            for (i, m) in mcaches
                .iter()
                .take(if plane.is_420() { 2 } else { 1 })
                .enumerate()
            {
                let count = m.count.min(3) as usize;
                a.count[i] = m.count.min(u32::from(u8::MAX)) as u8;
                for n in 0..count.saturating_sub(1) {
                    a.offsets[i][n] = m.offsets[n] as u16;
                }
                if count > 0 {
                    a.offsets[i][count - 1] = widths[i];
                }
            }
            mcache_alloc = Some(a);
            // Whether the plane's pipes can place its mcaches; if not,
            // admission MPC-splits it as pmo_dcn4_fams2_optimize_dcc_mcache
            // does.
            mcache_fits = Mcache::admissible(&mcaches, &plane, t.h_active, odm, dpps);
        }
        Ok(Self {
            stream,
            t,
            pclk: mhz(u64::from(t.pixel_clock_khz)),
            line: q(i64::from(t.h_total) * 1000, i64::from(t.pixel_clock_khz)),
            odm,
            dpps,
            det_bytes: det,
            vblank: t.v_total - t.v_active,
            ycbcr420: mode.ycbcr420,
            dsc_delay: mode.dsc.map_or(0, |d| dsc_delay(&t, d, odm)),
            plane,
            y,
            c: chroma,
            dpp: single / f64::from(dpps),
            dpp_unit: single == pixel_mhz,
            dram_nom,
            dram_pref,
            mcaches: mcache_count,
            mcache: mcache_alloc,
            mcache_fits,
        })
    }
    /// The MPC combine decision of dml2_core_dcn4_calcs.c's mode support
    /// for a plane in ODM bypass with `mpcc_combine_factor` auto (as DC
    /// passes it): two DPPs when one would need more than the
    /// downspread-limited DPPCLK maximum (MinDPPCLKUsingSingleDPP) or
    /// cannot take the whole viewport (SingleDPPViewportSizeSupport: the
    /// swath against the DET, the linear swath limit and the line buffer).
    /// DCN4's `mpc_combine_limit` is two. The decision is the same for
    /// every surface: linear or tiled, RGB or 4:2:0, with or without DCC,
    /// scanned horizontally or (rotated 90/270) vertically.
    fn mpc_combined(self, mode: &Mode, dppclk_ss_khz: u64, channels: u32) -> Result<Self, Error> {
        if self.odm > 1 || self.dpps > 1 {
            return Ok(self);
        }
        let dpp_over = if self.dpp_unit {
            u64::from(self.t.pixel_clock_khz) > dppclk_ss_khz
        } else {
            self.dpp > dppclk_ss_khz as f64 / 1000.0
        };
        if !dpp_over && self.buffers().is_ok() {
            return Ok(self);
        }
        Self::with_pipes(
            mode,
            self.plane,
            self.stream,
            1,
            MPC_COMBINE_LIMIT,
            channels,
        )
    }
    /// The surfaces of the plane: luma, then a 4:2:0 plane's chroma.
    fn surfaces(&self) -> impl Iterator<Item = &Surf> {
        core::iter::once(&self.y).chain(self.c.iter())
    }
    /// The surface's read bandwidth (mode support's or mode programming's
    /// vactive_sw_bw, luma plus chroma), over all of its pipes.
    fn vactive_bw(&self, mp: bool) -> Fx {
        let c = self.c.map_or(
            Fx::ZERO,
            |c| if mp { c.vactive_bw_mp } else { c.vactive_bw },
        );
        self.y.vactive_bw.plus(c)
    }
    /// `CalculateSwathAndDETConfiguration` support (ViewportSizeSupport):
    /// half of each full swath fits half the DET, and each swath fits
    /// MaximumSwathWidthSupport and the line buffer's
    /// MaximumSwathWidthInLineBuffer for its taps and ratios.
    fn buffers(&self) -> Result<(), Error> {
        let p = &self.plane;
        let full_c = self.c.map_or(0, |c| c.full_swath_bytes);
        if self.y.full_swath_bytes / 2 + full_c / 2 > self.det_bytes / 2 {
            return Err(Error::Buffer);
        }
        let support = if p.swizzle == Swizzle::Linear {
            MAX_LINEAR_SWATH
        } else if p.is_420() {
            if p.vertical_scan {
                4320 + 16
            } else {
                7680 + 16
            }
        } else if p.vertical_scan && self.y.bpp == 8 && p.dcc {
            3072 + 16
        } else {
            6144 + 16
        };
        let unity = u128::from(Plane::UNITY);
        let fits = |s: &Surf, limit: u32| {
            let ceil_v = u128::from(s.v_ratio).div_ceil(unity);
            let lines = u128::from(s.v_taps) + ceil_v.saturating_sub(2);
            let lb = LINE_BUFFER_BITS as u128 * u128::from(s.h_ratio).max(unity);
            s.swath <= limit
                && u128::from(s.swath) * LB_BITS_PER_PIXEL as u128 * lines * unity <= lb
        };
        let chroma_limit = if p.is_420() { support / 2 } else { support };
        if !fits(&self.y, support)
            || self
                .c
                .is_some_and(|c| c.height > 0 && !fits(&c, chroma_limit))
        {
            return Err(Error::Buffer);
        }
        Ok(())
    }
    /// `CalculateUrgentBurstFactor` for one surface. `None` is
    /// NotEnoughUrgentLatencyHiding.
    fn burst(&self, s: &Surf, urgent: Fx, vratio: Fx) -> Option<Fx> {
        let lines = s.det_lines(u64::from(s.det_bytes), s.swath_ub);
        let time = fx(lines as i64).times(self.line).over(vratio);
        if time.minus(urgent) <= Fx::ZERO {
            return None;
        }
        Some(time.over(time.minus(urgent)))
    }
    /// `CalculateDCFCLKDeepSleep`'s per-surface term with no tdlut: at
    /// VRatio up to 1 a pipe delivers its swath in `dpps` times its share of
    /// the line at the scaled rate, above it at the scaler's throughput.
    fn deep_sleep_surface(&self, dpp: Fx) -> Fx {
        let factor = q(DCFCLK_FACTOR_HUNDREDTHS, 100);
        let y = &self.y;
        let per_byte = factor.times(fx(i64::from(y.bpp))).over(fx(64));
        let rate = if y.v_ratio <= Plane::UNITY {
            per_byte
                .times(self.pclk)
                .times(y.hratio)
                .over(fx(i64::from(self.dpps)))
        } else {
            per_byte.times(fx_f(y.pscl)).times(dpp)
        };
        rate.max(self.pclk.over(fx(16)))
    }
    /// `RequiredDPPCLK`: the pipe's DPPCLK, the pixel clock over the pipes
    /// when unscaled, in MHz.
    fn dpp_mhz(&self) -> Fx {
        if self.dpp_unit {
            return q(
                i64::from(self.t.pixel_clock_khz),
                1000 * i64::from(self.dpps),
            );
        }
        fx_f(self.dpp)
    }
    /// The same as DML hands it to DPMM: truncated to kHz.
    fn dpp_khz(&self) -> u32 {
        if self.dpp_unit {
            return self.t.pixel_clock_khz / self.dpps;
        }
        (self.dpp * 1000.0) as u32
    }
    /// `RequiredDISPCLKPerSurface`: the pixel clock over the pipes, in kHz
    /// as DPMM takes it.
    fn disp_khz(&self) -> u32 {
        self.t.pixel_clock_khz / disp_divider(self.odm, self.ycbcr420)
    }
    fn disp_mhz(&self) -> Fx {
        q(
            i64::from(self.t.pixel_clock_khz),
            1000 * i64::from(disp_divider(self.odm, self.ycbcr420)),
        )
    }
}

/// `CalculateDCFCLKDeepSleep` over every admitted surface: the total read
/// bandwidth's term against each surface's own. A 4:2:0 plane's surface
/// term comes from Linux's doubles (`deep_sleep_khz_f`).
fn deep_sleep(shapes: &[Shape], mp: bool) -> Fx {
    if shapes.iter().any(|s| s.c.is_some()) {
        return fx_f(deep_sleep_f(shapes));
    }
    let factor = q(DCFCLK_FACTOR_HUNDREDTHS, 100);
    let read = shapes
        .iter()
        .fold(Fx::ZERO, |sum, s| sum.plus(s.vactive_bw(mp)));
    shapes.iter().fold(
        fx(8).max(factor.times(read).over(fx(RETURN_BUS_BYTES))),
        |ds, s| ds.max(s.deep_sleep_surface(s.dpp_mhz())),
    )
}
/// [`deep_sleep`] as DPMM passes it on: truncated to kHz. Unscaled, it is
/// computed exactly (over the product of the line totals) so a whole-kHz
/// result does not lose a unit to rounding; with a scaled or 4:2:0 plane,
/// in Linux's own doubles (CalculateDCFCLKDeepSleepTdlut, RequiredDPPCLK).
fn deep_sleep_khz(shapes: &[Shape]) -> u32 {
    let unscaled = |s: &Shape| {
        s.c.is_none() && s.plane.h_ratio == Plane::UNITY && s.plane.v_ratio == Plane::UNITY
    };
    if !shapes.iter().all(unscaled) {
        return deep_sleep_khz_f(shapes);
    }
    let f = DCFCLK_FACTOR_HUNDREDTHS as u128;
    let den: u128 = shapes.iter().map(|s| u128::from(s.t.h_total)).product();
    let num: u128 = shapes
        .iter()
        .map(|s| {
            u128::from(s.y.swath_single * s.y.bpp) * u128::from(s.t.pixel_clock_khz) * den
                / u128::from(s.t.h_total)
        })
        .sum();
    let bw = f * num / (100 * RETURN_BUS_BYTES as u128 * den);
    shapes.iter().fold(8000.max(bw) as u32, |ds, s| {
        let pclk = u64::from(s.t.pixel_clock_khz);
        let surface =
            (f as u64 * u64::from(s.y.bpp) * pclk / (100 * 64 * u64::from(s.dpps))).max(pclk / 16);
        ds.max(surface as u32)
    })
}
fn deep_sleep_khz_f(shapes: &[Shape]) -> u32 {
    (deep_sleep_f(shapes) * 1000.0) as u32
}
/// CalculateDCFCLKDeepSleepTdlut in Linux's doubles, in MHz.
fn deep_sleep_f(shapes: &[Shape]) -> f64 {
    const FACTOR: f64 = 1.15;
    let mut read = 0.0;
    let mut ds_surface: [f64; MAX_PLANES] = [0.0; MAX_PLANES];
    for (k, s) in shapes.iter().enumerate() {
        let pixel_mhz = f64::from(s.t.pixel_clock_khz) / 1000.0;
        let delivery = |u: &Surf| {
            let (h, v) = (ratio_f(u.h_ratio), ratio_f(u.v_ratio));
            let swath = f64::from(u.swath);
            if v <= 1.0 {
                swath * f64::from(s.dpps) / h / pixel_mhz
            } else {
                swath / u.pscl / s.dpp
            }
        };
        let y = &s.y;
        ds_surface[k] = match &s.c {
            None => FACTOR * f64::from(y.swath) * f64::from(y.bpp) / 64.0 / delivery(y),
            Some(c) => max_f(
                FACTOR * f64::from(y.swath) * f64::from(y.bpp) / 32.0 / delivery(y),
                FACTOR * f64::from(c.swath) * f64::from(c.bpp) / 32.0 / delivery(c),
            ),
        };
        ds_surface[k] = max_f(ds_surface[k], pixel_mhz / 16.0);
        let line = f64::from(s.t.h_total) / pixel_mhz;
        read += f64::from(y.swath_single) * f64::from(y.bpp) / line * ratio_f(y.v_ratio);
        if let Some(c) = &s.c {
            read += f64::from(c.swath_single) * f64::from(c.bpp) / line * ratio_f(c.v_ratio);
        }
    }
    let mut ds = max_f(8.0, FACTOR * read / RETURN_BUS_BYTES as f64);
    for &d in &ds_surface[..shapes.len()] {
        ds = max_f(ds, d);
    }
    ds
}

impl Shape {
    /// `CalculatePrefetchSchedule` with no VM, rows, meta, tdlut, cursor or
    /// dynamic metadata: VM and row stages take their quarter-line minimum.
    /// `mp` selects mode programming's vactive bandwidth.
    fn prefetch(
        &self,
        clk: PipeClocks,
        lat: &Latency,
        t_wait: Fx,
        extra_prefetch: Fx,
        t_calc: Fx,
        mp: bool,
    ) -> Schedule {
        let (t, l) = (self.t, self.line);
        let (dppclk, dispclk, deep_sleep) = (clk.dpp, clk.disp, clk.deep_sleep);
        let (trip, urgent) = (lat.trip, lat.urgent);
        let mut s = Schedule {
            vstartup: (self.vblank - 1).min(MAX_VSTARTUP),
            ..Schedule::default()
        };
        // CalculateVUpdateAndDynamicMetadataParameters.
        let repeaters =
            fx(MAX_INTER_DCN_TILE_REPEATERS).times(fx(2).over(dppclk).plus(fx(3).over(dispclk)));
        s.vupdate_width = fx(14)
            .over(deep_sleep)
            .plus(fx(12).over(dppclk))
            .plus(repeaters)
            .times(self.pclk)
            .ceil() as u32;
        s.vready_offset = fx(150)
            .over(dppclk)
            .max(
                repeaters
                    .plus(fx(20).over(deep_sleep))
                    .plus(fx(10).over(dppclk)),
            )
            .times(self.pclk)
            .ceil() as u32;
        if let Some([dpp, disp, ds]) = clk.khz {
            // The same sums over a common denominator: every clock (and the
            // pixel clock) in kHz, so the MHz units cancel.
            let (dpp, disp, ds) = (u128::from(dpp), u128::from(disp), u128::from(ds));
            let pclk = u128::from(t.pixel_clock_khz);
            let den = dpp * disp * ds;
            let repeaters = MAX_INTER_DCN_TILE_REPEATERS as u128 * (2 * disp + 3 * dpp) * ds;
            let width = 14 * dpp * disp + 12 * disp * ds + repeaters;
            s.vupdate_width = (pclk * width).div_ceil(den) as u32;
            let ready = (150 * disp * ds).max(repeaters + 20 * dpp * disp + 10 * disp * ds);
            s.vready_offset = (pclk * ready).div_ceil(den) as u32;
        }
        s.vupdate_offset = t.h_total.div_ceil(4);
        s.t_setup = fx(i64::from(
            s.vupdate_offset + s.vupdate_width + s.vready_offset,
        ))
        .over(self.pclk);
        let t_wait_p = t_wait.minus(trip);
        s.t_dmdl = t_wait_p.plus(extra_prefetch).plus(trip);
        // DPPCycles: the scaler's delay, or the line buffer's alone.
        let dpp_cycles = DPP_DELAY_CYCLES
            + if self.plane.scaler_enabled() {
                DPP_DELAY_SCL
            } else {
                DPP_DELAY_SCL_LB_ONLY
            };
        let dst_x = round(
            fx(dpp_cycles)
                .times(self.pclk)
                .over(dppclk)
                .plus(fx(DISPCLK_DELAY_CYCLES).times(self.pclk).over(dispclk))
                .plus(fx(i64::from(self.dsc_delay))),
        ) as u32;
        // ODM combine adds 18 pixels, and every further DPP of the plane (ODM
        // segment or MPC slice) its recout width (DPP_RECOUT_WIDTH: the
        // swath over the horizontal ratio, truncated).
        let recout = (u64::from(self.y.swath) * u64::from(Plane::UNITY)
            / u64::from(self.plane.h_ratio)) as u32;
        let dst_x = dst_x + if self.odm > 1 { 18 } else { 0 } + (self.dpps - 1) * recout;
        // CalculatePrefetchSchedule: one line after the scaler for a 4:2:0
        // output, then the pixel delay folded into lines.
        let dst_x = dst_x + if self.ycbcr420 { t.h_total } else { 0 };
        s.dst_y = dst_x / t.h_total;
        s.dst_x = dst_x - s.dst_y * t.h_total;

        let quarter = l.over(fx(4));
        let (y, c) = (&self.y, self.c.as_ref());
        let src = y.source_lines;
        let src_c = c.map_or(0, |c| c.source_lines);
        let src_max = src.max(src_c);
        let line_bytes = |u: &Surf| fx(i64::from(u.swath_ub * u.bpp));
        let sw_bytes = c.map_or(fx(src * i64::from(y.swath_ub * y.bpp)), |c| {
            fx(src * i64::from(y.swath_ub * y.bpp) + src_c * i64::from(c.swath_ub * c.bpp))
        });
        // One-to-one schedule, against this pipe's share of the surface's
        // active bandwidth.
        let min_lsw_oto = q(src_max, MAX_VRATIO_PRE_OTO).max(fx(2));
        let pipes = fx(i64::from(self.dpps));
        let per_pipe = c.map_or(y.vactive_bw.over(pipes), |c| {
            let bw = if mp { c.vactive_bw_mp } else { c.vactive_bw };
            y.vactive_bw.over(pipes).plus(bw.over(pipes))
        });
        let oto_line = c.map_or(line_bytes(y).over(l), |c| {
            line_bytes(y).over(l).plus(line_bytes(c).over(l))
        });
        let bw_oto = per_pipe
            .max(oto_line)
            .min(sw_bytes.over(min_lsw_oto.times(l)));
        let lsw_oto = ceil_quarter(sw_bytes.over(bw_oto).over(l));
        s.prefetch_bw_max = bw_oto;
        // VM and both row trips are one quarter line each.
        let dst_oto = q(3, 4).plus(lsw_oto);
        // Equalized schedule.
        let lo = s.dst_y;
        let min_lsw_equ = q(src_max, MAX_VRATIO_PRE_EQU).max(fx(2));
        let mut equ = fx(i64::from(s.vstartup))
            .minus(
                s.t_setup
                    .plus(t_calc.max(extra_prefetch))
                    .plus(t_wait_p)
                    .over(l),
            )
            .minus(fx(i64::from(lo)));
        if equ < Fx::ZERO {
            // No other plane impacts this one: the impacted schedule is zero.
            equ = equ.minus(Fx::ZERO.minus(equ));
        }
        equ = floor_quarter(equ.min(q(255, 4)).plus(q(1, 8)));
        let t_pre = equ.times(l);
        let lsw_equ_ok = t_pre >= quarter.times(fx(3)).plus(min_lsw_equ.times(l));
        let req_latency_ok = t_pre > urgent.max(trip).plus(extra_prefetch);
        if !(equ > Fx::ONE && lsw_equ_ok && req_latency_ok) {
            s.no_time = true;
            return s;
        }
        // Only the swath stage carries data, so prefetch_bw4 is the
        // equalized bandwidth (cases 1-3 need VM or row bytes).
        let bw_equ = sw_bytes.over(t_pre.minus(quarter.times(fx(3))));
        let dst = if dst_oto < equ {
            dst_oto
        } else {
            s.prefetch_bw_max = s.prefetch_bw_max.max(bw_equ);
            equ
        };
        let lsw = dst.minus(q(3, 4));
        if lsw < fx(2) || bw_equ <= Fx::ZERO {
            s.no_time = true;
            return s;
        }
        s.dst_y_prefetch = dst;
        // VRatioPrefetchY/C: the source lines over Lsw, and with swaths
        // taller than four lines and a prefill above three, every swath the
        // prefill spans within the lines after half the prefill's excess.
        let vratio = |u: Option<&Surf>| -> Option<Fx> {
            let Some(u) = u else {
                return Some(Fx::ZERO.max(Fx::ONE));
            };
            let mut v = fx(u.source_lines).over(lsw).max(Fx::ONE);
            if u.height > 4 && u.vinit > 3 {
                let excess = q(i64::from(u.vinit) - 3, 2);
                if lsw > excess {
                    v = v.max(fx(i64::from(u.max_num_swath * u.height)).over(lsw.minus(excess)));
                } else {
                    return None;
                }
            }
            Some(v)
        };
        let (Some(vy), Some(vc)) = (vratio(Some(y)), vratio(c)) else {
            s.no_time = true;
            return s;
        };
        s.vratio_pre = vy;
        s.vratio_pre_c = vc;
        s.prefetch_bw = fx(src)
            .over(lsw)
            .times(fx(i64::from(y.bpp * y.swath_ub)))
            .over(l);
        if let Some(c) = c {
            s.prefetch_bw_c = fx(src_c)
                .over(lsw)
                .times(fx(i64::from(c.bpp * c.swath_ub)))
                .over(l);
        }
        s
    }
}

/// The shared mode-support/mode-programming evaluation of every surface at
/// one state, each on its own pipe clocks. Latency and extra latency come
/// from `lat_state`; urgent bandwidth, summed over the surfaces, is checked
/// against `bw_state` (mode support uses the maximum clocks).
fn evaluate(
    shapes: &[Shape],
    lat_state: State,
    bw_state: State,
    uclk_khz: u64,
    clk: &[PipeClocks],
    reserved_us: i64,
) -> Result<Evaluation, Error> {
    let mp = clk[0].khz.is_some();
    let lat = latency(lat_state, uclk_khz);
    // CalculateExtraLatency: dcn4x, max outstanding when urgent expected
    // (of the largest request any surface makes); CalculateTarb: one pixel
    // chunk per DPP.
    let return_bw = {
        let a = available(lat_state).urgent[0];
        a[0].min(a[1])
    };
    let dpps: i64 = shapes.iter().map(|s| i64::from(s.dpps)).sum();
    let t_arb = fx(dpps * PIXEL_CHUNK_KBYTES * 1024).over(return_bw);
    let request = shapes
        .iter()
        .flat_map(Shape::surfaces)
        .map(|u| i64::from(u.request_bytes))
        .max()
        .unwrap_or(REQUEST_BYTES);
    let outstanding = fx(ROB_KBYTES * 1024 - MAX_OUTSTANDING_REQS * request).over(return_bw);
    let extra = outstanding.plus(t_arb);
    // Deep-sleep DCFCLK is global: every pipe carries the same value.
    let t_calc = fx(24).over(clk[0].deep_sleep);
    let t_wait = fx(reserved_us).plus(lat.urgent.max(lat.trip));
    let mut planes = [Schedule::default(); MAX_PLANES];
    let (mut urgent, mut non_urgent) = (Fx::ZERO, Fx::ZERO);
    let (mut urgent_dram, mut non_urgent_dram) = (Fx::ZERO, Fx::ZERO);
    for (k, shape) in shapes.iter().enumerate() {
        let pre = shape.prefetch(clk[k], &lat, t_wait, extra, t_calc, mp);
        // NotEnoughUrgentLatencyHiding for active fetch, then the schedule.
        let burst = shape
            .burst(&shape.y, lat.urgent, shape.y.vratio)
            .ok_or(Error::UrgentLatencyHiding)?;
        let burst_c = match &shape.c {
            Some(c) => Some(
                shape
                    .burst(c, lat.urgent, c.vratio)
                    .ok_or(Error::UrgentLatencyHiding)?,
            ),
            None => None,
        };
        if pre.no_time
            || pre.dst_y > 8
            || pre.dst_y_prefetch < fx(2)
            || pre.vratio_pre > fx(MAX_VRATIO_PRE)
            || pre.vratio_pre_c > fx(MAX_VRATIO_PRE)
        {
            return Err(Error::Prefetch);
        }
        let pre_burst = shape
            .burst(&shape.y, lat.urgent, pre.vratio_pre)
            .ok_or(Error::UrgentLatencyHiding)?;
        let pre_burst_c = match &shape.c {
            Some(c) => Some(
                shape
                    .burst(c, lat.urgent, pre.vratio_pre_c)
                    .ok_or(Error::UrgentLatencyHiding)?,
            ),
            None => None,
        };
        // calculate_peak_bandwidth_required (get_urgent_bandwidth_required):
        // no flip, VM, cursor or excess vactive fill; unity MALL factors and
        // DCC's DRAM overhead on DRAM only. Active bandwidth is the
        // surface's; prefetch is per pipe.
        let pipes = fx(i64::from(shape.dpps));
        let vbw_y = shape.y.vactive_bw;
        let vbw_c = shape.c.map_or(
            Fx::ZERO,
            |c| if mp { c.vactive_bw_mp } else { c.vactive_bw },
        );
        // One bandwidth sum: `bursts` (active, prefetch luma and chroma)
        // and the DRAM factors (nominal, prefetch luma and chroma).
        let required = |bursts: Option<[Fx; 4]>, nom: [Fx; 2], pref: [Fx; 2]| {
            let [b_y, b_c, pb_y, pb_c] = bursts.unwrap_or([Fx::ONE; 4]);
            let scale = |v: Fx, f: Fx| if f == Fx::ONE { v } else { v.times(f) };
            let (bpref_y, bpref_c) = (scale(pb_y, pref[0]), scale(pb_c, pref[1]));
            let (bnom_y, bnom_c) = (scale(b_y, nom[0]), scale(b_c, nom[1]));
            let chroma = shape.c.is_some();
            let with_c = |v: Fx, c: Fx| if chroma { v.plus(c) } else { v };
            let active = with_c(vbw_y.times(bnom_y), vbw_c.times(bnom_c));
            let prefetch = with_c(
                pre.prefetch_bw.times(bpref_y),
                pre.prefetch_bw_c.times(bpref_c),
            )
            .times(pipes);
            let prefetch_max = with_c(
                pre.prefetch_bw_max.times(bpref_y),
                pre.prefetch_bw_c.times(bpref_c),
            )
            .times(pipes);
            let excess = with_c(scale(vbw_y, nom[0]), scale(vbw_c, nom[1]));
            active.max(prefetch).max(prefetch_max).max(excess)
        };
        let bursts = [
            burst,
            burst_c.unwrap_or(Fx::ZERO),
            pre_burst,
            pre_burst_c.unwrap_or(Fx::ZERO),
        ];
        let unity = [Fx::ONE; 2];
        urgent = urgent.plus(required(Some(bursts), unity, unity));
        non_urgent = non_urgent.plus(required(None, unity, unity));
        urgent_dram = urgent_dram.plus(required(Some(bursts), shape.dram_nom, shape.dram_pref));
        non_urgent_dram = non_urgent_dram.plus(required(None, shape.dram_nom, shape.dram_pref));
        planes[k] = pre;
    }
    // check_urgent_bandwidth_support for sys-active and, with a MALL,
    // SVP-prefetch derates.
    let avail = available(bw_state);
    let mut frac = [Fx::ZERO; 2];
    for (state, a) in avail.urgent.iter().enumerate() {
        frac[state] = non_urgent.over(a[0]).max(non_urgent_dram.over(a[1]));
        if (state == 0 || MALL_PRESENT)
            && (urgent > a[0] || urgent_dram > a[1] || frac[state] > Fx::ONE)
        {
            return Err(Error::Bandwidth);
        }
    }
    Ok(Evaluation {
        planes,
        extra,
        extra_sr: t_arb,
        t_calc,
        t_wait,
        lat,
        frac_nom: frac[0],
        frac_mall: frac[1],
        non_urgent_sdp: non_urgent,
        urgent_sdp: urgent,
    })
}

impl Shape {
    /// CalculateWatermarksMALLUseAndDRAMSpeedChangeSupport: active latency
    /// hiding (the lesser of luma's and chroma's) against the GDDR6
    /// temperature-read watermark. With unbounded requesting the luma DET
    /// also counts the compressed buffer (`compbuf_bytes`).
    fn temp_read_ok(
        &self,
        e: &Evaluation,
        pre: &Schedule,
        surfaces: usize,
        compbuf_bytes: u32,
    ) -> bool {
        let unity = i64::from(Plane::UNITY);
        let hiding = |u: &Surf, det: u64| {
            // LBLatencyHidingSourceLines: the lines the line buffer holds of
            // the swath in source pixels, less the extra vertical taps (an
            // (unsigned int) of a double, so a negative count wraps).
            let h = i64::from(u.h_ratio).max(unity);
            let lb = (LINE_BUFFER_BITS / LB_BITS_PER_PIXEL * h / (i64::from(u.swath) * unity))
                .min(MAX_LINE_BUFFER_LINES)
                - (i64::from(u.v_taps) - 1);
            let lb_lines = i64::from(lb as u32);
            let det_lines = u.det_lines(det, u.swath) as i64;
            let mut hiding = fx(lb_lines + det_lines)
                .times(self.line)
                .over(u.vratio)
                .minus(
                    fx(i64::from(pre.dst_x))
                        .over(fx(i64::from(self.t.h_total)))
                        .plus(fx(i64::from(pre.dst_y)))
                        .times(self.line),
                );
            // Several surfaces each give up part of a swath.
            if surfaces > 1 {
                hiding = hiding.minus(
                    Fx::ONE
                        .minus(q(1, surfaces as i64))
                        .times(fx(i64::from(u.height)))
                        .times(self.line)
                        .over(u.vratio),
                );
            }
            hiding
        };
        let det_y = u64::from(self.y.det_bytes) + u64::from(compbuf_bytes);
        let mut hidden = hiding(&self.y, det_y);
        if let Some(c) = &self.c {
            hidden = hidden.min(hiding(c, u64::from(c.det_bytes)));
        }
        let urgent_wm = e.lat.urgent.plus(e.extra);
        hidden.minus(e.lat.g6_temp_read.plus(urgent_wm)) >= Fx::ZERO
    }
}

/// `dml2_mcg_dcn4` min-clock table for a single UCLK level with fine-grained
/// FCLK/DCFCLK, i.e. DML's fabric and DCF state for the pinned memory clock.
fn clock_state(soc: &Soc) -> Result<(u64, u64, u64), Error> {
    let bw_kbps = u64::from(soc.uclk_khz)
        * u64::from(soc.umc_channels)
        * CHANNEL_BYTES
        * TRANSACTIONS_PER_CLOCK;
    let derived = bw_kbps * URGENT_ACTIVE[2] as u64 * 100
        / (URGENT_ACTIVE[1] as u64 * 100)
        / RETURN_BUS_BYTES as u64;
    let fclk = (derived / 2)
        .max(u64::from(soc.fclk_khz[0]))
        .min(MAX_FCLK_FOR_UCLK_KHZ);
    let dcfclk = fclk * URGENT_ACTIVE[1] as u64 / URGENT_ACTIVE[0] as u64;
    if dcfclk > u64::from(soc.dcfclk_khz[1]) || fclk > u64::from(soc.fclk_khz[1]) {
        return Err(Error::ClockState);
    }
    Ok((dcfclk, fclk, bw_kbps))
}

/// dml2_dpmm_dcn4's calculate_system_active_minimums and
/// calculate_svp_prefetch_minimums: DPMM raises DCFCLK and FCLK above the
/// pinned UCLK's state (`clock_state`) when the mode-support average or
/// urgent SDP bandwidth, in whole kB/s over the 64-byte return path and
/// derated, needs more. Every value this port plans is computed at that
/// state, so a configuration that raises it is not planned here.
fn bandwidth_raises_clocks(e: &Evaluation, read: Fx, dcfclk_khz: u64, fclk_khz: u64) -> bool {
    // math_ceil2(bandwidth * 1000, 1).
    let kbps = |bw: Fx| bw.times(fx(1000)).ceil().max(0) as u128;
    let (urgent, average) = (kbps(e.urgent_sdp), kbps(read));
    // round_up(bw / 64 / (derate / 100)) > state, for a whole-kHz state.
    let over = |bw: u128, derate: i64, state: u64| {
        bw * 100 > u128::from(state) * RETURN_BUS_BYTES as u128 * derate as u128
    };
    [(0, dcfclk_khz), (1, fclk_khz)]
        .into_iter()
        .any(|(i, state)| {
            over(urgent, URGENT_ACTIVE[i], state)
                || over(average, AVERAGE_ACTIVE[i], state)
                || over(urgent, URGENT_PREFETCH[i], state)
                || over(average, AVERAGE_PREFETCH[i], state)
        })
}

/// `add_margin_and_round_to_dfs_grainularity` for a rational kHz request
/// `num / den`, returning the DFS output in kHz.
fn dfs(num: u128, den: u128, vco_khz: u32) -> Result<u32, Error> {
    let vco = u128::from(vco_khz);
    if num < den || num > vco * den {
        return Err(Error::PixelClock);
    }
    let divider = 4 * vco * den / num;
    // Like Linux, report vco * 4 / divider even where the DID saturates. A
    // saturated low DID runs faster than that, which is safe; below DID 8
    // (divide by 2) the hardware cannot reach the reported clock at all.
    if divider < 8 {
        return Err(Error::PixelClock);
    }
    Ok((vco * 4 / divider) as u32)
}

impl Soc {
    fn validate(&self) -> Result<(), Error> {
        if self.umc_channels == 0
            || self.umc_channels > 64
            || self.uclk_khz == 0
            || self.fclk_khz[0] == 0
            || self.fclk_khz[0] > self.fclk_khz[1]
            || self.dcfclk_khz[0] == 0
            || self.dcfclk_khz[0] > self.dcfclk_khz[1]
            || self.socclk_khz == 0
            || self.dispclk_max_khz == 0
            || self.dppclk_max_khz == 0
            || self.dentist_vco_khz < self.dispclk_max_khz
            || self.dentist_vco_khz < self.dppclk_max_khz
            || self.dchub_refclk_khz == 0
        {
            return Err(Error::Invalid);
        }
        // Far beyond any DCN4 clock; keeps every intermediate in range.
        let clocks = [
            self.uclk_khz,
            self.fclk_khz[1],
            self.dcfclk_khz[1],
            self.socclk_khz,
            self.dentist_vco_khz,
            self.dchub_refclk_khz,
        ];
        if clocks.iter().any(|&khz| khz > MAX_CLOCK_KHZ) || self.dchub_refclk_khz > 1_000_000 {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Admit `mode` on `soc`, returning its programming plan or the first DML
/// check it fails. Pure and deterministic: the same inputs give the same plan.
pub fn admit(soc: &Soc, mode: &Mode) -> Result<Plan, Error> {
    Ok(admit_all(soc, &[*mode])?[0])
}

/// Admit `modes` together, one stream each on one pipe or, where DML's ODM
/// policy splits it, two to four ([`Plan::pipes`]; an MPC-combined plane in
/// ODM bypass takes two DPPs, [`PlanePlan::dpps`]), returning their plans in order or
/// the first DML check the configuration fails. Every pipe keeps the fixed
/// DET, and the shared quantities are joint as in DML21: read and urgent
/// bandwidth sum over the surfaces (prefetch over each surface's pipes),
/// extra latency takes one pixel chunk per DPP, deep-sleep DCFCLK, DISPCLK
/// and DPPREFCLK cover every pipe, and stutter is budgeted only if every
/// stream's blank allows it. The global watermarks and arbiter are therefore
/// the same in every plan.
pub fn admit_all(soc: &Soc, modes: &[Mode]) -> Result<Vec<Plan>, Error> {
    admit_all_with(soc, modes, Policy::NATIVE)
}

/// What admission decides beyond DC's own inputs. DC leaves DCN401's
/// `mpcc_combine_factor` at auto; the factor-1 policy exists only to replay
/// reference vectors Linux planned with MPC combine forced off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// MPC-combine a plane in ODM bypass that one DPP cannot carry (two
    /// DPPs blended in its stream's MPCC tree, each with half the
    /// viewport), as DML's auto factor does; off is factor 1.
    pub mpc_combine: bool,
}
impl Policy {
    /// The native display path's policy: DC's.
    pub const NATIVE: Self = Self { mpc_combine: true };
}

/// `admit_all` for what the native display path lights: also refusing
/// (`Unsupported`) an ODM split whose horizontal timing the native OTG
/// cannot divide (`odm_timing_ok`). ValidateODMMode checks only the active
/// width against OTG_H_TIMING_DIV_MODE, leaving the other boundaries a
/// TODO; Linux plans such a stream.
pub fn admit_native(soc: &Soc, modes: &[Mode]) -> Result<Vec<Plan>, Error> {
    let plans = admit_all(soc, modes)?;
    if plans
        .iter()
        .any(|p| !odm_timing_ok(&p.mode.timing, u32::from(p.pipes), p.mode.ycbcr420))
    {
        return Err(Error::Unsupported);
    }
    Ok(plans)
}

/// Whether the native OTG takes stream `t` split `odm` ways (with 4:2:0
/// output when `ycbcr420`): every horizontal boundary a multiple of the
/// pixels per OTG clock (two for 2:1, four for 3:1 and 4:1; a 4:2:0 2:1
/// segment keeps whole pixel pairs), segments of
/// resource_get_odm_slice_dst_width within OPTC_SEGMENT_WIDTH, and at most
/// 4096 pixels per segment for its own ODM memories.
pub fn odm_timing_ok(t: &Timing, odm: u32, ycbcr420: bool) -> bool {
    if odm < 2 {
        return true;
    }
    let div = if odm > 2 { 4 } else { 2 };
    let start = t.h_total.wrapping_sub(t.h_front_porch);
    let end = start.wrapping_sub(t.h_active);
    let width = t.h_active / odm;
    let width = width + (width & 1 & u32::from(ycbcr420));
    let last = t.h_active.saturating_sub(width * (odm - 1));
    !(ycbcr420 && t.h_active % (2 * div) != 0)
        && [t.h_active, t.h_total, t.h_sync_width, start, end]
            .iter()
            .all(|v| v % div == 0)
        && width <= 0x1fff
        && last <= 0x1fff
        && t.h_active <= 4096 * odm
}

/// DML's max_dispclk/dppclk_freq_mhz: a board maximum less downspread.
fn ss_khz(khz: u32) -> u64 {
    u64::from(khz) * 10_000 / DOWNSPREAD_TENTHOUSANDTHS as u64
}

/// `admit_all` under `policy`. MPC combine only ever admits what factor 1
/// rejects, so a plan admitted without it re-admits unchanged.
///
/// dml2_top_soc15_build_mode_programming's mcache phase follows mode
/// support whatever the policy: when a supported configuration has a DCC
/// plane whose pipes cannot place its mcaches
/// (dml2_top_mcache_validate_admissability), pmo_dcn4_fams2_optimize_dcc_
/// mcache (no dynamic ODM: optimize_dcc_mcache_no_odm) gives each such
/// plane one more DPP from the free pipes, up to `mpc_combine_limit`, and
/// mode support runs again with those planes MPC-combined. A failing plane
/// on an ODM stream, at the limit or without a free pipe is rejected.
pub fn admit_all_with(soc: &Soc, modes: &[Mode], policy: Policy) -> Result<Vec<Plan>, Error> {
    soc.validate()?;
    if modes.is_empty() || modes.len() > MAX_STREAMS {
        return Err(Error::Invalid);
    }
    // The planes the mcache phase has put on two DPPs (factor 2).
    let mut split = [false; MAX_PLANES];
    loop {
        let shapes = shapes_for(soc, modes, policy, &split)?;
        if shapes.iter().all(|s| s.mcache_fits) {
            return plan_shapes(soc, modes, shapes, false);
        }
        // The mcache phase starts from a configuration mode support takes.
        plan_shapes(soc, modes, shapes.clone(), true)?;
        let used = shapes.iter().map(|s| s.dpps).sum::<u32>();
        let mut free = MAX_PIPES.saturating_sub(used);
        for (k, s) in shapes.iter().enumerate() {
            if s.mcache_fits {
                continue;
            }
            if s.odm > 1 || s.dpps >= MPC_COMBINE_LIMIT || free == 0 {
                return Err(Error::Unsupported);
            }
            split[k] = true;
            free -= 1;
        }
    }
}

/// Every plane's shape in admission order: its ODM split, then MPC combine
/// as `policy` decides it or (`split`) the mcache phase forces it.
fn shapes_for(
    soc: &Soc,
    modes: &[Mode],
    policy: Policy,
    split: &[bool; MAX_PLANES],
) -> Result<Vec<Shape>, Error> {
    let ss = ss_khz;
    let mut shapes = Vec::with_capacity(MAX_PLANES);
    for (k, mode) in modes.iter().enumerate() {
        for plane in mode.plane_list() {
            if shapes.len() == MAX_PLANES {
                return Err(Error::Pipes);
            }
            let mut shape = Shape::new(mode, plane, k, ss(soc.dispclk_max_khz), soc.umc_channels)?;
            if split[shapes.len()] && shape.odm == 1 {
                shape = Shape::with_pipes(mode, plane, k, 1, MPC_COMBINE_LIMIT, soc.umc_channels)?;
            } else if policy.mpc_combine {
                shape = shape.mpc_combined(mode, ss(soc.dppclk_max_khz), soc.umc_channels)?;
            }
            shape.buffers()?;
            shapes.push(shape);
        }
    }
    Ok(shapes)
}

/// Mode support and (unless `support_only`, which returns no plans) mode
/// programming of `shapes`.
fn plan_shapes(
    soc: &Soc,
    modes: &[Mode],
    mut shapes: Vec<Shape>,
    support_only: bool,
) -> Result<Vec<Plan>, Error> {
    let ss = ss_khz;
    // TotalAvailablePipesSupport: one DPP per plane and ODM segment or MPC
    // slice.
    // dcn401_resource_construct removes CC_DC_PIPE_DIS-fused pipes.
    let dpps = shapes.iter().map(|s| s.dpps).sum::<u32>();
    if dpps > MAX_PIPES.min(crate::amdgpu_rdna4::available_pipes()) {
        return Err(Error::Pipes);
    }
    // dml2_top_mcache_calc_mcache_count_and_offsets: every DCC plane's
    // mcaches within the SoC's num_dcc_mcaches.
    if shapes.iter().map(|s| s.mcaches).sum::<u32>() > DCC_MCACHES {
        return Err(Error::Unsupported);
    }
    // dml2_top_mcache_assign_global_mcache_ids: ascending over the DCC
    // planes, luma then chroma; the pseudo-last slice wraps to the first,
    // and a shared last chroma slice takes luma's last id.
    let mut next_id = 0u8;
    for a in shapes.iter_mut().filter_map(|s| s.mcache.as_mut()) {
        for i in 0..2 {
            let count = usize::from(a.count[i]).min(3);
            for j in 0..count {
                a.ids[i][j] = next_id;
                next_id += 1;
            }
            a.ids[i][count] = a.ids[i][0];
        }
        let (c0, c1) = (usize::from(a.count[0]), usize::from(a.count[1]));
        if a.shared && c0 > 0 && c1 > 0 {
            a.ids[1][c1 - 1] = a.ids[0][c0 - 1];
        }
    }
    // UnboundedRequest: one DPP in all, tiled and without chroma. The
    // compressed buffer then takes the CRB beyond the DET
    // (CalculateDETBufferSize); otherwise DML's minimum.
    let unbounded = dpps == 1
        && shapes
            .iter()
            .all(|s| s.c.is_none() && s.plane.swizzle != Swizzle::Linear);
    let compbuf_kbytes = if unbounded {
        CONFIG_RETURN_KBYTES - DET_KBYTES
    } else {
        SEGMENT_KBYTES
    };
    let compbuf_bytes = if unbounded { compbuf_kbytes * 1024 } else { 0 };
    let (dcfclk_khz, fclk_khz, bw_kbps) = clock_state(soc)?;
    let state = State {
        dcfclk: mhz(dcfclk_khz),
        fclk: mhz(fclk_khz),
        uclk: mhz(u64::from(soc.uclk_khz)),
        dram_bw: mhz(bw_kbps),
    };
    let max_state = State {
        dcfclk: mhz(u64::from(soc.dcfclk_khz[1])),
        fclk: mhz(u64::from(soc.fclk_khz[1])),
        ..state
    };
    let uclk_khz = u64::from(soc.uclk_khz);
    // Mode support: DISPCLK is the pixel clock over the stream's pipes,
    // each plane's DPPCLK that or what its scaler needs; both are checked
    // against the downspread-limited maximums. DISPCLK is the fastest
    // stream's, DPPREFCLK the fastest plane's.
    for s in &shapes {
        let pclk = u64::from(s.t.pixel_clock_khz);
        let dpps = u64::from(s.dpps);
        let dpp_over = if s.dpp_unit {
            pclk > dpps * ss(soc.dppclk_max_khz)
        } else {
            s.dpp > ss(soc.dppclk_max_khz) as f64 / 1000.0
        };
        let disp = u64::from(disp_divider(s.odm, s.ycbcr420));
        if pclk > disp * ss(soc.dispclk_max_khz) || dpp_over {
            return Err(Error::PixelClock);
        }
    }
    let max_dpp_khz = shapes.iter().map(Shape::dpp_khz).max().unwrap_or(0);
    let max_disp_khz = shapes.iter().map(Shape::disp_khz).max().unwrap_or(0);
    let ds = deep_sleep(&shapes, false);
    // Outstanding-request coverage at DML's DCF state, for every surface's
    // request size.
    let lat = latency(state, uclk_khz);
    for u in shapes.iter().flat_map(Shape::surfaces) {
        let outstanding_us = fx(MAX_OUTSTANDING_REQS * i64::from(u.request_bytes))
            .over(state.dcfclk.times(fx(RETURN_BUS_BYTES)));
        if outstanding_us < lat.avg_urgent || outstanding_us < lat.avg_non_urgent {
            return Err(Error::Latency);
        }
    }
    // Average bandwidth at maximum clocks (calculate_avg_bandwidth_required:
    // DCC's nominal overhead on DRAM).
    let read = shapes
        .iter()
        .fold(Fx::ZERO, |sum, s| sum.plus(s.vactive_bw(false)));
    let read_dram = shapes.iter().fold(Fx::ZERO, |sum, s| {
        let scale = |v: Fx, f: Fx| if f == Fx::ONE { v } else { v.times(f) };
        let c = s.c.map_or(Fx::ZERO, |c| scale(c.vactive_bw, s.dram_nom[1]));
        sum.plus(scale(s.y.vactive_bw, s.dram_nom[0]).plus(c))
    });
    for a in available(max_state).average {
        if read > a[0] || read_dram > a[1] {
            return Err(Error::Bandwidth);
        }
    }
    let max_disp = shapes.iter().fold(Fx::ZERO, |max, s| max.max(s.disp_mhz()));
    let support = |reserved_us: i64| -> Result<Evaluation, Error> {
        let clk: Vec<PipeClocks> = shapes
            .iter()
            .map(|s| PipeClocks {
                dpp: s.dpp_mhz(),
                disp: max_disp,
                deep_sleep: ds,
                khz: None,
            })
            .collect();
        let e = evaluate(&shapes, state, max_state, uclk_khz, &clk, reserved_us)?;
        let rob = fx((ROB_KBYTES - PIXEL_CHUNK_KBYTES) * 1024).over(e.non_urgent_sdp);
        if rob < e.lat.max_urgent {
            return Err(Error::Latency);
        }
        for (shape, pre) in shapes.iter().zip(e.planes.iter()) {
            if !shape.temp_read_ok(&e, pre, shapes.len(), compbuf_bytes) {
                return Err(Error::TempRead);
            }
        }
        Ok(e)
    };
    let unreserved = support(0)?;
    // dml2_pmo_dcn4_fams2 stutter candidate (no Z8 on DCN401): every
    // stream's nominal blank must be three times its cost.
    let blank_allows = shapes.iter().all(|s| {
        let vblank_us_x1000 = i64::from(s.t.h_total) * i64::from(s.vblank) * 1_000_000
            / i64::from(s.t.pixel_clock_khz);
        vblank_us_x1000 >= SR_ENTER_PLUS_EXIT_US * MIN_BLANK_STUTTER_FACTOR * 1000
    });
    let (reserved_us, supported) = match blank_allows
        .then(|| support(SR_ENTER_PLUS_EXIT_US).ok())
        .flatten()
    {
        Some(e) => (SR_ENTER_PLUS_EXIT_US, e),
        None => (0, unreserved),
    };
    if support_only {
        return Ok(Vec::new());
    }
    if bandwidth_raises_clocks(&supported, read, dcfclk_khz, fclk_khz) {
        return Err(Error::ClockState);
    }

    // dml2_dpmm_dcn4: DISPCLK gets downspread and ramp margin, DPPREFCLK
    // downspread only; both land on DFS steps, each pipe's DPPCLK on 1/255ths
    // of the shared DPPREFCLK.
    let (sp, sp_den) = (DOWNSPREAD_TENTHOUSANDTHS as u128, 10_000u128);
    let (ramp, ramp_den) = ((100 + DISPCLK_RAMP_MARGIN_PERCENT) as u128, 100u128);
    let req = u128::from(max_disp_khz);
    let disp_max = u128::from(soc.dispclk_max_khz);
    let (mut num, mut den) = (req * sp * ramp, sp_den * ramp_den);
    if num > disp_max * den {
        (num, den) = (disp_max, 1);
    }
    if num * sp_den < req * sp * den {
        (num, den) = (req * sp, sp_den);
    }
    let dispclk_khz = dfs(num, den, soc.dentist_vco_khz)?;
    let dpp_ref = (u128::from(max_dpp_khz) * sp / sp_den) as u32;
    let dpprefclk_khz = dfs(u128::from(dpp_ref), 1, soc.dentist_vco_khz)?;
    if dispclk_khz > soc.dispclk_max_khz || dpprefclk_khz > soc.dppclk_max_khz {
        return Err(Error::PixelClock);
    }
    let dppclk_khz: Vec<u32> = shapes
        .iter()
        .map(|s| {
            let own = u128::from(s.dpp_khz());
            let steps = (own * sp * 255).div_ceil(sp_den * u128::from(dpprefclk_khz));
            (u128::from(dpprefclk_khz) * steps / 255) as u32
        })
        .collect();
    let deep_sleep_khz = deep_sleep_khz(&shapes);

    // Mode programming at the chosen clocks.
    let dispclk = mhz(u64::from(dispclk_khz));
    let ds = mhz(u64::from(deep_sleep_khz));
    // Linux fails mode programming as a whole; keep the specific reason.
    let clk: Vec<PipeClocks> = dppclk_khz
        .iter()
        .map(|&khz| PipeClocks {
            dpp: mhz(u64::from(khz)),
            disp: dispclk,
            deep_sleep: ds,
            khz: Some([khz, dispclk_khz, deep_sleep_khz]),
        })
        .collect();
    let e = evaluate(&shapes, state, state, uclk_khz, &clk, reserved_us)?;

    // Global watermarks and arbiter.
    let urgent_wm = e.lat.urgent.plus(e.extra);
    let sr_tail = e
        .extra_sr
        .plus(fx(10).over(ds))
        .plus(e.lat.max_urgent)
        .plus(e.lat.df_response);
    let dram_wm = fx(DRAM_CLK_CHANGE_US).plus(urgent_wm);
    let refclk = mhz(u64::from(soc.dchub_refclk_khz));
    let ref_khz = i64::from(soc.dchub_refclk_khz);
    let refcyc = |us: Fx| reg(us.times(refclk));
    // min_return_latency_in_DCFCLK uses the table maxima and DML's DCF state.
    let max_uclk = mhz(uclk_khz);
    let max_fclk = mhz(u64::from(soc.fclk_khz[1]));
    let min_return = fx(MIN_RETURN_UCLK_CYCLES)
        .over(max_uclk)
        .plus(fx(MIN_RETURN_FCLK_CYCLES).over(max_fclk))
        .times(state.dcfclk);
    let hysteresis = fx(PIXEL_CHUNK_KBYTES * 1024 * 3 / 4 / 64)
        .minus(min_return)
        .max(fx(32));
    // compbuf_reserved_space_64b: two pixel chunks, or with unbounded
    // requesting what the ROB leaves beyond eight luma swaths.
    let mut compbuf_reserved_64b = 2 * PIXEL_CHUNK_KBYTES * 1024 / 64;
    if unbounded {
        let swath = i64::from(shapes[0].y.rounded_swath_bytes);
        compbuf_reserved_64b = compbuf_reserved_64b.max(ROB_KBYTES * 1024 / 64 - swath * 8 / 64);
    }
    // hw_debug5 (ALLOW_SDPIF_RATE_LIMIT_PRE_CSTATE): several surfaces.
    let hw_debug5 = shapes.len() > 1;
    let watermarks = Watermarks {
        urgent: refcyc(urgent_wm),
        sr_enter: refcyc(fx(SR_ENTER_PLUS_EXIT_US).plus(sr_tail)),
        sr_exit: refcyc(fx(SR_EXIT_US).plus(sr_tail)),
        uclk_pstate: refcyc(dram_wm),
        fclk_pstate: refcyc(urgent_wm),
        temp_read: refcyc(e.lat.g6_temp_read.plus(urgent_wm)),
        usr: refcyc(urgent_wm),
        refcyc_per_trip_to_mem: refcyc(urgent_wm),
        refcyc_per_meta_trip_to_mem: refcyc(urgent_wm),
        frac_urg_bw_flip: reg(e.frac_nom.times(fx(1000))),
        frac_urg_bw_nom: reg(e.frac_nom.times(fx(1000))),
        frac_urg_bw_mall: reg(e.frac_mall.times(fx(1000))),
    };
    let arbiter = Arbiter {
        max_req_outstanding: MAX_OUTSTANDING_REQS as u32,
        min_req_outstanding: MAX_OUTSTANDING_REQS as u32,
        sat_level_us: 60,
        compbuf_reserved_space_kbytes: (compbuf_reserved_64b * 64 / 1024) as u32,
        compbuf_segments: compbuf_kbytes / SEGMENT_KBYTES,
        sdpif_request_rate_limit: (3 * WORDS_PER_CHANNEL * soc.umc_channels / 4).max(96),
        dcfclk_deep_sleep_hysteresis: hysteresis.floor() as u32,
        pstate_stall_threshold: (MAX_ALLOW_DELAY_US * ref_khz / 1000) as u32,
        hvm_max_qos_commit_threshold: 0xf,
        hvm_min_req_outstand_commit_threshold: 0xa,
        allow_sdpif_rate_limit_when_cstate_req: hw_debug5,
    };
    let mut streams = [None; MAX_STREAMS];
    for (slot, mode) in streams.iter_mut().zip(modes) {
        *slot = Some(*mode);
    }

    // Each plane's DLG and TTU (rq_dlg_get_dlg_reg), then each stream's
    // plan from its first plane.
    let mut per_plane: Vec<(GlobalSync, PlanePlan)> = Vec::with_capacity(shapes.len());
    for (k, shape) in shapes.iter().enumerate() {
        let t = shape.t;
        let pre = e.planes[k];
        let l = shape.line;
        let pclk_i = i64::from(t.pixel_clock_khz);
        let min_ttu = e.t_wait.plus(e.extra).plus(e.t_calc);
        let vstartup = pre.vstartup;
        let blank_after = shape.vblank - vstartup;
        let vblank_start = t.v_total - t.v_front_porch;
        let l_setup = floor_quarter(pre.t_setup.over(l));
        let min_next = fx(i64::from(vblank_start + blank_after)).plus(l_setup);
        let vready_lines =
            i64::from(t.v_total - t.v_active - t.v_front_porch) - i64::from(vstartup);
        let vready_after = i64::from(pre.vupdate_offset + pre.vupdate_width + pre.vready_offset)
            <= vready_lines * i64::from(t.h_total);
        let keepout = (dram_wm.over(l).ceil() as u32).min(t.v_total - 1);
        // CalculatePixelDeliveryTimes: at a vertical ratio up to 1 a pipe
        // delivers its swath in its pipes' share of the line time at the
        // horizontal ratio (whole pixel counts over the pixel clock: exact);
        // above it at the scaler's throughput, in Linux's doubles.
        let odm = i128::from(shape.dpps);
        let unity = i128::from(Plane::UNITY);
        let ref_mhz = f64::from(soc.dchub_refclk_khz) / 1000.0;
        let dpp_mhz = f64::from(dppclk_khz[k]) / 1000.0;
        // One surface's line and request delivery (refcyc, and refcyc
        // in 1/1024ths per request).
        let delivery = |u: &Surf, above_one: bool| -> (u32, u32) {
            if above_one {
                let line = f64::from(u.swath_ub) / u.pscl / dpp_mhz;
                let req_per_swath = f64::from(u.swath_ub / u.req_w);
                (
                    (line * ref_mhz) as u32,
                    (line / req_per_swath * ref_mhz * 1024.0) as u32,
                )
            } else {
                let den = i128::from(u.h_ratio) * i128::from(pclk_i);
                (
                    (i128::from(u.swath_ub) * odm * unity * i128::from(ref_khz) / den) as u32,
                    (i128::from(u.req_w) * odm * unity * 1024 * i128::from(ref_khz) / den) as u32,
                )
            }
        };
        let y = &shape.y;
        let (line_delivery, refcyc_req) = delivery(y, y.v_ratio > Plane::UNITY);
        let (line_delivery_pre, refcyc_req_pre) = delivery(y, pre.vratio_pre > Fx::ONE);
        let ((line_c, req_c), (line_pre_c, req_pre_c)) = match &shape.c {
            Some(c) => (
                delivery(c, c.v_ratio > Plane::UNITY),
                delivery(c, pre.vratio_pre_c > Fx::ONE),
            ),
            None => ((0, 0), (0, 0)),
        };
        // rq_dlg_get_rq_reg: 8 KiB chunks with a 1 KiB minimum, no groups
        // or meta without GPUVM and MRQ, log2 swath heights, and a 4:2:0
        // DET's chroma half (or third, for a luma part over 1.5 times it).
        let rq_plane = |height: u32| RqPlane {
            chunk_size: (PIXEL_CHUNK_KBYTES as u32 * 1024).ilog2() - 10,
            min_chunk_size: MIN_PIXEL_CHUNK_BYTES.ilog2() - 7,
            swath_height: if height == 0 { 0 } else { height.ilog2() },
            ..RqPlane::default()
        };
        let plane1_base_address = match &shape.c {
            None => 0,
            Some(c) => {
                if 2 * u64::from(y.det_bytes) <= 3 * u64::from(c.det_bytes) {
                    shape.det_bytes / 2 / 1024
                } else {
                    shape.det_bytes * 2 / 3 / 1024
                }
            }
        };
        let rq = RqRegs {
            luma: rq_plane(y.height),
            chroma: rq_plane(shape.c.map_or(0, |c| c.height)),
            drq_expansion_mode: 2,
            prq_expansion_mode: 1,
            mrq_expansion_mode: 1,
            crq_expansion_mode: 1,
            plane1_base_address,
            unbounded_request_enabled: unbounded,
        };
        // rq_dlg_get_dlg_reg: each further ODM pipe's blank ends the
        // segments before it later (hactive / odm_combine_factor each).
        let odm_i = i64::from(shape.odm);
        let h_blank_end = |pipe: u32| {
            ((i64::from(t.h_blank_end()) * odm_i + i64::from(pipe) * i64::from(t.h_active))
                * ref_khz
                / (pclk_i * odm_i)) as u32
        };
        let sync = GlobalSync {
            vstartup,
            vupdate_offset: pre.vupdate_offset,
            vupdate_width: pre.vupdate_width,
            vready_offset: pre.vready_offset,
            pstate_keepout: keepout,
        };
        per_plane.push((
            sync,
            PlanePlan {
                dppclk_khz: dppclk_khz[k],
                dlg: Dlg {
                    refcyc_h_blank_end: h_blank_end(0),
                    dlg_vblank_end: t.v_blank_end(),
                    min_dst_y_next_start: (min_next.floor() as u32) * 4,
                    refcyc_per_htotal: (i64::from(t.h_total) * ref_khz * 256 / pclk_i) as u32,
                    refcyc_x_after_scaler: (i64::from(pre.dst_x) * ref_khz / pclk_i) as u32,
                    dst_y_after_scaler: pre.dst_y,
                    dst_y_prefetch: reg(pre.dst_y_prefetch.times(fx(4))),
                    dst_y_per_vm_vblank: 1,
                    dst_y_per_row_vblank: 1,
                    ref_freq_to_pix_freq: ((ref_khz << 19) / pclk_i) as u32,
                    vratio_prefetch: reg(pre.vratio_pre.times(fx(1 << 19))),
                    vratio_prefetch_c: reg(pre.vratio_pre_c.times(fx(1 << 19))),
                    refcyc_per_line_delivery_pre_l: line_delivery_pre,
                    refcyc_per_line_delivery_l: line_delivery,
                    refcyc_per_line_delivery_pre_c: line_pre_c,
                    refcyc_per_line_delivery_c: line_c,
                    vready_after_vcount0: vready_after,
                    dst_y_delta_drq_limit: 0x7fff,
                    dmdata_dl_delta: refcyc(pre.t_dmdl),
                },
                ttu: Ttu {
                    qos_level_low_wm: 0,
                    qos_level_high_wm: (4 * i64::from(t.h_total) * ref_khz / pclk_i) as u32,
                    min_ttu_vblank: refcyc(min_ttu),
                    qos_level_flip: 14,
                    refcyc_per_req_delivery_l: refcyc_req,
                    refcyc_per_req_delivery_pre_l: refcyc_req_pre,
                    refcyc_per_req_delivery_c: req_c,
                    refcyc_per_req_delivery_pre_c: req_pre_c,
                    qos_level_fixed_l: 8,
                    qos_level_fixed_c: 8,
                },
                det_bytes: shape.det_bytes,
                odm_refcyc_h_blank_end: core::array::from_fn(|i| {
                    let pipe = i as u32 + 1;
                    if pipe < shape.odm {
                        h_blank_end(pipe)
                    } else {
                        0
                    }
                }),
                dpps: shape.dpps as u8,
                rq,
                mcache: shape.mcache,
            },
        ));
    }

    let mut plans = Vec::with_capacity(modes.len());
    for (k, mode) in modes.iter().enumerate() {
        let mut planes = [None; MAX_PLANES];
        let mine = shapes
            .iter()
            .zip(&per_plane)
            .filter(|(s, _)| s.stream == k)
            .map(|(_, p)| *p);
        let mut first: Option<(GlobalSync, PlanePlan)> = None;
        for (slot, (sync, p)) in planes.iter_mut().zip(mine) {
            first.get_or_insert((sync, p));
            *slot = Some(p);
        }
        let (sync, p0) = first.ok_or(Error::Invalid)?;
        let odm = shapes.iter().find(|s| s.stream == k).map_or(1, |s| s.odm);
        let plan = Plan {
            mode: *mode,
            soc: *soc,
            clocks: Clocks {
                dispclk_khz,
                dpprefclk_khz,
                dppclk_khz: p0.dppclk_khz,
                deep_sleep_dcfclk_khz: deep_sleep_khz,
                dcfclk_khz: dcfclk_khz as u32,
                fclk_khz: fclk_khz as u32,
                uclk_khz: soc.uclk_khz,
                socclk_khz: soc.socclk_khz,
            },
            sync,
            dlg: p0.dlg,
            ttu: p0.ttu,
            watermarks,
            arbiter,
            det_bytes: p0.det_bytes,
            pipes: odm as u8,
            odm_refcyc_h_blank_end: p0.odm_refcyc_h_blank_end,
            stutter_reserved_us: reserved_us as u32,
            // The plan's own mode is `mode`; the others are kept for
            // `joint_modes` (records stay small: plans are copied a lot).
            streams: {
                let mut others = [None; MAX_STREAMS - 1];
                for (slot, m) in others
                    .iter_mut()
                    .zip(streams.iter().enumerate().filter(|&(n, _)| n != k))
                {
                    *slot = *m.1;
                }
                others
            },
            stream: k as u8,
            planes,
        };
        plan.check_ranges()?;
        plans.push(plan);
    }
    Ok(plans)
}

impl Plan {
    /// The DLG of the stream's pipe `pipe` (0-based, in ODM segment order,
    /// left to right), or `None` past the stream's pipes.
    pub fn pipe_dlg(&self, pipe: u8) -> Option<Dlg> {
        self.plane_dlg(0, pipe)
    }
    /// The DLG of plane `plane`'s pipe `pipe` (as `pipe_dlg`; an
    /// MPC-combined plane's pipes in slice order, all alike).
    pub fn plane_dlg(&self, plane: usize, pipe: u8) -> Option<Dlg> {
        let p = self.planes.get(plane).copied().flatten()?;
        if pipe >= p.dpps {
            return None;
        }
        if pipe == 0 || self.pipes == 1 {
            return Some(p.dlg);
        }
        Some(Dlg {
            refcyc_h_blank_end: p.odm_refcyc_h_blank_end[usize::from(pipe) - 1],
            ..p.dlg
        })
    }
    /// Plane `plane`'s share of the plan.
    pub fn plane(&self, plane: usize) -> Option<PlanePlan> {
        self.planes.get(plane).copied().flatten()
    }
    /// The configuration this plan was admitted in.
    pub fn joint_modes(&self) -> Vec<Mode> {
        let mut modes: Vec<Mode> = self.streams.iter().flatten().copied().collect();
        let at = usize::from(self.stream).min(modes.len());
        modes.insert(at, self.mode);
        modes
    }
    /// Whether admitting this plan's configuration again yields this plan:
    /// it was produced by [`admit_all`] from its recorded inputs.
    pub fn readmits(&self) -> bool {
        // Compared in place: plans are large, and this runs deep in the
        // deadline binding of every scanout operation.
        admit_all(&self.soc, &self.joint_modes())
            .is_ok_and(|plans| plans.get(usize::from(self.stream)) == Some(self))
    }
    /// Every programmed value must fit its dcn_4_1_0 register field. Linux
    /// only asserts these; a plan that cannot be programmed exactly is
    /// rejected here instead of being silently truncated.
    fn check_ranges(&self) -> Result<(), Error> {
        let (w, a) = (&self.watermarks, &self.arbiter);
        let global = [
            (w.urgent, 1 << 14),
            (w.usr, 1 << 14),
            (w.refcyc_per_trip_to_mem, 1 << 14),
            (w.refcyc_per_meta_trip_to_mem, 1 << 14),
            (w.sr_enter, 1 << 16),
            (w.sr_exit, 1 << 16),
            (w.uclk_pstate, 1 << 16),
            (w.fclk_pstate, 1 << 16),
            (w.temp_read, 1 << 16),
            (w.frac_urg_bw_nom, 1 << 10),
            (w.frac_urg_bw_flip, 1 << 10),
            (w.frac_urg_bw_mall, 1 << 10),
            (a.sdpif_request_rate_limit, 1 << 12),
            (a.pstate_stall_threshold, 1 << 27),
        ];
        let per_plane = |p: &PlanePlan| {
            let (d, t) = (&p.dlg, &p.ttu);
            [
                (d.refcyc_h_blank_end, 1 << 13),
                (p.odm_refcyc_h_blank_end[0], 1 << 13),
                (p.odm_refcyc_h_blank_end[1], 1 << 13),
                (p.odm_refcyc_h_blank_end[2], 1 << 13),
                (d.dlg_vblank_end, 1 << 15),
                (d.min_dst_y_next_start, 1 << 18),
                (d.refcyc_per_htotal, 1 << 21),
                (d.refcyc_x_after_scaler, 1 << 13),
                (d.dst_y_after_scaler, 8),
                (d.dst_y_prefetch, 1 << 8),
                (d.dst_y_per_vm_vblank, 1 << 7),
                (d.dst_y_per_row_vblank, 1 << 6),
                (d.ref_freq_to_pix_freq, 1 << 21),
                (d.vratio_prefetch, 1 << 22),
                (d.vratio_prefetch_c, 1 << 22),
                (d.refcyc_per_line_delivery_pre_l, 1 << 13),
                (d.refcyc_per_line_delivery_l, 1 << 13),
                (d.refcyc_per_line_delivery_pre_c, 1 << 13),
                (d.refcyc_per_line_delivery_c, 1 << 13),
                (t.refcyc_per_req_delivery_pre_c, 1 << 23),
                (t.refcyc_per_req_delivery_c, 1 << 23),
                (t.qos_level_high_wm, 1 << 14),
                (t.min_ttu_vblank, 1 << 24),
                (t.qos_level_flip, 1 << 4),
                (t.refcyc_per_req_delivery_pre_l, 1 << 23),
                (t.refcyc_per_req_delivery_l, 1 << 23),
                (t.qos_level_fixed_l, 1 << 4),
            ]
        };
        let over = |limits: &[(u32, u32)]| limits.iter().any(|&(v, limit)| v >= limit);
        if over(&global) || self.planes.iter().flatten().any(|p| over(&per_plane(p))) {
            return Err(Error::Register);
        }
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_dml_tests.rs"]
mod tests;
