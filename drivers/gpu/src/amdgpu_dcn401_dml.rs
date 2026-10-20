//! Native DCN4.0.1 scanout admission for up to four pipes: the DML21 mode-support and
//! mode-programming path that Linux runs for Navi48 (`dml2_core_dcn4_calcs.c`,
//! `dml2_dpmm_dcn4.c`, `dml2_mcg_dcn4.c`, `dml2_pmo_dcn4_fams2.c` stutter
//! reservation), reduced to the one configuration the native scanout path
//! implements and evaluated in fixed point.
//!
//! The admitted shape is up to four streams with progressive fixed timing,
//! each with one unscaled, unrotated, full-frame linear RGB plane of 2, 4 or
//! 8 bytes per pixel (DML's `dml2_444_16`, `dml2_444_32`, `dml2_444_64`)
//! in physical VRAM: GPUVM/HostVM, DCC, MALL/SubVP, cursor, tdlut, dynamic
//! metadata, writeback, MPC combine and immediate flip are all off; a 4:4:4
//! DP stream may use DSC.
//!
//! ODM is DML's `dml2_odm_mode_auto` with dynamic ODM off (DecideODMMode),
//! limited to bypass and 2:1: a stream takes two pipes (DPP + OPP each, one
//! DSC each) when its pixel clock exceeds the downspread-limited DISPCLK
//! maximum, its DSC line is wider than 5760 pixels or has more than four
//! slices, or its 4:2:0 line is wider than 4096 pixels. Each pipe then fetches
//! half the line at half the pixel clock; ValidateODMMode's even-split, slice
//! and width limits apply. A stream DML would split 3:1 or 4:1 is rejected,
//! and so is a configuration needing more than four pipes in all. A two-pipe
//! [`Plan`] carries both pipes' values: they differ only in the DLG blank end.
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
    /// A shape outside the admitted configuration, including a stream DML
    /// would split 3:1 or 4:1 or one ODM 2:1 cannot divide evenly.
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
    /// (an ODM 2:1 stream takes two).
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

/// One linear RGB plane of a stream as DC passes DML21 a plane state after
/// SPL: its surface, SPL's whole-plane viewport (DC hands DML the plane's
/// scaler data as if no ODM split it), the scale ratios and taps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plane {
    pub surface_width: u32,
    pub surface_height: u32,
    /// Surface pitch in pixels.
    pub pitch: u32,
    /// 2, 4 or 8 (`dml2_444_16`, `dml2_444_32`, `dml2_444_64`).
    pub bytes_per_pixel: u32,
    pub viewport_width: u32,
    pub viewport_height: u32,
    /// Input over output in units of 2^-19 (SPL's U3.19 ratios, which DC
    /// converts to the doubles DML takes exactly); `Plane::UNITY` is 1:1.
    pub h_ratio: u32,
    pub v_ratio: u32,
    pub h_taps: u32,
    pub v_taps: u32,
}

impl Plane {
    pub const UNITY: u32 = 1 << 19;
    /// The unscaled full-frame plane of `timing`.
    pub fn full(timing: &Timing, pitch: u32, bytes_per_pixel: u32) -> Self {
        Self {
            surface_width: timing.h_active,
            surface_height: timing.v_active,
            pitch,
            bytes_per_pixel,
            viewport_width: timing.h_active,
            viewport_height: timing.v_active,
            h_ratio: Self::UNITY,
            v_ratio: Self::UNITY,
            h_taps: 1,
            v_taps: 1,
        }
    }
    /// scaler_info.enabled as dml21_translation_helper sets it with SPL: a
    /// ratio other than 1, or more than one tap.
    pub fn scaler_enabled(&self) -> bool {
        self.h_ratio != Self::UNITY
            || self.v_ratio != Self::UNITY
            || self.h_taps > 1
            || self.v_taps > 1
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
/// pipes whose DISPCLK (the pixel clock over the pipes; an HDMI 4:2:0
/// output's TMDS rate is never the larger term) fits `dispclk_ss_khz`, at
/// least two for a DSC line wider than one DSC takes or a 4:2:0 line wider
/// than one formatter buffer, and two for more than four DSC slices. 3 stands
/// for any wider split (3:1 or 4:1), which DML would choose but this port
/// does not admit.
fn decide_odm(mode: &Mode, dispclk_ss_khz: u64) -> u32 {
    let t = &mode.timing;
    let pclk = u64::from(t.pixel_clock_khz);
    let fits = |pipes: u32| pclk <= u64::from(pipes) * dispclk_ss_khz;
    let span = |limit: u32| t.h_active.div_ceil(limit).max(1);
    let mut odm = if fits(1) {
        1
    } else if fits(2) {
        2
    } else {
        3
    };
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
    }
    odm.min(3)
}

/// The pipes admission gives a DSC stream of `timing` with `slices`
/// horizontal slices on a board whose highest DISPCLK is
/// `dispclk_max_khz` (DecideODMMode less downspread, as `admit_all` runs
/// it): 1, 2, or 3 for a wider split. DSC policy uses it to keep each
/// segment within one DSC.
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
    pub qos_level_fixed_l: u32,
    pub qos_level_fixed_c: u32,
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
}

/// A reproducible programming plan for one mode on one board state.
///
/// With `pipes == 2` (ODM 2:1) the stream's one OTG drives two OPPs, each fed
/// by its own DPP/HUBP reading one half of the line. Both pipes run at
/// `clocks.dppclk_khz` with `det_bytes` of DET and the same `ttu` and `dlg`,
/// except that the second pipe's `refcyc_h_blank_end` is
/// `odm_refcyc_h_blank_end` ([`Plan::pipe_dlg`]); Linux DML21 programs no
/// other per-pipe difference (check.sh verifies every register of the second
/// pipe against the first).
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
    /// DPP/OPP pipes the stream takes: 1 in ODM bypass, 2 in ODM 2:1 combine.
    /// DML's policy decides it ([`admit_all`]), not the caller.
    pub pipes: u8,
    /// The second ODM pipe's `refcyc_h_blank_end`: the blank end moved by
    /// half the active line. Zero with one pipe.
    pub odm_refcyc_h_blank_end: u32,
    /// Vertical blank budgeted for self-refresh entry and exit, if any.
    pub stutter_reserved_us: u32,
    /// Every mode admitted together with this one, in admission order; this
    /// plan is `streams[stream]`. A plan is only valid in that configuration.
    pub streams: [Option<Mode>; MAX_STREAMS],
    pub stream: u8,
    /// Each of the stream's planes (`Mode::plane_list` order): its own
    /// DPPCLK, DLG, TTU, DET and second ODM pipe's blank end. The fields
    /// above (`clocks.dppclk_khz`, `dlg`, `ttu`, `det_bytes`,
    /// `odm_refcyc_h_blank_end`) are the first plane's.
    pub planes: [Option<PlanePlan>; MAX_PLANES],
}

/// One plane's share of a stream's [`Plan`]: every one of its `Plan::pipes`
/// pipes runs at `dppclk_khz` with `det_bytes` and this DLG/TTU, the second
/// ODM pipe with its own blank end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanePlan {
    pub plane: Plane,
    pub dppclk_khz: u32,
    pub dlg: Dlg,
    pub ttu: Ttu,
    pub det_bytes: u32,
    pub odm_refcyc_h_blank_end: u32,
}

/// Streams admitted together at most: one per pipe.
pub const MAX_STREAMS: usize = 4;
/// `max_num_dpp` / `max_num_opp`: pipes every admitted stream shares.
pub const MAX_PIPES: u32 = 4;

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
/// Linear surfaces read one-line 256-byte blocks
/// (CalculateBytePerPixelAndBlockSizes: BlockHeight256Bytes 1, BlockWidth
/// 256 / BytePerPixel pixels per request).
const REQUEST_BYTES: i64 = 256;
/// Upper bound for any clock input: 10 GHz.
const MAX_CLOCK_KHZ: u32 = 10_000_000;
/// `DML2_MAX_FMT_420_BUFFER_WIDTH`: widest 4:2:0 output line per OPP.
pub(crate) const FMT_420_BUFFER_WIDTH: u32 = 4096;
/// PMO only budgets stutter when the nominal blank is three times its cost.
const MIN_BLANK_STUTTER_FACTOR: i64 = 3;

/// BlockWidth256BytesY of a linear plane: the pixels one 256-byte request
/// carries.
fn request_pixels(bytes_per_pixel: u32) -> u32 {
    REQUEST_BYTES as u32 / bytes_per_pixel
}
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
fn ceil_quarter(v: Fx) -> Fx {
    q(fx(4).times(v).ceil(), 4)
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

/// One plane's quantities that no clock changes, with its stream's.
#[derive(Clone, Copy)]
struct Shape {
    /// The plane's stream: its index among the admitted modes.
    stream: usize,
    t: Timing,
    pclk: Fx,
    line: Fx,
    /// Pipes (ODM segments): 1 or 2.
    odm: u32,
    /// Each pipe's swath width and its request-rounded width.
    swath: u32,
    swath_ub: u32,
    det_bytes: u32,
    /// The surface's read bandwidth, over all of its pipes.
    vactive_bw: Fx,
    vblank: u32,
    ycbcr420: bool,
    /// DSCDelayRequirement in pixels (0 without DSC).
    dsc_delay: u32,
    /// BytePerPixelY (= BytePerPixelDETY for these formats).
    bpp: u32,
    plane: Plane,
    hratio: Fx,
    vratio: Fx,
    /// PrefetchSourceLinesY: CalculatePrefetchSourceLines for one-line
    /// (linear) swaths, VInitPreFill plus the mandatory partial swath.
    source_lines: i64,
    /// PSCL_THROUGHPUT and RequiredDPPCLK (MHz), as Linux's doubles hold
    /// them; whether DPPCLK is just the pixel clock over the pipes.
    pscl: f64,
    dpp: f64,
    dpp_unit: bool,
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
    vratio_pre: Fx,
    prefetch_bw: Fx,
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
    /// ScaleRatioAndTapsSupport, ViewportExceedsSurface and PitchSupport:
    /// what DML refuses of a plane on its own.
    fn validate(&self) -> Result<(), Error> {
        let taps_ok = |t: u32| (1..=MAX_SCL_TAPS).contains(&t);
        let ratio_ok = |r: u32, taps: u32| {
            r != 0 && r <= MAX_SCL_RATIO * Self::UNITY && r <= taps * Self::UNITY
        };
        if self.surface_width == 0
            || self.surface_height == 0
            || self.surface_width > 0x3fff
            || self.surface_height > 0x3fff
            || self.viewport_width == 0
            || self.viewport_height == 0
            || self.viewport_width > self.surface_width
            || self.viewport_height > self.surface_height
            || self.pitch < self.surface_width
            || !matches!(self.bytes_per_pixel, 2 | 4 | 8)
            || !taps_ok(self.h_taps)
            || !taps_ok(self.v_taps)
            || (self.h_taps > 1 && self.h_taps % 2 == 1)
            || !ratio_ok(self.h_ratio, self.h_taps)
            || !ratio_ok(self.v_ratio, self.v_taps)
        {
            return Err(Error::Invalid);
        }
        // A 128-byte-aligned pitch changes the request width this omits.
        if u64::from(self.pitch) * u64::from(self.bytes_per_pixel) % 256 != 0 {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
}

impl Shape {
    /// `dispclk_ss_khz` is DML's `max_dispclk_freq_mhz`: the board maximum
    /// less downspread, which decides ODM combine.
    fn new(mode: &Mode, plane: Plane, stream: usize, dispclk_ss_khz: u64) -> Result<Self, Error> {
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
        // Only bypass and 2:1 are admitted; Linux would split wider.
        if odm > 2 {
            return Err(Error::Unsupported);
        }
        // ValidateODMMode: each pipe takes an even share of the line (a 4:2:0
        // output passes two pixels per clock), and fits the formatter's 4:2:0
        // line buffer.
        let ppc = if mode.ycbcr420 { 2 } else { 1 };
        if t.h_active % (odm * ppc) != 0
            || t.h_active % odm.max(ppc) != 0
            || (mode.ycbcr420 && t.h_active > odm * FMT_420_BUFFER_WIDTH)
        {
            return Err(Error::Unsupported);
        }
        // With DSC, ValidateODMMode (one DSC per pipe: at most 5760 pixels
        // and four slices each, the slices dividing the line and splitting
        // evenly between the pipes), the DSC unit/slice checks, and
        // DSCCLKRequiredMoreThanSupported (a third of each pipe's pixels).
        if let Some(dsc) = mode.dsc {
            if dsc.slices > odm * MAX_SLICES_PER_DSC
                || t.h_active > odm * MAX_PIXELS_PER_DSC
                || t.h_active % dsc.slices != 0
                || dsc.slices % odm != 0
            {
                return Err(Error::Unsupported);
            }
            if f64::from(t.pixel_clock_khz) / 1000.0 / (3.0 * f64::from(odm)) / 1.0
                > f64::from(MAX_DSCCLK_KHZ) / 1000.0
            {
                return Err(Error::PixelClock);
            }
        }
        // CalculateSwathWidth: the viewport, or with ODM each pipe's share
        // of the line in source pixels (math_round), at most the viewport;
        // rounded to whole requests within the surface.
        let vp = plane.viewport_width;
        let swath = if odm > 1 {
            let share = (u64::from(t.h_active) * u64::from(plane.h_ratio)
                + u64::from(Plane::UNITY))
                / (2 * u64::from(Plane::UNITY));
            vp.min(share as u32)
        } else {
            vp
        };
        let bpp = plane.bytes_per_pixel;
        let r = u64::from(request_pixels(bpp));
        let w = u64::from(plane.surface_width);
        let swath_ub = ceil_to(w, r).min(ceil_to(u64::from(swath).saturating_sub(1), r) + r) as u32;
        let ratio = |r: u32| q(i64::from(r), i64::from(Plane::UNITY));
        let (hratio, vratio) = (ratio(plane.h_ratio), ratio(plane.v_ratio));
        // CalculatePrefetchSourceLines: VInitPreFill =
        // floor((VRatio + VTaps + 1) / 2), then one more line.
        let vinit = (u64::from(plane.v_ratio)
            + u64::from(plane.v_taps + 1) * u64::from(Plane::UNITY))
            / (2 * u64::from(Plane::UNITY));
        // CalculateSinglePipeDPPCLKAndSCLThroughput, then RequiredDPPCLK.
        let (h, v) = (ratio_f(plane.h_ratio), ratio_f(plane.v_ratio));
        let pscl = if h > 1.0 {
            min_f(
                MAX_DCHUB_PSCL_BW as f64,
                MAX_PSCL_LB_BW as f64 * h / ceil_f(f64::from(plane.h_taps) / 6.0),
            )
        } else {
            min_f(MAX_DCHUB_PSCL_BW as f64, MAX_PSCL_LB_BW as f64)
        };
        let pixel_mhz = f64::from(t.pixel_clock_khz) / 1000.0;
        let vtaps_term = f64::from(plane.v_taps / 6) * min_f(1.0, h);
        let mut single = pixel_mhz * max_f(max_f(vtaps_term, h * v / pscl), 1.0);
        if (plane.h_taps > 6 || plane.v_taps > 6) && single < 2.0 * pixel_mhz {
            single = 2.0 * pixel_mhz;
        }
        Ok(Self {
            stream,
            t,
            pclk: mhz(u64::from(t.pixel_clock_khz)),
            line: q(i64::from(t.h_total) * 1000, i64::from(t.pixel_clock_khz)),
            odm,
            swath,
            swath_ub,
            det_bytes: DET_KBYTES * 1024,
            vactive_bw: q(
                i64::from(vp) * i64::from(bpp) * i64::from(t.pixel_clock_khz),
                i64::from(t.h_total) * 1000,
            )
            .times(vratio),
            vblank: t.v_total - t.v_active,
            ycbcr420: mode.ycbcr420,
            dsc_delay: mode.dsc.map_or(0, |d| dsc_delay(&t, d, odm)),
            bpp,
            plane,
            hratio,
            vratio,
            source_lines: vinit as i64 + 1,
            pscl,
            dpp: single / f64::from(odm),
            dpp_unit: single == pixel_mhz,
        })
    }
    /// `CalculateSwathAndDETConfiguration` support: the swath fits half
    /// the DET, the linear swath limit and the line buffer's
    /// MaximumSwathWidthInLineBuffer for its taps and ratios.
    fn buffers(&self) -> Result<(), Error> {
        let full_swath = self.swath_ub * self.bpp;
        let p = &self.plane;
        let unity = u128::from(Plane::UNITY);
        let ceil_v = u128::from(p.v_ratio).div_ceil(unity);
        let lines = u128::from(p.v_taps) + ceil_v.saturating_sub(2);
        let lb = LINE_BUFFER_BITS as u128 * u128::from(p.h_ratio).max(unity);
        if full_swath / 2 > self.det_bytes / 2
            || self.swath > MAX_LINEAR_SWATH
            || u128::from(self.swath) * LB_BITS_PER_PIXEL as u128 * lines * unity > lb
        {
            return Err(Error::Buffer);
        }
        Ok(())
    }
    /// `CalculateUrgentBurstFactor`, luma only. `None` is
    /// NotEnoughUrgentLatencyHiding.
    fn burst(&self, urgent: Fx, vratio: Fx) -> Option<Fx> {
        let lines = self.det_bytes / self.bpp / self.swath_ub;
        let time = fx(i64::from(lines)).times(self.line).over(vratio);
        if time.minus(urgent) <= Fx::ZERO {
            return None;
        }
        Some(time.over(time.minus(urgent)))
    }
    /// `CalculateDCFCLKDeepSleep`'s per-surface term with no tdlut: at
    /// VRatio up to 1 a pipe delivers its swath in `odm` times its share of
    /// the line at the scaled rate, above it at the scaler's throughput.
    fn deep_sleep_surface(&self, dpp: Fx) -> Fx {
        let factor = q(DCFCLK_FACTOR_HUNDREDTHS, 100);
        let per_byte = factor.times(fx(i64::from(self.bpp))).over(fx(64));
        let rate = if self.plane.v_ratio <= Plane::UNITY {
            per_byte
                .times(self.pclk)
                .times(self.hratio)
                .over(fx(i64::from(self.odm)))
        } else {
            per_byte.times(fx_f(self.pscl)).times(dpp)
        };
        rate.max(self.pclk.over(fx(16)))
    }
    /// `RequiredDPPCLK`: the pipe's DPPCLK, the pixel clock over the pipes
    /// when unscaled, in MHz.
    fn dpp_mhz(&self) -> Fx {
        if self.dpp_unit {
            return q(
                i64::from(self.t.pixel_clock_khz),
                1000 * i64::from(self.odm),
            );
        }
        fx_f(self.dpp)
    }
    /// The same as DML hands it to DPMM: truncated to kHz.
    fn dpp_khz(&self) -> u32 {
        if self.dpp_unit {
            return self.t.pixel_clock_khz / self.odm;
        }
        (self.dpp * 1000.0) as u32
    }
    /// `RequiredDISPCLKPerSurface`: the pixel clock over the pipes, in kHz
    /// as DPMM takes it.
    fn disp_khz(&self) -> u32 {
        self.t.pixel_clock_khz / self.odm
    }
    fn disp_mhz(&self) -> Fx {
        q(
            i64::from(self.t.pixel_clock_khz),
            1000 * i64::from(self.odm),
        )
    }
}

/// `CalculateDCFCLKDeepSleep` over every admitted surface: the total read
/// bandwidth's term against each surface's own.
fn deep_sleep(shapes: &[Shape]) -> Fx {
    let factor = q(DCFCLK_FACTOR_HUNDREDTHS, 100);
    let read = shapes
        .iter()
        .fold(Fx::ZERO, |sum, s| sum.plus(s.vactive_bw));
    shapes.iter().fold(
        fx(8).max(factor.times(read).over(fx(RETURN_BUS_BYTES))),
        |ds, s| ds.max(s.deep_sleep_surface(s.dpp_mhz())),
    )
}
/// [`deep_sleep`] as DPMM passes it on: truncated to kHz. Unscaled, it is
/// computed exactly (over the product of the line totals) so a whole-kHz
/// result does not lose a unit to rounding; with a scaled plane, in
/// Linux's own doubles (CalculateDCFCLKDeepSleepTdlut, RequiredDPPCLK).
fn deep_sleep_khz(shapes: &[Shape]) -> u32 {
    let unscaled = |s: &Shape| s.plane.h_ratio == Plane::UNITY && s.plane.v_ratio == Plane::UNITY;
    if !shapes.iter().all(unscaled) {
        return deep_sleep_khz_f(shapes);
    }
    let f = DCFCLK_FACTOR_HUNDREDTHS as u128;
    let den: u128 = shapes.iter().map(|s| u128::from(s.t.h_total)).product();
    let num: u128 = shapes
        .iter()
        .map(|s| {
            u128::from(s.plane.viewport_width * s.bpp) * u128::from(s.t.pixel_clock_khz) * den
                / u128::from(s.t.h_total)
        })
        .sum();
    let bw = f * num / (100 * RETURN_BUS_BYTES as u128 * den);
    shapes.iter().fold(8000.max(bw) as u32, |ds, s| {
        let pclk = u64::from(s.t.pixel_clock_khz);
        let surface =
            (f as u64 * u64::from(s.bpp) * pclk / (100 * 64 * u64::from(s.odm))).max(pclk / 16);
        ds.max(surface as u32)
    })
}
fn deep_sleep_khz_f(shapes: &[Shape]) -> u32 {
    const FACTOR: f64 = 1.15;
    let mut read = 0.0;
    let mut ds_surface: [f64; MAX_PLANES] = [0.0; MAX_PLANES];
    for (k, s) in shapes.iter().enumerate() {
        let pixel_mhz = f64::from(s.t.pixel_clock_khz) / 1000.0;
        let (h, v) = (ratio_f(s.plane.h_ratio), ratio_f(s.plane.v_ratio));
        let swath = f64::from(s.swath);
        let delivery = if v <= 1.0 {
            swath * f64::from(s.odm) / h / pixel_mhz
        } else {
            swath / s.pscl / s.dpp
        };
        let per = FACTOR * swath * f64::from(s.bpp) / 64.0 / delivery;
        ds_surface[k] = max_f(per, pixel_mhz / 16.0);
        read += f64::from(s.plane.viewport_width) * f64::from(s.bpp)
            / (f64::from(s.t.h_total) / pixel_mhz)
            * v;
    }
    let mut ds = max_f(8.0, FACTOR * read / RETURN_BUS_BYTES as f64);
    for &d in &ds_surface[..shapes.len()] {
        ds = max_f(ds, d);
    }
    (ds * 1000.0) as u32
}

impl Shape {
    /// `CalculatePrefetchSchedule` with no VM, rows, meta, tdlut, cursor or
    /// dynamic metadata: VM and row stages take their quarter-line minimum.
    fn prefetch(
        &self,
        clk: PipeClocks,
        lat: &Latency,
        t_wait: Fx,
        extra_prefetch: Fx,
        t_calc: Fx,
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
        // ODM combine adds 18 pixels and every further pipe's recout width
        // (DPP_RECOUT_WIDTH: the swath over the horizontal ratio, truncated).
        let recout = (u64::from(self.swath) * u64::from(Plane::UNITY)
            / u64::from(self.plane.h_ratio)) as u32;
        let dst_x = dst_x
            + if self.odm > 1 {
                18 + (self.odm - 1) * recout
            } else {
                0
            };
        // CalculatePrefetchSchedule: one line after the scaler for a 4:2:0
        // output, then the pixel delay folded into lines.
        let dst_x = dst_x + if self.ycbcr420 { t.h_total } else { 0 };
        s.dst_y = dst_x / t.h_total;
        s.dst_x = dst_x - s.dst_y * t.h_total;

        let quarter = l.over(fx(4));
        let src = self.source_lines;
        let sw_bytes = fx(src * i64::from(self.swath_ub * self.bpp));
        // One-to-one schedule, against this pipe's share of the surface's
        // active bandwidth.
        let min_lsw_oto = q(src, MAX_VRATIO_PRE_OTO).max(fx(2));
        let bw_oto = self
            .vactive_bw
            .over(fx(i64::from(self.odm)))
            .max(fx(i64::from(self.swath_ub * self.bpp)).over(l))
            .min(sw_bytes.over(min_lsw_oto.times(l)));
        let lsw_oto = ceil_quarter(sw_bytes.over(bw_oto).over(l));
        s.prefetch_bw_max = bw_oto;
        // VM and both row trips are one quarter line each.
        let dst_oto = q(3, 4).plus(lsw_oto);
        // Equalized schedule.
        let lo = s.dst_y;
        let min_lsw_equ = q(src, MAX_VRATIO_PRE_EQU).max(fx(2));
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
        s.vratio_pre = fx(src).over(lsw).max(Fx::ONE);
        s.prefetch_bw = fx(src)
            .over(lsw)
            .times(fx(i64::from(self.bpp * self.swath_ub)))
            .over(l);
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
    let lat = latency(lat_state, uclk_khz);
    // CalculateExtraLatency: dcn4x, max outstanding when urgent expected;
    // CalculateTarb: one pixel chunk per DPP.
    let return_bw = {
        let a = available(lat_state).urgent[0];
        a[0].min(a[1])
    };
    let dpps: i64 = shapes.iter().map(|s| i64::from(s.odm)).sum();
    let t_arb = fx(dpps * PIXEL_CHUNK_KBYTES * 1024).over(return_bw);
    let outstanding = fx(ROB_KBYTES * 1024 - MAX_OUTSTANDING_REQS * REQUEST_BYTES).over(return_bw);
    let extra = outstanding.plus(t_arb);
    // Deep-sleep DCFCLK is global: every pipe carries the same value.
    let t_calc = fx(24).over(clk[0].deep_sleep);
    let t_wait = fx(reserved_us).plus(lat.urgent.max(lat.trip));
    let mut planes = [Schedule::default(); MAX_PLANES];
    let (mut urgent, mut non_urgent) = (Fx::ZERO, Fx::ZERO);
    for (k, shape) in shapes.iter().enumerate() {
        let pre = shape.prefetch(clk[k], &lat, t_wait, extra, t_calc);
        // NotEnoughUrgentLatencyHiding for active fetch, then the schedule.
        let burst = shape
            .burst(lat.urgent, shape.vratio)
            .ok_or(Error::UrgentLatencyHiding)?;
        if pre.no_time
            || pre.dst_y > 8
            || pre.dst_y_prefetch < fx(2)
            || pre.vratio_pre > fx(MAX_VRATIO_PRE)
        {
            return Err(Error::Prefetch);
        }
        let pre_burst = shape
            .burst(lat.urgent, pre.vratio_pre)
            .ok_or(Error::UrgentLatencyHiding)?;
        // calculate_peak_bandwidth_required: no flip, VM, cursor or excess
        // vactive fill, and unity DCC/MALL factors for both SDP and DRAM.
        // Active bandwidth is the surface's; prefetch is per pipe.
        let pipes = fx(i64::from(shape.odm));
        urgent = urgent.plus(
            shape
                .vactive_bw
                .times(burst)
                .max(pre.prefetch_bw.times(pre_burst).times(pipes))
                .max(pre.prefetch_bw_max.times(pre_burst).times(pipes))
                .max(shape.vactive_bw),
        );
        non_urgent = non_urgent.plus(
            shape
                .vactive_bw
                .max(pre.prefetch_bw.times(pipes))
                .max(pre.prefetch_bw_max.times(pipes)),
        );
        planes[k] = pre;
    }
    // check_urgent_bandwidth_support for sys-active and, with a MALL,
    // SVP-prefetch derates.
    let avail = available(bw_state);
    let mut frac = [Fx::ZERO; 2];
    for (state, a) in avail.urgent.iter().enumerate() {
        frac[state] = non_urgent.over(a[0]).max(non_urgent.over(a[1]));
        if (state == 0 || MALL_PRESENT) && (urgent > a[0] || urgent > a[1] || frac[state] > Fx::ONE)
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
    /// hiding against the GDDR6 temperature-read watermark.
    fn temp_read_ok(&self, e: &Evaluation, pre: &Schedule, surfaces: usize) -> bool {
        // LBLatencyHidingSourceLinesY: the lines the line buffer holds of
        // the swath in source pixels, less the extra vertical taps (an
        // (unsigned int) of a double, so a negative count wraps).
        let unity = i64::from(Plane::UNITY);
        let h = i64::from(self.plane.h_ratio).max(unity);
        let lb = (LINE_BUFFER_BITS / LB_BITS_PER_PIXEL * h / (i64::from(self.swath) * unity))
            .min(MAX_LINE_BUFFER_LINES)
            - (i64::from(self.plane.v_taps) - 1);
        let lb_lines = i64::from(lb as u32);
        let det_lines = self.det_bytes / self.bpp / self.swath;
        let mut hiding = fx(lb_lines + i64::from(det_lines))
            .times(self.line)
            .over(self.vratio)
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
                    .times(self.line)
                    .over(self.vratio),
            );
        }
        let urgent_wm = e.lat.urgent.plus(e.extra);
        hiding.minus(e.lat.g6_temp_read.plus(urgent_wm)) >= Fx::ZERO
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
/// policy splits it, two ([`Plan::pipes`]), returning their plans in order or
/// the first DML check the configuration fails. Every pipe keeps the fixed
/// DET, and the shared quantities are joint as in DML21: read and urgent
/// bandwidth sum over the surfaces (prefetch over each surface's pipes),
/// extra latency takes one pixel chunk per DPP, deep-sleep DCFCLK, DISPCLK
/// and DPPREFCLK cover every pipe, and stutter is budgeted only if every
/// stream's blank allows it. The global watermarks and arbiter are therefore
/// the same in every plan.
pub fn admit_all(soc: &Soc, modes: &[Mode]) -> Result<Vec<Plan>, Error> {
    soc.validate()?;
    if modes.is_empty() || modes.len() > MAX_STREAMS {
        return Err(Error::Invalid);
    }
    // DML's max_dispclk/dppclk_freq_mhz: the board maximums less downspread.
    let ss = |khz: u32| u64::from(khz) * 10_000 / DOWNSPREAD_TENTHOUSANDTHS as u64;
    let mut shapes = Vec::with_capacity(MAX_PLANES);
    for (k, mode) in modes.iter().enumerate() {
        for plane in mode.plane_list() {
            if shapes.len() == MAX_PLANES {
                return Err(Error::Pipes);
            }
            let shape = Shape::new(mode, plane, k, ss(soc.dispclk_max_khz))?;
            shape.buffers()?;
            shapes.push(shape);
        }
    }
    // TotalAvailablePipesSupport: one DPP per plane and ODM segment.
    if shapes.iter().map(|s| s.odm).sum::<u32>() > MAX_PIPES {
        return Err(Error::Pipes);
    }
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
        let odm = u64::from(s.odm);
        let dpp_over = if s.dpp_unit {
            pclk > odm * ss(soc.dppclk_max_khz)
        } else {
            s.dpp > ss(soc.dppclk_max_khz) as f64 / 1000.0
        };
        if pclk > odm * ss(soc.dispclk_max_khz) || dpp_over {
            return Err(Error::PixelClock);
        }
    }
    let max_dpp_khz = shapes.iter().map(Shape::dpp_khz).max().unwrap_or(0);
    let max_disp_khz = shapes.iter().map(Shape::disp_khz).max().unwrap_or(0);
    let ds = deep_sleep(&shapes);
    // Outstanding-request coverage at DML's DCF state.
    let lat = latency(state, uclk_khz);
    let outstanding_us =
        fx(MAX_OUTSTANDING_REQS * REQUEST_BYTES).over(state.dcfclk.times(fx(RETURN_BUS_BYTES)));
    if outstanding_us < lat.avg_urgent || outstanding_us < lat.avg_non_urgent {
        return Err(Error::Latency);
    }
    // Average bandwidth at maximum clocks.
    let read = shapes
        .iter()
        .fold(Fx::ZERO, |sum, s| sum.plus(s.vactive_bw));
    for a in available(max_state).average {
        if read > a[0] || read > a[1] {
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
            if !shape.temp_read_ok(&e, pre, shapes.len()) {
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
    let min_det = CONFIG_RETURN_KBYTES - SEGMENT_KBYTES;
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
        compbuf_reserved_space_kbytes: (2 * PIXEL_CHUNK_KBYTES * 1024 / 64 * 64 / 1024) as u32,
        compbuf_segments: (CONFIG_RETURN_KBYTES - min_det) / SEGMENT_KBYTES,
        sdpif_request_rate_limit: (3 * WORDS_PER_CHANNEL * soc.umc_channels / 4).max(96),
        dcfclk_deep_sleep_hysteresis: hysteresis.floor() as u32,
        pstate_stall_threshold: (MAX_ALLOW_DELAY_US * ref_khz / 1000) as u32,
        hvm_max_qos_commit_threshold: 0xf,
        hvm_min_req_outstand_commit_threshold: 0xa,
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
        let odm = i128::from(shape.odm);
        let unity = i128::from(Plane::UNITY);
        let h = i128::from(shape.plane.h_ratio);
        let ref_mhz = f64::from(soc.dchub_refclk_khz) / 1000.0;
        let dpp_mhz = f64::from(dppclk_khz[k]) / 1000.0;
        let swath_ub = i128::from(shape.swath_ub);
        let req_per_swath = f64::from(shape.swath_ub / request_pixels(shape.bpp));
        let scaled_line = || f64::from(shape.swath_ub) / shape.pscl / dpp_mhz;
        let delivery = |above_one: bool| -> (u32, u32) {
            if above_one {
                let line = scaled_line();
                (
                    (line * ref_mhz) as u32,
                    (line / req_per_swath * ref_mhz * 1024.0) as u32,
                )
            } else {
                let den = h * i128::from(pclk_i);
                (
                    (swath_ub * odm * unity * i128::from(ref_khz) / den) as u32,
                    (i128::from(request_pixels(shape.bpp))
                        * odm
                        * unity
                        * 1024
                        * i128::from(ref_khz)
                        / den) as u32,
                )
            }
        };
        let (line_delivery, refcyc_req) = delivery(shape.plane.v_ratio > Plane::UNITY);
        let (line_delivery_pre, refcyc_req_pre) = delivery(pre.vratio_pre > Fx::ONE);
        // rq_dlg_get_dlg_reg: each further ODM pipe's blank ends its share
        // of the active line later.
        let h_blank_end = |pipe: u32| {
            (i64::from(t.h_blank_end() + pipe * (t.h_active / shape.odm)) * ref_khz / pclk_i) as u32
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
                plane: shape.plane,
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
                    vratio_prefetch_c: 1 << 19,
                    refcyc_per_line_delivery_pre_l: line_delivery_pre,
                    refcyc_per_line_delivery_l: line_delivery,
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
                    qos_level_fixed_l: 8,
                    qos_level_fixed_c: 8,
                },
                det_bytes: shape.det_bytes,
                odm_refcyc_h_blank_end: if shape.odm > 1 { h_blank_end(1) } else { 0 },
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
            streams,
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
    /// The DLG of plane `plane`'s pipe `pipe` (as `pipe_dlg`).
    pub fn plane_dlg(&self, plane: usize, pipe: u8) -> Option<Dlg> {
        let p = self.planes.get(plane).copied().flatten()?;
        match pipe {
            0 => Some(p.dlg),
            1 if self.pipes == 2 => Some(Dlg {
                refcyc_h_blank_end: p.odm_refcyc_h_blank_end,
                ..p.dlg
            }),
            _ => None,
        }
    }
    /// Plane `plane`'s share of the plan.
    pub fn plane(&self, plane: usize) -> Option<PlanePlan> {
        self.planes.get(plane).copied().flatten()
    }
    /// The configuration this plan was admitted in.
    pub fn joint_modes(&self) -> Vec<Mode> {
        self.streams.iter().flatten().copied().collect()
    }
    /// Whether admitting this plan's configuration again yields this plan:
    /// it was produced by [`admit_all`] from its recorded inputs.
    pub fn readmits(&self) -> bool {
        admit_all(&self.soc, &self.joint_modes())
            .ok()
            .and_then(|plans| plans.get(usize::from(self.stream)).copied())
            == Some(*self)
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
                (p.odm_refcyc_h_blank_end, 1 << 13),
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
