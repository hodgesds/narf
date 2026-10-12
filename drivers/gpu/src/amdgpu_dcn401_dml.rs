//! Native DCN4.0.1 single-pipe scanout admission: the DML21 mode-support and
//! mode-programming path that Linux runs for Navi48 (`dml2_core_dcn4_calcs.c`,
//! `dml2_dpmm_dcn4.c`, `dml2_mcg_dcn4.c`, `dml2_pmo_dcn4_fams2.c` stutter
//! reservation), reduced to the one configuration the native scanout path
//! implements and evaluated in fixed point.
//!
//! The admitted shape is one DP SST stream with progressive fixed timing and
//! one unscaled, unrotated, full-frame linear XRGB/XBGR8888 plane in physical
//! VRAM on one pipe: GPUVM/HostVM, DCC, MALL/SubVP, cursor, tdlut, dynamic
//! metadata, writeback, ODM/MPC combine, DSC and immediate flip are all off.
//! The default 320-KiB DET from the staged requestor is a fixed input rather
//! than DML's own allocation. Anything else is rejected, not approximated.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Inputs that cannot describe a real mode or board.
    Invalid,
    /// A shape outside the admitted single-pipe configuration.
    Unsupported,
    /// The clock tables cannot supply DML's fabric/DCF state for this UCLK.
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

/// One unscaled full-frame linear 32-bpp surface on one timing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode {
    pub timing: Timing,
    /// Surface pitch in pixels.
    pub pitch: u32,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub mode: Mode,
    pub soc: Soc,
    pub clocks: Clocks,
    pub sync: GlobalSync,
    pub dlg: Dlg,
    pub ttu: Ttu,
    pub watermarks: Watermarks,
    pub arbiter: Arbiter,
    pub det_bytes: u32,
    /// Vertical blank budgeted for self-refresh entry and exit, if any.
    pub stutter_reserved_us: u32,
}

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
/// dppclk_delay_subtotal + cnvc_formatter + scl_lb_only (scaler bypassed).
const DPP_DELAY_CYCLES: i64 = 47 + 28 + 16;
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
const BYTES_PER_PIXEL: u32 = 4;
/// Linear 32bpp reads one-line 256-byte blocks: 64 pixels per request.
const REQUEST_PIXELS: u32 = 64;
const REQUEST_BYTES: i64 = 256;
/// `CalculatePrefetchSourceLines` for VRatio = VTaps = swath height = 1:
/// VInitPreFill 1, one swath plus the mandatory partial swath.
const PREFETCH_SOURCE_LINES: i64 = 2;
/// Upper bound for any clock input: 10 GHz.
const MAX_CLOCK_KHZ: u32 = 10_000_000;
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

/// Mode quantities that no clock changes.
#[derive(Clone, Copy)]
struct Shape {
    t: Timing,
    pclk: Fx,
    line: Fx,
    swath: u32,
    swath_ub: u32,
    det_bytes: u32,
    vactive_bw: Fx,
    vblank: u32,
}

/// DPPCLK, DISPCLK and deep-sleep DCFCLK one evaluation runs the pipe at.
#[derive(Clone, Copy)]
struct PipeClocks {
    dpp: Fx,
    disp: Fx,
    deep_sleep: Fx,
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
    pre: Schedule,
    extra: Fx,
    extra_sr: Fx,
    t_calc: Fx,
    t_wait: Fx,
    lat: Latency,
    frac_nom: Fx,
    frac_mall: Fx,
    non_urgent_sdp: Fx,
}

impl Shape {
    fn new(mode: &Mode) -> Result<Self, Error> {
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
            || mode.pitch < t.h_active
        {
            return Err(Error::Invalid);
        }
        // DML needs a blank line after VStartup for MIN_DST_Y_NEXT_START, and
        // a 128-byte-aligned pitch changes the request width this omits.
        if t.v_total - t.v_active < 2
            || t.v_front_porch == 0
            || u64::from(mode.pitch) * u64::from(BYTES_PER_PIXEL) % 256 != 0
            || t.h_active > 0x3fff
            || t.v_active > 0x3fff
        {
            return Err(Error::Unsupported);
        }
        let w = u64::from(t.h_active);
        let r = u64::from(REQUEST_PIXELS);
        let swath_ub = ceil_to(w, r).min(ceil_to(w - 1, r) + r) as u32;
        Ok(Self {
            t,
            pclk: mhz(u64::from(t.pixel_clock_khz)),
            line: q(i64::from(t.h_total) * 1000, i64::from(t.pixel_clock_khz)),
            swath: t.h_active,
            swath_ub,
            det_bytes: DET_KBYTES * 1024,
            vactive_bw: q(
                i64::from(t.h_active) * i64::from(BYTES_PER_PIXEL) * i64::from(t.pixel_clock_khz),
                i64::from(t.h_total) * 1000,
            ),
            vblank: t.v_total - t.v_active,
        })
    }
    /// `CalculateSwathAndDETConfiguration` support and `PitchSupport`.
    fn buffers(&self) -> Result<(), Error> {
        let full_swath = self.swath_ub * BYTES_PER_PIXEL;
        let lb = LINE_BUFFER_BITS / LB_BITS_PER_PIXEL;
        if full_swath / 2 > self.det_bytes / 2
            || self.swath > MAX_LINEAR_SWATH
            || i64::from(self.swath) > lb
        {
            return Err(Error::Buffer);
        }
        Ok(())
    }
    /// `CalculateUrgentBurstFactor`, luma only. `None` is
    /// NotEnoughUrgentLatencyHiding.
    fn burst(&self, urgent: Fx, vratio: Fx) -> Option<Fx> {
        let lines = self.det_bytes / BYTES_PER_PIXEL / self.swath_ub;
        let time = fx(i64::from(lines)).times(self.line).over(vratio);
        if time.minus(urgent) <= Fx::ZERO {
            return None;
        }
        Some(time.over(time.minus(urgent)))
    }
    /// `CalculateDCFCLKDeepSleep` with VRatio 1 and no tdlut.
    fn deep_sleep(&self) -> Fx {
        let factor = q(DCFCLK_FACTOR_HUNDREDTHS, 100);
        let per_surface = factor
            .times(fx(i64::from(BYTES_PER_PIXEL)))
            .over(fx(64))
            .times(self.pclk)
            .max(self.pclk.over(fx(16)));
        fx(8)
            .max(factor.times(self.vactive_bw).over(fx(RETURN_BUS_BYTES)))
            .max(per_surface)
    }
    /// [`Self::deep_sleep`] as DPMM passes it on: truncated to kHz, computed
    /// exactly so a whole-kHz result does not lose a unit to rounding.
    fn deep_sleep_khz(&self) -> u32 {
        let pclk = u64::from(self.t.pixel_clock_khz);
        let f = DCFCLK_FACTOR_HUNDREDTHS as u64;
        let bw = f * u64::from(self.swath * BYTES_PER_PIXEL) * pclk
            / (100 * RETURN_BUS_BYTES as u64 * u64::from(self.t.h_total));
        let surface = (f * u64::from(BYTES_PER_PIXEL) * pclk / (100 * 64)).max(pclk / 16);
        8000.max(bw).max(surface) as u32
    }
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
        s.vupdate_offset = t.h_total.div_ceil(4);
        s.t_setup = fx(i64::from(
            s.vupdate_offset + s.vupdate_width + s.vready_offset,
        ))
        .over(self.pclk);
        let t_wait_p = t_wait.minus(trip);
        s.t_dmdl = t_wait_p.plus(extra_prefetch).plus(trip);
        let dst_x = round(
            fx(DPP_DELAY_CYCLES)
                .times(self.pclk)
                .over(dppclk)
                .plus(fx(DISPCLK_DELAY_CYCLES).times(self.pclk).over(dispclk)),
        ) as u32;
        s.dst_y = dst_x / t.h_total;
        s.dst_x = dst_x - s.dst_y * t.h_total;

        let quarter = l.over(fx(4));
        let sw_bytes = fx(PREFETCH_SOURCE_LINES * i64::from(self.swath_ub * BYTES_PER_PIXEL));
        // One-to-one schedule.
        let min_lsw_oto = q(PREFETCH_SOURCE_LINES, MAX_VRATIO_PRE_OTO).max(fx(2));
        let bw_oto = self
            .vactive_bw
            .max(fx(i64::from(self.swath_ub * BYTES_PER_PIXEL)).over(l))
            .min(sw_bytes.over(min_lsw_oto.times(l)));
        let lsw_oto = ceil_quarter(sw_bytes.over(bw_oto).over(l));
        s.prefetch_bw_max = bw_oto;
        // VM and both row trips are one quarter line each.
        let dst_oto = q(3, 4).plus(lsw_oto);
        // Equalized schedule.
        let lo = s.dst_y;
        let min_lsw_equ = q(PREFETCH_SOURCE_LINES, MAX_VRATIO_PRE_EQU).max(fx(2));
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
        s.vratio_pre = fx(PREFETCH_SOURCE_LINES).over(lsw).max(Fx::ONE);
        s.prefetch_bw = fx(PREFETCH_SOURCE_LINES)
            .over(lsw)
            .times(fx(i64::from(BYTES_PER_PIXEL * self.swath_ub)))
            .over(l);
        s
    }
    /// The shared mode-support/mode-programming evaluation at one state.
    /// Latency and extra latency come from `lat_state`; urgent bandwidth is
    /// checked against `bw_state` (mode support uses the maximum clocks).
    fn evaluate(
        &self,
        lat_state: State,
        bw_state: State,
        uclk_khz: u64,
        clk: PipeClocks,
        reserved_us: i64,
    ) -> Result<Evaluation, Error> {
        let lat = latency(lat_state, uclk_khz);
        // CalculateExtraLatency: dcn4x, max outstanding when urgent expected.
        let return_bw = {
            let a = available(lat_state).urgent[0];
            a[0].min(a[1])
        };
        let t_arb = fx(PIXEL_CHUNK_KBYTES * 1024).over(return_bw);
        let outstanding =
            fx(ROB_KBYTES * 1024 - MAX_OUTSTANDING_REQS * REQUEST_BYTES).over(return_bw);
        let extra = outstanding.plus(t_arb);
        let t_calc = fx(24).over(clk.deep_sleep);
        let t_wait = fx(reserved_us).plus(lat.urgent.max(lat.trip));
        let pre = self.prefetch(clk, &lat, t_wait, extra, t_calc);
        // NotEnoughUrgentLatencyHiding for active fetch, then the schedule.
        let burst = self
            .burst(lat.urgent, Fx::ONE)
            .ok_or(Error::UrgentLatencyHiding)?;
        if pre.no_time
            || pre.dst_y > 8
            || pre.dst_y_prefetch < fx(2)
            || pre.vratio_pre > fx(MAX_VRATIO_PRE)
        {
            return Err(Error::Prefetch);
        }
        let pre_burst = self
            .burst(lat.urgent, pre.vratio_pre)
            .ok_or(Error::UrgentLatencyHiding)?;
        // calculate_peak_bandwidth_required: no flip, VM, cursor or excess
        // vactive fill, and unity DCC/MALL factors for both SDP and DRAM.
        let urgent = self
            .vactive_bw
            .times(burst)
            .max(pre.prefetch_bw.times(pre_burst))
            .max(pre.prefetch_bw_max.times(pre_burst))
            .max(self.vactive_bw);
        let non_urgent = self
            .vactive_bw
            .max(pre.prefetch_bw)
            .max(pre.prefetch_bw_max);
        // check_urgent_bandwidth_support for sys-active and, with a MALL,
        // SVP-prefetch derates.
        let avail = available(bw_state);
        let mut frac = [Fx::ZERO; 2];
        for (state, a) in avail.urgent.iter().enumerate() {
            frac[state] = non_urgent.over(a[0]).max(non_urgent.over(a[1]));
            if (state == 0 || MALL_PRESENT)
                && (urgent > a[0] || urgent > a[1] || frac[state] > Fx::ONE)
            {
                return Err(Error::Bandwidth);
            }
        }
        Ok(Evaluation {
            pre,
            extra,
            extra_sr: t_arb,
            t_calc,
            t_wait,
            lat,
            frac_nom: frac[0],
            frac_mall: frac[1],
            non_urgent_sdp: non_urgent,
        })
    }
    /// CalculateWatermarksMALLUseAndDRAMSpeedChangeSupport: active latency
    /// hiding against the GDDR6 temperature-read watermark.
    fn temp_read_ok(&self, e: &Evaluation) -> bool {
        let lb_lines = (LINE_BUFFER_BITS / LB_BITS_PER_PIXEL / i64::from(self.swath))
            .min(MAX_LINE_BUFFER_LINES);
        let det_lines = self.det_bytes / BYTES_PER_PIXEL / self.swath;
        let hiding = fx(lb_lines + i64::from(det_lines)).times(self.line).minus(
            fx(i64::from(e.pre.dst_x))
                .over(fx(i64::from(self.t.h_total)))
                .plus(fx(i64::from(e.pre.dst_y)))
                .times(self.line),
        );
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
    soc.validate()?;
    let shape = Shape::new(mode)?;
    let t = shape.t;
    shape.buffers()?;
    let (dcfclk_khz, fclk_khz, bw_kbps) = clock_state(soc)?;
    let pclk_khz = u64::from(t.pixel_clock_khz);
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
    // Mode support: ODM bypass, one DPP, DISPCLK = DPPCLK = pixel clock,
    // checked against the downspread-limited maximums.
    let ss = |khz: u32| u64::from(khz) * 10_000 / DOWNSPREAD_TENTHOUSANDTHS as u64;
    if pclk_khz > ss(soc.dispclk_max_khz) || pclk_khz > ss(soc.dppclk_max_khz) {
        return Err(Error::PixelClock);
    }
    let deep_sleep = shape.deep_sleep();
    // Outstanding-request coverage at DML's DCF state.
    let lat = latency(state, uclk_khz);
    let outstanding_us =
        fx(MAX_OUTSTANDING_REQS * REQUEST_BYTES).over(state.dcfclk.times(fx(RETURN_BUS_BYTES)));
    if outstanding_us < lat.avg_urgent || outstanding_us < lat.avg_non_urgent {
        return Err(Error::Latency);
    }
    // Average bandwidth at maximum clocks.
    let avg = available(max_state).average;
    for a in avg {
        if shape.vactive_bw > a[0] || shape.vactive_bw > a[1] {
            return Err(Error::Bandwidth);
        }
    }
    let support = |reserved_us: i64| -> Result<(), Error> {
        let clk = PipeClocks {
            dpp: shape.pclk,
            disp: shape.pclk,
            deep_sleep,
        };
        let e = shape.evaluate(state, max_state, uclk_khz, clk, reserved_us)?;
        let rob = fx((ROB_KBYTES - PIXEL_CHUNK_KBYTES) * 1024).over(e.non_urgent_sdp);
        if rob < e.lat.max_urgent {
            return Err(Error::Latency);
        }
        if !shape.temp_read_ok(&e) {
            return Err(Error::TempRead);
        }
        Ok(())
    };
    support(0)?;
    // dml2_pmo_dcn4_fams2 stutter candidate (no Z8 on DCN401).
    let vblank_us_x1000 =
        i64::from(t.h_total) * i64::from(shape.vblank) * 1_000_000 / pclk_khz as i64;
    let reserved_us = if vblank_us_x1000 >= SR_ENTER_PLUS_EXIT_US * MIN_BLANK_STUTTER_FACTOR * 1000
        && support(SR_ENTER_PLUS_EXIT_US).is_ok()
    {
        SR_ENTER_PLUS_EXIT_US
    } else {
        0
    };

    // dml2_dpmm_dcn4: DISPCLK gets downspread and ramp margin, DPPREFCLK
    // downspread only; both land on DFS steps, the pipe DPPCLK on 1/255ths.
    let (sp, sp_den) = (DOWNSPREAD_TENTHOUSANDTHS as u128, 10_000u128);
    let (ramp, ramp_den) = ((100 + DISPCLK_RAMP_MARGIN_PERCENT) as u128, 100u128);
    let req = u128::from(t.pixel_clock_khz);
    let disp_max = u128::from(soc.dispclk_max_khz);
    let (mut num, mut den) = (req * sp * ramp, sp_den * ramp_den);
    if num > disp_max * den {
        (num, den) = (disp_max, 1);
    }
    if num * sp_den < req * sp * den {
        (num, den) = (req * sp, sp_den);
    }
    let dispclk_khz = dfs(num, den, soc.dentist_vco_khz)?;
    let dpp_ref = (req * sp / sp_den) as u32;
    let dpprefclk_khz = dfs(u128::from(dpp_ref), 1, soc.dentist_vco_khz)?;
    if dispclk_khz > soc.dispclk_max_khz || dpprefclk_khz > soc.dppclk_max_khz {
        return Err(Error::PixelClock);
    }
    let steps = (req * sp * 255).div_ceil(sp_den * u128::from(dpprefclk_khz));
    let dppclk_khz = (u128::from(dpprefclk_khz) * steps / 255) as u32;
    let deep_sleep_khz = shape.deep_sleep_khz();

    // Mode programming at the chosen clocks.
    let dppclk = mhz(u64::from(dppclk_khz));
    let dispclk = mhz(u64::from(dispclk_khz));
    let ds = mhz(u64::from(deep_sleep_khz));
    // Linux fails mode programming as a whole; keep the specific reason.
    let clk = PipeClocks {
        dpp: dppclk,
        disp: dispclk,
        deep_sleep: ds,
    };
    let e = shape.evaluate(state, state, uclk_khz, clk, reserved_us)?;
    let pre = e.pre;
    let l = shape.line;
    let min_ttu = e.t_wait.plus(e.extra).plus(e.t_calc);
    let vstartup = pre.vstartup;
    let blank_after = shape.vblank - vstartup;
    let vblank_start = t.v_total - t.v_front_porch;
    let l_setup = floor_quarter(pre.t_setup.over(l));
    let min_next = fx(i64::from(vblank_start + blank_after)).plus(l_setup);
    let vready_lines = i64::from(t.v_total - t.v_active - t.v_front_porch) - i64::from(vstartup);
    let vready_after = i64::from(pre.vupdate_offset + pre.vupdate_width + pre.vready_offset)
        <= vready_lines * i64::from(t.h_total);

    // Watermarks.
    let urgent_wm = e.lat.urgent.plus(e.extra);
    let sr_tail = e
        .extra_sr
        .plus(fx(10).over(ds))
        .plus(e.lat.max_urgent)
        .plus(e.lat.df_response);
    let dram_wm = fx(DRAM_CLK_CHANGE_US).plus(urgent_wm);
    let keepout = (dram_wm.over(l).ceil() as u32).min(t.v_total - 1);

    let refclk = mhz(u64::from(soc.dchub_refclk_khz));
    let ref_khz = i64::from(soc.dchub_refclk_khz);
    let pclk_i = pclk_khz as i64;
    let refcyc = |us: Fx| reg(us.times(refclk));
    // Delivery times are whole pixel counts over the pixel clock: exact.
    let line_delivery = (i64::from(shape.swath_ub) * ref_khz / pclk_i) as u32;
    let refcyc_req = (i64::from(REQUEST_PIXELS) * 1024 * ref_khz / pclk_i) as u32;

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

    let plan = Plan {
        mode: *mode,
        soc: *soc,
        clocks: Clocks {
            dispclk_khz,
            dpprefclk_khz,
            dppclk_khz,
            deep_sleep_dcfclk_khz: deep_sleep_khz,
            dcfclk_khz: dcfclk_khz as u32,
            fclk_khz: fclk_khz as u32,
            uclk_khz: soc.uclk_khz,
            socclk_khz: soc.socclk_khz,
        },
        sync: GlobalSync {
            vstartup,
            vupdate_offset: pre.vupdate_offset,
            vupdate_width: pre.vupdate_width,
            vready_offset: pre.vready_offset,
            pstate_keepout: keepout,
        },
        dlg: Dlg {
            refcyc_h_blank_end: (i64::from(t.h_blank_end()) * ref_khz / pclk_i) as u32,
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
            refcyc_per_line_delivery_pre_l: line_delivery,
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
            refcyc_per_req_delivery_pre_l: refcyc_req,
            qos_level_fixed_l: 8,
            qos_level_fixed_c: 8,
        },
        watermarks: Watermarks {
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
        },
        arbiter: Arbiter {
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
        },
        det_bytes: shape.det_bytes,
        stutter_reserved_us: reserved_us as u32,
    };
    plan.check_ranges()?;
    Ok(plan)
}

impl Plan {
    /// The register limits `rq_dlg_get_dlg_reg` asserts. Linux only logs
    /// them; a plan that cannot be programmed exactly is rejected here.
    fn check_ranges(&self) -> Result<(), Error> {
        let (d, t) = (&self.dlg, &self.ttu);
        let limits = [
            (d.refcyc_h_blank_end, 1 << 13),
            (d.min_dst_y_next_start, 1 << 18),
            (d.refcyc_x_after_scaler, 1 << 13),
            (d.dst_y_after_scaler, 8),
            (d.refcyc_per_line_delivery_pre_l, 1 << 13),
            (d.refcyc_per_line_delivery_l, 1 << 13),
            (t.refcyc_per_req_delivery_pre_l, 1 << 23),
            (t.refcyc_per_req_delivery_l, 1 << 23),
            (t.qos_level_high_wm, 1 << 14),
            (t.min_ttu_vblank, 1 << 24),
            (d.dst_y_prefetch, 1 << 8),
        ];
        if limits.iter().any(|&(v, limit)| v >= limit) {
            return Err(Error::Register);
        }
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_dml_tests.rs"]
mod tests;
