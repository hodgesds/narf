//! DCN 3.0 (Navi22) display mode math and HUBP register derivation for one
//! unscaled plane on one pipe. Parameters are `dcn3_0_ip` / `dcn3_0_soc` from
//! Linux `dml/dcn30/dcn30_fpu.c`; the algorithm follows
//! `display_mode_vba_30.c::DISPCLKDPPCLKDCFCLKDeepSleepPrefetchParametersWatermarksAndPerformanceCalculation`
//! (and the helpers it calls) and the register encoding follows
//! `display_rq_dlg_calc_30.c`. The fixed-point type and the shared result
//! structures come from [`crate::amdgpu_dml`]; none of its DCN3.1.4 constants
//! are used here.
//!
//! Scope, as Linux would see it: GPUVM and HostVM disabled (DCN30 scanout uses
//! physical MC addresses), no DCC, no dynamic metadata, no writeback, no
//! cursor, no ODM combine or MPC split, progressive scan, packed linear RGB.
//! With GPUVM disabled `CalculateVMAndRowBytes` returns zero page-table and
//! meta bytes, so `CalculatePrefetchSchedule`'s bandwidth cases 1 and 3 can
//! never be selected (they need row bytes at least the row trip time); only
//! cases 2 and 4 remain and are written out below. Everything else is the
//! Linux formula, in checked fixed point, with Linux's own truncations at the
//! register boundary (`(unsigned int)` casts floor).
use crate::{
    amdgpu_dml::{
        ceil_multiple, log2_floor, ClockState, Config, Error, Fx, Geometry, Prefetch, Watermarks,
    },
    amdgpu_dml_regs::{
        LatencyRegisters, Registers, RequestRegisters, Requests, ThrottleRegisters,
        W_DLG_VBLANK_END, W_DST_Y_AFTER_SCALER, W_DST_Y_PER_PTE_ROW_NOM_L, W_DST_Y_PER_ROW_VBLANK,
        W_DST_Y_PER_VM_VBLANK, W_DST_Y_PREFETCH, W_MIN_DST_Y_NEXT_START, W_MIN_TTU_VBLANK,
        W_QOS_LEVEL_WM, W_REFCYC_H_BLANK_END, W_REFCYC_PER_HTOTAL, W_REFCYC_PER_LINE_DELIVERY,
        W_REFCYC_PER_PTE_GROUP_NOM_L, W_REFCYC_PER_PTE_GROUP_VBLANK_L, W_REFCYC_PER_REQ_DELIVERY,
        W_REFCYC_X_AFTER_SCALER, W_REF_FREQ_TO_PIX_FREQ, W_VRATIO_PREFETCH,
    },
};

// ── dcn3_0_ip ──────────────────────────────────────────────────────────
/// `det_buffer_size_kbytes`.
pub const DET_BUFFER_KBYTES: u64 = 184;
const LINE_BUFFER_SIZE_BITS: u64 = 789_504;
/// `dm_lb_16`, which `dcn20_populate_dml_pipes_from_context` always selects.
const LB_BIT_PER_PIXEL: u64 = 48;
const MAX_LINE_BUFFER_LINES: i64 = 12;
const MAX_SCL_TAPS: u32 = 8;
/// `dpte_buffer_size_in_pte_reqs_luma`; DCN30 sets no chroma share, so a
/// single-plane surface gets exactly this.
const DPTE_BUFFER_IN_PTE_REQS: u64 = 84;
const PTE_GROUP_BYTES: u64 = 2048;
const GPUVM_MAX_PAGE_TABLE_LEVELS: i64 = 4;
const PIXEL_CHUNK_KBYTES: i64 = 8;
const DPPCLK_DELAY_SUBTOTAL: i64 = 46;
const DPPCLK_DELAY_SCL: i64 = 50;
const DPPCLK_DELAY_SCL_LB_ONLY: i64 = 16;
const DPPCLK_DELAY_CNVC_FORMATTER: i64 = 27;
const DISPCLK_DELAY_SUBTOTAL: i64 = 119;
const MAX_INTER_DCN_TILE_REPEATERS: i64 = 8;
/// `dispclk_ramp_margin_percent` = 1 and `dcn_downspread_percent` = 0.5.
const DISPCLK_RAMP_MARGIN_HUNDREDTHS: i64 = 100;
const DOWNSPREAD_HUNDREDTHS: i64 = 50;
/// Linear surfaces: `MaximumSwathWidthSupportLuma`.
const MAX_SWATH_WIDTH_LINEAR: u64 = 8192;
// rq sizing (`get_surf_rq_param`).
const CHUNK_BYTES: u64 = 8192;
const MIN_CHUNK_BYTES: u64 = 1024;
const META_CHUNK_BYTES: u64 = 2048;
const MIN_META_CHUNK_BYTES: u64 = 256;
const MPTE_GROUP_BYTES: u64 = 2048;
const GPUVM_MIN_PAGE_BYTES: u64 = 4096;

// ── dcn3_0_soc ─────────────────────────────────────────────────────────
/// `sr_exit_time_us` 15.5 and `sr_enter_plus_exit_time_us` 20 (WM_A inputs).
const SR_EXIT_US_TENTHS: i64 = 155;
const SR_ENTER_PLUS_EXIT_US: i64 = 20;
/// `urgent_latency_*_us`: all three are 4.0, so the max3 collapses.
const URGENT_LATENCY_US: i64 = 4;
/// `do_urgent_latency_adjustment` with a 1.0 us component at 1000 MHz.
const URGENT_ADJUST_COMPONENT_US: i64 = 1;
const URGENT_ADJUST_REFERENCE_MHZ: i64 = 1000;
const URGENT_OUT_OF_ORDER_BYTES_PER_CHANNEL: i64 = 4096;
const PCT_IDEAL_AFTER_URGENT_PIXEL_ONLY: i64 = 80;
const FABRIC_DATAPATH_TO_DCN_RETURN_BYTES: i64 = 64;
const RETURN_BUS_WIDTH_BYTES: i64 = 64;
const ROUND_TRIP_PING_LATENCY_DCFCLK_CYCLES: i64 = 191;
/// `dram_clock_change_latency_us`, the WM_A p-state latency.
pub const DRAM_CLOCK_CHANGE_LATENCY_US: i64 = 404;
/// DCN30's prefetch search starts here (`v->VStartupLines = 13`).
const FIRST_VSTARTUP_LINES: u32 = 13;
/// `max_vratio_pre`.
const MAX_VRATIO_PREFETCH: i64 = 4;

/// The SoC state the plan is computed for, taken from the board: the clock
/// ceilings and memory rate from the running DAL DPM table, the channel count
/// and width from the VBIOS `vram_info`, and the DENTIST VCO and DCHUB
/// reference clock from the clock owner and HUBBUB timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Soc {
    pub dcfclk_khz: u32,
    /// `fabricclk_mhz`: DCN30's bounding box copies DCFCLK into it.
    pub fabric_khz: u32,
    pub socclk_khz: u32,
    /// `memclk_mhz * 16`, as `dcn30_update_bw_bounding_box` forms it.
    pub dram_speed_mts: u32,
    pub channels: u32,
    pub channel_width_bytes: u32,
    pub max_dispclk_khz: u32,
    pub max_dppclk_khz: u32,
    pub max_phyclk_khz: u32,
    pub dentist_vco_khz: u32,
    pub dchub_refclk_khz: u32,
}
impl Soc {
    fn valid(&self) -> bool {
        self.dcfclk_khz > 0
            && self.fabric_khz > 0
            && self.socclk_khz > 0
            && self.dram_speed_mts > 0
            && (1..=32).contains(&self.channels)
            && matches!(self.channel_width_bytes, 2 | 4 | 8)
            && self.max_dispclk_khz > 0
            && self.max_dppclk_khz > 0
            && self.max_phyclk_khz > 0
            && self.dentist_vco_khz > 0
            && self.dchub_refclk_khz > 0
    }
}

/// HUBBUB watermark set, in reference-clock cycles, as `hubbub21_program_*`
/// would write it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatermarkSet {
    pub urgent: u32,
    pub urgent_latency: u32,
    pub sr_enter: u32,
    pub sr_exit: u32,
    pub dram_clock_change: u32,
    /// `frac_urg_bw_nom` / `frac_urg_bw_flip`, thousandths.
    pub frac_urg_bw_nom: u32,
    pub frac_urg_bw_flip: u32,
}

/// Whether the DRAM may switch p-state in this configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DramClockChange {
    Vactive,
    Vblank,
    Unsupported,
}

/// A validated single-plane plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The prefetch mode the support search settled on (0 keeps DRAM p-state
    /// and self refresh allowed in vblank, 2 allows neither).
    pub prefetch_mode: u8,
    pub geometry: Geometry,
    pub clocks: ClockState,
    pub watermarks: Watermarks,
    pub prefetch: Prefetch,
    pub registers: Registers,
    pub hubbub: WatermarkSet,
    pub dram_clock_change: DramClockChange,
    /// Fraction of the urgent return bandwidth this plane needs, thousandths.
    pub urgent_bandwidth_thousandths: u32,
}

fn mhz(khz: u32) -> Fx {
    Fx::ratio(khz as i64, 1000)
}
fn one_plus_hundredths(hundredths: i64) -> Fx {
    Fx::ONE.plus(Fx::ratio(hundredths, 10_000))
}
/// `RoundToDFSGranularityUp/Down`.
fn dfs_up(clock: Fx, vco: Fx) -> Fx {
    let quad = vco.times(Fx::int(4));
    quad.over(Fx::int(quad.over(clock).floor().max(1)))
}
fn dfs_down(clock: Fx, vco: Fx) -> Fx {
    let quad = vco.times(Fx::int(4));
    quad.over(Fx::int(quad.over(clock).ceil().max(1)))
}
/// `dml_ceil(4 * value / unit, 1) / 4`.
fn quarter_up(value: Fx, unit: Fx) -> Fx {
    Fx::ratio(Fx::int(4).times(value).over(unit).ceil(), 4)
}
/// `(unsigned int)(value * 2^frac)`, refused when it does not fit the field.
fn field(value: Fx, frac: u32, bits: u32) -> Result<u32, Error> {
    let scaled = value.times(Fx::int(1i64 << frac)).floor();
    if scaled < 0 || scaled >= 1i64 << bits {
        return Err(Error::Unsupported);
    }
    Ok(scaled as u32)
}
fn whole(value: u64, bits: u32) -> Result<u32, Error> {
    if value >= 1u64 << bits {
        return Err(Error::Unsupported);
    }
    Ok(value as u32)
}

fn validate(config: &Config) -> Result<(), Error> {
    let t = &config.timing;
    let p = &config.plane;
    if t.pixel_clock_khz == 0
        || t.h_active == 0
        || t.v_active == 0
        || t.h_total <= t.h_active
        || t.v_total <= t.v_active
        || t.h_front_porch == 0
        || t.v_front_porch == 0
        || t.h_front_porch >= t.h_total - t.h_active
        || t.v_front_porch >= t.v_total - t.v_active
        || t.h_sync_width == 0
        || t.v_sync_width == 0
        || t.h_sync_width > t.h_blank_end()
        || t.v_sync_width > t.v_blank_end()
    {
        return Err(Error::Invalid);
    }
    if p.viewport_width == 0
        || p.viewport_height == 0
        || p.surface_width < p.viewport_width
        || p.surface_height < p.viewport_height
        || p.pitch < p.surface_width
    {
        return Err(Error::Invalid);
    }
    if p.h_taps == 0 || p.v_taps == 0 || p.h_taps > MAX_SCL_TAPS || p.v_taps > MAX_SCL_TAPS {
        return Err(Error::Unsupported);
    }
    // This port drives the scaler in bypass only: one unscaled plane.
    if p.viewport_width != t.h_active
        || p.viewport_height != t.v_active
        || p.h_taps != 1
        || p.v_taps != 1
        || config.cursors != 0
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}

/// `CalculateSwathWidth` + `CalculateSwathAndDETConfiguration` for one linear
/// RGB plane: swath height is one line and the DET holds only luma.
fn geometry(config: &Config) -> Result<Geometry, Error> {
    let format = config.plane.format;
    let bytes_per_pixel = format.bytes_per_pixel();
    let block_height_256 = 1;
    let block_width_256 = 256 / bytes_per_pixel;
    let swath_width = config.plane.viewport_width as u64;
    let surface_width_ub = ceil_multiple(config.plane.surface_width as u64, block_width_256);
    let swath_width_ub =
        surface_width_ub.min(ceil_multiple(swath_width - 1, block_width_256) + block_width_256);
    let swath_height = block_height_256;
    let det_bytes = DET_BUFFER_KBYTES * 1024;
    // RoundedUpMinSwathSizeBytesY must fit half the DET (double buffering).
    if swath_width_ub * bytes_per_pixel * swath_height > det_bytes / 2 {
        return Err(Error::ViewportTooLarge);
    }
    // MaximumSwathWidthLuma: the linear limit and the line buffer.
    let line_buffer = LINE_BUFFER_SIZE_BITS / LB_BIT_PER_PIXEL / config.plane.v_taps as u64;
    if swath_width > MAX_SWATH_WIDTH_LINEAR.min(line_buffer) {
        return Err(Error::ViewportTooLarge);
    }
    Ok(Geometry {
        bytes_per_pixel,
        block_width_256,
        block_height_256,
        swath_width,
        swath_width_ub,
        swath_height,
        det_buffer_bytes: det_bytes,
        h_ratio: Fx::ONE,
        v_ratio: Fx::ONE,
    })
}

/// The DCN30 single-plane values the prefetch, watermark and register stages
/// share.
struct Common {
    line_time: Fx,
    pixel_clock: Fx,
    dppclk: Fx,
    dispclk: Fx,
    deep_sleep: Fx,
    return_bw: Fx,
    extra_latency: Fx,
    urgent_latency: Fx,
    read_bandwidth: Fx,
    t_calc: Fx,
    dst_x_after_scaler: Fx,
    dst_y_after_scaler: u32,
    after_scaler_lines: Fx,
    t_setup: Fx,
    v_update_offset: Fx,
    v_update_width: Fx,
    v_ready_offset: Fx,
    source_lines: Fx,
    v_init_pre_fill: Fx,
    max_num_swath: u32,
    max_v_startup: u32,
}

/// `CalculateTWait`.
fn t_wait(mode: u8, urgent: Fx) -> Fx {
    let pstate = Fx::int(DRAM_CLOCK_CHANGE_LATENCY_US);
    let sr = Fx::int(SR_ENTER_PLUS_EXIT_US);
    match mode {
        0 => pstate.plus(urgent).max(sr.max(urgent)),
        1 => sr.max(urgent),
        _ => urgent,
    }
}

/// One `CalculatePrefetchSchedule` result for a VStartup, or `None` for
/// `MyError`.
#[derive(Clone, Copy)]
struct Schedule {
    dst_y_prefetch: Fx,
    dst_y_per_vm_vblank: Fx,
    dst_y_per_row_vblank: Fx,
    lines_for_pixel_data: Fx,
    v_ratio_prefetch: Fx,
    required_bandwidth: Fx,
    bandwidth: Fx,
}

fn schedule(c: &Common, geometry: &Geometry, v_startup: u32, t_wait: Fx) -> Option<Schedule> {
    let line_time = c.line_time;
    let bytes_per_pixel = Fx::int(geometry.bytes_per_pixel as i64);
    let ub = Fx::int(geometry.swath_width_ub as i64);
    // Tdmdl with GPUVM disabled.
    let t_dmdl = t_wait.plus(c.extra_latency);
    let mut equ = Fx::int(v_startup as i64)
        .minus(
            c.t_setup
                .plus(t_wait.plus(c.t_calc).max(t_dmdl))
                .over(line_time),
        )
        .minus(c.after_scaler_lines);
    // U6.2 DST_Y_PREFETCH limit; values are negative-safe in Fx.
    equ = equ.min(Fx::ratio(6375, 100));
    let lsw = c.source_lines;
    let t_sw_oto = lsw.times(line_time);
    let sw_bytes = lsw.times(ub).times(bytes_per_pixel);
    let prefetch_bw_oto = sw_bytes.over(t_sw_oto);
    let t_vm_oto = line_time.over(Fx::int(4));
    let t_r0_oto = line_time.minus(t_vm_oto).over(Fx::int(2));
    let dst_y_prefetch_oto = quarter_up(t_vm_oto, line_time)
        .plus(Fx::int(2).times(quarter_up(t_r0_oto, line_time)))
        .plus(lsw);
    // dml_floor(4 * (equ + 0.125), 1) / 4, on a possibly negative value.
    let quarters = Fx::int(4).times(equ.plus(Fx::ratio(125, 1000))).raw() >> 24;
    let equ = Fx::ratio(quarters, 4);
    if equ <= Fx::ONE {
        return None;
    }
    let trip = c.urgent_latency;
    let t_vm_trips = c
        .extra_latency
        .plus(trip.times(Fx::int(GPUVM_MAX_PAGE_TABLE_LEVELS - 1)));
    let t_r0_trips = trip;
    // Tpre_rounded, Tvm_trips_rounded, Tr0_trips_rounded and Tno_bw (one line
    // with no GPUVM or DCC) are all whole quarter lines, so both slacks are
    // compared in exact quarter-line integers: DML's double arithmetic lands
    // exactly on zero there, and a truncated fixed-point product must not
    // turn that into a tiny positive slack and an enormous bandwidth.
    let q_vm = Fx::int(4).times(t_vm_trips).over(line_time).ceil();
    let q_r0 = Fx::int(4).times(t_r0_trips).over(line_time).ceil();
    let q_no_bw = 4;
    let slack = |q: i64| (q > 0).then(|| sw_bytes.over(Fx::ratio(q, 4).times(line_time)));
    let bw2 = slack(quarters - q_no_bw - 2 * q_r0).unwrap_or(Fx::ZERO);
    let bw4 = slack(quarters - q_vm - 2 * q_r0).unwrap_or(Fx::ZERO);
    // Case2OK: Tno_bw + 0 >= Tvm_trips_rounded and 0 < Tr0_trips_rounded.
    let case2 = bw2 > Fx::ZERO && q_no_bw >= q_vm && q_r0 > 0;
    let bw_equ = if case2 { bw2 } else { bw4 };
    let (t_vm_equ, t_r0_equ) = if bw_equ > Fx::ZERO {
        let vm = line_time.over(Fx::int(4));
        (vm, line_time.minus(vm).over(Fx::int(2)))
    } else {
        (Fx::ZERO, Fx::ZERO)
    };
    let (dst_y_prefetch, fetch_vm, fetch_row, bandwidth) = if dst_y_prefetch_oto < equ {
        (dst_y_prefetch_oto, t_vm_oto, t_r0_oto, prefetch_bw_oto)
    } else {
        (equ, t_vm_equ, t_r0_equ, bw_equ)
    };
    let vm = quarter_up(fetch_vm, line_time);
    let row = quarter_up(fetch_row, line_time);
    let lines = dst_y_prefetch.minus(vm).minus(Fx::int(2).times(row));
    if lines <= Fx::ZERO || bw_equ <= Fx::ZERO {
        return None;
    }
    let v_ratio_prefetch = lsw.over(lines).max(Fx::ONE);
    let required = lsw
        .over(lines)
        .times(bytes_per_pixel)
        .times(ub)
        .over(line_time);
    Some(Schedule {
        dst_y_prefetch,
        dst_y_per_vm_vblank: vm,
        dst_y_per_row_vblank: row,
        lines_for_pixel_data: lines,
        v_ratio_prefetch,
        required_bandwidth: required,
        bandwidth,
    })
}

/// `CalculateUrgentBurstFactor` for luma; `None` is `NotEnoughUrgentLatencyHiding`.
fn urgent_burst(geometry: &Geometry, line_time: Fx, urgent: Fx, v_ratio: Fx) -> Option<Fx> {
    let lines = geometry.det_buffer_bytes / geometry.bytes_per_pixel / geometry.swath_width_ub;
    let lines = lines / geometry.swath_height * geometry.swath_height;
    let time = Fx::int(lines as i64).times(line_time).over(v_ratio);
    if time <= urgent {
        return None;
    }
    Some(time.over(time.minus(urgent)))
}

/// Mode support plus the performance calculation for one plane. Fails before
/// any hardware is touched when the board cannot carry the mode.
pub fn plan(config: &Config, soc: &Soc) -> Result<Plan, Error> {
    validate(config)?;
    if !soc.valid() || config.dentist_vco_khz == 0 {
        return Err(Error::Invalid);
    }
    let geometry = geometry(config)?;
    let t = &config.timing;
    let pixel_clock = mhz(t.pixel_clock_khz);
    let h_total = Fx::int(t.h_total as i64);
    let line_time = h_total.over(pixel_clock);
    let bytes_per_pixel = Fx::int(geometry.bytes_per_pixel as i64);
    let vco = mhz(config.dentist_vco_khz);
    let downspread = one_plus_hundredths(DOWNSPREAD_HUNDREDTHS);
    let dcfclk = mhz(soc.dcfclk_khz);
    let fabric = mhz(soc.fabric_khz);

    // TMDS 8 bpc: the PHY clock is the pixel clock (RequiredPHYCLK).
    if t.pixel_clock_khz > soc.max_phyclk_khz {
        return Err(Error::Unsupported);
    }

    // IdealSDPPortBandwidthPerState and ReturnBW (HostVM disabled).
    let ideal = Fx::int(RETURN_BUS_WIDTH_BYTES)
        .times(dcfclk)
        .min(
            Fx::int(soc.dram_speed_mts as i64)
                .times(Fx::int(soc.channels as i64))
                .times(Fx::int(soc.channel_width_bytes as i64)),
        )
        .min(fabric.times(Fx::int(FABRIC_DATAPATH_TO_DCN_RETURN_BYTES)));
    let return_bw = ideal
        .times(Fx::int(PCT_IDEAL_AFTER_URGENT_PIXEL_ONLY))
        .over(Fx::int(100));

    // DPPCLK: unscaled, so one pixel per clock whatever the PSCL throughput
    // (min(max_dchub_pscl_bw 4, max_pscl_lb_bw 2)) is.
    let dppclk_needed = pixel_clock.times(downspread);
    let global_dppclk = dfs_up(dppclk_needed, vco);
    // DPPCLK_calculated = Global / 255 * ceil(DPPCLK * 255 / Global).
    let dppclk = global_dppclk.over(Fx::int(255)).times(Fx::int(
        dppclk_needed.times(Fx::int(255)).over(global_dppclk).ceil(),
    ));
    // DISPCLK with and without ramping, against the DFS-rounded ceiling.
    let without = dfs_up(pixel_clock.times(downspread), vco);
    let with = dfs_up(
        pixel_clock
            .times(downspread)
            .times(one_plus_hundredths(DISPCLK_RAMP_MARGIN_HUNDREDTHS)),
        vco,
    );
    let ceiling = dfs_down(mhz(soc.max_dispclk_khz), vco);
    let dispclk = if without > ceiling {
        without
    } else if with > ceiling {
        ceiling
    } else {
        with
    };
    if dispclk > mhz(soc.max_dispclk_khz) || global_dppclk > mhz(soc.max_dppclk_khz) {
        return Err(Error::Unsupported);
    }

    // ReadBandwidthPlaneLuma, in bytes per microsecond.
    let read_bandwidth = Fx::int(geometry.swath_width as i64)
        .times(bytes_per_pixel)
        .over(line_time);
    // CalculateDCFCLKDeepSleep: delivery time cancels the swath width.
    let per_plane = Fx::ratio(11, 10)
        .times(bytes_per_pixel)
        .times(pixel_clock)
        .over(Fx::int(64))
        .max(pixel_clock.over(Fx::int(16)));
    let deep_sleep = Fx::int(8)
        .max(read_bandwidth.over(Fx::int(RETURN_BUS_WIDTH_BYTES)))
        .max(per_plane);

    // CalculateExtraLatency and CalculateUrgentLatency.
    let reorder = Fx::int(soc.channels as i64 * URGENT_OUT_OF_ORDER_BYTES_PER_CHANNEL);
    let extra_latency = Fx::int(ROUND_TRIP_PING_LATENCY_DCFCLK_CYCLES + 32)
        .over(dcfclk)
        .plus(
            reorder
                .plus(Fx::int(PIXEL_CHUNK_KBYTES * 1024))
                .over(return_bw),
        );
    let urgent_latency = Fx::int(URGENT_LATENCY_US).plus(
        Fx::int(URGENT_ADJUST_COMPONENT_US)
            .times(Fx::int(URGENT_ADJUST_REFERENCE_MHZ).over(fabric))
            .minus(Fx::int(URGENT_ADJUST_COMPONENT_US)),
    );
    if urgent_latency <= Fx::ZERO {
        return Err(Error::Invalid);
    }
    let t_calc = Fx::int(24).over(deep_sleep);

    // CalculateDynamicMetadataParameters (Tsetup only).
    let repeater = Fx::int(MAX_INTER_DCN_TILE_REPEATERS)
        .times(Fx::int(2).over(dppclk).plus(Fx::int(3).over(dispclk)));
    let v_update_width = Fx::int(14)
        .over(deep_sleep)
        .plus(Fx::int(12).over(dppclk))
        .plus(repeater)
        .times(pixel_clock);
    let v_ready_offset = Fx::int(150)
        .over(dppclk)
        .max(
            repeater
                .plus(Fx::int(20).over(deep_sleep))
                .plus(Fx::int(10).over(dppclk)),
        )
        .times(pixel_clock);
    let v_update_offset = Fx::int(t.h_total.div_ceil(4) as i64);
    let t_setup = v_update_offset
        .plus(v_update_width)
        .plus(v_ready_offset)
        .over(pixel_clock);

    // DSTXAfterScaler / DSTYAfterScaler: no DSC, ODM or split.
    let scaler = config.plane.h_taps > 1 || config.plane.v_taps > 1;
    let dpp_cycles = DPPCLK_DELAY_SUBTOTAL
        + DPPCLK_DELAY_CNVC_FORMATTER
        + if scaler {
            DPPCLK_DELAY_SCL
        } else {
            DPPCLK_DELAY_SCL_LB_ONLY
        };
    let after_scaler = Fx::int(dpp_cycles).times(pixel_clock).over(dppclk).plus(
        Fx::int(DISPCLK_DELAY_SUBTOTAL)
            .times(pixel_clock)
            .over(dispclk),
    );
    let dst_y_after_scaler = after_scaler.over(h_total).floor().max(0) as u32;
    let dst_x_after_scaler = after_scaler.minus(Fx::int(dst_y_after_scaler as i64).times(h_total));
    let after_scaler_lines =
        Fx::int(dst_y_after_scaler as i64).plus(dst_x_after_scaler.over(h_total));

    // CalculatePrefetchSourceLines, viewport positioning honoured.
    let pre_fill = Fx::ONE
        .plus(Fx::int(config.plane.v_taps as i64))
        .plus(Fx::ONE)
        .over(Fx::int(2))
        .floor()
        .max(0) as u64;
    let swath_height = geometry.swath_height;
    let max_num_swath = pre_fill.saturating_sub(1).div_ceil(swath_height) + 1;
    let partial = if pre_fill > 1 {
        (pre_fill - 2) % swath_height
    } else {
        (pre_fill + swath_height - 2) % swath_height
    }
    .max(1);
    let source_lines = Fx::int((max_num_swath * swath_height + partial) as i64);

    // MaxVStartupLines: progressive, no writeback.
    let max_v_startup = (t.v_total - t.v_active).saturating_sub(1);
    let common = Common {
        line_time,
        pixel_clock,
        dppclk,
        dispclk,
        deep_sleep,
        return_bw,
        extra_latency,
        urgent_latency,
        read_bandwidth,
        t_calc,
        dst_x_after_scaler,
        dst_y_after_scaler,
        after_scaler_lines,
        t_setup,
        v_update_offset,
        v_update_width,
        v_ready_offset,
        source_lines,
        v_init_pre_fill: Fx::int(pre_fill as i64),
        max_num_swath: max_num_swath as u32,
        max_v_startup,
    };

    // ModeSupport tries the prefetch modes in order; the first that passes is
    // the one the configuration runs with.
    let burst = urgent_burst(&geometry, line_time, urgent_latency, geometry.v_ratio)
        .ok_or(Error::NoTimeForPrefetch)?;
    for mode in 0..=2u8 {
        let wait = t_wait(mode, urgent_latency);
        let mut lines = FIRST_VSTARTUP_LINES;
        loop {
            let v_startup = lines.min(max_v_startup);
            if let Some(s) = schedule(&common, &geometry, v_startup, wait) {
                let pre_burst =
                    urgent_burst(&geometry, line_time, urgent_latency, s.v_ratio_prefetch);
                if let Some(pre_burst) = pre_burst {
                    let total = read_bandwidth
                        .times(burst)
                        .max(s.required_bandwidth.times(pre_burst));
                    if total <= return_bw
                        && s.dst_y_prefetch >= Fx::int(2)
                        && s.v_ratio_prefetch <= Fx::int(MAX_VRATIO_PREFETCH)
                    {
                        return finish(config, soc, &geometry, &common, mode, v_startup, &s);
                    }
                }
            }
            lines += 1;
            if lines > max_v_startup {
                break;
            }
        }
    }
    Err(Error::NoTimeForPrefetch)
}

fn finish(
    config: &Config,
    soc: &Soc,
    geometry: &Geometry,
    c: &Common,
    mode: u8,
    v_startup: u32,
    s: &Schedule,
) -> Result<Plan, Error> {
    let line_time = c.line_time;
    // CalculateWatermarksAndDRAMSpeedChangeSupport.
    let pstate_latency = Fx::int(DRAM_CLOCK_CHANGE_LATENCY_US);
    let sr_exit = Fx::ratio(SR_EXIT_US_TENTHS, 10);
    let sr_enter_plus_exit = Fx::int(SR_ENTER_PLUS_EXIT_US);
    let urgent_wm = c.urgent_latency.plus(c.extra_latency);
    let pstate_wm = pstate_latency.plus(urgent_wm);
    let wake = Fx::int(10).over(c.deep_sleep);
    let stutter_exit = sr_exit.plus(c.extra_latency).plus(wake);
    let lines_in_det = geometry.det_buffer_bytes / geometry.bytes_per_pixel / geometry.swath_width;
    let lines_rounded = lines_in_det / geometry.swath_height * geometry.swath_height;
    // TimeToFinishSwathTransferStutterCriticalPlane for one plane.
    let finish_swath = Fx::int(geometry.swath_height as i64)
        .minus(
            Fx::ratio(
                geometry.det_buffer_bytes as i64,
                (geometry.bytes_per_pixel * geometry.swath_width) as i64,
            )
            .minus(Fx::int(lines_rounded as i64)),
        )
        .times(line_time)
        .max(Fx::ZERO);
    let stutter_enter = sr_enter_plus_exit
        .plus(c.extra_latency)
        .plus(wake)
        .max(finish_swath);
    // ActiveDRAMClockChangeLatencyMargin, luma only.
    let lb_lines = Fx::int(
        MAX_LINE_BUFFER_LINES
            .min((LINE_BUFFER_SIZE_BITS / LB_BIT_PER_PIXEL / geometry.swath_width) as i64)
            - (config.plane.v_taps as i64 - 1),
    );
    let margin = lb_lines
        .times(line_time)
        .plus(Fx::int(lines_rounded as i64).times(line_time))
        .minus(urgent_wm)
        .minus(line_time.times(c.after_scaler_lines))
        .minus(pstate_wm);
    let dram_clock_change = if margin > Fx::ZERO {
        DramClockChange::Vactive
    } else if mode == 0 {
        // One active OTG.
        DramClockChange::Vblank
    } else {
        DramClockChange::Unsupported
    };
    let watermarks = Watermarks {
        urgent_us: urgent_wm,
        pstate_change_us: pstate_wm,
        stutter_exit_us: stutter_exit,
        stutter_enter_plus_exit_us: stutter_enter,
        z8_stutter_exit_us: Fx::ZERO,
        z8_stutter_enter_plus_exit_us: Fx::ZERO,
        urgent_latency_us: c.urgent_latency,
        extra_latency_us: c.extra_latency,
        return_bandwidth_bytes_per_us: c.return_bw,
        pstate_latency_us: pstate_latency,
        sr_exit_us: sr_exit,
        sr_enter_plus_exit_us: sr_enter_plus_exit,
    };
    // MinTTUVBlank for the selected prefetch mode, plus TCalc.
    let min_ttu_vblank = c.t_calc.plus(match mode {
        0 => pstate_wm.max(stutter_enter.max(urgent_wm)),
        1 => stutter_enter.max(urgent_wm),
        _ => urgent_wm,
    });
    // VBA values the DLG layer reads back through `(unsigned int)` casts.
    let v_update_offset = c.v_update_offset.floor().max(0) as u32;
    let v_update_width = c.v_update_width.floor().max(0) as u32;
    let v_ready_offset = c.v_ready_offset.floor().max(0) as u32;
    let dst_x_after_scaler = c.dst_x_after_scaler.floor().max(0) as u32;
    let prefetch = Prefetch {
        v_startup,
        max_v_startup: c.max_v_startup,
        dst_y_prefetch: s.dst_y_prefetch,
        dst_y_per_vm_vblank: s.dst_y_per_vm_vblank,
        dst_y_per_row_vblank: s.dst_y_per_row_vblank,
        lines_for_prefetch_pixel_data: s.lines_for_pixel_data,
        v_ratio_prefetch: s.v_ratio_prefetch,
        required_prefetch_bandwidth_bytes_per_us: s.required_bandwidth,
        prefetch_bandwidth_bytes_per_us: s.bandwidth,
        dst_x_after_scaler,
        dst_y_after_scaler: c.dst_y_after_scaler,
        v_update_offset_pix: v_update_offset,
        v_update_width_pix: v_update_width,
        v_ready_offset_pix: v_ready_offset,
        t_setup_us: c.t_setup,
        t_calc_us: c.t_calc,
        t_wait_us: t_wait(mode, c.urgent_latency),
        prefetch_source_lines: c.source_lines,
        v_init_pre_fill: c.v_init_pre_fill,
        max_num_swath: c.max_num_swath,
    };
    let clocks = ClockState {
        dcfclk_khz: soc.dcfclk_khz,
        fclk_khz: soc.fabric_khz,
        socclk_khz: soc.socclk_khz,
        dispclk_khz: c
            .dispclk
            .times(Fx::int(1000))
            .ceil()
            .clamp(0, u32::MAX as i64) as u32,
        dppclk_khz: c
            .dppclk
            .times(Fx::int(1000))
            .ceil()
            .clamp(0, u32::MAX as i64) as u32,
        deep_sleep_dcfclk_khz: c
            .deep_sleep
            .times(Fx::int(1000))
            .ceil()
            .clamp(0, u32::MAX as i64) as u32,
    };
    let registers = registers(
        config,
        geometry,
        c,
        &prefetch,
        min_ttu_vblank,
        soc.dchub_refclk_khz,
    )?;
    // FractionOfUrgentBandwidth without urgent burst.
    let fraction = c.read_bandwidth.max(s.required_bandwidth).over(c.return_bw);
    let frac_urg_bw_nom = fraction.times(Fx::int(1000)).floor().clamp(0, 0x3ff) as u32;
    // convert_and_clamp(ns, refclk): ns is already truncated by the caller.
    let cycles = |us: Fx| -> u32 {
        let ns = us.times(Fx::int(1000)).floor().max(0);
        (ns as u64 * (soc.dchub_refclk_khz as u64 / 1000) / 1000).min(0x1f_ffff) as u32
    };
    let hubbub = WatermarkSet {
        urgent: cycles(urgent_wm),
        urgent_latency: cycles(c.urgent_latency),
        sr_enter: cycles(stutter_enter),
        sr_exit: cycles(stutter_exit),
        dram_clock_change: cycles(pstate_wm),
        frac_urg_bw_nom,
        frac_urg_bw_flip: 0,
    };
    Ok(Plan {
        prefetch_mode: mode,
        geometry: *geometry,
        clocks,
        watermarks,
        prefetch,
        registers,
        hubbub,
        dram_clock_change,
        urgent_bandwidth_thousandths: frac_urg_bw_nom,
    })
}

/// `get_refcyc_per_delivery`, no ODM combine.
fn refcyc_per_delivery(
    refclk: Fx,
    pixel_clock: Fx,
    recout_width: u64,
    v_ratio: Fx,
    hscale_pixel_rate: Fx,
    delivery_width: u64,
    req_per_swath_ub: u64,
) -> Fx {
    if v_ratio <= Fx::ONE {
        refclk
            .times(Fx::int(recout_width as i64))
            .over(pixel_clock)
            .over(Fx::int(req_per_swath_ub as i64))
    } else {
        refclk
            .times(Fx::int(delivery_width as i64))
            .over(hscale_pixel_rate)
            .over(Fx::int(req_per_swath_ub as i64))
    }
}

/// `dml30_rq_dlg_get_rq_reg` + `dml30_rq_dlg_get_dlg_reg` for the plane.
fn registers(
    config: &Config,
    geometry: &Geometry,
    c: &Common,
    prefetch: &Prefetch,
    min_ttu_vblank: Fx,
    dchub_refclk_khz: u32,
) -> Result<Registers, Error> {
    let t = &config.timing;
    let refclk = mhz(dchub_refclk_khz);
    let ref_to_pix = refclk.over(c.pixel_clock);
    if ref_to_pix >= Fx::int(4) {
        return Err(Error::Unsupported);
    }
    let h_total = t.h_total as u64;
    let bytes_per_pixel = geometry.bytes_per_pixel;
    let pitch = config.plane.pitch as u64;
    // get_meta_and_pte_attr: the swath upper bound is capped at the pitch.
    let vp_width = config.plane.viewport_width as u64;
    let mut swath_width_ub =
        ceil_multiple(vp_width - 1, geometry.block_width_256) + geometry.block_width_256;
    if pitch >= geometry.block_width_256 && swath_width_ub > pitch && pitch >= vp_width {
        swath_width_ub = pitch;
    }
    let req_per_swath_ub = swath_width_ub >> log2_floor(geometry.block_width_256);
    // Linear dpte: 8 PTEs per 64-byte request, row height from the pitch.
    let log2_vmpg_width = log2_floor(GPUVM_MIN_PAGE_BYTES) - log2_floor(bytes_per_pixel);
    let dpte_req_width = 1u64 << (log2_vmpg_width + 3);
    let log2_row = log2_floor(DPTE_BUFFER_IN_PTE_REQS * dpte_req_width / pitch.max(1));
    if log2_row < 3 {
        return Err(Error::Unsupported);
    }
    let dpte_row_height = 1u64 << log2_row.min(7);
    let dpte_row_width_ub =
        ceil_multiple(pitch * dpte_row_height - 1, dpte_req_width) + dpte_req_width;
    let dpte_group_width = (PTE_GROUP_BYTES / 64) * dpte_req_width;
    let dpte_groups_per_row_ub = dpte_row_width_ub.div_ceil(dpte_group_width);
    let requests = Requests {
        dpte_req_width,
        dpte_row_height,
        dpte_row_width_ub,
        dpte_req_per_row_ub: dpte_row_width_ub / dpte_req_width,
        dpte_groups_per_row_ub,
        req_per_swath_ub,
    };
    let rq = RequestRegisters {
        chunk_size: log2_floor(CHUNK_BYTES) - 10,
        min_chunk_size: log2_floor(MIN_CHUNK_BYTES) - 8 + 1,
        meta_chunk_size: log2_floor(META_CHUNK_BYTES) - 10,
        min_meta_chunk_size: log2_floor(MIN_META_CHUNK_BYTES) - 6 + 1,
        dpte_group_size: log2_floor(PTE_GROUP_BYTES) - 6,
        mpte_group_size: log2_floor(MPTE_GROUP_BYTES) - 6,
        // Linear: log2 swath height 0.
        swath_height: 0,
        pte_row_height_linear: log2_floor(dpte_row_height) - 3,
        drq_expansion_mode: 2,
        prq_expansion_mode: 1,
        mrq_expansion_mode: 1,
        crq_expansion_mode: 1,
    };
    let vready_sum = (prefetch.v_ready_offset_pix
        + prefetch.v_update_width_pix
        + prefetch.v_update_offset_pix) as i64;
    let vready_after_vcount0 = u32::from(
        Fx::int(prefetch.v_startup as i64).minus(Fx::ratio(vready_sum, h_total as i64))
            <= Fx::int(t.v_blank_end() as i64),
    );
    // dlg_vblank_start = vtotal - front porch.
    let vblank_start = (t.v_total - t.v_front_porch) as u64;
    let hscale_pixel_rate = Fx::int(2).times(c.dppclk);
    let recout = t.h_active as u64;
    let line_delivery = refcyc_per_delivery(
        refclk,
        c.pixel_clock,
        recout,
        Fx::ONE,
        hscale_pixel_rate,
        swath_width_ub,
        1,
    );
    let line_delivery_pre = refcyc_per_delivery(
        refclk,
        c.pixel_clock,
        recout,
        prefetch.v_ratio_prefetch,
        hscale_pixel_rate,
        swath_width_ub,
        1,
    );
    let req_delivery = refcyc_per_delivery(
        refclk,
        c.pixel_clock,
        recout,
        Fx::ONE,
        hscale_pixel_rate,
        vp_width,
        req_per_swath_ub,
    );
    let req_delivery_pre = refcyc_per_delivery(
        refclk,
        c.pixel_clock,
        recout,
        prefetch.v_ratio_prefetch,
        hscale_pixel_rate,
        vp_width,
        req_per_swath_ub,
    );
    let row_lines = Fx::int(dpte_row_height as i64);
    let groups = Fx::int(dpte_groups_per_row_ub as i64);
    let pte_group_nom = row_lines
        .times(Fx::int(h_total as i64))
        .times(ref_to_pix)
        .over(groups)
        .floor()
        .clamp(0, (1 << 23) - 1);
    let dlg = LatencyRegisters {
        ref_freq_to_pix_freq: field(ref_to_pix, 19, W_REF_FREQ_TO_PIX_FREQ)?,
        refcyc_per_htotal: field(
            ref_to_pix.times(Fx::int(h_total as i64)),
            8,
            W_REFCYC_PER_HTOTAL,
        )?,
        refcyc_h_blank_end: field(
            Fx::int(t.h_blank_end() as i64).times(ref_to_pix),
            0,
            W_REFCYC_H_BLANK_END,
        )?,
        dlg_vblank_end: whole(t.v_blank_end() as u64, W_DLG_VBLANK_END)?,
        min_dst_y_next_start: whole(vblank_start * 4, W_MIN_DST_Y_NEXT_START)?,
        refcyc_x_after_scaler: field(
            Fx::int(prefetch.dst_x_after_scaler as i64).times(ref_to_pix),
            0,
            W_REFCYC_X_AFTER_SCALER,
        )?,
        dst_y_after_scaler: whole(prefetch.dst_y_after_scaler as u64, W_DST_Y_AFTER_SCALER)?,
        dst_y_prefetch: field(prefetch.dst_y_prefetch, 2, W_DST_Y_PREFETCH)?,
        dst_y_per_vm_vblank: field(prefetch.dst_y_per_vm_vblank, 2, W_DST_Y_PER_VM_VBLANK)?,
        dst_y_per_row_vblank: field(prefetch.dst_y_per_row_vblank, 2, W_DST_Y_PER_ROW_VBLANK)?,
        vratio_prefetch: field(prefetch.v_ratio_prefetch, 19, W_VRATIO_PREFETCH)?,
        vready_after_vcount0,
        dst_y_per_pte_row_nom_l: field(row_lines, 2, W_DST_Y_PER_PTE_ROW_NOM_L)?,
        refcyc_per_pte_group_nom_l: whole(pte_group_nom as u64, W_REFCYC_PER_PTE_GROUP_NOM_L)?,
        refcyc_per_pte_group_vblank_l: field(
            prefetch
                .dst_y_per_row_vblank
                .times(Fx::int(h_total as i64))
                .times(ref_to_pix)
                .over(groups),
            0,
            W_REFCYC_PER_PTE_GROUP_VBLANK_L,
        )?,
        refcyc_per_line_delivery_l: field(line_delivery, 0, W_REFCYC_PER_LINE_DELIVERY)?,
        refcyc_per_line_delivery_pre_l: field(line_delivery_pre, 0, W_REFCYC_PER_LINE_DELIVERY)?,
        dst_y_delta_drq_limit: 0x7fff,
        chunk_hdl_adjust_cur0: 3,
        dst_y_offset_cur0: 0,
    };
    let ttu = ThrottleRegisters {
        min_ttu_vblank: field(min_ttu_vblank.times(refclk), 0, W_MIN_TTU_VBLANK)?,
        qos_level_low_wm: 0,
        qos_level_high_wm: field(
            Fx::int(4).times(Fx::int(h_total as i64)).times(ref_to_pix),
            0,
            W_QOS_LEVEL_WM,
        )?,
        qos_level_flip: 14,
        refcyc_per_req_delivery_l: field(req_delivery, 10, W_REFCYC_PER_REQ_DELIVERY)?,
        refcyc_per_req_delivery_pre_l: field(req_delivery_pre, 10, W_REFCYC_PER_REQ_DELIVERY)?,
        qos_level_fixed_l: 8,
        qos_ramp_disable_l: 0,
    };
    Ok(Registers {
        requests,
        rq,
        dlg,
        ttu,
    })
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dml30_tests.rs"]
mod tests;
