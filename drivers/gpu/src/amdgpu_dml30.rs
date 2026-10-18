//! DCN 3.0 (Navi22) display mode math and HUBP register derivation for up to
//! six unscaled planes, one per stream, planned jointly. Parameters are
//! `dcn3_0_ip` / `dcn3_0_soc` from Linux `dml/dcn30/dcn30_fpu.c`; the
//! algorithm follows `display_mode_vba_30.c` — the ODM choice of
//! `dml30_ModeSupportAndSystemConfigurationFull` and
//! `DISPCLKDPPCLKDCFCLKDeepSleepPrefetchParametersWatermarksAndPerformanceCalculation`
//! with the helpers it calls — under the prefetch-mode policy of
//! `dcn30_internal_validate_bw`, and the register encoding follows
//! `display_rq_dlg_calc_30.c`. The fixed-point type and the shared result
//! structures come from [`crate::amdgpu_dml`]; none of its DCN3.1.4 constants
//! are used here.
//!
//! Scope, as Linux would see it: GPUVM and HostVM disabled (DCN30 scanout uses
//! physical MC addresses), no DCC, no dynamic metadata, no writeback, at most
//! the one 256-wide 32-bpp cursor `dcn20_populate_dml_pipes_from_context`
//! always budgets for a graphics plane (`number_of_cursors` = 1), progressive
//! scan, packed linear RGB; ODM 2:1 where mode support needs it (never 4:1),
//! DSC as an input (slices and compressed bpp), no MPC combine (Linux's
//! `MPC_SPLIT_AVOID`), and OTGs never synchronized (`disable_timing_sync`).
//! Every plane shares one DISPCLK, one DPPCLK DFS step, the return bandwidth,
//! the VStartup search and one watermark set; each pipe gets its own DLG/TTU.
//! With GPUVM disabled `CalculateVMAndRowBytes` returns zero page-table and
//! meta bytes, so `CalculatePrefetchSchedule`'s bandwidth cases 1 and 3 can
//! never be selected (they need row bytes at least the row trip time); only
//! cases 2 and 4 remain and are written out below. Everything else is the
//! Linux formula, in checked fixed point, with Linux's own truncations at the
//! register boundary (`(unsigned int)` casts floor). Reference vectors come
//! from Linux's own DML compiled on the host
//! (`drivers/gpu/tests/navi22_dml30/check.sh`).
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
use alloc::vec::Vec;

// ── dcn3_0_ip ──────────────────────────────────────────────────────────
/// `det_buffer_size_kbytes`.
pub const DET_BUFFER_KBYTES: u64 = 184; // linux: n/a (dcn30_fpu.c dcn3_0_ip.det_buffer_size_kbytes)
                                        // linux: n/a (dcn30_fpu.c dcn3_0_ip.line_buffer_size_bits)
const LINE_BUFFER_SIZE_BITS: u64 = 789_504;
/// `dm_lb_16`, which `dcn20_populate_dml_pipes_from_context` always selects.
const LB_BIT_PER_PIXEL: u64 = 48; // linux: n/a (display_mode_vba.c: dm_lb_16 lb_depth 48)
const MAX_LINE_BUFFER_LINES: i64 = 12; // linux: n/a (dcn30_fpu.c dcn3_0_ip.max_line_buffer_lines)
const MAX_SCL_TAPS: u32 = 8; // linux: n/a (dcn30_fpu.c dcn3_0_ip.max_hscl_taps / max_vscl_taps)
/// `dpte_buffer_size_in_pte_reqs_luma`; DCN30 sets no chroma share, so a
/// single-plane surface gets exactly this.
// linux: n/a (dcn30_fpu.c dcn3_0_ip.dpte_buffer_size_in_pte_reqs_luma)
const DPTE_BUFFER_IN_PTE_REQS: u64 = 84;
const PTE_GROUP_BYTES: u64 = 2048; // linux: n/a (dcn30_fpu.c dcn3_0_ip.pte_group_size_bytes)
                                   // linux: n/a (dcn30_fpu.c dcn3_0_ip.gpuvm_max_page_table_levels)
const GPUVM_MAX_PAGE_TABLE_LEVELS: i64 = 4;
const PIXEL_CHUNK_KBYTES: i64 = 8; // linux: n/a (dcn30_fpu.c dcn3_0_ip.pixel_chunk_size_kbytes)
const DPPCLK_DELAY_SUBTOTAL: i64 = 46; // linux: n/a (dcn30_fpu.c dcn3_0_ip.dppclk_delay_subtotal)
const DPPCLK_DELAY_SCL: i64 = 50; // linux: n/a (dcn30_fpu.c dcn3_0_ip.dppclk_delay_scl)
                                  // linux: n/a (dcn30_fpu.c dcn3_0_ip.dppclk_delay_scl_lb_only)
const DPPCLK_DELAY_SCL_LB_ONLY: i64 = 16;
// linux: n/a (dcn30_fpu.c dcn3_0_ip.dppclk_delay_cnvc_formatter)
const DPPCLK_DELAY_CNVC_FORMATTER: i64 = 27;
/// `dppclk_delay_cnvc_cursor`, per cursor.
// linux: n/a (dcn30_fpu.c dcn3_0_ip.dppclk_delay_cnvc_cursor)
const DPPCLK_DELAY_CNVC_CURSOR: i64 = 6;
/// `cursor_buffer_size` in KiB and `number_of_cursors`.
const CURSOR_BUFFER_KBYTES: u64 = 8; // linux: n/a (dcn30_fpu.c dcn3_0_ip.cursor_buffer_size)
const MAX_CURSORS: u32 = 1; // linux: n/a (dcn30_fpu.c dcn3_0_ip.number_of_cursors)
/// `cur0_src_width` 256 at `dm_cur_32bit`.
// linux: n/a (dcn20_fpu.c dcn20_populate_dml_pipes_from_context: cur0_src_width = 256)
pub const CURSOR_WIDTH: u64 = 256;
const CURSOR_BPP: u64 = 32; // linux: n/a (display_mode_vba.c: dm_cur_32bit = 32 bpp)
                            // linux: n/a (dcn30_fpu.c dcn3_0_ip.dispclk_delay_subtotal)
const DISPCLK_DELAY_SUBTOTAL: i64 = 119;
// linux: n/a (dcn30_fpu.c dcn3_0_ip.max_inter_dcn_tile_repeaters)
const MAX_INTER_DCN_TILE_REPEATERS: i64 = 8;
/// `dispclk_ramp_margin_percent` = 1 and `dcn_downspread_percent` = 0.5.
// linux: n/a (dcn30_fpu.c dcn3_0_ip.dispclk_ramp_margin_percent = 1)
const DISPCLK_RAMP_MARGIN_HUNDREDTHS: i64 = 100;
// linux: n/a (dcn30_fpu.c dcn3_0_soc.dcn_downspread_percent = 0.5)
const DOWNSPREAD_HUNDREDTHS: i64 = 50;
/// Linear surfaces: `MaximumSwathWidthSupportLuma`.
// linux: n/a (literal 8192 in display_mode_vba_30.c, dm_sw_linear)
const MAX_SWATH_WIDTH_LINEAR: u64 = 8192;
// rq sizing (`get_surf_rq_param`).
// linux: n/a (display_rq_dlg_calc_30.c get_surf_rq_param: chunk_bytes)
const CHUNK_BYTES: u64 = 8192;
// linux: n/a (display_rq_dlg_calc_30.c get_surf_rq_param: min_chunk_bytes)
const MIN_CHUNK_BYTES: u64 = 1024;
// linux: n/a (display_rq_dlg_calc_30.c get_surf_rq_param: meta_chunk_bytes)
const META_CHUNK_BYTES: u64 = 2048;
// linux: n/a (display_rq_dlg_calc_30.c get_surf_rq_param: min_meta_chunk_bytes)
const MIN_META_CHUNK_BYTES: u64 = 256;
// linux: n/a (display_rq_dlg_calc_30.c get_surf_rq_param: mpte_group_bytes, no hostvm)
const MPTE_GROUP_BYTES: u64 = 2048;
// linux: n/a (dcn30_fpu.c dcn3_0_soc.gpuvm_min_page_size_bytes)
const GPUVM_MIN_PAGE_BYTES: u64 = 4096;

// ── dcn3_0_soc ─────────────────────────────────────────────────────────
/// `sr_exit_time_us` 15.5 and `sr_enter_plus_exit_time_us` 20 (WM_A inputs).
const SR_EXIT_US_TENTHS: i64 = 155; // linux: n/a (dcn30_fpu.c dcn3_0_soc.sr_exit_time_us = 15.5)
                                    // linux: n/a (dcn30_fpu.c dcn3_0_soc.sr_enter_plus_exit_time_us)
const SR_ENTER_PLUS_EXIT_US: i64 = 20;
/// `urgent_latency_*_us`: all three are 4.0, so the max3 collapses.
// linux: n/a (dcn30_fpu.c dcn3_0_soc.urgent_latency_us and the pixel/vm variants)
const URGENT_LATENCY_US: i64 = 4;
/// `do_urgent_latency_adjustment` with a 1.0 us component at 1000 MHz.
// linux: n/a (dcn30_fpu.c dcn3_0_soc.urgent_latency_adjustment_fabric_clock_component_us)
const URGENT_ADJUST_COMPONENT_US: i64 = 1;
// linux: n/a (dcn30_fpu.c dcn3_0_soc.urgent_latency_adjustment_fabric_clock_reference_mhz)
const URGENT_ADJUST_REFERENCE_MHZ: i64 = 1000;
// linux: n/a (dcn30_fpu.c dcn3_0_soc.urgent_out_of_order_return_per_channel_pixel_only_bytes)
const URGENT_OUT_OF_ORDER_BYTES_PER_CHANNEL: i64 = 4096;
// linux: n/a (dcn30_fpu.c dcn3_0_soc.pct_ideal_dram_sdp_bw_after_urgent_pixel_only)
const PCT_IDEAL_AFTER_URGENT_PIXEL_ONLY: i64 = 80;
// linux: n/a (dcn30_fpu.c dcn3_0_soc.fabric_datapath_to_dcn_data_return_bytes)
const FABRIC_DATAPATH_TO_DCN_RETURN_BYTES: i64 = 64;
// linux: n/a (dcn30_fpu.c dcn3_0_soc.return_bus_width_bytes)
const RETURN_BUS_WIDTH_BYTES: i64 = 64;
// linux: n/a (dcn30_fpu.c dcn3_0_soc.round_trip_ping_latency_dcfclk_cycles)
const ROUND_TRIP_PING_LATENCY_DCFCLK_CYCLES: i64 = 191;
/// `dram_clock_change_latency_us`, the WM_A p-state latency.
// linux: n/a (dcn30_fpu.c dcn3_0_soc.dram_clock_change_latency_us)
pub const DRAM_CLOCK_CHANGE_LATENCY_US: i64 = 404;
/// `max_avg_sdp_bw_use_normal_percent` and `max_avg_dram_bw_use_normal_percent`.
const MAX_AVG_SDP_PERCENT: i64 = 60;
const MAX_AVG_DRAM_PERCENT: i64 = 40;
/// `rob_buffer_size_kbytes`.
const ROB_BUFFER_KBYTES: i64 = 184;
/// DCN30's prefetch search starts here (`v->VStartupLines = 13`).
// linux: n/a (literal in display_mode_vba_30.c: v->VStartupLines = 13)
const FIRST_VSTARTUP_LINES: u32 = 13;
/// `max_vratio_pre`.
// linux: n/a (literal 4 in display_mode_vba_30.c: VRatioPrefetchY > 4; soc.max_vratio_pre unset)
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
/// `dcn3_0_soc.min_dcfclk`: `dcn30_fpu_calculate_wm_and_dlg` plans with at
/// least this DCFCLK whatever the state, so a board whose top DCFCLK is lower
/// would get watermarks for a clock it cannot run; such a board is refused.
const MIN_DCFCLK_KHZ: u32 = 500_000;

impl Soc {
    fn valid(&self) -> bool {
        self.dcfclk_khz >= MIN_DCFCLK_KHZ
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

impl Soc {
    /// The top DCN30 bounding-box state from the running board: DCFCLK (also
    /// the fabric clock, as `dcn30_fpu_update_bw_bounding_box` sets it),
    /// SOCCLK and `memclk * 16` from the DAL DPM table, the DENTIST-reachable
    /// display/DPP ceilings, VBIOS channels, and the HUBBUB reference.
    pub fn from_board(
        levels: &crate::amdgpu_dcn30_clk::Levels,
        channels: u32,
        channel_width_bytes: u32,
        dchub_refclk_khz: u32,
    ) -> Result<Self, Error> {
        use crate::amdgpu_dcn30_clk::Clock;
        let dcfclk = levels.range(Clock::Dcf).max_khz();
        let soc = Self {
            dcfclk_khz: dcfclk,
            fabric_khz: dcfclk,
            socclk_khz: levels.range(Clock::Soc).max_khz(),
            dram_speed_mts: levels.range(Clock::Memory).max_khz() / 1000 * 16,
            channels,
            channel_width_bytes,
            max_dispclk_khz: levels.ceiling(Clock::Display).map_err(|_| Error::Invalid)?,
            max_dppclk_khz: levels.ceiling(Clock::Pixel).map_err(|_| Error::Invalid)?,
            max_phyclk_khz: levels.range(Clock::Phy).max_khz(),
            dentist_vco_khz: levels.vco_khz,
            dchub_refclk_khz,
        };
        if !soc.valid() {
            return Err(Error::Invalid);
        }
        Ok(soc)
    }
    /// The bounding-box states up to this (top) one, one per UCLK DPM
    /// level ascending, as `dcn30_fpu_update_bw_bounding_box` lists them.
    /// Deviation: Linux pairs each UCLK with the DCFCLK/FCLK that just
    /// carries its bandwidth (`dcn_bw_get_optimal_dcfclk_fclk_for_uclk`);
    /// here every state keeps the top DCFCLK, so only the memory floor drops.
    pub fn states(&self, memory_mhz: &[u16]) -> Vec<Soc> {
        let mut states: Vec<Soc> = memory_mhz
            .iter()
            .map(|&mhz| u32::from(mhz) * 16)
            .filter(|&mts| mts > 0 && mts < self.dram_speed_mts)
            .map(|dram_speed_mts| Soc {
                dram_speed_mts,
                ..*self
            })
            .collect();
        states.dedup_by_key(|s| s.dram_speed_mts);
        states.push(*self);
        states
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
    /// `DCN_CUR0_TTU_CNTL0/1` for the budgeted cursor (`calculate_ttu_cursor`),
    /// or `None` without one.
    pub cursor: Option<CursorTtu>,
}
/// The cursor's request pacing, as `dml30_rq_dlg_get_dlg_reg` fills
/// `refcyc_per_req_delivery_{pre_,}cur0`, `qos_level_fixed_cur0` and
/// `qos_ramp_disable_cur0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorTtu {
    /// U?.10 reference cycles per request.
    pub refcyc_per_req_delivery: u32,
    pub refcyc_per_req_delivery_pre: u32,
    pub qos_level_fixed: u32,
    pub qos_ramp_disable: u32,
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

// ── Joint admission (several streams, ODM 2:1, DSC) ────────────────────
/// `max_num_dpp` / `max_num_otg`.
pub const MAX_PIPES: usize = 6;
/// `DCN30_MAX_DSC_IMAGE_WIDTH`.
const MAX_DSC_IMAGE_WIDTH: u32 = 5184;
/// `dsc_input_bpc`, which `dcn20_populate_dml_pipes_from_context` fixes at 12.
const DSC_INPUT_BPC: u32 = 12;
/// `DSTXAfterScaler`'s ODM combine allowance (`CalculatePrefetchSchedule`).
const ODM_DST_X_PIXELS: i64 = 18;

/// ODM combine, as `dml30_ModeSupportAndSystemConfigurationFull` chooses it:
/// only when one pipe's DISPCLK would exceed the DFS-rounded ceiling, or a
/// compressed line is wider than one DSC engine takes. 4:1 is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Odm {
    None,
    TwoToOne,
}
impl Odm {
    pub const fn pipes(self) -> u32 {
        match self {
            Odm::None => 1,
            Odm::TwoToOne => 2,
        }
    }
}

/// DSC on a stream, as DML sees it (`dout.dsc_slices`, `dout.output_bpp`
/// from `dsc_cfg.bits_per_pixel`): slices per line and the compressed rate in
/// 1/16 bpp. DML assumes 12-bit DSC input on a 4:4:4 stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dsc {
    pub slices: u32,
    pub bits_per_pixel_x16: u32,
}

/// One stream of a configuration: its single unscaled plane, its DSC, and
/// the PHY clock its link needs (the TMDS character clock, or the DP symbol
/// clock), which must fit `max_phyclk`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stream {
    pub config: Config,
    pub dsc: Option<Dsc>,
    pub phy_khz: u32,
}
impl Stream {
    /// An uncompressed 8-bpc TMDS stream: the PHY runs at the pixel clock.
    pub const fn tmds(config: Config) -> Self {
        Self {
            phy_khz: config.timing.pixel_clock_khz,
            config,
            dsc: None,
        }
    }
}

/// What one HUBP of a plane fetches: its ODM slice of the surface and the
/// pacing `dml30_rq_dlg_get_dlg_reg` gives that pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipePlan {
    /// `DCSURF_PRI_VIEWPORT_START.X` and the slice width.
    pub viewport_x: u32,
    pub viewport_width: u32,
    pub registers: Registers,
    pub cursor: Option<CursorTtu>,
}

/// One stream's plane in a joint plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanePlan {
    pub odm: Odm,
    /// Per pipe: an ODM slice's swath.
    pub geometry: Geometry,
    pub prefetch: Prefetch,
    /// `DPPCLK_calculated`: the DPP DTO of each of this plane's pipes.
    pub dppclk_khz: u32,
    /// `DSCDelay`, pixels.
    pub dsc_delay: u32,
    /// The ODM slices left to right; the second only for 2:1.
    pub pipes: [Option<PipePlan>; 2],
}

/// The admission of a whole configuration: the shared clocks and the one
/// HUBBUB watermark set every stream runs under, and each stream's plane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JointPlan {
    /// The prefetch mode Linux's validation settles on: 0, or 1 when mode 0
    /// fails or leaves the DRAM clock change unsupported.
    pub prefetch_mode: u8,
    /// DISPCLK, the highest plane DPPCLK and deep-sleep DCFCLK; DCFCLK,
    /// FCLK and SOCCLK are the top state's.
    pub clocks: ClockState,
    pub watermarks: Watermarks,
    pub hubbub: WatermarkSet,
    pub dram_clock_change: DramClockChange,
    pub urgent_bandwidth_thousandths: u32,
    /// In the order the streams were given.
    pub planes: Vec<PlanePlan>,
}
impl JointPlan {
    /// HUBP/DPP pipes the configuration occupies.
    pub fn pipes(&self) -> u32 {
        self.planes.iter().map(|p| p.odm.pipes()).sum()
    }
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
        || config.cursors > MAX_CURSORS
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}

/// `CalculateSwathWidth` + `CalculateSwathAndDETConfiguration` for one linear
/// RGB plane on `odm`'s pipes: swath height is one line, the DET (one per
/// pipe) holds only luma, and an ODM pipe's swath is half the active width.
fn geometry(config: &Config, odm: Odm) -> Result<Geometry, Error> {
    let format = config.plane.format;
    let bytes_per_pixel = format.bytes_per_pixel();
    let block_height_256 = 1;
    let block_width_256 = 256 / bytes_per_pixel;
    let viewport = config.plane.viewport_width as u64;
    let swath_width = match odm {
        Odm::None => viewport,
        // dml_round(HActive / 2.0 * HRatio)
        Odm::TwoToOne => viewport.min((config.timing.h_active as u64).div_ceil(2)),
    };
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

/// `dscceComputeDelay` for 4:4:4 at 12-bit input, in pixels.
fn dscce_delay(bits_per_pixel_x16: u32, slice_width: u32, slices: u32) -> u32 {
    // initalXmitDelay = dml_round(rcModelSize / 2 / BPP)
    let initial = (131_072 + bits_per_pixel_x16) / (2 * bits_per_pixel_x16);
    // ssm delay for 12 bpc
    let d = match DSC_INPUT_BPC {
        8 => 81,
        10 => 89,
        _ => 113,
    };
    let w = slice_width;
    let ix = initial + 45;
    let wx = w.div_ceil(3);
    let p = 3 * wx - w;
    let l0 = ix / w;
    let a = ix + p * l0;
    let ax = a.div_ceil(3) + d + 6 + 1;
    let l = ax.div_ceil(wx);
    let lstall = u32::from(ix % w == 0 && p != 0);
    let delay = l * wx * slices.saturating_sub(1) + ax + lstall + 22;
    delay * 3
}
/// `dscComputeDelay` for 4:4:4: the DSC wrapper's fixed pipeline.
const DSC_WRAPPER_DELAY: u32 = 2 + 3 + 12 + 2 + 7 + 1 + 2 + 1;
/// `DSCDelay[k]` (PixelClockBackEnd equals PixelClock for progressive).
fn dsc_delay(dsc: &Dsc, h_active: u32, odm: Odm) -> Result<u32, Error> {
    if dsc.slices == 0 || dsc.bits_per_pixel_x16 == 0 {
        return Err(Error::Invalid);
    }
    let slice_width = h_active.div_ceil(dsc.slices);
    Ok(match odm {
        Odm::None => dscce_delay(dsc.bits_per_pixel_x16, slice_width, dsc.slices),
        // NumberOfDSCSlices / 2.0 passed as unsigned int
        Odm::TwoToOne => 2 * dscce_delay(dsc.bits_per_pixel_x16, slice_width, dsc.slices / 2),
    } + DSC_WRAPPER_DELAY)
}

/// The values every plane's prefetch, watermark and register stages share.
struct Global {
    dispclk: Fx,
    deep_sleep: Fx,
    return_bw: Fx,
    extra_latency: Fx,
    urgent_latency: Fx,
    t_calc: Fx,
}

/// One plane's DCN30 values the prefetch, watermark and register stages use.
struct PlaneCalc {
    config: Config,
    odm: Odm,
    dpp: u32,
    geometry: Geometry,
    dsc_delay: u32,
    line_time: Fx,
    pixel_clock: Fx,
    dppclk: Fx,
    /// `ReadBandwidthPlaneLuma`, the whole plane.
    read_bandwidth: Fx,
    /// `cursor_bw` at VRatio 1: cursors x 256 x 32 / 8 bytes per line.
    cursor_bandwidth: Fx,
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
    /// `UrgentBurstFactorLuma/Cursor` at VRatio 1.
    burst: Fx,
    cursor_burst: Fx,
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

fn schedule(g: &Global, p: &PlaneCalc, v_startup: u32, t_wait: Fx) -> Option<Schedule> {
    let line_time = p.line_time;
    let geometry = &p.geometry;
    let bytes_per_pixel = Fx::int(geometry.bytes_per_pixel as i64);
    let ub = Fx::int(geometry.swath_width_ub as i64);
    // Tdmdl with GPUVM disabled.
    let t_dmdl = t_wait.plus(g.extra_latency);
    let mut equ = Fx::int(v_startup as i64)
        .minus(
            p.t_setup
                .plus(t_wait.plus(g.t_calc).max(t_dmdl))
                .over(line_time),
        )
        .minus(p.after_scaler_lines);
    // U6.2 DST_Y_PREFETCH limit; values are negative-safe in Fx.
    equ = equ.min(Fx::ratio(6375, 100));
    let lsw = p.source_lines;
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
    let trip = g.urgent_latency;
    let t_vm_trips = g
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

/// The cursor half of `CalculateUrgentBurstFactor`: the cursor buffer holds
/// `2^floor(log2(8 KiB / 1 KiB per line))` = 8 lines. `None` is
/// `NotEnoughUrgentLatencyHiding`; a plane without a cursor (CursorWidth 0)
/// has no cursor factor to hide.
fn cursor_burst(cursors: u32, line_time: Fx, urgent: Fx, v_ratio: Fx) -> Option<Fx> {
    if cursors == 0 {
        return Some(Fx::ONE);
    }
    let lines = 1u64 << log2_floor(CURSOR_BUFFER_KBYTES * 1024 / (CURSOR_WIDTH * CURSOR_BPP / 8));
    let time = Fx::int(lines as i64).times(line_time).over(v_ratio);
    if time <= urgent {
        return None;
    }
    Some(time.over(time.minus(urgent)))
}

/// `pixel_clock / n`, exact for one pipe.
fn per_pipe(clock: Fx, pipes: u32) -> Fx {
    if pipes == 1 {
        clock
    } else {
        clock.over(Fx::int(pipes as i64))
    }
}

/// Mode support plus the performance calculation for one plane. Fails before
/// any hardware is touched when the board cannot carry the mode.
pub fn plan(config: &Config, soc: &Soc) -> Result<Plan, Error> {
    let joint = plan_joint(&[Stream::tmds(*config)], soc)?;
    let plane = joint.planes.first().ok_or(Error::Invalid)?;
    let pipe = plane.pipes[0].ok_or(Error::Invalid)?;
    if plane.odm != Odm::None {
        // The single-stream callers drive one pipe.
        return Err(Error::Unsupported);
    }
    Ok(Plan {
        prefetch_mode: joint.prefetch_mode,
        geometry: plane.geometry,
        clocks: joint.clocks,
        watermarks: joint.watermarks,
        prefetch: plane.prefetch,
        registers: pipe.registers,
        hubbub: joint.hubbub,
        dram_clock_change: joint.dram_clock_change,
        urgent_bandwidth_thousandths: joint.urgent_bandwidth_thousandths,
        cursor: pipe.cursor,
    })
}

/// The voltage-level search of `dcn30_internal_validate_bw`
/// (`dcn20_validate_apply_pipe_split_flags` aside): the lowest of `states`
/// (ascending, as [`Soc::states`] lists them) whose joint plan is
/// supported, and that plan. Its UCLK is the admission's memory floor.
pub fn plan_joint_lowest(streams: &[Stream], states: &[Soc]) -> Result<(usize, JointPlan), Error> {
    let mut last = Error::Unsupported;
    for (i, soc) in states.iter().enumerate() {
        match plan_joint(streams, soc) {
            Ok(plan) => return Ok((i, plan)),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Joint mode support and the performance calculation for every stream of a
/// configuration at once, as `dcn30_validate_bandwidth` runs DML30 on the
/// whole context: ODM per stream, one DISPCLK and DPPCLK DFS step for all,
/// the summed read bandwidth against the return bandwidth, one VStartup
/// search across every plane, one urgent/stutter/p-state watermark set, and
/// each pipe's DLG/TTU registers. Fails before any hardware is touched.
pub fn plan_joint(streams: &[Stream], soc: &Soc) -> Result<JointPlan, Error> {
    if streams.is_empty() || streams.len() > MAX_PIPES {
        return Err(Error::Unsupported);
    }
    let vco_khz = streams[0].config.dentist_vco_khz;
    for s in streams {
        validate(&s.config)?;
        if s.config.dentist_vco_khz != vco_khz {
            return Err(Error::Invalid);
        }
        if s.phy_khz == 0 || s.phy_khz > soc.max_phyclk_khz {
            return Err(Error::Unsupported);
        }
    }
    if !soc.valid() || vco_khz == 0 {
        return Err(Error::Invalid);
    }
    let vco = mhz(vco_khz);
    let downspread = one_plus_hundredths(DOWNSPREAD_HUNDREDTHS);
    let ramp = one_plus_hundredths(DISPCLK_RAMP_MARGIN_HUNDREDTHS);
    let dcfclk = mhz(soc.dcfclk_khz);
    let fabric = mhz(soc.fabric_khz);
    let max_dispclk = mhz(soc.max_dispclk_khz);
    let max_dispclk_down = dfs_down(max_dispclk, vco);
    let max_dppclk_down = dfs_down(mhz(soc.max_dppclk_khz), vco);

    // ModeSupport at the top state: ODM where one pipe cannot carry the
    // pixel rate (DCN30's ramping margin is dropped where it alone would
    // exceed the ceiling), or where DSC is wider than one engine.
    let mut odm = [Odm::None; MAX_PIPES];
    for (k, s) in streams.iter().enumerate() {
        let pixel_clock = mhz(s.config.timing.pixel_clock_khz);
        let required = |pipes: u32| {
            let with = per_pipe(pixel_clock, pipes).times(downspread).times(ramp);
            if with >= max_dispclk {
                per_pipe(pixel_clock, pipes).times(downspread)
            } else {
                with
            }
        };
        if required(2) > max_dispclk_down {
            return Err(Error::Unsupported);
        }
        odm[k] = if required(1) > max_dispclk_down {
            Odm::TwoToOne
        } else {
            Odm::None
        };
        let h_active = s.config.timing.h_active;
        if s.dsc.is_some() && h_active > MAX_DSC_IMAGE_WIDTH {
            if h_active / 2 > MAX_DSC_IMAGE_WIDTH {
                return Err(Error::Unsupported);
            }
            odm[k] = Odm::TwoToOne;
        }
        let pipes = odm[k].pipes();
        // The pipes split the active line in half on whole pixels.
        if pipes == 2 && h_active % 2 != 0 {
            return Err(Error::Unsupported);
        }
        if required(pipes) > max_dispclk_down
            || per_pipe(pixel_clock, pipes).times(downspread) > max_dppclk_down
        {
            return Err(Error::Unsupported);
        }
    }
    let odm = &odm[..streams.len()];
    let total_dpp: u32 = odm.iter().map(|o| o.pipes()).sum();
    if total_dpp as usize > MAX_PIPES {
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
    let dram_bw = Fx::int(soc.dram_speed_mts as i64)
        .times(Fx::int(soc.channels as i64))
        .times(Fx::int(soc.channel_width_bytes as i64));
    let reorder = Fx::int(soc.channels as i64 * URGENT_OUT_OF_ORDER_BYTES_PER_CHANNEL);
    // ROBSupport: the reorder buffer outlasts the round trip.
    if Fx::int((ROB_BUFFER_KBYTES - PIXEL_CHUNK_KBYTES) * 1024).over(return_bw)
        <= Fx::int(ROUND_TRIP_PING_LATENCY_DCFCLK_CYCLES + 32)
            .over(dcfclk)
            .plus(reorder.over(return_bw))
    {
        return Err(Error::Unsupported);
    }

    // DISPCLK with and without ramping across every plane, against the
    // DFS-rounded ceiling.
    let mut with = Fx::ZERO;
    let mut without = Fx::ZERO;
    for (s, o) in streams.iter().zip(odm) {
        let clock = per_pipe(mhz(s.config.timing.pixel_clock_khz), o.pipes()).times(downspread);
        with = with.max(clock.times(ramp));
        without = without.max(clock);
    }
    let without = dfs_up(without, vco);
    let with = dfs_up(with, vco);
    let dispclk = if without > max_dispclk_down {
        without
    } else if with > max_dispclk_down {
        max_dispclk_down
    } else {
        with
    };
    // DPPCLK: unscaled, so one pixel per clock per pipe whatever the PSCL
    // throughput (min(max_dchub_pscl_bw 4, max_pscl_lb_bw 2)) is; one DFS
    // step for every plane, then each plane's 1/255 DTO share of it.
    let mut needed = [Fx::ZERO; MAX_PIPES];
    for ((n, s), o) in needed.iter_mut().zip(streams).zip(odm) {
        *n = per_pipe(mhz(s.config.timing.pixel_clock_khz), o.pipes()).times(downspread);
    }
    let needed = &needed[..streams.len()];
    let global_dppclk = dfs_up(needed.iter().fold(Fx::ZERO, |a, b| a.max(*b)), vco);
    if dispclk > max_dispclk || global_dppclk > mhz(soc.max_dppclk_khz) {
        return Err(Error::Unsupported);
    }

    // Per plane: geometry, read bandwidth, DSC delay.
    let mut planes: Vec<PlaneCalc> = Vec::new();
    planes
        .try_reserve_exact(streams.len())
        .map_err(|_| Error::Unsupported)?;
    let mut total_read = Fx::ZERO;
    let mut deep_sleep = Fx::int(8);
    for ((s, o), dpp_needed) in streams.iter().zip(odm).zip(needed) {
        let config = s.config;
        let t = &config.timing;
        let geometry = geometry(&config, *o)?;
        let pixel_clock = mhz(t.pixel_clock_khz);
        let line_time = Fx::int(t.h_total as i64).over(pixel_clock);
        let bytes_per_pixel = Fx::int(geometry.bytes_per_pixel as i64);
        // DPPCLK_calculated = Global / 255 * ceil(DPPCLK * 255 / Global).
        let dppclk = global_dppclk.over(Fx::int(255)).times(Fx::int(
            dpp_needed.times(Fx::int(255)).over(global_dppclk).ceil(),
        ));
        // ReadBandwidthPlaneLuma, the whole viewport, bytes per microsecond.
        let read_bandwidth = Fx::int(config.plane.viewport_width as i64)
            .times(bytes_per_pixel)
            .over(line_time);
        total_read = total_read.plus(read_bandwidth);
        // CalculateDCFCLKDeepSleep: delivery time cancels the swath width.
        let per_plane = per_pipe(
            Fx::ratio(11, 10)
                .times(bytes_per_pixel)
                .times(pixel_clock)
                .over(Fx::int(64)),
            o.pipes(),
        )
        .max(pixel_clock.over(Fx::int(16)));
        deep_sleep = deep_sleep.max(per_plane);
        let dsc_delay = match &s.dsc {
            Some(dsc) => dsc_delay(dsc, t.h_active, *o)?,
            None => 0,
        };
        let cursor_bandwidth =
            Fx::int((config.cursors as u64 * CURSOR_WIDTH * CURSOR_BPP / 8) as i64).over(line_time);
        planes.push(PlaneCalc {
            config,
            odm: *o,
            dpp: o.pipes(),
            geometry,
            dsc_delay,
            line_time,
            pixel_clock,
            dppclk,
            read_bandwidth,
            cursor_bandwidth,
            dst_x_after_scaler: Fx::ZERO,
            dst_y_after_scaler: 0,
            after_scaler_lines: Fx::ZERO,
            t_setup: Fx::ZERO,
            v_update_offset: Fx::ZERO,
            v_update_width: Fx::ZERO,
            v_ready_offset: Fx::ZERO,
            source_lines: Fx::ZERO,
            v_init_pre_fill: Fx::ZERO,
            max_num_swath: 0,
            max_v_startup: 0,
            burst: Fx::ONE,
            cursor_burst: Fx::ONE,
        });
    }
    let deep_sleep = deep_sleep.max(total_read.over(Fx::int(RETURN_BUS_WIDTH_BYTES)));
    // TotalVerticalActiveBandwidthSupport: the planes' active reads within
    // the share of SDP and DRAM bandwidth display may use in normal operation.
    let vactive_limit = ideal
        .times(Fx::int(MAX_AVG_SDP_PERCENT))
        .over(Fx::int(100))
        .min(
            dram_bw
                .times(Fx::int(MAX_AVG_DRAM_PERCENT))
                .over(Fx::int(100)),
        );
    if total_read > vactive_limit {
        return Err(Error::Unsupported);
    }

    // CalculateExtraLatency (every active DPP's pixel chunk) and
    // CalculateUrgentLatency.
    let extra_latency = Fx::int(ROUND_TRIP_PING_LATENCY_DCFCLK_CYCLES + 32)
        .over(dcfclk)
        .plus(
            reorder
                .plus(Fx::int(total_dpp as i64 * PIXEL_CHUNK_KBYTES * 1024))
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
    let global = Global {
        dispclk,
        deep_sleep,
        return_bw,
        extra_latency,
        urgent_latency,
        t_calc: Fx::int(24).over(deep_sleep),
    };

    for p in planes.iter_mut() {
        let t = p.config.timing;
        let pixel_clock = p.pixel_clock;
        let h_total = Fx::int(t.h_total as i64);
        // CalculateDynamicMetadataParameters (Tsetup only).
        let repeater = Fx::int(MAX_INTER_DCN_TILE_REPEATERS)
            .times(Fx::int(2).over(p.dppclk).plus(Fx::int(3).over(dispclk)));
        p.v_update_width = Fx::int(14)
            .over(deep_sleep)
            .plus(Fx::int(12).over(p.dppclk))
            .plus(repeater)
            .times(pixel_clock);
        p.v_ready_offset = Fx::int(150)
            .over(p.dppclk)
            .max(
                repeater
                    .plus(Fx::int(20).over(deep_sleep))
                    .plus(Fx::int(10).over(p.dppclk)),
            )
            .times(pixel_clock);
        p.v_update_offset = Fx::int(t.h_total.div_ceil(4) as i64);
        p.t_setup = p
            .v_update_offset
            .plus(p.v_update_width)
            .plus(p.v_ready_offset)
            .over(pixel_clock);

        // DSTXAfterScaler / DSTYAfterScaler: DSC delay, ODM's 18 pixels and
        // the other pipes' recout.
        let scaler = p.config.plane.h_taps > 1 || p.config.plane.v_taps > 1;
        let dpp_cycles = DPPCLK_DELAY_SUBTOTAL
            + DPPCLK_DELAY_CNVC_FORMATTER
            + p.config.cursors as i64 * DPPCLK_DELAY_CNVC_CURSOR
            + if scaler {
                DPPCLK_DELAY_SCL
            } else {
                DPPCLK_DELAY_SCL_LB_ONLY
            };
        let mut after_scaler = Fx::int(dpp_cycles).times(pixel_clock).over(p.dppclk).plus(
            Fx::int(DISPCLK_DELAY_SUBTOTAL)
                .times(pixel_clock)
                .over(dispclk),
        );
        if p.dsc_delay != 0 {
            after_scaler = after_scaler.plus(Fx::int(p.dsc_delay as i64));
        }
        if p.odm != Odm::None {
            after_scaler = after_scaler.plus(Fx::int(
                ODM_DST_X_PIXELS + (p.dpp as i64 - 1) * p.geometry.swath_width as i64,
            ));
        }
        p.dst_y_after_scaler = after_scaler.over(h_total).floor().max(0) as u32;
        p.dst_x_after_scaler =
            after_scaler.minus(Fx::int(p.dst_y_after_scaler as i64).times(h_total));
        p.after_scaler_lines =
            Fx::int(p.dst_y_after_scaler as i64).plus(p.dst_x_after_scaler.over(h_total));

        // CalculatePrefetchSourceLines, viewport positioning honoured.
        let pre_fill = Fx::ONE
            .plus(Fx::int(p.config.plane.v_taps as i64))
            .plus(Fx::ONE)
            .over(Fx::int(2))
            .floor()
            .max(0) as u64;
        let swath_height = p.geometry.swath_height;
        let max_num_swath = pre_fill.saturating_sub(1).div_ceil(swath_height) + 1;
        let partial = if pre_fill > 1 {
            (pre_fill - 2) % swath_height
        } else {
            (pre_fill + swath_height - 2) % swath_height
        }
        .max(1);
        p.source_lines = Fx::int((max_num_swath * swath_height + partial) as i64);
        p.v_init_pre_fill = Fx::int(pre_fill as i64);
        p.max_num_swath = max_num_swath as u32;
        // MaxVStartupLines: progressive, no writeback.
        p.max_v_startup = (t.v_total - t.v_active).saturating_sub(1);

        // UrgentBurstFactorLuma/Cursor in active (VRatio 1): no VStartup can
        // hide a latency the DET or cursor buffer cannot.
        p.burst = urgent_burst(&p.geometry, p.line_time, urgent_latency, Fx::ONE)
            .ok_or(Error::NoTimeForPrefetch)?;
        p.cursor_burst = cursor_burst(p.config.cursors, p.line_time, urgent_latency, Fx::ONE)
            .ok_or(Error::NoTimeForPrefetch)?;
    }
    let maximum_max_v_startup = planes.iter().map(|p| p.max_v_startup).max().unwrap_or(0);

    // dcn30_internal_validate_bw: prefetch mode 0 (self refresh and the DRAM
    // clock change allowed in vblank); mode 1 when that fails or leaves the
    // clock change unsupported. Mode 2 is never used. Each mode runs DML's
    // VStartup search: one VStartupLines for every plane, each capped at
    // its own MaxVStartupLines, until the configuration fits.
    let mut schedules: Vec<Schedule> = Vec::new();
    schedules
        .try_reserve_exact(planes.len())
        .map_err(|_| Error::Unsupported)?;
    for mode in 0..=1u8 {
        let wait = t_wait(mode, urgent_latency);
        let mut lines = FIRST_VSTARTUP_LINES;
        loop {
            schedules.clear();
            let mut total = Fx::ZERO;
            let mut fits = true;
            for p in &planes {
                let v_startup = lines.min(p.max_v_startup);
                let Some(s) = schedule(&global, p, v_startup, wait) else {
                    fits = false;
                    break;
                };
                let pre =
                    urgent_burst(&p.geometry, p.line_time, urgent_latency, s.v_ratio_prefetch);
                let cursor_pre = cursor_burst(
                    p.config.cursors,
                    p.line_time,
                    urgent_latency,
                    s.v_ratio_prefetch,
                );
                let (Some(pre), Some(cursor_pre)) = (pre, cursor_pre) else {
                    fits = false;
                    break;
                };
                // MaxTotalRDBandwidth: active fetch plus cursor, or every
                // pipe's prefetch plus the cursor at the prefetch VRatio.
                total = total.plus(
                    p.read_bandwidth
                        .times(p.burst)
                        .plus(p.cursor_bandwidth.times(p.cursor_burst))
                        .max(
                            Fx::int(p.dpp as i64)
                                .times(s.required_bandwidth.times(pre))
                                .plus(
                                    p.cursor_bandwidth
                                        .times(s.v_ratio_prefetch)
                                        .times(cursor_pre),
                                ),
                        ),
                );
                if s.dst_y_prefetch < Fx::int(2)
                    || s.v_ratio_prefetch > Fx::int(MAX_VRATIO_PREFETCH)
                {
                    fits = false;
                    break;
                }
                schedules.push(s);
            }
            if fits && total <= return_bw {
                let plan = finish(soc, &global, &planes, &schedules, mode, lines)?;
                if mode == 0 && plan.dram_clock_change == DramClockChange::Unsupported {
                    break;
                }
                return Ok(plan);
            }
            lines += 1;
            if lines > maximum_max_v_startup {
                break;
            }
        }
    }
    Err(Error::NoTimeForPrefetch)
}

fn finish(
    soc: &Soc,
    g: &Global,
    planes: &[PlaneCalc],
    schedules: &[Schedule],
    mode: u8,
    lines: u32,
) -> Result<JointPlan, Error> {
    let n = planes.len();
    // CalculateWatermarksAndDRAMSpeedChangeSupport.
    let pstate_latency = Fx::int(DRAM_CLOCK_CHANGE_LATENCY_US);
    let sr_exit = Fx::ratio(SR_EXIT_US_TENTHS, 10);
    let sr_enter_plus_exit = Fx::int(SR_ENTER_PLUS_EXIT_US);
    let urgent_wm = g.urgent_latency.plus(g.extra_latency);
    let pstate_wm = pstate_latency.plus(urgent_wm);
    let wake = Fx::int(10).over(g.deep_sleep);
    let stutter_exit = sr_exit.plus(g.extra_latency).plus(wake);
    let mut min_margin: Option<(usize, Fx)> = None;
    let mut margins = [Fx::ZERO; MAX_PIPES];
    let mut critical: Option<(Fx, Fx)> = None;
    for (k, p) in planes.iter().enumerate() {
        let geometry = &p.geometry;
        let line_time = p.line_time;
        let lines_in_det =
            geometry.det_buffer_bytes / geometry.bytes_per_pixel / geometry.swath_width;
        let lines_rounded = lines_in_det / geometry.swath_height * geometry.swath_height;
        let full_det_time = Fx::int(lines_rounded as i64).times(line_time);
        // ActiveDRAMClockChangeLatencyMargin, luma only, less the other
        // planes' share of a swath when several are active.
        let lb_lines = Fx::int(
            MAX_LINE_BUFFER_LINES
                .min((LINE_BUFFER_SIZE_BITS / LB_BIT_PER_PIXEL / geometry.swath_width) as i64)
                - (p.config.plane.v_taps as i64 - 1),
        );
        let mut margin = lb_lines
            .times(line_time)
            .plus(full_det_time)
            .minus(urgent_wm)
            .minus(line_time.times(p.after_scaler_lines))
            .minus(pstate_wm);
        if n > 1 {
            margin = margin.minus(
                Fx::ONE
                    .minus(Fx::ratio(1, n as i64))
                    .times(Fx::int(geometry.swath_height as i64))
                    .times(line_time),
            );
        }
        margins[k] = margin;
        if min_margin.is_none_or(|(_, m)| margin < m) {
            min_margin = Some((k, margin));
        }
        // TimeToFinishSwathTransferStutterCriticalPlane: the plane with the
        // shortest full-DET buffering time (the last of equals).
        if critical.is_none_or(|(t, _)| full_det_time <= t) {
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
            critical = Some((full_det_time, finish_swath));
        }
    }
    let (min_plane, min_margin) = min_margin.ok_or(Error::Invalid)?;
    // SecondMinActiveDRAMClockChangeMarginOneDisplayInVBLank.
    let second = margins[..n]
        .iter()
        .enumerate()
        .filter(|(k, _)| *k != min_plane)
        .map(|(_, m)| *m)
        .min();
    // SynchronizedVBlank is false: this driver never synchronizes OTGs.
    let dram_clock_change = if min_margin > Fx::ZERO {
        DramClockChange::Vactive
    } else if mode == 0 && (n == 1 || second.is_some_and(|m| m > Fx::ZERO)) {
        DramClockChange::Vblank
    } else {
        DramClockChange::Unsupported
    };
    let stutter_enter = sr_enter_plus_exit
        .plus(g.extra_latency)
        .plus(wake)
        .max(critical.map_or(Fx::ZERO, |(_, f)| f));
    let watermarks = Watermarks {
        urgent_us: urgent_wm,
        pstate_change_us: pstate_wm,
        stutter_exit_us: stutter_exit,
        stutter_enter_plus_exit_us: stutter_enter,
        z8_stutter_exit_us: Fx::ZERO,
        z8_stutter_enter_plus_exit_us: Fx::ZERO,
        urgent_latency_us: g.urgent_latency,
        extra_latency_us: g.extra_latency,
        return_bandwidth_bytes_per_us: g.return_bw,
        pstate_latency_us: pstate_latency,
        sr_exit_us: sr_exit,
        sr_enter_plus_exit_us: sr_enter_plus_exit,
    };
    // MinTTUVBlank for the selected prefetch mode, plus TCalc.
    let min_ttu_vblank = g.t_calc.plus(match mode {
        0 => pstate_wm.max(stutter_enter.max(urgent_wm)),
        1 => stutter_enter.max(urgent_wm),
        _ => urgent_wm,
    });
    let khz = |clock: Fx| clock.times(Fx::int(1000)).ceil().clamp(0, u32::MAX as i64) as u32;
    let mut out: Vec<PlanePlan> = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Error::Unsupported)?;
    let mut fraction = Fx::ZERO;
    for (p, s) in planes.iter().zip(schedules) {
        // VBA values the DLG layer reads back through `(unsigned int)` casts.
        let prefetch = Prefetch {
            v_startup: lines.min(p.max_v_startup),
            max_v_startup: p.max_v_startup,
            dst_y_prefetch: s.dst_y_prefetch,
            dst_y_per_vm_vblank: s.dst_y_per_vm_vblank,
            dst_y_per_row_vblank: s.dst_y_per_row_vblank,
            lines_for_prefetch_pixel_data: s.lines_for_pixel_data,
            v_ratio_prefetch: s.v_ratio_prefetch,
            required_prefetch_bandwidth_bytes_per_us: s.required_bandwidth,
            prefetch_bandwidth_bytes_per_us: s.bandwidth,
            dst_x_after_scaler: p.dst_x_after_scaler.floor().max(0) as u32,
            dst_y_after_scaler: p.dst_y_after_scaler,
            v_update_offset_pix: p.v_update_offset.floor().max(0) as u32,
            v_update_width_pix: p.v_update_width.floor().max(0) as u32,
            v_ready_offset_pix: p.v_ready_offset.floor().max(0) as u32,
            t_setup_us: p.t_setup,
            t_calc_us: g.t_calc,
            t_wait_us: t_wait(mode, g.urgent_latency),
            prefetch_source_lines: p.source_lines,
            v_init_pre_fill: p.v_init_pre_fill,
            max_num_swath: p.max_num_swath,
        };
        // FractionOfUrgentBandwidth: MaxTotalRDBandwidthNoUrgentBurst.
        fraction = fraction.plus(
            p.read_bandwidth.plus(p.cursor_bandwidth).max(
                Fx::int(p.dpp as i64)
                    .times(s.required_bandwidth)
                    .plus(p.cursor_bandwidth.times(s.v_ratio_prefetch)),
            ),
        );
        let mut pipes = [None; 2];
        let slice = p.config.timing.h_active / p.dpp;
        for (index, pipe) in pipes.iter_mut().take(p.dpp as usize).enumerate() {
            let registers = registers(
                p,
                &prefetch,
                min_ttu_vblank,
                soc.dchub_refclk_khz,
                index as u32,
            )?;
            *pipe = Some(PipePlan {
                viewport_x: slice * index as u32,
                viewport_width: if p.dpp == 1 {
                    p.config.plane.viewport_width
                } else {
                    slice
                },
                registers,
                cursor: cursor_ttu(p, &prefetch, soc.dchub_refclk_khz)?,
            });
        }
        out.push(PlanePlan {
            odm: p.odm,
            geometry: p.geometry,
            prefetch,
            dppclk_khz: khz(p.dppclk),
            dsc_delay: p.dsc_delay,
            pipes,
        });
    }
    let fraction = fraction.over(g.return_bw);
    // linux-lit: 0x3ff=DCHUBBUB_ARB_FRAC_URG_BW_NOM_A__DCHUBBUB_ARB_FRAC_URG_BW_NOM_A_MASK
    let frac_urg_bw_nom = fraction.times(Fx::int(1000)).floor().clamp(0, 0x3ff) as u32;
    // convert_and_clamp(ns, refclk): ns is already truncated by the caller.
    let cycles = |us: Fx| -> u32 {
        let ns = us.times(Fx::int(1000)).floor().max(0);
        // linux: n/a (clamp 0x1fffff, literal in dcn21_hubbub.c convert_and_clamp calls)
        (ns as u64 * (soc.dchub_refclk_khz as u64 / 1000) / 1000).min(0x1f_ffff) as u32
    };
    let hubbub = WatermarkSet {
        urgent: cycles(urgent_wm),
        urgent_latency: cycles(g.urgent_latency),
        sr_enter: cycles(stutter_enter),
        sr_exit: cycles(stutter_exit),
        // dcn30_fpu_calculate_wm_and_dlg: without p-state support set A
        // takes set C's values with no p-state watermark.
        dram_clock_change: if dram_clock_change == DramClockChange::Unsupported {
            0
        } else {
            cycles(pstate_wm)
        },
        frac_urg_bw_nom,
        frac_urg_bw_flip: 0,
    };
    let clocks = ClockState {
        dcfclk_khz: soc.dcfclk_khz,
        fclk_khz: soc.fabric_khz,
        socclk_khz: soc.socclk_khz,
        dispclk_khz: khz(g.dispclk),
        dppclk_khz: out.iter().map(|p| p.dppclk_khz).max().unwrap_or(0),
        deep_sleep_dcfclk_khz: khz(g.deep_sleep),
    };
    Ok(JointPlan {
        prefetch_mode: mode,
        clocks,
        watermarks,
        hubbub,
        dram_clock_change,
        urgent_bandwidth_thousandths: frac_urg_bw_nom,
        planes: out,
    })
}

/// `calculate_ttu_cursor` for one 256-wide 32-bpp cursor: 256-byte requests
/// of 64 pixels, four per line, hscl_ratio 1. None without a cursor.
fn cursor_ttu(
    p: &PlaneCalc,
    prefetch: &Prefetch,
    refclk_khz: u32,
) -> Result<Option<CursorTtu>, Error> {
    if p.config.cursors == 0 {
        return Ok(None);
    }
    let refclk = mhz(refclk_khz);
    let ref_to_pix = refclk.over(p.pixel_clock);
    let req_width = 256 / (CURSOR_BPP / 8);
    let req_per_width = CURSOR_WIDTH.div_ceil(req_width) as i64;
    let delivery = |v_ratio: Fx| {
        if v_ratio <= Fx::ONE {
            Fx::int(CURSOR_WIDTH as i64)
                .times(ref_to_pix)
                .over(Fx::int(req_per_width))
        } else {
            refclk
                .times(Fx::int(CURSOR_WIDTH as i64))
                .over(Fx::int(2).times(p.dppclk))
                .over(Fx::int(req_per_width))
        }
    };
    // linux: n/a (refcyc_per_req_delivery_cur0 * 2^10, display_rq_dlg_calc_30.c)
    Ok(Some(CursorTtu {
        refcyc_per_req_delivery: field(delivery(Fx::ONE), 10, 23)?,
        refcyc_per_req_delivery_pre: field(delivery(prefetch.v_ratio_prefetch), 10, 23)?,
        qos_level_fixed: 8, // linux: n/a (qos_level_fixed_cur0 = 8, display_rq_dlg_calc_30.c)
        qos_ramp_disable: 0,
    }))
}

/// `get_refcyc_per_delivery`. With ODM combine Linux scales the full recout
/// by the combine factor and caps it at the slice: for an even active width
/// that is the same `refclk x recout / pclk` as without.
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

/// `dml30_rq_dlg_get_rq_reg` + `dml30_rq_dlg_get_dlg_reg` for ODM slice
/// `slice` of the plane (0 without ODM).
fn registers(
    p: &PlaneCalc,
    prefetch: &Prefetch,
    min_ttu_vblank: Fx,
    dchub_refclk_khz: u32,
    slice: u32,
) -> Result<Registers, Error> {
    let config = &p.config;
    let geometry = &p.geometry;
    let t = &config.timing;
    let refclk = mhz(dchub_refclk_khz);
    let ref_to_pix = refclk.over(p.pixel_clock);
    if ref_to_pix >= Fx::int(4) {
        return Err(Error::Unsupported);
    }
    let h_total = t.h_total as u64;
    let bytes_per_pixel = geometry.bytes_per_pixel;
    let pitch = config.plane.pitch as u64;
    // get_meta_and_pte_attr: an ODM pipe's viewport is its slice of the
    // active width; the swath upper bound is capped at the pitch.
    let vp_width = match p.odm {
        Odm::None => config.plane.viewport_width as u64,
        Odm::TwoToOne => (config.plane.viewport_width as u64).min(t.h_active as u64 / 2),
    };
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
        // linux: n/a (dml_log2(chunk_bytes) - 10, display_rq_dlg_calc_30.c:extract_rq_sizing_regs)
        chunk_size: log2_floor(CHUNK_BYTES) - 10,
        // linux: n/a (dml_log2(min_chunk_bytes) - 8 + 1, display_rq_dlg_calc_30.c)
        min_chunk_size: log2_floor(MIN_CHUNK_BYTES) - 8 + 1,
        // linux: n/a (dml_log2(meta_chunk_bytes) - 10, display_rq_dlg_calc_30.c)
        meta_chunk_size: log2_floor(META_CHUNK_BYTES) - 10,
        // linux: n/a (dml_log2(min_meta_chunk_bytes) - 6 + 1, display_rq_dlg_calc_30.c)
        min_meta_chunk_size: log2_floor(MIN_META_CHUNK_BYTES) - 6 + 1,
        // linux: n/a (dml_log2(dpte_group_bytes) - 6, display_rq_dlg_calc_30.c)
        dpte_group_size: log2_floor(PTE_GROUP_BYTES) - 6,
        // linux: n/a (dml_log2(mpte_group_bytes) - 6, display_rq_dlg_calc_30.c)
        mpte_group_size: log2_floor(MPTE_GROUP_BYTES) - 6,
        // Linear: log2 swath height 0.
        swath_height: 0,
        // linux: n/a (dml_log2(dpte_row_height) - 3, display_rq_dlg_calc_30.c)
        pte_row_height_linear: log2_floor(dpte_row_height) - 3,
        // linux: n/a (drq_expansion_mode = 2, display_rq_dlg_calc_30.c:dml30_rq_dlg_get_rq_reg)
        drq_expansion_mode: 2,
        prq_expansion_mode: 1, // linux: n/a (prq_expansion_mode = 1, display_rq_dlg_calc_30.c)
        mrq_expansion_mode: 1, // linux: n/a (mrq_expansion_mode = 1, display_rq_dlg_calc_30.c)
        crq_expansion_mode: 1, // linux: n/a (crq_expansion_mode = 1, display_rq_dlg_calc_30.c)
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
    let hscale_pixel_rate = Fx::int(2).times(p.dppclk);
    let recout = t.h_active as u64;
    let line_delivery = refcyc_per_delivery(
        refclk,
        p.pixel_clock,
        recout,
        Fx::ONE,
        hscale_pixel_rate,
        swath_width_ub,
        1,
    );
    let line_delivery_pre = refcyc_per_delivery(
        refclk,
        p.pixel_clock,
        recout,
        prefetch.v_ratio_prefetch,
        hscale_pixel_rate,
        swath_width_ub,
        1,
    );
    let req_delivery = refcyc_per_delivery(
        refclk,
        p.pixel_clock,
        recout,
        Fx::ONE,
        hscale_pixel_rate,
        vp_width,
        req_per_swath_ub,
    );
    let req_delivery_pre = refcyc_per_delivery(
        refclk,
        p.pixel_clock,
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
        .clamp(0, (1 << 23) - 1); // linux: n/a (dml_pow(2, 23) - 1 clamp, display_rq_dlg_calc_30.c)
                                  // An ODM pipe's horizontal blank ends where its slice starts.
    let h_blank_end = t.h_blank_end() as i64 + (slice * (t.h_active / p.dpp)) as i64;
    let dlg = LatencyRegisters {
        // linux: n/a (ref_freq_to_pix_freq * dml_pow(2, 19), display_rq_dlg_calc_30.c)
        ref_freq_to_pix_freq: field(ref_to_pix, 19, W_REF_FREQ_TO_PIX_FREQ)?,
        // linux: n/a (refcyc_per_htotal * dml_pow(2, 8), display_rq_dlg_calc_30.c)
        refcyc_per_htotal: field(
            ref_to_pix.times(Fx::int(h_total as i64)),
            8,
            W_REFCYC_PER_HTOTAL,
        )?,
        refcyc_h_blank_end: field(
            Fx::int(h_blank_end).times(ref_to_pix),
            0,
            W_REFCYC_H_BLANK_END,
        )?,
        dlg_vblank_end: whole(t.v_blank_end() as u64, W_DLG_VBLANK_END)?,
        // linux: n/a (min_dst_y_next_start * dml_pow(2, 2), display_rq_dlg_calc_30.c)
        min_dst_y_next_start: whole(vblank_start * 4, W_MIN_DST_Y_NEXT_START)?,
        refcyc_x_after_scaler: field(
            Fx::int(prefetch.dst_x_after_scaler as i64).times(ref_to_pix),
            0,
            W_REFCYC_X_AFTER_SCALER,
        )?,
        dst_y_after_scaler: whole(prefetch.dst_y_after_scaler as u64, W_DST_Y_AFTER_SCALER)?,
        // linux: n/a (dst_y_prefetch * dml_pow(2, 2), display_rq_dlg_calc_30.c)
        dst_y_prefetch: field(prefetch.dst_y_prefetch, 2, W_DST_Y_PREFETCH)?,
        // linux: n/a (dst_y_per_vm_vblank * dml_pow(2, 2), display_rq_dlg_calc_30.c)
        dst_y_per_vm_vblank: field(prefetch.dst_y_per_vm_vblank, 2, W_DST_Y_PER_VM_VBLANK)?,
        // linux: n/a (dst_y_per_row_vblank * dml_pow(2, 2), display_rq_dlg_calc_30.c)
        dst_y_per_row_vblank: field(prefetch.dst_y_per_row_vblank, 2, W_DST_Y_PER_ROW_VBLANK)?,
        // linux: n/a (vratio_prefetch * dml_pow(2, 19), display_rq_dlg_calc_30.c)
        vratio_prefetch: field(prefetch.v_ratio_prefetch, 19, W_VRATIO_PREFETCH)?,
        vready_after_vcount0,
        // linux: n/a (dst_y_per_pte_row_nom_l * dml_pow(2, 2), display_rq_dlg_calc_30.c)
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
        // linux: n/a (dst_y_delta_drq_limit = 0x7fff "off", display_rq_dlg_calc_30.c)
        dst_y_delta_drq_limit: 0x7fff,
        // linux: n/a (chunk_hdl_adjust_cur0 = 3, display_rq_dlg_calc_30.c)
        chunk_hdl_adjust_cur0: 3,
        dst_y_offset_cur0: 0,
    };
    let ttu = ThrottleRegisters {
        min_ttu_vblank: field(min_ttu_vblank.times(refclk), 0, W_MIN_TTU_VBLANK)?,
        qos_level_low_wm: 0, // linux: n/a (qos_level_low_wm = 0, display_rq_dlg_calc_30.c)
        // linux: n/a (4.0 * htotal * ref_freq_to_pix_freq, display_rq_dlg_calc_30.c)
        qos_level_high_wm: field(
            Fx::int(4).times(Fx::int(h_total as i64)).times(ref_to_pix),
            0,
            W_QOS_LEVEL_WM,
        )?,
        qos_level_flip: 14, // linux: n/a (qos_level_flip = 14, display_rq_dlg_calc_30.c)
        // linux: n/a (refcyc_per_req_delivery_l * dml_pow(2, 10), display_rq_dlg_calc_30.c)
        refcyc_per_req_delivery_l: field(req_delivery, 10, W_REFCYC_PER_REQ_DELIVERY)?,
        // linux: n/a (refcyc_per_req_delivery_pre_l * dml_pow(2, 10), display_rq_dlg_calc_30.c)
        refcyc_per_req_delivery_pre_l: field(req_delivery_pre, 10, W_REFCYC_PER_REQ_DELIVERY)?,
        qos_level_fixed_l: 8, // linux: n/a (qos_level_fixed_l = 8, display_rq_dlg_calc_30.c)
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
