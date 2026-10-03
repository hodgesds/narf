//! DCN 3.1.4 display mode math: the geometry, buffer and clock derivation that
//! Linux performs in DML. Parameters are `dcn3_14_ip` / `dcn3_14_soc` from
//! `dcn314_fpu.c`; the algorithms follow `display_mode_vba_314.c`.
//!
//! DML computes in `double`. This port uses fixed point, because kernel
//! floating point is not available here: `x86_64-unknown-none` is a soft-float
//! target and `arch/x86_64/kernel_ctx.rs` deliberately saves no FP/SIMD state
//! across a kernel context switch, while aarch64 keeps hardware FP whose
//! callee-saved `d8..d15` that switch does not preserve either. Rounding is
//! therefore chosen per quantity instead of inherited: anything that must not
//! be underestimated (required clocks, latencies, watermarks) rounds up, and
//! anything that must not be overestimated (buffer capacity, lines held in the
//! detile buffer) rounds down. A conservative watermark costs bandwidth; an
//! optimistic one underflows the pipe.
//!
//! Formulas are also rearranged where DML's own ordering would build a tiny
//! intermediate and then divide by it. A pipe delivery time of ~0.013 holds few
//! fixed-point units, so dividing by it amplifies its truncation; cancelling it
//! algebraically first keeps the result exact. The arithmetic is equivalent,
//! the magnitudes are not.
//!
//! Scope is one plane on one pipe: packed linear RGB, no DCC, no chroma
//! subsampling, no ODM combine, no MPC split, no DSC and no writeback — the
//! same surface shape the boot handoff is willing to inherit. Anything else is
//! rejected rather than approximated.

/// Fixed point with 2^-24 resolution. Products and quotients go through `i128`,
/// so no intermediate rounds twice. Arithmetic saturates instead of wrapping or
/// panicking, and every saturation moves a result toward a larger clock or
/// watermark, which is the safe direction. All quantities here are
/// non-negative; `floor`/`ceil` assume that.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Fx(i64);

const FRAC: u32 = 24;
const ONE: i64 = 1 << FRAC;

fn clamp(value: i128) -> Fx {
    Fx(value.clamp(i64::MIN as i128, i64::MAX as i128) as i64)
}
impl Fx {
    pub const ZERO: Fx = Fx(0);
    pub const ONE: Fx = Fx(ONE);
    pub const MAX: Fx = Fx(i64::MAX);
    pub const fn int(value: i64) -> Fx {
        Fx(value.saturating_mul(ONE))
    }
    pub fn ratio(numerator: i64, denominator: i64) -> Fx {
        Fx::int(numerator).over(Fx::int(denominator))
    }
    /// `1 + p%`, where `tenths` is p in tenths of a percent: 5 gives 1.005.
    fn one_plus_percent_tenths(tenths: i64) -> Fx {
        Fx::ONE.plus(Fx::ratio(tenths, 1000))
    }
    pub fn plus(self, other: Fx) -> Fx {
        Fx(self.0.saturating_add(other.0))
    }
    pub fn minus(self, other: Fx) -> Fx {
        Fx(self.0.saturating_sub(other.0))
    }
    pub fn times(self, other: Fx) -> Fx {
        clamp((self.0 as i128 * other.0 as i128) >> FRAC)
    }
    /// A zero denominator saturates to `MAX` rather than trapping. Callers
    /// validate their inputs, so this is unreachable; if it were reached the
    /// result would be an impossibly large requirement, which fails closed.
    pub fn over(self, other: Fx) -> Fx {
        if other.0 == 0 {
            return Fx::MAX;
        }
        clamp(((self.0 as i128) << FRAC) / other.0 as i128)
    }
    pub fn min(self, other: Fx) -> Fx {
        if self.0 <= other.0 {
            self
        } else {
            other
        }
    }
    pub fn max(self, other: Fx) -> Fx {
        if self.0 >= other.0 {
            self
        } else {
            other
        }
    }
    pub fn floor(self) -> i64 {
        self.0 >> FRAC
    }
    pub fn ceil(self) -> i64 {
        self.0.saturating_add(ONE - 1) >> FRAC
    }
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
    pub fn raw(self) -> i64 {
        self.0
    }
}
/// `dml_ceil(value, multiple)`.
pub(crate) fn ceil_multiple(value: u64, multiple: u64) -> u64 {
    if multiple == 0 {
        return value;
    }
    value.div_ceil(multiple).saturating_mul(multiple)
}
/// Integer log2 of a power of two, floored. DML's `dml_log2` is only applied to
/// power-of-two sizes in the paths this port uses.
pub(crate) fn log2_floor(value: u64) -> u32 {
    value.max(1).ilog2()
}
/// `dml_floor(value, multiple)`. Only the rounding tests need it: every
/// production path here rounds outward.
#[cfg(feature = "kernel-test")]
fn floor_multiple(value: u64, multiple: u64) -> u64 {
    if multiple == 0 {
        return value;
    }
    value / multiple * multiple
}
/// `RoundToDFSGranularityUp`: the DFS can only divide the VCO by whole steps,
/// so a request lands on the next frequency the divider can actually produce.
fn dfs_up(clock_khz: Fx, vco_khz: Fx) -> Fx {
    let quad = vco_khz.times(Fx::int(4));
    let steps = quad.over(clock_khz).floor().max(1);
    quad.over(Fx::int(steps))
}
fn dfs_down(clock_khz: Fx, vco_khz: Fx) -> Fx {
    let quad = vco_khz.times(Fx::int(4));
    let steps = quad.over(clock_khz).ceil().max(1);
    quad.over(Fx::int(steps))
}

// ── dcn3_14_ip / dcn3_14_soc ────────────────────────────────────────────
/// `det_buffer_size_kbytes` (`DCN3_14_DEFAULT_DET_SIZE`).
pub const DET_BUFFER_KBYTES: u64 = 384;
const LINE_BUFFER_SIZE_BITS: u64 = 789_504;
const LINE_BUFFER_BPP: u64 = 48;
const MAX_DCHUB_TO_PSCL_PIX_PER_CLK: i64 = 4;
const MAX_PSCL_TO_LB_PIX_PER_CLK: i64 = 2;
const MAX_SCL_RATIO: u32 = 6;
const MAX_SCL_TAPS: u32 = 8;
const RETURN_BUS_WIDTH_BYTES: i64 = 64;
/// `dispclk_ramp_margin_percent` = 1.0, `dcn_downspread_percent` = 0.5, both in
/// tenths of a percent.
const DISPCLK_RAMP_MARGIN_TENTHS: i64 = 10;
const DOWNSPREAD_TENTHS: i64 = 5;
/// `__DML_MIN_DCFCLK_FACTOR__`, in hundredths.
const MIN_DCFCLK_FACTOR_HUNDREDTHS: i64 = 115;
/// Linear surfaces are limited by the detile buffer, not the DPP line store.
const MAX_SWATH_WIDTH_LINEAR: u64 = 8192;
/// `gpuvm_min_page_size_bytes` and `dpte_buffer_size_in_pte_reqs_luma`.
pub(crate) const GPUVM_MIN_PAGE_BYTES: u64 = 4096;
pub(crate) const DPTE_BUFFER_IN_PTE_REQS_LUMA: u64 = 64;
/// `pixel_chunk_size_kbytes`, `meta_chunk_size_kbytes` and the minimum chunk
/// sizes the RQ registers encode, in bytes.
pub(crate) const CHUNK_BYTES: u64 = 8192;
pub(crate) const MIN_CHUNK_BYTES: u64 = 1024;
pub(crate) const META_CHUNK_BYTES: u64 = 2048;
pub(crate) const MIN_META_CHUNK_BYTES: u64 = 256;
pub(crate) const DPTE_GROUP_BYTES: u64 = 2048;
pub(crate) const MPTE_GROUP_BYTES: u64 = 2048;
/// `get_vco_frequency_from_reg` fallback. The caller should pass the measured
/// DENTIST VCO instead of assuming this.
pub const DEFAULT_DENTIST_VCO_KHZ: u32 = 3_600_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A surface, scaling or timing shape this port does not model.
    Unsupported,
    Invalid,
    /// The configuration exceeds a hardware buffer, not just a clock ceiling.
    ViewportTooLarge,
    /// No VStartup between DML's minimum and the vertical blank can fit the
    /// prefetch this mode needs.
    NoTimeForPrefetch,
}
/// The packed RGB formats the boot handoff is willing to inherit, named by
/// their DML source format (`dm_444_16/32/64`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Rgb16,
    Rgb32,
    Rgb64,
}
impl Format {
    pub fn bytes_per_pixel(self) -> u64 {
        match self {
            Format::Rgb16 => 2,
            Format::Rgb32 => 4,
            Format::Rgb64 => 8,
        }
    }
    /// `BlockHeight256BytesY` for linear tiling is always one line.
    fn block_height_256(self) -> u64 {
        1
    }
    fn block_width_256(self) -> u64 {
        256 / self.bytes_per_pixel() / self.block_height_256()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    pub pixel_clock_khz: u32,
    pub h_active: u32,
    pub h_total: u32,
    pub h_front_porch: u32,
    pub h_sync_width: u32,
    pub v_active: u32,
    pub v_total: u32,
    pub v_front_porch: u32,
    pub v_sync_width: u32,
    /// Sync polarity as the sink's mode declares it. The timing generator
    /// programs the inverse, since its field means "negative".
    pub h_sync_positive: bool,
    pub v_sync_positive: bool,
}
impl Timing {
    /// The blanking that follows the front porch, which is what the DLG's
    /// blank-end fields count: sync plus back porch.
    pub fn h_blank_end(&self) -> u32 {
        self.h_total
            .saturating_sub(self.h_active)
            .saturating_sub(self.h_front_porch)
    }
    pub fn v_blank_end(&self) -> u32 {
        self.v_total
            .saturating_sub(self.v_active)
            .saturating_sub(self.v_front_porch)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plane {
    pub format: Format,
    /// Allocated surface extent in pixels/lines, which bounds the swath.
    pub surface_width: u32,
    pub surface_height: u32,
    pub viewport_width: u32,
    pub viewport_height: u32,
    /// Surface pitch in pixels; the linear PTE row height depends on it.
    pub pitch: u32,
    /// Scaler taps. One tap each means the scaler is bypassed.
    pub h_taps: u32,
    pub v_taps: u32,
}
/// One plane on one pipe, with the DENTIST VCO the clock manager measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub timing: Timing,
    pub plane: Plane,
    pub dentist_vco_khz: u32,
    /// Cursors on this pipe; each adds a CNVC cursor delay to the scaler path.
    pub cursors: u32,
}
/// Detile-buffer geometry. `swath_width_ub` is the width actually fetched once
/// rounded up to a 256-byte request, which is what the DET must hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub bytes_per_pixel: u64,
    pub block_width_256: u64,
    pub block_height_256: u64,
    pub swath_width: u64,
    pub swath_width_ub: u64,
    pub swath_height: u64,
    pub det_buffer_bytes: u64,
    pub h_ratio: Fx,
    pub v_ratio: Fx,
}
/// Clock requirements, already rounded to what the DFS dividers can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requirements {
    pub dispclk_khz: u32,
    pub dppclk_khz: u32,
    pub deep_sleep_dcfclk_khz: u32,
    /// Luma read bandwidth in bytes per microsecond.
    pub read_bandwidth_bytes_per_us: Fx,
    pub pscl_throughput: Fx,
}

impl Config {
    fn validate(&self) -> Result<(), Error> {
        let t = &self.timing;
        let p = &self.plane;
        if t.pixel_clock_khz == 0
            || t.h_active == 0
            || t.v_active == 0
            || t.h_total <= t.h_active
            || t.v_total <= t.v_active
            || self.dentist_vco_khz == 0
        {
            return Err(Error::Invalid);
        }
        if p.viewport_width == 0
            || p.viewport_height == 0
            || p.surface_width < p.viewport_width
            || p.surface_height < p.viewport_height
        {
            return Err(Error::Invalid);
        }
        if p.pitch < p.surface_width {
            return Err(Error::Invalid);
        }
        if t.h_front_porch == 0
            || t.v_front_porch == 0
            || t.h_front_porch >= t.h_total - t.h_active
            || t.v_front_porch >= t.v_total - t.v_active
        {
            return Err(Error::Invalid);
        }
        // Sync has to fit inside the blanking that follows the front porch.
        if t.h_sync_width == 0
            || t.v_sync_width == 0
            || t.h_sync_width > t.h_blank_end()
            || t.v_sync_width > t.v_blank_end()
        {
            return Err(Error::Invalid);
        }
        if p.h_taps == 0 || p.v_taps == 0 || p.h_taps > MAX_SCL_TAPS || p.v_taps > MAX_SCL_TAPS {
            return Err(Error::Unsupported);
        }
        // Downscaling beyond the scaler's ratio limit is a different pipeline.
        if p.viewport_width > t.h_active.saturating_mul(MAX_SCL_RATIO)
            || p.viewport_height > t.v_active.saturating_mul(MAX_SCL_RATIO)
        {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    fn ratios(&self) -> (Fx, Fx) {
        (
            Fx::ratio(
                self.plane.viewport_width as i64,
                self.timing.h_active as i64,
            ),
            Fx::ratio(
                self.plane.viewport_height as i64,
                self.timing.v_active as i64,
            ),
        )
    }
    /// `CalculateSwathAndDETConfiguration` for a single linear RGB plane.
    /// Linear tiling pins the minimum swath height to the maximum, so the
    /// detile buffer is never split between luma and chroma here.
    pub fn geometry(&self) -> Result<Geometry, Error> {
        self.validate()?;
        let (h_ratio, v_ratio) = self.ratios();
        let format = self.plane.format;
        let bytes_per_pixel = format.bytes_per_pixel();
        let block_width_256 = format.block_width_256();
        let block_height_256 = format.block_height_256();
        let swath_width = self.plane.viewport_width as u64;
        // swath_width_ub: round the fetched width up to a whole 256-byte
        // request, but never past the allocated surface.
        let surface_width_ub = ceil_multiple(self.plane.surface_width as u64, block_width_256);
        let swath_width_ub =
            surface_width_ub.min(ceil_multiple(swath_width - 1, block_width_256) + block_width_256);
        // Linear: MinimumSwathHeightY == MaximumSwathHeightY.
        let swath_height = block_height_256;
        let det_bytes = ceil_multiple(DET_BUFFER_KBYTES, 64) * 1024;
        let swath_bytes = swath_width_ub
            .saturating_mul(bytes_per_pixel)
            .saturating_mul(swath_height);
        // Double buffering: two swaths must fit, so one swath may use half.
        if swath_bytes > det_bytes / 2 {
            return Err(Error::ViewportTooLarge);
        }
        let line_buffer_limit = (LINE_BUFFER_SIZE_BITS * h_ratio.max(Fx::ONE).ceil() as u64)
            / LINE_BUFFER_BPP
            / (self.plane.v_taps as u64 + (v_ratio.ceil() as u64).saturating_sub(2));
        if swath_width > MAX_SWATH_WIDTH_LINEAR.min(line_buffer_limit) {
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
            h_ratio,
            v_ratio,
        })
    }
    /// Required DISPCLK/DPPCLK and the deep-sleep DCFCLK floor. DISPCLK keeps
    /// DML's ramping margin where the DPM table can supply it and drops to the
    /// unramped requirement otherwise, so a mode is never refused for a margin.
    pub fn requirements(
        &self,
        geometry: &Geometry,
        max_dispclk_khz: u32,
    ) -> Result<Requirements, Error> {
        self.validate()?;
        let pixel_clock = Fx::int(self.timing.pixel_clock_khz as i64);
        let vco = Fx::int(self.dentist_vco_khz as i64);
        let downspread = Fx::one_plus_percent_tenths(DOWNSPREAD_TENTHS);
        let ramping = Fx::one_plus_percent_tenths(DISPCLK_RAMP_MARGIN_TENTHS);
        let Geometry {
            h_ratio, v_ratio, ..
        } = *geometry;

        // PSCL throughput in pixels per DPPCLK.
        let max_dchub = Fx::int(MAX_DCHUB_TO_PSCL_PIX_PER_CLK);
        let max_pscl = Fx::int(MAX_PSCL_TO_LB_PIX_PER_CLK);
        let pscl_throughput = if h_ratio > Fx::ONE {
            let taps = Fx::int(Fx::ratio(self.plane.h_taps as i64, 6).ceil().max(1));
            max_dchub.min(max_pscl.times(h_ratio).over(taps))
        } else {
            max_dchub.min(max_pscl)
        };
        let mut dppclk = pixel_clock.times(
            Fx::ratio(self.plane.v_taps as i64, 6)
                .times(Fx::ONE.min(h_ratio))
                .max(h_ratio.times(v_ratio).over(pscl_throughput).max(Fx::ONE)),
        );
        if (self.plane.h_taps > 6 || self.plane.v_taps > 6)
            && dppclk < pixel_clock.times(Fx::int(2))
        {
            dppclk = pixel_clock.times(Fx::int(2));
        }
        let dppclk = dfs_up(dppclk.times(downspread), vco);

        let without_ramping = dfs_up(pixel_clock.times(downspread), vco);
        let with_ramping = dfs_up(pixel_clock.times(downspread).times(ramping), vco);
        let ceiling = dfs_down(Fx::int(max_dispclk_khz as i64), vco);
        let dispclk = if without_ramping > ceiling {
            // The mode needs more than the DPM table offers; report the real
            // requirement and let the caller refuse it.
            without_ramping
        } else if with_ramping > ceiling {
            ceiling
        } else {
            with_ramping
        };

        // CalculateDCFCLKDeepSleep for one plane, luma only. The swath width
        // appears in both the byte count and the line delivery time, so it
        // cancels: the rate the pipe consumes the line is what matters.
        let bytes_per_pixel = Fx::int(geometry.bytes_per_pixel as i64);
        let bytes_per_cycle = Fx::ratio(MIN_DCFCLK_FACTOR_HUNDREDTHS, 100)
            .times(bytes_per_pixel)
            .over(Fx::int(RETURN_BUS_WIDTH_BYTES));
        let pixels_per_unit_time = if v_ratio <= Fx::ONE {
            h_ratio.times(pixel_clock)
        } else {
            pscl_throughput.times(dppclk)
        };
        let deep_sleep = bytes_per_cycle
            .times(pixels_per_unit_time)
            .max(pixel_clock.over(Fx::int(16)));

        // Bytes per microsecond fetched for this plane. Lines per unit time is
        // formed first so the product never reaches the saturation range.
        let lines_per_unit_time = pixel_clock.over(Fx::int(self.timing.h_total as i64));
        let read_bandwidth = Fx::int(geometry.swath_width as i64)
            .times(bytes_per_pixel)
            .times(v_ratio)
            .times(lines_per_unit_time)
            .over(Fx::int(1000));

        Ok(Requirements {
            dispclk_khz: dispclk.ceil().clamp(0, u32::MAX as i64) as u32,
            dppclk_khz: dppclk.ceil().clamp(0, u32::MAX as i64) as u32,
            deep_sleep_dcfclk_khz: deep_sleep.ceil().clamp(0, u32::MAX as i64) as u32,
            read_bandwidth_bytes_per_us: read_bandwidth,
            pscl_throughput,
        })
    }
}

// ── Watermarks and the prefetch schedule ────────────────────────────────
/// `pixel_chunk_size_kbytes`, `round_trip_ping_latency_dcfclk_cycles` and the
/// `__DML_ARB_TO_RET_DELAY__` pair, plus the fabric/DRAM efficiency percentages.
const PIXEL_CHUNK_KBYTES: i64 = 8;
const ROUND_TRIP_PING_LATENCY_DCFCLK_CYCLES: i64 = 106;
const ARB_TO_RET_DELAY_CYCLES: i64 = 7 + 95;
const URGENT_OUT_OF_ORDER_BYTES_PER_CHANNEL: i64 = 4096;
const FABRIC_DATAPATH_TO_DCN_RETURN_BYTES: i64 = 32;
const PCT_IDEAL_SDP_AFTER_URGENT: i64 = 80;
const PCT_IDEAL_DRAM_AFTER_URGENT_PIXEL_ONLY: i64 = 65;
/// `urgent_latency_pixel_data_only_us`; the mixed and VM-only values match it,
/// and `do_urgent_latency_adjustment` is false, so the max3 collapses.
const URGENT_LATENCY_US_TENTHS: i64 = 40;
/// Z8 self-refresh times stay from the SOC bounding box; only the three
/// non-Z8 latencies are overridden per memory type.
const SR_EXIT_Z8_US: i64 = 268;
const SR_ENTER_PLUS_EXIT_Z8_US: i64 = 393;
/// DPP and DISPCLK pipeline delays in clocks (`dppclk_delay_*`,
/// `dispclk_delay_subtotal`), and `max_inter_dcn_tile_repeaters`.
const DPPCLK_DELAY_SUBTOTAL: i64 = 46;
const DPPCLK_DELAY_SCL: i64 = 50;
const DPPCLK_DELAY_SCL_LB_ONLY: i64 = 16;
const DPPCLK_DELAY_CNVC_FORMATTER: i64 = 27;
const DPPCLK_DELAY_CNVC_CURSOR: i64 = 6;
const DISPCLK_DELAY_SUBTOTAL: i64 = 119;
const MAX_INTER_DCN_TILE_REPEATERS: i64 = 8;
/// `VBlankNomDefaultUS`.
const VBLANK_NOM_DEFAULT_US: i64 = 668;
/// `__DML_VBA_MIN_VSTARTUP__` and the DST_Y_PREFETCH register's U6.2 ceiling.
const MIN_VSTARTUP: u32 = 9;
const MAX_VSTARTUP: u32 = 1023;
/// `max_vratio_pre`: prefetch may not exceed four source lines per dest line.
const MAX_VRATIO_PREFETCH: i64 = 4;

fn mhz(khz: u32) -> Fx {
    Fx::ratio(khz as i64, 1000)
}
/// `dml_ceil(4 * value / unit, 1) / 4`: a quarter-line quantisation.
fn quarter_lines(value: Fx, line_time: Fx) -> Fx {
    Fx::ratio(Fx::int(4).times(value).over(line_time).ceil(), 4)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryKind {
    Ddr5,
    Lpddr5,
}
/// Memory configuration. Bandwidth and the p-state latency both depend on it,
/// so the channel count and width must come from the platform's VBIOS
/// integrated info and the speed from the DPM table — never a default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Memory {
    pub kind: MemoryKind,
    pub channels: u32,
    pub channel_width_bytes: u32,
    /// DRAM data rate in MT/s, as the DPM table reports it.
    pub speed_mts: u32,
}
impl Memory {
    /// The WM_A entry of Linux's per-memory-type watermark table overrides the
    /// SOC bounding box's three non-Z8 latencies.
    fn latencies(&self) -> (Fx, Fx, Fx) {
        match self.kind {
            MemoryKind::Ddr5 => (Fx::ratio(1172, 100), Fx::ratio(125, 10), Fx::ratio(145, 10)),
            MemoryKind::Lpddr5 => (Fx::ratio(1_165_333, 100_000), Fx::int(30), Fx::int(32)),
        }
    }
    fn valid(&self) -> bool {
        self.channels > 0
            && self.channels <= 16
            && matches!(self.channel_width_bytes, 2 | 4 | 8)
            && self.speed_mts > 0
    }
}
/// The clocks the pipeline will actually run at, as applied by the clock
/// manager. Watermarks derived for one clock state do not hold at another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockState {
    pub dcfclk_khz: u32,
    pub fclk_khz: u32,
    pub socclk_khz: u32,
    pub dispclk_khz: u32,
    pub dppclk_khz: u32,
    pub deep_sleep_dcfclk_khz: u32,
}
impl ClockState {
    fn valid(&self) -> bool {
        self.dcfclk_khz > 0
            && self.fclk_khz > 0
            && self.socclk_khz > 0
            && self.dispclk_khz > 0
            && self.dppclk_khz > 0
            && self.deep_sleep_dcfclk_khz > 0
    }
}
/// Watermarks in microseconds. The register encoding multiplies these by the
/// DCHUB reference clock, which belongs to the register layer, not here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watermarks {
    pub urgent_us: Fx,
    pub pstate_change_us: Fx,
    pub stutter_exit_us: Fx,
    pub stutter_enter_plus_exit_us: Fx,
    pub z8_stutter_exit_us: Fx,
    pub z8_stutter_enter_plus_exit_us: Fx,
    pub urgent_latency_us: Fx,
    pub extra_latency_us: Fx,
    pub return_bandwidth_bytes_per_us: Fx,
    /// The memory-type latencies the prefetch schedule needs in raw form.
    pub pstate_latency_us: Fx,
    pub sr_exit_us: Fx,
    pub sr_enter_plus_exit_us: Fx,
}
/// The prefetch schedule, in the units the DLG registers are derived from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefetch {
    pub v_startup: u32,
    pub max_v_startup: u32,
    pub dst_y_prefetch: Fx,
    pub dst_y_per_vm_vblank: Fx,
    pub dst_y_per_row_vblank: Fx,
    pub lines_for_prefetch_pixel_data: Fx,
    pub v_ratio_prefetch: Fx,
    pub required_prefetch_bandwidth_bytes_per_us: Fx,
    pub prefetch_bandwidth_bytes_per_us: Fx,
    pub dst_x_after_scaler: u32,
    pub dst_y_after_scaler: u32,
    pub v_update_offset_pix: u32,
    pub v_update_width_pix: u32,
    pub v_ready_offset_pix: u32,
    pub t_setup_us: Fx,
    pub t_calc_us: Fx,
    pub t_wait_us: Fx,
    pub prefetch_source_lines: Fx,
    pub v_init_pre_fill: Fx,
    pub max_num_swath: u32,
}

impl Config {
    fn line_time_us(&self) -> Fx {
        Fx::int(self.timing.h_total as i64).over(mhz(self.timing.pixel_clock_khz))
    }
    /// `ReturnBW`: the smaller of what the fabric/SDP port and the DRAM can
    /// deliver after urgent latency, both derated by their ideal percentage.
    /// HostVM is disabled, so the pixel-data-only DRAM percentage applies.
    fn return_bandwidth(&self, memory: &Memory, clocks: &ClockState) -> Fx {
        let fabric_sdp = Fx::int(RETURN_BUS_WIDTH_BYTES)
            .times(mhz(clocks.dcfclk_khz))
            .min(mhz(clocks.fclk_khz).times(Fx::int(FABRIC_DATAPATH_TO_DCN_RETURN_BYTES)));
        let dram = Fx::int(memory.speed_mts as i64)
            .times(Fx::int(memory.channels as i64))
            .times(Fx::int(memory.channel_width_bytes as i64));
        // Scale by the integer percentage before dividing, as DML writes it: a
        // pre-rounded 0.80 multiplier is not exact in binary fixed point.
        fabric_sdp
            .times(Fx::int(PCT_IDEAL_SDP_AFTER_URGENT))
            .over(Fx::int(100))
            .min(
                dram.times(Fx::int(PCT_IDEAL_DRAM_AFTER_URGENT_PIXEL_ONLY))
                    .over(Fx::int(100)),
            )
    }
    /// `CalculateExtraLatency`. GPUVM and HostVM are both off for a kernel-owned
    /// physical scanout, so the page-table term is zero and the byte count is
    /// just the reordering allowance plus this pipe's pixel chunk.
    fn extra_latency(&self, memory: &Memory, clocks: &ClockState, return_bw: Fx) -> Fx {
        let reordering_bytes =
            Fx::int(memory.channels as i64).times(Fx::int(URGENT_OUT_OF_ORDER_BYTES_PER_CHANNEL));
        let bytes = reordering_bytes.plus(Fx::int(PIXEL_CHUNK_KBYTES * 1024));
        Fx::int(ROUND_TRIP_PING_LATENCY_DCFCLK_CYCLES + ARB_TO_RET_DELAY_CYCLES)
            .over(mhz(clocks.dcfclk_khz))
            .plus(bytes.over(return_bw))
    }
    /// `CalculateWatermarksAndDRAMSpeedChangeSupport` for a single plane with no
    /// writeback, so the writeback watermarks and their chunk term drop out.
    pub fn watermarks(&self, memory: &Memory, clocks: &ClockState) -> Result<Watermarks, Error> {
        self.validate()?;
        if !memory.valid() || !clocks.valid() {
            return Err(Error::Invalid);
        }
        let (pstate_latency, sr_exit, sr_enter_plus_exit) = memory.latencies();
        let urgent_latency = Fx::ratio(URGENT_LATENCY_US_TENTHS, 10);
        let return_bw = self.return_bandwidth(memory, clocks);
        let extra_latency = self.extra_latency(memory, clocks, return_bw);
        let urgent = urgent_latency.plus(extra_latency);
        // The deep-sleep term is DML's fixed ten-cycle DCHUB wake allowance.
        let wake = Fx::int(10).over(mhz(clocks.deep_sleep_dcfclk_khz));
        Ok(Watermarks {
            urgent_us: urgent,
            pstate_change_us: pstate_latency.plus(urgent),
            stutter_exit_us: sr_exit.plus(extra_latency).plus(wake),
            stutter_enter_plus_exit_us: sr_enter_plus_exit.plus(extra_latency).plus(wake),
            z8_stutter_exit_us: Fx::int(SR_EXIT_Z8_US).plus(extra_latency).plus(wake),
            z8_stutter_enter_plus_exit_us: Fx::int(SR_ENTER_PLUS_EXIT_Z8_US)
                .plus(extra_latency)
                .plus(wake),
            urgent_latency_us: urgent_latency,
            extra_latency_us: extra_latency,
            return_bandwidth_bytes_per_us: return_bw,
            pstate_latency_us: pstate_latency,
            sr_exit_us: sr_exit,
            sr_enter_plus_exit_us: sr_enter_plus_exit,
        })
    }
    /// `CalculateMaxVStartup`: progressive scan with no writeback delay, so the
    /// vblank is reduced by a single line.
    fn max_v_startup(&self) -> u32 {
        let line_time = self.line_time_us();
        let vblank_actual = self.timing.v_total - self.timing.v_active;
        let vblank_nom_default = Fx::int(VBLANK_NOM_DEFAULT_US).over(line_time).floor() as u32;
        let vblank_size = vblank_actual.min(vblank_nom_default);
        vblank_size.saturating_sub(1).min(MAX_VSTARTUP)
    }
    /// `CalculatePrefetchSourceLines` with viewport positioning honoured.
    fn prefetch_source_lines(&self, geometry: &Geometry) -> (Fx, Fx, u32) {
        let swath_height = geometry.swath_height.max(1);
        let pre_fill = geometry
            .v_ratio
            .plus(Fx::int(self.plane.v_taps as i64))
            .plus(Fx::ONE)
            .over(Fx::int(2))
            .floor()
            .max(0) as u64;
        let max_num_swath = (pre_fill.saturating_sub(1)).div_ceil(swath_height) + 1;
        let partial = if pre_fill > 1 {
            (pre_fill - 2) % swath_height
        } else {
            (pre_fill + swath_height - 2) % swath_height
        }
        .max(1);
        (
            Fx::int((max_num_swath * swath_height + partial) as i64),
            Fx::int(pre_fill as i64),
            max_num_swath as u32,
        )
    }
    /// `CalculateVupdateAndDynamicMetadataParameters`. Dynamic metadata is not
    /// transmitted, so only the VUpdate/VReady geometry and TSetup are needed.
    fn vupdate(&self, clocks: &ClockState) -> (u32, u32, u32, Fx) {
        let dppclk = mhz(clocks.dppclk_khz);
        let dispclk = mhz(clocks.dispclk_khz);
        let deep_sleep = mhz(clocks.deep_sleep_dcfclk_khz);
        let pixel_clock = mhz(self.timing.pixel_clock_khz);
        let repeater_delay = Fx::int(MAX_INTER_DCN_TILE_REPEATERS)
            .times(Fx::int(2).over(dppclk).plus(Fx::int(3).over(dispclk)));
        let width = Fx::int(14)
            .over(deep_sleep)
            .plus(Fx::int(12).over(dppclk))
            .plus(repeater_delay)
            .times(pixel_clock)
            .ceil()
            .max(0) as u32;
        let ready = Fx::int(150)
            .over(dppclk)
            .max(
                repeater_delay
                    .plus(Fx::int(20).over(deep_sleep))
                    .plus(Fx::int(10).over(dppclk)),
            )
            .times(pixel_clock)
            .ceil()
            .max(0) as u32;
        let offset = Fx::ratio(self.timing.h_total as i64, 4).ceil().max(0) as u32;
        let setup = Fx::int((offset + width + ready) as i64).over(pixel_clock);
        (offset, width, ready, setup)
    }
    /// `CalculatePrefetchSchedule` for this pipeline: no GPUVM, no DCC, no DSC,
    /// no ODM combine, one DPP and no dynamic metadata. Every page-table and
    /// meta term DML would add is therefore zero, which collapses the four
    /// candidate prefetch bandwidths to the two whose numerators survive. The
    /// schedule is retried from DML's minimum VStartup upward, exactly as the
    /// mode-support loop does, and reports the first line count that fits.
    pub fn prefetch(
        &self,
        geometry: &Geometry,
        clocks: &ClockState,
        watermarks: &Watermarks,
    ) -> Result<Prefetch, Error> {
        self.validate()?;
        if !clocks.valid() {
            return Err(Error::Invalid);
        }
        let line_time = self.line_time_us();
        let pixel_clock = mhz(self.timing.pixel_clock_khz);
        let h_total = Fx::int(self.timing.h_total as i64);
        let bytes_per_pixel = Fx::int(geometry.bytes_per_pixel as i64);
        let max_v_startup = self.max_v_startup();
        if max_v_startup < MIN_VSTARTUP {
            // The vertical blank cannot even hold DML's minimum prefetch.
            return Err(Error::ViewportTooLarge);
        }
        let (offset, width, ready, t_setup) = self.vupdate(clocks);
        // CalculateTWait at PrefetchMode 0, which keeps DRAM p-state change
        // allowed. That is the longest wait and so the largest prefetch
        // requirement: a schedule that fits here fits the shallower modes.
        let t_wait = watermarks
            .pstate_latency_us
            .plus(watermarks.urgent_latency_us)
            .max(
                watermarks
                    .sr_enter_plus_exit_us
                    .max(watermarks.urgent_latency_us),
            );
        let t_calc = Fx::int(24).over(mhz(clocks.deep_sleep_dcfclk_khz));
        // Tdmdl with dynamic metadata disabled.
        let t_dmdl = t_wait.plus(watermarks.extra_latency_us);

        // DSTXAfterScaler: pipeline delay from the scaler to the OPTC, in
        // pixels. One DPP, no ODM and no DSC, so only the clock delays apply.
        let scaler_enabled = self.plane.h_taps > 1 || self.plane.v_taps > 1;
        let dpp_cycles = DPPCLK_DELAY_SUBTOTAL
            + DPPCLK_DELAY_CNVC_FORMATTER
            + if scaler_enabled {
                DPPCLK_DELAY_SCL
            } else {
                DPPCLK_DELAY_SCL_LB_ONLY
            }
            + DPPCLK_DELAY_CNVC_CURSOR * self.cursors as i64;
        let after_scaler = Fx::int(dpp_cycles)
            .times(pixel_clock)
            .over(mhz(clocks.dppclk_khz))
            .plus(
                Fx::int(DISPCLK_DELAY_SUBTOTAL)
                    .times(pixel_clock)
                    .over(mhz(clocks.dispclk_khz)),
            );
        // The schedule uses the exact fractional delay, as DML does; only the
        // register fields quantise, and they round up so the OPTC is told about
        // at least the delay that really exists.
        let after_scaler_lines = after_scaler.over(h_total);
        let dst_y_after_scaler = after_scaler_lines.floor().max(0) as u32;
        let dst_x_after_scaler = after_scaler
            .minus(Fx::int(dst_y_after_scaler as i64).times(h_total))
            .ceil()
            .max(0) as u32;

        let (source_lines, pre_fill, max_num_swath) = self.prefetch_source_lines(geometry);
        // Tno_bw with neither GPUVM nor DCC is one whole line.
        let t_no_bw = line_time;
        let tr0_trips = watermarks.urgent_latency_us;
        let tr0_trips_rounded = quarter_lines(tr0_trips, line_time).times(line_time);
        let tvm_oto = line_time.over(Fx::int(4));
        let tr0_oto = line_time.minus(tvm_oto).over(Fx::int(2));
        let prefetch_sw_bytes = source_lines
            .times(Fx::int(geometry.swath_width_ub as i64))
            .times(bytes_per_pixel);
        let max_tsw = source_lines.times(line_time);
        let prefetch_bw_pr = bytes_per_pixel
            .times(pixel_clock)
            .times(Fx::ONE.min(geometry.v_ratio));
        let prefetch_bw_oto = prefetch_bw_pr.max(prefetch_sw_bytes.over(max_tsw));
        let min_lsw = Fx::ONE.max(source_lines.over(Fx::int(MAX_VRATIO_PREFETCH)));
        let lsw_oto = Fx::ratio(
            Fx::int(4)
                .times(
                    prefetch_sw_bytes
                        .over(prefetch_bw_oto)
                        .over(line_time)
                        .max(min_lsw),
                )
                .ceil(),
            4,
        );
        let dst_y_prefetch_oto = quarter_lines(tvm_oto, line_time)
            .plus(Fx::int(2).times(quarter_lines(tr0_oto, line_time)))
            .plus(lsw_oto);

        for v_startup in MIN_VSTARTUP..=max_v_startup {
            // dst_y_prefetch_equ, clamped to the DST_Y_PREFETCH U6.2 field and
            // quantised down to a quarter line with DML's 0.125 bias.
            let equ = Fx::int(v_startup as i64)
                .minus(
                    t_setup
                        .plus(t_wait.plus(t_calc).max(t_dmdl))
                        .over(line_time),
                )
                .minus(after_scaler_lines)
                .min(Fx::ratio(6375, 100));
            let dst_y_prefetch_equ = Fx::ratio(
                Fx::int(4)
                    .times(equ.plus(Fx::ratio(125, 1000)))
                    .floor()
                    .max(0),
                4,
            );
            if dst_y_prefetch_equ <= Fx::ONE {
                continue;
            }
            let t_pre_rounded = dst_y_prefetch_equ.times(line_time);
            // With no page-table or meta bytes, only the swath term remains:
            // DML's case 2 when the trip-rounded slack is positive, else case 4.
            let case2_slack = t_pre_rounded
                .minus(t_no_bw)
                .minus(Fx::int(2).times(tr0_trips_rounded));
            let case4_slack = t_pre_rounded.minus(Fx::int(2).times(tr0_trips_rounded));
            let prefetch_bw_equ = if case2_slack > Fx::ZERO {
                prefetch_sw_bytes.over(case2_slack)
            } else if case4_slack > Fx::ZERO {
                prefetch_sw_bytes.over(case4_slack)
            } else {
                continue;
            };
            let tvm_equ = line_time.over(Fx::int(4));
            let tr0_equ = line_time.minus(tvm_equ).over(Fx::int(2));
            let (dst_y_prefetch, fetch_meta_pte, fetch_row, bandwidth) =
                if dst_y_prefetch_oto < dst_y_prefetch_equ {
                    (dst_y_prefetch_oto, tvm_oto, tr0_oto, prefetch_bw_oto)
                } else {
                    (dst_y_prefetch_equ, tvm_equ, tr0_equ, prefetch_bw_equ)
                };
            let dst_y_per_vm_vblank = quarter_lines(fetch_meta_pte, line_time);
            let dst_y_per_row_vblank = quarter_lines(fetch_row, line_time);
            let lines = dst_y_prefetch
                .minus(dst_y_per_vm_vblank)
                .minus(Fx::int(2).times(dst_y_per_row_vblank));
            if lines <= Fx::ZERO {
                continue;
            }
            // SwathHeightY is one for linear, so DML's deep-swath correction
            // for VInitPreFill cannot apply here.
            let v_ratio_prefetch = source_lines.over(lines).max(Fx::ONE);
            if v_ratio_prefetch > Fx::int(MAX_VRATIO_PREFETCH) {
                continue;
            }
            let required = source_lines
                .over(lines)
                .times(bytes_per_pixel)
                .times(Fx::int(geometry.swath_width_ub as i64))
                .over(line_time);
            return Ok(Prefetch {
                v_startup,
                max_v_startup,
                dst_y_prefetch,
                dst_y_per_vm_vblank,
                dst_y_per_row_vblank,
                lines_for_prefetch_pixel_data: lines,
                v_ratio_prefetch,
                required_prefetch_bandwidth_bytes_per_us: required,
                prefetch_bandwidth_bytes_per_us: bandwidth,
                dst_x_after_scaler,
                dst_y_after_scaler,
                v_update_offset_pix: offset,
                v_update_width_pix: width,
                v_ready_offset_pix: ready,
                t_setup_us: t_setup,
                t_calc_us: t_calc,
                t_wait_us: t_wait,
                prefetch_source_lines: source_lines,
                v_init_pre_fill: pre_fill,
                max_num_swath,
            });
        }
        Err(Error::NoTimeForPrefetch)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dml_tests.rs"]
mod tests;
