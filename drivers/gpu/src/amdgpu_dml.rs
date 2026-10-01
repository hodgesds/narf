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
fn ceil_multiple(value: u64, multiple: u64) -> u64 {
    if multiple == 0 {
        return value;
    }
    value.div_ceil(multiple).saturating_mul(multiple)
}
/// `dml_floor(value, multiple)`.
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
/// `__DML_MIN_DCFCLK_FACTOR__`.
const MIN_DCFCLK_FACTOR_TENTHS: i64 = 15;
/// Linear surfaces are limited by the detile buffer, not the DPP line store.
const MAX_SWATH_WIDTH_LINEAR: u64 = 8192;
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
    pub v_active: u32,
    pub v_total: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plane {
    pub format: Format,
    /// Allocated surface extent in pixels/lines, which bounds the swath.
    pub surface_width: u32,
    pub surface_height: u32,
    pub viewport_width: u32,
    pub viewport_height: u32,
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
        let bytes_per_cycle = Fx::ratio(MIN_DCFCLK_FACTOR_TENTHS, 10)
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

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dml_tests.rs"]
mod tests;
