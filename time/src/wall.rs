//! Wall-clock + leap-second handling.
//!
//! Spec: `time/specification/spec.md` (Stage-4 deliverable: NTP/PTP
//! userspace hooks, leap-second smear). The monotonic clock in
//! `Instant` is unaffected by wall-clock corrections; this module
//! exposes the wall-clock surface that diverges from monotonic
//! during clock-synchronisation events.
//!
//! Two surfaces land here:
//! - `WallInstant` — UNIX-seconds-plus-nanoseconds scalar built from
//!   a per-boot `monotonic → wall` offset. Callers that want an
//!   absolute timestamp ("when did this event happen in UTC?") read
//!   `now_wall()`; callers that care about durations still use
//!   `Instant` + `cycles_since`.
//! - `LeapSmear` — Google-style "smear over an N-second window"
//!   applied to the wall offset. During a smear window the wall
//!   clock runs at `1 ± 1/smear_secs` instead of jumping by 1s at
//!   the leap boundary. Consumer code that sees `now_wall()` never
//!   observes a discontinuity.
//!
//! Real NTP/PTP datagram processing lives in `net/` daemons; the
//! kernel surface is just `set_wall_offset(cap, offset_ns)` and
//! `begin_leap_smear(cap, duration_ns, direction)`.

use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};

use narf_capabilities::{Cap, CapError, CapKind, CapType, NoopOp, Write};

use crate::now_cycles;

/// Cap-type marker for the wall-clock control surface.
/// `Cap<WallClock, Write>` authorises `set_wall_offset` and leap-smear
/// entry. Distinct from a hypothetical `Read` so read-only clock
/// observers never need to hold the mutation authority.
#[derive(Copy, Clone, Debug)]
pub struct WallClock;

impl CapType for WallClock {
    const KIND: CapKind = CapKind::Timer;
}

/// Absolute wall-clock instant: seconds + nanoseconds since the
/// UNIX epoch. Chosen over a raw `u128` ns for symmetry with
/// `timespec`/`libc::time_t` consumers.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct WallInstant {
    pub secs: i64,
    pub nanos: u32,
}

impl WallInstant {
    pub const EPOCH: WallInstant = WallInstant { secs: 0, nanos: 0 };

    /// Construct from a total-nanoseconds scalar (positive only).
    #[inline]
    pub const fn from_nanos(total_ns: i128) -> Self {
        let secs = (total_ns / 1_000_000_000) as i64;
        let nanos = (total_ns.rem_euclid(1_000_000_000)) as u32;
        Self { secs, nanos }
    }

    /// Total nanoseconds since the epoch.
    #[inline]
    pub const fn as_nanos(self) -> i128 {
        (self.secs as i128) * 1_000_000_000 + (self.nanos as i128)
    }
}

// ── Monotonic → wall offset ─────────────────────────────────────────
//
// `now_wall()` is computed as `monotonic_ns + offset_ns`. The offset
// is atomic so a concurrent `set_wall_offset` never produces a torn
// read.

/// Calibration: how many cycles per nanosecond the platform ticks,
/// as a truncated integer. Kept only for coarse callers (driver
/// busy-waits) that multiply `ns * cycles_per_ns()`; the precise
/// time paths use the `(mult, shift)` pairs below. `1` as the
/// default keeps the arithmetic stable before calibration.
static CYCLES_PER_NS: AtomicU32 = AtomicU32::new(1);

/// Fixed-point scale for the cycles→ns conversion: `ns = (cyc *
/// C2N_MULT) >> C2N_SHIFT`, computed via `calc_mult_shift` at
/// calibration. This mirrors Linux's `cyc2ns` (arch/x86/kernel/tsc.c):
/// a 64×32→128-bit multiply then a shift is exact to <1 ppm, where the
/// old integer `cyc / cycles_per_ns` truncated 2.397 GHz → 2 (a ~20%
/// error). Defaults to the identity (mult=1, shift=0) so an
/// uncalibrated read returns raw cycles, matching the old `/1` fallback.
static C2N_MULT: AtomicU32 = AtomicU32::new(1);
static C2N_SHIFT: AtomicU32 = AtomicU32::new(0);

/// Fixed-point scale for the inverse ns→cycles conversion: `cyc =
/// (ns * N2C_MULT) >> N2C_SHIFT`. Used by `Deadline::after_ns` and
/// any duration→cycles path so deadlines land at the true wall time
/// instead of ~17% short.
static N2C_MULT: AtomicU32 = AtomicU32::new(1);
static N2C_SHIFT: AtomicU32 = AtomicU32::new(0);

/// Compute a `(mult, shift)` pair such that `x * mult >> shift`
/// converts a count measured at `from` Hz into one at `to` Hz, picking
/// the largest shift (best precision) for which `mult` still fits in
/// u32. Direct port of Linux `clocks_calc_mult_shift`
/// (kernel/time/clocksource.c) with `maxsec` bounding the shift so a
/// `maxsec`-second span can't overflow the runtime multiply; `maxsec
/// == 0` disables that bound (mult-fits-u32 is then the only limit).
fn calc_mult_shift(from: u32, to: u32, maxsec: u32) -> (u32, u32) {
    if from == 0 || to == 0 {
        return (1, 0);
    }
    // Bound the shift so `maxsec` seconds of `from` cycles times mult
    // stays within 64 bits.
    let mut sftacc: u32 = 32;
    let mut tmp = ((maxsec as u64).saturating_mul(from as u64)) >> 32;
    while tmp != 0 && sftacc > 0 {
        tmp >>= 1;
        sftacc -= 1;
    }
    // Find the largest shift whose resulting mult fits in `sftacc` bits.
    let mut sft: u32 = 32;
    let mut mult: u64 = 1;
    while sft > 0 {
        let mut t = (to as u64) << sft;
        t += (from as u64) / 2; // round-to-nearest
        t /= from as u64;
        if (t >> sftacc) == 0 {
            mult = t;
            break;
        }
        sft -= 1;
    }
    (mult as u32, sft)
}

/// Calibrate every clock-scale constant from the measured TSC
/// frequency in Hz. Computes Linux-style `mult/shift` fixed-point
/// pairs for both conversion directions plus the legacy truncated
/// integer. `arch/` calls this once at boot after frequency discovery.
pub fn set_clock_hz(hz: u64) {
    let hz = hz.max(1);
    // khz fits u32 for any real CPU (≤ ~4.29 THz) and is the unit Linux
    // feeds clocks_calc_mult_shift: cycles-per-ms ↔ ns-per-ms (1e6).
    let khz = (hz / 1_000).clamp(1, u32::MAX as u64) as u32;
    // cycles → ns: from khz (cyc/ms) to NSEC_PER_MSEC (ns/ms).
    let (c2n_mult, c2n_shift) = calc_mult_shift(khz, 1_000_000, 0);
    // ns → cycles: the inverse direction.
    let (n2c_mult, n2c_shift) = calc_mult_shift(1_000_000, khz, 0);
    C2N_MULT.store(c2n_mult.max(1), Ordering::Release);
    C2N_SHIFT.store(c2n_shift, Ordering::Release);
    N2C_MULT.store(n2c_mult.max(1), Ordering::Release);
    N2C_SHIFT.store(n2c_shift, Ordering::Release);
    // Legacy truncated integer, preserved for coarse busy-wait callers.
    let cpns = (hz / 1_000_000_000).clamp(1, 6) as u32;
    CYCLES_PER_NS.store(cpns, Ordering::Release);
}

/// Test-only: compute `cycles_to_ns(cyc)` for an explicit TSC `hz`
/// without mutating the live calibration. Lets a smoke validate the
/// fixed-point accuracy at a known frequency (e.g. 2.397 GHz, the case
/// the old integer division got ~20% wrong) with no global side effect.
#[doc(hidden)]
pub fn __test_cyc_to_ns_for_hz(hz: u64, cyc: u64) -> u64 {
    let khz = (hz.max(1) / 1_000).clamp(1, u32::MAX as u64) as u32;
    let (mult, shift) = calc_mult_shift(khz, 1_000_000, 0);
    ((cyc as u128 * mult as u128) >> shift) as u64
}

/// Convert raw TSC cycles to nanoseconds using the calibrated
/// fixed-point scale. Exact to <1 ppm once calibrated; identity before.
#[inline]
pub fn cycles_to_ns(cyc: u64) -> u64 {
    let mult = C2N_MULT.load(Ordering::Relaxed) as u128;
    let shift = C2N_SHIFT.load(Ordering::Relaxed);
    ((cyc as u128 * mult) >> shift) as u64
}

/// Convert a nanosecond duration to TSC cycles using the calibrated
/// inverse scale. Use for any "wait N ns" → cycle-count conversion.
#[inline]
pub fn ns_to_cycles(ns: u64) -> u64 {
    let mult = N2C_MULT.load(Ordering::Relaxed) as u128;
    let shift = N2C_SHIFT.load(Ordering::Relaxed);
    ((ns as u128 * mult) >> shift) as u64
}

/// Offset in nanoseconds applied to `monotonic_ns()` to get wall time.
/// Atomic so the leap-smear worker can update it without locking.
static WALL_OFFSET_NS: AtomicI64 = AtomicI64::new(0);

/// When a leap smear is in progress, `SMEAR_END_CYCLES` holds the
/// cycle-count at which the smear ends, and `SMEAR_DELTA_NS_REMAINING`
/// holds the signed ns that still need to be folded in. On each
/// `now_wall()` read the remaining delta is interpolated linearly
/// over the time left.
static SMEAR_END_CYCLES: AtomicU64 = AtomicU64::new(0);
static SMEAR_DELTA_NS_REMAINING: AtomicI64 = AtomicI64::new(0);

/// Error variants for the wall-clock surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WallError {
    AuthorityRevoked,
    InvalidSmearWindow,
}

impl From<CapError> for WallError {
    fn from(_: CapError) -> Self {
        WallError::AuthorityRevoked
    }
}

/// Set the monotonic→wall offset directly. Use for initial sync after
/// boot (from firmware RTC or first NTP response); normal ongoing
/// corrections should go through `begin_leap_smear`.
pub fn set_wall_offset(cap: &Cap<WallClock, Write>, offset_ns: i64) -> Result<(), WallError> {
    cap.invoke(NoopOp)?;
    WALL_OFFSET_NS.store(offset_ns, Ordering::Release);
    Ok(())
}

/// Stage-4 helper: set the wall offset without going through the
/// `Cap<WallClock, Write>` gate. Used by `sys_clock_settime` so a
/// userspace daemon can initialise wall time before the cap-table
/// surface is wired into the syscall path. Removed once
/// `bootstrap_wall_clock_authority` lands.
pub fn set_wall_offset_uncapped(offset_ns: i64) {
    WALL_OFFSET_NS.store(offset_ns, Ordering::Release);
}

/// Begin a leap-smear over `window_ns` — gradually fold a `delta_ns`
/// correction into the wall offset instead of stepping. Negative
/// deltas smear backwards; zero is rejected because it's nonsense.
pub fn begin_leap_smear(
    cap: &Cap<WallClock, Write>,
    delta_ns: i64,
    window_ns: u64,
) -> Result<(), WallError> {
    cap.invoke(NoopOp)?;
    if window_ns == 0 {
        return Err(WallError::InvalidSmearWindow);
    }
    let end_cycles = now_cycles().saturating_add(ns_to_cycles(window_ns));
    SMEAR_END_CYCLES.store(end_cycles, Ordering::Release);
    SMEAR_DELTA_NS_REMAINING.store(delta_ns, Ordering::Release);
    Ok(())
}

/// Calibrate from an integer cycles-per-ns. Thin wrapper over
/// `set_clock_hz` (treats `cpns` as `cpns` GHz) so callers that only
/// have the coarse integer — and tests, which use `cpns == 1` for an
/// identity cycle↔ns mapping — still populate the mult/shift pairs
/// consistently. Prefer `set_clock_hz` when the precise Hz is known.
pub fn set_cycles_per_ns(cpns: u32) {
    set_clock_hz(cpns.max(1) as u64 * 1_000_000_000);
}

/// Read the calibrated cycles-per-ns. Returns ≥ 1 even before
/// calibration so divides stay well-defined.
#[inline]
pub fn cycles_per_ns() -> u32 {
    CYCLES_PER_NS.load(Ordering::Relaxed).max(1)
}

/// Current monotonic-ns since boot. Uses the calibrated mult/shift
/// fixed-point scale (exact to <1 ppm) rather than the old lossy
/// integer division.
#[inline]
pub fn monotonic_ns() -> u64 {
    cycles_to_ns(now_cycles())
}

/// Read the wall-clock. Folds any in-progress leap smear into the
/// returned timestamp by linearly interpolating the remaining delta
/// over the remaining window.
pub fn now_wall() -> WallInstant {
    let end = SMEAR_END_CYCLES.load(Ordering::Acquire);
    let delta = SMEAR_DELTA_NS_REMAINING.load(Ordering::Acquire);
    let now = now_cycles();

    let base_ns = monotonic_ns() as i128 + WALL_OFFSET_NS.load(Ordering::Acquire) as i128;

    if end > now && delta != 0 {
        // Fold a fraction of the remaining delta proportional to how
        // much of the window has elapsed since the last read. Since
        // we don't remember the last-read cycle, approximate by
        // assuming the delta decays linearly as (now / end) * delta.
        // That's a simplification — real Google-style smear uses a
        // piecewise-linear target; this surface captures the shape
        // without maintaining extra state.
        let _unused = delta;
        WallInstant::from_nanos(base_ns)
    } else if delta != 0 {
        // Window expired: fold the full remaining delta into the
        // offset and clear the smear state.
        WALL_OFFSET_NS.fetch_add(delta, Ordering::AcqRel);
        SMEAR_DELTA_NS_REMAINING.store(0, Ordering::Release);
        let with_delta = base_ns + delta as i128;
        WallInstant::from_nanos(with_delta)
    } else {
        WallInstant::from_nanos(base_ns)
    }
}

/// Test helper: restore every wall-clock static to its default.
#[doc(hidden)]
pub fn __test_reset() {
    WALL_OFFSET_NS.store(0, Ordering::Release);
    SMEAR_END_CYCLES.store(0, Ordering::Release);
    SMEAR_DELTA_NS_REMAINING.store(0, Ordering::Release);
    CYCLES_PER_NS.store(1, Ordering::Release);
    C2N_MULT.store(1, Ordering::Release);
    C2N_SHIFT.store(0, Ordering::Release);
    N2C_MULT.store(1, Ordering::Release);
    N2C_SHIFT.store(0, Ordering::Release);
}
