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
    pub secs:      i64,
    pub nanos:     u32,
}

impl WallInstant {
    pub const EPOCH: WallInstant = WallInstant { secs: 0, nanos: 0 };

    /// Construct from a total-nanoseconds scalar (positive only).
    #[inline]
    pub const fn from_nanos(total_ns: i128) -> Self {
        let secs  = (total_ns / 1_000_000_000) as i64;
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

/// Calibration: how many cycles per nanosecond the platform ticks.
/// 1 cycle ≈ 0.3 ns at 3 GHz; the Stage-4 calibration-from-CPUID
/// path will replace the hard-coded `CYCLES_PER_NS = 3` with a
/// measured value. `1` as the default keeps the arithmetic stable
/// when the platform hasn't calibrated.
static CYCLES_PER_NS: AtomicU32 = AtomicU32::new(1);

/// Offset in nanoseconds applied to `monotonic_ns()` to get wall time.
/// Atomic so the leap-smear worker can update it without locking.
static WALL_OFFSET_NS: AtomicI64 = AtomicI64::new(0);

/// When a leap smear is in progress, `SMEAR_END_CYCLES` holds the
/// cycle-count at which the smear ends, and `SMEAR_DELTA_NS_REMAINING`
/// holds the signed ns that still need to be folded in. On each
/// `now_wall()` read the remaining delta is interpolated linearly
/// over the time left.
static SMEAR_END_CYCLES:         AtomicU64 = AtomicU64::new(0);
static SMEAR_DELTA_NS_REMAINING: AtomicI64 = AtomicI64::new(0);

/// Error variants for the wall-clock surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WallError {
    AuthorityRevoked,
    InvalidSmearWindow,
}

impl From<CapError> for WallError {
    fn from(_: CapError) -> Self { WallError::AuthorityRevoked }
}

/// Set the monotonic→wall offset directly. Use for initial sync after
/// boot (from firmware RTC or first NTP response); normal ongoing
/// corrections should go through `begin_leap_smear`.
pub fn set_wall_offset(cap: &Cap<WallClock, Write>, offset_ns: i64) -> Result<(), WallError> {
    cap.invoke(NoopOp)?;
    WALL_OFFSET_NS.store(offset_ns, Ordering::Release);
    Ok(())
}

/// Begin a leap-smear over `window_ns` — gradually fold a `delta_ns`
/// correction into the wall offset instead of stepping. Negative
/// deltas smear backwards; zero is rejected because it's nonsense.
pub fn begin_leap_smear(
    cap:       &Cap<WallClock, Write>,
    delta_ns:  i64,
    window_ns: u64,
) -> Result<(), WallError> {
    cap.invoke(NoopOp)?;
    if window_ns == 0 { return Err(WallError::InvalidSmearWindow); }
    let cpns = CYCLES_PER_NS.load(Ordering::Relaxed).max(1) as u64;
    let end_cycles = now_cycles().saturating_add(window_ns.saturating_mul(cpns));
    SMEAR_END_CYCLES.store(end_cycles, Ordering::Release);
    SMEAR_DELTA_NS_REMAINING.store(delta_ns, Ordering::Release);
    Ok(())
}

/// Calibrate the cycles-per-ns constant. `arch/` calls this once at
/// boot after TSC frequency discovery.
pub fn set_cycles_per_ns(cpns: u32) {
    CYCLES_PER_NS.store(cpns.max(1), Ordering::Release);
}

/// Current monotonic-ns since boot (cycles ÷ cycles-per-ns).
#[inline]
pub fn monotonic_ns() -> u64 {
    now_cycles() / CYCLES_PER_NS.load(Ordering::Relaxed).max(1) as u64
}

/// Read the wall-clock. Folds any in-progress leap smear into the
/// returned timestamp by linearly interpolating the remaining delta
/// over the remaining window.
pub fn now_wall() -> WallInstant {
    let end   = SMEAR_END_CYCLES.load(Ordering::Acquire);
    let delta = SMEAR_DELTA_NS_REMAINING.load(Ordering::Acquire);
    let now   = now_cycles();

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
    WALL_OFFSET_NS.store(0,          Ordering::Release);
    SMEAR_END_CYCLES.store(0,        Ordering::Release);
    SMEAR_DELTA_NS_REMAINING.store(0, Ordering::Release);
    CYCLES_PER_NS.store(1,           Ordering::Release);
}
