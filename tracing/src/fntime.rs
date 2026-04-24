//! `FnTime` — function-level latency aggregates.
//!
//! Spec: `tracing/specification/spec.md` §3.2. A `FnTime` accumulates
//! enter → exit cycle counts for a named scope and exposes running
//! mean + variance via Welford's online algorithm and a histogram
//! sketch for approximate percentiles.
//!
//! Typical usage:
//!
//! ```ignore
//! use narf_tracing::fntime::{FnTime, scope};
//! static LAT: FnTime = FnTime::new("fs::read");
//!
//! pub fn read() -> Result<(), ()> {
//!     let _g = scope(&LAT);
//!     // … work …
//!     Ok(())
//! }
//! ```
//!
//! Stage-3 accumulator: Welford mean + variance + min/max + count
//! (all `u64` where the variance is kept as `M2 = Σ(x−μ)²` so a single
//! division at read time gives σ²). The sketch lives in
//! `tracing::sketch::Histogram`. No allocations on the hot path; all
//! state is behind a single `IrqSafeSpinLock` per scope.

use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use narf_time::Instant;

use crate::sketch::Histogram;

/// Running sample statistics — Welford / Knuth online variance.
#[derive(Copy, Clone, Debug, Default)]
pub struct Welford {
    pub count: u64,
    /// Running mean in cycles.
    pub mean:  f64,
    /// Running `M2 = Σ(x - μ)²`. Divide by `count - 1` for the
    /// sample variance; divide by `count` for the population variance.
    pub m2:    f64,
    pub min:   u64,
    pub max:   u64,
}

impl Welford {
    pub const fn new() -> Self {
        Self { count: 0, mean: 0.0, m2: 0.0, min: u64::MAX, max: 0 }
    }

    /// Add a sample. `x` is typically a cycle count.
    #[inline]
    pub fn add(&mut self, x: u64) {
        self.count = self.count.saturating_add(1);
        let xf = x as f64;
        let delta = xf - self.mean;
        self.mean += delta / (self.count as f64);
        let delta2 = xf - self.mean;
        self.m2 += delta * delta2;
        if x < self.min { self.min = x; }
        if x > self.max { self.max = x; }
    }

    /// Sample variance (`M2 / (n - 1)`). Returns 0 when n < 2.
    #[inline]
    pub fn sample_variance(&self) -> f64 {
        if self.count < 2 { 0.0 } else { self.m2 / ((self.count - 1) as f64) }
    }
}

/// Per-scope aggregated timing state.
#[derive(Debug)]
struct State {
    welford: Welford,
    hist:    Histogram,
}

/// Named function-timing accumulator. Construct as a `static`:
///
/// ```ignore
/// static LAT: FnTime = FnTime::new("fs::read");
/// ```
pub struct FnTime {
    name:  &'static str,
    /// Cheap counter of live entries (enters without matching exits).
    /// Exposed for diagnostics; `ScopeGuard::drop` closes the balance.
    live:  AtomicU64,
    state: IrqSafeSpinLock<State>,
}

impl core::fmt::Debug for FnTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FnTime")
            .field("name", &self.name)
            .field("live", &self.live.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl FnTime {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            live:  AtomicU64::new(0),
            state: IrqSafeSpinLock::new(State {
                welford: Welford::new(),
                hist:    Histogram::new(),
            }),
        }
    }

    #[inline]
    pub const fn name(&self) -> &'static str { self.name }

    /// Snapshot of the welford state for read-back (tests / observers).
    pub fn welford(&self) -> Welford { self.state.lock().welford }

    /// Borrow a histogram snapshot. Cloned to release the lock quickly.
    pub fn histogram(&self) -> Histogram { self.state.lock().hist.clone() }

    /// Number of scope guards currently live.
    #[inline]
    pub fn live_scopes(&self) -> u64 { self.live.load(Ordering::Relaxed) }

    /// Record a directly-measured duration (when the caller already
    /// has a cycle delta from somewhere other than a `ScopeGuard`).
    pub fn record_cycles(&self, cycles: u64) {
        let mut s = self.state.lock();
        s.welford.add(cycles);
        s.hist.add(cycles);
    }
}

/// RAII guard: captures an `Instant` on construction and on drop
/// records the elapsed cycles into the target `FnTime`. Cheap enough
/// to drop at the top of every instrumented function.
#[derive(Debug)]
pub struct ScopeGuard {
    target: &'static FnTime,
    start:  Instant,
}

impl ScopeGuard {
    #[inline]
    pub fn new(target: &'static FnTime) -> Self {
        target.live.fetch_add(1, Ordering::Relaxed);
        Self { target, start: Instant::now() }
    }
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        let elapsed = Instant::now().cycles_since(self.start);
        self.target.record_cycles(elapsed);
        self.target.live.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Convenience: `let _g = scope(&LAT);` at a function's top.
#[inline]
pub fn scope(target: &'static FnTime) -> ScopeGuard { ScopeGuard::new(target) }
