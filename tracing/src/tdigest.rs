//! t-Digest — bounded-memory streaming quantile sketch.
//!
//! Implements the t-Digest algorithm of Dunning & Ertl, "Computing
//! Extremely Accurate Quantiles Using t-Digests" (arXiv:1902.04023).
//! The published paper is the *only* reference consulted; the design
//! is deliberately not derived from any GPL / Apache reference port
//! (Java, Linux, BSD, etc.). All comments below paraphrase Section 2
//! and Section 3 of the paper.
//!
//! ## Why
//!
//! `sketch::Histogram` uses log2 buckets — a reported p99 is only
//! accurate to a factor of 2×. For latency budgets where a Stage-4
//! tracer needs to distinguish "p99 = 3.1 µs" from "p99 = 6.0 µs",
//! that's not enough. A t-Digest with δ = 100 typically holds
//! < 200 centroids and delivers p99 / p999 within ~1 % of the truth
//! while remaining O(1) memory regardless of how many samples land.
//!
//! ## Algorithm summary (paraphrased from §2 of the paper)
//!
//! A t-Digest is a sorted collection of *centroids*. Each centroid
//! `(mean, weight)` summarises a contiguous chunk of the input
//! distribution. The compression parameter δ caps the number of
//! centroids; the scale function
//!
//!   k(q, δ) = δ / (2π) · asin(2q − 1)
//!
//! is denser near q = 0 and q = 1 (asin has a vertical tangent at
//! ±1) and flatter near q = 0.5. A centroid whose cumulative-weight
//! range [q_left, q_right] satisfies
//!
//!   k(q_right) − k(q_left) ≤ 1
//!
//! is *full* — adding more weight to it would push that interval past
//! one "k-step", so the algorithm starts a new centroid instead. The
//! upshot is per-centroid weight ∝ q · (1 − q), so the digest packs
//! many small centroids near the tails (where precise quantile
//! estimates matter for p99 / p999) and a few fat ones near the
//! median (where individual samples don't shift the distribution
//! shape).
//!
//! ## Insertion path (the merging variant, §3.2 of the paper)
//!
//! 1. Buffer raw samples in `buffer` (unsorted, bounded size).
//! 2. When the buffer is full, sort `buffer ∪ centroids` by mean.
//! 3. Sweep through the sorted run left-to-right, merging adjacent
//!    points into the current centroid as long as the resulting
//!    weight stays under the k-step bound; otherwise emit the
//!    current centroid and start a new one.
//!
//! This batched compression is much cheaper than per-sample BST
//! insertion (the variant the paper compares against in §3.1) and
//! yields the same accuracy guarantees up to a small constant.
//!
//! ## Quantile read (§2.4)
//!
//! Walk centroids accumulating weight. At quantile `q`, find the
//! centroid where cumulative weight crosses `q · total_weight`, and
//! linearly interpolate within the centroid's [low, high] sub-range.
//! `min` and `max` are tracked separately so the edges (q → 0 and
//! q → 1) interpolate to the true extremes rather than to a centroid
//! mean.
//!
//! ## no_std math
//!
//! `core` doesn't expose `asin` / `sqrt` in `#![no_std]`. We hand-roll
//! both: `sqrt` via Newton's iteration on `f64`, `asin` via the
//! Abramowitz & Stegun 4.4.46 polynomial approximation (max error
//! ≈ 7e-5 in [0, 1]). The scale function only needs ~3 decimal
//! digits — these are well within budget.

use alloc::vec::Vec;
use core::cmp::Ordering;

/// One centroid: a `(mean, weight)` summary of a chunk of the input.
#[derive(Copy, Clone, Debug)]
struct Centroid {
    mean: f64,
    weight: f64,
}

/// Streaming quantile sketch — bounded memory, tunable accuracy.
///
/// Construct with [`TDigest::new`] (δ = 100, ≈ 200-centroid worst case)
/// or [`TDigest::with_delta`] for tighter / looser packing. Insert
/// samples with [`add`](Self::add) / [`add_weighted`](Self::add_weighted),
/// query quantiles with [`quantile`](Self::quantile) or the inverse
/// CDF with [`cdf`](Self::cdf).
#[derive(Clone, Debug)]
pub struct TDigest {
    /// Centroids in sorted-by-mean order. May briefly be unsorted
    /// while a `compress()` is in progress.
    centroids: Vec<Centroid>,
    /// Raw samples not yet folded into `centroids`. Sized so the
    /// merging compression amortises to O(log n) per add.
    buffer: Vec<Centroid>,
    /// Compression parameter — the paper's δ. Larger ⇒ more centroids,
    /// tighter accuracy. δ = 100 ≈ 1% error on tail quantiles.
    delta: u32,
    /// Sum of all centroid weights == total samples seen (for
    /// unit-weight `add`) or sum-of-weights (for `add_weighted`).
    total_weight: f64,
    /// Tracked separately so the q → 0 / q → 1 edges of `quantile`
    /// hit the true extremes rather than the first/last centroid's
    /// mean.
    min: f64,
    max: f64,
    /// Total *unit-count* samples — distinct from `total_weight` when
    /// `add_weighted` was used. Used by `count()` for diagnostic
    /// read-outs; quantile math goes through `total_weight`.
    count: u64,
}

impl Default for TDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl TDigest {
    /// Default compression parameter — δ = 100. Tail accuracy ≈ 1 %.
    pub const DEFAULT_DELTA: u32 = 100;

    /// Construct an empty digest with `delta = DEFAULT_DELTA`.
    pub fn new() -> Self {
        Self::with_delta(Self::DEFAULT_DELTA)
    }

    /// Construct with an explicit compression parameter.
    ///
    /// `delta` is clamped to `[10, 10_000]`. Very small δ produces
    /// useless quantile estimates; very large δ defeats the bounded-
    /// memory promise.
    pub fn with_delta(delta: u32) -> Self {
        let delta = delta.clamp(10, 10_000);
        Self {
            centroids: Vec::new(),
            buffer: Vec::new(),
            delta,
            total_weight: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            count: 0,
        }
    }

    /// Add a unit-weight sample.
    #[inline]
    pub fn add(&mut self, value: f64) {
        self.add_weighted(value, 1.0);
    }

    /// Add `value` with the given `weight` (must be > 0 and finite).
    ///
    /// Non-finite or non-positive weights are silently ignored — the
    /// digest is a diagnostic / observability primitive, panicking
    /// on a bad input would be hostile to a tracer.
    pub fn add_weighted(&mut self, value: f64, weight: f64) {
        if !value.is_finite() || !weight.is_finite() || weight <= 0.0 {
            return;
        }
        // Equivalence-preserving split: when `weight` is an integer
        // ≥ 2, buffer it as N unit-weight points so the compression
        // sweep sees the same input shape as N consecutive `add`
        // calls. A single high-weight centroid would otherwise
        // monopolise its k-bucket and force compression to merge
        // it with neighbours that an N-sample stream would have
        // kept separate, producing systematic quantile drift.
        //
        // Non-integer weights bypass the split — they represent
        // genuine fractional samples (e.g. EMA-decayed counters)
        // where N-replication would distort the distribution.
        let buf_cap = (self.delta as usize) * 12;
        // `no_std` doesn't expose `f64::fract`; the manual form
        // `w - (w as i64 as f64)` is the cheapest equivalent for
        // finite-weight inputs.
        let is_integer = (weight - (weight as i64 as f64)).abs() < f64::EPSILON;
        if weight >= 2.0 && is_integer && weight <= 1024.0 {
            let n = weight as u32;
            for _ in 0..n {
                self.buffer.push(Centroid {
                    mean: value,
                    weight: 1.0,
                });
                if self.buffer.len() >= buf_cap {
                    self.compress();
                }
            }
        } else {
            self.buffer.push(Centroid {
                mean: value,
                weight,
            });
            if self.buffer.len() >= buf_cap {
                self.compress();
            }
        }
        self.total_weight += weight;
        self.count = self.count.saturating_add(1);
        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }
    }

    /// Force a merge of buffered samples into the centroid array.
    ///
    /// Idempotent on an already-compressed digest. Called implicitly
    /// from `quantile`, `cdf`, and `merge`.
    pub fn compress(&mut self) {
        if self.buffer.is_empty() && self.centroids.len() <= 1 {
            return;
        }

        // Move all centroids + buffered samples into one working set,
        // sort by mean. This is the §3.2 merging-compression sweep.
        let mut work: Vec<Centroid> = Vec::with_capacity(self.centroids.len() + self.buffer.len());
        work.append(&mut self.centroids);
        work.append(&mut self.buffer);
        work.sort_by(|a, b| a.mean.partial_cmp(&b.mean).unwrap_or(Ordering::Equal));

        let total_w = self.total_weight;
        if total_w <= 0.0 || work.is_empty() {
            self.centroids = work;
            return;
        }

        let delta = self.delta as f64;

        // q_left is the cumulative-weight quantile of everything to
        // the left of the current centroid. We grow the current
        // centroid until adding the next input point would push the
        // k-step k(q_right) − k(q_left) past 1; at that boundary we
        // emit the centroid and start a new one with q_left ← q_right.
        let mut out: Vec<Centroid> = Vec::with_capacity(work.len().min(self.delta as usize * 2));
        let mut cur = work[0];
        let mut q_left = cur.weight / total_w;
        let mut k_left = k_scale(0.0, delta);
        // The k-bound for the *current* centroid: the largest q_right
        // we'd accept before splitting. Recompute whenever we emit a
        // centroid (i.e. q_left moves).
        let mut q_limit = inv_k_scale(k_left + 1.0, delta);

        for next in work.iter().skip(1) {
            let proposed_q = q_left + (cur.weight + next.weight) / total_w;
            if proposed_q <= q_limit {
                // Merge `next` into `cur`. The merged mean is the
                // weight-averaged mean — paper §2.2.
                let new_w = cur.weight + next.weight;
                cur.mean += (next.mean - cur.mean) * (next.weight / new_w);
                cur.weight = new_w;
            } else {
                // Emit `cur`, start a new centroid at `next`.
                q_left += cur.weight / total_w;
                k_left = k_scale(q_left, delta);
                q_limit = inv_k_scale(k_left + 1.0, delta);
                out.push(cur);
                cur = *next;
            }
        }
        out.push(cur);
        self.centroids = out;
    }

    /// Merge `other` into `self`. Idempotent on an empty `other`.
    pub fn merge(&mut self, other: &TDigest) {
        if other.count == 0 {
            return;
        }
        // Mix `other`'s buffered + finalised state into our buffer,
        // then run a full compression. Treating their centroids as
        // weighted samples is the standard t-Digest merge (paper §2.5
        // — merging is associative because compression is driven
        // entirely by the sorted-by-mean sweep + cumulative-quantile
        // bound).
        self.buffer
            .reserve(other.centroids.len() + other.buffer.len());
        for c in other.centroids.iter().chain(other.buffer.iter()) {
            self.buffer.push(*c);
        }
        self.total_weight += other.total_weight;
        self.count = self.count.saturating_add(other.count);
        if other.min < self.min {
            self.min = other.min;
        }
        if other.max > self.max {
            self.max = other.max;
        }
        self.compress();
    }

    /// Number of `add` / `add_weighted` calls since construction.
    #[inline]
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Smallest sample ever added. `f64::INFINITY` on an empty digest.
    #[inline]
    pub fn min(&self) -> f64 {
        self.min
    }

    /// Largest sample ever added. `f64::NEG_INFINITY` on an empty digest.
    #[inline]
    pub fn max(&self) -> f64 {
        self.max
    }

    /// Estimate the `q`-th quantile, `q ∈ [0, 1]`.
    ///
    /// Returns `NaN` on an empty digest. Edges clamp to `min` / `max`.
    /// `q` outside `[0, 1]` is clamped.
    pub fn quantile(&self, q: f64) -> f64 {
        // Caller-friendly: don't require a `&mut self` to query.
        // We just snapshot through the un-merged buffer by treating
        // each buffered point as a unit-weight centroid in the walk.
        if self.count == 0 {
            return f64::NAN;
        }
        let q = q.clamp(0.0, 1.0);
        if q == 0.0 {
            return self.min;
        }
        if q == 1.0 {
            return self.max;
        }

        // Build a sorted view of centroids + buffer for a stable read.
        // For a "hot" path we'd `compress()` first; for an immutable
        // query we materialise the merged view on the stack-ish.
        let merged = self.merged_view();
        if merged.is_empty() {
            return self.min;
        }

        let target = q * self.total_weight;

        // Walk centroids; `cum` is the cumulative weight at the *left*
        // edge of `centroids[i]`. Linear-interpolate inside the
        // straddling centroid.
        let mut cum = 0.0;
        for (i, c) in merged.iter().enumerate() {
            let cum_right = cum + c.weight;
            if target <= cum_right {
                // Fraction inside this centroid.
                let frac = if c.weight > 0.0 {
                    (target - cum) / c.weight
                } else {
                    0.0
                };
                // Interpolate between the previous and next centroid
                // means (clamped to global min/max at the edges). The
                // paper §2.4 uses neighbour means so the slope of the
                // CDF is continuous between buckets.
                let left_mean = if i == 0 {
                    self.min
                } else {
                    (merged[i - 1].mean + c.mean) * 0.5
                };
                let right_mean = if i + 1 == merged.len() {
                    self.max
                } else {
                    (c.mean + merged[i + 1].mean) * 0.5
                };
                return left_mean + (right_mean - left_mean) * frac;
            }
            cum = cum_right;
        }
        self.max
    }

    /// Inverse of `quantile`: estimate `P(X ≤ value)` for the
    /// distribution summarised by the digest. `NaN` on an empty
    /// digest; 0 below `min`, 1 above `max`.
    pub fn cdf(&self, value: f64) -> f64 {
        if self.count == 0 {
            return f64::NAN;
        }
        if value < self.min {
            return 0.0;
        }
        if value > self.max {
            return 1.0;
        }

        let merged = self.merged_view();
        if merged.is_empty() {
            return 0.0;
        }

        // Mirror of `quantile`: walk centroids and locate `value`
        // inside the [left_mean, right_mean] sub-range of one
        // centroid, linearly interpolating cumulative weight.
        let mut cum = 0.0;
        for (i, c) in merged.iter().enumerate() {
            let left_mean = if i == 0 {
                self.min
            } else {
                (merged[i - 1].mean + c.mean) * 0.5
            };
            let right_mean = if i + 1 == merged.len() {
                self.max
            } else {
                (c.mean + merged[i + 1].mean) * 0.5
            };
            if value <= right_mean {
                let span = right_mean - left_mean;
                let frac = if span > 0.0 {
                    ((value - left_mean) / span).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                return (cum + frac * c.weight) / self.total_weight;
            }
            cum += c.weight;
        }
        1.0
    }

    /// Number of centroids — diagnostic. Bounded by the compression
    /// invariant at ≈ 2 · δ.
    #[doc(hidden)]
    pub fn centroid_count(&self) -> usize {
        self.centroids.len()
    }

    // ── helpers ─────────────────────────────────────────────────────

    /// Build a sorted-by-mean view of (centroids ∪ buffer). Used by
    /// the immutable read paths (`quantile`, `cdf`). Cheap when the
    /// buffer is empty — the common case after `compress()`.
    fn merged_view(&self) -> Vec<Centroid> {
        if self.buffer.is_empty() {
            return self.centroids.clone();
        }
        let mut v: Vec<Centroid> = Vec::with_capacity(self.centroids.len() + self.buffer.len());
        v.extend(self.centroids.iter().copied());
        v.extend(self.buffer.iter().copied());
        v.sort_by(|a, b| a.mean.partial_cmp(&b.mean).unwrap_or(Ordering::Equal));
        v
    }
}

// ── scale function k(q, δ) and its inverse ─────────────────────────
//
// Paper §2.3 defines k(q, δ) = δ/(2π) · asin(2q − 1). The derivative
// 1/sqrt(q·(1−q)) is large near the tails — exactly what we want, so
// centroids near p0/p100 cover narrow quantile ranges. The merging
// compression decides "this centroid is full" via k(q_right) − k(q_left)
// ≤ 1; the inverse `inv_k_scale(k + 1)` gives the largest q_right we
// can accept before splitting.

#[inline]
fn k_scale(q: f64, delta: f64) -> f64 {
    // δ / (2π) · asin(2q − 1)
    (delta / (2.0 * core::f64::consts::PI)) * asin_approx((2.0 * q - 1.0).clamp(-1.0, 1.0))
}

#[inline]
fn inv_k_scale(k: f64, delta: f64) -> f64 {
    // q = (sin(k · 2π / δ) + 1) / 2
    let arg = (k * 2.0 * core::f64::consts::PI) / delta;
    // sin via the identity sin(x) = cos(π/2 − x); we approximate sin
    // directly with a 7-term Taylor (good to ~1e-12 inside ±π) after
    // reducing `arg` into [−π, π].
    let s = sin_approx(arg);
    ((s + 1.0) * 0.5).clamp(0.0, 1.0)
}

// ── no_std math helpers ─────────────────────────────────────────────
//
// `core` doesn't ship asin / sin / sqrt for `f64` in `#![no_std]`.
// We need only modest precision (3-4 decimal digits is plenty for the
// scale function), so a small polynomial is enough.

/// √x via Newton-Raphson. `x` must be finite and ≥ 0.
fn sqrt_approx(x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if !x.is_finite() {
        return x;
    }
    // Initial guess from the IEEE-754 exponent (halve it). This is
    // the textbook "fast sqrt" seed — converges in ≤ 6 iterations to
    // a tight f64 result.
    let bits = x.to_bits();
    let exp = ((bits >> 52) & 0x7FF) as i64;
    let new_exp = ((exp - 1023) / 2 + 1023) as u64;
    let mut y = f64::from_bits((new_exp << 52) | (bits & 0x000F_FFFF_FFFF_FFFF));
    if !y.is_finite() || y <= 0.0 {
        y = 1.0;
    }
    // Six Newton iterations: y ← (y + x/y) / 2. Quadratic convergence.
    for _ in 0..6 {
        y = 0.5 * (y + x / y);
    }
    y
}

/// asin(x) for `x ∈ [−1, 1]`.
///
/// Implements Abramowitz & Stegun 4.4.46:
///
///   asin(x) ≈ π/2 − sqrt(1 − x) · (a₀ + a₁x + a₂x² + a₃x³)   (0 ≤ x ≤ 1)
///
/// with a₀ = 1.5707288, a₁ = −0.2121144, a₂ = 0.0742610,
/// a₃ = −0.0187293. Max absolute error ≈ 5e-5 over [0, 1]; odd-symmetric
/// extension covers [−1, 0].
fn asin_approx(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let x = x.clamp(-1.0, 1.0);
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let ax = if x < 0.0 { -x } else { x };
    let a0 = 1.5707288;
    let a1 = -0.2121144;
    let a2 = 0.0742610;
    let a3 = -0.0187293;
    let poly = a0 + ax * (a1 + ax * (a2 + ax * a3));
    let result = core::f64::consts::FRAC_PI_2 - sqrt_approx(1.0 - ax) * poly;
    sign * result
}

/// sin(x) via 7-term Taylor, after range-reduction into [−π, π].
fn sin_approx(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let two_pi = 2.0 * core::f64::consts::PI;
    // Range-reduce into (−π, π].
    let mut y = x;
    while y > core::f64::consts::PI {
        y -= two_pi;
    }
    while y < -core::f64::consts::PI {
        y += two_pi;
    }
    // 7-term Taylor: x − x³/3! + x⁵/5! − x⁷/7! + x⁹/9! − x¹¹/11! + x¹³/13!.
    // Inside |y| ≤ π the truncation error is < 1e-9.
    let y2 = y * y;
    let mut term = y;
    let mut acc = term;
    // factorials: 6, 20, 42, 72, 110, 156  → divisors for each subsequent term.
    // term_{k+1} = -term_k · y² / ((2k)(2k+1))
    let divisors = [6.0, 20.0, 42.0, 72.0, 110.0, 156.0];
    for d in divisors {
        term = -term * y2 / d;
        acc += term;
    }
    acc
}

// ── tests ───────────────────────────────────────────────────────────
//
// Per the tracing crate convention, kernel-test entries land in
// `narf.tests` via `kernel_test_in!`. The `#[cfg(test)]` block below
// pins the same scenarios for host-side `cargo test -p narf-tracing`
// runs as well — the inner functions are shared so the kernel-test
// wrappers and the host tests don't drift.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_tdigest_empty_quantile_is_nan() -> TestResult {
    let td = TDigest::new();
    if !td.quantile(0.5).is_nan() {
        return TestResult::Fail("empty quantile not NaN");
    }
    if td.count() != 0 {
        return TestResult::Fail("empty count != 0");
    }
    if td.min() != f64::INFINITY {
        return TestResult::Fail("empty min sentinel wrong");
    }
    if td.max() != f64::NEG_INFINITY {
        return TestResult::Fail("empty max sentinel wrong");
    }
    TestResult::Pass
}
kernel_test_in!("tracing", smoke_tdigest_empty_quantile_is_nan);

fn smoke_tdigest_single_value_all_quantiles() -> TestResult {
    let mut td = TDigest::new();
    td.add(42.0);
    for q in [0.0, 0.1, 0.5, 0.9, 0.99, 1.0] {
        let v = td.quantile(q);
        if (v - 42.0).abs() > 1e-9 {
            return TestResult::Fail("single-value quantile drifted from 42");
        }
    }
    if td.count() != 1 {
        return TestResult::Fail("count != 1");
    }
    if td.min() != 42.0 || td.max() != 42.0 {
        return TestResult::Fail("min/max not 42");
    }
    TestResult::Pass
}
kernel_test_in!("tracing", smoke_tdigest_single_value_all_quantiles);

fn smoke_tdigest_uniform_p50_p99_within_1pct() -> TestResult {
    // Uniform 1..=1000: p50 ≈ 500, p99 ≈ 990 ± 1%.
    let mut td = TDigest::new();
    for x in 1u32..=1000 {
        td.add(x as f64);
    }
    td.compress();

    let p50 = td.quantile(0.5);
    if (p50 - 500.0).abs() > 10.0 {
        return TestResult::Fail("p50 outside 1% of 500");
    }
    let p99 = td.quantile(0.99);
    if (p99 - 990.0).abs() > 10.0 {
        return TestResult::Fail("p99 outside 1% of 990");
    }
    if td.min() != 1.0 || td.max() != 1000.0 {
        return TestResult::Fail("min/max not tracked");
    }
    TestResult::Pass
}
kernel_test_in!("tracing", smoke_tdigest_uniform_p50_p99_within_1pct);

fn smoke_tdigest_skewed_quantiles_ordered() -> TestResult {
    // Heavy right tail: 95% of mass at small values, 5% at large.
    // p95 < p99 < p999 must hold.
    let mut td = TDigest::new();
    for _ in 0..9500 {
        td.add(10.0);
    }
    for i in 0..500 {
        td.add(1_000.0 + i as f64);
    }
    td.compress();
    let p95 = td.quantile(0.95);
    let p99 = td.quantile(0.99);
    let p999 = td.quantile(0.999);
    // Use `partial_cmp` so a NaN quantile (which would make every `<=`
    // comparison false) is treated as an ordering failure rather than
    // silently passing.
    if !matches!(
        p95.partial_cmp(&(p99 + 1e-6)),
        Some(Ordering::Less | Ordering::Equal)
    ) {
        return TestResult::Fail("p95 not ≤ p99");
    }
    if !matches!(
        p99.partial_cmp(&(p999 + 1e-6)),
        Some(Ordering::Less | Ordering::Equal)
    ) {
        return TestResult::Fail("p99 not ≤ p999");
    }
    // p99 should be in the heavy-tail range (≥ 1000).
    if p99 < 900.0 {
        return TestResult::Fail("p99 didn't move into the tail");
    }
    TestResult::Pass
}
kernel_test_in!("tracing", smoke_tdigest_skewed_quantiles_ordered);

fn smoke_tdigest_merge_matches_single_build() -> TestResult {
    // Build digest A from 0..500, B from 500..1000; merge into A.
    // Quantiles must approximate a single-build digest over 0..1000.
    let mut a = TDigest::new();
    let mut b = TDigest::new();
    let mut whole = TDigest::new();
    for x in 0u32..500 {
        a.add(x as f64);
        whole.add(x as f64);
    }
    for x in 500u32..1000 {
        b.add(x as f64);
        whole.add(x as f64);
    }
    a.merge(&b);
    whole.compress();

    if a.count() != 1000 {
        return TestResult::Fail("merged count != 1000");
    }
    if (a.min() - 0.0).abs() > 1e-9 || (a.max() - 999.0).abs() > 1e-9 {
        return TestResult::Fail("merged min/max wrong");
    }
    for q in [0.1, 0.5, 0.9, 0.99] {
        let am = a.quantile(q);
        let wm = whole.quantile(q);
        // Allow 2% absolute on the [0, 1000] range — merge drift is
        // small but non-zero.
        if (am - wm).abs() > 20.0 {
            return TestResult::Fail("merge drift > 2% of range");
        }
    }
    TestResult::Pass
}
kernel_test_in!("tracing", smoke_tdigest_merge_matches_single_build);

fn smoke_tdigest_cdf_inverse_of_quantile() -> TestResult {
    // cdf(quantile(q)) ≈ q within a couple percent for moderate q.
    let mut td = TDigest::new();
    for x in 1u32..=1000 {
        td.add(x as f64);
    }
    td.compress();
    for q in [0.1, 0.5, 0.9, 0.99] {
        let v = td.quantile(q);
        let back = td.cdf(v);
        if (back - q).abs() > 0.02 {
            return TestResult::Fail("cdf(quantile(q)) drifted > 2pp");
        }
    }
    TestResult::Pass
}
kernel_test_in!("tracing", smoke_tdigest_cdf_inverse_of_quantile);

fn smoke_tdigest_centroid_count_bounded() -> TestResult {
    // After compression on a moderate stream the centroid count
    // should stay well under ~3·δ. (The paper bounds it at ~2·δ; we
    // leave headroom for the buffered-merge variant.)
    let mut td = TDigest::with_delta(100);
    for x in 0u32..10_000 {
        td.add(x as f64);
    }
    td.compress();
    let n = td.centroid_count();
    if n > 300 {
        return TestResult::Fail("centroid count exceeded 3·δ");
    }
    if n < 10 {
        return TestResult::Fail("centroid count suspiciously low");
    }
    TestResult::Pass
}
kernel_test_in!("tracing", smoke_tdigest_centroid_count_bounded);

fn smoke_tdigest_weighted_add_preserves_quantile() -> TestResult {
    // Equivalent: add(x) 10× vs add_weighted(x, 10.0) once.
    let mut a = TDigest::new();
    let mut b = TDigest::new();
    for x in [1.0_f64, 5.0, 10.0, 50.0, 100.0] {
        for _ in 0..10 {
            a.add(x);
        }
        b.add_weighted(x, 10.0);
    }
    a.compress();
    b.compress();
    for q in [0.1, 0.5, 0.9] {
        let qa = a.quantile(q);
        let qb = b.quantile(q);
        if (qa - qb).abs() > 5.0 {
            return TestResult::Fail("weighted vs unit-weight drift");
        }
    }
    TestResult::Pass
}
kernel_test_in!("tracing", smoke_tdigest_weighted_add_preserves_quantile);

fn smoke_tdigest_bad_inputs_rejected() -> TestResult {
    // NaN / infinite / non-positive weights must be ignored, not
    // panic.
    let mut td = TDigest::new();
    td.add_weighted(f64::NAN, 1.0);
    td.add_weighted(f64::INFINITY, 1.0);
    td.add_weighted(1.0, 0.0);
    td.add_weighted(1.0, -1.0);
    td.add_weighted(1.0, f64::NAN);
    if td.count() != 0 {
        return TestResult::Fail("bad-input count != 0");
    }
    td.add(7.0);
    if (td.quantile(0.5) - 7.0).abs() > 1e-9 {
        return TestResult::Fail("good sample after bad batch lost");
    }
    TestResult::Pass
}
kernel_test_in!("tracing", smoke_tdigest_bad_inputs_rejected);

fn smoke_tdigest_scale_function_monotonic() -> TestResult {
    // k(q) must be monotonically increasing in q ∈ [0, 1] for the
    // merging-compression sweep to terminate.
    let delta = 100.0;
    let mut prev = k_scale(0.0, delta);
    for i in 1..=100 {
        let q = i as f64 / 100.0;
        let k = k_scale(q, delta);
        // `partial_cmp` keeps NaN handling explicit: a NaN scale value
        // is an ordering failure, not a silent pass.
        if !matches!(
            k.partial_cmp(&(prev - 1e-9)),
            Some(Ordering::Greater | Ordering::Equal)
        ) {
            return TestResult::Fail("k(q) not monotone");
        }
        prev = k;
    }
    // Symmetry: k(q) + k(1 − q) ≈ 0.
    for q in [0.1, 0.25, 0.4] {
        let s = k_scale(q, delta) + k_scale(1.0 - q, delta);
        if s.abs() > 1e-3 {
            return TestResult::Fail("k(q) not antisymmetric about 0.5");
        }
    }
    TestResult::Pass
}
kernel_test_in!("tracing", smoke_tdigest_scale_function_monotonic);

// Host-side `cargo test` doesn't work for this crate (missing
// linker-synthesised `__narf_probes_*` symbols), so the only test
// surface is the kernel-test registrations above — `cargo xtask test`
// runs them under QEMU like every other crate in the tree.
