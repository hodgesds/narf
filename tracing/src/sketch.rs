//! Latency sketches — approximate quantiles in bounded memory.
//!
//! Spec: `tracing/specification/spec.md` §3.2 (live aggregates: Welford
//! mean/variance + tDigest for quantiles). Stage-3 scope: a
//! **log2-bucket `Histogram`** that gives the same shape of API
//! (`add(x)`, `quantile(p)`) with O(1) insert and O(log N) read over a
//! fixed 64-bucket table. This is strictly a stub for the real
//! tDigest — the accuracy budget and centroid-merge machinery for a
//! production tDigest is a Stage-4 follow-up once a NARF-wide
//! quantile-accuracy contract is defined.
//!
//! Bucket layout: `bucket(x) = 64 - leading_zeros(x)`. So bucket 0
//! catches `x == 0`, bucket 1 catches `[1]`, bucket 2 catches `[2..4)`,
//! bucket 3 catches `[4..8)`, etc. Max bucket is 64 (covers up to
//! `2^64 - 1`, every u64 input fits). Error at read-time is bounded
//! by the bucket width: a reported 99th-percentile is within a
//! factor of 2× of the true value.
//!
//! Stage-4 replacement plan (tracked in the module doc on the real
//! `tdigest.rs` that lands later): bounded centroid array + buffered
//! insert + periodic merge + configurable compression factor δ.

use core::sync::atomic::{AtomicU64, Ordering};

/// Number of buckets. Matches the u64 bit-width + 1.
pub const HISTOGRAM_BUCKETS: usize = 65;

/// Log2-bucket histogram.
///
/// The layout is atomic so concurrent adders from multiple scopes on
/// the same `FnTime` don't serialise on a lock for the insert hot
/// path. `FnTime` itself uses a lock for the Welford-plus-histogram
/// update; this type is also usable standalone for lock-free metrics.
#[repr(C, align(64))]
pub struct Histogram {
    buckets: [AtomicU64; HISTOGRAM_BUCKETS],
    /// Saturating sample count; separately tracked so `quantile` can
    /// short-circuit the empty case without iterating buckets.
    count: AtomicU64,
}

impl Histogram {
    pub const fn new() -> Self {
        // Cannot `#[derive(Default)]` because `AtomicU64` isn't Copy.
        // Use array-repeat via `const {}` trick.
        Self {
            buckets: [const { AtomicU64::new(0) }; HISTOGRAM_BUCKETS],
            count: AtomicU64::new(0),
        }
    }

    /// Bucket index for `x`. Bucket `i` covers `[2^(i-1), 2^i)` for
    /// `i >= 1`; bucket 0 is the `x == 0` special case.
    #[inline]
    pub const fn bucket_for(x: u64) -> usize {
        if x == 0 {
            0
        } else {
            (64 - x.leading_zeros()) as usize
        }
    }

    /// Lower bound of bucket `i` (inclusive). `i == 0 → 0`,
    /// `i == 1 → 1`, `i == 2 → 2`, `i == 3 → 4`, …
    #[inline]
    pub const fn bucket_lower(i: usize) -> u64 {
        match i {
            0 => 0,
            1 => 1,
            _ => 1u64 << (i - 1),
        }
    }

    /// Add a sample.
    #[inline]
    pub fn add(&self, x: u64) {
        self.buckets[Self::bucket_for(x)].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Total sample count.
    #[inline]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Estimate the `p`-th percentile, expressed in permille
    /// (parts per thousand, 0..=1000). Returns the **lower bound**
    /// of the containing bucket — conservative. Returns 0 on an
    /// empty histogram. Permille-based because `f64::ceil` is not
    /// available in `no_std` core and `FnTime` callers know the
    /// target percentile at compile time anyway (p50 = 500, p99 = 990).
    pub fn quantile_permille(&self, p: u32) -> u64 {
        let total = self.count.load(Ordering::Relaxed);
        if total == 0 {
            return 0;
        }
        let p = p.min(1000) as u64;
        // target = ceil(total * p / 1000). Integer ceil = (a + b - 1) / b.
        let numer = total.saturating_mul(p);
        let target_count = (numer + 999) / 1000;
        let target = target_count.max(1);
        let mut cum = 0u64;
        for (i, b) in self.buckets.iter().enumerate() {
            cum = cum.saturating_add(b.load(Ordering::Relaxed));
            if cum >= target {
                return Self::bucket_lower(i);
            }
        }
        Self::bucket_lower(HISTOGRAM_BUCKETS - 1)
    }

    /// Shorthand: p50 / p90 / p99 / p999 in one line each.
    #[inline]
    pub fn p50(&self) -> u64 {
        self.quantile_permille(500)
    }
    #[inline]
    pub fn p90(&self) -> u64 {
        self.quantile_permille(900)
    }
    #[inline]
    pub fn p99(&self) -> u64 {
        self.quantile_permille(990)
    }
    #[inline]
    pub fn p999(&self) -> u64 {
        self.quantile_permille(999)
    }

    /// Snapshot into a plain-u64 array for external readers. Each
    /// bucket is loaded independently so the snapshot may tear across
    /// a concurrent adder — acceptable for diagnostic read-outs.
    pub fn snapshot(&self) -> [u64; HISTOGRAM_BUCKETS] {
        let mut out = [0u64; HISTOGRAM_BUCKETS];
        for (i, b) in self.buckets.iter().enumerate() {
            out[i] = b.load(Ordering::Relaxed);
        }
        out
    }
}

// Hand-rolled so `FnTime::histogram()` can clone cheaply. Cloning a
// Histogram atomically-snapshots each bucket into a fresh owner.
impl Clone for Histogram {
    fn clone(&self) -> Self {
        let out = Histogram::new();
        for (i, b) in self.buckets.iter().enumerate() {
            out.buckets[i].store(b.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        out.count
            .store(self.count.load(Ordering::Relaxed), Ordering::Relaxed);
        out
    }
}

impl core::fmt::Debug for Histogram {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Histogram")
            .field("count", &self.count.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}
