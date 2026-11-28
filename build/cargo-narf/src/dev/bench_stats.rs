//! The statistical protocol from `verification/specification/spec.md` §8.
//!
//! Every function here exists because §8 names it. Nothing here is a
//! convenience: a median without a bootstrap CI, or a Welch's t without the
//! Mann-Whitney cross-check, is precisely the shape of number the protocol was
//! written to keep out of NARF's release notes.
//!
//! ## Why this is host-side, and why it has unit tests
//!
//! The kernel emits raw samples and nothing else. It has to — §8.5 forbids
//! trimming, so the samples must survive to the report, and §8.8 archives the
//! whole vector. Once they have left the kernel, the arithmetic belongs
//! somewhere it can be checked, because a wrong t-distribution tail silently
//! invalidates every conclusion drawn through it. The tests at the bottom
//! anchor each distribution function on a closed form:
//!
//! * Student's t with ν = 1 is Cauchy: `P(T ≤ 1) = 0.75` exactly.
//! * Student's t with ν = 2 has the closed form `½ + t / (2√(2 + t²))`.
//! * The normal CDF at ±1.96 is 0.975 / 0.025 to four places.
//!
//! Those are checks against mathematics rather than against a previous run of
//! this code, which is the only kind of check worth having here.

// Only the report path uses every helper; the module is written to be complete
// against §8 rather than to the current call sites, so a later phase adding
// p99.9 or a BCa interval finds it already here and tested.
#![allow(dead_code)]

/// A benchmark's samples plus its declaration, as parsed off the serial log.
#[derive(Clone, Debug)]
pub struct Series {
    pub name: String,
    pub subsystem: String,
    pub unit: String,
    pub lower_is_better: bool,
    pub iters: u64,
    pub warmup: u64,
    /// Work units one sample covered (interpreted instructions retired,
    /// program loads performed…). Zero when the benchmark declared none.
    pub work: u64,
    /// Set when samples disagreed about how much work they did, which
    /// invalidates any per-work figure derived from them.
    pub work_varied: bool,
    /// The benchmark's declared δ, in percent (§8.6.6).
    pub delta_pct: f64,
    /// The benchmark this one is the A/B counterpart of.
    pub pair: Option<String>,
    /// Sample count declared by the guest record header. The host checks this
    /// against the values actually harvested from the serial stream.
    pub declared_n: usize,
    /// Benchmark-declared sample target (§8.1), which an operator override may
    /// raise but never lower.
    pub target_n: usize,
    pub samples: Vec<f64>,
}

/// §8.4's summary block for one series.
#[derive(Clone, Copy, Debug)]
pub struct Summary {
    pub n: usize,
    pub median: f64,
    pub mean: f64,
    /// 95% bootstrap CI of the **mean**, per §8.4.
    pub mean_ci: (f64, f64),
    /// 95% bootstrap CI of the **median**, which is what §8.4 asks be
    /// reported first and what the effect size below is built on.
    pub median_ci: (f64, f64),
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub p999: f64,
    pub cv: f64,
    pub min: f64,
    pub max: f64,
    pub skew: f64,
}

/// A two-sample comparison, per §8.6.
#[derive(Clone, Debug)]
pub struct Comparison {
    pub baseline: String,
    pub candidate: String,
    /// Percentage change of the median, candidate relative to baseline.
    pub delta_pct: f64,
    /// 95% bootstrap CI of that percentage change.
    pub delta_ci: (f64, f64),
    pub welch_p: f64,
    /// Whether Welch ran on log-transformed samples (§8.6.2).
    pub welch_logged: bool,
    pub mwu_p: f64,
    /// δ this comparison is judged against.
    pub delta_threshold: f64,
    /// Filled in after the Benjamini-Hochberg pass over the whole suite.
    pub welch_significant: bool,
    pub mwu_significant: bool,
}

/// What §8.6.6 says to do about a comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Welch and Mann-Whitney disagree. §8.6.3: not a finding in either
    /// direction — *not* an excuse to quote whichever test was friendlier.
    Inconclusive,
    /// Neither test rejects. No difference established.
    NotSignificant,
    /// Both tests reject, but the effect is smaller than δ. Tracked.
    SignificantWithinDelta,
    /// Both tests reject and the effect is beyond δ.
    SignificantBeyondDelta,
}

impl Decision {
    pub fn label(self) -> &'static str {
        match self {
            Decision::Inconclusive => "inconclusive (tests disagree)",
            Decision::NotSignificant => "no difference established",
            Decision::SignificantWithinDelta => "significant, within delta (tracked)",
            Decision::SignificantBeyondDelta => "significant, beyond delta",
        }
    }
}

impl Comparison {
    pub fn decision(&self) -> Decision {
        if self.welch_significant != self.mwu_significant {
            return Decision::Inconclusive;
        }
        if !self.welch_significant {
            return Decision::NotSignificant;
        }
        // §8.6.5: an effect whose CI crosses δ is not established as being
        // beyond δ. Judged on the magnitude of the *interval*, not of the point
        // estimate, because a point estimate of 4% with a CI of [1%, 7%] has
        // not shown a 3% threshold to be exceeded.
        let lo = self.delta_ci.0.abs().min(self.delta_ci.1.abs());
        if lo > self.delta_threshold {
            Decision::SignificantBeyondDelta
        } else {
            Decision::SignificantWithinDelta
        }
    }
}

// ── descriptive statistics ──────────────────────────────────────────

/// Sorted copy. Every quantile below wants one and none of them may reorder
/// the caller's samples, since §8.8 archives them in collection order.
fn sorted(xs: &[f64]) -> Vec<f64> {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("samples are finite"));
    v
}

pub fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return f64::NAN;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Median of an already-sorted slice.
pub fn median_sorted(v: &[f64]) -> f64 {
    match v.len() {
        0 => f64::NAN,
        n if n % 2 == 1 => v[n / 2],
        n => (v[n / 2 - 1] + v[n / 2]) / 2.0,
    }
}

pub fn median(xs: &[f64]) -> f64 {
    median_sorted(&sorted(xs))
}

/// Linear-interpolated quantile (the "type 7" definition, which is what
/// numpy, R's default, and every latency tool agree on).
pub fn quantile_sorted(v: &[f64], q: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    if v.len() == 1 {
        return v[0];
    }
    let pos = q.clamp(0.0, 1.0) * (v.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    if lo == hi {
        return v[lo];
    }
    let frac = pos - lo as f64;
    v[lo] * (1.0 - frac) + v[hi] * frac
}

/// Sample standard deviation (n − 1 denominator).
pub fn stddev(xs: &[f64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let m = mean(xs);
    let ss: f64 = xs.iter().map(|x| (x - m) * (x - m)).sum();
    (ss / (xs.len() - 1) as f64).sqrt()
}

/// Sample skewness (the adjusted Fisher-Pearson g1). Used only to decide
/// whether §8.6.2's log transform applies and whether the bootstrap should be
/// BCa rather than percentile.
pub fn skewness(xs: &[f64]) -> f64 {
    let n = xs.len();
    if n < 3 {
        return 0.0;
    }
    let m = mean(xs);
    let sd = stddev(xs);
    if sd == 0.0 {
        return 0.0;
    }
    let n = n as f64;
    let s3: f64 = xs.iter().map(|x| ((x - m) / sd).powi(3)).sum();
    (n / ((n - 1.0) * (n - 2.0))) * s3
}

pub fn summarize(xs: &[f64], resamples: usize, seed: u64) -> Summary {
    let v = sorted(xs);
    let m = mean(xs);
    let sd = stddev(xs);
    Summary {
        n: xs.len(),
        median: median_sorted(&v),
        mean: m,
        mean_ci: bootstrap_ci(xs, resamples, seed, mean),
        median_ci: bootstrap_ci(xs, resamples, seed ^ 0x9E37_79B9, median),
        p50: quantile_sorted(&v, 0.50),
        p95: quantile_sorted(&v, 0.95),
        p99: quantile_sorted(&v, 0.99),
        p999: quantile_sorted(&v, 0.999),
        cv: if m == 0.0 { 0.0 } else { sd / m },
        min: *v.first().unwrap_or(&f64::NAN),
        max: *v.last().unwrap_or(&f64::NAN),
        skew: skewness(xs),
    }
}

// ── the bootstrap ───────────────────────────────────────────────────

/// SplitMix64. A fixed, seeded generator rather than a system source, because
/// §8.8 archives the record and a CI that cannot be recomputed from the
/// archived samples is not reproducible.
struct SplitMix(u64);

impl SplitMix {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// 95% bootstrap CI of `stat`, BCa when the samples are visibly skewed and
/// percentile otherwise — §8.4's rule verbatim.
///
/// BCa matters here rather than being ceremony: cycle counts under a
/// hypervisor have a hard floor and a long right tail, and a percentile
/// interval on a skewed statistic is biased in a direction that flatters
/// whichever arm happened to be sampled during a quiet moment.
pub fn bootstrap_ci(
    xs: &[f64],
    resamples: usize,
    seed: u64,
    stat: fn(&[f64]) -> f64,
) -> (f64, f64) {
    if xs.len() < 2 {
        let v = stat(xs);
        return (v, v);
    }
    let observed = stat(xs);
    let mut rng = SplitMix(seed | 1);
    let mut boots = Vec::with_capacity(resamples);
    let mut buf = vec![0.0; xs.len()];
    for _ in 0..resamples {
        for slot in buf.iter_mut() {
            *slot = xs[rng.below(xs.len())];
        }
        boots.push(stat(&buf));
    }
    boots.sort_by(|a, b| a.partial_cmp(b).expect("bootstrap statistic is finite"));

    const ALPHA: f64 = 0.05;
    if skewness(xs).abs() < 0.5 {
        return (
            quantile_sorted(&boots, ALPHA / 2.0),
            quantile_sorted(&boots, 1.0 - ALPHA / 2.0),
        );
    }

    // Bias correction: where the observed statistic falls among the resamples.
    let below = boots.iter().filter(|b| **b < observed).count() as f64;
    let frac = (below / resamples as f64).clamp(1e-6, 1.0 - 1e-6);
    let z0 = norm_ppf(frac);

    // Acceleration, from the jackknife.
    let mut jack = Vec::with_capacity(xs.len());
    let mut without = Vec::with_capacity(xs.len() - 1);
    for skip in 0..xs.len() {
        without.clear();
        without.extend(
            xs.iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .map(|(_, v)| *v),
        );
        jack.push(stat(&without));
    }
    let jbar = mean(&jack);
    let num: f64 = jack.iter().map(|j| (jbar - j).powi(3)).sum();
    let den: f64 = jack.iter().map(|j| (jbar - j).powi(2)).sum();
    let a = if den <= 0.0 {
        0.0
    } else {
        num / (6.0 * den.powf(1.5))
    };

    let adjust = |z_alpha: f64| -> f64 {
        let z = z0 + (z0 + z_alpha) / (1.0 - a * (z0 + z_alpha));
        norm_cdf(z).clamp(0.0, 1.0)
    };
    let lo_q = adjust(norm_ppf(ALPHA / 2.0));
    let hi_q = adjust(norm_ppf(1.0 - ALPHA / 2.0));
    (
        quantile_sorted(&boots, lo_q.min(hi_q)),
        quantile_sorted(&boots, lo_q.max(hi_q)),
    )
}

/// Percentage change of `cand`'s median relative to `base`'s, with a 95%
/// bootstrap CI — §8.6.5's effect size.
///
/// The two groups are resampled independently, which is the right null for two
/// separately-collected sample sets even though the harness interleaves their
/// collection. Treating them as paired would be tighter and would also be a
/// claim about sample i of A and sample i of B sharing a condition, which
/// round-robin collection makes plausible but does not establish.
pub fn delta_pct_ci(base: &[f64], cand: &[f64], resamples: usize, seed: u64) -> (f64, (f64, f64)) {
    let point = pct_change(median(base), median(cand));
    if base.len() < 2 || cand.len() < 2 {
        return (point, (f64::NAN, f64::NAN));
    }
    let mut rng = SplitMix(seed | 1);
    let mut boots = Vec::with_capacity(resamples);
    let mut b = vec![0.0; base.len()];
    let mut c = vec![0.0; cand.len()];
    for _ in 0..resamples {
        for slot in b.iter_mut() {
            *slot = base[rng.below(base.len())];
        }
        for slot in c.iter_mut() {
            *slot = cand[rng.below(cand.len())];
        }
        boots.push(pct_change(median(&b), median(&c)));
    }
    boots.sort_by(|a, b| a.partial_cmp(b).expect("bootstrap statistic is finite"));
    (
        point,
        (
            quantile_sorted(&boots, 0.025),
            quantile_sorted(&boots, 0.975),
        ),
    )
}

fn pct_change(base: f64, cand: f64) -> f64 {
    if base == 0.0 {
        return f64::NAN;
    }
    (cand - base) / base * 100.0
}

// ── hypothesis tests ────────────────────────────────────────────────

/// Welch's t-test, two-sided. §8.6.2.
///
/// Returns `(p, logged)`. `logged` records whether the samples were
/// log-transformed first, which §8.6.2 asks for when the metric is strictly
/// positive and skewed — the usual case for a latency-like measurement, where
/// the multiplicative model is the realistic one and an untransformed t-test
/// is testing a difference of means nobody cares about.
pub fn welch_t_test(a: &[f64], b: &[f64]) -> (f64, bool) {
    let positive = a.iter().chain(b.iter()).all(|x| *x > 0.0);
    let skewed = skewness(a).abs() > 0.5 || skewness(b).abs() > 0.5;
    let logged = positive && skewed;
    let (a, b) = if logged {
        (
            a.iter().map(|x| x.ln()).collect::<Vec<_>>(),
            b.iter().map(|x| x.ln()).collect::<Vec<_>>(),
        )
    } else {
        (a.to_vec(), b.to_vec())
    };
    if a.len() < 2 || b.len() < 2 {
        return (f64::NAN, logged);
    }
    let (n1, n2) = (a.len() as f64, b.len() as f64);
    let (v1, v2) = (stddev(&a).powi(2), stddev(&b).powi(2));
    let se2 = v1 / n1 + v2 / n2;
    if se2 <= 0.0 {
        // Both groups constant. Either identical (no difference to find) or
        // different with zero variance, which no t-test can speak to.
        let p = if (mean(&a) - mean(&b)).abs() < f64::EPSILON {
            1.0
        } else {
            0.0
        };
        return (p, logged);
    }
    let t = (mean(&a) - mean(&b)) / se2.sqrt();
    // Welch-Satterthwaite.
    let df = se2 * se2 / ((v1 / n1).powi(2) / (n1 - 1.0) + (v2 / n2).powi(2) / (n2 - 1.0));
    (2.0 * student_t_sf(t.abs(), df), logged)
}

/// Mann-Whitney U, two-sided, normal approximation with the tie correction.
///
/// The normal approximation is sound here because §8.3 puts N ≥ 30 in each
/// group; below that it would need the exact distribution and this would be
/// the wrong implementation.
pub fn mann_whitney_u(a: &[f64], b: &[f64]) -> f64 {
    let (n1, n2) = (a.len(), b.len());
    if n1 == 0 || n2 == 0 {
        return f64::NAN;
    }
    // Midranks over the pooled sample.
    let mut pooled: Vec<(f64, bool)> = a
        .iter()
        .map(|v| (*v, true))
        .chain(b.iter().map(|v| (*v, false)))
        .collect();
    pooled.sort_by(|x, y| x.0.partial_cmp(&y.0).expect("samples are finite"));

    let mut rank_sum_a = 0.0;
    let mut tie_term = 0.0;
    let mut i = 0;
    while i < pooled.len() {
        let mut j = i;
        while j + 1 < pooled.len() && pooled[j + 1].0 == pooled[i].0 {
            j += 1;
        }
        let group = (j - i + 1) as f64;
        // Ranks are 1-based; the midrank of a tied block is the mean of the
        // ranks it spans.
        let midrank = (i + j + 2) as f64 / 2.0;
        rank_sum_a += pooled[i..=j].iter().filter(|(_, is_a)| *is_a).count() as f64 * midrank;
        tie_term += group * group * group - group;
        i = j + 1;
    }

    let (fn1, fn2) = (n1 as f64, n2 as f64);
    let u_a = rank_sum_a - fn1 * (fn1 + 1.0) / 2.0;
    let u = u_a.min(fn1 * fn2 - u_a);
    let mu = fn1 * fn2 / 2.0;
    let n = fn1 + fn2;
    let var = (fn1 * fn2 / 12.0) * ((n + 1.0) - tie_term / (n * (n - 1.0)));
    if var <= 0.0 {
        return 1.0;
    }
    // Continuity correction, so a borderline p is not optimistic.
    let z = ((u - mu).abs() - 0.5).max(0.0) / var.sqrt();
    2.0 * (1.0 - norm_cdf(z))
}

/// Benjamini-Hochberg step-up at FDR `q`, over `ps`.
///
/// Returns, per input position, whether that hypothesis is rejected. §8.6.4:
/// without this, a suite of 22 benchmarks with one flaky arm reports a
/// regression roughly every other run.
pub fn benjamini_hochberg(ps: &[f64], q: f64) -> Vec<bool> {
    let m = ps.len();
    let mut order: Vec<usize> = (0..m).collect();
    order.sort_by(|x, y| ps[*x].partial_cmp(&ps[*y]).expect("p-values are finite"));
    // Largest k (1-based) with p_(k) ≤ k·q/m; reject that one and everything
    // ranked below it.
    let mut cutoff = 0usize;
    for (rank, idx) in order.iter().enumerate() {
        if ps[*idx] <= (rank + 1) as f64 * q / m as f64 {
            cutoff = rank + 1;
        }
    }
    let mut out = vec![false; m];
    for idx in order.iter().take(cutoff) {
        out[*idx] = true;
    }
    out
}

// ── distribution functions ──────────────────────────────────────────

/// Standard normal CDF, via `erfc`.
pub fn norm_cdf(z: f64) -> f64 {
    0.5 * erfc(-z / std::f64::consts::SQRT_2)
}

/// Complementary error function. Numerical Recipes' `erfc` — a Chebyshev
/// rational fit good to ~1.2e-7 relative, which is three orders tighter than
/// any p-value here is interpreted to.
///
/// The coefficients are transcribed verbatim from the published table.
/// `excessive_precision` and `inconsistent_digit_grouping` are allowed for
/// exactly that reason: a published constant is a citation, and re-rounding one
/// to whatever the linter finds tidy is how a fit silently stops being the fit
/// that was validated.
#[allow(clippy::excessive_precision, clippy::inconsistent_digit_grouping)]
fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 2.0 / (2.0 + z);
    let ty = 4.0 * t - 2.0;
    // Chebyshev coefficients, highest order first.
    const COF: [f64; 28] = [
        -1.3026537197817094,
        6.419_697_923_564_902e-1,
        1.9476473204185836e-2,
        -9.561_514_786_808_631e-3,
        -9.46595344482036e-4,
        3.66839497852761e-4,
        4.2523324806907e-5,
        -2.0278578112534e-5,
        -1.624290004647e-6,
        1.303655835580e-6,
        1.5626441722e-8,
        -8.5238095915e-8,
        6.529054439e-9,
        5.059343495e-9,
        -9.91364156e-10,
        -2.27365122e-10,
        9.6467911e-11,
        2.394038e-12,
        -6.886027e-12,
        8.94487e-13,
        3.13092e-13,
        -1.12708e-13,
        3.81e-16,
        7.106e-15,
        -1.523e-15,
        -9.4e-17,
        1.21e-16,
        -2.8e-17,
    ];
    let mut d = 0.0f64;
    let mut dd = 0.0f64;
    for c in COF.iter().skip(1).rev() {
        let tmp = d;
        d = ty * d - dd + c;
        dd = tmp;
    }
    let ans = t * (-z * z + 0.5 * (COF[0] + ty * d) - dd).exp();
    if x >= 0.0 {
        ans
    } else {
        2.0 - ans
    }
}

/// Inverse standard normal CDF (Acklam's rational approximation, refined by one
/// Halley step against [`norm_cdf`] so the result is accurate to ~1e-15).
pub fn norm_ppf(p: f64) -> f64 {
    if p <= 0.0 {
        return f64::NEG_INFINITY;
    }
    if p >= 1.0 {
        return f64::INFINITY;
    }
    const A: [f64; 6] = [
        -3.969_683_028_665_376e1,
        2.209_460_984_245_205e2,
        -2.759_285_104_469_687e2,
        1.383_577_518_672_69e2,
        -3.066_479_806_614_716e1,
        2.506_628_277_459_239,
    ];
    const B: [f64; 5] = [
        -5.447_609_879_822_406e1,
        1.615_858_368_580_409e2,
        -1.556_989_798_598_866e2,
        6.680_131_188_771_972e1,
        -1.328_068_155_288_572e1,
    ];
    const C: [f64; 6] = [
        -7.784_894_002_430_293e-3,
        -3.223_964_580_411_365e-1,
        -2.400_758_277_161_838,
        -2.549_732_539_343_734,
        4.374_664_141_464_968,
        2.938_163_982_698_783,
    ];
    const D: [f64; 4] = [
        7.784_695_709_041_462e-3,
        3.224_671_290_700_398e-1,
        2.445_134_137_142_996,
        3.754_408_661_907_416,
    ];
    const P_LOW: f64 = 0.024_25;
    let x = if p < P_LOW {
        let q = (-2.0 * p.ln()).sqrt();
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    } else if p <= 1.0 - P_LOW {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -(((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    };
    // One Halley refinement. Acklam's fit is ~1.15e-9 relative; the refinement
    // costs one `erfc` and removes the approximation from the BCa endpoints,
    // where it would otherwise show up as a systematic shift in every CI.
    let e = norm_cdf(x) - p;
    let u = e * (2.0 * std::f64::consts::PI).sqrt() * (x * x / 2.0).exp();
    x - u / (1.0 + x * u / 2.0)
}

/// Upper-tail survival function of Student's t with `df` degrees of freedom:
/// `P(T > t)`.
pub fn student_t_sf(t: f64, df: f64) -> f64 {
    if !t.is_finite() || !df.is_finite() || df <= 0.0 {
        return f64::NAN;
    }
    // P(|T| > t) = I_{df/(df+t²)}(df/2, 1/2); halve for the one-sided tail.
    let x = df / (df + t * t);
    0.5 * betai(df / 2.0, 0.5, x)
}

/// Regularised incomplete beta `I_x(a, b)`.
fn betai(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let front = (lgamma(a + b) - lgamma(a) - lgamma(b) + a * x.ln() + b * (1.0 - x).ln()).exp();
    // The continued fraction converges only for x < (a+1)/(a+b+2); reflect
    // otherwise.
    if x < (a + 1.0) / (a + b + 2.0) {
        front * betacf(a, b, x) / a
    } else {
        1.0 - front * betacf(b, a, 1.0 - x) / b
    }
}

/// Lentz's algorithm for the beta continued fraction (Numerical Recipes
/// `betacf`).
fn betacf(a: f64, b: f64, x: f64) -> f64 {
    const MAXIT: usize = 300;
    const EPS: f64 = 3.0e-16;
    const FPMIN: f64 = 1.0e-300;
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < FPMIN {
        d = FPMIN;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=MAXIT {
        let fm = m as f64;
        let m2 = 2.0 * fm;
        // Even step.
        let mut aa = fm * (b - fm) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        h *= d * c;
        // Odd step.
        aa = -(a + fm) * (qab + fm) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < EPS {
            break;
        }
    }
    h
}

/// Log-gamma, Lanczos g = 7, n = 9. Coefficients verbatim from the published
/// table; see [`erfc`] for why the precision lints are allowed here.
#[allow(clippy::excessive_precision, clippy::inconsistent_digit_grouping)]
fn lgamma(x: f64) -> f64 {
    const G: [f64; 9] = [
        0.999_999_999_999_809_93,
        676.520_368_121_885_1,
        -1259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        // Reflection, so the series is only ever evaluated where it converges.
        (std::f64::consts::PI / (std::f64::consts::PI * x).sin()).ln() - lgamma(1.0 - x)
    } else {
        let x = x - 1.0;
        let mut a = G[0];
        let t = x + 7.5;
        for (i, g) in G.iter().enumerate().skip(1) {
            a += g / (x + i as f64);
        }
        0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, tol: f64) {
        assert!(
            (a - b).abs() <= tol,
            "expected {b} within {tol}, got {a} (diff {})",
            (a - b).abs()
        );
    }

    #[test]
    fn median_handles_both_parities() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), 2.5);
        assert_eq!(median(&[7.0]), 7.0);
    }

    #[test]
    fn quantiles_match_the_type_7_definition() {
        let v: Vec<f64> = (1..=100).map(f64::from).collect();
        // Type 7: position = q·(n−1), so p50 of 1..100 is 50.5 and p99 is 99.01.
        close(quantile_sorted(&v, 0.50), 50.5, 1e-12);
        close(quantile_sorted(&v, 0.99), 99.01, 1e-12);
        close(quantile_sorted(&v, 0.0), 1.0, 1e-12);
        close(quantile_sorted(&v, 1.0), 100.0, 1e-12);
    }

    #[test]
    fn stddev_matches_the_hand_computed_value() {
        // Sample variance of 2,4,4,4,5,5,7,9 with n−1 is 32/7.
        let sd = stddev(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        close(sd, (32.0f64 / 7.0).sqrt(), 1e-12);
    }

    // ── distribution anchors, each against a closed form ────────────

    #[test]
    fn normal_cdf_hits_the_textbook_quantiles() {
        close(norm_cdf(0.0), 0.5, 1e-12);
        close(norm_cdf(1.959_963_984_540_054), 0.975, 1e-9);
        close(norm_cdf(-1.959_963_984_540_054), 0.025, 1e-9);
        close(norm_cdf(1.0), 0.841_344_746_068_543, 1e-9);
    }

    #[test]
    fn normal_ppf_inverts_the_cdf() {
        for p in [0.001, 0.01, 0.025, 0.1, 0.5, 0.9, 0.975, 0.99, 0.999] {
            close(norm_cdf(norm_ppf(p)), p, 1e-12);
        }
        close(norm_ppf(0.975), 1.959_963_984_540_054, 1e-9);
    }

    #[test]
    fn student_t_df1_is_cauchy() {
        // ν = 1 is the standard Cauchy: P(T ≤ 1) = ¾ exactly, so the upper
        // tail is ¼ and the two-sided p at |t| = 1 is ½.
        close(student_t_sf(1.0, 1.0), 0.25, 1e-10);
        close(2.0 * student_t_sf(1.0, 1.0), 0.5, 1e-10);
    }

    #[test]
    fn student_t_df2_matches_its_closed_form() {
        // ν = 2: P(T ≤ t) = ½ + t / (2√(2 + t²)).
        for t in [0.5f64, 1.0, 2.0, 4.0] {
            let cdf = 0.5 + t / (2.0 * (2.0 + t * t).sqrt());
            close(student_t_sf(t, 2.0), 1.0 - cdf, 1e-10);
        }
    }

    #[test]
    fn student_t_approaches_the_normal() {
        // At ν = 100 000 the t tail is the normal tail to five places, which
        // is the sanity check that `betai`'s reflection branch is right.
        close(student_t_sf(1.96, 100_000.0), 1.0 - norm_cdf(1.96), 1e-5);
    }

    #[test]
    fn lgamma_matches_known_values() {
        close(lgamma(1.0), 0.0, 1e-12);
        close(lgamma(2.0), 0.0, 1e-12);
        // Γ(½) = √π.
        close(lgamma(0.5), std::f64::consts::PI.sqrt().ln(), 1e-12);
        // Γ(6) = 120.
        close(lgamma(6.0), 120.0f64.ln(), 1e-11);
    }

    // ── the tests §8.6 mandates ─────────────────────────────────────

    #[test]
    fn welch_finds_no_difference_between_identical_groups() {
        let a: Vec<f64> = (0..40).map(|i| 100.0 + f64::from(i % 5)).collect();
        let b = a.clone();
        let (p, _) = welch_t_test(&a, &b);
        close(p, 1.0, 1e-12);
    }

    #[test]
    fn welch_finds_a_clear_shift() {
        let a: Vec<f64> = (0..40).map(|i| 100.0 + f64::from(i % 5)).collect();
        let b: Vec<f64> = a.iter().map(|x| x + 20.0).collect();
        let (p, _) = welch_t_test(&a, &b);
        assert!(p < 1e-20, "expected a decisive p, got {p}");
    }

    #[test]
    fn welch_matches_a_hand_computed_t() {
        // Equal-size groups with hand-computable moments: means 2 and 4,
        // sample variances 1 each, n = 5 → SE² = 2/5, t = −2/√0.4, df = 8.
        let a = [1.0, 1.0, 2.0, 3.0, 3.0];
        let b = [3.0, 3.0, 4.0, 5.0, 5.0];
        close(mean(&a), 2.0, 1e-12);
        close(stddev(&a), 1.0, 1e-12);
        let t = 2.0 / (0.4f64).sqrt();
        let expected = 2.0 * student_t_sf(t, 8.0);
        let (p, logged) = welch_t_test(&a, &b);
        // Neither group is skewed, so no log transform should have happened —
        // if it had, this comparison would not hold.
        assert!(!logged);
        close(p, expected, 1e-12);
    }

    #[test]
    fn welch_log_transforms_only_skewed_positive_samples() {
        let symmetric: Vec<f64> = (0..40).map(|i| 100.0 + f64::from(i % 7)).collect();
        let (_, logged) = welch_t_test(&symmetric, &symmetric);
        assert!(!logged);
        // A long right tail: 39 samples at ~100 and one at 1000.
        let mut skewed = vec![100.0; 39];
        skewed.push(1000.0);
        let (_, logged) = welch_t_test(&skewed, &skewed);
        assert!(logged, "a strictly-positive skewed sample must be logged");
    }

    #[test]
    fn mann_whitney_separated_groups() {
        // Complete separation of 4 vs 4: U = 0, μ = 8, σ² = 4·4·9/12 = 12.
        // With the continuity correction z = 7.5/√12.
        let p = mann_whitney_u(&[1.0, 2.0, 3.0, 4.0], &[5.0, 6.0, 7.0, 8.0]);
        let z = 7.5 / 12.0f64.sqrt();
        close(p, 2.0 * (1.0 - norm_cdf(z)), 1e-12);
    }

    #[test]
    fn mann_whitney_identical_groups_is_not_significant() {
        let a: Vec<f64> = (0..30).map(f64::from).collect();
        let p = mann_whitney_u(&a, &a);
        assert!(p > 0.9, "identical groups must not look significant: {p}");
    }

    #[test]
    fn mann_whitney_applies_the_tie_correction() {
        // All values tied: the variance term collapses, so the test can say
        // nothing and must return 1 rather than dividing by zero.
        let a = vec![5.0; 10];
        let b = vec![5.0; 10];
        close(mann_whitney_u(&a, &b), 1.0, 1e-12);
    }

    #[test]
    fn mann_whitney_is_symmetric_in_its_arguments() {
        let a: Vec<f64> = (0..30).map(|i| f64::from(i) * 1.5).collect();
        let b: Vec<f64> = (0..30).map(|i| f64::from(i) * 1.5 + 4.0).collect();
        close(mann_whitney_u(&a, &b), mann_whitney_u(&b, &a), 1e-12);
    }

    #[test]
    fn benjamini_hochberg_step_up() {
        // The textbook boundary case: p_(k) = k·q/m for every k, so every
        // hypothesis is rejected (the comparison is ≤, not <).
        let ps = [0.01, 0.02, 0.03, 0.04, 0.05];
        assert_eq!(benjamini_hochberg(&ps, 0.05), vec![true; 5]);
    }

    #[test]
    fn benjamini_hochberg_rejects_only_below_the_cutoff() {
        // m = 2, q = 0.05: thresholds 0.025 and 0.05. Only the first passes.
        let out = benjamini_hochberg(&[0.001, 0.9], 0.05);
        assert_eq!(out, vec![true, false]);
    }

    #[test]
    fn benjamini_hochberg_rejects_the_whole_step_up_run() {
        // p = [0.001, 0.049, 0.9], m = 3, q = 0.05: thresholds are 0.0167,
        // 0.0333, 0.05. Rank 2's p (0.049) exceeds its threshold, but rank 3's
        // (0.9) also fails, so the cutoff is rank 1 — the step-*up* rule
        // rejects everything at or below the largest passing rank, and here
        // that is only the first.
        let out = benjamini_hochberg(&[0.001, 0.049, 0.9], 0.05);
        assert_eq!(out, vec![true, false, false]);
    }

    #[test]
    fn benjamini_hochberg_is_permutation_invariant() {
        let a = benjamini_hochberg(&[0.9, 0.001, 0.02], 0.05);
        let b = benjamini_hochberg(&[0.001, 0.02, 0.9], 0.05);
        assert_eq!(a, vec![false, true, true]);
        assert_eq!(b, vec![true, true, false]);
    }

    // ── the bootstrap ───────────────────────────────────────────────

    #[test]
    fn bootstrap_ci_of_a_constant_is_degenerate() {
        let xs = vec![42.0; 40];
        let (lo, hi) = bootstrap_ci(&xs, 2000, 1, mean);
        close(lo, 42.0, 1e-12);
        close(hi, 42.0, 1e-12);
    }

    #[test]
    fn bootstrap_ci_brackets_the_point_estimate() {
        let xs: Vec<f64> = (0..60).map(|i| 100.0 + f64::from(i % 11)).collect();
        let m = mean(&xs);
        let (lo, hi) = bootstrap_ci(&xs, 4000, 7, mean);
        assert!(lo < m && m < hi, "CI [{lo}, {hi}] must bracket {m}");
        // And be tight: the normal-theory 95% interval for this sample is
        // ±1.96·σ/√n ≈ ±0.83, so a decade wider than that means the resampler
        // is broken.
        assert!(hi - lo < 4.0, "CI is implausibly wide: [{lo}, {hi}]");
    }

    #[test]
    fn bootstrap_ci_is_reproducible_from_the_seed() {
        let xs: Vec<f64> = (0..50).map(|i| 10.0 + f64::from(i % 7)).collect();
        assert_eq!(
            bootstrap_ci(&xs, 1000, 99, median),
            bootstrap_ci(&xs, 1000, 99, median)
        );
    }

    #[test]
    fn bootstrap_switches_to_bca_when_skewed() {
        // A hard floor with a long right tail is exactly the shape §8.4's BCa
        // clause is for. The assertion is that the branch is taken and still
        // produces a sane, bracketing interval — the percentile branch is
        // covered by the tests above.
        let mut xs = vec![100.0; 50];
        for i in 0..6 {
            xs.push(400.0 + f64::from(i) * 50.0);
        }
        assert!(skewness(&xs).abs() > 0.5, "fixture must be skewed");
        let (lo, hi) = bootstrap_ci(&xs, 4000, 3, median);
        assert!(lo <= median(&xs) && median(&xs) <= hi, "[{lo}, {hi}]");
    }

    #[test]
    fn delta_pct_is_signed_and_relative_to_the_baseline() {
        let base = vec![100.0; 40];
        let cand = vec![110.0; 40];
        let (d, _) = delta_pct_ci(&base, &cand, 500, 5);
        close(d, 10.0, 1e-12);
        let (d, _) = delta_pct_ci(&cand, &base, 500, 5);
        close(d, -100.0 / 11.0, 1e-12);
    }

    #[test]
    fn delta_ci_brackets_zero_for_identical_groups() {
        let a: Vec<f64> = (0..50).map(|i| 100.0 + f64::from(i % 9)).collect();
        let (d, (lo, hi)) = delta_pct_ci(&a, &a, 4000, 11);
        close(d, 0.0, 1e-12);
        assert!(lo <= 0.0 && hi >= 0.0, "CI [{lo}, {hi}] must contain 0");
    }

    // ── the decision rule ───────────────────────────────────────────

    fn comparison(welch: bool, mwu: bool, ci: (f64, f64)) -> Comparison {
        Comparison {
            baseline: "a".into(),
            candidate: "b".into(),
            delta_pct: (ci.0 + ci.1) / 2.0,
            delta_ci: ci,
            welch_p: 0.0,
            welch_logged: false,
            mwu_p: 0.0,
            delta_threshold: 3.0,
            welch_significant: welch,
            mwu_significant: mwu,
        }
    }

    #[test]
    fn disagreement_is_inconclusive_not_a_finding() {
        assert_eq!(
            comparison(true, false, (10.0, 20.0)).decision(),
            Decision::Inconclusive
        );
        assert_eq!(
            comparison(false, true, (10.0, 20.0)).decision(),
            Decision::Inconclusive
        );
    }

    #[test]
    fn agreement_below_delta_is_tracked_not_blocking() {
        assert_eq!(
            comparison(true, true, (1.0, 2.0)).decision(),
            Decision::SignificantWithinDelta
        );
    }

    #[test]
    fn a_ci_straddling_delta_has_not_established_delta() {
        // Point estimate 4% > δ = 3%, but the interval reaches down to 1%.
        assert_eq!(
            comparison(true, true, (1.0, 7.0)).decision(),
            Decision::SignificantWithinDelta
        );
    }

    #[test]
    fn a_ci_entirely_beyond_delta_blocks() {
        assert_eq!(
            comparison(true, true, (5.0, 9.0)).decision(),
            Decision::SignificantBeyondDelta
        );
        // Sign-insensitive: a 5-9% improvement is just as much beyond δ.
        assert_eq!(
            comparison(true, true, (-9.0, -5.0)).decision(),
            Decision::SignificantBeyondDelta
        );
    }

    #[test]
    fn neither_test_rejecting_establishes_nothing() {
        assert_eq!(
            comparison(false, false, (-1.0, 1.0)).decision(),
            Decision::NotSignificant
        );
    }
}
