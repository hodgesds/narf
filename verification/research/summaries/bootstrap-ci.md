# Bootstrap Confidence Intervals

**Primary sources:** Efron & Tibshirani, *An Introduction to the
Bootstrap* (Chapman & Hall, 1993); Davison & Hinkley, *Bootstrap
Methods and their Application* (CUP, 1997).

> Distilled for NARF's perf-protocol. Why and how we compute CIs.

## Why not ±σ?

`mean ± 1.96·σ/√n` assumes the sample mean is normally distributed. For
latency-type measurements this is almost never true: they are
right-skewed, often heavy-tailed. A parametric CI can be wildly
asymmetric relative to reality, and can produce a lower bound that is
physically impossible (e.g. negative latency).

Bootstrap CIs make no such assumption. They estimate the sampling
distribution of the statistic directly from the data by resampling.

## The basic bootstrap (percentile method)

Given samples `x = [x_1, ..., x_n]` and a statistic `T(x)` (e.g. mean,
median, p99):

1. Resample `x*` from `x` *with replacement* to size `n`.
2. Compute `T(x*)`.
3. Repeat B times (B = 10 000 for NARF).
4. The 2.5th and 97.5th percentiles of the `T(x*)` values are the 95%
   CI for `T`.

## BCa (bias-corrected, accelerated)

The percentile method is biased when `T`'s sampling distribution is
skewed. BCa corrects by estimating:

- Bias correction `z_0` from the fraction of bootstrap replicates below `T(x)`.
- Acceleration `a` from the jackknife estimate of skewness.

Then computes corrected percentiles:

```
α_lo = Φ(z_0 + (z_0 + z_{α/2})   / (1 - a·(z_0 + z_{α/2})))
α_hi = Φ(z_0 + (z_0 + z_{1-α/2}) / (1 - a·(z_0 + z_{1-α/2})))
```

For NARF: percentile method by default; switch to BCa when the bootstrap
distribution's skewness is above a documented threshold.

## Practical choices NARF makes

- **B = 10 000 replicates.** Large enough that BCa/percentile stability
  is not a concern; small enough to run in well under a second on any
  modern machine.
- **Per-benchmark CIs for:** median, mean, p95, p99.
- **Delta CIs** for regression: resample both `new` and `baseline`
  paired per iteration index when paired comparison makes sense;
  otherwise unpaired resample and take the difference.
- **Reported as:** `median: 412 ns (95% CI 409–416 ns)` — one decimal
  place past what's meaningful, never more.

## Caveats

- Bootstrap assumes i.i.d. samples. Noise control (§8.2 of the
  verification spec) exists to make this approximately true.
- Bootstrap CIs for *extreme* percentiles (p99.99, p99.999) degrade
  rapidly because few samples inform the tail. For those, prefer
  larger N or specialised methods (order-statistic intervals).
- Bootstrap is not free for large N × large B; budget accordingly in CI.
