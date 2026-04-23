# Multiple Comparisons — Benjamini-Hochberg

**Primary sources:** Benjamini & Hochberg, "Controlling the False
Discovery Rate: A Practical and Powerful Approach to Multiple Testing"
(JRSSB, 1995); Benjamini & Yekutieli (2001) for the dependent case.

> Distilled for NARF's perf protocol.

## The problem

Running K independent statistical tests at significance α inflates the
probability of at least one false positive to `1 - (1-α)^K`. With 22
benchmarks at α = 0.05 that's `1 - 0.95^22 ≈ 68%` — a virtual
certainty of a spurious "regression" every run.

Two classical corrections:

- **Bonferroni:** use α' = α / K. Controls *family-wise error rate*
  (FWER) — the probability of *any* false positive. Very conservative;
  kills power quickly.
- **Benjamini-Hochberg (BH):** controls *false discovery rate* (FDR) —
  the expected fraction of declared positives that are false. Much
  better power when you can tolerate some false positives so long as
  most declared positives are real.

NARF uses **BH**. Perf regressions are a triage signal, not a
life-and-death test; FDR is the right frame.

## BH procedure

Given K p-values `p_1, ..., p_K` from K tests, at target FDR q:

1. Sort them ascending: `p_(1) ≤ p_(2) ≤ ... ≤ p_(K)`.
2. Find the largest `i` such that `p_(i) ≤ (i/K)·q`.
3. Reject all hypotheses with p-values ≤ `p_(i)` (i.e. declare them
   significant).

If no such `i` exists, declare nothing significant.

NARF defaults q = 0.05. Tuneable per-suite.

## Dependent tests

Strict BH assumes independent (or "positive regression dependent")
tests. NARF benchmarks are not strictly independent — shared noise
from the runner couples them. Two responses:

1. Use **Benjamini-Yekutieli** (BY), which is valid under arbitrary
   dependence at cost of extra factor `∑_{i=1}^K 1/i ≈ ln K`. Safer
   but more conservative.
2. Use BH and acknowledge the assumption in the protocol doc.

NARF's default: BH with an annual audit of flagged "significant"
regressions to confirm most were real. If false-positive rate creeps
up, switch the suite to BY.

## Practical reporting

Each perf run reports:

- Raw p-values per benchmark.
- BH-adjusted q-values per benchmark (smallest q at which this
  benchmark would be declared significant).
- The suite-level summary: "2 of 22 benchmarks flagged at FDR 0.05."

A benchmark is merge-blocking only if it is both BH-significant **and**
its effect-size CI (bootstrap) is beyond the benchmark's declared δ.

## Caveats

- Very small K (K ≤ 3): correction buys little; consider not correcting
  and instead demanding both Welch + MWU agreement.
- Very large K (K ≥ 100): BH remains valid but per-benchmark power
  drops; widen N.
- BH requires *all* p-values before deciding, so it cannot be
  streaming. Perf CI must collect the whole suite before reporting.
