# verification — Specification

> Status: **Outline v0.2**. Statistical protocol is the v0.2 addition;
> earlier sections remain outlines.

## 1. Purpose & scope

**Owns:** Test taxonomy, the QEMU-based functional harness, fuzz
infrastructure, formal-methods (Kani/Creusot) targets, and the
**statistical protocol** for performance testing and regression
detection.

**Does NOT own:** Per-subsystem unit tests (live beside their code),
build orchestration (`build/`), release sign-off (`process/`).

## 2. Assumptions

- `build/`'s `cargo xtask test` can boot the kernel in QEMU and collect
  structured exit codes + instrumentation output.
- `console/` provides a deterministic log sink we can parse.
- CI runners have dedicated (not shared) cores, with frequency scaling
  and turbo disabled for perf jobs.

## 3. Test taxonomy

| Category        | Runs on       | Who gates | What it protects against                     |
| --------------- | ------------- | --------- | -------------------------------------------- |
| Unit            | host          | every PR  | pure-logic regressions in a single module    |
| Property        | host          | every PR  | algebraic invariants (e.g. cap derivation ⊆) |
| Functional      | QEMU          | every PR  | "does the whole kernel still work?"          |
| Fuzz            | host          | nightly   | parser / state-machine robustness             |
| Performance     | dedicated HW  | perf-sensitive PRs + nightly | throughput / latency regressions |
| Stress / soak   | dedicated HW  | pre-release | leaks, drift, long-running correctness      |
| Formal (opt-in) | host          | when claimed | proven invariants on small TCB cores      |

## 4. Unit tests

- Live in each crate as `#[cfg(test)]` modules or `tests/` dir.
- Must compile `no_std`-clean when the target crate does.
- No filesystem, no network, no `sleep`.
- Enforced runtime budget: each unit test ≤ 100 ms on reference hardware.

## 5. Property tests

- Powered by `proptest` (or `arbtest` for `no_std`-friendly use cases).
- Target properties that are cheap to specify but hard to cover manually:
  - Capability derivation: derived rights are always a subset.
  - Ring buffer: enqueue/dequeue is a permutation of inputs for SPSC.
  - Page allocator: allocate+free is a no-op on accounting.
  - Domain tag assignment: no tag bleed between disjoint ranges.
- Shrinker output is printed with every failure.

## 6. Functional tests

- A `#[kernel_test]` macro registers a function that runs **inside** the
  booted kernel. The harness boots QEMU, runs the test, examines the
  exit code and log.
- Three outcome channels: success (QEMU exit 0x10), failure (0x11),
  timeout (harness kill).
- Runs on `x86_64` and `aarch64` targets on every PR.
- Each test declares:
  - Required features (e.g. PKS, MTE). Skipped on archs without them
    unless the test is specifically an arch check.
  - Expected domain configuration.
  - Max runtime.

Example functional tests:

- Boot, print, cleanly shutdown.
- Allocate and free 10 000 frames; check accounting.
- Assign domains 0..15, cross-write attempts fault as expected.
- Narf-Ring round-trip: N producers, 1 consumer, count matches.

## 7. Fuzz targets

- `cargo-fuzz` (libFuzzer) or `cargo-bolero` (multi-engine) on host.
- Initial targets:
  - Cap-table slot decoder.
  - Narf-Ring message parser.
  - Virtio descriptor validator.
  - ELF loader (Stage 4).
- Corpus stored in-tree under `fuzz/corpus/`; minimised weekly.
- Crash reports become regression unit tests.

## 8. Performance testing — statistical protocol

NARF's public perf claims must be defensible. Every perf number in
release notes, blog posts, or README tables comes from this protocol.

### 8.1 Benchmark unit

A **benchmark** is a deterministic routine that returns one *sample*
of a single scalar metric, in a declared unit (e.g. cycles, ns, ops/s).
Each benchmark declares:

- Metric and unit.
- Whether lower-is-better or higher-is-better.
- Warmup iterations (discarded).
- Measured iterations per sample (inner loop; reduces timing granularity error).
- Target sample count (see §8.3).

### 8.2 Noise control

Required for perf CI runners, documented in `build/`:

- Dedicated core(s); no co-tenants.
- CPU frequency fixed at nominal (no turbo, no governor dynamism).
- HyperThreading / SMT disabled on perf runners.
- ASLR disabled for the benchmark process.
- Background services minimised; boot a known minimal userland.
- Thermal throttling tripwires abort and invalidate the run.

Runs that fail the noise-control precondition are **discarded**, not
averaged. This is not negotiable — averaging a throttled run with a
clean run hides regressions.

**Harness-side precondition verification (mandatory).** The benchmark
harness must actively verify all noise-control preconditions *at
run start*, not rely on runner configuration alone. Required checks:

- CPU governor is `performance` (or arch equivalent).
- Turbo / boost is disabled.
- SMT / HyperThreading is off on the chosen runner.
- ASLR is disabled in the benchmark process.
- Thermal counters report below the throttle threshold for the prior 30 s.
- No sibling CPU on the same LLC has a load average > 0.05.

A failed check **aborts the run with a structured `PreconditionFailed`
error and emits no performance record** — better to publish nothing
than to publish a polluted number. Configuration drift is caught the
moment it happens, not weeks later when somebody notices the noise.

### 8.3 Sample size

Minimum `N = 30` independent samples per benchmark per build. Rationale:
central-limit behaviour becomes acceptable around 30, *and* bootstrap
resampling works well. Increase to `N = 100` for benchmarks where the
observed coefficient of variation (CV = σ/μ) exceeds 5%.

For regression detection where the magnitude of the expected regression
is small, use a **power analysis** to pick N:

Required N ≈ `(z_{α/2} + z_β)² · 2σ² / δ²`

for two-sample tests at significance α, power β, pooled standard
deviation σ, and detectable effect size δ. NARF defaults α = 0.01,
β = 0.20; δ is chosen per-benchmark and documented in the test
declaration (e.g. "detect 2% slowdown").

### 8.4 Summary statistics

For each set of N samples we report, in this order:

- **Median** (robust central tendency).
- **Mean ± 95% bootstrap confidence interval** (10 000 resamples, BCa
  when skewness is detectable, percentile otherwise).
- **Percentiles** p50, p95, p99, p99.9 for latency-like metrics.
- **CV** (for health: CV > 10% means the benchmark is noisy, investigate).
- **Min / max** — informational, never a headline number.

Never report mean alone. Never report a single sample.

### 8.5 Outlier treatment

- **Do not** silently trim.
- Report robust statistics (median, bootstrap CI) so outliers are
  visible but not controlling.
- If a *justified* reason exists to trim (e.g. a clearly-documented
  interrupt during the run), trim using the **median absolute
  deviation (MAD)** rule: drop samples outside median ± 3·MAD, and
  disclose the trimming in the result record.

### 8.6 Regression detection

For `build_new` vs. `baseline`:

1. Collect N samples of each using the same protocol on the same runner.
2. Primary test: **Welch's t-test** (unequal variances) on log-transformed
   samples when the metric is strictly positive and skewed (typical for
   latency), plain otherwise.
3. Non-parametric cross-check: **Mann-Whitney U** (rank-sum). If Welch
   says regression and Mann-Whitney disagrees, the result is
   "inconclusive" — do not merge claiming a regression.
4. When running K benchmarks in a suite, apply a **multiple-comparison
   correction**. Default: **Benjamini-Hochberg** (FDR control at q = 0.05).
   This prevents the "22 benchmarks, one flaky = false alarm" problem.
5. Effect size reported as **percentage change with 95% bootstrap CI**.
   A regression that is statistically significant but whose CI crosses
   `< δ` (e.g. 1%) is noted but not blocking.
6. Decision:
   - Significant *and* magnitude beyond the benchmark's declared δ →
     merge blocked pending investigation.
   - Significant but below δ → tracked, not blocking.
   - Not significant → pass.

### 8.7 Baseline management

- Baselines rotate on every merged commit to `main` that passes perf CI,
  with a rolling 30-day record retained.
- Regression tests compare against the **previous green `main`**
  baseline, not a historical "golden" number. This avoids slow-cooking
  regressions but keeps per-PR tests actionable.
- Each release tags a "release baseline" archived permanently.
- **Cumulative regression check.** In addition to comparing against
  the previous green `main` baseline, every perf run also compares
  against the most recent **release** baseline. A finding of "not
  significant vs. main" but "significant and beyond declared δ vs.
  release" is flagged as a **slow-cooking regression** — non-blocking
  on the current PR but auto-opens an issue that must be
  investigated within one release cycle. Without this check, a 0.5%
  regression every PR drifts into a 20% release-over-release
  regression undetected, because each individual delta is below noise.

### 8.8 Performance result record

Each perf run emits a machine-readable record (JSON) including:

```json
{
  "benchmark": "ipc.narf_ring.round_trip_ns",
  "unit": "ns",
  "lower_is_better": true,
  "samples": [/* N values */],
  "n": 100,
  "median": 412.0,
  "mean": 418.3,
  "ci95": [415.1, 421.5],
  "p95": 439.0,
  "p99": 457.0,
  "cv": 0.021,
  "runner": "perf-runner-01",
  "commit": "abc1234",
  "baseline_commit": "def5678",
  "delta_pct": 1.4,
  "delta_ci95": [0.3, 2.6],
  "welch_p": 0.004,
  "mwu_p": 0.007,
  "decision": "pass-within-delta"
}
```

Records are archived for at least two release cycles.

## 9. Stress / soak tests

- Runs pre-release, on dedicated hardware.
- Minimum 24 h uninterrupted execution.
- Checks: no memory leaks (frame allocator accounting stable), no
  capability-table growth without bound, no latency tail drift (p99
  at hour 24 within 10% of hour 1).

## 10. Formal methods (opt-in)

- **Kani** (Rust bounded model checker) for targeted proofs:
  - Cap derivation preserves subset-of-rights invariant.
  - SPSC ring indices never let the consumer read an unpublished slot.
- Each Kani target is checked into `proofs/` and runs in a separate,
  non-blocking CI job; failures open issues, not block merges.

## 11. Architecture notes

Tests run on both primary arches. Per-arch differences are tagged
`#[cfg(target_arch = "...")]` in test source. Runners are labelled
and the record carries arch info so cross-arch perf deltas are
visible.

## 12. Dependencies

- **Consumes:** `build/` (runner orchestration, QEMU harness), `console/`
  (log sink), `process/` (merge-gate rules).
- **Provides to:** `process/` (definitions of "green"), every subsystem
  (testing conventions).

## 13. Stage assignment

- Stage 1: unit + functional harness + trivial functional tests.
- Stage 2: fuzz scaffolding, property tests for domain manager.
- Stage 3: full statistical-perf protocol, first perf gates on Narf-Ring.
- Stage 4: stress / soak suite, expanded fuzz targets, optional Kani
  proofs on cap-table core.

## 14. Open questions

- Benchmark runner HW: cloud instances (cheap, variable) vs. bare-metal
  boxes we rent (pricier, consistent).
- How to integrate perf records into PR comments without spam.
- When (if ever) to adopt a "frequentist + Bayesian" dual report on
  regressions — Bayesian credible intervals can be easier to reason
  about but adds machinery.
- Whether to publish perf records publicly (transparency win, attack
  surface for cherry-picking).
- Integration with `observability/` — verification consumes trace /
  perf-counter output from `observability/`, especially for performance
  benchmarks. Keep instrumentation definitions there; keep statistical
  analysis here.
