# verification — Specification

> Status: **v1.0** (Stage 4 design lock). v0.2 added the
> statistical regression protocol; v1.0 locks the
> benchmark-runner hardware policy, the perf-record publication
> stance, the PR-comment integration, and ABI versioning for
> the harness consumers.

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
- `cargo xtask test --subsystem NAME` selects one exact registered subsystem
  for fast local iteration; the unfiltered command remains the merge gate.
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
- `user-mode-e2e` enables filesystem-independent, instruction-embedded user
  tests, including the AArch64 two-task EL0 timer-preemption and TLS/FP-state
  isolation smoke. `firmware-allow-unsigned` independently mirrors the
  firmware crate's bring-up policy for tests that need unsigned blobs.
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
- The xtask benchmark runner accepts the previous green-main record through
  `--baseline` and the release record through `--release-baseline`. It refuses
  cross-runner, cross-architecture, accelerator, unit, direction, iteration,
  warmup, or work-declaration mismatches instead of treating unlike sample
  vectors as comparable. A comparison is publishable only when both records
  passed the §8.2 precondition gate and both source trees were clean. Schema 1
  records predate clean-tree provenance and are therefore accepted only as
  advisory baselines.

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

The current xtask JSON format is schema 3. It retains every raw sample and the
benchmark's declared delta, and records main/release comparisons separately
with both commit IDs, corrected significance decisions, direction-aware
improvement/regression labels, and a `publishable` bit. The reader accepts
schema 1 and 2 records as advisory baselines so rotation does not invalidate
historical archives, but treats their missing source-tree or guest timing
provenance conservatively. Schema 3 records include a `dirty` bit, the guest
`irq_masked` and `tick_reliable` gates, and each benchmark's declared target N;
dirty candidates or baselines cannot produce a publishable comparison.

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

## 14. Resolved decisions

### 14.1 Benchmark runner hardware (resolved)

**Decision:** **bare-metal rented boxes for perf-critical
benchmarks; cloud instances for functional CI**.

Two CI tiers:

- **Functional CI** (every PR): GitHub-hosted runners under
  KVM. Runs `cargo xtask test` on x86_64 + aarch64, all
  smokes, basic correctness. Variable hardware OK because
  results are pass/fail.
- **Perf CI** (nightly + on `perf-test` PR label): rented
  bare-metal (one Cascade Lake, one Ampere Altra, one
  Sapphire Rapids). Runs the perf benchmark suite under the
  statistical protocol; outputs comparison vs. last release.

Bare-metal rental is ~$200/month per box at v1.0 vendors;
the budget is committed.

### 14.2 Perf record publication (resolved)

**Decision:** **publish perf records publicly under
`reports.narf.dev` (or analogue)**. Each release tag and each
nightly emits a signed JSON-Lines file with: timestamp, git
sha, hardware ID, benchmark name, p50/p95/p99 latency,
throughput.

Signing per `crypto/spec` §9 (kernel CA). Publication is
write-once; historical records are immutable.

The cherry-picking risk (an attacker exploits a transient
regression to scare users) is mitigated by:
- Statistical protocol (§v0.2) requires significance, not
  single-data-point regressions.
- Public records show the trend over time.
- Each record is reproducible (we publish the test command).

Net: transparency wins.

### 14.3 PR-comment integration (resolved)

**Decision:** **inline summary comment on PRs that touch
performance-sensitive code paths**, with a "show details"
link to the full perf-CI run.

Heuristic for "performance-sensitive": touches files under
`scheduler/`, `interrupts/`, `arch/`, `ipc/`, `io/`, or any
driver's hot path. CI computes the touched-files set and
gates whether to run perf-CI.

Comments are minimal:
- Headline change in p99 latency for relevant benchmarks.
- "No statistically significant regression" when applicable.
- Link to full report.

No spam: PRs not touching perf-sensitive paths get no perf
comment.

### 14.4 Frequentist + Bayesian (resolved)

**Decision:** **frequentist only at v1.0**, with Bayesian as
a possible v1.x addition.

Frequentist (current v0.2 protocol): Welch's t-test +
Bonferroni for the multiple-benchmark family. Fast,
well-understood, supports CI gates with clear false-positive
rates.

Bayesian credible intervals would be useful for long-term
trend analysis but require more careful prior selection per
benchmark. Defer until we have enough historical data to
parameterise the priors.

### 14.5 `observability/` integration (resolved)

**Decision:** **verification consumes `tracing/` events for
performance attribution, but the statistical analysis stays
here**.

The `tracing/` ring during a benchmark captures per-event
timing breakdowns. `verification/`'s perf harness reads the
ring at the end of the run, attributes time to subsystems,
and includes the breakdown in the PR comment ("regression
spent 80% in `narf-bus::probe_all_pci`").

This makes perf regressions actionable: not just "slower"
but "slower in this code path."

## 15. ABI versioning

`verification/`'s `kernel_test!` macro and `Cap<TestHarness, _>`
are exported at `@v0` for in-tree test consumers. Out-of-tree
verification consumers (e.g. CI scripts that consume
`reports.narf.dev`) follow the JSON-Lines schema, frozen at
v1.0.

`VERIFICATION_ABI_MAJOR = 1`.

## 16. Open questions

(none — all v0.2 questions resolved in §14)
