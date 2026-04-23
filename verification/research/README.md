# verification — Research

## Primary sources

### Formal methods
- **seL4 proofs repository** — gold standard of OS verification.
  <https://github.com/seL4/l4v>
- **Kani Rust Verifier book** — bounded model checking for Rust.
  <https://model-checking.github.io/kani/>
- **Creusot** — deductive verification of Rust.
  <https://github.com/creusot-rs/creusot>

### Fuzzing
- **`cargo-fuzz` book.** <https://rust-fuzz.github.io/book/>
- **`bolero`** — unified engine (libFuzzer/AFL/Honggfuzz/Kani).
  <https://github.com/camshaft/bolero>

### Property testing
- **`proptest`** — Hypothesis-for-Rust. <https://altsysrq.github.io/proptest-book/>
- **`arbtest`** — `no_std`-compatible property testing.

### Statistical methods (load-bearing)
- **Efron & Tibshirani, *An Introduction to the Bootstrap* (1993)** — bootstrap CI.
- **Benjamini & Hochberg (1995), "Controlling the False Discovery Rate"** —
  multiple-comparison correction we use for benchmark suites.
  <https://www.jstor.org/stable/2346101>
- **Welch (1947), "The generalization of 'Student's' problem when several
  different population variances are involved"** — Welch's t-test.
- **Mann & Whitney (1947), "On a Test of Whether one of Two Random
  Variables is Stochastically Larger than the Other"** — U test.
- **Criterion.rs documentation — "Analyzing Results"**. Criterion's
  approach to microbench statistics is NARF's closest precedent.
  <https://bheisler.github.io/criterion.rs/book/>

## Secondary sources

- **"Always Measure One Level Deeper" (Ousterhout, CACM 2018)** —
  methodology on not-drawing-false-conclusions.
  <https://cacm.acm.org/magazines/2018/7/229035-always-measure-one-level-deeper/>
- **"Producing wrong data without doing anything obviously wrong!"**
  (Mytkowicz et al., ASPLOS 2009) — why measurement bias is real.
  <https://users.cs.northwestern.edu/~robby/courses/322-2013-spring/mytkowicz-wrong-data.pdf>
- **`hdrhistogram-rs`** — HdrHistogram for wide-dynamic-range latency.
- **SPEC / TPC benchmarking methodology** — formal benchmarking discipline.
- **Linux `perf` and the "lkp" test infrastructure** — CI-scale perf.
- **Phil Oppermann "Testing"** — the kernel-in-QEMU harness pattern.
  <https://os.phil-opp.com/testing/>

## Distilled summaries

- [`summaries/bootstrap-ci.md`](./summaries/bootstrap-ci.md) —
  non-parametric confidence intervals; what we use for every perf number.
- [`summaries/multiple-comparisons.md`](./summaries/multiple-comparisons.md) —
  Benjamini-Hochberg, why we need it when running K benchmarks.
- [`summaries/seL4-formal-verification.md`](./summaries/seL4-formal-verification.md) —
  seL4 L4.verified, multi-layer refinement, capability integrity proofs.
- [`summaries/creusot-deductive-verification.md`](./summaries/creusot-deductive-verification.md) —
  Creusot deductive verifier for Rust, Why3 backend, async and MTE verification.

## Fetched this round

### 2026-04-22
- seL4-formal-verification.md (fetch successful)
- creusot-deductive-verification.md (fetch successful)

## Open research questions

- Which Kani targets have tractable proof budgets for our cap-table code.
- Calibration for CV threshold (5% vs. 10%) before flagging a benchmark as noisy.
- Are there benchmarks where Bayesian credible intervals would
  meaningfully outperform bootstrap CI for decision-making?
