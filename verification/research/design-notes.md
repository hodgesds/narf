# verification — Design Notes

> 2026-04-22. Author: Claude Sonnet 4.6 (design-phase analysis).

---

## Load-bearing decisions

**The statistical protocol is the strongest subsystem spec in the repository — and it has one critical gap.** §8.6 requires both Welch's t-test and Mann-Whitney U to agree before a regression is declared. It requires Benjamini-Hochberg FDR correction across the suite. It mandates median + 95% bootstrap CI. This is rigorous. The gap: the protocol uses "previous green `main`" as the baseline (§8.7), which means a regression that is introduced across multiple commits, each individually below δ, can accumulate undetected until it totals a large regression. Linux's `lkp` infrastructure and the kernel CI community call this "slow-cooking." NARF needs a "cumulative regression" check: compare against the release baseline as a secondary check, not just the rolling green `main`.

**Noise control prerequisites are specified but not enforced by tooling.** §8.2 requires dedicated cores, no turbo, no SMT, no ASLR. These are correct. But the spec says "runs that fail the noise-control precondition are discarded, not averaged" without specifying *how* discarding is detected. Either the test harness actively enforces these (checks `/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor` and `/proc/sys/kernel/randomize_va_space` before running) or it trusts the runner configuration. Trusting configuration produces slow-cooking regressions via runner misconfiguration. The harness must actively verify and abort with a clear error, not assume.

**The formal methods plan (§10) is opt-in and non-blocking — this is too weak for TCB code.** seL4's verified TCB provides the gold standard: the capability derivation invariants and ring buffer safety properties are exactly the kind of bounded proof that Kani handles well. The spec says "failures open issues, not block merges." For TCB code (cap table, SPSC ring indices), a failing Kani proof should block the merge for TCB changes, not just open an issue. The current plan allows the TCB invariant to be broken without merge blockage, undermining the value of formal methods.

**The functional test `#[kernel_test]` macro is the right pattern, but the arch-specific skip mechanism is underspecified.** §6 says tests declare "required features (e.g. PKS, MTE). Skipped on archs without them." But a test that requires PKS and is skipped on aarch64 provides zero coverage of NARF's MTE isolation path. Domain isolation tests must have *both* a PKS variant and an MTE variant — skipping is acceptable only if a matching test exists for the other arch. The harness should enforce "if you skip on arch A, a test for the equivalent mechanism on arch A must exist."

**Fuzz targets are correct but missing the most dangerous attack surface.** §7 lists: cap-table slot decoder, Narf-Ring message parser, virtio descriptor validator, ELF loader. The most dangerous untested surface is the `tracing/` probe install path (`install_probe`) which accepts a virtual address and a `ProbeAction`. A maliciously constructed `ProbeAction::Chain` or a `FnAddr(0xdeadbeef)` could cause the patch-instruction path to write arbitrary code. `install_probe` must be a fuzz target before Stage 3 lands.

---

## Divergences from precedent

**seL4's full functional verification vs. NARF's Kani bounded model checking:** seL4 proves functional correctness of every line of the TCB in Isabelle/HOL, including memory safety and information-flow non-interference. Kani is bounded model checking — it exhausts a finite search space but does not prove unbounded properties. For NARF's cap derivation (a simple subset-monotone function over a finite capability set), Kani is probably sufficient. For the async executor's fairness or the RCU grace period correctness, Kani is likely intractable (unbounded execution paths). NARF must be explicit about what "formal methods" means in its context: Kani for finite TCB invariants, not full functional correctness. Claiming "proven invariants" without this qualification overstates the security guarantee.

**Creusot (deductive verification) vs. Kani (bounded model checking):** The spec lists both. Creusot requires manual proof annotations (pre/postconditions, loop invariants) but proves unbounded properties. Kani is fully automatic but bounded. These are complementary, not alternatives. The spec's §10 says "opt-in via Kani or Creusot" without guidance on when to use each. A clear policy: use Kani for "does this function panic?" and "are these indices always in range?" (bounded, automatic); use Creusot for "does this cap derivation always produce a subset?" (requires invariant annotation but proves the property for all inputs). The spec should state this distinction.

**Linux lkp/0day CI vs. NARF's statistical protocol:** Linux's lkp infrastructure runs thousands of benchmarks across hundreds of configurations and catches regressions via comparison. It does not use formal statistical protocols — it uses ad-hoc percentage thresholds. NARF's protocol is statistically sounder, but lkp's scale is orders of magnitude larger. NARF should plan to add benchmarks incrementally as subsystems land, not wait for a full benchmark suite. The CI must support partial suites with BH correction applied to whatever is present.

**Criterion.rs as the microbench framework:** The spec implicitly inherits Criterion's statistical approach. Criterion does Welch's t-test and bootstrap CI internally, which means the spec is proposing a *custom* implementation of the same protocol rather than using Criterion. This duplication is justified only if NARF's protocol needs features Criterion does not provide (e.g., in-kernel benchmarks via the `#[kernel_test]` path, or the BH correction across a suite). The spec should acknowledge this and note that for host-side benchmarks (pure Rust unit benchmarks), Criterion is the preferred runner with NARF's custom reporting layered on top.

---

## Proposed spec changes

- **§8.7 Baseline management — add cumulative regression check:** "In addition to comparing against the previous green `main` baseline, every perf run also compares against the most recent release baseline (tagged in git). A finding of 'not significant vs. `main`' but 'significant and beyond δ vs. release' is flagged as a slow-cooking regression and opens an issue. It is non-blocking on the current PR but must be investigated within one release cycle."

- **§8.2 Noise control — mandate harness-side precondition verification:** "The benchmark harness must actively verify all noise-control preconditions before a run begins, not rely on runner configuration alone. Verification checks: CPU governor is `performance`, turbo is disabled, SMT is off, ASLR is disabled. A failed check aborts the run with a structured error and does not produce a performance record."

- **§10 Formal methods — make TCB Kani proofs merge-blocking:** "Kani proofs targeting TCB code (capability derivation, SPSC ring index safety, domain-assignment invariants) must pass before merging TCB changes, per the TCB change class in `process/`. Kani failures on non-TCB proofs open issues. This distinction must be reflected in CI gate configuration."

- **§7 Fuzz targets — add probe install path as a required Stage 3 target:** "Add `install_probe(target, kind, action)` as a fuzz target at Stage 3. The fuzzer must cover: out-of-range `FnAddr`, deeply nested `ProbeAction::Chain`, and `ProbeAction::Snapshot` with an invalid `RecorderRef`. Crash = the probe install path must not produce undefined behavior or kernel panics without an explicit `Err` return."

- **§6 Functional tests — require paired arch coverage:** "A functional test that is skipped on architecture A due to a missing feature must have a companion test covering the equivalent mechanism on architecture A. CI must fail if a `#[skip_if_no(Feature::Pks)]` test exists without a corresponding `#[skip_if_no(Feature::Mte)]` test covering the same isolation semantics."

- **§3 Test taxonomy — add `no_std` enforcement to unit test gate:** "Unit tests in a `no_std` crate must compile and pass without `std` or `alloc` (unless the crate explicitly feature-gates `alloc`). The CI unit-test gate must run unit tests with `--no-default-features` for all `no_std` crates to catch accidental `std` pulls."

---

## Open invariants / cross-subsystem hazards

**`build/` §? (runner setup) ↔ `verification/` §8.2 (noise control):** The noise-control requirements depend on CI runner configuration that belongs to `build/`. The spec says "documented in `build/`" but this is a loose coupling. Until `build/` has a verified runner provisioning script that sets the required CPU governor/turbo/SMT flags and the verification harness checks them, the statistical protocol's validity guarantee is aspirational. This must be a hard dependency in Stage 3: `verification/` gates on `build/` providing a verified runner setup.

**`tracing/` §3.5 live aggregates ↔ `verification/` §8.6 regression detection:** The verification statistical protocol compares samples from two builds. If one build has FnTime live aggregates enabled and another does not, the benchmarks are measuring different things (with-aggregation vs. without). The perf gates must document which tracing configuration is active during benchmark runs, and `tracing/` must expose a "benchmarking mode" where aggregates are disabled or held quiescent during measurement windows.

**`observability/` §3.1 PMU readings ↔ `verification/` §8.1 benchmark unit:** Several perf benchmarks will report cycles via PMU counters (`observability::read(cycles_counter)`). But PMU counter access requires `Cap<Pmu, Read>`, and the benchmark environment (a `#[kernel_test]`) must have this cap. Who grants it? The test harness bootstrap process must grant `Cap<Pmu, Read>` to all kernel tests, or the PMU-based benchmarks will fail with a capability error rather than a measurement. This needs an explicit entry in `verification/` §6 (functional test setup) documenting what caps a kernel test has by default.

**`capabilities/` property tests ↔ `verification/` §5:** The §5 property tests list "capability derivation: derived rights are always a subset." But this property requires knowing the capability lattice structure — which rights compose and which are leaves. If `capabilities/` has not finalized its rights lattice before Stage 2 verification work begins, the property test cannot be written. There is a staging dependency: `capabilities/` §3 rights model must be stable before `verification/` §5 property tests can be implemented. This coupling is not documented in either spec.

---

## Additional opinionated commentary

The statistical protocol is genuinely excellent — median + bootstrap CI + BH correction is better than the practice of any major OS project I am aware of. The risk is that it is so rigorous it becomes a barrier to adding benchmarks. If every new benchmark requires 30–100 samples on a dedicated runner, and the dedicated runner is a single box or a limited cloud budget, the queue of "benchmarks pending initial baseline establishment" will grow indefinitely. Consider a "provisional benchmark" tier that runs on shared CI with weaker statistical guarantees (N=10, no noise control) to catch gross regressions early, graduating to the full protocol on the dedicated runner before release. This is explicitly how Linux's lkp works — quick checks on shared hardware, trusted numbers only from dedicated runners.

The Kani/Creusot opt-in status should be reconsidered for at least two proofs: the SPSC ring index non-wraparound proof and the capability rights subset proof. These are tractable, high-value, and would demonstrate that Rust-in-kernel code can be mechanically verified without full seL4-style investment. Making two specific proofs *mandatory* (merge-blocking for their respective TCB code) would signal to contributors that NARF takes formal verification seriously and provide a template for future proofs. Opt-in for all formal methods is a missed opportunity to establish a verification culture early.
