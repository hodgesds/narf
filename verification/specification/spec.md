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
- `cargo xtask test --subsystem NAME` selects that registered subsystem and
  its `/`-delimited children; comma-separated names select their union.
  PR and push CI select all tests owned by changed crates and their reverse
  dependents. Equivalent prefixes compact large inventories without widening
  the selected set. Nightly/manual runs and conservative fallback cases retain
  the unfiltered suite; `ci-full` explicitly requests it for a PR.
- `cargo xtask test --exclude-subsystem NAME` removes that subtree from
  whatever the include filter (or the full suite) selects, with the same
  prefix matching; the two filters compose. The primary CI invocation always
  excludes `drivers/gpu`, which runs in a dedicated job gated on the affected
  plan's `run_gpu_tests` output — the union of the two jobs is the full
  suite, and a GPU-fixture hang (issue #879) costs only the GPU job's cap.
- `cargo xtask test --kernel-tests-only` is restricted to secondary CI
  configuration shards after that architecture's primary invocation has run
  the production boot and host interoperability postflight. It does not
  replace the complete merge gate.
- `console/` provides a deterministic log sink we can parse.
- CI runners have dedicated (not shared) cores, with frequency scaling
  and turbo disabled for perf jobs.

## 3. Test taxonomy

Wi-Fi and GPU implementations and maintained validation execute native Rust.
They do not extract Linux/Mesa C functions, compile C shims, slice Rust source
into temporary adapters, or invoke Python/compiler wrappers for comparisons.
Fixed source-cited reference vectors and required hardware tables remain reviewed
data. Native tests exercise production APIs with literal wire cases, property
and boundary checks, register/transport models, failure/cancellation and ownership
invariants. Expected results must not be regenerated from the implementation
under test. Historical fixture provenance identifies sources; it is not an active
source-equivalence proof. Real hardware and external userspace interoperability
remain separate acceptance work.

The affected-plan outputs and full-run fallback rules are specified in
`build/specification/spec.md` §3. Secondary large-memory, xAPIC, virtio-mmio,
and user-mode configurations run when their inputs are affected or the plan
requires full coverage; the GPU group runs as its own job under the same
rule. The primary selected run still performs the normal
production boot and host interoperability postflight.

Wi-Fi conversation fixtures share the no_std `narf-wifi-fixtures` kit in
`verification/wifi-fixtures`. Its `FakeAp` exchanges legacy 2.4-GHz Open or
WPA2-PSK/CCMP authentication, association and EAPOL frames; phase, peer,
fragment, replay and MIC checks gate authorization. `DhcpServer` provides an
initial lease only after a MAC- and transaction-correlated DISCOVER/REQUEST,
checking Ethernet/IPv4/UDP framing and control options. `NetworkPlan` defines
the expected address, mask, gateway, DNS and duration; `udp_ipv4` builds test
data. `FakeAp::with_basic_1mbps()` selects a checked CCK basic-rate profile
before authentication for RTL8188EU; the default OFDM profile is unchanged.
The kit has no device, driver-registration or carrier authority.
Driver adapters retain native RX/TX framing, completions and controlled-port
admission. MT76 and ath11k compose production station/security paths through a
lease and exact bidirectional Ethernet data; ath11k retains its x86_64 native
ring fixture. Intel Sc c103 composes its post-INIT Device/Connection through
native TFH/RFH command/data queues, the shared AP and kernel DHCP. Its model
does not replace the separate firmware-boot/PCI/MSI checks or admit other Intel
command tables. RTL8188EU composes channel1/20-MHz/basic1Mbps native USB,
Station/Service, RSNA and software CCMP through the same AP and DHCP client.
CYW SDPCM/BDC and BCM43602 CR4/msgbuf shared5/6 with zero descriptor prefix
compose the common FullMAC station and DHCP path. Their WPA2 proof is
firmware-offloaded key completion, including both association/key-event orders
for PCIe; it does not simulate firmware-internal cryptography.

These conversations check carrier and IPv4 binding retirement, controlled-port
closure before the terminal M4/key receipt, stale authorization, disconnect
failure and retained DMA after ambiguous completion. Test-only policy,
qualification, firmware and board inputs cannot authorize a real device.
The shared signed-policy bootstrap additionally uses a real isolated firmware
registry entry and current capability invocation, with missing/unsigned/invalid
asset, revocation, cache and concurrent caller-policy checks. These
kernel-dependent types are not a host test executable, and none of these
checks establish RF or real firmware/silicon acceptance.

The retained host WPA2/CCMP key and terminal-reply suites live with shared
`wireless::{packet_key, station_security}`; RTL8188EU adapters preserve their
raw-profile admission before those owners. Ath10k's RAW/non-PFC legacy model
composes native management/HTT, the shared security owner and exact
bidirectional Ethernet/IP across six WMI dialects. Its firmware model consumes
actual retained referenced-management DMA, including bytes beyond the64-byte
TLV command prefetch. Its retained Device now additionally drives synchronous
CE/HTC/HTT progress and the real kernel DHCP client for Open/WPA2 across all
six dialects, including early EAPOL, withheld receipts, occupied bounce slots,
policy restriction and close/publication interleavings. Separate EU, CYW and
Intel regressions exercise old-link publication while actual disconnect waits
for device state ownership, checking terminal closure before a repair poll.
Intel also exercises actual socket-owner release through the spawned
auto-disconnect worker while the native M4 receipt holds state ownership;
the worker waits for that owner and then tears down instead of losing Busy.
AR9285 and RTL8188EE now compose their exact retained packet owners, shared
MLME/RSNA/CCMP and public Device through the real kernel DHCP client and exact
bidirectional IP. Their fixtures consume actual published DMA and generate
native RX descriptors. They check held/modified/cancelled M4 bytes and terminal
receipts, consumed error frames versus genuine RX-idle fences, entropy and peer
deadlines, live policy, concurrent publication/close and storage retention.
EE additionally checks actual CAM/mailbox and reserved-beacon prerequisites,
including cancellation while an async operation owns the driver. The shared
raw BSS observer checks bounded original RSN/RSNX/rate/channel/peer facts before
driver-specific profile admission; it grants no radio or transmit authority.
AR9285 channel/calibration, RTL8188EE radio/channel/power and RTW89 PCI basic,
cold/factory and TX-only download owners compare native register/delay or
numeric results with fixed Rust reference vectors and explicit invariants.
AR9285 includes 32 calibration traces and 35 signed/wrapping IQ vectors;
RTL8188EE checks its actual ring-register map independently of the generic
8192EE scaffolds. Native packet/stop models check ownership, width and current
authority. AR9285 retains 72 fixed TX descriptor vectors, ten RX-status vectors and
ten complete MAC traces. RTL8822CE factory/OTP/feature/MAC/PHY-table and signed
board-power checks cover actual retained continuations; RTL8852B checks
post-WCPU MAC, 36-bit RXBD/RPQ/C2H, RF-v1 and conditional table selection.
These software checks cannot establish RF readiness.

RTL8822CE now composes that retained firmware/factory/radio owner through
source station mailbox control, native raw packet DMA and CCX receipts into
the same public Device and actual kernel DHCP client. Open/WPA2 fixtures
consume published DMA and verify exact bidirectional IP. Held, altered and
cancelled M4, queued peer loss, current policy and actual calibration-epoch
revocation between descriptor write and doorbell close the controlled port.
Fixed Rust reference vectors check TXD/BD/RXD/CCX, calibration, non-QoS DCF
and mailbox fields alongside actual DMA/receipt and ownership assertions.

Signed FullMAC board-selection fixtures bind exact PCI/SDIO host/card facts
and actual asset SHA256 before CR4/CM3 upload, then compose the selected
native owner through DHCP/IP. Missing or revoked assets leave pre-attempt
owners retryable; malformed executable extents fail before hardware admission.
Separate retained-startup regressions cover Intel firmware staged after
detection and RTL8188EU/EE asset retry on the same owner. Current firmware
copies and native PCI/MMIO operations execute inside actual capability
invocation, with revocation tests at the operation boundary. Physical carrier
updates preserve operator IFF_UP and cannot invoke administrative hooks under
driver locks. Whole rekey deadlines are tracked independently of pending
reply/port state, including the old-key-open wait between M2 and M3.

RTL8852B adds the exact source controller and fresh native packet core through
the public Device and actual kernel DHCP for Open/WPA2, exact bidirectional IP,
held/altered/cancelled M4, queued peer loss and terminal disconnect/rekey cases.
This controller/packet fixture cannot create a production full-radio grant.
Native Rust RF models exercise the actual retained
channel/BB/trim/RXDCK/IQK/TSSI/DPK/power owners on the same register backing;
faults, current epoch loss and cancelled real PMAC waits cannot publish Ready.
Actual PHY-capability mailbox replies, source awake status, measured v2 peaks
and publication inside current device plus signed-record invocations remain
independent prerequisites. The temporal FLR suite verifies the full quiet
interval, restore/readbacks and cancellation without config access; a retained
probe test rejects replacement or re-parking during reset ownership. Software
evidence does not establish real firmware instruction execution or RF acceptance.

`narf_wifi_fixtures::firmware::metadata_replay(image_len, fragments)` builds
parser-only structural images up to 16 MiB. It validates nonempty, ordered,
nonoverlapping fragment extents before allocation and zeroes every opaque gap.
The native Rust `cargo xtask wifi-fixtures` tool reads explicit SHA256-pinned
vendor blobs and retains structural headers/TLV geometry, version/API facts,
section addresses and board-name metadata. Its host parsers are independent of
production driver parsers and do not harvest or compile reference source.
`check` verifies existing data; `write` reproduces it without silently updating
source pins; `extract` requires an explicit format, input, name, hash and new
output directory. Kernel smokes feed these images only
to parsers, never a firmware registry, board-calibration authority or hardware
loader. Passing proves layout handling; signatures, instructions and RF/board
acceptance require original authenticated assets and physical validation.

| Category        | Runs on       | Who gates | What it protects against                     |
| --------------- | ------------- | --------- | -------------------------------------------- |
| Unit            | host          | every PR  | pure-logic regressions in a single module    |
| Property        | host          | every PR  | algebraic invariants (e.g. cap derivation ⊆) |
| Functional      | QEMU          | every PR  | "does the whole kernel still work?"          |
| Fuzz            | host          | nightly   | parser / state-machine robustness             |
| Performance     | dedicated HW  | perf-sensitive PRs + nightly | throughput / latency regressions |
| Stress / soak   | dedicated HW  | pre-release | leaks, drift, long-running correctness      |
| Formal (opt-in) | host          | when claimed | proven invariants on small TCB cores      |

Release-readiness automation is review-producing rather than self-releasing.
The monthly crate-version workflow is dormant until the repository variable
`NARF_MONTHLY_CRATE_BUMPS=true` is set. It selects only explicitly
release-managed crates changed since their per-crate publication tags,
package-checks the resulting archives, and opens a pull request. Manual runs
may select independent patch or exact versions at any time. Neither path has a
crates.io token or a publication step. The job explicitly dispatches the
ordinary CI workflow on the created branch because GitHub suppresses recursive
pull-request events from its own workflow token.

The weekly distribution-readiness workflow is likewise dormant until
`NARF_DISTRO_READINESS=true` (manual dispatch remains available). It builds
both package architectures across Debian, Ubuntu, Fedora, Arch, and Gentoo;
native x86_64 packages must survive install/query/remove in disposable
containers, while cross-architecture and Gentoo artifacts receive structural
validation. It uploads only short-lived CI artifacts and never creates a
release.

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
- Functional CI sets `XTASK_QEMU_SERIAL_TEE=1`: kernel-test and boot-smoke
  serial is flushed into the live job log while the same captured bytes remain
  authoritative for marker parsing, summaries, and bounded failure tails.
- Driver-specific live acceptance can add a host harness to this boot. The
  x86_64 `e1000-module-net-smoke` gate requires pre-probe initramfs loading in
  an operator-selected driver frame, exclusive ownership of QEMU's 82540EM,
  and successful off-box TCP, UDP, and DNS traffic through the resulting
  module datapath. Synthetic descriptor injection is not sufficient for this
  gate.
- Native UEFI package acceptance boots the installed x86_64 layout through
  OVMF, GRUB, config-bound Limine, and the packaged kernel, and boots the
  aarch64 layout through AAVMF and NARF's digest-bound loader. Secure Boot
  acceptance uses an ephemeral enrolled OVMF certificate and a signed loader.
  Both integrity chains include a negative boot in which one kernel byte is
  changed and the NARF clean-exit marker must remain unreachable.
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

The `verification/pipe-abi` subsystem (`user-mode-e2e` feature) executes the
standalone `userspace/pipe-test` Linux syscall fixture in a real user process
on both architectures. Its completion marker distinguishes success from an
early exit or fault. The same source runs on Linux as a differential oracle;
coverage, reference revision and design invariants are recorded in
[`pipe-linux-parity.md`](../pipe-linux-parity.md).

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
