# bpf/bench — BPF Benchmark Sampling Harness

`narf-bpf-bench` is the in-kernel sampling half of NARF's performance
measurement protocol. The verification spec splits a performance number into
two jobs — collecting samples under stated conditions, and deciding what the
samples mean — and this crate does only the first. It declares benchmarks,
collects raw samples inside the kernel under controlled conditions, and emits
every raw sample to the console; the statistics (median, bootstrap confidence
intervals, Welch's t-test, Mann-Whitney U, and multiple-comparison correction)
are computed host-side by the `cargo xtask bpf-bench` tooling that consumes the
emitted lines.

That division is deliberate rather than squeamishness about floating point in
the kernel. The protocol forbids silent trimming and archives the whole sample
vector, so the samples must leave the kernel regardless; once they have, the
heavy resampling belongs somewhere with a heap, a debugger, and unit tests
rather than in an initcall.

## This is not a test

Benchmarks are intentionally not registered through the kernel test framework.
A test answers pass or fail, and a benchmark reduced to pass/fail has already
discarded the number that is its whole point. Nothing in this harness can fail
a build; the suite runs only when the kernel command line asks for it, and a
case that cannot run reports a skip with a reason rather than contributing a
misleading zero.

## What the harness controls, and what it cannot

The harness guarantees the measurement properties it actually owns: warmup
iterations are discarded, each sample brackets a batch of measured inner
iterations so that the timing reads amortize away instead of dominating,
samples are collected round-robin across the whole suite so that any drift over
a run lands on every benchmark equally and keeps an A/B comparison genuinely
paired, and interrupts are masked for exactly the duration of each individual
sample and no longer. It also records per-sample how much work each sample
covered, so that if two samples of the same benchmark disagree about their work
units the discrepancy is flagged rather than silently averaged into fiction.

The preconditions it cannot control — CPU frequency governor, turbo, SMT,
address-space randomization, thermal state — are properties of the machine
outside the kernel. The harness emits what it can observe about the
environment and leaves the host side to refuse to call a run publishable until
it has verified the rest.

## Output and relationships

Output is a line-oriented stream of key-value records — an environment line, a
record and its sample chunks per benchmark, and an end line — rather than JSON,
because the in-kernel emitter is plain formatting and the host parser is a
simple tokenizer; the structured record is assembled host-side where the
statistics live. The crate is intentionally independent of `narf-bpf`: the
benchmark cases themselves live in `narf-bpf` behind its own `bench` feature
and depend on this harness, so pointing the dependency this way keeps the
harness free of a cycle and reusable by any other subsystem that wants
protocol-shaped samples.

## no_std

The crate is `no_std` and uses the kernel allocator for its sample buffers; its
only dependencies are core NARF library, time, console, init, and boot crates —
notably not `narf-bpf`.
