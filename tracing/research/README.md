# tracing — Research

## Primary sources

### USDT lineage
- **DTrace — Dynamic Tracing in the Solaris Operating System**
  (Cantrill, Shapiro, Leventhal; USENIX ATC 2004).
  <https://www.usenix.org/legacy/event/usenix04/tech/general/cantrill/cantrill_html/>
- **`sys/sdt.h`** (SystemTap / DTrace-compatible USDT macros).
  <https://sourceware.org/systemtap/>
- **Linux tracepoints**.
  <https://docs.kernel.org/trace/tracepoints.html>
- **Linux uprobes + uretprobes**.
  <https://docs.kernel.org/trace/uprobetracer.html>

### Dynamic probe mechanisms
- **KProbes / optimised KProbes (Linux)**.
  <https://docs.kernel.org/trace/kprobes.html>
- **ftrace function_graph tracer** — per-function entry/return timing
  via `-pg` mcount preamble. Precedent for `FnTime`.
  <https://docs.kernel.org/trace/ftrace.html>
- **Intel text_poke_bp protocol** — safe cross-modifying code.
  <https://lwn.net/Articles/753064/>

### HW trace
- **Intel Processor Trace (PT)** — SDM Vol. 3C §33.
- **ARM CoreSight ETM** — ETMv4 Architecture Specification (IHI 0064).
- **ARM PMU v3** — part of Arm ARM.

### Flight recorder / snapshot tracing
- **Java Flight Recorder (JFR)** — low-overhead continuous event
  capture with dump-on-demand; mature precedent for the flight-recorder
  model NARF adopts.
  <https://docs.oracle.com/en/java/javase/21/jfapi/>
- **DTrace speculative tracing** — `speculate()` / `commit()` /
  `discard()` — keeps event streams available but conditional.
- **Linux ftrace snapshot buffer** — `echo 1 > /sys/kernel/tracing/snapshot`.

### Statistical sketches
- **Welford (1962), "Note on a method for calculating corrected sums
  of squares and products"** — online numerically-stable mean/variance.
- **Dunning & Ertl, "Computing Extremely Accurate Quantiles Using
  t-Digests" (2019)**.
  <https://arxiv.org/abs/1902.04023>
- **HdrHistogram** — wide-dynamic-range histogram alternative.
  <http://hdrhistogram.org/>
- **KLL sketch — Karnin, Lang, Liberty (2016)** — another quantile
  sketch; worth comparing.

### Capability-aware tracing precedent
- **Shiva — Programmable Runtime Linker (elfmaster/shiva)** — userland
  PLT-hook arming mechanism. Direct precedent for how we arm
  USDTs in userspace processes from `userspace/`.
  <https://github.com/elfmaster/shiva>

## Secondary sources

- **Brendan Gregg, *Systems Performance* and *BPF Performance Tools***
  — the canonical catalogue of questions a tracing layer should answer.
- **`uftrace`** — userspace function tracer with call-graph timing.
  <https://github.com/namhyung/uftrace>
- **`bpftrace`** — DTrace-shaped frontend; taxonomy of useful one-liners.
- **Intel VTune** — reference for function-level counter attribution.
- **coz / "Coz: Finding Code that Counts with Causal Profiling"**
  (Curtsinger & Berger, SOSP 2015) — future `CausalDelay` probe action.

## Distilled summaries

- [`summaries/usdt-and-dynamic-tracing.md`](./summaries/usdt-and-dynamic-tracing.md)
  — USDT ELF-note layout, arming protocol, USDT vs. dynamic probe
  comparison.
- [`summaries/dtrace-usdt-history.md`](./summaries/dtrace-usdt-history.md) —
  DTrace architecture, USDT statically-defined probes, flight-recorder design.

## Fetched this round

### 2026-04-22
- dtrace-usdt-history.md (fallback)

## Open research questions

- tDigest vs. HdrHistogram vs. KLL on NARF's latency shapes.
- Memory / CPU budget for maintaining live sketches on the hot path.
- Safe declarative aggregation (histogram-by-arg-value) without
  introducing a probe-site VM.
- Cross-modifying-code batching strategy — arm/disarm N markers in a
  single stop-the-world.
- Userspace Stage 4 USDT arming via Shiva-style PLT hook vs. direct
  `text_poke`-equivalent in the process's address space.
