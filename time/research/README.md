# time — Research

## Primary sources

- **Intel SDM Vol. 3B — Chapter 17 (Debug, Branch Profile, **TSC**, Intel
  RDT)** — TSC invariance, `rdtsc` / `rdtscp` ordering, TSC-deadline.
  <https://www.intel.com/sdm>
- **Arm ARM — Generic Timer** (section D11 in DDI 0487).
  <https://developer.arm.com/documentation/ddi0487/latest/>
- **`CLOCK_MONOTONIC` / `CLOCK_REALTIME` in POSIX** — vocabulary
  source even though NARF's API is native-Rust.
- **RFC 5905 — NTPv4**. <https://datatracker.ietf.org/doc/html/rfc5905>
- **IEEE 1588-2019 — PTP**.
- **ITU-T TF.460-6 — UTC leap-second handling**.

## Secondary sources

- **Linux `kernel/time/` + `include/linux/clocksource.h` + clockevents**
  — canonical reference for the two-trait split NARF follows.
- **Paul McKenney, "Clocksources and timekeeping"** — LWN series.
  <https://lwn.net/Articles/388188/>
- **Ingo Molnar, "hrtimers" LWN write-up** — design rationale for
  high-res timers atop a coarse tick.
  <https://lwn.net/Articles/152436/>
- **Google, "Leap-Smear" (2011)** — industry precedent for smearing.
  <https://developers.google.com/time/smear>

## Distilled summaries

- [`summaries/clocksources-lwn.md`](./summaries/clocksources-lwn.md) —
  Kernel timekeeping architecture, clocksource abstraction, vsyscall paths.
- [`summaries/hrtimers-ingo.md`](./summaries/hrtimers-ingo.md) —
  High-resolution timers, RB-tree scheduling, interrupt coalescing.
- [`summaries/google-leap-smear.md`](./summaries/google-leap-smear.md) —
  Leap-second handling, UTC smear, monotonicity preservation.

## Fetched this round

### 2026-04-22
- clocksources-lwn.md (fallback)
- hrtimers-ingo.md (fallback)
- google-leap-smear.md (fetch successful)

## Open research questions

- Are there QEMU quirks (especially `-cpu host,-invtsc`) that will
  bite CI if we assume invariant TSC?
- Generic Timer frequency on embedded aarch64 boards varies widely —
  confirm `CNTFRQ_EL0` is reliable across our target platforms.
- Cost of `rdtscp` vs `rdtsc` + LFENCE on current silicon — decide
  the canonical read sequence for `now_monotonic()`.
