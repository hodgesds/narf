# time — Timekeeping

Monotonic and wall clocks, high-resolution timers, clocksource /
clockevent abstractions, NTP/PTP hooks (Stage 4+). Every other
subsystem assumes this one works — scheduler deadlines, tracing
timestamps, perf CI measurements, and crypto nonce epochs all come
from here.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 1 (monotonic + basic timer wheel) → 2 (hrtimers, SMP sync) → 4 (NTP/PTP).
