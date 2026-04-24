# tracing — Events, Probes, Flight Recorders

Event-driven observability: static USDT markers, dynamic probes,
function-level timing, flight-recorder rings (snapshot-on-trigger),
and the in-domain tracer task that consumes all of this. Distinct
from `observability/` (perf counters + debugger + crash), which deals
with *state inspection*, not *event streams*.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: **Stage 2/3 landed (static markers + flight ring).**
  `probe!` macro emits a nop-sled marker + metadata record into
  `.note.narf.probes` (KEEP'd in both arches' linker scripts;
  `__narf_probes_start`/`_end` bound the section). `FlightRing<T, N>`
  is a per-slot-seqlock drop-oldest ring with const-asserted
  power-of-two capacity. Deferred to Stage 3+ / Stage 4: in-domain
  tracer task, dynamic probe arming (needs `arch/` instruction-patch
  primitive + `capabilities/` cap gate), `FnTime` + tDigest /
  Welford live aggregates, HW trace (Intel PT / CoreSight ETM).
