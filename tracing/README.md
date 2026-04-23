# tracing — Events, Probes, Flight Recorders

Event-driven observability: static USDT markers, dynamic probes,
function-level timing, flight-recorder rings (snapshot-on-trigger),
and the in-domain tracer task that consumes all of this. Distinct
from `observability/` (perf counters + debugger + crash), which deals
with *state inspection*, not *event streams*.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 1 (static markers, basic ring) → 2 (tracer domain) → 3 (dynamic probes + FnTime) → 4 (HW trace, full aggregate sketches).
