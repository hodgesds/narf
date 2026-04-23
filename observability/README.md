# observability — Perf Counters, Debugger, Crash

State-inspection observability. Owns hardware performance counters,
GDB remote-serial stub, and the kernel crash / post-mortem flow.

Event-stream observability (USDT markers, dynamic probes, `FnTime`,
flight-recorder rings, tracer task) lives in [`../tracing/`](../tracing/).

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 1 (PMU basics + crash dump) → 4 (GDB stub + live peek).
