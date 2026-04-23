# Humility: Capability-Microkernel Debugger

## Overview

Humility is a specialized debugger for Hubris, a capability-based microkernel written in Rust. It exemplifies observability-first design for real-time embedded systems, providing a reference implementation for NARF's observability requirements.

## Core Observability Mechanisms

**Production-Grade Tradeoffs:** Humility operates exclusively on optimized release builds, extracting insight via unloaded DWARF debug symbols rather than instrumentation. This preserves the kernel's actual performance envelope—critical for timing-sensitive systems.

**Domain-Specific Visibility:** Rather than generic debugging, Humility encodes Hubris concepts—tasks, IPC boundaries, memory regions, capability grants—as first-class observability primitives. Commands like `tasks` reveal task state and generation counts; `map` correlates fault addresses to task memory regions.

**Multi-Channel Access:** The debugger supports probes (USB, OpenOCD, JLink), network interfaces (IPv6 management), postmortem dumps, and archive-only analysis. This flexibility accommodates development workflows without disrupting production.

## Key Invariants for Observability

**Memory Safety Under Inspection:** Task isolation enforces that debugger reads cannot leak cross-task state. The memory map maintains per-task boundaries; reads respect capability domains.

**Non-Intrusive Fault Capture:** The supervisor (Jefe) records faults without stopping the kernel. Humility can inspect halted state or read dumps asynchronously, decoupling diagnosis from system timing.

**Deterministic Symbol Resolution:** DWARF information maps binary addresses to source locations. Ring buffers capture task counters and IPC traffic patterns at kernel boundaries.

## Performance Trade-offs

**Zero Runtime Cost When Detached:** Hubris adds no debug hooks when Humility isn't attached. The kernel's execution is unmodified; observability is purely external.

**Selective Halting:** Commands requiring kernel pause (register reads, memory dumps) halt execution briefly; read-only operations (archive inspection, symbol lookup) run offline.

**IPC Instrumentation:** Idol-generated IPC adapters can emit counter data showing call frequency and error rates per client task, revealing communication bottlenecks without altering message latency.

## Observability-Specific Adoption Patterns

**Postmortem-First Debugging:** Dumps preserve system state for analysis on different machines, enabling distributed debugging and artifact retention.

**Environment Files:** Multi-target setups define probe mappings and auxiliary commands per device, supporting fleet observability.

**Layered Introspection:** Start with high-level summaries (`tasks`, `map`, `probe`) before drilling into low-level state (register contents, memory regions).

**Async Task Introspection:** NARF should expose executor state (pending tasks, blocked resources, domain transitions) via custom Humility-like commands.

## Pitfalls to Avoid

**Symbol Drift:** Mismatched DWARF metadata and binary can produce nonsensical address mappings. Always pair archives with their exact builds.

**Probe Conflicts:** Direct attachment prevents concurrent debugger use. Prefer network or dump-based debugging for non-invasive observation.

**Memory Region Assumptions:** Device memory addresses don't map across architectures; commands must target correct variants (x86-64, aarch64).

**Capability Leakage:** Unguarded inspection of capability tables in dumps could expose tokens. Use sealed structures or restrict inspection scope.

## Conclusion

Humility demonstrates that observability in capability microkernels requires encoding domain semantics—tasks, capability grants, IPC patterns—rather than generic register inspection. By shifting all debuggability work to external tools, Hubris achieves production-grade performance while maintaining rich introspection paths. NARF should adopt this observability-first design.

## Reference
- Humility Debugger (Hubris)
- https://github.com/oxidecomputer/humility
