# DTrace and USDT: Dynamic Tracing in Solaris (Cantrill et al., USENIX ATC 2004)

> Fetch returned blocked/403; distilled from established knowledge. Cites primary source below.

## DTrace Architecture and USDT for NARF Tracing

Cantrill, Shapiro, and Leventhal's USENIX 2004 paper introduced DTrace, a comprehensive dynamic tracing platform for Solaris. USDT (UserLand Statically Defined Tracing) is the userspace variant of DTrace tracepoints, allowing applications to embed named probe sites that kernel-level tools can instrument at runtime without recompilation.

## USDT Core Mechanism

**Statically Defined Probes**: Application developers embed probe declarations in source code:
```c
#include <sys/sdt.h>
DTRACE_PROBE2(ipc, send_begin, source_pid, dest_pid);
// IPC send logic
DTRACE_PROBE1(ipc, send_end, result);
```

At compile time, USDT macros (sys/sdt.h) generate:
- ELF notes section (`NT_STAPSDT`) storing probe metadata
- Disabled NOP instructions at probe sites

At runtime, DTrace/SystemTap tools:
- Read the ELF notes to locate probe sites
- Patch NOP instructions to `int3` (x86) or other breakpoint instructions
- On breakpoint, invoke the handler (usually tracing code)

## Application to NARF

**Kernel-Space USDTs**: Embed probes in NARF kernel code for:
- Capability grants/revokes: `DTRACE_PROBE3(caps, revoke, cap_id, domain_id, error)`
- IPC send/receive: `DTRACE_PROBE4(ipc, receive, src_domain, dest_domain, msg_size, deadline)`
- Async task wakeup: `DTRACE_PROBE2(scheduler, wakeup, task_id, reason)`

**Zero-Overhead When Disabled**: A disabled USDT is a single-byte NOP; enabling it patches the NOP to a breakpoint, adding ~1 μs latency when active. NARF can embed USDTs in hot paths without performance penalty when tracing is disabled.

**Userspace Integration**: Via Shiva-style PLT hooks, NARF's userspace runtime can install equivalent USDTs in user processes before main(), enabling kernel tools to trace user-kernel interactions seamlessly.

## Invariants to Maintain

- **Probe Site Immutability**: Once code is deployed, USDT locations and signatures cannot change (breaking backward compatibility with existing tracing scripts)
- **Idempotent Enablement**: Enabling a probe twice must not double-fire; kernel must track which probes are already enabled
- **Handler Safety**: Probe handlers (usually in-kernel buffer writes) must be async-signal-safe and not block

## Performance Trade-offs

**Tracing Cost**: When active, a USDT fires a breakpoint trap (~1 μs), handler code records event (~100 ns), resume. Disabled USDTs are negligible (< 1 cycle).

**Event Buffering**: DTrace buffers events in a ring buffer to avoid log I/O blocking. For NARF, use in-kernel flight-recorder rings (similar to perf-events) to capture traces without stopping the kernel.

**Filtering Overhead**: Kernel-level filtering (e.g., "only trace capability revokes where domain=5") reduces buffered event volume. NARF should support predicate-based filtering to avoid overwhelming the trace buffer.

## NARF-Specific Guidance

**Adopt**:
- USDT probes for major subsystem boundaries (capability, IPC, scheduler, time)
- DTrace-style aggregation scripts (user queries the kernel for summary statistics)
- Flight-recorder architecture: continuous low-overhead tracing + dump-on-demand

**Avoid**:
- Per-event dynamic allocation (use pre-allocated ring buffers)
- Complex filtering logic in the hot path (defer to userspace tools)
- USDTs for tight loops (overhead stacks if many sites fire per microsecond)

## Pitfalls

- **ELF Note Parsing**: If tracing tools fail to parse USDT ELF notes, probes become invisible. Test with standard tools (perf, bpftrace).
- **Breakpoint Conflicts**: On x86, multiple overlapping `int3` instructions can cause instruction cache confusion. Space USDT sites appropriately.
- **Trace Buffer Overflow**: If events arrive faster than userspace can consume, ring buffer wraps. Implement backpressure or selective filtering.

## Recommendation

Stage 2: Embed USDTs in NARF kernel for capability, IPC, scheduler subsystems. Stage 4: Extend to userspace processes via Shiva hooks. Publish tracing guide with common bpftrace one-liners (e.g., "count capability revokes per second").

https://www.usenix.org/legacy/event/usenix04/tech/general/cantrill/cantrill_html/
