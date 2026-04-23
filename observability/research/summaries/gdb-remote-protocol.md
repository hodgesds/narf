# GDB Remote Serial Protocol

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

The GDB Remote Serial Protocol defines a request-response protocol for remote debugging over serial, TCP, or other transports. For NARF's observability subsystem, it provides a reference for debugger-kernel communication, allowing external tools (GDB, LLDB) to inspect kernel state without blocking forward progress.

## Mechanisms

**Packet Format:** The protocol uses ASCII packets (e.g., `$command#checksum`) for human readability and robustness. Each packet is acknowledged with `+` (success) or `-` (resend), enabling reliable delivery over noisy transports.

**Stop Reply Packets:** When the debugged target halts (breakpoint, fault), it sends a stop-reply packet indicating the reason (e.g., `S05` for SIGTRAP, signal 5). This allows debuggers to decide whether to halt all threads or resume.

**General Query Packets:** Debuggers request information via `q` packets (e.g., `qSymbol` for symbol lookup, `qThreadInfo` for thread list). Responses vary by query, allowing extensibility for domain-specific observability.

**Thread and Task Support:** The protocol defines thread-aware commands (`Hc`, `Hg`, `qThreadInfo`), enabling inspection of individual tasks in a multithreaded system. For NARF's multi-domain architecture, this maps naturally to per-domain task inspection.

**Register and Memory Access:** The `g` command reads all registers; `p` reads individual registers; `m` and `M` read/write memory. This enables post-mortem debugging (reading dumps) and live inspection.

## Key Invariants

**Statelessness:** The protocol is stateless; each packet contains complete context. The debugger must track state across multiple queries.

**Reliable Delivery:** Checksums and acknowledgments ensure packets reach their destination correctly, even over lossy transports (serial COM ports).

**Non-Blocking Observability:** The target can continue execution while the debugger processes responses, enabling asynchronous observation without stalling the kernel.

## Performance Trade-offs

**Latency:** Each register or memory read incurs round-trip latency (milliseconds on serial, microseconds on network). Batching queries reduces trips.

**Bandwidth:** ASCII encoding consumes ~2× the bytes of binary formats. For high-frequency sampling (breakpoint on memory writes), this can become a bottleneck.

**Intrusiveness:** Halting the target for inspection pauses all tasks. For real-time systems, this is a hard constraint; NARF should support non-stop debugging (continue one task while halting others).

## Observability-Specific Adoption

**Extend for Capabilities:** Standard GDB doesn't understand capabilities. NARF should define custom `q` packets (e.g., `qCapabilities` for capability token inspection) and custom stop-reply reasons (e.g., `C` for capability violation).

**Domain-Aware Breakpoints:** Breakpoints should be domain-scoped: a breakpoint might trigger only for domain D, not globally. This reduces noise in capability-driven systems.

**Async Executor Integration:** Define commands to inspect executor state: pending tasks, task queues, domain transitions. Standard GDB thread commands can be mapped to executor tasks.

**Postmortem Debugging:** Use memory dump support (`m` packets on a dump file) to enable offline analysis. NARF crash dumps should include task state, capability tables, and async queues.

## Pitfalls to Avoid

**Request-Response Mismatch with Async Kernel:** GDB's blocking request-response model assumes the target is halted. Async kernels may be executing other tasks while one is debugged. Support non-stop mode or clearly document halting semantics.

**Symbol Table Bloat:** Uncompressed DWARF debug info can be large. NARF should compress (e.g., with DWARF compression) or use split debug files for efficient transmission.

**Capability Leakage via Registers:** If capability tokens are stored in registers, GDB inspection could leak them to unprivileged debuggers. Use sealed capabilities or restrict register inspection based on debugger privilege.

## Reference
- GDB Remote Serial Protocol
- https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html
