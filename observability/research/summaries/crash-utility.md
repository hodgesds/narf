# Crash Utility: Post-Mortem Kernel Debugging

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

The crash utility is a post-mortem debugger for Linux kernel crash dumps (vmcore files). It is the gold standard for offline analysis of kernel failures, providing tools to inspect task state, memory, and kernel structures without a live kernel.

## Mechanisms

**Dump File Parsing:** Crash loads a vmcore (kernel dump) and an optional kernel image file. It parses ELF headers to locate kernel memory regions and symbol information.

**Symbol Resolution:** Using kernel symbols (from System.map or embedded in the kernel), crash maps virtual addresses to function names and variables, enabling source-level debugging.

**Macro Framework:** Crash allows users to write C-like code snippets (macros) that inspect kernel data structures at runtime on the dump. For example, to list all task structs, a macro would walk the kernel's task list data structure.

**Output Formatting:** Crash provides commands to format kernel structures (e.g., `ps` lists processes, `struct task_struct <address>` displays a task structure). This makes kernel analysis accessible without manual pointer dereferencing.

## Key Invariants

**Read-Only Access:** Crash cannot modify kernel memory; it only reads dumps. This ensures analysis safety but limits to post-mortem inspection.

**Deterministic Structure Interpretation:** Kernel structures (task_struct, mm_struct, etc.) are well-defined by the kernel version. Crash must know the exact layout to parse dumps correctly.

**Symbol Availability:** Without symbols, crash can only work with raw addresses. A release kernel with symbol files is necessary for meaningful analysis.

## Performance Trade-offs

**Analysis Latency:** Offline analysis on a different machine allows the production kernel to restart quickly. Analysis time is decoupled from production impact.

**Dump Size:** Uncompressed kernel dumps are gigabytes. Compression or selective dumping (kernel memory only, not user pages) reduces size.

**Tool Maturity:** Crash is Linux-specific and mature. Porting to NARF requires custom macros and understanding of NARF's internal structure.

## Observability-Specific Adoption

**NARF Macros:** Write crash-like macros for NARF-specific structures:
- **`domains`** — list all domains, their PKS/MTE settings, and assigned pages
- **`tasks`** — list async executor tasks, their state, and blocked-on resources
- **`capabilities`** — display capability table, including token, holder, and rights
- **`ipc-log`** — walk IPC history (if logged) to understand communication patterns

**Dump Generation:** Integrate dump generation into NARF's fault handler. On a fatal fault, halt all domains, capture state, and write to a safe location (disk, network).

**Postmortem Workflow:** After a crash, transfer the dump to an analysis machine, run NARF-specific macros, and generate a report. This decouples analysis from production recovery.

## Pitfalls to Avoid

**Stale Symbols:** If the kernel image changes between dump generation and analysis, symbols may not match. Crash will refuse to analyze; always archive the kernel image with the dump.

**Incomplete Information:** If critical data structures are corrupted or unmapped, analysis becomes speculative. Validate dump integrity before analysis.

**Custom Data Structures:** Crash doesn't know about NARF-specific structures (capabilities, domains, async tasks). Custom macros must be written; this requires maintenance as NARF evolves.

**Capability Confidentiality:** If capabilities are readable data in dumps, they can be forged offline. Consider encrypting capability tables or storing only tokens (indices), not the underlying rights.

## Reference
- Crash Utility
- https://crash-utility.github.io/
- Linux kernel source: `kernel/crash_dump.c`, `fs/proc/kcore.c`
