# ELF Core File Format

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

The ELF (Executable and Linkable Format) core file format captures the state of a process at a moment in time (typically after a crash). For NARF's observability subsystem, core dumps provide post-mortem analysis without live debugger access, enabling offline analysis of kernel failures.

## Mechanisms

**ELF Header:** A core file begins with an ELF header identifying the architecture (e.g., EM_X86_64 for x86-64, EM_AARCH64 for Arm64) and indicating it is a core dump (e_type = ET_CORE).

**Program Headers:** Core files use program headers to describe memory regions (PT_LOAD for mapped memory, PT_NOTE for notes). Each PT_LOAD entry specifies a virtual address and file offset, allowing reconstruction of the process's memory map.

**Notes Sections:** PT_NOTE program headers contain variable-length notes with metadata:
- **NT_PRSTATUS:** Process status (register values, signal information)
- **NT_PRPSINFO:** Process information (filename, command-line arguments)
- **NT_FILE:** Mapped file information (address, size, filename)
- **NT_AUXV:** Auxiliary vector (environment, random seed)

**Symbol Tables and DWARF:** If debug symbols are embedded, the core file can reference them (via the ELF section header table) for source-level debugging.

## Key Invariants

**Deterministic Layout:** Core files are platform-specific (e.g., x86-64 registers differ from Arm64). The architecture field determines interpretation.

**Memory Reconstruction:** PT_LOAD sections must be contiguous or explicitly mapped; gaps represent unmapped memory. Analysis tools use this to reconstruct virtual address space.

**Notes Ordering:** Standard notes (PRSTATUS, PRPSINFO) conventionally appear in a specific order. Custom notes are permitted and can extend observability.

## Performance Trade-offs

**Dump Size:** Full memory dumps can be large (gigabytes for systems with substantial heaps). Compression (gzip) or selective dumping (user-visible pages, not kernel pages) reduces size.

**Analysis Time:** Dumped cores can be analyzed offline, enabling quick return to production while diagnosis happens on separate machines.

**I/O Cost:** Generating a dump incurs significant I/O overhead (disk write, potentially slow on remote storage). NARF should make dumping asynchronous or optional.

## Observability-Specific Adoption

**Custom Notes for Capabilities:** NARF should extend the core format with PT_NOTE sections encoding:
- **NT_NARF_CAPS:** Capability table snapshot (token, holder, rights)
- **NT_NARF_DOMAINS:** Domain state (active domain, PKS/MTE settings)
- **NT_NARF_TASKS:** Async executor task queue

**Address Mapping:** Use NT_FILE to document page tables, enabling offline reconstruction of PKS domain isolation boundaries.

**Domain-Specific Registers:** For Arm MTE, include tag memory state (NT_ARM_TAGS) to aid buffer overflow analysis.

## Pitfalls to Avoid

**Incomplete Memory:** If the core dump is truncated or selective, analysis becomes speculative. NARF should ensure critical regions (capability tables, task state) are always included.

**Symbol Drift:** If the binary changes between dump generation and analysis, symbols may not match. Always store the build ID (GNU.build-id ELF section) in the dump.

**Capability Exposure:** If capabilities are represented as readable data structures in the dump, an attacker with dump access could forge capabilities. Use sealed structures or exclude sensitive capabilities.

**Temporal Inconsistency:** Async kernels may have inconsistent state in dumps (task partially migrated, capability being revoked). Add timestamps and generation numbers to aid reconstruction.

## Reference
- ELF Specification (System V ABI, Generic ABI)
- https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html
- Linux kernel: `fs/binfmt_elf.c` (reference implementation)
