# Intel® 64 and IA-32 Architectures SDM — PKS and Domain Isolation

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

The Intel Software Developer's Manual, particularly Volume 3 (System Programming), documents Protection Keys Supervisor (PKS), a hardware feature for memory access control in privileged (kernel) mode. PKS is the x86_64 counterpart to User-mode Instruction Prevention (UIP) and provides fine-grained per-domain memory isolation critical to NARF's architecture.

## Key Mechanisms

**Protection Keys Supervisor (PKS):**
- PKS extends the paging system with 4-bit protection key tags on memory pages (similar to PKU for user mode, but for supervisor mode)
- Each page can be tagged with one of 16 protection keys (0-15), allowing 16 isolated domains on a single logical CPU
- Access control is defined by the PKRS (Protection Key Rights for Supervisor) MSR, which holds 16 2-bit fields (one per key)
- Each 2-bit field defines access rights: read/write allowed (RW), write-protected (WP), or access-denied (AD)

**Access Control Semantics:**
- When supervisor code accesses memory, the processor checks the page's protection key and consults PKRS
- If access violates the key's rights, the processor raises a Page Fault (PF) exception with a new bit in the error code indicating PKS violation
- PKRS can be modified only by privileged code; switching domains requires an WRMSR instruction
- Switching keys incurs a serializing instruction cost (flushes the pipeline) but not a TLB shootdown

**Domain Transitions:**
- Switching an execution context from one domain to another requires updating PKRS (one WRMSR per transition)
- The WRMSR is a serializing operation; all prior instructions complete before it executes
- No TLB flush is needed; the same virtual address can have different access rights depending on the current key
- Instruction fetches can be protected by PKS (on newer CPU generations) or rely on code segment isolation

**Page Table Organization:**
- PKS keys are stored in bits [62:59] of the page table entry (PTE)
- Keys are inherited during page table walks; a page cannot change keys mid-access
- All page sizes (4KB, 2MB, 1GB) support PKS tagging via similar PTE fields

## Critical Invariants

1. **Key-based isolation is per-logical-CPU:** PKS is per-thread context; multi-threaded systems must reload PKRS on context switches
2. **Kernel-only enforcement:** User mode (CPL=3) cannot use PKS; only privileged code (CPL≤2) benefits from this isolation
3. **No capability encoding in keys:** Keys are static; they do not encode object identity or rights—just access policy
4. **Exceptions are synchronous:** Page faults from PKS violations are precise; you know exactly which instruction triggered the fault
5. **Keys are coarse-grained:** 16 keys can protect 16 domains, but you cannot arbitrarily map objects to keys

## Performance Trade-offs

**WRMSR latency:**
- Switching keys via WRMSR is a serializing operation, typically 10-20 cycles on modern CPUs
- If domain switches are frequent (e.g., on every IPC), this overhead accumulates
- Batching multiple IPC operations before switching can amortize the cost

**Memory access overhead:**
- PKS checks are performed in parallel with TLB lookups; no additional latency for memory accesses within a domain
- Speculative prefetches and instruction fetches must respect PKS; mispredicted paths that violate keys cause exceptions

**TLB efficiency:**
- PKS allows page reuse across domains without TLB invalidation
- If two domains share a page (e.g., shared memory region), both can have the page in their TLB simultaneously
- Different key values for the same page in different domains reduce TLB overhead vs. separate page tables per domain

**Power and thermal:**
- Fewer TLB shootdowns and context switches reduce overall CPU frequency scaling pressure
- Reduced pipeline stalls from fewer MSR operations vs. full page-table switches

## Pitfalls and Warnings

1. **Serialization hazards:** WRMSR is serializing; prefetched or out-of-order instructions may stall before the MSR write commits
2. **Speculative access violations:** Speculative prefetches can trigger page faults even if the speculative path is never executed; handlers must distinguish real faults from speculative noise
3. **Key exhaustion:** With only 16 keys, a system with more than 16 isolated domains cannot use PKS alone (must combine with page-table switching)
4. **Instruction fetch protection uncertainty:** Early PKS implementations did not protect instruction fetches; only newer CPUs (Sapphire Rapids onwards) guarantee I-fetch protection
5. **UIPI interaction:** User Interrupt Protocol Instructions (UIPI) may bypass PKS on some CPU generations; verify documentation for your target CPU
6. **Covert channels:** PKRS state is not visible to user mode, but instruction timing (cache effects from faulting accesses) can leak information about which domain is active
7. **Shared memory coherency:** If two domains read/write a shared page, you must ensure consistency; PKS does not provide atomic operations across domains

## Recommendations for NARF Arch Designers

**Adopt:**
- PKS as the primary domain-isolation mechanism on x86_64
- 16-domain model (one per key) as a reasonable limit
- Batch IPC operations before domain switches to amortize WRMSR cost
- Separate key assignments: e.g., key 0 for kernel, keys 1-15 for user domains
- Fault handlers to distinguish PKS violations from other page faults

**Avoid:**
- Assuming instruction fetches are protected by PKS on older CPUs (Cascade Lake and earlier)
- Per-object key assignment (keys are too coarse; use a flat domain model instead)
- Frequent domain switches in latency-critical paths (batch operations, group related work)
- Forgetting to reload PKRS on context switches (a frequent source of data leaks between processes)

**Specific to NARF:**
- Document which CPU generations your NARF instance targets (SDM Vol. 1, section 3.7 for PKS feature requirements)
- Combine PKS with MTE on Arm to achieve domain isolation on both architectures
- Use WRMSR cost in latency budget for async-first design; consider whether executor can batch operations
- Integrate PKRS state into your capability revocation mechanism; revoking a capability in one domain should not affect another domain's view of the same object
- Model zero-copy IPC buffers as shared pages with restricted PKS keys; prevent writes from one domain if the buffer is read-only

<https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>
