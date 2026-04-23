# Arm Architecture Reference Manual DDI 0487 — MTE and EL State

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

The Arm Architecture Reference Manual for A-profile architecture (DDI 0487) documents the full instruction set, privilege levels (EL0-EL4), exception handling, and memory protection mechanisms including Memory Tagging Extensions (MTE) and Pointer Authentication Code (PAC). This is essential for NARF's aarch64 implementation.

## Key Mechanisms

**Memory Tagging Extensions (MTE):**
- MTE adds a 4-bit tag to every 16-byte granule of memory (the physical granule size, though virtual tags are cached)
- Every memory access (load/store) carries a 4-bit tag in the high bits of the virtual address
- The processor compares the access tag against the memory granule's tag; a mismatch triggers a tag-check fault
- Tags are set with dedicated instructions (STG, STZG, ST2G) and cleared automatically on allocation
- Tag checking can be disabled per-instruction (using the .nt suffix) or per-exception-level

**Exception Levels (EL0-EL3):**
- EL0 is unprivileged userspace; EL1 is kernel; EL2 is hypervisor; EL3 is secure monitor
- Each EL has separate page tables, exception handlers, and privilege gates
- Transitions between ELs are explicit (exception entry, exception return); no implicit mode switches
- NARF likely uses EL1 for kernel, EL0 for unprivileged domains

**Memory Management Unit (MMU):**
- Two-level translation: virtual address → intermediate physical address → final physical address
- Stage 1 (EL0/EL1) and Stage 2 (EL2) translations are independent; hypervisors can further isolate guests
- TTBR (Translation Table Base Register) holds the base of the page table; contexts switch via TTBR reload
- TLB entries are tagged by ASID (Address Space ID) to reduce shootdown overhead

**Pointer Authentication Code (PAC):**
- PAC signs return addresses and function pointers to prevent ROP (Return-Oriented Programming) attacks
- Signing uses the PACIA/PACIB instructions; verification is implicit in RET or explicit via AUTIA/AUTIB
- PAC can sign against the LR (Link Register), SP (Stack Pointer), or a general register
- Mismatches trigger a Tag Fault (similar to MTE) at the EL where the mismatch is detected

**Generic Interrupt Controller (GIC) Integration:**
- GIC receives interrupts from peripherals and routes them to CPU cores
- EL1 can register handlers; EL2 hypervisor mode can intercept and emulate interrupts for EL1 guests
- GICD (Distributor) and GICR (Redistributor per-CPU) manage interrupt routing

## Critical Invariants

1. **Tags are per-granule (16 bytes):** You cannot assign different tags to the same granule; coherency is per-granule
2. **Tag mismatch is synchronous:** Tag faults are precise exceptions, not deferred
3. **MTE is opt-in per EL:** MTE can be disabled for backward compatibility; exception handlers can unmask tag faults
4. **ASID reduces TLB shoots:** Even if page tables change, ASID allows a process's old TLB entries to persist safely
5. **PAC does not prevent control flow:** It only detects corruption; you still need CFI (Control Flow Integrity) mechanisms

## Performance Trade-offs

**MTE overhead:**
- Tag storing (STG) and tag clearing (DC ZVA with tag zeroing) add memory bandwidth
- Tag checking is parallel with TLB lookup; no additional latency for memory accesses if tags are cached
- Tag mismatches cause exceptions; exception handling overhead depends on handler complexity

**PAC overhead:**
- Signing and authentication add ~1-3 cycles per operation
- Can be disabled on performance-critical paths (marked with .nt)
- Return address signing on every function call adds significant overhead if not selectively applied

**ASID efficiency:**
- 16-bit ASID space allows up to 65,536 unique contexts before TLB flush required
- ASID allocation/deallocation adds bookkeeping overhead but saves TLB shootdowns

**Multi-EL overhead:**
- Switching between ELs (e.g., EL0 ↔ EL1) via exception entry/return is ~50-100 cycles (rough estimate)
- Careful system design minimizes EL switches; batching reduces frequency

## Pitfalls and Warnings

1. **Tag coherency:** If two CPUs have different views of a memory location's tag (cache incoherency), tag faults may be non-deterministic
2. **MTE with DRAM scrubbing:** Memory initialization routines must clear tags properly; stale tags cause false faults
3. **PAC key recovery:** If the key used for signing is leaked, signatures can be forged
4. **TLB aliasing:** Using different page tables (different TTBR) for the same virtual address can leave conflicting TLB entries; shootdowns must be precise
5. **GICD/GICR configuration:** Interrupt routing is not transactional; misconfiguration can lose or duplicate interrupts
6. **EL2 trap handling:** If running as a hypervisor, trapping all EL1 memory operations (to emulate isolation) adds significant latency
7. **Cache side-channels:** Even with MTE isolation, cache timing can leak information about which granules are accessed by other cores

## Recommendations for NARF Arch Designers

**Adopt:**
- MTE as the primary memory isolation mechanism on aarch64
- 16-domain model aligned with 4-bit tag space (0 = invalid, 1-15 = valid domains)
- Separate TTBR per domain (or per-process) to isolate page tables
- ASID to reduce TLB shootdown cost on context switches
- PAC for return address protection; selectively disable on performance-critical hot paths

**Avoid:**
- Relying on MTE tags without explicit synchronization (tags can be stale if memory is not synchronized)
- Assuming PAC is cryptographically strong (it is not; it's a probabilistic defense)
- Frequent EL switches; batch work to minimize exception overhead
- Disabling MTE entirely for performance (the cost of tag faults is usually less than fixing the bugs they prevent)
- Forgetting to initialize tags on memory allocation

**Specific to NARF:**
- Combine NARF's domain-isolation model (16 domains per design) with MTE's 4-bit tag granularity
- Use TTBR per domain to isolate page tables; ASID can group related domains if you need more than 16 contexts
- Zero-copy IPC: shared buffers should have both domains' tags set (atomic STG operation from one domain, then read by other)
- Async executor: ensure EL switches do not occur mid-await; context should remain on same EL
- Capability model: encode domain identity in high bits of capability pointers; MTE tags verify integrity
- Interrupt handling: model interrupts as async events, not synchronous exceptions; route through executor

<https://developer.arm.com/documentation/ddi0487/latest/>
