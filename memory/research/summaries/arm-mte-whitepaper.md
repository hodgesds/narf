# Memory Tagging Extension: Enhancing Memory Safety (Arm Whitepaper)

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview
Arm's Memory Tagging Extension (MTE) is a hardware feature that tags memory with 4-bit tags at a granularity of 16 bytes (per-tag granule). The CPU checks that pointer tags match memory tags on every load/store, catching memory safety violations (use-after-free, buffer overflow) in hardware.

## Mechanisms

**Tag Granule:**
Memory is divided into 16-byte regions, each with a 4-bit tag stored in a separate tag memory (not part of the normal address space). A pointer's top 4 bits (in the 64-bit virtual address space used for tagging) encode the expected tag.

**Pointer Encoding:**
In AArch64, the top 8 bits of a pointer (bits 56–63) are normally reserved for operating-system use. MTE repurposes bits 56–59 as the pointer tag, leaving bits 60–63 for OS use. When MTE is enabled, the CPU compares the pointer tag to the memory tag on each access.

**Fault Modes:**
- **Synchronous mode:** Tag mismatch raises a Data Abort exception (fault) immediately.
- **Asynchronous mode:** Tag mismatches are logged but do not fault immediately. Allows continued execution but makes faults harder to attribute to specific instructions.

**Tag Generation:**
Tags are assigned via the `st2g` (store 2 granules with tag) and `stzg` (store zero and tag) instructions. These atomically write data and set the memory tag.

## Key Invariants

**Tag isolation:** Memory tagged with tag T is only accessible via pointers with tag T. Mismatched pointers cause faults (or logging in async mode).

**Granule independence:** Each 16-byte granule has its own tag. A 32-byte structure might span multiple granules, each with a different tag, or all granules might share a tag via pointer arithmetic.

**Non-coherency with CPU cache:** MTE tags are not cached like normal data. They are checked from the tag memory (a separate structure) on each access, avoiding cache coherency complications.

## Performance Trade-offs

**Latency:** Tag checking adds a few cycles to load/store operations (typically 2–5 cycles per access). Modern Arm cores pipeline the check, making the latency transparent in deep pipelines.

**Memory overhead:** Tag memory is ~1/16 the size of data memory (4 bits per 16 bytes). A system with 16 GB of data memory needs ~1 GB of tag memory.

**Async mode overhead:** In asynchronous mode, faults are not immediate, so a mistagged access doesn't trap. Instead, fault records accumulate in a fault register. The OS must periodically drain the register to detect faults. This adds polling overhead.

## Pitfalls

1. **Async mode attribution:** In asynchronous mode, a fault is logged but not tied to a specific instruction. If multiple mistagged accesses occur before the fault is drained, attribution is ambiguous.

2. **Tag wrap-around:** With only 4 bits, tags cycle (0–15). If memory is freed and reallocated within the same tag epoch, the new allocation might be accessible to freed pointers. NARF must use a larger epoch (combine MTE tags with generation numbers in software).

3. **Pointer arithmetic:** Pointer arithmetic that changes the tag bits (e.g., `ptr = (void*)((uintptr_t)ptr + offset)`) creates mismatched pointers. Rust's strict type system mitigates this, but inline assembly and unsafe code can violate the invariant.

4. **No bounds checking:** MTE checks tags but not bounds. A pointer with the correct tag but an out-of-bounds offset will still match the memory tag (if the offset lands in another tagged granule with the same tag).

## Adoption Guidance for NARF

**Adopt:**
- **Synchronous mode for safety-critical code:** Use synchronous MTE for strict memory safety enforcement. Faults immediately trap, simplifying debugging.
- **MTE + PKS combination:** On Arm servers supporting both PKS (implemented via SMMU domain keys) and MTE, use MTE for memory safety and domain keys for access control. This provides defense in depth.
- **Tag generation per-allocation:** Assign a new tag to each allocated memory region. Combine MTE's 4-bit tag with a software generation number to prevent tag reuse.

**Avoid:**
- **Asynchronous mode for deterministic systems:** Async mode complicates fault attribution. Use synchronous for real-time or safety-critical applications.
- **Relying on MTE alone for access control:** MTE catches memory corruption but does not isolate domains. Pair with SMMU or PKS for access control.
- **Mixing tagged and untagged code:** All pointers must have consistent tagging. Heterogeneous tagging strategies are error-prone.

**Design point:**
Enable MTE synchronous mode globally in NARF. On each memory allocation (from the allocator), assign a unique 4-bit tag and store in a table indexed by allocation ID. On deallocation, invalidate the tag (mark as inaccessible). Pair with Rust's type system to prevent dangling pointer use: the Rust compiler enforces borrowing rules; MTE catches violations at runtime.

## Reference
- "Memory Tagging Extension: Enhancing Memory Safety through Architecture" (Arm, 2019)
- https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Arm_Memory_Tagging_Extension_Whitepaper.pdf
- Arm ARM (Architecture Reference Manual), Chapter D6
- https://developer.arm.com/documentation/ddi0487/latest/
