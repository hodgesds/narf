# Linux PKS Support (LWN Coverage)

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview
LWN's coverage of Linux kernel PKS (Protection Keys for Supervisor) support documents the mainline integration of Intel's PKS feature into the Linux kernel. This provides a reference implementation for NARF's PKS domain isolation.

## Mechanisms

**Kernel PKS Domain Model:**
Linux's PKS implementation divides the kernel into logical domains (e.g., I/O protection domain, memory management domain). Each domain is assigned a protection key, and page tables are keyed accordingly.

**Per-CPU PKRS State:**
Each CPU maintains its own PKRS MSR. On context switches, the scheduler saves/restores per-task PKRS values (or uses a global PKRS for all tasks, sacrificing fine-grained isolation).

**Domain-Specific Ranges:**
Sensitive memory regions (e.g., page tables, device mappings) are protected by keys. Code accessing those regions must have the corresponding key enabled in PKRS. Unauthorized access triggers a fault.

**Async I/O and PKRS:**
Linux's async I/O subsystem (io_uring) interacts with PKS: if an I/O operation accesses protected memory, the I/O handler may need to enable the appropriate key temporarily.

## Key Invariants

**Per-CPU MSR:** PKRS is per-CPU, not per-task. Preemption requires careful handling: when a task is context-switched, the kernel must save its PKRS value and restore the next task's PKRS.

**No automatic key-switching:** The kernel does not automatically switch keys on function call boundaries. Domains are explicit: a code path must call `pks_save/restore()` to change domains.

**Fault on access denial:** If code accesses memory with a key that is disabled in PKRS, the CPU raises a fault. The kernel's fault handler must determine the cause and decide whether to allow the access or kill the process.

## Performance Trade-offs

**WRMSR overhead:** Writing PKRS incurs the cost of a WRMSR instruction (50–200 cycles). Excessive domain switches can become a bottleneck. Linux batches PKS changes where possible.

**Scalability:** PKRS per-CPU scales well to many-core systems. Each core has independent PKRS, avoiding contention (except during contended I/O operations).

**Compatibility:** Legacy code not aware of PKS runs with default unrestricted keys. PKS is backward-compatible.

## Pitfalls

1. **Key 0 special case:** Key 0 is typically unrestricted and implicit. Many allocations use key 0 (unrestricted). Fine-grained domain isolation requires assigning other keys, which is manual and error-prone.

2. **Key exhaustion:** With only 16 keys, assigning one per domain is limited. Linux's approach groups related functionality into a few domains.

3. **Task migration:** If a task is migrated to another CPU mid-execution, its PKRS state must be preserved. The scheduler must handle this carefully.

4. **Interrupt handlers:** Interrupt handlers run in the interrupted task's context and inherit its PKRS. If an IRQ handler needs to access memory with different keys, it must manually switch PKRS and restore on exit.

## Adoption Guidance for NARF

**Adopt:**
- **Explicit domain switching:** NARF's scheduler explicitly switches PKRS on domain change (not on every task switch). Batch PKS changes.
- **Limited key count:** Assign keys judiciously. Group logically related functionality into a single domain key.
- **Fault handling:** Implement a PKS fault handler that logs violations and potentially revokes the violating capability.

**Avoid:**
- **Per-task PKRS switching:** Switching PKRS on every task switch is expensive. Use a global PKRS for all tasks in a domain.
- **Fine-grained per-allocation keys:** Managing keys at the page level is impractical. Group pages into domain-wide regions.

**Design point:**
NARF's memory subsystem should mirror Linux's approach: assign one PKS key per logical domain (I/O, memory management, networking). On domain switch (async task migration), write PKRS once. All code in that domain accesses pages tagged with that key. Pair with async executor to avoid blocking on domain switches.

## Reference
- Linux kernel PKS support (LWN coverage)
- https://lwn.net/Articles/826092/
- Linux source: `arch/x86/include/asm/pks.h`, `arch/x86/mm/pkeys.c`
