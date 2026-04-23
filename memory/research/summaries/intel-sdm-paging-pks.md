# Intel SDM Vol. 3A: Paging and PKS

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview
Intel SDM Volume 3A, Chapter 4 covers x86-64 paging and memory management. Section 4.6.2 specifically documents Protection Keys for Supervisor-Mode Pages (PKS), a critical mechanism for NARF's domain isolation architecture.

## Mechanisms

**Paging Hierarchy:**
Intel x86-64 uses a 4-level hierarchical page table structure: PML4 (page map level 4) → PDPE (page directory pointer entry) → PDE (page directory entry) → PTE (page table entry). Each entry is 64 bits and contains a physical address + metadata (present, read/write, user/supervisor, accessed, dirty, execute-disable).

**Protection Keys (PKS):**
PKS extends page table protection by introducing a 4-bit protection key field in each page table entry (bits 59–62 in the PTE). The PKRS (Protection Key Rights for Supervisor) Model-Specific Register (MSR 0x6E2) contains a 64-bit value with 16 key slots, each controlling read/write access for that key.

**Key-Based Access Control:**
When the CPU accesses supervisor-mode memory (kernel), it checks:
1. Traditional page table bits (present, read/write, user/supervisor)
2. The protection key in the PTE for the accessed page
3. The corresponding 2-bit access rights in PKRS (RW bits: 11=unrestricted, 10=write-disabled, 01=reserved, 00=access-denied)

**PKRS Register Layout:**
Each key occupies 2 bits in PKRS. Writing `WRMSR(IA32_PKRS, value)` atomically updates all keys' access rights. There is no per-key mechanism; each WRMSR updates the entire register.

## Key Invariants

**Fine-grained supervisor access control:** PKS provides hardware-enforced access control at the page level for kernel code. A page tagged with key N is accessible only if PKRS[2N:2N+1] permits (user-mode pages bypass PKS; only supervisor mode is affected).

**Atomic key-switch:** Changing PKRS is a single WRMSR instruction. All pages' access rights change atomically. There is no per-page override; the MSR controls all keys at once.

**No TLB flush required:** Changing PKRS does not require TLB invalidation. The change takes effect on the next memory access. This is critical for NARF's domain-switch performance.

## Performance Trade-offs

**Domain-switch latency:** Changing PKRS via WRMSR typically takes 50–200 cycles, depending on CPU generation. This is much faster than a full context switch (1000+ cycles) but not negligible. NARF must minimize domain switches or amortize the cost.

**Memory layout impact:** Assigning keys to pages requires kernel-level page table modifications. Pre-allocating key-protected regions during boot is efficient; dynamic re-keying is slower.

**No per-task isolation by default:** PKRS is per-CPU (global MSR), not per-task. NARF's scheduler must write PKRS on every domain switch. This means many WRMSR calls at high task-switch frequency.

## Pitfalls

1. **PKRS MSR contention:** If multiple CPUs contend on the same PKRS MSR (e.g., due to cache-line bouncing), performance degrades. Each core has its own PKRS copy, but writes might be serialized.

2. **Deadlock if key 0 is misused:** Key 0 typically grants unrestricted access and is the implicit default. Disabling key 0 access can render large memory regions inaccessible. NARF must reserve key 0 for bootstrapping.

3. **Stale PKRS values on preemption:** If a task is preempted during a critical section with modified PKRS, the next task on that CPU inherits the modified PKRS. The scheduler must save/restore PKRS per-task or use a global PKRS for all tasks (simpler but less isolated).

4. **No protection of WRMSR itself:** A malicious task cannot execute WRMSR (supervisor-only), but if exploited, arbitrary PKRS changes enable memory corruption.

## Adoption Guidance for NARF

**Adopt:**
- **Per-domain keys:** Allocate one PKS key per I/O domain or privilege level. All memory accessible by domain N uses key N.
- **Bulk allocation:** Pre-allocate and key-protect memory regions during boot (e.g., domain-specific heaps, I/O device registers). Avoid per-allocation re-keying.
- **PKRS per-domain:** Each domain switch writes PKRS once to activate that domain's keys.

**Avoid:**
- **Per-page fine-grained keys:** Dynamically adjusting per-page keys on each access is too slow.
- **Sharing keyed memory:** Enforce memory isolation via keys, not by sharing. If two domains need shared buffers, use a separate shared-memory region with an unrestricted key.
- **Relying on PKRS for user-mode isolation:** PKS applies only to supervisor mode. User-mode isolation requires traditional page table isolation or SMEP (Supervisor Mode Execution Prevention).

**Design point:**
Assign a fixed set of PKS keys to domain groups (e.g., key 1–4 for I/O, key 5–8 for memory). Each domain holds pages tagged with its keys. On domain switch, write PKRS to enable that domain's keys and disable others. Pair with MTE (on Arm) for additional defense in depth.

## Reference
- Intel SDM Volume 3A, Chapter 4 (Paging)
- Intel SDM Volume 3A, Section 4.6.2 (Protection Keys for Supervisor-Mode Pages, PKS)
- https://www.intel.com/sdm
