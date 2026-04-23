# Intel User Interrupts (UIPI) Specification

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview
Intel User Interrupts (UIPI) enable user-mode processes to send interrupts directly to other user-mode processes without kernel intervention, reducing context-switch latency for IPC and event notification. The mechanism complements hardware-level interrupt handling (APIC) by bringing similar hardware-accelerated signaling to unprivileged code.

## Mechanisms
UIPI operates through several key structures:

**UITT (User Interrupt Target Table):** Each task has a per-process UITT indexed by interrupt vector. The UITT entry contains the target task's UID (user interrupt ID) and handler context. Only the OS kernel can modify UITT entries, enforcing isolation.

**SENDUIPI instruction:** User code executes SENDUIPI to deliver an interrupt to a target UID. The CPU checks the sender's privilege and the UITT entry; if valid, the receiver is interrupted asynchronously (does not wait for the receiver to be scheduled).

**STUI / CLUI:** Set/Clear User Interrupt. Receiver-side instructions to enable/disable interrupt delivery and acknowledge pending interrupts.

**Receiver task model:** An interrupted task is notified via a user-level interrupt handler or by setting a pending flag that the task polls. The receiver remains scheduled on its CPU unless voluntarily yielding; UIPI does not preempt.

## Invariants
- **Kernel-mediated setup:** UIPI cannot be used without prior OS-installed UITT entries. The kernel grants a UID and binds it to a handler address.
- **Unidirectional:** A task can send to any UID it knows, but the receiver's UITT controls whether delivery succeeds.
- **No capability transfer:** UIPI itself does not carry capability data; it is a pure interrupt mechanism.

## Performance Trade-offs
**Latency:** UIPI latency is typically 100–500 ns from SENDUIPI to receiver wakeup, much faster than a syscall (5–10 µs). This is critical for NARF's async executor IPC paths.

**Receiver overhead:** If the receiver is not already running, UIPI delivers an interrupt but does not schedule it. NARF must pair UIPI with a scheduler integration to ensure the receiver runs.

**Cache footprint:** UIPI uses only the UITT (per-process, small) and MSRs for state. No shared kernel queue or lock contention.

## Pitfalls

1. **Handler re-entrancy:** If a UIPI handler calls code that triggers another UIPI, careful MSR state management is needed.
2. **Receiver scheduling:** Delivering a UIPI to a task not currently on a CPU requires the scheduler to wake it. NARF's async executor must integrate UIPI delivery with ready-queue insertion.
3. **Transient delivery:** If the receiver is in a different PKS domain, the UIPI handler may run in the sender's domain context. NARF must clarify whether the handler runs in the receiver's domain or if domain switch is deferred.

## Adoption Guidance

**For NARF:**
- **Adopt:** UIPI for latency-sensitive IPC between ready tasks in the same domain. Pair with work-stealing scheduler to ensure receiver is runnable.
- **Avoid:** Using UIPI for cross-domain IPC until the domain-switch semantics are clarified. Instead, fall back to doorbell via shared queue for cross-domain, or use capability-based RPC.
- **Design point:** Integrate UIPI into the async executor's waker; when a capability-based task is notified via UIPI, the executor's scheduler module immediately enqueues it.

## Reference
- Intel SDM Vol. 3A, Chapter 11: User Interrupts (UIPI)
- https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
