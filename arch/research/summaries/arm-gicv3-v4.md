# Arm Generic Interrupt Controller v3/v4 Architecture (IHI 0069)

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

The Arm Generic Interrupt Controller (GIC) specification, particularly v3 and v4, defines how interrupts from peripherals are collected, prioritized, and delivered to CPU cores. GICv3 introduced per-CPU redistributors and message-signaled interrupts; v4 added support for virtualization and ITS (Interrupt Translation Service). Understanding GIC architecture is critical for NARF's interrupt handling and async executor design.

## Key Mechanisms

**GIC Architecture Overview:**
- Distributor (GICD) is a single system component managing shared interrupts (SGIs, PPIs, SPIs)
- Redistributor (GICR) is per-CPU, handling per-CPU interrupts (SGIs, PPIs, PPIs for virtualization)
- CPU Interface (CPU IF) is per-core, handling interrupt acceptance and priority masking

**Interrupt Types:**
- **SGI (Software-Generated Interrupts):** Triggered by code, not hardware; used for IPI (Inter-Processor Interrupts)
- **PPI (Private Peripheral Interrupts):** Per-CPU, typically for timers and CPU-local events
- **SPI (Shared Peripheral Interrupts):** Global interrupts from peripherals, routable to any CPU

**Interrupt Flow:**
1. Peripheral asserts interrupt signal or sends message to GIC
2. GICD prioritizes and determines target CPU(s)
3. GICR acknowledges on the target CPU, signals CPU IF
4. CPU IF delivers to EL1 (kernel) or EL2 (hypervisor) exception handler
5. Handler services the interrupt; CPU writes EOIR (End Of Interrupt) to GICR

**Message-Signaled Interrupts (MSI) and ITS:**
- GICv4 introduces ITS (Interrupt Translation Service), allowing peripherals to send interrupt messages with a device ID and event ID
- ITS translates these into CPU-routable interrupts; enables efficient message-passing architectures
- LPIs (Locality-Preserving Interrupts) are dynamically allocated via ITS, allowing 24-bit LPI numbers (up to 16M per processor)

**Virtualization Support (GICv4):**
- Virtual interrupts for guest VMs; hypervisor can trap and emulate guest interrupt delivery
- Direct injection: with VLPI (Virtual LPI), an interrupt can be delivered directly to a guest without hypervisor intervention
- vPE (Virtual Processor Element): tracks virtualized CPUs across VMs; scheduler-controlled

**Priority and Preemption:**
- Interrupts are prioritized by a numeric priority field (lower = higher priority)
- Running interrupt can be preempted by higher-priority interrupt
- Interrupt grouping (Group 0 vs. Group 1) separates secure vs. non-secure (TrustZone-aware) or FIQ vs. IRQ semantics

## Critical Invariants

1. **Interrupt delivery is atomic:** Once a CPU claims an interrupt, no other CPU will receive it (mutual exclusion)
2. **Acknowledgment is required:** CPU must explicitly acknowledge via GICC_IAR to receive next interrupt
3. **EOIR must be written to clear:** Writing EOIR to the redistributor signals completion; level-triggered interrupts remain asserted until the peripheral deasserts
4. **Priority ordering is total:** At any moment, the highest-priority pending interrupt (that isn't masked) will be delivered next
5. **No interrupt can be delivered before its enable bit is set:** Disabling an interrupt prevents delivery, but doesn't cancel pending state

## Performance Trade-offs

**Polling vs. Interrupts:**
- Interrupt-driven model incurs context-switch overhead (exception entry/exit) but allows CPU to work while waiting
- Polling allows tighter loops but burns CPU; efficient for predictable, high-frequency workloads

**MSI vs. traditional signals:**
- MSI is more efficient for high-frequency interrupts (e.g., from NICs); no need for shared interrupt lines
- Signal-based is simpler but requires shared IRQ handling and priority arbitration

**ITS scalability:**
- ITS allows devices to send interrupts directly (via writes to a GIC-provided address) without hypervisor mediation
- LPI space (24-bit) scales better than older 10-bit SPI space for many-device systems
- ITS lookup overhead is typically minimal but can be a bottleneck if misconfigured

**Virtualization overhead:**
- Direct VLPI injection (GICv4) can deliver guest interrupts without hypervisor traps
- Without direct injection, every guest interrupt requires EL2 entry; significant overhead

## Pitfalls and Warnings

1. **Interrupt affinity races:** Changing a CPU's interrupt affinity while an interrupt is pending can cause delivery to the wrong CPU
2. **Level-triggered edge cases:** If the peripheral doesn't deassert the interrupt signal, a level-triggered interrupt will immediately re-trigger after handler returns
3. **Shared interrupt lines:** If multiple devices share an interrupt line and one is slower to acknowledge, both may see elevated latency
4. **EOIR write errors:** Writing EOIR with wrong interrupt ID or from the wrong CPU can corrupt GIC state
5. **Redistributor offline:** Taking a CPU offline (GICR_WAKER.ProcessorSleep) without migrating its interrupts can lose incoming interrupts
6. **LPI configuration corruption:** ITS lookup tables are not protected by the GIC; memory corruption can corrupt LPI routing
7. **Covert channels:** Interrupt latency and timing can leak information about system load, other CPUs' activities, and even information across security boundaries (if groups are not properly configured)

## Recommendations for NARF Interrupt Subsystem Design

**Adopt:**
- GIC-based interrupt delivery; use GICR (redistributor) for per-CPU efficiency
- MSI/ITS for high-frequency interrupts from devices (scalable to many devices)
- Interrupt affinity: route each interrupt to a single CPU by default; avoid sharing lines
- Priority-based delivery: assign priorities based on latency requirements (high-priority = short latency)
- Event-based wakeup for async executor: interrupts wake executor, executor polls work queues

**Avoid:**
- Shared interrupt lines (if device supports MSI, use it instead)
- Polling-based interrupt handling in latency-critical paths (cost of exceptions is usually worth it)
- Frequent CPU online/offline without careful interrupt migration
- Direct level-triggered interrupts; prefer edge-triggered or MSI with proper deassert logic

**Specific to NARF:**
- Model interrupts as async events in the executor; each interrupt type has a handler registered with the kernel
- Use GICR per-domain: each NARF domain has its own set of interrupt handlers; GIC delivers to the appropriate redistributor
- Zero-copy IPC notification: consider whether IPC completion should signal via interrupt (async) or be polled (sync)
- Async executor wakeup: interrupt handler enqueues a task in the executor's work queue; executor resumes from interrupt context
- Capability model: interrupt delivery grants temporary authority to an interrupt handler; revocation removes from handler list
- Multi-domain safety: ensure interrupt handlers in one domain cannot access memory of another (enforce with PKS/MTE)
- Avoid busy-waiting on interrupt status; prefer event-based wakeup

<https://developer.arm.com/documentation/ihi0069/latest/>
