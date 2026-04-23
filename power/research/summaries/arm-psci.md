# Arm Power State Coordination Interface (PSCI)

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

Arm PSCI is the firmware interface for power state transitions on Arm platforms (aarch64). Unlike x86's ACPI (firmware-driven), PSCI is firmware-aware but OS-driven: the OS requests state changes via PSCI calls, and firmware executes them.

## Mechanisms

**CPU Operations:**
- **PSCI_CPU_ON:** Boot a CPU from a specified entry point. Returns immediately; CPU wakes asynchronously.
- **PSCI_CPU_OFF:** Power off the calling CPU. This is a one-way operation; the CPU must be re-activated via PSCI_CPU_ON.
- **PSCI_CPU_SUSPEND:** Suspend the CPU, optionally to a specific power state level (0=retention, higher=deeper sleep).

**System Operations:**
- **PSCI_SYSTEM_SUSPEND:** Suspend the entire system (equivalent to S-state on x86).
- **PSCI_SYSTEM_RESET / SHUTDOWN:** Reset or power off the system.

**Power State Format:**
Power states are 32-bit values encoding the topology (affinity levels: core, cluster, system) and power state. For example, `0x0010000` might mean "suspend this core, keep cluster alive."

## Key Invariants

**Explicit CPU Coordination:** PSCI_CPU_OFF does not wake other CPUs; the OS must explicitly manage CPU bringup/down. This is simpler than ACPI but requires careful scheduler coordination.

**Atomic entry:** PSCI calls are atomic from the OS perspective. Once PSCI_CPU_SUSPEND is called, firmware takes control until the CPU wakes.

**Entry Point Pinning:** When offlining a CPU, pending tasks must be migrated to other CPUs before calling PSCI_CPU_OFF. Failure to do so loses tasks.

## Performance Trade-Offs

**Firmware latency:** PSCI calls incur firmware overhead (typically microseconds to tens of microseconds). Real-time tasks should avoid frequent suspension/resumption.

**Power state negotiation:** Some PSCI implementations allow partial suspension (core off, cluster alive) for faster wakeup. NARF can exploit this for responsive idle.

**Memory coherency:** On CPU wake-up after deep sleep (core off), caches must be re-enabled. Early boot code (CPU reset vector) re-establishes coherency.

## Pitfalls

1. **CPU offline without task migration:** Calling PSCI_CPU_OFF while tasks are runnable on that CPU will deadlock them. The scheduler must migrate all runnable tasks before offending the CPU.

2. **Wakeup race:** If an interrupt arrives during PSCI_SYSTEM_SUSPEND entry, the system may not suspend correctly. The firmware must handle edge cases.

3. **NUMA awareness:** On NUMA systems, CPU topology varies. NARF must discover NUMA structure via device tree or ACPI and respect it in power decisions.

4. **Frequency coordination:** Unlike x86's P-states, Arm PSCI does not specify frequency management. Frequency is often a separate firmware interface (e.g., SCMI or vendor-specific), creating complexity.

## Adoption Guidance for NARF (Arm)

**CPU Hotplug:**
- Use PSCI_CPU_ON during boot to bring up all CPUs.
- During idle, migrate tasks to fewer CPUs and use PSCI_CPU_OFF to power down unused cores.
- On wakeup, PSCI_CPU_ON brings cores back; scheduler rebalances tasks.

**Suspend Strategy:**
- For light sleep: use CPU suspend (core retention).
- For deep sleep (servers): typically skip; servers don't suspend.
- For embedded (clients): use PSCI_SYSTEM_SUSPEND for S3-like behavior.

**Integration with Scheduler:**
- Pair CPU offlining with task migration. The scheduler must guarantee all runnable tasks are on powered-on CPUs.
- Use power state hints (topology masks in PSCI calls) to optimize wakeup latency.

**Frequency Management:**
- PSCI does not handle frequency; use SCMI (below) or vendor interfaces.
- Do not assume PSCI controls performance; implement frequency scaling separately.

## Reference
- Arm Power State Coordination Interface (PSCI) Specification
- https://developer.arm.com/documentation/den0022/latest/
