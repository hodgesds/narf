# Arm GICv3/GICv4 Architecture

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview
The Arm Generic Interrupt Controller (GIC) provides hardware interrupt handling for Arm systems, with GICv3 introducing significant architectural changes and GICv4 extending support for virtual interrupts and ITS (Interrupt Translation Service). NARF targets aarch64 systems and must interface with GICv3 minimum; GICv4 support enables advanced virtualization scenarios.

## Mechanisms

**GICv3 Core:**
- **Distributor (GICD):** Central unit routing interrupts to CPUs. Maintains enable/priority/target registers for each interrupt.
- **CPU Interface (GICR):** Per-CPU redistributor handling CPU-local interrupts (SGIs, PPIs) and IPI (Interrupt Processor Interrupts).
- **ITS (Interrupt Translation Service):** Translates device-generated interrupts (MSI-X vectors) to IRI (Interrupt Request Identifiers) via event-to-LPI (Locality-Specific Peripheral Interrupt) translation tables. Enables per-device interrupt steering without per-device MSI-X address ranges.

**GICv4 extensions:**
- **Virtual ITS:** Each vPE (virtual Processor Element) can host virtualized interrupts without traps to hypervisor.
- **Direct injection:** LPIs can be directly injected into vPE without hypervisor intervention when direct deactivation is supported.

## Invariants
- **Priority masking:** CPU interface priority mask (PMR) gates interrupt delivery. Lower numeric priority is higher urgency.
- **Group handling:** Interrupts divided into Group 0 (secure, FIQ) and Group 1 (nonsecure, IRQ); each has separate enable and priority.
- **Edge vs. level:** PPIs/SGIs can be edge-triggered; SPIs (Shared Peripheral Interrupts) default to level-sensitive unless configured otherwise.

## Performance Trade-offs

**ITS efficiency:** ITS translation adds one memory lookup per event (cached in a hardware cache in typical implementations). Much faster than software interrupt routing tables, enabling high-frequency device MSI-X without syscall per interrupt.

**CPU affinity:** GICD affinity tables allow per-interrupt steering to CPU sets. NARF can use this to direct device interrupts to cores in a specific PKS domain or partition.

**Latency:** GICv3/v4 interrupt latency is hardware-determined (typically 10–50 cycles after delivery to CPU interface). No OS-imposed latency beyond the trap handler.

## Pitfalls

1. **ITS configuration complexity:** ITS tables (DeviceID→EventID→INTID mapping) are platform-specific. Drivers must discover device capabilities and ITS table layout via ACPI IORT (I/O Remapping Table).
2. **Virtual vs. physical:** In virtualized environments, vPE initialization and LPI injection ordering matter. GICv4 direct injection can race if not carefully sequenced.
3. **LPI storm:** Spurious LPI delivery (e.g., bad ITS table entry) can cause interrupt storms. Mitigate with per-IRQ rate limiting in the OS.

## Adoption Guidance

**For NARF:**
- **Adopt:** GICv3 as the baseline interrupt controller for aarch64. Use ITS for MSI-X device steering; it integrates naturally with zero-copy DMA (devices write to ITS translate address, avoid mailbox).
- **Avoid:** GICv4 virtual-interrupt injection until Stage 4 virtualization. Early stages should focus on GICv3 bare-metal usage.
- **Design point:** Map each PKS domain to a GICv3 CPU affinity set. Device interrupts routed to domain-specific cores; ISR runs in domain context. Pair with async executor work-stealing to ensure domain-aware scheduling.
- **ITS usage:** Leverage ITS for per-device interrupt isolation. Each device gets its own event stream; no shared interrupt-vector table.

## Reference
- Arm GICv3 Architecture Specification (IHI 0069)
- https://developer.arm.com/documentation/ihi0069/latest/
- Arm GICv4 Architecture Specification (IHI 0069 extending GICv3)
