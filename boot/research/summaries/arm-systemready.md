# Arm SystemReady Certification Program

## Overview

Arm SystemReady is a compliance framework ensuring "software interoperability on Arm-based hardware." For NARF microkernel developers, this means understanding standardized firmware-to-OS interfaces that your boot subsystem must either comply with or deliberately diverge from—a critical architectural decision.

## Key Mechanisms for Boot Design

SystemReady defines two primary bands relevant to boot initialization:

**SystemReady Band** uses Advanced Configuration and Power Interface (ACPI), enabling generic operating systems to install on hardware without modification. This abstracts hardware details through standardized firmware tables and runtime services. Your boot code would need to produce ACPI tables, implement UEFI runtime protocols, or consume them from firmware.

**SystemReady Devicetree Band** optimizes for embedded systems using device tree as the hardware description mechanism. This is lighter-weight and deterministic—properties are statically defined rather than dynamically queried. Given NARF's focus on predictable isolation and zero-copy semantics, devicetree alignment may reduce boot-time complexity.

The Pre-Silicon Program offers compliance testing frameworks before silicon tape-out, relevant if you're designing for emerging Arm platforms.

## Architectural Invariants for Capability Security

Three invariants matter for NARF's boot phase:

1. **Capability Establishment**: Before domain isolation (PKS/MTE) activates, you must establish the initial capability graph. SystemReady's firmware→kernel handoff must preserve or reconstruct this safely. If firmware constructs ACPI tables with device addresses, your boot code must translate these into capabilities, not raw pointers.

2. **MTE Granularity**: Memory Tagging Extension enforcement during boot requires that firmware-provided memory maps align with tag boundaries. Misaligned handoff data creates vulnerability windows.

3. **Async Executor Readiness**: The boot sequence must complete synchronously before the async executor threads begin. SystemReady's model (especially ACPI) assumes synchronous initialization; asynchronous boot discovery conflicts with deterministic isolation setup.

## Performance Trade-Offs

**ACPI Compliance** adds complexity: parsing binary tables, queking runtime services, handling variable hardware layouts. This delays boot and increases TCB. For latency-critical systems, the benefit—broad hardware compatibility—may not justify the cost.

**Devicetree** is faster at boot because parsing is simpler and hardware descriptions are static. However, it assumes the bootloader (firmware) correctly describes all devices. If firmware is untrusted or buggy, this concentrates risk.

**Pre-Silicon Testing** accelerates compliance validation but requires access to Arm's test suites and simulators, adding dependency and schedule coupling.

## Pitfalls for Boot Designers

1. **Firmware Trust Boundary**: SystemReady assumes firmware is trustworthy. In NARF's threat model with capability security, firmware-provided memory maps or capability metadata must be validated, not blindly accepted. Design boot code to audit all firmware-supplied data.

2. **ACPI Runtime Services Persistence**: Some ACPI services remain available at runtime. If your boot code relies on these, you've created a long-lived firmware dependency that violates principle of least privilege. Resolve all hardware discovery during boot; don't defer to runtime.

3. **Devicetree Mutability**: If bootloaders modify device trees after hand-off, your boot code may miss critical updates. Verify devicetree integrity (via signatures if needed) before consuming it.

4. **Interrupt Controller Setup**: SystemReady requires interrupt controllers to be initialized before OS runs. If your boot code defers this to the async executor, you lose determinism. Complete interrupt routing during synchronous boot.

5. **Memory Map Fragmentation**: ACPI or devicetree hardware descriptions may fragment available memory. Your boot allocator must handle non-contiguous regions; if zero-copy IPC assumes contiguity, you'll hit allocation failures at runtime.

## What NARF Boot Should Adopt

- **Strict Handoff Validation**: Parse SystemReady firmware data, but validate every entry. Build a shadow capability graph from validated hardware descriptions.
- **Synchronous Initialization**: Keep boot fully synchronous. Defer async work only after isolation is active.
- **Devicetree for Determinism**: If targeting controlled platforms (not broad compatibility), use Devicetree band and static descriptions to minimize boot-time parsing.
- **Pre-Silicon Compliance Testing**: Use Arm's Pre-Silicon BSA/SBSA tests to catch firmware handoff bugs early.

## What NARF Boot Should Avoid

- Trusting firmware-provided addresses as capabilities directly; translate them through a validated mapping.
- Relying on ACPI runtime services for device access; resolve all via UEFI or devicetree during boot.
- Deferring interrupt or MMU setup to the async executor; these must complete synchronously.
- Assuming memory contiguity from SystemReady-compliant firmware; allocate defensively for fragmented layouts.

## Conclusion

SystemReady provides valuable standards for firmware-kernel handoff, but NARF's capability and isolation model requires an adversarial stance: assume firmware data is incomplete or malicious, validate exhaustively, and complete all security-critical setup synchronously before untrusted components run.

<https://www.arm.com/architecture/system-architectures/systemready-certification-program>
