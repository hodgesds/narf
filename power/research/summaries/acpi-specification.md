# ACPI Specification: Power and Thermal Management

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

The Advanced Configuration and Power Interface (ACPI) specification defines the firmware-kernel interface for power management on x86/x64 platforms. It covers S-states (sleep), C-states (idle), P-states (frequency), and thermal management—essential for NARF's power subsystem on server and client platforms.

## Mechanisms

**S-States (System Sleep States):**
- **S0:** Working state; normal execution.
- **S3:** Suspend to RAM; CPU/chipset off, memory powered.
- **S4:** Suspend to disk; all state saved to disk, power off.
- **S5:** Soft off; like power-off but firmware can wake on events.

Entry into S-states requires ACPI methods (AML code) to configure chipset and CPU. Wakeup is via ACPI events (keyboard, network, timer).

**C-States (CPU Idle States):**
- **C0:** Running.
- **C1:** Halt; CPU powered, no execution.
- **C2-C3:** Deeper sleep; caches flushed, longer wakeup latency.

Entry via ACPI `_CST` method; CPU executes MWAIT or HLT instruction.

**P-States (CPU Performance States):**
Frequency/voltage pairs. Kernel requests via ACPI `_PSS` method or Hardware P-States (HWP). Transitions take microseconds to milliseconds, impacting latency-sensitive workloads.

**Device Power States (D-States):**
- **D0:** Fully powered.
- **D3Cold:** Powered off; no context preserved.

Managed via `_PSx` and `_PRx` ACPI methods.

## Key Invariants

**AML Evaluation:** ACPI methods are Firmware programs (AML bytecode) executed by the ACPI Machine Language (AML) interpreter. The kernel must evaluate these methods to change power states, trusting firmware correctness.

**Non-atomic transitions:** Power state changes (S-state, C-state entry) are not atomic. Between request and completion, various CPU/chipset states must be synchronized. Interrupts must be managed carefully.

**Memory coherency in sleep:** After S3/S4 resume, cache coherency must be re-established. Early resume code (typically written in assembly) disables caches and re-enables them, ensuring memory visibility.

## Performance Trade-Offs

**C-State latency vs. power:** Deeper C-states save more power but have longer wakeup latency (10s of microseconds to milliseconds). Real-time systems may avoid C2+ states.

**DVFS overhead:** Frequency transitions incur power draw and latency. NARF should batch transitions and use predictive governors rather than reactive scaling.

**Thermal throttling:** When thermal limits are exceeded, ACPI throttles the CPU (reducing P-state). This is automatic but impacts predictability; NARF should monitor thermal events.

## Pitfalls

1. **AML interpretation overhead:** Evaluating ACPI methods (especially in hot paths) can be slow. Linux's ACPICA library mitigates this with caching, but complex AML can cause stalls.

2. **Platform firmware bugs:** Buggy firmware AML can cause crashes or hang during power transitions. Known issues are often platform-specific; NARF should have a firmware quirks database.

3. **Interrupt races during transitions:** If an interrupt arrives during S-state entry, the system may not enter the state correctly. Firmware and OS must coordinate carefully.

4. **Wakeup event loss:** If wakeup sources (keyboard, network) are not correctly configured, the system cannot wake. NARF must track enabled wakeup events.

## Adoption Guidance for NARF

**For x86/x64:**
- **C-states:** Use C1 by default; enable C2+ only if real-time constraints permit.
- **P-states:** Integrate with the async executor: when idle, request lower P-states; on wakeup, request higher P-states to improve responsiveness.
- **S-states:** For servers, skip S3/S4 (not relevant during operation); for clients, support S3 suspend.
- **Thermal:** Monitor ACPI thermal events; throttle tasks if overtemp to preserve hardware.

**For Arm:**
- **Skip ACPI:** Most Arm platforms use device trees instead. ACPI support is limited on Arm.

**Quirks management:**
- Maintain a platform quirks list; disable specific power states on known-bad firmware.
- Test power transitions during development; don't discover firmware bugs in production.

## Reference
- ACPI Specification (UEFI Forum)
- https://uefi.org/specifications
- Linux source: `drivers/acpi/`, `drivers/cpufreq/`, `drivers/cpuidle/`
