# Arm System Control and Management Interface (SCMI)

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

Arm SCMI is a standardized protocol for OS-firmware communication on Arm platforms. It abstracts vendor-specific power management, clock, and sensor interfaces (performance domains, clock domains, thermal sensors). NARF can use SCMI for CPU frequency scaling and power state management.

## Mechanisms

**Performance Domains (DVFS):**
SCMI allows the OS to query and set CPU performance levels (equivalent to P-states on x86). Each performance domain (e.g., CPU cluster) supports a set of discrete performance levels with associated frequency and voltage.

**Clock Domains:**
The OS can query and set clock frequencies for individual clock domains (e.g., GPU, memory controller). This enables dynamic clock gating for power saving.

**Power Domains:**
Similar to PSCI C-states, but with explicit power state descriptors. The OS can request specific power states and query entry/exit latencies.

**Sensor Interface:**
Firmware provides thermal, power, and voltage sensor readings via SCMI. The OS can poll sensors to detect overtemp conditions.

**Event Notification:**
SCMI supports firmware-initiated events (thermal alerts, performance throttling) that interrupt the OS via notifications.

## Key Invariants

**Discrete performance levels:** Unlike software-controlled DVFS (Linux cpufreq with frequency scaling), SCMI offers a discrete set of performance levels. The OS selects the closest level to its desired frequency.

**Latency transparency:** SCMI queries (frequency, power state) may incur latency (milliseconds for vendor firmware). Real-time operations should cache results.

**Topology independence:** SCMI abstracts vendor-specific implementations. A single NARF kernel can support multiple platforms (Arm SVE, Cavium, Broadcom) via SCMI.

## Performance Trade-Offs

**Firmware latency:** SCMI calls incur firmware overhead. Batching frequency updates (once per idle period) is more efficient than per-interrupt updates.

**Performance level granularity:** Discrete levels are coarser than software DVFS. NARF may not hit optimal frequency for every workload but gains simplicity and power efficiency.

**Latency impact:** Frequency transitions take microseconds to milliseconds. Real-time tasks should avoid low-latency guarantees during transitions.

## Pitfalls

1. **Transient frequency oscillation:** If the OS requests frequency changes too frequently (e.g., on every task arrival), the system oscillates between levels, wasting power and impacting stability.

2. **Thermal throttling races:** If firmware throttles due to overtemp while the OS requests higher frequency, conflicts arise. NARF must respect firmware throttling decisions.

3. **Incomplete implementation:** Not all SCMI agents implement all protocols. NARF must gracefully degrade if performance or power domain protocols are missing.

4. **Clock synchronization:** If the OS changes clock domains (e.g., for GPU), dependent subsystems (memory controller, cache) must be synchronized. NARF should avoid dynamic clock changes unless necessary.

## Adoption Guidance for NARF

**DVFS Strategy:**
- Query performance domains at boot; cache topology.
- Use a simple governor: if CPU utilization > threshold, request higher level; if < threshold, request lower.
- Update levels once per scheduler tick (e.g., 10ms), not per task.
- Respect firmware throttling (if current level is unavailable, use the closest lower level).

**Sensor Polling:**
- Poll thermal sensors periodically (e.g., every 100ms).
- If temperature exceeds a threshold, throttle to the lowest performance level and invoke emergency cooling (halt some CPUs).

**Event Handling:**
- Register for SCMI thermal alerts; react immediately if firmware raises an alert.

**Fallback:**
- If SCMI is unavailable, use PSCI CPU_SUSPEND with hardcoded power states, or skip power management entirely.

## Reference
- Arm System Control and Management Interface (SCMI) Specification
- https://developer.arm.com/documentation/den0056/latest/
- Linux driver: `drivers/firmware/arm_scmi/`
