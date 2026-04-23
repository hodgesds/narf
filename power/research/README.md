# power — Research

## Primary sources

- **ACPI Specification** — S-states, C-states, P-states, thermal.
  <https://uefi.org/specifications>
- **Intel SDM Vol. 3B — Chapter 14 (Power and Thermal Management)**
  and HWP discussion.
- **AMD CPPC** — `CPPC` specification in AMD system programming guides.
- **Arm Power State Coordination Interface (PSCI) Specification**.
  <https://developer.arm.com/documentation/den0022/latest/>
- **Arm SCMI Specification** (System Control and Management Interface).
  <https://developer.arm.com/documentation/den0056/latest/>
- **CPPC for Arm (ACPI)** — CPU performance control on aarch64 servers.

## Secondary sources

- **Linux `drivers/cpuidle/`, `drivers/cpufreq/`, `kernel/power/`** —
  canonical reference implementations.
- **`tlp` / `powertop`** — diagnostic tools describing what good PM
  looks like on Linux.
- **Intel "Idle Micro-benchmarks and Governor Design" papers / docs**
  — motivation for predictive idle governors.
- **"Modern Standby" (Microsoft)** — what S0ix replaces S3 with on
  many laptops; design consideration for Stage 4+.

## Distilled summaries

- `summaries/acpi-specification.md` — ACPI S/C/P/D-states, AML evaluation, power transitions
- `summaries/arm-psci.md` — ARM PSCI, CPU on/off/suspend, power state coordination
- `summaries/arm-scmi.md` — Arm SCMI, performance domains, DVFS, sensor interface

## Open research questions

- Energy-aware scheduling accuracy without per-core power telemetry —
  is platform-reported energy good enough?
- AML evaluation cost: can we bound it? Fuchsia's ACPICA integration
  has lessons here.
- DVFS transition latency vs. hard real-time deadlines — `scheduler/`
  deadline tasks may want to veto transitions.
