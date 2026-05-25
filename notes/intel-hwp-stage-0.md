# Intel HWP — Stage-0 summary + activation

Date: 2026-05-25. Companion to `power/src/hwp.rs`.

## What landed

A new `hwp` module in `power/src/` that:

- Vendor-gates on `GenuineIntel` (silent return for AMD — the
  cpu-pstate initcall serves both vendors).
- Probes CPUID 0x06 EAX (bits 7/8/9/10/11/20:
  base/notification/activity_window/EPP/PLR/fast-write).
- Reads `IA32_HWP_CAPABILITIES` (0x771) via `rdmsr_or_gp` so a
  BIOS-locked / hypervisor-redirected read surfaces as
  `HwpSummary::CapabilitiesGp` instead of wedging boot.
- Decodes the four 8-bit perf values (highest / guaranteed /
  efficient / lowest) and converts to approximate MHz using
  `base_mhz * perf / guaranteed_perf`, where `base_mhz` comes from
  CPUID 0x16 or `MSR_PLATFORM_INFO` × 100 MHz BCLK.
- Activates HWP via `wrmsr_or_gp(IA32_PM_ENABLE, 1)` (sticky;
  idempotent re-entry) and programs `IA32_HWP_REQUEST` with
  min=lowest, max=highest, desired=0 (autonomous), EPP=0x80.
- Returns a structured `HwpSummary` so callers / tests can
  distinguish each `#GP` outcome from the happy path.

Wired into the existing `cpu-pstate` Stage::Subsys initcall
alongside `amd_pstate_summary()`. Each is vendor-gated; only one
emits a log line on a given host.

Smokes: feature probe shape, CAPABILITIES bitfield order +
reserved-high-half mask, vendor-gated summary alignment with
`pstate::detect()`.

## QEMU TCG

`-cpu max` reports `AuthenticAMD` (TCG default) → summary returns
`NotIntel`, silent. Intel models (`SandyBridge`, `Skylake-Server`,
etc.) advertise `GenuineIntel` but don't populate CPUID 0x06
EAX[7] → `hwp: not supported`. Both validated via
`NARF_QEMU_CPU=... cargo xtask run --arch=x86_64 --display none`.

## Out of scope (Stage-1+)

- cpufreq policy / governor wiring (governor → REQUEST per CPU).
- `IA32_HWP_INTERRUPT` (0x773) — needs IDT vector + handler.
- `IA32_HWP_STATUS` (0x777) excursion telemetry.
- Per-AP programming — BSP only today; APs need their own
  REQUEST write from `frame/src/x86_64/smp.rs`.

## References

- Intel SDM Vol 4 §2.16 — HWP MSR layout
- Intel SDM Vol 3B §14.4 — Hardware-Controlled Performance States
- Linux `drivers/cpufreq/intel_pstate.c::intel_pstate_hwp_enable`
  / `::intel_pstate_get_hwp_cap` — same activation order
