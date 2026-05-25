# Intel-compat audit — CPU/platform/timer code

Date: 2026-05-25. Post-Renoir-bringup. Focus: AMD-isms that will
break (or under-perform) on Intel silicon.

## arch/src/x86_64/cpuid.rs
- `Features` struct (line 47-58) probes x2APIC, TSC-deadline,
  invariant TSC, but **does not probe ARAT** (CPUID 0x06 EAX[2]).
  Linux uses ARAT to keep the LAPIC timer running through C3 and
  to bump its clockevent rating above HPET. Without ARAT detection
  we have no way to know whether the LAPIC timer can be trusted in
  deep C-states on Intel. **Fix**: add `arat` flag.

## arch/src/x86_64/tsc.rs
- `calibrate_via_amd_pstate0` (line 129-196) is Family-0x17+
  AMD-only by design — fine.
- **Missing Intel fallback**: between CPUID 0x16 (which only
  reports MHz precision and may be zero on virtualised hosts) and
  the HPET cross-check, there is no `MSR_PLATFORM_INFO` (0xCE)
  read. Linux uses `cpu_khz_from_msr()` on Sandy Bridge+ Intel
  where the max non-turbo ratio in bits[15:8] × 100 MHz BCLK gives
  the TSC base frequency. **Fix**: add `from_msr_platform_info()`.

## time/src/lib.rs
- `CalibrationSource` enum (line 370-390) names the Intel paths
  (CpuId15h, CpuId16h) and AMD path (AmdPstate0) but has no slot
  for `MSR_PLATFORM_INFO`. **Fix**: add `IntelPlatformInfo` variant
  and wire it into the calibration pipeline between CpuId16h and
  AmdPstate0 (so Intel Skylake+ without 0x15 crystal still gets a
  good answer before AMD-specific MSR access is attempted).
- The `apply_cycles_per_ns` (line 496-505) clamps cpns to ≤ 6,
  which holds for current Intel/AMD; fine.
- Documentation in `calibrate_clocks_with_source` (line 428-435)
  asserts a Zen4 laptop "should land on AmdPstate0" but doesn't
  document the Intel expectation; comment-only improvement.

## interrupts/src/x86_64/apic.rs
- `LapicClockEvent::resolution_ns` (line 364-367) hardcodes 160 ns
  based on a "100 MHz post-divide" assumption. On TSC-deadline
  mode the resolution is one TSC tick (~0.25-0.5 ns on modern
  CPUs); on Intel parts with ARAT the resolution is "as good as
  TSC." **Fix**: when TSC-deadline is active use TSC resolution.
- xAPIC fallback paths (post-d677c61) cover EOI / apic_id /
  error / wrmsr_icr / self_ipi — these look correct. The init
  path two-step WRMSR (EN, then EXTD) is the canonical Linux
  sequence, no AMD/Intel difference.
- `start_timer` (line 229-275) periodic-InitialCount path uses
  DIV_16; the "100 MHz raw bus → 6.25 MHz" assumption is AMD-
  centric. Intel parts can use 1.6 GHz / 16 = 100 MHz post-divide
  on Skylake. The fallback `initial_count = 10_000` (line 344)
  is intentionally conservative — fast on any plausible bus — so
  not a bug, just a deliberate undershoot. No action.

## interrupts/src/x86_64/timer_pump.rs
- `pick_gsi` (line 83-104) has hard-coded legacy reservations
  (0=PIT, 1=i8042, 8=RTC, 13=FPU). These are PC-standard, not
  AMD-specific. No action.
- IOAPIC delivery uses `POLARITY_HIGH | TRIGGER_LEVEL` (line 239)
  for HPET — matches HPET spec, not AMD-specific. No action.

## interrupts/src/x86_64/hpet_clockevent.rs
- FSB-MSI preferred over IOAPIC GSI for HPET (line 132-163).
  Comment notes "platforms (Renoir) where the IOAPIC silently
  drops HPET's GSI" — also helps on Intel Cherry Trail. No
  action; behaviour already platform-agnostic.

## time/src/hpet.rs
- HPET register layout + arming sequence is per Intel HPET spec
  rev 1.0a — vendor-neutral. No action.

## power/src/pstate.rs
- `amd_pstate_summary` (line 391) — AMD-only by design.
  Intel-side mirror would be `IA32_PERF_STATUS` / `IA32_HWP_STATUS`
  decode, but boot diagnostics for Intel can read HWP capabilities
  directly. Out of scope for this pass.
</content>
</invoke>