# power — Design Notes

> 2026-04-22. Author: Claude Sonnet 4.6 (design-phase analysis).

---

## Load-bearing decisions

**The Governor trait is pluggable but the default is predictive.** §3.1 specifies the default idle governor as "predictive" — EWMA over recent idle durations + next hrtimer deadline. This is the right default (avoids the Linux `menu` governor's pathological cases on uniform workloads), but it is critically dependent on `time/` providing the next-timer-deadline with low latency. The `idle_enter()` function must query `time/`'s timer wheel *before* selecting the C-state, and the timer wheel lookup must be cheaper than the cheapest C-state entry. If `time/` §3.2 does not provide an O(1) `next_deadline()` function, the idle governor is forced to use a conservative (shallow) C-state, negating power savings.

**Suspend completeness is the spec's weakest point.** The suspend flow in §3.3 says: freeze tasks → quiesce drivers → save CPU state → enter low-power → restore → resume drivers → unfreeze. This is correct at the highest level of abstraction but leaves several hard problems unaddressed: (1) the executor has in-flight Futures that cannot be "frozen" at an arbitrary point — only at an await. The freeze must happen at quiescent points in all domain tasks, which requires cooperation from every active Future. (2) Interrupt state — disabled/re-enabled around suspend — is mentioned in §6's dependencies but the sequence is not specified. (3) Device state across S3: PCIe devices lose power; their driver must re-initialize them fully on resume, not just resume from a D3cold snapshot. The spec implies `Driver::quiesce` / `resume` handles this, but the contract for drivers emerging from true power loss vs. simple quiesce is not distinguished.

**The thermal emergency shutdown path calls `frame/`'s panic path.** §3.4 states "emergency shutdown takes the panic path in `frame/` with a clear reason." This is a hard coupling: thermal events, which can be asynchronous hardware interrupts, must be able to call into the panic path safely. The panic path must be reentrant-safe (it may already be executing for a different reason) and must not block on anything that requires power. This constraint should be in `frame/`'s invariants, not buried in `power/`'s description.

**DVFS governor `tick()` is synchronous — this is a hidden SMP hazard.** The `Governor::tick(load: LoadSnapshot) -> Opp` signature is a synchronous call. On an SMP system, the "load" snapshot is across all CPUs, but P-state transitions affect per-cluster (or per-CPU) frequency domains. The governor tick must know which frequency domain it is operating on, and calling it from the scheduler's idle path on CPU N with a system-wide `LoadSnapshot` creates a race: by the time the tick returns an `Opp`, the load on other CPUs may have changed. Either the governor must be per-domain (frequency domain, not PKS domain) or the tick must be serialized per frequency domain with a lock or message.

**AML evaluation is blocked until Stage 4, but C-states on x86_64 require it.** §5 says C-states are obtained via ACPI `_CST` objects for newer CPUs, with MWAIT as the default. The MWAIT fallback works for C1 only; deeper C-states (C3, C6, C7) almost universally require AML to configure the CPU correctly. The Stage 2 target is "WFI / MWAIT C1" — fine for development — but the note in §8 "Table-only path for Stage 2, full AML only if needed in Stage 4" is optimistic. On Intel laptops (the obvious development target), C3+ saves 3-5 W vs. C1. Deferring AML to Stage 4 means NARF will run hot and drain battery through all of Stages 2 and 3. This is a developer experience problem, not just a feature gap.

---

## Divergences from precedent

**Linux `cpuidle` governor is not predictive by default.** Linux defaults to the `menu` governor (latency-constrained selection) with `teo` as a newer alternative. The `menu` governor is historically complex and error-prone on tickless systems. NARF choosing a predictive EWMA-based governor from the start is the right divergence. The risk is implementation: an EWMA that tracks the wrong thing (e.g., average wake latency instead of time-between-wakes) will systematically undersleep. The governor design must be validated against pathological workloads: 100 µs periodic timer, 10 ms sporadic wakeup, and the sleeping-on-a-busy-runq case (should not enter any C-state).

**Linux `cpufreq` is a framework with 6+ drivers and governors; NARF starts with 3 governors and a clean trait.** This is the right call — complexity can be added. But Linux's lesson is that `performance` and `powersave` governors are trivially implemented but the interesting one is `schedutil` (now `EnergyAware` in NARF's naming), which requires tight integration with the scheduler. NARF defers `EnergyAware` to Stage 4, but the governor trait's `tick(load: LoadSnapshot)` signature must be designed now to support it. `LoadSnapshot` needs to carry per-CPU runqueue depth, recent utilization, and estimated next wakeup — this is not a simple type.

**Fuchsia's ACPICA integration:** Fuchsia uses ACPICA (the reference AML interpreter) as a component. Integrating ACPICA into a Rust kernel is non-trivial (C FFI, unbounded stack usage in AML evaluation, table trust issues). If NARF targets x86_64 seriously, it will eventually need either ACPICA, a partial Rust AML evaluator, or a severely restricted "table-only" mode that works for only a fraction of real hardware. The research summary notes "AML evaluation cost: can we bound it?" — the answer is no, you cannot bound AML in general. Plan for ACPICA via a sandboxed domain (it gets its own PKS key and runs in an isolated domain) rather than assuming table-only coverage is sufficient.

**PSCI for aarch64 is clean by comparison.** PSCI is well-specified, firmware is generally trustworthy on server platforms, and CPU_SUSPEND / SYSTEM_SUSPEND have predictable latency. The aarch64 power story is simpler than x86_64's. However, the SCMI research summary reveals that DVFS on aarch64 is *not* part of PSCI — it goes through a separate SCMI channel to a firmware agent (often a Cortex-M coprocessor). The `arch/` HAL for `set_cpu_governor` on aarch64 must abstract over SCMI, and SCMI itself may have millisecond latency per call. The governor tick rate (every scheduler tick?) may be incompatible with SCMI's latency floor.

---

## Proposed spec changes

- **§3.1 Idle — add O(1) next_deadline contract:** "Before selecting a C-state, `idle_enter()` queries `time/`'s `next_deadline()` for the calling CPU's hrtimer horizon. This call must be O(1) and have bounded worst-case latency less than the shortest C-state entry cost. `time/` §3.2 must provide this contract." This makes the idle→time dependency explicit and sets a concrete perf requirement.

- **§3.3 Suspend — distinguish quiesce-for-resume vs. quiesce-for-power-loss:** Split `Driver::quiesce` into two cases: `quiesce_freeze(reason: SuspendTarget)` for S1/retention (device state preserved) and `quiesce_reset(reason: SuspendTarget)` for S3/power-loss (driver must fully reinitialize on resume). This avoids drivers assuming their registers are preserved after a deep sleep.

- **§3.2 DVFS — add frequency-domain ID to Governor::tick:** Change `fn tick(&mut self, load: LoadSnapshot) -> Opp` to `fn tick(&mut self, domain: FreqDomainId, load: DomainLoadSnapshot) -> Opp`. Per-domain governors prevent the cross-CPU TOCTOU race and enable heterogeneous-core (P+E-core) policies.

- **§4 Invariants — add SCMI latency acknowledgement for aarch64:** Add: "On aarch64, DVFS transitions via SCMI may take up to the declared `transition_latency` of the OPP, which for SCMI-backed platforms may be in the hundreds of microseconds. `scheduler/` deadline tasks must be able to veto a DVFS transition if the transition would violate their deadline." Define a `FreqVeto` mechanism or note it as a `power/`-to-`scheduler/` callback.

- **§8 Open questions — upgrade AML decision to pre-Stage-4 mandatory:** "The AML evaluation strategy must be decided before Stage 4 begins: ACPICA in a sandboxed PKS domain, a restricted Rust evaluator, or explicit table-only with documented platform incompatibilities. This affects C3+ support, which impacts developer power consumption during Stages 2–3."

- **§3.4 Thermal — add uniqueness requirement for zone names:** `register_zone` takes `name: &'static str` but there is no uniqueness check. Add: "`register_zone` panics in debug and returns `Err(ZoneAlreadyRegistered)` in release if a zone with the same name already exists."

---

## Open invariants / cross-subsystem hazards

**`scheduler/` §3.5 (CPU hot-plug) and `power/` S3 suspend:** S3 suspend must quiesce all CPUs. The spec says `scheduler/` is responsible for hot-plug mechanics and `power/` uses it. But S3 is not a hot-plug — it is a full system quiesce including the boot CPU. The protocol for quiescing the scheduler's executor on the boot CPU is different from offloading a secondary CPU. NARF's global async executor does not have a documented "pause all" interface; this needs to be designed jointly by `power/` and `scheduler/` before Stage 4 or S3 will be a fire drill.

**`time/` §? clock fast-forward on resume:** §3 says `time/` "pauses/re-synchronizes clocks around suspend/resume." The power spec says "monotonic time never goes backwards across suspend/resume; wall time jumps forward by the measured suspend duration." The measurement of suspend duration is problematic: the RTC is the only source of elapsed time during S3, and RTC accuracy is ±1 second on cheap hardware. If NARF measures suspend duration via RTC delta, the wall clock jump is coarse. The `time/` spec needs to document its precision commitment for the post-S3 time jump and acknowledge the RTC accuracy floor.

**`interrupts/` §? disable/re-enable around suspend:** §6 lists `interrupts/` as a dependency for suspend. But which interrupts must be disabled and when? On x86_64, local APIC timer must be stopped before entering S3 (otherwise a missed tick can prevent wake). GICv3 on aarch64 has similar requirements. The interaction between `power/` and `interrupts/` needs a protocol: `power/` calls `interrupts::quiesce_for_suspend()` and `interrupts::resume_from_suspend()` in defined positions in the suspend sequence.

**`drivers/` quiesce ordering and dependency between drivers:** The spec says `power/` iterates devices in reverse-start order for quiesce. But drivers can have dependencies (e.g., the NVMe driver depends on PCIe, which depends on the IOMMU driver). Quiescing out-of-order can cause bus errors. The `bus/` subsystem must expose the correct dependency-ordered quiesce sequence, not just a flat reverse-start list. This is a `power/`-to-`bus/` cross-subsystem invariant not documented in either spec.

---

## Additional opinionated commentary

The power spec is the most "Linux-port" feeling of all the subsystem specs — it faithfully enumerates ACPI/PSCI/SCMI mechanisms without deeply questioning whether they fit the framekernel model. The Governor trait is clean, but the broader question — "who has `Cap<FreqHint, Set>` and who decides?" — is not addressed. On Linux, userspace tools (tlp, powertop, thermald) manage power policy; on NARF with no root, the policy must come from a capability-holding session manager. That session manager does not exist in Stages 1–3. The power subsystem will therefore spend its first two stages with hard-coded performance governors and no runtime policy adjustment, which is fine for a kernel under development but must be acknowledged explicitly rather than implied by the deferred Stage 4 items.

The EnergyAware governor is the most interesting item in the spec and the most hand-wavy. "Scheduler-informed" means the scheduler must publish per-CPU utilization data that the governor consumes. On a real SoC with asymmetric cores (Cortex-X + Cortex-A), the governor must also have an energy model (power per operation point per core type). Neither the energy model format nor the scheduler-to-governor data path is specified. Linux's EAS (Energy Aware Scheduling) took years to converge; NARF should either prototype a simpler form or explicitly scope it as a research item rather than a Stage 4 deliverable.
