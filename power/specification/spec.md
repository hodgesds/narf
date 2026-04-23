# power — Specification

> Status: **Outline v0.1** (Stage 2 → 4).

## 1. Purpose & scope

**Owns:**

- **CPU idle** — selection of C-state / WFI variant on idle, exit
  latency accounting, idle-time bookkeeping.
- **Frequency scaling (DVFS)** — P-state / operating-performance-
  point (OPP) selection, governor (latency vs. throughput vs.
  energy-aware), thermal-capped ceiling.
- **Suspend / resume** — S3 mem-suspend (x86_64), platform-equivalent
  on aarch64. Freeze user tasks, quiesce drivers, save state, enter
  low-power, restore.
- **Thermal management** — thermal zone monitoring, throttle
  triggers, emergency shutdown.
- **Runtime power management** — per-device PM states (D0/D1/D2/D3
  on PCIe; driver-specific elsewhere) and quiesce/wake lifecycle.
- **Governor framework** — pluggable policy objects (`governor`
  trait) that decide among C-states / P-states.

**Does NOT own:**

- Per-device power logic — each driver implements its quiesce/wake
  methods. `power/` orchestrates; drivers execute.
- CPU hot-plug mechanics — `scheduler/` §3.5. `power/` uses it.
- Time after suspend (clock fast-forward) — `time/` handles re-sync.

## 2. Assumptions

- `scheduler/` can quiesce CPUs and take them offline per §3.5.
- `time/` can pause / re-synchronise clocks around suspend/resume.
- `arch/` exposes C-state / P-state / thermal primitives.
- `drivers/` framework can iterate devices and call
  `Driver::quiesce` / `resume`.
- `tracing/` can log power transitions (with sufficient budget).

## 3. Public interface

### 3.1 Idle

```rust
pub fn idle_enter() -> !;                   // called by scheduler at empty runq
pub fn register_cstate(info: CstateInfo);   // arch backend populates at boot

pub struct CstateInfo {
    pub depth:         u8,                  // 0 = C0 (running); higher = deeper
    pub exit_latency:  Duration,            // worst-case
    pub target_residency: Duration,
    pub power_uw:      u32,                 // typical
    pub enter:         fn(),                // arch-specific instruction sequence
}
```

Default governor: **predictive**, picking the deepest C-state whose
`target_residency` is less than the predicted idle time (EWMA over
recent idle durations + upcoming hrtimer deadline from `time/`).

**`time/` `next_deadline()` contract.** `idle_enter` queries
`time::next_deadline()` to bound the C-state choice. That call is
required to be O(1) with bounded worst-case latency strictly less
than the shortest C-state's `enter` cost; the spec is enforced in
`time/` §3.2 via a per-CPU "next deadline" cache updated on every
`timer_oneshot` / `timer_cancel`. A regression in that contract
flips us into spending more time picking a C-state than we save by
entering one.

### 3.2 DVFS

```rust
pub struct Opp { pub freq_khz: u32, pub voltage_uv: u32 }

pub fn set_cpu_governor(g: impl Governor);
pub fn current_opp(cpu: CpuId) -> Opp;
pub fn request_min_freq(cpu: CpuId, khz: u32, cap: &Cap<FreqHint, Set>);

pub trait Governor {
    fn tick(&mut self, load: LoadSnapshot) -> Opp;
    fn name(&self) -> &'static str;
}
```

Built-in governors: `Performance`, `Powersave`, `EnergyAware`
(scheduler-informed). Pluggability is opt-in via `Cap<Governor, Install>`.

### 3.3 Suspend / resume

```rust
pub async fn suspend(target: SuspendTarget, cap: &Cap<Power, Suspend>) -> SuspendOutcome;

pub enum SuspendTarget { Freeze, StandbyS1, SuspendToRamS3, SuspendToDiskS4 }
pub enum SuspendOutcome { WokeUp(Cause), Aborted(Reason) }
```

Flow:

1. Freeze user tasks (scheduler refuses to pick them).
2. Call `quiesce` on every driver in reverse-start order.
3. Save remaining CPU state and enter low-power state (arch-specific).
4. On wake: restore arch state, resume drivers, unfreeze tasks,
   hand `time/` the suspend duration so it can jump forward the
   wall clock without violating monotonic.

### 3.4 Thermal

```rust
pub struct ThermalZone { pub name: &'static str, pub trips: &'static [TripPoint] }
pub struct TripPoint { pub temp_mc: i32, pub action: ThermalAction }

pub enum ThermalAction { Notify, Throttle(u8 /* percent */), EmergencyShutdown }

pub fn register_zone(z: ThermalZone);
pub fn latest_reading(zone: &str) -> Millidegrees;
```

Throttle actions call into DVFS to cap the ceiling; emergency
shutdown takes the panic path in `frame/` with a clear reason.

### 3.5 Runtime PM for devices

```rust
pub trait RuntimePm {
    /// State-preserving quiesce. Use for S1 / retention-class
    /// suspends where device registers stay powered. Driver may
    /// stop processing but does not need to save/restore state.
    async fn quiesce_freeze(&mut self, target: SuspendTarget) -> Result<(), PmError>;

    /// Power-loss quiesce. Use for S3 / S4 / D3-cold where device
    /// power is removed. Driver must save what it needs to
    /// reinitialise on `resume`. The corresponding `resume` runs the
    /// full bring-up sequence, not just an unblock.
    async fn quiesce_reset(&mut self, target: SuspendTarget) -> Result<(), PmError>;

    async fn resume(&mut self)  -> Result<(), PmError>;
    fn latency_hint(&self) -> Duration;
}
```

Drivers implementing `RuntimePm` can be autosuspended after an
idle timeout, with wake on the next request. Gated behind
`Cap<Device, PmControl>`.

**Why two quiesce variants.** A driver that has only a single
`quiesce` method must conservatively assume power loss, which means
running the full save sequence on every retention-class suspend —
expensive and pointless. The split lets the framework call the cheap
path for S1 and the expensive path only when needed, and makes the
power-loss assumption explicit at the ABI rather than hiding in
driver implementation.

## 4. Invariants & safety properties

- Suspend never returns without either `WokeUp` or `Aborted`;
  wedging is impossible (caller owns the timeout).
- C-state exit latency accounting is honest — we never enter a
  state whose worst-case exit would miss the next timer deadline.
- Thermal emergency shutdown is idempotent and signal-safe.
- DVFS changes are bounded: no transition takes longer than its
  declared `transition_latency`.
- Monotonic time never goes backwards across suspend/resume.
  Wall time jumps forward by the measured suspend duration.
- Per-driver `suspend` must be callable from the runtime or
  system-wide paths; must tolerate concurrent invocation being
  serialised by `power/`.

## 5. Architecture notes

### x86_64
- **C-states:** MWAIT + CPUID leaf 5 for supported states; newer
  CPUs expose via ACPI `_CST` objects. Default: MWAIT-based.
- **P-states:** Intel HWP (Hardware P-States) preferred; fallback
  to ACPI `_PSS`. AMD CPPC analogous.
- **Suspend:** ACPI S3 via `FADT`'s `PM1a_CNT` block; S4 via
  `hibernate` image written to a pre-configured partition.
- **Thermal:** MSR-based package temperature + ACPI thermal zones.

### aarch64
- **C-states / idle:** WFI for shallow; PSCI `CPU_SUSPEND` with
  implementation-defined state IDs for deeper.
- **P-states:** platform-specific; often CPPC via PCC mailbox on
  SystemReady boards.
- **Suspend:** PSCI `SYSTEM_SUSPEND`; `SYSTEM_OFF` / `SYSTEM_RESET`
  for shutdown/reboot.
- **Thermal:** platform-defined; often via PCC or an SCMI
  coprocessor.

## 6. Dependencies

- **Consumes:** `arch/` (C-state / P-state primitives, PSCI),
  `scheduler/` (freeze tasks, CPU hot-plug), `time/` (clock fast-
  forward), `drivers/` (iterate + quiesce), `capabilities/`,
  `interrupts/` (disable / re-enable around suspend),
  `tracing/` (power events), `frame/` (emergency shutdown).
- **Provides to:** `scheduler/` (EnergyAware governor reads + hints),
  `drivers/` (runtime PM harness), `userspace/` (suspend cap for
  a session manager in Stage 4).

## 7. Stage assignment

| Stage | Lands                                                        |
| ----- | ------------------------------------------------------------ |
| 2     | C-state registration + simple idle governor (WFI / MWAIT C1). |
| 3     | DVFS governor framework, Performance / Powersave governors, per-driver runtime PM trait. |
| 4     | Suspend-to-RAM (S3 / PSCI), thermal zones + throttling, EnergyAware governor coupled to `scheduler/`. |
| post-1.0 | S4 hibernate, deep platform states, battery / AC integration on laptop-class targets. |

## 8. Open questions

- **Tickless idle.** Linux's `NOHZ_FULL` equivalent — do we want
  per-CPU tickless operation and what does it cost the
  `time/` subsystem? Likely yes for Stage 3+.
- **E-core / P-core scheduling policy** — ties to `scheduler/` open
  question; `power/` contributes the energy model.
- **PM firmware trust.** ACPI DSDT (AML) for full PM; refuse to
  evaluate AML means losing some platforms' features. Table-only
  path for Stage 2, full AML only if needed in Stage 4.
- **S3 vs. modern standby.** Modern laptops often lack S3 entirely
  (only S0ix). Modern-standby is a very different implementation
  story; defer the decision.
- **Thermal coprocessor integration.** Many aarch64 SoCs hide
  thermal/DVFS behind SCMI; do we integrate SCMI as a bus-like
  subsystem under `bus/`?
