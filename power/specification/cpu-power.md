# cpu-power — CPU power management primitives

> Status: **v0.1** (Stage 5 land). Supplements `power/specification/
> spec.md` §3 with the concrete CPU-side surface — `pstate`,
> `idle`, `rapl` — that the governor framework calls into.

This spec covers the three Tier-1 primitives the governor /
scheduler need from CPU silicon:

  * **P-states** — voltage/frequency operating points.
  * **C-states** — idle entry depths via `MWAIT`.
  * **RAPL** — Running Average Power Limit energy telemetry.

It locks the MSR set + the API shape for each so userspace
(via `narf-user-runtime::power`) and the scheduler can reason
about realised power without round-tripping through ACPI.

## 1. P-states (voltage / frequency)

### 1.1 Detection priority

Check in order; first hit wins.

| priority | mechanism                  | gate                                        |
|----------|----------------------------|---------------------------------------------|
| 1        | Intel HWP                  | CPUID(6).EAX[7] = 1                         |
| 2        | Intel SpeedStep            | CPUID(1).ECX[7] = 1 (`EIST`)                |
| 3        | AMD P-state (legacy)       | CPUID(0x8000_0007).EDX[7] = 1 (`HwPstate`)  |
| 4        | None                       | leave at firmware default                   |

The `Mechanism` enum surfaces the chosen path:
`{ Hwp, SpeedStep, AmdLegacy, None }`.

### 1.2 Intel HWP MSRs

| MSR    | name                  | purpose                                   |
|--------|-----------------------|-------------------------------------------|
| 0x770  | IA32_PM_ENABLE        | bit 0 = HWP enable (write-1, sticky)      |
| 0x771  | IA32_HWP_CAPABILITIES | min/max/efficient/guaranteed perf bytes   |
| 0x772  | IA32_HWP_REQUEST_PKG  | package-wide hints (skipped in NARF v0.1) |
| 0x773  | IA32_HWP_INTERRUPT    | interrupt-on-perf-change (off in v0.1)    |
| 0x774  | IA32_HWP_REQUEST      | per-CPU min/max/desired/EPP/activity      |
| 0x777  | IA32_HWP_STATUS       | hint observed bits                        |

`HwpRequest::write` lays out the 64-bit value:

| bits   | field                | meaning                          |
|--------|----------------------|----------------------------------|
| 7:0    | minimum_performance  | lower bound (0 = no min)         |
| 15:8   | maximum_performance  | upper bound (0xFF = max)         |
| 23:16  | desired_performance  | autonomous = 0                   |
| 31:24  | energy_perf_pref     | 0 = perf, 0xFF = power           |
| 41:32  | activity_window      | 0 = HW chooses                   |
| 42     | package_control      | 0 = per-CPU, 1 = follow PKG MSR  |

Default at boot: `min = capabilities.minimum`, `max =
capabilities.maximum`, `desired = 0`, `EPP = 0x80` (balanced).

### 1.3 Intel SpeedStep / AMD legacy

Single MSR pair:

| MSR    | name             | direction |
|--------|------------------|-----------|
| 0x198  | IA32_PERF_STATUS | read      |
| 0x199  | IA32_PERF_CTL    | write     |

Bits 15:0 of `IA32_PERF_CTL` carry the per-vendor P-state
identifier (Intel: bus ratio | voltage; AMD: P-state index 0..7).
NARF v0.1 surfaces these as opaque `u16` IDs; userspace gets the
ACPI `_PSS` mapping later when the AML evaluator lands.

AMD also exposes:

| MSR        | name             | purpose                       |
|------------|------------------|-------------------------------|
| 0xC0010061 | MSR_PSTATE_LIMIT | software P-state limit (0..7) |
| 0xC0010063 | MSR_PSTATE_STATUS| current P-state (low 3 bits)  |
| 0xC0010064 | MSR_PSTATE_DEF_0 | P-state 0 definition          |
| ...        | ...              | up to MSR_PSTATE_DEF_7        |

### 1.4 API shape

```rust
pub enum Mechanism { Hwp, SpeedStep, AmdLegacy, None }

pub struct HwpCaps {
    pub max_perf:        u8,
    pub guaranteed_perf: u8,
    pub efficient_perf:  u8,
    pub min_perf:        u8,
}

pub fn detect() -> Mechanism;
pub unsafe fn hwp_capabilities() -> HwpCaps;
pub unsafe fn hwp_set(min: u8, max: u8, desired: u8, epp: u8);
pub unsafe fn legacy_set(perf_ctl: u16);
pub unsafe fn current_status() -> u64;  // raw IA32_PERF_STATUS / HWP_STATUS
```

Test surface: `pstate::__reset_for_test()`.

## 2. C-states (idle)

### 2.1 Detection

| primitive   | gate                         |
|-------------|------------------------------|
| MONITOR/MWAIT | CPUID(1).ECX[3] = 1        |
| MWAIT extensions | CPUID(5).ECX[0] = 1     |
| MWAIT bit 1 (interrupt break) | CPUID(5).ECX[1] = 1 |

CPUID leaf 5 also reports the depth supported (number of
sub-C-states for each MWAIT C-state ECX value).

### 2.2 MWAIT encoding

`MWAIT EAX` carries `(C-state-hint << 4) | sub-state`:

| EAX byte | meaning                             |
|----------|-------------------------------------|
| 0x00     | C1                                  |
| 0x01     | C1E (Intel) — sub-state 1           |
| 0x10     | C2                                  |
| 0x20     | C3                                  |
| 0x30     | C4 / no-OS-control                  |
| 0x40     | C6                                  |
| 0x50     | C7                                  |

`MWAIT ECX` bit 0 = "interrupts can break out" (always set in
NARF — we want IPI / timer to wake).

### 2.3 Idle-loop wiring

`idle::halt()` is the universal entrypoint called from the
kernel's per-CPU idle task. Behaviour:

  1. If `mwait_supported()` and the current C-state policy
     allows depth `d`: arm MONITOR on a per-CPU dummy address,
     then `MWAIT EAX = encode(d)`.
  2. Else: `STI; HLT`.
  3. Wake: any IRQ.

Default policy at boot: deepest C-state offered by CPUID 5
(QEMU TCG advertises C1 only; Intel hosts up to C7 / C10).

### 2.4 API shape

```rust
pub struct MwaitCaps {
    pub supported:       bool,
    pub interrupt_break: bool,
    /// Sub-state count per C-state (4-bit nibbles) from CPUID(5).EDX.
    pub sub_states:      u32,
    /// Number of architectural C-states the CPU supports.
    pub max_cstate:      u8,
}

pub fn caps() -> MwaitCaps;
pub unsafe fn enter_cstate(depth: u8);
pub unsafe fn idle();   // policy-driven; the canonical entry
```

## 3. RAPL energy telemetry

### 3.1 Detection

Intel: CPUID(6).EAX[14] = 1 (RAPL counters present).
AMD: starting Family 17h, the same MSR layout is implemented;
detect via CPUID(0x8000_0007).EDX[12] (`HwPstate`) AND the
presence of `MSR_AMD64_RAPL_POWER_UNIT` (read returning a non-
zero unit triple).

### 3.2 MSR set

| MSR    | name                       | scope     |
|--------|----------------------------|-----------|
| 0x606  | MSR_RAPL_POWER_UNIT        | unit decode (per-domain) |
| 0x611  | MSR_PKG_ENERGY_STATUS      | package energy (32-bit J) |
| 0x639  | MSR_PP0_ENERGY_STATUS      | core domain |
| 0x641  | MSR_PP1_ENERGY_STATUS      | uncore / iGPU |
| 0x619  | MSR_DRAM_ENERGY_STATUS     | DRAM (server SKUs) |
| 0x614  | MSR_PKG_POWER_INFO         | thermal design power info |

`MSR_RAPL_POWER_UNIT` (0x606):

| bits   | field            | meaning                          |
|--------|------------------|----------------------------------|
| 3:0    | power_units      | watts = `1.0 / 2^value`          |
| 12:8   | energy_units     | joules = `1.0 / 2^value`         |
| 19:16  | time_units       | seconds = `1.0 / 2^value`        |

### 3.3 Joule decode

```rust
let raw_j = rdmsr(0x611);                  // u32 in low half
let joules_per_unit = 1.0 / (1 << energy_units);
let joules = (raw_j as u64 * 1_000_000) >> energy_units;  // µJ
```

NARF returns µJ (microjoules) as an integer to avoid float
in the kernel.

### 3.4 Counter wraparound

`MSR_*_ENERGY_STATUS` is a 32-bit counter that wraps; consumers
must take a snapshot delta. The driver exposes `read_pkg_uj()`
returning the raw 32-bit value scaled by the unit; the
governor / observability surface caches deltas across reads.

### 3.5 Thermal sibling

| MSR    | name                            | purpose       |
|--------|---------------------------------|---------------|
| 0x19C  | MSR_IA32_THERM_STATUS           | per-CPU temp  |
| 0x1B1  | MSR_IA32_PACKAGE_THERM_STATUS   | package temp  |
| 0x1A2  | MSR_TEMPERATURE_TARGET          | TjMax (°C)    |

Read pattern: `temp_c = TjMax - ((THERM_STATUS >> 16) & 0x7F)`.
TjMax is exposed in bits[23:16] of `MSR_TEMPERATURE_TARGET`.

### 3.6 API shape

```rust
pub struct EnergyUnits {
    pub power_uw_per_unit:  u64,
    pub energy_uj_per_unit: u64,
    pub time_us_per_unit:   u64,
}

pub fn is_supported() -> bool;
pub unsafe fn units() -> EnergyUnits;
pub unsafe fn read_pkg_uj() -> u64;
pub unsafe fn read_pp0_uj() -> u64;
pub unsafe fn read_pp1_uj() -> Option<u64>;   // None on server SKUs
pub unsafe fn read_dram_uj() -> Option<u64>;
pub unsafe fn read_temp_c() -> Option<u8>;
pub unsafe fn read_pkg_temp_c() -> Option<u8>;
```

## 4. Cross-reference

`scheduler/` consumes `pstate::Mechanism` + `idle::caps` to
decide whether the boot CPU can offer deep idle. `observability/`
consumes RAPL deltas for energy-aware tracing. `governor` (the
trait defined in `power/spec.md` §3) reads + writes
`hwp_set` / `legacy_set` based on the workload classification it
synthesises; v0.1 of NARF ships only the trivial "balanced"
governor that holds HWP at the mid-range default.

## 5. Test surface

Smokes (kernel-test):

| smoke                                | what it asserts                |
|--------------------------------------|--------------------------------|
| `pstate_detect_mechanism`            | `detect()` returns a sane variant |
| `pstate_hwp_caps_when_supported`     | min ≤ max, all bytes non-zero  |
| `idle_caps_decode_cpuid5`            | `caps().supported` matches CPUID(1) |
| `rapl_unit_decode_plausible`         | unit fields ≤ 0x1F, energy_units in [10..18] |
| `rapl_pkg_uj_advances`               | two reads with a busy-wait between yield monotonic increase (skip on TCG) |

## 6. Out of scope (v0.1)

- Per-package vs per-core HWP request differentiation.
- HWP autonomous activity-window tuning.
- Intel HFI / Thread Director (separate spec).
- ACPI _PSS / _CST evaluation (no AML).
- AMD CPB (Core Performance Boost) toggle.
- Suspend-to-RAM lifecycle (S3); covered by `power/spec.md` §4.
- RAPL package power limits (write to MSR 0x610); read-only in v0.1.
