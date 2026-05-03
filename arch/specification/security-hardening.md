# security-hardening — CPU-side defensive primitives

> Status: **v0.1** (Stage 5 land). Supplements
> `arch/specification/spec.md` §3 with the CPU-side surface for
> three security/observability hardening features.

This spec covers:

  * **CET** — Intel Control-flow Enforcement Technology: shadow
    stacks + Indirect Branch Tracking.
  * **PEBS** — Precise Event-Based Sampling: per-event records
    streamed to an OS-supplied buffer.
  * **Boot CPU validation** — assert the architectural baseline
    NARF assumes (invariant TSC, NX, SMEP, SMAP, UMIP, WRGSBASE,
    PCID, x2APIC) is actually enabled on this silicon before we
    rely on it.

It locks the MSR / CR / CPUID surface so that `frame/`,
`memory/`, and `observability/` can be coded against it.

## 1. CET (Control-flow Enforcement)

### 1.1 Detection

CPUID(7, 0).ECX[7]  = `CET_SS` (shadow stack).
CPUID(7, 0).EDX[20] = `CET_IBT` (indirect branch tracking).

Both gated independently. NARF enables whichever the silicon
advertises; missing features no-op.

### 1.2 Control bits

CR4.CET (bit 23) — global gate. Required to enable either path.

### 1.3 MSRs

| MSR    | name          | scope             |
|--------|---------------|-------------------|
| 0x6A0  | IA32_U_CET    | user (CPL=3) CET cfg |
| 0x6A2  | IA32_S_CET    | supervisor (CPL=0) CET cfg |
| 0x6A4  | IA32_PL0_SSP  | shadow stack pointer for CPL 0 |
| 0x6A5  | IA32_PL1_SSP  | CPL 1 |
| 0x6A6  | IA32_PL2_SSP  | CPL 2 |
| 0x6A7  | IA32_PL3_SSP  | CPL 3 |
| 0x6A8  | IA32_INTERRUPT_SSP_TABLE | per-CPU interrupt SSP table |

`IA32_U_CET` / `IA32_S_CET` shape (per SDM §17.2.3):

| bits | field                          |
|------|--------------------------------|
| 0    | SH_STK_EN — shadow stack enable |
| 1    | WR_SHSTK_EN — allow `WRSS`      |
| 2    | ENDBR_EN — IBT enable           |
| 3    | LEG_IW_EN — legacy IBT path     |
| 4    | NO_TRACK_EN — `NOTRACK` prefix legal |
| 5    | SUPPRESS_DIS                    |
| 6    | reserved (write 0)              |
| 9    | SUPPRESS                        |
| 10   | TRACKER (set by HW when waiting for ENDBR) |
| 63:12 | EB_LEG_BITMAP_BASE             |

### 1.4 API shape

```rust
pub struct CetCaps {
    pub shadow_stack:   bool,
    pub ibt:            bool,
    pub cr4_cet:        bool,
}

pub fn caps() -> CetCaps;
pub unsafe fn enable_supervisor(shadow_stack: bool, ibt: bool);
pub unsafe fn enable_user(shadow_stack: bool, ibt: bool);
pub unsafe fn write_pl0_ssp(addr: u64);
pub unsafe fn read_pl0_ssp() -> u64;
```

CR4.CET is set by `enable_supervisor` / `enable_user` on first
use; subsequent calls preserve it.

## 2. PEBS

### 2.1 Detection

CPUID(0xA, 0).EAX[7:0] >= 1 + the model-specific PEBS feature
bit reported indirectly by `IA32_MISC_ENABLE.PEBS_UNAVAILABLE`
(bit 12 of MSR 0x1A0 — when set, PEBS is *disabled*).

### 2.2 DS Save Area

PEBS streams records into the Debug-Store buffer described by
`MSR_IA32_DS_AREA` (0x600). Layout (SDM Vol 3 §19.6.1.1):

```
struct DebugStoreSaveArea {
  u64 bts_buffer_base;
  u64 bts_index;
  u64 bts_absolute_max;
  u64 bts_interrupt_threshold;
  u64 pebs_buffer_base;
  u64 pebs_index;
  u64 pebs_absolute_max;
  u64 pebs_interrupt_threshold;
  u64 pebs_counter_reset[8];
}
```

`pebs_buffer_base` points at the first byte; `pebs_index` is
where the CPU writes the next record (initialise to base).
`pebs_absolute_max` = base + (capacity * record_size); when
the index reaches `pebs_interrupt_threshold` the CPU raises
PMI.

### 2.3 PEBS records

Skylake+ "basic" PEBS record is 192 bytes laid out as the GPRs
+ EIP + various counts. The record format is model-specific;
NARF v0.1 captures the raw bytes + lets userspace decode.

### 2.4 MSRs

| MSR    | name                          |
|--------|-------------------------------|
| 0x600  | IA32_DS_AREA                  |
| 0x3F1  | MSR_PEBS_ENABLE               |
| 0x3F7  | MSR_PEBS_DATA_CFG (Skylake+)  |
| 0x1A0  | IA32_MISC_ENABLE              |

`MSR_PEBS_ENABLE` bit `i` enables PEBS for `IA32_PMCi`.

### 2.5 API shape

```rust
pub struct PebsBuffer {
    pub base:               u64,
    pub capacity_records:   u32,
    pub record_size:        u32,
    pub interrupt_threshold:u64,
}

pub fn supported() -> bool;
pub unsafe fn install_ds(ds_area_phys: u64, pebs: PebsBuffer);
pub unsafe fn enable(general_mask: u32);
pub unsafe fn disable();
pub unsafe fn current_index() -> u64;
```

## 3. Boot CPU validation

### 3.1 Required-feature matrix

Validated at boot before NARF starts using the corresponding
mechanism:

| feature        | source                          | required? |
|----------------|--------------------------------|-----------|
| Long Mode      | CPUID(0x80000001).EDX[29]       | yes       |
| RDTSCP         | CPUID(0x80000001).EDX[27]       | yes       |
| Invariant TSC  | CPUID(0x80000007).EDX[8]        | yes       |
| NX             | CPUID(0x80000001).EDX[20]       | yes       |
| SMEP           | CPUID(7, 0).EBX[7]              | yes       |
| SMAP           | CPUID(7, 0).EBX[20]             | yes       |
| UMIP           | CPUID(7, 0).ECX[2]              | recommended (warn if missing) |
| WRGSBASE       | CPUID(7, 0).EBX[0]              | yes       |
| PCID           | CPUID(1).ECX[17]                | recommended |
| x2APIC         | CPUID(1).ECX[21]                | recommended |
| XSAVE          | CPUID(1).ECX[26]                | yes       |

### 3.2 Control-register enable matrix

Validated separately — features can be in CPUID but not enabled
in CR4 / EFER:

| bit              | required value at NARF runtime |
|------------------|--------------------------------|
| EFER.LME         | 1                              |
| EFER.NXE         | 1 (gates NX bit in PTEs)       |
| CR4.PAE          | 1                              |
| CR4.PGE          | 1 (global pages; perf)         |
| CR4.OSFXSR       | 1 (XMM context save)           |
| CR4.OSXMMEXCPT   | 1                              |
| CR4.OSXSAVE      | 1                              |
| CR4.SMEP         | 1 if CPUID supports            |
| CR4.SMAP         | 1 if CPUID supports            |
| CR4.UMIP         | 1 if CPUID supports            |
| CR4.FSGSBASE     | 1 if CPUID supports            |

### 3.3 Validation result

```rust
pub struct CpuValidation {
    pub long_mode:      bool,
    pub rdtscp:         bool,
    pub invariant_tsc:  bool,
    pub nx:             bool,
    pub smep:           bool,
    pub smap:           bool,
    pub umip:           bool,
    pub wrgsbase:       bool,
    pub pcid:           bool,
    pub x2apic:         bool,
    pub xsave:          bool,
    pub cr4_smep_on:    bool,
    pub cr4_smap_on:    bool,
    pub cr4_umip_on:    bool,
    pub cr4_fsgsbase_on:bool,
    pub efer_nxe_on:    bool,
}

pub fn validate() -> CpuValidation;
pub fn baseline_ok(v: &CpuValidation) -> Result<(), &'static str>;
```

`baseline_ok` returns `Err` for the first hard requirement
that fails (Long Mode / RDTSCP / Invariant TSC / NX / SMEP /
SMAP / WRGSBASE / XSAVE missing in CPUID, or any of EFER.LME /
EFER.NXE / CR4.PAE / CR4.OSFXSR / CR4.OSXSAVE not enabled).
Recommended-but-not-required misses surface via the matching
boolean field but don't fail the validator.

## 4. Test surface

| smoke                              | what it asserts                |
|------------------------------------|--------------------------------|
| `cet_caps_decode`                  | `caps()` returns coherent struct |
| `pebs_supported_when_pmu_v4`       | PMU version >= 4 ⇒ PEBS_UNAVAILABLE = 0 |
| `cpu_validation_baseline_ok`       | NARF boot passes `baseline_ok` |

## 5. Out of scope (v0.1)

- Per-task shadow stack switching at context-switch time.
- IBT prologue (`endbr64`) emission across the kernel — that's
  a build-flag concern.
- PEBS PMI handler decode — buffer is captured raw.
- Adaptive PEBS (Skylake+ extended record formats with
  conditional fields).
- Deferred validation of hardware errata (e.g. early Sandy
  Bridge PCID quirks) — the matrix above is a baseline, not
  a per-model errata table.
