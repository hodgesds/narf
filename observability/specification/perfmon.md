# perfmon — CPU performance monitoring primitives

> Status: **v0.1** (Stage 5 land). Supplements
> `observability/specification/spec.md` §2 with the concrete
> hardware surface for performance counters, branch tracing, and
> instruction tracing on x86_64.

This spec covers three Intel-style performance facilities:

  * **PMU** — architectural performance counters (general-purpose
    + fixed) per Intel's "Performance Monitoring" architecture.
  * **LBR** — Last Branch Records: a hardware-managed ring of
    recent branches.
  * **Intel PT** — Processor Trace: full instruction-trace
    streaming into an OS-provided ToPA buffer.

It locks the MSR set + the API shape so `observability/`'s
event-sampling layer + the `tracing/` profile recorder can be
coded against a stable surface.

## 1. PMU (architectural perfmon)

### 1.1 Detection

CPUID leaf `0x0A` reports the PMU version + counter geometry:

| field              | source              | meaning                       |
|--------------------|---------------------|-------------------------------|
| version            | CPUID(0xA, 0).EAX[7:0] | 0 = none; >= 1 = arch perfmon  |
| n_general_counters | CPUID(0xA, 0).EAX[15:8] | per-LP counter count         |
| width_general      | CPUID(0xA, 0).EAX[23:16] | counter width in bits        |
| n_fixed_counters   | CPUID(0xA, 0).EDX[4:0]   | architectural fixed counters |
| width_fixed        | CPUID(0xA, 0).EDX[12:5]  | fixed counter width          |

Architectural events (CPUID(0xA, 0).EBX = bitmap of "not
available"):

| bit | event                                |
|-----|--------------------------------------|
| 0   | UnHalted Core Cycles (event 0x3C / umask 0x00) |
| 1   | Instructions Retired (event 0xC0 / umask 0x00)  |
| 2   | UnHalted Reference Cycles (event 0x3C / umask 0x01) |
| 3   | LLC Reference (event 0x2E / umask 0x4F)         |
| 4   | LLC Miss (event 0x2E / umask 0x41)              |
| 5   | Branch Instruction Retired (event 0xC4)         |
| 6   | Branch Mispredict Retired (event 0xC5)          |

A bit reads "0" if the event is supported; "1" means not present.

### 1.2 MSR set

| MSR    | name                       | direction |
|--------|----------------------------|-----------|
| 0x186+i| IA32_PERFEVTSELi (i=0..N)  | RW        |
| 0xC1+i | IA32_PMCi                  | RW        |
| 0x309+i| MSR_PERF_FIXED_CTRi        | RW        |
| 0x38D  | MSR_PERF_FIXED_CTR_CTRL    | RW        |
| 0x38E  | IA32_PERF_GLOBAL_STATUS    | R         |
| 0x38F  | IA32_PERF_GLOBAL_CTRL      | RW        |
| 0x390  | IA32_PERF_GLOBAL_OVF_CTRL  | RW (W1C)  |

`IA32_PERFEVTSELi` layout (low 32 bits):

| bits  | field         | meaning                           |
|-------|---------------|-----------------------------------|
| 7:0   | event_select  | event byte                        |
| 15:8  | umask         | unit mask (sub-event)             |
| 16    | usr           | count CPL > 0                     |
| 17    | os            | count CPL = 0                     |
| 18    | edge          | edge-detect                       |
| 19    | pin_control   | (legacy; leave 0)                 |
| 20    | apic_int      | overflow generates LVTPC interrupt |
| 21    | any_thread    | count both threads of an SMT pair  |
| 22    | enable        | counter enable                     |
| 23    | inv           | invert counter mask               |
| 31:24 | counter_mask  | edge counter mask                 |

`MSR_PERF_FIXED_CTR_CTRL` layout (4 bits per fixed counter):

| bits  | field           |
|-------|-----------------|
| 0     | ENi.OS          |
| 1     | ENi.USR         |
| 2     | ENi.AnyThread   |
| 3     | ENi.PMI         |

`IA32_PERF_GLOBAL_CTRL`: bit `i` enables `IA32_PMCi`; bit
`32 + i` enables `MSR_PERF_FIXED_CTRi`.

### 1.3 Counter shape

Counter widths range from 40 bits (Nehalem) to 48 bits
(Skylake+). Writes to `IA32_PMCi` should respect the width
(write 0 to start; CPU sign-extends on read to 64 bits). The
`width_general` CPUID field is authoritative.

### 1.4 API shape

```rust
pub struct PmuCaps {
    pub version:            u8,
    pub n_general_counters: u8,
    pub width_general:      u8,
    pub n_fixed_counters:   u8,
    pub width_fixed:        u8,
    /// Bitmap of unsupported architectural events (low 7 bits).
    pub unsupported_arch:   u8,
}

pub struct PerfEvtSel {
    pub event_select:    u8,
    pub umask:           u8,
    pub usr:             bool,
    pub os:              bool,
    pub edge:            bool,
    pub apic_int:        bool,
    pub any_thread:      bool,
    pub inv:             bool,
    pub counter_mask:    u8,
}

pub fn caps() -> PmuCaps;
pub unsafe fn program_general(idx: u8, sel: PerfEvtSel);
pub unsafe fn enable_global(general_mask: u32, fixed_mask: u8);
pub unsafe fn disable_global();
pub unsafe fn read_general(idx: u8) -> u64;
pub unsafe fn write_general(idx: u8, val: u64);
pub unsafe fn read_fixed(idx: u8) -> u64;
pub unsafe fn enable_fixed(idx: u8, os: bool, usr: bool);
```

## 2. LBR (Last Branch Records)

### 2.1 Detection

Available on every Intel CPU since Pentium Pro; the size + layout
varies. CPUID(0xA, 0).EAX[7:0] >= 1 implies LBR is present
implicitly via the same MSR cluster as the PMU.

### 2.2 MSRs

| MSR    | name                          |
|--------|-------------------------------|
| 0x1D9  | IA32_DEBUGCTL                 |
| 0x1DD  | MSR_LBR_TOS                   |
| 0x1DB+i| MSR_LASTBRANCH_FROM_i (legacy)|
| 0x40+i | MSR_LASTBRANCH_FROM_i (modern)|
| 0x60+i | MSR_LASTBRANCH_TO_i           |
| 0x680+i| MSR_LASTBRANCH_FROM_i (Skylake+, 32 entries) |
| 0x6C0+i| MSR_LASTBRANCH_TO_i (Skylake+) |
| 0xDCA  | MSR_LBR_SELECT                |

The Skylake+ layout exposes 32 entries (Pentium Pro had 4);
NARF v0.1 uses the Skylake+ MSR base and caps the entry count
at the model-discovered limit.

`IA32_DEBUGCTL.LBR` (bit 0) enables LBR recording.

`MSR_LBR_SELECT` masks which branch types are recorded:

| bit | filter                          |
|-----|---------------------------------|
| 0   | CPL_EQ_0 (kernel)               |
| 1   | CPL_NEQ_0 (user)                |
| 2   | JCC                             |
| 3   | NEAR_REL_CALL                   |
| 4   | NEAR_IND_CALL                   |
| 5   | NEAR_RET                        |
| 6   | NEAR_IND_JMP                    |
| 7   | NEAR_REL_JMP                    |
| 8   | FAR_BRANCH                      |

### 2.3 Ring read

`MSR_LBR_TOS` holds the index of the most-recent record. Walk
backwards: `i = TOS, TOS-1, ..., 0, n-1, ...` for the ring.

### 2.4 API shape

```rust
pub struct LbrCaps {
    pub n_entries: u8,        // 4 / 8 / 16 / 32 per model
    pub from_base: u32,       // MSR base for FROM
    pub to_base:   u32,       // MSR base for TO
}

pub fn caps() -> LbrCaps;
pub unsafe fn enable(filter: u32);
pub unsafe fn disable();
pub unsafe fn read_pair(idx: u8) -> (u64, u64); // (from, to)
pub unsafe fn read_tos() -> u8;
```

## 3. Intel PT (Processor Trace)

### 3.1 Detection

CPUID(0x14, 0).EAX (max sub-leaf number) being non-zero implies
PT support. CPUID(0x14, 0).EBX bits expose feature flags:

| bit | feature                          |
|-----|----------------------------------|
| 0   | CR3 filtering                    |
| 1   | Configurable PSB / cycle / mtc   |
| 2   | IP filtering / TraceStop         |
| 3   | MTC packet generation            |
| 4   | PTWrite                          |

CPUID(0x14, 0).ECX bits:

| bit | feature                          |
|-----|----------------------------------|
| 0   | ToPA                             |
| 1   | ToPA multi-entry                 |
| 2   | Single-range output              |
| 3   | TransportLanes (PCIe)            |
| 31  | LIP (linear IPs in payload)      |

### 3.2 MSRs

| MSR    | name                       |
|--------|----------------------------|
| 0x570  | IA32_RTIT_CTL              |
| 0x571  | IA32_RTIT_STATUS           |
| 0x560  | IA32_RTIT_OUTPUT_BASE      |
| 0x561  | IA32_RTIT_OUTPUT_MASK_PTRS |
| 0x572  | IA32_RTIT_CR3_MATCH        |
| 0x580  | IA32_RTIT_ADDRn_A          |
| 0x581  | IA32_RTIT_ADDRn_B          |

`IA32_RTIT_CTL` key bits:

| bit | field                          |
|-----|--------------------------------|
| 0   | TraceEn                        |
| 2   | OS                             |
| 3   | USR                            |
| 6:4  | reserved (writes must be 0)    |
| 7   | CR3Filter                      |
| 8   | ToPA                           |
| 11  | DisRETC                        |
| 13  | BranchEn                       |

### 3.3 ToPA (Table of Physical Addresses)

ToPA is a list of 8-byte entries, each describing a 4 KiB ..
2 MiB physical region:

| bits   | field        |
|--------|--------------|
| 51:12  | base         |
| 11:6   | reserved     |
| 5      | END (last entry — wrap to base of ToPA) |
| 4      | INT (raise PMI when filled) |
| 3      | reserved     |
| 2:0    | size (0=4K, 1=8K, 2=16K, 3=32K, 4=64K, 5=128K, 6=256K, 7=512K) |

`IA32_RTIT_OUTPUT_BASE` = phys of the ToPA itself. NARF v0.1
uses a single-entry ToPA pointing at one 4 KiB ring buffer.

### 3.4 API shape

```rust
pub struct PtCaps {
    pub supported:        bool,
    pub topa:             bool,
    pub multi_topa:       bool,
    pub branch_filter:    bool,
}

pub fn caps() -> PtCaps;
pub unsafe fn install_topa(topa_phys: u64, ring_phys: u64, ring_size_log2: u8);
pub unsafe fn enable(os: bool, usr: bool);
pub unsafe fn disable();
pub unsafe fn output_offset() -> u32;
pub unsafe fn status() -> u64;
```

## 4. Test surface

| smoke                              | what it asserts                |
|------------------------------------|--------------------------------|
| `pmu_caps_decode`                  | version > 0 implies n_general > 0 + width >= 32 |
| `pmu_program_cycles_counter`       | program PMC0 for cycles, count moves |
| `lbr_caps_when_supported`          | n_entries ∈ {4, 8, 16, 32}     |
| `pt_caps_decode`                   | supported = true ⇒ topa or single-range path |

## 5. Out of scope (v0.1)

- PEBS (Precise Event-Based Sampling).
- Multi-entry ToPA with INT-on-fill chaining.
- Per-CPU counter virtualisation across context switches.
- LBR call-stack mode (Skylake+ feature).
- AMD IBS (Instruction-Based Sampling) — different MSR set.
- Userspace `rdpmc` enable (CR4.PCE) — covered by `observability/spec.md`.
- PMI vector wiring (the IDT-vector binding lives in
  `interrupts/`, not here).
