# cpu-telemetry-qos — Tier-5 telemetry + QoS CPU surface

> Status: **v0.1**. Locks the surface for cache / memory QoS
> primitives + the new event-delivery + branch-trace plumbing.

Covers, for x86_64:

  * **Intel RDT** — Cache Allocation Technology (CAT), Cache
    Monitoring Technology (CMT), Memory Bandwidth Monitoring
    (MBM), and Memory Bandwidth Allocation (MBA).
  * **FRED** — Flexible Return and Event Delivery; replaces
    IDT + IRET + SYSCALL/SYSRET on supporting silicon.

For aarch64:

  * **BRBE** — Branch Record Buffer Extension (LBR analogue).
  * **TRBE** — Trace Buffer Extension (Intel PT analogue).
  * **MPAM** — Memory Partitioning and Monitoring (RDT
    analogue).

## 1. Intel RDT

### 1.1 Detection

CPUID(7, 0).EBX[12] = `RDT-M` (resource director, monitoring).
CPUID(7, 0).EBX[15] = `RDT-A` (resource director, allocation).

Sub-features come from CPUID(0x0F, 0/1) and CPUID(0x10, 0/N):

| leaf / sub      | meaning                                  |
|-----------------|------------------------------------------|
| `0x0F, 0`.EDX[1] | L3 monitoring supported                 |
| `0x0F, 1`       | L3 monitoring details (RMID range, scale) |
| `0x10, 0`.EBX   | bitmap of allocation sub-features        |
| `0x10, 1`       | L3 CAT details                           |
| `0x10, 2`       | L2 CAT details                           |
| `0x10, 3`       | MBA details                              |

### 1.2 MSRs

| MSR              | name             | content                         |
|------------------|------------------|---------------------------------|
| `0xC8D`          | IA32_QM_EVTSEL   | RMID + event ID for QM_CTR read |
| `0xC8E`          | IA32_QM_CTR      | monitoring counter              |
| `0xC8F`          | IA32_PQR_ASSOC   | per-task RMID + CLOSID          |
| `0xC90 + n`      | IA32_L3_QOS_n    | L3 CAT mask (per CLOSID)        |
| `0xD10 + n`      | IA32_L2_QOS_n    | L2 CAT mask (per CLOSID)        |
| `0xD50 + n`      | IA32_MBA_THRTL_n | MBA throttle (per CLOSID)       |

### 1.3 Events

| event-id | name          |
|----------|---------------|
| `0x01`   | L3_OCCUPANCY  |
| `0x02`   | TOTAL_MEM_BW  |
| `0x03`   | LOCAL_MEM_BW  |

### 1.4 API

```rust
pub struct RdtCaps {
    pub monitoring:    bool,
    pub allocation:    bool,
    pub l3_monitoring: bool,
    pub l3_cat:        bool,
    pub l2_cat:        bool,
    pub mba:           bool,
    pub max_rmid:      u32,
    pub max_closid:    u32,
}

pub fn caps() -> RdtCaps;
pub unsafe fn assoc(rmid: u16, closid: u16);
pub unsafe fn read_event(rmid: u16, evt_id: u32) -> u64;
pub unsafe fn write_l3_mask(closid: u16, mask: u64);
pub unsafe fn write_l2_mask(closid: u16, mask: u64);
pub unsafe fn write_mba_throttle(closid: u16, throttle_pct: u16);
```

## 2. FRED

### 2.1 Detection

CPUID(7, 1).EAX[17] = `FRED`. Replaces the legacy IDT-driven
event delivery path with a register-only mechanism configured
via the IA32_FRED_* MSRs.

### 2.2 MSRs

| MSR     | name              | content                       |
|---------|-------------------|-------------------------------|
| `0x1D0` | IA32_FRED_RSP0    | event-delivery RSP for CPL=0  |
| `0x1CC` | IA32_FRED_RSP1    | RSP for CPL=1 (rarely used)   |
| `0x1CD` | IA32_FRED_RSP2    | RSP for CPL=2                 |
| `0x1CE` | IA32_FRED_RSP3    | RSP for CPL=3                 |
| `0x1CF` | IA32_FRED_STKLVLS | per-vector stack-level lookup |
| `0x1D1` | IA32_FRED_SSP1    | shadow-stack ptr CPL=1        |
| `0x1D2` | IA32_FRED_SSP2    | shadow-stack ptr CPL=2        |
| `0x1D3` | IA32_FRED_SSP3    | shadow-stack ptr CPL=3        |
| `0x1D4` | IA32_FRED_CONFIG  | event-handler base + caps     |

`IA32_FRED_CONFIG`:

| bits   | field                      |
|--------|----------------------------|
| 5:0    | NMI bias                   |
| 11:10  | reserved                   |
| 63:12  | event-handler base address (VA, page-aligned) |

CR4.FRED (bit 32 in the 64-bit form) gates the feature.

### 2.3 API

```rust
pub fn supported() -> bool;
pub unsafe fn enable_cr4();
pub unsafe fn write_handler_base(va: u64);
pub unsafe fn write_rsp0(rsp: u64);
pub unsafe fn write_stklvls(map: u64);
```

## 3. aarch64 BRBE

### 3.1 Detection

`ID_AA64DFR0_EL1.BRBE` (bits[55:52]):

| value | meaning            |
|-------|--------------------|
| 0     | not implemented    |
| 1     | BRBE                |
| 2     | + BRBE-EL3         |

### 3.2 Registers

| sysreg          | content                                   |
|-----------------|-------------------------------------------|
| `BRBCR_EL1`     | BRBE control                              |
| `BRBFCR_EL1`    | BRBE filter control                       |
| `BRBTS_EL1`     | timestamp                                 |
| `BRBINFINJ_EL1` | injection (debug)                         |
| `BRBSRCINJ_EL1` | injection (debug)                         |
| `BRBTGTINJ_EL1` | injection (debug)                         |
| `BRBSRC<n>_EL1` | source IP, 0..N-1                         |
| `BRBTGT<n>_EL1` | target IP, 0..N-1                         |
| `BRBINF<n>_EL1` | metadata, 0..N-1                          |

### 3.3 API

```rust
pub fn caps() -> u8;        // raw BRBE field [3:0]
pub unsafe fn read_brbcr_el1() -> u64;
pub unsafe fn write_brbcr_el1(v: u64);
pub unsafe fn read_brbfcr_el1() -> u64;
pub unsafe fn write_brbfcr_el1(v: u64);
pub unsafe fn enable();     // BRBCR.E1BRE | E0BRE
pub unsafe fn disable();
pub unsafe fn freeze();     // sets BRBCR.PAUSED
```

## 4. aarch64 TRBE

### 4.1 Detection

`ID_AA64DFR0_EL1.TraceBuffer` (bits[47:44]):

| value | meaning                |
|-------|------------------------|
| 0     | not implemented        |
| 1     | TRBE                   |

### 4.2 Registers

| sysreg            | content                            |
|-------------------|------------------------------------|
| `TRBLIMITR_EL1`   | buffer limit + enable              |
| `TRBPTR_EL1`      | current write pointer              |
| `TRBBASER_EL1`    | base address                       |
| `TRBSR_EL1`       | status                             |
| `TRBMAR_EL1`      | memory attributes                  |
| `TRBTRG_EL1`      | trigger configuration              |
| `TRBIDR_EL1`      | implementation ID                  |

### 4.3 API

```rust
pub fn supported() -> bool;
pub unsafe fn read_trbidr() -> u64;
pub unsafe fn read_trblimitr() -> u64;
pub unsafe fn write_trblimitr(v: u64);
pub unsafe fn write_base(base: u64, limit: u64);
pub unsafe fn enable();
pub unsafe fn disable();
```

## 5. aarch64 MPAM

### 5.1 Detection

`ID_AA64PFR0_EL1.MPAM` (bits[43:40]) ≥ 1.
`ID_AA64PFR1_EL1.MPAM_frac` (bits[19:16]) gives the fractional
revision.

### 5.2 Registers

| sysreg              | content                            |
|---------------------|------------------------------------|
| `MPAM0_EL1`         | per-task PARTID + PMG (EL0 / EL1)  |
| `MPAM1_EL1`         | per-EL1 PARTID + PMG               |
| `MPAMHCR_EL2`       | virtualisation control             |
| `MPAMIDR_EL1`       | ID + capabilities                  |

`MPAM<n>_EL1` shape:

| bits  | field                  |
|-------|------------------------|
| 15:0  | PARTID_D (data)        |
| 31:16 | PARTID_I (instruction) |
| 39:32 | PMG_D                  |
| 47:40 | PMG_I                  |
| 63    | MPAMEN (enable)        |

### 5.3 API

```rust
pub struct MpamCaps {
    pub supported: bool,
    pub revision:  u8,           // major
    pub frac:      u8,           // minor
    pub max_partid:u16,
    pub max_pmg:   u8,
}

pub fn caps() -> MpamCaps;
pub unsafe fn write_mpam0(partid_d: u16, partid_i: u16,
                          pmg_d: u8, pmg_i: u8, enable: bool);
pub unsafe fn write_mpam1(partid_d: u16, partid_i: u16,
                          pmg_d: u8, pmg_i: u8, enable: bool);
```

## 6. Test surface

| smoke                            | asserts                              |
|----------------------------------|--------------------------------------|
| `smoke_rdt_caps`                 | gates coherent (alloc-only OK)        |
| `smoke_fred_supported_path`       | CPUID(7,1).EAX[17] gate, no panic    |
| `smoke_brbe_caps`                | reads ID_AA64DFR0 BRBE field         |
| `smoke_trbe_supported_path`      | TraceBuffer field decode             |
| `smoke_mpam_caps`                | MPAM + MPAM_frac decode              |

## 7. Out of scope (v0.1)

- Per-CLOSID scheduler binding (passing CLOSID through context
  switch).
- TRBE → file-export pipeline (the perf-buffer drain path).
- BRBE record decode → narf-tracing event format.
- MPAM partition allocation policy; we expose the primitives
  but do not pick PARTID assignments.
- FRED user-mode entry path; only the kernel-side configure
  surface lands.
