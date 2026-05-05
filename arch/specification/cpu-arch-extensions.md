# cpu-arch-extensions — Tier-6 Arm extensions + x86 LASS

> Status: **v0.1**. Locks the surface for a batch of recent
> Armv9 architectural extensions plus the x86 LASS security
> primitive.

For aarch64:

  * **SPE** — Statistical Profiling Extension; PEBS analogue.
  * **ETE** — Embedded Trace Extension; pairs with TRBE as the
    in-core trace generator.
  * **GCS** — Guarded Control Stack; CET-SHSTK analogue.
  * **RNDR / RNDRRS** — Architecturally-mandated hardware RNG.

For x86_64:

  * **LASS** — Linear Address Space Separation.

## 1. aarch64 SPE

### 1.1 Detection

`ID_AA64DFR0_EL1.PMSVer` (bits[35:32]):

| value | meaning              |
|-------|----------------------|
| 0     | not implemented      |
| 1     | SPEv1                |
| 2     | SPEv1p1              |
| 3     | SPEv1p2              |

### 1.2 Registers

| sysreg            | content                              |
|-------------------|--------------------------------------|
| `PMSCR_EL1`       | sampling control                      |
| `PMSEVFR_EL1`     | event-filter mask                     |
| `PMSFCR_EL1`      | filter control                        |
| `PMSICR_EL1`      | interval counter                      |
| `PMSIRR_EL1`      | interval reload                       |
| `PMSLATFR_EL1`    | latency filter                        |
| `PMBLIMITR_EL1`   | profiling buffer limit + enable       |
| `PMBPTR_EL1`      | profiling buffer write pointer        |
| `PMBSR_EL1`       | profiling buffer status               |
| `PMSIDR_EL1`      | implementation ID                     |

Raw encodings (op0=3, op1=0):

| name             | encoding              |
|------------------|-----------------------|
| `PMSCR_EL1`      | `S3_0_C9_C9_0`        |
| `PMSICR_EL1`     | `S3_0_C9_C9_2`        |
| `PMSIRR_EL1`     | `S3_0_C9_C9_3`        |
| `PMSFCR_EL1`     | `S3_0_C9_C9_4`        |
| `PMSEVFR_EL1`    | `S3_0_C9_C9_5`        |
| `PMSLATFR_EL1`   | `S3_0_C9_C9_6`        |
| `PMSIDR_EL1`     | `S3_0_C9_C9_7`        |
| `PMBLIMITR_EL1`  | `S3_0_C9_C10_0`       |
| `PMBPTR_EL1`     | `S3_0_C9_C10_1`       |
| `PMBSR_EL1`      | `S3_0_C9_C10_3`       |

### 1.3 API

```rust
pub fn caps() -> u8;        // raw PMSVer field
pub unsafe fn read_pmsidr() -> u64;
pub unsafe fn write_pmscr(v: u64);
pub unsafe fn write_interval(period: u64);   // PMSIRR
pub unsafe fn program_buffer(base: u64, limit: u64);  // PMBLIMITR + PMBPTR
pub unsafe fn enable();
pub unsafe fn disable();
```

## 2. aarch64 ETE

### 2.1 Detection

`ID_AA64DFR0_EL1.TraceVer` (bits[7:4]):

| value | meaning            |
|-------|--------------------|
| 0     | not implemented    |
| 1     | ETMv4 / ETE       |

### 2.2 Registers

ETE shares register layout with ETMv4 and pipes its byte stream
into TRBE. Of the wide register set, v0.1 surfaces only the
control + status entry points:

| sysreg            | content                        |
|-------------------|--------------------------------|
| `TRCPRGCTLR`      | program-control (enable bit)   |
| `TRCSTATR`        | status                         |
| `TRCCONFIGR`      | configuration                  |
| `TRCEVENTCTL0R`   | event-condition control 0      |
| `TRCEVENTCTL1R`   | event-condition control 1      |
| `TRCSTALLCTLR`    | stall control                  |
| `TRCTSCTLR`       | timestamp control              |
| `TRCAUTHSTATUS`   | authentication state            |

### 2.3 API

```rust
pub fn supported() -> bool;
pub unsafe fn enable();
pub unsafe fn disable();
pub unsafe fn read_status() -> u64;
```

## 3. aarch64 GCS

### 3.1 Detection

`ID_AA64PFR1_EL1.GCS` (bits[47:44]):

| value | meaning               |
|-------|-----------------------|
| 0     | not implemented       |
| 1     | GCS implemented       |

### 3.2 Registers

| sysreg           | content                              |
|------------------|--------------------------------------|
| `GCSCR_EL1`      | EL1 GCS control                      |
| `GCSCRE0_EL1`    | EL0 GCS control                      |
| `GCSPR_EL1`      | EL1 GCS pointer                      |
| `GCSPR_EL0`      | EL0 GCS pointer                      |

`GCSCR{,E0}_EL1` shape (mirrors CET-SHSTK gating):

| bit | field                                         |
|-----|-----------------------------------------------|
| 0   | PCRSEL — push-on-call select                  |
| 1   | RVCHKEN — return-vector check enable          |
| 2   | EX — exception-entry push enable              |
| 3   | STREN — store-instruction enable              |

### 3.3 API

```rust
pub fn caps() -> u8;
pub unsafe fn enable_el1(rvcheck: bool, exception_push: bool);
pub unsafe fn enable_el0(rvcheck: bool);
pub unsafe fn disable_el1();
pub unsafe fn disable_el0();
pub unsafe fn read_gcspr_el1() -> u64;
pub unsafe fn write_gcspr_el1(v: u64);
pub unsafe fn read_gcspr_el0() -> u64;
pub unsafe fn write_gcspr_el0(v: u64);
```

## 4. aarch64 RNDR / RNDRRS

### 4.1 Detection

`ID_AA64ISAR0_EL1.RNDR` (bits[63:60]):

| value | meaning           |
|-------|-------------------|
| 0     | not implemented   |
| 1     | RNDR + RNDRRS     |

### 4.2 Instructions

- **`MRS Xt, RNDR`** — pseudo-random 64 bits, NZCV.C = 0 on
  failure (entropy starvation), C = 1 on success.
- **`MRS Xt, RNDRRS`** — random number suitable for reseeding;
  same return semantics.

### 4.3 API

```rust
pub fn supported() -> bool;
pub fn try_rndr() -> Option<u64>;
pub fn try_rndrrs() -> Option<u64>;
```

## 5. x86_64 LASS

### 5.1 Detection

CPUID(7, 1).EAX[6] = `LASS`. When CR4.LASS (bit 27) is set,
load + store accesses are checked against the linear-address
space half: kernel addresses (sign-bit = 1) cannot be accessed
from CPL = 3, and user addresses (sign-bit = 0) cannot be
accessed from CPL = 0. Defeats SMAP-bypass-style probes.

### 5.2 Control

| MSR / bit                | meaning                                   |
|--------------------------|-------------------------------------------|
| CR4.LASS (bit 27)        | global LASS enable                        |
| `IA32_PKRS` interaction  | LASS check applies before PKS check       |

### 5.3 API

```rust
pub fn supported() -> bool;
pub unsafe fn enable_cr4();
pub unsafe fn disable_cr4();
```

## 6. Test surface

| smoke                          | asserts                                  |
|--------------------------------|------------------------------------------|
| `smoke_spe_caps`               | `PMSVer` field decoded, ≤ 3              |
| `smoke_ete_supported_path`     | `TraceVer` decode, no panic              |
| `smoke_gcs_caps`               | `GCS` field decoded, ≤ 1                 |
| `smoke_rndr_supported_path`    | `RNDR` field decoded                     |
| `smoke_lass_supported_path`    | CPUID(7,1).EAX[6] gate, no panic         |

## 7. Out of scope (v0.1)

- SPE record-format decode → `narf-tracing` event format.
- ETE / TRBE pipeline integration with the formatter.
- GCS exception entry shadow-stack pivoting (relies on the
  exception-vector rewrite landing first in `frame/`).
- LASS user-space self-tests; pairs with the user-mode
  testbin which is governed by `init/` instead.
- RNDR retry policy; the helpers expose `Option<u64>` and
  let the caller decide.
