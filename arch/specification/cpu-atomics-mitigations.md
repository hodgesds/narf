# cpu-atomics-mitigations — Tier-11 atomics + mitigations + ID-regs

> Status: **v0.1**.

For x86_64:

  * **SLD** — Split Lock Detect via `IA32_TEST_CTRL` bit 29.
  * **BUSLOCK_TRAP** — `IA32_DEBUGCTL.BUS_LOCK_DETECT` bit.

For aarch64:

  * **LSE128** — 128-bit large-system-extension atomics
    (`FEAT_LSE128`).
  * **RCPC3** — Release Consistency processor consistent v3
    (`FEAT_LRCPC3`).
  * **S1PIE / S2PIE** — Permission Indirect Encoding (`FEAT_S1PIE`,
    `FEAT_S2PIE`).
  * **SCTLR2** — extended `SCTLR2_EL1` (`FEAT_SCTLR2`).

## 1. Intel Split Lock Detect

### 1.1 Detection

CPUID(7, 0).EDX[5] = `IA32_CORE_CAPABILITIES` exists.
`IA32_CORE_CAPABILITIES` (`0xCF`):

| bit | field                                       |
|-----|---------------------------------------------|
| 5   | `SPLIT_LOCK_DETECT_SUPPORTED`               |

`IA32_TEST_CTRL` (`0x33`):

| bit | field                                       |
|-----|---------------------------------------------|
| 29  | `SLD_DISABLE_AC_GP` (1 = #AC, 0 = #GP)      |
| 30  | `SLD_AC_VOTE`                                |
| 31  | `SLD_DISABLE_AC`                             |

### 1.2 API

```rust
pub fn supported() -> bool;          // CORE_CAPS bit 5
pub unsafe fn read_test_ctrl() -> u64;
pub unsafe fn write_test_ctrl(v: u64);
pub unsafe fn enable_ac();           // bit 31 = 0, bit 29 = 1
pub unsafe fn disable();             // bit 31 = 1
```

## 2. Intel Bus Lock Trap

### 2.1 Detection

CPUID(7, 0).ECX[24] = `BUS_LOCK_DETECT`.
`IA32_DEBUGCTL` (`0x1D9`):

| bit | field                                       |
|-----|---------------------------------------------|
| 2   | `BUS_LOCK_DETECT` (1 = trap on bus lock)    |

### 2.2 API

```rust
pub fn supported() -> bool;
pub unsafe fn enable();      // sets DEBUGCTL bit 2
pub unsafe fn disable();
```

## 3. aarch64 LSE128

### 3.1 Detection

`ID_AA64ISAR0_EL1.Atomic` (bits[23:20]):

| value | meaning                |
|-------|------------------------|
| 0     | not implemented        |
| 1     | LSE                    |
| 2     | + LSE128               |

### 3.2 API

```rust
pub fn caps() -> u8;               // raw Atomic field
pub fn lse_supported() -> bool;
pub fn lse128_supported() -> bool;
```

## 4. aarch64 RCPC / RCPC2 / RCPC3

`ID_AA64ISAR1_EL1.LRCPC` (bits[23:20]):

| value | meaning                |
|-------|------------------------|
| 0     | not implemented        |
| 1     | LRCPC                  |
| 2     | + LRCPC2               |
| 3     | + LRCPC3               |

```rust
pub fn rcpc_caps() -> u8;
pub fn rcpc2_supported() -> bool;
pub fn rcpc3_supported() -> bool;
```

## 5. aarch64 FEAT_S1PIE / FEAT_S2PIE

### 5.1 Detection

`ID_AA64MMFR3_EL1.S1PIE` (bits[7:4]) and
`ID_AA64MMFR3_EL1.S2PIE` (bits[3:0]). Both are 0/1.

### 5.2 Registers

| sysreg              | content                            |
|---------------------|------------------------------------|
| `PIRE0_EL1`         | EL0 stage-1 indirection            |
| `PIR_EL1`           | EL1 stage-1 indirection            |
| `S2PIR_EL2`         | stage-2 indirection                |

PIE replaces the legacy `MAIR_EL1` + page-table AP/UXN field
encoding with an indirection-table lookup; useful for richer
permission domains.

### 5.3 API

```rust
pub struct PieCaps { pub s1pie: bool, pub s2pie: bool }

pub fn caps() -> PieCaps;
pub unsafe fn read_pir_el1() -> u64;
pub unsafe fn write_pir_el1(v: u64);
pub unsafe fn read_pire0_el1() -> u64;
pub unsafe fn write_pire0_el1(v: u64);
```

## 6. aarch64 FEAT_SCTLR2

### 6.1 Detection

`ID_AA64MMFR3_EL1.SCTLRX` (bits[15:12]) ≥ 1.

### 6.2 Register

`SCTLR2_EL1` (raw `S3_0_C1_C0_3`) extends `SCTLR_EL1` with
new bits for FEAT_NMI, FEAT_THE, etc.

### 6.3 API

```rust
pub fn supported() -> bool;
pub unsafe fn read_sctlr2_el1() -> u64;
pub unsafe fn write_sctlr2_el1(v: u64);
```

## 7. Test surface

| smoke                          | asserts                          |
|--------------------------------|----------------------------------|
| `smoke_sld_supported_path`     | gate decoded                     |
| `smoke_buslock_supported_path` | gate decoded                     |
| `smoke_lse_caps`               | LSE field ≤ 2                    |
| `smoke_rcpc_caps`              | LRCPC field ≤ 3                  |
| `smoke_pie_caps`               | S1PIE / S2PIE booleans coherent  |
| `smoke_sctlr2_supported_path`  | SCTLRX field decoded             |

## 8. Out of scope (v0.1)

- Per-thread SLD policy (kernel-wide AC mode is the v0.1
  default).
- Bus-lock-trap → narf-tracing event format.
- LSE128 / RCPC3 inline-asm wrappers; the architectural ldp/stp
  encodings stay in `arch::asm` once stable LLVM intrinsics
  ship.
- PIE indirection-table programming policy (lives in `memory/`).
- SCTLR2 per-bit semantics — only the read/write surface lands.
