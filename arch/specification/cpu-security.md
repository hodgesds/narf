# cpu-security — CPU-side security hardening (Tier 2)

> Status: **v0.1** (Stage 5 land). Supplements
> `arch/specification/security-hardening.md` with the next-tier
> hardening surfaces for both arches.

This spec covers six facilities:

  * **PAC** (aarch64) — Pointer Authentication: signed return
    addresses + signed function pointers (APIA / APIB / APDA /
    APDB / APGA keys).
  * **BTI** (aarch64) — Branch Target Identification: every
    indirect branch must land on a `BTI` instruction.
  * **SSBS** (aarch64) — Speculative Store Bypass Safe runtime
    control.
  * **LAM** (Intel, Sapphire Rapids+) — Linear Address Masking:
    pointer tagging in the high VA bits.
  * **UINTR** (Intel) — User Interrupts: fast user-to-user IPI.
  * **KeyLocker** (Intel) — encrypt AES keys with a CPU-bound
    key.

## 1. aarch64 PAC

### 1.1 Detection

`ID_AA64ISAR1_EL1`:

| bits   | field   | meaning                             |
|--------|---------|-------------------------------------|
| 7:4    | APA     | Address auth (QARMA)                |
| 11:8   | API     | Address auth (impl-defined)         |
| 27:24  | GPA     | Generic auth (QARMA)                |
| 31:28  | GPI     | Generic auth (impl-defined)         |

`ID_AA64ISAR2_EL1.APA3`/`GPA3` adds QARMA3 alternates; v8.6+
adds enhanced PAC (FEAT_EPAC).

### 1.2 Keys

Per-CPU 128-bit keys live in pairs of 64-bit MSRs:

| MSR (op0/op1/CRn/CRm/op2)            | name        |
|--------------------------------------|-------------|
| `S3_0_C2_C1_0` / `_1`                | APIAKEY (low/high) |
| `S3_0_C2_C1_2` / `_3`                | APIBKEY     |
| `S3_0_C2_C2_0` / `_1`                | APDAKEY     |
| `S3_0_C2_C2_2` / `_3`                | APDBKEY     |
| `S3_0_C2_C3_0` / `_1`                | APGAKEY     |

Enable bits in `SCTLR_EL1`:

| bit | name  | enables                    |
|-----|-------|----------------------------|
| 13  | EnIB  | PACI{A,B} for instruction-B |
| 27  | EnDA  | PACD{A,B} data-A           |
| 30  | EnIA  | PACI{A,B} instruction-A    |
| 13  | EnDB  | data-B                     |

### 1.3 API

```rust
pub struct PacCaps {
    pub address_auth: bool,
    pub generic_auth: bool,
    pub enhanced:     bool,
}

pub fn caps() -> PacCaps;
pub unsafe fn write_apia_key(low: u64, high: u64);
pub unsafe fn write_apib_key(low: u64, high: u64);
pub unsafe fn write_apda_key(low: u64, high: u64);
pub unsafe fn write_apdb_key(low: u64, high: u64);
pub unsafe fn write_apga_key(low: u64, high: u64);
pub unsafe fn enable_keys(ia: bool, ib: bool, da: bool, db: bool);
```

## 2. aarch64 BTI

### 2.1 Detection

`ID_AA64PFR1_EL1.BT` (bits[3:0]) — 0 = absent, 1 = present.

### 2.2 Enforcement

Each translation-table descriptor has a "GP" bit (bits[50] of the
attribute field) that, when set, requires every indirect branch
landing on a page within that mapping to be either `bti j`,
`bti c`, `bti jc`, or a known-safe instruction. Otherwise `#BTI`
exception (synchronous).

### 2.3 API

```rust
pub fn caps() -> bool;             // ID_AA64PFR1_EL1.BT >= 1
```

Enabling per-page is a `memory/` page-table concern — this
module surfaces only the detection; the page-flag plumbing
lives where the page-table builder is.

## 3. aarch64 SSBS

### 3.1 Detection

`ID_AA64PFR1_EL1.SSBS` (bits[7:4]):

| value | meaning                                 |
|-------|-----------------------------------------|
| 0     | not present                             |
| 1     | SSBS supported (PSTATE.SSBS controllable)|
| 2     | + MSR `SSBS` instruction                 |

### 3.2 Runtime control

`PSTATE.SSBS` is bit 12 of PSTATE; setting it instructs the CPU
to forbid speculative store-bypass. v8.5+ provides `MSR SSBS, #0/#1`
or via `MSR SCTLR_EL1.DSSBS`.

### 3.3 API

```rust
pub fn caps() -> u8;        // raw ID_AA64PFR1_EL1.SSBS field
pub unsafe fn enable();     // sets PSTATE.SSBS
pub unsafe fn disable();    // clears PSTATE.SSBS
```

## 4. Intel LAM

### 4.1 Detection

`CPUID(7, 1).EAX[26]` = LAM (Linear Address Masking).

### 4.2 Control

Per-mode enable bits:

| location          | bit  | enables                        |
|-------------------|------|--------------------------------|
| `CR3` (LAM_U48)   | 62   | user-mode 48-bit canonical (top 6 bits ignored) |
| `CR3` (LAM_U57)   | 61   | user-mode 57-bit canonical (top 6 bits ignored) |
| `CR4` (LAM_SUP)   | 28   | supervisor LAM enable           |

Only one of LAM_U48 / LAM_U57 may be active at a time.

### 4.3 API

```rust
pub fn supported() -> bool;
pub unsafe fn enable_user_lam_u48();
pub unsafe fn enable_user_lam_u57();
pub unsafe fn enable_supervisor_lam();
pub unsafe fn disable_user_lam();
```

## 5. Intel UINTR

### 5.1 Detection

`CPUID(7, 0).EDX[5]` = UINTR.

### 5.2 MSRs

| MSR    | name                          |
|--------|-------------------------------|
| 0x985  | IA32_UINTR_RR                 |
| 0x986  | IA32_UINTR_HANDLER            |
| 0x987  | IA32_UINTR_STACKADJUST        |
| 0x988  | IA32_UINTR_MISC               |
| 0x989  | IA32_UINTR_PD                 |
| 0x98A  | IA32_UINTR_TT                 |

### 5.3 Instructions

| insn         | meaning                              |
|--------------|--------------------------------------|
| `senduipi`   | send a user-IPI to a UPID             |
| `clui`       | clear UIF (mask user IRQs)            |
| `stui`       | set UIF                               |
| `testui`     | read UIF into CF                      |
| `uiret`      | return from user-IRQ handler          |

### 5.4 API

```rust
pub fn supported() -> bool;
pub unsafe fn install_handler(handler_va: u64);
pub unsafe fn install_pd(pd_phys: u64);
pub unsafe fn enable();
pub unsafe fn disable();
pub unsafe fn senduipi(upid_index: u32);
```

## 6. Intel KeyLocker

### 6.1 Detection

`CPUID(7, 0).ECX[23]` = KL (KeyLocker present).
`CPUID(0x19, 0)` enumerates the variants:

| bit | feature                                  |
|-----|------------------------------------------|
| 0   | AES_KLE (AES key-locker encrypt)         |
| 1   | reserved                                 |
| 2   | KL wide instructions                     |
| 3   | KL with hardware key support             |

### 6.2 Internal Wrap Key (IWKEY)

The IWKEY is a CPU-internal symmetric key the CPU uses to wrap
user-supplied AES keys into "handles." Userspace then computes
AES-128 / AES-256 against the handle without ever holding the
plaintext key.

`LOADIWKEY` instruction loads the IWKEY from XMM registers + a
128-bit IV. Caller-side IWKEY rotation is recommended periodically.

### 6.3 API

```rust
pub fn caps() -> u32;          // CPUID(0x19, 0).EAX bitmap
pub fn supported() -> bool;
```

Instruction wrappers for `LOADIWKEY` / `ENCODEKEY128` /
`ENCODEKEY256` / `AESENC128KL` etc. land when a userspace
crypto consumer needs them.

## 7. Test surface

| smoke                         | what it asserts                  |
|-------------------------------|----------------------------------|
| `pac_caps_aarch64`            | `caps()` field shape coherent    |
| `bti_caps_aarch64`            | `caps()` returns true / false    |
| `ssbs_caps_aarch64`           | raw value < 4                    |
| `lam_supported_path_x86_64`   | `supported()` non-panicking      |
| `uintr_supported_path_x86_64` | `supported()` non-panicking      |
| `keylocker_caps_x86_64`       | shape coherent                   |

## 8. Out of scope (v0.1)

- Per-task PAC key reseeding at fork().
- Page-flag plumbing for BTI's GP bit in the page-table builder.
- LAM-aware syscall-arg sanitization.
- UINTR userspace handler shim + UPID allocator.
- KeyLocker IWKEY rotation policy.
