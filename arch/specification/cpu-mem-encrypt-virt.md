# cpu-mem-encrypt-virt — Tier-10 mem-encrypt + nested virt + page-protect

> Status: **v0.1**.

For x86_64:

  * **TME / MKTME** — Total Memory Encryption + multi-key
    extension. Caps decode + activation-MSR programming.
  * **RTM_ALWAYS_ABORT** — Intel TSX kill-switch via
    IA32_TSX_FORCE_ABORT.

For aarch64:

  * **ECV** — Enhanced Counter Virtualization (FEAT_ECV).
  * **NV2** — Nested Virtualization v2 (FEAT_NV2).
  * **E0PD** — privileged-only-data on TTBR1 (FEAT_E0PD).

## 1. Intel TME / MKTME

### 1.1 Detection

CPUID(7, 0).ECX[13] = `TME_EN` available.
`IA32_TME_CAPABILITY` (`0x981`):

| bits   | field                                            |
|--------|--------------------------------------------------|
| 0      | AES_XTS_128                                      |
| 1      | AES_XTS_128_INTEGRITY                            |
| 2      | AES_XTS_256                                      |
| 35:32  | MK_TME_MAX_KEYID_BITS                            |
| 50:36  | MK_TME_MAX_KEYS                                  |

`IA32_TME_ACTIVATE` (`0x982`):

| bits   | field                                            |
|--------|--------------------------------------------------|
| 0      | LOCK                                             |
| 1      | TME_ENABLE                                        |
| 4      | KEY_SELECT (1 = use HW-generated key)             |
| 5      | SAVE_KEY_FOR_STANDBY                              |
| 7:4    | TME_POLICY_KS                                    |
| 31:8   | reserved                                          |
| 35:32  | TME_BYPASS                                        |
| 39:36  | MK_TME_KEYID_BITS                                |
| 47:40  | MK_TME_CRYPTO_ALGS_ENABLED                       |

### 1.2 API

```rust
pub struct TmeCaps {
    pub aes_xts_128:           bool,
    pub aes_xts_128_integrity: bool,
    pub aes_xts_256:           bool,
    pub max_keyid_bits:        u8,
    pub max_keys:              u16,
}

pub fn supported() -> bool;
pub unsafe fn read_caps() -> TmeCaps;
pub unsafe fn read_activate() -> u64;
pub unsafe fn write_activate(v: u64);
pub fn locked(activate: u64) -> bool;
```

## 2. Intel RTM_ALWAYS_ABORT

CPUID(7, 0).EDX[11] = `RTM_ALWAYS_ABORT`.
`IA32_TSX_FORCE_ABORT` (`0x10F`):

| bit | field                                        |
|-----|----------------------------------------------|
| 0   | RTM_FORCE_ABORT — XBEGIN aborts unconditionally |
| 1   | TSX_CPUID_CLEAR — drops the TSX-related CPUID bits |
| 2   | SDV_ENABLE_RTM                                |

```rust
pub fn rtm_always_abort_supported() -> bool;
pub unsafe fn read_force_abort() -> u64;
pub unsafe fn write_force_abort(v: u64);
pub unsafe fn force_rtm_abort();      // sets bit 0
```

## 3. aarch64 ECV

`ID_AA64MMFR0_EL1.ECV` (bits[63:60]):

| value | meaning                  |
|-------|--------------------------|
| 0     | not implemented          |
| 1     | ECV (FEAT_ECV)           |
| 2     | + CNTPOFF support        |

ECV adds direct EL2 visibility into CNTP / CNTV without trap.
v0.1 surfaces caps only.

```rust
pub fn caps() -> u8;          // raw ECV field
pub fn supported() -> bool;
pub fn cntpoff_supported() -> bool;     // ECV >= 2
```

## 4. aarch64 NV2

`ID_AA64MMFR2_EL1.NV` (bits[27:24]):

| value | meaning              |
|-------|----------------------|
| 0     | not implemented      |
| 1     | FEAT_NV              |
| 2     | FEAT_NV2             |

NV2 hands the guest hypervisor a sysreg shadow page so most
EL2 accesses don't trap to the host. v0.1 surfaces caps only;
shadow-page placement lives in the hypervisor crate.

```rust
pub fn caps() -> u8;
pub fn supported() -> bool;
pub fn nv2_supported() -> bool;
```

## 5. aarch64 FEAT_E0PD

`ID_AA64MMFR2_EL1.E0PD` (bits[63:60]):

| value | meaning                  |
|-------|--------------------------|
| 0     | not implemented          |
| 1     | TTBR1.E0PD1 + TTBR0.E0PD0 |

E0PD makes EL0 accesses to a half raise a translation fault
without the address being walked — defeats Meltdown-style
KASLR-bypass timing attacks even on cores that don't quote
KPTI as a mitigation.

`TCR_EL1` bits:
- `E0PD0` (bit 55) — restrict TTBR0 EL0 access.
- `E0PD1` (bit 56) — restrict TTBR1 EL0 access.

```rust
pub fn caps() -> u8;
pub fn supported() -> bool;
pub unsafe fn enable_kernel_half();         // sets TCR_EL1.E0PD1
pub unsafe fn disable_kernel_half();
```

## 6. Test surface

| smoke                            | asserts                          |
|----------------------------------|----------------------------------|
| `smoke_tme_supported_path`       | gate decoded, no panic           |
| `smoke_rtm_always_abort_path`    | gate decoded                     |
| `smoke_ecv_caps`                 | field ≤ 2                        |
| `smoke_nv2_caps`                 | field ≤ 2                        |
| `smoke_e0pd_caps`                | field ≤ 1                        |

## 7. Out of scope (v0.1)

- TME activation policy (the OS wraps a `[[bin]]` boot-stage
  hook; v0.1 only exposes the MSR surface).
- MKTME per-keyid programming (PCONFIG instruction; lands when
  the IOMMU pipeline grows multi-tenant accelerator support).
- ECV-driven CNTPOFF programming inside the hypervisor.
- NV2 shadow-page placement.
- E0PD plumbing into `memory/`'s page-table walker (only the
  TCR helper lives here).
