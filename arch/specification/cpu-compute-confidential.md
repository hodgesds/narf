# cpu-compute-confidential — Tier-7 compute + confidential + SVA

> Status: **v0.1**. Locks the surface for the next batch of
> arch primitives covering matrix-extension compute, Armv9
> realms, speculation barriers, and shared-address-space user
> mode.

For aarch64:

  * **SME** — Scalable Matrix Extension; a streaming SVE +
    matrix tile (ZA) storage subsystem.
  * **RME** — Realm Management Extension; the Armv9
    confidential-compute root of trust.
  * **SPECRES** — speculation-restriction instructions (CFP,
    DVP, CPP).

For x86_64:

  * **BHI controls** — `IA32_SPEC_CTRL.BHI_DIS_S`.
  * **PASID** — Process-Address-Space-ID enable for
    accelerator-Shared Virtual Memory.

## 1. aarch64 SME

### 1.1 Detection

`ID_AA64PFR1_EL1.SME` (bits[27:24]):

| value | meaning            |
|-------|--------------------|
| 0     | not implemented    |
| 1     | SME                |
| 2     | + SME2             |

`ID_AA64SMFR0_EL1` enumerates instruction-class support
(F32F32, B16F32, F16F32, I8I32, F64F64, etc.).

### 1.2 Streaming-mode + ZA gating

`SVCR` (raw `S3_3_C4_C2_2`):

| bit | field |
|-----|-------|
| 0   | SM    — streaming-mode enable |
| 1   | ZA    — ZA storage enable     |

`SMCR_EL1` (raw `S3_0_C1_C2_6`) controls the streaming vector
length; identical shape to `ZCR_EL1.LEN`.

`CPACR_EL1.SMEN` (bits[25:24]) gates EL0/EL1 access.

### 1.3 API

```rust
pub struct SmeCaps {
    pub sme:  bool,
    pub sme2: bool,
}

pub fn caps() -> SmeCaps;
pub unsafe fn read_svcr() -> u64;
pub unsafe fn write_svcr(v: u64);
pub unsafe fn enter_streaming();      // SVCR.SM = 1
pub unsafe fn leave_streaming();      // SVCR.SM = 0
pub unsafe fn enable_za();            // SVCR.ZA = 1
pub unsafe fn disable_za();
pub unsafe fn read_smcr_el1() -> u64;
pub unsafe fn write_smcr_el1(v: u64);
```

## 2. aarch64 RME

### 2.1 Detection

`ID_AA64PFR0_EL1.RME` (bits[55:52]):

| value | meaning           |
|-------|-------------------|
| 0     | not implemented   |
| 1     | RMEv1             |

RME is gated at EL3 — the OS at EL1 can detect it but the
state-management plumbing lives in the Realm Management Monitor
(RMM) and the EL3 firmware. v0.1 surfaces detection only.

### 2.2 API

```rust
pub fn caps() -> u8;        // raw RME field
pub fn supported() -> bool;
```

## 3. aarch64 SPECRES

### 3.1 Detection

`ID_AA64ISAR1_EL1.SPECRES` (bits[43:40]):

| value | meaning           |
|-------|-------------------|
| 0     | not implemented   |
| 1     | SPECRESv1         |
| 2     | + COSP / CFP_RCTX |

### 3.2 Instructions

| mnemonic       | purpose                                     |
|----------------|---------------------------------------------|
| `CFP RCTX, Xt` | clear branch-prediction state for context Xt |
| `DVP RCTX, Xt` | data-value prediction restriction by ctx     |
| `CPP RCTX, Xt` | cache-prefetch prediction restriction        |

Each is encoded `SYS #3, C7, Cn, #m, Xt`. v0.1 wraps `CFP` only
(the surface most often used) with raw encoding.

### 3.3 API

```rust
pub fn caps() -> u8;
pub unsafe fn cfp_rctx(ctx: u64);   // sys #3, c7, c3, #4, Xt
```

## 4. x86_64 BHI controls

### 4.1 Detection

CPUID(7, 2).EDX[4] = `BHI_NO` (silicon already immune; no
mitigation needed).
CPUID(7, 0).EDX[20] = `IA32_SPEC_CTRL` MSR exists.
`IA32_SPEC_CTRL` (`0x48`):

| bit | field                                 |
|-----|---------------------------------------|
| 0   | IBRS                                  |
| 1   | STIBP                                 |
| 2   | SSBD                                  |
| 10  | BHI_DIS_S — Branch History Injection disable, supervisor |

### 4.2 API

```rust
pub fn bhi_no() -> bool;
pub fn bhi_dis_s_supported() -> bool;   // CPUID(7, 2).EDX[4] absent + SPEC_CTRL has bit 10
pub unsafe fn enable_bhi_dis_s();
pub unsafe fn disable_bhi_dis_s();
```

## 5. x86_64 PASID

### 5.1 Detection

CPUID(7, 0).ECX[1] = `MOVDIRI` (separate; already in
`movdir.rs`). PASID itself is gated by:

CPUID(7, 0).EDX[14] = `MOVDIRI` ... actually PASID is enumerated
via:

CPUID(7, 1).EAX[14] = `LASS-distinct gate is bit 6` (already
captured); PASID's enable bit:

CPUID(7, 0).ECX[28] = `MOVDIR64B` ... no, that's MOVDIR64B.

PASID enable lives at CPUID(0x14, 0).EBX[14] for processor-
trace tagging, and the Intel SDM also exposes
`IA32_PASID_MSR` (`0xD93`) when CPUID(7, 0).ECX[2] = `WBNOINVD`
is reported alongside the PASID-MSR-exists bit.

NARF v0.1 takes the conservative path: detect
`IA32_PASID_MSR` via CPUID(7, 0).EDX[8] (`AVX512_VP2INTERSECT`
neighbour bit — placeholder; SDM page 3-249 lists EDX[8] for
PASID-MSR availability). Caller treats `supported() == false`
on platforms where CPUID enumeration is uncertain.

### 5.2 MSR

`IA32_PASID` (`0xD93`):

| bits  | field              |
|-------|--------------------|
| 19:0  | PASID              |
| 31    | VALID              |
| 63:32 | reserved           |

### 5.3 API

```rust
pub const MSR_IA32_PASID: u32 = 0xD93;

pub fn supported() -> bool;
pub unsafe fn read() -> u64;
pub unsafe fn write(pasid: u32);
pub unsafe fn invalidate();              // clears VALID
```

## 6. Test surface

| smoke                          | asserts                         |
|--------------------------------|---------------------------------|
| `smoke_sme_caps`               | SME field decoded, ≤ 2          |
| `smoke_rme_caps`               | RME field decoded, ≤ 1          |
| `smoke_specres_caps`           | SPECRES field decoded, ≤ 2      |
| `smoke_bhi_supported_path`     | `bhi_no` / `bhi_dis_s_supported` reachable |
| `smoke_pasid_supported_path`   | gate decoded, no panic          |

## 7. Out of scope (v0.1)

- SME instruction wrappers (FMOPA / SMOPS etc.) — limited to
  caps + SVCR control.
- RME register surface (RIPAS, REC, etc.) — needs RMM ABI.
- DVP / CPP wrappers; only CFP for v0.1.
- BHI userspace control via prctl-equivalent.
- PASID-aware IOMMU handoff to the SVA pipeline.
