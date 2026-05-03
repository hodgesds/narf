# virt-confidential — Virtualization + confidential-computing detection

> Status: **v0.1** (Stage 5 land). Supplements
> `arch/specification/spec.md` §3 with the detection-only CPU
> surface for hardware virtualisation extensions and confidential-
> computing primitives.

This spec covers four detection surfaces:

  * **VMX** — Intel VMX root-mode capability decode.
  * **SVM** — AMD SVM capability decode.
  * **SGX** — Intel Software Guard Extensions enclave support.
  * **Confidential guest** — TDX (Intel) + SEV / SEV-ES /
    SEV-SNP (AMD) detection from inside the guest.

Hosting (entering VMX root, building a VMCB, etc.) is out of
scope for v0.1 — this lands the capability surfaces so the
boot path can advertise + future work can layer on top.

## 1. VMX (Intel)

### 1.1 Detection

CPUID(1).ECX[5] = `VMX`. Pre-condition: `IA32_FEATURE_CONTROL`
(MSR `0x3A`) has its `VMXON` lock bit set with VMXON enabled
in either / both VMX-outside-SMX / VMX-inside-SMX. NARF v0.1
just reads + reports — it does not flip the lock bit.

### 1.2 MSRs

| MSR    | name                          | content                  |
|--------|-------------------------------|--------------------------|
| 0x3A   | IA32_FEATURE_CONTROL          | lock + enable bits       |
| 0x480  | IA32_VMX_BASIC                | revision id + region size + memtype |
| 0x481  | IA32_VMX_PINBASED_CTLS        | allowed pin-based ctls   |
| 0x482  | IA32_VMX_PROCBASED_CTLS       | allowed proc-based ctls  |
| 0x483  | IA32_VMX_EXIT_CTLS            | allowed exit ctls        |
| 0x484  | IA32_VMX_ENTRY_CTLS           | allowed entry ctls       |
| 0x485  | IA32_VMX_MISC                 | misc capabilities        |
| 0x486  | IA32_VMX_CR0_FIXED0           | CR0 must-be-0 bits       |
| 0x487  | IA32_VMX_CR0_FIXED1           | CR0 must-be-1 bits       |
| 0x488  | IA32_VMX_CR4_FIXED0           | CR4 must-be-0 bits       |
| 0x489  | IA32_VMX_CR4_FIXED1           | CR4 must-be-1 bits       |
| 0x48A  | IA32_VMX_VMCS_ENUM            | max VMCS field index     |
| 0x48B  | IA32_VMX_PROCBASED_CTLS2      | secondary proc-based ctls |
| 0x48C  | IA32_VMX_EPT_VPID_CAP         | EPT + VPID capabilities  |

`IA32_VMX_BASIC` shape (low 64 bits):

| bits   | field                          |
|--------|--------------------------------|
| 30:0   | revision id                    |
| 44:32  | VMCS region size               |
| 48     | physical-address width (1 = 32-bit)|
| 49     | dual-monitor SMI support       |
| 53:50  | VMCS memory type               |
| 54     | INS/OUTS exit reporting        |
| 55     | true controls                  |

### 1.3 API shape

```rust
pub struct VmxBasic {
    pub revision_id:    u32,
    pub vmcs_region_size: u16,
    pub physaddr_32bit: bool,
    pub memory_type:    u8,
    pub true_ctls:      bool,
}

pub struct VmxCaps {
    pub supported:      bool,
    pub feature_locked: bool,
    pub vmxon_outside_smx: bool,
    pub basic:          VmxBasic,
    pub ept_supported:  bool,
    pub vpid_supported: bool,
    pub unrestricted_guest: bool,
    pub apicv:          bool,
    pub vmcs_shadowing: bool,
}

pub fn caps() -> VmxCaps;
pub unsafe fn read_basic() -> VmxBasic;
```

## 2. SVM (AMD)

### 2.1 Detection

CPUID(0x80000001).ECX[2] = `SVM`. Locked / disabled state via
`MSR_VM_CR` (`0xC0010114`).bit 4 (`SVMDIS`).

### 2.2 Capability MSRs / CPUID

| source               | content                                |
|----------------------|----------------------------------------|
| CPUID(0x8000000A).EAX[7:0]  | SVM revision (1, 2, ...)        |
| CPUID(0x8000000A).EBX       | number of ASIDs                 |
| CPUID(0x8000000A).EDX[0]    | NP (Nested Paging)              |
| CPUID(0x8000000A).EDX[1]    | LBR Virt                        |
| CPUID(0x8000000A).EDX[2]    | SVM Lock                        |
| CPUID(0x8000000A).EDX[3]    | NRIP Save                       |
| CPUID(0x8000000A).EDX[4]    | TSC Rate MSR                    |
| CPUID(0x8000000A).EDX[5]    | VMCB Clean bits                 |
| CPUID(0x8000000A).EDX[6]    | Flush-by-ASID                   |
| CPUID(0x8000000A).EDX[7]    | Decode Assists                  |
| CPUID(0x8000000A).EDX[10]   | Pause-Filter                    |
| CPUID(0x8000000A).EDX[12]   | PauseFilterThreshold            |
| MSR_VM_CR (0xC0010114).bit 4 | SVMDIS                         |

### 2.3 API shape

```rust
pub struct SvmCaps {
    pub supported:         bool,
    pub disabled:          bool,
    pub revision:          u8,
    pub n_asids:           u32,
    pub np:                bool,
    pub lbr_virt:          bool,
    pub svm_lock:          bool,
    pub nrip_save:         bool,
    pub tsc_rate_msr:      bool,
    pub vmcb_clean:        bool,
    pub flush_by_asid:     bool,
    pub decode_assists:    bool,
    pub pause_filter:      bool,
}

pub fn caps() -> SvmCaps;
```

## 3. SGX (Intel)

### 3.1 Detection

CPUID(7, 0).EBX[2] = `SGX` (instruction set support).
CPUID(0x12, 0).EAX[0] = `SGX1`; bit 1 = `SGX2`. `EBX` reports
`MISCSELECT` bitmap; `ECX` reports max enclave-page-cache index.

CPUID(0x12, 1) reports `ATTRIBUTES` allowed flags; CPUID(0x12, n)
for `n >= 2` enumerates EPC sections.

### 3.2 API shape

```rust
pub struct EpcSection {
    pub base:       u64,
    pub size_bytes: u64,
    pub valid:      bool,
}

pub struct SgxCaps {
    pub instruction_supported: bool,
    pub sgx1:                  bool,
    pub sgx2:                  bool,
    pub miscselect:            u32,
    pub max_size_64:           u8,
    pub max_size_32:           u8,
    pub epc_sections:          [Option<EpcSection>; 4],
}

pub fn caps() -> SgxCaps;
```

## 4. Confidential guest detection

### 4.1 TDX (Intel)

A TDX guest runs unmodified standard x86_64 code; the
distinguishing signal is the CPUID(0x21, 0) leaf which returns
`b"IntelTDX    "` (12 ASCII bytes spread across EBX/ECX/EDX
following the standard CPUID-vendor-string layout).

`MSR 0x6F` (`MSR_TDX_FIXED_PROPERTIES`) read inside TDX returns
TDX-specific property bits; outside TDX this MSR may #GP.

### 4.2 SEV / SEV-ES / SEV-SNP (AMD)

CPUID(0x8000001F).EAX bits indicate AMD memory-encryption
generations:

| bit | feature                                      |
|-----|----------------------------------------------|
| 0   | SME (Secure Memory Encryption)               |
| 1   | SEV (Secure Encrypted Virtualization)        |
| 3   | SEV-ES (Encrypted State)                     |
| 4   | SEV-SNP (Secure Nested Paging)               |

`MSR_AMD64_SEV` (`0xC001_0131`) inside a SEV guest:

| bit | meaning                          |
|-----|----------------------------------|
| 0   | SEV active                       |
| 1   | SEV-ES active                    |
| 2   | SEV-SNP active                   |

### 4.3 API shape

```rust
pub enum ConfidentialEnvironment {
    Bare,
    TdxGuest,
    SevGuest,
    SevEsGuest,
    SevSnpGuest,
}

pub fn detect_environment() -> ConfidentialEnvironment;
pub fn host_supports_sme() -> bool;
pub fn host_supports_sev() -> bool;
```

`detect_environment` returns the highest-confidence environment
classification. Inside a SEV-SNP guest it returns `SevSnpGuest`
(taking precedence over `SevEsGuest` / `SevGuest`); inside a
TDX guest it returns `TdxGuest`; otherwise `Bare`.

## 5. Test surface

| smoke                                | what it asserts                |
|--------------------------------------|--------------------------------|
| `vmx_caps_decode`                    | shape coherent; supported ⇒ basic.vmcs_region_size > 0 |
| `svm_caps_decode`                    | shape coherent; supported ⇒ revision > 0 |
| `sgx_caps_decode`                    | shape coherent; instr-supported ⇒ sgx1 = true |
| `confidential_detect_runs`           | `detect_environment()` returns a valid variant |

## 6. Out of scope (v0.1)

- VMXON / VMCB construction / VMRUN — actual hypervisor host code.
- SGX ECREATE / EADD / EINIT — enclave construction.
- TDX guest call flow (`TDCALL`).
- SEV-SNP page state changes (`PVALIDATE`, `RMPADJUST`).
- KVM hypercall interface (`KVM_CPUID_SIGNATURE`).
- Hyper-V root partition detection.
