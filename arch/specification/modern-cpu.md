# modern-cpu — Modern x86_64 CPU features

> Status: **v0.1** (Stage 5 land). Supplements
> `arch/specification/spec.md` §3 with the surface for four
> "modern but not yet covered" facilities.

This spec covers:

  * **Hypervisor detection** — CPUID 0x40000000 leaves for KVM,
    Hyper-V, Xen, VMware.
  * **XSAVE state** — CPUID 0x0D enumeration, XCR0 + IA32_XSS
    enable bits for AVX-512 + AMX, XSAVE-area size discovery,
    XSAVES / XRSTORS instruction wrappers.
  * **WAITPKG** — UMWAIT / UMONITOR / TPAUSE for short user-or-
    kernel waits.
  * **AMD SMCA** — Scalable MCA: per-bank `MCi_CONFIG` /
    `MCi_IPID` / `MCi_SYND` / `MCi_DESTAT` registers Zen+ ships
    in addition to the legacy MCA bank shape.

## 1. Hypervisor detection

### 1.1 Detection

CPUID(1).ECX[31] = `Hypervisor Present`. Set inside any
hypervisor; clear on bare metal. When set, CPUID(0x40000000)
returns the hypervisor's vendor signature in EBX/ECX/EDX
(12 ASCII bytes, same encoding as CPUID(0).vendor).

### 1.2 Known signatures

| signature      | hypervisor                         |
|----------------|-----------------------------------|
| `KVMKVMKVM\0\0\0` | Linux KVM                       |
| `Microsoft Hv` | Hyper-V (incl. Windows guest VMs) |
| `XenVMMXenVMM` | Xen                                |
| `VMwareVMware` | VMware ESXi/Workstation           |
| `TCGTCGTCGTCG` | QEMU TCG (no acceleration)        |
| `bhyve bhyve ` | bhyve (FreeBSD)                   |
| `prl hyperv  ` | Parallels                         |
| `___ NARF ___` | Reserved for NARF-as-host         |

### 1.3 Capability sub-leaves

After identifying the hypervisor, sub-leaves at
`0x40000000 + i` enumerate caps:

- **KVM** (`KVMKVMKVM`):
  - `0x40000001`.EAX = bitmap of paravirt features
    (KVM_FEATURE_CLOCKSOURCE2, KVM_FEATURE_ASYNC_PF, ...).
- **Hyper-V** (`Microsoft Hv`):
  - `0x40000002` = build / version info.
  - `0x40000003`.EAX = HV_PARTITION_PRIVILEGES low half;
    EBX = high half.
  - `0x40000004` = recommendations.

NARF v0.1 surfaces just the vendor classification + the KVM /
Hyper-V version bits; full hypercall surfaces are out of scope.

### 1.4 API

```rust
pub enum Hypervisor {
    None,
    Kvm,
    HyperV,
    Xen,
    VMware,
    QemuTcg,
    Bhyve,
    Parallels,
    Other([u8; 12]),
}

pub fn detect() -> Hypervisor;
pub fn signature() -> Option<[u8; 12]>;
pub fn kvm_features() -> u32;       // KVM-specific; 0 elsewhere
pub fn hyperv_recommendations() -> u32;
```

## 2. XSAVE state management

### 2.1 Enumeration

CPUID(0x0D, 0):

| reg / bits        | meaning                                  |
|-------------------|------------------------------------------|
| EAX[31:0]         | XCR0 supported bits (low half)           |
| EBX               | XSAVE-area size for the currently-enabled XCR0 set |
| ECX               | XSAVE-area size for *all* user state (XCR0) |
| EDX[31:0]         | XCR0 supported bits (high half)          |

CPUID(0x0D, 1):

| reg / bits | meaning                                   |
|------------|-------------------------------------------|
| EAX[0]     | XSAVEOPT supported                        |
| EAX[1]     | XSAVEC supported (compacted)              |
| EAX[2]     | XGETBV with ECX = 1 supported             |
| EAX[3]     | XSAVES / XRSTORS supported                |
| EBX        | XSAVE-area size for XCR0 ∪ IA32_XSS       |
| ECX        | IA32_XSS-supported bitmap (low half)      |
| EDX        | IA32_XSS-supported bitmap (high half)     |

CPUID(0x0D, n) for `n >= 2` enumerates each component:

| reg / bits | meaning                                    |
|------------|--------------------------------------------|
| EAX        | size of component `n`                       |
| EBX        | offset of component `n` in the XSAVE area   |
| ECX[0]     | 0 = user-state (XCR0), 1 = supervisor (IA32_XSS) |
| ECX[1]     | aligned (matters in compacted form)         |

### 2.2 Component bits

| bit | component                         |
|-----|-----------------------------------|
| 0   | x87 (always set; legacy FXSAVE)   |
| 1   | SSE (always set on x86_64)        |
| 2   | AVX (YMM upper halves)            |
| 5   | AVX-512 opmask (k0..k7)           |
| 6   | AVX-512 ZMM_Hi256 (Z16..Z31 upper)|
| 7   | AVX-512 Hi16_ZMM (Z16..Z31)       |
| 9   | PKRU (Protection Keys)            |
| 17  | TILECFG (AMX)                     |
| 18  | TILEDATA (AMX)                    |

CR4.OSXSAVE (bit 18) must be set before XSAVE is usable; the
boot CPU validation already requires it.

### 2.3 Enable

`xsetbv(0, xcr0)` writes XCR0 with the user-state component
mask. Supervisor-state mask lives in `IA32_XSS` (`0xDA0`).

NARF's default XCR0:

```
    bit 0 (x87) | bit 1 (SSE) | bit 2 (AVX, if supported)
                | bit 5..7 (AVX-512, if supported)
                | bit 9 (PKRU, if PKU enabled)
                | bit 17..18 (AMX, if supported)
```

AMX additionally requires permission via the
`arch_prctl(ARCH_REQ_XCOMP_PERM, ...)` flow on Linux; the
NARF kernel-hosted equivalent is to set the bit in XCR0 once at
boot — userspace inherits via the standard XSAVE area layout.

### 2.4 API

```rust
pub struct XsaveCaps {
    pub xcr0_supported:    u64,
    pub xss_supported:     u64,
    pub area_size_xcr0:    u32,
    pub area_size_xcr0_xss:u32,
    pub xsaveopt:          bool,
    pub xsavec:            bool,
    pub xsaves:            bool,
    pub xgetbv1:           bool,
    pub avx:               bool,
    pub avx512:            bool,
    pub amx:               bool,
}

pub fn caps() -> XsaveCaps;
pub unsafe fn read_xcr0() -> u64;
pub unsafe fn write_xcr0(v: u64);
pub unsafe fn read_xss() -> u64;
pub unsafe fn write_xss(v: u64);
pub unsafe fn enable_default();   // sets XCR0 to caps.xcr0_supported & SAFE_BITS
pub unsafe fn xsave(buf: *mut u8, mask: u64);
pub unsafe fn xrstor(buf: *const u8, mask: u64);
```

## 3. WAITPKG

### 3.1 Detection

CPUID(7, 0).ECX[5] = `WAITPKG`.

### 3.2 Instructions

- **`UMONITOR rax`** — arm a monitor on the user-supplied
  linear address (no fault if unmapped, just no-arm).
- **`UMWAIT eax`** — wait until either the monitored address
  changes, or the deadline (TSC value in EDX:EAX). EAX[0]
  selects optimised vs default state. Bit 1 disables interrupt
  break. Returns `CF = 1` if timeout, `CF = 0` if monitor
  triggered.
- **`TPAUSE eax`** — same as UMWAIT but without arming a
  monitor; pauses for up to the deadline.

### 3.3 MSR

`IA32_UMWAIT_CONTROL` (`0xE1`):

| bits | field                                    |
|------|------------------------------------------|
| 0    | C0.2 disable (1 = forbid C0.2; only C0.1 used) |
| 31:2 | maximum wait time (TSC ticks, low 30 bits) |

Defaulting to `0` (no upper limit, both states allowed) suits
NARF's idle path.

### 3.4 API

```rust
pub fn supported() -> bool;
pub unsafe fn set_max_wait_tsc(ticks: u32, allow_c02: bool);
pub unsafe fn umonitor(addr: *const u8);
pub unsafe fn umwait(deadline_tsc: u64, optimised: bool) -> bool; // true = monitor fired
pub unsafe fn tpause(deadline_tsc: u64, optimised: bool) -> bool;
```

## 4. AMD SMCA (Scalable MCA)

### 4.1 Detection

CPUID(0x80000007).EBX[3] = `SMCA` (Scalable MCA). Available on
Zen+ silicon. NARF v0.1 surfaces the per-bank extended
registers; the legacy MCA shape we already decode in
`arch::x86_64::mce` continues to work for SMCA-disabled CPUs.

### 4.2 Per-bank extended MSRs

| MSR offset (per bank) | name        | content                |
|-----------------------|-------------|------------------------|
| `0xC000_2000 + 16*i`  | MCi_CONFIG  | bank-control bits      |
| `0xC000_2008 + 16*i`  | MCi_STATUS  | (mirrored from legacy) |
| `0xC000_2003 + 16*i`  | MCi_IPID    | hardware ID + bank type |
| `0xC000_2006 + 16*i`  | MCi_SYND    | syndrome                |
| `0xC000_2007 + 16*i`  | MCi_DESTAT  | deferred-error status  |
| `0xC000_2004 + 16*i`  | MCi_MISC0   | extended misc          |

`MCi_IPID` shape:

| bits   | field              |
|--------|--------------------|
| 15:0   | InstanceId         |
| 31:16  | HardwareId         |
| 47:44  | McaType            |
| 63:48  | reserved           |

`McaType` enumerates the bank: 0 = LS (Load-Store), 1 = IF
(Instruction Fetch), 2 = L2, 3 = DE (Decoder), 5 = EX
(Execution), 6 = FP, 7 = L3, 8 = MP5, ... (Zen-family deltas
between sub-architectures).

### 4.3 API

```rust
pub fn supported() -> bool;

#[derive(Copy, Clone, Debug)]
pub struct SmcaBankInfo {
    pub instance_id: u16,
    pub hardware_id: u16,
    pub mca_type:    u8,
}

pub unsafe fn read_ipid(bank: u8) -> u64;
pub unsafe fn read_synd(bank: u8) -> u64;
pub unsafe fn read_destat(bank: u8) -> u64;
pub unsafe fn read_config(bank: u8) -> u64;
pub fn decode_ipid(raw: u64) -> SmcaBankInfo;
```

## 5. Test surface

| smoke                              | what it asserts                |
|------------------------------------|--------------------------------|
| `hypervisor_detect_runs`           | returns a valid variant        |
| `hypervisor_signature_when_present`| CPUID(1).ECX[31] ⇒ signature is non-zero |
| `xsave_caps_decode`                | x87 + SSE bits set in supported |
| `waitpkg_supported_path`           | returns coherent + non-panicking |
| `smca_supported_path`              | returns coherent on AMD silicon |

## 6. Out of scope (v0.1)

- KVM / Hyper-V hypercall implementations (paravirt clock,
  apf, vmcall surface).
- Per-bank `XSAVE` lazy-restore of AMX TILE state.
- Full `arch_prctl(ARCH_REQ_XCOMP_PERM)` user-permission
  delegation.
- TPAUSE-driven scheduler-tick smoothing.
- AMD MCA error-thresholding / corrected-error reporting via
  the deferred-error vector.
