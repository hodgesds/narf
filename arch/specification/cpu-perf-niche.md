# cpu-perf-niche — Tier-3 performance / niche CPU features

> Status: **v0.1**. Supplements `arch/specification/spec.md` and
> the modern-cpu / cpu-security specs with a batch of "niche but
> useful" CPU primitives. None are required for boot; each
> degrades gracefully if absent.

This spec covers, for x86_64:

  * **AMD INVLPGB / TLBSYNC** — broadcast TLB invalidation that
    skips the IPI dance on Zen3+.
  * **AMD RDPRU** — read selected MSRs from CPL = 3 without a
    syscall round-trip (`MPERF`, `APERF`).
  * **CLDEMOTE / MOVDIRI / MOVDIR64B** — cache-line hints +
    direct-store streaming.
  * **WRMSRNS** — non-serialising MSR write (Sapphire Rapids+).
  * **AVX10** — unified AVX-512 / AVX2 vector ISA enumeration.

For aarch64:

  * **SVE / SVE2** — Scalable Vector Extension caps + `ZCR_EL1`
    vector-length control.

## 1. AMD INVLPGB (`InstrEnc 0F 01 FE`)

### 1.1 Detection

CPUID(`0x8000_0008`).EBX[3] = `INVLPGB`. Implies TLBSYNC + a max
"pages-per-instruction" limit in EBX[31:16] (equiv. `ASID_MAX`)
and EAX[15:0] = `INVLPGB_COUNT_MAX`.

### 1.2 Operation

`INVLPGB` takes a virtual-address range + a flag word in
`RAX = vaddr | flags`, `ECX = ((nr_extra_pages << 0) | (asid <<
16))` etc., and broadcasts the invalidation across the CCX /
package without an IPI. Pair with `TLBSYNC` afterwards to wait
for completion (`TLBSYNC` blocks until all in-flight INVLPGB on
this CPU's home node have drained).

`RAX` flags:

| bit | field                           |
|-----|---------------------------------|
| 0   | VA valid                        |
| 1   | PCID/ASID valid                 |
| 2   | include global pages            |
| 3   | final-only (skip intermediate)  |
| 4   | nested (treat as guest TLB)     |

### 1.3 API

```rust
pub fn supported() -> bool;
pub fn count_max() -> u16;       // EAX[15:0]
pub fn asid_max() -> u16;        // EBX[31:16]
pub unsafe fn invlpgb(rax: u64, ecx: u32, edx: u32);
pub unsafe fn tlbsync();
pub unsafe fn invalidate_all_global();   // RAX flags = bit 2 only
pub unsafe fn invalidate_asid(asid: u16);
```

## 2. AMD RDPRU

### 2.1 Detection

CPUID(`0x8000_0008`).EBX[4] = `RDPRU` (Read Processor Register
at User level). Permits CPL = 3 reads of selected MSRs:

| ECX  | register read   |
|------|-----------------|
| 0    | MPERF           |
| 1    | APERF           |

Output goes to `EDX:EAX` like RDMSR. Future ECX values reserved.

### 2.2 API

```rust
pub fn supported() -> bool;
pub unsafe fn rdpru(reg: u32) -> u64;
pub fn read_mperf() -> u64;        // helper; falls back to RDMSR if needed
pub fn read_aperf() -> u64;
```

## 3. CLDEMOTE / MOVDIRI / MOVDIR64B

### 3.1 Detection

| feature      | CPUID                   |
|--------------|-------------------------|
| `CLDEMOTE`   | (7, 0).ECX[25]          |
| `MOVDIRI`    | (7, 0).ECX[27]          |
| `MOVDIR64B`  | (7, 0).ECX[28]          |

### 3.2 Semantics

- **`CLDEMOTE m8`** — hint to demote the line containing
  `m8` from L1 toward LLC; useful before producer/consumer hand-off
  on the same socket. Silent no-op if unsupported (the encoding is
  a `NOP` on older CPUs).
- **`MOVDIRI m32, r32`** — direct store of 4 / 8 bytes that
  bypasses the cache (write-combining). Useful for MMIO doorbells.
- **`MOVDIR64B m512, m512`** — 64-byte atomic store. Source +
  destination both memory; writes a full cache line atomically
  (no torn 64-B store on the consumer). Used for IDXD / DMA
  doorbells.

### 3.3 API

```rust
pub fn cldemote_supported() -> bool;
pub fn movdiri_supported() -> bool;
pub fn movdir64b_supported() -> bool;

pub unsafe fn cldemote(addr: *const u8);
pub unsafe fn movdiri32(dst: *mut u32, val: u32);
pub unsafe fn movdiri64(dst: *mut u64, val: u64);
pub unsafe fn movdir64b(dst: *mut u8, src: *const u8);
```

## 4. WRMSRNS

### 4.1 Detection

CPUID(7, 1).EAX[19] = `WRMSRNS` (Sapphire Rapids+). Encoded as
`0F 01 C6` and behaves like `WRMSR` minus the architectural
serialising side-effects — the next instruction can be issued
out of order.

### 4.2 Use cases

Hot-path MSR writes (TSC_DEADLINE, TSC_AUX, IA32_PKRS during
domain switch) shed ~50–100 cycles vs `WRMSR`.

### 4.3 API

```rust
pub fn supported() -> bool;
pub unsafe fn wrmsrns(msr: u32, value: u64);
```

## 5. AVX10

### 5.1 Detection

CPUID(7, 1).EDX[19] = `AVX10` enumeration leaf supported.
CPUID(`0x24`, 0):

| reg / bits | meaning                             |
|------------|-------------------------------------|
| EAX[7:0]   | AVX10 version                       |
| EBX[7:0]   | XMM size supported (always 1)       |
| EBX[8]     | YMM size supported                  |
| EBX[9]     | ZMM size supported                  |
| EBX[16]    | AVX10/256 converged with AVX-512    |

### 5.2 API

```rust
pub struct Avx10Caps {
    pub supported: bool,
    pub version:   u8,
    pub xmm:       bool,
    pub ymm:       bool,
    pub zmm:       bool,
}

pub fn caps() -> Avx10Caps;
```

## 6. aarch64 SVE / SVE2

### 6.1 Detection

`ID_AA64PFR0_EL1.SVE` (bits[35:32]) ≥ 1 indicates SVE.
`ID_AA64ZFR0_EL1.SVEver` (bits[3:0]):

| value | meaning  |
|-------|----------|
| 0     | SVE      |
| 1     | SVE2     |
| 2     | SVE2.1   |

`ZCR_EL1.LEN` (bits[3:0]) selects the per-EL vector length;
hardware-max from `ZCR_EL1` after writing `0xF`. Length-in-bits
= `(LEN + 1) * 128`.

### 6.2 API

```rust
pub struct SveCaps {
    pub sve:   bool,
    pub sve2:  bool,
    pub sve21: bool,
}

pub fn caps() -> SveCaps;
pub unsafe fn probe_max_vl_bits() -> u16;
pub unsafe fn set_vl_bits(bits: u16);
pub unsafe fn read_zcr_el1() -> u64;
pub unsafe fn write_zcr_el1(v: u64);
```

`caps()` reads only `ID_AA64PFR0_EL1` + `ID_AA64ZFR0_EL1` and is
safe regardless of `CPACR_EL1.ZEN`. `probe_max_vl_bits` /
`set_vl_bits` / `read|write_zcr_el1` all touch `ZCR_EL1` and
require `CPACR_EL1.ZEN` open + the boot CPU validation path to
have run.

## 7. Test surface

| smoke                                | asserts                               |
|--------------------------------------|---------------------------------------|
| `smoke_invlpgb_caps`                 | `count_max` / `asid_max` coherent     |
| `smoke_rdpru_supported_path`         | gated by CPUID, no panic              |
| `smoke_cldemote_no_op_path`          | runs even without HW support          |
| `smoke_movdir_caps_decode`           | bits decoded from CPUID(7,0).ECX      |
| `smoke_wrmsrns_supported_path`       | CPUID(7,1).EAX[19] gate               |
| `smoke_avx10_caps_decode`            | reports xmm bit when supported        |
| `smoke_sve_caps`                     | aarch64; SVE gate decoded             |

## 8. Out of scope (v0.1)

- INVLPGB error-recovery (unmapped page, ASID overflow) — caller
  asserts the range is currently mapped.
- AVX10/256 convergence policy (whether to fall back to AVX-512
  when AVX10/256 is the preferred form).
- SVE streaming-mode (`SME`) integration; SME is its own tier.
- CLDEMOTE-driven scheduler hand-off heuristics.
