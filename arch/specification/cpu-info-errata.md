# cpu-info-errata — Tier-4 CPU info + errata + PMI binding

> Status: **v0.1**. Supplements the previous arch tiers with the
> "we already had to compute this; expose it cleanly" surface.

Covers, for x86_64:

  * **CPU identification** — vendor + brand string + family /
    model / stepping / signature.
  * **Cache geometry** — line size, CLFLUSH / CLFLUSHOPT / CLWB
    detection + wrappers.
  * **CPU errata workarounds** — small per-vendor table that
    matches on (family, model) and applies known fix-ups.
  * **PMI vector binding** — LAPIC LVT-PC (`0xFEE0_0340`)
    programming + per-CPU PMI handler hook.

For aarch64:

  * **MIDR_EL1 / REVIDR_EL1 decode** — implementer + part + rev.
  * **CTR_EL0 decode** — D-cache + I-cache line widths via
    DminLine / IminLine.
  * **Errata table mirror** — same shape as x86 errata, dispatched
    on implementer + part.

## 1. x86_64 CPU identification

### 1.1 Vendor

CPUID(0).EBX:EDX:ECX = 12-byte ASCII vendor string.
Common signatures (decode by exact match):

| signature      | enum                |
|----------------|---------------------|
| `GenuineIntel` | `Intel`             |
| `AuthenticAMD` | `Amd`               |
| `HygonGenuine` | `Hygon`             |
| `CentaurHauls` | `Centaur`           |
| `VIA VIA VIA`  | `Via`               |
| `  Shanghai  ` | `Zhaoxin`           |
| anything else  | `Other([u8; 12])`   |

### 1.2 Family / Model / Stepping

CPUID(1).EAX:

| bits  | field            |
|-------|------------------|
| 3:0   | stepping         |
| 7:4   | base model       |
| 11:8  | base family      |
| 13:12 | processor type   |
| 19:16 | extended model   |
| 27:20 | extended family  |

Effective values (per SDM §3.2 "CPUID-EAX = 1"):

```
family   = base_family + (base_family == 0xF ? extended_family : 0)
model    = base_model | ((base_family >= 6 || base_family == 0xF)
                         ? (extended_model << 4) : 0)
```

### 1.3 Brand string

CPUID(0x8000_0002 / 0x8000_0003 / 0x8000_0004) — 48-byte ASCII
brand string. Trim trailing NUL + leading spaces for display.

### 1.4 API

```rust
pub enum Vendor {
    Intel, Amd, Hygon, Centaur, Via, Zhaoxin,
    Other([u8; 12]),
}

pub struct CpuId {
    pub vendor:    Vendor,
    pub family:    u16,
    pub model:     u16,
    pub stepping:  u8,
    pub signature: u32,            // raw CPUID(1).EAX
    pub brand:     [u8; 48],       // NUL-padded
}

pub fn read() -> CpuId;
pub fn brand_str(c: &CpuId) -> &str;
```

## 2. x86_64 cache geometry

### 2.1 Line size

Two equivalent sources for the L1D line size:

- **CPUID(1).EBX[15:8]** = `CLFLUSH line size / 8` (legacy).
- **CPUID(0x80000006).ECX[7:0]** = L2 cache line size (AMD).

NARF v0.1 reports the CPUID(1) value as `clflush_line_bytes`
and L1/L2/L3 line sizes from leaf 4 / 0x8000_001D when present.

### 2.2 Detection

| feature      | CPUID                       |
|--------------|-----------------------------|
| `CLFLUSH`    | (1).EDX[19]                 |
| `CLFLUSHOPT` | (7, 0).EBX[23]              |
| `CLWB`       | (7, 0).EBX[24]              |
| `WBNOINVD`   | (0x80000008).EBX[9] (AMD)   |

### 2.3 API

```rust
pub struct CacheCaps {
    pub clflush:    bool,
    pub clflushopt: bool,
    pub clwb:       bool,
    pub wbnoinvd:   bool,
    pub line_bytes: u16,
}

pub fn caps() -> CacheCaps;
pub unsafe fn clflush(p: *const u8);
pub unsafe fn clflushopt(p: *const u8);
pub unsafe fn clwb(p: *const u8);
pub unsafe fn wbnoinvd();
```

## 3. x86_64 errata workarounds

A tiny lookup table — Stage 1 only carries entries that affect
boot. Each entry maps `(vendor, family, model_min..=model_max,
stepping_mask)` → a closure invoked once per AP after CPU
identification, before the AP enters the scheduler.

v0.1 entries:

  * **Intel Skylake-X / SKL-SP `KBL027`** — disable TSX-RTM via
    `MSR_IA32_TSX_CTRL` if the platform microcode advertises
    the TSX_CTRL MSR (CPUID(7,0).EDX[29]). Marker only — the
    actual TSX disable lives in `spec_ctrl`.
  * **AMD Zen1 errata 1474** — set `MSR_DE_CFG[9]` to limit
    address-space sharing across SMT siblings.

Both are no-ops on hardware that doesn't match. The table is
designed to be appended without touching call sites; the
intended future shape is a `&'static [Errata]` array sorted by
vendor.

### 3.1 API

```rust
pub struct Errata {
    pub name:        &'static str,
    pub vendor:      Vendor,
    pub family:      u16,
    pub model_lo:    u16,
    pub model_hi:    u16,
    pub stepping_mask: u32,        // bit `s` set ⇒ apply at stepping s
    pub apply:       unsafe fn(),
}

pub fn table() -> &'static [Errata];
pub unsafe fn apply_for_current_cpu();
```

## 4. PMI vector binding

PMU + LBR + Intel-PT all funnel through the LAPIC LVT-PC entry
at `LAPIC_BASE + 0x340`. Until a vector is installed, overflow
events are masked.

```
LVT_PC layout (Intel SDM Vol 3 §10.5.1):
  bits[7:0]   = vector
  bits[10:8]  = delivery mode (000 = fixed, 100 = NMI)
  bit  16     = mask
```

The PMU subsystem takes a hook + vector; the arch crate just
exposes the programming primitive.

### 4.1 API

```rust
pub const LAPIC_LVT_PC_OFFSET: u32 = 0x340;

/// Program the LVT-PC entry at `lapic_base + 0x340`.
///
/// `delivery = 0` for fixed (default), `delivery = 4` for NMI
/// (used when the PMI is meant to interrupt unconditionally
/// even with IF clear).
pub unsafe fn program_lvt_pc(lapic_base: usize, vector: u8,
                              nmi: bool, masked: bool);
pub unsafe fn mask_lvt_pc(lapic_base: usize);
pub unsafe fn unmask_lvt_pc(lapic_base: usize);
```

## 5. aarch64 mirror

### 5.1 MIDR_EL1

| bits  | field        |
|-------|--------------|
| 31:24 | implementer  |
| 23:20 | variant      |
| 19:16 | architecture |
| 15:4  | part number  |
| 3:0   | revision     |

Implementer codes (Arm DDI 0487):

| value | implementer        |
|-------|--------------------|
| `0x41` | Arm Limited       |
| `0x42` | Broadcom          |
| `0x43` | Cavium            |
| `0x44` | DEC               |
| `0x46` | Fujitsu           |
| `0x49` | Infineon          |
| `0x4D` | Motorola / Freescale |
| `0x4E` | NVIDIA            |
| `0x50` | Applied Micro     |
| `0x51` | Qualcomm          |
| `0x53` | Samsung           |
| `0x56` | Marvell           |
| `0x61` | Apple             |
| `0x66` | Faraday           |
| `0x69` | Intel             |
| `0xC0` | Ampere            |

### 5.2 CTR_EL0

| bits  | field                              |
|-------|------------------------------------|
| 3:0   | IminLine — words (4-byte) in I-line |
| 19:16 | DminLine — words in smallest D-line |
| 27:24 | CWG — cache-writeback granule       |
| 31:28 | format / arch revision              |

Line-size-in-bytes = `4 << field`.

### 5.3 API

```rust
pub struct AarchIdent {
    pub implementer: u8,
    pub variant:     u8,
    pub part:        u16,
    pub revision:    u8,
    pub raw:         u64,
}

pub fn ident() -> AarchIdent;

pub struct AarchCacheCaps {
    pub iline_bytes: u16,
    pub dline_bytes: u16,
    pub cwg_bytes:   u16,
}

pub fn cache_caps() -> AarchCacheCaps;
```

## 6. Test surface

| smoke                                 | asserts                              |
|---------------------------------------|--------------------------------------|
| `smoke_x86_ident_decode`              | vendor parses, family ≥ 6 on QEMU    |
| `smoke_x86_brand_string_nonempty`     | brand string contains at least one ASCII non-space byte |
| `smoke_x86_cache_caps`                | `line_bytes` ≥ 32 on QEMU            |
| `smoke_x86_errata_table_sorted`       | table is sorted (vendor, family, model_lo) |
| `smoke_lvt_pc_program_helper`         | mask + unmask round-trips through a buffer |
| `smoke_aarch_midr_decode`             | implementer / part nonzero on QEMU virt |
| `smoke_aarch_cache_caps`              | iline/dline ≥ 16 on QEMU virt         |

## 7. Out of scope (v0.1)

- Topology-aware errata application (per-die / per-CCX scope).
- Errata revocation when microcode update lands later in boot.
- aarch64 erratum auto-application (we only carry the table).
- PMI delivery-mode arbitration with HFI / SMI handlers.
- Brand-string canonicalisation (Intel's "Genuine Intel(R)
  CPU @ ..." prefix collapsing).
