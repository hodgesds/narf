# irq-cache-numa — Tier-9 IRQ remap + cache topology + NUMA

> Status: **v0.1**. Locks the surface for IRQ remapping (Intel
> IR + AMD GA), aarch64 GICv3 ITS, multi-level cache topology
> on both arches, and NUMA-affinity primitives.

For x86_64:

  * **Intel IR** — Interrupt Remap Table Entry (IRTE) layout
    + IR enable plumbing on top of the existing VT-d primitives.
  * **AMD GA** — Guest Address Mode detection.
  * **Cache topology** — CPUID(4) / CPUID(0x8000_001D) → per-
    level `(level, type, sets, ways, line, sharing-mask)`.

For aarch64:

  * **GICv3 ITS** — Interrupt Translation Service register
    block + caps decode + command-queue base programming.
  * **Cache topology** — CLIDR_EL1 + CCSIDR_EL1 enumeration.

For both:

  * **NUMA** — node count + per-CPU domain ID (x86 via SRAT
    callback; aarch64 via MPIDR_EL1.Aff{0..3} cluster decode).

## 1. Intel IR

### 1.1 IRTE layout

128-bit entry, `qword[0]` + `qword[1]`:

| qword[0] bits | field                                     |
|---------------|-------------------------------------------|
| 0             | present                                   |
| 1             | fault disable                              |
| 2             | dest-mode (0 = physical, 1 = logical)     |
| 4:3           | redirection-hint / trigger-mode bits       |
| 7:5           | delivery mode (000 = fixed, 100 = NMI)    |
| 11:8          | reserved                                   |
| 15:12         | vector                                     |
| 23:16         | source-validation type                     |
| 47:32         | destination ID                             |
| 63:48         | reserved                                   |

`qword[1]` carries the source-id + SVT data — kept opaque in
v0.1.

### 1.2 IR enable

Builds on the GCMD/GSTS bits already declared in `vtd`:

| bit | name  | meaning                                |
|-----|-------|----------------------------------------|
| 25  | IRE   | interrupt-remap enable                 |
| 24  | SIRTP | set interrupt-remap-table pointer      |

`IRTAR_REG` (`0xB8`) carries the `(table_base | extended-mode |
size)` programming.

### 1.3 API

```rust
pub struct Irte {
    pub present:         bool,
    pub fault_disable:   bool,
    pub dest_logical:    bool,
    pub vector:          u8,
    pub delivery_mode:   u8,
    pub destination:     u16,
}

pub fn encode_irte(e: Irte) -> [u64; 2];
pub fn decode_irte(raw: [u64; 2]) -> Irte;

pub const VTD_IRTAR: usize = 0xB8;

pub unsafe fn write_irtar(reg_base: usize, table_pa: u64, log2_size: u8);
```

## 2. AMD GA

CPUID(0x8000_001F).EAX carries the SEV-ES / GA-mode caps:

| bit | name        |
|-----|-------------|
| 0   | SME         |
| 1   | SEV         |
| 7   | GUEST_PHYSICAL_ADDR_PROTECT |
| 13  | DEBUG_VIRTUALIZATION |

GA-mode itself lives in the AMD-Vi `EXT_FEATURES` register —
bit 7 (`IASUP`) + bit 8 (`GASUP`) — already enumerated in the
existing `amd_vi` module. v0.1 just exposes a thin
`ga_supported()` predicate on top.

### 2.1 API

```rust
pub fn ga_supported(amd_vi_efr: u64) -> bool;
pub fn ia_supported(amd_vi_efr: u64) -> bool;
```

## 3. aarch64 GICv3 ITS

### 3.1 Register block

| offset   | name           | content                             |
|----------|----------------|-------------------------------------|
| `0x0000` | GITS_CTLR      | enable + ready                      |
| `0x0004` | GITS_IIDR      | implementer / version               |
| `0x0008` | GITS_TYPER     | caps (64-bit)                        |
| `0x0080` | GITS_CBASER    | command-queue base + cacheability   |
| `0x0088` | GITS_CWRITER   | command-queue write pointer         |
| `0x0090` | GITS_CREADR    | command-queue read pointer          |
| `0x0100` | GITS_BASER<n>  | per-table base / size               |

`GITS_TYPER` selected fields:

| bits  | field                              |
|-------|------------------------------------|
| 4:0   | ID-bits (DeviceID width)           |
| 12:8  | Devbits (per-device bits)          |
| 31:16 | Hardware Collection Count (HCC)    |
| 32    | Physical (1 = LPI delivery)        |

### 3.2 API

```rust
pub struct GitsCaps {
    pub id_bits:    u8,
    pub dev_bits:   u8,
    pub hcc:        u16,
    pub physical:   bool,
}

pub unsafe fn read_caps(reg_base: usize) -> GitsCaps;
pub unsafe fn enable(reg_base: usize);
pub unsafe fn disable(reg_base: usize);
pub unsafe fn write_cbaser(reg_base: usize, value: u64);
```

## 4. x86_64 cache topology

### 4.1 Detection

CPUID(4, n) on Intel and CPUID(0x8000_001D, n) on AMD share the
output shape:

| reg / bits | meaning                              |
|------------|--------------------------------------|
| EAX[4:0]   | cache type (1 = data, 2 = instr, 3 = unified, 0 = sentinel) |
| EAX[7:5]   | cache level                          |
| EAX[8]     | self-initialising                    |
| EAX[9]     | fully-associative                    |
| EAX[25:14] | "max APIC ids sharing this cache" - 1 |
| EAX[31:26] | "max cores in package" - 1            |
| EBX[11:0]  | line size - 1                         |
| EBX[21:12] | physical line partitions - 1          |
| EBX[31:22] | ways of associativity - 1             |
| ECX        | sets - 1                              |

### 4.2 API

```rust
#[derive(Copy, Clone, Debug)]
pub struct CacheLevel {
    pub level:           u8,
    pub kind:            CacheKind,
    pub line_bytes:      u16,
    pub partitions:      u16,
    pub ways:            u16,
    pub sets:            u32,
    pub size_bytes:      u32,        // line × partitions × ways × sets
    pub fully_assoc:     bool,
    pub apic_ids_sharing: u16,
}

pub enum CacheKind { Data, Instruction, Unified }

pub fn levels<F: FnMut(CacheLevel)>(mut f: F);
```

## 5. aarch64 cache topology

### 5.1 Detection

`CLIDR_EL1`:

| bits           | field                                    |
|----------------|------------------------------------------|
| 2:0  / 5:3 / … | per-level cache type (3-bit fields, levels 1..7) |
| 26:24          | LoUIS — Level of Unification Inner Shareable |
| 29:27          | LoUC  — Level of Unification Coherence       |

For each level, write `CSSELR_EL1` to select level + (D / I)
and read `CCSIDR_EL1`:

| bits  | field                            |
|-------|----------------------------------|
| 2:0   | log2(line bytes / 4)             |
| 12:3  | associativity - 1                |
| 27:13 | sets - 1                         |

### 5.2 API

```rust
pub fn levels<F: FnMut(CacheLevel)>(mut f: F);
```

(The struct definition is shared; aarch64 ignores
`apic_ids_sharing`.)

## 6. NUMA primitives

### 6.1 Per-CPU domain ID

x86_64: SRAT-derived. The arch crate exposes a hook
`set_apic_to_domain(cb)` that accepts a closure; callers in
`acpi/` install it after parsing the SRAT. `domain_for_apic_id`
returns the cached value.

aarch64: MPIDR_EL1 carries the affinity tuple. Aff{0..3} maps
naturally to NUMA: typical hardware uses Aff2 for the cluster
ID = NUMA domain.

### 6.2 API

```rust
// x86_64
pub fn set_apic_to_domain(cb: fn(u32) -> u8);
pub fn domain_for_apic_id(apic_id: u32) -> u8;

// aarch64
pub fn domain_for_current_cpu() -> u8;
pub fn cluster_id(mpidr: u64) -> u8;        // pure helper
```

## 7. Test surface

| smoke                              | asserts                            |
|------------------------------------|------------------------------------|
| `smoke_irte_encode_decode`         | round-trip preserves fields         |
| `smoke_amd_ga_predicate`           | predicate matches EFR.GASUP bit    |
| `smoke_gits_caps_decode`           | TYPER decode for synthetic value   |
| `smoke_x86_cache_levels_present`   | enumerator yields ≥ L1D            |
| `smoke_aarch_cache_levels_present` | enumerator yields ≥ L1             |
| `smoke_numa_cluster_id`            | aarch64 mpidr decode helper         |

## 8. Out of scope (v0.1)

- IRTE source-validation entry shape (qword[1]).
- ITS command-queue submission (MAPI / MAPC / INV / SYNC).
- Cache-coherence-domain partitioning beyond enumeration.
- NUMA distance matrix (SLIT decode lives in `acpi`).
- aarch64 GICv4 direct-injection.
