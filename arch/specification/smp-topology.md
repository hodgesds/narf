# smp-topology — SMP bring-up + CPU topology + hybrid hints

> Status: **v0.1** (Stage 5 land). Supplements `arch/specification/
> spec.md` §3 with the concrete surface for multi-CPU enumeration,
> AP bring-up, and hybrid-CPU scheduling hints.

This spec covers four primitives:

  * **CPU topology** — CPUID 4 / 0xB / 0x1F decoded into `(sockets,
    cores_per_socket, threads_per_core)` + per-level cache geometry.
  * **AP bring-up** — INIT-IPI → SIPI-IPI sequence to start
    application processors.
  * **Intel HFI / Thread Director** — class-based scheduling hints
    on Alder Lake+ hybrid CPUs.
  * **Idle-loop cooperation** — APs land in the kernel idle task
    after their boot trampoline drops them into long mode + the
    per-CPU GDT/IDT/TSS.

It locks the API shape so `scheduler/`, `frame/`, and
`observability/` can be coded against a stable surface even
before SMP is fully wired into the boot path.

## 1. CPU topology decoding

### 1.1 Detection priority

| priority | leaf                     | gate                               |
|----------|--------------------------|------------------------------------|
| 1        | CPUID 0x1F (V2 ext topo) | available when `CPUID(0).EAX >= 0x1F` and leaf returns non-zero EBX |
| 2        | CPUID 0x0B (ext topo)    | available when `CPUID(0).EAX >= 0xB` and leaf returns non-zero EBX |
| 3        | CPUID 0x01 (legacy)      | always; gives only HT-thread count |

Leaves `0x1F` and `0x0B` are both probed by sub-leaf (ECX). The
caller iterates ECX = 0, 1, ... until a sub-leaf returns
`EAX = 0` (no more levels).

### 1.2 Wire format

| leaf | sub-leaf      | output meaning                                |
|------|---------------|-----------------------------------------------|
| 0x0B | 0 (SMT)       | `EAX[4:0]` = bits to shift APIC for next-level id; `EBX[15:0]` = logical processors at this level; `ECX[15:8]` = level type (1=SMT, 2=Core) |
|      | 1 (Core)      | same fields                                   |
| 0x1F | 0..N          | adds Module / Tile / Die / Domain levels      |

### 1.3 Cache geometry (leaf 4)

Sub-leaf-iterated. For sub-leaf `i`:

| field                    | bits in EAX/EBX/ECX                       |
|--------------------------|-------------------------------------------|
| Cache type               | EAX[4:0] (1=data, 2=instr, 3=unified, 0=null end) |
| Cache level              | EAX[7:5] (1, 2, 3)                        |
| Self-init                | EAX[8]                                    |
| Fully-associative        | EAX[9]                                    |
| Max threads sharing      | EAX[25:14] + 1                            |
| Cores per package        | EAX[31:26] + 1                            |
| Line size                | EBX[11:0] + 1                             |
| Partitions               | EBX[21:12] + 1                            |
| Ways                     | EBX[31:22] + 1                            |
| Sets                     | ECX + 1                                   |
| Total bytes              | line × partitions × ways × sets           |

### 1.4 Hybrid classification

CPUID(7, 0).EDX[15] = `Hybrid` bit. When set, CPUID(0x1A, 0).EAX
encodes the core's "native model id":

| bits  | type              |
|-------|-------------------|
| 31:24 | Core type byte    |

Type byte:

| value | core type   |
|-------|-------------|
| 0x20  | Atom (E)    |
| 0x40  | Core (P)    |

### 1.5 API shape

```rust
pub struct LevelInfo {
    pub kind:                 LevelKind,  // Smt, Core, Module, Die, Package
    pub apic_shift:           u8,         // bits to shift right
    pub logical_at_this_level: u32,       // count
}

pub struct Topology {
    pub levels:              [Option<LevelInfo>; 6],
    pub n_levels:            u8,
    pub package_count:       u32,         // best-effort (== 1 on TCG)
    pub core_count:          u32,
    pub thread_count:        u32,
    pub hybrid:              bool,
}

pub struct CacheLevelInfo {
    pub level:                u8,
    pub kind:                 CacheKind,  // Data, Instr, Unified
    pub bytes:                u64,
    pub line_size:            u16,
    pub ways:                 u16,
    pub sets:                 u32,
    pub max_threads_sharing:  u32,
    pub fully_associative:    bool,
}

pub fn discover() -> Topology;
pub fn discover_caches() -> [Option<CacheLevelInfo>; 4];
```

## 2. AP bring-up (INIT/SIPI)

### 2.1 Sequence (Intel SDM Vol 3 §9.4.4.1 "MP Initialization Protocol")

For each AP discovered via the MADT (`narf_arch::x86_64::acpi`):

  1. **INIT-IPI**: write `LAPIC.ICR_HI = (apic_id << 24)`,
     `LAPIC.ICR_LO = 0x000C_4500` (delivery=INIT, level=assert,
     destmode=physical).
  2. Spin ~10 ms.
  3. **INIT-IPI deassert**: `ICR_LO = 0x0008_8500` (level=deassert).
  4. Spin ~10 ms.
  5. **First SIPI**: `ICR_LO = 0x0000_4600 | (vector & 0xFF)` where
     `vector = trampoline_phys >> 12`. Trampoline must live below
     1 MiB (the SIPI vector field is 8 bits scaled by 4 KiB).
  6. Spin 200 µs, send the SIPI again (per SDM: "if spin loops
     don't observe AP started, send second SIPI").
  7. Wait for the AP to bump a per-CPU "alive" flag.

### 2.2 Trampoline

The AP boots in 16-bit real mode at `vector << 12`. The
trampoline (NARF places it at `0x9000`):

  1. Sets up a basic GDT in real mode.
  2. Switches to protected mode (`CR0.PE`).
  3. Loads CR3 with the kernel's pre-built page tables.
  4. Sets `EFER.LME` + `CR4.PAE`.
  5. Switches to long mode via `lretq`.
  6. Jumps to `ap_long_mode_entry(cpu_id)` which loads the
     per-CPU GDT/IDT/TSS, marks itself "alive", and enters the
     idle task.

### 2.3 LAPIC ICR layout

| reg     | offset | content                          |
|---------|--------|----------------------------------|
| ICR_LO  | 0x300  | vector + delivery + flags        |
| ICR_HI  | 0x310  | dest APIC id (bits[31:24])       |

x2APIC variant: `MSR_X2APIC_ICR (0x830)` — single 64-bit write,
`(dest << 32) | (icr_lo bits)`.

### 2.4 API shape

```rust
pub struct ApBringUpResult {
    pub apic_id: u32,
    pub started: bool,
    pub boot_time_us: u64,
}

pub fn aps_from_madt(t: &narf_arch::x86_64::acpi::Tables) -> alloc::vec::Vec<u32>;

pub unsafe fn install_trampoline(phys: u64);

pub unsafe fn start_ap(apic_id: u32, trampoline_phys: u64) -> ApBringUpResult;

pub fn alive_count() -> u32;
```

## 3. Intel HFI / Thread Director

### 3.1 Detection

CPUID(7, 1).EAX[19] = `HFI`. CPUID(0x14, 0) carries the structure
size + content. Hardware Feedback only meaningful on hybrid CPUs;
gate on `topology().hybrid` AND HFI bit.

### 3.2 MSRs (SDM Vol 4 §14.6)

| MSR    | name                          | width | direction |
|--------|-------------------------------|-------|-----------|
| 0x17D0 | IA32_HW_FEEDBACK_PTR          | u64   | RW        |
| 0x17D1 | IA32_HW_FEEDBACK_CONFIG       | u64   | RW        |
| 0x17D2 | IA32_THREAD_FEEDBACK_CHAR     | u64   | RW        |
| 0x17D3 | IA32_HW_FEEDBACK_THREAD_CONFIG| u64   | RW        |

`IA32_HW_FEEDBACK_PTR` carries a 4 KiB-aligned phys address +
bit 0 = valid. The CPU writes a structured 4 KiB block at that
phys (per-class capabilities + change indicators).

`IA32_HW_FEEDBACK_CONFIG`:
  bit 0 = enable HFI
  bit 1 = enable interrupt on update (we leave 0; we poll)

The HFI structure layout (per SDM Vol 4 §14.6.3):

```
struct hfi_global {
  u32 timestamp;
  u8  reserved[60];
  // ... per-class entries follow
}
```

We don't decode the rich content in v0.1 — just read the
timestamp + bump-on-change + log when classes shift.

### 3.3 API shape

```rust
pub struct HfiCaps {
    pub supported: bool,
    pub n_classes: u8,           // CPUID(0x14, 0).EAX[7:0]
    pub size_bytes: u32,         // CPUID(0x14, 0).EBX
}

pub fn caps() -> HfiCaps;

/// Install the per-package feedback page. Caller allocates a 4 KiB
/// coherent page; the CPU writes class hints there.
pub unsafe fn install(page_phys: u64);

pub unsafe fn enable();
pub unsafe fn disable();

pub fn read_timestamp(page_phys: u64) -> u32;
```

## 4. Test surface

| smoke                              | what it asserts                |
|------------------------------------|--------------------------------|
| `topology_discover_levels`         | `discover()` returns ≥ 1 level + plausible thread_count |
| `topology_caches_l1_l2`            | every level has line=64, ways≥2, bytes≥4096 |
| `smp_aps_from_madt`                | when ACPI present, returns the BSP-relative AP list |
| `hfi_caps_when_hybrid`             | `supported = true` ⇒ `n_classes >= 2` |

## 5. Out of scope (v0.1)

- Actually starting APs in the boot path (the
  `start_ap` surface lands; calling it from `frame/main.rs` is
  the next-stage commit gated on per-CPU GDT/IDT/TSS scaffolding).
- Trampoline blob compilation (a 16-bit asm stub is needed —
  this v0.1 ships the LAPIC ICR write surface; the trampoline
  itself lands separately).
- HFI interrupt-driven updates (we poll).
- Class-based scheduling actually consuming HFI hints — that
  requires the `scheduler/` policy hook + per-task class
  tracking.
- Full V2 extended topology (CPUID 0x1F) Module / Tile / Die /
  Domain levels are decoded structurally but NARF v0.1
  collapses them into "Package" for scheduling purposes.
