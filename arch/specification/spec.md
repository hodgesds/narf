# arch — Specification

> Status: **Outline v0.2** (Stage 1→2). v0.2 splits the `DomainPrimitive`
> trait to acknowledge that PKS and MTE are structurally different —
> not two implementations of the same abstraction.

## 1. Purpose & scope

**Owns:** The Rust trait surface that abstracts CPU, MMU, interrupt
controller, timer, and cache operations. Per-arch crates (`arch-x86_64`,
`arch-aarch64`) implement the traits.

**Does NOT own:** Policy (who gets which domain, which IRQ goes where).
That lives in `frame/`, `memory/`, `interrupts/`.

## 2. Assumptions

- Boot environment hands control to the kernel with MMU either off or in
  a known identity-mapped state (see `boot/`).
- Exactly one arch backend is linked at build time; `#[cfg(target_arch)]`
  selects it.

## 3. Public interface

Sketched shape:

```rust
pub trait Cpu {
    fn halt() -> !;
    fn current_cpu() -> CpuId;
    unsafe fn enable_interrupts();
    unsafe fn disable_interrupts();
    fn feature_flags() -> FeatureFlags; // PKS, PKU, UIPI, MTE, PAC, ...
}

pub trait Mmu { /* map, unmap, tlb ops; base + huge page sizes */ }
pub trait IntCtrl { /* configure, mask, send_ipi, eoi */ }
pub trait Timer { /* read_counter, set_oneshot_ns */ }

/// Domain-rights primitive. The backends are NOT interchangeable —
/// see §4 and §5. Callers MUST use `DomainPrimitive::BACKEND` to
/// decide whether a single-instruction rights flip is available.
pub trait DomainPrimitive {
    const BACKEND: DomainBackend;     // Pks | Mte
    type SavedState: Copy;

    /// Read the live domain-rights state on this CPU into `out`.
    unsafe fn save(out: &mut Self::SavedState);

    /// Restore `s` to the live domain-rights state on this CPU.
    /// Must serialise with respect to subsequent loads / stores.
    unsafe fn restore(s: &Self::SavedState);

    /// Assign `domain` to `region`. On PKS, edits PTE PK bits.
    /// On MTE, writes tag storage for every 16-B granule in `region`;
    /// callers MUST NOT pass sub-granule ranges.
    unsafe fn assign(region: VirtRange, domain: DomainId);

    /// Rights-flip helper. On PKS this is a single `WRMSR IA32_PKRS`.
    /// On MTE there is no equivalent — the function reconfigures
    /// `SCTLR_EL1.TCF` and relies on pointer-tag discipline for the
    /// actual access check. Callers must not treat the two as
    /// performance-equivalent.
    unsafe fn set_rights(domain: DomainId, rights: DomainRights);
}

pub enum DomainBackend { Pks, Mte }
```

## 4. Invariants & safety properties

- All trait methods marked `unsafe` require the caller to hold the
  equivalent capability in `capabilities/` once Stage 3 is in place.
- Feature-flag queries are monotonic: a flag that is absent at boot is
  absent forever.
- The HAL never allocates; callers pass in storage.
- **`DomainPrimitive::BACKEND` is part of the type-level contract.**
  Code that depends on a single-instruction rights flip (e.g.
  `scheduler/` direct context transfer) must either pin to
  `BACKEND == Pks` via `#[cfg(target_arch = "x86_64")]` or provide a
  fallback that accepts the MTE discipline cost. Treating the two as
  symmetric is a bug, not a simplification.
- **All domain / TLB / cache / MSR intrinsics are wrapped with
  `compiler_fence(SeqCst)` before and after the `asm!`.** Under fat
  LTO (see `build/` §4) the `"memory"` clobber alone is not enough
  to prevent reordering of loads/stores around a privileged write.
  The `DomainPrimitive` impls, `Mmu::invlpg`, `Mmu::tlb_flush`, and
  cache-maintenance helpers are the only supported paths to the
  underlying instructions; they all carry the double-fence discipline.
  Callers must not reach around the HAL to raw `asm!`.
- **Required features fail boot, optional features degrade.** Boot
  panics if any of these are absent: PKS (x86_64) or MTE (aarch64),
  invariant TSC / Generic Timer, x2APIC / GICv3. Optional features
  (UIPI, CET, MTE2, PAC) degrade to software fallbacks where feasible.
  The `build/` subsystem emits the required CPU-feature flags at
  compile time so LLVM can emit the right intrinsics (PKRS manipulation,
  MTE tag-set instructions); missing the flag is a build-time error,
  not a runtime check.

## 5. Architecture notes

### x86_64

- Boot mode: long mode, provided by `boot/` via Limine or multiboot2.
- Feature detection via `CPUID`: PKS (leaf 7), PKU, UIPI.
- IntCtrl: x2APIC preferred; fall back to xAPIC.
- Timer: TSC deadline preferred; fall back to LAPIC timer.
- `DomainPrimitive::BACKEND = Pks`. `save` / `restore` are single
  MSR accesses (`RDMSR` / `WRMSR IA32_PKRS`). `assign` edits PTE PK
  bits and invalidates the TLB entry (typically via per-page INVLPG,
  batched where possible). `set_rights` is one `WRMSR`.

### aarch64

- Boot mode: EL1, MMU off, little-endian.
- Feature detection via `ID_AA64*_EL1` registers: MTE (`ID_AA64PFR1_EL1.MTE`),
  PAC (`ID_AA64ISAR1_EL1.APA/API`).
- IntCtrl: GICv3 (with ITS where present).
- Timer: generic timer (`CNTPCT_EL0`, `CNTP_CVAL_EL0`).
- `DomainPrimitive::BACKEND = Mte`. `save` / `restore` snapshot
  `SCTLR_EL1.TCF` and `TCR_EL1` MTE bits. `assign` writes tag storage
  for every 16-B granule in `region` via `STG` / `STGM`. `set_rights`
  has **no direct analogue to `WRMSR`** — it reconfigures `TCF` mode
  (sync / async / off) and relies on the pointer-tagging discipline in
  `memory/` §5 and `ipc/` §4 for the actual per-access check. A caller
  expecting PKS-style O(1) rights flip will be surprised on aarch64.

## 6. Dependencies

- **Consumes:** `boot/` (entry state), nothing from other subsystems.
- **Provides to:** every other subsystem. This spec is a fan-out root.

## 7. Stage assignment

Stage 1 (minimal trait + per-arch stubs sufficient to boot & print), Stage 2
(full surface: PKS/MTE, UIPI/GICv3 ITS, cache ops).

## 8. Open questions

- Should the HAL expose raw MSR/system-register access, or only typed helpers?
- Single workspace with `#[cfg]` vs. separate crates per arch — decide in
  Stage 1.
