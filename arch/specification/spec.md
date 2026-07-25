# arch — Specification

> Status: **v1.0** (Stage 2 design lock). v0.2 split DomainPrimitive
> into a backend-aware trait; v1.0 locks the MSR/system-register
> access policy, the crate layout, the canonical idle primitive
> (`idle_halt_then_disable`), the per-arch MMIO discipline, and
> the SDK ABI versioning policy.

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

/// Current-CPU speculative-execution policy. Remote changes require an
/// IPI/rendezvous that executes this function on the target CPU.
pub enum speculation::Policy { Disabled, Protected }
pub enum speculation::State {
    Unconfigured, Disabled, Protected, Unsupported, Failed,
}
pub unsafe fn speculation::configure_current_cpu(
    policy: speculation::Policy,
) -> speculation::State;
pub fn speculation::state(cpu: usize) -> speculation::State;

#[cfg(target_arch = "x86_64")]
pub unsafe fn pmu::arm_sampling(
    counter: &pmu::PmuCounter,
    period: u64,
) -> Result<(), pmu::PmuError>;
#[cfg(target_arch = "x86_64")]
pub unsafe fn pmu::handle_sampling_overflow() -> u8;
#[cfg(target_arch = "x86_64")]
pub unsafe fn pmu::pause_sampling(
    counter: &pmu::PmuCounter,
) -> Result<(), pmu::PmuError>;
#[cfg(target_arch = "x86_64")]
pub unsafe fn pmi::program_current_lvt_pc(vector: u8, masked: bool);

#[cfg(target_arch = "x86_64")]
pub mod amd_pstate {
    pub const MSR_AMD_CPPC_CAP1: u32 = 0xC001_02B0;
    pub const MSR_AMD_CPPC_ENABLE: u32 = 0xC001_02B1;
    pub const MSR_AMD_CPPC_CAP2: u32 = 0xC001_02B2;
    pub const MSR_AMD_CPPC_REQ: u32 = 0xC001_02B3;
    pub const MSR_AMD_CPPC_STATUS: u32 = 0xC001_02B4;

    pub fn read_caps() -> Option<Result<CppcCaps, MsrFault>>;
    pub fn read_status() -> Option<Result<u8, MsrFault>>;
pub fn amd_pstate_request(
        min_perf: u8,
        max_perf: u8,
        desired_perf: u8,
        epp: u8,
    ) -> Option<Result<(), MsrFault>>;
}

#[cfg(target_arch = "x86_64")]
pub mod xsave {
    /// Selects x87/SSE/AVX/AVX-512/PKRU dependencies as complete groups;
    /// deliberately excludes opt-in AMX state.
    pub const fn default_xcr0_mask(supported: u64) -> u64;

    /// Standard-format bytes required by exactly `mask`, derived from
    /// CPUID.(0Dh,n) component offsets rather than the all-supported size.
    pub fn area_size_for_mask(mask: u64) -> usize;
}
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
- **Speculation policy is current-CPU scoped.** A transition masks and
  restores ordinary IRQ delivery, rejects nested transitions, updates only
  the executing CPU's hardware state, and publishes observable state only
  after write/read-back completion. Callers must pin/non-preempt the CPU;
  remote policy changes require a rendezvous. NMI/SError handlers must be
  correct under either the old or new policy. Disabling additionally requires
  policy authorisation and quiescence from protected-boundary entry.
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

## 8. Resolved decisions

### 8.1 Raw MSR/system-register access (resolved)

**Decision (was open):** **typed helpers only** for the public
surface; raw MSR/MRS access is `pub(crate)` inside `arch/` and
gated behind specific Cap kinds for any escapee path.

The typed-helper layer wraps every privileged register the
kernel actually uses (PKRS, IA32_APIC_*, IA32_UINTR_*,
SCTLR_EL1, TCR_EL1, TTBR0/1_EL1, GICR_*, etc.). Adding a new
register goes through:

1. Add a typed accessor in `arch/x86_64/msr.rs` or
   `arch/aarch64/sysreg.rs`.
2. If a driver needs it, expose via SDK at `@v0`.
3. If it's TCB-only (e.g. PKRS), keep `pub(crate)` and let
   `frame/` and `interrupts/` consume it.

Raw `WRMSR` / `MSR` from outside `arch/` is a build-time error
(rejected by the `xtask check-driver-isolation` SDK gate).

### 8.2 Crate layout (resolved)

**Decision (was open):** **single `narf-arch` crate with
`#[cfg(target_arch = "...")]` modules**, not separate per-arch
crates.

Rationale: the trait surface is shared; per-arch modules
implement it. Two crates would require either (a) a third
`narf-arch-trait` crate with no implementation (extra
indirection, slower compile), or (b) duplicated trait
definitions (maintenance burden). The `#[cfg]` approach has
been working; promote to permanent.

The internal layout (already in code as of `arch/src/`):

```text
arch/
  src/
    lib.rs              # public API + re-exports
    mmio.rs             # arch-portable MMIO accessors
    percpu.rs           # arch-portable per-CPU primitives
    x86_64/
      mod.rs
      asm.rs            # halt_until_irq, idle_halt_then_disable, sti/cli
      msr.rs            # typed MSR accessors
      io_port.rs        # in/out instructions
      cr.rs             # CR0..4 access
      ...
    aarch64/
      mod.rs
      asm.rs            # halt_until_irq, idle_halt_then_disable, wfi
      sysreg.rs         # typed system-register accessors
      ...
```

### 8.3 The canonical idle primitive

**Decision:** `arch::idle_halt_then_disable()` is the spec's
mandated way to wait-for-condition. The previously-existing
`halt_until_irq()` has the documented check-halt race for
condition-loop use; new code uses `idle_halt_then_disable`
in the canonical pattern:

```text
cli;
while !condition() {
    idle_halt_then_disable();   // sti;hlt;cli (atomic)
}
sti;
```

Mirrors Linux's `default_idle` (`raw_safe_halt` then
`raw_local_irq_disable`). On x86_64: `sti;hlt;cli`. On
aarch64: `msr DAIFClr,#2; wfi; msr DAIFSet,#2`.

`halt_until_irq()` is retained for opportunistic-idle paths
(scheduler runs out of work) where a missed wake just means
the next condition check spins; it's documented as racy and
must not be used in correctness-critical condition loops.

### 8.4 MMIO accessor discipline

**Decision:** all driver-side MMIO goes through
`arch::mmio::{read8,16,32, write8,16,32}` which:

- Are `unsafe fn` (caller asserts the address is mapped).
- Use `core::ptr::read_volatile` / `write_volatile`.
- On x86_64: emit a `compiler_fence(SeqCst)` before and after.
- On aarch64: emit `dmb ishld` after a load, `dmb ishst`
  before / `dsb st` after a store — the equivalent of x86's
  TSO ordering for MMIO.

Drivers do not write inline `read_volatile` / `write_volatile`
calls; the driver-isolation gate rejects such calls in driver
crates. (See `drivers/spec` §3 for the gate.)

## 9. ABI versioning

`narf-arch` re-exports through `narf-driver-sdk` at `@v0`:

- `mmio::read8/16/32`, `mmio::write8/16/32`
- `idle_halt_then_disable`
- `halt_until_irq`
- `interrupts_enabled`
- `enable_interrupts` / `disable_interrupts` (slow-path
  drivers' explicit IRQ control; most drivers shouldn't touch
  these directly)

`ARCH_ABI_MAJOR = 1`, `ARCH_ABI_MINOR = 0`. Adding a new MMIO
width (`read64`/`write64`) is a minor bump. Removing or
changing existing semantics is a major bump.

## 10. Open questions

(none — all v0.2 questions resolved in §8)
