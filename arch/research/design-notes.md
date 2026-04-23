# arch — Design Notes
_2026-04-22_

## Load-bearing decisions

**The HAL is the only place where x86_64 and aarch64 diverge.** Every subsystem
above `arch/` assumes it is talking to a uniform `Cpu`, `Mmu`, `IntCtrl`, and
`Timer` trait. This means the HAL must paper over the deepest asymmetries
identified in the pks-vs-mte summary: PKS changes rights with one WRMSR; MTE
changes rights via page-table AP bits with a potential TLB flush. If the HAL
trait surface pretends these are equivalent, callers will write code that is
correct on one arch and wrong on the other.

**`FeatureFlags` is the single point of hardware-capability truth.** The spec
says feature-flag queries are monotonic: absent at boot means absent forever.
This is correct but the spec doesn't say who calls `feature_flags()` at boot,
where the result is stored, or how subsystems that need a flag (e.g., `memory/`
needing PKS, `interrupts/` needing UIPI) signal failure when the flag is absent.
If UIPI is absent on a CI machine, the kernel must decide: panic, degrade
gracefully, or refuse to boot. The spec is silent on policy.

**Single workspace `#[cfg(target_arch)]` vs. separate crates is an open
question deferred to Stage 1.** This is actually a TCB surface question.
Separate crates with a clean trait boundary make it impossible to accidentally
call x86_64-specific code from aarch64 paths. `#[cfg]` in a single crate does
not prevent this — a missing `#[cfg(target_arch = "x86_64")]` guard compiles
silently on x86_64 and panics at link time (or worse, silently on the wrong
arch). Separate crates are strongly preferable.

**`Mmu` trait body is a placeholder.** The spec says `/* map, unmap, tlb ops,
domain-tag hooks */` with no actual method signatures. This is the most
consequential blank in the HAL: the entire PKS/MTE domain model in `memory/`
and `frame/` depends on `Mmu` being able to (a) assign a domain tag to a
virtual range and (b) flush TLB entries when domain membership changes. Until
`Mmu` has real signatures, every subsystem that uses domains is building on
undefined ground.

## Divergences from precedent

**vs. Linux:** Linux uses C macros and inline assembly for arch-specific HAL,
not Rust traits. The practical difference is that Linux can partially specialize
(using `#ifdef` inside a function body) while NARF's trait must have a complete
implementation on every arch. This is more rigorous but means the trait surface
must be carefully scoped — UIPI is x86_64-only; there is no aarch64 analogue,
so it cannot be in the shared `Cpu` trait. The spec currently puts
`FeatureFlags` in `Cpu::feature_flags()` which includes UIPI; the trait is
arch-specific in all but name.

**vs. Hubris:** Hubris's HAL is a set of per-peripheral device drivers, not a
general-purpose CPU/MMU abstraction. It is too embedded-specific for NARF. But
Hubris is instructive on one point: its HAL crates never allocate, never panic
(they return `Result`), and never block. NARF's spec says "The HAL never
allocates; callers pass in storage" — correct — but doesn't mandate `Result`
return on fallible HAL ops. An `Mmu::map` that can fail (ENOMEM, bad alignment)
should return `Result`, not panic.

**vs. Redox:** Redox's `kernel/src/arch` uses per-arch modules rather than
traits. This means inter-arch code reuse happens via copy-paste, not
abstraction. NARF's trait surface is strictly better for multi-arch correctness,
provided the trait is actually completed (see Mmu above).

**PKS instruction fetch protection divergence:** The intel-sdm-pks summary notes
that "early PKS implementations did not protect instruction fetches; only newer
CPUs (Sapphire Rapids onwards) guarantee I-fetch protection." The pks-vs-mte
comparison confirms: "instruction fetches are not gated on either arch." NARF's
security model depends on CET (x86_64) and BTI+PAC (aarch64) for code-execution
control. The `FeatureFlags` must include `CET` and `BTI` as separate flags,
distinct from `PKS` and `MTE`, because code-execution isolation and data
isolation require different hardware features. The current `FeatureFlags` list
in the spec (PKS, PKU, UIPI, MTE, PAC) omits CET and BTI.

**MTE sync vs. async mode commitment:** The pks-vs-mte summary recommends NARF
use **synchronous** MTE mode on aarch64 for domain enforcement. This is the
right call — async mode can report faults from a different instruction than the
faulting access, making `dispatch_trap` attribution unreliable. The spec's
aarch64 §5 section says nothing about TCF (Tag Check Fault) mode selection.
This must be locked down before Stage 2 to prevent `memory/` and `frame/` from
making conflicting assumptions.

## Proposed spec changes

- §3 Public interface — `Mmu` trait: **Expand the Mmu stub** to at minimum
  include:
  ```rust
  pub trait Mmu {
      unsafe fn map(va: VirtAddr, pa: PhysAddr, size: usize, flags: MapFlags) -> Result<(), MmuError>;
      unsafe fn unmap(va: VirtAddr, size: usize);
      unsafe fn tlb_flush_page(va: VirtAddr);
      unsafe fn tlb_flush_all();
      unsafe fn assign_domain(range: VirtRange, domain: DomainId) -> Result<(), MmuError>;
      unsafe fn set_domain_rights(domain: DomainId, rights: DomainRights);
  }
  ```
  Without this, `memory/` and `frame/` cannot specify their contracts.

- §3 Public interface — `FeatureFlags`: Add `Cet`, `Bti`, `Pac` as distinct
  flags. `BTI` and `CET` are required for cross-domain code-execution control
  per the security model. Flag absence must be documented as either a boot-time
  panic or a graceful degradation with reduced security guarantee.

- §4 Invariants: Add **"Fallible HAL methods return `Result<T, ArchError>`;
  infallible ones (interrupts enable/disable, halt) may return `()`."** Panicking
  in a HAL method called from `dispatch_trap` would create an infinite fault loop.

- §5 Architecture notes (aarch64): **Commit to synchronous MTE tag-check fault
  mode (`TCF = 0b01`)** for domain enforcement. State that async mode
  (`TCF = 0b10`) is reserved for optional intra-domain memory-safety use only
  and is not used by the domain manager.

- §5 Architecture notes (x86_64): Specify **`x2APIC` is required, `xAPIC` is
  not supported.** xAPIC requires a memory-mapped register page at a fixed
  physical address (0xFEE0_0000); managing its PKS domain assignment adds
  complexity. x2APIC uses MSRs only. All CPUs shipping since 2010 have x2APIC.
  Dropping xAPIC simplifies the `IntCtrl` trait.

- §8 Open questions: Resolve **"Single workspace with `#[cfg]` vs. separate
  crates per arch."** The correct answer is **separate crates
  (`narf-arch-x86_64`, `narf-arch-aarch64`)** with a shared `narf-arch-api`
  crate defining the trait surface. The workspace `Cargo.toml` feature-flags
  which impl crate to include. This prevents cross-arch code from compiling
  silently.

## Open invariants / cross-subsystem hazards

**arch ↔ memory:** `memory/` §2 depends on `arch/` providing "CPU/MMU
primitives" to implement the domain manager. But `memory/` is also a Stage 2
dependency while `arch/` has a Stage 1 stub. If the Stage 1 `Mmu` stub returns
dummy values for `assign_domain` and `set_domain_rights`, `memory/` will build
but silently not enforce domains. There must be a compile-time or boot-time
assert that domain enforcement is not called before Stage 2 `arch/` is wired.

**arch ↔ frame:** `frame/` calls `enter_domain(id)` which "hooks memory/ domain
manager." But the actual hardware operation (WRMSR or MTE pointer discipline)
must be implemented in `arch/`. The call chain is:
`frame::enter_domain` → `memory::DomainManager::enter` → `arch::Mmu::set_domain_rights`.
This three-layer call is not described anywhere. If any layer stubs a method, the
domain switch silently does nothing. The spec should make the layering explicit.

**arch ↔ interrupts:** `IntCtrl` trait includes `send_ipi`. On x86_64 an IPI via
x2APIC is an MSR write. On aarch64 an IPI is an SGI via GICD_SGIR or GICv3's
ICC_SGI1R_EL1. These have different addressing models (x86_64: destination APIC
ID; aarch64: affinity + target list). The `send_ipi` signature in the current
spec is `fn send_ipi(target: ???, vector: ???)` — the parameter types must be
defined before `scheduler/` can implement SMP wakeup in Stage 2.

**arch ↔ build:** The target JSON files for `x86_64-unknown-none` and
`aarch64-unknown-none-softfloat` must set `"features"` to enable PKS (for
x86_64) and MTE (for aarch64) at the LLVM level. Without the right CPU feature
flags, intrinsics for PKRS manipulation and MTE tag-setting instructions will
not be available. `arch/` owns the requirement; `build/` must implement it.
This dependency is not listed in either spec.

## Additional opinionated commentary

The `arch/` spec is appropriate in its minimalism for a design-phase document,
but the Mmu-trait blank is not a detail — it is the central contract. Every
subsystem that talks about PKS or MTE is implicitly filling in that blank with
their own mental model, and those models will diverge. The design phase should
nail the Mmu trait surface completely even if the implementations are stubs.

The feature-flag monotonicity invariant deserves more thought: if UIPI is absent,
the `interrupts/` spec's "UIPI configuration on x86_64" block is dead code. NARF
should define required features (PKS/MTE, TSC, x2APIC) that cause a boot-time
panic if absent, versus optional features (UIPI, CET, MTE2) that degrade
gracefully. The current spec treats all flags uniformly.
