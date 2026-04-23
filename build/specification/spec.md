# build — Specification

> Status: **Outline v0.2** (Stage 1). v0.2 acknowledges that fat LTO
> can legally reorder memory accesses across domain-switch intrinsics
> and specifies the compiler-fence discipline that prevents it.

## 1. Purpose & scope

**Owns:** Cargo workspace layout, `build-std` configuration, linker scripts
per arch, xtask commands (`run`, `test`, `qemu`, `image`), Global LTO config.

**Does NOT own:** Release management, CI (yet), debian-style packaging.

## 2. Assumptions

- Nightly Rust toolchain (`build-std` is unstable).
- `rust-src` component available.
- QEMU with KVM on host for faster iteration; TCG fallback.

## 3. Public interface

- `cargo xtask run --arch=x86_64 [--release]` — build + QEMU boot.
- `cargo xtask test --arch=aarch64` — boot + run kernel tests.
- `cargo xtask image --arch=x86_64 --bootloader=limine` — produce bootable ISO.
- Workspace: single Cargo workspace so Global LTO spans everything.

## 4. Invariants & safety properties

- Release builds must use `lto = "fat"` across the whole workspace.
- `panic = "abort"`; no unwinding in the kernel.
- Reproducibility: identical inputs produce identical binaries
  (`-Z remap-path-prefix`, `SOURCE_DATE_EPOCH`).
- **Fat LTO + domain switches is a correctness hazard.** With whole-
  program LTO, LLVM sees the inline asm / intrinsic that writes PKRS
  (x86_64) or `SCTLR_EL1.TCF` (aarch64) as just another memory-barrier-
  less operation. It is free to sink a load across the write or hoist
  a store past it, silently observing the wrong domain's rights at
  the wrong time. This must be prevented at the source level — LTO
  flags alone cannot fix it.
- **Every domain-switch intrinsic is wrapped in an `asm!` block with
  the `"memory"` clobber** *plus* an explicit
  `core::sync::atomic::compiler_fence(Ordering::SeqCst)` before and
  after. The `"memory"` clobber alone is insufficient under fat LTO
  because LLVM can still hoist / sink pure-register operations around
  the asm block when it proves they do not touch memory — but it
  cannot prove that about a post-domain-switch load, because the
  *meaning* of the load changed. The double-fence discipline is what
  tells LLVM that correctness depends on no reorder.
- **Any inline asm that the codegen could plausibly reorder around** —
  TLB invalidations (`INVLPG`, `DSB ISHST`), cache maintenance (`CLFLUSHOPT`,
  `DC CVAC`), MMIO writes to doorbell pages, `WRMSR` to security-
  relevant MSRs (PKRS, CR3, TCR_ELx) — uses the same discipline.
  `arch/` owns the wrapper functions; callers must not reach around
  to raw asm.
- **`build/` emits the required CPU-feature flags to rustc** so the
  above intrinsics are even available. PKS requires
  `-C target-feature=+pks` (gated behind a nightly feature); MTE
  requires `+mte`. Missing flags produce a compile-time error in
  `arch/` wrappers rather than silent emit-nothing behaviour.

## 5. Architecture notes

### x86_64
- Target: `x86_64-unknown-none`.
- Linker script places kernel at `-2GiB` (kernel high-half).
- Bootloader: Limine by default; multiboot2 supported.

### aarch64
- Target: `aarch64-unknown-none-softfloat` (no SIMD in kernel).
- Linker script places kernel per platform (QEMU virt at `0x4008_0000`).
- Bootloader: U-Boot / EFI stub; devicetree consumed by `boot/`.

## 6. Dependencies

- **Consumes:** nothing inside NARF.
- **Provides to:** everything; `xtask` is the entry point for every other
  subsystem's tests.

## 7. Stage assignment

Stage 1; extended each stage as new targets/tests appear.

## 8. Open questions

- Should we pin a specific nightly, or track a rolling pin?
- `cargo-binutils` vs. `llvm-tools-preview` vs. host `lld` for linking.
- How do we wire `bolt`/FDO for Global LTO post-Stage-4?
- **Audit-via-build for LTO reorder hazards.** Can we statically
  guarantee the `compiler_fence` wrappers are the *only* path to
  PKRS / TCF / CR3 / TLBI in the built kernel, e.g. via a Clippy
  lint or a post-link symbol-reference pass? A Stage 2 investment
  that pays off every release.
