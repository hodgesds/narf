# build — Design Notes
_2026-04-22_

## Load-bearing decisions

**Global LTO (`lto = "fat"`) is a release-build invariant.** This is the
project's core claim for "single binary optimization." Fat LTO means all crates
in the workspace are merged into one LLVM module at link time. The practical
consequence: link time for a release build will be 3–10 minutes on a modern
machine. Debug builds with `lto = false` are essential for developer iteration.
The spec correctly says release must use fat LTO, but does not define a
`profile.dev` that explicitly disables LTO and sets low codegen-units.

**`panic = "abort"` is specified but its interaction with `build-std` is not.**
When using `build-std`, Rust recompiles `core`, `alloc`, and (if requested)
`std` from source. The `panic_handler` in `frame/` must be the *only*
panic handler in the entire workspace. If any third-party crate (e.g., a DT
parser) pulls in a default `panic = "unwind"` handler via its own `Cargo.toml`
profile, the link fails. The spec should mandate that the workspace-level
`[profile.release]` and `[profile.dev]` both set `panic = "abort"` and that no
crate is allowed to override it.

**`build-std` is unstable and toolchain-pinned.** The cargo-std-aware summary is
direct: this feature "carries a large number of known issues" and targets
experimentation only. NARF must pin a specific nightly date in `rust-toolchain.toml`
and treat toolchain upgrades as a deliberate, tested change — not a rolling
update. The spec lists `rust-src` as a required component but gives no
guidance on pinning.

**Reproducible builds require more than `-Z remap-path-prefix`.** The spec
mentions `SOURCE_DATE_EPOCH` and `remap-path-prefix` for reproducibility. But
fat LTO with LLVM introduces non-determinism through: (a) parallel codegen
threads whose order affects output, (b) LLVM's non-deterministic module passes,
and (c) DWARF debug-info timestamps. To achieve byte-identical builds, NARF also
needs `RUSTFLAGS=-C codegen-units=1` for release builds (one module, no
parallelism) and must lock the exact LLVM revision (not just the rustc version).
The spec understates this challenge.

## Divergences from precedent

**vs. Hubris:** Hubris pins an exact nightly in its `rust-toolchain.toml` and
has a `xtask` that validates the toolchain version before any build operation.
NARF's spec leaves toolchain pinning as an open question. This should not be
open — it must be resolved at Stage 1 because every `build-std` invocation
depends on it.

**vs. Redox:** Redox uses a `mk`-based build system with a manifest for each
component. NARF uses `xtask`, which is pure Rust and strictly better for
cross-platform consistency. However, Redox's component manifests make it easy
to trace what goes into each artifact. NARF's single-binary LTO model makes
this tracing harder — there is no clear boundary between what is in the TCB
binary and what is a loadable module. The spec should specify that `cargo xtask
image` produces a manifest listing every crate in the final image.

**LTO + domain isolation code:** The rustc-linker-plugin-lto summary notes a
specific hazard: domain-isolation code (PKRS manipulation, MTE tag-setting
assembly) should *not* be LTO'd across language boundaries if it contains C or
assembly. NARF is Rust-only, so this is less critical, but LLVM can still
inline across the domain boundary when using fat LTO, potentially moving a
`WRMSR` instruction to a different point in the instruction stream relative to
the memory accesses it gates. This is a security-relevant optimization: the
compiler must not reorder domain-switch instructions. The spec should require
`#[no_mangle]` and a `core::sync::atomic::compiler_fence` (or inline `fence`)
around domain-switch code to prevent LLVM reordering.

**`aarch64-unknown-none-softfloat` vs. a custom target:** The `softfloat`
variant disables SIMD and FP in the kernel. This is correct — FP state
save/restore on interrupt is expensive and SIMD has no place in kernel code.
But the target `aarch64-unknown-none-softfloat` is a tier-3 target, which
means less CI coverage by the Rust project and possible regressions. Consider
defining a custom `.json` target that locks the CPU feature flags explicitly
(+mte, +pac if available) rather than relying on a generic tier-3 target.

## Proposed spec changes

- §2 Assumptions: Add **"A pinned nightly toolchain is specified in
  `rust-toolchain.toml` at workspace root; no CI job runs without it."** This
  makes toolchain pinning a build invariant, not an open question.

- §4 Invariants: **Expand the reproducibility requirement** to: "Release builds
  set `codegen-units = 1`, `RUSTFLAGS=-C codegen-units=1`, `lto = "fat"`,
  `SOURCE_DATE_EPOCH`, and `-Z remap-path-prefix`. Byte-identical output is
  verified in CI via `sha256sum` comparison across two independent build hosts."
  The current wording is aspirational without being actionable.

- §4 Invariants: Add **"Workspace-level `[profile.release]` and `[profile.dev]`
  both set `panic = "abort"`; individual crate overrides of `panic` are
  forbidden."** This closes the multi-panic-handler link failure.

- §4 Invariants: Add **"Domain-switch functions (`enter_domain`, PKRS write
  helpers) are marked `#[inline(never)]` in debug builds and surrounded by
  compiler fences in release builds to prevent LLVM reordering across the
  domain boundary."**

- §5 Architecture notes (aarch64): **Define a custom `.json` target** rather
  than relying on `aarch64-unknown-none-softfloat`. The custom target should
  specify `+mte` in the features field so MTE intrinsics are available, and
  `+bti` to enable Branch Target Identification. Document the JSON file location
  as `build/targets/narf-aarch64.json`.

- §8 Open questions: **Resolve the `bolt`/FDO question immediately.** FDO
  (Feedback-Driven Optimization) requires profiling instrumentation in production
  binaries, which conflicts with the security model (profiling can reveal
  addresses). BOLT is an LTO post-pass that is safe but requires symbol
  tables. Decision: **defer BOLT/FDO to post-1.0; document in §7 that Stage 4
  may add a `cargo xtask bolt` command as a separate, optional post-link step.**

## Open invariants / cross-subsystem hazards

**build ↔ arch:** `arch/` needs CPU feature flags set in the target JSON or via
`RUSTFLAGS` to compile MTE tag-setting instructions (`STG`, `STZG`) and PKRS
manipulation intrinsics. If `build/` does not pass `+mte` to the aarch64
compiler, `arch-aarch64` will compile silently but any MTE intrinsic will be
undefined behavior or a compile error. This dependency is not listed in either
spec's `§6 Dependencies`.

**build ↔ frame:** The `frame/` crate defines the `#[panic_handler]`. It must
be linked into the final binary before any other crate that might define one.
With fat LTO and `build-std`, link order is non-trivial. `xtask` must ensure
`frame` appears first in the link order or use `--allow-multiple-definition`
with an explicit symbol override. The spec does not mention this.

**build ↔ verification:** The `verification/` spec (from ROADMAP) describes a
statistical performance protocol requiring dedicated cores, fixed frequency, and
ASLR off. `cargo xtask test` must support a `--perf` flag that configures the
QEMU invocation to match these constraints. Without it, CI performance tests
are invalid. Neither `build/` §3 nor `verification/` spec mentions this
requirement on `xtask`.

**build ↔ all:** The `build-std` approach recompiles `core` with NARF's
profiles. If a crate conditionally enables features via `cfg(feature = "...")`,
and those features are not present in `build-std`'s compilation of `core`, the
kernel will silently use a degraded `core`. The workspace must have a `[features]`
section that is validated at CI time.

## Additional opinionated commentary

The spec is appropriately thin for a build subsystem in the design phase, but
it makes one strategic mistake: treating fat LTO as a done deal without
budgeting its cost. Fat LTO on a large Rust codebase (100+ crates) can
take 20–40 minutes on a developer machine. If every `cargo xtask run` triggers
a fat LTO link, developer iteration becomes painful enough to encourage
workarounds (like `lto = false` in developer configs) that then break the
single-binary optimization guarantee.

The right model — used by Firefox, Chrome, and LLVM itself — is:
- `profile.dev`: no LTO, many codegen-units, fast
- `profile.release-thin`: thin LTO (fast, ~5–15% optimization, 1–3 min link)
- `profile.release-fat`: fat LTO (maximum optimization, 10–40 min link)
- CI gate uses `release-thin` for functional tests; a nightly build uses `release-fat` for perf tests

The spec should adopt this three-tier profile structure explicitly rather than
implying that `--release` always means fat LTO.
