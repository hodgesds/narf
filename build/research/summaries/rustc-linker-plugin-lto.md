# Rustc Linker-Plugin-Based LTO

## Overview

Linker-plugin-based LTO (`-C linker-plugin-lto`) defers Link-Time Optimization to the linking phase, enabling interprocedural optimization across language boundaries when all object files use LLVM-based toolchains with matching LTO modes. For a capability-secure microkernel like NARF with domain isolation requirements, this offers strategic optimization opportunities but introduces non-trivial build complexity.

## Key Mechanisms

**LTO Deferral Architecture**: Instead of optimizing during compilation, `-C linker-plugin-lto` preserves LLVM bitcode in object files, allowing the linker plugin (typically LLD with LLVM plugin support) to perform whole-program optimization at link time. This enables cross-language optimization between Rust kernel code, C/C++ HAL layers, and potentially assembly stubs.

**Mode Alignment Requirement**: Both thin LTO (default) and fat LTO require all interoperable components to use **identical** modes:

```bash
# Thin LTO (recommended for NARF due to compilation speed)
rustc -C linker-plugin-lto -C lto=thin -C opt-level=3 ./kernel.rs
clang -flto=thin -c -O3 hal.c

# Fat LTO (for maximum optimization, slower builds)
rustc -C linker-plugin-lto -C lto=fat -C opt-level=3 ./kernel.rs
clang -flto=full -c -O3 hal.c
```

**Linker Plugin Requirement**: LLD with LLVM plugin support is mandatory. The plugin path can be explicitly specified:

```bash
rustc -C linker-plugin-lto="/path/to/LLVMgold.so" -C linker=lld
```

## Invariants for NARF Build Design

**Toolchain Version Matching**: LLVM versions must align. Reference the compatibility table: Rust 1.82-1.86 requires Clang 19, Rust 1.87-1.90 requires Clang 20. Version mismatch causes linker errors that are difficult to diagnose. Establish a build contract:

```bash
# Validate toolchain consistency
rustc -V --verbose | grep LLVM
clang --version | grep LLVM
```

**Reproducibility Constraint**: LTO introduces non-determinism unless carefully controlled. For a security microkernel, establish a locked toolchain configuration in your build manifest. Document the exact LLVM commit hash, not just version numbers, since Rust uses unstable LLVM revisions.

**Domain Isolation Boundary**: PKS/MTE domain isolation code (likely assembly or intrinsics) must be compiled without LTO or in a separate static library not participating in cross-language LTO. Mixing LTO and non-LTO object files creates linker plugin compatibility issues. Segregate domain switch code:

```bash
# Domain isolation - no LTO
rustc -C opt-level=3 ./domains/isolation.rs  # no -C linker-plugin-lto

# Kernel core - with LTO
rustc -C linker-plugin-lto -C lto=thin -C opt-level=3 ./kernel.rs
```

## Performance Trade-offs

**Compilation Time**: Fat LTO significantly increases link-time compilation (can add minutes to build cycle). For development, prefer thin LTO or disable LTO entirely. Reserve fat LTO for release builds. Configure cargo:

```toml
[profile.dev]
# Fast iteration
lto = false

[profile.release]
# Optimize for capability-secure IPC hot paths
lto = "thin"  # or "fat" if link-time overhead acceptable
```

**Optimization Gains**: Cross-language LTO can eliminate capability check redundancy at HAL boundaries and inline zero-copy IPC marshaling code. However, gains are modest (typically 5-15%) unless HAL is performance-critical path. For NARF's async executor and IPC, measure before committing to build complexity.

**Memory Usage**: Linker plugins consume significant memory during optimization. On resource-constrained build systems, this can cause OOM failures. Monitor link-phase memory usage; consider disabling LTO on CI systems with <8GB RAM.

## Build System Pitfalls

**Proc-Macro Incompatibility**: On Windows (`x86_64-pc-windows-msvc`), linker-plugin LTO conflicts with `-C prefer-dynamic` used by proc-macros:

```bash
# AVOID: This breaks if you have proc-macros
RUSTFLAGS="-C linker-plugin-lto" cargo build

# CORRECT: Explicitly specify target
cargo build --target x86_64-pc-windows-msvc
```

**Implicit Flag Propagation**: Build scripts and dependencies receive RUSTFLAGS globally. If a dependency (e.g., `cc` crate for C bindings) isn't compiled with matching LTO, linker failures occur silently:

```bash
# Set environment variables, don't just use RUSTFLAGS
export CC=clang
export CXX=clang
export CFLAGS="-flto=thin -fuse-ld=lld"
export CXXFLAGS="-flto=thin -fuse-ld=lld"
export AR=llvm-ar
cargo build --release
```

**Linker Plugin Mismatches**: If your linker (lld-link, gold) doesn't support LLVM plugins, you'll get cryptic "cannot read LLVM bitcode" errors. Validate:

```bash
lld --version  # Must show LLVM version matching rustc
```

## Build Designer Recommendations

**Adopt:**
- Thin LTO for microkernel releases (acceptable compilation overhead, good optimization)
- Explicit target specification in CI/CD to prevent proc-macro flag pollution
- Per-component LTO control: disable for architecture-specific isolation code
- Locked toolchain specifications (use `rust-toolchain.toml` with explicit LLVM version)
- Cargo feature gates allowing dev builds to skip LTO entirely

**Avoid:**
- Fat LTO unless profiling proves critical path optimization (IPC, scheduler)
- Mixing LTO-compiled and non-LTO-compiled object files in the same binary
- Relying on implicit RUSTFLAGS without explicit target specification
- Updating LLVM without validating all interoperable dependencies follow
- Building domain isolation code with cross-language LTO enabled

**For NARF specifically:** Prioritize linker-plugin LTO for the async executor hot path and capability-checked IPC marshaling layers, but keep PKS/MTE domain switches in non-LTO static libraries. Use thin LTO to balance optimization gains against build time—the microkernel's security model values predictability over maximal performance.

<https://doc.rust-lang.org/rustc/linker-plugin-lto.html>
