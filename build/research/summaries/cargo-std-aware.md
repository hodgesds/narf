# Cargo std-Aware (wg-cargo-std-aware)

## Overview

The `wg-cargo-std-aware` initiative addresses a fundamental architectural challenge: enabling local compilation of Rust's standard library rather than relying on pre-built artifacts. For NARF's build subsystem—which must support PKS/MTE domain isolation, async execution, and capability-based security—this work reveals critical design patterns.

## Key Mechanisms

The project identifies four primary compilation scenarios:

1. **Custom profile optimization**: Building stdlib with project-specific settings (debug levels, optimization flags)
2. **Unsupported target support**: Compiling libcore for architectures lacking official binaries
3. **Conditional compilation**: Disabling stdlib features via `cfg` flags for minimal kernels
4. **Explicit sysroot dependencies**: Declaring stdlib crates directly in manifests

The MVP implementation uses a simple `-Z` flag on nightly Rust, intentionally minimal to expose design issues before RFC formalization. This staged approach—experimental implementation preceding standardization—proves valuable for kernel projects needing stdlib modifications.

## Critical Invariants for NARF

**Build reproducibility**: PKS/MTE domain isolation and capability security require deterministic linking. The project's focus on explicit dependency declaration aligns with this requirement—implicit stdlib bindings create invisible attack surfaces.

**Isolation boundaries**: NARF's zero-copy IPC demands knowing precisely which stdlib components enter each domain. Current Rust distributions bundle everything; selective compilation enables enforcing domain-specific APIs at the build level.

**Async executor integration**: The framework supports building stdlib with custom `cfg` settings, essential for NARF's async runtime. You cannot bolt custom scheduling onto incompatible stdlib concurrency primitives; recompilation ensures coherence.

## Performance Trade-offs

Compilation overhead is substantial. Rebuilding stdlib locally transforms incremental builds into full reconstructions unless caching strategies improve. For NARF development, accept longer initial builds in exchange for:

- Eliminating unused allocator code (critical for predictable memory isolation)
- Removing unsupported target assumptions from panic handling
- Enabling domain-specific feature gates without downstream runtime checks

## Architectural Pitfalls

**Fragmentation risk**: As stated, "It is possible that we will not address all of these use cases." NARF must resist the temptation to accumulate custom stdlib variants. Establish a single, documented configuration; divergence becomes unmaintainable across compiler updates.

**Transitive complexity**: Sysroot crate dependencies create implicit ordering constraints. NARF's capability model requires explicit dependency flow—ensure manifest syntax forces this visibility rather than allowing hidden sysroot assumptions.

**Testing coverage gaps**: The MVP explicitly carries "a large number of known issues" and targets "experimentation and testing" only. Do not adopt unstable features for production kernels until RFCs formalize semantics.

## Recommendations for NARF Build Design

**Adopt explicit sysroot declarations**: Rather than relying on compiler magic, declare stdlib dependencies as normal Cargo entries. This approach—addressed in issue #5—aligns perfectly with capability-based security's principle of explicit authority.

**Establish stdlib compilation profiles early**: Define a single, versioned configuration describing custom profile settings, target specifications, and `cfg` overrides. Document the rationale for each deviation from defaults; future maintainers (and compiler updates) will demand clarity.

**Integrate with your verification pipeline**: Recompiling stdlib should trigger full reproducibility checks. Capability isolation means different builds must produce byte-identical binaries for the same isolation domains. Make this automated and non-negotiable.

**Avoid RFC-unstable features for core builds**: The project itself remains pre-RFC for key mechanisms. Pin compiler versions and maintain a changelog documenting which `-Z` flags and experimental features your builds depend upon. This creates an upgrade surface you can systematically address.

**Design for minimal stdlib**: Use conditional compilation aggressively to eliminate panic infrastructure, I/O implementations, and other components irrelevant to a capability-isolated microkernel. NARF's threat model differs fundamentally from general-purpose systems.

## Conclusion

The std-aware Cargo effort demonstrates that building Rust's standard library is increasingly tractable, but remains intentionally limited. For NARF, this represents both opportunity and risk. Leverage the explicit dependency declaration mechanisms and custom compilation profiles to enforce architectural boundaries. Resist early adoption of unstable features; wait for RFC stabilization unless experimentation provides clear security or isolation benefits. The project's staged approach—nightly MVP before standardization—provides a useful model: prototype thoroughly before committing to production microkernel builds.

<https://github.com/rust-lang/wg-cargo-std-aware>
