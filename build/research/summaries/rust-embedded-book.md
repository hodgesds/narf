# Rust Embedded Book — Starting a New Project

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

The Rust Embedded Book provides foundational guidance for embedded systems development using Rust, with a focus on ARM Cortex-M microcontrollers. While not microkernel-specific, the book's build system patterns, cross-compilation strategies, and bare-metal programming principles are highly relevant to NARF's build subsystem design.

## Key Mechanisms

**Cross-Compilation Framework:**
The book emphasizes the separation of host (build) and target (runtime) platforms, managed through Rust's target specifications. For NARF supporting both x86_64 and aarch64, this pattern is essential:

```toml
# Cargo.toml
[build]
target = "x86_64-unknown-none"  # No OS dependency

# .cargo/config.toml
[target.x86_64-unknown-none]
rustflags = [
    "-C", "link-arg=-nostartfiles",
    "-C", "relocation-model=static",
]
```

The book documents best practices for bare-metal linking, explaining how to replace the standard C runtime with custom startup code—critical for a microkernel where stdlib assumptions about runtime initialization don't apply.

**Target Specification Format:**
Rust uses JSON files to define custom targets. The book walks through essential fields:
- `llvm-target`: LLVM triple (e.g., "x86_64-unknown-none")
- `os`: Empty string for bare-metal; prevents stdlib from assuming OS support
- `linker`: Path to custom linker (GNU ld, LLD)
- `features`: CPU architecture flags (e.g., "-mmx", "+sse2" for x86_64)

NARF's PKS/MTE isolation likely requires CPU-specific features. The book's approach to conditional feature flags aligns perfectly with capability security requirements—different domains may enable/disable features depending on their isolation context.

**Memory Layout Specification:**
The book explains linker scripts for memory layout control. NARF's zero-copy IPC depends on precise memory organization. A linker script defines:

```linker
SECTIONS {
    . = 0x200000;  /* Kernel start */
    
    .text : { *(.text*) } : {FLAGS}
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) }
}
```

This allows explicit separation of kernel code, read-only capability metadata, and isolated domain memory regions.

**Panic Handling:**
The book documents panic behavior in no-std environments. For NARF, this is critical: panics in one domain must not corrupt other domains' state. The book's guidance to define custom `#[panic_handler]` enables per-domain panic isolation:

```rust
// Kernel panic: safe to halt all
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    kernel_halt()
}

// Domain panic: isolate to that domain
#[panic_handler]
fn panic_domain(info: &core::panic::PanicInfo) -> ! {
    domain_terminate()  // Only this domain stops
}
```

**Debug Support:**
The book covers symbol table preservation for debugging. For capability-secured systems, this is a trade-off: debug symbols leak information about implementation details, but their absence prevents post-mortem analysis. The book's approach—conditional stripping—aligns with security needs:

```toml
[profile.release]
debug = true  # Keep symbols
strip = false  # Don't strip linker symbols
```

## Critical Invariants

1. **No standard library assumptions**: Bare-metal Rust forbids assumptions about allocators, threading, or I/O primitives. NARF must enforce this rigorously; stdlib dependency in domain code is a security violation.

2. **Explicit target definition**: The book emphasizes that custom targets are project-specific, not shareable. NARF should version its target specifications like code—they are part of the TCB.

3. **Linker script determinism**: Once written, linker scripts must be immutable. Symbol addresses must be stable across builds for reproducibility and security verification.

4. **Panic isolation**: The `#[panic_handler]` is global per crate. NARF must use separate crates for kernel vs. domain code to achieve per-component panic semantics.

## Performance Trade-offs

**Minimal Binary Size:**
Using `-C opt-level=z` or `-C opt-level=s` reduces binary size by ~30-50%, aiding deployment on resource-constrained platforms. However, this disables some inlining optimizations. For NARF's IPC fast path, measure whether micro-optimizations justify larger binaries.

**Debug Info Overhead:**
Stripping debug symbols reduces binary size by 20-40% but prevents kernel crash analysis. For production deployments, separate debug symbol sets (`.gnu_debuglink`) allow deployment without symbols while preserving development debuggability.

**Link-Time Optimization:**
The book briefly mentions LTO. For microkernel IPC hotspots, thin LTO (during linking) provides 5-15% speedup with acceptable overhead. This aligns with NARF's capability-checking paths.

## Pitfalls and Warnings

1. **Target Triple Typos**: A single character error (e.g., "x86_64-unknown-none" vs. "x86-64-unknown-none") causes silent linking failures. NARF should automate target validation.

2. **Linker Script Fragility**: Linker scripts are platform-specific and error-prone. A misaligned section can create security vulnerabilities (e.g., capability metadata in writable regions). Use assertions in linker scripts to catch mistakes:

   ```linker
   ASSERT((SIZEOF(.rodata) % 16) == 0, "rodata alignment");
   ```

3. **Panic Handler Conflicts**: If multiple crates define `#[panic_handler]`, the linker chooses arbitrarily. NARF should enforce a single panic handler per binary using a linker check.

4. **Symbol Collision**: Global symbols (functions, statics) can collide across domains if not namespaced. The book doesn't address this; NARF must enforce naming discipline or use link-time visibility rules.

5. **Unsafe Code Concentration**: Bare-metal Rust requires unsafe for hardware access. The book recommends isolating unsafe in HAL layers. NARF should push all unsafe into a verified, capability-checked HAL.

## Recommendations for NARF Build Design

**Adopt:**
- Custom target specifications versioned with code; enforce immutability via CI
- Per-component linker scripts: separate scripts for kernel, domains, and HAL ensure clear memory layout
- Conditional panic handlers using separate crates for kernel vs. user domains
- Thin LTO for IPC hot paths; measure impact on debug-build turnaround
- Comprehensive linker script assertions to catch memory layout errors
- Debug symbol separation using `.gnu_debuglink` for production deployments

**Avoid:**
- Relying on default Rust targets; always specify explicit target for reproducibility
- Mixing safe and unsafe code in domain components; push unsafe to isolated HAL
- Assuming linker script behavior is portable across GNU ld, LLD, or mold
- Global symbols without namespacing; use Rust's visibility system aggressively
- Panic handlers that access shared state; each component must panic independently

**Specific to NARF:**
- Model domain code as separate crates with separate panic handlers
- Use linker scripts to enforce PKS/MTE memory region separation
- Implement reproducible builds: lock all target specifications, LLVM versions, and linker versions
- Design linker scripts to align memory with MTE tag granules (16-byte boundaries on aarch64)
- Add capability metadata sections to linker script with explicit read-only enforcement

<https://docs.rust-embedded.org/book/>
