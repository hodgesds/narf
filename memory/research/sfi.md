# Research note — Software Fault Isolation as a domain-isolation backend

## What it is

Software Fault Isolation (SFI) restricts a sandboxed code region to a
specified memory range using compiler-inserted instrumentation — every
load and store is rewritten to mask its address into the sandbox
region, so the *compiler* (plus a verifier on the resulting binary)
guarantees that the code cannot read or write outside its allowed
range. No hardware support required.

Primary references:
- Wahbe, Lucco, Anderson, Graham — **"Efficient Software-Based Fault
  Isolation"** (SOSP 1993). The original paper.
- Yee et al. — **"Native Client: A Sandbox for Portable, Untrusted
  x86 Native Code"** (IEEE S&P 2009). Brought SFI to production.
- Tan, **"Principles and Implementation Techniques of Software-Based
  Fault Isolation"** (Foundations and Trends in Privacy and Security,
  2017). Survey.
- WebAssembly memory model — sandboxed linear memory + bounds-checked
  memory ops; conceptually a modern SFI dialect.

## Why it is a candidate for NARF

- **Hardware-independent.** Works on any silicon — no PKS, no MTE, no
  PCID-class TLB tagging required. Uniform deployment across Intel,
  AMD, ARM, RISC-V.
- **Per-load enforcement, zero per-crossing cost.** Domain entry/exit
  is free; the cost is amortised into a small instrumentation overhead
  on every memory op (typically 3–10% throughput hit measured).
- **Compiler is a known component.** NARF already builds with a
  curated Rust toolchain under whole-kernel LTO. An SFI pass is a
  natural fit.
- **Formally checkable.** The verifier is a small static analyser over
  the emitted code — much smaller TCB component than a hardware MMU
  spec.

## Why we are not building it now

1. **Trust shifts from silicon to compiler + verifier.** A miscompile
   or a verifier bug becomes a domain-isolation escape. The hardware
   backends fail closed on a `RDMSR`-class bug; SFI fails closed on a
   compiler-class bug. Different threat model.
2. **Rust is not yet expressive enough.** A driver written in
   "unsandboxed Rust + raw pointer arithmetic + inline asm" cannot be
   meaningfully SFI-instrumented. Drivers would need to compile under
   a restricted Rust dialect (no `unsafe`, no raw pointers, masked
   loads/stores) — a substantial language and tooling project.
3. **Throughput overhead is not free.** The 3–10% per-load cost shows
   up on driver hot paths (NVMe completion, network RX) where the
   framekernel's selling point is "isolation without an IPC tax."
4. **Tooling.** A sound Rust SFI verifier does not exist off the
   shelf. Building one is research-grade work, not a Stage-4
   deliverable.

## What would change to revisit

- A target deployment requires uniform isolation on silicon that has
  neither PKS nor MTE *and* cannot tolerate the PCID fallback's
  per-crossing cost (e.g. ultra-low-latency networking on older AMD).
- The Rust ecosystem produces a verified subset suitable for driver
  authoring (see ongoing research on `wasm-of-rust`, `verus`,
  `prusti`, `creusot`).
- A formal verification effort on the kernel makes "compiler-trusted"
  acceptable as a TCB extension.

Until those conditions hold, **no implementation work**. The PCID
backend is the silicon-agnostic path of record; SFI is a long-term
bet.
