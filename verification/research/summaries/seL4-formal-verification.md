# seL4 Formal Verification: Lessons from L4.verified

## Formal Verification for NARF: Lessons from seL4's L4.verified

The seL4 L4.verified project—a comprehensive formal verification effort for the seL4 microkernel using Isabelle/HOL—offers critical insights for verifying a Rust-based subsystem like NARF.

## Verification Architecture

L4.verified employs a **multi-layer refinement approach**: abstract specification → design specification → C implementation. For NARF, consider parallel layers: Rust semantics → capability abstractions → async runtime behavior. The repository demonstrates that "refinement between abstract and design specifications" and "C semantics" remains tractable even for complex systems. Your async executor and zero-copy IPC mechanisms warrant similar stratification.

## Critical Invariants for NARF

The seL4 work identifies key invariants:
- **Capability system integrity**: cap distribution must remain consistent across operations
- **Access control boundaries**: authority confinement prevents unauthorized delegation
- **Information flow**: intransitive non-interference prevents covert channels

For NARF, PKS/MTE domains create an additional layer requiring invariants around:
- Metadata tag consistency during cap transfer
- Domain boundary enforcement during async context switches
- Zero-copy buffer ownership transitions

## Mechanisms to Adopt

1. **Separation Logic Frameworks**: L4.verified uses "separation logic instance on capDL" for resource reasoning. Model NARF's async task ownership and zero-copy buffers similarly.

2. **Proof-Producing Tools**: The autocorres abstraction tool converts low-level C into verified higher-level functions. Develop equivalent extraction for Rust unsafe blocks, focusing on IPC and scheduling paths.

3. **Distributed Proof Strategy**: L4.verified scales across multiple cores—essential since your async runtime complexity demands concurrent verification efforts.

## Performance-Verification Trade-offs

- **Zero-copy complicates aliasing proofs**: Buffer lending requires tracking ownership through async await points. Budget extra verification effort for suspension safety.
- **PKS/MTE runtime costs**: Hardware domain isolation adds negligible overhead but multiplies proof state space. Consider abstraction layers hiding tag mechanics.
- **Capability revocation during async**: Prove that in-flight operations respect revoked caps—this doesn't flow from sync proofs alone.

## Pitfalls to Avoid

1. **Async executor verification gap**: Don't assume scheduler correctness follows from task-level proofs. Model executor state machines explicitly.
2. **Capability aliasing in cap transfer**: Zero-copy IPC risks duplicate capability instances mid-transfer. Enforce strict ownership handoff semantics.
3. **Insufficient domain boundary specs**: PKS/MTE provide *mechanism*—verification must specify *policy*. Separate what hardware enforces from what code must maintain.

L4.verified required 6,199 commits and supports ARM, X64, RISCV64, AARCH64. NARF's Rust foundation simplifies some reasoning (no buffer overflow classes), but async control flow introduces verification challenges seL4 didn't face. Allocate equivalent engineering resources to formal foundations.

https://github.com/seL4/l4v
