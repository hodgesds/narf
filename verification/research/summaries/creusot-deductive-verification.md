# Creusot: Deductive Verification of Rust

## Creusot for NARF Microkernel Verification

Creusot is a deductive verifier for Rust that translates code to Why3's intermediate language, enabling formal verification of safety properties and functional correctness.

## Mechanisms for Kernel Verification

Creusot's architecture suits NARF's verification needs through:

**Panic/Overflow Prevention**: The tool automatically detects unsafe arithmetic and panics, critical for kernel stability where crashes cascade through capability domains.

**Assertion Discharge**: Users annotate invariants (e.g., capability validity, memory isolation), then Why3's solvers prove them hold throughout execution—essential for PKS/MTE enforcement.

**Memory Safety**: Rust's ownership system, verified by Creusot, prevents use-after-free in zero-copy IPC paths where buffers cross domain boundaries.

## Critical Invariants for NARF

1. **Capability Integrity**: Verify caps cannot be forged, duplicated illegitimately, or revoked while in-flight through IPC channels.

2. **Domain Isolation**: Prove PKS tag violations trigger exceptions, and MTE metadata remains consistent across async context switches.

3. **Async Executor Fairness**: Establish all tasks eventually progress (no starvation in capability redistribution).

4. **Buffer Lifecycle**: Confirm zero-copy regions remain valid from sender's grant until receiver's consume operation.

## Performance Trade-offs

**Adoption Benefits**: Verification catches domain violations at compile-time rather than runtime faults. Proof automation reduces manual testing for complex invariants.

**Adoption Costs**: Annotation overhead (pre/postconditions, loop invariants) slows kernel development. Why3 solver timeouts on non-linear arithmetic complicate performance-critical path verification.

**Avoidance Strategies**: Skip full verification of hot loops; use partial specs for async executor scheduling algorithms where termination proofs may exceed solver capacity.

## Pitfalls for NARF

- **Capability Operations**: Subtle state transitions (grant→active→revoked) require precise invariants; incomplete specs create false verification.
- **IPC Serialization**: If buffers contain pointers, verification must track validity across domain crossings—feasible but complex.
- **MTE Complexity**: Formal models of tag semantics must match hardware; misalignment invalidates proofs.

Creusot's Why3 foundation provides the rigor NARF demands, though kernel-specific abstractions will require custom plugins.

https://github.com/creusot-rs/creusot
