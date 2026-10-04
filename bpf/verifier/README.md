# bpf/verifier — The Static Safety Verifier

`narf-bpf-verifier` proves a BPF program memory-safe before the subsystem will
let it run. It is the gatekeeper on which the rest of the pipeline depends: the
interpreter's safety once came from never dereferencing a program-supplied
address, and enabling native code generation trades that for the verifier's
proof plus the exception table plus the arena guard slots — a trade that is
only sound once a real verifier exists. This crate is that verifier, kept as
pure logic with no kernel dependencies and no unsafe code so it builds and
tests on the host.

## What verification is, conceptually

Verification is an abstract interpretation of the program over a numeric
abstract domain, driven to a fixpoint. The decoded instruction stream (from
`bpf/isa`) is first lifted into a control-flow graph with basic blocks,
dominators, strongly connected components, and a call graph. A forward
worklist then propagates an abstract state — the contents of registers, the
stack, typed pointers, and live references — through the transfer functions
for each instruction, joining states where control flow merges and widening
around loops so the analysis converges. The numeric domain is a single
combination of a tristate-number (bitwise-known) representation with a signed
interval, which replaces the several overlapping value domains a conventional
BPF verifier carries. A liveness-and-precision dataflow runs alongside to bound
how much of that state must be tracked. When the fixpoint settles without any
transfer function flagging an out-of-bounds access, an illegal pointer use, or
a violated reference rule, the program is accepted; otherwise it is rejected.

The result of a successful run is a verified program image carrying everything
the JIT and the runtime need downstream: the peak stack depth across the call
graph, the set of fault sites that require exception-table coverage,
subprogram boundaries, and the program's initial fuel.

## Load-bearing design choices

Several decisions distinguish this verifier from Linux's and shape its
structure. Termination is treated as a runtime property rather than a
verification one: because every program runs under a fuel counter, the
verifier needs only a sound over-approximation that converges by widening, not
a termination proof — which removes the instruction and state-count limits and
the separate loop constructs, and makes acceptance a function of the program
alone rather than of a search budget. There is one numeric domain rather than
several overlapping ones. There is one call ABI, with argument semantics
carried by Rust types instead of BTF suffixes. The verifier works on an IR and
lowers once, so nothing patches instructions in place. And a single rule
governs references, lock discipline, and sleep safety at once: at an await
point, every value whose validity domain does not survive the await dies,
collapsing what Linux spreads across many separate mechanisms into one.

Two constructs remain unimplemented and fail closed rather than guessing —
both are wide-immediate pseudo-forms (a kernel variable's address and a
subprogram address taken as a value) that are blocked on runtime facilities
NARF does not yet carry, so admitting them here alone would turn a clean
rejection into an accept-then-trap, a strictly worse contract.

## Relationships

The verifier consumes the ISA model from `bpf/isa` and produces the verified
image that `bpf/jit` lowers to native code and that the parent `narf-bpf`
runtime executes. Keeping it dependency-free is deliberate: a conventional
in-kernel verifier can only be exercised by booting a kernel, whereas this one
can be differentially fuzzed against a concrete reference interpreter in
seconds on the host, which for a component whose bugs are kernel-compromise
bugs is worth more than any amount of in-kernel testing.

## no_std and features

The crate is `no_std` for kernel builds and `cfg`-switches to a hosted build
under test. The `kernel-test` feature (off by default) gates in-kernel smoke
tests registered through `narf-kernel-test`.
