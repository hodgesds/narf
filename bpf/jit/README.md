# bpf/jit — Native Code Generation for Verified BPF

`narf-bpf-jit` turns a verified BPF program into native machine code for the
host architecture. It is the performance half of the runtime: the subsystem
executes a program through the fuel-metered interpreter until the verifier has
proved it, at which point this crate lowers the verified image to x86-64 or
aarch64 code that runs directly. Codegen is enabled strictly behind the
verifier — the interpreter was safe because it never dereferenced a
program-supplied address, and native code gives that up in exchange for the
verifier's proof, the exception table, and the arena guard slots.

The crate deliberately knows nothing about where the emitted code will live. It
writes bytes into a buffer the caller provides; the executable-text allocator,
the read-write to read-execute seal, and the registration of the exception
table are the parent runtime's and the memory subsystem's concern. That
separation is what keeps this crate free of kernel dependencies and testable on
the host against golden encodings.

## What it emits, and the order that matters

Code generation produces two things together: the machine-code bytes and a
fault table describing the sites where the native code may trap on a bounded
memory access. The two are returned from a single operation so there is no way
to obtain the code without also obtaining the table it depends on — and the
caller must register that table before sealing the text as executable, a
requirement the memory subsystem enforces rather than trusts.

## Why there is no sizing fixpoint

Neither backend runs a branch-size convergence loop, and each reaches that
property a different way. On x86-64 every branch uses a 32-bit relative
displacement, so nothing shrinks and nothing needs re-measuring. On aarch64 the
emitter chooses fixed branch shapes rather than a single branch width — because
the unconditional and conditional branch ranges differ, a conditional jump
always lowers to an inverted-condition short branch over an unconditional one,
two instructions regardless of distance — which avoids the oscillation a
distance-dependent choice would cause.

## Fuel and out-of-band status

Because the verifier deliberately does not prove termination, fuel is the only
thing bounding a program's work, so the native code must burn fuel too or an
infinite loop would run forever on a hook that may have interrupts masked. Fuel
is charged per basic block — decremented by the block's instruction count on
entry — which yields the same total as the interpreter's per-instruction burn
at far fewer operations; equal totals is a correctness property, since a
program's verdict must not depend on whether it ran JITed or interpreted, and
both backends compute the charge from the same shared block module so they
cannot drift. Fuel exhaustion is reported out of band in a second return
register (both ABIs return a wide value in a register pair), so "ran out of
fuel" is never confused with a program that legitimately returned a sentinel
value; that out-of-band channel carries a status code rather than a mere
boolean so the arena lowering has its own way to stop.

## The arena lowering

An in-program arena pointer is a slot-relative handle, so an arena access
lowers to a base-plus-handle-plus-offset addressing form whose slot base is
passed as an extra entry argument, letting the same emitted image run against
whatever arena slot the program is given. Two properties of the emitted
sequence are load-bearing and asserted by golden tests: the handle is
zero-extended from 32 bits so that the reachable address range is a property of
the emitted bytes rather than an inherited verifier invariant, and the access
displacement is folded into the index register so that at the moment of a fault
the register holds exactly the handle the interpreter would have computed —
which lets the fault epilogue name the offending handle instead of reporting
zero.

## Relationships, no_std, and features

The JIT consumes the ISA model from `bpf/isa` and the verified program from
`bpf/verifier`, and emits code the parent `narf-bpf` runtime installs and runs.
It is `no_std` and dependency-free of the kernel; the `kernel-test` feature
(off by default) gates in-kernel smokes registered through `narf-kernel-test`,
while the default build is validated on the host against golden disassembly.
