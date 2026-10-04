# bpf/isa — The eBPF Instruction-Set Model

`narf-bpf-isa` is the shared vocabulary of NARF's BPF subsystem: a precise
model of the eBPF instruction set together with the machinery to decode raw
instruction bytes into that model, encode the model back into bytes, and
disassemble it into human-readable text. It is the one place in the subsystem
that knows the on-the-wire shape of an instruction, so every other BPF crate
speaks to the ISA through this model rather than poking at opcode bytes
directly — the verifier decodes with it, the JIT lowers from it, and the
runtime disassembles with it for logs and verifier output.

## Why the encoding is Linux's

NARF's BPF is instruction-set compatible with Linux while remaining
ABI-divergent: the binary encoding is Linux's verbatim so that LLVM's `bpf`
target can serve as the compiler, but the data model, call ABI, and
verification strategy above the encoding are designed fresh. Because the
encoding is not NARF's to change, the model faithfully carries the warts of
the real eBPF ISA — offset fields that select signed-division and sign-extend
variants or address-space casts, atomic operations encoded in the immediate
field (two of them too wide for eight bits), and source-register fields that
distinguish the several wide-immediate pseudo-forms and the kinds of call.
Modelling the encoding exactly is what keeps `clang -target bpf` usable as the
toolchain without NARF having to write its own backend.

## What it deliberately rejects

Even though the encoding is Linux's, this crate refuses at decode time two
constructs that Linux accepts, because excluding them here keeps the exclusion
in a single location rather than scattering unreachable match arms through the
verifier and both JIT backends. Helper calls are rejected because NARF has a
single call ABI — kfuncs only, with argument semantics carried by Rust types
rather than BTF parameter-name suffixes — and the legacy packet-load
instructions (`LD_ABS`/`LD_IND`), long considered an artifact of classic-BPF
compatibility, are rejected outright.

## Layering

A decoded instruction here is a decoding, not an intermediate representation:
it is faithful to the encoding, one case per instruction shape, and nothing
more. The verifier builds a control-flow and SSA IR on top of these decodings,
and everything downstream of verification works on that IR instead, so raw
instruction indices stop being meaningful once a program is verified. That
split is what lets NARF lower a program to native code once rather than
patching instructions in place the way Linux does.

## no_std and testing

The crate is `no_std` for kernel builds, carries zero dependencies, and forbids
unsafe code, so it builds and tests entirely on the host. In-kernel smoke tests
are gated behind the `kernel-test` feature, which is off by default so that a
host `cargo test` needs no kernel dependencies at all; when enabled it registers
those smokes through `narf-kernel-test`.
