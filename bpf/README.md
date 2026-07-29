# `bpf/` — in-kernel BPF

Verified, JIT-compiled, sandboxed execution of programs supplied at runtime.
NARF's BPF is **instruction-set compatible with Linux and ABI-divergent**: the
encoding is Linux's verbatim so `clang -target bpf` is the compiler, while the
data model, memory model, call ABI, and verification strategy are designed
fresh — arena-first memory, one kfunc call ABI with semantics carried by Rust
types, fuel-metered execution so termination is a runtime property rather than
a verification one, and a single validity-domain rule that covers sleep
safety, lock discipline, and reference tracking at once.

Spec: [`specification/spec.md`](specification/spec.md).
Reading list: [`research/README.md`](research/README.md).

| Crate | Role |
|---|---|
| `isa/` | instruction encode/decode/disassemble — zero deps, host-testable |
| `verifier/` | type graph, IR, abstract interpretation — zero kernel deps, host-testable |
| `jit/` | x86_64 and aarch64 emitters — host-testable against golden disassembly |
| `src/` | kernel runtime, `kfunc!`/`struct_ops!` macros, attach adapters |

Stage 5+.
