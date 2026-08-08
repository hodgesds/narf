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
| `btf/` | BTF blob parser for `BPF_BTF_LOAD` — a loader-compatibility surface, not NARF's type system. Zero deps, `forbid(unsafe_code)`, host-testable |
| `isa/` | instruction encode/decode/disassemble — zero deps, host-testable |
| `verifier/` | type graph, IR, abstract interpretation — zero kernel deps, host-testable |
| `jit/` | x86_64 and aarch64 emitters — host-testable against golden disassembly |
| `src/` | kernel runtime, `kfunc!`/`struct_ops!` macros, attach adapters |

## Where it is

Landed:

- **Instruction layer** — encode/decode/disassemble for the whole ISA.
- **Verifier** — the abstract interpreter is real: `verify()` runs
  `fixpoint::run` over the type graph, enforcing pointer classes, bounds, and
  the single validity-domain rule (sleep safety + lock discipline + reference
  tracking). Raw pointer deref is rejected; there is no `bpf_probe_read`.
- **Runtime** — the fuel-metered interpreter, and the x86_64/aarch64 **JIT**
  behind it. `run_atomic` enters native code once the verifier has proved the
  program and falls back to the interpreter otherwise. The JIT lowers the full
  loadable instruction set; the residual falls back (below).
- **Maps & arenas** — five map kinds (array, hash, per-CPU array/hash, ringbuf)
  plus program arenas.
- **Extension contracts** — the `kfunc!` and `struct_ops!` macros (Rust-native
  type descriptors, no BTF, no trampoline).
- **Attach surfaces** — dynamic probes, net classifier (XDP), perf, struct_ops.
- **`bpf(2)`** — load, test-run, the full map element and batch ops, object info
  and id/fd enumeration for progs/maps/links/BTF, pin/get, attach/detach, link
  create/update/detach, prog-query, task-fd-query, and iterators.

Residual: JIT lowering of arena atomics and arena access under a subprogram call
(register-allocation blockers — these fall back to the interpreter); typed
object access for tracing; and hardware domain confinement (below).

The JIT is enabled **behind the verifier**: the interpreter's safety came from
never dereferencing a program-supplied address, and native code trades that for
the verifier plus the extable plus the arena guard slots — the right trade only
once the verifier exists, which it now does.

## Hardware confinement (design)

BPF is the one Ring-0 subsystem that runs attacker-authored code, and today it is
the one with no framekernel domain tag: a verifier escape is a full Ring-0
primitive. The next layer confines the BPF runtime to its own PKS/MTE domain, so
an escape is contained to `DOMAIN_BPF` instead of reaching the Frame's capability
table or another domain — hardware defense-in-depth *under* the verifier. Because
NARF BPF already reaches memory only through its own stack/ctx/maps/arena (no raw
kernel deref, no `bpf_probe_read`), confinement costs the policy/struct_ops path
nothing. Observability, if it ever lands, reads through a Frame-mediated
`narf_probe_read` kfunc that accepts only verifier-tracked pointers — never a raw
address — so the fence holds even for tracing.

Full design, threat model, the `run_atomic` enter/exit seam, the tracing read
model, why BTF is not the path there, and the first milestone (a PKS-confined BPF
idle governor as the first `struct_ops` consumer) are in
[`specification/domain-confinement.md`](specification/domain-confinement.md).
