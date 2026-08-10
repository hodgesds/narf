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
  tracking). Raw pointer deref is rejected; typed tracing reads use the
  independently rechecked `narf_probe_read` mediator.
- **Runtime** — the fuel-metered interpreter, and the x86_64/aarch64 **JIT**
  behind it. `run_atomic` enters native code once the verifier has proved the
  program and falls back to the interpreter otherwise. The JIT lowers the full
  loadable instruction set; the residual falls back (below).
- **Maps & arenas** — five map kinds (array, hash, per-CPU array/hash, ringbuf)
  plus program arenas.
- **Extension contracts** — the `kfunc!` and `struct_ops!` macros (Rust-native
  type descriptors, no BTF, no trampoline).
- **Attach surfaces** — dynamic probes, net classifier (XDP), perf, struct_ops.
  XDP exposes a writable `data` pointer paired with a read-only `data_end`:
  packet loads *and* stores require a verifier-proved dynamic bound and are
  independently slice-bounded by the interpreter (a write is bounds-checked
  against `data_end` with the same interval check as a read, and the JIT lowers
  a bounded store natively, symmetric to a bounded read). A program may rewrite
  header bytes in place, and *resize* the frame with
  `bpf_xdp_adjust_head`/`_tail` — these move `data`/`data_end` to trim or grow
  the packet, staged into a per-CPU `[headroom | packet | tailroom]` buffer so a
  grow has room the bare RX frame lacks (interpreter intrinsics; the JIT refuses
  a resizing program, as it does the ring-buffer intrinsics; the verifier
  invalidates every proven packet bound at an adjust call, so a fresh
  `data < data_end` is required before the next access). Actions:
  `PASS`/`DROP`/`ABORTED` plus `TX` and `REDIRECT` as retransmission of the
  *possibly-modified, possibly-resized* frame — `TX` reflects out the ingress
  iface, `REDIRECT` sends out the iface named by a `bpf_redirect(ifindex)` kfunc
  or by a `bpf_redirect_map(map, key, flags)` lookup. That helper serves both
  redirect map kinds: a `BPF_MAP_TYPE_DEVMAP` (a dense `u32`-keyed table of
  ifindexes) arms the looked-up ifindex and sends the frame out that NIC, and a
  `BPF_MAP_TYPE_CPUMAP` (keyed by target CPU) arms that CPU and delivers the
  frame to its stack — which on NARF's single RX-processing context is *local*
  delivery, the documented degradation of Linux's cross-CPU steering. A hit
  returns `REDIRECT`; a miss (empty slot, out-of-range key), a non-redirect map,
  or an out-of-range `flags` returns the program's `flags` fallback action.
  `bpf_redirect_map` is an ordinary shim the JIT lowers natively (the map handle
  is a real address on both backends), not an interpreter intrinsic. It also
  serves `BPF_F_BROADCAST`: a devmap broadcast fans the frame out to *every* live
  port (the `key` ignored), with `BPF_F_EXCLUDE_INGRESS` skipping the iface it
  arrived on — the staged port list is drained by the RX handler and sent to each
  after the classifier's lock releases, the same deferral the single-target
  retransmits use.
- **`bpf(2)`** — load, test-run, the full map element (including atomic
  lookup-and-delete) and batch ops, descriptor-local map read/write modes,
  object info and id/fd enumeration for progs/maps/links/BTF, pin/get with
  directory-fd-relative paths, attach/detach, link create/update/detach,
  keyed-map freeze, load-time map/BTF fd arrays, program-map lifetime binding,
  translated/native instruction dumps, stable Linux program tags, license and
  load-provenance metadata, bounded verifier logs, native raw-tracepoint program
  loads and named opens, fd-gated runtime statistics, recursion-miss accounting,
  prog-query, task-fd-query, and iterators.
  XDP test-run translates `data_in` into a kernel-owned writable frame (never a
  caller-authored native context pointer) and copies the post-program bytes back
  to `data_out` — including a resized packet's new length in `data_size_out`,
  matching Linux `BPF_PROG_TEST_RUN`.

Direct typed-field loads now land alongside the mediated path: a `BPF_LDX`
through a schema-tracked trace pointer is verifier-admitted only at an exact
declared field (the same check `narf_probe_read` runs, moved to verification
time), and is refused otherwise rather than lowered to a raw dereference. The
base register holds the tracing wrapper rather than the object, so the certified
load is serviced by the interpreter through the live `TypedProbeRef` — with the
runtime field recheck intact — and is deliberately kept out of the JIT's bare-
dereference set.

BPF's hardware confinement is now wired on every backend, not just PKS: on
x86_64 `run_atomic` enters the BPF domain through the unified `Pks` enforcer, so
an AMD / pre-SPR host drives it via **PCID** (a `CR3` swap into the BPF domain's
PML4 — a bootstrap byte-clone, so every BPF kernel-VA region stays mapped) rather
than falling back to unconfined; on aarch64 it enters via **MTE** (a structural
`SCTLR_EL1`/`GCR_EL1` save today, real tag-fault enforcement pairing with the
Stage-3 MTE-tag-aware allocator). As with PKS, the mechanism is complete on each
backend and the isolation strength grows as subsystems move state into private
domains. Residual: subsystem private-domain tagging, which turns the fence from
an escape-containment property into a positive one (below).

Two former JIT residuals now lower. **Fetching bitwise arena atomics**: x86_64
via a `cmpxchg` loop that preserves R0 in a reserved frame word, aarch64 via its
LSE fetch. **Arena access under a BPF-to-BPF call**: x86_64 anchors the entry
`rsp` in a spare register, so an arena access reaches its base at any call depth
and an arena fault or out-of-fuel exit resets `rsp` to that anchor before
unwinding — an arena access inside a subprogram now JITs. aarch64 has no equally
free register, so it composes arena with calls for accesses in the *main*
program and leaves an access inside a subprogram interpreted (correct, not
native).

The JIT is enabled **behind the verifier**: the interpreter's safety came from
never dereferencing a program-supplied address, and native code trades that for
the verifier plus the extable plus the arena guard slots — the right trade only
once the verifier exists, which it now does.

## Hardware confinement (design)

BPF is the one Ring-0 subsystem that runs attacker-authored code. Its own
framekernel domain, `DomainId::BPF`, now confines it: `run_atomic` runs every
program behind `enter_domain(FRAME, BPF)` on PKS silicon, so a verifier or JIT
escape that stores into another subsystem's domain (the cap table, the scheduler,
a driver) takes a protection-key fault instead of an arbitrary Ring-0 write —
hardware defense-in-depth *under* the verifier. FRAME stays reachable, so the
interpreter, the kfunc shims, and the fault handler keep working; on AMD PCID it
is a `CR3` swap into the BPF domain's PML4 and on aarch64 MTE a structural
system-register save (both wired; see below). Because NARF BPF already reaches
memory only through its own stack/ctx/maps/arena (no raw kernel deref, no
arbitrary `bpf_probe_read`), it cost the runtime nothing. Typed observability now
reads through a Frame-mediated `narf_probe_read` kfunc that accepts only
schema-tracked pointers — never a raw address — and rechecks the exact field at
runtime, so the fence holds for tracing.

Full design, threat model, the FRAME-stays-writable rationale, the tracing read
model, why BTF is not the path there, the PKS/PCID/MTE backends (all wired), and
what remains (subsystem private-domain tagging, and the Stage-3 tag-aware
allocator that upgrades the aarch64 structural save into real tag-fault
enforcement) are in
[`specification/domain-confinement.md`](specification/domain-confinement.md).
