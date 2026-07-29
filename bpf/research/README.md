# `bpf/` — research reading list

Primary sources for the NARF BPF subsystem. Linux tree references are to
`v7.0-rc3` (`b90c984d615e`).

## Read in this order

1. **`Documentation/bpf/standardization/instruction-set.rst`** (790 lines) —
   the only real specification of the instruction set, and the one part of
   Linux's BPF we adopt verbatim.
2. **`Documentation/bpf/bpf_design_QA.rst`** (351) — the design rationale and,
   more usefully, its regrets. `:105` concedes that "the only way to know that
   the program is going to be accepted by the verifier is to try to load it",
   which is the failure NARF's fuel model is meant to avoid.
3. **`include/linux/bpf_verifier.h`** (1,098) — the whole verifier data model
   in one file. The 40-line comment at `:370` on the state tree and loop
   detection reads as a specification.
4. **`kernel/bpf/liveness.c:1-120`** — how a modern BPF dataflow analysis
   *should* be written. Twenty years of ad-hoc parent-chain marking replaced by
   a textbook lattice formulation. NARF should start here rather than evolve
   into it.
5. **`kernel/bpf/verifier.c:4798-4886`** — precision, the hardest concept, with
   the best available explanation of why Linux tracks it retroactively.
6. **`kernel/bpf/verifier.c:9126-9203`** — open-coded iterators and the
   termination argument, including an honest worked example of a safe program
   the heuristic rejects.
7. **`kernel/bpf/arena.c:16-47`** — the arena addressing trick and, in
   particular, the derivation of `GUARD_SZ` from the instruction encoding's
   immediate width. Genuinely elegant; NARF keeps it.
8. **`arch/x86/net/bpf_jit_comp.c:70-113`** — a real JIT convergence
   oscillation bug and its fix (capping 8-bit jump offsets at 123, plus
   `jmp_padding`). Worth reading before writing any two-pass emitter.
9. **`arch/x86/net/bpf_jit_comp.c:3145-3210`** — the trampoline ABI, written
   out as literal assembly. The context for a fentry program is just the
   spilled argument array, which is why NARF needs no context-rewriting layer.
10. **`kernel/bpf/core.c:862-1013`** — the prog-pack allocator and its iTLB
    rationale, stated verbatim at `:863`.
11. **`Documentation/bpf/graph_ds_impl.rst:81-180`** — owning vs non-owning
    references, and the admission at `:22` that the map API was over-applied.
12. **`Documentation/bpf/kfuncs.rst`** (734) — the current extension mechanism.

## Where the bulk is

`kernel/bpf/` totals 83,531 LOC across 60 files. `verifier.c` (26,199),
`btf.c` (9,744), and `syscall.c` (6,595) are 51% of it; add
`net/core/filter.c` (12,581) and you have about two-thirds. Maps, the JIT,
trampolines, and arenas are each comparatively small.

## What NARF deliberately does differently

Each entry names the Linux artefact it removes. Full argument in
`specification/spec.md` and in the plan that produced this subsystem.

| NARF choice | Deletes |
|---|---|
| Fuel-metered execution | insn limit, state limits, five loop constructs |
| One numeric domain (`tnum × interval`) | ~800 LOC of pairwise deduction across six domains |
| One call ABI, semantics in Rust types | helper table + kfunc BTF-suffix parsing (~2,000 LOC) |
| Arena-first memory | map-in-map, kptrs, graph API, 14-way `btf_field_type` |
| Dedicated per-CPU BPF stack | `MAX_BPF_STACK`, `priv_stack`, stack-depth machinery |
| Context = typed argument tuple | `convert_ctx_access` and most of `filter.c` |
| Verify an IR, lower once | ~1,700 LOC of in-place instruction patching |
| Speculation as a separate pass | `speculative` state colouring (~600 LOC) |
| One privilege regime | `allow_ptr_leaks`/`bpf_capable`/`bypass_spec_*` forks |
| One validity-domain rule | `bpf_rcu_read_lock`, `KF_RCU_PROTECTED`, lock bookkeeping |

## Non-Linux sources worth consulting

- **PREVAIL** (Gershuni et al., PLDI 2019) — an abstract-interpretation BPF
  verifier using zone/octagon domains. The closest published work to NARF's
  approach, and the argument that a declared lattice beats a search budget.
- **Sound, Precise, and Fast Abstract Interpretation with Tristate Numbers**
  (Vishwanathan et al., CGO 2022) — the tnum correctness proofs, including
  bugs found in Linux's implementation.
- **Bonwick, "The Slab Allocator"** (USENIX 1994) — already the basis of
  `memory/src/slab.rs`; relevant again for the prog-pack chunk allocator.
