# `bpf/` — specification

## 1. Purpose & scope

In-kernel BPF: a verified, JIT-compiled, sandboxed execution environment for
programs supplied at runtime by userspace.

NARF's BPF is **instruction-set compatible with Linux and ABI-divergent**. The
instruction encoding is Linux's verbatim, because LLVM's `bpf` target is our
compiler and rewriting the encoding would mean writing a backend. Everything
above the encoding — the data model, memory model, call ABI, and verification
strategy — is designed here rather than inherited.

For scale: Linux's BPF is ~83.5k LOC in `kernel/bpf/` plus ~40k across arch
JITs plus 12.6k in `net/core/filter.c`; `verifier.c` alone is 26,199 lines.
Roughly half of that is accreted complexity, and §8 of `research/README.md`
enumerates which half and why.

**In scope:** the verifier, the JIT, arenas and maps, the kfunc and struct_ops
extension mechanisms, and four attach surfaces (tracing/fentry, struct_ops,
net classifier, perf).

**Out of scope, permanently:** helper calls (we have one call ABI), `LD_ABS`/
`LD_IND`, unprivileged BPF, and Linux's map-type zoo beyond the five native
kinds in §3.4.

**Out of scope, for now:** offloaded programs, `bpffs` pinning, CO-RE
relocation in-kernel (it is a userspace concern), and continuation-style JIT
lowering of sleepable programs (§8.5).

## 2. Assumptions

1. **The instruction encoding is fixed.** Including its warts: `off` selecting
   the `SDIV`/`SMOD`/`MOVSX` variants and `ADDR_SPACE_CAST`; atomic operations
   living in `imm` with two of them (`BPF_LOAD_ACQ`, `BPF_STORE_REL`) too wide
   for eight bits; `src_reg` selecting seven `LD_IMM64` pseudo-forms and three
   kinds of call.
2. **Programs are hostile.** Every guarantee is enforced, never assumed.
3. **`alloc` is available**, but a *running* program may not use it — see §4.6.
4. **The kernel address space is currently RWX.** `memory/src/x86_64/mmu.rs`
   maps the low identity window `PRESENT | WRITABLE | HUGE_PAGE` with no
   `NO_EXEC`, and there is no huge-page demote helper. JIT text mapped RX at
   its own VA is therefore *simultaneously aliased RWX* through the identity
   map. See §4.2 — this is stated as a limitation, not claimed as a boundary.
5. **BPF kernel-VA slots must exist before the first user address space.**
   `new_user_pml4_on` (`memory/src/x86_64/paging.rs:239`) snapshot-copies
   PML4[256..511] *by value*, and nothing propagates later changes. See §4.1.

## 3. Public interface

### 3.1 Crates

| Crate | Contents | Dependencies |
|---|---|---|
| `narf-bpf-isa` | instruction encode/decode/disasm | none |
| `narf-bpf-verifier` | type graph, IR, abstract interpretation | `isa` |
| `narf-bpf-jit` | x86_64 and aarch64 emitters | `isa`, `verifier` |
| `narf-bpf` | kernel runtime, `kfunc!`/`struct_ops!`, attach adapters | the above + kernel crates |

The first three are dependency-free of the kernel and host-testable via
`cargo xtask host-test`. `narf-bpf` must **not** depend on `narf-userspace` —
that would be a cycle. The `bpf(2)` handler lives in `narf-userspace`, which
depends on `narf-bpf`.

### 3.2 The kfunc contract

`narf_bpf_verifier::kfunc` — `KfuncDesc`, `ArgDesc`, `ValidityDomain`,
`PtrKind`, `Context`. Argument semantics are derived from Rust types by the
`kfunc!` macro through a `BpfType` trait:

| Rust type | Meaning | Linux equivalent |
|---|---|---|
| `u32`/`u64`/`i64` | scalar | plain arg |
| `Trusted<T>` | trusted non-null pointer, dies at an await | `PTR_TRUSTED` |
| `Owned<T>` (return) | acquires a reference | `KF_ACQUIRE` |
| `Owned<T>` (argument) | releases it; consumed | `KF_RELEASE` |
| `Option<T>` | nullable; must be tested | `KF_RET_NULL` / `__nullable` |
| `Rcu<'g, T>` | QSBR-domain; dies at an await | `KF_RCU` / `MEM_RCU` |
| `SleepableRcu<'g, T>` | survives awaits; needs `Cap<SleepableReader>` | `KF_RCU_PROTECTED` |
| `&[u8]` | pointer + length pair | `__sz` |
| `&mut MaybeUninit<T>` | callee initialises | `__uninit` |
| `ArenaPtr<T>` | arena-space pointer | `KF_ARENA_ARG*` |
| `Const<N>` | verified constant | `__k` |
| `Guard<'_>` | critical-section guard; linear, never sleep-safe | `bpf_spin_lock` |

Descriptors go into a `narf.kfuncs` link section, collected at boot exactly as
`narf-kernel-test` collects `narf.tests`.

### 3.3 Memory-subsystem interface (Stream B)

```rust
// memory/src/bpf_text.rs
pub fn reserve_kernel_slots() -> Result<(), TextError>;   // §4.1, boot-order critical
pub fn alloc(cap: &Cap<Jit, Grant>, len: usize) -> Result<TextAlloc, TextError>;
pub fn seal(cap: &Cap<Jit, Grant>, a: &TextAlloc) -> Result<(), TextError>;
pub fn free(a: TextAlloc);                                 // via RCU retire

// memory/src/bpf_arena.rs
impl Arena {
    pub fn new(cap: &Cap<BpfArena, Grant>, max_pages: usize) -> Result<Arena, ArenaError>;
    pub fn kva(&self) -> u64;                              // stable for the arena's life
    pub fn populate(&self, page: usize) -> Result<u64, ArenaError>;
}
```

### 3.4 Maps

Five native kinds behind an ~8-method trait: `Array`, `Hash`, `PerCpuArray`,
`PerCpuHash`, `RingBuf`. Everything else Linux makes a map type — LRU, LPM
tries, bloom filters, queues/stacks, map-in-map, and the graph data-structure
API — is an arena + kfunc library here, not kernel code.

## 4. Invariants

Numbered for `safety-argument.toml` references. **This subsystem touches
`frame/`, `memory/`, and `capabilities/`, so it is a TCB change** under
AGENTS.md: two maintainers (one security), signed commit, `security-review`,
and a `safety-argument.toml` entry.

**4.1 — BPF kernel-VA top-level tables are allocated at boot, before the first
user address space.** `new_user_pml4_on` snapshot-copies PML4[256..511] by
value with no later propagation, so a slot first populated after a user AS
exists leaves that AS's CR3 holding a zero entry, and any BPF access while
that task is current **triple-faults**. `reserve_kernel_slots()` is a direct
call from `bare_main.rs` after MMU init, *not* a staged initcall. A
`debug_assert` in `new_user_pml4_on` checks both slots are present so a future
reordering fails loudly.

**4.2 — JIT text is mapped RX at its own VA, and this is not yet a security
boundary.** Per assumption 2.4 the identity map aliases the same frames RWX.
The RX mapping is still correct and worth doing, but W^X for kernel text is
incomplete until the identity map is demoted to NX (tracked; §8.6).
Consequence: the RW→RX publish writes *through the identity alias*. Do **not**
build Linux's temporary-alias mechanism — it exists because Linux's direct map
is NX, and here it would add attack surface for nothing.

**4.3 — Extable registration precedes execution.** Every faulting instruction
the JIT emits has an `ExEntry` registered *before* `seal()` publishes the text
as executable. A fault with no entry is fatal, by design.

**4.4 — Sleep safety, lock discipline, and reference tracking are one rule.**
At an await point, every live register whose `ValidityDomain` fails
`survives_await()` is killed. No separate lock-held check, no
`bpf_rcu_read_lock` equivalent.

**4.5 — Sleepability is declared by the hook, not by the program.** A program
verified for `Context::Atomic` cannot attach to a sleepable hook or vice
versa; the mismatch is a type error at attach, not a runtime flag check.

**4.6 — A running program may not allocate.** Permitted: `try_alloc_atomic`
(handling `None`), `atomic_pool`. Forbidden: the global allocator,
`alloc_frame`, any `IrqSafeSpinLock` a caller might hold, and all of
`narf_tracing::dispatch::*` (§4.7). Map values live in slabs pre-sized at
creation, so `map_update_elem` never allocates.

**4.7 — BPF programs must not re-enter the probe dispatcher.**
`tracing::dispatch::fire()` invokes handlers *while holding* `TABLE.inner`
with IRQs masked. Any BPF-reachable path back into `dispatch::*` self-
deadlocks. The kfunc set is a closed, audited list, and the `dispatch.rs`
Stage-4 rework (drop the lock before invoking) is a **prerequisite** of the
fentry attach type, not a follow-up.

**4.8 — Atomic and sleepable programs use different stacks.** Atomic programs
draw frames from the per-CPU BPF stack region; sleepable programs get a heap
stack owned by the future, because a sleeping program cannot hold a per-CPU
slot across a yield.

**4.9 — Fuel bounds total work and is never refilled.** `narf_yield()` lets a
sleepable program cooperate; it does not restore fuel. Exhaustion terminates
the program with a diagnostic, not a fault.

**4.10 — Loading requires `Cap<BpfProgLoad, Grant>`.** There is no
unprivileged mode and no second set of limits.

**4.11 — The verifier fails closed.** Any construct it cannot prove safe is
rejected. `VerifyError` carries an instruction index wherever one exists.

## 5. Architecture notes

### x86_64

- **VA layout.** BPF text and arena windows each take a dedicated PML4 slot,
  clear of the identity map (0), high MMIO (1), the per-domain PCID slots
  (256..=271), vmalloc (272 — note `vmalloc.rs:15`'s "273" comment is wrong),
  the direct map, and the kernel image (511).
- **Prog pack.** One 2 MiB hugepage per pack from `memory/src/hugepage.rs`
  (`alloc_hugepage_2m_on`), mapped by a single PMD entry so ~500 programs cost
  **one iTLB entry** instead of one each — the entire rationale, stated
  verbatim at `kernel/bpf/core.c:863`. Hugepages do not fall back to the buddy
  (`hugepage.rs:17`), so a 4 KiB fallback path is required rather than failing
  the load.
- **Seal.** Rewrite leaf PTEs to drop `WRITABLE`, drop `NO_EXEC`, add `GLOBAL`;
  then one ranged `invlpg_global_range`, not 512 IPIs; then a serialising
  instruction. `GLOBAL` is correct: BPF text is identical under every CR3.
- **Extable hook.** `frame/src/x86_64/trap.rs`, inserted after every legitimate
  recovery surface (demand paging, stack grow, COW) and *before*
  `probe::consume` and `diag::note_pf`, so a recovered BPF fault neither steals
  another recovery nor poisons the first-fault-wins panic latch. Kernel-mode
  only. The fixup zeroes the destination GPR by mutating the trap frame, so the
  JIT needs one fixup label per program rather than a stub per site.
- **Arena addressing.** One register pinned to the window base; accesses are
  `[base + reg + off16]`. Guard regions are whole unmapped slots, so escape by
  immediate displacement is structurally impossible — the same derivation as
  Linux's `GUARD_SZ` (`arena.c:45`), with room to spare.

### aarch64

- **There is no kernel fault recovery today.** No `arch/src/aarch64/probe.rs`
  exists, and `frame/src/aarch64/trap.rs` handles only data aborts from a
  *lower* EL; `EC = 0b100101` (current EL) falls through to `exit_kernel(42)`.
  The extable is first-of-its-kind here, not a re-wiring.
- **Cache maintenance.** `arch::patch_word` does `dsb ish; ic ivau; dsb ish;
  isb` with **no `dc cvau`** — architecturally required before `ic ivau` unless
  `CTR_EL0.IDC == 1`. A bulk JIT publish hits this far harder than a 4-byte
  probe patch; fix it as part of this work.
- **TLB.** `tlbi vale1is` is inner-shareable and self-broadcasts, so no IPI
  plumbing is needed — an asymmetry with x86_64 worth remembering.
- The JIT is x86_64-first; aarch64 runs interpreted until its emitter lands.

## 6. Dependencies

`narf-bpf-isa` → nothing. `narf-bpf-verifier` → `isa`. `narf-bpf-jit` → `isa`,
`verifier`. `narf-bpf` → those plus `narf-lib`, `narf-arch`, `narf-memory`,
`narf-capabilities`, `narf-rcu`, `narf-filesystem`, `narf-tracing`,
`narf-init`. `narf-userspace` → `narf-bpf` (never the reverse).

Capabilities: `Jit` (0x0053), `BpfProgLoad`/`BpfAttach`/`BpfMap`/`BpfArena`/
`BpfStructOps` (0x0300..). struct_ops reuses the existing pluggable-policy
caps — `SchedPolicy` (0x0203), `IoScheduler` (0x0206), `CongestionControl`
(0x0207), `IdleGovernor` (0x0208) — so it needs no new cap plumbing.

## 7. Stage assignment

Stage 5+. Depends on the MMU, buddy/slab, capabilities, RCU, tracing dispatch,
and the perf event layer, all of which are closed.

## 8. Open questions

1. **Arena pointer width and truncation sequence.** A 32-bit in-program pointer
   costs one `mov eax,eax`; a wider one costs a shift pair but lifts the 4 GiB
   cap. Whether to keep a 32-bit fast path for small arenas is a Phase-3 call.
2. **Demand-populated arenas need a new `FileOps` hook.** `mmap_frames` is
   eager and whole-range, and takes its frame snapshot at mmap time — so a page
   the *program* populates later is never visible to userspace. A
   `mmap_fault(offset)` hook routed from the demand-paging arm of the trap
   handler fixes this and would make every device node demand-pageable, not
   just arenas. Roughly 40 lines; scope in Phase 3.
3. **Nested locks.** v1 permits one live `Guard` at a time. Nesting under a
   declared lock-order lattice is deferred.
4. **`struct_ops!` form.** Whether it re-declares traits or mirrors existing
   ones via `struct_ops_for!(path::Trait { … })`.
5. **Continuation-style JIT lowering for sleepable programs**, replacing "
   sleepable ⇒ interpreted".
6. **Demoting the low identity map to NX**, which is what would make §4.2 an
   actual W^X boundary. Needs a huge-page demote helper that does not exist.
7. **Fuel accounting granularity** — per back-edge only, or per basic block.
8. **aarch64 `probe.rs`.** Porting the x86_64 recoverable-probe module would
   let `memory/src/tests.rs`'s four `probe::arm` sites stop being x86-only.
   Optional scope, but adjacent.
