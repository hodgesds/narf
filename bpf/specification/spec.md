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
// memory/src/bpf_text.rs — executable kernel text
pub struct Jit;                       // CapType, CapKind::Jit
pub type JitCap = Cap<Jit, Grant>;

pub fn reserve_kernel_slots() -> Result<(), TextError>;   // §4.1, boot-order critical
pub fn slots_reserved() -> bool;                          // what §4.1's debug_assert reads
pub fn alloc(cap: &JitCap, len: usize, node: usize) -> Result<TextAlloc, TextError>;
pub fn write(a: &TextAlloc, off: usize, bytes: &[u8]) -> Result<(), TextError>;
pub fn seal(cap: &JitCap, a: &TextAlloc) -> Result<(), TextError>;
pub fn free(a: TextAlloc);            // quarantine, then the reclaim hook
pub fn reclaim(a: TextAlloc);         // call only after a grace period
pub fn install_reclaim_hook(h: fn(TextAlloc));
pub fn stats() -> (usize, usize, usize);   // (packs, chunks used, quarantined)
```

`write` goes through the identity alias, so it is legal before *and* after
`seal` (§4.2). `narf-memory` cannot depend on `narf-rcu` — the dependency graph
already runs `rcu → time → console → memory` — so the RCU grace period arrives
through `install_reclaim_hook`, the same seam shape as `install_pager`.

```rust
// memory/src/bpf_arena.rs — the program heap
pub struct BpfArena;                  // CapType, CapKind::BpfArena
impl Arena {
    pub fn new(cap: &ArenaCap, max_pages: usize) -> Result<Arena, ArenaError>;
    pub fn kva(&self) -> u64;                              // stable for the arena's life
    pub fn window_offset(&self) -> u64;                    // the base-relative pointer
    pub fn populate(&self, page: usize) -> Result<u64, ArenaError>;
    pub fn populate_range(&self, from: usize, count: usize) -> Result<(), ArenaError>;
    pub fn first_unpopulated(&self, from: usize) -> Option<usize>;
    pub fn snapshot_frames(&self) -> Vec<PhysAddr>;        // freezes the arena — §8.2
    pub fn resolve(&self, offset: u64) -> Option<u64>;
}
```

```rust
// memory/src/bpf_extable.rs — recoverable fault sites
pub struct ExEntry { pub fault_pc: u64, pub fixup_pc: u64, pub dst: GpReg }
pub fn register_image(token: u64, base: u64, end: u64, e: Vec<ExEntry>) -> Result<(), ExError>;
pub fn unregister_image(token: u64);
pub fn try_recover(fault_pc: u64) -> Option<Recovery>;     // called from both trap handlers
```

`GpReg` is the *architectural* register number the JIT already emitted —
0..=15 in x86_64's ModRM/REX encoding, 0..=30 for aarch64's `x0..x30` — so no
translation table exists to drift.

```rust
// memory/src/bpf_stack.rs — the per-CPU atomic-program stack
pub const STACK_BYTES: u64;  pub const MAX_NEST: u32;
pub fn init(cpus: usize) -> Result<(), StackError>;
pub fn try_enter() -> Option<StackLease>;   // None ⇒ decline the program
pub const fn bytes_per_level() -> u64;      // the verifier's stack bound
```

`StackLease` is `!Send` and releases on drop; it must be taken and dropped
inside one non-preemptible region, because the depth counter is a per-CPU
non-atomic RMW. Sleepable programs use a heap stack instead (§4.8), so this is
not the only path — `STACK_BYTES` is public so both size identically.

```rust
// memory/src/wx.rs — the W^X capability gate
pub fn jit_grants_init();
pub fn grant_jit(task: u64) -> JitCap;      // idempotent per task
pub fn jit_cap(task: u64) -> Option<JitCap>;
pub fn revoke_jit(task: u64);               // wired to the thread exit-observer fan-out
pub fn jit_mprotect(cap: &JitCap, space: &AddressSpace,
                    base: VirtAddr, len: u64, new: RegionPerms) -> Result<(), WxError>;
```

`jit_mprotect` is the only path by which a `W | X` user mapping can come into
existence. `AddressSpace::mprotect_range` keeps rejecting `W | X` outright and
stays the cap-free fast path.

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
- **Cache maintenance — fixed.** `arch::patch_word` used to do `dsb ish; ic
  ivau; dsb ish; isb` with **no `dc cvau`**, which the architecture requires
  before `ic ivau` unless `CTR_EL0.IDC == 1`. It now delegates to
  `narf_arch::aarch64::asm::flush_icache_range`, which reads `CTR_EL0` for the
  line size and elides `dc cvau` / `ic ivau` on `IDC` / `DIC` exactly as
  Linux's `__flush_cache_user_range` does. `bpf_text::seal` uses the same
  primitive, scoped to the sealed allocation rather than the whole pack.
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
   **Interim behaviour (landed):** `Arena::snapshot_frames` freezes the arena
   and `Arena::populate` then returns `ArenaError::SnapshotTaken`, so the
   mistake surfaces as a typed error at the call that makes it rather than as
   a page that silently does not exist in userspace.
3. **Nested locks.** v1 permits one live `Guard` at a time. Nesting under a
   declared lock-order lattice is deferred.
4. **`struct_ops!` form.** Whether it re-declares traits or mirrors existing
   ones via `struct_ops_for!(path::Trait { … })`.
5. **Continuation-style JIT lowering for sleepable programs**, replacing "
   sleepable ⇒ interpreted".
6. **Demoting the low identity map to NX**, which is what would make §4.2 an
   actual W^X boundary. Needs a huge-page demote helper that does not exist.
7. ~~**Fuel accounting granularity**~~ — **resolved: per instruction.** Per
   back-edge bounds iterations rather than work: 65536 straight-line
   instructions cost one unit, so the default tank permitted ~7e10
   instructions per invocation, which is no bound inside an atomic probe. The
   interpreter burns per instruction retired; the JIT will burn per basic
   block, the same bound at coarser granularity.

   The cost of that choice is now **measured**, not asserted. `cargo xtask
   bpf-bench` runs the interpreter over four instruction mixes under both
   policies as an A/B pair, N = 60 each, samples interleaved round-robin, and
   applies §8's protocol. Median cycles per interpreted instruction, and the
   per-instruction policy's cost relative to the hoisted one:

   | shape  | cycles/insn | delta | 95% CI | decision |
   |--------|------------:|------:|--------|----------|
   | alu    | 97.4 | +0.22% | [+0.07, +0.37] | inconclusive (tests disagree) |
   | mem    | 122.7 | +0.40% | [+0.26, +0.62] | significant, within δ |
   | branch | 89.6 | +0.63% | [+0.43, +0.79] | significant, within δ |
   | call   | 88.1 | +0.03% | [−0.11, +0.25] | no difference established |

   Declared δ is 3%. The suite also carries an **A/A control** — a second
   monomorphisation of the production policy, compared against production —
   whose delta bounds what the harness can resolve: within ±0.2% on this
   runner. The controls are what make the numbers above readable, and they
   corrected an earlier answer: a two-arm build measured +2.4% on `mem` and
   +1.2% on `branch`, and adding a third instantiation moved both to under
   0.7%. Most of that 2.4% was where the function landed in the image, not
   what it did. Between-build code placement is a larger effect on this
   interpreter than the fuel policy is.

   So the original justification — "the interpreter already pays a decode and
   a match per instruction, so the marginal cost is noise" — holds, with the
   number attached: at most ~0.7% of interpreter throughput, on the
   branch-heavy mix, well inside δ. Item 7 stays resolved.

   Runner caveat: collected under KVM on an AMD Zen4 laptop whose §8.2
   noise-control preconditions (governor, boost, SMT, ASLR) are **not** met.
   `bpf-bench` refuses such a runner unless `--allow-unverified-runner` is
   passed and marks every record it emits `noise_control: unverified`. These
   are development measurements, not publishable perf numbers; the conclusion
   survives because the effect is an order of magnitude below δ, not because
   the environment was clean.
8. **aarch64 `probe.rs`.** Porting the x86_64 recoverable-probe module would
   let `memory/src/tests.rs`'s four `probe::arm` sites stop being x86-only.
   Optional scope, but adjacent.
9. **An ABI for kfuncs that await.** The kfunc calling convention is one
   uniform `extern "C" fn(u64, u64, u64, u64, u64) -> u64`, which is what lets
   the interpreter transmute a shim address once and the JIT emit one call
   sequence — but a `u64` is not a future, so a sleepable kfunc cannot go
   through it. `narf_yield()` is currently an interpreter intrinsic recognised
   by id (`interp::Vm::call_kfunc`). A second sleepable kfunc, or any kfunc
   that parks on real I/O rather than yielding to itself, needs a real answer:
   either a second shim shape returning `Poll`, or a registry flag routing
   sleepable kfuncs through a boxed-future path. Related: `interp::drive`
   spins because `YieldNow` wakes itself, which is only sound while `yield` is
   the sole await point.
10. **A `Guard` cannot be both linear and sleep-unsafe under the Phase-0
    contract.** `ArgDesc::consumes_in_arg_position` requires
    `domain.requires_release()`, which only `ValidityDomain::Owned` satisfies —
    but `KfuncDesc::validate` rejects a `PtrKind::LockGuard` return whose
    domain survives an await, and `Owned` does. §1.11's three properties want
    both. The fix is probably for linearity to key on `PtrKind::LockGuard`
    directly rather than on the validity domain; it should land with the
    abstract interpreter, which is the first consumer that cares.
11. **`bpf(2)` load latency has no yield point, and verification dominates
    it.** Measured by `cargo xtask bpf-bench` (N = 60, same runner caveat as
    item 7), for one `BpfProg::load` of a 64-instruction straight-line
    program:

    | phase | median cycles | share |
    |-------|--------------:|------:|
    | verify | 140 050 | 69% |
    | codegen | 11 076 | 5% |
    | publish (text alloc + write + extable + seal) | 47 322 | 23% |
    | **total, end to end** | **203 878** | |

    The three parts sum to 198 448 against a measured 203 878 — a 2.7%
    residual for `BpfProg::load`'s own bookkeeping, which is also the check
    that the decomposition is real.

    The concern is the scaling. Verification costs 3 030 cycles per
    instruction at 16 slots, 2 188 at 64, and 1 978 at 256 — flat, because it
    is amortising a fixed cost, not because the fixpoint is cheap. Forking
    changes that: the 194-slot `branchy194` shape (64 forward forks) costs
    5 121 cycles per instruction, 2.6× the straight-line rate at comparable
    size. `MAX_INSNS` is 65 536, so a maximally-branchy program at that rate
    is on the order of 3 × 10⁸ cycles — ~100 ms — spent inside `sys_bpf` with
    no yield point and no fuel-equivalent bound on the *verifier's* own work.
    Fuel bounds what a program does at runtime; nothing bounds what proving it
    costs.

    Two things this suggests, neither scoped yet: a work budget on the
    fixpoint that fails a program as too complex rather than making the caller
    wait, and an await point in the load path so a long verification is
    preemptible. Note that Linux's `BPF_COMPLEXITY_LIMIT_INSNS` is exactly the
    first of those, and §4.9's argument for not having one was about
    *termination*, which fuel does handle — it was never an argument about
    latency.

    **Severity, and why nothing is being changed yet.** This is a quality-of-
    service characteristic, not a denial of service: `bpf(2)` requires euid 0
    (§4.10, `task_may_load_bpf`), so the only caller who can provoke a 100 ms
    stall is one who can already do considerably worse. It is a privileged
    process making its own syscall slow.

    The existing `fixpoint_round_budget` does not bound this and is not the
    lever. The measured 5 121 cycles per instruction is the cost of a fixpoint
    that *converges* — real work proportional to branching, not a divergence —
    so a tighter round cap would reject legitimate programs without addressing
    the cost of legitimate ones.

    So: recorded with numbers, deliberately unfixed. Adding a complexity limit
    now would trade a real capability (large branchy programs verify) against a
    problem no caller has reported, and the design already carries one
    cautionary example of defensive machinery guarding a case that could not
    arise (§9, the sizing fixpoint). The lever if this ever bites is an await
    point in the load path, which costs nothing when verification is fast.

12. **A packet pointer needs *dynamic* region bounds, and the obvious
    shortcut is an information leak.** XDP programs currently receive the frame
    *summarised* into the context tuple (length, then 24 bytes as three words)
    because a program cannot dereference the frame at all. Lifting that is the
    next substantial verifier feature, and the shape of it is worth recording
    before someone reaches for the easy version.

    `PtrClass::Mem` is already the right class — "an untyped bounded byte
    region", which is exactly what a packet is. What blocks it is that
    `PtrVal::size` is an `Option<u64>`: a *constant*. A packet's length is only
    known at runtime, so the feature is `Mem` whose bound comes from a register
    or a sibling context field rather than from a literal. That is the same
    feature a variable-size map value needs, and the same one a kfunc returning
    `&[u8]` needs — the descriptor cannot express a size in return position
    today for the same reason.

    **The shortcut to avoid:** declaring the region a fixed size (an MTU, say)
    and letting programs read anywhere inside it. That is unsound here in a way
    it would not be for a buffer we owned. The frame reaches the classifier as
    an *immutable borrow of a driver DMA buffer* — see the XDP attach notes —
    so the runtime cannot zero the tail, and a program reading past a short
    frame's real length would see the previous packet's bytes. An
    information leak, and exactly the fail-open shape §9 records two of.

    So: dynamic bounds or nothing. Until then the context summary is honest
    about what a program gets, which is the property that matters — a program
    that appeared to hold a packet pointer while silently seeing zeroes would
    be worse than one that never had one.

## 9. Post-review corrections

A Fable review of the merged subsystem returned **do not land** with three
kernel-compromise or kernel-hang defects, two of them reachable unprivileged.
All fourteen findings are recorded here because several were *documentation*
that had come loose from the code, and the pattern is worth keeping.

Closed: unbounded arithmetic on faulting pointer classes (arbitrary kernel
read/write); a non-terminating fixpoint (stack slots joined, never widened —
an unprivileged kernel hang); `bpf(2)` gated on a capability the syscall
minted for itself; a 32-bit null test discharging a reference; unbounded arena
byte regions; a wrapping ctx access panicking the kernel; a per-CPU frame
released on the wrong CPU; BPF-to-BPF frames ignoring the verifier's table;
`seal` not enforcing §4.3; the runtime never depending on the memory
subsystem at all; a boot-order guard compiled out of release builds;
`CAP_JIT` gating the inverse of the JIT flip; a cross-crate frame-zeroing
obligation stated nowhere; fuel bounding iterations rather than work.

**The dominant failure mode was not any individual bug.** Four separate
safety arguments lived in one crate while depending on another's behaviour,
and stayed correct-looking after the thing they rested on changed:

* `PerCpuFrames: Sync` rested on handlers running with IRQs masked for their
  whole duration — a premise *this same series* removed when `dispatch::fire`
  was reworked to drop its lock before invoking.
* §4.3's extable-before-execute was prose; `seal` never checked.
* The verifier's caller-frame precision loss was safe only because the runtime
  zeroes frames, with nothing on either side saying so.
* `Ok` from the verifier carried obligations (`fault_sites`, `subprogs`,
  `uses_arena`) that nothing consumed.

Accordingly: an invariant that spans two crates belongs in a test, not in a
comment on one side of the seam.
