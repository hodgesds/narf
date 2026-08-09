# `bpf/` — hardware-domain confinement (design note)

Status: **design, pre-implementation.** Companion to `spec.md`. Scoped to
PKS/Intel first; AMD PCID and aarch64 MTE are deferred (§8).

## 1. Purpose

BPF in NARF is a **software-isolated** extension mechanism: the verifier is the
trust boundary, and a *running* program's safety comes from the verifier plus an
interpreter that never dereferences a program-supplied address (`spec.md` §4,
`interp.rs:613`). This note asks a different question: **can we put a second,
hardware-enforced fence around the BPF runtime** — the same PKS/MTE domain fence
the framekernel already puts around drivers — so that a verifier escape is
contained instead of catastrophic?

The framekernel already commits to belt-and-braces: *"Every kernel-side data
access is covered by both a capability check and a domain tag — defence in
depth, not a single-point-of-failure"* (`security-model/`). BPF is the one
Ring-0 subsystem that runs **attacker-authored code**, and today it is the one
subsystem with **no domain tag at all**. This note closes that gap.

The organizing claim: **the verifier is BPF's software isolation; a PKS domain
is the hardware isolation that backs it up.** They are peers, not alternatives.

## 2. Background: two facts that make this cheap

### 2.1 BPF barely uses address-space visibility

Unlike Linux BPF, NARF BPF has no `bpf_probe_read` and no way to dereference an
arbitrary kernel pointer. A program reaches memory by exactly four paths, and
only two are real dereferences — of the program's *own* memory:

| Path | Mechanism | Real cross-domain deref? |
|---|---|---|
| ctx tuple | copied in by value; synthetic `CTX_REGION` (`interp.rs:94`) | no |
| kfunc call | typed scalars/handles; the shim runs in kernel context | no |
| map value | pointer into that map's own value bytes | its own bytes only |
| arena | bounds-checked deref of the program's own frames (`interp.rs:649`) | its own frames only |

The verifier rejects raw object deref outright (`OpaqueDeref`,
`verifier/src/fixpoint.rs:931` — no BTF, so no offset is provably in-bounds),
and a wild pointer in the interpreter **traps, never faults**
(`smoke_bpf_interp_wild_load_traps_not_faults`). The kfunc surface is four typed
functions, deliberately: *"the closed, audited list is the safety property"*
(`kfuncs.rs:3`).

**Consequence.** The "visibility into an address space" that confinement would
remove is the Linux *tracing* model (kprobe + `probe_read` reading arbitrary
kernel memory) — which NARF has already declined (`spec.md` §1, "out of scope,
permanently: … unprivileged BPF"; there is no probe_read helper). For the BPF we
actually run, confinement removes almost nothing.

### 2.2 The domain fence is already live (on Intel)

PKS is wired end-to-end and **tested**: `smoke_pks_enforces_deny_all`
(`memory/src/tests.rs`) maps a page with a pkey, sets that domain to `DENY_ALL`,
and observes the write `#PF` with the PK-fault signature. The primitives:

- A domain is a **4-bit protection key** in PTE bits 59–62, set at map time via
  `PtFlags::pk(domain)` (`memory/src/x86_64/paging.rs`).
- Access rights live in the **`IA32_PKRS` MSR**, 2 bits/domain (access-disable,
  write-disable); `arch/src/x86_64/pks.rs` reads/writes it (`save`, `restore`,
  `set_rights`, `enter_domain`, `exit_domain`).
- Entering a domain is **one `WRMSR`** (~tens of cycles, no TLB flush).
- **Domain 0 (FRAME) is readable from every domain** — kernel text, cap table,
  and the direct map stay reachable, which is what lets a kfunc shim still work.

Two nuances that make PKS the *right* primitive here:

1. **PKS gates data loads/stores, not instruction fetch.** So JIT text
   executability stays governed by W^X (`memory/src/bpf_text.rs`), and the pkey
   restricts precisely the escape surface we care about — a rogue load/store
   reaching the cap table or kernel heap.
2. It is per-page, in the *shared* page tables, so no CR3 switch and no
   per-domain PML4 is needed (that is the AMD-PCID story, §7).

Today BPF is domain-blind: JIT text at shared slot 273 (`bpf_text.rs`), maps on
the global heap (`map.rs`), arena at shared slot 275 (`arena.rs`), zero coupling
to the domain machinery. A verifier escape is therefore a **full Ring-0
primitive**.

## 3. Threat model

- **In scope.** A verifier bug (a program that passes verification but performs
  an out-of-bounds or type-confused load/store) or a JIT-lowering bug. Today
  either is an arbitrary Ring-0 read/write. Goal: reduce its blast radius to the
  two domains the fence leaves open — **FRAME** (shared kernel infrastructure)
  and **`DOMAIN_BPF`** — so a store into any *other* subsystem's domain (the
  capability table in `CAPS`, the scheduler in `SCHED`, the driver domains)
  takes a protection-key `#PF`. A subsystem's state is protected exactly insofar
  as it lives in its own domain rather than in FRAME; the fence denies those
  domains, and that protection strengthens as subsystem memory-tagging lands.
- **Out of scope.** A bug in the *Frame* itself (kfunc shims, the run_atomic
  bracket, the domain manager). These are TCB and confinement cannot fence the
  fence. This is the same trust boundary drivers already sit behind.
- **Not a goal.** Confidentiality against a correct, verified program. A
  verified program is already confined by construction; the domain is insurance
  against the verifier being wrong.

## 4. Design

### 4.1 `DOMAIN_BPF` and the FRAME-stays-writable model

`DOMAIN_BPF` is a dedicated domain id (as built: `DomainId::BPF = 14`, taking the
former `DRIVER_5` slot — the 16-key budget was full).

**FRAME (domain 0) stays read-*write* during confinement, not read-only.** A
read-only FRAME was the first design and is wrong: the interpreter runs Rust in
domain 0 and writes its own call stack, the kfunc shims write kernel state, and
the `#PF` handler writes its stack — under a read-only FRAME the first of those
faults, and the fault handler faults trying to handle it, cascading to a triple
fault. So the fence is the framekernel's ordinary `enter_domain(FRAME, BPF)`:
allow FRAME + BPF, deny the other fourteen domains.

A consequence worth stating plainly: because FRAME stays writable, confinement
does **not** protect FRAME/domain-0 memory (the general kernel heap) from a wild
store — only the memory that other subsystems have tagged into *their own*
domains. That is the correct framekernel shape (protection is per-domain, not
per-privilege), and it means:

- BPF's own memory — interpreter stack, maps on the heap, arena frames (slot
  275), JIT text — can stay in FRAME and keep working with **no tagging
  required** for the core fence. (This is why wiring the fence was non-breaking:
  every page BPF touches today is FRAME.)
- The isolation the fence buys today is BPF-from-every-other-subsystem-domain.
  Optionally tagging BPF's private memory into `DOMAIN_BPF` is *hardening* (so a
  confined driver cannot read a map/arena either); it is not needed for the
  escape-containment property and is deferred.

### 4.2 The enter/exit seam is `run_atomic`

`BpfProg::run_atomic` (`prog.rs`) already brackets an IRQs-masked section — the
natural and only seam. Shape:

```
run_atomic(ctx, n):
    saved = pks::save()                       // one RDMSR
    pks::enter_domain(FRAME, DOMAIN_BPF)      // one WRMSR: allow 0 + BPF, deny rest
    outcome = <interpret or call JIT entry>
    pks::restore(saved)                       // one WRMSR
    return outcome
```

A kfunc that legitimately needs broader reach does **not** widen the program's
pkey; it is a call into FRAME-visible kernel code that already runs with full
rights. That is the framekernel pattern: cross-domain reach is a *mediated,
audited call*, never ambient access. If observability BPF ever lands, its
`probe_read` is exactly this — a Frame shim that reads with FRAME visibility and
copies into the program's (BPF-pkey) buffer.

### 4.3 Cost

Three MSR writes per program run (~tens of cycles each, no TLB effect), added to
a path that already does frame acquisition and an IRQ-mask bracket. Negligible
against a program run; measured, not assumed, before it lands.

## 5. The maps tension (the one real wrinkle)

Maps are a shared surface: userspace drives them through the element syscalls,
and native readers may consume them. If map bytes carry `DOMAIN_BPF`'s pkey:

- **Syscall element path** — runs in FRAME (domain 0), which reads every pkey.
  Fine.
- **A native consumer in another *driver* domain** reading a map directly —
  this is the only genuinely broken case. Options: (a) put such maps in a
  shared-read pkey, (b) route the read through a Frame-mediated copy, (c) accept
  that cross-domain map sharing requires an explicit grant. Rare in practice;
  resolved per-map, documented, not blanket.

The percpu maps we just landed are the easy case: the BPF program writes its own
CPU's slot from inside `DOMAIN_BPF`, and the syscall aggregation view reads all
slots from FRAME.

## 6. Answering the visibility question directly

The two BPF roles split cleanly on address-space visibility:

- **Policy / struct_ops** (idle governor, sched, congestion, io-sched, pager —
  the `CapKind`s `structops.rs` already enumerates). These take everything by
  typed value through the ctx tuple and return a scalar. They need **zero**
  address-space visibility, so confinement costs them nothing. This is the
  bulk of what NARF BPF is *for*.
- **Observability** (Linux tracing + `probe_read`). This is the role that would
  lose visibility — and NARF does not have it. If it is ever added, the correct
  framekernel shape is a Frame-mediated `probe_read` kfunc (§4.2, fully
  specified in §7), which is strictly better than ambient reads:
  capability-checked and auditable.

So the loss the confinement implies is real but narrow, and it lands entirely on
a use case NARF has deliberately not built.

## 7. Program tiers, tracing reads, and BTF

Two ways to give tracing the visibility that policy/struct_ops does not need
were considered. This section records the resolution, because the tempting
version is unsound in a way worth pinning before anyone builds it.

### 7.1 Rejected: two program-trust tiers

A "global (unconfined) tracing type" beside a "frame-confined struct_ops type"
was considered and **rejected**. It is structurally Linux's privileged /
unprivileged split — which `spec.md` §4.10 kills ("there is no unprivileged mode
and no second set of limits") and §1 lists out of scope *permanently*. Worse, it
places the tier running the most attacker-authored code (tracing) in the
*least*-isolated placement, reintroducing the exact "verifier escape = full
Ring-0 primitive" defect this note exists to close.

### 7.2 The tier is a kfunc capability, not a domain

All BPF runs in the one `DOMAIN_BPF`. "Tracing" vs "policy" is **which kfuncs a
program may call**: a tracing program is granted the capability that admits
`narf_probe_read`; a struct_ops program is not. A visibility difference expressed
as an allow-list entry, not a trust or address-space difference — matching how
NARF already gates everything (capabilities + the closed, audited kfunc list).
One confinement model, one trust tier.

### 7.3 Reads are mediated, and only off trusted pointers

There is a confinement asymmetry to state plainly: FRAME (domain 0) stays fully
**read-write** during confinement (§4.1) — the interpreter's stack, the kfunc
shims, and the `#PF` handler all need it. So the fence stops escaped *reads and
writes* into *other subsystems'* domains, but neither a read nor a write into
FRAME/domain-0 memory itself. A read of core-kernel state (the info-leak class)
is therefore closed by *mediation plus the verifier*, not by the domain tag.
Concretely:

- `narf_probe_read(dst, len, src: TraceSource, offset)` runs its mediated copy
  in the FRAME shim (full visibility) into a verifier-bounded program buffer.
  `TraceSource` is a wildcard only at the kfunc signature: the program carries
  one concrete Rust-native object schema, and both the verifier and live wrapper
  require an exact declared `(offset, len)`. The shim holds the visibility; the
  program never does, so a verifier escape in a tracing program stays contained.
- The source **must be a verifier-tracked pointer** (`Trusted`/`Owned`/`Object`)
  obtained from ctx or an acquiring kfunc — never a raw scalar. This is enforced
  *for free* by the existing kfunc argument typing (`ArgDesc`), which already
  rejects a scalar where a pointer class is required, rejects direct `Object`
  deref (`OpaqueDeref`, `verifier/src/fixpoint.rs:931`), and kills a dead-
  validity handle at an await point (`spec.md` §4.4). This closes *"read
  arbitrary address."*
- The shim **clamps** `offset + len` against the pointer's size, closing *"read
  past the object"* — a runtime bound a verifier bug cannot bypass. An opaque
  `Object` of unknown size cannot be clamped; that is precisely the case that
  needs a size-carrying descriptor (§7.4).

### 7.4 On BTF: not needed; typed access is a Rust-native extension

NARF was built to *not* need BTF, so "implement BTF first" would mostly mean
building a second, parallel type system beside the one already in use. BTF's jobs
map onto NARF as:

- **kfunc argument typing** and **struct_ops matching** — already done
  Rust-natively (`BpfType`, `kfunc!`, `struct_ops!`/`StructOpsDesc`); Linux's
  BTF `btf_id` matching has no analogue here because the descriptor comes from
  the Rust signature;
- **CO-RE relocation** — out of scope (`spec.md` §1, a userspace concern);
- **typed ctx/object field access** — the *only* open job, and it is served by
  extending the existing Rust-native descriptors (`BpfType`, the `Object` class),
  not by importing Linux BTF. Importing BTF would duplicate the kfunc/struct_ops
  type machinery for the overlap and drag in the rejected CO-RE.

Sequencing, with the security reason for it: mediated `narf_probe_read` (bytes
off a schema-tracked handle, §7.3) **precedes** typed direct access. The
mediated slice has now landed; typed direct access remains deferred. Direct access
puts *all* read-safety in the verifier — a single point of failure a verifier
bug defeats, and (per §7.3) confinement does not catch a domain-0 read. The
mediated shim re-checks bounds at runtime, so a verifier bug does not bypass it.
Typed direct access is the speed / ergonomics play; mediation is the
defense-in-depth play, and it wins on the "a verifier bug is a primitive"
priority this whole note is organized around.

## 8. Scope / non-goals

- **PKS / Intel SPR+ only**, first cut. Enforcement is already live there.
- **AMD PCID deferred.** PCID isolates spatially via per-domain PML4s, not
  per-page pkeys, so "BPF in a domain" there means giving BPF a private VA range
  and a CR3 switch on entry (~50–100 cyc) — a larger change. The confinement
  *policy* (§3) is identical; only the mechanism differs.
- **aarch64 MTE deferred.** `enter_domain`/`exit_domain` are structural saves
  today; real tag-fault enforcement is a Stage-3 allocator task
  (`arch/src/aarch64/mte.rs`).
- Not changing the verifier, the kfunc surface, or the map ABI. This is a
  containment layer *under* them.

## 9. First milestone

The BPF idle governor is the ideal first consumer *because* it is pure policy
(§6): `power::IdleGovernor::select_idle_state` takes `latency_budget_us` /
`predicted_idle_us` by value and returns a `CStateIdx` — no visibility needed.
It is also the reference struct_ops consumer the `struct_ops!` macro was written
for (`structops.rs` `#[commit(...)]` → `power::install_idle_governor`,
`power/src/lib.rs:779`).

Milestone: a BPF program installed as the idle governor via struct_ops, whose
`run_atomic` is the first call site to enter `DOMAIN_BPF`, plus a **negative
test** proving a deliberately-wild store from that program faults into the PKS
handler (PK-fault signature) instead of reaching FRAME memory — the hardware
analogue of `smoke_bpf_interp_wild_load_traps_not_faults`, and the proof that
the fence is load-bearing.

## 10. Open questions

1. **One BPF domain or per-program?** One `DOMAIN_BPF` contains escapes to "the
   BPF world" (all maps/arenas of all programs). Per-program pkeys would contain
   a program to *its own* memory but exhaust the 16-domain budget fast and
   collide with driver domains. Start with one; revisit if BPF programs need
   isolation from *each other*.
2. **JIT text writable-alias tagging** interacts with `text_poke`
   (`bpf_text.rs`) — the poke window runs in FRAME, so it is unaffected, but
   confirm the sealed RX mapping and the writable alias can carry different
   pkeys without a second mapping.
3. **Measure the three-MSR cost** against `run_atomic` on a hot struct_ops path
   (the idle governor fires from the scheduler idle loop) before committing.
4. **Cross-domain map sharing** (§5) — is a shared-read pkey worth a permanent
   slot, or is Frame-mediated copy always acceptable?

## 11. As built

The struct_ops consumer and the confinement fence have both landed on PKS.

- **Domain.** `DomainId::BPF = 14` (`lib/src/id.rs`), taking the former
  `DRIVER_5` slot; the dedicated-driver pool is now `DRIVER_0..=DRIVER_4` (cap 5).
- **Fence.** `bpf/src/domain.rs`: `enter() -> Confined` calls
  `pks::enter_domain(FRAME, BPF)` when the PKS backend is live and restores on
  `Drop`; a no-op on AMD PCID / aarch64 MTE (deferred, §8). `BpfProg::run_atomic`
  holds the guard across the whole run, so **both** the interpreter and the JIT
  path are confined — feasible precisely because FRAME stays rw (§4.1).
- **Non-breaking.** Every page BPF touches today is FRAME (arena/text are mapped
  with no `pk()`), so no memory-tagging was needed and all runtime smokes pass
  with the fence live under real PKS.
- **Proof.** `smoke_bpf_domain_confines_cross_domain_writes` (`bpf`, x86_64):
  under `crate::domain::enter()`, a store into a `SCHED`-tagged page takes a
  PK-`#PF` (vector 14, error-code bit 5) while a store into a `BPF`-tagged page
  succeeds — the fence is load-bearing. Runs under QEMU (PKS exposed), skips
  where PKS is absent.
- **Typed tracing mediation.** `TypedProbe` schemas feed the verifier's
  `ObjectDesc`; a distinct `TraceObject` provenance prevents ordinary kernel
  object pointers from satisfying `narf_probe_read`, which admits only exact
  declared fields and whose live `TypedProbeRef` repeats the check. Kfuncs
  cannot return `TraceObject`. Typed programs are atomic-only and cannot use
  either public raw-context execution entry point. Direct object loads remain
  opaque.

Deferred from here: kfunc-shim behaviour is already correct (shims run in FRAME,
which stays rw), so the "no-kfunc only" restriction §7 anticipated proved
unnecessary. Remaining: subsystem memory-tagging (which turns the fence from
"isolates BPF from other domains" into "protects the cap table", once
`capabilities/` tags its table into `CAPS`), optional BPF-private-memory tagging
into `DOMAIN_BPF` (hardening), and the AMD PCID / aarch64 MTE backends.
