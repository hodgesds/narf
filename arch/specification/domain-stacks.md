# domain-stacks — scoping per-domain stacks for driver domains

> Status: **scoping only**. Nothing here is implemented. The headline is a
> bug found while scoping, which is a prerequisite for this work and is
> also live today.

## The blocker, and it is not about stacks

**Domain state leaks across preemption.**

`bpf::domain::enter` takes a `narf_scheduler::PreemptGuard`.
`modules::domain::enter` does not, nothing disables preemption around
`loader::invoke_init`, and no scheduler code saves or restores `IA32_PKRS`
(x86) or `SCTLR_EL1.TCF` (aarch64) across a context switch. Those are
per-CPU registers, so if a module's `init()` or `exit()` is preempted mid
scope, **the next task on that CPU inherits the narrowed domain state**.

This was close to harmless until recently, which is why it survived:

  * On aarch64 `Mte::enter_domain` was a structural no-op, so there was no
    TCF to leak.
  * On x86 the only keyed pages were module images, which few tasks touch.

Both halves of that changed. Module images and the per-domain heap now
carry `pk(D)` on x86, and TCF really flips to Sync on aarch64. A leaked
scope now means an unrelated task running with fifteen keys denied, or
with tag checking on against pages whose tags it does not carry. On
aarch64 the failure is a synchronous tag check fault in code with no
exception-table entry — fatal, and attributed to whatever ran next rather
than to the module that leaked it.

### Two fixes, and they are not equivalent

**A `PreemptGuard` around module entry**, mirroring `bpf::domain`. One
line, and wrong in general: a BPF program is bounded and non-blocking, but
module `init()` is arbitrary code that may legitimately allocate, wait, or
otherwise sleep. Holding preemption across it converts a latency problem
into a deadlock. Acceptable as a stopgap, not as the answer.

**Per-task domain state, saved and restored by the context switch.** The
correct fix: treat `PKRS`/`TCF` as task state rather than CPU state, so a
switch out of a scoped task restores the incoming task's own view. More
invasive — it touches the task structure and both switch paths — and it is
the prerequisite for everything below, because a per-domain *stack* makes
a leaked scope worse rather than better.

Recommendation: fix the leak before any stack work, and treat the
`PreemptGuard` as a stopgap only if the leak needs closing sooner than the
scheduler change can land.

## What a per-domain stack would take

The goal is that module code cannot read another domain's stale stack
frames, by running on a stack in the domain's own protected region.

**Allocation and switch.** A stack per domain in the `domain_heap` region,
with `domain::enter` switching `SP` and `exit` restoring it. On aarch64
the `SP` must carry the domain's tag, or every push faults once TCF is
Sync; a tagged `SP` is fine for translation because `TCR_EL1.TBI1` is set.

**Exception entry lands on it.** On x86 only NMI, `#DF` and `#MC` have
their own IST stacks (`idt.rs`); an ordinary IRQ or `#PF` taken at CPL0
pushes onto the interrupted task's stack — which would be the domain
stack. That is fine while the scope is open, since PKRS permits the key,
but it means exception frames for kernel faults would sit in domain-owned
memory. On aarch64 the handler pushes in software through `SP`, so a
tagged `SP` keeps those stores matched.

**Overflow needs a guard page and somewhere to land.** A stack with no
guard corrupts whatever follows it in the region. With a guard, overflow
faults — and the fault handler needs a stack that is not the one that just
overflowed. x86 can use an IST entry; aarch64 needs an explicit overflow
stack, which it does not currently have.

**Attribution breaks quietly.** Backtraces walk the stack and attribute
addresses to modules; a tagged `SP` and a stack outside the usual range
will not be recognised without the same untagging `is_module_va` needed.
The failure mode is a silently truncated or misattributed trace, not a
crash.

## Whether it is worth doing

Honestly: unclear, and worth deciding before building.

What it buys is narrow. A module's *live* frames are already unreachable
in practice — another domain would have to derive a pointer into a stack
region it never sees. The concrete gain is against *stale* frames: data
left on the shared kernel stack by domain A and read later by domain B.
That is a real information leak, and it is the same class of leak the
kernel has anywhere it reuses stack memory without scrubbing.

The cost is high and lands in the most delicate paths in the tree —
exception entry, stack overflow, unwinding. A cheaper mitigation for the
same leak is scrubbing the used extent of the stack on scope exit, which
needs no SP switch, no guard page and no overflow stack, and whose cost is
proportional to how much stack the module actually touched.

Recommended order: fix the preemption leak; then, if stale-frame leakage
still matters, measure scrub-on-exit before committing to per-domain
stacks.
