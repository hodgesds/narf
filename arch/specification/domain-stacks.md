# domain-stacks — scoping per-domain stacks for driver domains

> Status: **scoping only**, revision 2. Nothing here is implemented.
>
> Revision 1 of this document led with a claimed prerequisite — that domain
> state leaks across preemption — which was **wrong**. The correction is
> below, kept rather than deleted, because the way it was wrong is the
> more useful lesson.

## Correction: domain state does not leak across a context switch

Revision 1 said `modules::domain::enter` takes no `PreemptGuard` and "no
scheduler code saves or restores `IA32_PKRS` or `SCTLR_EL1.TCF` across a
context switch", then spent a section weighing two fixes for a bug that
does not exist.

Both architectures have carried this state all along:

  * x86_64 `KernelContext` holds `domain_state` at offset 72 (PKRS or
    CR3) plus a `domain_kind` discriminant, and `kernel_switch` saves and
    restores it.
  * aarch64 `KernelContext` holds `domain_active`, `domain_sctlr` and
    `domain_gcr`, and the switch does `mrs x9, sctlr_el1` /
    `msr sctlr_el1, x11` around the swap.
  * `smoke_stackful_switch_preserves_domain_state` already asserts a
    cooperative switch carries domain state with the task while restoring
    the executor's neutral state.

The first clause was true — `modules::domain::enter` really does not hold
a `PreemptGuard` where `bpf::domain::enter` does — but it is not a bug on
its own, because the switch preserves what a preempted scope was holding.

**How the error happened.** The check was
`grep -rn "PKRS|pkrs|SCTLR_EL1|sctlr" --include=*.rs sched/src/ 2>/dev/null`.
The crate is `scheduler/`, not `sched/`. The path did not exist, `2>/dev/null`
swallowed the error, and an empty result was read as "nothing saves it".
A search that cannot distinguish "found nothing" from "looked nowhere" is
not evidence, and suppressing stderr is what removed the distinction.

## What *was* broken

One thing, and it was introduced by the commit that made
`current_domain()` real rather than being longstanding: `CURRENT_DOMAIN`,
the per-CPU byte that hook reads, is not in either `KernelContext`. It was
the one piece of domain state a switch dropped.

Silent when wrong, which is the worst property to have here. Nothing
faults; instead `domain_heap::alloc` picks the wrong window for the next
task's allocation, and `block::encrypted`'s constructor assertion reads a
domain that is not its own and passes.

Fixed by carrying the byte with the task, the way the hardware state
already rides in `ctx` — restored before the switch, re-captured after.
Both a voluntary yield and an involuntary preemption resume at the same
point in `poll_to_yield`, so one capture covers both. Asserted by
`smoke_domain_byte_follows_the_task_across_a_yield`, which checks both
halves: the task must resume holding the domain it yielded with, and must
not leave it behind for the caller.

## What a per-domain stack would take

Unblocked — there is no prerequisite here, contrary to revision 1. The
goal is that module code cannot read another domain's stale stack frames,
by running on a stack in the domain's own protected region.

**Allocation and switch.** A stack per domain in the `domain_heap` region,
with `domain::enter` switching `SP` and `exit` restoring it. On aarch64
the `SP` must carry the domain's tag or every push faults once TCF is
Sync; a tagged `SP` translates correctly because `TCR_EL1.TBI1` is set.

**Exception entry lands on it.** On x86 only NMI, `#DF` and `#MC` have
their own IST stacks (`idt.rs`); an ordinary IRQ or `#PF` taken at CPL0
pushes onto the interrupted task's stack, which would be the domain stack.
That works while the scope is open, since PKRS permits the key, but it
means kernel exception frames would sit in domain-owned memory. On aarch64
the handler pushes in software through `SP`, so a tagged `SP` keeps those
stores matched.

**Overflow needs a guard page and somewhere to land.** Without a guard,
overflow corrupts whatever follows in the region. With one, overflow
faults — and the handler needs a stack that is not the one that just
overflowed. x86 can use an IST entry; aarch64 has no overflow stack today.

**Attribution breaks quietly.** Backtraces walk the stack and attribute
addresses to modules; a tagged `SP` and a stack outside the usual range
will not be recognised without the untagging `is_module_va` already needed.
The failure is a truncated or misattributed trace, not a crash.

## Whether it is worth doing

Unclear, and worth deciding before building — this part of revision 1
stands.

The gain is narrow. A module's *live* frames are already unreachable in
practice: another domain would have to derive a pointer into a stack
region it never sees. The concrete win is against *stale* frames — data
left on the shared kernel stack by domain A and read later by domain B.
Real, and the same class of leak the kernel has anywhere it reuses stack
memory without scrubbing.

The cost lands in the most delicate paths in the tree: exception entry,
stack overflow, unwinding. A cheaper mitigation for the same leak is
scrubbing the used extent of the stack on scope exit — no SP switch, no
guard page, no overflow stack, and a cost proportional to how much stack
the module actually touched.

Recommended: measure scrub-on-exit before committing to per-domain stacks.
