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

## Scrub-on-exit: measured

`smoke_measure_stack_scrub_cost` times `write_bytes` over the sizes a scrub
would cover, median of 65 runs after a warm pass.

| bytes | aarch64 ticks | x86_64 cycles |
|---|---|---|
| 512 | 184 | 216 |
| 1024 | 276 | 798 |
| 2048 | 469 | 930 |
| 4096 | 850 | 1184 |
| 8192 | 1751 | 2912 |
| 16384 | 3141 | 5910 |
| 32768 | 6164 | 12418 |

aarch64's `CNTFRQ_EL0` reads 1 GHz, so those ticks are nanoseconds: a full
32 KiB stack costs about **6 µs**. The x86 column is raw TSC with no
frequency anchor.

**Read these as shape, not as hardware.** Both runs are QEMU TCG, which
emulates rather than executes, and a `memset` under TCG has no particular
relationship to one on silicon. What survives the caveat is that cost is
roughly linear in bytes with no cliff, which is the only property the
decision below depends on.

## The decision, split by site

The question "is scrub-on-exit cheap enough" has two answers, because the
two scope sites differ by orders of magnitude in how often they run.

**Module scopes: yes, comfortably.** `modules::domain::enter` is called
from exactly two places, both in `loader.rs` — around a module's `init()`
and its `exit()`. That is twice per module *lifetime*. Even scrubbing an
entire 32 KiB stack at both ends adds ~12 µs to a module load, against
work that already includes ELF parsing, relocation, mapping and sealing.
It does not need depth tracking either: scrubbing everything *below* the
current `SP` is safe, since that memory is dead by definition, and it is
exactly where the stale frames are.

**BPF scopes: no.** `bpf::domain::enter` wraps every program run, four
sites in `prog.rs`. A scrub of even 4 KiB is ~850 ns on the aarch64
figures — the same order as a whole program invocation. That is not a
tax on the hot path, it *is* the hot path.

So the recommendation is asymmetric, which the original framing did not
anticipate:

  * Adopt scrub-on-exit for **module** domain scopes. Cheap, needs no SP
    switch, no guard page, no overflow stack, and no change to exception
    entry or unwinding.
  * Do **not** scrub on BPF scope exit. If stale BPF frames matter, the
    options are per-domain stacks or nothing — and per-domain stacks cost
    a stack switch per program run, which is its own hot-path problem.

Per-domain stacks therefore remain unbuilt and, for the module case,
unnecessary. Whether BPF stale frames are worth anything at all is the
open question, and it is a threat-model question rather than a
measurement one.

## Scrub-on-exit: implemented, and reverted

Built, and backed out. It works on aarch64 and faults on x86, and the
reasons are worth recording because most of them are traps rather than
bugs.

`smoke_module_scope_scrubs_dead_stack_on_exit` passed on aarch64 — the
planted pattern in dead stack was gone after a scope closed. The same code
on x86 took a `#PF` with `rip = 0x0`: control transferred to null, meaning
a live return address had been zeroed. A scrub that corrupts the stack is
strictly worse than the leak it closes, so the implementation is out and
only the supporting pieces are kept.

### What to check before the next attempt

**`&0u8 as *const u8` is not a stack address.** Rust const-promotes the
literal to a `'static`, so it yields `.rodata` in the kernel image. Three
rounds of this work computed a scrub extent from that address and drew
conclusions from comparing it against real stack bounds — first "the
aarch64 scheduler reports the wrong stack", then "async locals live on the
heap", both wrong. The giveaway was the address being byte-identical
across two rewrites that should have moved it. Read `RSP`/`SP` with `asm!`
and nothing else.

**A containment check is load-bearing, not defensive.** Requiring the live
SP to lie inside the stack `current_stack_range()` reports is what turned
the `.rodata` extent into a decline instead of an 8 KiB write into the
kernel image. Any future version needs it from the first commit.

**x86 is the harder target and the failure is not yet understood.** The
fault shows the scrub reaching memory that was live. Candidates not ruled
out: the red zone (data below `RSP` is live if the target does not build
with `-mno-red-zone`), and the scrub running at a shallower `RSP` than the
frames it is trying to erase, so that "below SP" at scrub time still
contains a caller's frame. Establish which before writing any of it again.

**The measurement still stands.** Module scopes run twice per module
lifetime, so a scrub there is affordable; BPF scopes wrap every program
run, where it is not. That conclusion did not depend on the
implementation.

### Kept from the attempt

  * `scheduler::stackful::current_stack_range()` — the current task's stack
    bounds, needed by anything writing into the dead part of a stack.
  * `scheduler::stackful::run_on_stackful_task()` — drives a future to
    completion on a real `KernelTask`. `block_on` polls inline on the
    caller's stack, where there is no task stack at all; a test that needs
    one and reaches for `block_on` silently tests nothing.
