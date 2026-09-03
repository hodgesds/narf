# Preemptive Scheduling — Implementation Contract

> Status: **implemented for stackful kernel tasks and own-stack user
> continuations on x86_64 and aarch64.** Audited arbitrary-kernel-mode user
> continuation preemption remains incomplete.

## 1. Purpose

The cooperative executor cannot recover when a future busy-loops inside
`poll()`. NARF therefore provides an own-stack execution mode whose live
continuation can be switched back to the executor from the timer trap. The
same tick enforces time slices and core-owned periodic CPU budgets.

Scheduling policy is deliberately outside this mechanism. A policy chooses an
opaque task handle from read-only metadata; it cannot access stacks, trap
frames, saved domain rights, executor contexts, or switch functions.

## 2. Execution modes

| Work | Spawn path | Timer-preemptible today |
|---|---|---|
| Stackless async task | `spawn`, `spawn_with_spec` | No; cooperative poll boundary only |
| Stackful kernel thread | `spawn_stackful*` | x86_64 CPL0 / aarch64 EL1, unless `no_preempt` |
| Own-stack user thread | `spawn_user` | x86_64 CPL3 / aarch64 EL0 |
| User thread in syscall | `spawn_user` | No arbitrary CPL0/EL1 preemption yet |
| Hard IRQ/NMI | interrupt entry | Not schedulable work |
| Deferred IRQ work | task with `WorkKind::SoftIrq` | According to its execution mode |

`spawn_stackful_with_spec` is the public bridge for kernel/realtime threads
that need both policy metadata and preemption options. The `StackfulAdapter`
and `KernelTask` bodies remain private.

## 3. Own-stack switch path

Each `KernelTask` owns a stable kernel stack and `KernelContext`. The executor
polls its `StackfulAdapter`, which publishes the task in a per-CPU
`CURRENT_STACKFUL_TASK` slot and calls `kernel_switch` into that stack.

On a scheduler-timer trap:

1. The trap prologue has already saved the interrupted register frame on the
   current task's own kernel stack and entered the Frame domain.
2. The architecture preemption hook validates that the frame lies inside the
   current task's stack and that the interrupted exception level is eligible.
3. The hook checks the time slice and the core-published periodic-budget
   boundaries.
4. If a switch is required, it re-arms the task waker, records an involuntary
   return for RCU, saves live user FPU/SIMD state when applicable, clears the
   per-CPU current pointer, and calls
   `kernel_switch(&mut task.ctx, executor_ctx)` directly from the trap handler
   with interrupts disabled.
5. The executor accounts the elapsed on-CPU interval and dispatches another
   eligible slot.
6. A later `kernel_switch` resumes inside the suspended trap handler. The task
   republishes itself, restores address-space and TLS state, and returns
   through the untouched common-trap frame to the interrupted instruction.
   AArch64 also restores FPSIMD eagerly. On x86_64, resume instead arms CR0.TS;
   the first user FP/SIMD instruction raises `#NM`, restores the image, and
   retries without advancing the user instruction pointer.

The retired `preempt_yield_stub`/IRET-rewrite design is not used.

## 4. Tick decision

The timer hook evaluates two independent boundaries:

- `slice_end = task_start + StackfulOptions::slice_cycles`;
- periodic budget soft/hard ends published by the core before entering the
  task.

The decision is:

```text
hard budget end reached                 -> switch
soft budget end reached + competitor    -> switch
soft budget end reached + no competitor -> mark borrowing; resume same task
slice expired + competitor              -> switch
slice expired + no competitor           -> resume same task
otherwise                               -> resume same task
```

This avoids an executor/idle/task round trip when the current task is the only
useful work. A wake makes an idle borrower preemptible at the next tick. The
architecture clockevent is armed no later than the next soft budget or period
boundary so a long slice cannot hide a shorter budget.

`has_other_runnable_work` considers deferred wakes, due timer-wheel work, and
other queue slots whose core-computed budget state is `Eligible` or
`Borrowable`. Strictly throttled work does not force a pointless switch.

## 5. Period budgets

`PeriodBudget` is mechanism-owned input:

```rust
pub struct PeriodBudget {
    pub runtime_cycles: u64,
    pub period_cycles: u64,
    pub max_borrow_cycles: u64,
    pub exhaustion: ExhaustionPolicy, // Strict | IdleBorrow
}
```

At dispatch, the executor applies any due replenishment and publishes a
read-only `BudgetView`. Runtime is charged after every poll/switch-back.
Cooperative or temporarily non-preemptible overshoot is retained as debt;
future replenishments repay that debt rather than minting replacement CPU
time.

- `Strict`: zero remaining runtime is ineligible until replenishment, even if
  the CPU would idle.
- `IdleBorrow`: after ordinary runtime is exhausted, bounded idle capacity may
  be consumed only when no regular candidate is eligible. Borrowed capacity is
  debt against future replenishment.

When all local slots are parked or throttled, the CPU may still steal eligible
remote work. If none exists, it arms the earliest budget replenishment along
with timer-wheel deadlines and enters the normal race-free idle path.

Policy receives `BudgetView { eligibility, remaining_cycles,
replenish_at_cycles, borrowed_cycles, debt_cycles }`, but cannot replenish,
charge, forgive debt, or make a throttled slot dispatchable. Core validation
overrides stale, invalid, or wrong-eligibility policy choices.

The optional policy CPU-state callback observes `Active`/`Idle` execution edges
and logical hot-plug states. It does not control halt, clockevents, or DVFS.
Frequency selection remains a separate capability-gated `power/` decision fed
by scheduler demand observations.

Replacing policy does not touch the live continuation or its budget window.
The core drains the old per-CPU policy callback, publishes a fully installed
new policy on that CPU, and preserves all task/mechanism state across the
rolling generation-ordered cutover.

## 6. Safety boundaries

- Run-queue locks are released before entering a task.
- A policy callback receives no mutable queue or execution state.
- A preemption return is not an RCU quiescent state.
- User FPU/SIMD, address-space, TLS, trap continuation, and task stack remain
  paired across preemption and migration. X86 saves every live FP/SIMD image
  before migration and permits deferred restore only while the task-owned
  memory image is current; AArch64 captures live `TPIDR_EL0` at switch-out
  because EL0 may write it directly.
- Budget state is stored with the task slot and therefore follows migration.
- Invalid period contracts are rejected before a slot is published.
- Realtime class metadata is demoted on generic spawn paths. Only
  `spawn_realtime*` can attach a live reservation, after atomically checking
  per-CPU, system, and capability-domain ceilings.
- `preempt_disable()` is nestable and CPU-local; its guard is `!Send`.
- Hard-IRQ residency is accumulated outside task runtime and subtracted from
  poll budget charging. Deferred `SoftIrq` work remains a normal task.
- Budget-cap revocation is checked by the core; maintenance pops keep
  revocation observable even if every task is parked or throttled.

The load-bearing involuntary domain-state requirement is closed on x86_64 and
aarch64. Common trap/vector entry captures rights in the architecture-owned
trap frame and enters neutral Frame state before Rust. Fast x86_64 `SYSCALL`
does the same. `kernel_switch` owns the stackful boundary: with interrupts
masked, it captures live PKRS/CR3 or SCTLR/GCR before its first outgoing-context
store, and restores the incoming snapshot after its final context load. A task
preempted inside a trap resumes the neutral trap continuation first; the trap
epilogue restores the interrupted rights immediately before IRET/ERET. Policy
code receives none of this state.

## 7. Remaining gates

- Audit kernel-mode user/syscall critical regions and adopt the nestable
  `preempt_disable()` guard before changing their conservative opt-out.
- Wire the public NMI accounting guard into each architecture's NMI/FIQ entry;
  hard-IRQ entry/exit is live on both architectures.
- Reconcile direct time-slice donation with periodic runtime transfer. Current
  period eligibility remains authoritative and donation cannot bypass it.
- Add a real MTE-tag-aware allocator on aarch64; switch/vector mechanics
  preserve SCTLR/GCR today, while enforcement remains structural.

## 8. Validation

Required gates for changes to this mechanism:

- budget-account tests for strict replenishment, idle borrowing, debt
  repayment, and non-preemptible overshoot;
- policy tests proving strict class order and core fallback when a policy
  declines work, plus edge-triggered CPU Active/Idle notifications;
- external-crate compile proof in `scheduler/policy-example`;
- x86_64 and aarch64 scheduler subsystem QEMU suites;
- x86_64 and aarch64 busy-loop preemption and own-stack
  trap-frame/FPU-or-SIMD/TLS/RCU smokes;
- TCB safety argument and two-maintainer review including security review.
