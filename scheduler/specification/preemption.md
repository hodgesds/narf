# Preemptive Scheduling — Design

Status: design-phase. Driven by real-HW bring-up wedge where a
cooperative-async kernel task busy-looped inside `poll()` on
Phoenix silicon, blocking `run_until_empty` from ever reaching
the queued userspace init/shell tasks.

## Problem statement

The current `narf-scheduler::run_until_empty` is a pure
cooperative executor:

```rust
loop {
    for slot in ready_queue {
        let poll = slot.task.poll(&mut ctx);
        match poll { Pending => requeue, Ready => drop }
    }
    if ready_this_round == 0 { halt_until_irq(); }
}
```

Failure modes on real silicon:

1. **Busy-loop in `poll()`**: a spawned future has `loop { do_io() }` without `.await`. The poll never returns. The
   executor is stuck on that one task forever; init/shell are queued behind it but never picked.
2. **All-pending + IRQ silence**: if HPET/LAPIC timer IRQs don't deliver on real silicon, `sleep_cycles(N).await`
   never wakes. Every periodic-poll task stays `Pending`. The executor halts on `halt_until_irq` waiting for an
   IRQ that never comes.

(2) is mitigated by switching `sleep_cycles` to a TSC-deadline self-poll fallback (separate change). (1) requires
real preemption.

## Design goals

- **Survive busy-loop in `poll()`** — a wedged task must not prevent other tasks from running.
- **No regression for well-behaved cooperative tasks** — existing async fns that yield correctly should still work.
- **Minimal API change** — `narf_scheduler::spawn(future)` stays the same shape; preemption is internal.
- **Multi-core ready** — design should extend cleanly when SMP scheduling lands beyond BSP-only.

## Approach: stackful kernel tasks + timer-driven preemption

### Layer 1 — Per-task kernel stack

Each spawned kernel task gets its own kernel stack (default 16 KiB, configurable via `TaskSpec`). When the
executor "picks" the task it switches stacks; the future runs on its own stack. When the future returns
(`Ready` or `Pending`), the task-side code switches back to the executor's stack.

Backing the future on a dedicated stack means the task's RIP can be anywhere when an IRQ fires — its
register file + stack pointer can be saved into a TCB without unwinding the future's stackless state.

### Layer 2 — Kernel context-switch primitive

```rust
#[repr(C, align(16))]
pub struct KernelContext {
    // Callee-saved GPRs (SysV-AMD64) + rsp + rip.
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rsp: u64,
    pub rip: u64,
}

/// Save the current GPRs into `*out`, restore from `*in`. The
/// "return" from this fn is on the in-context's stack; the
/// out-context's caller resumes when something switches back.
pub unsafe extern "C" fn kernel_switch(
    out: *mut KernelContext,
    in_: *const KernelContext,
);
```

Shape mirrors existing `setjmp`/`longjmp` but takes both halves explicitly so the executor can do a true swap
in one operation (no `if (setjmp(...))` pattern).

### Layer 3 — Executor restructured around `kernel_switch`

`run_until_empty`'s inner loop becomes:

```rust
for task in ready_queue {
    EXECUTOR_CONTEXT.lock().save_into(&mut executor_ctx);
    CURRENT_TASK.store(task.id);
    unsafe { kernel_switch(&mut executor_ctx, &task.ctx) };
    // ← We return here when the task yields back. CURRENT_TASK
    // has been cleared by the task-side yield path.
    handle_task_outcome(task);
}
```

Task-side `yield_to_executor()`:

```rust
fn yield_to_executor() {
    let mut my_ctx = KernelContext::zeroed();
    unsafe { kernel_switch(&mut my_ctx, &EXECUTOR_CONTEXT) };
    // Returns here when the executor switches back into us.
}
```

The future's `poll()` runs inside the task's stack. When `.await` returns `Pending`, the task wrapper calls
`yield_to_executor()` before truly being suspended (the waker mechanism still works for cross-task signaling;
yield is what actually puts the executor back in charge).

### Layer 4 — Timer-driven preemption

The LAPIC timer ISR detects a long-running task and force-yields. The ISR is what actually preempts a
busy-loop:

```asm
; ISR entry — trap frame already on the task's stack
push gprs
mov rdi, &CURRENT_TASK.ctx           ; out: task ctx
mov rsi, &EXECUTOR_CONTEXT           ; in:  executor ctx
call kernel_switch                    ; saves task state, restores executor
; we don't return; the executor "returns from" its kernel_switch on its stack
```

The task's RIP/RSP from the interrupted state get saved into its `KernelContext`. When the executor later
reschedules the task, `kernel_switch` restores those — the task resumes execution at the exact instruction
the timer IRQ interrupted.

Preemption budget: TSC-deadline per task (default 10 ms slice). Stored on the task TCB; checked in the timer
ISR. If exceeded, force-yield.

## Implementation phases

### Phase 1 — Per-task kernel stack + cooperative switch

- New crate `narf-task` (or extension of `narf-scheduler`):
  - `KernelTaskStack` — `Box<[u8; 16384]>` with guard-page hooks.
  - `KernelContext` — repr-C, 8 u64 layout above.
  - `kernel_switch` — naked asm.
- `narf_scheduler::spawn` allocates a stack + initial context (rip = task entry trampoline, rsp = top of new stack).
- Task entry trampoline: calls `future.poll(cx)` on the new stack, returns its result via `yield_to_executor`.
- Executor restructured: `kernel_switch` instead of `task.poll()` directly.
- No preemption yet — tasks still need to yield voluntarily. But the layout for phase 2 is in place.

Validates: existing well-behaved tasks still run end-to-end; a deliberately misbehaving task ("infinite loop in
poll") still wedges (we verify that and ship phase 2 to fix).

### Phase 2 — Timer-driven preemption

- LAPIC timer ISR extended:
  - Save trap-frame GPRs into `CURRENT_TASK.ctx`.
  - Set `CURRENT_TASK.preempted = true`.
  - Tail-call to executor's resume point via `kernel_switch`.
- Per-task `TSC_deadline` checked at ISR entry.
- The executor's `kernel_switch` resumption point distinguishes "task yielded voluntarily" from "task was
  preempted" so it can re-queue accordingly.

Validates: the deliberate busy-loop task from phase-1 testing no longer wedges the executor.

### Phase 3 — TaskSpec preemption controls + per-CPU stacks

- `TaskSpec::no_preempt()` for tasks that genuinely must run to completion (deadlocks-around-locks scenarios).
- Per-CPU executor stacks (currently one global; per-CPU lets each CPU's run_until_empty run independently).
- Affinity + work-stealing already exist in scheduler; preemption stays per-CPU naturally.

## Interaction with existing subsystems

| Subsystem | Effect |
|---|---|
| User-task `setjmp`/`longjmp` | Unchanged. User-task path still uses its own JmpBuf; preemption applies to kernel-side poll only. |
| RCU quiescent reporting | Each `kernel_switch` is a QSBR quiescent state. Preserved at the existing report point. |
| TSS.rsp0 | Per-task kernel stack means TSS.rsp0 must be updated on context switch (so user→kernel trap from a CPL=3 task lands on that task's kernel stack). Pattern already exists for user tasks (`set_kernel_rsp0`). |
| Trap handler | Unchanged for synchronous traps. Timer-driven preemption is a new ISR path. |
| Sleep/wake plumbing | Preserved — `Waker` still works, `yield_to_executor` is in addition. |
| FP/SSE/AVX state | Currently kernel doesn't use FP. If that changes, `xsave`/`xrstor` joins `kernel_switch`. |

## Open questions

- **Stack guard pages** — should each kernel-task stack have a redzone page at the bottom that page-faults on
  overflow? Adds vmalloc pressure (~5% per task) but catches stack overflows cleanly.
- **Default time slice** — 10 ms matches Linux. NARF's HPET wheel currently runs at ~10 Hz, so 10 ms means
  preempt on every tick. Could tune.
- **Stack size** — 16 KiB per task = 16 MiB for 1000 tasks. Might be too small for some drivers; large enough
  is configurable per spec.

## Validation plan

- New smoke: `smoke_scheduler_preempt_busy_loop` — spawn a task that runs `loop {}` (no await), spawn a
  second task that prints + completes. Assert second task completes within N ticks.
- QEMU iso-boot: existing boot continues to reach `narf>` shell.
- Real-HW: confirm Phoenix laptop reaches shell with at least the well-known busy-loops in current async tasks
  (e1000 RX pump, USB HID supervisor) actively misbehaving.
