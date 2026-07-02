# Task lifetime redesign — Linux-style reference counting

Status: DESIGN + full teardown/signal audit (2026-07-02).
Goal: eliminate the task-teardown use-after-free class and the ~40-table
stale-state swamp behind the intermittent boot hangs, and give
multithreaded processes (weston, Qt/KDE apps) correct exit/signal
semantics. Hard cutover — no compat shims.

## 1. Current lifetime model (audited)

Ownership chain, all-or-nothing:

    TaskSlot (scheduler READY queue)
      └── Pin<Box<StackfulAdapter>>
            └── Box<KernelTask>            (own 16K kernel stack, KernelContext)
                  └── Pin<Box<UserTaskFuture>>
                        ├── UserTaskCtx    (park state, saved UserState)
                        ├── FpuArea        (FXSAVE image)
                        ├── JmpBuf
                        └── UserProcess    (Arc<AddressSpace>, entry, …)

Dropping the slot frees EVERYTHING at once. Meanwhile these hold raw
pointers or ids into that box:

| Holder | What | Guard |
|---|---|---|
| `USER_TASK_CTXS` (user_task.rs:601) | `*mut UserTaskCtx` by tid | deref-under-lock convention (`with_user_task_ctx`) |
| per-CPU `CURRENT`/`CURRENT_FPU`/`CURRENT_JMP` (user_task.rs) | raw ptrs into the box | "in-flight on this CPU" convention |
| per-CPU `CURRENT_STACKFUL_TASK` (stackful.rs:156) | `*mut KernelTask` | same convention; deref'd from IRQ (`try_preempt*`) |
| ~48 `current_user_task()` call sites (handlers.rs) | raw `*mut UserTaskCtx` | "current can't be freed while running" |
| futex/io/signal/wait-child/timer-wheel tables | `Waker` = `Arc<WakeCell>` | safe (Arc), but entries go stale/leak |

Key facts: scheduler TaskIds (tids) are monotonic and NEVER reused;
PIDs are lowest-free and REUSED. Wakers are `Arc<WakeCell>` — firing a
dead task's waker is memory-safe. Signal sends never write target
memory (bit-set + wake; victim self-delivers on its own trap return).

## 2. Confirmed hazards (from the 3-way audit)

### Memory safety (UAF class)
- **H1 (the trap):** `run_until_empty`/`poll_one_round` drop a slot on
  `ChargeOutcome::Kill` (lib.rs:2039) or revoked budget-cap
  (lib.rs:1842) with ZERO teardown: no `unregister_user_task_ctx`, no
  exit observers. `register_user_task_ctx` ran at the top of that very
  poll → `USER_TASK_CTXS` holds a dangling pointer forever (tids never
  recycle). Any later `wake_signal`/`wake_one`/`futex_wake_waiters` →
  `with_user_task_ctx` → **deref of freed memory**. Currently gated only
  by "no user task uses OverrunPolicy::Kill".
- **H2:** `CURRENT_FPU` per-CPU slot is never cleared; an FPU hook firing
  between task free and the next publish FXSAVEs into freed memory.
- **H3:** `exit_current_stackful` (stackful.rs:1306) degrades to a
  silent infinite spin-loop when `CURRENT`/`exec_ctx` is null — a lost
  CPU indistinguishable from "getty never scheduled".

### Teardown completeness (stale-state class)
- **~40 of ~56 per-task tables never cleaned on ANY exit path** (full
  inventory in §6). Only fd table, TASK_STOPPED, clear_child_tid,
  pending-exit plumbing, pidfd, pid_ns, cgroup are cleaned.
- **No reparenting:** a child whose parent already exited pushes its
  exit status to the DEAD parent's queue; its pid is never released;
  nobody is woken. (Early-boot transient parents make this a prime
  boot-hang candidate.)
- **exit_group == exit** (syscall.rs:2481): sibling threads are never
  killed. A multithreaded process half-dies; the parent reaps while
  threads keep running on the shared AS.
- **No remote kill:** `terminate_current_task` only runs on the victim's
  own trap path. A parked task whose waker was lost is unkillable.
- **Robust futex list never walked** on death → peers deadlock.
- **execve** leaks: no FD_CLOEXEC sweep; stale `CLEAR_CHILD_TID`,
  `ROBUST_LIST`, `SIG_ALTSTACK` uaddrs from the OLD image are used
  against the NEW image (silent user-memory corruption).
- **posix timers/itimers have no exit observer** — fire forever into
  dead tids (alloc-free IRQ path, but wrong-target).
- **PID_TO_TASK/TASK_TO_PID never removed** + pid reuse → signals and
  exit statuses routed to the wrong live process.

### Signal semantics (thread/desktop blockers)
- **CLONE_SIGHAND is parsed and discarded** (handlers.rs:8624): pthreads
  get an EMPTY sigaction table → any signal to a worker thread takes
  default action (kills it). musl `setuid()`/`pthread_cancel`
  broadcast signals to all threads — instant thread death.
- Threads don't inherit sigmask; process-directed signals only ever hit
  the group leader (and are LOST if the leader died first).
- `kill(-pgid)`/`kill(0)`/`kill(-1)` unimplemented (silent no-op with a
  phantom-tid pending bit); no ESRCH anywhere.
- SIGKILL/SIGSTOP catchable via rt_sigaction and blockable via
  sigprocmask; `oldact` never written back.
- sigaltstack not reset on execve.

## 3. Design: `Arc<Task>` with get/put semantics

Linux mapping: `task_struct` refcount → `Arc<Task>`; pid table →
`TASKS` registry (holds one ref while task is findable);
`release_task()` → `release_task()`; `zap_other_threads()` → group-kill
walk; `signal_struct`/`sighand_struct` → `Arc<ThreadGroup>` +
`Arc<SigHand>`.

### 3.1 The object (new `userspace/src/task.rs`)

```rust
pub struct Task {
    pub tid: u64,                       // scheduler TaskId.raw(), never reused
    pub pid: AtomicU64,                 // tgid (POSIX pid); pids ARE reused
    pub state: AtomicU32,               // RUNNING | EXITING | ZOMBIE | DEAD
    pub uctx: UserTaskCtx,              // MOVED out of UserTaskFuture
    pub exit_code: AtomicI32,
    pub group: Arc<ThreadGroup>,        // shared across CLONE_THREAD
    pub sighand: IrqSafeSpinLock<Arc<SigHand>>, // shared on CLONE_SIGHAND
    pub parent: IrqSafeSpinLock<u64>,   // parent tid (0 = none/init)
    // per-thread signal state migrates here from the BTreeMap swamp
    // incrementally (mask, pending, altstack, sigreturn layout).
}

pub struct ThreadGroup {
    pub tgid: u64,
    pub threads: IrqSafeSpinLock<BTreeSet<u64>>, // live tids
    pub group_exiting: AtomicBool,
    pub shared_pending: AtomicU64,      // process-directed signal bits
}

pub struct SigHand {
    pub actions: IrqSafeSpinLock<[Option<SigAction>; NSIG]>,
}

static TASKS: IrqSafeSpinLock<BTreeMap<u64, Arc<Task>>> = …;
pub fn task_get(tid: u64) -> Option<Arc<Task>>;   // get_task_struct
pub fn current_task() -> Option<Arc<Task>>;       // by current_task_id()
```

Invariants:
1. `TASKS` holds exactly one ref from spawn-registration until
   `release_task` (reap). Any holder that needs the task past a lock
   section clones the Arc — deref NEVER requires holding the registry
   lock (this deletes the `SendPtr` + deref-under-lock contraption).
2. `UserTaskFuture` holds `Arc<Task>` instead of an inline
   `UserTaskCtx`. Slot drop = one `put`, not a free. The box's
   `UserTaskCtx` address is stable for the Task's whole life, so the
   existing `*mut UserTaskCtx` self-deref sites become sound
   automatically (pointer now points into the Arc'd Task).
3. Per-CPU `CURRENT*` publications count as an implicit ref (Linux
   `rq->curr` rule): the executor may only drop its slot ref AFTER the
   task has switched out and the per-CPU slots are cleared. This is the
   existing switch-out ordering, now stated as an invariant.
4. **IRQ contexts never drop an `Arc<Task>`** (NARF forbids allocator
   frees in IRQ context — the deferred_wake precedent). IRQ paths use
   tid + `Arc<WakeCell>` only, as they already do. If an IRQ-side Arc
   ever becomes necessary, route the put through a deferred-drop queue
   (Linux `delayed_put_task_struct` analogue).

### 3.2 Exit state machine

```
RUNNING ──exit/exit_group/fatal-signal──▶ EXITING
  EXITING (on own stack): exit_work():
     • robust-list walk (FUTEX_OWNER_DIED + wake)
     • clear_child_tid write + futex wake
     • per-tid table purge: release_task_tables(tid)   ← §6 sweep
     • fd::detach, timers disarm, waker-table purge
     • reparent MY children to init (pid 1) + rewake init's wait
     • thread-group bookkeeping: leave group; if last thread (or
       group_exit), notify parent (SIGCHLD + PENDING_EXITS + wake)
  ──▶ ZOMBIE   (Task stays in TASKS carrying exit_code for wait4)
  parent wait4/waitid reap ──▶ release_task(tid):
     • remove from TASKS (final registry put), release_pid,
       PID_TO_TASK/TASK_TO_PID rows, cpu-time rows
  ──▶ DEAD (memory freed when the last Arc drops)
```

`exit_current_stackful` null-context path becomes a `panic!` with
attribution (H3) — a lost CPU must never be silent.

Scheduler hook (H1 fix): a new `set_slot_reap_hook(fn(TaskId))` in the
scheduler; `run_until_empty`/`poll_one_round` call it on EVERY slot
drop that didn't come from `Poll::Ready` (budget kill, cap revoke).
The hook runs the same EXITING→ZOMBIE teardown so no drop path can
bypass cleanup.

### 3.3 Thread groups: exit_group + zap

`sys_exit_group`: set `group.group_exiting`, then for every sibling tid
set SIGKILL pending + `wake_signal(tid)` (zap_other_threads). Parked
siblings wake through the existing signal wakers/wheel fallback and
self-terminate on their next delivery point; running siblings die on
their next trap (timer tick worst case). The caller then exits itself.
wait4 reports the group_exit code. SIGKILL send also sets
`group_exiting` when the group has >1 thread (Linux fatal-signal
group-kill semantics).

`kill(pid)` (process-directed): set bit in `group.shared_pending`, wake
ANY thread with the signal unblocked (fallback: leader, else first
live tid). Delivery drains per-thread pending first, then shared.
`kill(-pgid)`/`kill(0)`/`kill(-1)` route through the existing
`deliver_signal_to_pgrp` machinery; missing targets return ESRCH.

`SigHand` sharing: CLONE_SIGHAND/CLONE_THREAD clone shares the Arc;
plain fork deep-copies the table; execve resets caught→SIG_DFL in
place AND clears sigaltstack, robust list, clear_child_tid (unless
set by the new image), and sweeps FD_CLOEXEC.

### 3.4 What does NOT change

- Wakers stay `Arc<WakeCell>` — already sound.
- The own-stack execution model, `KernelTask`, `kernel_switch`, and the
  executor loop keep their shape; only slot-drop gains the reap hook
  and the "clear per-CPU slots before final put" invariant.
- tid allocation stays monotonic (our ABA-safety anchor — do NOT
  introduce tid reuse).

## 4. Implementation stages (each = one commit, boot-verified)

1. **task.rs core** — DONE (commit dffb4cc8). `Task`/`TASKS`/`task_get`,
   `UserTaskFuture` holds `Arc<Task>`, deleted
   `USER_TASK_CTXS`+`SendPtr` (callers → `task_get`), spawn-time
   registration, exit → ZOMBIE → reap `release_task`. Scheduler
   slot-reap hook (H1). exit_current_stackful panic (H3).
2. **release_task_tables sweep** — DONE (commit 354141e0). Master exit
   sweep over every tid-keyed table; orphan handling (auto-release
   dead-parent children, drop PARENT_OF); robust-futex owner-died walk;
   posix/itimer disarm; waker-table purge; PID_TO_TASK/TASK_TO_PID at
   reap.
3. **thread groups + signal parity** — DONE (this stage). SigHand
   `Arc`-shared on CLONE_SIGHAND/CLONE_THREAD (deep-copy on fork),
   sigmask inheritance, dedicated `exit_group` that zaps siblings +
   `group_exiting` flag, `kill()` pgrp/broadcast/zombie routing +
   fatal-SIGKILL group fan-out, ESRCH on missing target (kill/tkill/
   tgkill/rt_[tg]sigqueueinfo), EINVAL + SIGKILL/SIGSTOP-uncatchable in
   rt_sigaction, SIGKILL/SIGSTOP force-unblock in procmask/suspend,
   rt_sigaction oldact write-back, tgkill (tgid,tid) check,
   sigaltstack + robust-list + clear_child_tid cleared on execve,
   FD_CLOEXEC sweep on execve, pgrp-delivery wakes parked targets.
4. **remaining parity (follow-up)**: RT-signal queue depth (still
   coalesces), ITIMER_VIRTUAL/PROF (only ITIMER_REAL fires), full
   "any thread may dequeue a process-directed signal" shared-pending
   set, orphaned-pgrp SIGHUP. Pinned in §5.
5. Regression tests per stage (abi_signal/process_e2e suites) + boot
   smoke + full kernel-test run (KVM + TCG).

## 5. Linux-parity matrix (all in scope — brought to parity, not pinned)

| Area | Linux behaviour | NARF today | Fix stage |
|---|---|---|---|
| exit_group | kills all threads, group exit code | alias of exit | 3 |
| CLONE_SIGHAND/THREAD | shared sighand, inherited mask, shared pending | discarded; empty tables | 3 |
| kill(-pgid)/kill(0)/kill(-1) | pgrp/broadcast routing | silent no-op | 3 |
| Missing target | ESRCH | ok(0) + phantom bit | 3 |
| SIGKILL/SIGSTOP | uncatchable, unblockable | catchable + blockable | 3 |
| rt_sigaction oldact | written back | ignored | 3 |
| RT signals (>=SIGRTMIN) | queued with siginfo, per-signal FIFO depth | coalesced single slot | 3 |
| sigaltstack on execve | reset (SS_DISABLE) | stale uaddr kept | 4 |
| FD_CLOEXEC on execve | swept | never | 4 |
| robust futex list | walked on death, FUTEX_OWNER_DIED | recorded, never walked | 2 |
| orphan reparenting | reparent to init/subreaper, init auto-reaps | exit status pushed to dead parent | 2 |
| orphaned pgrp | SIGHUP+SIGCONT to newly-orphaned stopped pgrp | nothing | 3 |
| remote kill of parked task | wake + delivery guaranteed | relies on surviving waker | 2 (zap wake path) |
| ITIMER_VIRTUAL/PROF | SIGVTALRM/SIGPROF on cpu time | only ITIMER_REAL | 3 |
| tgkill tgid check | (tgid,tid) consistency enforced | tgid ignored | 3 |
| wait status for group exit | leader reports when group dead | per-thread only | 3 |

ptrace interactions remain out of scope for this redesign.

## 6. Per-task table inventory (cleanup matrix)

Keyed by tid unless noted. "Sweep" = to be purged in
`release_task_tables` (stage 2). Today-status from the audit:

| Table | Today | Plan |
|---|---|---|
| fd TABLES, advisory locks | cleaned (fd::detach) | keep |
| TASK_STOPPED | cleaned | keep |
| CLEAR_CHILD_TID | fired+taken | keep + clear on execve |
| PENDING_TERMINATION / PENDING_EXITS / PENDING_STOPCONT | drained via reap | reparent fixes orphan case |
| PARENT_OF (pid) | reap-only | + exit-time reparent |
| TASK_CPU_NS / TASK_CHILD_CPU_NS | reap-only | keep (release_task) |
| pidfd watchers, pid_ns, cgroup | cleaned | keep |
| PID_TO_TASK / TASK_TO_PID (pid reuse hazard!) | never | release_task |
| SIGNAL_PENDING / SIGNAL_MASK / SIGACTION / SIG_ALTSTACK / SIGQUEUE_INFO / SIGRETURN_{USE_RSP,IS_RT,SAVED_MASK} | never | migrate into Task / sweep |
| SIGNAL_WAKERS / IO_WAKERS / FUTEX_WAITERS / WAIT_CHILD_WAKERS | never (Arc-safe leak) | sweep |
| ROBUST_LIST_TABLE | never, never walked | walk on exit + sweep + execve clear |
| TCB_OWNER | socket-close only | sweep |
| CWD / ROOT_DIR / UMASK / BRK / RLIMIT / PRCTL / NICE / SCHED_PARAM / SCHED_ATTR / PGID / SID / CTTY / UIDGID / TASK_TERMIOS / TASK_MOUNT_NS / PROC_ARGV / PROC_COMM / PROC_ENVIRON / PROC_AUXV / PROC_OOM_ADJ / PROC_COREDUMP_FILTER / CAP_TABLE / XATTR / PKEY / MEMPOLICY / MBIND / FLOCK_TABLE / BOOTSTRAP_TABLE | never | sweep |
| FOREGROUND_TASK (atomic) | never | clear-if-self on exit |
| posix timers / itimers | never | exit observer disarm |
| timer wheel SleepHandle | self-healing (gen-guarded) | keep |
