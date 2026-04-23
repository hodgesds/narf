# Embassy Executor

**Primary source:** Embassy book
(<https://embassy.dev/book/>), `embassy-executor` crate docs and source
(<https://docs.rs/embassy-executor/>,
<https://github.com/embassy-rs/embassy/tree/main/embassy-executor>).

> Distilled for NARF design. Reading notes.

## Why Embassy is NARF's closest prior art

Embassy is a `no_std` async executor built for bare-metal Rust on
microcontrollers. It runs Rust `Future`s without an underlying OS,
which is the same context NARF has. Its internals are small enough to
read in an afternoon and make most of the design trade-offs we face
explicit.

## Core structures

- **`Executor`** — per-CPU struct holding a ready queue. Runs tasks
  until the queue is empty, then sleeps waiting for a wake.
- **`TaskStorage<F>`** — statically-allocated storage for a single
  future of type `F`. Each task is a fixed `TaskStorage`; the
  executor never allocates.
- **`TaskRef`** — erased reference to a task, used in queues and
  wakers. A `TaskRef` is conceptually a pointer + a vtable for
  `poll` / `wake`.
- **`TaskHeader`** — the common header shared by every TaskStorage,
  containing the intrusive queue links, `state` bits (spawned /
  run_queue / timer_queue), executor backpointer, and waker vtable.

## Queue design

- **Intrusive linked list** in `TaskHeader`. The ready queue is a
  lock-free MPSC with `AtomicPtr` head.
- Wakers push the task onto the ready queue by CAS on the head.
- The executor pops tasks one at a time and polls them.

## No allocation

Embassy compiles tasks into static storage via the `#[embassy_executor::task]`
attribute macro, which generates a `TaskPool<F, N>` that owns `N` task
slots. `spawn` finds a free slot and initialises it with the Future.

This matches NARF's "kernel has no general-purpose heap for tasks" goal.
Tasks ultimately will live in slab-allocated storage per domain, but
the lifecycle discipline is the same: reserve, initialise, spawn, poll.

## Waker strategy

Embassy's waker is pointer-identity with the task header. Waking
another task is O(1):

```text
Waker -> TaskHeader* -> enqueue(ready_queue)
         -> pend executor (if sleeping)
```

The "pend executor" step is per-platform — on ARM Cortex-M it's a
`SEV` / NVIC pend; on NARF we'd wire this into the per-CPU scheduler
wake path (IPI or UIPI).

## SMP support

`embassy-executor` has experimental multi-core support; canonically
it runs one executor per core with tasks pinned to a core. Work
stealing is *not* a core feature. NARF will add work-stealing in
Stage 3; Embassy's minimal single-core executor is the right starting
point for Stage 1.

## Timers

Embassy integrates with `embassy-time` for timer-driven wakes. The
executor exposes a `timer_queue` separate from the ready queue; a
per-CPU timer ISR scans for expired deadlines and wakes the
associated tasks. NARF's timer path will look similar.

## Why it matters for NARF

- **Stage 1 scheduler should look like Embassy minus microcontroller
  assumptions.** Single-CPU, intrusive-list ready queue, static-ish
  task storage, minimal waker machinery.
- **Domain-aware polling.** NARF diverges from Embassy by requiring
  the executor to `enter_domain(task.domain)` before calling
  `Future::poll`. This is a clean extension — add a `DomainId` field
  to `TaskHeader`.
- **No heap in executor core.** Embassy proves this works at real
  complexity levels. Keeps our TCB small.
- **Work-stealing upgrade path.** Embassy has an MPSC per-core queue;
  swapping it for crossbeam-style deques in Stage 3 is a localised
  change.

## Caveats / where NARF must diverge

- Embassy pins tasks statically at compile time via `task_pool!`. NARF
  runs drivers discovered at boot, so we need runtime-sized pools
  (slab-allocated TaskStorage).
- Embassy's `unsafe` uses are comfortable with a single trusted
  compilation unit. NARF has driver domains that are much less
  trusted; the executor running in the TCB must not be tricked by
  malformed `TaskHeader` from a driver-supplied task.
- SMP + direct context transfer is ours to invent — Embassy has neither.

## Further pointers

- `embassy-executor-raw`'s SMP branch for the newest SMP sketch.
- `smol` / `async-executor` crate for the simplest non-Embassy
  host-side executor (useful mental model).
- Tokio scheduler blog posts for when NARF earns work-stealing complexity.
