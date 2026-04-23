# L4 Direct Process Switch (Liedtke 1993)

**Primary source:** Jochen Liedtke, "Improving IPC by Kernel Design",
SOSP 1993; also Liedtke's "On µ-Kernel Construction" (SOSP 1995).
Bershad et al., "Lightweight Remote Procedure Call" (TOCS 1990), gives
the same idea framed for RPC.

> Distilled for NARF design. Reading notes.

## The idea

When task A invokes task B via synchronous IPC and B is ready to
receive, the kernel *does not* go through its normal scheduler round
trip. Instead, it directly switches address space to B, copies the
small message in registers, and starts executing B — using A's
remaining time slice. The scheduler proper is only re-entered if the
call cannot proceed immediately (B isn't ready) or when the time slice
expires.

This shaves the classic microkernel double-trip (A → kernel → scheduler
→ B → kernel → scheduler → A) down to a single ring-crossing each way.
Liedtke's measurements showed L4 IPC reaching a few hundred cycles on
mid-90s hardware, an order of magnitude below contemporaries.

## Key ingredients Liedtke used

1. **Register-passed messages** for short payloads; memory copies only
   for long ones.
2. **Lazy scheduling queues** — the scheduler's ready queue is only
   updated when a task blocks or its slice expires, not on every IPC.
3. **Direct process switch** — the IPC path flips page-table root, TSS,
   and FS/GS, then returns to user with B's PC.
4. **Thread control blocks stored in a per-thread kernel stack UTCB**
   so register state is at a predictable offset.
5. **Clan & Chief** (L3) / **endpoints** (L4.X.Y) for addressing — a
   sender names a target thread via an unforgeable handle.

## Why NARF cares

NARF's **Direct Context Transfer** (described in `DESIGN.md` §2 and
`scheduler/specification/spec.md`) is the same move, in an async world:

- In L4, sync IPC invokes the receiver immediately using the sender's time.
- In NARF, an async call posts into a Narf-Ring and the executor polls
  the receiver Future immediately on the same CPU (still holding the
  caller's slice) rather than returning to the idle/scheduler loop.

The invariants Liedtke cared about translate:

- **Receiver must be ready.** In L4, "ready" means "blocked in recv on
  this endpoint." In NARF, it means "receiver's Future is wakeable and
  not already running." If not ready, we fall back to regular wake.
- **Small messages first.** L4's register-only path is NARF's
  "inline" submission fields; larger payloads move by handle into
  shared memory. Same dichotomy.
- **Caller's slice, callee's code.** Scheduler accounting must *not*
  double-charge: if B runs on A's time, B's runtime is booked against
  A until A's slice ends.

## What NARF changes from pure L4

- **No address-space switch** on the common case. Because drivers live
  in the same VM with PKS/MTE domains, we switch domain key rights
  (cheap MSR write on x86_64, pointer-tag discipline on aarch64) rather
  than flipping CR3. This is the framekernel's central speed win over
  classic microkernels.
- **Async, not sync.** Liedtke assumed both parties are runnable threads;
  NARF treats "thread" and "Future" as largely interchangeable, so the
  donation works over a Future poll, not a thread-switch.
- **Capabilities everywhere.** L4 endpoints granted ambient receive
  authority; NARF gates donation with `Cap<Task, Invoke>` so only caps
  justify priority gifting.

## Risks Liedtke's work flagged

- Scheduling fairness is easy to break: if A keeps donating to B and B
  keeps donating back, observers see a pair burning cycles while other
  tasks starve. Solution in L4: slice budget follows original owner.
  NARF should carry this forward.
- Priority inversion if a low-priority caller donates to a high-priority
  receiver — seL4 calls this out explicitly and handles via priority
  ceiling semantics on endpoints.
- Implementation complexity in saving/restoring exactly the right CPU
  state. The async stackless-Future model is a win here: `Waker` + ring
  state is far smaller than a preempted thread's register file.

## Further reading surfaced by this one

- seL4 scheduling paper (Lyons et al.) for how modern verified L4s
  handle the fairness/priority issues.
- "NOVA: a microhypervisor-based secure virtualization architecture"
  for an L4-style kernel applied to the hypervisor use case.
