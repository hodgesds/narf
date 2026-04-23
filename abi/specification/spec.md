# abi — Specification

> Status: **Outline v0.2** (Stage 3). v0.2 codifies the uniform
> cancellation protocol that every subsystem crossing this boundary
> must follow — the single most common UAF source in async kernels.

## 1. Purpose & scope

**Owns:** The stable shape of operations that cross the kernel↔user
boundary — how a user task submits work, how it receives completions,
how capabilities are passed and returned, and the canonical error channel.

**Does NOT own:** The on-the-wire format of a specific driver (that's
per-driver), nor the in-kernel ring implementation (that's `ipc/`).

## 2. Assumptions

- `ipc/` provides Narf-Ring primitives with ownership transfer semantics.
- `capabilities/` provides forgery-proof `Cap<T>` tokens that can be
  encoded as indices into a per-task cap table.
- `scheduler/` can wake a user task when a completion is posted.

## 3. Public interface

Sketch: the ABI is defined by a pair of rings per task — a submission
ring and a completion ring, plus a capability-table handle namespace.
No `int 0x80` / `svc` syscalls on the fast path.

```rust
// Conceptual
#[repr(C)] pub struct Submission {
    op:      OpCode,
    flags:   SubmissionFlags,    // CANCELLABLE, LINKED, DRAIN, ...
    caps:    [CapSlot; 4],
    tag:     u64,                // echoed in completion
    inline:  [u64; 6],
}
#[repr(C)] pub struct Completion {
    tag:     u64,
    status:  NarfStatus,         // incl. Cancelled, CancelRequested, CapRevoked
    result:  [u64; 6],
}
```

- `OpCode` enumerates every user-callable operation, grouped by
  subsystem (memory, ipc, scheduler, drivers).
- `CapSlot` is a tagged index into the task's capability table.
- **Slow-path `svc`/`syscall` is restricted to four operation classes**
  (anything else MUST go through the fast-path ring):
  1. **Initial ring-pair allocation** (returns submission +
     completion ring caps) — chicken-egg case before any ring exists.
  2. **Cap derivation and revocation** — synchronous semantics
     required for security ordering guarantees.
  3. **Task creation and destruction** — needs to atomically
     install initial caps + ring pair before the new task runs.
  4. **Domain configuration** — TCB-only operation; uses the slow
     path so `frame/` can audit synchronously.

  Without this enumeration, implementers will disagree about what
  belongs on the slow path, and the slow-path surface will sprawl.

### 3.1 Bootstrap

```rust
pub struct BootstrapRequest { min_abi: u32, max_abi: u32 }
pub struct BootstrapReply   {
    abi_version: u32,        // chosen from intersection of caller's range and kernel's
    sq_cap:      CapSlot,    // submission ring cap
    cq_cap:      CapSlot,    // completion ring cap
    cfg_cap:     CapSlot,    // read-only config-page cap (per `userspace/` §3)
}
```

The task's first slow-path syscall is `bootstrap(BootstrapRequest)`.
The kernel returns the negotiated `abi_version` plus the ring-pair +
config caps. Subsequent operations use the rings; the slow path is
re-entered only for the four classes above. Version negotiation lets
future ABI evolution proceed without breaking running userspace.

### 3.1 Cancellation protocol (uniform across all subsystems)

Every long-running operation submitted through this ABI is
**cooperatively cancellable**. Dropping the Future returned by a
submission helper requests cancellation; it does NOT silently
discard the operation, because the kernel may still hold DMA
targets, cap references, or scheduling reservations whose release
the user side cannot unilaterally force.

```rust
// Userland side (in the relibc / native futures wrapper)
pub struct SubmissionHandle<T> {
    tag: u64,
    cq:  Arc<CompletionRing>,
}

impl<T> Future for SubmissionHandle<T> { /* polls completion */ }

impl<T> Drop for SubmissionHandle<T> {
    fn drop(&mut self) {
        // Issue an OpCode::Cancel(tag). Block until a terminal
        // completion with status Cancelled | Ok | Error is drained
        // for this tag. Any held DMA buffer / cap is reclaimed only
        // after that terminal completion is seen.
    }
}
```

**Protocol (all parties):**

1. **Submit.** Producer submits with a tag. The submission may
   reference caps, DMA buffers, or other resources; those remain
   conceptually borrowed by the kernel until a terminal completion.
2. **Cancel request.** If the user side drops the `SubmissionHandle`
   or explicitly calls `cancel(tag)`, an `OpCode::Cancel(tag)` is
   submitted. This is **non-blocking for the kernel**: the cancel
   op always succeeds (`Ok`) regardless of whether the target
   op is in-flight, already done, or unknown.
3. **Terminal completion.** The original submission eventually
   drains a *terminal* completion with one of:
   - `NarfStatus::Ok(...)` — finished before cancel took effect.
   - `NarfStatus::Cancelled` — cancellation took effect; no partial
     side effects beyond what the completion reports in `result`.
   - `NarfStatus::CancelRequested` — operation cannot be cancelled
     (e.g. mid-flush on a block device); caller must await the
     eventual `Ok` or `Error`.
   - `NarfStatus::Error(code)` — failed independently of cancel.
4. **Resource release.** Borrowed resources (DMA buffers, cap
   references, ring slots) are reclaimed by the kernel *only on
   terminal completion*. The user side MUST drain the terminal
   completion — blindly dropping without ever polling the CQ is a
   leak and, in debug builds, a `tracing/` critical event plus
   eventual per-task resource-budget overrun.

**Partial-completion disclosure.** `Cancelled` MUST report in
`result` any durable side effect that survived cancellation
(bytes written, blocks TRIMmed, frames TX'd). Callers can recover
without a separate "how much got through?" roundtrip.

**Cancel granularity.** An `OpCode::Cancel(tag)` targets exactly
one outstanding submission. There is no "cancel all" primitive at
the ABI level; userland builds bulk cancellation by iterating its
in-flight set.

**Linked submissions.** If `SubmissionFlags::LINKED` chains
operations, cancelling any one of them auto-cancels the rest of
the chain; each chain member produces its own terminal completion.

**Non-cancellable operations.** A small set of operations (flush,
commit, fence-like barriers) may return `CancelRequested` and keep
running. Drivers SHOULD keep this set small; any operation that
does expensive work MUST be cancellable within O(ms).

## 4. Invariants & safety properties

- An ABI change is a breaking change; bumps a version number in the
  submission header.
- No pointer ever crosses the boundary — only capability slots and inline
  scalar data. Buffers are referenced via Narf-Ring ownership transfer.
- **`CapSlot` carries a 128-bit (generation + index + rights + type_tag)
  value, not a 32-bit handle.** The generation is compared to the
  object's current epoch at dispatch. A submission whose cap is
  revoked between enqueue and dispatch completes with
  `NarfStatus::CapRevoked`. Userspace must not retry such a
  completion as if it were a transient error — it is authoritative.
- **Back-pressure is concrete, not gestural:**
  - **SQ full on submit:** the submitter is blocked by the executor
    (waker registered on the consumer's advance). It does not spin
    and does not receive an error. For tasks that explicitly
    request non-blocking, a `TrySubmission` path returns
    `Err(Full)`.
  - **CQ full on completion produce:** the kernel sets an overflow
    flag in the ring header and refuses further completions until
    userspace clears it. Operations whose completions could not be
    posted are held on a per-task overflow list; userspace
    discovers them by clearing the overflow flag and draining.
    Completions are never silently dropped.
- Completions are monotonic per-ring modulo the 2-bit wrap counter +
  AVAIL/USED flag (see `ipc/` §4).
- **Doorbell pages are mapped Write-Combining.** PAT index 1 on
  x86_64 (WC), Device-nGnRE on aarch64. Write-Back is forbidden:
  WB caches can silently coalesce notification writes, dropping
  doorbells the producer thought it had issued. The `memory/`
  mapping API for doorbell pages enforces this attribute at map
  time; the wrong attribute is a panic.

## 5. Architecture notes

### x86_64
- Slow-path entry via `syscall`/`sysret`; MSR-configured.
- Submission ring in user-shared memory.
- **Doorbell delivery, in preference order:**
  1. **UIPI** (CPUID UINTR present) — kernel delivers
     submission-complete via UIPI directly to the user task's
     receiver, bypassing ring polling on the user side.
  2. **`UMWAIT` / `WAITPKG`** (CPUID WAITPKG present) — user task
     waits with bounded latency on a doorbell page.
  3. **MMIO write to per-task doorbell page** (always available
     fallback). The doorbell page is WC-mapped per §4 above.

### aarch64
- Slow-path entry via `svc #0`; HVC reserved.
- Same ring model; doorbell via `WFE`/`SEV` event channel.

## 6. Dependencies

- **Consumes:** `ipc/`, `capabilities/`, `scheduler/`, `arch/`.
- **Provides to:** `userspace/`, every user-visible driver spec.

## 7. Stage assignment

Stage 3.

## 8. Open questions

- Submission-ring back-pressure: block task, drop with error, or spill to
  a per-task overflow queue?
- How many capability slots per submission entry — fixed 4, variable?
- Do we version each op independently or the whole ABI as a unit?
- ~~PLT-hook-style capability checks at call sites~~ **Resolved
  (v0.2): PLT-hook checks live in *userspace*, not in the kernel
  ABI.** The kernel ABI verifies cap validity at ring-drain time
  (the only authoritative point). PLT hooks are an optional
  userspace optimisation that can short-circuit a syscall if the
  local cap-table cache says the cap is invalid. Putting them in
  the kernel grows the TCB; leaving them as a userspace convention
  keeps them auditable and per-process-tunable.
