# abi — Design Notes
_2026-04-22_

## Load-bearing decisions

**No pointer crosses the boundary; only CapSlot indices and inline scalars.**
This is the correct invariant and is more disciplined than io_uring (which
accepts user pointers for buffer registration). The consequence: every piece of
data a syscall needs that doesn't fit in `[u64; 6]` must be pre-staged in a
Narf-Ring buffer and referenced by a `CapSlot`. This is correct for security but
means the ABI is useless without a working `capabilities/` subsystem. Stage 3
must deliver both simultaneously; the ABI cannot be tested in isolation.

**Fast path has no trap — rings live in shared memory; doorbell via
`mwait`/`umwait` or MMIO.** The design is exactly io_uring's model and is the
right call. But `umwait`/`umonitor` (User-Mode Monitor/Wait) are x86_64-specific
and gated on `WAITPKG` CPUID feature (available on Ice Lake and later — 2019
onwards). The spec lists this as "when available, otherwise MMIO to a per-task
doorbell page." The fallback (MMIO doorbell page) is correct, but the per-task
doorbell page must be mapped with an uncacheable or write-combining memory type
to have any notification effect. The spec says nothing about caching attributes
for the doorbell page, which will cause silent MMIO polling failures on
implementations that map the page as WB (write-back).

**Slow-path `syscall`/`svc` exists only for bootstrap and cap operations with
no natural async shape.** This is correct, but "cap operations with no natural
async shape" is a large class: initial ring allocation, cap derivation, cap
revocation, task creation. In seL4 these are all synchronous. In Fuchsia they
are channeled through FIDL (async but typed). NARF's slow path is undefined
beyond "bootstrap." The boundary between fast-path and slow-path ops must be
explicitly enumerated, not gesturally defined.

**Submissions carry `caps: [CapSlot; 4]`.** Four capability slots per submission
is a guess. The io_uring summary notes that pre-validated buffer registration
reduces per-operation permission checks. If NARF pre-registers buffers (as io_uring
does), most submissions need zero or one cap slot. Conversely, an IPC that
transfers a buffer plus grants a derived cap plus attaches a time budget would
need three. Four is plausible but the spec should document the reasoning: "four
was chosen to fit one Submission in one or two cache lines; empirical review
needed at Stage 3." Magic constants without rationale accumulate as ABI debt.

## Divergences from precedent

**vs. io_uring:** io_uring uses 64-byte SQEs with a fixed-size inline data
payload and registered-buffer indices. NARF's `Submission` is conceptually
identical but uses `CapSlot` instead of buffer indices. The critical difference:
io_uring's buffer indices point into kernel-validated pre-registered regions;
NARF's CapSlots are resolved by the kernel against the cap table at submission
time. io_uring's pre-registration amortizes the validation cost; NARF's cap
resolution happens per-submission (unless NARF also pre-registers cap-bound
buffer regions). This is a latency concern on the hot path.

**vs. seL4 invocations:** seL4 invocations are synchronous register-based calls
with no ring. This is maximally simple but incompatible with async-first design.
The sel4-invocations summary correctly notes: "seL4's blocking semantics do not
compose well with async executors." NARF's divergence from seL4's ABI is
justified. However, seL4's explicit op-code-per-invocation model (where
mismatched type/op is rejected before the kernel handler runs) is a model NARF
should follow for the `OpCode` enum — every opcode should statically declare
which cap types and rights it requires, so the kernel dispatcher can reject
mismatches with zero-cost checks at the dispatch table.

**vs. Fuchsia FIDL:** FIDL is a schema language that generates typed stubs.
NARF's `OpCode` enum is flat and untyped at the ABI level. The fuchsia-fidl
summary highlights that "unrecognized values trigger clear errors" in FIDL
because the schema is enforced at both ends. NARF's ring-based ABI has no schema
enforcement — a submission with an invalid `OpCode` or a `CapSlot` pointing to
the wrong cap type is caught at dispatch, not at the ring boundary. Consider a
lightweight schema layer for NARF: each `OpCode` declares required `CapSlot`
types in a static table that the ring-draining code validates before dispatch.
This is much cheaper than FIDL code generation but catches most type errors.

**vs. Linux syscall table:** Linux's syscall table is versioned per-arch with
stable ABI guarantees across kernel versions. NARF's spec says "An ABI change
is a breaking change; bumps a version number in the submission header." This is
the correct micro-kernel approach (no stable syscall ABI, only versioned ABI),
but it implies userspace must negotiate the ABI version at task creation. The
spec doesn't describe this negotiation — does the kernel expose the current ABI
version via a well-known cap, or via the bootstrap syscall response?

## Proposed spec changes

- §3 Public interface: **Enumerate the slow-path operation classes explicitly:**
  "The slow path handles: (1) initial ring-pair allocation (returns submission +
  completion ring caps), (2) cap derivation and revocation, (3) task creation and
  destruction, (4) domain configuration. All other operations use the fast-path
  ring." Without this list, implementers will disagree about what belongs on the
  slow path.

- §3 Public interface: Add **version negotiation to the bootstrap syscall:**
  ```rust
  pub struct BootstrapRequest { min_abi: u32, max_abi: u32 }
  pub struct BootstrapReply   { abi_version: u32, sq_cap: CapSlot, cq_cap: CapSlot }
  ```
  This allows future ABI evolution without breaking existing userspace.

- §4 Invariants: Specify **caching attributes for doorbell pages**: "Per-task
  doorbell pages are mapped as Write-Combining (PAT index 1 on x86_64, device-nGnRE
  on aarch64) so that MMIO writes are visible to the kernel promptly without
  full serialization. Write-back doorbell pages are forbidden — they can silently
  coalesce notification writes."

- §4 Invariants: Replace "Completions are monotonic per-ring; drops are
  impossible (back-pressure via ring full)" with a concrete back-pressure policy:
  **"Ring-full on the submission side: the submitting task is blocked by the
  executor until ring space is available; it does not spin and does not receive
  an error. Ring-full on the completion side: the kernel drops the completion
  and sets an overflow flag in the ring header; userspace is responsible for
  checking the flag and resubmitting affected operations."** The current spec
  says "back-pressure via ring full" without specifying which side (SQ or CQ)
  or what "back-pressure" means (block? drop? error?).

- §5 Architecture notes (x86_64): Add **"If `WAITPKG` CPUID is absent, the
  fallback is MMIO to the per-task doorbell page. If `UIPI` is available (target
  CPU generation), the kernel delivers submission-complete notifications via UIPI
  rather than ring polling."** This wires UIPI into the ABI explicitly rather than
  leaving it implied.

- §8 Open questions: **Resolve the PLT-hook capability check question.** Decision:
  PLT-hook-style capability checks live in **userspace**, not in the kernel ABI.
  The kernel ABI checks cap validity at ring-drain time. PLT hooks are a userspace
  optimization that can short-circuit a syscall if the local capability check
  fails. Defining this as a kernel ABI mechanism makes the TCB larger; as a
  userspace convention it is optional and auditable.

## Open invariants / cross-subsystem hazards

**abi ↔ ipc:** The spec says `ipc/` provides "Narf-Ring primitives with
ownership transfer semantics." The ABI is defined by a *pair* of rings. But the
`ipc/` spec owns the ring implementation; `abi/` owns the semantic layer above.
If `ipc/` changes the ring wire format (e.g., ring-entry size), the `Submission`
and `Completion` structs in `abi/` must change. There is no stated versioning
contract between `ipc/` and `abi/`. These two subsystems must share a `NarfRingLayout`
struct that is defined in a common location (likely `lib/` or a shared
`narf-abi-types` crate).

**abi ↔ scheduler:** §2 says "`scheduler/` can wake a user task when a completion
is posted." But if the task is blocked on a ring-full submission, the scheduler
must park it and resume it when ring space opens. This requires the ring
implementation to call into `scheduler/` for the park/wake. If `ipc/` owns the
ring and `scheduler/` owns park/wake, `ipc/` depends on `scheduler/`. But the
current dependency graph lists `abi/` → `scheduler/`, not `ipc/` → `scheduler/`.
This will produce a circular dependency or an incorrect dependency graph.

**abi ↔ capabilities:** `CapSlot` is defined in `capabilities/` (Stage 3). The
`Submission` and `Completion` types in `abi/` use `CapSlot`. If both land in
Stage 3, there is a compile-time dependency: `abi` crate imports `capabilities`
crate for the `CapSlot` type. This is fine but must be explicit. `abi/` §6
lists `capabilities/` as a dependency, which is correct. The risk is that if
`capabilities/` is not ready when `abi/` begins implementation, `abi/` will stub
`CapSlot` as `u32` and those stubs will persist.

**abi ↔ userspace:** `abi/` provides the stable ABI that `userspace/` uses. If
`abi/` is Stage 3 and `userspace/` is Stage 4, the ABI must be stable before
the first user-facing code is written. Any Stage 3 ABI change after `userspace/`
starts is a breaking change. Establish a flag: "ABI is frozen at end of Stage 3
review; changes after that follow the version-bump protocol."

## Additional opinionated commentary

The ABI spec's most important gap is the absence of a concrete back-pressure
story for ring-full conditions. io_uring has had multiple CVE-class bugs
stemming from incorrect overflow handling. NARF's spec papers over this with
"back-pressure via ring full" — a phrase that says nothing about who blocks,
who signals, or how the kernel avoids livelock when both SQ and CQ are full
simultaneously (an impossible condition per the spec's "CQ drops are impossible"
claim, but one that arises in practice if the completion draining task is
preempted by the submitting task on the same CPU).

The PLT-hook question (Shiva-inspired) deserves a clear answer: it is
architecturally fascinating but belongs in userspace. Putting capability checks
in kernel-side PLT stubs makes the TCB responsible for correct stub installation
and correct CET/BTI interaction. Userspace-side stubs are auditable, replaceable,
and outside the TCB. This is an easy call.

The four-cap-slot design is fine, but the spec should note that it determines the
`Submission` struct's cache footprint. A `Submission` with 4 CapSlots (4×4 = 16
bytes) + 1 OpCode (4 bytes) + 6 inline u64s (48 bytes) = 68 bytes — does not
fit in one 64-byte cache line. Either reduce to 3 CapSlots (64 bytes total) or
accept two cache lines per submission. This has measurable impact on ring
throughput and should be decided with a perf measurement, not left unresolved.
