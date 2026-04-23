# capabilities — Design Notes
_2026-04-22_

## Load-bearing decisions

**`Cap<T, R>` is a Rust type, not just a runtime token.** The spec uses phantom
types (`PhantomData<(T, R)>`) to enforce rights at compile time. This is
powerful but it means rights checks that *should* happen at runtime (e.g.,
checking that a `Cap<BlockDevice, Write>` is still valid after revocation) must
be separate from the type-level checks. The type alone proves the *original*
grant was sound; it proves nothing about present validity. Callers must not
conflate "I hold a `Cap<T, Write>`" with "my Write access is currently
authorized." The spec does not distinguish these two forms of soundness.

**CDT vs. refcount+badges is unresolved in Stage 3, the full implementation
stage.** This is the most important unresolved design question in the
capabilities subsystem. The choice has memory, latency, and revocation-semantics
consequences. The keykos-eros summary recommends epoch-based revocation as O(1);
the sel4-capabilities summary shows CDT gives clean mass-revocation semantics.
These are not actually incompatible: NARF can use a hybrid — a CDT-shaped tree
in memory (for audit/derivation tracking) but revocation that invalidates via
epoch stamps rather than tree walks. This is closer to EROS than seL4.

**128-bit CAS for cap slots is preferred but not resolved.** On x86_64, CMPXCHG16B
provides 128-bit atomic CAS; on aarch64, `LDXP/STXP` provides 128-bit
exclusive access (but not a true CAS — it is a load-linked/store-conditional
pair). The spec lists this as an open question. It must be resolved before
Stage 3 implementation begins, because the cap slot layout (generation + index +
rights + type tag) determines the wire size of every in-memory cap.

**Cap tables are in DOMAIN_CAPS.** Any code reading or writing cap tables must
hold `enter_domain(DOMAIN_CAPS)`. The spec states this but does not specify
*where* DOMAIN_CAPS sits in the domain numbering space, whether it is the same
domain as DOMAIN_KERNEL, or whether the async executor runs in DOMAIN_CAPS or
must switch into it for every cap operation. If DOMAIN_CAPS == DOMAIN_KERNEL,
cap table isolation provides no additional protection; if they are distinct
domains, every syscall entry must domain-switch twice (to DOMAIN_CAPS for the
cap check, then to the target domain for the operation).

## Divergences from precedent

**vs. seL4:** seL4's CDT is a per-kernel singly-linked tree with O(depth)
revocation. seL4's untyped memory means the kernel itself never allocates — cap
table nodes are carved out of user-supplied untyped memory. NARF's spec doesn't
commit to this: "Task creation supplies an initial cap set (from its creator)"
implies the kernel allocates cap table nodes internally. This is simpler but
means the kernel has a heap (or a dedicated slab allocator), which is a TCB
complexity that seL4 deliberately avoids. If NARF wants a minimal TCB, adopt
seL4's untyped discipline. If developer ergonomics are higher priority, keep
an internal allocator and document the trade-off.

**vs. Fuchsia Zircon:** Fuchsia uses handles (opaque 32-bit integers) that map
to kernel objects via a per-process handle table. Rights are a bitmask stored
in the handle table entry. Revocation is per-handle, not tree-based. NARF's
`Cap<T, R>` is richer at the type level (the Rust type encodes the rights) but
Fuchsia's 32-bit handle is more compact for ABI transmission. NARF's current
plan to transmit caps as `CapSlot` indices is correct — the index is the
ABI-stable handle, the `Cap<T, R>` is the in-memory representation.

**vs. KeyKOS/EROS:** EROS's epoch revocation uses a generation counter per
capability stored *in the capability* plus an epoch table in the kernel. When
revocation occurs, the kernel increments the epoch for that capability's object;
any held `Cap` with a stale epoch is automatically invalid on next invocation.
NARF's spec has "revocation is atomic from a single CPU's view; parallel
invocations observe either pre- or post-revocation state, never torn." This is
consistent with epoch revocation but the spec doesn't commit to the epoch
mechanism. Epoch revocation is strictly preferable to CDT walk for NARF because
NARF's async model makes "parallel invocations" a real concern — multiple
async tasks may hold the same cap.

**vs. CHERI:** CHERI encodes capability metadata (bounds, permissions) in
registers at the hardware level. NARF's `Cap<T, R>` is purely software.
Long-term, CHERI compatibility would require `Cap<T, R>` to be a newtype over a
CHERI capability register value. This is a future-proofing concern, not a Stage
3 action item, but the spec should not close the door.

## Proposed spec changes

- §3 Public interface: Add **`pub fn invoke<O: CapOp<T, R>>(&self, op: O) ->
  Result<O::Output, CapError>`** to `Cap<T, R>`. The current interface shows
  `derive`, `badge`, and `revoke` but not invocation. Without an `invoke`
  method, the cap type is just a guard — it doesn't express *using* a
  capability, which is the primary operation. `CapOp` is a trait that
  encodes the operation type and validates that R includes the rights for that
  operation at compile time.

- §3 Public interface: Add **a generation/epoch field to the runtime cap slot**:
  ```rust
  pub struct CapSlot {
      index:      u32,
      generation: u32,  // matched against object epoch on invocation
  }
  ```
  This commits to epoch-based revocation without requiring a CDT walk. The
  `generation` field makes stale-cap detection O(1) and resolves the CDT-vs-
  refcount open question in favor of epoch stamps.

- §4 Invariants: Replace "Revocation is atomic from a single CPU's view"
  with **"Revocation increments the object's epoch counter (with
  acquire-release ordering); any subsequent invocation of a cap with a
  stale epoch returns `CapError::Revoked`. Callers must treat `Revoked` as
  a permanent failure — they must not retry with the same cap."** This pins
  the revocation model and removes ambiguity about "torn" state.

- §4 Invariants: Add **"DOMAIN_CAPS is domain index 1; DOMAIN_KERNEL is domain
  index 0. The executor runs in DOMAIN_KERNEL and explicitly enters DOMAIN_CAPS
  for cap-table reads/writes."** Until domain numbering is fixed, every
  subsystem that references DOMAIN_CAPS uses an undefined constant.

- §5 Architecture notes: **Resolve the 128-bit CAS question.** Decision:
  use **two adjacent 64-bit atomics** (index/rights word + generation/type word)
  protected by a seqlock rather than a single 128-bit CAS. A seqlock is
  available on both arches, avoids the `LDXP/STXP` retry-under-contention
  problem on aarch64, and is already in `lib/` scope. 128-bit CAS should be
  a future optimization, not a baseline requirement.

- §8 Open questions: **Resolve cross-task cap transfer.** Decision: "any cap
  with the Grant right" is the correct model — it mirrors seL4's badge and
  Fuchsia's handle-duplicate. Requiring a dedicated `grant` cap creates a
  meta-capability that complicates bootstrapping. Document: a cap transfer
  via the ABI submission ring requires the sender to hold Grant right; the
  kernel moves the cap (not copies) unless the sender explicitly requests
  a derived copy.

## Open invariants / cross-subsystem hazards

**capabilities ↔ frame:** `§4` mandates `enter_domain(DOMAIN_CAPS)` for cap
table access. `frame/` defines `enter_domain`. But `frame/` must call into
`capabilities/` for bootstrap (creating the initial cap set for the first task).
This is a circular dependency: `capabilities/` needs `frame::enter_domain`;
`frame::init_bsp` needs `capabilities::bootstrap`. This must be resolved by
ordering: `frame::init_bsp` calls `capabilities::bootstrap` *before* domains
are enforced (while in DOMAIN_KERNEL = 0 with full access), then enables domain
enforcement afterward. The spec says nothing about this bootstrap ordering.

**capabilities ↔ rcu:** `§6` lists `rcu/` (QSBR for cap-table lookup readers)
as a dependency. Cap-table readers are extremely frequent (every syscall does a
lookup). QSBR requires readers to register quiescent states. In an async
executor, a quiescent state is a yield point — the executor can inject the QSBR
quiescent hook at every `.await`. But if a Future holds a `Cap<T, R>` across
an await point, the cap table node cannot be freed during that await even if
the cap is revoked. The spec does not address how `rcu/` and `Cap<T, R>` lifetimes
interact. This is a subtle correctness hazard.

**capabilities ↔ abi:** `§3` says caps are passed as `CapSlot` indices (never
raw pointers) into ABI submissions. `abi/` spec says `caps: [CapSlot; 4]` per
submission entry. But `CapSlot` is defined in `capabilities/`, and `abi/` must
reference it. This creates a compile-time dependency: `abi/` depends on
`capabilities/`. If `capabilities/` is Stage 3 and `abi/` is also Stage 3, the
type must be defined in a shared `lib/` or `capabilities/` stub available
earlier. The spec does not acknowledge this.

**capabilities ↔ scheduler:** Capability-checked time-slice donation (Stage 3)
requires the scheduler to verify the donating task holds a scheduling cap. This
means `scheduler/` calls into `capabilities/` at donate time. But if the
scheduler runs in DOMAIN_KERNEL and cap tables are in DOMAIN_CAPS, every
donation decision requires a domain switch. At tens of thousands of context
switches per second, this is a real latency concern that is not budgeted.

## Additional opinionated commentary

The spec's biggest gap is the missing distinction between *type-level soundness*
and *runtime validity*. A `Cap<BlockDevice, Write>` tells the Rust compiler that
the *original derivation* was write-authorized. It says nothing about whether
the underlying `BlockDevice` object still exists, whether the cap has been
revoked, or whether the domain holding it is still trusted. Every capability
invocation must check runtime validity — the type check is a compile-time
*necessary* condition but not a *sufficient* condition for correctness.

NARF should make this explicit: `Cap<T, R>` is a *proof of prior authorization*
(compile-time), not a *currently-valid credential* (runtime). The `invoke`
method is where runtime validity is checked. Conflating the two will lead to
UAF-equivalent bugs where revoked caps are used because the compiler says the
type is correct.

The open question about "CDT vs. refcount+badges" has been studied to death in
the literature. The clear winner for an async microkernel is **epoch stamps**
(EROS-style), not CDT, because epoch checks are O(1), composable with async
quiescence, and require no tree-walk under any workload. Adopt it now, before
Stage 3 implementation begins.
