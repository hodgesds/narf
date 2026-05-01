# capabilities — Specification

> Status: **v1.0** (Stage 3 design lock). Builds on v0.2's
> EROS-style epoch revocation + 128-bit slot decisions; v1 locks
> the `CapKind` registry, the cross-boundary wire format, and
> the cap-table storage layout that the rest of the framework
> consumes.

## 1. Purpose & scope

**Owns:** Per-task capability tables, the `Cap<T, R>` Rust type family,
derivation rules (how a cap with rights R creates a weaker cap with
rights R' ⊆ R), badging, revocation (CDT or refcount, TBD).

**Does NOT own:** Object lifetimes (the owning subsystem owns those),
domain placement (`memory/`), threat model narrative (`security-model/`).

## 2. Assumptions

- `memory/` provides a dedicated domain for the cap-table storage so a
  compromised driver can't scribble on it.
- Task creation supplies an initial cap set (from its creator).

## 3. Public interface

```rust
/// 128-bit runtime capability slot. Atomically updatable via
/// CMPXCHG16B (x86_64) or LDXP/STXP (aarch64).
#[repr(C, align(16))]
pub struct CapSlot {
    pub generation: u32,   // EROS-style epoch; bumped on revoke
    pub index:      u32,   // object-table index in the cap domain
    pub rights:     u32,   // Rights bitmask (runtime mirror of R)
    pub type_tag:   u32,   // compact type id for T (e.g. NodeRef, BusDevice)
}

pub struct Cap<T, R: Rights> {
    slot: CapSlot,
    _marker: PhantomData<(T, R)>,
}

pub trait Rights: Sealed { const BITS: u32; }
pub struct Read; pub struct Write; pub struct Grant;

impl<T, R: Rights> Cap<T, R> {
    pub fn derive<R2: Rights + SubsetOf<R>>(&self) -> Result<Cap<T, R2>, CapError>;
    pub fn badge(&self, badge: Badge)          -> Cap<T, R>;

    /// Authority check. Returns `Err(Revoked)` if the stored epoch is
    /// less than the current object epoch. This is the *only* valid
    /// way to access the underlying object — never dereference from
    /// the slot directly.
    pub fn invoke<O: CapOp<T, R>>(&self, op: O) -> Result<O::Output, CapError>;

    /// Destroy this cap *and* bump the object's epoch so every other
    /// cap referencing the same object observes `Err(Revoked)` on
    /// next invoke.
    pub fn revoke(self);
}

pub enum CapError { Revoked, DomainMismatch, TypeMismatch, RightsTooWeak }
```

**Epoch revocation mechanics.** Every capability-addressable object
carries a `u32` *object epoch* in its kernel-side metadata. Every
`CapSlot` carries a snapshot of the epoch at mint time. `invoke`
atomically loads the object epoch and compares to the slot; a
mismatch short-circuits to `Err(Revoked)`. `revoke(cap)` increments
the object epoch — O(1) mass invalidation of every derived + badged
cap that references it, regardless of how many tasks hold them.

**This is the single most important runtime invariant in NARF's
security model:** *holding a `Cap<T, R>` proves you were granted
the capability at some point; only `invoke` proves your access is
currently authorised.* Callers MUST NOT treat the type alone as
present authority.

Invocation: caps are passed into ABI submissions by `CapSlot`
(a 128-bit value — the generation + index pair, not just an index),
resolved by the kernel against the per-task table. The submitted
generation is compared to the current object epoch at dispatch time.

### 3.1 `CapKind` — the cap-type registry

Every capability type that crosses an external boundary (driver
manifests, the user ABI, audit attestations) is named by a single
authoritative enum maintained here. Drivers' `caps_required`
manifest field is parsed against this enum at signature-verification
time; an unknown name is a load-time error, not a runtime "cap not
held" surprise.

```rust
#[non_exhaustive]
#[repr(u32)]                          // stable wire repr; CapKind::FOO as u32 is the manifest int
pub enum CapKind {
    // Bus / device
    BusDevice            = 0x0001,
    BusDeviceP2pDma      = 0x0002,
    BusReconfigureAcs    = 0x0003,    // privileged; isolation-relaxing
    BusRegistry          = 0x0004,    // bus/ registry admin; mints BusDevice caps

    // Block / storage
    BlockDevice          = 0x0010,
    BlockDeviceBackend   = 0x0011,    // driver side (impl side of trait)
    BlockIoQueueOwn      = 0x0012,    // exclusive queue — drivers/nvme/
    Namespace            = 0x0013,    // NVMe logical namespace — drivers/nvme/

    // Network
    NetIface             = 0x0020,
    StackInstall         = 0x0021,    // userspace stack daemon attach

    // Filesystem
    FileNode             = 0x0030,
    DirNode              = 0x0031,
    MountPoint           = 0x0032,
    FsInstance           = 0x0033,    // driver side

    // IPC / ABI
    Ring                 = 0x0040,
    RingPair             = 0x0041,
    Endpoint             = 0x0042,

    // Memory / domain
    Domain               = 0x0050,    // claim a DomainId; security-sensitive
    DmaBuffer            = 0x0051,
    SharedRegion         = 0x0052,

    // Tracing / observability
    Probe                = 0x0060,
    TraceRing            = 0x0061,
    Recorder             = 0x0062,
    Pmu                  = 0x0063,
    HwCrypto             = 0x0064,
    HwTrace              = 0x0065,
    Debugger             = 0x0066,
    Diagnostics          = 0x0067,
    Watchpoint           = 0x0068,    // debug watchpoint install — observability/

    // Crypto
    Key                  = 0x0070,    // generic; concrete `Key<Alg>` is type-parametric
    KeyMgr               = 0x0071,
    Rng                  = 0x0072,
    Tpm                  = 0x0073,

    // Scheduler / power / time
    Task                 = 0x0080,
    CpuAffinity          = 0x0081,
    CpuLifecycle         = 0x0082,
    CpuBudget            = 0x0083,
    FreqHint             = 0x0084,
    Power                = 0x0085,    // system-level suspend/resume
    Timer                = 0x0086,
    DevicePm             = 0x0087,    // per-device runtime PM — power/ §5
    Governor             = 0x0088,    // pluggable frequency governor — power/ §3.2

    // RCU
    SleepableReader      = 0x0090,

    // Process / governance
    Process              = 0x00A0,
    Driver               = 0x00A1,    // driver framework administrative cap
}

pub trait CapType: 'static {          // marker trait + reflection
    const KIND: CapKind;
}

/// Parse a manifest-supplied string against the enum. Returns
/// `Err(UnknownKind)` if the name is unrecognised. Used by
/// `drivers/`'s manifest verifier and by the audit-trail formatter
/// in `process/` §6.5.
pub fn parse_kind(name: &str) -> Result<CapKind, UnknownKind>;
```

**Rules of the registry:**

- The enum is `#[non_exhaustive]` but the *integer values* are
  permanent. Adding a kind is allowed; renumbering or removing one
  is a breaking ABI change (Interface class per `process/` §4).
- Numbering scheme: high byte groups by subsystem (`0x00n` =
  bus/device, `0x01n` = block, …) so a new subsystem gets a clean
  range without disturbing existing values.
- Every `Cap<T, R>` whose `T` is one of these is required to provide
  `impl CapType for T { const KIND: CapKind = CapKind::FOO; }`. The
  `type_tag` field of `CapSlot` (§3) holds `KIND as u32` — the
  runtime check that `dispatch` uses to reject a wrong-typed cap.

**Type-parametric kinds.** A handful of cap types are
type-parametric and collapse to a single `CapKind` at the manifest
boundary:

- `Key<Alg>` → `CapKind::Key`. The algorithm is encoded in the
  cap's `Badge` and checked at `Cap::invoke` by the crypto driver.
- `Irq(n)` → `CapKind::BusDevice` badged with the IRQ number. The
  raw IRQ line is not a separately-addressable capability — it is
  a right on the owning device.
- `FnTimeShadow<D>` → `CapKind::Recorder` badged with the target
  `DomainId`. The domain-scoped shadow profiler is a per-domain
  recorder, not a new kind.

The runtime never sees the `<Alg>` / `<n>` / `<D>` parameter —
it's a Rust-level type for compile-time checking and a Badge
value for runtime dispatch. Manifests name the outer `CapKind`
and, where relevant, the badge value separately.

## 4. Invariants & safety properties

- `Cap<T, R>` cannot be constructed outside `capabilities/` — the only
  way in is derivation from an existing cap or bootstrap at task creation.
- Derivation never *increases* rights (`SubsetOf` is type-checked).
- **Type-level rights prove *prior grant*; epoch check proves *current
  validity*.** These are distinct soundness properties. The Rust type
  system enforces the first; `invoke` + object epoch enforces the second.
  Callers that dereference without going through `invoke` are in
  undefined territory.
- Revocation is atomic from a single CPU's view; parallel invocations
  observe either pre- or post-revocation state, never torn. Enforced by
  128-bit CAS on `CapSlot` (CMPXCHG16B / LDXP-STXP).
- **Epoch bump is O(1) and propagates globally.** A revoke on an object
  with N outstanding caps does not scan or walk; it increments the
  object-table entry's epoch. Next `invoke` from any cap fails.
- Cap tables are stored in the capability domain; any subsystem that
  touches them must hold `enter_domain(DOMAIN_CAPS)`.
- **Audit / derivation tracking is separate from revocation.** A
  CDT-shaped parent/child graph is maintained per-object for audit and
  for per-subtree mass revoke, but the *authority check* is always the
  epoch comparison. Hybrid model: CDT for audit, epoch for authority.

## 5. Architecture notes

Arch-neutral except for atomic-compare-and-swap width; 128-bit CAS
preferred for cap slots (see Open Questions).

## 6. Dependencies

- **Consumes:** `memory/`, `frame/`, `rcu/` (QSBR for cap-table lookup
  readers; epoch for the CDT when used).
- **Provides to:** `abi/`, every subsystem that exposes user-facing ops.

## 7. Stage assignment

Stage 1: design sketch of `Cap<T, R>` in a design doc; no runtime.
Stage 3: full cap table, derivation, revocation, ABI integration.

## 8. Cross-boundary wire format

When a `CapSlot` crosses a kernel boundary — a syscall argument,
an IPC payload, an audit log entry — it serialises to a fixed
16-byte little-endian record. This is the only legal external
representation of a cap.

```text
+0  generation : u32  LE      // slot.generation snapshot
+4  index      : u32  LE      // slot.index
+8  rights     : u32  LE      // slot.rights
+12 type_tag   : u32  LE      // slot.type_tag (CapKind as u32)
```

The wire format is **frozen as of v1.0**. Adding fields requires
a major-version bump of the cap ABI (`CAP_ABI_MAJOR`, exported
to `abi/` and `userspace/`), not a renumber. Receivers that don't
recognise a future-version cap reject it with `CapError::WireVersionTooNew`.

A cap arriving over the wire is **always** revalidated by:
1. `type_tag` lookup against the kernel's `CapKind` registry;
   unknown → `Err(TypeMismatch)`.
2. Per-task cap-table lookup at `index`; out-of-range or empty →
   `Err(Revoked)`.
3. `generation` compared to object epoch; older →
   `Err(Revoked)`.
4. `rights` AND-checked against required rights for the
   operation; insufficient → `Err(RightsTooWeak)`.
5. Domain-tag match between the requested operation's required
   domain and the calling task's active domain →
   `Err(DomainMismatch)` if mismatched.

All five steps are mandatory; skipping any is a soundness bug.

## 9. Resolved decisions

### 9.1 Cross-task transfer

**Decision:** any cap with `Grant` right may be transferred to
another task via the `Endpoint` IPC primitive (`CapKind::Endpoint`,
in `ipc/`). There is no separate "transferable" cap kind; the
`Grant` rights bit is the gate.

The receiving task gets a fresh slot in *its* cap table referring
to the same underlying object (same `index`, same `generation`).
The sending task either retains its own slot (the cap is
essentially shared) or revokes it explicitly (`Cap::revoke()`
on the sender side bumps the object epoch — affecting all
holders, including the receiver). The framework does not
distinguish "move" from "copy"; both are explicit operations
on the sender.

### 9.2 Per-object epoch storage

**Decision:** epoch lives **in-object**, in a fixed-position
header word added to the kernel-side struct. Concretely, every
type that implements `CapType` must include:

```rust
#[repr(C)]
pub struct CapHeader {
    pub epoch:    AtomicU32,
    pub kind_tag: u32,      // matches CapKind::KIND, for double-check
}
```

as the first 8 bytes of its struct. The `cap_invoke!` macro
generated by the `CapType` derive writes the field at the right
offset on object construction. Hot-path `invoke()` reads
`(*ptr).epoch.load(Acquire)` — one cache line, no indirection.

A separate audit-only epoch table is **not** maintained; if
audit needs to know "what was the previous epoch", it can
inspect the panic / revoke event log. Saves a domain hop and
the per-revoke double write.

### 9.3 `DOMAIN_CAPS` vs `DOMAIN_FRAME`

**Decision:** `DOMAIN_CAPS` (slot 1) is **distinct from**
`DOMAIN_FRAME` (slot 0). Cap-table reads/writes go through a
`enter_domain(DomainId::CAPS)` switch. The double switch on
syscall entry (FRAME → CAPS → caller-domain) is budgeted at
~50 cycles per syscall on contemporary x86_64 silicon — a real
cost but the isolation is load-bearing for the security model
(`security-model/` §4.1).

`enter_domain` is hand-rolled inline asm: `WRMSR(IA32_PKRS,
new_pkrs)` on x86_64, `MSR(SCTLR_EL1.TCF, new_tcf)` +
`MSR(GCR_EL1, new_gcr)` on aarch64. Inlined at every syscall
boundary; not a function call.

### 9.4 `FileNode` vs `NodeRef`

**Decision:** the Rust-level type is renamed to `FileNode`
(matching `CapKind::FileNode`). `NodeRef` is removed. The
filesystem spec is being updated in lockstep; this is a Stage 3
PR that touches `filesystem/`, `vfs/`, and the few callers in
`userspace/`.

`DirNode` is a distinct Rust type (also matching
`CapKind::DirNode`); the rights bitset on a `Cap<FileNode,_>`
or `Cap<DirNode,_>` distinguishes regular file / directory /
symlink semantics. Symlinks are `FileNode` with the `SYMLINK`
right tag, not a separate type — there are too few semantic
differences to justify a third type.

### 9.5 Revocation propagation guarantee

**Decision:** epoch bump is **immediately visible to all CPUs**
modulo the AtomicU32 release-acquire ordering. There is no
TLB-shootdown analogue; cap checks read the epoch atomically
and observe the new value within a few cycles (cache-line
invalidate latency).

**Edge case:** an in-flight `invoke()` that already loaded the
old epoch and is about to dereference completes with the old
authority. This is the same race as a userspace process
unmapping a page after another thread has loaded its address
into a register; the kernel does not promise serialisation
beyond the atomic load. Callers requiring strict revocation
(e.g. an emergency revoke for a compromised driver) must
also call `Driver::reset()` on the affected instance to halt
in-flight operations — same protocol the loader uses on unload
(`drivers/spec` §7.3).

### 9.6 Subtree revocation

**Decision:** the CDT (capability derivation tree) is preserved
per-object as a compact arena of `(parent_slot, child_slot)`
pairs allocated alongside cap-table rows. `Cap::revoke_subtree(self)`
walks the tree depth-first and bumps the **per-object** epoch
once at the end — not once per descendant. The tree exists
purely so audit logs and the `revoke_subtree` operation can
identify which derived caps were affected; it is **never** on
the hot path.

CDT memory is bounded: each cap derivation adds one
`(u32 parent, u32 child)` pair; a cap with N derivations costs
8 × N bytes. The arena is in `DOMAIN_CAPS`. Revocation of the
entire object frees the arena O(1).

### 9.7 Cap-table sizing

**Decision:** per-task cap tables are **growable, paged**, with
a starting size of one 4 KiB page (256 slots). Growth doubles
the table up to a per-task hard cap of 2 MiB (131072 slots).
Insertion past the cap returns `Err(CapTableFull)`.

The hard cap is a sanity bound; tasks legitimately needing more
caps should be split into multiple tasks. Trying to enlarge
past the cap is a strong signal of a leak.

The first 16 slots of every task's table are **reserved** for
bootstrap caps installed by the kernel at task creation
(boot-time process holds `Cap<RootAuthority, Grant>` at slot 0,
etc.). Slot 0 in any cap table that doesn't have a
RootAuthority is the well-known sentinel "null cap" — `invoke`
on it returns `Err(Revoked)` deterministically.

## 10. ABI versioning

`CAP_ABI_MAJOR = 1`, `CAP_ABI_MINOR = 0` exported via the
`narf-driver-sdk` re-export and consumed by the loader's
ABI-check (`drivers/spec` §4.3).

Bumping `CAP_ABI_MAJOR` (which would change the wire format
in §8 or rename a `CapKind` integer) is a flag-day reboot;
all drivers and userspace need recompilation. Such bumps are
governed by `process/` Interface-class review.

Bumping `CAP_ABI_MINOR` is additive — new `CapKind` values,
new rights bits, new operations. Existing wire-format records
still decode correctly. Old binaries see new minor as
backward-compatible.

## 11. Open questions

(none — all v0.2 questions resolved in §9)
