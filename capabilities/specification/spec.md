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
pub struct Spend; pub struct Invoke; pub struct Create;

impl<T, R: Rights> Cap<T, R> {
    pub fn derive<R2: Rights + SubsetOf<R>>(&self) -> Result<Cap<T, R2>, CapError>;
    pub fn badge(&self, badge: Badge)          -> Cap<T, R>;

    /// Legacy ungated mint (SEC-B1, #1281) — removal tracked in #1538.
    pub fn bootstrap() -> Self;
    /// Creator-gated mint (§9.8): mints only when presented with a
    /// live `Cap<C, Create>` naming a Task-kind object.
    pub fn bootstrap_with<C: CapType>(creator: &Cap<C, Create>) -> Result<Self, CapError>;

    /// Authority check. Returns `Err(Revoked)` if the stored epoch is
    /// less than the current object epoch. This is the *only* valid
    /// way to access the underlying object — never dereference from
    /// the slot directly.
    ///
    /// `invoke` is also the in-kernel enforcement point for the
    /// runtime checks behind §8 steps 3–4 (SEC-B2, #1282): epoch
    /// (`Revoked`), object-table kind cross-check (`TypeMismatch`),
    /// slot `type_tag` (`TypeMismatch`), slot rights cover `R::BITS`
    /// (`RightsTooWeak`) — in that order, using one indexed
    /// metadata read (`epoch_and_kind`) without a global lock. §8 step 5
    /// (domain-tag match) is NOT checked here — it is enforced at
    /// ABI dispatch instead (#1547): the per-op required-domain
    /// table is `OpCode::required_domain` (`abi/`), and
    /// `DispatchContext::validate` compares it against the submitting
    /// task's active domain in `Dispatcher::dispatch_one` and
    /// `sys_ring_kick`.
    pub fn invoke<O: CapOp<T, R>>(&self, op: O) -> Result<O::Output, CapError>;

    /// Destroy this cap *and* bump the object's epoch so every other
    /// cap referencing the same object observes `Err(Revoked)` on
    /// next invoke.
    pub fn revoke(self);
}

impl<T: CapType, R: Rights> Cap<T, R> {
    /// The only public mint: allocates a fresh object-table entry
    /// with `T::KIND` and `R::BITS`. `Cap::mint` itself is
    /// crate-private (SEC-B5, #1293) — no external crate can
    /// construct a `Cap` from a hand-built `CapSlot`.
    pub fn bootstrap() -> Self;
}

impl<T: CapType> Cap<T, Grant> {
    /// Grant-gated cross-task transfer (§9.1). Installs `cap`'s slot
    /// into `target`'s table; returns the receiver's task-local slot
    /// number. Both caps must be live and name the same object, else
    /// `ObjectMismatch`. The sender retains its slot (sharing).
    pub fn transfer<R: Rights>(&self, cap: &Cap<T, R>, target: &mut CapTable) -> Result<u32, CapError>;
}

/// One task's capability table (§9.7). Dense slots; a position is the
/// task-local slot number. Stored entries carry the global object
/// index, so epoch revocation still invalidates all holders in O(1).
pub struct CapTable { /* 256 slots initially, doubling to 131072 */ }

impl CapTable {
    pub const INITIAL_SLOTS: usize = 256;
    pub const MAX_SLOTS: usize = 131_072;
    pub const RESERVED_SLOTS: usize = 16; // bootstrap region 0..16

    pub fn new() -> Self;
    /// Task-creation install into the reserved region (creator-held
    /// `&mut` is the gate; no prior Grant holder exists at mint).
    pub fn install_bootstrap<T: CapType, R: Rights>(&mut self, cap: &Cap<T, R>) -> Result<u32, CapError>;
    /// Task-boundary dispatch validation (§8 steps 1–4). Returns the
    /// stored entry on success; the resolved object always comes
    /// from the table, never from the presented bytes.
    pub fn lookup(&self, presented: CapSlot) -> Result<CapSlot, CapError>;
    /// Raw-slot twin of `Cap<T, Grant>::transfer` for ABI dispatch
    /// (§9.1, #1363 wiring): installs a RESOLVED entry (a sender
    /// `lookup` result, never presented bytes) into this table's
    /// general region; returns the receiver's fresh slot number.
    pub fn install_transfer(&mut self, grant_entry: CapSlot, cap_entry: CapSlot) -> Result<u32, CapError>;
}

pub enum CapError { Revoked, DomainMismatch, TypeMismatch, RightsTooWeak, CapTableFull, ObjectMismatch }
```

**Epoch revocation mechanics.** Every capability-addressable object
carries a `u32` *object epoch* in its kernel-side metadata. Every
`CapSlot` carries a snapshot of the epoch at mint time. `invoke`
atomically loads the object epoch and compares to the slot; a
mismatch short-circuits to `Err(Revoked)`. `revoke(cap)` increments
the object epoch — O(1) mass invalidation of every derived + badged
cap that references it, regardless of how many tasks hold them.

**Indexed metadata.** Object indices are never reused. A sparse four-byte
index directory publishes immutable kinds and stable leaves once; readers
perform three acquire pointer loads and an acquire epoch load, with no global
read lock or search. Kind is initialized before release publication of epoch 1
and never changes, so `epoch_and_kind` observes a coherent kind/epoch pair.
Allocation failure leaves an invalid hole and `bootstrap_with` reports
`CapTableFull`; the legacy infallible mint retains its panic policy. Published
pages are permanent. Epoch wrap reaches terminal zero and never revives an
old capability. Neither `CapSlot` nor task-local slot addressing changes.

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
    NetfilterAdmin       = 0x0022,    // namespace-scoped firewall control

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
    PmBus                = 0x0089,    // ATX 3.x telemetry — pmbus/

    // RCU
    SleepableReader      = 0x0090,

    // SCMI
    Scmi                 = 0x00B0,

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

- `Cap<T, R>` cannot be constructed outside `capabilities/` — enforced
  by the compiler, not by convention: `Cap::mint` is crate-private
  (SEC-B5, #1293), so the only ways in are derivation from an existing
  cap, the creator-gated mint (`bootstrap_with`, §9.8), the legacy
  ungated `bootstrap()` at task creation (removal tracked in #1538;
  until it lands, "bootstrap at task creation" is a convention, not an
  enforced gate — SEC-B1), or Grant-gated `Cap::transfer`. A `CapSlot`
  is ABI data, not authority — its fields and constructor stay public
  so syscall arguments can carry it, but no public constructor consumes
  a slot, so a hand-built slot cannot be re-typed into a `Cap`.
- Derivation never *increases* rights (`SubsetOf` is type-checked).
- **Type-level rights prove *prior grant*; epoch check proves *current
  validity*.** These are distinct soundness properties. The Rust type
  system enforces the first; `invoke` + object epoch enforces the second.
  `invoke` additionally cross-checks the object-table kind and the
  slot's `type_tag` / `rights` at runtime (SEC-B2, #1282, §9.9) —
  the type alone never proves a forged slot is authorised.
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
- **Per-task table entries have exactly two provenances.** An entry
  appears only via task creation (`CapTable::install_bootstrap`,
  gated by possession of `&mut` to that task's table) or via
  Grant-gated transfer (`Cap<T, Grant>::transfer`, both caps live,
  same object). There is no ungated insert, and slot numbers are
  never reused within a table's lifetime, so a stale presented slot
  can never alias a new grant. A wire slot copied across tasks
  resolves only against the submitting task's table (§8 step 2) —
  the resolved object comes from the table, never from the
  presented bytes.

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

Enforcement split, as implemented (SEC-B2, #1282, §9.9): at the ABI
boundary, `CapTable::lookup` performs steps 1–4 against the
submitting task's own table (the #1363 wiring, merged PR #1502); in
the kernel, `Cap::invoke` performs the runtime equivalents of steps
3–4 for the typed path — epoch, object-table kind cross-check,
slot `type_tag`, slot rights — before `execute` runs. Step 5
(domain-tag match) is enforced at ABI dispatch (#1547): the per-op
required-domain table is `OpCode::required_domain` (`abi/` — every
user-submittable op requires `DomainId::USERSPACE_K`, security-model/
§4.1; `DomainEnter`/`DomainExit` carry no static requirement, their
target domain being dynamic). `DispatchContext::validate` compares it against
its directly bound task authority's logical domain, after steps 1–4. The same
atomic state checks live publication and execution-image generation; a stale
or retired context completes `CapRevoked`, and mismatch completes `Forbidden`.
Scope entry/exit, suspension and migration preserve this task-owned state.
Production unbound dispatch fails closed; legacy empty-cap test fixtures do
not represent a production grant.

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

**§9.1 reading confirmed by the #1363 wiring.** "Same `index`,
same `generation`" is the *stored entry's* global object index
and generation — the receiver's slot NUMBER is fresh (general
region, ≥ 16), never the sender's number. A literal
"identical slot numbers" reading is incompatible with §9.7's
dense task-local numbering plus the 0..16 bootstrap reservation
(two tasks cannot both own slot 0 for different objects), so the
wiring follows the stored-index reading; if the maintainer
instead wants identical slot numbers, that is a spec
clarification the wiring must follow, not a code fix. The ABI
transfer op (`OpCode::CapTransfer`, `abi/` §3) is the dispatch
surface for this decision: it resolves both presented slots
against the sender's table, then installs the resolved entry
into the receiver's table via `CapTable::install_transfer`.

### 9.2 Per-object epoch storage

**Decision:** the current implementation stores the epoch and immutable kind
in a stable `object_table` entry addressed by the capability's global object
index. Wire indices still select the submitting task's own table first;
only the resolved entry supplies this global index. `CapType` implementors
do not need an intrusive object header or a generated offset accessor.

The index is split across lazily allocated 256-way directories and leaves.
Readers use three acquire pointer loads and one acquire epoch load, without
a registry search or global read lock. Kind is initialized before release
publication of epoch 1 and never changes, so a nonzero acquire epoch also
publishes a valid kind. Published metadata never moves or gets reclaimed;
indices are never reused. Failed allocation leaves an invalid hole and the
fallible mint reports `CapTableFull`. Epoch exhaustion reaches terminal zero,
which cannot be revived by another revoke or mistaken for a new object.

There is one authoritative epoch per object. Audit history remains in the
panic/revoke event log, rather than an additional epoch table or a second
write on every revocation.

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

### 9.8 Creator-gated mint (SEC-B1, #1281)

**Decision:** minting goes through a creator capability:
`Cap::bootstrap_with(&Cap<C, Create>)` mints a fresh object-table
entry only when presented with a live creator cap — a `Cap<C, Create>`
whose slot names a `Task`-kind object (`CapKind::Task`, i.e.
`scheduler::Task`) and carries the `Create` right bit. Checks, in
order: creator live (`Revoked`), creator names a Task-kind object
(`TypeMismatch`), creator slot carries the Create bit
(`RightsTooWeak` — reachable only via a hand-forged slot, since the
type system pins `R = Create`).

Why generic `C`: `capabilities/` cannot depend on `scheduler/`, so
the creator type cannot be named as `scheduler::Task`; the runtime
`type_tag` check is the gate, and in practice only `scheduler::Task`
has `KIND == CapKind::Task`.

Why `Create` has no lattice edges: `SubsetOf` has no impl into or
out of `Create` (beyond the reflexive identity, so a creator can
share its own authority for the same object). A Grant holder must
never derive mint authority, and a creator cap must never weaken
into an operational cap.

The minted cap is independent of the creator: revoking the creator
does not revoke caps it minted, and minting does not consume the
creator (sharing semantics, like §9.1 transfer).

Composition with the #1363 wiring (merged PR #1502): a task creator
mints a task's initial caps with `bootstrap_with` and installs them
via `CapTable::install_bootstrap`. No second install path, no second
table, no change to `derive` / `transfer` / `invoke` / `revoke` or
to the semantics of any existing granted cap.

Remainders (tracked in #1538): the root creator's boot provenance
(which boot path mints the first `Cap<Task, Create>` and where it is
held), migration of all 807 `::bootstrap()` call sites (285 files at
1307de44), and removal of the ungated `bootstrap()`. Until removal
lands, the gate is a mechanism, not an enforcement: `bootstrap()`
still mints without authority.

### 9.9 Invoke-time kind/rights checks (SEC-B2, #1282)

**Decision:** `Cap::invoke` verifies more than the epoch before
`execute` runs. Checks, in order: epoch against the slot's
generation snapshot (`Revoked` — checked first, preserving the
pre-#1282 observable behaviour that a revoked cap reports
`Revoked` regardless of its other fields), object-table kind
equals `T::KIND` (`TypeMismatch`), slot `type_tag` equals
`T::KIND` (`TypeMismatch`), slot `rights` covers `R::BITS`
(`RightsTooWeak`).

Why both a kind check and a `type_tag` check: the slot-local
`type_tag` compare cannot catch a slot whose `type_tag` says `T`
but whose index aliases a live object of a different kind; only
the object-table cross-check (`kind_at(index) == T::KIND`)
catches that forgery. The two `TypeMismatch` sources are distinct
forgeries and are pinned separately in fixtures.

The epoch and immutable kind come from one stable indexed metadata read
(`object_table::epoch_and_kind`), with acquire publication and no global read
lock. The type-tag and rights checks remain same-slot integer comparisons.
`check_live` retains its epoch-only contract for derive/transfer/bootstrap,
which perform their own type checks where needed.

Why no domain check here: neither the cap nor the object-table
entry records a domain, the wire format is frozen (§8), and no
per-op required-domain table exists in `capabilities/` — so there
is nothing authoritative for `invoke` to compare a caller domain
against, and `capabilities/` cannot name the `DomainId` type
(namespace owned by security-model/ §4.1). The step-5 check belongs
at dispatch, where the calling task's active domain is known, and
it is implemented there (#1547): `OpCode::required_domain` (`abi/`)
is the per-op table, the directly bound task authority is
the caller-domain source, and `DispatchContext::validate` enforces the
match in `Dispatcher::dispatch_one` and `sys_ring_kick`.
`DomainMismatch` is therefore produced by dispatch, not by this
path.

Composition with the #1363 wiring (merged PR #1502): that PR owns
`CapTable::lookup` and the ABI dispatch gate (§8 steps 1–4 at the
boundary); this change owns the in-kernel typed path and does not
touch `lookup`, `install_transfer`, the scheduler wiring, or any
`invoke` call site — every existing caller passes a legitimately
minted or derived cap, whose slot already carries the right kind,
type tag, and rights. Composition with the #1281 mechanism (merged
PR #1542): `bootstrap_with`-minted caps carry the same slot
shape, so they pass the new legs unchanged. Note: #1542 landed first with §9.8 (creator-gated mint), so this section is §9.9.

Remainders: the `DomainEnter`/`DomainExit` dynamic target-domain leg
(their target domain is named by `caps[0]`, a `Cap<Domain>` — no
`Domain` cap type and no dispatch arm exist yet, so both ops still
complete `InvalidOp`). Task-owned logical scope tracking is implemented in
the scheduler, separate from temporary trap domain neutralization. Performance
claims require verification/ §8; kernel tests alone establish no timings.

Perf class (b) — hot path, unmeasured, with measurement plan:
`check_live` is documented as "the hot-path check for every op."
Measure per-`invoke` cycle cost of epoch-only vs
epoch+kind+rights on real hardware (x86_64 + aarch64 CI runners,
NOT TCG — TCG numbers are never perf claims), across a JIT-alloc
loop and an audio-stream `invoke` loop. Regression bar: no
measurable regression in `invoke` throughput beyond noise, since
the added checks are same-cache-line integer compares once the
kind table is consulted; the single-lock design above is what
keeps the bar attainable — if measurement shows the kind lookup
still costs a lock acquisition beyond the old path, the table
must become lock-free-read first. No measurement was possible in
this lane (no real hardware); the plan is the explicit close
condition for #1282.

Remainders: §8 step 5 is implemented at dispatch (#1547); the
remaining items are the `DomainEnter`/`DomainExit` dynamic
target-domain leg and the step-5 measurement plan, both listed
above.

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

- **Scoped creators.** Should a creator mint only certain `CapKind`s
  (e.g. a driver loader that may mint `Driver`-kind caps but not
  `Task`-kind ones)? The §9.8 mechanism is all-or-nothing mint
  authority; per-kind scoping is future work for the migration lane
  (#1538) or a follow-on.
