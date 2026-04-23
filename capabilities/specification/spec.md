# capabilities — Specification

> Status: **Outline v0.2** (Stage 1 sketch → Stage 3 full). v0.2
> commits to **EROS-style epoch revocation** over seL4 CDT walks and
> specifies the per-slot generation stamp that distinguishes prior
> authorisation from current validity.

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

## 8. Open questions

- ~~**CDT vs. refcount+badges**~~ **Resolved (v0.2):** EROS-style epoch
  revocation for authority, CDT-shape tree for audit and subtree-scoped
  mass revoke. The epoch is the hot-path check; the CDT only participates
  in explicit `revoke_subtree` operations.
- ~~64-bit vs 128-bit cap slot layout~~ **Resolved (v0.2):** 128-bit slot
  (generation + index + rights + type_tag), updated via CMPXCHG16B on
  x86_64 and LDXP/STXP on aarch64. The LDXP/STXP sequence is
  load-linked/store-conditional, not a true CAS — revoke logic must
  retry on spurious failure.
- Cross-task transfer semantics — explicit `grant` cap only, or any cap
  with Grant right?
- **Per-object epoch storage.** Where does the `u32` object epoch
  live — alongside the object, or in a dedicated epoch table in
  `DOMAIN_CAPS`? In-object is faster (one cache line for the access
  check); separate table is cleaner for revoke auditability.
- **DOMAIN_CAPS == DOMAIN_KERNEL?** If they are the same domain,
  cap-table isolation provides no additional protection. If they are
  distinct, every syscall entry must domain-switch twice. Likely
  answer: distinct; budget the double switch.
- **`FileNode` vs `NodeRef` naming.** `filesystem/` §3 declares
  `pub type FileCap = Cap<NodeRef, FileRights>` — the Rust-level
  type is `NodeRef`, but the manifest-level `CapKind::FileNode`
  names the same object (with `DirNode`/`Symlink` distinguished
  by rights flavour). Decide whether to rename the Rust type to
  `FileNode` for consistency, or note `NodeRef` as the Rust-side
  name and keep `FileNode` as the wire label. Leaning toward the
  rename; blocked on `filesystem/` spec review.
