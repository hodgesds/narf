//! narf-capabilities — typed capability tokens.
//!
//! Spec: `capabilities/specification/spec.md`. Stage-3 Wave 0 subset:
//! the type surface needed to compile-check cap flow through the rest
//! of Stage 3. Types and enums only — no runtime cap table, no epoch
//! revocation, no 128-bit CAS yet. `invoke` / `derive` / `revoke` are
//! surface stubs that return `Err(CapError::Revoked)` until the cap
//! table lands in Wave 2.
//!
//! What exists:
//! - `CapSlot`: 128-bit `{ generation, index, rights, type_tag }` with
//!   the alignment discipline needed for CMPXCHG16B / LDXP-STXP.
//! - `Cap<T, R: Rights>`: `PhantomData`-tagged wrapper. Construction
//!   is gated behind `unsafe fn mint` — the sole TCB entry point until
//!   Wave 2 replaces it with a cap-table-backed mint path.
//! - `Rights` + `SubsetOf<R>`: type-level rights narrowing. `Read` /
//!   `Write` / `Grant` land; richer combined rights come with the
//!   subsystems that need them.
//! - `CapKind`: the full wire registry from §3.1 of the spec. Integer
//!   values are permanent (renumbering is a breaking ABI change).
//! - `CapType`: marker trait binding a Rust type to its `CapKind`.
//! - `parse_kind`: manifest-string → `CapKind` for the driver
//!   manifest verifier in `drivers/` (Stage 3 Wave 3).
//!
//! Non-goals for Wave 0:
//! - Per-task cap table (Wave 2).
//! - Epoch revocation / CDT (Wave 2).
//! - 128-bit CAS on `CapSlot` (Wave 2).
//! - `CapOp` dispatch machinery (Wave 2).
//! - Cross-task `grant` semantics (Wave 2+).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU32, Ordering};

use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

// ── Rights ──────────────────────────────────────────────────────────

mod sealed { pub trait Sealed {} }
use sealed::Sealed;

/// Runtime mirror of a type-level rights marker. `BITS` lands in the
/// `rights` field of `CapSlot` so the kernel can cross-check at dispatch.
pub trait Rights: Sealed + 'static {
    const BITS: u32;
}

/// Read access. Reflexive subset of itself; richer hierarchies land with
/// the subsystems that declare combined rights flavours.
#[derive(Copy, Clone, Debug)]
pub struct Read;

/// Write access (does not imply Read at this layer — hierarchy is the
/// subsystem's to declare).
#[derive(Copy, Clone, Debug)]
pub struct Write;

/// Grant: authority to derive + transfer further caps. Deliberately
/// orthogonal to Read/Write so an audit can tell "may hand out" apart
/// from "may touch".
#[derive(Copy, Clone, Debug)]
pub struct Grant;

impl Sealed for Read  {}
impl Sealed for Write {}
impl Sealed for Grant {}

impl Rights for Read  { const BITS: u32 = 0b001; }
impl Rights for Write { const BITS: u32 = 0b010; }
impl Rights for Grant { const BITS: u32 = 0b100; }

/// Type-level subset proof: `R: SubsetOf<Super>` means "a cap with
/// rights `Super` may derive a cap with rights `R`". Reflexive impls
/// only in Wave 0; cross-rights subsetting (e.g. `Read: SubsetOf<ReadWrite>`)
/// lands with whichever subsystem first declares a combined rights type.
pub trait SubsetOf<Super: Rights>: Rights {}
impl SubsetOf<Read>  for Read  {}
impl SubsetOf<Write> for Write {}
impl SubsetOf<Grant> for Grant {}

// ── CapSlot ─────────────────────────────────────────────────────────

/// 128-bit capability slot. Laid out for CMPXCHG16B on x86_64 and
/// LDXP/STXP on aarch64 (both demand 16-byte alignment). Field order
/// is fixed by the wire format: a cap submitted through `abi/` is just
/// the 128-bit value.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CapSlot {
    /// EROS-style epoch snapshot taken at mint time.
    pub generation: u32,
    /// Index into the capability domain's object table.
    pub index:      u32,
    /// Runtime mirror of `R: Rights` — what the type-level tag claimed.
    pub rights:     u32,
    /// Compact `CapKind as u32`; dispatch cross-checks against the
    /// callee's expected type.
    pub type_tag:   u32,
}

impl CapSlot {
    pub const EMPTY: CapSlot = CapSlot {
        generation: 0, index: 0, rights: 0, type_tag: 0,
    };

    #[inline]
    pub const fn new(generation: u32, index: u32, rights: u32, type_tag: u32) -> Self {
        Self { generation, index, rights, type_tag }
    }

    /// `true` iff every field is zero. An empty slot is never a live cap
    /// — `generation == 0` is reserved by the cap-table bootstrap.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.generation == 0 && self.index == 0 && self.rights == 0 && self.type_tag == 0
    }
}

// Layout pins: if either of these fires the `ipc/` submission format
// (which embeds a CapSlot into its slot payload) silently breaks.
const _: () = assert!(core::mem::size_of::<CapSlot>()  == 16);
const _: () = assert!(core::mem::align_of::<CapSlot>() == 16);

// ── Badge ───────────────────────────────────────────────────────────

/// Opaque per-cap tag set at mint time. Used by type-parametric kinds
/// (`Key<Alg>`, `Irq(n)`, `FnTimeShadow<D>`) to distinguish between
/// instances that share a `CapKind`. Runtime-visible; never inspected
/// by the cap-invocation fast path (left to the subsystem invoked).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Badge(pub u64);

// ── CapError ────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CapError {
    /// Object epoch advanced past this cap's generation snapshot.
    Revoked,
    /// Cap references an object in a domain the invoker can't enter.
    DomainMismatch,
    /// `type_tag` didn't match the callee's expected `CapKind`.
    TypeMismatch,
    /// Slot's `rights` didn't satisfy the op's required `Rights`.
    RightsTooWeak,
}

/// Returned by `parse_kind` when a manifest names an unrecognised kind.
/// Separate type from `CapError` because this is a load-time surface,
/// not a runtime dispatch failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UnknownKind;

// ── Cap<T, R> ───────────────────────────────────────────────────────

/// Typed capability token. The sole way to obtain one outside this crate
/// is `derive` from an existing cap (Rust-level subset proof) or `mint`
/// (unsafe, TCB-only). The Wave-2 cap table will replace `mint` with a
/// safe surface gated on a `Cap<Task, Create>`.
///
/// `Cap` is `Send`, `Sync`, `Copy`, and `Clone` unconditionally: the
/// slot is plain `Copy` metadata with no interior mutability, and `T`
/// is named purely at the type level (via `fn() -> T`, not `T`
/// directly). The Copy/Clone impls are hand-rolled because `derive`
/// would wrongly require `T: Copy`.
pub struct Cap<T, R: Rights> {
    slot: CapSlot,
    _marker: PhantomData<(fn() -> T, fn() -> R)>,
}

impl<T, R: Rights> Copy for Cap<T, R> {}
impl<T, R: Rights> Clone for Cap<T, R> {
    fn clone(&self) -> Self { *self }
}

impl<T, R: Rights> core::fmt::Debug for Cap<T, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cap").field("slot", &self.slot).finish_non_exhaustive()
    }
}

impl<T, R: Rights> Cap<T, R> {
    /// Mint a cap from a raw slot. The sole TCB entry point — Wave 2
    /// replaces it with a cap-table-backed safe constructor gated on a
    /// creator cap.
    ///
    /// # Safety
    ///
    /// The caller asserts kernel authority to mint: that `slot.rights`
    /// is genuinely `R::BITS`, that `slot.type_tag` matches the
    /// `CapType` of whatever concrete `T` is, and that the object
    /// referred to by `slot.index` exists and will not be torn down
    /// without bumping its epoch.
    #[inline]
    pub const unsafe fn mint(slot: CapSlot) -> Self {
        Self { slot, _marker: PhantomData }
    }

    #[inline]
    pub const fn slot(&self) -> CapSlot { self.slot }

    #[inline]
    pub const fn rights_bits(&self) -> u32 { self.slot.rights }

    /// Derive a cap with narrower rights. Compile-time checked via
    /// `SubsetOf`; runtime fields are copied from the parent with
    /// `rights` retagged to the narrower set.
    #[inline]
    pub fn derive<R2: SubsetOf<R>>(&self) -> Cap<T, R2> {
        let mut slot = self.slot;
        slot.rights = R2::BITS;
        // SAFETY: the parent's authority subsumes R2 by `SubsetOf`;
        // we preserve `generation` + `index` + `type_tag`, only
        // narrowing `rights`.
        unsafe { Cap::<T, R2>::mint(slot) }
    }

    /// Badge a cap with a per-instance tag. Does not change authority;
    /// receiver inspection of `slot().index` (via the owning subsystem)
    /// is how badging is checked. Wave-0 stub: returns a fresh cap with
    /// no separate badge field yet — the spec leaves badge storage open,
    /// Wave 2 pins it down.
    #[inline]
    pub const fn badge(&self, _badge: Badge) -> Self { *self }

    /// Cheap epoch check: `Ok(())` iff the referenced object still
    /// matches this cap's generation snapshot. The hot authority
    /// check for every op — see `invoke`.
    #[inline]
    pub fn check_live(&self) -> Result<(), CapError> {
        match object_table::current_epoch(self.slot.index) {
            Some(cur) if cur == self.slot.generation => Ok(()),
            _                                        => Err(CapError::Revoked),
        }
    }

    #[inline]
    pub fn is_live(&self) -> bool { self.check_live().is_ok() }

    /// Invoke an operation. Wave 2 does the epoch gate; each `CapOp`
    /// supplies its own `execute` body. Full user-ABI dispatch (via
    /// `abi/` submissions) layers over this in Wave 3.
    pub fn invoke<O: CapOp<T, R>>(&self, op: O) -> Result<O::Output, CapError> {
        self.check_live()?;
        op.execute(self)
    }

    /// Destroy this cap and bump the object's epoch. Every other cap
    /// referencing the same object (clones, badged copies, derived
    /// narrowings) observes `Err(Revoked)` on its next `check_live` —
    /// O(1) global invalidation per spec §4.
    pub fn revoke(self) {
        let _ = object_table::bump_epoch(self.slot.index);
    }
}

impl<T: CapType, R: Rights> Cap<T, R> {
    /// Safe mint: allocates a fresh object-table entry with
    /// `T::KIND` and produces a cap with `R::BITS`. Wave 2 scope: a
    /// global bootstrap path the kernel uses to seed initial caps.
    /// Wave 3 replaces this with a per-task `Cap<Task, Create>`-gated
    /// surface so userspace can't mint caps out of thin air.
    pub fn bootstrap() -> Self {
        let (index, generation) = object_table::register(T::KIND);
        let slot = CapSlot::new(generation, index, R::BITS, T::KIND as u32);
        // SAFETY: fields synthesised consistently from a fresh
        // object-table entry — the invariants listed on `mint` hold
        // by construction.
        unsafe { Self::mint(slot) }
    }
}

// SAFETY: `CapSlot` is plain metadata (no interior mutability, no raw
// pointers to per-task state). `PhantomData<fn() -> _>` is Send+Sync.
unsafe impl<T, R: Rights> Send for Cap<T, R> {}
// SAFETY: see above.
unsafe impl<T, R: Rights> Sync for Cap<T, R> {}

/// An operation that can be invoked against a `Cap<T, R>`.
/// `Cap::invoke` gates on the epoch (`check_live`) and then calls
/// `execute`; each op supplies its own body. This is deliberately
/// local to the op — there is no global `CapKind` dispatcher in
/// Wave 2 (that is the abi/ Wave-3 story once user submissions arrive).
pub trait CapOp<T, R: Rights>: Sized {
    type Output;
    fn execute(self, cap: &Cap<T, R>) -> Result<Self::Output, CapError>;
}

/// Zero-state op whose `execute` is `Ok(())`. Handy for
/// authority-only checks and smoke tests ("can this cap still do
/// anything?") — drop it through `invoke` and inspect the result.
#[derive(Copy, Clone, Debug, Default)]
pub struct NoopOp;

impl<T, R: Rights> CapOp<T, R> for NoopOp {
    type Output = ();
    fn execute(self, _cap: &Cap<T, R>) -> Result<(), CapError> { Ok(()) }
}

// ── object_table ────────────────────────────────────────────────────

/// Global registry of object epochs. Wave-2 scope:
///
/// - Append-only `Vec<Entry>` under a single `IrqSafeSpinLock`.
/// - `u32` epoch per entry, bumped on revoke; slot reuse is deferred
///   to Wave 3 (once revocation becomes frequent enough to make the
///   append-only table bloat observable).
/// - Hot-path reads still take the lock; the RCU-backed reader path
///   is a Wave-3 optimisation already flagged in the STAGE3 follow-ups.
pub mod object_table {
    use super::{AtomicU32, CapKind, IrqSafeSpinLock, Ordering, Vec};

    struct Entry {
        epoch: AtomicU32,
        kind:  CapKind,
    }

    static TABLE: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());

    /// Register a new object. Returns its table index + initial
    /// generation (always `1` — `0` is reserved for "empty slot"
    /// in the `CapSlot::EMPTY` sentinel).
    pub fn register(kind: CapKind) -> (u32, u32) {
        let mut t = TABLE.lock();
        let index = t.len() as u32;
        t.push(Entry { epoch: AtomicU32::new(1), kind });
        (index, 1)
    }

    /// Current epoch of object `index`, or `None` if the index has
    /// never been registered.
    pub fn current_epoch(index: u32) -> Option<u32> {
        let t = TABLE.lock();
        t.get(index as usize).map(|e| e.epoch.load(Ordering::Acquire))
    }

    /// Bump the epoch; returns the new value, or `None` on unknown
    /// index. Caps with the previous generation observe `Revoked`.
    pub fn bump_epoch(index: u32) -> Option<u32> {
        let t = TABLE.lock();
        t.get(index as usize).map(|e| e.epoch.fetch_add(1, Ordering::AcqRel) + 1)
    }

    /// `CapKind` of object `index`, or `None` on unknown.
    pub fn kind_at(index: u32) -> Option<CapKind> {
        let t = TABLE.lock();
        t.get(index as usize).map(|e| e.kind)
    }

    /// Size of the object table, for diagnostics.
    pub fn len() -> usize { TABLE.lock().len() }
}

// ── CapKind registry ────────────────────────────────────────────────

/// Every capability type that crosses an external boundary (driver
/// manifests, the user ABI, audit attestations) is named here. Integer
/// values are permanent; adding is allowed, renumbering is an ABI break.
/// High byte groups by subsystem: 0x00n bus, 0x01n block, 0x02n net,
/// 0x03n fs, 0x04n ipc, 0x05n memory, 0x06n tracing, 0x07n crypto,
/// 0x08n scheduler/power/time, 0x09n rcu, 0x0An governance.
#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CapKind {
    // Bus / device
    BusDevice            = 0x0001,
    BusDeviceP2pDma      = 0x0002,
    BusReconfigureAcs    = 0x0003,
    BusRegistry          = 0x0004,

    // Block / storage
    BlockDevice          = 0x0010,
    BlockDeviceBackend   = 0x0011,
    BlockIoQueueOwn      = 0x0012,
    Namespace            = 0x0013,

    // Network
    NetIface             = 0x0020,
    StackInstall         = 0x0021,

    // Filesystem
    FileNode             = 0x0030,
    DirNode              = 0x0031,
    MountPoint           = 0x0032,
    FsInstance           = 0x0033,

    // IPC / ABI
    Ring                 = 0x0040,
    RingPair             = 0x0041,
    Endpoint             = 0x0042,

    // Memory / domain
    Domain               = 0x0050,
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
    Watchpoint           = 0x0068,

    // Crypto
    Key                  = 0x0070,
    KeyMgr               = 0x0071,
    Rng                  = 0x0072,
    Tpm                  = 0x0073,

    // Scheduler / power / time
    Task                 = 0x0080,
    CpuAffinity          = 0x0081,
    CpuLifecycle         = 0x0082,
    CpuBudget            = 0x0083,
    FreqHint             = 0x0084,
    Power                = 0x0085,
    Timer                = 0x0086,
    DevicePm             = 0x0087,
    Governor             = 0x0088,

    // RCU
    SleepableReader      = 0x0090,

    // Process / governance
    Process              = 0x00A0,
    Driver               = 0x00A1,
}

/// Marker binding a Rust type to its wire `CapKind`. Every `Cap<T, R>`
/// whose `T` is registry-tracked provides `impl CapType for T`.
pub trait CapType: 'static {
    const KIND: CapKind;
}

/// Manifest-string → `CapKind`. Linear scan is fine: this runs at
/// driver-manifest signature-verification time, not on the hot path.
pub fn parse_kind(name: &str) -> Result<CapKind, UnknownKind> {
    for &(n, k) in KIND_TABLE {
        if n == name { return Ok(k); }
    }
    Err(UnknownKind)
}

/// Inverse of `parse_kind` for audit-trail formatters.
pub fn kind_name(kind: CapKind) -> &'static str {
    for &(n, k) in KIND_TABLE {
        if k as u32 == kind as u32 { return n; }
    }
    "Unknown"
}

const KIND_TABLE: &[(&str, CapKind)] = &[
    ("BusDevice",           CapKind::BusDevice),
    ("BusDeviceP2pDma",     CapKind::BusDeviceP2pDma),
    ("BusReconfigureAcs",   CapKind::BusReconfigureAcs),
    ("BusRegistry",         CapKind::BusRegistry),
    ("BlockDevice",         CapKind::BlockDevice),
    ("BlockDeviceBackend",  CapKind::BlockDeviceBackend),
    ("BlockIoQueueOwn",     CapKind::BlockIoQueueOwn),
    ("Namespace",           CapKind::Namespace),
    ("NetIface",            CapKind::NetIface),
    ("StackInstall",        CapKind::StackInstall),
    ("FileNode",            CapKind::FileNode),
    ("DirNode",             CapKind::DirNode),
    ("MountPoint",          CapKind::MountPoint),
    ("FsInstance",          CapKind::FsInstance),
    ("Ring",                CapKind::Ring),
    ("RingPair",            CapKind::RingPair),
    ("Endpoint",            CapKind::Endpoint),
    ("Domain",              CapKind::Domain),
    ("DmaBuffer",           CapKind::DmaBuffer),
    ("SharedRegion",        CapKind::SharedRegion),
    ("Probe",               CapKind::Probe),
    ("TraceRing",           CapKind::TraceRing),
    ("Recorder",            CapKind::Recorder),
    ("Pmu",                 CapKind::Pmu),
    ("HwCrypto",            CapKind::HwCrypto),
    ("HwTrace",             CapKind::HwTrace),
    ("Debugger",            CapKind::Debugger),
    ("Diagnostics",         CapKind::Diagnostics),
    ("Watchpoint",          CapKind::Watchpoint),
    ("Key",                 CapKind::Key),
    ("KeyMgr",              CapKind::KeyMgr),
    ("Rng",                 CapKind::Rng),
    ("Tpm",                 CapKind::Tpm),
    ("Task",                CapKind::Task),
    ("CpuAffinity",         CapKind::CpuAffinity),
    ("CpuLifecycle",        CapKind::CpuLifecycle),
    ("CpuBudget",           CapKind::CpuBudget),
    ("FreqHint",            CapKind::FreqHint),
    ("Power",               CapKind::Power),
    ("Timer",               CapKind::Timer),
    ("DevicePm",            CapKind::DevicePm),
    ("Governor",            CapKind::Governor),
    ("SleepableReader",     CapKind::SleepableReader),
    ("Process",             CapKind::Process),
    ("Driver",              CapKind::Driver),
];
