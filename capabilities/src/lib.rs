//! narf-capabilities — typed capability tokens.
//!
//! Spec: `capabilities/specification/spec.md`. Stage-3 Wave 2:
//! runtime cap table, epoch revocation, 128-bit CAS.

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

/// Spend: authority to charge against a consumable quota (e.g. CPU
/// budget, DMA-buffer allowance). Distinct from Write so the scheduler
/// can tell "may debit" apart from "may mutate the budget policy
/// itself". `scheduler/` spec §3.4 names `Cap<CpuBudget, Spend>`.
#[derive(Copy, Clone, Debug)]
pub struct Spend;

/// Invoke: authority to **execute / activate / trigger** an object's
/// operational surface. NARF's "execute" right — the classic EROS
/// "invoke a service" right with a clearer name. Held by callers that
/// want to *fire* an action without necessarily reading or mutating
/// state: bring up a CPU (`Cap<CpuLifecycle, Invoke>`), donate a
/// time-slice (`Cap<Task, Invoke>` per `scheduler/` §3.3), fire a
/// tracepoint (`Cap<Probe, Invoke>`), start/quiesce a driver
/// (`Cap<DriverHandle, Invoke>`).
///
/// We deliberately don't introduce a separate `Execute` rights marker
/// — `Invoke` is the same concept and the name avoids overloading
/// page-table NX semantics. An audit reads `Read | Write | Invoke` as
/// the orthogonal triple "observe / mutate / trigger."
#[derive(Copy, Clone, Debug)]
pub struct Invoke;

impl Sealed for Read   {}
impl Sealed for Write  {}
impl Sealed for Grant  {}
impl Sealed for Spend  {}
impl Sealed for Invoke {}

impl Rights for Read   { const BITS: u32 = 0b0_0001; }
impl Rights for Write  { const BITS: u32 = 0b0_0010; }
impl Rights for Grant  { const BITS: u32 = 0b0_0100; }
impl Rights for Spend  { const BITS: u32 = 0b0_1000; }
impl Rights for Invoke { const BITS: u32 = 0b1_0000; }

/// Authority to derive R2 from R.
pub trait SubsetOf<R: Rights>: Rights {}

impl<R: Rights> SubsetOf<R> for R {}
impl SubsetOf<Grant> for Read   {}
impl SubsetOf<Grant> for Write  {}
impl SubsetOf<Grant> for Spend  {}
impl SubsetOf<Grant> for Invoke {}

// Lattice rules. `SubsetOf<Y> for X` reads "X is a subset of Y, so
// holders of Y may `derive::<X>()`." The reverse direction is
// intentionally never declared so privilege escalation isn't
// possible through `derive`. Write and Spend stay orthogonal —
// neither can derive the other — because the scheduler wants
// "may mutate budget policy" distinct from "may debit the budget."
//
// Read ⊂ Write: a writer can always observe what it can change.
// Lets `Cap<T, Write>` derive `Cap<T, Read>` for the read-only side
// of typed APIs (drivers::ParamSlot, observability hooks).
impl SubsetOf<Write>  for Read   {}
// Read ⊂ Invoke: an invoker can always observe the object it can
// trigger. `Cap<Probe, Invoke>` (fire) → `Cap<Probe, Read>` (sample);
// `Cap<Task, Invoke>` (donate) → `Cap<Task, Read>` (inspect the donee).
impl SubsetOf<Invoke> for Read   {}
// Read ⊂ Spend: a holder of spend authority can observe the quota
// it's debiting. `Cap<CpuBudget, Spend>` → `Cap<CpuBudget, Read>`
// for budget-status readouts without giving up the debit cap.
impl SubsetOf<Spend>  for Read   {}

// ── CapSlot ─────────────────────────────────────────────────────────

/// 128-bit runtime capability slot. Atomically updatable via
/// CMPXCHG16B (x86_64) or CASP (aarch64).
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

    /// Convert to a raw u128 for atomic operations.
    #[inline]
    pub fn as_u128(self) -> u128 {
        unsafe { core::mem::transmute(self) }
    }

    /// Convert from a raw u128.
    #[inline]
    pub fn from_u128(v: u128) -> Self {
        unsafe { core::mem::transmute(v) }
    }

    /// Atomic compare-and-swap on a 128-bit slot.
    ///
    /// # Safety
    /// `ptr` must be 16-byte aligned.
    pub unsafe fn atomic_cas(ptr: *mut CapSlot, old: CapSlot, new: CapSlot) -> Result<CapSlot, CapSlot> {
        let res = unsafe { narf_arch::cas128(ptr as *mut u128, old.as_u128(), new.as_u128()) };
        match res {
            Ok(v)  => Ok(Self::from_u128(v)),
            Err(v) => Err(Self::from_u128(v)),
        }
    }

    /// Atomic load of a 128-bit slot. On x86_64 this requires CMPXCHG16B
    /// with identical old/new values because 128-bit loads are not
    /// guaranteed atomic.
    ///
    /// # Safety
    /// `ptr` must be 16-byte aligned.
    pub unsafe fn atomic_load(ptr: *const CapSlot) -> CapSlot {
        // Use CAS with dummy values to get an atomic load.
        let p = ptr as *mut u128;
        // We don't know the current value, but we can use 0 and if it
        // fails, the Err(actual) gives us the atomic snapshot.
        match unsafe { narf_arch::cas128(p, 0, 0) } {
            Ok(_)  => Self::EMPTY,
            Err(v) => Self::from_u128(v),
        }
    }
}

const _: () = assert!(core::mem::size_of::<CapSlot>()  == 16);
const _: () = assert!(core::mem::align_of::<CapSlot>() == 16);

// ── Cap<T, R> ───────────────────────────────────────────────────────

/// A typed capability token.
///
/// Wraps a 128-bit `CapSlot` with Rust-level type safety. Holding a
/// `Cap<T, R>` proves prior authorisation; `invoke` proves current
/// validity via the epoch check.
#[derive(Debug)]
pub struct Cap<T, R: Rights> {
    slot:   CapSlot,
    _tag:   PhantomData<T>,
    _right: PhantomData<R>,
}

impl<T, R: Rights> Cap<T, R> {
    /// Internal: construct a cap from a raw slot.
    ///
    /// # Safety
    /// The slot must have been minting by a TCB-authorised path and
    /// its `type_tag` and `rights` must match `T` and `R`.
    pub const unsafe fn mint(slot: CapSlot) -> Self {
        Self {
            slot,
            _tag:   PhantomData,
            _right: PhantomData,
        }
    }

    #[inline]
    pub const fn slot(&self) -> CapSlot { self.slot }

    /// Authority check: returns `Ok(())` iff the object's current epoch
    /// matches the generation snapshot in this cap. If the object has
    /// been revoked, returns `Err(Revoked)`.
    ///
    /// This is the hot-path check for every op — see `invoke`.
    #[inline]
    pub fn check_live(&self) -> Result<(), CapError> {
        match object_table::current_epoch(self.slot.index) {
            Some(e) if e == self.slot.generation => Ok(()),
            _ => Err(CapError::Revoked),
        }
    }

    #[inline]
    pub fn is_live(&self) -> bool { self.check_live().is_ok() }

    /// Invoke an operation. Wave 2 does the epoch gate; each `CapOp`
    /// supplies its own `execute` body.
    pub fn invoke<O: CapOp<T, R>>(&self, op: O) -> Result<O::Output, CapError> {
        self.check_live()?;
        op.execute(self)
    }

    /// Destroy this cap and bump the object's epoch. Every other cap
    /// referencing the same object observes `Err(Revoked)` on its next
    /// `check_live` — O(1) global invalidation per spec §4.
    pub fn revoke(self) {
        let _ = object_table::bump_epoch(self.slot.index);
    }

    /// Derive a weaker capability.
    pub fn derive<R2: Rights + SubsetOf<R>>(&self) -> Result<Cap<T, R2>, CapError> {
        self.check_live()?;
        let mut slot = self.slot;
        slot.rights = R2::BITS;
        unsafe { Ok(Cap::mint(slot)) }
    }
}

impl<T: CapType, R: Rights> Cap<T, R> {
    /// Safe mint: allocates a fresh object-table entry with
    /// `T::KIND` and produces a cap with `R::BITS`.
    pub fn bootstrap() -> Self {
        let (index, generation) = object_table::register(T::KIND);
        let slot = CapSlot::new(generation, index, R::BITS, T::KIND as u32);
        unsafe { Self::mint(slot) }
    }
}

// Manual impls to avoid T: Copy/Clone bounds.
impl<T, R: Rights> Copy for Cap<T, R> {}
impl<T, R: Rights> Clone for Cap<T, R> {
    fn clone(&self) -> Self { *self }
}

unsafe impl<T, R: Rights> Send for Cap<T, R> {}
unsafe impl<T, R: Rights> Sync for Cap<T, R> {}

// ── CapOp ───────────────────────────────────────────────────────────

pub trait CapOp<T, R: Rights>: Sized {
    type Output;
    fn execute(self, cap: &Cap<T, R>) -> Result<Self::Output, CapError>;
}

#[derive(Copy, Clone, Debug, Default)]
pub struct NoopOp;

impl<T, R: Rights> CapOp<T, R> for NoopOp {
    type Output = ();
    fn execute(self, _cap: &Cap<T, R>) -> Result<(), CapError> { Ok(()) }
}

// ── object_table ────────────────────────────────────────────────────

pub mod object_table {
    use super::{AtomicU32, CapKind, IrqSafeSpinLock, Ordering, Vec};

    struct Entry {
        epoch: AtomicU32,
        kind:  CapKind,
    }

    static TABLE: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());

    pub fn register(kind: CapKind) -> (u32, u32) {
        let mut t = TABLE.lock();
        let index = t.len() as u32;
        t.push(Entry { epoch: AtomicU32::new(1), kind });
        (index, 1)
    }

    pub fn current_epoch(index: u32) -> Option<u32> {
        let t = TABLE.lock();
        t.get(index as usize).map(|e| e.epoch.load(Ordering::Acquire))
    }

    pub fn bump_epoch(index: u32) -> Option<u32> {
        let t = TABLE.lock();
        t.get(index as usize).map(|e| e.epoch.fetch_add(1, Ordering::AcqRel) + 1)
    }

    pub fn kind_at(index: u32) -> Option<CapKind> {
        let t = TABLE.lock();
        t.get(index as usize).map(|e| e.kind)
    }

    pub fn len() -> usize { TABLE.lock().len() }
}

// ── CapKind registry ────────────────────────────────────────────────

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

    // Display
    FbScanout            = 0x00B0,

    // Audio
    AudioStream          = 0x00C0,
}

pub trait CapType: 'static {
    const KIND: CapKind;
}

#[derive(Debug)]
pub struct UnknownKind;

pub fn parse_kind(name: &str) -> Result<CapKind, UnknownKind> {
    for (k_name, k) in KIND_NAMES {
        if *k_name == name { return Ok(*k); }
    }
    Err(UnknownKind)
}

pub fn kind_name(kind: CapKind) -> &'static str {
    for (name, k) in KIND_NAMES {
        if *k == kind { return *name; }
    }
    "Unknown"
}

const KIND_NAMES: &[(&str, CapKind)] = &[
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
    ("FbScanout",           CapKind::FbScanout),
    ("AudioStream",         CapKind::AudioStream),
];

// ── Badge ───────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Badge(pub u64);

// ── CapError ────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CapError {
    Revoked,
    DomainMismatch,
    TypeMismatch,
    RightsTooWeak,
}
