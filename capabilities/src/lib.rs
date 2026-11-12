//! narf-capabilities — typed capability tokens.
//!
//! Spec: `capabilities/specification/spec.md`. Stage-3 Wave 2:
//! runtime cap table, epoch revocation, 128-bit CAS.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

mod tests;

use core::marker::PhantomData;

use alloc::vec::Vec;

// ── Rights ──────────────────────────────────────────────────────────

mod sealed {
    pub trait Sealed {}
}
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

impl Sealed for Read {}
impl Sealed for Write {}
impl Sealed for Grant {}
impl Sealed for Spend {}
impl Sealed for Invoke {}

/// Create: authority to **mint fresh capabilities**. Held only by the
/// kernel's creator (boot / task creation) as `Cap<Task, Create>`
/// (`scheduler::Task`, `CapKind::Task`) and presented to
/// `Cap::bootstrap_with` — the creator-gated mint (SEC-B1, #1281;
/// the Stage 4 deferred item, `capabilities/` §9.8).
///
/// `Create` is deliberately orthogonal in the `SubsetOf` lattice: it
/// has NO edges to or from any other right (beyond the reflexive
/// identity, so a creator can share its own authority via
/// `derive::<Create>()` for the same object). In particular there
/// is no `SubsetOf<Grant> for Create` — a Grant holder for an object
/// must never be able to derive mint authority over it — and no
/// `SubsetOf<Create> for X` — a creator cap cannot be weakened into
/// an operational cap; it exists only to gate minting.
#[derive(Copy, Clone, Debug)]
pub struct Create;

impl Sealed for Create {}

impl Rights for Read {
    const BITS: u32 = 0b0_0001;
}
impl Rights for Write {
    const BITS: u32 = 0b0_0010;
}
impl Rights for Grant {
    const BITS: u32 = 0b0_0100;
}
impl Rights for Spend {
    const BITS: u32 = 0b0_1000;
}
impl Rights for Invoke {
    const BITS: u32 = 0b1_0000;
}
impl Rights for Create {
    const BITS: u32 = 0b10_0000;
}

/// Authority to derive R2 from R.
pub trait SubsetOf<R: Rights>: Rights {}

impl<R: Rights> SubsetOf<R> for R {}
impl SubsetOf<Grant> for Read {}
impl SubsetOf<Grant> for Write {}
impl SubsetOf<Grant> for Spend {}
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
impl SubsetOf<Write> for Read {}
// Read ⊂ Invoke: an invoker can always observe the object it can
// trigger. `Cap<Probe, Invoke>` (fire) → `Cap<Probe, Read>` (sample);
// `Cap<Task, Invoke>` (donate) → `Cap<Task, Read>` (inspect the donee).
impl SubsetOf<Invoke> for Read {}
// Read ⊂ Spend: a holder of spend authority can observe the quota
// it's debiting. `Cap<CpuBudget, Spend>` → `Cap<CpuBudget, Read>`
// for budget-status readouts without giving up the debit cap.
impl SubsetOf<Spend> for Read {}

// Create ⊂ nothing, nothing ⊂ Create: the mint authority has no
// lattice edges at all (beyond the reflexive identity, so a creator
// can share its own authority for the same object). A Grant holder
// must never derive mint authority, and a creator cap must never
// weaken into an operational cap — see `Create`'s docs and spec §9.8.

// ── CapSlot ─────────────────────────────────────────────────────────

/// 128-bit runtime capability slot. Atomically updatable via
/// CMPXCHG16B (x86_64) or CASP (aarch64).
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CapSlot {
    /// EROS-style epoch snapshot taken at mint time.
    pub generation: u32,
    /// Index into the capability domain's object table.
    pub index: u32,
    /// Runtime mirror of `R: Rights` — what the type-level tag claimed.
    pub rights: u32,
    /// Compact `CapKind as u32`; dispatch cross-checks against the
    /// callee's expected type.
    pub type_tag: u32,
}

impl CapSlot {
    pub const EMPTY: CapSlot = CapSlot {
        generation: 0,
        index: 0,
        rights: 0,
        type_tag: 0,
    };

    #[inline]
    pub const fn new(generation: u32, index: u32, rights: u32, type_tag: u32) -> Self {
        Self {
            generation,
            index,
            rights,
            type_tag,
        }
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
        // SAFETY: source and destination have identical size and a compatible layout.
        unsafe { core::mem::transmute(self) }
    }

    /// Convert from a raw u128.
    #[inline]
    pub fn from_u128(v: u128) -> Self {
        // SAFETY: source and destination have identical size and a compatible layout.
        unsafe { core::mem::transmute(v) }
    }

    /// Atomic compare-and-swap on a 128-bit slot.
    ///
    /// # Safety
    /// `ptr` must be 16-byte aligned.
    pub unsafe fn atomic_cas(
        ptr: *mut CapSlot,
        old: CapSlot,
        new: CapSlot,
    ) -> Result<CapSlot, CapSlot> {
        // SAFETY: the pointer is non-null, aligned, and points to a live value for this access.
        let res = unsafe { narf_arch::cas128(ptr as *mut u128, old.as_u128(), new.as_u128()) };
        match res {
            Ok(v) => Ok(Self::from_u128(v)),
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
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        match unsafe { narf_arch::cas128(p, 0, 0) } {
            Ok(_) => Self::EMPTY,
            Err(v) => Self::from_u128(v),
        }
    }
}

const _: () = assert!(core::mem::size_of::<CapSlot>() == 16);
const _: () = assert!(core::mem::align_of::<CapSlot>() == 16);

// ── Cap<T, R> ───────────────────────────────────────────────────────

/// A typed capability token.
///
/// Wraps a 128-bit `CapSlot` with Rust-level type safety. Holding a
/// `Cap<T, R>` proves prior authorisation; `invoke` proves current
/// validity via the epoch check.
#[derive(Debug)]
pub struct Cap<T, R: Rights> {
    slot: CapSlot,
    _tag: PhantomData<T>,
    _right: PhantomData<R>,
}

impl<T, R: Rights> Cap<T, R> {
    /// In-crate constructor from a raw slot. Deliberately NOT public
    /// (SEC-B5, #1293): `Cap<T, R>` cannot be constructed outside
    /// `capabilities/` — the only public entry points are
    /// `Cap::bootstrap` (fresh object-table entry),
    /// `Cap::derive` (weaken a live cap), and `Cap::transfer`
    /// (Grant-gated cross-table install). A `CapSlot` on its own
    /// carries no authority: it is ABI data, and without this
    /// constructor it cannot be re-typed into a `Cap`.
    ///
    /// # Safety
    /// The slot must have been minted by a TCB-authorised path and
    /// its `type_tag` and `rights` must match `T` and `R`.
    const unsafe fn mint(slot: CapSlot) -> Self {
        Self {
            slot,
            _tag: PhantomData,
            _right: PhantomData,
        }
    }

    #[inline]
    pub const fn slot(&self) -> CapSlot {
        self.slot
    }

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
    pub fn is_live(&self) -> bool {
        self.check_live().is_ok()
    }

    /// Invoke an operation. SEC-B2 (#1282): the epoch gate alone is
    /// not enough — a hand-forged slot (reachable via unsafe
    /// `Cap::mint`, the only way to build a `Cap` outside the
    /// mint/derive/transfer paths) could name a live object of the
    /// wrong kind or claim rights it was never granted, and the old
    /// epoch-only check would have run `execute` anyway. Checks, in
    /// order:
    /// 1. Epoch: the object's current epoch equals the slot's
    ///    generation snapshot, else `Revoked` (checked first, so a
    ///    revoked cap reports `Revoked` regardless of its other
    ///    fields — the pre-#1282 observable behaviour).
    /// 2. Object kind: `object_table`'s recorded kind for the slot's
    ///    index equals `T::KIND`, else `TypeMismatch`. This is the
    ///    cross-check a slot-local `type_tag` compare cannot do: it
    ///    catches a slot whose `type_tag` says `T` but whose index
    ///    aliases a different-kind object.
    /// 3. Slot type tag: `slot.type_tag == T::KIND`, else
    ///    `TypeMismatch`.
    /// 4. Slot rights: `slot.rights` covers `R::BITS`, else
    ///    `RightsTooWeak`.
    ///
    /// Steps 1–2 run as a single object-table read
    /// (`epoch_and_kind`): one stable indexed metadata read per
    /// `invoke`; immutable kind publication adds no lock. Steps 3–4 are same-slot
    /// integer compares, no lock, no table touch.
    ///
    /// What this does NOT check: the caller's domain (spec §8
    /// step 5). Neither the cap nor the object-table entry records
    /// a domain, and no per-op required-domain table exists here —
    /// so there is nothing authoritative for `invoke` to compare
    /// against. That check belongs at dispatch, where the calling
    /// task's domain is known, and it is implemented there:
    /// `OpCode::required_domain` (`abi/`) is the per-op table and
    /// `DispatchContext::validate` enforces it in `Dispatcher::dispatch_one`
    /// and `sys_ring_kick` (#1547). `DomainMismatch` therefore
    /// remains unproduced by this path, but is produced by dispatch.
    pub fn invoke<O: CapOp<T, R>>(&self, op: O) -> Result<O::Output, CapError>
    where
        T: CapType,
    {
        let (epoch, kind) =
            object_table::epoch_and_kind(self.slot.index).ok_or(CapError::Revoked)?;
        if epoch != self.slot.generation {
            return Err(CapError::Revoked);
        }
        if kind != T::KIND {
            return Err(CapError::TypeMismatch);
        }
        if self.slot.type_tag != T::KIND as u32 {
            return Err(CapError::TypeMismatch);
        }
        if self.slot.rights & R::BITS != R::BITS {
            return Err(CapError::RightsTooWeak);
        }
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
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        unsafe { Ok(Cap::mint(slot)) }
    }
}

impl<T: CapType> Cap<T, Grant> {
    /// Grant-gated cross-task transfer (spec §9.1, issue #1283).
    ///
    /// Installs `cap`'s slot into `target`'s table and returns the
    /// receiver's task-local slot number. Both caps must be live and
    /// must name the *same object* (`slot.index` equal): a Grant cap
    /// for object A authorises handing out caps for object A only,
    /// never for an unrelated object B. The sender retains its own
    /// slot — §9.1 sharing semantics; an explicit `revoke()` is the
    /// only move-like operation, and it invalidates all holders via
    /// the epoch bump.
    ///
    /// This is the only cross-table install path besides
    /// `CapTable::install_bootstrap` (task creation). There is no
    /// ungated insert: a table entry always traces to a live Grant
    /// cap or to a kernel mint at task creation.
    pub fn transfer<R: Rights>(
        &self,
        cap: &Cap<T, R>,
        target: &mut CapTable,
    ) -> Result<u32, CapError> {
        self.check_live()?;
        cap.check_live()?;
        if self.slot.index != cap.slot.index {
            return Err(CapError::ObjectMismatch);
        }
        if cap.slot.type_tag != T::KIND as u32 {
            return Err(CapError::TypeMismatch);
        }
        target.install_general(cap.slot)
    }
}

impl<T: CapType, R: Rights> Cap<T, R> {
    /// Legacy ungated mint: allocates a fresh object-table entry with
    /// `T::KIND` and produces a cap with `R::BITS`.
    ///
    /// This is the SEC-B1 hole (#1281): any caller can mint any cap,
    /// so until it is removed every `Cap` parameter at a trust
    /// boundary is advisory only. New code must use
    /// [`bootstrap_with`]; removal of this
    /// function once all call sites migrate is tracked in #1538.
    pub fn bootstrap() -> Self {
        let (index, generation) = object_table::register(T::KIND);
        let slot = CapSlot::new(generation, index, R::BITS, T::KIND as u32);
        // SAFETY: the operation upholds its documented invariant (see surrounding context).
        unsafe { Self::mint(slot) }
    }

    /// Creator-gated mint (SEC-B1 mechanism, #1281; the Stage 4
    /// deferred item, spec §9.8). Mints a fresh object-table entry
    /// for `T` with `R::BITS` — but only when the caller presents a
    /// live creator capability: a `Cap<C, Create>` whose slot names
    /// a `Task`-kind object (`CapKind::Task`) and carries the
    /// `Create` right bit. An ungated caller cannot mint through
    /// this path: there is no other way to obtain the creator
    /// argument, and `Create` is not derivable from any other right
    /// (spec §3 lattice — no `SubsetOf` edges into `Create`).
    ///
    /// The creator type is generic (`C: CapType`) rather than
    /// naming `scheduler::Task` because `capabilities/` cannot
    /// depend on `scheduler/`; the runtime `type_tag` check is the
    /// gate, and in practice only `scheduler::Task` has
    /// `KIND == CapKind::Task`. Checks, in order: creator live
    /// (`check_live`, else `Revoked`), creator names a Task-kind
    /// object (else `TypeMismatch`), creator slot carries the
    /// `Create` bit (else `RightsTooWeak` — reachable only via a
    /// hand-forged slot, since the type system pins `R = Create`).
    ///
    /// The minted cap is independent of the creator: revoking the
    /// creator does not revoke caps it minted (the creator
    /// authorises the mint; it does not own the minted object),
    /// and the creator itself is unaffected (sharing semantics,
    /// like `transfer`).
    ///
    /// Composes with the #1363 wiring (merged PR #1502): a task
    /// creator mints a task's initial caps with this function and
    /// installs them via `CapTable::install_bootstrap` — this
    /// function adds no second install path and no second table.
    pub fn bootstrap_with<C: CapType>(creator: &Cap<C, Create>) -> Result<Self, CapError> {
        creator.check_live()?;
        if creator.slot().type_tag != CapKind::Task as u32 {
            return Err(CapError::TypeMismatch);
        }
        if creator.slot().rights & Create::BITS == 0 {
            return Err(CapError::RightsTooWeak);
        }
        let (index, generation) = object_table::try_register(T::KIND)?;
        let slot = CapSlot::new(generation, index, R::BITS, T::KIND as u32);
        // SAFETY: the slot was just registered on the TCB-authorised
        // creator-gated path and its type_tag/rights match T and R.
        unsafe { Ok(Self::mint(slot)) }
    }
}

// Manual impls to avoid T: Copy/Clone bounds.
impl<T, R: Rights> Copy for Cap<T, R> {}
impl<T, R: Rights> Clone for Cap<T, R> {
    fn clone(&self) -> Self {
        *self
    }
}

// SAFETY: the operation upholds its documented invariant (see surrounding context).
unsafe impl<T, R: Rights> Send for Cap<T, R> {}
// SAFETY: the operation upholds its documented invariant (see surrounding context).
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
    fn execute(self, _cap: &Cap<T, R>) -> Result<(), CapError> {
        Ok(())
    }
}

// ── object_table ────────────────────────────────────────────────────

pub mod object_table;

// ── CapTable: per-task capability tables ────────────────────────────
//
// Spec §9.7 sizing, spec §8 dispatch validation, spec §9.1 transfer.
// This is the #1283 fix: before this type existed, every cap resolved
// against the single global object table, so a copied (index,
// generation) pair was usable by any holder. A `CapTable` binds slots
// to one task: slot numbers are meaningful only within their table,
// and the only ways an entry appears are task creation
// (`install_bootstrap`) and Grant-gated `transfer`.
//
// Two index namespaces — read carefully, they are the whole design:
// - A table POSITION (0..len) is the task-local slot number. At the
//   task boundary (ABI `Submission` caps, spec §8 step 2) the
//   presented `CapSlot.index` IS this position: dispatch looks the
//   entry up in the submitting task's table, never in a global table.
// - The STORED entry's `index` field is the global object-table
//   index (the same index an in-kernel `Cap` carries). The epoch
//   check runs against that global index, so `revoke()` still
//   invalidates every table entry for the object in O(1).
// A copied wire slot therefore resolves only against the submitter's
// own table: presenting another task's bytes yields the submitter's
// own entry at that position (or `Revoked` for an empty one) — never
// the victim's object, because the resolved object comes from the
// table, never from the presented bytes.
//
// `CapTable` is deliberately NOT internally synchronized: it is a
// value owned by task state, and the owning subsystem (task
// creation / scheduler / ABI dispatch) serializes access to that
// state. Tables live in the capability domain's memory (spec §4);
// holding `&mut CapTable` is the authority to modify that task's
// table, which is why `install_bootstrap` is a method on the table
// rather than a free function.
//
// Slots are never freed or reused within a table's lifetime: entries
// for revoked objects linger as dead entries (bounded by MAX_SLOTS).
// Reuse would let a stale presented slot alias a new grant, so the
// install cursors are monotonic.

/// One task's capability table (spec §9.7).
#[derive(Debug)]
pub struct CapTable {
    /// Dense slots; position = task-local slot number. `EMPTY` = never
    /// installed (or, at position 0, the null-cap sentinel).
    slots: Vec<CapSlot>,
    /// Next free position in the bootstrap region (0..RESERVED_SLOTS).
    next_bootstrap: usize,
    /// Next free position in the general region (RESERVED_SLOTS..).
    next_general: usize,
}

impl CapTable {
    /// Starting size: one 4 KiB page of 16-byte slots (spec §9.7).
    pub const INITIAL_SLOTS: usize = 256;
    /// Per-task hard cap: 2 MiB of slots (spec §9.7). Installing past
    /// this returns `Err(CapTableFull)`.
    pub const MAX_SLOTS: usize = 131_072;
    /// First 16 slots are reserved for bootstrap caps installed by
    /// the kernel at task creation (spec §9.7). General installs
    /// (transfer) never land here.
    pub const RESERVED_SLOTS: usize = 16;

    /// An empty table: `INITIAL_SLOTS` empty slots. Position 0 is the
    /// null-cap sentinel — `lookup` on it returns `Err(Revoked)`
    /// deterministically — unless task creation installs a bootstrap
    /// cap there.
    pub fn new() -> Self {
        Self {
            slots: alloc::vec![CapSlot::EMPTY; Self::INITIAL_SLOTS],
            next_bootstrap: 0,
            next_general: Self::RESERVED_SLOTS,
        }
    }

    /// Current capacity in slots (grows by doubling up to MAX_SLOTS).
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Install a bootstrap cap into the reserved region (task
    /// creation path, spec §2: the creator supplies the initial cap
    /// set). Returns the task-local slot number. The cap must be
    /// live and its type tag must match `T::KIND`; the reserved
    /// region holds at most `RESERVED_SLOTS` entries, past that this
    /// returns `Err(CapTableFull)`.
    ///
    /// This is intentionally NOT Grant-gated: the kernel mints the
    /// first caps of a task's life (there is no prior Grant holder
    /// to gate on). The gate here is possession of `&mut self` —
    /// only the task's creator/manager ever holds it.
    pub fn install_bootstrap<T: CapType, R: Rights>(
        &mut self,
        cap: &Cap<T, R>,
    ) -> Result<u32, CapError> {
        cap.check_live()?;
        if cap.slot.type_tag != T::KIND as u32 {
            return Err(CapError::TypeMismatch);
        }
        if self.next_bootstrap >= Self::RESERVED_SLOTS {
            return Err(CapError::CapTableFull);
        }
        let at = self.next_bootstrap;
        self.slots[at] = cap.slot;
        self.next_bootstrap += 1;
        Ok(at as u32)
    }

    /// General-region install: the `transfer` path. Not public —
    /// cross-table installs go through `Cap<T, Grant>::transfer`,
    /// which is where the Grant gate lives.
    fn install_general(&mut self, slot: CapSlot) -> Result<u32, CapError> {
        if self.next_general == self.slots.len() {
            if self.slots.len() >= Self::MAX_SLOTS {
                return Err(CapError::CapTableFull);
            }
            let new_len = (self.slots.len() * 2).min(Self::MAX_SLOTS);
            self.slots.resize(new_len, CapSlot::EMPTY);
        }
        let at = self.next_general;
        self.slots[at] = slot;
        self.next_general += 1;
        Ok(at as u32)
    }

    /// Task-boundary dispatch validation (spec §8 steps 1–4; step 5's
    /// domain-tag match stays dispatch-side, where the calling
    /// task's domain is known).
    ///
    /// `presented.index` is the task-local slot number (the position
    /// in THIS table). Validation, in spec order:
    /// 1. Position in range and entry non-empty, else `Revoked`
    ///    (out-of-range or the null-cap sentinel).
    /// 2. `presented.type_tag` matches the entry's, else
    ///    `TypeMismatch`.
    /// 3. `presented.generation` matches the entry's, and the
    ///    entry's global object epoch still equals it, else
    ///    `Revoked` (a `revoke()` anywhere invalidates all holders).
    /// 4. `presented.rights` must be a subset of the entry's,
    ///    else `RightsTooWeak`. Presenting fewer rights than held
    ///    is a voluntary downgrade for this op and is allowed.
    ///
    /// On success returns the stored entry — the resolved global
    /// object slot dispatch should use. The resolved object always
    /// comes from the table, never from the presented bytes.
    pub fn lookup(&self, presented: CapSlot) -> Result<CapSlot, CapError> {
        let entry = self
            .slots
            .get(presented.index as usize)
            .ok_or(CapError::Revoked)?;
        if entry.is_empty() {
            return Err(CapError::Revoked);
        }
        if presented.type_tag != entry.type_tag {
            return Err(CapError::TypeMismatch);
        }
        if presented.generation != entry.generation {
            return Err(CapError::Revoked);
        }
        match object_table::current_epoch(entry.index) {
            Some(e) if e == entry.generation => {}
            _ => return Err(CapError::Revoked),
        }
        if (presented.rights & !entry.rights) != 0 {
            return Err(CapError::RightsTooWeak);
        }
        Ok(*entry)
    }

    /// Grant-gated cross-task install for the ABI path (spec §9.1,
    /// #1363 wiring). The typed `Cap<T, Grant>::transfer` is the
    /// in-kernel form; this is its raw-slot twin for dispatch, which
    /// only ever sees wire `CapSlot`s.
    ///
    /// `grant_entry` and `cap_entry` must be RESOLVED entries — the
    /// return values of the sender table's `lookup` on the presented
    /// slots — never the presented bytes themselves. Checks, in order:
    /// the resolved grant entry carries the `Grant` right, both
    /// entries name the same object (`index` equal — the stored
    /// global object index, per the §9.1 reading the #1283 mechanism
    /// chose and this wiring confirms: the receiver's slot NUMBER is
    /// fresh, only the stored index/generation are shared), and both
    /// entries carry the same `type_tag`.
    ///
    /// On success installs the resolved cap entry into this table's
    /// general region and returns the receiver's fresh task-local
    /// slot number (≥ `RESERVED_SLOTS`). The sender retains its slot
    /// (sharing semantics); `revoke()` is the only move-like
    /// operation. A revoke landing between the sender-side `lookup`
    /// and this install yields a dead entry: a later `lookup` on it
    /// fails `Revoked` via the epoch check, exactly like the typed
    /// transfer's check-then-install race (§9.5).
    pub fn install_transfer(
        &mut self,
        grant_entry: CapSlot,
        cap_entry: CapSlot,
    ) -> Result<u32, CapError> {
        if grant_entry.rights & Grant::BITS == 0 {
            return Err(CapError::RightsTooWeak);
        }
        if grant_entry.index != cap_entry.index {
            return Err(CapError::ObjectMismatch);
        }
        if grant_entry.type_tag != cap_entry.type_tag {
            return Err(CapError::TypeMismatch);
        }
        self.install_general(cap_entry)
    }
}

impl Default for CapTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── CapKind registry ────────────────────────────────────────────────

#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CapKind {
    // Bus / device
    BusDevice = 0x0001,
    BusDeviceP2pDma = 0x0002,
    BusReconfigureAcs = 0x0003,
    BusRegistry = 0x0004,

    // Block / storage
    BlockDevice = 0x0010,
    BlockDeviceBackend = 0x0011,
    BlockIoQueueOwn = 0x0012,
    Namespace = 0x0013,

    // Network
    NetIface = 0x0020,
    StackInstall = 0x0021,
    NetfilterAdmin = 0x0022,

    // Filesystem
    FileNode = 0x0030,
    DirNode = 0x0031,
    MountPoint = 0x0032,
    FsInstance = 0x0033,

    // IPC / ABI
    Ring = 0x0040,
    RingPair = 0x0041,
    Endpoint = 0x0042,

    // Memory / domain
    Domain = 0x0050,
    DmaBuffer = 0x0051,
    SharedRegion = 0x0052,
    /// Authority to make a mapping executable that was previously
    /// writable — the JIT codegen flip. `memory/src/wx.rs` has described
    /// this capability since it was written ("the JIT exception expressed
    /// as a *capability* not a per-process bit, so the privilege is named
    /// and revocable"); this is the `CapKind` that finally backs it.
    ///
    /// Deliberately a *memory* capability rather than a BPF one: any JIT
    /// needs it, and a userspace JS engine reaching it through `mprotect`
    /// is the same authority as the BPF JIT reaching it through
    /// `bpf_text::seal`.
    Jit = 0x0053,
    /// `narf_io::sg::PageList`: a list of page frames one DMA payload spans.
    DmaPageList = 0x0054,

    // Tracing / observability
    Probe = 0x0060,
    TraceRing = 0x0061,
    Recorder = 0x0062,
    Pmu = 0x0063,
    HwCrypto = 0x0064,
    HwTrace = 0x0065,
    Debugger = 0x0066,
    Diagnostics = 0x0067,
    Watchpoint = 0x0068,

    // Crypto
    Key = 0x0070,
    KeyMgr = 0x0071,
    Rng = 0x0072,
    Tpm = 0x0073,
    Spdm = 0x0074,

    // Scheduler / power / time
    Task = 0x0080,
    CpuAffinity = 0x0081,
    CpuLifecycle = 0x0082,
    CpuBudget = 0x0083,
    FreqHint = 0x0084,
    Power = 0x0085,
    Timer = 0x0086,
    DevicePm = 0x0087,
    Governor = 0x0088,
    PmBus = 0x0089,

    // RCU
    SleepableReader = 0x0090,

    // Platform Management
    Scmi = 0x0091,

    // Process / governance
    Process = 0x00A0,
    Driver = 0x00A1,

    // Display
    FbScanout = 0x00B0,

    // Audio
    AudioStream = 0x00C0,

    // Peripherals
    I3cBus = 0x00D0,
    Pwm = 0x00D1,

    // Firmware
    Firmware = 0x00E0,
    FirmwareRegistry = 0x00E1,

    // Wireless / radios
    Bluetooth = 0x00F0,
    UsbPd = 0x00F1,

    // Read-only CPU power / energy telemetry. Distinct from `Pmu`
    // (HW perf counters) — this covers CPPC/HWP delivered-perf,
    // RAPL energy joules, and C-state residency. Granted broadly
    // since it can't change anything.
    CpuTelemetry = 0x00F2,

    // Event bus — per-topic publish/subscribe (see `event_bus/SPEC.md`).
    // `TopicRegistry` gates mint/lookup of topics; `EventPublisher`
    // gates `publish()` on a topic; `EventSubscriber` gates
    // `subscribe()` and `recv()`. Three distinct kinds so a
    // compromised consumer can't forge events on the topic it
    // subscribes to. `Event` prefix because the unqualified
    // `Publisher`/`Subscriber` names collide with subscriber lists
    // elsewhere.
    TopicRegistry = 0x0100,
    EventPublisher = 0x0101,
    EventSubscriber = 0x0102,

    // Pluggable-policy install authorities. Each marker gates a
    // `install_<policy>` entry point that swaps the runtime backend
    // for a core subsystem (frame allocator, heap, pager, scheduler
    // policy, donation policy, work-stealing strategy, block I/O
    // scheduler, TCP congestion control, idle governor, tracing
    // sink). See `docs/PLUGGABILITY.md`.
    MemAlloc = 0x0200,
    HeapBackend = 0x0201,
    Pager = 0x0202,
    SchedPolicy = 0x0203,
    DonationPolicy = 0x0204,
    StealStrategy = 0x0205,
    IoScheduler = 0x0206,
    CongestionControl = 0x0207,
    IdleGovernor = 0x0208,
    EventSink = 0x0209,

    // BPF (0x0300..). Split by operation rather than lumped into one
    // "CAP_BPF", because the authorities are genuinely different: loading
    // a program runs the verifier and the JIT, attaching one changes
    // kernel behaviour at a hook, and creating an arena commits memory.
    // A tool that only needs to read a map should not be able to attach.
    //
    // NARF has exactly one privilege regime for BPF — there is no
    // unprivileged mode, so none of these have a weakened variant. See
    // `bpf/specification/spec.md` §4.
    /// Load and verify a BPF program.
    BpfProgLoad = 0x0300,
    /// Attach a verified program to a hook.
    BpfAttach = 0x0301,
    /// Create BPF maps.
    BpfMap = 0x0302,
    /// Create or grow a BPF arena.
    BpfArena = 0x0303,
    /// Install a struct_ops program set into a pluggable trait slot.
    BpfStructOps = 0x0304,
}

pub trait CapType: 'static {
    const KIND: CapKind;
}

#[derive(Debug)]
pub struct UnknownKind;

pub fn parse_kind(name: &str) -> Result<CapKind, UnknownKind> {
    for (k_name, k) in KIND_NAMES {
        if *k_name == name {
            return Ok(*k);
        }
    }
    Err(UnknownKind)
}

pub fn kind_name(kind: CapKind) -> &'static str {
    for (name, k) in KIND_NAMES {
        if *k == kind {
            return name;
        }
    }
    "Unknown"
}

const KIND_NAMES: &[(&str, CapKind)] = &[
    ("BusDevice", CapKind::BusDevice),
    ("BusDeviceP2pDma", CapKind::BusDeviceP2pDma),
    ("BusReconfigureAcs", CapKind::BusReconfigureAcs),
    ("BusRegistry", CapKind::BusRegistry),
    ("BlockDevice", CapKind::BlockDevice),
    ("BlockDeviceBackend", CapKind::BlockDeviceBackend),
    ("BlockIoQueueOwn", CapKind::BlockIoQueueOwn),
    ("Namespace", CapKind::Namespace),
    ("NetIface", CapKind::NetIface),
    ("StackInstall", CapKind::StackInstall),
    ("NetfilterAdmin", CapKind::NetfilterAdmin),
    ("FileNode", CapKind::FileNode),
    ("DirNode", CapKind::DirNode),
    ("MountPoint", CapKind::MountPoint),
    ("FsInstance", CapKind::FsInstance),
    ("Ring", CapKind::Ring),
    ("RingPair", CapKind::RingPair),
    ("Endpoint", CapKind::Endpoint),
    ("Domain", CapKind::Domain),
    ("DmaBuffer", CapKind::DmaBuffer),
    ("DmaPageList", CapKind::DmaPageList),
    ("SharedRegion", CapKind::SharedRegion),
    ("Jit", CapKind::Jit),
    ("Probe", CapKind::Probe),
    ("TraceRing", CapKind::TraceRing),
    ("Recorder", CapKind::Recorder),
    ("Pmu", CapKind::Pmu),
    ("HwCrypto", CapKind::HwCrypto),
    ("HwTrace", CapKind::HwTrace),
    ("Debugger", CapKind::Debugger),
    ("Diagnostics", CapKind::Diagnostics),
    ("Watchpoint", CapKind::Watchpoint),
    ("Key", CapKind::Key),
    ("KeyMgr", CapKind::KeyMgr),
    ("Rng", CapKind::Rng),
    ("Tpm", CapKind::Tpm),
    ("Spdm", CapKind::Spdm),
    ("Task", CapKind::Task),
    ("CpuAffinity", CapKind::CpuAffinity),
    ("CpuLifecycle", CapKind::CpuLifecycle),
    ("CpuBudget", CapKind::CpuBudget),
    ("FreqHint", CapKind::FreqHint),
    ("Power", CapKind::Power),
    ("Timer", CapKind::Timer),
    ("DevicePm", CapKind::DevicePm),
    ("Governor", CapKind::Governor),
    ("PmBus", CapKind::PmBus),
    ("SleepableReader", CapKind::SleepableReader),
    ("Scmi", CapKind::Scmi),
    ("Process", CapKind::Process),
    ("Driver", CapKind::Driver),
    ("FbScanout", CapKind::FbScanout),
    ("AudioStream", CapKind::AudioStream),
    ("I3cBus", CapKind::I3cBus),
    ("Pwm", CapKind::Pwm),
    ("Firmware", CapKind::Firmware),
    ("FirmwareRegistry", CapKind::FirmwareRegistry),
    ("Bluetooth", CapKind::Bluetooth),
    ("UsbPd", CapKind::UsbPd),
    ("CpuTelemetry", CapKind::CpuTelemetry),
    ("TopicRegistry", CapKind::TopicRegistry),
    ("EventPublisher", CapKind::EventPublisher),
    ("EventSubscriber", CapKind::EventSubscriber),
    ("MemAlloc", CapKind::MemAlloc),
    ("HeapBackend", CapKind::HeapBackend),
    ("Pager", CapKind::Pager),
    ("SchedPolicy", CapKind::SchedPolicy),
    ("DonationPolicy", CapKind::DonationPolicy),
    ("StealStrategy", CapKind::StealStrategy),
    ("IoScheduler", CapKind::IoScheduler),
    ("CongestionControl", CapKind::CongestionControl),
    ("IdleGovernor", CapKind::IdleGovernor),
    ("EventSink", CapKind::EventSink),
    ("BpfProgLoad", CapKind::BpfProgLoad),
    ("BpfAttach", CapKind::BpfAttach),
    ("BpfMap", CapKind::BpfMap),
    ("BpfArena", CapKind::BpfArena),
    ("BpfStructOps", CapKind::BpfStructOps),
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
    /// A `CapTable` install past its per-task hard cap (spec §9.7:
    /// 131072 slots) or past the 16-slot bootstrap region.
    CapTableFull,
    /// A `transfer` whose Grant cap and transferred cap name different
    /// objects. A Grant cap for object A never authorises handing out
    /// caps for object B.
    ObjectMismatch,
}
