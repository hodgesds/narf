//! The abstract state: registers, stack, typed pointers, and live references.
//!
//! ## Pointers
//!
//! A pointer is a *region* plus an *offset*, and the offset is a
//! [`Scalar`] — the same abstract value an arithmetic register holds. That is
//! the whole of pointer arithmetic: `r1 += r2` on a pointer adds `r2`'s scalar
//! to the offset, and the bounds check at the eventual load asks whether the
//! offset's range fits the region. Linux keeps a separate `off` field *and* a
//! `var_off` tnum *and* the four range pairs, and reconciles them
//! (`verifier.c`'s `__reg_bound_offset`); here there is one thing to update and
//! one thing to check.
//!
//! [`PtrClass::Arena`] is the exception, and deliberately so: arena pointer
//! arithmetic is unrestricted, with safety coming from unmapped guard regions
//! and the exception table rather than from a proof. That is the same bargain
//! Linux strikes at `verifier.c:16186`, and it is a good one — the guard here
//! is a whole unmapped 512 GiB slot on each side, so an escape by the ISA's
//! 16-bit displacement is structurally impossible.
//!
//! ## References, locks, and sleep safety are one mechanism
//!
//! [`Ref`] tracks anything that must be released before exit. A refcounted
//! `Owned<T>` and a lock `Guard<'_>` are the same kind of entry, differing
//! only in their [`ValidityDomain`] — and that domain is what decides whether
//! the value survives an await. So "no sleeping with a lock held", "no
//! `Trusted<T>` across a yield", and "every acquired reference is released"
//! are three consequences of two fields, against Linux's `REF_TYPE_LOCK`,
//! `active_lock_id`, `process_spin_lock()`, `invalidate_non_owning_refs()`,
//! `bpf_rcu_read_lock`, `KF_RCU_PROTECTED`, and `MEM_RCU`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use narf_bpf_isa::Size;

use crate::domain::Scalar;
use crate::kfunc::{TypeKey, ValidityDomain};

/// Bytes per stack slot, matching the ISA's widest access.
pub const SLOT_BYTES: u32 = 8;

/// "No reference id."
pub const NO_REF: u32 = u32::MAX;

/// What a pointer points at.
///
/// Distinct from [`crate::kfunc::PtrKind`], which is the *interface* vocabulary
/// a kfunc signature speaks. This is the verifier's internal taxonomy and has
/// members — `Stack`, `Null` — that no kfunc can name.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PtrClass {
    /// Frame-pointer relative. Offsets are negative and bounded by the
    /// program's stack budget.
    Stack,
    /// The context tuple. Read-only, and accessed field-wise.
    Ctx,
    /// A map value: a bounded, writable region.
    MapValue,
    /// An untyped bounded byte region — what `&[u8]` lowers to, and what a
    /// caller's stack region looks like from inside a subprogram.
    Mem,
    /// A typed kernel object. Opaque: its fields are reachable only through a
    /// fault-recoverable probe load, because NARF has no in-kernel BTF and
    /// therefore no field layout to check against.
    Object,
    /// A pointer into a BPF arena. Arithmetic is unrestricted.
    Arena,
    /// A critical-section guard. Linear, and never sleep-safe.
    LockGuard,
    /// The literal null pointer, as produced by comparing an
    /// [`crate::kfunc::ArgFlags::NULLABLE`] result against zero.
    Null,
}

impl PtrClass {
    /// Whether an access through this pointer must be proved in bounds.
    ///
    /// False for `Object` and `Arena`, whose accesses are instead covered by
    /// exception-table entries — a fault zeroes the destination and resumes.
    #[inline]
    #[must_use]
    pub const fn needs_bounds_check(self) -> bool {
        !matches!(self, PtrClass::Object | PtrClass::Arena)
    }

    /// Whether an access through this pointer needs an exception-table entry.
    #[inline]
    #[must_use]
    pub const fn is_faulting(self) -> bool {
        matches!(self, PtrClass::Object | PtrClass::Arena)
    }
}

/// A pointer value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PtrVal {
    /// What kind of region.
    pub class: PtrClass,
    /// Which type, for [`PtrClass::Object`].
    pub key: TypeKey,
    /// How long it stays valid.
    pub domain: ValidityDomain,
    /// Byte offset from the region base. Negative for [`PtrClass::Stack`].
    pub off: Scalar,
    /// Region size in bytes, or `None` when the region is unbounded
    /// (`Arena`) or opaque (`Object`).
    pub size: Option<u64>,
    /// Whether the value may be null and has not yet been tested.
    pub nullable: bool,
    /// Which acquired reference this pointer belongs to, or [`NO_REF`].
    pub ref_id: u32,
    /// Whether stores through it are forbidden.
    pub readonly: bool,
}

impl PtrVal {
    /// A non-null, non-refcounted pointer to a bounded region.
    #[must_use]
    pub fn region(class: PtrClass, size: u64) -> PtrVal {
        PtrVal {
            class,
            key: TypeKey::NONE,
            domain: ValidityDomain::Static,
            off: Scalar::constant(0),
            size: Some(size),
            nullable: false,
            ref_id: NO_REF,
            readonly: false,
        }
    }

    /// The frame pointer, R10.
    #[must_use]
    pub fn frame_pointer() -> PtrVal {
        PtrVal {
            class: PtrClass::Stack,
            key: TypeKey::NONE,
            domain: ValidityDomain::Static,
            off: Scalar::constant(0),
            size: None,
            nullable: false,
            ref_id: NO_REF,
            readonly: false,
        }
    }

    /// Whether the value may be held across an await point.
    #[inline]
    #[must_use]
    pub fn survives_await(&self) -> bool {
        self.domain.survives_await()
    }

    /// Join, when both sides describe the same kind of region.
    fn join(&self, other: &PtrVal) -> Option<PtrVal> {
        if self.class != other.class || self.key != other.key || self.ref_id != other.ref_id {
            return None;
        }
        Some(PtrVal {
            class: self.class,
            key: self.key,
            // Never widen a validity domain: the shorter-lived of the two is
            // the only thing both paths guarantee.
            domain: weaker_domain(self.domain, other.domain),
            off: self.off.join(&other.off),
            size: match (self.size, other.size) {
                (Some(a), Some(b)) => Some(a.min(b)),
                _ => None,
            },
            nullable: self.nullable || other.nullable,
            ref_id: self.ref_id,
            readonly: self.readonly || other.readonly,
        })
    }

    fn is_subset_of(&self, other: &PtrVal) -> bool {
        self.class == other.class
            && self.key == other.key
            && self.ref_id == other.ref_id
            && self.domain == other.domain
            && self.off.is_subset_of(&other.off)
            && (other.nullable || !self.nullable)
            && (other.readonly || !self.readonly)
            && match (self.size, other.size) {
                (Some(a), Some(b)) => a >= b,
                (_, None) => true,
                (None, Some(_)) => false,
            }
    }

    fn widen(&self, next: &PtrVal, thresholds: &[i64]) -> Option<PtrVal> {
        let mut j = self.join(next)?;
        j.off = self.off.widen(&next.off, thresholds);
        Some(j)
    }
}

/// The more restrictive of two validity domains.
///
/// Ordered by what a value in the domain can outlive, not by the enum's
/// declaration order — `Static` outlives everything, `NonPreemptible` and
/// `RcuRead` die at the next await.
#[must_use]
pub fn weaker_domain(a: ValidityDomain, b: ValidityDomain) -> ValidityDomain {
    fn rank(d: ValidityDomain) -> u8 {
        match d {
            ValidityDomain::NonPreemptible => 0,
            ValidityDomain::RcuRead => 1,
            ValidityDomain::SleepableRcuRead => 2,
            ValidityDomain::Owned => 3,
            ValidityDomain::Static => 4,
        }
    }
    if rank(a) <= rank(b) {
        a
    } else {
        b
    }
}

/// The abstract value of a register or a spilled stack slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AbsValue {
    /// Never written. Reading it is an error.
    NotInit,
    /// A number.
    Scalar(Scalar),
    /// A pointer.
    Ptr(PtrVal),
}

impl AbsValue {
    /// An unconstrained number.
    pub const UNKNOWN_SCALAR: AbsValue = AbsValue::Scalar(Scalar::UNKNOWN);

    /// The scalar, if this is one.
    #[inline]
    #[must_use]
    pub const fn as_scalar(&self) -> Option<&Scalar> {
        match self {
            AbsValue::Scalar(s) => Some(s),
            _ => None,
        }
    }

    /// The pointer, if this is one.
    #[inline]
    #[must_use]
    pub const fn as_ptr(&self) -> Option<&PtrVal> {
        match self {
            AbsValue::Ptr(p) => Some(p),
            _ => None,
        }
    }

    /// Join.
    ///
    /// // LINUX-GAP: merging a pointer with a scalar, or two pointers into
    /// different regions, degrades to an unconstrained *scalar* rather than to
    /// a poison value. Memory safety is unaffected — a scalar cannot be
    /// dereferenced — but the pointer's numeric value becomes readable, which
    /// Linux forbids under `!allow_ptr_leaks`. NARF has one privilege regime
    /// (spec §1.9: loading requires `Cap<BpfProgLoad, Grant>`), so a loader
    /// that can already run arbitrary verified code learns nothing from a
    /// kernel address. The alternative — a fourth `AbsValue` variant that is
    /// an error to read — buys nothing and costs a case in every match.
    #[must_use]
    pub fn join(&self, other: &AbsValue) -> AbsValue {
        match (self, other) {
            (AbsValue::NotInit, _) | (_, AbsValue::NotInit) => AbsValue::NotInit,
            (AbsValue::Scalar(a), AbsValue::Scalar(b)) => AbsValue::Scalar(a.join(b)),
            (AbsValue::Ptr(a), AbsValue::Ptr(b)) => match a.join(b) {
                Some(p) => AbsValue::Ptr(p),
                None => AbsValue::UNKNOWN_SCALAR,
            },
            _ => AbsValue::UNKNOWN_SCALAR,
        }
    }

    /// Widening, used where the CFG says a cycle is entered.
    #[must_use]
    pub fn widen(&self, next: &AbsValue, thresholds: &[i64]) -> AbsValue {
        match (self, next) {
            (AbsValue::Scalar(a), AbsValue::Scalar(b)) => AbsValue::Scalar(a.widen(b, thresholds)),
            (AbsValue::Ptr(a), AbsValue::Ptr(b)) => match a.widen(b, thresholds) {
                Some(p) => AbsValue::Ptr(p),
                None => AbsValue::UNKNOWN_SCALAR,
            },
            _ => self.join(next),
        }
    }

    /// Whether `self` describes a subset of `other`.
    #[must_use]
    pub fn is_subset_of(&self, other: &AbsValue) -> bool {
        match (self, other) {
            (_, AbsValue::NotInit) => true,
            (AbsValue::NotInit, _) => false,
            (AbsValue::Scalar(a), AbsValue::Scalar(b)) => a.is_subset_of(b),
            (AbsValue::Ptr(a), AbsValue::Ptr(b)) => a.is_subset_of(b),
            _ => false,
        }
    }
}

/// One eight-byte stack slot.
///
/// Slot `i` covers bytes `[-8(i+1), -8i)` relative to R10, so slot 0 is the
/// eight bytes immediately below the frame pointer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StackSlot {
    /// Which of the eight bytes have been written. Bit `n` is the byte at
    /// `-8(i+1) + n`.
    ///
    /// Per-byte rather than per-slot because a program may initialise a slot
    /// with four one-byte stores and then read a word from it, and rejecting
    /// that would reject real compiler output. Linux tracks the same thing as
    /// `STACK_MISC`/`STACK_ZERO`/`STACK_SPILL` per byte.
    pub init: u8,
    /// The value, when the whole slot was written as a single unit.
    pub value: AbsValue,
    /// Whether [`value`](Self::value) describes all eight bytes. Only a
    /// whole-slot write sets this, and any narrower write clears it — a
    /// pointer with one byte overwritten is not a pointer any more.
    pub whole: bool,
}

impl StackSlot {
    /// A slot nothing has been written to.
    pub const EMPTY: StackSlot = StackSlot {
        init: 0,
        value: AbsValue::NotInit,
        whole: false,
    };

    fn join(&self, other: &StackSlot) -> StackSlot {
        let whole = self.whole && other.whole;
        StackSlot {
            // A byte is initialised only if it is initialised on *every* path.
            init: self.init & other.init,
            value: if whole {
                self.value.join(&other.value)
            } else {
                AbsValue::NotInit
            },
            whole,
        }
    }

    /// Widen against `next`, mirroring [`StackSlot::join`]'s shape.
    ///
    /// A slot's value has to widen for the same reason a register's does: it
    /// can carry a value around a loop. Joining here instead — which is what
    /// this did — gives the slot an infinite ascending chain, so a counter
    /// spilled to the stack never converges.
    fn widen(&self, next: &StackSlot, thresholds: &[i64]) -> StackSlot {
        let whole = self.whole && next.whole;
        StackSlot {
            init: self.init & next.init,
            value: if whole {
                self.value.widen(&next.value, thresholds)
            } else {
                AbsValue::NotInit
            },
            whole,
        }
    }

    fn is_subset_of(&self, other: &StackSlot) -> bool {
        // More initialised bytes is a smaller (more defined) state.
        (other.init & !self.init) == 0
            && (!other.whole || (self.whole && self.value.is_subset_of(&other.value)))
    }
}

/// The stack frame.
///
/// Sparse: only touched slots are stored, because the budget is 16 KiB and a
/// dense array per abstract state would dominate the analysis's memory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stack {
    slots: BTreeMap<u32, StackSlot>,
    /// Deepest byte offset touched, as a positive distance below R10.
    pub depth: u32,
}

impl Stack {
    /// Slot index containing byte offset `off` (negative, relative to R10).
    #[inline]
    #[must_use]
    pub const fn slot_index(off: i64) -> u32 {
        ((-off - 1) / SLOT_BYTES as i64) as u32
    }

    /// Byte position of `off` within its slot.
    #[inline]
    #[must_use]
    pub const fn byte_in_slot(off: i64) -> u32 {
        let i = Self::slot_index(off) as i64;
        (off + SLOT_BYTES as i64 * (i + 1)) as u32
    }

    /// The slot at `index`, or an empty one.
    #[must_use]
    pub fn slot(&self, index: u32) -> StackSlot {
        self.slots.get(&index).copied().unwrap_or(StackSlot::EMPTY)
    }

    /// Write a value covering the byte range `[off, off + size)`.
    pub fn write(&mut self, off: i64, size: Size, value: AbsValue) {
        self.note_depth(off);
        let bytes = size.bytes() as i64;
        let aligned_whole = size == Size::Dw && off % SLOT_BYTES as i64 == 0;
        if aligned_whole {
            self.slots.insert(
                Stack::slot_index(off),
                StackSlot {
                    init: 0xff,
                    value,
                    whole: true,
                },
            );
            return;
        }
        for b in off..off + bytes {
            let idx = Stack::slot_index(b);
            let bit = 1u8 << Stack::byte_in_slot(b);
            let mut s = self.slot(idx);
            // A partial write destroys any spilled value in the slot: half a
            // pointer is not a pointer.
            s.whole = false;
            s.value = AbsValue::NotInit;
            s.init |= bit;
            self.slots.insert(idx, s);
        }
    }

    /// Mark `[off, off + size)` written with an unspecified value — what a
    /// kfunc taking `&mut MaybeUninit<T>` promises.
    pub fn write_unspecified(&mut self, off: i64, len: u64) {
        // `off` is the lowest address in the range, so it is what sets depth.
        self.note_depth(off);
        for b in off..off + len as i64 {
            let idx = Stack::slot_index(b);
            let mut s = self.slot(idx);
            s.whole = false;
            s.value = AbsValue::NotInit;
            s.init |= 1u8 << Stack::byte_in_slot(b);
            self.slots.insert(idx, s);
        }
    }

    /// Whether every byte in `[off, off + len)` has been written.
    #[must_use]
    pub fn is_initialized(&self, off: i64, len: u64) -> bool {
        (off..off + len as i64).all(|b| {
            let s = self.slot(Stack::slot_index(b));
            (s.init & (1u8 << Stack::byte_in_slot(b))) != 0
        })
    }

    /// Read `size` bytes at `off`, assuming [`Stack::is_initialized`] holds.
    #[must_use]
    pub fn read(&self, off: i64, size: Size) -> AbsValue {
        if size == Size::Dw && off % SLOT_BYTES as i64 == 0 {
            let s = self.slot(Stack::slot_index(off));
            if s.whole && s.init == 0xff {
                return s.value;
            }
        }
        // A narrow read of a spilled pointer, or a read of bytes written
        // separately: nothing survives but the width.
        AbsValue::Scalar(Scalar::unsigned_bits(size.bits()))
    }

    /// Invalidate everything, keeping it *initialised*.
    ///
    /// Used when a subprogram is handed a pointer into this frame: the callee
    /// may have written anything, so no spilled pointer survives, but the
    /// bytes are certainly no less defined than they were.
    pub fn clobber(&mut self) {
        for s in self.slots.values_mut() {
            s.whole = false;
            s.value = AbsValue::NotInit;
        }
    }

    fn note_depth(&mut self, off: i64) {
        if off < 0 {
            self.depth = self.depth.max((-off) as u32);
        }
    }

    fn join(&self, other: &Stack) -> Stack {
        let mut out = BTreeMap::new();
        for (&i, a) in &self.slots {
            let b = other.slot(i);
            let j = a.join(&b);
            if j != StackSlot::EMPTY {
                out.insert(i, j);
            }
        }
        // Slots only `other` touched join against an empty slot, which leaves
        // nothing initialised — so they need no entry at all.
        Stack {
            slots: out,
            depth: self.depth.max(other.depth),
        }
    }

    /// Widen against `next`. Same traversal as [`Stack::join`]; only the
    /// per-slot combinator differs.
    fn widen(&self, next: &Stack, thresholds: &[i64]) -> Stack {
        let mut out = BTreeMap::new();
        for (&i, a) in &self.slots {
            let b = next.slot(i);
            let w = a.widen(&b, thresholds);
            if w != StackSlot::EMPTY {
                out.insert(i, w);
            }
        }
        Stack {
            slots: out,
            depth: self.depth.max(next.depth),
        }
    }

    fn is_subset_of(&self, other: &Stack) -> bool {
        other
            .slots
            .iter()
            .all(|(&i, o)| self.slot(i).is_subset_of(o))
    }
}

/// One live reference the program must release before it exits.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ref {
    /// Identity, and the reason reference tracking terminates: the id is the
    /// IR index of the *acquisition site*, not a fresh counter. Re-acquiring
    /// in a loop yields the same id, so the reference set is bounded by the
    /// program's size and the fixpoint cannot diverge by minting ids.
    pub id: u32,
    /// Whether this is a lock guard, which v1 permits only one of.
    pub is_lock: bool,
    /// The domain the reference was acquired in.
    pub domain: ValidityDomain,
}

/// The abstract state at a program point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbsState {
    /// R0..R10.
    pub regs: [AbsValue; 11],
    /// The current frame.
    pub stack: Stack,
    /// Outstanding references, sorted by id.
    pub refs: Vec<Ref>,
}

impl AbsState {
    /// The state on entry to a program: R1 is the context, R10 the frame
    /// pointer, everything else uninitialised.
    #[must_use]
    pub fn entry(ctx_size: u64) -> AbsState {
        let mut regs = [AbsValue::NotInit; 11];
        regs[1] = AbsValue::Ptr(PtrVal {
            readonly: true,
            ..PtrVal::region(PtrClass::Ctx, ctx_size)
        });
        regs[10] = AbsValue::Ptr(PtrVal::frame_pointer());
        AbsState {
            regs,
            stack: Stack::default(),
            refs: Vec::new(),
        }
    }

    /// Add a reference, or leave it if the same acquisition site is already
    /// recorded.
    pub fn acquire(&mut self, r: Ref) {
        if let Err(pos) = self.refs.binary_search_by_key(&r.id, |e| e.id) {
            self.refs.insert(pos, r);
        }
    }

    /// Drop a reference. Returns whether it was held.
    pub fn release(&mut self, id: u32) -> bool {
        match self.refs.binary_search_by_key(&id, |e| e.id) {
            Ok(pos) => {
                self.refs.remove(pos);
                true
            }
            Err(_) => false,
        }
    }

    /// Whether `id` is currently held.
    #[must_use]
    pub fn holds(&self, id: u32) -> bool {
        self.refs.binary_search_by_key(&id, |e| e.id).is_ok()
    }

    /// How many lock guards are live.
    #[must_use]
    pub fn live_locks(&self) -> usize {
        self.refs.iter().filter(|r| r.is_lock).count()
    }

    /// Forget every register holding `id`, after it has been released.
    pub fn kill_ref(&mut self, id: u32) {
        for r in &mut self.regs {
            if matches!(r, AbsValue::Ptr(p) if p.ref_id == id) {
                *r = AbsValue::NotInit;
            }
        }
        for s in self.stack.slots.values_mut() {
            if matches!(s.value, AbsValue::Ptr(p) if p.ref_id == id) {
                s.value = AbsValue::NotInit;
                s.whole = false;
            }
        }
    }

    /// Kill every value that does not survive an await.
    ///
    /// **This is spec §4.4, and it is one function.** Sleep safety, lock
    /// discipline, and RCU-section discipline all fall out of it, because all
    /// three are questions about a [`ValidityDomain`]. Returns the registers
    /// it killed, so the caller can report the ones liveness says were still
    /// wanted — a diagnostic naming the register and its domain, rather than
    /// an "uninitialised register" error several instructions later.
    pub fn kill_at_await(&mut self) -> Vec<(u8, ValidityDomain)> {
        let mut killed = Vec::new();
        for (i, r) in self.regs.iter_mut().enumerate() {
            if let AbsValue::Ptr(p) = r {
                if !p.survives_await() {
                    killed.push((i as u8, p.domain));
                    *r = AbsValue::NotInit;
                }
            }
        }
        for s in self.stack.slots.values_mut() {
            if matches!(s.value, AbsValue::Ptr(p) if !p.survives_await()) {
                s.value = AbsValue::NotInit;
                s.whole = false;
            }
        }
        killed
    }

    /// Join two states.
    #[must_use]
    pub fn join(&self, other: &AbsState) -> AbsState {
        let mut regs = [AbsValue::NotInit; 11];
        for (i, out) in regs.iter_mut().enumerate() {
            *out = self.regs[i].join(&other.regs[i]);
        }
        AbsState {
            regs,
            stack: self.stack.join(&other.stack),
            // A reference held on either path must be released, so the union
            // is the conservative answer: a program that acquires in one arm
            // of a branch has to release it in both.
            refs: union_refs(&self.refs, &other.refs),
        }
    }

    /// Widen towards `next`.
    ///
    /// `precise` is the precision analysis's answer for this program point: a
    /// bit per register saying whether its *value* can still reach a memory
    /// address, a branch guarding one, or a kfunc argument. A precise register
    /// is widened to the nearest program constant, keeping the loop bound a
    /// later bounds check depends on; an imprecise one is widened straight to
    /// top, which converges faster and cannot cost an accepted program
    /// anything, because nothing downstream reads it.
    ///
    /// That is the whole use of precision here, and it is why it can be
    /// computed up front. Linux discovers precision mid-search and has to walk
    /// its state history backwards to apply it — `backtrack_insn()` plus
    /// `__mark_chain_precision()`, 474 lines behind a 95-line comment at
    /// `verifier.c:4798` explaining why there is no other way. There is no
    /// search here to discover anything mid-way through.
    #[must_use]
    pub fn widen(&self, next: &AbsState, thresholds: &[i64], precise: u16) -> AbsState {
        let joined = self.join(next);
        let mut regs = [AbsValue::NotInit; 11];
        for (i, out) in regs.iter_mut().enumerate() {
            let t = if (precise & (1 << i)) != 0 {
                thresholds
            } else {
                // No thresholds means the first widening goes to top.
                &[][..]
            };
            *out = self.regs[i].widen(&joined.regs[i], t);
        }
        AbsState {
            regs,
            // Widen the stack too. Taking `joined.stack` here was the defect:
            // the operator existed and was correct, it was simply never
            // reached for slot state, so anything carried around a loop
            // through the stack diverged.
            stack: self.stack.widen(&joined.stack, thresholds),
            refs: joined.refs,
        }
    }

    /// Whether `self` describes a subset of `other`, which is how the fixpoint
    /// decides a block's input has stopped changing.
    #[must_use]
    pub fn is_subset_of(&self, other: &AbsState) -> bool {
        self.regs
            .iter()
            .zip(other.regs.iter())
            .all(|(a, b)| a.is_subset_of(b))
            && self.stack.is_subset_of(&other.stack)
            && other.refs.iter().all(|r| self.holds(r.id))
            && self.refs.iter().all(|r| other.holds(r.id))
    }
}

fn union_refs(a: &[Ref], b: &[Ref]) -> Vec<Ref> {
    let mut out: Vec<Ref> = a.to_vec();
    for r in b {
        if let Err(pos) = out.binary_search_by_key(&r.id, |e| e.id) {
            out.insert(pos, *r);
        }
    }
    out
}
