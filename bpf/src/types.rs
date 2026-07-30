//! `BpfType` — argument semantics carried by the Rust type system.
//!
//! This module is the reason NARF's kfunc surface is ~400 lines where Linux's
//! is ~2,000. Linux encodes argument semantics in *BTF parameter name
//! suffixes* (`__k`, `__sz`, `__uninit`, `__alloc`, `__nullable`, `__ign`,
//! `__refcounted_kptr`, `__irq_flag`, `__str`, `__map`, `__prog`), decoded by
//! string comparison in `kernel/bpf/btf.c::btf_check_func_arg_match`, plus a
//! `special_kfunc_list[]` of ~60 BTF ids that `kernel/bpf/verifier.c`
//! special-cases by name. A misspelt suffix is a silently-wrong contract.
//!
//! Here the contract is the signature. [`BpfType::DESC`] is the verifier's
//! description of a type, so the kfunc's *implementation* and the verifier's
//! *model of it* cannot drift: they are derived from the same `impl`.
//!
//! ## The wrapper types
//!
//! Each names a validity domain from `bpf/specification/spec.md` §3.2, and
//! the domain is what makes sleep-safety, lock discipline, and reference
//! tracking one rule instead of three subsystems:
//!
//! | Type | Domain | Survives an await? |
//! |---|---|---|
//! | [`Trusted<T>`] | `NonPreemptible` | no |
//! | [`Rcu<'g, T>`] | `RcuRead` | no — NARF invariant #11 |
//! | [`SleepableRcu<'g, T>`] | `SleepableRcuRead` | yes |
//! | [`Owned<T>`] | `Owned` | yes; must be released |
//! | [`ArenaPtr<T>`] | `Static` | yes — arena pages are pinned |
//! | [`Guard<'_>`] | `NonPreemptible` | no — by construction |
//!
//! ## Raw representation
//!
//! Every kfunc shim has the same `extern "C"` signature —
//! `fn(u64, u64, u64, u64, u64) -> u64` — so the interpreter (and later the
//! JIT) can call any kfunc through one function-pointer type instead of
//! synthesising a per-signature thunk. [`BpfType::from_raw`] reconstitutes a
//! parameter from its register, and `next` (the following register) for the
//! one type that spans two: `&[u8]`, whose length is the next argument. That
//! is exactly the [`ArgFlags::SIZED_BY_NEXT`] contract, so the ABI and the
//! verifier's model agree by construction rather than by convention.

use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::NonNull;

use narf_bpf_verifier::kfunc::{ArgDesc, ArgFlags, PtrKind, TypeKey, TypeKind, ValidityDomain};

/// A kernel type that BPF programs may hold a pointer to.
///
/// Implementing this is the whole of "expose a type to BPF". The
/// [`TypeKey`] is derived from the name rather than assigned by a boot-time
/// registry, so it is stable across boots and across link orders — which
/// matters because a program's kfunc references travel with the program.
pub trait BpfObject: 'static {
    /// The name the verifier and diagnostics use. Must be unique kernel-wide.
    const TYPE_NAME: &'static str;

    /// Stable identity, derived from [`Self::TYPE_NAME`].
    const TYPE_KEY: TypeKey = TypeKey(fnv1a32_nonzero(Self::TYPE_NAME));
}

/// FNV-1a over the name, forced non-zero because `TypeKey(0)` is reserved for
/// "not a typed object".
///
/// FNV rather than a cryptographic hash because this is a *namespacing*
/// device, not a security boundary: the kfunc registry is a closed, in-tree
/// set and a collision is a build-time bug, caught by the duplicate check in
/// `crate::kfunc::Registry::build`.
#[must_use]
pub const fn fnv1a32_nonzero(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut hash: u32 = 0x811C_9DC5;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        i += 1;
    }
    if hash == 0 {
        1
    } else {
        hash
    }
}

/// A type that may appear in a kfunc signature.
///
/// # Safety
///
/// [`Self::from_raw`] reconstitutes a value from a register the *program*
/// controls. An implementor must therefore never produce a value whose
/// validity the program could have violated — pointer-shaped implementors
/// build inert handles (see [`Trusted`]) and defer dereferencing to code that
/// can check, rather than materialising a Rust reference from a program-
/// supplied integer.
pub unsafe trait BpfType: Sized {
    /// How the verifier sees this type.
    const DESC: ArgDesc;

    /// Whether this type may appear in argument position. `()` may not.
    const LEGAL_IN_ARG: bool = true;

    /// Whether this type may appear in return position. `Const<T>` and the
    /// borrowed slice types may not — a "must be a verified constant"
    /// obligation is meaningless on a value the kernel produces, and a
    /// borrowed region has no lifetime the program could honour.
    const LEGAL_IN_RET: bool = true;

    /// Rebuild the value from its argument register.
    ///
    /// `next` is the following argument register, used only by the
    /// `SIZED_BY_NEXT` types.
    ///
    /// # Safety
    ///
    /// `raw` (and `next`) must be values the verifier has proved satisfy
    /// [`Self::DESC`] — non-null where the type is non-nullable, in-bounds
    /// where it names a region, and live in the declared validity domain.
    unsafe fn from_raw(raw: u64, next: u64) -> Self;

    /// Reduce the value to the single return register, R0.
    fn into_raw(self) -> u64;
}

// ── scalars ─────────────────────────────────────────────────────────

macro_rules! impl_scalar {
    ($($t:ty => ($bits:expr, $signed:expr)),* $(,)?) => {$(
        // SAFETY: a scalar carries no validity obligation — every 64-bit
        // pattern is a legal value, so `from_raw` cannot produce anything
        // the program was not already allowed to hold.
        unsafe impl BpfType for $t {
            const DESC: ArgDesc = ArgDesc {
                kind: TypeKind::Scalar { bits: $bits, signed: $signed },
                domain: ValidityDomain::Static,
                flags: ArgFlags::NONE,
            };
            #[inline]
            unsafe fn from_raw(raw: u64, _next: u64) -> Self {
                raw as $t
            }
            #[inline]
            fn into_raw(self) -> u64 {
                // Sign-extend narrow signed types the way the BPF ABI does:
                // R0 is 64 bits and a negative `i32` return must read as a
                // negative `i64` to the program.
                self as i64 as u64
            }
        }
    )*};
}

impl_scalar! {
    u8  => (8,  false),
    u16 => (16, false),
    u32 => (32, false),
    u64 => (64, false),
    i8  => (8,  true),
    i16 => (16, true),
    i32 => (32, true),
    i64 => (64, true),
}

// SAFETY: `()` carries no data; `from_raw` is unreachable because
// `LEGAL_IN_ARG` is false and the macro asserts it at compile time.
unsafe impl BpfType for () {
    const DESC: ArgDesc = ArgDesc::VOID;
    const LEGAL_IN_ARG: bool = false;
    #[inline]
    unsafe fn from_raw(_raw: u64, _next: u64) -> Self {}
    #[inline]
    fn into_raw(self) -> u64 {
        0
    }
}

// ── pointer wrappers ────────────────────────────────────────────────

/// A non-null pointer to a live kernel object, valid only for the duration of
/// the current non-preemptible region.
///
/// The Linux spelling is `PTR_TRUSTED`. The difference is that here "dies at
/// an await" is not a separate flag the verifier consults — it falls out of
/// `ValidityDomain::NonPreemptible::survives_await()` being `false`, which is
/// the same predicate that rejects sleeping with a lock held.
#[derive(Debug)]
pub struct Trusted<T: BpfObject> {
    ptr: NonNull<T>,
}

impl<T: BpfObject> Trusted<T> {
    /// The raw pointer.
    ///
    /// Deliberately not a `Deref`: the kernel side must decide, per call site,
    /// whether it can prove the pointee outlives the borrow. A blanket
    /// `Deref` would make that decision invisible.
    #[inline]
    #[must_use]
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
}

// SAFETY: `from_raw` stores the integer without dereferencing it. The
// verifier's obligation (non-null, live, trusted domain) is discharged
// before the call; this type never itself creates a Rust reference.
unsafe impl<T: BpfObject> BpfType for Trusted<T> {
    const DESC: ArgDesc = ArgDesc {
        kind: TypeKind::Ptr {
            kind: PtrKind::Object,
            key: T::TYPE_KEY,
        },
        domain: ValidityDomain::NonPreemptible,
        flags: ArgFlags::NONE,
    };
    #[inline]
    unsafe fn from_raw(raw: u64, _next: u64) -> Self {
        Self {
            // SAFETY: the verifier proves a non-`Option` object pointer
            // non-null before the call; `Option<Trusted<T>>` is the nullable
            // spelling and takes the `Option` impl below instead.
            ptr: unsafe { NonNull::new_unchecked(raw as *mut T) },
        }
    }
    #[inline]
    fn into_raw(self) -> u64 {
        self.ptr.as_ptr() as u64
    }
}

/// A refcounted handle. Survives anything, and must be released before the
/// program exits.
///
/// Position decides the meaning, which is why there is no `KF_ACQUIRE` /
/// `KF_RELEASE` pair to keep in sync: in return position this acquires a
/// reference, in argument position it consumes one. See
/// `ArgDesc::consumes_in_arg_position`.
#[derive(Debug)]
pub struct Owned<T: BpfObject> {
    ptr: NonNull<T>,
}

impl<T: BpfObject> Owned<T> {
    /// Wrap a pointer whose refcount the caller has already incremented.
    ///
    /// # Safety
    ///
    /// `ptr` must be non-null and must carry a reference the caller owns and
    /// is transferring.
    #[inline]
    pub unsafe fn from_owned_ptr(ptr: *mut T) -> Self {
        Self {
            // SAFETY: caller guarantees non-null.
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        }
    }

    /// The raw pointer. Does not release the reference.
    #[inline]
    #[must_use]
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
}

// SAFETY: as `Trusted` — an inert handle, never dereferenced here.
unsafe impl<T: BpfObject> BpfType for Owned<T> {
    const DESC: ArgDesc = ArgDesc {
        kind: TypeKind::Ptr {
            kind: PtrKind::Object,
            key: T::TYPE_KEY,
        },
        domain: ValidityDomain::Owned,
        flags: ArgFlags::NONE,
    };
    #[inline]
    unsafe fn from_raw(raw: u64, _next: u64) -> Self {
        Self {
            // SAFETY: the verifier tracks acquired references and proves this
            // register still holds one at the release site.
            ptr: unsafe { NonNull::new_unchecked(raw as *mut T) },
        }
    }
    #[inline]
    fn into_raw(self) -> u64 {
        self.ptr.as_ptr() as u64
    }
}

/// A pointer valid inside a QSBR read section.
///
/// Killed at an await, because NARF invariant #11 forbids awaiting inside a
/// QSBR critical section (`rcu`'s `ReadGuard` is `!Send` to enforce it). Use
/// [`SleepableRcu`] where a sleep is required.
#[derive(Debug)]
pub struct Rcu<'g, T: BpfObject> {
    ptr: NonNull<T>,
    _guard: PhantomData<&'g T>,
}

impl<T: BpfObject> Rcu<'_, T> {
    /// The raw pointer.
    #[inline]
    #[must_use]
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
}

// SAFETY: inert handle; the `'g` lifetime is the read-section marker and is
// checked on the kernel side, not reconstructed from `raw`.
unsafe impl<T: BpfObject> BpfType for Rcu<'_, T> {
    const DESC: ArgDesc = ArgDesc {
        kind: TypeKind::Ptr {
            kind: PtrKind::Object,
            key: T::TYPE_KEY,
        },
        domain: ValidityDomain::RcuRead,
        flags: ArgFlags::NONE,
    };
    #[inline]
    unsafe fn from_raw(raw: u64, _next: u64) -> Self {
        Self {
            // SAFETY: the verifier proves the register holds a live
            // QSBR-domain pointer at this call site.
            ptr: unsafe { NonNull::new_unchecked(raw as *mut T) },
            _guard: PhantomData,
        }
    }
    #[inline]
    fn into_raw(self) -> u64 {
        self.ptr.as_ptr() as u64
    }
}

/// A pointer valid inside a *sleepable* RCU read section, and therefore the
/// only borrowed pointer that survives an await.
///
/// Backed by `rcu/src/sleepable.rs` and gated on `CapKind::SleepableReader`,
/// both of which predate BPF: this type is the BPF-visible spelling of a
/// capability the kernel already had.
#[derive(Debug)]
pub struct SleepableRcu<'g, T: BpfObject> {
    ptr: NonNull<T>,
    _guard: PhantomData<&'g T>,
}

impl<T: BpfObject> SleepableRcu<'_, T> {
    /// The raw pointer.
    #[inline]
    #[must_use]
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
}

// SAFETY: inert handle, as `Rcu`.
unsafe impl<T: BpfObject> BpfType for SleepableRcu<'_, T> {
    const DESC: ArgDesc = ArgDesc {
        kind: TypeKind::Ptr {
            kind: PtrKind::Object,
            key: T::TYPE_KEY,
        },
        domain: ValidityDomain::SleepableRcuRead,
        flags: ArgFlags::NONE,
    };
    #[inline]
    unsafe fn from_raw(raw: u64, _next: u64) -> Self {
        Self {
            // SAFETY: the verifier proves the register holds a live
            // sleepable-RCU pointer at this call site.
            ptr: unsafe { NonNull::new_unchecked(raw as *mut T) },
            _guard: PhantomData,
        }
    }
    #[inline]
    fn into_raw(self) -> u64 {
        self.ptr.as_ptr() as u64
    }
}

/// A pointer into a BPF arena, as a base-relative offset.
///
/// Base-relative, not a truncated absolute address. Linux's arena pointer is
/// the low bits of a *user* virtual address (`kernel/bpf/arena.c:16-42`),
/// which is why `arena_map_mmap` returns `-EBUSY` unless every process maps
/// the arena at the same VA. An offset has no such coupling.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ArenaPtr<T> {
    offset: u64,
    _ty: PhantomData<fn() -> T>,
}

impl<T> ArenaPtr<T> {
    /// The byte offset from the arena base.
    #[inline]
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }
}

// SAFETY: an offset, not an address — it is never dereferenced without the
// arena base, and out-of-arena offsets land in the unmapped guard slots.
unsafe impl<T: 'static> BpfType for ArenaPtr<T> {
    const DESC: ArgDesc = ArgDesc {
        kind: TypeKind::Ptr {
            kind: PtrKind::Arena,
            key: TypeKey::NONE,
        },
        // Arena pages are pinned for the arena's lifetime, so an arena
        // pointer survives anything.
        domain: ValidityDomain::Static,
        flags: ArgFlags::NONE,
    };
    #[inline]
    unsafe fn from_raw(raw: u64, _next: u64) -> Self {
        Self {
            offset: raw,
            _ty: PhantomData,
        }
    }
    #[inline]
    fn into_raw(self) -> u64 {
        self.offset
    }
}

/// A critical-section guard. Linear, and never sleep-safe.
///
/// Three properties Linux implements as three mechanisms
/// (`REF_TYPE_LOCK`, `active_lock_id`, `process_spin_lock()`, plus
/// `rqspinlock.c`'s deadlock detector) fall out of this one type:
/// acquisition is fallible because the kfunc returns `Option<Guard>`;
/// release is mandatory because `PtrKind::LockGuard` is linear; and sleeping
/// while held is rejected because `survives_await()` is `false`.
///
/// Contract note for the verifier: `ArgDesc::consumes_in_arg_position`
/// currently requires `domain.requires_release()`, which only
/// `ValidityDomain::Owned` satisfies — but `KfuncDesc::validate` rejects a
/// `LockGuard` return whose domain survives an await, and `Owned` does. A
/// guard therefore cannot be both linear and sleep-unsafe under the Phase-0
/// contract. `NonPreemptible` is the domain that satisfies `validate()`, and
/// linearity for `PtrKind::LockGuard` needs to come from the pointer kind
/// rather than the domain when the abstract interpreter lands.
#[derive(Debug)]
pub struct Guard<'a> {
    token: u64,
    _lock: PhantomData<&'a ()>,
}

impl Guard<'_> {
    /// The opaque lock token this guard holds.
    #[inline]
    #[must_use]
    pub const fn token(&self) -> u64 {
        self.token
    }
}

// SAFETY: an opaque token, never dereferenced.
unsafe impl BpfType for Guard<'_> {
    const DESC: ArgDesc = ArgDesc {
        kind: TypeKind::Ptr {
            kind: PtrKind::LockGuard,
            key: TypeKey::NONE,
        },
        // `NonPreemptible`, not `Owned`: a guard must be released before the
        // program exits *and* may not cross an await. `Owned` would satisfy
        // only the first.
        domain: ValidityDomain::NonPreemptible,
        flags: ArgFlags::NONE,
    };
    #[inline]
    unsafe fn from_raw(raw: u64, _next: u64) -> Self {
        Self {
            token: raw,
            _lock: PhantomData,
        }
    }
    #[inline]
    fn into_raw(self) -> u64 {
        self.token
    }
}

// ── flag-carrying wrappers ──────────────────────────────────────────

/// A value the verifier has proved constant. Linux spells it `__k`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Const<T>(pub T);

// SAFETY: delegates to `T`, which carries the safety argument.
unsafe impl<T: BpfType> BpfType for Const<T> {
    const DESC: ArgDesc = {
        assert!(
            T::DESC.flags.bits() == 0,
            "Const<T> where T already carries argument flags: the flag set \
             would be lost. Nesting flag-carrying types is not supported."
        );
        // Caught at build time as well as at registration, so a kfunc that
        // asks for something meaningless fails to compile rather than
        // failing to validate at boot.
        assert!(
            matches!(
                T::DESC.kind,
                narf_bpf_verifier::kfunc::TypeKind::Scalar { .. }
            ),
            "Const<T> is only meaningful for a scalar: 'the verifier proved a \
             single value' has no reading for a pointer, and the flag was \
             silently ignored there."
        );
        ArgDesc {
            kind: T::DESC.kind,
            domain: T::DESC.domain,
            flags: ArgFlags::CONST,
        }
    };
    // "Must be a constant the verifier proved" is an obligation on the
    // *caller*. In return position it would describe nothing.
    const LEGAL_IN_RET: bool = false;
    #[inline]
    unsafe fn from_raw(raw: u64, next: u64) -> Self {
        // SAFETY: same obligation as `T`, plus constness, which is strictly
        // stronger.
        Self(unsafe { T::from_raw(raw, next) })
    }
    #[inline]
    fn into_raw(self) -> u64 {
        self.0.into_raw()
    }
}

// SAFETY: `None` is spelt as the null register value, which is exactly what
// the verifier's `NULLABLE` obligation makes the program test for.
unsafe impl<T: BpfType> BpfType for Option<T> {
    const DESC: ArgDesc = {
        assert!(
            T::DESC.flags.bits() == 0,
            "Option<T> where T already carries argument flags: the flag set \
             would be lost. Nesting flag-carrying types is not supported."
        );
        ArgDesc {
            kind: T::DESC.kind,
            domain: T::DESC.domain,
            flags: ArgFlags::NULLABLE,
        }
    };
    #[inline]
    unsafe fn from_raw(raw: u64, next: u64) -> Self {
        if raw == 0 {
            None
        } else {
            // SAFETY: non-null checked above; the rest of `T`'s obligation is
            // discharged by the verifier as for a non-nullable `T`.
            Some(unsafe { T::from_raw(raw, next) })
        }
    }
    #[inline]
    fn into_raw(self) -> u64 {
        match self {
            Some(v) => v.into_raw(),
            None => 0,
        }
    }
}

// ── memory regions ──────────────────────────────────────────────────

/// The byte-region types are `SIZED_BY_NEXT`: the pointer occupies this
/// argument's register and the *next* declared argument is its length. That
/// is Linux's `__sz` suffix, expressed as a type instead of a name.
///
// SAFETY: the slice is built from a program-supplied pointer/length pair the
// verifier has proved describes an in-bounds region. This is the one place
// where a Rust reference *is* materialised, and it is sound exactly to the
// extent that the verifier's region check is — which is why
// `bpf/specification/spec.md` §4.11 makes the verifier fail closed.
unsafe impl BpfType for &[u8] {
    const DESC: ArgDesc = ArgDesc {
        kind: TypeKind::Ptr {
            kind: PtrKind::Mem,
            key: TypeKey::NONE,
        },
        domain: ValidityDomain::NonPreemptible,
        flags: ArgFlags::SIZED_BY_NEXT,
    };
    // A borrowed region has no lifetime a program could honour after the
    // call returns.
    const LEGAL_IN_RET: bool = false;
    #[inline]
    unsafe fn from_raw(raw: u64, next: u64) -> Self {
        if raw == 0 || next == 0 {
            return &[];
        }
        // SAFETY: verifier-proved in-bounds region; see the type-level note.
        unsafe { core::slice::from_raw_parts(raw as *const u8, next as usize) }
    }
    #[inline]
    fn into_raw(self) -> u64 {
        self.as_ptr() as u64
    }
}

/// A region the callee initialises. Linux spells it `__uninit`.
///
// SAFETY: as `&[u8]`, plus the `UNINIT` flag telling the verifier the caller
// need not have initialised the region — so the kfunc must write it before
// any read, which `MaybeUninit` enforces on the Rust side.
unsafe impl<T: 'static> BpfType for &mut MaybeUninit<T> {
    const DESC: ArgDesc = ArgDesc {
        kind: TypeKind::Ptr {
            kind: PtrKind::Mem,
            key: TypeKey::NONE,
        },
        domain: ValidityDomain::NonPreemptible,
        flags: ArgFlags::UNINIT,
    };
    const LEGAL_IN_RET: bool = false;
    #[inline]
    unsafe fn from_raw(raw: u64, _next: u64) -> Self {
        // SAFETY: the verifier proves the register names a writable region of
        // at least `size_of::<T>()` bytes, correctly aligned for `T`.
        unsafe { &mut *(raw as *mut MaybeUninit<T>) }
    }
    #[inline]
    fn into_raw(self) -> u64 {
        (self as *mut MaybeUninit<T>) as u64
    }
}
