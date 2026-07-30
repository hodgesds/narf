//! The kfunc calling contract.
//!
//! NARF has **one** way to call into the kernel from a BPF program. Linux has
//! two — a helper table with an `ARG_*` enum, and kfuncs whose argument
//! semantics are encoded in *BTF parameter name suffixes* (`__k`, `__sz`,
//! `__uninit`, `__alloc`, `__nullable`, `__ign`, `__refcounted_kptr`,
//! `__irq_flag`, `__str`, `__map`, `__prog`) plus a hardcoded list of ~60 BTF
//! ids the verifier special-cases by name. Between them that is roughly 2,000
//! lines of verifier code for a single concept.
//!
//! Here, the semantics come from the Rust signature. `bpf/src/kfunc.rs`'s
//! `kfunc!` macro derives an [`ArgDesc`] for every parameter through a
//! `BpfType` trait, so declaring
//!
//! ```ignore
//! kfunc! {
//!     pub fn narf_task_from_pid(pid: u32) -> Option<Owned<Task>>;
//!     pub fn narf_task_release(task: Owned<Task>);
//! }
//! ```
//!
//! is what tells the verifier that the first function acquires a reference
//! which may be null, and the second consumes one. There is no flag to forget
//! to set and no suffix to misspell: the kfunc's implementation and the
//! verifier's model of it are derived from the same type.
//!
//! ## The one rule that does the work
//!
//! Every pointer carries a [`ValidityDomain`] saying how long it stays valid.
//! At an await point the verifier kills every live register whose domain does
//! not satisfy [`ValidityDomain::survives_await`]. That single rule delivers
//! three things Linux implements as three separate subsystems:
//!
//!   * **sleep safety** — a `Trusted<T>` cannot outlive a sleep, so Linux's
//!     `bpf_rcu_read_lock`/`KF_RCU_PROTECTED` layer is unnecessary;
//!   * **lock discipline** — a lock `Guard` is simply not sleep-safe, so
//!     "no sleeping with a lock held" needs no dedicated check;
//!   * **reference tracking** — an `Owned<T>` survives anything but must be
//!     released, which is ordinary linear-type bookkeeping.

use narf_bpf_isa::Size;

/// How long a pointer stays valid.
///
/// Ordered loosely from most to least restrictive. The verifier never widens
/// a domain; a kfunc that wants to hand back something longer-lived must say
/// so in its signature.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ValidityDomain {
    /// Valid only inside the current non-preemptible region. Rust spelling:
    /// `Trusted<T>`, and lock guards. Killed at any await point.
    NonPreemptible,
    /// Valid inside a QSBR read section. Rust spelling: `Rcu<'g, T>`.
    ///
    /// Killed at any await point, because NARF invariant #11 forbids awaiting
    /// inside a QSBR critical section (`ReadGuard` is `!Send` to enforce it).
    RcuRead,
    /// Valid across awaits, inside a sleepable-RCU read section. Rust
    /// spelling: `SleepableRcu<'g, T>`. Requires `Cap<SleepableReader, _>`,
    /// which NARF already has as `CapKind::SleepableReader`.
    SleepableRcuRead,
    /// Valid until explicitly released; a refcount holds the object alive.
    /// Rust spelling: `Owned<T>`. Must be released before the program exits.
    Owned,
    /// Always valid — scalars, the context pointer, arena pointers (arena
    /// pages are pinned for the arena's lifetime), and map values.
    Static,
}

impl ValidityDomain {
    /// Whether a value in this domain may be held across an await point.
    ///
    /// This is the whole of NARF's sleep-safety rule. Compare Linux, which
    /// needs `bpf_rcu_read_lock`, `KF_RCU_PROTECTED`, `MEM_RCU`, and
    /// refcounted kptrs to express the same thing — because sleepability
    /// arrived years after the pointer model and had to be retrofitted.
    #[inline]
    #[must_use]
    pub const fn survives_await(self) -> bool {
        match self {
            Self::NonPreemptible | Self::RcuRead => false,
            Self::SleepableRcuRead | Self::Owned | Self::Static => true,
        }
    }

    /// Whether the verifier must see a value in this domain released before
    /// the program exits.
    #[inline]
    #[must_use]
    pub const fn requires_release(self) -> bool {
        matches!(self, Self::Owned)
    }
}

/// Identifies the pointee type of an object pointer.
///
/// Assigned by the kfunc registry at boot from the Rust type's
/// `core::any::TypeId`-equivalent, so two kfuncs naming the same Rust type
/// agree without a shared BTF blob. Type id 0 is reserved for "no type".
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct TypeKey(pub u32);

/// FNV-1a over a type or symbol name, forced non-zero because
/// [`TypeKey::NONE`] is reserved.
///
/// Lives in the verifier rather than in `narf-bpf` because the verifier is the
/// crate that has to *name* a type without being able to see the Rust `impl` —
/// `MAP_HANDLE_TYPE_KEY` below is the first such case. `narf-bpf`'s
/// `types::fnv1a32_nonzero` re-exports this rather than carrying a second copy;
/// two implementations of the same hash silently disagreeing is how a program's
/// kfunc references stop resolving.
///
/// Not cryptographic, and not a security boundary: this is a namespacing device
/// over a closed in-tree set, and a collision is a build-time bug the kfunc
/// registry's duplicate check catches.
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

/// The pointee type name a BPF map handle carries.
///
/// A map handle is an opaque object pointer: a program obtains one from
/// `LD_IMM64`'s map pseudo-form and can only hand it back to a kfunc.
/// `access()` rejects dereferencing it ([`crate::VerifyError::OpaqueDeref`]),
/// which is exactly right — Linux's `CONST_PTR_TO_MAP` is equally
/// undereferenceable.
pub const MAP_HANDLE_TYPE_NAME: &str = "narf_bpf_map";

/// The [`TypeKey`] a map handle carries.
pub const MAP_HANDLE_TYPE_KEY: TypeKey = TypeKey(fnv1a32_nonzero(MAP_HANDLE_TYPE_NAME));

impl TypeKey {
    /// The reserved "not a typed object" key.
    pub const NONE: TypeKey = TypeKey(0);

    /// Whether this key names an actual type.
    #[inline]
    #[must_use]
    pub const fn is_some(self) -> bool {
        self.0 != 0
    }
}

/// What kind of thing a pointer points at.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PtrKind {
    /// A typed kernel object, identified by [`TypeKey`].
    Object,
    /// An untyped byte region whose length is the *following* argument.
    /// Rust spelling: `&[u8]` / `&mut [u8]`.
    Mem,
    /// A pointer into a BPF arena.
    Arena,
    /// The program's context tuple.
    Ctx,
    /// A map value.
    MapValue,
    /// A critical-section guard. Linear, and never sleep-safe.
    LockGuard,
}

/// The type of one kfunc parameter or return value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TypeKind {
    /// An integer. `bits` is 8, 16, 32, or 64.
    Scalar { bits: u8, signed: bool },
    /// A pointer.
    Ptr { kind: PtrKind, key: TypeKey },
    /// No value. Return position only.
    Void,
}

impl TypeKind {
    /// The access width of a scalar, if this is one.
    #[must_use]
    pub const fn size(self) -> Option<Size> {
        match self {
            Self::Scalar { bits: 8, .. } => Some(Size::B),
            Self::Scalar { bits: 16, .. } => Some(Size::H),
            Self::Scalar { bits: 32, .. } => Some(Size::W),
            Self::Scalar { bits: 64, .. } => Some(Size::Dw),
            _ => None,
        }
    }
}

/// Extra obligations on an argument, beyond its type and domain.
///
/// A bitflag set rather than separate bools so [`ArgDesc`] stays cheap to copy
/// and compare — the verifier compares these on every call site.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct ArgFlags(u16);

impl ArgFlags {
    /// No obligations.
    pub const NONE: ArgFlags = ArgFlags(0);
    /// May be null; the program must test before dereferencing. Rust
    /// spelling: `Option<T>`.
    pub const NULLABLE: ArgFlags = ArgFlags(1 << 0);
    /// The callee initialises this region; the caller need not. Rust
    /// spelling: `&mut MaybeUninit<T>`.
    pub const UNINIT: ArgFlags = ArgFlags(1 << 1);
    /// The *next* argument is this region's length in bytes.
    pub const SIZED_BY_NEXT: ArgFlags = ArgFlags(1 << 2);
    /// Must be a value the verifier has proved constant. Rust spelling:
    /// `Const<T>`.
    pub const CONST: ArgFlags = ArgFlags(1 << 3);
    /// Read-only; the program may not write through this pointer.
    pub const READONLY: ArgFlags = ArgFlags(1 << 4);

    /// Union of two flag sets.
    ///
    /// Duplicates [`core::ops::BitOr`] because a trait impl cannot be `const`
    /// and [`crate::ArgDesc`]s are built in `const` position — so a type that
    /// carries two flags had no way to spell it. `&mut [u8]` is the first:
    /// a region that is both sized by the next argument *and* written by the
    /// callee.
    #[inline]
    #[must_use]
    pub const fn with(self, other: ArgFlags) -> ArgFlags {
        ArgFlags(self.0 | other.0)
    }

    /// Whether every flag in `other` is set here.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: ArgFlags) -> bool {
        (self.0 & other.0) == other.0
    }

    /// The raw bits, for tests and diagnostics.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }
}

impl core::ops::BitOr for ArgFlags {
    type Output = ArgFlags;
    #[inline]
    fn bitor(self, rhs: ArgFlags) -> ArgFlags {
        ArgFlags(self.0 | rhs.0)
    }
}

/// The full description of one kfunc parameter or return value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ArgDesc {
    /// What it is.
    pub kind: TypeKind,
    /// How long it stays valid. Meaningless for scalars, which are always
    /// [`ValidityDomain::Static`].
    pub domain: ValidityDomain,
    /// Additional obligations.
    pub flags: ArgFlags,
}

impl ArgDesc {
    /// A plain 64-bit scalar — the common case.
    pub const SCALAR64: ArgDesc = ArgDesc {
        kind: TypeKind::Scalar {
            bits: 64,
            signed: false,
        },
        domain: ValidityDomain::Static,
        flags: ArgFlags::NONE,
    };

    /// No value.
    pub const VOID: ArgDesc = ArgDesc {
        kind: TypeKind::Void,
        domain: ValidityDomain::Static,
        flags: ArgFlags::NONE,
    };

    /// Whether a value of this type may be held across an await point.
    #[inline]
    #[must_use]
    pub const fn survives_await(&self) -> bool {
        // Scalars are always sleep-safe regardless of the declared domain;
        // only pointers carry validity.
        match self.kind {
            TypeKind::Ptr { .. } => self.domain.survives_await(),
            TypeKind::Scalar { .. } | TypeKind::Void => true,
        }
    }

    /// Whether passing this value *consumes* it — i.e. the caller's copy is
    /// dead afterwards.
    ///
    /// Positional, not a flag: a linear value in argument position releases,
    /// and the same type in return position acquires. The verifier reads it
    /// both ways round.
    ///
    /// A `Guard<'_>` is linear **structurally**, from its [`PtrKind`], not from
    /// its [`ValidityDomain`]. Keying it on the domain made "linear" and "not
    /// sleep-safe" mutually exclusive, which is exactly backwards for a lock:
    /// [`ValidityDomain::Owned`] is the only domain
    /// [`ValidityDomain::requires_release`] accepts, and `Owned` *survives* an
    /// await — so the one spelling that gave linearity was the one
    /// [`KfuncDesc::validate`] rejects. A guard is by definition something you
    /// must give back, whatever its lifetime; the domain's job is only to say
    /// how long that lifetime is.
    ///
    /// The canonical spelling is therefore [`PtrKind::LockGuard`] +
    /// [`ValidityDomain::NonPreemptible`]: linear, and killed at every await by
    /// the same rule that kills a `Trusted<T>`. Spec §1.11's three properties —
    /// fallible acquire, linear release, never held across a sleep — all follow.
    #[inline]
    #[must_use]
    pub const fn consumes_in_arg_position(&self) -> bool {
        match self.kind {
            TypeKind::Ptr {
                kind: PtrKind::LockGuard,
                ..
            } => true,
            TypeKind::Ptr {
                kind: PtrKind::Object,
                ..
            } => self.domain.requires_release(),
            _ => false,
        }
    }
}

/// Which execution context a kfunc may be called from.
///
/// Declared by the *hook*, not by a flag on the program — see
/// `bpf/specification/spec.md` §1.10. A program verified for
/// [`Context::Atomic`] cannot attach to a sleepable hook, and vice versa;
/// mismatches are rejected at attach time by type rather than at runtime.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Context {
    /// IRQs may be masked and caller locks may be held. No awaits.
    /// Tracing/fentry, the perf tracepoint drain, XDP.
    Atomic,
    /// Runs as a real executor task and may await. Syscall-invoked programs,
    /// iterators, process-context struct_ops.
    Sleepable,
}

impl Context {
    /// Whether a kfunc requiring `required` may be called from `self`.
    ///
    /// A sleepable program may call atomic-safe kfuncs; the reverse is not
    /// true.
    #[inline]
    #[must_use]
    pub const fn permits(self, required: Context) -> bool {
        matches!(
            (self, required),
            (Context::Sleepable, _) | (Context::Atomic, Context::Atomic)
        )
    }
}

/// One registered kernel function callable from BPF.
///
/// Built by the `kfunc!` macro into a `narf.kfuncs` link section and collected
/// at boot, mirroring how `narf-kernel-test` collects `narf.tests` and how
/// `probe!` collects `.note.narf.probes`.
#[derive(Copy, Clone, Debug)]
pub struct KfuncDesc {
    /// The id a `call` instruction's `imm` carries to name this kfunc.
    ///
    /// Resolution is by *id*, not by position in [`Program::kfuncs`]. That
    /// distinction is load-bearing: making `imm` an index would silently
    /// couple every compiled program to the order in which the loader happens
    /// to enumerate the registry, so adding a kfunc would re-target existing
    /// programs' calls. The id is stable across builds and independent of
    /// registration order.
    ///
    /// Linux puts a BTF id here and resolves against a global registry plus a
    /// hardcoded `special_kfunc_list[]` of ~60 ids the verifier knows by name
    /// (`verifier.c:13911`). Here the verifier's entire model of a kfunc is
    /// this descriptor, so there is nothing to special-case.
    ///
    /// No value is reserved: `KfuncDesc` has no `Default`, so every
    /// construction site is forced by the compiler to spell `id` out, and
    /// there is nothing a sentinel would catch that the type system does not.
    pub id: i32,
    /// The symbol name, as programs refer to it.
    pub name: &'static str,
    /// Address of the `extern "C"` shim.
    pub addr: usize,
    /// Parameter types, in order. At most [`MAX_KFUNC_ARGS`].
    pub args: &'static [ArgDesc],
    /// Return type.
    pub ret: ArgDesc,
    /// The weakest context this may be called from. A kfunc that can sleep
    /// declares [`Context::Sleepable`] and is then unreachable from atomic
    /// programs — enforced by type, not by a runtime check.
    pub context: Context,
}

/// Maximum number of kfunc arguments.
///
/// Five, matching the BPF ABI's five argument registers (R1..R5).
/// `Documentation/bpf/bpf_design_QA.rst:41` records that this is permanent in
/// Linux for C-ABI compatibility reasons; it is equally permanent here
/// because we share the instruction set.
pub const MAX_KFUNC_ARGS: usize = 5;

impl KfuncDesc {
    /// Check the descriptor is self-consistent.
    ///
    /// Called once per kfunc at registration. A malformed descriptor is a
    /// build-time bug in a `kfunc!` invocation, so failing loudly at boot is
    /// better than letting the verifier reason from a broken contract.
    ///
    /// # Errors
    ///
    /// Returns the first inconsistency found.
    pub fn validate(&self) -> Result<(), KfuncError> {
        if self.args.len() > MAX_KFUNC_ARGS {
            return Err(KfuncError::TooManyArgs(self.args.len()));
        }
        if self.addr == 0 {
            return Err(KfuncError::NullAddress);
        }
        validate_type(self.ret, usize::MAX)?;
        for (i, a) in self.args.iter().enumerate() {
            validate_type(*a, i)?;
            // A sized region needs a following argument to be its length.
            if a.flags.contains(ArgFlags::SIZED_BY_NEXT) {
                match self.args.get(i + 1).map(|n| n.kind) {
                    Some(TypeKind::Scalar { .. }) => {}
                    _ => return Err(KfuncError::MissingSizeArg(i)),
                }
            }
            // Only pointers carry a non-static validity domain.
            if matches!(a.kind, TypeKind::Scalar { .. }) && a.domain != ValidityDomain::Static {
                return Err(KfuncError::ScalarWithDomain(i));
            }
            if matches!(a.kind, TypeKind::Void) {
                return Err(KfuncError::VoidArgument(i));
            }
            // `CONST` means "the verifier proved a single value", which only
            // has a meaning for a scalar. On a pointer it was silently
            // ignored, so a kfunc author writing `Const<Trusted<T>>` got a
            // guarantee they did not have.
            //
            // Rejected rather than reinterpreted: for a pointer the nearest
            // sensible reading is "the offset is known", which is a different
            // and weaker property than the one the name promises. Inventing
            // that mapping silently would be worse than refusing the shape.
            if a.flags.contains(ArgFlags::CONST) && !matches!(a.kind, TypeKind::Scalar { .. }) {
                return Err(KfuncError::ConstOnNonScalar(i));
            }
            // A lock guard is never sleep-safe, in either position. Checking
            // arguments too closes the hole where a kfunc *takes back* a guard
            // it claims survived a sleep, which would legitimise the very
            // state the return-position check exists to prevent.
            if matches!(
                a.kind,
                TypeKind::Ptr {
                    kind: PtrKind::LockGuard,
                    ..
                }
            ) && a.domain.survives_await()
            {
                return Err(KfuncError::SleepableLockGuardArg(i));
            }
        }
        // A lock guard is never sleep-safe; a kfunc claiming otherwise would
        // let a program sleep holding a lock.
        //
        // Note this rejects [`ValidityDomain::Static`] as well as `Owned` and
        // `SleepableRcuRead`: a guard that is "always valid" is not a guard.
        // What is left — `NonPreemptible` and `RcuRead` — is exactly the set
        // of domains that die at an await, which is the property spec §4.4
        // needs and the only thing the domain has to say about a lock.
        if matches!(
            self.ret.kind,
            TypeKind::Ptr {
                kind: PtrKind::LockGuard,
                ..
            }
        ) && self.ret.domain.survives_await()
        {
            return Err(KfuncError::SleepableLockGuard);
        }
        Ok(())
    }
}

/// Why a [`KfuncDesc`] is malformed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KfuncError {
    /// More than [`MAX_KFUNC_ARGS`] parameters.
    TooManyArgs(usize),
    /// The shim address was null.
    NullAddress,
    /// An argument is flagged [`ArgFlags::SIZED_BY_NEXT`] but the following
    /// argument is missing or is not a scalar.
    MissingSizeArg(usize),
    /// A scalar argument declared a non-static validity domain.
    ScalarWithDomain(usize),
    /// [`ArgFlags::CONST`] on a non-scalar argument, where it has no meaning
    /// and was previously ignored.
    ConstOnNonScalar(usize),
    /// An argument had type [`TypeKind::Void`].
    VoidArgument(usize),
    /// A lock guard was declared sleep-safe in return position.
    SleepableLockGuard,
    /// A lock guard argument was declared sleep-safe. Separate from
    /// [`SleepableLockGuard`](Self::SleepableLockGuard) so the diagnostic can
    /// name which parameter.
    SleepableLockGuardArg(usize),
    /// A scalar declared a width no access has. `bits` must be 8, 16, 32 or 64.
    ///
    /// Worth a distinct variant because the failure it prevents was a *panic*,
    /// not a rejection: `Scalar::signed_bits(0)` computes `1 << (bits - 1)` and
    /// underflowed.
    BadScalarWidth { at: usize, bits: u8 },
}

/// Validate one type descriptor in isolation.
///
/// Split out of [`KfuncDesc::validate`] so the *context* descriptor gets the
/// same treatment. It did not: `verify()` validated `prog.kfuncs` and never
/// `prog.ctx_fields`, so a malformed ctx field reached the abstract domain
/// directly. Scalar width was not checked on either path.
///
/// `at` is the position being described — an argument index or a ctx field
/// index — and appears only in diagnostics.
pub const fn validate_type(a: ArgDesc, at: usize) -> Result<(), KfuncError> {
    if let TypeKind::Scalar { bits, .. } = a.kind {
        if !matches!(bits, 8 | 16 | 32 | 64) {
            return Err(KfuncError::BadScalarWidth { at, bits });
        }
    }
    Ok(())
}
