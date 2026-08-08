//! `struct_ops!` — runtime-supplied implementations of pluggable traits.
//!
//! The framing that makes this cheap: **a struct_ops program set is a
//! runtime-supplied impl of a `docs/PLUGGABILITY.md` trait**. NARF already has
//! that shape — a trait, a `CapKind`, an `IrqSafeSpinLock<Option<Box<dyn _>>>`
//! slot, and a cap-gated install function — for six subsystems, and
//! `CapKind::{SchedPolicy, IoScheduler, CongestionControl, IdleGovernor,
//! Pager}` already exist (`capabilities/src/lib.rs:494-509`). So struct_ops
//! needs no new capability plumbing at all, and the reference implementation
//! to mirror is `power::install_governor` (`power/src/lib.rs:747`).
//!
//! ## What the macro emits
//!
//! 1. **the trait, unchanged** — native in-tree impls keep working and keep
//!    being the fast path;
//! 2. a [`StructOpsDesc`] in a `narf.structops` link section, carrying one
//!    [`MethodDesc`] per method with the ctx-type descriptors derived from the
//!    method's Rust signature through `BpfType`, exactly as `kfunc!` does;
//! 3. a cap-gated install entry point, named by the invocation.
//!
//! ## There is no trampoline, and there does not need to be
//!
//! Linux generates one per attach point — `arch_prepare_bpf_trampoline`, 306
//! lines of assembly emission (`bpf_jit_comp.c:3211`) — because it patches
//! machine code into an arbitrary kernel function's `__fentry__` nop. At that
//! seam there is no C, let alone Rust, to interpose: the trampoline *is* the
//! adapter, and it has to spill the native arguments into a stack array by
//! hand because nothing else can.
//!
//! NARF's struct_ops targets are `PLUGGABILITY.md` trait slots with a
//! **Rust-level install point**, so the adapter is an ordinary `impl` of the
//! trait. It builds the context tuple from its own typed arguments and calls
//! [`BpfProg::run_atomic`], which already owns frame acquisition and — when the
//! program compiled — the native call. Nothing needs generating.
//!
//! This is the clearest case in the subsystem of the clean-slate framing paying
//! off: the work is not done more cheaply than Linux, it is *absent*, because
//! the attach mechanism was chosen to be one a host language can express.
//! The generated impl below is what Linux spends a code generator on.

use alloc::vec::Vec;

use narf_bpf_verifier::kfunc::ArgDesc;
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use narf_bpf::prog::BpfProg;

/// One method of a struct_ops trait, as the verifier sees it.
#[derive(Copy, Clone, Debug)]
pub struct MethodDesc {
    /// The method name a program set binds against.
    pub name: &'static str,
    /// The context tuple: the method's real argument list, typed. There is no
    /// ctx-rewriting layer here — `struct __sk_buff` is a fiction that costs
    /// Linux `convert_ctx_accesses()` plus most of `net/core/filter.c`.
    pub ctx: &'static [ArgDesc],
    /// The return descriptor.
    pub ret: ArgDesc,
    /// Whether a program set may omit this method and inherit the trait's
    /// default implementation.
    pub optional: bool,
}

/// One struct_ops trait.
#[derive(Copy, Clone, Debug)]
pub struct StructOpsDesc {
    /// The trait name a program set names.
    pub name: &'static str,
    /// The capability required to install a program set for it.
    pub cap: CapKind,
    /// The methods, in declaration order.
    pub methods: &'static [MethodDesc],
}

// ── link-section collection ─────────────────────────────────────────

extern "Rust" {
    static __narf_structops_start: StructOpsDesc;
    static __narf_structops_end: StructOpsDesc;
}

/// Every `struct_ops!`-declared trait in the image.
#[must_use]
pub fn descriptors() -> &'static [StructOpsDesc] {
    // SAFETY: as `narf_bpf::kfunc::entries` — the linker synthesises the
    // bracketing symbols around the `narf.structops` section, whose only
    // writer is the `struct_ops!` macro, and `StructOpsDesc`'s size is a
    // multiple of its alignment so elements sit back to back.
    let (start, end) = unsafe {
        (
            &__narf_structops_start as *const StructOpsDesc,
            &__narf_structops_end as *const StructOpsDesc,
        )
    };
    let len = (end as usize - start as usize) / core::mem::size_of::<StructOpsDesc>();
    // SAFETY: `start` and `len` derive from the linker symbols above.
    unsafe { core::slice::from_raw_parts(start, len) }
}

// ── program sets ────────────────────────────────────────────────────

/// A method name bound to a verified program.
///
/// `Clone` is cheap — `prog` is an `Arc` — and it is what lets a committed
/// trait keep a copy in the [`INSTALLED`] record while handing another to the
/// live-slot adapter, both pointing at the same programs.
#[derive(Debug, Clone)]
pub struct Binding {
    /// The method this program implements.
    pub method: &'static str,
    /// The program.
    pub prog: alloc::sync::Arc<BpfProg>,
}

/// A set of programs implementing one struct_ops trait.
#[derive(Debug, Default, Clone)]
pub struct ProgSet {
    bindings: Vec<Binding>,
}

impl ProgSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `prog` to `method`.
    #[must_use]
    pub fn with(mut self, method: &'static str, prog: alloc::sync::Arc<BpfProg>) -> Self {
        self.bindings.push(Binding { method, prog });
        self
    }

    /// The bindings.
    #[must_use]
    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    /// The program bound to `method`, if any.
    ///
    /// Linear scan. A struct_ops trait has a handful of methods, so this beats
    /// a map on both allocation and cache behaviour — and it must not allocate,
    /// because a dispatch may happen in a context where the global allocator is
    /// off limits (spec §4.6). A per-method index is the optimisation if a hot
    /// slot ever needs it.
    #[must_use]
    pub fn get(&self, method: &str) -> Option<&alloc::sync::Arc<BpfProg>> {
        self.bindings
            .iter()
            .find(|b| b.method == method)
            .map(|b| &b.prog)
    }

    /// Whether `method` is bound.
    #[must_use]
    pub fn binds(&self, method: &str) -> bool {
        self.bindings.iter().any(|b| b.method == method)
    }
}

/// Why installing a program set failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StructOpsError {
    /// The capability was revoked between mint and use.
    AuthorityRevoked,
    /// The capability's kind does not match the one the trait declares.
    ///
    /// A runtime check rather than a type-level one because `macro_rules!`
    /// cannot synthesise the marker type's name; the declared `CapKind` in the
    /// descriptor is the source of truth either way.
    WrongCapability {
        /// What the trait requires.
        required: CapKind,
        /// What was presented.
        presented: CapKind,
    },
    /// A non-`#[optional]` method has no program bound.
    MissingMethod(&'static str),
    /// A binding names a method the trait does not declare.
    UnknownMethod,
    /// No trait with that name is registered.
    UnknownTrait,
    /// A bound program was verified for a context this hook does not provide.
    ///
    /// struct_ops dispatch is `Atomic`; a `Sleepable` program cannot run there,
    /// and binding one anyway made every call return `DEFAULT_RET` — the policy
    /// looks installed and does nothing.
    WrongContext {
        /// The method whose binding was rejected.
        method: &'static str,
    },
    /// The subsystem's live-slot installer rejected the adapter.
    ///
    /// Returned by a `#[commit(...)]` committer when moving the verified
    /// adapter into the subsystem's `Box<dyn Trait>` slot fails for a reason
    /// only the subsystem can name — a revoked slot authority, a governor that
    /// refuses to be replaced while active, and so on. The set is validated
    /// before the committer runs, so this never masks a malformed program set.
    CommitFailed(&'static str),
}

impl From<CapError> for StructOpsError {
    fn from(_: CapError) -> Self {
        StructOpsError::AuthorityRevoked
    }
}

/// Installed program sets, keyed by trait name.
///
/// The `Box<dyn Trait>` slot each pluggable subsystem already owns stays where
/// it is; this registry holds the *programs*, and Phase 5's generated adapter
/// is what bridges the two.
static INSTALLED: IrqSafeSpinLock<Vec<(&'static str, ProgSet)>> = IrqSafeSpinLock::new(Vec::new());

/// Install a program set for the trait `desc` describes.
///
/// Cap-gated exactly as `power::install_governor` is, with the one difference
/// that the capability type is a parameter and the required `CapKind` comes
/// from the descriptor.
///
/// # Errors
///
/// [`StructOpsError::WrongCapability`] if `M` is not the kind the trait
/// declares, [`StructOpsError::MissingMethod`] if a required method is
/// unbound, [`StructOpsError::UnknownMethod`] if a binding names a method the
/// trait does not have.
pub fn install<M: CapType>(
    desc: &StructOpsDesc,
    cap: &Cap<M, Grant>,
    set: ProgSet,
) -> Result<(), StructOpsError> {
    validate(desc, cap, &set)?;
    let mut slot = INSTALLED.lock();
    slot.retain(|(n, _)| *n != desc.name);
    slot.push((desc.name, set));
    Ok(())
}

/// Check that `set` is a legal implementation of `desc` under `cap`, without
/// recording or committing anything.
///
/// Split out of [`install`] so a `#[commit(...)]` trait can prove the set good
/// *before* building the adapter and handing it to the subsystem's live slot —
/// a malformed set must never reach the slot, and validating first is what
/// guarantees it. The checks are borrow-only, so the caller keeps ownership of
/// `set` to both record it and build the adapter from it.
///
/// # Errors
///
/// [`StructOpsError::WrongCapability`] if `M` is not the kind the trait
/// declares, [`StructOpsError::MissingMethod`] if a required method is unbound,
/// [`StructOpsError::UnknownMethod`] if a binding names a method the trait does
/// not declare, [`StructOpsError::WrongContext`] if a bound program was
/// verified for a context struct_ops dispatch cannot provide.
pub fn validate<M: CapType>(
    desc: &StructOpsDesc,
    cap: &Cap<M, Grant>,
    set: &ProgSet,
) -> Result<(), StructOpsError> {
    if M::KIND != desc.cap {
        return Err(StructOpsError::WrongCapability {
            required: desc.cap,
            presented: M::KIND,
        });
    }
    cap.check_live()?;
    for m in desc.methods {
        if !m.optional && !set.binds(m.name) {
            return Err(StructOpsError::MissingMethod(m.name));
        }
    }
    for b in set.bindings() {
        if !desc.methods.iter().any(|m| m.name == b.method) {
            return Err(StructOpsError::UnknownMethod);
        }
        // Every struct_ops dispatch goes through `run_atomic`, which returns
        // `None` for a program verified for `Sleepable` — and `None` maps to
        // `DEFAULT_RET`. So binding a sleepable program installed cleanly and
        // then silently returned the default on every call: the policy looks
        // installed and does nothing. Rejected at install, by type, exactly as
        // spec §4.5 requires and as `attach_probe` and (now) XDP attach do.
        if b.prog.context() != narf_bpf_verifier::Context::Atomic {
            return Err(StructOpsError::WrongContext { method: b.method });
        }
    }
    Ok(())
}

/// How many program sets are installed.
#[must_use]
pub fn installed_count() -> usize {
    INSTALLED.lock().len()
}

/// Whether a program set is installed for `trait_name`.
#[must_use]
pub fn is_installed(trait_name: &str) -> bool {
    INSTALLED.lock().iter().any(|(n, _)| *n == trait_name)
}

/// Const-context string equality, for the `#[optional(...)]` list.
#[must_use]
pub const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `name` appears in `list`. Evaluated in a `const` by the
/// `struct_ops!` macro.
#[must_use]
pub const fn is_optional(name: &str, list: &[&str]) -> bool {
    let mut i = 0;
    while i < list.len() {
        if str_eq(name, list[i]) {
            return true;
        }
        i += 1;
    }
    false
}

/// Declare a pluggable trait whose implementation may come from BPF.
///
/// ```ignore
/// narf_bpf::struct_ops! {
///     #[cap(IdleGovernor)]
///     #[install(install_bpf_idle_governor)]
///     #[desc(IDLE_GOVERNOR_OPS)]
///     #[optional(init)]
///     pub trait BpfIdleGovernor {
///         fn select_state(&self, expected_idle_ns: u64) -> u32;
///         fn init(&self) -> i32;
///     }
/// }
/// ```
///
/// The trait comes out verbatim, so a native impl is unaffected. `#[desc(…)]`
/// names the generated descriptor constant because `macro_rules!` cannot
/// derive an identifier from the trait name.
///
/// `#[optional(…)]` lists the methods a program set may omit rather than
/// tagging each one, because a per-method `#[optional]` attribute sits
/// immediately after that method's doc comments and `macro_rules!` cannot
/// choose between the two without lookahead into a fragment — a genuine local
/// ambiguity, not a stylistic preference. Listing them together also puts the
/// optional set in one visible place.
///
/// # Reaching a live slot: `#[commit(...)]`
///
/// Without `#[commit(...)]` the generated install entry point only *records*
/// the verified program set (so `is_installed` can see it); nothing runs it,
/// because there is no slot to run it from. A pluggable subsystem owns that
/// slot — the `IrqSafeSpinLock<Option<Box<dyn Trait>>>` its hot path dispatches
/// through — and names a committer with `#[commit(commit_fn)]`, placed *before*
/// any `#[optional(...)]`. The committer has the shape
///
/// ```ignore
/// fn commit_fn<M: CapType>(cap: &Cap<M, Grant>, adapter: TheAdapter)
///     -> Result<(), StructOpsError>;
/// ```
///
/// and moves the already-verified `adapter` into its slot. The generated
/// install fn validates the set, records it, builds the adapter, and calls the
/// committer — so a bad set never reaches the slot, and a good one becomes the
/// live implementation the subsystem's own query path invokes. This is the seam
/// that turns a loaded program set into behaviour.
#[macro_export]
macro_rules! struct_ops {
    ($(
        $(#[doc = $tdoc:literal])*
        #[cap($cap:ident)]
        #[install($install:ident)]
        #[desc($descname:ident)]
        #[adapter($descname2:ident)]
        $(#[commit($commit:path)])?
        $(#[optional($($optm:ident),* $(,)?)])?
        $vis:vis trait $trait_name:ident {
            $(
                $(#[doc = $mdoc:literal])*
                fn $method:ident (&self $(, $pname:ident : $pty:ty)* $(,)?) -> $mret:ty;
            )*
        }
    )*) => {$(
        $(#[doc = $tdoc])*
        $vis trait $trait_name: Send + Sync + 'static {
            $(
                $(#[doc = $mdoc])*
                fn $method (&self $(, $pname : $pty)*) -> $mret;
            )*
        }

        #[doc = concat!(
            "`struct_ops!`-generated descriptor for [`", stringify!($trait_name), "`]."
        )]
        $vis const $descname: $crate::structops::StructOpsDesc = {
            const OPTIONAL: &[&str] = &[$($(stringify!($optm)),*)?];
            $crate::structops::StructOpsDesc {
                name: stringify!($trait_name),
                cap: $crate::reexport::CapKind::$cap,
                methods: &[$(
                    $crate::structops::MethodDesc {
                        name: stringify!($method),
                        ctx: &[$(<$pty as $crate::types::BpfType>::DESC),*],
                        ret: <$mret as $crate::types::BpfType>::DESC,
                        optional: $crate::structops::is_optional(stringify!($method), OPTIONAL),
                    },
                )*],
            }
        };

        const _: () = {
            #[used]
            #[link_section = "narf.structops"]
            static ENTRY: $crate::structops::StructOpsDesc = $descname;
        };

        #[doc = concat!(
            "A BPF program set dispatching as [`", stringify!($trait_name), "`]."
        )]
        ///
        /// The adapter Linux generates a trampoline for. Each method packs its
        /// typed arguments into the context tuple and runs the bound program;
        /// a method with no program bound falls back to the trait's default,
        /// which is what `#[optional(...)]` declares.
        #[derive(Debug)]
        $vis struct $descname2 {
            progs: $crate::structops::ProgSet,
        }

        impl $descname2 {
            /// Wrap a program set.
            #[must_use]
            $vis fn new(progs: $crate::structops::ProgSet) -> Self {
                Self { progs }
            }
        }

        impl $trait_name for $descname2 {
            $(
                fn $method (&self $(, $pname : $pty)*) -> $mret {
                    // The context tuple is the method's own argument list —
                    // no rewriting layer, because there is no fictional UAPI
                    // struct to rewrite from (spec §1.6).
                    // Arity is a compile-time error, not a silent truncation.
                    //
                    // The adapter can only carry `MAX_CTX_WORDS` arguments, and
                    // it used to drop the rest with no diagnostic — while
                    // `MethodDesc::ctx` was still built from the *full*
                    // signature. So the descriptor the verifier consults
                    // described a wider context than the runtime can ever fill,
                    // and the moment struct_ops programs are verified against
                    // `MethodDesc::ctx` that becomes a proved-in-bounds read of
                    // a word nothing supplies. `kfunc!` already asserts its
                    // arity; this is the same brace for the other macro.
                    const _: () = {
                        let __arity = 0usize $(+ { let _ = stringify!($pname); 1 })*;
                        assert!(
                            __arity <= $crate::interp::MAX_CTX_WORDS,
                            "struct_ops method takes more arguments than the \
                             context tuple can carry",
                        );
                    };
                    #[allow(unused_mut)]
                    let mut __ctx = [0u64; $crate::interp::MAX_CTX_WORDS];
                    #[allow(unused_mut)]
                    let mut __n = 0usize;
                    $(
                        if __n < $crate::interp::MAX_CTX_WORDS {
                            __ctx[__n] =
                                <$pty as $crate::types::BpfType>::into_raw($pname);
                            __n += 1;
                        }
                    )*
                    match self.progs.get(stringify!($method)) {
                        Some(p) => match p.run_atomic(__ctx, __n) {
                            // Only a *returned* value decides. `Outcome::value()`
                            // is 0 for a trap, so matching on it sent every
                            // trapped run through `from_ret(0)` instead of
                            // `DEFAULT_RET` — benign only for as long as every
                            // `BpfRet::DEFAULT_RET` happens to be 0, which is not
                            // a property any implementor is asked to preserve.
                            // Same fix already applied to the XDP and perf paths.
                            Some($crate::interp::Outcome::Returned(v)) =>
                                <$mret as $crate::types::BpfRet>::from_ret(v),
                            // Declined (nesting limit, no frame) or trapped:
                            // fall back rather than fabricate a value. A
                            // policy hook returning nonsense is worse than one
                            // returning the default.
                            Some($crate::interp::Outcome::Trapped(_)) | None =>
                                <$mret as $crate::types::BpfRet>::DEFAULT_RET,
                        },
                        None => <$mret as $crate::types::BpfRet>::DEFAULT_RET,
                    }
                }
            )*
        }

        #[doc = concat!(
            "Install a BPF program set implementing [`", stringify!($trait_name),
            "`]. Cap-gated on the kind the trait declares."
        )]
        ///
        /// # Errors
        ///
        /// See [`narf_bpf_structops::structops::install`](narf_bpf_structops::structops::install).
        $vis fn $install<M: $crate::reexport::CapType>(
            cap: &$crate::reexport::Cap<M, $crate::reexport::Grant>,
            set: $crate::structops::ProgSet,
        ) -> ::core::result::Result<(), $crate::structops::StructOpsError> {
            // A `#[commit(...)]` trait builds its live-slot adapter from a
            // clone and keeps the original for the record — validating first so
            // a malformed set can never reach the slot. An uncommitted trait
            // builds nothing and lets the `install` below do the sole
            // validation, so its path is unchanged.
            #[allow(unused_mut, unused_variables)]
            let mut __adapter: ::core::option::Option<$descname2> =
                ::core::option::Option::None;
            $(
                let _ = ::core::stringify!($commit);
                $crate::structops::validate(&$descname, cap, &set)?;
                __adapter = ::core::option::Option::Some($descname2::new(
                    <$crate::structops::ProgSet as ::core::clone::Clone>::clone(&set),
                ));
            )?
            // Record the verified set so `is_installed`/`installed_count` see
            // it — for both committed and uncommitted traits.
            $crate::structops::install(&$descname, cap, set)?;
            // Hand the adapter to the subsystem's live slot, if one was named.
            // Uncommitted traits stop at the record above; there is nothing to
            // dispatch through.
            #[allow(unused_mut)]
            let mut __result: ::core::result::Result<(), $crate::structops::StructOpsError> =
                ::core::result::Result::Ok(());
            $(
                if let ::core::option::Option::Some(__a) = __adapter.take() {
                    __result = $commit(cap, __a);
                }
            )?
            __result
        }
    )*};
}
