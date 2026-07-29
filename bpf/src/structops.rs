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
//! ## What it does not emit yet
//!
//! The generated `BpfFoo` that implements the trait by invoking programs
//! through trampolines is Phase 5. Until then [`install`] records the program
//! set in a registry and reports it; nothing dispatches through it. Getting
//! the macro, the descriptors, and the registry right first is deliberate —
//! the trampoline is the mechanical part.

use alloc::vec::Vec;

use narf_bpf_verifier::kfunc::ArgDesc;
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::prog::BpfProg;

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
    // SAFETY: as `crate::kfunc::entries` — the linker synthesises the
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
#[derive(Debug)]
pub struct Binding {
    /// The method this program implements.
    pub method: &'static str,
    /// The program.
    pub prog: alloc::sync::Arc<BpfProg>,
}

/// A set of programs implementing one struct_ops trait.
#[derive(Debug, Default)]
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
    }
    let mut slot = INSTALLED.lock();
    slot.retain(|(n, _)| *n != desc.name);
    slot.push((desc.name, set));
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
#[macro_export]
macro_rules! struct_ops {
    ($(
        $(#[doc = $tdoc:literal])*
        #[cap($cap:ident)]
        #[install($install:ident)]
        #[desc($descname:ident)]
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
            "Install a BPF program set implementing [`", stringify!($trait_name),
            "`]. Cap-gated on the kind the trait declares."
        )]
        ///
        /// # Errors
        ///
        /// See [`narf_bpf::structops::install`](crate::structops::install).
        $vis fn $install<M: $crate::reexport::CapType>(
            cap: &$crate::reexport::Cap<M, $crate::reexport::Grant>,
            set: $crate::structops::ProgSet,
        ) -> ::core::result::Result<(), $crate::structops::StructOpsError> {
            $crate::structops::install(&$descname, cap, set)
        }
    )*};
}
