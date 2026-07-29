//! The `kfunc!` macro and the boot-time kfunc registry.
//!
//! NARF has exactly one way to call into the kernel from a BPF program.
//! Linux has two — a helper table (`check_helper_call()`, 534 lines, plus an
//! `ARG_*` enum) *and* kfuncs — and the semantics of both live outside the
//! function's type: in an enum table for helpers, in BTF parameter-name
//! suffixes for kfuncs. Here they live in the signature, and
//! [`crate::types::BpfType`] is what reads them out.
//!
//! ## What one `kfunc!` item expands to
//!
//! 1. the function, verbatim — it stays an ordinary Rust `fn` that other
//!    kernel code can call directly;
//! 2. an `extern "C"` shim with the uniform
//!    `fn(u64, u64, u64, u64, u64) -> u64` signature, which unpacks each
//!    argument register into its declared Rust type (`Option<T>` from a null
//!    register, `&[u8]` from a pointer and the next register's length) and
//!    packs the return back into R0;
//! 3. a `#[used] #[link_section = "narf.kfuncs"]` [`KfuncEntry`], collected at
//!    boot exactly as `narf-kernel-test` collects `narf.tests` via
//!    `__narf_tests_start`/`__narf_tests_end`;
//! 4. a `const _: () = { … }` block asserting the signature is legal — every
//!    argument type implements `BpfType` and is legal in argument position,
//!    the return type is legal in return position, and the argument list is
//!    well-formed (`≤ 5` arguments, every `SIZED_BY_NEXT` region followed by
//!    a scalar length).
//!
//! Adding a kfunc therefore never touches the verifier.
//!
//! ## Why a separate `KfuncEntry`
//!
//! The verifier's [`KfuncDesc`] holds the shim address as a `usize`, and a
//! function pointer cannot be cast to an integer during const evaluation. The
//! link-section entry stores a real `fn` pointer and the boot-time collector
//! materialises the `KfuncDesc`. That split is the right layering anyway: the
//! entry is a runtime artefact, the descriptor is the verifier's view.
//!
//! ## Identity
//!
//! A `call` instruction with `src_reg == BPF_PSEUDO_KFUNC_CALL` carries the
//! callee in `imm`. Linux puts a BTF type id there, which is assigned per
//! kernel build. NARF puts [`KfuncEntry::id`] — an FNV-1a hash of the name —
//! so the same object file resolves against any NARF build, and a loader can
//! compute the id without reading BTF.

use alloc::vec::Vec;

use narf_bpf_verifier::kfunc::MAX_KFUNC_ARGS;
use narf_bpf_verifier::kfunc::{ArgDesc, ArgFlags, Context, KfuncDesc, KfuncError, TypeKind};
use narf_lib::sync::IrqSafeSpinLock;

use crate::types::{fnv1a32_nonzero, BpfType};

/// The uniform kfunc calling convention.
///
/// One signature for every kfunc, so the interpreter needs one
/// `core::mem::transmute` site and the JIT needs one call sequence. Arguments
/// the callee does not declare are passed as zero.
pub type KfuncShim = extern "C" fn(u64, u64, u64, u64, u64) -> u64;

/// One entry in the `narf.kfuncs` link section.
#[derive(Copy, Clone, Debug)]
pub struct KfuncEntry {
    /// The name programs refer to.
    pub name: &'static str,
    /// The `extern "C"` shim.
    pub shim: KfuncShim,
    /// Parameter descriptors, in declaration order.
    pub args: &'static [ArgDesc],
    /// Return descriptor.
    pub ret: ArgDesc,
    /// The weakest execution context this may be called from.
    pub context: Context,
}

impl KfuncEntry {
    /// The id a `call` instruction's `imm` field carries.
    #[inline]
    #[must_use]
    pub fn id(&self) -> i32 {
        fnv1a32_nonzero(self.name) as i32
    }

    /// The verifier's view of this kfunc.
    #[must_use]
    pub fn desc(&self) -> KfuncDesc {
        KfuncDesc {
            // The verifier resolves a `call` by matching this id against the
            // instruction's `imm`, so it must be the same hash `id()` hands
            // out to whoever emitted the program. Leaving it unset would make
            // every kfunc call fail to resolve — fail-closed, but silently.
            id: self.id(),
            name: self.name,
            addr: self.shim as usize,
            args: self.args,
            ret: self.ret,
            context: self.context,
        }
    }
}

/// The id for a kfunc name, so callers (and test programs) can compute a
/// `call` immediate without consulting the registry.
#[inline]
#[must_use]
pub fn id_for(name: &str) -> i32 {
    fnv1a32_nonzero(name) as i32
}

// ── link-section collection ─────────────────────────────────────────

extern "Rust" {
    static __narf_kfuncs_start: KfuncEntry;
    static __narf_kfuncs_end: KfuncEntry;
}

/// Every `kfunc!`-declared entry in the image.
///
/// Mirrors `narf_kernel_test::tests()`; the linker synthesises the bracketing
/// symbols around the `narf.kfuncs` output section.
#[must_use]
pub fn entries() -> &'static [KfuncEntry] {
    // SAFETY: the linker synthesises `__narf_kfuncs_start`/`_end` at the
    // boundaries of the `narf.kfuncs` output section, which the `kfunc!`
    // macro is the only writer of. Every element is a `KfuncEntry` laid out
    // back-to-back: the section is 8-aligned and `KfuncEntry`'s size is a
    // multiple of its 8-byte alignment, so there is no inter-element padding
    // for the pointer arithmetic below to trip over.
    let (start, end) = unsafe {
        (
            &__narf_kfuncs_start as *const KfuncEntry,
            &__narf_kfuncs_end as *const KfuncEntry,
        )
    };
    let len = (end as usize - start as usize) / core::mem::size_of::<KfuncEntry>();
    // SAFETY: `start` and `len` derive from the linker symbols above.
    unsafe { core::slice::from_raw_parts(start, len) }
}

// ── registry ────────────────────────────────────────────────────────

/// Why the boot-time registry build failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// A descriptor failed `KfuncDesc::validate`. Carries the offending name.
    Malformed(&'static str, KfuncError),
    /// Two kfuncs hash to the same id — a build-time bug, since the id is a
    /// pure function of the name and names must be unique.
    DuplicateId(&'static str, &'static str),
}

/// The collected, validated kfunc set.
///
/// Built once at boot and never mutated, so lookups need no lock. Held behind
/// an `IrqSafeSpinLock<Option<_>>` only for the one-shot install; the hot path
/// takes a `&'static` snapshot via [`registry`].
#[derive(Debug)]
pub struct Registry {
    entries: Vec<KfuncEntry>,
}

impl Registry {
    /// Validate and collect every entry in the `narf.kfuncs` section.
    ///
    /// # Errors
    ///
    /// Returns the first malformed or duplicate descriptor. Both are
    /// build-time bugs in a `kfunc!` invocation, so failing loudly at boot
    /// beats letting the verifier reason from a broken contract
    /// (`bpf/specification/spec.md` §4.11).
    pub fn build() -> Result<Self, RegistryError> {
        let src = entries();
        let mut out: Vec<KfuncEntry> = Vec::with_capacity(src.len());
        for e in src {
            e.desc()
                .validate()
                .map_err(|err| RegistryError::Malformed(e.name, err))?;
            if let Some(prev) = out.iter().find(|p| p.id() == e.id()) {
                return Err(RegistryError::DuplicateId(prev.name, e.name));
            }
            out.push(*e);
        }
        Ok(Self { entries: out })
    }

    /// Look a kfunc up by the id a `call` immediate carries.
    #[must_use]
    pub fn by_id(&self, id: i32) -> Option<&KfuncEntry> {
        self.entries.iter().find(|e| e.id() == id)
    }

    /// Look a kfunc up by name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&KfuncEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Every registered kfunc.
    #[must_use]
    pub fn all(&self) -> &[KfuncEntry] {
        &self.entries
    }

    /// How many kfuncs are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// One-shot boot install. `&'static Registry` is leaked deliberately: the set
// is immutable for the kernel's life, and a `&'static` lets the interpreter
// resolve a kfunc without taking a lock on a path that may run with IRQs
// masked under `tracing::dispatch`'s table lock.
static REGISTRY: IrqSafeSpinLock<Option<&'static Registry>> = IrqSafeSpinLock::new(None);

/// Build and install the registry. Idempotent; the second call is a no-op.
///
/// # Errors
///
/// Propagates [`Registry::build`].
pub fn install() -> Result<usize, RegistryError> {
    let mut slot = REGISTRY.lock();
    if let Some(r) = *slot {
        return Ok(r.len());
    }
    let built = Registry::build()?;
    let n = built.len();
    let leaked: &'static Registry = alloc::boxed::Box::leak(alloc::boxed::Box::new(built));
    *slot = Some(leaked);
    Ok(n)
}

/// The installed registry, or `None` before `install()` runs.
#[must_use]
pub fn registry() -> Option<&'static Registry> {
    *REGISTRY.lock()
}

// ── macro support ───────────────────────────────────────────────────

/// Whether an argument list is well-formed. Evaluated in a `const` block by
/// the `kfunc!` macro, so a malformed signature is a compile error rather
/// than a boot failure.
#[must_use]
pub const fn args_well_formed(args: &[ArgDesc]) -> bool {
    if args.len() > MAX_KFUNC_ARGS {
        return false;
    }
    let mut i = 0;
    while i < args.len() {
        if matches!(args[i].kind, TypeKind::Void) {
            return false;
        }
        if args[i].flags.contains(ArgFlags::SIZED_BY_NEXT) {
            if i + 1 >= args.len() {
                return false;
            }
            if !matches!(args[i + 1].kind, TypeKind::Scalar { .. }) {
                return false;
            }
        }
        i += 1;
    }
    true
}

/// Unpack argument `i` from the shim's register array.
///
/// # Safety
///
/// The registers must satisfy `T::DESC` — see [`BpfType::from_raw`].
#[doc(hidden)]
#[inline]
pub unsafe fn __arg<T: BpfType>(raw: &[u64; MAX_KFUNC_ARGS], i: usize) -> T {
    let next = if i + 1 < MAX_KFUNC_ARGS {
        raw[i + 1]
    } else {
        0
    };
    // SAFETY: forwarded from the caller's obligation.
    unsafe { T::from_raw(raw[i], next) }
}

/// Declare one or more kfuncs.
///
/// Every item declares its execution context explicitly, because
/// `bpf/specification/spec.md` §4.5 makes sleepability a property of the
/// *hook* rather than a program flag — a kfunc that can sleep must say so, and
/// is then unreachable from atomic programs by type rather than by a runtime
/// check.
///
/// ```ignore
/// narf_bpf::kfunc! {
///     /// Monotonic nanoseconds since boot.
///     #[context(Atomic)]
///     pub fn narf_ktime_get_ns() -> u64 {
///         narf_time::monotonic_ns()
///     }
/// }
/// ```
///
/// The return type is mandatory; write `-> ()` for a kfunc that returns
/// nothing.
#[macro_export]
macro_rules! kfunc {
    ($(
        $(#[doc = $doc:literal])*
        #[context($ctx:ident)]
        $vis:vis fn $name:ident ( $($pname:ident : $pty:ty),* $(,)? ) -> $ret:ty $body:block
    )*) => {$(
        $(#[doc = $doc])*
        $vis fn $name ( $($pname : $pty),* ) -> $ret $body

        const _: () = {
            // The signature assertions. Each is a plain `const` assert, so a
            // bad kfunc fails to build rather than failing to verify.
            $(
                assert!(
                    <$pty as $crate::types::BpfType>::LEGAL_IN_ARG,
                    concat!(
                        "kfunc `", stringify!($name), "`: parameter `",
                        stringify!($pname), "` has a type that is not legal in \
                         argument position"
                    ),
                );
            )*
            assert!(
                <$ret as $crate::types::BpfType>::LEGAL_IN_RET,
                concat!(
                    "kfunc `", stringify!($name),
                    "`: return type is not legal in return position"
                ),
            );
            assert!(
                $crate::kfunc::args_well_formed(ARGS),
                concat!(
                    "kfunc `", stringify!($name),
                    "`: malformed argument list (more than 5 arguments, a \
                     void argument, or a sized region not followed by a \
                     scalar length)"
                ),
            );

            const ARGS: &[$crate::reexport::ArgDesc] =
                &[$(<$pty as $crate::types::BpfType>::DESC),*];

            // Uniform-ABI entry point; see `crate::kfunc::KfuncShim`.
            extern "C" fn __shim(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
                let __raw = [a0, a1, a2, a3, a4];
                // Positional index. `macro_rules!` cannot count, so the
                // counter is a local the optimiser folds away.
                #[allow(unused_mut)]
                let mut __i = 0usize;
                $(
                    let $pname: $pty = {
                        // SAFETY: the verifier proved every register satisfies
                        // the corresponding `ArgDesc` before emitting this
                        // call — that is the whole point of verification.
                        let __v = unsafe { $crate::kfunc::__arg::<$pty>(&__raw, __i) };
                        __i += 1;
                        __v
                    };
                )*
                let _ = (&__raw, __i);
                $crate::types::BpfType::into_raw($name($($pname),*))
            }

            #[used]
            #[link_section = "narf.kfuncs"]
            static ENTRY: $crate::kfunc::KfuncEntry = $crate::kfunc::KfuncEntry {
                name: stringify!($name),
                shim: __shim,
                args: ARGS,
                ret: <$ret as $crate::types::BpfType>::DESC,
                context: $crate::reexport::Context::$ctx,
            };
        };
    )*};
}
