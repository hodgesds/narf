//! Contract-bound runtime implementations of pluggable kernel traits.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_bpf::prog::{BpfProg, StructOpsContract};
use narf_bpf_verifier::kfunc::{ArgDesc, Context};
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

mod ctx_arg_sealed {
    pub trait Sealed {}

    macro_rules! impl_sealed {
        ($($ty:ty),* $(,)?) => {$(impl Sealed for $ty {})*};
    }

    impl_sealed!(u8, u16, u32, u64, i8, i16, i32, i64, bool);
}

/// A value that may be exposed in a struct-ops context tuple.
///
/// Only scalars implement this trait. References, raw pointers, physical
/// addresses, and general [`narf_bpf::types::BpfType`] pointer wrappers do not.
///
/// ```compile_fail
/// use narf_bpf_structops::BpfCtxArg;
/// fn require_context_arg<T: BpfCtxArg>() {}
/// require_context_arg::<&'static u64>();
/// ```
pub trait BpfCtxArg: ctx_arg_sealed::Sealed + Copy + Send + Sync + 'static {
    /// Verifier-visible scalar descriptor.
    const DESC: ArgDesc;
    /// Encode one context word.
    fn encode(self) -> u64;
}

macro_rules! impl_ctx_arg {
    ($($ty:ty),* $(,)?) => {$(
        impl BpfCtxArg for $ty {
            const DESC: ArgDesc = <$ty as narf_bpf::types::BpfType>::DESC;

            #[inline]
            fn encode(self) -> u64 {
                <Self as narf_bpf::types::BpfType>::into_raw(self)
            }
        }
    )*};
}

impl_ctx_arg!(u8, u16, u32, u64, i8, i16, i32, i64);

impl BpfCtxArg for bool {
    const DESC: ArgDesc = <u8 as narf_bpf::types::BpfType>::DESC;

    #[inline]
    fn encode(self) -> u64 {
        u64::from(self)
    }
}

/// One method of a struct-ops target.
#[derive(Copy, Clone, Debug)]
pub struct MethodDesc {
    /// Stable method name for diagnostics.
    pub name: &'static str,
    /// Stable method id within the target.
    pub id: u32,
    /// Hash of the target version and method signature.
    pub abi_hash: u64,
    /// Exact scalar context tuple.
    pub ctx: &'static [ArgDesc],
    /// Result descriptor.
    pub ret: ArgDesc,
    /// Complete kfunc allowlist.
    pub allowed_kfuncs: &'static [i32],
    /// Hook execution context.
    pub context: Context,
    /// Per-call fuel budget.
    pub fuel: u64,
    /// Stable native-fallback name.
    pub fallback: &'static str,
    /// Whether the generated builder may omit this method.
    pub optional: bool,
}

impl MethodDesc {
    /// Materialize the complete load and dispatch contract.
    #[must_use]
    pub const fn contract(&self, target_id: u64) -> StructOpsContract {
        StructOpsContract {
            target_id,
            method_id: self.id,
            abi_hash: self.abi_hash,
            ctx: self.ctx,
            ret: self.ret,
            allowed_kfuncs: self.allowed_kfuncs,
            context: self.context,
            fuel: self.fuel,
            fallback: self.fallback,
        }
    }
}

/// One versioned struct-ops target.
#[derive(Copy, Clone, Debug)]
pub struct StructOpsDesc {
    /// Rust trait name, for diagnostics.
    pub name: &'static str,
    /// Stable external target name.
    pub target: &'static str,
    /// Stable hash of `target`.
    pub target_id: u64,
    /// Contract version.
    pub version: u32,
    /// Capability required to install this target.
    pub cap: CapKind,
    /// Execution context shared by every method in this target.
    pub context: Context,
    /// Methods in declaration order.
    pub methods: &'static [MethodDesc],
}

impl StructOpsDesc {
    /// Find a method by stable id.
    #[must_use]
    pub fn method(&self, id: u32) -> Option<&MethodDesc> {
        self.methods.iter().find(|method| method.id == id)
    }
}

extern "Rust" {
    static __narf_structops_start: StructOpsDesc;
    static __narf_structops_end: StructOpsDesc;
}

/// Every `struct_ops!` descriptor linked into the image.
#[must_use]
pub fn descriptors() -> &'static [StructOpsDesc] {
    // SAFETY: the linker brackets a section written only by `struct_ops!`.
    let (start, end) = unsafe {
        (
            &__narf_structops_start as *const StructOpsDesc,
            &__narf_structops_end as *const StructOpsDesc,
        )
    };
    let len = (end as usize - start as usize) / core::mem::size_of::<StructOpsDesc>();
    // SAFETY: `start` and `len` came from the linker symbols above.
    unsafe { core::slice::from_raw_parts(start, len) }
}

/// One typed method binding, constructed by a generated builder.
#[derive(Debug, Clone)]
pub struct Binding {
    method_id: u32,
    prog: Arc<BpfProg>,
}

/// Programs prepared by a target-specific builder.
#[derive(Debug, Default, Clone)]
pub struct ProgSet {
    bindings: Vec<Binding>,
}

impl ProgSet {
    /// Internal macro support: bind an already contract-loaded program.
    #[doc(hidden)]
    pub fn bind(&mut self, method_id: u32, prog: Arc<BpfProg>) {
        if let Some(binding) = self
            .bindings
            .iter_mut()
            .find(|binding| binding.method_id == method_id)
        {
            binding.prog = prog;
        } else {
            self.bindings.push(Binding { method_id, prog });
        }
    }

    /// Program for a stable method id.
    #[must_use]
    pub fn get(&self, method_id: u32) -> Option<&Arc<BpfProg>> {
        self.bindings
            .iter()
            .find(|binding| binding.method_id == method_id)
            .map(|binding| &binding.prog)
    }

    fn binds(&self, method_id: u32) -> bool {
        self.get(method_id).is_some()
    }
}

/// Why a struct-ops attachment failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StructOpsError {
    /// The capability was revoked between mint and use.
    AuthorityRevoked,
    /// The capability kind does not match the target.
    WrongCapability {
        /// Required kind.
        required: CapKind,
        /// Presented kind.
        presented: CapKind,
    },
    /// A required method was omitted.
    MissingMethod(&'static str),
    /// A program was not verified for the exact method contract.
    WrongProgram(&'static str),
    /// A descriptor contains invalid or duplicate metadata.
    MalformedDescriptor(&'static str),
    /// Another install or detach transaction is in progress.
    Busy,
    /// Registry snapshot allocation failed.
    NoMemory,
    /// The subsystem rejected the prepared adapter.
    CommitFailed(&'static str),
}

impl From<CapError> for StructOpsError {
    fn from(_: CapError) -> Self {
        Self::AuthorityRevoked
    }
}

/// Validate authority, descriptor shape, completeness, and exact contracts.
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
    if desc.target_id == 0 || desc.version == 0 || desc.methods.is_empty() {
        return Err(StructOpsError::MalformedDescriptor(desc.name));
    }
    if descriptors()
        .iter()
        .filter(|registered| registered.target_id == desc.target_id)
        .count()
        != 1
    {
        return Err(StructOpsError::MalformedDescriptor(desc.name));
    }
    for (index, method) in desc.methods.iter().enumerate() {
        if method.id == 0
            || method.abi_hash == 0
            || method.fallback.is_empty()
            || method.fuel == 0
            || method.context != desc.context
            || desc.methods[..index]
                .iter()
                .any(|earlier| earlier.id == method.id)
        {
            return Err(StructOpsError::MalformedDescriptor(method.name));
        }
        if !method.optional && !set.binds(method.id) {
            return Err(StructOpsError::MissingMethod(method.name));
        }
    }
    for binding in &set.bindings {
        let Some(method) = desc.method(binding.method_id) else {
            return Err(StructOpsError::MalformedDescriptor(desc.name));
        };
        if binding.prog.struct_ops_contract() != Some(method.contract(desc.target_id)) {
            return Err(StructOpsError::WrongProgram(method.name));
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct InstalledRecord {
    target_id: u64,
    name: &'static str,
    generation: u64,
    state: Arc<AttachmentState>,
}

static INSTALLED: IrqSafeSpinLock<Option<Arc<Vec<InstalledRecord>>>> = IrqSafeSpinLock::new(None);
static INSTALL_BUSY: AtomicBool = AtomicBool::new(false);
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Admission gate shared by one generated adapter and its owning link.
///
/// A caller that observes `true` has created an in-flight invocation and may
/// finish after detach. Once the link stores `false`, later adapter calls take
/// their native fallback without entering BPF, even if a caller retained an
/// old `Arc` to the displaced adapter.
#[doc(hidden)]
#[derive(Debug)]
pub struct AttachmentState {
    active: AtomicBool,
}

impl AttachmentState {
    /// Construct an unpublished live gate.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active: AtomicBool::new(true),
        }
    }

    /// Admit one invocation.
    #[inline]
    #[must_use]
    pub fn admit(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    fn close(&self) {
        self.active.store(false, Ordering::Release);
    }
}

impl Default for AttachmentState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct InstallPermit;

impl InstallPermit {
    fn try_acquire() -> Result<Self, StructOpsError> {
        INSTALL_BUSY
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| StructOpsError::Busy)
    }

    fn acquire_for_drop() -> Self {
        loop {
            if let Ok(permit) = Self::try_acquire() {
                return permit;
            }
            core::hint::spin_loop();
        }
    }
}

impl Drop for InstallPermit {
    fn drop(&mut self) {
        INSTALL_BUSY.store(false, Ordering::Release);
    }
}

/// A validated install with all fallible registry allocation completed.
#[doc(hidden)]
#[derive(Debug)]
pub struct PreparedInstall {
    _permit: InstallPermit,
    desc: &'static StructOpsDesc,
    generation: u64,
    set: ProgSet,
    state: Arc<AttachmentState>,
    next: Arc<Vec<InstalledRecord>>,
}

impl PreparedInstall {
    /// Generation the subsystem must publish beside the adapter.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Validate and prepare a transactional installation.
#[doc(hidden)]
pub fn prepare_install<M: CapType>(
    desc: &'static StructOpsDesc,
    cap: &Cap<M, Grant>,
    set: ProgSet,
    state: Arc<AttachmentState>,
) -> Result<PreparedInstall, StructOpsError> {
    validate(desc, cap, &set)?;
    let permit = InstallPermit::try_acquire()?;
    let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
    if generation == 0 {
        return Err(StructOpsError::MalformedDescriptor(desc.name));
    }
    let snapshot = INSTALLED.lock().clone();
    let old_len = snapshot.as_ref().map_or(0, |records| records.len());
    let mut records = Vec::new();
    records
        .try_reserve_exact(old_len.saturating_add(1))
        .map_err(|_| StructOpsError::NoMemory)?;
    if let Some(snapshot) = snapshot {
        records.extend(
            snapshot
                .iter()
                .filter(|record| record.target_id != desc.target_id)
                .cloned(),
        );
    }
    records.push(InstalledRecord {
        target_id: desc.target_id,
        name: desc.name,
        generation,
        state: state.clone(),
    });
    Ok(PreparedInstall {
        _permit: permit,
        desc,
        generation,
        set,
        state,
        next: Arc::new(records),
    })
}

/// Subsystem callback used when an owning link closes.
pub type DetachFn = fn(u64) -> bool;

/// Publish a successful subsystem commit and return its owning link.
#[doc(hidden)]
pub fn finish_install(prepared: PreparedInstall, detach: DetachFn) -> StructOpsLink {
    let PreparedInstall {
        _permit,
        desc,
        generation,
        set,
        state,
        next,
    } = prepared;
    let old = {
        let mut installed = INSTALLED.lock();
        installed.replace(next)
    };
    if let Some(old) = &old {
        for record in old
            .iter()
            .filter(|record| record.target_id == desc.target_id && record.generation != generation)
        {
            record.state.close();
        }
    }
    drop(old);
    drop(_permit);
    StructOpsLink {
        target_id: desc.target_id,
        target_name: desc.name,
        generation,
        detach,
        state,
        attached: true,
        _programs: set,
    }
}

/// Owning lifetime of one live struct-ops attachment.
#[derive(Debug)]
pub struct StructOpsLink {
    target_id: u64,
    target_name: &'static str,
    generation: u64,
    detach: DetachFn,
    state: Arc<AttachmentState>,
    attached: bool,
    _programs: ProgSet,
}

impl StructOpsLink {
    /// Stable target name.
    #[must_use]
    pub const fn target_name(&self) -> &'static str {
        self.target_name
    }

    /// Attachment generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Detach explicitly. Dropping an already-closed link is a no-op.
    pub fn close(mut self) {
        self.detach_now();
    }

    fn detach_now(&mut self) {
        if !self.attached {
            return;
        }
        self.attached = false;
        // Linearization point for invocation admission. Calls admitted before
        // this store are in flight and retain their adapter; calls after it
        // take the generated fallback without touching BPF.
        self.state.close();
        let _permit = InstallPermit::acquire_for_drop();

        // Prepare the diagnostic-registry replacement outside its IRQ-masking
        // lock. The live subsystem detacher is likewise required to move any
        // displaced Arc out of its lock before dropping it.
        let snapshot = INSTALLED.lock().clone();
        let mut records = Vec::with_capacity(snapshot.as_ref().map_or(0, |r| r.len()));
        if let Some(snapshot) = snapshot {
            records.extend(
                snapshot
                    .iter()
                    .filter(|record| {
                        record.target_id != self.target_id || record.generation != self.generation
                    })
                    .cloned(),
            );
        }
        let replacement = if records.is_empty() {
            None
        } else {
            Some(Arc::new(records))
        };
        let _ = (self.detach)(self.generation);
        let old = {
            let mut installed = INSTALLED.lock();
            core::mem::replace(&mut *installed, replacement)
        };
        drop(old);
    }
}

impl Drop for StructOpsLink {
    fn drop(&mut self) {
        self.detach_now();
    }
}

/// Number of currently owned attachments.
#[must_use]
pub fn installed_count() -> usize {
    INSTALLED.lock().as_ref().map_or(0, |records| records.len())
}

/// Whether a target currently has an owning link.
#[must_use]
pub fn is_installed(trait_name: &str) -> bool {
    INSTALLED
        .lock()
        .as_ref()
        .is_some_and(|records| records.iter().any(|record| record.name == trait_name))
}

/// FNV-1a 64-bit stable id and hash.
#[must_use]
pub const fn fnv1a64(value: &str) -> u64 {
    let bytes = value.as_bytes();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    if hash == 0 {
        1
    } else {
        hash
    }
}

/// FNV-1a 32-bit stable method id.
#[must_use]
pub const fn fnv1a32(value: &str) -> u32 {
    let bytes = value.as_bytes();
    let mut hash = 0x811c_9dc5u32;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        index += 1;
    }
    if hash == 0 {
        1
    } else {
        hash
    }
}

/// Const string equality for the optional-method table.
#[must_use]
pub const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut index = 0;
    while index < a.len() {
        if a[index] != b[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Whether a method name is listed as optional.
#[must_use]
pub const fn is_optional(name: &str, list: &[&str]) -> bool {
    let mut index = 0;
    while index < list.len() {
        if str_eq(name, list[index]) {
            return true;
        }
        index += 1;
    }
    false
}

/// Declare a contract-bound BPF implementation of a pluggable trait.
///
/// Atomic targets use ordinary methods. A target marked
/// `#[context(Sleepable)]` uses `async fn` declarations; the generated trait
/// lowers them to the object-safe [`crate::StructOpsFuture`] ABI.
#[macro_export]
macro_rules! struct_ops {
    ($(
        $(#[doc = $tdoc:literal])*
        #[target($target:literal)]
        #[version($version:literal)]
        #[context(Sleepable)]
        #[cap($cap:ident)]
        #[install($install:ident)]
        #[desc($descname:ident)]
        #[adapter($adapter:ident)]
        #[builder($builder:ident)]
        #[commit($commit:path)]
        #[detach($detach:path)]
        $(#[optional($($optm:ident),* $(,)?)])?
        $vis:vis trait $trait_name:ident {
            $(
                $(#[doc = $mdoc:literal])*
                #[fallback($fallback:path)]
                #[validate($result:path)]
                #[fuel($fuel:expr)]
                #[kfuncs($($kfunc:expr),* $(,)?) ]
                async fn $method:ident (&self $(, $pname:ident : $pty:ty)* $(,)?) -> $mret:ty;
            )*
        }
    )*) => {
        $crate::__sleepable_struct_ops_impl! {$(
            $(#[doc = $tdoc])*
            #[target($target)]
            #[version($version)]
            #[cap($cap)]
            #[install($install)]
            #[desc($descname)]
            #[adapter($adapter)]
            #[builder($builder)]
            #[commit($commit)]
            #[detach($detach)]
            $(#[optional($($optm),*)])?
            $vis trait $trait_name {
                $(
                    $(#[doc = $mdoc])*
                    #[fallback($fallback)]
                    #[validate($result)]
                    #[fuel($fuel)]
                    #[kfuncs($($kfunc),*)]
                    async fn $method(&self $(, $pname : $pty)*) -> $mret;
                )*
            }
        )*}
    };

    ($(
        $(#[doc = $tdoc:literal])*
        #[target($target:literal)]
        #[version($version:literal)]
        #[cap($cap:ident)]
        #[install($install:ident)]
        #[desc($descname:ident)]
        #[adapter($adapter:ident)]
        #[builder($builder:ident)]
        #[commit($commit:path)]
        #[detach($detach:path)]
        $(#[optional($($optm:ident),* $(,)?)])?
        $vis:vis trait $trait_name:ident {
            $(
                $(#[doc = $mdoc:literal])*
                #[fallback($fallback:path)]
                #[validate($result:path)]
                #[fuel($fuel:expr)]
                #[kfuncs($($kfunc:expr),* $(,)?) ]
                fn $method:ident (&self $(, $pname:ident : $pty:ty)* $(,)?) -> $mret:ty;
            )*
        }
    )*) => {$(
        $(#[doc = $tdoc])*
        $vis trait $trait_name: Send + Sync + 'static {
            $(
                $(#[doc = $mdoc])*
                fn $method(&self $(, $pname: $pty)*) -> $mret;
            )*
        }

        $vis const $descname: $crate::structops::StructOpsDesc = {
            const OPTIONAL: &[&str] = &[$($(stringify!($optm)),*)?];
            $crate::structops::StructOpsDesc {
                name: stringify!($trait_name),
                target: $target,
                target_id: $crate::structops::fnv1a64($target),
                version: $version,
                cap: $crate::reexport::CapKind::$cap,
                context: $crate::verifier::Context::Atomic,
                methods: &[$(
                    $crate::structops::MethodDesc {
                        name: stringify!($method),
                        id: $crate::structops::fnv1a32(concat!(
                            $target,
                            "::",
                            stringify!($method),
                        )),
                        abi_hash: $crate::structops::fnv1a64(concat!(
                            $target,
                            "@",
                            stringify!($version),
                            "::",
                            stringify!($method),
                            "::",
                            stringify!(fn($($pty),*) -> $mret),
                        )),
                        ctx: &[$(<$pty as $crate::structops::BpfCtxArg>::DESC),*],
                        ret: <$mret as $crate::types::BpfRet>::DESC,
                        allowed_kfuncs: &[$($kfunc),*],
                        context: $crate::verifier::Context::Atomic,
                        fuel: $fuel,
                        fallback: stringify!($fallback),
                        optional: $crate::structops::is_optional(
                            stringify!($method),
                            OPTIONAL,
                        ),
                    },
                )*],
            }
        };

        const _: () = {
            #[used]
            #[link_section = "narf.structops"]
            static ENTRY: $crate::structops::StructOpsDesc = $descname;
        };

        /// Target-specific, method-safe program builder.
        #[derive(Debug, Default)]
        $vis struct $builder {
            $($method: ::core::option::Option<$crate::runtime::Arc<$crate::runtime::BpfProg>>,)*
        }

        #[allow(dead_code)]
        impl $builder {
            /// Start an empty target-specific program set.
            #[must_use]
            $vis fn new() -> Self {
                Self::default()
            }

            $(
                #[doc = concat!("Verify and bind `", stringify!($method), "`.")]
                $vis fn $method(
                    mut self,
                    cap: &$crate::reexport::Cap<
                        $crate::runtime::BpfProgLoad,
                        $crate::reexport::Grant,
                    >,
                    req: $crate::runtime::LoadRequest,
                ) -> ::core::result::Result<Self, $crate::runtime::LoadError> {
                    let id = $crate::structops::fnv1a32(concat!(
                        $target,
                        "::",
                        stringify!($method),
                    ));
                    let method = $descname
                        .method(id)
                        .expect("generated struct_ops method missing from descriptor");
                    self.$method = ::core::option::Option::Some(
                        $crate::runtime::BpfProg::load_for_struct_ops(
                            cap,
                            req,
                            method.contract($descname.target_id),
                        )?,
                    );
                    ::core::result::Result::Ok(self)
                }
            )*

            fn into_set(self) -> $crate::structops::ProgSet {
                let mut set = $crate::structops::ProgSet::default();
                $(
                    if let ::core::option::Option::Some(prog) = self.$method {
                        set.bind(
                            $crate::structops::fnv1a32(concat!(
                                $target,
                                "::",
                                stringify!($method),
                            )),
                            prog,
                        );
                    }
                )*
                set
            }
        }

        /// Generated Rust adapter used by the subsystem's live slot.
        #[derive(Debug)]
        $vis struct $adapter {
            progs: $crate::structops::ProgSet,
            state: $crate::runtime::Arc<$crate::structops::AttachmentState>,
        }

        impl $adapter {
            fn new(
                progs: $crate::structops::ProgSet,
                state: $crate::runtime::Arc<$crate::structops::AttachmentState>,
            ) -> Self {
                Self { progs, state }
            }
        }

        impl $trait_name for $adapter {
            $(
                fn $method(&self $(, $pname: $pty)*) -> $mret {
                    if !self.state.admit() {
                        return $fallback($($pname),*);
                    }
                    const _: () = {
                        let arity = 0usize $(+ { let _ = stringify!($pname); 1 })*;
                        assert!(arity <= $crate::interp::MAX_CTX_WORDS);
                    };
                    let id = $crate::structops::fnv1a32(concat!(
                        $target,
                        "::",
                        stringify!($method),
                    ));
                    let method = $descname
                        .method(id)
                        .expect("generated struct_ops method missing from descriptor");
                    let contract = method.contract($descname.target_id);
                    #[allow(unused_mut)]
                    let mut ctx = [0u64; $crate::interp::MAX_CTX_WORDS];
                    #[allow(unused_mut)]
                    let mut len = 0usize;
                    $(
                        ctx[len] = <$pty as $crate::structops::BpfCtxArg>::encode($pname);
                        len += 1;
                    )*
                    match self.progs.get(id) {
                        ::core::option::Option::Some(prog) => {
                            match prog.run_struct_ops_atomic(contract, ctx, len) {
                                ::core::option::Option::Some(
                                    $crate::interp::Outcome::Returned(raw),
                                ) => $result(raw).unwrap_or_else(|| $fallback($($pname),*)),
                                ::core::option::Option::Some(
                                    $crate::interp::Outcome::Trapped(_),
                                ) | ::core::option::Option::None => $fallback($($pname),*),
                            }
                        }
                        ::core::option::Option::None => $fallback($($pname),*),
                    }
                }
            )*
        }

        #[doc = concat!("Install a contract-bound `", stringify!($trait_name), "` set.")]
        $vis fn $install<M: $crate::reexport::CapType>(
            cap: &$crate::reexport::Cap<M, $crate::reexport::Grant>,
            builder: $builder,
        ) -> ::core::result::Result<
            $crate::structops::StructOpsLink,
            $crate::structops::StructOpsError,
        > {
            let set = builder.into_set();
            // Complete every allocation before the transaction permit is
            // acquired and before the subsystem publishes anything.
            let state = $crate::runtime::Arc::new(
                $crate::structops::AttachmentState::new(),
            );
            let adapter = $crate::runtime::Arc::new(
                $adapter::new(set.clone(), state.clone()),
            );
            let prepared = $crate::structops::prepare_install(
                &$descname,
                cap,
                set,
                state.clone(),
            )?;
            let generation = prepared.generation();
            $commit(cap, generation, adapter)?;
            ::core::result::Result::Ok($crate::structops::finish_install(
                prepared,
                $detach,
            ))
        }
    )*};
}

/// Implementation arm for sleepable `struct_ops!` targets.
#[doc(hidden)]
#[macro_export]
macro_rules! __sleepable_struct_ops_impl {
    ($(
        $(#[doc = $tdoc:literal])*
        #[target($target:literal)]
        #[version($version:literal)]
        #[cap($cap:ident)]
        #[install($install:ident)]
        #[desc($descname:ident)]
        #[adapter($adapter:ident)]
        #[builder($builder:ident)]
        #[commit($commit:path)]
        #[detach($detach:path)]
        $(#[optional($($optm:ident),* $(,)?)])?
        $vis:vis trait $trait_name:ident {
            $(
                $(#[doc = $mdoc:literal])*
                #[fallback($fallback:path)]
                #[validate($result:path)]
                #[fuel($fuel:expr)]
                #[kfuncs($($kfunc:expr),* $(,)?) ]
                async fn $method:ident (&self $(, $pname:ident : $pty:ty)* $(,)?) -> $mret:ty;
            )*
        }
    )*) => {$ (
        $(#[doc = $tdoc])*
        $vis trait $trait_name: Send + Sync + 'static {
            $(
                $(#[doc = $mdoc])*
                fn $method<'a>(
                    &'a self,
                    $($pname: $pty),*
                ) -> $crate::StructOpsFuture<'a, $mret>;
            )*
        }

        $vis const $descname: $crate::structops::StructOpsDesc = {
            const OPTIONAL: &[&str] = &[$($(stringify!($optm)),*)?];
            $crate::structops::StructOpsDesc {
                name: stringify!($trait_name),
                target: $target,
                target_id: $crate::structops::fnv1a64($target),
                version: $version,
                cap: $crate::reexport::CapKind::$cap,
                context: $crate::verifier::Context::Sleepable,
                methods: &[$(
                    $crate::structops::MethodDesc {
                        name: stringify!($method),
                        id: $crate::structops::fnv1a32(concat!(
                            $target,
                            "::",
                            stringify!($method),
                        )),
                        abi_hash: $crate::structops::fnv1a64(concat!(
                            $target,
                            "@",
                            stringify!($version),
                            "::async::",
                            stringify!($method),
                            "::",
                            stringify!(fn($($pty),*) -> $mret),
                        )),
                        ctx: &[$(<$pty as $crate::structops::BpfCtxArg>::DESC),*],
                        ret: <$mret as $crate::types::BpfRet>::DESC,
                        allowed_kfuncs: &[$($kfunc),*],
                        context: $crate::verifier::Context::Sleepable,
                        fuel: $fuel,
                        fallback: stringify!($fallback),
                        optional: $crate::structops::is_optional(
                            stringify!($method),
                            OPTIONAL,
                        ),
                    },
                )*],
            }
        };

        const _: () = {
            #[used]
            #[link_section = "narf.structops"]
            static ENTRY: $crate::structops::StructOpsDesc = $descname;
        };

        /// Target-specific, method-safe program builder.
        #[derive(Debug, Default)]
        $vis struct $builder {
            $($method: ::core::option::Option<$crate::runtime::Arc<$crate::runtime::BpfProg>> ,)*
        }

        #[allow(dead_code)]
        impl $builder {
            /// Start an empty target-specific program set.
            #[must_use]
            $vis fn new() -> Self {
                Self::default()
            }

            $(
                #[doc = concat!("Verify and bind `", stringify!($method), "`.")]
                $vis fn $method(
                    mut self,
                    cap: &$crate::reexport::Cap<
                        $crate::runtime::BpfProgLoad,
                        $crate::reexport::Grant,
                    >,
                    req: $crate::runtime::LoadRequest,
                ) -> ::core::result::Result<Self, $crate::runtime::LoadError> {
                    let id = $crate::structops::fnv1a32(concat!(
                        $target,
                        "::",
                        stringify!($method),
                    ));
                    let method = $descname
                        .method(id)
                        .expect("generated struct_ops method missing from descriptor");
                    self.$method = ::core::option::Option::Some(
                        $crate::runtime::BpfProg::load_for_struct_ops(
                            cap,
                            req,
                            method.contract($descname.target_id),
                        )?,
                    );
                    ::core::result::Result::Ok(self)
                }
            )*

            fn into_set(self) -> $crate::structops::ProgSet {
                let mut set = $crate::structops::ProgSet::default();
                $(
                    if let ::core::option::Option::Some(prog) = self.$method {
                        set.bind(
                            $crate::structops::fnv1a32(concat!(
                                $target,
                                "::",
                                stringify!($method),
                            )),
                            prog,
                        );
                    }
                )*
                set
            }
        }

        /// Generated asynchronous Rust adapter used by a subsystem live slot.
        #[derive(Debug)]
        $vis struct $adapter {
            progs: $crate::structops::ProgSet,
            state: $crate::runtime::Arc<$crate::structops::AttachmentState>,
        }

        impl $adapter {
            fn new(
                progs: $crate::structops::ProgSet,
                state: $crate::runtime::Arc<$crate::structops::AttachmentState>,
            ) -> Self {
                Self { progs, state }
            }
        }

        impl $trait_name for $adapter {
            $(
                fn $method<'a>(
                    &'a self,
                    $($pname: $pty),*
                ) -> $crate::StructOpsFuture<'a, $mret> {
                    let admitted = self.state.admit();
                    const _: () = {
                        let arity = 0usize $(+ { let _ = stringify!($pname); 1 })*;
                        assert!(arity <= $crate::interp::MAX_CTX_WORDS);
                    };
                    $crate::runtime::Box::pin(async move {
                        if !admitted {
                            return $fallback($($pname),*).await;
                        }
                        let id = $crate::structops::fnv1a32(concat!(
                            $target,
                            "::",
                            stringify!($method),
                        ));
                        let method = $descname
                            .method(id)
                            .expect("generated struct_ops method missing from descriptor");
                        let contract = method.contract($descname.target_id);
                        #[allow(unused_mut)]
                        let mut ctx = [0u64; $crate::interp::MAX_CTX_WORDS];
                        #[allow(unused_mut)]
                        let mut len = 0usize;
                        $(
                            ctx[len] = <$pty as $crate::structops::BpfCtxArg>::encode($pname);
                            len += 1;
                        )*
                        match self.progs.get(id) {
                            ::core::option::Option::Some(prog) => {
                                match prog
                                    .run_struct_ops_sleepable(contract, ctx, len)
                                    .await
                                {
                                    ::core::option::Option::Some(
                                        $crate::interp::Outcome::Returned(raw),
                                    ) => match $result(raw) {
                                        ::core::option::Option::Some(value) => value,
                                        ::core::option::Option::None => $fallback($($pname),*).await,
                                    },
                                    ::core::option::Option::Some(
                                        $crate::interp::Outcome::Trapped(_),
                                    ) | ::core::option::Option::None => $fallback($($pname),*).await,
                                }
                            }
                            ::core::option::Option::None => $fallback($($pname),*).await,
                        }
                    })
                }
            )*
        }

        #[doc = concat!("Install a contract-bound `", stringify!($trait_name), "` set.")]
        $vis fn $install<M: $crate::reexport::CapType>(
            cap: &$crate::reexport::Cap<M, $crate::reexport::Grant>,
            builder: $builder,
        ) -> ::core::result::Result<
            $crate::structops::StructOpsLink,
            $crate::structops::StructOpsError,
        > {
            let set = builder.into_set();
            let state = $crate::runtime::Arc::new(
                $crate::structops::AttachmentState::new(),
            );
            let adapter = $crate::runtime::Arc::new(
                $adapter::new(set.clone(), state.clone()),
            );
            let prepared = $crate::structops::prepare_install(
                &$descname,
                cap,
                set,
                state.clone(),
            )?;
            let generation = prepared.generation();
            $commit(cap, generation, adapter)?;
            ::core::result::Result::Ok($crate::structops::finish_install(
                prepared,
                $detach,
            ))
        }
    )*};
}
