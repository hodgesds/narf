//! Dynamic probe dispatch.
//!
//! Spec: `tracing/specification/spec.md` §3.2. Armed probe sites
//! invoke `fire(probe_id, args)` which looks up a registered handler
//! and dispatches. No handler → no-op. The lookup is a bounded-size
//! `probe_id → handler` table: probe IDs are stable `u32`s assigned
//! at register time.
//!
//! Stage-3 scope:
//! - Linear-scan handler table (N ≤ 256) under a single `IrqSafeSpinLock`.
//!   Stage 4 swaps in a per-probe-id slot array backed by `rcu/`'s
//!   hazard pointers so the hot path is wait-free.
//! - Up to 4 u64 args per fire — matches the `abi/` Submission inline
//!   slot width and covers every built-in probe site. Variadic
//!   arg-lists are Stage 4.
//! - Handlers run in the firing task's context. `fire()` no longer holds
//!   `TABLE.inner` across the handler call: it clones the `Arc<dyn
//!   ProbeHandler>` under the lock, releases it, and invokes outside.
//!   That is the Stage-4 rework this header used to promise, and it is a
//!   *prerequisite* of the BPF fentry attach type rather than a
//!   nice-to-have — `IrqSafeSpinLock` is not reentrant, so a handler that
//!   fires a probe (or calls anything that does) deadlocked the kernel
//!   outright under the old shape. See `bpf/specification/spec.md` §4.7.
//!   Re-entrancy beyond the lock is still the handler's concern; a
//!   handler that fires its *own* probe id recurses until the stack runs
//!   out, exactly as a self-recursive function would.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

/// Cap-type marker for the dynamic-probe installation surface.
/// Distinct from `ProbeArming` (the patch-word gate) — arming flips
/// the site's enable bit; *registering a handler* for a probe_id is
/// the separate authority gated here.
#[derive(Debug)]
pub struct ProbeHandlerInstall;
impl CapType for ProbeHandlerInstall {
    const KIND: CapKind = CapKind::Probe;
}

/// Monotonic source of probe IDs. `0` is reserved as "unassigned".
static NEXT_PROBE_ID: AtomicU32 = AtomicU32::new(1);
static PROBE_OBSERVER: AtomicUsize = AtomicUsize::new(0);

#[derive(Copy, Clone, Debug)]
struct NamedProbe {
    name: &'static str,
    probe_id: u32,
}

/// Bound on kernel tracepoint names exported to name-based attach APIs.
const MAX_NAMED_PROBES: usize = 256;
static NAMED_PROBES: IrqSafeSpinLock<Vec<NamedProbe>> = IrqSafeSpinLock::new(Vec::new());

/// Why a kernel tracepoint name could not be registered.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NamedProbeError {
    /// Names are non-empty, NUL-free, and at most Linux's 127-byte copy bound.
    InvalidName,
    /// Tracepoint names are kernel-wide unique.
    DuplicateName,
    /// The bounded registry is full.
    TableFull,
}

/// Reserve an id and publish a kernel tracepoint under a stable name.
///
/// Registration is a cold-path operation. The firing site retains the returned
/// id and continues to call [`fire`] directly, so name lookup adds no hot-path
/// work. Names are globally unique because Linux's raw-tracepoint ABI has no
/// provider namespace in its selector.
pub fn register_named_probe(name: &'static str) -> Result<u32, NamedProbeError> {
    if name.is_empty() || name.len() > 127 || name.as_bytes().contains(&0) {
        return Err(NamedProbeError::InvalidName);
    }
    let mut probes = NAMED_PROBES.lock();
    if probes.iter().any(|entry| entry.name == name) {
        return Err(NamedProbeError::DuplicateName);
    }
    if probes.len() >= MAX_NAMED_PROBES {
        return Err(NamedProbeError::TableFull);
    }
    let probe_id = reserve_probe_id();
    probes.push(NamedProbe { name, probe_id });
    Ok(probe_id)
}

/// Resolve a registered kernel tracepoint name to its dispatch id.
#[must_use]
pub fn named_probe_id(name: &str) -> Option<u32> {
    NAMED_PROBES
        .lock()
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.probe_id)
}

/// Install one allocation-free observer invoked for every dynamic probe fire.
pub fn install_probe_observer(observer: fn(u32, ProbeArgs)) {
    PROBE_OBSERVER.store(observer as usize, Ordering::Release);
}

/// Reserve a fresh probe ID. Every compiled probe site calls this
/// once at first fire (lazy assignment) so the ID is stable across
/// the life of the kernel.
#[inline]
pub fn reserve_probe_id() -> u32 {
    NEXT_PROBE_ID.fetch_add(1, Ordering::Relaxed)
}

/// Handler trait. Kept narrow: four `u64` args cover every
/// currently-spec'd probe shape.
pub trait ProbeHandler: Send + Sync + 'static {
    fn fire(&self, args: ProbeArgs);
}

/// One field a [`TypedProbe`] deliberately exposes to tracing programs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProbeField {
    /// Stable source-level field name, for diagnostics and tooling.
    pub name: &'static str,
    /// Byte offset from the start of the object.
    pub offset: u32,
    /// Field width in bytes. Typed BPF reads require an exact match.
    pub size: u32,
}

/// A Rust type whose selected fields may be read by a typed tracing program.
///
/// # Safety
///
/// Every field must lie wholly inside `Self`, and its offset/size must describe
/// the bytes named by `name`. Every exposed byte must be initialized and must
/// not be mutated, including through interior mutability, for the synchronous
/// duration of [`fire_typed`]. `TYPE_NAME` must be unique kernel-wide. The
/// mediated copy path checks the descriptor again at runtime, but it cannot
/// prove that an unsafe implementation described the intended Rust field.
pub unsafe trait TypedProbe: 'static {
    /// Stable kernel-wide type name.
    const TYPE_NAME: &'static str;
    /// Stable identity used by the BPF verifier and attach adapter.
    const TYPE_KEY: u32 = type_key(Self::TYPE_NAME);
    /// The only fields tracing programs may read.
    const FIELDS: &'static [ProbeField];
}

/// FNV-1a identity shared with BPF's Rust-native type descriptors.
#[must_use]
pub const fn type_key(name: &str) -> u32 {
    let bytes = name.as_bytes();
    let mut hash = 0x811C_9DC5u32;
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

/// Borrowed typed object passed only for the synchronous duration of
/// [`fire_typed`].
#[derive(Debug)]
pub struct TypedProbeRef {
    type_key: u32,
    data: *const u8,
    len: usize,
    fields: &'static [ProbeField],
}

impl TypedProbeRef {
    /// Stable schema identity.
    #[must_use]
    pub const fn type_key(&self) -> u32 {
        self.type_key
    }

    /// Size of the borrowed Rust object.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the object has no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Declared readable fields.
    #[must_use]
    pub const fn fields(&self) -> &'static [ProbeField] {
        self.fields
    }

    /// Opaque context word consumed by the BPF typed-probe adapter.
    #[must_use]
    pub fn as_context_word(&self) -> u64 {
        self as *const Self as u64
    }

    /// Copy one exactly-declared field into `dst`.
    ///
    /// Both the field boundary and the whole-object boundary are checked here,
    /// after verification, so a verifier bug cannot turn a tracing read into
    /// an out-of-object kernel read.
    pub fn copy_field(&self, offset: u64, dst: &mut [u8]) -> bool {
        let Ok(offset32) = u32::try_from(offset) else {
            return false;
        };
        let Ok(size32) = u32::try_from(dst.len()) else {
            return false;
        };
        if !self
            .fields
            .iter()
            .any(|f| f.offset == offset32 && f.size == size32)
        {
            return false;
        }
        let Some(end) = (offset as usize).checked_add(dst.len()) else {
            return false;
        };
        if end > self.len {
            return false;
        }
        // SAFETY: `fire_typed` constructed this wrapper from a live `&T` and
        // invokes handlers synchronously before returning. The unsafe
        // `TypedProbe` contract plus the checks above prove this exact range is
        // inside `T`; `dst` is independently verifier-bounded by the kfunc ABI.
        unsafe {
            core::ptr::copy(self.data.add(offset as usize), dst.as_mut_ptr(), dst.len());
        }
        true
    }
}

/// Four-u64 scalar arguments or one borrowed typed object.
///
/// The representation is private so an ordinary probe cannot forge the typed
/// marker around an arbitrary kernel pointer. Scalar observers see zero words
/// for a typed fire; the object address is available only through
/// [`Self::typed`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProbeArgs {
    words: [u64; 4],
    typed: usize,
}

impl ProbeArgs {
    #[inline]
    pub const fn none() -> Self {
        Self {
            words: [0; 4],
            typed: 0,
        }
    }
    #[inline]
    pub const fn one(a: u64) -> Self {
        Self {
            words: [a, 0, 0, 0],
            typed: 0,
        }
    }
    #[inline]
    pub const fn two(a: u64, b: u64) -> Self {
        Self {
            words: [a, b, 0, 0],
            typed: 0,
        }
    }

    /// Scalar tuple. Typed fires deliberately return zeros here.
    #[inline]
    #[must_use]
    pub const fn words(self) -> [u64; 4] {
        self.words
    }

    /// Borrowed typed object, if this came from [`fire_typed`].
    ///
    /// # Safety
    ///
    /// The caller must be executing synchronously inside the observer or
    /// handler invocation that received this `ProbeArgs`. The reference must
    /// not escape that callback; `fire_typed`'s stack wrapper is gone when
    /// dispatch returns.
    #[inline]
    #[must_use]
    pub unsafe fn typed(self) -> Option<&'static TypedProbeRef> {
        if self.typed == 0 {
            None
        } else {
            // SAFETY: only `fire_typed` creates a non-zero marker, and it calls
            // every observer/handler synchronously while the wrapper is live.
            // The returned lifetime is intentionally consumed within that
            // callback; retaining it would violate `ProbeHandler`'s contract.
            Some(unsafe { &*(self.typed as *const TypedProbeRef) })
        }
    }
}

struct Entry {
    probe_id: u32,
    /// `Arc`, not `Box`, so `fire()` can take a counted reference under the
    /// lock and invoke after dropping it. The clone is one relaxed atomic
    /// increment — cheap enough for the hot path, and the only alternative
    /// (holding the lock across the call) is what made a probe-firing handler
    /// self-deadlock.
    handler: Arc<dyn ProbeHandler>,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("probe_id", &self.probe_id)
            .finish_non_exhaustive()
    }
}

/// Bound on concurrently-installed handlers. Stage 4 removes when the
/// hazard-pointer-backed table lands.
const MAX_HANDLERS: usize = 256;

#[derive(Debug)]
pub struct HandlerTable {
    inner: IrqSafeSpinLock<Vec<Entry>>,
}

static TABLE: HandlerTable = HandlerTable {
    inner: IrqSafeSpinLock::new(Vec::new()),
};

#[inline]
pub fn table() -> &'static HandlerTable {
    &TABLE
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegisterError {
    AuthorityRevoked,
    DuplicateProbeId,
    TableFull,
}

impl From<CapError> for RegisterError {
    fn from(_: CapError) -> Self {
        RegisterError::AuthorityRevoked
    }
}

impl HandlerTable {
    /// Install a handler for `probe_id`. Cap-gated.
    pub fn register<H: ProbeHandler + 'static>(
        &self,
        cap: &Cap<ProbeHandlerInstall, Grant>,
        probe_id: u32,
        handler: H,
    ) -> Result<(), RegisterError> {
        cap.check_live()?;
        let mut q = self.inner.lock();
        if q.iter().any(|e| e.probe_id == probe_id) {
            return Err(RegisterError::DuplicateProbeId);
        }
        if q.len() >= MAX_HANDLERS {
            return Err(RegisterError::TableFull);
        }
        q.push(Entry {
            probe_id,
            handler: Arc::new(handler),
        });
        Ok(())
    }

    /// Remove the handler for `probe_id` (no-op if not installed).
    pub fn unregister(
        &self,
        cap: &Cap<ProbeHandlerInstall, Grant>,
        probe_id: u32,
    ) -> Result<(), CapError> {
        cap.check_live()?;
        let mut q = self.inner.lock();
        q.retain(|e| e.probe_id != probe_id);
        Ok(())
    }

    /// Handler count.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// `true` iff empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

/// Fire a probe. No-op if no handler installed for `probe_id`.
/// Called from armed probe sites and from tests.
#[inline]
pub fn fire(probe_id: u32, args: ProbeArgs) {
    let observer = PROBE_OBSERVER.load(Ordering::Acquire);
    if observer != 0 {
        // SAFETY: the slot is written only from a function pointer with this
        // exact signature and remains valid for the kernel lifetime.
        let observer: fn(u32, ProbeArgs) = unsafe { core::mem::transmute(observer) };
        observer(probe_id, args);
    }
    // Clone the counted handler reference under the lock, then drop the lock
    // before invoking. Holding `TABLE.inner` across the call meant any
    // handler that reached `dispatch::*` again — directly, or through a
    // helper that fires a probe — deadlocked on a non-reentrant
    // `IrqSafeSpinLock` with IRQs masked. The `Arc` also keeps the handler
    // alive if a concurrent `unregister` drops the table's copy mid-call.
    //
    // A hazard-pointer-backed slot array would avoid the refcount entirely;
    // that is still worth doing, but it is an optimisation, not the
    // correctness fix.
    let handler = {
        let q = TABLE.inner.lock();
        q.iter()
            .find(|e| e.probe_id == probe_id)
            .map(|e| Arc::clone(&e.handler))
    };
    if let Some(h) = handler {
        h.fire(args);
    }
}

/// Fire a probe with one Rust-described typed object.
///
/// The wrapper lives across the complete synchronous dispatch. Ordinary scalar
/// handlers and the global scalar observer receive zero words, preventing the
/// borrowed kernel address from becoming an accidental pointer disclosure.
#[inline]
pub fn fire_typed<T: TypedProbe>(probe_id: u32, value: &T) {
    let borrowed = TypedProbeRef {
        type_key: T::TYPE_KEY,
        data: (value as *const T).cast::<u8>(),
        len: core::mem::size_of::<T>(),
        fields: T::FIELDS,
    };
    fire(
        probe_id,
        ProbeArgs {
            words: [0; 4],
            typed: (&borrowed as *const TypedProbeRef) as usize,
        },
    );
}
