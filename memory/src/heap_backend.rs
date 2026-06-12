//! Wave-B of the pluggable-policy pass: the `HeapBackend` policy
//! seam.
//!
//! The interior of [`BumpAllocator`](crate::heap::BumpAllocator) —
//! the workspace's `#[global_allocator]` shell — dispatches every
//! `GlobalAlloc::alloc` / `dealloc` through an installed
//! `&'static dyn HeapBackend`. Two shipped impls live alongside the
//! trait: `BumpBackend` wraps the bootstrap bump arena (the only
//! backend that can serve allocations *before* the frame allocator
//! is up) and `SlabBackend` wraps the production size-class slab.
//!
//! The slot type follows Wave A's principled deviation
//! (`frame.rs::FRAME_ALLOC_SLOT`): a
//! `IrqSafeSpinLock<Option<&'static dyn HeapBackend>>` rather than
//! `Box<dyn HeapBackend>`. The heap can't `Box` until it's already
//! alive, and we want the trait live before the very first
//! allocation. One uncontended `IrqSafeSpinLock` per `alloc`/
//! `dealloc` is the same cost the slab was already paying for its
//! own central-list lock; if hot-path measurements ever show this
//! matters, an `AtomicPtr` over a thin-pointer wrapper can replace
//! it without changing the call sites.
//!
//! Installation is cap-gated on `Cap<HeapAuthority, Grant>`. The
//! runtime kind variant is reserved at `CapKind::HeapBackend =
//! 0x0201` (Wave 0).

use core::alloc::Layout;
use core::ptr::NonNull;

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

/// A pluggable global-heap backend. Implementations cover the
/// `GlobalAlloc` surface plus an atomic-context try-allocate hook
/// (so IRQ-safe code paths can shop for memory without taking the
/// central lock).
pub trait HeapBackend: Send + Sync + 'static {
    /// Stable identifier (e.g. `"bump"`, `"slab"`).
    fn name(&self) -> &'static str;

    /// Serve `layout`. Returns `core::ptr::null_mut()` on failure
    /// to match `GlobalAlloc::alloc`.
    ///
    /// # Safety
    /// Caller upholds `Layout` invariants per `GlobalAlloc::alloc`.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8;

    /// Return a pointer obtained from a previous `alloc` of
    /// `layout`. No-op when the backend cannot reclaim (bump).
    ///
    /// # Safety
    /// `ptr` was returned by a prior `alloc` of `layout` on the
    /// same backend.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout);

    /// IRQ-safe try-allocate. Some backends (the slab's per-CPU
    /// magazines, the trivial bump-cursor) can satisfy this
    /// lock-free; others can return `None` immediately. Default
    /// returns `None`.
    fn try_alloc_atomic(&self, _layout: Layout) -> Option<NonNull<u8>> {
        None
    }
}

/// Reasons `install_heap_backend` can fail.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HeapError {
    /// `current_heap_backend_*` consulted but no backend has been
    /// installed yet (pre-`install_default_if_unset`).
    NotInstalled,
    /// `install_heap_backend` was called with an authority cap
    /// whose epoch has been revoked.
    AuthorityRevoked,
}

impl From<CapError> for HeapError {
    fn from(_: CapError) -> Self {
        HeapError::AuthorityRevoked
    }
}

/// Cap-marker type for `install_heap_backend`. The runtime kind
/// variant is reserved at `CapKind::HeapBackend = 0x0201` (Wave 0).
///
/// Named `HeapAuthority` rather than `HeapBackend` so the cap
/// marker does not collide with the trait of the same conceptual
/// name. The trait is the policy contract; this type is the
/// installation right.
#[derive(Copy, Clone, Debug)]
pub struct HeapAuthority;
impl CapType for HeapAuthority {
    const KIND: CapKind = CapKind::HeapBackend;
}

// `&'static dyn HeapBackend` is a fat pointer (data + vtable). An
// `AtomicPtr` can only hold one word, so we park the trait object
// behind an `IrqSafeSpinLock<Option<…>>`. The lock is taken for
// the entire duration of a dispatched call, which keeps the
// vtable load + the indirect call atomic with respect to a swap.
static HEAP_BACKEND_SLOT: IrqSafeSpinLock<Option<&'static dyn HeapBackend>> =
    IrqSafeSpinLock::new(None);

/// The shipped bootstrap-bump backend. Backs allocations between
/// `_start_rust` and `crate::heap::promote_to_slab()`. Zero-sized:
/// the underlying arena lives in `crate::heap`'s module statics
/// (`HEAP` + `OFFSET`) and is reached through the
/// `crate::heap::bump_*` thin shims.
#[derive(Copy, Clone, Debug, Default)]
pub struct BumpBackend;

impl HeapBackend for BumpBackend {
    fn name(&self) -> &'static str {
        "bump"
    }
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        crate::heap::bump_alloc(layout)
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump arena cannot reclaim per-slot — bump semantics. The
        // arena is small + bounded; the bytes stay leaked until the
        // slab takes over and the arena retires.
    }
    fn try_alloc_atomic(&self, layout: Layout) -> Option<NonNull<u8>> {
        // The bump arena services any layout that fits; the CAS
        // loop inside is lock-free + IRQ-safe.
        NonNull::new(crate::heap::bump_alloc(layout))
    }
}

/// The shipped slab backend. Backs allocations after
/// `crate::heap::promote_to_slab()`. Zero-sized: the underlying
/// state lives in `crate::slab`.
#[derive(Copy, Clone, Debug, Default)]
pub struct SlabBackend;

impl HeapBackend for SlabBackend {
    fn name(&self) -> &'static str {
        "slab"
    }
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match crate::slab::alloc(layout) {
            Ok(p) => p.as_ptr(),
            Err(_) => core::ptr::null_mut(),
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(nn) = NonNull::new(ptr) {
            // SAFETY: caller asserts pointer/layout pair came from
            // a prior `alloc` on this backend, i.e. from
            // `crate::slab::alloc` with the same layout.
            // SAFETY: Valid memory or trusted environment
            unsafe { crate::slab::dealloc(nn, layout) };
        }
    }
    fn try_alloc_atomic(&self, layout: Layout) -> Option<NonNull<u8>> {
        crate::slab::try_alloc_atomic(layout)
    }
}

/// Static singletons for the shipped backends. Re-exported through
/// `lib.rs` so install callers can hand them directly to
/// `install_heap_backend` without needing to materialise a
/// `&'static` themselves.
pub static BUMP_BACKEND: BumpBackend = BumpBackend;
pub static SLAB_BACKEND: SlabBackend = SlabBackend;

/// Install a `HeapBackend` impl. Cap-gated on
/// `Cap<HeapAuthority, Grant>`.
///
/// The previous installed backend is replaced; the caller is
/// responsible for ensuring no pointers handed out by the old
/// backend will be freed via the new one. In practice this means
/// installs happen at well-defined transitions: bump → slab once
/// at promotion, and test-driven swaps that restore the prior
/// backend before any cross-backend frees can occur.
pub fn install_heap_backend(
    cap: &Cap<HeapAuthority, Grant>,
    backend: &'static dyn HeapBackend,
) -> Result<(), HeapError> {
    cap.check_live()?;
    *HEAP_BACKEND_SLOT.lock() = Some(backend);
    Ok(())
}

/// Install `BUMP_BACKEND` if no backend is yet installed. Called
/// from `BumpAllocator::alloc` on first miss so the very first
/// allocation has somewhere to go. Idempotent: a slot already
/// holding `Some(_)` is left alone, which is what makes a later
/// `promote_to_slab` install of `SLAB_BACKEND` stick.
pub(crate) fn install_default_if_unset() {
    let mut slot = HEAP_BACKEND_SLOT.lock();
    if slot.is_none() {
        *slot = Some(&BUMP_BACKEND);
    }
}

/// Crate-internal, uncapped install. The only caller is
/// `crate::heap::promote_to_slab`, which is itself the
/// kernel-internal canonical promotion point — every other install
/// path goes through the cap-gated `install_heap_backend`. Kept
/// out of the public surface so accidental uncapped swaps can't
/// happen from outside the crate.
pub(crate) fn install_uncapped(backend: &'static dyn HeapBackend) {
    *HEAP_BACKEND_SLOT.lock() = Some(backend);
}

/// Snapshot the active backend's `name()`. Returns `None` when no
/// backend has been installed yet.
pub fn current_heap_backend_name() -> Option<&'static str> {
    HEAP_BACKEND_SLOT.lock().as_ref().map(|b| b.name())
}

/// Snapshot the currently-installed backend. `None` pre-install.
#[inline]
pub(crate) fn current_backend() -> Option<&'static dyn HeapBackend> {
    *HEAP_BACKEND_SLOT.lock()
}
