//! narf-rcu — deferred reclamation (QSBR default, epoch, hazard, sleepable).
//!
//! Spec: `rcu/specification/spec.md`. Stage-2 subset (per `ROADMAP.md` +
//! `STAGE3.md` side-track A) promotes the Stage-1 stub into real QSBR +
//! Epoch reclamation with a per-CPU reader counter, a global epoch, and
//! working `defer_drop` queues whose grace periods actually wait for
//! every CPU to pass a quiescent point.
//!
//! Non-goals for this wave:
//! - Hazard-pointer variant — API surface only, `unimplemented!()`.
//! - Sleepable variant (SRCU-analogue) — API surface only; real impl
//!   needs Wave-2 capabilities and lands in the main track.
//! - Per-domain reclamation-worker Future — depends on scheduler domain
//!   changes; stubbed, flagged to the main agent.
//! - Direct integration with `scheduler::run_until_empty` — the hook
//!   `rcu::report_quiescent()` is exported so the scheduler can call it
//!   at each poll boundary (spec §3.7); the Stage-2 scheduler does not
//!   call it yet, so tests drive it manually. This is a stub to be wired
//!   by the main agent.
//!
//! # Reader discipline
//!
//! QSBR readers must **not `.await`** across a `ReadGuard`. The guard is
//! `!Send + !Sync` and cannot be held across yield points in practice —
//! doing so is undefined behaviour under the QSBR contract and would
//! let reclamation run under the reader's feet. The sleepable variant
//! (§3.5) is the explicit exception; its guard is a different type.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod epoch;
pub mod policy;
pub mod qsbr;

pub use policy::ReclamationPolicy;

use alloc::boxed::Box;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicPtr, Ordering};

// ── Core pointer primitives ─────────────────────────────────────────
//
// `Owned<T>` is an exclusive heap allocation awaiting publication.
// `Shared<'g, T>` is a borrowed view tied to a `ReadGuard`'s lifetime,
// which statically forbids use-after-free by well-typed consumers.
// `Atomic<T>` is the epoch-collected pointer cell — loads require a
// `ReadGuard`, stores don't but queue the displaced value into the
// reclamation queue.

/// Exclusively-owned heap allocation not yet visible to any reader.
#[derive(Debug)]
pub struct Owned<T: Send + 'static> {
    ptr: *mut T,
}

// SAFETY: `Owned<T>` owns a unique pointer; it acts like `Box<T>` for
// aliasing purposes. Send if `T: Send`.
unsafe impl<T: Send + 'static> Send for Owned<T> {}
// SAFETY: shared access to `Owned<T>` is safe if `T: Sync`; we never
// hand out `&mut T` except inside `Drop`.
unsafe impl<T: Sync + Send + 'static> Sync for Owned<T> {}

impl<T: Send + 'static> Owned<T> {
    /// Allocate a new `Owned<T>`. Currently backed by `Box`.
    pub fn new(value: T) -> Self {
        let boxed = Box::new(value);
        Self { ptr: Box::into_raw(boxed) }
    }

    /// Raw pointer — `Atomic<T>::store` consumes this.
    fn into_raw(self) -> *mut T {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl<T: Send + 'static> Drop for Owned<T> {
    fn drop(&mut self) {
        // If we're being dropped without publishing, reclaim immediately.
        if !self.ptr.is_null() {
            // SAFETY: `ptr` was produced by `Box::into_raw`; we restore
            // the Box so its destructor runs.
            unsafe { drop(Box::from_raw(self.ptr)); }
        }
    }
}

/// Borrowed view of a value published through `Atomic<T>`, tied to a
/// `ReadGuard`'s lifetime. The borrow-checker forbids outliving the guard.
#[derive(Copy, Clone)]
pub struct Shared<'g, T: 'static> {
    ptr: *const T,
    _g:  PhantomData<&'g ()>,
}

impl<'g, T> core::fmt::Debug for Shared<'g, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Shared")
            .field("ptr", &self.ptr)
            .finish_non_exhaustive()
    }
}

impl<'g, T: 'static> Shared<'g, T> {
    /// Null shared pointer — the empty-cell reading.
    pub fn null() -> Self { Self { ptr: core::ptr::null(), _g: PhantomData } }

    /// Whether the cell was empty.
    pub fn is_null(&self) -> bool { self.ptr.is_null() }

    /// Safe dereference — lifetime tied to `'g`. Returns `None` for null.
    pub fn as_ref(&self) -> Option<&'g T> {
        if self.ptr.is_null() { None }
        // SAFETY: the reader holds a live `ReadGuard` for `'g`; any
        // `Owned<T>` whose publication we observed is retained by QSBR
        // at least until the guard reports quiescence (i.e. drops).
        else { Some(unsafe { &*self.ptr }) }
    }
}

/// Epoch-collected pointer cell.
pub struct Atomic<T: Send + 'static> {
    ptr: AtomicPtr<T>,
}

impl<T: Send + 'static> core::fmt::Debug for Atomic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Atomic")
            .field("ptr", &self.ptr.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl<T: Send + 'static> Atomic<T> {
    /// Construct an empty cell.
    pub const fn null() -> Self { Self { ptr: AtomicPtr::new(core::ptr::null_mut()) } }

    /// Construct with an initial value already published.
    pub fn new(value: T) -> Self {
        Self { ptr: AtomicPtr::new(Box::into_raw(Box::new(value))) }
    }

    /// Load the current pointer tied to a read guard's lifetime.
    /// Acquire ordering — ensures the pointed-to fields are visible.
    pub fn load<'g>(&self, _g: &'g ReadGuard) -> Shared<'g, T> {
        let p = self.ptr.load(Ordering::Acquire) as *const T;
        Shared { ptr: p, _g: PhantomData }
    }

    /// Publish a new value, queueing the displaced one for deferred drop.
    ///
    /// Release ordering — ensures the new value's fields are visible to
    /// any reader who observes the new pointer via `load`.
    pub fn store(&self, new: Owned<T>, _g: &ReadGuard) {
        let new_ptr = new.into_raw();
        let old_ptr = self.ptr.swap(new_ptr, Ordering::AcqRel);
        if !old_ptr.is_null() {
            enqueue_drop::<T>(old_ptr);
        }
    }

    /// Compare-and-set: publish `new` iff the current pointer equals
    /// `expected`. Returns the new `Shared<'g, T>` on success; returns
    /// `(new, current)` on failure so the caller can retry or reclaim.
    pub fn compare_and_set<'g>(
        &self,
        expected: Shared<'_, T>,
        new: Owned<T>,
        _g: &'g ReadGuard,
    ) -> Result<Shared<'g, T>, (Owned<T>, Shared<'g, T>)> {
        let new_ptr = new.ptr;
        match self.ptr.compare_exchange(
            expected.ptr as *mut T, new_ptr,
            Ordering::AcqRel, Ordering::Acquire,
        ) {
            Ok(old) => {
                // Publication succeeded — forget the Owned (now owned
                // by the cell) and defer-drop the displaced pointer.
                core::mem::forget(new);
                if !old.is_null() { enqueue_drop::<T>(old); }
                Ok(Shared { ptr: new_ptr, _g: PhantomData })
            }
            Err(current) => Err((
                new,
                Shared { ptr: current as *const T, _g: PhantomData },
            )),
        }
    }
}

impl<T: Send + 'static> Drop for Atomic<T> {
    fn drop(&mut self) {
        let p = *self.ptr.get_mut();
        if !p.is_null() {
            // SAFETY: `p` came from `Box::into_raw` and nobody else
            // holds a `ReadGuard` tied to this cell (we're in Drop).
            unsafe { drop(Box::from_raw(p)); }
        }
    }
}

// ── ReadGuard ───────────────────────────────────────────────────────

/// Reader pin — prevents reclamation of anything loaded through this
/// guard. `!Send + !Sync` enforces single-CPU, single-task scope; the
/// guard cannot cross an `.await` point because doing so would move it
/// off the origin CPU (enforced socially until the async executor gets
/// the `!Send` bound — see §3.3).
#[derive(Debug)]
pub struct ReadGuard<'g> {
    _not_send: PhantomData<*const ()>,
    _phantom:  PhantomData<&'g ()>,
}

impl<'g> ReadGuard<'g> {
    fn new() -> Self { Self { _not_send: PhantomData, _phantom: PhantomData } }
}

impl<'g> Drop for ReadGuard<'g> {
    fn drop(&mut self) { qsbr::reader_unpin(); }
}

/// Obtain a QSBR reader pin.
pub fn pin() -> ReadGuard<'static> {
    qsbr::reader_pin();
    ReadGuard::new()
}

// ── defer_drop + enqueue ────────────────────────────────────────────

fn enqueue_drop<T: Send + 'static>(ptr: *mut T) {
    // Box the pointer back into a boxed dyn FnOnce-equivalent closure
    // that reclaims it. We erase `T` into a raw pointer plus a monomorphic
    // dropper fn so the queue itself is non-generic.
    // SAFETY: `ptr` was produced from `Box::into_raw::<T>`.
    let dropper: unsafe fn(*mut ()) = |raw| unsafe {
        drop(Box::from_raw(raw as *mut T))
    };
    qsbr::defer_raw(ptr as *mut (), dropper);
}

/// Queue `owned` for deferred drop once every CPU has passed a
/// quiescent state beyond the current epoch.
pub fn defer_drop<T: Send + 'static>(owned: Owned<T>, _g: &ReadGuard) {
    let raw = owned.into_raw();
    enqueue_drop::<T>(raw);
}

// ── Grace-period machinery ──────────────────────────────────────────

/// Declare a quiescent state on the current CPU. The scheduler is
/// expected to call this at every `Future::poll` boundary (spec §3.7);
/// consumers running outside the scheduler may call it manually (used
/// by the verification harness).
#[inline]
pub fn report_quiescent() { qsbr::report_quiescent(); }

/// Wait one grace period and drain the resulting drop batch.
///
/// This is the synchronous form intended for kernel-thread-style use and
/// for the test harness; the async `sync_async()` form awaits a yield
/// between polls. For Stage-2 single-CPU kernels the synchronous form
/// is sufficient because `report_quiescent` happens at poll boundaries.
pub fn sync() {
    qsbr::sync_blocking();
}

/// Async form of `sync()`. Yields to the executor between polls so a
/// cooperative executor can drive other tasks while this awaits.
pub fn sync_async() -> impl core::future::Future<Output = ()> {
    qsbr::SyncFuture::new()
}

// ── Sleepable + Hazard stubs ────────────────────────────────────────

/// Sleepable RCU reader handle (SRCU-analogue). Cap-gated; Stage-3
/// follow-up.
#[derive(Debug)]
pub struct SleepableReader { _private: () }

/// Sleepable RCU guard. Unlike the QSBR `ReadGuard`, this one *is*
/// Future-safe — the whole point of the sleepable variant.
#[derive(Debug)]
pub struct SleepableGuard<'a> { _p: PhantomData<&'a ()> }

/// Sleepable-scope handle. Stub — real impl needs Wave-2 capabilities.
#[derive(Debug)]
pub struct SleepableScope { _private: () }

/// Outcome of `sleepable_sync`.
#[derive(Debug)]
pub enum SyncOutcome {
    Drained,
    Timeout,
}

/// Hazard-pointer reader slot. Stub for Stage-3; see spec §3.6.
#[derive(Debug)]
pub struct HazardSlot { _private: () }
