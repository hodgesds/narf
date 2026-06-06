//! Pluggable ring-transport seam (Wave K).
//!
//! `RingTransport<T>` is the generic-not-`dyn` seam that lets downstream
//! consumers swap their own ring layout (e.g. an MMIO-doorbell transport
//! sitting on top of a device BAR) underneath any code that's written
//! against `impl RingTransport<T>`. Unlike the other pluggable-policy
//! waves, **there is no install slot and no CapKind**: ring choice is
//! per-channel, not global, so it lives at the type level instead.
//!
//! The trait is monomorphised per `T`. Doing `Box<dyn RingTransport>`
//! would erase `T` and force `T` through a virtual table, wrecking the
//! cache-line discipline that the existing rings are tuned for. That's
//! the explicit Wave-K design deviation called out in the plan.
//!
//! In-tree impls shipped today:
//!
//! - `Ring<T, N>` — SPSC (cache-line partitioned head/tail/payload).
//!   `impl` lives in `lib.rs` next to the type.
//! - `MpscRing<T, N>` — multi-producer / single-consumer (Vyukov).
//!   `impl` lives in `mpsc_ring.rs`.
//! - `SpmcRing<T, N>` — single-producer / multi-consumer (Vyukov).
//!   `impl` lives in `spmc_ring.rs`.
//! - `VecRing<T>` — `VecDeque` behind a spinlock; runtime-sized,
//!   no const-generic dance. Demonstrates the seam from a third party's
//!   perspective and gives smoke tests a dirt-simple baseline.
//!
//! The existing inherent push/pop methods on Producer/Consumer wrappers
//! and on the underlying ring types are unchanged — the trait is purely
//! additive. Existing in-tree callers keep their `try_send` / `try_recv`
//! signatures and their typed error variants; new code that wants
//! transport-polymorphism uses the trait.

use alloc::collections::VecDeque;

use narf_lib::sync::IrqSafeSpinLock;

/// Generic transport seam for a bounded ring of `T`.
///
/// `try_push` returns the value back on failure (full or closed) so the
/// caller can retry or surface it. `try_pop` returns `None` on empty.
/// Implementors are responsible for whatever concurrency story their
/// ring guarantees (SPSC, MPSC, SPMC, MPMC) — the trait itself only
/// requires that the methods be safely callable through `&self` when
/// the implementor's documented invariants are respected.
///
/// Send + Sync are bounds on the trait, not on per-method dispatch;
/// this lets `Arc<dyn RingTransport<T>>` exist if a caller wants it,
/// but the trait is intended to be used monomorphically via generics
/// (`fn f<R: RingTransport<T>>(r: &R)`) rather than as a trait object.
pub trait RingTransport<T>: Send + Sync {
    /// Try to push `val`. On failure, returns `Err(val)` so the caller
    /// keeps ownership and can retry or surface it.
    fn try_push(&self, val: T) -> Result<(), T>;

    /// Try to pop. `None` means empty (or closed-and-empty).
    fn try_pop(&self) -> Option<T>;

    /// Current occupancy — approximate under concurrent producers /
    /// consumers, exact under the ring's documented single-side
    /// concurrency model.
    fn len(&self) -> usize;

    /// Maximum capacity. Constant for any given ring.
    fn capacity(&self) -> usize;

    /// Default: `len() == capacity()`.
    fn is_full(&self) -> bool {
        self.len() == self.capacity()
    }

    /// Default: `len() == 0`.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── VecRing — runtime-sized, spinlock-backed baseline ──────────────

/// Dirt-simple `RingTransport` impl backed by a `VecDeque` behind a
/// spinlock. Runtime-sized (no const generics), no cache-line tuning,
/// no MPSC/SPMC trickery — just a bounded queue.
///
/// Useful as:
///
/// 1. A third in-tree impl that proves the seam compiles + dispatches
///    against something fundamentally different from the cache-line
///    rings (no power-of-two requirement, no per-slot sequence, no
///    `MaybeUninit`).
/// 2. A baseline that's easy to inspect under a debugger.
///
/// Not the right choice for hot-path IPC: every op takes a spinlock.
pub struct VecRing<T> {
    inner: IrqSafeSpinLock<VecDeque<T>>,
    cap: usize,
}

impl<T> VecRing<T> {
    /// Allocate a ring with capacity `cap` (must be > 0).
    pub fn new(cap: usize) -> Self {
        assert!(cap > 0, "VecRing capacity must be non-zero");
        Self {
            inner: IrqSafeSpinLock::new(VecDeque::with_capacity(cap)),
            cap,
        }
    }
}

impl<T> core::fmt::Debug for VecRing<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VecRing")
            .field("capacity", &self.cap)
            .finish_non_exhaustive()
    }
}

impl<T: Send> RingTransport<T> for VecRing<T> {
    fn try_push(&self, val: T) -> Result<(), T> {
        let mut q = self.inner.lock();
        if q.len() >= self.cap {
            return Err(val);
        }
        q.push_back(val);
        Ok(())
    }

    fn try_pop(&self) -> Option<T> {
        self.inner.lock().pop_front()
    }

    fn len(&self) -> usize {
        self.inner.lock().len()
    }

    fn capacity(&self) -> usize {
        self.cap
    }
}
