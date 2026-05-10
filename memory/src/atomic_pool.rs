//! Fixed-capacity pool for IRQ-critical paths that can't tolerate
//! allocator failure.
//!
//! Some kernel paths (network RX descriptors, TLB-shootdown IPI
//! payload, scheduler tick metadata) need a guaranteed-success
//! allocation under IRQ. Even `try_alloc_atomic` can fail (per-CPU
//! magazine empty); pool-only paths can't.
//!
//! `AtomicPool<T>` solves this by reserving N pre-built `T`s at
//! init time (sleepable context), then handing them out from
//! `try_get()` / returning them via `Drop` of `Pooled<T>` in
//! atomic context. Both hot paths take an `IrqSafeSpinLock`,
//! pop / push the back of a fixed-capacity stack, and return.
//! The stack's backing storage is reserved up-front, so no
//! reallocation ever happens.
//!
//! Pool exhaustion (`try_get` returns `None`) is a driver bug —
//! the pool was sized too small for the peak request rate.
//! Drivers should size pools with peak workload + headroom and
//! treat `None` as a hard failure to surface.
//!
//! Provenance: clean-room. Bonwick & Adams 2001 §6 ("Magazines
//! and Vmem") describes the same shape — fixed object cache,
//! lock per cache, used as a substrate under per-CPU magazines.
//! No Linux source consulted.

extern crate alloc as alloc_crate;

use alloc_crate::boxed::Box;
use alloc_crate::vec::Vec;
use core::ops::{Deref, DerefMut};

use narf_lib::sync::IrqSafeSpinLock;

/// Fixed-capacity pool of pre-allocated `T`s. Construction
/// happens in sleepable context; get / put are IRQ-safe.
///
/// `T: 'static` is enforced by the API surface (the pool holds
/// `Box<T>`s indefinitely; `Pooled<T>` borrows from a `'static`
/// pool reference).
#[derive(Debug)]
pub struct AtomicPool<T: 'static> {
    free: IrqSafeSpinLock<Vec<Box<T>>>,
    capacity: usize,
}

impl<T: 'static> AtomicPool<T> {
    /// Build a pool of `capacity` items, each constructed via
    /// `init`. Runs in sleepable context — `init` is called
    /// `capacity` times. Total memory footprint:
    /// `capacity * size_of::<Box<T>>()` for the stack +
    /// `capacity * size_of::<T>()` for the items.
    pub fn new(capacity: usize, mut init: impl FnMut() -> T) -> Self {
        let mut free = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            free.push(Box::new(init()));
        }
        Self {
            free: IrqSafeSpinLock::new(free),
            capacity,
        }
    }

    /// Try to lease one item from the pool. Returns `None` when
    /// the pool is exhausted — caller should treat this as a
    /// driver-bug-grade event, not a recoverable transient.
    ///
    /// O(1) hot path: lock + Vec::pop. Safe to call from IRQ
    /// context (lock is `IrqSafeSpinLock`).
    pub fn try_get(&'static self) -> Option<Pooled<T>> {
        let item = self.free.lock().pop()?;
        Some(Pooled {
            pool: self,
            item: Some(item),
        })
    }

    /// Pool's built-in capacity (the value passed to `new`).
    /// Stays constant for the lifetime of the pool.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of items currently free (not leased). Snapshot for
    /// diagnostics / liveness checks.
    pub fn free_count(&self) -> usize {
        self.free.lock().len()
    }
}

/// Lease handle to one `T` from an `AtomicPool`. Drop returns
/// the item to the pool — IRQ-safe via the pool's
/// `IrqSafeSpinLock`. Deref / DerefMut give access to the `T`.
#[derive(Debug)]
pub struct Pooled<T: 'static> {
    pool: &'static AtomicPool<T>,
    // `Option` so Drop can move the item out without violating
    // the no-default-and-no-Clone surface.
    item: Option<Box<T>>,
}

impl<T: 'static> Deref for Pooled<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // Always Some until Drop. The Option is for move-out,
        // not for dynamic absence.
        self.item.as_deref().expect("Pooled<T> moved-out before Drop")
    }
}

impl<T: 'static> DerefMut for Pooled<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        self.item.as_deref_mut().expect("Pooled<T> moved-out before Drop")
    }
}

impl<T: 'static> Drop for Pooled<T> {
    fn drop(&mut self) {
        if let Some(item) = self.item.take() {
            // The pool's stack capacity equals self.pool.capacity,
            // and at any time the number of leased items + items
            // on the stack equals capacity. So this push never
            // exceeds capacity and never realloc-grows. (Vec
            // doesn't enforce this directly; the invariant is
            // structural.)
            self.pool.free.lock().push(item);
        }
    }
}
