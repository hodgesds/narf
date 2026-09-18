//! narf-rcu — deferred reclamation (QSBR default, epoch, hazard, sleepable).
//!
//! Spec: `rcu/specification/spec.md`. Stage-2 subset (per `ROADMAP.md` +
//! `STAGE3.md` side-track A) promotes the Stage-1 stub into real QSBR +
//! Epoch reclamation with a per-CPU reader counter, a global epoch, and
//! working `defer_drop` queues whose grace periods actually wait for
//! every CPU to pass a quiescent point.
//!
//! Non-goals for this wave:
//! - Per-domain reclamation-worker Future — depends on scheduler domain
//!   changes; stubbed, flagged to the main agent.
//! - Scheduled (timer-driven) hazard-pointer reclamation pass — Stage-4.
//!   Today the only triggers are the inline-on-threshold scan and
//!   explicit `HazardDomain::scan()`; see `hazard.rs` module docs.
//! - Direct integration with `scheduler::run_until_empty` — the hook
//!   `rcu::report_quiescent()` is exported so the scheduler can call it
//!   at each poll boundary (spec §3.7); Stage 3 wires it inside
//!   `scheduler::run_until_empty` already, so QSBR sees grace ticks
//!   without test-harness help.
//!
//! Stage-3 round-2 added the **sleepable** variant (`sleepable` module,
//! spec §3.5): cap-gated scopes, deadline-bounded `sync_async`, per-
//! scope reader budget. The QSBR types here are unchanged; the
//! sleepable variant is a parallel surface that lives in its own
//! module.
//!
//! Stage-3 round-4 added the **hazard-pointer** variant (`hazard`
//! module, spec §3.6): per-CPU `HazardSlot` array, retire-list with a
//! threshold-driven inline scan + explicit `HazardDomain::scan()`,
//! `HazardGuard<'_, T>` RAII for the load-publish-verify discipline.
//! The retire-list scan threshold is the Stage-3 budget knob; a
//! periodic scheduled pass is Stage-4.
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

pub mod batched;
pub mod epoch;
pub mod hazard;
pub mod policy;
pub mod qsbr;
pub mod sleepable;

mod tests;

pub use batched::{BatchedReclaimer, ReclaimBatch, BATCH_CAP};
pub use hazard::{retire, HazardDomain, HazardGuard, HazardSlot};
pub use policy::ReclamationPolicy;
pub use sleepable::{SleepableGuard, SleepableReader, SleepableScope, SleepableSync, SyncOutcome};

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

// ── Intrusive retirement node ───────────────────────────────────────
//
// Every RCU-managed allocation carries a retirement header, exactly as
// Linux reserves a `struct rcu_head` inside each object. The reason is the
// same one in both kernels: once an object is retired it must be threaded
// onto a reclamation list from a context that may not be able to allocate,
// so the list node has to already exist. A queue that can fail to enqueue
// is a queue that leaks — which is precisely what the previous
// fixed-capacity per-CPU bucket did, silently, on its 65th entry.
//
// The header is NEVER touched by readers. `Shared::as_ref` hands out
// `&node.value`, and a retiring writer writes only `next`/`epoch`, so a
// reader still dereferencing the value during its grace period cannot
// observe or race the list wiring.

/// Retirement list node, embedded ahead of every RCU-managed value.
#[repr(C)]
pub(crate) struct DeferHdr {
    /// Next node in this CPU's reclamation list. Written only after the
    /// value has been unlinked from its `Atomic`.
    pub(crate) next: *mut DeferHdr,
    /// Global epoch at retirement. The node is reclaimable once every CPU
    /// has reported quiescence strictly past this.
    pub(crate) epoch: u64,
    /// Monomorphised reclaimer — reconstitutes the `Box<DeferNode<T>>`.
    /// Set at allocation so retirement is a pure list splice.
    pub(crate) dropper: Option<unsafe fn(*mut DeferHdr)>,
}

/// An RCU-managed allocation: retirement header, then the value.
///
/// `#[repr(C)]` with `hdr` first is load-bearing — `drop_node` casts a
/// `*mut DeferHdr` straight back to `*mut DeferNode<T>`.
#[repr(C)]
pub(crate) struct DeferNode<T> {
    pub(crate) hdr: DeferHdr,
    pub(crate) value: T,
}

/// Reclaim a node. Installed as `DeferHdr::dropper` at allocation time.
///
/// # Safety
/// `hdr` must be the header of a live `DeferNode<T>` produced by
/// [`alloc_node`], whose grace period has elapsed.
unsafe fn drop_node<T: Send + 'static>(hdr: *mut DeferHdr) {
    // SAFETY: `DeferNode<T>` is `#[repr(C)]` with `hdr` first, so the
    // header address IS the node address; the node came from
    // `Box::into_raw` in `alloc_node`.
    unsafe {
        drop(Box::from_raw(hdr as *mut DeferNode<T>));
    }
}

fn alloc_node<T: Send + 'static>(value: T) -> *mut DeferNode<T> {
    Box::into_raw(Box::new(DeferNode {
        hdr: DeferHdr {
            next: core::ptr::null_mut(),
            epoch: 0,
            dropper: Some(drop_node::<T>),
        },
        value,
    }))
}

/// Hand a node to this CPU's reclamation list. Allocation-free and
/// infallible, which is the whole point of the embedded header.
fn retire_node<T: Send + 'static>(node: *mut DeferNode<T>) {
    if node.is_null() {
        return;
    }
    // SAFETY: `hdr` is the first field of a `#[repr(C)]` node.
    qsbr::defer_node(node as *mut DeferHdr);
}

/// Exclusively-owned heap allocation not yet visible to any reader.
#[derive(Debug)]
pub struct Owned<T: Send + 'static> {
    ptr: *mut DeferNode<T>,
}

// SAFETY: `Owned<T>` owns a unique pointer; it acts like `Box<T>` for
// aliasing purposes. Send if `T: Send`.
unsafe impl<T: Send + 'static> Send for Owned<T> {}
// SAFETY: shared access to `Owned<T>` is safe if `T: Sync`; we never
// hand out `&mut T` except inside `Drop`.
unsafe impl<T: Sync + Send + 'static> Sync for Owned<T> {}

impl<T: Send + 'static> Owned<T> {
    /// Allocate a new `Owned<T>`, with its retirement header.
    pub fn new(value: T) -> Self {
        Self {
            ptr: alloc_node(value),
        }
    }

    /// Raw node pointer — `Atomic<T>::store` consumes this.
    fn into_raw(self) -> *mut DeferNode<T> {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl<T: Send + 'static> Drop for Owned<T> {
    fn drop(&mut self) {
        // If we're being dropped without publishing, reclaim immediately:
        // no reader ever saw this node, so no grace period is owed.
        if !self.ptr.is_null() {
            // SAFETY: `ptr` was produced by `alloc_node`'s
            // `Box::into_raw`; we restore the Box so its destructor runs.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                drop(Box::from_raw(self.ptr));
            }
        }
    }
}

/// Borrowed view of a value published through `Atomic<T>`, tied to a
/// `ReadGuard`'s lifetime. The borrow-checker forbids outliving the guard.
#[derive(Copy, Clone)]
pub struct Shared<'g, T: 'static> {
    /// The NODE, not the value. `compare_and_set` compares what the cell
    /// stores, and the cell stores nodes; `as_ref` does the offset.
    ptr: *const DeferNode<T>,
    _g: PhantomData<&'g ()>,
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
    pub fn null() -> Self {
        Self {
            ptr: core::ptr::null(),
            _g: PhantomData,
        }
    }

    /// Whether the cell was empty.
    pub fn is_null(&self) -> bool {
        self.ptr.is_null()
    }

    /// Safe dereference — lifetime tied to `'g`. Returns `None` for null.
    ///
    /// Hands out `&node.value`: the retirement header stays private, so a
    /// reader can never see or race the list wiring a writer adds when the
    /// node is retired.
    pub fn as_ref(&self) -> Option<&'g T> {
        if self.ptr.is_null() {
            None
        } else {
            // SAFETY: the reader holds a live `ReadGuard` for `'g`; any
            // `Owned<T>` whose publication we observed is retained by QSBR
            // at least until the guard reports quiescence (i.e. drops). The
            // pointer was non-null (checked above) and points at a valid
            // `T` that outlives `'g`, so producing a `&'g T` is sound.
            // SAFETY: Valid memory or trusted environment
            Some(unsafe { &(*self.ptr).value })
        }
    }
}

/// Epoch-collected pointer cell.
pub struct Atomic<T: Send + 'static> {
    ptr: AtomicPtr<DeferNode<T>>,
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
    pub const fn null() -> Self {
        Self {
            ptr: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Construct with an initial value already published.
    pub fn new(value: T) -> Self {
        Self {
            ptr: AtomicPtr::new(alloc_node(value)),
        }
    }

    /// Load the current pointer tied to a read guard's lifetime.
    /// Acquire ordering — ensures the pointed-to fields are visible.
    pub fn load<'g>(&self, _g: &'g ReadGuard) -> Shared<'g, T> {
        let p = self.ptr.load(Ordering::Acquire) as *const DeferNode<T>;
        Shared {
            ptr: p,
            _g: PhantomData,
        }
    }

    /// Publish a new value, queueing the displaced one for deferred drop.
    ///
    /// Release ordering — ensures the new value's fields are visible to
    /// any reader who observes the new pointer via `load`.
    pub fn store(&self, new: Owned<T>, _g: &ReadGuard) {
        let new_ptr = new.into_raw();
        let old_ptr = self.ptr.swap(new_ptr, Ordering::AcqRel);
        // Infallible: the displaced node's retirement header was allocated
        // with it, so handing it to the reclamation list cannot fail and
        // cannot allocate.
        retire_node::<T>(old_ptr);
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
            expected.ptr as *mut DeferNode<T>,
            new_ptr,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(old) => {
                // Publication succeeded — forget the Owned (now owned
                // by the cell) and retire the displaced node.
                core::mem::forget(new);
                retire_node::<T>(old);
                Ok(Shared {
                    ptr: new_ptr,
                    _g: PhantomData,
                })
            }
            Err(current) => Err((
                new,
                Shared {
                    ptr: current as *const DeferNode<T>,
                    _g: PhantomData,
                },
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
            // SAFETY: Valid memory or trusted environment
            unsafe {
                drop(Box::from_raw(p));
            }
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
    _phantom: PhantomData<&'g ()>,
}

impl<'g> ReadGuard<'g> {
    fn new() -> Self {
        Self {
            _not_send: PhantomData,
            _phantom: PhantomData,
        }
    }
}

impl<'g> Drop for ReadGuard<'g> {
    fn drop(&mut self) {
        qsbr::reader_unpin();
    }
}

/// Obtain a QSBR reader pin.
pub fn pin() -> ReadGuard<'static> {
    qsbr::reader_pin();
    ReadGuard::new()
}

// ── defer_drop + enqueue ────────────────────────────────────────────

/// Queue `owned` for deferred drop once every CPU has passed a
/// quiescent state beyond the current epoch.
pub fn defer_drop<T: Send + 'static>(owned: Owned<T>, _g: &ReadGuard) {
    retire_node::<T>(owned.into_raw());
}

/// Queue an owned `Box<T>` for deferred reclamation: its memory is not
/// freed (and `T`'s `Drop` does not run) until every CPU has passed a
/// quiescent point beyond the current epoch. Use when a raw `*mut T`
/// derived from this box may still be held by another CPU that hasn't
/// yet reached a quiescent state — freeing synchronously would let that
/// CPU dereference freed memory. Allocation-free and IRQ-safe (the
/// enqueue writes into a fixed per-CPU bucket under an IRQ mask).
///
/// Reclamation progress: retired entries become reclaimable only once a
/// LATER global epoch exists and every CPU has reported quiescence under
/// it. The executor drives that via [`advance_epoch_if_pending`] each
/// round, so `retire_box` needs no explicit `sync()`.
///
/// Unlike [`Owned`], a caller-supplied `Box<T>` has no room for a
/// retirement header, so one is allocated here to hold it — in the
/// CALLER's context, never on the retirement path. Callers already
/// allocate to build the box, so this adds no new constraint on where
/// `retire_box` may be used.
pub fn retire_box<T: Send + 'static>(b: alloc::boxed::Box<T>) {
    // Wrapping rather than re-boxing the value: `T`'s destructor runs when
    // the inner `Box` drops, so a `T` that is expensive or non-movable is
    // never copied.
    retire_node(alloc_node(b));
}

// ── Grace-period machinery ──────────────────────────────────────────

/// Declare a quiescent state on the current CPU. The scheduler is
/// expected to call this at every `Future::poll` boundary (spec §3.7);
/// consumers running outside the scheduler may call it manually (used
/// by the verification harness).
#[inline]
pub fn report_quiescent() {
    qsbr::report_quiescent();
}

/// Lock-free watchdog snapshot of active CPUs that have not crossed a QSBR
/// quiescent boundary within `threshold_ns`.
#[inline]
pub fn stalled_cpu_mask(now_ns: u64, threshold_ns: u64) -> u64 {
    qsbr::stalled_cpu_mask(now_ns, threshold_ns)
}

/// Executor maintenance hook: open the next grace period when this CPU
/// holds deferred objects that the current epoch can never release. See
/// [`qsbr::advance_epoch_if_pending`]. Called once per executor round;
/// near-free when the local defer bucket is empty.
#[inline]
pub fn advance_epoch_if_pending() {
    qsbr::advance_epoch_if_pending();
}

/// Declare that the current CPU is going idle (about to halt and
/// stop polling). Resets the per-CPU `last_quiescent` to the
/// inactive sentinel so `sync()` doesn't block on an asleep CPU.
/// The CPU re-adopts the live epoch on its first
/// `report_quiescent` after wake.
#[inline]
pub fn report_idle() {
    qsbr::report_idle();
}

/// Wait one grace period and drain the resulting drop batch.
///
/// Blocks for as long as the grace period takes — see
/// [`qsbr::sync_blocking`] for why it no longer gives up partway, and
/// what that means for a caller that cannot block indefinitely or that
/// runs with interrupts masked. `sync_until` takes a deadline and
/// reports whether the grace period actually elapsed; `sync_async`
/// yields to the executor instead of spinning.
pub fn sync() {
    qsbr::sync_blocking();
}

/// [`sync`] with an absolute `narf_time::monotonic_ns` deadline.
///
/// Returns whether the grace period elapsed. `false` means it did NOT,
/// and nothing retired before the call may be freed.
#[must_use = "false means the grace period did NOT elapse"]
pub fn sync_until(deadline_ns: u64) -> bool {
    qsbr::sync_until(deadline_ns)
}

/// Grace periods that waited past [`qsbr::STALL_WARN_NS`] on `cpu` —
/// spec §3.3's `stuck_quiescent_cpu`.
pub fn stuck_quiescent_cpu(cpu: usize) -> u64 {
    qsbr::stuck_quiescent_cpu(cpu)
}

/// Times a grace-period wait was refused because the caller held a live
/// read guard on its own CPU.
pub fn sync_reader_held_count() -> u64 {
    qsbr::sync_reader_held_count()
}

/// Test-only re-export of [`qsbr::__test_last_quiescent`].
#[doc(hidden)]
pub fn __test_last_quiescent(cpu: usize) -> u64 {
    qsbr::__test_last_quiescent(cpu)
}

/// Async form of `sync()`. Yields to the executor between polls so a
/// cooperative executor can drive other tasks while this awaits.
pub fn sync_async() -> impl core::future::Future<Output = ()> {
    qsbr::SyncFuture::new()
}

// Hazard-pointer types live in `hazard.rs` and are re-exported above.
