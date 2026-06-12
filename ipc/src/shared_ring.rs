//! Shared-memory SPSC ring designed to live in a single 4 KiB page.
//!
//! Spec: extension to `ipc/specification/spec.md` for the Stage-4
//! "user-mappable rings" deliverable. Where `Ring<T, N>` (the
//! kernel-only primitive in `lib.rs`) carries Rust-managed wakers
//! and Arc-shared backing, this `SharedRing<T, N>` is byte-for-byte
//! a wire layout: head/tail/closed atomics live at fixed offsets at
//! the start of the page, slots follow at offset 64. The kernel and
//! user reach the same backing through different virtual mappings —
//! both produce/consume against the same 4 KiB page.
//!
//! Wave 1 surface (this module):
//! - `SharedRing<T, N>`: pinned `#[repr(C)]` layout. Construct
//!   in-place via `init_in(*mut SharedRing<T, N>)` against a
//!   zero-fillable buffer.
//! - `SharedProducer<T, N>` / `SharedConsumer<T, N>`: split halves.
//!   Each holds a raw `*mut SharedRing<T, N>` and a `PhantomData`
//!   marker. No `Drop` plumbing — the backing is owned by whoever
//!   allocated the page.
//! - `try_send` / `try_recv` only. Async/waker support is a future
//!   round (it'd need a side-channel for the kernel to deliver
//!   user-mode wakes; UIPI / UMWAIT lands later).
//!
//! Layout (`SharedRing<Submission, 16>` example):
//!
//!   offset  0 +-- head:   AtomicU32 -+
//!           4 +-- tail:   AtomicU32 -+- header
//!           8 +-- closed: AtomicU32 -+
//!          12 ....pad to 64...........
//!          64 +-- slots[0..N]
//!
//! The ring is explicitly **not** `Drop` — slot destructors run
//! through `try_recv`. A page that's been mapped by both kernel and
//! user can be dropped only by unmap/free at the page level; doing
//! so before draining the ring leaks `T`'s payload (a frame leak
//! that the caller is expected to manage).

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, Ordering};

/// Shared-memory SPSC ring. `N` must be a non-zero power of two.
/// Layout is wire-stable: kernel-side and user-side must agree on
/// the byte offsets of every field. `#[repr(C)]` + the explicit
/// padding pin them.
#[repr(C)]
pub struct SharedRing<T, const N: usize> {
    /// Producer-owned head index. Wraps freely; modular arithmetic
    /// against `N` masks to a slot. Kernel and user both observe
    /// release/acquire ordering on this field.
    pub head: AtomicU32,
    /// Consumer-owned tail index. Same wrap discipline as `head`.
    pub tail: AtomicU32,
    /// Latches non-zero when either end declares EOF. The other
    /// half observes via `is_closed()` on its next op.
    pub closed: AtomicU32,
    /// Pad to 64 bytes so `slots` starts on a fresh cache line and
    /// the layout is a flat 64+N*sizeof(T) shape.
    _pad: [u8; 52],
    /// Slot storage. `UnsafeCell` because head/tail are the only
    /// synchronisation; Rust's borrow rules don't apply across the
    /// kernel/user boundary anyway.
    pub slots: [UnsafeCell<MaybeUninit<T>>; N],
}

// SAFETY: the ring itself only owns plain atomics and `MaybeUninit<T>`
// slots that hold moved-in values; moving the whole ring to another
// thread is sound whenever `T: Send`.
unsafe impl<T: Send, const N: usize> Send for SharedRing<T, N> {}
// SAFETY: the wire-stable atomics order all cross-side memory accesses.
// A given slot index is written by exactly one side (the producer)
// between a `head` advance and the matching `tail` advance, and the
// release-store of `head` / `tail` happens-before the paired acquire on
// the other side, so there is never a data race on `slots`. `T: Send`
// because payload ownership is transferred between the two sides.
unsafe impl<T: Send, const N: usize> Sync for SharedRing<T, N> {}

impl<T, const N: usize> core::fmt::Debug for SharedRing<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedRing")
            .field("capacity", &N)
            .field("head", &self.head.load(Ordering::Relaxed))
            .field("tail", &self.tail.load(Ordering::Relaxed))
            .field("closed", &(self.closed.load(Ordering::Relaxed) != 0))
            .finish_non_exhaustive()
    }
}

impl<T, const N: usize> SharedRing<T, N> {
    const POW2_GUARD: () = assert!(
        N > 0 && (N & (N - 1)) == 0,
        "SharedRing capacity must be a non-zero power of two",
    );
    const MASK: u32 = (N as u32) - 1;

    /// Total byte size occupied by a `SharedRing<T, N>`. Useful for
    /// callers verifying the ring fits in their allocation budget.
    pub const fn size_bytes() -> usize {
        core::mem::size_of::<Self>()
    }

    /// Initialise a fresh `SharedRing` in place at `ptr`. Zeros all
    /// header atomics; slot storage is left as uninitialised
    /// `MaybeUninit`, which is valid for `try_send` to overwrite.
    ///
    /// # Safety
    /// - `ptr` must be 8-aligned and point at writable storage of at
    ///   least `size_bytes()` bytes.
    /// - The buffer must outlive any `SharedProducer` / `SharedConsumer`
    ///   constructed against it.
    /// - The caller is responsible for zero-filling the page first
    ///   (or at least ensuring header bytes are writable). The Stage-4
    ///   call sites zero a freshly-allocated frame, satisfying this.
    pub unsafe fn init_in(ptr: *mut Self) {
        let () = Self::POW2_GUARD;
        // Direct atomic stores (rather than constructing a Self via
        // the stack) avoid touching the slot region — important when
        // the buffer might be partially writable or partially uncached.
        // SAFETY: per this fn's `# Safety` contract, `ptr` is 8-aligned
        // and points at writable storage of at least `size_bytes()`
        // bytes, so the `head`/`tail`/`closed` atomics (the first 12
        // bytes of the `#[repr(C)]` layout) are valid to store into.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            (*ptr).head.store(0, Ordering::Relaxed);
            (*ptr).tail.store(0, Ordering::Relaxed);
            (*ptr).closed.store(0, Ordering::Relaxed);
        }
    }
}

/// Producer half. Holds a raw pointer to the shared ring; the
/// actual storage lives in the page the caller mapped. Single
/// active producer per ring (SPSC).
#[derive(Debug)]
pub struct SharedProducer<T, const N: usize> {
    ring: *mut SharedRing<T, N>,
    _marker: PhantomData<*const ()>, // !Send + !Sync by construction
}

/// Consumer half — counterpart to `SharedProducer`.
#[derive(Debug)]
pub struct SharedConsumer<T, const N: usize> {
    ring: *mut SharedRing<T, N>,
    _marker: PhantomData<*const ()>,
}

// SAFETY: the producer half is explicitly !Sync (one active producer
// per side). Sending it to another thread is sound because it only
// owns a raw `*mut SharedRing<T, N>`; cross-thread correctness is
// carried by the release/acquire pair on head/tail, and `T: Send`
// allows the payload to move with the producer.
unsafe impl<T: Send, const N: usize> Send for SharedProducer<T, N> {}
// SAFETY: the consumer half is the mirror of `SharedProducer`: !Sync,
// holds only a raw pointer to the shared page, and ordering is carried
// by head/tail. `T: Send` for the same payload-transfer reason.
unsafe impl<T: Send, const N: usize> Send for SharedConsumer<T, N> {}

/// Errors `try_send` can surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TrySendError<T> {
    /// Ring full; caller can retry. Returns the message so no data
    /// is silently dropped.
    Full(T),
    /// Counterpart half declared the ring closed.
    Closed(T),
}

impl<T, const N: usize> SharedProducer<T, N> {
    /// Construct a producer half against a shared-ring backing.
    ///
    /// # Safety
    /// - `ring` must point at a `SharedRing<T, N>` that has been
    ///   `init_in`-initialised.
    /// - At most one `SharedProducer` may exist for a given ring at
    ///   a time — SPSC contract.
    pub unsafe fn from_raw(ring: *mut SharedRing<T, N>) -> Self {
        Self {
            ring,
            _marker: PhantomData,
        }
    }

    /// Non-blocking enqueue.
    pub fn try_send(&mut self, msg: T) -> Result<(), TrySendError<T>> {
        // SAFETY: `self.ring` is valid per `from_raw` contract.
        let r = unsafe { &*self.ring };
        if r.closed.load(Ordering::Acquire) != 0 {
            return Err(TrySendError::Closed(msg));
        }
        let head = r.head.load(Ordering::Relaxed);
        // Acquire on tail: pairs with consumer's Release in try_recv.
        let tail = r.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= N as u32 {
            return Err(TrySendError::Full(msg));
        }
        let idx = (head & SharedRing::<T, N>::MASK) as usize;
        // SAFETY: producer is sole writer of slot `idx` until the
        // release-store of `head` publishes it; consumer cannot
        // observe slot before that store.
        //
        // `write_volatile` (rather than `MaybeUninit::write`) is
        // load-bearing: the consumer reaches the slot through a
        // raw `*mut SharedRing<T, N>` cast from a `u64` phys
        // address that traversed an opaque kernel/user boundary
        // (function-pointer dispatch in the syscall table). LLVM
        // can't trace the read across that boundary, and the
        // int-to-pointer cast on both sides carries no provenance,
        // so a plain store of the non-atomic slot payload is
        // eligible for dead-store elimination — the consumer then
        // reads zero bytes even though the atomic `head` store
        // (immune to DSE) advances correctly. Volatile pins the
        // write as architecturally observable, matching the actual
        // contract: the slot is a wire-format mailbox shared with
        // another execution context the compiler can't see.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::ptr::write_volatile(r.slots[idx].get(), MaybeUninit::new(msg));
        }
        // Release: pairs with consumer's Acquire on `head` — slot
        // payload becomes visible before the consumer sees the new
        // head.
        r.head.store(head.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Mark the ring closed from the producer side. Idempotent.
    pub fn close(&mut self) {
        // SAFETY: `self.ring` is valid per `from_raw` contract.
        unsafe {
            (*self.ring).closed.store(1, Ordering::Release);
        }
    }
}

/// Errors `try_recv` can surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TryRecvError {
    /// Ring empty.
    Empty,
    /// Counterpart half declared the ring closed and the ring is
    /// now drained.
    Closed,
}

impl<T, const N: usize> SharedConsumer<T, N> {
    /// Construct a consumer half against a shared-ring backing.
    ///
    /// # Safety
    /// Same SPSC contract as `SharedProducer::from_raw`.
    pub unsafe fn from_raw(ring: *mut SharedRing<T, N>) -> Self {
        Self {
            ring,
            _marker: PhantomData,
        }
    }

    /// Non-blocking dequeue.
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        // SAFETY: `self.ring` is valid per `from_raw` contract.
        let r = unsafe { &*self.ring };
        let tail = r.tail.load(Ordering::Relaxed);
        // Acquire on head: pairs with producer's Release in try_send.
        let head = r.head.load(Ordering::Acquire);
        if tail == head {
            if r.closed.load(Ordering::Acquire) != 0 {
                return Err(TryRecvError::Closed);
            }
            return Err(TryRecvError::Empty);
        }
        let idx = (tail & SharedRing::<T, N>::MASK) as usize;
        // SAFETY: producer published this slot before its release
        // store of `head`; we acquired that store, so the payload
        // is now ours to read. Volatile pairs with the producer's
        // `write_volatile` — same reasoning: the slot lives in a
        // wire-format page shared with an execution context LLVM
        // can't see, so non-volatile reads were eligible for
        // load forwarding from a stale "uninitialized" lattice.
        // SAFETY: Valid memory or trusted environment
        let msg = unsafe {
            core::ptr::read_volatile(r.slots[idx].get() as *const MaybeUninit<T>).assume_init()
        };
        // Release: pairs with producer's Acquire on tail — frees
        // the slot for the producer to reuse.
        r.tail.store(tail.wrapping_add(1), Ordering::Release);
        Ok(msg)
    }

    /// Mark the ring closed from the consumer side. Idempotent.
    pub fn close(&mut self) {
        // SAFETY: `self.ring` is valid per `from_raw` contract.
        unsafe {
            (*self.ring).closed.store(1, Ordering::Release);
        }
    }
}

// ── Wire-format pins ──────────────────────────────────────────────
//
// These const asserts catch silent layout drift. The exact byte
// budget for the Stage-4 ring shapes (`Submission` / `Completion`)
// is verified at the abi/ side; here we just pin the header.

const _: () = assert!(core::mem::size_of::<AtomicU32>() == 4);
// Header is exactly 64 bytes (head+tail+closed+pad).
const _: () = {
    // Use a representative T (u8 here) because the offset of `slots`
    // is independent of `T`'s alignment as long as `T`'s alignment
    // <= 64.
    let off = core::mem::offset_of!(SharedRing<u8, 1>, slots);
    assert!(off == 64, "SharedRing header is not exactly 64 bytes");
};
