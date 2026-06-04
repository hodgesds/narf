//! narf-ipc — Narf-Ring: SPSC shared-memory rings.
//!
//! Spec: `ipc/specification/spec.md`. Stage-3 Wave 1 subset: a single
//! shared-memory ring split into a `Producer` / `Consumer` pair with
//! ownership-transfer semantics (`T: Send + 'static + Retag`, moved through
//! `MaybeUninit<T>` slots), cache-line-partitioned header, and
//! release/acquire discipline on every index transition — the latter
//! being the #1 correctness hazard per the spec's invariants.
//!
//! What exists in Wave 1:
//! - `Ring<T, N>`: fixed power-of-two capacity; producer `head` and
//!   consumer `tail` on separate cache lines; `closed` flag; two
//!   `Waker` slots (one each side).
//! - `channel()`: splits a fresh ring into `Producer<T, N>` +
//!   `Consumer<T, N>`. Both are `!Sync` (single-caller invariant
//!   enforced at the type level via `PhantomData<*const ()>`).
//! - `Producer::try_send` (non-blocking, returns `Err(TrySendError)`)
//!   and `Producer::send` (async, registers a waker when `Full`).
//! - `Consumer::recv`: async, registers a waker when empty. Returns
//!   `RecvError::Closed` when the producer half has been dropped.
//! - `CapType` impl for the ring handle so Wave-2 cap-table integration
//!   can drop real `Cap<Ring, Send/Recv>` without shuffling types.
//!
//! Non-goals for Wave 1:
//! - Real `Cap<Ring, Send/Recv>` gating (Wave 2, after cap-table runtime).
//! - MPSC / SPMC variants.
//! - MMIO / UIPI doorbell (Stage 3 driver framework).
//! - Per-op cancellation via `OpCode::Cancel` (that is `abi/` Wave 2).
//!
//! aarch64 MTE retag on publish: the `Retag` trait gives a blanket
//! identity default; types whose payload carries raw pointers opt in
//! by implementing `retag` to call `narf_arch::aarch64::mte::{irg,
//! stg}` on each field. Stable Rust can't reflect into arbitrary `T`,
//! so opt-in is the only sound surface.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod retag;
pub use retag::Retag;

pub mod mpsc;
pub use mpsc::{mpsc_channel, MpscConsumer, MpscProducer, MpscRecvError, MpscSendError};

pub mod mpsc_ring;
pub use mpsc_ring::{
    mpsc_ring_channel, MpscRing, MpscRingConsumer, MpscRingProducer, MpscRingRecvError,
    MpscRingSendError,
};

pub mod spmc_ring;
pub use spmc_ring::{
    spmc_ring_channel, SpmcRing, SpmcRingConsumer, SpmcRingProducer, SpmcRingRecvError,
    SpmcRingSendError,
};

pub mod shared_ring;
pub use shared_ring::{
    SharedConsumer, SharedProducer, SharedRing, TryRecvError as SharedTryRecvError,
    TrySendError as SharedTrySendError,
};

mod tests;

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::future::Future;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use narf_capabilities::{CapKind, CapType};
use narf_lib::sync::{IrqSafeSpinLock, IrqsEnabled, SpinLock};

// ── Ring<T, N> ──────────────────────────────────────────────────────
//
// Cache-line partitioning discipline: producer head, consumer tail, and
// the payload array each live on their own 64-byte line via the
// `Align64` wrapper. 64 B is the common denominator of x86_64 / aarch64
// L1 lines; Apple-silicon 128 B would over-pad, not mis-align.

/// SPSC shared-memory ring, `N` must be a non-zero power of two.
/// Layout discipline (spec §4): producer head, consumer tail, and the
/// payload array each live on their own cache line to avoid
/// Disruptor-style false sharing.
#[repr(C)]
pub struct Ring<T, const N: usize> {
    /// Producer-owned cache line.
    head: Align64<AtomicU64>,
    /// Consumer-owned cache line.
    tail: Align64<AtomicU64>,
    /// Latches `true` when either end drops; the other half observes
    /// EOF on its next op.
    closed: AtomicBool,
    /// Waker for the producer, stored by the consumer when the ring
    /// is full and the producer needs to know a slot freed.
    producer_waker: SpinLock<Option<Waker>>,
    /// Waker for the consumer, stored by the producer when it
    /// publishes and the consumer had previously observed empty.
    /// `IrqSafe` because a driver (Stage 3) may publish from an IRQ
    /// handler on the producer side.
    consumer_waker: IrqSafeSpinLock<Option<Waker>>,
    /// Payload. `UnsafeCell` because producer + consumer write/read
    /// different slots concurrently; ordering is proven by the
    /// release/acquire pair on `head` / `tail`, not by Rust borrow
    /// rules.
    slots: UnsafeCell<[MaybeUninit<T>; N]>,
}

/// 64-byte alignment wrapper — forces the wrapped field onto its own
/// cache line. `repr(C, align(64))` is the standard trick.
#[repr(C, align(64))]
struct Align64<T>(T);

impl<T, const N: usize> core::fmt::Debug for Ring<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ring")
            .field("capacity", &N)
            .field("head", &self.head.0.load(Ordering::Relaxed))
            .field("tail", &self.tail.0.load(Ordering::Relaxed))
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// SAFETY: cross-task sharing is correct under the release/acquire pair
// on `head` / `tail`. `T: Send` so moving ownership through a slot
// across task boundaries is sound.
unsafe impl<T: Send, const N: usize> Send for Ring<T, N> {}
unsafe impl<T: Send, const N: usize> Sync for Ring<T, N> {}

impl<T, const N: usize> Ring<T, N> {
    // Compile-time invariant: N must be a non-zero power of two so
    // `idx & (N - 1)` is a valid mask. A non-power-of-two would force
    // a divide in the hot path.
    const POW2_GUARD: () = assert!(
        N > 0 && (N & (N - 1)) == 0,
        "Ring capacity must be a non-zero power of two",
    );
    const MASK: u64 = (N as u64) - 1;

    const fn new() -> Self {
        // Touch the guard so a non-pow2 N fails at compile time.
        let _ = Self::POW2_GUARD;
        Self {
            head: Align64(AtomicU64::new(0)),
            tail: Align64(AtomicU64::new(0)),
            closed: AtomicBool::new(false),
            producer_waker: SpinLock::new(None),
            consumer_waker: IrqSafeSpinLock::new(None),
            // SAFETY: MaybeUninit does not require initialisation.
            slots: UnsafeCell::new(unsafe {
                MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init()
            }),
        }
    }
}

impl<T: 'static, const N: usize> CapType for Ring<T, N> {
    const KIND: CapKind = CapKind::Ring;
}

impl<T, const N: usize> Drop for Ring<T, N> {
    fn drop(&mut self) {
        // Run destructors on any undelivered slots. With the Arc<Ring>
        // split, this only runs once both Producer and Consumer are
        // gone, so no torn access to `head` / `tail` is possible.
        let head = *self.head.0.get_mut();
        let tail = *self.tail.0.get_mut();
        let slots = self.slots.get_mut();
        let mut i = tail;
        while i != head {
            let idx = (i & Self::MASK) as usize;
            // SAFETY: indices in [tail, head) were published by the
            // producer but not consumed; their payloads are live
            // `MaybeUninit<T>` initialised values.
            unsafe {
                core::mem::replace(&mut slots[idx], MaybeUninit::uninit()).assume_init_drop();
            }
            i = i.wrapping_add(1);
        }
    }
}

// ── split into producer + consumer ──────────────────────────────────

/// Allocate a fresh ring and split it into a `(Producer, Consumer)` pair.
pub fn channel<T: Send + 'static + Retag, const N: usize>() -> (Producer<T, N>, Consumer<T, N>) {
    let ring = Arc::new(Ring::<T, N>::new());
    (
        Producer {
            ring: ring.clone(),
            _not_sync: PhantomData,
        },
        Consumer {
            ring,
            _not_sync: PhantomData,
        },
    )
}

// ── Producer ────────────────────────────────────────────────────────

/// Send end of the ring. `!Sync` — a single task owns it at a time.
pub struct Producer<T: Send + 'static + Retag, const N: usize> {
    ring: Arc<Ring<T, N>>,
    // `*const ()` is !Send and !Sync. Override Send below; leave !Sync.
    _not_sync: PhantomData<*const ()>,
}

// SAFETY: Producer is a single-owner handle; `Arc<Ring>` is Send when
// the payload is Send. The `!Sync` constraint is preserved by keeping
// the PhantomData above.
unsafe impl<T: Send + 'static + Retag, const N: usize> Send for Producer<T, N> {}

impl<T: Send + 'static + Retag, const N: usize> core::fmt::Debug for Producer<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Producer")
            .field("ring", &*self.ring)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum TrySendError<T> {
    /// Ring full — caller can retry later or `await` via `send`.
    Full(T),
    /// Consumer has dropped; no future recv will observe this message.
    Closed(T),
}

impl<T: Send + 'static + Retag, const N: usize> Producer<T, N> {
    /// Diagnostic: pointer to the inner `Ring`. Useful in canary
    /// smokes that need to verify channel construction landed the
    /// `Arc<Ring>` allocation inside the expected heap range, not
    /// in MMIO / reserved territory.
    #[doc(hidden)]
    pub fn __ring_ptr_for_test(&self) -> *const () {
        Arc::as_ptr(&self.ring) as *const ()
    }

    /// Non-blocking send. On `Full`, the message is returned to the
    /// caller so no data is silently dropped.
    pub fn try_send(&mut self, msg: T) -> Result<(), TrySendError<T>> {
        if self.ring.closed.load(Ordering::Acquire) {
            return Err(TrySendError::Closed(msg));
        }
        let head = self.ring.head.0.load(Ordering::Relaxed);
        // Use acquire on tail so we see the consumer's most-recent
        // advance — required to know whether the slot we're about to
        // write is free.
        let tail = self.ring.tail.0.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= N as u64 {
            return Err(TrySendError::Full(msg));
        }
        let idx = (head & Ring::<T, N>::MASK) as usize;
        // SAFETY: the producer is the sole writer of slot `idx` until
        // the release-store of `head` below publishes it; between
        // `head - tail < N` and that store, the consumer cannot
        // observe the slot. `retag::retag_on_publish` is identity for
        // types not implementing `Retag`; opt-in types (e.g. payloads
        // carrying raw pointers crossing aarch64 MTE domains) get
        // their `Retag::retag` invoked here.
        unsafe {
            let slots = &mut *self.ring.slots.get();
            slots[idx].write(retag::retag_on_publish(msg));
        }
        // Release: pairs with the consumer's Acquire on `head`. Makes
        // the slot payload visible before the consumer observes the
        // new head.
        self.ring
            .head
            .0
            .store(head.wrapping_add(1), Ordering::Release);

        // Wake the consumer if it registered one.
        if let Some(w) = self.ring.consumer_waker.lock().take() {
            w.wake();
        }
        Ok(())
    }

    /// Async send: awaits capacity on `Full`. Registers a waker the
    /// consumer calls when it advances the tail.
    pub fn send(&mut self, msg: T) -> SendFuture<'_, T, N> {
        SendFuture {
            producer: self,
            slot: Some(msg),
        }
    }
}

impl<T: Send + 'static + Retag, const N: usize> Drop for Producer<T, N> {
    fn drop(&mut self) {
        self.ring.closed.store(true, Ordering::Release);
        if let Some(w) = self.ring.consumer_waker.lock().take() {
            w.wake();
        }
    }
}

/// Future returned by `Producer::send`. Holds the message until it has
/// been moved into a slot (ownership transfer = move semantics).
#[derive(Debug)]
pub struct SendFuture<'a, T: Send + 'static + Retag, const N: usize> {
    producer: &'a mut Producer<T, N>,
    slot: Option<T>,
}

// SendFuture only owns `&mut Producer` (a reference) and `Option<T>`
// (movable by value), so it is structurally Unpin regardless of T.
impl<T: Send + 'static + Retag, const N: usize> core::marker::Unpin for SendFuture<'_, T, N> {}

impl<'a, T: Send + 'static + Retag, const N: usize> Future for SendFuture<'a, T, N> {
    type Output = Result<(), T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let msg = this
            .slot
            .take()
            .expect("SendFuture polled after completion");
        match this.producer.try_send(msg) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(TrySendError::Closed(m)) => Poll::Ready(Err(m)),
            Err(TrySendError::Full(m)) => {
                // Register our waker, then re-check: the consumer may
                // have drained between our try_send and the waker
                // install (lost-wakeup avoidance).
                *this.producer.ring.producer_waker.lock(IrqsEnabled) = Some(cx.waker().clone());
                match this.producer.try_send(m) {
                    Ok(()) => {
                        // Clear the waker — we no longer need a wake.
                        *this.producer.ring.producer_waker.lock(IrqsEnabled) = None;
                        Poll::Ready(Ok(()))
                    }
                    Err(TrySendError::Closed(m)) => Poll::Ready(Err(m)),
                    Err(TrySendError::Full(m)) => {
                        this.slot = Some(m);
                        Poll::Pending
                    }
                }
            }
        }
    }
}

// ── Consumer ────────────────────────────────────────────────────────

pub struct Consumer<T: Send + 'static + Retag, const N: usize> {
    ring: Arc<Ring<T, N>>,
    _not_sync: PhantomData<*const ()>,
}

// SAFETY: Consumer is single-owner; see Producer.
unsafe impl<T: Send + 'static + Retag, const N: usize> Send for Consumer<T, N> {}

impl<T: Send + 'static + Retag, const N: usize> core::fmt::Debug for Consumer<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Consumer")
            .field("ring", &*self.ring)
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecvError {
    /// Producer has dropped and the ring is empty. Any further recv
    /// will also observe `Closed`.
    Closed,
}

impl<T: Send + 'static + Retag, const N: usize> Consumer<T, N> {
    /// Diagnostic: pointer to the inner `Ring`. Mirror of
    /// `Producer::__ring_ptr_for_test` on the consumer half.
    #[doc(hidden)]
    pub fn __ring_ptr_for_test(&self) -> *const () {
        Arc::as_ptr(&self.ring) as *const ()
    }

    /// Non-blocking peek-and-take. `None` means empty; `Closed` is
    /// only reported once the ring has drained.
    pub fn try_recv(&mut self) -> Result<Option<T>, RecvError> {
        let tail = self.ring.tail.0.load(Ordering::Relaxed);
        // Acquire on head so we see a fully-published slot written
        // before the producer's release-store.
        let head = self.ring.head.0.load(Ordering::Acquire);
        if head == tail {
            // Empty. Report closed only after drain.
            return if self.ring.closed.load(Ordering::Acquire) {
                Err(RecvError::Closed)
            } else {
                Ok(None)
            };
        }
        let idx = (tail & Ring::<T, N>::MASK) as usize;
        // SAFETY: the slot was published by a release-store of `head`
        // that our acquire-load just observed; consumer is sole reader.
        let msg = unsafe {
            let slots = &mut *self.ring.slots.get();
            core::mem::replace(&mut slots[idx], MaybeUninit::uninit()).assume_init()
        };
        // Release: pairs with the producer's Acquire on `tail`. Makes
        // the slot-freed fact visible before the producer observes the
        // new tail.
        self.ring
            .tail
            .0
            .store(tail.wrapping_add(1), Ordering::Release);

        if let Some(w) = self.ring.producer_waker.lock(IrqsEnabled).take() {
            w.wake();
        }
        Ok(Some(msg))
    }

    pub fn recv(&mut self) -> RecvFuture<'_, T, N> {
        RecvFuture { consumer: self }
    }
}

impl<T: Send + 'static + Retag, const N: usize> Drop for Consumer<T, N> {
    fn drop(&mut self) {
        self.ring.closed.store(true, Ordering::Release);
        if let Some(w) = self.ring.producer_waker.lock(IrqsEnabled).take() {
            w.wake();
        }
    }
}

#[derive(Debug)]
pub struct RecvFuture<'a, T: Send + 'static + Retag, const N: usize> {
    consumer: &'a mut Consumer<T, N>,
}

// Same rationale as SendFuture's Unpin: only a &mut reference inside.
impl<T: Send + 'static + Retag, const N: usize> core::marker::Unpin for RecvFuture<'_, T, N> {}

impl<'a, T: Send + 'static + Retag, const N: usize> Future for RecvFuture<'a, T, N> {
    type Output = Result<T, RecvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.consumer.try_recv() {
            Ok(Some(msg)) => Poll::Ready(Ok(msg)),
            Err(e) => Poll::Ready(Err(e)),
            Ok(None) => {
                // Install waker and re-check for lost-wakeup avoidance.
                *this.consumer.ring.consumer_waker.lock() = Some(cx.waker().clone());
                match this.consumer.try_recv() {
                    Ok(Some(msg)) => {
                        *this.consumer.ring.consumer_waker.lock() = None;
                        Poll::Ready(Ok(msg))
                    }
                    Err(e) => Poll::Ready(Err(e)),
                    Ok(None) => Poll::Pending,
                }
            }
        }
    }
}
