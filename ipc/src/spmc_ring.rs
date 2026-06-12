//! Single-producer / multi-consumer lock-free ring.
//!
//! Algorithm: Dmitry Vyukov's bounded MPMC ring, specialised here
//! to a single producer (the producer increments tail with no CAS
//! since it is the sole writer; consumers CAS the shared head).
//!   <https://www.1024cores.net/home/lock-free-algorithms/queues/bounded-mpmc-queue>
//!
//! Memory-order rationale (release / acquire pairing on every index
//! transition) follows the C++ memory model:
//!   <https://en.cppreference.com/w/cpp/atomic/memory_order>
//!
//! Cross-check with Michael & Scott's "Simple, Fast, and Practical
//! Non-Blocking and Blocking Concurrent Queue Algorithms" (PODC '96)
//! for the broader lock-free-queue context.
//!
//! Layout discipline mirrors `Ring<T, N>` (Stage-3 SPSC): producer
//! tail, consumer-shared head, and the slot array each sit on their
//! own 64-byte cache line via `Align64`. Each slot carries a per-slot
//! `AtomicU64` sequence counter — the producer writes a slot whose
//! `seq == pos` (always true for the sole writer once a wrap is
//! complete), then release-stores `seq = pos + 1` to publish;
//! consumers CAS-claim a slot whose `seq == pos + 1`, take the value,
//! then release-store `seq = pos + N` to mark the slot reusable.

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::future::Future;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use narf_lib::sync::IrqSafeSpinLock;

#[repr(C, align(64))]
struct Align64<T>(T);

struct Slot<T> {
    seq: AtomicU64,
    val: UnsafeCell<MaybeUninit<T>>,
}

/// Bounded SPMC ring. `N` must be a non-zero power of two.
#[repr(C)]
pub struct SpmcRing<T, const N: usize> {
    /// Producer-owned tail.
    tail: Align64<AtomicU64>,
    /// Consumer-shared head (claimed via CAS).
    head: Align64<AtomicU64>,
    /// Number of live consumers; producer treats `consumers == 0`
    /// as a closed ring once observed.
    consumers: AtomicUsize,
    /// Latches when the producer drops.
    producer_gone: AtomicBool,
    /// Any consumer parks here when empty; first-waker-wins.
    consumer_waker: IrqSafeSpinLock<Option<Waker>>,
    /// Producer parks here when full.
    producer_waker: IrqSafeSpinLock<Option<Waker>>,
    slots: Align64<UnsafeCell<[Slot<T>; N]>>,
}

impl<T, const N: usize> core::fmt::Debug for SpmcRing<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpmcRing")
            .field("capacity", &N)
            .field("tail", &self.tail.0.load(Ordering::Relaxed))
            .field("head", &self.head.0.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// SAFETY: the ring owns only atomics, lock-guarded wakers, and
// `MaybeUninit<T>` slots holding moved-in values; moving the whole ring
// across threads is sound when `T: Send`.
unsafe impl<T: Send, const N: usize> Send for SpmcRing<T, N> {}
// SAFETY: Vyukov-style bounded queue with per-slot `seq` atomics. The
// sole producer writes a slot's payload only after observing its slot
// is free, and a consumer reads it only after a successful CAS on
// `head` claims it plus an acquire-load of the producer's release-store
// of `seq`. That per-slot release/acquire pairing means each payload is
// accessed by exactly one side at a time, so concurrent `&SpmcRing` use
// from one producer plus many consumers is data-race-free when
// `T: Send`.
unsafe impl<T: Send, const N: usize> Sync for SpmcRing<T, N> {}

impl<T, const N: usize> SpmcRing<T, N> {
    const POW2_GUARD: () = assert!(
        N > 0 && (N & (N - 1)) == 0,
        "SpmcRing capacity must be a non-zero power of two",
    );
    const MASK: u64 = (N as u64) - 1;

    fn new() -> Self {
        let () = Self::POW2_GUARD;
        // SAFETY: see `MpscRing::new` — same uninit-then-init idiom.
        let slots: [Slot<T>; N] = unsafe {
            let mut arr: MaybeUninit<[Slot<T>; N]> = MaybeUninit::uninit();
            let ptr = arr.as_mut_ptr() as *mut Slot<T>;
            for i in 0..N {
                core::ptr::write(
                    ptr.add(i),
                    Slot {
                        seq: AtomicU64::new(i as u64),
                        val: UnsafeCell::new(MaybeUninit::uninit()),
                    },
                );
            }
            arr.assume_init()
        };
        Self {
            tail: Align64(AtomicU64::new(0)),
            head: Align64(AtomicU64::new(0)),
            consumers: AtomicUsize::new(1),
            producer_gone: AtomicBool::new(false),
            consumer_waker: IrqSafeSpinLock::new(None),
            producer_waker: IrqSafeSpinLock::new(None),
            slots: Align64(UnsafeCell::new(slots)),
        }
    }
}

// ── RingTransport impl (Wave K) ─────────────────────────────────────
//
// SPMC: consumer side already operates against `&self` (multiple
// consumers race via CAS on `head`). The producer's inherent
// `try_send` takes `&mut self` on the producer wrapper to enforce
// single-producer at the type level — but the ring's push logic
// itself only needs `&self`. Trait callers are responsible for
// upholding the single-producer invariant when they push through the
// trait.
impl<T: Send + 'static, const N: usize> crate::transport::RingTransport<T> for SpmcRing<T, N> {
    fn try_push(&self, val: T) -> Result<(), T> {
        if self.consumers.load(Ordering::Acquire) == 0 {
            return Err(val);
        }
        let pos = self.tail.0.load(Ordering::Relaxed);
        let slot_ptr = self.slots.0.get();
        // SAFETY: slot array lives for the ring's lifetime.
        let slot = unsafe { &(*slot_ptr)[(pos & Self::MASK) as usize] };
        let seq = slot.seq.load(Ordering::Acquire);
        let diff = seq.wrapping_sub(pos) as i64;
        if diff != 0 {
            // <0: slot still occupied; >0: shouldn't happen with a
            // single producer — both collapse to "can't push".
            return Err(val);
        }
        // SAFETY: caller upholds single-producer invariant; the slot
        // is exclusively ours until our release-store of `seq` below.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            (*slot.val.get()).write(val);
        }
        self.tail.0.store(pos.wrapping_add(1), Ordering::Relaxed);
        slot.seq.store(pos.wrapping_add(1), Ordering::Release);
        if let Some(w) = self.consumer_waker.lock().take() {
            w.wake();
        }
        Ok(())
    }

    fn try_pop(&self) -> Option<T> {
        // Mirror `SpmcRingConsumer::try_recv`: CAS-claim on `head`
        // (multiple consumers race).
        loop {
            let pos = self.head.0.load(Ordering::Relaxed);
            let slot_ptr = self.slots.0.get();
            // SAFETY: slot array lives for the ring's lifetime.
            let slot = unsafe { &(*slot_ptr)[(pos & Self::MASK) as usize] };
            let seq = slot.seq.load(Ordering::Acquire);
            let diff = seq.wrapping_sub(pos.wrapping_add(1)) as i64;
            if diff < 0 {
                return None;
            }
            if diff > 0 {
                // Another consumer raced ahead; re-read head.
                continue;
            }
            match self.head.0.compare_exchange_weak(
                pos,
                pos.wrapping_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // SAFETY: we won the claim CAS; we are the sole
                    // consumer of this slot until our release-store
                    // of `seq` below.
                    // SAFETY: Valid memory or trusted environment
                    let msg = unsafe {
                        let v = core::mem::replace(&mut *slot.val.get(), MaybeUninit::uninit());
                        v.assume_init()
                    };
                    slot.seq
                        .store(pos.wrapping_add(N as u64), Ordering::Release);
                    if let Some(w) = self.producer_waker.lock().take() {
                        w.wake();
                    }
                    return Some(msg);
                }
                Err(_) => continue,
            }
        }
    }

    fn len(&self) -> usize {
        let tail = self.tail.0.load(Ordering::Acquire);
        let head = self.head.0.load(Ordering::Acquire);
        tail.wrapping_sub(head) as usize
    }

    fn capacity(&self) -> usize {
        N
    }
}

impl<T, const N: usize> Drop for SpmcRing<T, N> {
    fn drop(&mut self) {
        let head = *self.head.0.get_mut();
        let tail = *self.tail.0.get_mut();
        // SAFETY: `drop` has `&mut self`, so we hold exclusive access to
        // the ring; no producer or consumer can be touching `slots`
        // concurrently, making the `UnsafeCell` deref to `&mut` sound.
        // SAFETY: Valid memory or trusted environment
        let slots = unsafe { &mut *self.slots.0.get() };
        let mut i = head;
        while i != tail {
            let idx = (i & Self::MASK) as usize;
            let slot = &mut slots[idx];
            if *slot.seq.get_mut() == i.wrapping_add(1) {
                // SAFETY: producer published slot at `i + 1`; no
                // consumer ever claimed it. Payload is live.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    let mut v = core::mem::replace(slot.val.get_mut(), MaybeUninit::uninit());
                    v.assume_init_drop();
                }
            }
            i = i.wrapping_add(1);
        }
    }
}

#[derive(Debug)]
pub enum SpmcRingSendError<T> {
    Full(T),
    Closed(T),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpmcRingRecvError {
    Closed,
}

/// Producer handle — single-owner.
pub struct SpmcRingProducer<T: Send + 'static, const N: usize> {
    ring: Arc<SpmcRing<T, N>>,
    _not_sync: PhantomData<*const ()>,
}

// SAFETY: the producer owns an `Arc<SpmcRing<T, N>>` (Send when
// `T: Send`) plus a hint-only `PhantomData<*const ()>` that keeps the
// handle !Sync but is never dereferenced. Moving the single-owner
// producer to another thread is therefore sound.
unsafe impl<T: Send + 'static, const N: usize> Send for SpmcRingProducer<T, N> {}

impl<T: Send + 'static, const N: usize> core::fmt::Debug for SpmcRingProducer<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpmcRingProducer")
            .field("ring", &*self.ring)
            .finish_non_exhaustive()
    }
}

impl<T: Send + 'static, const N: usize> SpmcRingProducer<T, N> {
    pub fn try_send(&mut self, msg: T) -> Result<(), SpmcRingSendError<T>> {
        if self.ring.consumers.load(Ordering::Acquire) == 0 {
            return Err(SpmcRingSendError::Closed(msg));
        }
        let pos = self.ring.tail.0.load(Ordering::Relaxed);
        let slot_ptr = self.ring.slots.0.get();
        // SAFETY: slot array lives for the ring's lifetime.
        let slot = unsafe { &(*slot_ptr)[(pos & SpmcRing::<T, N>::MASK) as usize] };
        let seq = slot.seq.load(Ordering::Acquire);
        let diff = seq.wrapping_sub(pos) as i64;
        if diff < 0 {
            // Slot still occupied by an unread payload — full.
            return Err(SpmcRingSendError::Full(msg));
        }
        if diff > 0 {
            // Should not happen with a single producer — the sequence
            // can only advance to `pos` (consumer reset) or stay
            // behind (slot still pending). Treat conservatively.
            return Err(SpmcRingSendError::Full(msg));
        }
        // SAFETY: as the sole producer, we own this slot exclusively
        // between its release-store of `seq = pos + N` from the last
        // consumer and our own release-store of `seq = pos + 1`.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            (*slot.val.get()).write(msg);
        }
        self.ring
            .tail
            .0
            .store(pos.wrapping_add(1), Ordering::Relaxed);
        // Release: pairs with the consumer's Acquire on `seq`. Makes
        // payload visible before the consumer observes the new
        // sequence.
        slot.seq.store(pos.wrapping_add(1), Ordering::Release);
        if let Some(w) = self.ring.consumer_waker.lock().take() {
            w.wake();
        }
        Ok(())
    }

    pub fn send(&mut self, msg: T) -> SpmcRingSendFuture<'_, T, N> {
        SpmcRingSendFuture {
            producer: self,
            slot: Some(msg),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.ring.consumers.load(Ordering::Acquire) == 0
    }
}

impl<T: Send + 'static, const N: usize> Drop for SpmcRingProducer<T, N> {
    fn drop(&mut self) {
        self.ring.producer_gone.store(true, Ordering::Release);
        if let Some(w) = self.ring.consumer_waker.lock().take() {
            w.wake();
        }
    }
}

#[derive(Debug)]
pub struct SpmcRingSendFuture<'p, T: Send + 'static, const N: usize> {
    producer: &'p mut SpmcRingProducer<T, N>,
    slot: Option<T>,
}

impl<T: Send + 'static, const N: usize> core::marker::Unpin for SpmcRingSendFuture<'_, T, N> {}

impl<'p, T: Send + 'static, const N: usize> Future for SpmcRingSendFuture<'p, T, N> {
    type Output = Result<(), T>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let msg = this
            .slot
            .take()
            .expect("send future polled after completion");
        match this.producer.try_send(msg) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(SpmcRingSendError::Closed(m)) => Poll::Ready(Err(m)),
            Err(SpmcRingSendError::Full(m)) => {
                *this.producer.ring.producer_waker.lock() = Some(cx.waker().clone());
                match this.producer.try_send(m) {
                    Ok(()) => {
                        *this.producer.ring.producer_waker.lock() = None;
                        Poll::Ready(Ok(()))
                    }
                    Err(SpmcRingSendError::Closed(m)) => Poll::Ready(Err(m)),
                    Err(SpmcRingSendError::Full(m)) => {
                        this.slot = Some(m);
                        Poll::Pending
                    }
                }
            }
        }
    }
}

/// Consumer handle — `Clone` so N tasks can drain in parallel.
/// `Send + Sync`.
pub struct SpmcRingConsumer<T: Send + 'static, const N: usize> {
    ring: Arc<SpmcRing<T, N>>,
}

impl<T: Send + 'static, const N: usize> core::fmt::Debug for SpmcRingConsumer<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpmcRingConsumer")
            .field("ring", &*self.ring)
            .finish_non_exhaustive()
    }
}

impl<T: Send + 'static, const N: usize> Clone for SpmcRingConsumer<T, N> {
    fn clone(&self) -> Self {
        self.ring.consumers.fetch_add(1, Ordering::Relaxed);
        Self {
            ring: Arc::clone(&self.ring),
        }
    }
}

impl<T: Send + 'static, const N: usize> Drop for SpmcRingConsumer<T, N> {
    fn drop(&mut self) {
        if self.ring.consumers.fetch_sub(1, Ordering::AcqRel) == 1 {
            if let Some(w) = self.ring.producer_waker.lock().take() {
                w.wake();
            }
        }
    }
}

impl<T: Send + 'static, const N: usize> SpmcRingConsumer<T, N> {
    pub fn try_recv(&self) -> Result<Option<T>, SpmcRingRecvError> {
        let mut pos = self.ring.head.0.load(Ordering::Relaxed);
        let slot_ptr = self.ring.slots.0.get();
        loop {
            // SAFETY: slot array lives for the ring's lifetime.
            let slot = unsafe { &(*slot_ptr)[(pos & SpmcRing::<T, N>::MASK) as usize] };
            let seq = slot.seq.load(Ordering::Acquire);
            let diff = seq.wrapping_sub(pos.wrapping_add(1)) as i64;
            if diff == 0 {
                match self.ring.head.0.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // SAFETY: we are now the sole owner of this
                        // slot until we mark it reusable.
                        // SAFETY: Valid memory or trusted environment
                        let msg = unsafe {
                            let v = core::mem::replace(&mut *slot.val.get(), MaybeUninit::uninit());
                            v.assume_init()
                        };
                        // Release: pairs with the producer's Acquire
                        // load of `seq` the next time it visits this
                        // slot — payload zero (replaced with uninit)
                        // happens-before the producer's next write.
                        slot.seq
                            .store(pos.wrapping_add(N as u64), Ordering::Release);
                        if let Some(w) = self.ring.producer_waker.lock().take() {
                            w.wake();
                        }
                        return Ok(Some(msg));
                    }
                    Err(observed) => {
                        pos = observed;
                        continue;
                    }
                }
            } else if diff < 0 {
                // Empty for now. Check closed.
                if self.ring.producer_gone.load(Ordering::Acquire) {
                    // Re-check the slot after observing producer
                    // dropped, then re-check the tail to know if
                    // a published item might still be on the way
                    // (producer's release of `seq` happens-before
                    // its release of `producer_gone`).
                    let seq2 = slot.seq.load(Ordering::Acquire);
                    if seq2.wrapping_sub(pos.wrapping_add(1)) as i64 == 0 {
                        continue; // race: another publish landed.
                    }
                    return Err(SpmcRingRecvError::Closed);
                }
                return Ok(None);
            } else {
                // Another consumer raced; re-read head.
                pos = self.ring.head.0.load(Ordering::Relaxed);
            }
        }
    }

    pub fn recv(&self) -> SpmcRingRecvFuture<'_, T, N> {
        SpmcRingRecvFuture { consumer: self }
    }
}

#[derive(Debug)]
pub struct SpmcRingRecvFuture<'c, T: Send + 'static, const N: usize> {
    consumer: &'c SpmcRingConsumer<T, N>,
}

impl<T: Send + 'static, const N: usize> core::marker::Unpin for SpmcRingRecvFuture<'_, T, N> {}

impl<'c, T: Send + 'static, const N: usize> Future for SpmcRingRecvFuture<'c, T, N> {
    type Output = Result<T, SpmcRingRecvError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.consumer.try_recv() {
            Ok(Some(v)) => Poll::Ready(Ok(v)),
            Err(e) => Poll::Ready(Err(e)),
            Ok(None) => {
                *this.consumer.ring.consumer_waker.lock() = Some(cx.waker().clone());
                match this.consumer.try_recv() {
                    Ok(Some(v)) => {
                        *this.consumer.ring.consumer_waker.lock() = None;
                        Poll::Ready(Ok(v))
                    }
                    Err(e) => Poll::Ready(Err(e)),
                    Ok(None) => Poll::Pending,
                }
            }
        }
    }
}

/// Allocate a fresh ring and return a producer / consumer pair.
pub fn spmc_ring_channel<T: Send + 'static, const N: usize>(
) -> (SpmcRingProducer<T, N>, SpmcRingConsumer<T, N>) {
    let ring = Arc::new(SpmcRing::<T, N>::new());
    (
        SpmcRingProducer {
            ring: Arc::clone(&ring),
            _not_sync: PhantomData,
        },
        SpmcRingConsumer { ring },
    )
}
