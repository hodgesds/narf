//! Multi-producer / single-consumer lock-free ring.
//!
//! Algorithm: Dmitry Vyukov's bounded MPMC/MPSC ring, specialised
//! here to one consumer.
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
//! tail, consumer head, and the slot array each sit on their own
//! 64-byte cache line via `Align64`. Each slot carries a per-slot
//! `AtomicU64` sequence counter that doubles as the publish flag —
//! producers CAS-claim a slot whose `seq == pos`, then store
//! `seq = pos + 1` to publish; the consumer reads a slot whose
//! `seq == pos + 1`, takes the value, then stores `seq = pos + N`
//! to mark the slot reusable on the next wrap.

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

/// Bounded MPSC ring. `N` must be a non-zero power of two.
#[repr(C)]
pub struct MpscRing<T, const N: usize> {
    /// Producer-shared tail (the next slot to claim).
    tail: Align64<AtomicU64>,
    /// Consumer-owned head (the next slot to drain).
    head: Align64<AtomicU64>,
    /// Number of live producers; consumer treats `producers == 0`
    /// as drained-then-EOF.
    producers: AtomicUsize,
    /// Latches when the consumer drops.
    consumer_gone: AtomicBool,
    /// Consumer parks here when empty.
    consumer_waker: IrqSafeSpinLock<Option<Waker>>,
    /// Any producer parks here when full; first-waker-wins.
    producer_waker: IrqSafeSpinLock<Option<Waker>>,
    slots: Align64<UnsafeCell<[Slot<T>; N]>>,
}

impl<T, const N: usize> core::fmt::Debug for MpscRing<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MpscRing")
            .field("capacity", &N)
            .field("tail", &self.tail.0.load(Ordering::Relaxed))
            .field("head", &self.head.0.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

unsafe impl<T: Send, const N: usize> Send for MpscRing<T, N> {}
unsafe impl<T: Send, const N: usize> Sync for MpscRing<T, N> {}

impl<T, const N: usize> MpscRing<T, N> {
    const POW2_GUARD: () = assert!(
        N > 0 && (N & (N - 1)) == 0,
        "MpscRing capacity must be a non-zero power of two",
    );
    const MASK: u64 = (N as u64) - 1;

    fn new() -> Self {
        let _ = Self::POW2_GUARD;
        // SAFETY: MaybeUninit array does not require initialisation;
        // each slot's `seq` is then explicitly set to its index so
        // producer CAS sees the expected ready-for-pos-0 invariant.
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
            producers: AtomicUsize::new(1),
            consumer_gone: AtomicBool::new(false),
            consumer_waker: IrqSafeSpinLock::new(None),
            producer_waker: IrqSafeSpinLock::new(None),
            slots: Align64(UnsafeCell::new(slots)),
        }
    }
}

impl<T, const N: usize> Drop for MpscRing<T, N> {
    fn drop(&mut self) {
        let head = *self.head.0.get_mut();
        let tail = *self.tail.0.get_mut();
        let slots = unsafe { &mut *self.slots.0.get() };
        let mut i = head;
        while i != tail {
            let idx = (i & Self::MASK) as usize;
            let slot = &mut slots[idx];
            if *slot.seq.get_mut() == i + 1 {
                // SAFETY: producer published slot at sequence `i + 1`;
                // consumer never claimed it. Payload is live.
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
pub enum MpscRingSendError<T> {
    Full(T),
    Closed(T),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MpscRingRecvError {
    Closed,
}

/// Producer handle — `Clone` so N tasks can share. `Send + Sync`.
pub struct MpscRingProducer<T: Send + 'static, const N: usize> {
    ring: Arc<MpscRing<T, N>>,
}

impl<T: Send + 'static, const N: usize> core::fmt::Debug for MpscRingProducer<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MpscRingProducer")
            .field("ring", &*self.ring)
            .finish_non_exhaustive()
    }
}

impl<T: Send + 'static, const N: usize> Clone for MpscRingProducer<T, N> {
    fn clone(&self) -> Self {
        self.ring.producers.fetch_add(1, Ordering::Relaxed);
        Self {
            ring: Arc::clone(&self.ring),
        }
    }
}

impl<T: Send + 'static, const N: usize> Drop for MpscRingProducer<T, N> {
    fn drop(&mut self) {
        if self.ring.producers.fetch_sub(1, Ordering::AcqRel) == 1 {
            if let Some(w) = self.ring.consumer_waker.lock().take() {
                w.wake();
            }
        }
    }
}

impl<T: Send + 'static, const N: usize> MpscRingProducer<T, N> {
    /// Non-blocking send. CAS-claims the next slot; returns the
    /// payload back on `Full` / `Closed`.
    pub fn try_send(&self, msg: T) -> Result<(), MpscRingSendError<T>> {
        if self.ring.consumer_gone.load(Ordering::Acquire) {
            return Err(MpscRingSendError::Closed(msg));
        }
        let mut pos = self.ring.tail.0.load(Ordering::Relaxed);
        let slot_ptr = self.ring.slots.0.get();
        loop {
            // SAFETY: slots array lives for the ring's lifetime; we
            // only touch `seq` (atomic) and, after a successful CAS,
            // our own slot's value cell.
            let slot = unsafe { &(*slot_ptr)[(pos & MpscRing::<T, N>::MASK) as usize] };
            let seq = slot.seq.load(Ordering::Acquire);
            let diff = seq.wrapping_sub(pos) as i64;
            if diff == 0 {
                match self.ring.tail.0.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // SAFETY: we own this slot until we publish.
                        unsafe {
                            (*slot.val.get()).write(msg);
                        }
                        // Release: pairs with the consumer's Acquire
                        // on `seq` — makes payload visible before
                        // the consumer observes the new sequence.
                        slot.seq.store(pos.wrapping_add(1), Ordering::Release);
                        if let Some(w) = self.ring.consumer_waker.lock().take() {
                            w.wake();
                        }
                        return Ok(());
                    }
                    Err(observed) => {
                        pos = observed;
                        continue;
                    }
                }
            } else if diff < 0 {
                // Slot still holds an unread value — ring is full.
                return Err(MpscRingSendError::Full(msg));
            } else {
                // Another producer raced ahead; re-read tail.
                pos = self.ring.tail.0.load(Ordering::Relaxed);
            }
        }
    }

    pub fn send(&self, msg: T) -> MpscRingSendFuture<'_, T, N> {
        MpscRingSendFuture {
            producer: self,
            slot: Some(msg),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.ring.consumer_gone.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct MpscRingSendFuture<'p, T: Send + 'static, const N: usize> {
    producer: &'p MpscRingProducer<T, N>,
    slot: Option<T>,
}

impl<T: Send + 'static, const N: usize> core::marker::Unpin for MpscRingSendFuture<'_, T, N> {}

impl<'p, T: Send + 'static, const N: usize> Future for MpscRingSendFuture<'p, T, N> {
    type Output = Result<(), T>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let msg = this.slot.take().expect("send future polled after completion");
        match this.producer.try_send(msg) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(MpscRingSendError::Closed(m)) => Poll::Ready(Err(m)),
            Err(MpscRingSendError::Full(m)) => {
                *this.producer.ring.producer_waker.lock() = Some(cx.waker().clone());
                match this.producer.try_send(m) {
                    Ok(()) => {
                        *this.producer.ring.producer_waker.lock() = None;
                        Poll::Ready(Ok(()))
                    }
                    Err(MpscRingSendError::Closed(m)) => Poll::Ready(Err(m)),
                    Err(MpscRingSendError::Full(m)) => {
                        this.slot = Some(m);
                        Poll::Pending
                    }
                }
            }
        }
    }
}

/// Consumer handle — single-owner.
pub struct MpscRingConsumer<T: Send + 'static, const N: usize> {
    ring: Arc<MpscRing<T, N>>,
    _not_sync: PhantomData<*const ()>,
}

unsafe impl<T: Send + 'static, const N: usize> Send for MpscRingConsumer<T, N> {}

impl<T: Send + 'static, const N: usize> core::fmt::Debug for MpscRingConsumer<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MpscRingConsumer")
            .field("ring", &*self.ring)
            .finish_non_exhaustive()
    }
}

impl<T: Send + 'static, const N: usize> MpscRingConsumer<T, N> {
    pub fn try_recv(&mut self) -> Result<Option<T>, MpscRingRecvError> {
        let pos = self.ring.head.0.load(Ordering::Relaxed);
        let slot_ptr = self.ring.slots.0.get();
        // SAFETY: slot array lives for the ring's lifetime.
        let slot = unsafe { &(*slot_ptr)[(pos & MpscRing::<T, N>::MASK) as usize] };
        let seq = slot.seq.load(Ordering::Acquire);
        let diff = seq.wrapping_sub(pos.wrapping_add(1)) as i64;
        if diff == 0 {
            // SAFETY: producer published payload before its
            // release-store of `seq`; we have the matching acquire.
            let msg = unsafe {
                let v = core::mem::replace(&mut *slot.val.get(), MaybeUninit::uninit());
                v.assume_init()
            };
            self.ring
                .head
                .0
                .store(pos.wrapping_add(1), Ordering::Relaxed);
            // Release: pairs with the producer's Acquire load on
            // `seq` for the same slot once wrap arrives at it again.
            slot.seq
                .store(pos.wrapping_add(N as u64), Ordering::Release);
            if let Some(w) = self.ring.producer_waker.lock().take() {
                w.wake();
            }
            Ok(Some(msg))
        } else if self.ring.producers.load(Ordering::Acquire) == 0 {
            // Re-check the slot after observing zero producers —
            // covers the race where the last producer published
            // between our slot load and the producer-count load.
            let seq2 = slot.seq.load(Ordering::Acquire);
            if seq2.wrapping_sub(pos.wrapping_add(1)) as i64 == 0 {
                Ok(None)
            } else {
                Err(MpscRingRecvError::Closed)
            }
        } else {
            Ok(None)
        }
    }

    pub fn recv(&mut self) -> MpscRingRecvFuture<'_, T, N> {
        MpscRingRecvFuture { consumer: self }
    }
}

impl<T: Send + 'static, const N: usize> Drop for MpscRingConsumer<T, N> {
    fn drop(&mut self) {
        self.ring.consumer_gone.store(true, Ordering::Release);
        if let Some(w) = self.ring.producer_waker.lock().take() {
            w.wake();
        }
    }
}

#[derive(Debug)]
pub struct MpscRingRecvFuture<'c, T: Send + 'static, const N: usize> {
    consumer: &'c mut MpscRingConsumer<T, N>,
}

impl<T: Send + 'static, const N: usize> core::marker::Unpin for MpscRingRecvFuture<'_, T, N> {}

impl<'c, T: Send + 'static, const N: usize> Future for MpscRingRecvFuture<'c, T, N> {
    type Output = Result<T, MpscRingRecvError>;
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
pub fn mpsc_ring_channel<T: Send + 'static, const N: usize>(
) -> (MpscRingProducer<T, N>, MpscRingConsumer<T, N>) {
    let ring = Arc::new(MpscRing::<T, N>::new());
    (
        MpscRingProducer {
            ring: Arc::clone(&ring),
        },
        MpscRingConsumer {
            ring,
            _not_sync: PhantomData,
        },
    )
}
