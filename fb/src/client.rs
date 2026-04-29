//! `FbClient` — ergonomic producer wrapper for the DrawCmd ring.
//!
//! What a userspace process will eventually instantiate over an
//! mmap'd DrawRing page; today instantiated by kernel-resident
//! tasks that drive the ring through the same surface. The
//! implementation is cap-aware but the cap itself stays opaque to
//! the producer side — the consumer (kernel-side `drain`) is what
//! actually exercises the capability against the FbWriter.
//!
//! Kernel-resident producers + consumer share a single 4 KiB page;
//! once mmap-of-shared-region lands for userspace, the same code
//! works without modification — only the page-source changes.

use alloc::boxed::Box;

use narf_ipc::shared_ring::{
    SharedConsumer, SharedProducer, TrySendError,
};

use crate::cmd_ring::{self, DrawCmd, DrawRing, RING_DEPTH};
use crate::Rect;

/// Producer-side handle. Owns the SharedProducer half of a
/// DrawRing; the consumer half lives elsewhere (typically inside
/// the kernel-side drain task, eventually a compositor).
#[derive(Debug)]
pub struct FbClient {
    producer: SharedProducer<DrawCmd, RING_DEPTH>,
}

impl FbClient {
    /// Build a client over an existing producer. Use
    /// `allocate_singleton_ring` when the caller wants a fresh
    /// ring; this constructor is for callers that already split
    /// a ring elsewhere.
    pub fn new(producer: SharedProducer<DrawCmd, RING_DEPTH>) -> Self {
        Self { producer }
    }

    /// Enqueue a Fill command. Returns `Err(Full(_))` when the
    /// ring is at capacity; the caller is expected to retry after
    /// the consumer drains.
    pub fn fill(&mut self, rect: Rect, pixel: u32)
        -> Result<(), TrySendError<DrawCmd>>
    {
        self.producer.try_send(DrawCmd::fill(rect, pixel))
    }

    /// Enqueue a Flush.
    pub fn flush(&mut self, rect: Rect)
        -> Result<(), TrySendError<DrawCmd>>
    {
        self.producer.try_send(DrawCmd::flush(rect))
    }
}

/// Allocate a heap-backed DrawRing, init it in place, and split
/// into producer + consumer halves. The returned tuple includes
/// the boxed backing so the caller can keep it alive for the
/// ring's lifetime.
///
/// # Safety
/// SPSC contract — only one producer + consumer per ring.
pub unsafe fn allocate_singleton_ring()
    -> (
        Box<DrawRing>,
        SharedProducer<DrawCmd, RING_DEPTH>,
        SharedConsumer<DrawCmd, RING_DEPTH>,
    )
{
    // SAFETY: SharedRing is repr(C) of u32 atomics + a slot array;
    // zero-init is the canonical "fresh ring" state.
    let mut ring: Box<DrawRing> = Box::new(unsafe { core::mem::zeroed() });
    let ptr: *mut DrawRing = &mut *ring;
    // SAFETY: ptr points at a fresh, zero-initialised DrawRing
    // sized for SharedRing<DrawCmd, 16>.
    unsafe { cmd_ring::init_in(ptr); }
    // SAFETY: SPSC invariant — caller asserts no other halves
    // exist for this ring.
    let (p, c) = unsafe { cmd_ring::split(ptr) };
    (ring, p, c)
}
