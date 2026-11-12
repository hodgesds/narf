//! Asynchronous submission queues behind registry devices (Linux blk-mq's
//! `request_queue` + `queue_limits`, reduced to what a driver must expose).
//!
//! A [`crate::BlockDeviceSync`] device is what the registry holds, and the
//! [`crate::SyncBlock`] adapter is how filesystems reach it as an async
//! [`crate::BlockDevice`]. Without this module every `SyncBlock::submit`
//! performs the transfer synchronously inside `submit` itself and hands back
//! an already-complete future: one request per device at a time, the
//! submitting CPU held for the device round trip. A driver with a real
//! queued data path (NVMe I/O queues, a virtqueue with many descriptors in
//! flight) publishes a [`BlockQueue`] through
//! [`crate::BlockDeviceSync::queue`]; `SyncBlock` then submits through it and
//! returns a *pending* future, so N callers have N commands at the device.
//!
//! The trait is object-safe (boxed futures) because registry devices are
//! `Arc<dyn BlockDeviceSync>`; wrappers that window (partitions) or gate
//! (disk policy) a device forward the queue through [`OffsetQueue`] and
//! their own guard so every layer keeps its contract on the async path too.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::{BlockCompletion, BlockError, BlockOp, BlockRequest, CancelResult};

/// Boxed completion future of one request.
pub type BoxedCompletion = Pin<Box<dyn Future<Output = BlockCompletion> + Send + 'static>>;
/// Boxed future of a queue-wide operation (flush).
pub type BoxedResult = Pin<Box<dyn Future<Output = Result<(), BlockError>> + Send + 'static>>;
/// Boxed future of a cancellation.
pub type BoxedCancel = Pin<Box<dyn Future<Output = CancelResult> + Send + 'static>>;

/// What one request may ask of the queue (Linux `struct queue_limits`,
/// the fields a submitter must respect). A request outside these limits is
/// refused with [`BlockError::InvalidRange`] rather than silently split.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QueueLimits {
    /// Logical block size in bytes.
    pub logical_block_size: u32,
    /// Largest transfer one request may carry, in bytes
    /// (`max_hw_sectors_kb`): NVMe MDTS, a virtqueue's descriptor budget.
    pub max_transfer_bytes: u32,
    /// Most scatter-gather segments one request may carry
    /// (`max_segments`). 1 for a device that takes one contiguous buffer.
    pub max_segments: u32,
    /// Largest single segment in bytes (`max_segment_size`).
    pub max_segment_bytes: u32,
    /// Required alignment of every segment's device address and length
    /// (`dma_alignment + 1`): 4 for NVMe PRPs, 1 for virtio.
    pub dma_alignment: u32,
    /// Requests the queue set can hold at once (`nr_requests` — the sum
    /// of the hardware queues' tags).
    pub queue_depth: u32,
    /// Hardware queues behind the device (`nr_hw_queues`).
    pub nr_queues: u32,
}

/// An asynchronous submission queue set (blk-mq hardware queues) a registry
/// device exposes. Every method is non-blocking at the call: the returned
/// future carries the wait.
///
/// Contract (shared with [`crate::BlockDevice`]): a future that returns
/// `Poll::Pending` registers the supplied waker with the state that can make
/// progress and is woken by the completion, the device's removal or reset,
/// or released queue capacity. Dropping a submission future before it
/// resolves *requests* cancellation; the request's resources (tag, DMA
/// mappings, descriptor memory) are released only on its terminal
/// completion, never by the drop (AGENTS.md invariant 7).
pub trait BlockQueue: Send + Sync {
    /// The queue's limits.
    fn limits(&self) -> QueueLimits;
    /// Submit `req`; the future resolves with its completion.
    fn submit(&self, req: BlockRequest) -> BoxedCompletion;
    /// Drain the device's volatile write cache (Linux `REQ_PREFLUSH`).
    fn flush(&self) -> BoxedResult;
    /// Cancel the in-flight request carrying kernel tag `tag`.
    fn cancel(&self, tag: u64) -> BoxedCancel;
    /// Requests currently at the device (diagnostic; the queued-submission
    /// smokes assert it exceeds one under concurrent submitters).
    fn in_flight(&self) -> usize;
}

/// A window `[start, start + len)` LBAs onto `inner`, for partitions.
/// Requests are range-checked against the window and shifted; everything
/// else forwards.
pub struct OffsetQueue {
    inner: Arc<dyn BlockQueue>,
    start: u64,
    len: u64,
}

impl core::fmt::Debug for OffsetQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OffsetQueue")
            .field("start", &self.start)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl OffsetQueue {
    pub fn new(inner: Arc<dyn BlockQueue>, start: u64, len: u64) -> Arc<Self> {
        Arc::new(Self { inner, start, len })
    }
}

/// An already-known completion, for a request refused before dispatch.
pub fn ready_completion(user_tag: u64, result: Result<(), BlockError>) -> BoxedCompletion {
    Box::pin(core::future::ready(BlockCompletion {
        tag: 0,
        user_tag,
        result,
    }))
}

impl BlockQueue for OffsetQueue {
    fn limits(&self) -> QueueLimits {
        self.inner.limits()
    }
    fn submit(&self, mut req: BlockRequest) -> BoxedCompletion {
        let end = req.lba.checked_add(req.blocks as u64);
        if end.is_none_or(|end| end > self.len) {
            return ready_completion(req.user_tag, Err(BlockError::InvalidRange));
        }
        req.lba += self.start;
        self.inner.submit(req)
    }
    fn flush(&self) -> BoxedResult {
        self.inner.flush()
    }
    fn cancel(&self, tag: u64) -> BoxedCancel {
        self.inner.cancel(tag)
    }
    fn in_flight(&self) -> usize {
        self.inner.in_flight()
    }
}

/// Whether `op` changes media contents (a policy guard refuses these on a
/// read-only device; a flush does not count — it drains a cache).
pub fn op_writes(op: BlockOp) -> bool {
    matches!(
        op,
        BlockOp::Write { .. } | BlockOp::WriteZeroes | BlockOp::Trim
    )
}

/// The future [`crate::SyncBlock::submit`] returns: either a completion
/// computed synchronously (the device has no queue, or the request was
/// refused before dispatch) or a queued submission still in flight.
pub enum SyncSubmit {
    Ready(Option<BlockCompletion>),
    Queued(BoxedCompletion),
}

impl core::fmt::Debug for SyncSubmit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SyncSubmit::Ready(c) => f.debug_tuple("Ready").field(c).finish(),
            SyncSubmit::Queued(_) => f.debug_tuple("Queued").finish_non_exhaustive(),
        }
    }
}

impl Future for SyncSubmit {
    type Output = BlockCompletion;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<BlockCompletion> {
        // SAFETY: `Ready` holds only `Unpin` data and `Queued` holds a pinned
        // box that is polled in place; neither variant is moved out of the
        // pinned enum.
        let this = unsafe { self.get_unchecked_mut() };
        match this {
            SyncSubmit::Ready(c) => Poll::Ready(c.take().expect("SyncSubmit polled after Ready")),
            SyncSubmit::Queued(f) => f.as_mut().poll(cx),
        }
    }
}

/// The future [`crate::SyncBlock::flush_result`] returns.
pub enum SyncFlush {
    Ready(Option<Result<(), BlockError>>),
    Queued(BoxedResult),
}

impl core::fmt::Debug for SyncFlush {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SyncFlush::Ready(c) => f.debug_tuple("Ready").field(c).finish(),
            SyncFlush::Queued(_) => f.debug_tuple("Queued").finish_non_exhaustive(),
        }
    }
}

impl Future for SyncFlush {
    type Output = Result<(), BlockError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: as for `SyncSubmit`.
        let this = unsafe { self.get_unchecked_mut() };
        match this {
            SyncFlush::Ready(c) => Poll::Ready(c.take().expect("SyncFlush polled after Ready")),
            SyncFlush::Queued(f) => f.as_mut().poll(cx),
        }
    }
}
