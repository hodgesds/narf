//! Scatter-gather block requests (Linux `bio` with a `bio_vec` list, and
//! `bio_split_to_limits` against `queue_limits`).
//!
//! An [`SgRequest`] carries its payload as a `Cap<PageList, Read>`: the
//! caller's own pages, no bounce buffer. The block layer, not every
//! submitter, fits it to the device: [`split_to_limits`] cuts a request
//! that exceeds the queue's [`QueueLimits`] into conforming children on
//! block boundaries, issues them all at once and combines their
//! completions ([`SplitCompletion`]: the parent completes when every child
//! has, the first error wins). Only a request that can never conform — a
//! segment misaligned to the device's DMA alignment, a range outside the
//! device — is refused with [`BlockError::InvalidRange`].
//!
//! Dropping the parent's future requests cancellation of every outstanding
//! child (each child's drop abandons its command; resources release on the
//! terminal completion, AGENTS.md invariant 7).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use narf_capabilities::{Cap, Read};
use narf_io::sg::{PageList, Segment};

use crate::queue::{ready_completion, BoxedCompletion, QueueLimits};
use crate::{BlockCompletion, BlockError, BlockOp, QosHint};

/// A block request whose payload is a list of pages.
#[derive(Debug)]
pub struct SgRequest {
    pub op: BlockOp,
    pub lba: u64,
    pub blocks: u32,
    /// The pages; the payload is `offset .. offset + blocks * lba_size`
    /// bytes into the list.
    pub pages: Cap<PageList, Read>,
    pub offset: usize,
    pub qos: QosHint,
    pub user_tag: u64,
}

impl SgRequest {
    /// A request over the whole of `pages`' payload from its start.
    pub fn new(
        op: BlockOp,
        lba: u64,
        blocks: u32,
        pages: Cap<PageList, Read>,
        user_tag: u64,
    ) -> Self {
        Self {
            op,
            lba,
            blocks,
            pages,
            offset: 0,
            qos: QosHint::Throughput,
            user_tag,
        }
    }

    /// Resolve the page list (a revoked or stale cap resolves to `None`).
    pub fn resolve(&self) -> Option<Arc<PageList>> {
        narf_io::resolve_pages_cap(&self.pages)
    }

    /// The payload's segments as the device sees them, or `None` when the
    /// request runs past the page list.
    pub fn segments(&self, list: &PageList, lba_size: u32) -> Option<Vec<Segment>> {
        let bytes = (self.blocks as usize).checked_mul(lba_size as usize)?;
        list.segments_in(self.offset, bytes)
    }
}

/// Where a request stands against a queue's limits.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Fit {
    /// Issue as is.
    Fits,
    /// Split into children (`split_to_limits`).
    Split,
    /// Can never conform.
    Refused(BlockError),
}

/// Classify `segments` (a request of `blocks` logical blocks) against `l`.
pub fn fit(segments: &[Segment], blocks: u32, l: &QueueLimits) -> Fit {
    let align = l.dma_alignment.max(1) as u64;
    if segments.is_empty() {
        return Fit::Refused(BlockError::InvalidRange);
    }
    for s in segments {
        if s.dma % align != 0 || s.len as u64 % align != 0 || s.len == 0 {
            return Fit::Refused(BlockError::InvalidRange);
        }
    }
    let bytes = blocks as u64 * l.logical_block_size as u64;
    if bytes <= l.max_transfer_bytes as u64
        && segments.len() as u32 <= l.max_segments.max(1)
        && segments.iter().all(|s| s.len <= l.max_segment_bytes.max(1))
    {
        Fit::Fits
    } else {
        Fit::Split
    }
}

/// Cut the payload `offset .. offset + total` of `list` into child byte
/// ranges `(offset, len)` that each conform to `l` — at most
/// `max_transfer_bytes`, at most `max_segments` device segments, no segment
/// over `max_segment_bytes` — every child a whole number of
/// `logical_block_size` blocks (Linux `bio_split_rw`). Greedy, one block at
/// a time, so a child is cut exactly where the next block would break a
/// limit. `None` when one block alone breaks a limit (it can never fit).
pub fn child_ranges(
    list: &PageList,
    offset: usize,
    total: usize,
    l: &QueueLimits,
) -> Option<Vec<(usize, usize)>> {
    let lba = l.logical_block_size.max(1) as usize;
    let max_bytes = l.max_transfer_bytes as usize;
    let max_segs = l.max_segments.max(1) as usize;
    let max_seg_bytes = l.max_segment_bytes as usize;
    if total % lba != 0 || lba > max_bytes {
        return None;
    }
    let mut out = Vec::new();
    let mut start = offset;
    let mut bytes = 0usize; // bytes in the open child
    let mut segs: Vec<Segment> = Vec::new(); // the open child's segments
    let mut at = offset;
    let end = offset + total;
    while at < end {
        let block = list.segments_in(at, lba)?;
        // Merge the block's segments onto the child's tail.
        let mut trial = segs.clone();
        for s in &block {
            match trial.last_mut() {
                Some(t) if t.dma + t.len as u64 == s.dma => t.len += s.len,
                _ => trial.push(*s),
            }
        }
        let fits = bytes + lba <= max_bytes
            && trial.len() <= max_segs
            && trial.iter().all(|s| s.len as usize <= max_seg_bytes);
        if fits {
            segs = trial;
            bytes += lba;
            at += lba;
            continue;
        }
        if bytes == 0 {
            // This single block breaks a limit on its own.
            return None;
        }
        out.push((start, bytes));
        start = at;
        bytes = 0;
        segs.clear();
    }
    if bytes > 0 {
        out.push((start, bytes));
    }
    Some(out)
}

/// Submit `req` through `submit_one` (the queue's native scatter-gather
/// entry, which must accept any request that conforms to `l`), splitting
/// it into conforming children first when it does not (Linux
/// `__bio_split_to_limits`). `lba_size` is the device's logical block.
pub fn split_to_limits(
    req: SgRequest,
    l: &QueueLimits,
    submit_one: &dyn Fn(SgRequest) -> BoxedCompletion,
) -> BoxedCompletion {
    let user_tag = req.user_tag;
    let Some(list) = req.resolve() else {
        return ready_completion(user_tag, Err(BlockError::PermissionDenied));
    };
    let lba = l.logical_block_size.max(1);
    let Some(segments) = req.segments(&list, lba) else {
        return ready_completion(user_tag, Err(BlockError::InvalidRange));
    };
    match fit(&segments, req.blocks, l) {
        Fit::Refused(e) => ready_completion(user_tag, Err(e)),
        Fit::Fits => submit_one(req),
        Fit::Split => {
            let total = req.blocks as usize * lba as usize;
            let Some(ranges) = child_ranges(&list, req.offset, total, l) else {
                return ready_completion(user_tag, Err(BlockError::InvalidRange));
            };
            let mut children = Vec::with_capacity(ranges.len());
            let mut lba_at = req.lba;
            for (off, len) in ranges {
                let blocks = (len / lba as usize) as u32;
                let child = SgRequest {
                    op: req.op,
                    lba: lba_at,
                    blocks,
                    pages: req.pages,
                    offset: off,
                    qos: req.qos,
                    user_tag,
                };
                lba_at += blocks as u64;
                children.push(submit_one(child));
            }
            Box::pin(SplitCompletion {
                children,
                first_err: None,
                tag: 0,
                user_tag,
            })
        }
    }
}

/// The parent completion of a split request: pending until every child
/// completed; the first child error is the parent's result; dropping it
/// drops (cancels) the children still outstanding.
pub struct SplitCompletion {
    children: Vec<BoxedCompletion>,
    first_err: Option<BlockError>,
    tag: u64,
    user_tag: u64,
}

impl core::fmt::Debug for SplitCompletion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SplitCompletion")
            .field("outstanding", &self.children.len())
            .finish_non_exhaustive()
    }
}

impl Future for SplitCompletion {
    type Output = BlockCompletion;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<BlockCompletion> {
        let this = self.get_mut();
        let mut i = 0;
        while i < this.children.len() {
            match this.children[i].as_mut().poll(cx) {
                Poll::Pending => i += 1,
                Poll::Ready(c) => {
                    if this.tag == 0 {
                        this.tag = c.tag;
                    }
                    if let Err(e) = c.result {
                        this.first_err.get_or_insert(e);
                    }
                    drop(this.children.swap_remove(i));
                }
            }
        }
        if this.children.is_empty() {
            return Poll::Ready(BlockCompletion {
                tag: this.tag,
                user_tag: this.user_tag,
                result: match this.first_err {
                    Some(e) => Err(e),
                    None => Ok(()),
                },
            });
        }
        Poll::Pending
    }
}

/// Copy between a page list payload and a kernel slice: `to_pages` writes
/// `data` into the list at `offset`; otherwise reads from it. For
/// backends without scatter-gather DMA (RAM disk, `SyncBlock`).
pub fn copy_pages(list: &PageList, offset: usize, data: &mut [u8], to_pages: bool) -> bool {
    let page = narf_memory::PAGE_SIZE as usize;
    let mut at = offset;
    let mut done = 0usize;
    while done < data.len() {
        let i = at / page;
        let in_page = at % page;
        let take = (page - in_page).min(data.len() - done);
        let Some(p) = list.cpu_ptr(i) else {
            return false;
        };
        // SAFETY: the list's frames are the caller's live pages (kept
        // allocated for the list's lifetime); `in_page + take <= PAGE_SIZE`.
        unsafe {
            let p = p.add(in_page);
            if to_pages {
                core::ptr::copy_nonoverlapping(data.as_ptr().add(done), p, take);
            } else {
                core::ptr::copy_nonoverlapping(p, data.as_mut_ptr().add(done), take);
            }
        }
        at += take;
        done += take;
    }
    true
}
