//! Block I/O on one member device, straight from the caller's pages (Linux
//! `btrfs_submit_bio` → `btrfs_map_bio`: one bio per stripe, its payload the
//! caller's own pages).
//!
//! A read or write builds a page list over its destination or source buffer
//! and submits it as ONE scatter-gather request; the block layer splits it to
//! the device's limits and the device has it in flight beside every other
//! task's. Nothing is held across the round trip and there is no shared
//! scratch buffer, so concurrency is bounded by the device's queue, not by
//! the volume. (The previous design serialised every read, exec and page
//! fault on a volume behind one 64 KiB coherent buffer per member.)
//!
//! A buffer the device cannot take in place goes through a *bounce* of
//! order-0 frames owned by the page list: one outside the kernel direct map
//! (a vmalloc fallback, a hosted build), a range that starts or ends inside a
//! device block (read-modify-write), a segment the device refuses, or a wait
//! the caller may abandon on SIGKILL — the frames then outlive the dropped
//! waiter exactly as a bio's page references do, because the device keeps
//! the list until the command's terminal completion.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use narf_block::{BlockDevice, BlockError, BlockOp, QosHint, SgRequest};
use narf_capabilities::{Cap, Read, Write};
use narf_filesystem::FsError;
use narf_io::sg::PageList;
use narf_io::{register_pages_with_cap, resolve_pages_cap, unregister_pages};
use narf_lib::id::DomainId;
use narf_memory::{PhysAddr, PhysFrame, PAGE_SIZE};

/// The whole device blocks a byte range touches.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Run {
    /// First block.
    pub lba: u64,
    /// Blocks in the run.
    pub blocks: u32,
    /// Bytes of the first block before the range starts.
    pub head: usize,
    /// Bytes in the run (`blocks * block_size`).
    pub bytes: usize,
}

impl Run {
    /// The range starts and ends on block boundaries.
    pub fn aligned(&self, len: usize) -> bool {
        self.head == 0 && self.bytes == len
    }
}

/// The run of `block_size`-byte blocks covering `offset .. offset + len`.
/// Pure: the unit of the request-shape tests.
pub(crate) fn run_of(offset: u64, len: usize, block_size: usize) -> Result<Run, FsError> {
    let bs = block_size as u64;
    let lba = offset / bs;
    let head = (offset % bs) as usize;
    let blocks = (head + len).div_ceil(block_size);
    Ok(Run {
        lba,
        blocks: u32::try_from(blocks).map_err(|_| FsError::InvalidData)?,
        head,
        bytes: blocks * block_size,
    })
}

/// Order-0 frames of a bounce payload, freed when the list naming them
/// drops (after the last command over them completed).
struct BounceFrames(Vec<PhysFrame>);

impl Drop for BounceFrames {
    fn drop(&mut self) {
        for frame in self.0.drain(..) {
            narf_memory::free_frame(frame);
        }
    }
}

/// A registered page list: its cap, revoked on drop (the object-table index
/// is released for reuse under a greater generation, so a copy of the cap a
/// device still holds can never resolve to a later payload). The list
/// itself (and any bounce frames it owns) goes when the device drops its
/// last reference.
struct Registered {
    cap: Cap<PageList, Write>,
}

impl Registered {
    fn new(list: PageList) -> Self {
        Self {
            cap: register_pages_with_cap(list),
        }
    }

    fn request(&self, op: BlockOp, run: &Run, offset: usize) -> Result<SgRequest, BlockError> {
        let pages = self
            .cap
            .derive::<Read>()
            .map_err(|_| BlockError::PermissionDenied)?;
        Ok(SgRequest {
            op,
            lba: run.lba,
            blocks: run.blocks,
            pages,
            offset,
            qos: QosHint::Latency,
            user_tag: 0,
        })
    }

    fn list(&self) -> Result<Arc<PageList>, FsError> {
        resolve_pages_cap(&self.cap).ok_or(FsError::Io(BlockError::PermissionDenied))
    }

    /// Copy the list's payload at `offset` out into `dst`.
    fn copy_out(&self, offset: usize, dst: &mut [u8]) -> Result<(), FsError> {
        let list = self.list()?;
        if narf_block::sg::copy_pages(&list, offset, dst, false) {
            Ok(())
        } else {
            Err(FsError::Io(BlockError::InvalidRange))
        }
    }

    /// Copy `src` into the list's payload at `offset`.
    fn copy_in(&self, offset: usize, src: &[u8]) -> Result<(), FsError> {
        let list = self.list()?;
        let page = PAGE_SIZE as usize;
        let mut at = offset;
        let mut done = 0usize;
        while done < src.len() {
            let in_page = at % page;
            let take = (page - in_page).min(src.len() - done);
            let p = list
                .cpu_ptr(at / page)
                .ok_or(FsError::Io(BlockError::InvalidRange))?;
            // SAFETY: the list's frames are live (owned by it or by the
            // caller's buffer for the call); `in_page + take <= PAGE_SIZE`.
            unsafe {
                core::ptr::copy_nonoverlapping(src.as_ptr().add(done), p.add(in_page), take);
            }
            at += take;
            done += take;
        }
        Ok(())
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        unregister_pages(self.cap);
    }
}

/// The frames behind `buf` when a device can reach it in place: every byte
/// inside the kernel direct map, where `PhysAddr::from_kernel_ptr` is exact
/// for every page. Returns the page-aligned frames and the byte offset of
/// `buf` in the first. `None` for a buffer the map does not cover — a
/// vmalloc fallback (physically scattered behind its VA), the kernel image,
/// a hosted build — which then bounces.
fn direct_frames(buf: &[u8]) -> Option<(Vec<PhysAddr>, usize)> {
    if !narf_memory::direct_map_live() {
        return None;
    }
    let base = narf_memory::direct_map_base();
    let start = buf.as_ptr() as u64;
    let end = start.checked_add(buf.len() as u64)?;
    if start < base || end - base > narf_memory::direct_map_phys_end() {
        return None;
    }
    if narf_memory::vmalloc::is_valloc_ptr(buf.as_ptr()) {
        return None;
    }
    let page = PAGE_SIZE as usize;
    let first = PhysAddr::from_kernel_ptr(buf.as_ptr()).raw();
    let in_page = (first % PAGE_SIZE) as usize;
    let pages = (in_page + buf.len()).div_ceil(page);
    let first_page = first - in_page as u64;
    let frames = (0..pages as u64)
        .map(|i| PhysAddr::new(first_page + i * PAGE_SIZE))
        .collect();
    Some((frames, in_page))
}

/// A page list over `buf` in place, or `None` when it must bounce.
fn direct_list(buf: &[u8], domain: DomainId) -> Option<(Registered, usize)> {
    let (frames, in_page) = direct_frames(buf)?;
    let list = PageList::new(frames, in_page + buf.len(), domain).ok()?;
    Some((Registered::new(list), in_page))
}

/// A bounce list of `bytes` bytes over fresh order-0 frames the list owns.
fn bounce_list(bytes: usize, domain: DomainId) -> Result<Registered, FsError> {
    let page = PAGE_SIZE as usize;
    let mut frames = BounceFrames(Vec::with_capacity(bytes.div_ceil(page)));
    for _ in 0..bytes.div_ceil(page) {
        frames
            .0
            .push(narf_memory::alloc_frame().map_err(|_| FsError::OutOfMemory)?);
    }
    let pages = frames.0.iter().map(|f| f.start_address()).collect();
    let list = PageList::new(pages, bytes, domain)
        .map_err(|_| FsError::OutOfMemory)?
        .with_owner(Box::new(frames));
    Ok(Registered::new(list))
}

/// Submit one request and wait for its completion.
async fn submit<B: BlockDevice>(
    device: &B,
    reg: &Registered,
    op: BlockOp,
    run: &Run,
    offset: usize,
) -> Result<(), BlockError> {
    let req = reg.request(op, run, offset)?;
    device.submit_sg(req).await.result
}

/// Test-only: while set, every submission waits (a device that does not
/// answer), so a test can observe who waits on I/O and how.
#[cfg(feature = "kernel-test")]
pub(crate) static IO_GATE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

async fn gate() {
    #[cfg(feature = "kernel-test")]
    while IO_GATE.load(core::sync::atomic::Ordering::Acquire) {
        narf_time::sleep_ms(1).await;
    }
}

/// Read `dst.len()` bytes at device byte offset `offset` (`limit` the
/// device's size). Straight into `dst` when the device can reach it and the
/// wait cannot be abandoned; through a bounce otherwise. A killable wait is
/// a plain reader's (outside any operation or commit): sent SIGKILL it
/// returns `Interrupted` at once, the command completing into frames the
/// page list owns.
pub(crate) async fn read_exact_from<B: BlockDevice>(
    device: &B,
    block_size: usize,
    domain: DomainId,
    limit: u64,
    offset: u64,
    dst: &mut [u8],
    killable: bool,
) -> Result<(), FsError> {
    let end = offset
        .checked_add(dst.len() as u64)
        .ok_or(FsError::InvalidData)?;
    if end > limit {
        return Err(FsError::InvalidData);
    }
    if dst.is_empty() {
        return Ok(());
    }
    gate().await;
    let run = run_of(offset, dst.len(), block_size)?;
    if !killable && run.aligned(dst.len()) {
        if let Some((reg, in_page)) = direct_list(dst, domain) {
            match submit(device, &reg, BlockOp::Read, &run, in_page).await {
                Ok(()) => return Ok(()),
                // A segment the device cannot take (its DMA alignment): the
                // bounce below is page aligned.
                Err(BlockError::InvalidRange) => {}
                Err(e) => return Err(FsError::Io(e)),
            }
        }
    }
    let reg = bounce_list(run.bytes, domain)?;
    let io = submit(device, &reg, BlockOp::Read, &run, 0);
    let result = if killable {
        crate::volume::killable(io).await?
    } else {
        io.await
    };
    result.map_err(FsError::Io)?;
    reg.copy_out(run.head, dst)
}

/// Write `src` at device byte offset `offset`: one request straight from
/// `src` (or a bounce of it) when the range is block aligned — a superblock
/// copy or a tree node is therefore a single request whatever the device's
/// logical block size, and the FUA primary superblock can never be torn into
/// per-block writes. A range that starts or ends inside a block is
/// read-modify-written under `rmw`, which serialises only such runs.
pub(crate) async fn write_exact_to<B: BlockDevice>(
    device: &B,
    block_size: usize,
    domain: DomainId,
    rmw: &narf_lib::mutex::Mutex<()>,
    limit: u64,
    offset: u64,
    src: &[u8],
    fua: bool,
) -> Result<(), FsError> {
    let end = offset
        .checked_add(src.len() as u64)
        .ok_or(FsError::InvalidData)?;
    if end > limit {
        return Err(FsError::InvalidData);
    }
    if src.is_empty() {
        return Ok(());
    }
    gate().await;
    let run = run_of(offset, src.len(), block_size)?;
    let op = BlockOp::Write { fua };
    if run.aligned(src.len()) {
        if let Some((reg, in_page)) = direct_list(src, domain) {
            match submit(device, &reg, op, &run, in_page).await {
                Ok(()) => return Ok(()),
                Err(BlockError::InvalidRange) => {}
                Err(e) => return Err(FsError::Io(e)),
            }
        }
        let reg = bounce_list(run.bytes, domain)?;
        reg.copy_in(0, src)?;
        return submit(device, &reg, op, &run, 0).await.map_err(FsError::Io);
    }
    let _rmw = rmw.lock().await;
    let reg = bounce_list(run.bytes, domain)?;
    submit(device, &reg, BlockOp::Read, &run, 0)
        .await
        .map_err(FsError::Io)?;
    reg.copy_in(run.head, src)?;
    submit(device, &reg, op, &run, 0).await.map_err(FsError::Io)
}

/// A boxed I/O future of a join.
pub(crate) type IoFut<'a> = Pin<Box<dyn Future<Output = Result<(), FsError>> + Send + 'a>>;

/// Run `pending` together — at most `window` started at once — and wait for
/// EVERY one of them even after a failure: a request still in flight reads
/// or writes the caller's pages, so none may be abandoned. The first error
/// is the result.
pub(crate) fn join_all(pending: Vec<IoFut<'_>>, window: usize) -> JoinAll<'_> {
    JoinAll {
        pending,
        running: Vec::new(),
        window: window.max(1),
        first_err: None,
    }
}

/// See [`join_all`].
pub(crate) struct JoinAll<'a> {
    pending: Vec<IoFut<'a>>,
    running: Vec<IoFut<'a>>,
    window: usize,
    first_err: Option<FsError>,
}

impl Future for JoinAll<'_> {
    type Output = Result<(), FsError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            while this.running.len() < this.window {
                match this.pending.pop() {
                    Some(f) => this.running.push(f),
                    None => break,
                }
            }
            let before = this.running.len();
            let mut i = 0;
            while i < this.running.len() {
                match this.running[i].as_mut().poll(cx) {
                    Poll::Pending => i += 1,
                    Poll::Ready(r) => {
                        if let Err(e) = r {
                            this.first_err.get_or_insert(e);
                        }
                        drop(this.running.swap_remove(i));
                    }
                }
            }
            if this.running.is_empty() && this.pending.is_empty() {
                return Poll::Ready(match this.first_err.take() {
                    Some(e) => Err(e),
                    None => Ok(()),
                });
            }
            // Something finished and a slot opened: start the next before
            // sleeping, so the window stays full.
            if this.running.len() == before || this.pending.is_empty() {
                return Poll::Pending;
            }
        }
    }
}

/// How many of a commit's writes may be started at once. The device's queue
/// bounds what is in flight (a full tag set parks the next submission); this
/// bounds the bounce memory and the futures a huge commit would otherwise
/// build all at once.
pub(crate) const WRITE_WINDOW: usize = 256;
