//! The gate-free block request path (Linux `nvme_queue_rq` and what blk-mq
//! wraps around it): a [`NvmeRequest`] future per block request, posted on
//! the submitting CPU's [`IoQueue`] without taking the controller's
//! request gate, awaiting its own completion while any number of other
//! requests are at the device.
//!
//! What the future needs of the controller — its queues and namespace
//! geometry — is an immutable snapshot ([`IoPath`]) the gate holder
//! publishes whenever either changes ([`super::ControllerGuard`]'s drop);
//! the future clones the `Arc` and never touches the controller itself.
//! The gate is taken only on the slow paths: a command timeout (the
//! controller is reset and the request replayed, as `run_with_replay`
//! does for the sync wrappers) and a controller found dead or mid-reset
//! at submission.
//!
//! A request longer than the controller's maximum transfer is issued as a
//! sequence of commands, one in flight at a time, as the Linux block layer
//! splits a bio at `max_hw_sectors`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{compiler_fence, Ordering};
use core::task::{Context, Poll};

use narf_block::{
    BlockCompletion, BlockError, BlockOp, BlockQueue, BlockRequest, BoxedCancel, BoxedCompletion,
    BoxedResult, CancelResult, QueueLimits,
};
use narf_io::DmaBuffer;

use super::mq::{Cmd, CmdId, CmdOutcome, CmdResources, IoQueue, STATUS_COMMAND_ABORT_REQUESTED};
use super::ns::NamespaceInfo;
use super::{prp, IoOpcode, NvmeError, Sqe};

/// The gate-free data path's view of one controller.
pub struct IoPath {
    pub queues: Vec<Arc<IoQueue>>,
    pub namespaces: Vec<NamespaceInfo>,
    pub primary_nsid: u32,
    pub max_transfer: u32,
    /// Identify Controller VWC: a Flush is a real command.
    pub vwc: bool,
    /// BAR0 physical address, for log lines.
    pub bar: u64,
}

impl core::fmt::Debug for IoPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoPath")
            .field("queues", &self.queues.len())
            .field("namespaces", &self.namespaces.len())
            .finish_non_exhaustive()
    }
}

impl IoPath {
    pub fn ns(&self, nsid: u32) -> Option<NamespaceInfo> {
        self.namespaces.iter().copied().find(|n| n.nsid == nsid)
    }
    pub fn in_flight(&self) -> usize {
        self.queues.iter().map(|q| q.in_flight()).sum()
    }
}

/// The queue the submitting CPU uses (Linux `blk_mq_map_queue`: CPU →
/// hardware queue, modulo when there are fewer queues than CPUs).
pub fn pick_queue(queues: &[Arc<IoQueue>]) -> Option<&Arc<IoQueue>> {
    if queues.is_empty() {
        return None;
    }
    let cpu = narf_lib::percpu::current_cpu();
    queues.get(cpu % queues.len())
}

/// Validate an NVM Read/Write of `n_blocks` at `lba` against `ns` and
/// `max_transfer`, and build its SQE with PRPs for the physically
/// contiguous range `dma .. dma + len` (Linux `nvme_setup_rw` +
/// `nvme_pci_setup_data_prp`). A transfer longer than two pages takes a
/// PRP-list page from `q`; it and `hold` travel in the command's resources.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_rw_sqe(
    q: &IoQueue,
    ns: NamespaceInfo,
    max_transfer: u32,
    fua: bool,
    opcode: u8,
    lba: u64,
    n_blocks: u32,
    dma: u64,
    len: usize,
    hold: Option<Arc<DmaBuffer>>,
) -> Result<(Sqe, CmdResources), NvmeError> {
    let bytes = check_rw(ns, max_transfer, lba, n_blocks)?;
    if bytes > len {
        return Err(NvmeError::BadTransfer);
    }
    let mut res = CmdResources {
        prp_list: None,
        hold,
        pages: None,
    };
    let pair = if prp::prp_list_pages_needed(dma, bytes) == 0 {
        prp::setup_prps(dma, bytes, &mut [], &[])
    } else {
        let page = q.prp_page().ok_or(NvmeError::OutOfDmaMemory)?;
        // SAFETY: `page` is a fresh 4 KiB coherent page (PRPS_PER_PAGE u64
        // entries, page aligned) owned by this command until its terminal
        // completion.
        let entries = unsafe {
            core::slice::from_raw_parts_mut(page.cpu_mut_ptr::<u64>(), prp::PRPS_PER_PAGE)
        };
        let r = prp::setup_prps(dma, bytes, entries, &[page.dma_addr().raw()]);
        res.prp_list = Some(page);
        r
    }
    .map_err(|e| match e {
        prp::PrpError::ListTooSmall => NvmeError::ExceedsMaxTransfer,
        _ => NvmeError::BadTransfer,
    })?;
    // Publish the list entries before the SQE + doorbell that let the
    // controller fetch them.
    compiler_fence(Ordering::Release);
    Ok((
        rw_sqe(ns, fua, opcode, lba, n_blocks, pair.prp1, pair.prp2),
        res,
    ))
}

/// [`build_rw_sqe`] over a list of `(device address, length)` segments:
/// every segment but the first starts page aligned and every segment but
/// the last ends page aligned (one PRP entry per page, NVMe Base Spec
/// §4.1.1). Up to [`prp::PRPS_PER_PAGE`] pages after PRP1.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_rw_sqe_segments(
    q: &IoQueue,
    ns: NamespaceInfo,
    max_transfer: u32,
    fua: bool,
    opcode: u8,
    lba: u64,
    n_blocks: u32,
    segs: &[(u64, u32)],
    pages: Option<Arc<narf_io::sg::PageList>>,
) -> Result<(Sqe, CmdResources), NvmeError> {
    let bytes = check_rw(ns, max_transfer, lba, n_blocks)?;
    let page = prp::NVME_CTRL_PAGE_SIZE as u64;
    // Expand the segments into page addresses covering `bytes`.
    let mut prps: Vec<u64> = Vec::new();
    let mut left = bytes as u64;
    for (i, &(addr, len)) in segs.iter().enumerate() {
        if left == 0 {
            break;
        }
        if addr & 0x3 != 0 || (i > 0 && addr % page != 0) {
            return Err(NvmeError::BadTransfer);
        }
        let take = (len as u64).min(left);
        let mut at = addr;
        let end = addr.checked_add(take).ok_or(NvmeError::BadTransfer)?;
        while at < end {
            prps.push(at);
            let step = page - (at % page);
            at = at.saturating_add(step);
        }
        left -= take;
        // A segment that is not the last must end on a page boundary.
        if left != 0 && end % page != 0 {
            return Err(NvmeError::BadTransfer);
        }
    }
    if left != 0 || prps.is_empty() {
        return Err(NvmeError::BadTransfer);
    }
    let mut res = CmdResources {
        prp_list: None,
        hold: None,
        pages,
    };
    let (prp1, prp2) = match prps.len() {
        1 => (prps[0], 0),
        2 => (prps[0], prps[1]),
        n => {
            if n - 1 > prp::PRPS_PER_PAGE {
                return Err(NvmeError::TooManyPages);
            }
            let list = q.prp_page().ok_or(NvmeError::OutOfDmaMemory)?;
            // SAFETY: fresh coherent 4 KiB page owned by this command.
            unsafe {
                let p = list.cpu_mut_ptr::<u64>();
                for (i, e) in prps[1..].iter().enumerate() {
                    core::ptr::write_volatile(p.add(i), *e);
                }
            }
            let dma = list.dma_addr().raw();
            res.prp_list = Some(list);
            (prps[0], dma)
        }
    };
    compiler_fence(Ordering::Release);
    Ok((rw_sqe(ns, fua, opcode, lba, n_blocks, prp1, prp2), res))
}

/// The bytes of an NVM Read/Write after the namespace / NLB / range /
/// MDTS checks.
fn check_rw(
    ns: NamespaceInfo,
    max_transfer: u32,
    lba: u64,
    n_blocks: u32,
) -> Result<usize, NvmeError> {
    if !ns.usable {
        return Err(NvmeError::NamespaceUnusable);
    }
    // NLB is a 16-bit zero-based field (NVM Command Set §3.2.4).
    if n_blocks == 0 || n_blocks > 0x1_0000 {
        return Err(NvmeError::BadTransfer);
    }
    if lba
        .checked_add(n_blocks as u64)
        .is_none_or(|end| end > ns.nsze)
    {
        return Err(NvmeError::OutOfRange);
    }
    let bytes = n_blocks as u64 * ns.lba_bytes as u64;
    if bytes > max_transfer as u64 {
        return Err(NvmeError::ExceedsMaxTransfer);
    }
    Ok(bytes as usize)
}

fn rw_sqe(
    ns: NamespaceInfo,
    fua: bool,
    opcode: u8,
    lba: u64,
    n_blocks: u32,
    prp1: u64,
    prp2: u64,
) -> Sqe {
    let mut sqe = Sqe::zero();
    sqe.cdw0 = opcode as u32;
    sqe.nsid = ns.nsid;
    sqe.prp1 = prp1;
    sqe.prp2 = prp2;
    // CDW10/11 = SLBA (64-bit, little-endian split).
    sqe.cdw10 = (lba & 0xFFFF_FFFF) as u32;
    sqe.cdw11 = (lba >> 32) as u32;
    // CDW12 bits[15:0] = NLB-1; bit 30 = FUA (NVM Command Set 1.0c
    // Figure 63), as Linux `nvme_setup_rw` sets for `REQ_FUA`.
    sqe.cdw12 = n_blocks - 1;
    if fua && opcode == IoOpcode::Write as u8 {
        sqe.cdw12 |= super::shutdown::CDW12_FUA;
    }
    sqe
}

// ── the request future ────────────────────────────────────────────

/// What a request asks of the namespace.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ReqOp {
    Read,
    Write { fua: bool },
    Flush,
}

impl ReqOp {
    fn opcode(self) -> u8 {
        match self {
            ReqOp::Read => IoOpcode::Read as u8,
            ReqOp::Write { .. } => IoOpcode::Write as u8,
            ReqOp::Flush => IoOpcode::Flush as u8,
        }
    }
    fn name(self) -> &'static str {
        match self {
            ReqOp::Read => "read",
            ReqOp::Write { .. } => "write",
            ReqOp::Flush => "flush",
        }
    }
}

/// Why a request's current command stopped making progress.
enum Stall {
    /// No tag free; the waker is registered with the queue.
    NoTag,
    /// The controller is dead or between queue sets.
    NoPath,
}

/// One block request against namespace `nsid` of controller `instance`.
pub struct NvmeRequest {
    instance: u32,
    nsid: u32,
    op: ReqOp,
    lba: u64,
    blocks: u32,
    payload: Option<Arc<DmaBuffer>>,
    /// Scatter-gather payload: the page list and the byte offset into it.
    pages: Option<(Arc<narf_io::sg::PageList>, usize)>,
    user_tag: u64,
    /// Blocks completed by earlier commands of this request.
    done: u32,
    /// Blocks the command in flight covers.
    cur_blocks: u32,
    /// The command in flight, if any.
    cmd: Option<Cmd>,
    /// Kernel tag of the last posted command (echoed in the completion).
    last_tag: u64,
    /// Replays after a controller reset.
    replays: u32,
    /// Resubmissions after finding no path, bounded so a controller that
    /// never comes back fails the request instead of spinning it.
    path_retries: u32,
}

impl core::fmt::Debug for NvmeRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NvmeRequest")
            .field("instance", &self.instance)
            .field("nsid", &self.nsid)
            .field("op", &self.op)
            .field("lba", &self.lba)
            .field("blocks", &self.blocks)
            .finish_non_exhaustive()
    }
}

/// The kernel tag of command `id` on queue `qid` of `instance`
/// (`BlockCompletion::tag`): unique across every in-flight command
/// system-wide, and decodable by [`NvmeQueue::cancel`].
fn kernel_tag(instance: u32, qid: u16, id: CmdId) -> u64 {
    ((instance as u64 & 0xFF) << 56)
        | ((qid as u64) << 40)
        | ((id.tag as u64) << 24)
        | (id.generation as u64 & 0xFF_FFFF)
}

fn split_kernel_tag(tag: u64) -> (u32, u16, u16, u32) {
    (
        (tag >> 56) as u32,
        (tag >> 40) as u16,
        (tag >> 24) as u16,
        (tag & 0xFF_FFFF) as u32,
    )
}

impl NvmeRequest {
    /// A Read / Write / Flush request. `payload` is the resolved buffer
    /// (`None` only for Flush); the request pins it until its last
    /// command's terminal completion.
    fn new(
        instance: u32,
        nsid: u32,
        op: ReqOp,
        lba: u64,
        blocks: u32,
        payload: Option<Arc<DmaBuffer>>,
        user_tag: u64,
    ) -> Self {
        Self {
            instance,
            nsid,
            op,
            lba,
            blocks,
            payload,
            pages: None,
            user_tag,
            done: 0,
            cur_blocks: 0,
            cmd: None,
            last_tag: 0,
            replays: 0,
            path_retries: 0,
        }
    }

    fn completion(&self, result: Result<(), BlockError>) -> BlockCompletion {
        BlockCompletion {
            tag: self.last_tag,
            user_tag: self.user_tag,
            result,
        }
    }

    /// Post the next command of this request.
    fn issue(&mut self, cx: &mut Context<'_>) -> Result<Result<(), Stall>, BlockError> {
        let slot = super::slot_of(self.instance).ok_or(BlockError::DeviceRemoved)?;
        let Some(path) = slot.io_path() else {
            return Ok(Err(Stall::NoPath));
        };
        let ns = path.ns(self.nsid).ok_or(BlockError::DeviceRemoved)?;
        let Some(q) = pick_queue(&path.queues) else {
            return Ok(Err(Stall::NoPath));
        };
        let Some(tag) = q.try_alloc_tag(Some(cx.waker())) else {
            return Ok(Err(Stall::NoTag));
        };
        let built = match self.op {
            ReqOp::Flush => {
                let mut sqe = Sqe::zero();
                sqe.cdw0 = IoOpcode::Flush as u32;
                sqe.nsid = ns.nsid;
                Ok((sqe, CmdResources::default()))
            }
            ReqOp::Read | ReqOp::Write { .. } if self.pages.is_some() => {
                let (list, base) = self.pages.clone().expect("pages");
                let lba_bytes = ns.lba_bytes as usize;
                let per_cmd = (path.max_transfer as usize / lba_bytes).max(1) as u32;
                let n = per_cmd.min(self.blocks - self.done);
                self.cur_blocks = n;
                let offset = base + self.done as usize * lba_bytes;
                let fua = matches!(self.op, ReqOp::Write { fua: true });
                match list.segments_in(offset, n as usize * lba_bytes) {
                    None => Err(BlockError::InvalidRange),
                    Some(segs) => {
                        let segs: Vec<(u64, u32)> = segs.iter().map(|s| (s.dma, s.len)).collect();
                        build_rw_sqe_segments(
                            q,
                            ns,
                            path.max_transfer,
                            fua,
                            self.op.opcode(),
                            self.lba + self.done as u64,
                            n,
                            &segs,
                            Some(list),
                        )
                        .map_err(super::map_nvme_err)
                    }
                }
            }
            ReqOp::Read | ReqOp::Write { .. } => {
                let payload = self.payload.clone().ok_or(BlockError::PermissionDenied);
                payload.and_then(|payload| {
                    let lba_bytes = ns.lba_bytes as u64;
                    let per_cmd = (path.max_transfer as u64 / lba_bytes).max(1) as u32;
                    let n = per_cmd.min(self.blocks - self.done);
                    self.cur_blocks = n;
                    let offset = self.done as u64 * lba_bytes;
                    let fua = matches!(self.op, ReqOp::Write { fua: true });
                    build_rw_sqe(
                        q,
                        ns,
                        path.max_transfer,
                        fua,
                        self.op.opcode(),
                        self.lba + self.done as u64,
                        n,
                        payload.dma_addr_at(offset).raw(),
                        payload.len().saturating_sub(offset as usize),
                        Some(payload),
                    )
                    .map_err(super::map_nvme_err)
                })
            }
        };
        let (sqe, res) = match built {
            Ok(b) => b,
            Err(e) => {
                q.release_tag_unused(tag);
                return Err(e);
            }
        };
        match q.post(tag, sqe, res) {
            Ok(id) => {
                self.last_tag = kernel_tag(self.instance, q.qid, id);
                self.cmd = Some(Cmd::new(Arc::clone(q), id));
                Ok(Ok(()))
            }
            // Quiesced under us: the queue set is being replaced.
            Err(_) => Ok(Err(Stall::NoPath)),
        }
    }

    /// No I/O path: the controller is dead (reset it, as the sync entry
    /// points do) or between queue sets (wait for the gate holder).
    fn recover_path(&mut self) -> Result<(), BlockError> {
        let slot = super::slot_of(self.instance).ok_or(BlockError::DeviceRemoved)?;
        if self.path_retries >= super::IO_MAX_RETRIES {
            return Err(BlockError::IOError);
        }
        self.path_retries += 1;
        // Taking the gate waits for whoever is rebuilding the queues.
        let guard = super::acquire(slot).map_err(super::map_nvme_err)?;
        if guard.is_dead() {
            match super::recover_held(slot, guard) {
                Ok(Some(g)) => drop(g),
                Ok(None) => {}
                Err(e) => return Err(super::map_nvme_err(e)),
            }
        }
        Ok(())
    }

    /// The command in flight timed out: reset the controller and replay
    /// (Linux `nvme_timeout` → `nvme_reset_ctrl`; `nvme_retry_req`),
    /// within the slot's timeout streak budget.
    fn handle_timeout(&mut self, cmd: Cmd) -> Result<(), BlockError> {
        use core::fmt::Write as _;
        let slot = super::slot_of(self.instance).ok_or(BlockError::DeviceRemoved)?;
        let q = Arc::clone(cmd.queue());
        let tag = cmd.id().tag;
        q.report_timeout(tag);
        let name = super::ns::controller_name(slot.instance);
        let what = self.op.name();
        let mut guard = super::acquire(slot).map_err(super::map_nvme_err)?;
        guard.mark_dead();
        // The command's pages stay with the slot until the reset frees (or
        // leaks) them.
        drop(cmd);
        let streak = slot.timeout_streak.fetch_add(1, Ordering::Relaxed) + 1;
        if super::SHUTTING_DOWN.load(Ordering::Acquire) {
            let _ = writeln!(
                narf_console::Writer,
                "nvme: {name}: ERROR: {what} timed out during shutdown; not reset, not replayed"
            );
            return Err(BlockError::IOError);
        }
        let _ = writeln!(
            narf_console::Writer,
            "nvme: {name}: {what} timed out ({streak} consecutive command timeout(s)); \
             resetting the controller"
        );
        match super::recover_held(slot, guard) {
            Ok(Some(g)) => {
                super::mark_gate_progress(slot);
                drop(g);
            }
            Ok(None) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "nvme: {name}: ERROR: namespace set changed across the reset; \
                     {what} not replayed"
                );
                return Err(BlockError::IOError);
            }
            Err(_) => return Err(BlockError::IOError),
        }
        if streak > super::IO_MAX_RETRIES {
            let _ = writeln!(
                narf_console::Writer,
                "nvme: {name}: ERROR: {what} failed: {streak} consecutive command timeouts \
                 (replayed {} time(s), limit {}); returning an I/O error",
                self.replays,
                super::IO_MAX_RETRIES
            );
            return Err(BlockError::IOError);
        }
        self.replays += 1;
        super::IO_REPLAYS.fetch_add(1, Ordering::Relaxed);
        let _ = writeln!(
            narf_console::Writer,
            "nvme: {name}: replaying {what} (replay {}, timeout streak {streak} of {})",
            self.replays,
            super::IO_MAX_RETRIES
        );
        Ok(())
    }
}

impl Future for NvmeRequest {
    type Output = BlockCompletion;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<BlockCompletion> {
        let this = self.get_mut();
        loop {
            if let Some(cmd) = this.cmd.as_mut() {
                let outcome = match cmd.poll_outcome(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(o) => o,
                };
                match outcome {
                    CmdOutcome::Completed { status, .. } => {
                        this.cmd = None;
                        if let Some(slot) = super::slot_of(this.instance) {
                            // The controller answered: the streak is over.
                            if slot.timeout_streak.load(Ordering::Relaxed) != 0 {
                                slot.timeout_streak.store(0, Ordering::Relaxed);
                            }
                        }
                        if status != 0 {
                            let e = if status == STATUS_COMMAND_ABORT_REQUESTED {
                                BlockError::Cancelled
                            } else {
                                BlockError::IOError
                            };
                            return Poll::Ready(this.completion(Err(e)));
                        }
                        match this.op {
                            ReqOp::Flush => return Poll::Ready(this.completion(Ok(()))),
                            _ => {
                                this.done += this.cur_blocks;
                                if this.done >= this.blocks {
                                    return Poll::Ready(this.completion(Ok(())));
                                }
                                continue;
                            }
                        }
                    }
                    CmdOutcome::Reset => {
                        // Torn down under us by a reset: requeue the command
                        // (Linux `nvme_cancel_request` → retry).
                        this.cmd = None;
                        continue;
                    }
                    CmdOutcome::TimedOut => {
                        let cmd = this.cmd.take().expect("command in flight");
                        if let Err(e) = this.handle_timeout(cmd) {
                            return Poll::Ready(this.completion(Err(e)));
                        }
                        continue;
                    }
                }
            }
            // Nothing in flight: issue the next command.
            if this.blocks == 0 && this.op != ReqOp::Flush {
                return Poll::Ready(this.completion(Ok(())));
            }
            if this.op == ReqOp::Flush {
                // No volatile write cache: every completed write is durable.
                let vwc = super::slot_of(this.instance)
                    .and_then(|s| s.io_path())
                    .map(|p| p.vwc);
                if vwc == Some(false) {
                    return Poll::Ready(this.completion(Ok(())));
                }
            }
            match this.issue(cx) {
                Ok(Ok(())) => continue,
                Ok(Err(Stall::NoTag)) => return Poll::Pending,
                Ok(Err(Stall::NoPath)) => {
                    if let Err(e) = this.recover_path() {
                        return Poll::Ready(this.completion(Err(e)));
                    }
                    continue;
                }
                Err(e) => return Poll::Ready(this.completion(Err(e))),
            }
        }
    }
}

// SAFETY: the request owns `Arc`s and plain data; `Cmd` is `Send`.
unsafe impl Send for NvmeRequest {}

// ── the block-layer queue ─────────────────────────────────────────

/// Namespace `nsid` of controller `instance` as a [`BlockQueue`]: what
/// the registry's `NvmeNamespaceBlock` exposes and `SyncBlock` submits
/// through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvmeQueue {
    pub instance: u32,
    pub nsid: u32,
}

impl NvmeQueue {
    fn path(&self) -> Option<Arc<IoPath>> {
        super::slot_of(self.instance)?.io_path()
    }

    fn ready(user_tag: u64, result: Result<(), BlockError>) -> BoxedCompletion {
        narf_block::queue::ready_completion(user_tag, result)
    }
}

impl BlockQueue for NvmeQueue {
    fn limits(&self) -> QueueLimits {
        let path = self.path();
        let lba = path
            .as_ref()
            .and_then(|p| p.ns(self.nsid))
            .map_or(512, |n| n.lba_bytes);
        let max_transfer = path
            .as_ref()
            .map_or(prp::NVME_CTRL_PAGE_SIZE as u32, |p| p.max_transfer);
        QueueLimits {
            logical_block_size: lba,
            max_transfer_bytes: max_transfer,
            // One PRP entry per page after PRP1, from one list page.
            max_segments: (prp::PRPS_PER_PAGE + 1) as u32,
            max_segment_bytes: max_transfer,
            // PRP entries are dword aligned (NVMe Base Spec §4.1.1).
            dma_alignment: 4,
            queue_depth: path
                .as_ref()
                .map_or(0, |p| p.queues.iter().map(|q| q.tag_count() as u32).sum()),
            nr_queues: path.as_ref().map_or(0, |p| p.queues.len() as u32),
        }
    }

    fn submit(&self, req: BlockRequest) -> BoxedCompletion {
        let op = match req.op {
            BlockOp::Read => ReqOp::Read,
            BlockOp::Write { fua } => ReqOp::Write { fua },
            // No data moves: these take the controller's gate-held paths,
            // which never touch the request's buffer (#927).
            BlockOp::Trim => {
                let r = super::nvme_discard_ns(self.instance, self.nsid, req.lba, req.blocks);
                return Self::ready(req.user_tag, r);
            }
            BlockOp::WriteZeroes => {
                let r = super::nvme_write_zeroes_ns(self.instance, self.nsid, req.lba, req.blocks);
                return Self::ready(req.user_tag, r);
            }
        };
        // Resolve the cap up front: a revoked or stale cap fails
        // `check_live` inside `narf_io::resolve_cap`.
        let Some(buffer) = narf_io::resolve_cap(&req.buffer) else {
            return Self::ready(req.user_tag, Err(BlockError::PermissionDenied));
        };
        let Some(path) = self.path() else {
            // Dead or mid-reset: the future's own recovery handles it.
            return Box::pin(NvmeRequest::new(
                self.instance,
                self.nsid,
                op,
                req.lba,
                req.blocks,
                Some(buffer),
                req.user_tag,
            ));
        };
        let Some(ns) = path.ns(self.nsid) else {
            return Self::ready(req.user_tag, Err(BlockError::DeviceRemoved));
        };
        let total = (req.blocks as u64).checked_mul(ns.lba_bytes as u64);
        if total.is_none_or(|t| t > buffer.len() as u64) {
            return Self::ready(req.user_tag, Err(BlockError::InvalidRange));
        }
        if req
            .lba
            .checked_add(req.blocks as u64)
            .is_none_or(|end| end > ns.nsze)
        {
            return Self::ready(req.user_tag, Err(BlockError::InvalidRange));
        }
        Box::pin(NvmeRequest::new(
            self.instance,
            self.nsid,
            op,
            req.lba,
            req.blocks,
            Some(buffer),
            req.user_tag,
        ))
    }

    fn flush(&self) -> BoxedResult {
        let fut = NvmeRequest::new(self.instance, self.nsid, ReqOp::Flush, 0, 0, None, 0);
        Box::pin(async move { fut.await.result })
    }

    /// Cancel the command carrying `tag`: an NVMe Abort (admin opcode
    /// 0x08) names it; the controller reports whether it was aborted
    /// before it completed (Abort completion dword 0 bit 0 clear, NVMe
    /// Base Spec §5.1). The owner's completion then carries
    /// `BlockError::Cancelled` (status Command Abort Requested).
    fn cancel(&self, tag: u64) -> BoxedCancel {
        let instance = self.instance;
        Box::pin(async move {
            let (inst, qid, cid, generation) = split_kernel_tag(tag);
            if inst != instance & 0xFF {
                return CancelResult::NotFound;
            }
            let Some(slot) = super::slot_of(instance) else {
                return CancelResult::NotFound;
            };
            let Some(path) = slot.io_path() else {
                return CancelResult::NotFound;
            };
            let Some(q) = path.queues.iter().find(|q| q.qid == qid) else {
                return CancelResult::NotFound;
            };
            let id = CmdId {
                tag: cid,
                generation,
            };
            if q.timed_out(id).is_none() {
                // Not in flight under this generation: it completed (and
                // its owner may already have reaped it) or never existed.
                return CancelResult::Completed;
            }
            let Ok(mut guard) = super::acquire(slot) else {
                return CancelResult::NotFound;
            };
            let aborted = guard.abort_command(qid, cid).unwrap_or(false);
            drop(guard);
            if aborted {
                CancelResult::Cancelled
            } else if q.timed_out(id).is_none() {
                CancelResult::Completed
            } else {
                // Still in flight and the controller would not abort it: it
                // finishes on its own.
                CancelResult::Completed
            }
        })
    }

    fn in_flight(&self) -> usize {
        self.path().map_or(0, |p| p.in_flight())
    }

    /// One conforming scatter-gather request (the splitter,
    /// `narf_block::queue::submit_sg`, cut it to [`Self::limits`]): PRPs
    /// are built straight from the page list's segments.
    fn submit_sg(&self, req: narf_block::SgRequest) -> BoxedCompletion {
        let op = match req.op {
            BlockOp::Read => ReqOp::Read,
            BlockOp::Write { fua } => ReqOp::Write { fua },
            BlockOp::Trim => {
                let r = super::nvme_discard_ns(self.instance, self.nsid, req.lba, req.blocks);
                return Self::ready(req.user_tag, r);
            }
            BlockOp::WriteZeroes => {
                let r = super::nvme_write_zeroes_ns(self.instance, self.nsid, req.lba, req.blocks);
                return Self::ready(req.user_tag, r);
            }
        };
        let Some(list) = req.resolve() else {
            return Self::ready(req.user_tag, Err(BlockError::PermissionDenied));
        };
        let mut fut = NvmeRequest::new(
            self.instance,
            self.nsid,
            op,
            req.lba,
            req.blocks,
            None,
            req.user_tag,
        );
        fut.pages = Some((list, req.offset));
        Box::pin(fut)
    }
}
