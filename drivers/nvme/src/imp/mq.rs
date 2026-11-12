//! Queued I/O submission: the blk-mq + `nvme-pci` model.
//!
//! One [`IoQueue`] per NVMe I/O SQ/CQ pair. Each has its own command-id
//! tag space (Linux `blk_mq_tags`: one tag per SQ slot, `depth - 1` of
//! them so the SQ is never full), a per-command [`CmdSlot`] holding the
//! command's state, waker and owned DMA resources, a submission lock held
//! only to write one SQE and ring the tail doorbell, and a completion lock
//! held only to walk fresh CQEs. Nothing here is held across an `.await`:
//! a waiter owns a tag, not the queue.
//!
//! Completions are consumed by whoever notices them first — the queue's
//! MSI-X handler ([`isr`], Linux `nvme_irq` → `nvme_process_cq`), or any
//! waiter that sees a fresh phase bit at the CQ head (the polled path,
//! Linux `nvme_poll`, which is also the lost-interrupt fallback and the
//! only path on a queue created without a vector). Either way
//! [`IoQueue::process_cq`] matches each CQE to its command id, publishes
//! the status in the command's slot and wakes the owner by reference; the
//! owner reaps the slot — drops the PRP page back to the pool, releases
//! its hold on the payload, returns the tag — in process context, never
//! in the interrupt.
//!
//! A command whose owner went away while it was in flight (its future was
//! dropped) is *abandoned*, not freed: the device may still read or write
//! the command's pages, so the slot keeps them until the completion lands
//! (AGENTS.md invariant 7). Abandoned-and-done slots are reclaimed by the
//! next process-context visitor ([`IoQueue::sweep`]).
//!
//! Timeouts follow blk-mq: one timer per queue (`blk_rq_timed_out_timer`),
//! armed for the earliest outstanding deadline, whose expiry marks every
//! expired command and wakes its owner (`blk_mq_timeout_work` →
//! `nvme_timeout`). The owner decides what the timeout means — a last
//! look at the CQ, then the controller reset + replay the block entry
//! points perform — exactly as before, but no waiter polls a deadline of
//! its own on the hot path.
//!
//! Teardown ([`IoQueue::teardown`], Linux `nvme_suspend_queue` +
//! `nvme_cancel_request`) quiesces the queue under the submission lock,
//! unhooks the interrupt, marks every in-flight command as reset — its
//! owner requeues — and releases abandoned commands' pages only when the
//! controller was confirmed stopped; otherwise they are leaked, as a
//! command that may still be live in the device demands.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::mem::ManuallyDrop;
use core::pin::Pin;
use core::sync::atomic::{
    compiler_fence, AtomicBool, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicUsize,
    Ordering,
};
use core::task::{Context, Poll, Waker};

use narf_bus::MmioRegion;
use narf_io::pool::DmaPool;
use narf_io::DmaBuffer;
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::timer::{self as wheel, TimerList};

use super::{note_stray_cqe, peek_cqe, write_sqe, Cqe, NvmeError, Sqe, REG_DOORBELL_BASE};

/// Deepest I/O queue the host creates whatever CAP.MQES allows: Linux
/// `io_queue_depth` (drivers/nvme/host/pci.c, default 1024, min 2).
pub const IO_QUEUE_DEPTH_MAX: u16 = 1024;
/// Shallowest usable queue: one slot must stay empty (tail == head means
/// empty, so `depth - 1` commands fit).
pub const IO_QUEUE_DEPTH_MIN: u16 = 2;

/// The queue depth for a controller reporting `mqes` (zero-based).
pub fn io_queue_depth(mqes: u16) -> u16 {
    (mqes as u32 + 1).clamp(IO_QUEUE_DEPTH_MIN as u32, IO_QUEUE_DEPTH_MAX as u32) as u16
}

/// How long one wait may park before the CQ is checked regardless of
/// whether the queue's vector fired: the phase-poll fallback for a lost or
/// never-delivered MSI, and the only clock on a polled queue.
pub const CQ_POLL_SLICE_MS: u64 = 250;

/// Handler name under which every queue's ISR is installed.
const ISR_NAME: &str = "nvme";

/// NVMe status (SCT 0, SC 0x07): the command was aborted at the host's
/// request (an Abort admin command).
pub const STATUS_COMMAND_ABORT_REQUESTED: u16 = 0x07;

// ── command slot ──────────────────────────────────────────────────

/// Free: no command uses this tag.
const FREE: u8 = 0;
/// Posted; an owner is waiting for it.
const INFLIGHT: u8 = 1;
/// The CQE landed; the owner reaps it.
const DONE: u8 = 2;
/// Posted, owner gone; the completion still to come.
const ABANDONED: u8 = 3;
/// Completed after its owner went away; the sweeper reclaims it.
const ABANDONED_DONE: u8 = 4;
/// The queue was torn down under the command; the owner must requeue.
const RESET: u8 = 5;

/// DMA resources one command holds until its terminal completion.
#[derive(Default)]
pub struct CmdResources {
    /// The command's PRP-list page, from the queue's pool.
    pub prp_list: Option<DmaBuffer>,
    /// The caller's payload, pinned for the device's use.
    pub hold: Option<Arc<DmaBuffer>>,
}

impl core::fmt::Debug for CmdResources {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CmdResources")
            .field("prp_list", &self.prp_list.is_some())
            .field("hold", &self.hold.is_some())
            .finish()
    }
}

/// One command id's bookkeeping (Linux `struct request` + `nvme_iod`).
struct CmdSlot {
    state: AtomicU8,
    opcode: AtomicU8,
    /// Set by the timeout timer; cleared when the slot is reaped.
    timed_out: AtomicBool,
    /// Test-only (`IO_LATE_FOR_TEST`): the owner ignores the completion
    /// until the budget is spent, so only the last look finds it.
    late: AtomicBool,
    /// Raw CQE status word (phase bit included) once completed.
    status: AtomicU16,
    cmd_specific: AtomicU32,
    /// Generation of the current use of this tag (the block-layer tag).
    generation: AtomicU32,
    /// `now_cycles()` at posting; 0 while free.
    started: AtomicU64,
    /// Monotonic ns at which the command times out.
    deadline_ns: AtomicU64,
    /// The vector's `fire_count` at posting, for the timeout report.
    fires_at_submit: AtomicU64,
    waker: IrqSafeSpinLock<Option<Waker>>,
    res: IrqSafeSpinLock<Option<CmdResources>>,
}

impl CmdSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(FREE),
            opcode: AtomicU8::new(0),
            timed_out: AtomicBool::new(false),
            late: AtomicBool::new(false),
            status: AtomicU16::new(0),
            cmd_specific: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            started: AtomicU64::new(0),
            deadline_ns: AtomicU64::new(u64::MAX),
            fires_at_submit: AtomicU64::new(0),
            waker: IrqSafeSpinLock::new(None),
            res: IrqSafeSpinLock::new(None),
        }
    }

    /// Wake the owner, if any, by reference: safe in interrupt context
    /// (no `Waker` is dropped here).
    fn wake(&self) {
        if let Some(w) = self.waker.lock().as_ref() {
            w.wake_by_ref();
        }
    }
}

/// Outcome of a posted command, as its owner sees it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CmdOutcome {
    /// The CQE landed. `status` is the NVMe status (SCT|SC, phase bit
    /// stripped); `late` when it was found after the command timed out.
    Completed {
        status: u16,
        cmd_specific: u32,
        late: bool,
    },
    /// The queue was torn down (controller reset) under the command.
    Reset,
    /// The command ran out its budget and the last look at the CQ found
    /// nothing: it may still be live in the device.
    TimedOut,
}

/// Tag allocator + waiters for a tag (`blk_mq_get_tag` wait queue). Tags
/// are handed out in rotation (front) and returned to the back, as
/// sbitmap's allocation hint walks the tag space: a freshly freed tag is
/// the last to be reused, which keeps a late completion for it from
/// landing on a new command.
struct TagState {
    free: VecDeque<u16>,
    waiters: VecDeque<Waker>,
}

struct CqState {
    head: u16,
    phase: u16,
}

/// The queue's timeout timer (`request_queue::timeout`), with its back
/// pointer: the queue deletes the timer synchronously before it is freed.
#[repr(C)]
struct QueueTimer {
    timer: TimerList,
    queue: AtomicPtr<IoQueue>,
}

/// One NVMe I/O queue pair with queued submission.
pub struct IoQueue {
    pub qid: u16,
    pub depth: u16,
    bar0: MmioRegion,
    db_stride: u64,
    /// The CQ's interrupt vector; `None` on a polled queue.
    pub vector: Option<u8>,
    sq_buf: ManuallyDrop<DmaBuffer>,
    cq_buf: ManuallyDrop<DmaBuffer>,
    /// SQ tail; held to write an SQE and ring the doorbell, and by
    /// teardown to quiesce.
    sq: IrqSafeSpinLock<u16>,
    cq: IrqSafeSpinLock<CqState>,
    /// `head | phase << 16`, the CQ cursor as of the last `process_cq`,
    /// for the lock-free "anything fresh?" peek.
    cq_cursor: AtomicU32,
    tags: IrqSafeSpinLock<TagState>,
    slots: Box<[CmdSlot]>,
    /// PRP-list pages, one per command that needs one.
    prp_pool: DmaPool,
    /// Set under `sq` by `teardown`: no more postings.
    quiesced: AtomicBool,
    /// Whether the controller was confirmed stopped at teardown (so a
    /// reset command's pages may be freed rather than leaked).
    stopped: AtomicBool,
    torn_down: AtomicBool,
    in_flight: AtomicUsize,
    /// Most commands in flight at once since creation.
    peak_in_flight: AtomicUsize,
    /// Commands posted since creation; the generation source.
    posted: AtomicU64,
    /// Diagnostics: handler invocations, completions matched to a command.
    isr_runs: AtomicU64,
    reaped: AtomicU64,
    /// Completions whose command id matched no in-flight command.
    strays: AtomicU64,
    /// ISR registration: the leaked `Arc` the cookie points at.
    isr_cookie: AtomicU64,
    timer: Box<QueueTimer>,
}

impl core::fmt::Debug for IoQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoQueue")
            .field("qid", &self.qid)
            .field("depth", &self.depth)
            .field("vector", &self.vector)
            .field("in_flight", &self.in_flight())
            .finish_non_exhaustive()
    }
}

// SAFETY: every field is `Sync` except the raw back pointer inside the
// boxed timer, which is only read by the timer callback while the queue is
// alive (the queue deletes the timer synchronously before dropping).
unsafe impl Sync for IoQueue {}
// SAFETY: as above; the DMA buffers are `Send`.
unsafe impl Send for IoQueue {}

/// A posted command's identity for cancellation (the block-layer tag).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmdId {
    pub tag: u16,
    pub generation: u32,
}

impl IoQueue {
    /// Wrap the SQ/CQ pages of queue `qid` (already created on the
    /// controller) into a queued-submission queue. Each command's budget
    /// is [`super::io_timeout_ms`] at posting (Linux `NVME_IO_TIMEOUT`).
    pub fn new(
        qid: u16,
        depth: u16,
        sq_buf: DmaBuffer,
        cq_buf: DmaBuffer,
        bar0: MmioRegion,
        db_stride: u64,
        vector: Option<u8>,
    ) -> Arc<Self> {
        let tags = depth.saturating_sub(1).max(1) as usize;
        let mut free = VecDeque::with_capacity(tags);
        for t in 0..tags as u16 {
            free.push_back(t);
        }
        let mut slots = Vec::with_capacity(tags);
        for _ in 0..tags {
            slots.push(CmdSlot::new());
        }
        let q = Arc::new(Self {
            qid,
            depth,
            bar0,
            db_stride,
            vector,
            sq_buf: ManuallyDrop::new(sq_buf),
            cq_buf: ManuallyDrop::new(cq_buf),
            sq: IrqSafeSpinLock::new(0),
            cq: IrqSafeSpinLock::new(CqState { head: 0, phase: 1 }),
            cq_cursor: AtomicU32::new(1 << 16),
            tags: IrqSafeSpinLock::new(TagState {
                free,
                waiters: VecDeque::with_capacity(tags),
            }),
            slots: slots.into_boxed_slice(),
            prp_pool: DmaPool::new(
                super::prp::NVME_CTRL_PAGE_SIZE,
                DomainId::DRIVER_0,
                tags.min(64),
            ),
            quiesced: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            torn_down: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
            peak_in_flight: AtomicUsize::new(0),
            posted: AtomicU64::new(0),
            isr_runs: AtomicU64::new(0),
            reaped: AtomicU64::new(0),
            strays: AtomicU64::new(0),
            isr_cookie: AtomicU64::new(0),
            timer: Box::new(QueueTimer {
                timer: TimerList::new(timeout_timer, 0),
                queue: AtomicPtr::new(core::ptr::null_mut()),
            }),
        });
        q.timer
            .queue
            .store(Arc::as_ptr(&q) as *mut IoQueue, Ordering::Release);
        q
    }

    /// Install this queue's completion handler on its vector (Linux
    /// `queue_request_irq`). The cookie is a leaked strong reference,
    /// released by [`Self::teardown`].
    pub fn install_isr(self: &Arc<Self>) {
        let Some(v) = self.vector else {
            return;
        };
        if self.isr_cookie.load(Ordering::Acquire) != 0 {
            return;
        }
        let cookie = Arc::into_raw(Arc::clone(self)) as u64;
        self.isr_cookie.store(cookie, Ordering::Release);
        narf_interrupts::install_handler_named(v, ISR_NAME, cookie, isr);
    }

    /// Commands at the device right now.
    #[inline]
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Most commands at the device at once since the queue was created.
    pub fn peak_in_flight(&self) -> usize {
        self.peak_in_flight.load(Ordering::Relaxed)
    }

    /// Completions that matched no command.
    pub fn strays(&self) -> u64 {
        self.strays.load(Ordering::Relaxed)
    }

    /// Tags this queue hands out (`depth - 1`).
    #[inline]
    pub fn tag_count(&self) -> usize {
        self.slots.len()
    }

    /// Tags currently free.
    pub fn free_tags(&self) -> usize {
        self.tags.lock().free.len()
    }

    pub fn is_quiesced(&self) -> bool {
        self.quiesced.load(Ordering::Acquire)
    }

    fn sq_db_off(&self) -> u64 {
        REG_DOORBELL_BASE + 2 * (self.qid as u64) * self.db_stride
    }
    fn cq_db_off(&self) -> u64 {
        REG_DOORBELL_BASE + (2 * (self.qid as u64) + 1) * self.db_stride
    }

    /// A PRP-list page from the queue's pool (`None` when out of DMA
    /// memory). Process context only.
    pub fn prp_page(&self) -> Option<DmaBuffer> {
        self.prp_pool.acquire()
    }

    // ── tags ──────────────────────────────────────────────────────

    /// Take a free tag. With `waker`, a caller that gets `None` is woken
    /// when one is returned (`blk_mq_get_tag`'s wait).
    pub fn try_alloc_tag(&self, waker: Option<&Waker>) -> Option<u16> {
        if let Some(t) = self.tags.lock().free.pop_front() {
            return Some(t);
        }
        // Nothing free: reclaim completed-but-abandoned commands first.
        if self.sweep() > 0 {
            if let Some(t) = self.tags.lock().free.pop_front() {
                return Some(t);
            }
        }
        if let Some(w) = waker {
            let mut g = self.tags.lock();
            // Register, then re-check under the lock: a tag freed between
            // the pop above and here is not missed.
            if let Some(t) = g.free.pop_front() {
                return Some(t);
            }
            if !g.waiters.iter().any(|q| q.will_wake(w)) {
                g.waiters.push_back(w.clone());
            }
        }
        None
    }

    /// Return a tag taken by [`Self::try_alloc_tag`] that was never
    /// posted (the SQE could not be built).
    pub fn release_tag_unused(&self, tag: u16) {
        self.free_tag(tag);
    }

    fn free_tag(&self, tag: u16) {
        let waiter = {
            let mut g = self.tags.lock();
            g.free.push_back(tag);
            g.waiters.pop_front()
        };
        if let Some(w) = waiter {
            w.wake();
        }
    }

    // ── posting ───────────────────────────────────────────────────

    /// Post `sqe` under `tag` (its command id is overwritten with `tag`),
    /// with `res` held until the command's terminal completion. On a
    /// quiesced queue the tag and resources are released here and
    /// [`NvmeError::ControllerDead`] returned.
    pub(crate) fn post(
        &self,
        tag: u16,
        mut sqe: Sqe,
        res: CmdResources,
    ) -> Result<CmdId, NvmeError> {
        let slot = &self.slots[tag as usize];
        debug_assert_eq!(slot.state.load(Ordering::Relaxed), FREE);
        let opcode = (sqe.cdw0 & 0xFF) as u8;
        sqe.cdw0 = (sqe.cdw0 & 0x0000_FFFF) | ((tag as u32) << 16);
        // Nonzero and within the 24 bits the block-layer tag carries.
        let generation = ((self.posted.fetch_add(1, Ordering::Relaxed) as u32) & 0xFF_FFFE) | 1;
        let now_ns = narf_time::monotonic_ns();
        let deadline_ns = now_ns.saturating_add(super::io_timeout_ms().saturating_mul(1_000_000));
        *slot.res.lock() = Some(res);
        // Test-only fault injection (see `IO_LOSE_FOR_TEST` /
        // `IO_LATE_FOR_TEST`).
        let lose = super::take_test_fault(&super::IO_LOSE_FOR_TEST);
        let late = super::take_test_fault(&super::IO_LATE_FOR_TEST);
        slot.opcode.store(opcode, Ordering::Relaxed);
        slot.timed_out.store(false, Ordering::Relaxed);
        slot.late.store(late, Ordering::Relaxed);
        slot.generation.store(generation, Ordering::Relaxed);
        slot.started
            .store(narf_time::now_cycles(), Ordering::Relaxed);
        slot.deadline_ns.store(deadline_ns, Ordering::Relaxed);
        slot.fires_at_submit.store(
            self.vector.map_or(0, narf_interrupts::fire_count),
            Ordering::Relaxed,
        );
        // Publish the PRP list / payload before the state that lets a
        // completion (or teardown) act on the slot, and before the SQE +
        // doorbell that let the device fetch them.
        compiler_fence(Ordering::Release);
        slot.state.store(INFLIGHT, Ordering::Release);
        let now_in_flight = self.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
        self.peak_in_flight
            .fetch_max(now_in_flight, Ordering::AcqRel);
        {
            let mut tail = self.sq.lock();
            if self.quiesced.load(Ordering::Acquire) {
                drop(tail);
                // Teardown may already have seen the slot in flight and
                // marked it reset (taking it out of the count); either way
                // nothing reached the device.
                if slot
                    .state
                    .compare_exchange(INFLIGHT, FREE, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    self.in_flight.fetch_sub(1, Ordering::AcqRel);
                } else {
                    slot.state.store(FREE, Ordering::Release);
                }
                let res = slot.res.lock().take();
                self.release_resources(res);
                self.free_tag(tag);
                return Err(NvmeError::ControllerDead);
            }
            // SAFETY: the SQ page is live, sized for `depth` SQEs; the
            // tail is bounded by `depth`.
            unsafe {
                write_sqe(&self.sq_buf, *tail, &sqe);
            }
            *tail = (*tail + 1) % self.depth;
            if !lose {
                // SAFETY: identity-mapped MMIO doorbell.
                unsafe {
                    self.bar0.write32(self.sq_db_off(), *tail as u32);
                }
            }
        }
        self.arm_timeout(deadline_ns);
        Ok(CmdId { tag, generation })
    }

    /// `blk_add_timer`: make sure the queue's timer fires by `deadline_ns`.
    fn arm_timeout(&self, deadline_ns: u64) {
        let expires = wheel::ns_to_jiffies(deadline_ns) + 1;
        let t = &self.timer.timer;
        if t.is_pending() && t.expires() <= expires {
            return;
        }
        // SAFETY: the timer lives in a `Box` inside this queue, which
        // deletes it synchronously before it is freed (`Drop`).
        unsafe {
            wheel::mod_timer(t, expires);
        }
    }

    /// The timeout timer fired: mark every expired command, wake its owner,
    /// and re-arm for the earliest remaining deadline.
    fn on_timeout_timer(&self) {
        let now = narf_time::monotonic_ns();
        let mut next = u64::MAX;
        for slot in self.slots.iter() {
            let s = slot.state.load(Ordering::Acquire);
            if s != INFLIGHT && s != ABANDONED {
                continue;
            }
            let dl = slot.deadline_ns.load(Ordering::Relaxed);
            if dl <= now {
                if !slot.timed_out.swap(true, Ordering::AcqRel) {
                    slot.wake();
                }
            } else {
                next = next.min(dl);
            }
        }
        if next != u64::MAX && !self.quiesced.load(Ordering::Acquire) {
            self.arm_timeout(next);
        }
    }

    /// Whether `cmd` is still the command in flight under its tag, and if
    /// so whether it has timed out (`None` when it is not in flight).
    pub fn timed_out(&self, cmd: CmdId) -> Option<bool> {
        let slot = &self.slots[cmd.tag as usize];
        if slot.generation.load(Ordering::Acquire) != cmd.generation {
            return None;
        }
        match slot.state.load(Ordering::Acquire) {
            INFLIGHT | ABANDONED => Some(slot.timed_out.load(Ordering::Acquire)),
            _ => None,
        }
    }

    /// Owner's view of command `tag`'s state: whether its timer expired
    /// (the owner-side check for contexts in which no timer wheel runs).
    fn deadline_passed(&self, tag: u16) -> bool {
        let slot = &self.slots[tag as usize];
        slot.timed_out.load(Ordering::Acquire)
            || slot.deadline_ns.load(Ordering::Relaxed) <= narf_time::monotonic_ns()
    }

    // ── completion ────────────────────────────────────────────────

    /// Whether a fresh CQE sits at the head (lock-free peek).
    #[inline]
    pub fn cq_has_fresh(&self) -> bool {
        let cur = self.cq_cursor.load(Ordering::Acquire);
        let (head, phase) = ((cur & 0xFFFF) as u16, (cur >> 16) as u16);
        // SAFETY: the CQ page is live and sized for `depth` CQEs; head < depth.
        let cqe = unsafe { peek_cqe(&self.cq_buf, head) };
        (cqe.status & 1) == (phase & 1)
    }

    /// Consume every fresh CQE (Linux `nvme_process_cq`): match each to its
    /// command, publish the status, wake the owner. Returns how many were
    /// consumed. From the ISR (`from_irq`) nothing is freed; from process
    /// context, completed abandoned commands are reclaimed too.
    pub fn process_cq(&self, from_irq: bool) -> usize {
        let mut reclaim: [u16; 16] = [0; 16];
        let mut n_reclaim = 0usize;
        let mut n = 0usize;
        if from_irq {
            self.isr_runs.fetch_add(1, Ordering::Relaxed);
        }
        {
            let mut g = self.cq.lock();
            loop {
                // SAFETY: live CQ page; head < depth.
                let cqe = unsafe { peek_cqe(&self.cq_buf, g.head) };
                if (cqe.status & 1) != (g.phase & 1) {
                    break;
                }
                let (head, phase) = (g.head, g.phase);
                g.head += 1;
                if g.head == self.depth {
                    g.head = 0;
                    g.phase ^= 1;
                }
                n += 1;
                if let Some(tag) = self.complete_one(&cqe, head, phase, from_irq) {
                    if !from_irq && n_reclaim < reclaim.len() {
                        reclaim[n_reclaim] = tag;
                        n_reclaim += 1;
                    }
                }
            }
            if n > 0 {
                self.cq_cursor
                    .store(g.head as u32 | ((g.phase as u32) << 16), Ordering::Release);
                // SAFETY: identity-mapped MMIO doorbell.
                unsafe {
                    self.bar0.write32(self.cq_db_off(), g.head as u32);
                }
            }
        }
        for &tag in &reclaim[..n_reclaim] {
            self.reclaim_abandoned(tag);
        }
        n
    }

    /// Match one CQE to its slot. Returns the tag when the slot is an
    /// abandoned command that can now be reclaimed. Strays are counted
    /// always and reported only from process context (no console writes
    /// in the interrupt).
    fn complete_one(&self, cqe: &Cqe, head: u16, phase: u16, from_irq: bool) -> Option<u16> {
        let stray = |cqe: &Cqe| {
            self.strays.fetch_add(1, Ordering::Relaxed);
            if from_irq {
                super::STRAY_CQE_DROPS.fetch_add(1, Ordering::Relaxed);
            } else {
                note_stray_cqe(self.bar0.phys.raw(), self.qid, head, phase, None, cqe);
            }
        };
        let Some(slot) = self.slots.get(cqe.cid as usize) else {
            stray(cqe);
            return None;
        };
        slot.status.store(cqe.status, Ordering::Relaxed);
        slot.cmd_specific.store(cqe.cmd_specific, Ordering::Relaxed);
        // Publish the status before the state the owner reads.
        if slot
            .state
            .compare_exchange(INFLIGHT, DONE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            self.reaped.fetch_add(1, Ordering::Relaxed);
            slot.wake();
            return None;
        }
        if slot
            .state
            .compare_exchange(
                ABANDONED,
                ABANDONED_DONE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return Some(cqe.cid);
        }
        // A free, already-done or reset slot: nobody expects this CQE.
        stray(cqe);
        None
    }

    /// Owner-side: the command's outcome if it reached a terminal state,
    /// reaping the slot (resources released, tag returned) when it did.
    /// `Some(TimedOut)` leaves the slot in flight: the command may still
    /// be live in the device and the owner must decide (reset, or wait
    /// on). Process context only.
    pub fn poll_cmd(&self, tag: u16) -> Option<CmdOutcome> {
        let slot = &self.slots[tag as usize];
        match slot.state.load(Ordering::Acquire) {
            // Injected late completion: unseen until the budget is spent.
            DONE if slot.late.load(Ordering::Relaxed) && !self.deadline_passed(tag) => None,
            DONE => {
                let status = slot.status.load(Ordering::Relaxed) >> 1;
                let cmd_specific = slot.cmd_specific.load(Ordering::Relaxed);
                // Late when its budget ran out before it was found — by the
                // timer's mark or, where no timer wheel runs, by the clock.
                let late = self.deadline_passed(tag);
                if late {
                    super::note_late_completion(
                        self.bar0.phys.raw(),
                        self.qid,
                        slot.opcode.load(Ordering::Relaxed),
                        tag,
                        slot.started.load(Ordering::Relaxed),
                    );
                }
                self.reap(tag, true);
                Some(CmdOutcome::Completed {
                    status,
                    cmd_specific,
                    late,
                })
            }
            RESET => {
                self.reap(tag, self.stopped.load(Ordering::Acquire));
                Some(CmdOutcome::Reset)
            }
            INFLIGHT if self.deadline_passed(tag) => {
                // One last look (Linux `nvme_timeout` polls the queue).
                self.process_cq(false);
                if slot.state.load(Ordering::Acquire) == DONE {
                    slot.timed_out.store(true, Ordering::Relaxed);
                    return self.poll_cmd(tag);
                }
                Some(CmdOutcome::TimedOut)
            }
            _ => None,
        }
    }

    /// Register `waker` to be woken by the command's completion, reset or
    /// timeout. The caller re-checks [`Self::poll_cmd`] afterwards.
    pub fn register_waker(&self, tag: u16, waker: &Waker) {
        let mut g = self.slots[tag as usize].waker.lock();
        match g.as_ref() {
            Some(w) if w.will_wake(waker) => {}
            _ => {
                let old = g.replace(waker.clone());
                drop(g);
                drop(old);
            }
        }
    }

    /// Report command `tag`'s timeout (Linux `nvme_timeout`'s log line),
    /// plus where the queue's rings are and whether the completion sits
    /// anywhere in the CQ (a cursor that lost track of the device).
    pub fn report_timeout(&self, tag: u16) {
        use core::fmt::Write as _;
        let slot = &self.slots[tag as usize];
        let cur = self.cq_cursor.load(Ordering::Acquire);
        {
            let mut w = narf_console::Writer;
            let _ = write!(
                w,
                "nvme: queue {}: sq {:#x} cq {:#x} depth {} in_flight {} free_tags {} isr_runs {} \
                 reaped {} strays {}; cq[0..4] =",
                self.qid,
                self.sq_buf.dma_addr().raw(),
                self.cq_buf.dma_addr().raw(),
                self.depth,
                self.in_flight(),
                self.free_tags(),
                self.isr_runs.load(Ordering::Relaxed),
                self.reaped.load(Ordering::Relaxed),
                self.strays(),
            );
            for i in 0..4u16.min(self.depth) {
                // SAFETY: live CQ page; i < depth.
                let c = unsafe { peek_cqe(&self.cq_buf, i) };
                let _ = write!(
                    w,
                    " [{:#06x} st {:#06x} dw0 {:#x}]",
                    c.cid, c.status, c.cmd_specific
                );
            }
            let found = (0..self.depth).find(|&i| {
                // SAFETY: as above.
                let c = unsafe { peek_cqe(&self.cq_buf, i) };
                c.cid == tag && c.status != 0
            });
            let _ = writeln!(w, "; cid {tag:#06x} found at {found:?}");
        }
        super::log_io_timeout(
            &self.bar0,
            self.qid,
            (cur & 0xFFFF) as u16,
            (cur >> 16) as u16,
            // SAFETY: live CQ page; head < depth.
            unsafe { peek_cqe(&self.cq_buf, (cur & 0xFFFF) as u16) },
            *self.sq.lock(),
            slot.opcode.load(Ordering::Relaxed),
            tag,
            self.vector,
            Some(slot.fires_at_submit.load(Ordering::Relaxed)),
            Some(slot.started.load(Ordering::Relaxed)),
        );
    }

    /// The owner lets go of an in-flight command without its completion
    /// (its future was dropped, or it timed out and the owner moves on):
    /// the slot keeps the command's pages until the CQE lands or the queue
    /// is torn down. A command that already completed is reaped at once.
    pub fn abandon(&self, tag: u16) {
        let slot = &self.slots[tag as usize];
        // Drop the owner's waker: it must not be woken for a command it no
        // longer waits on.
        let old = self.slots[tag as usize].waker.lock().take();
        drop(old);
        loop {
            match slot.state.load(Ordering::Acquire) {
                INFLIGHT => {
                    if slot
                        .state
                        .compare_exchange(INFLIGHT, ABANDONED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return;
                    }
                }
                DONE => return self.reap(tag, true),
                RESET => return self.reap(tag, self.stopped.load(Ordering::Acquire)),
                _ => return,
            }
        }
    }

    /// Reclaim every completed abandoned command. Returns how many.
    pub fn sweep(&self) -> usize {
        let mut n = 0;
        for tag in 0..self.slots.len() as u16 {
            if self.slots[tag as usize].state.load(Ordering::Acquire) == ABANDONED_DONE {
                self.reclaim_abandoned(tag);
                n += 1;
            }
        }
        n
    }

    fn reclaim_abandoned(&self, tag: u16) {
        let slot = &self.slots[tag as usize];
        if slot
            .state
            .compare_exchange(ABANDONED_DONE, DONE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.reap(tag, true);
        }
    }

    /// Release the slot: resources dropped (or leaked when `free_pages`
    /// is false — the device may still use them), tag returned.
    fn reap(&self, tag: u16, free_pages: bool) {
        let slot = &self.slots[tag as usize];
        let res = slot.res.lock().take();
        let old = slot.waker.lock().take();
        drop(old);
        if free_pages {
            self.release_resources(res);
        } else if let Some(res) = res {
            super::RETAINED_IO_BUFFERS.fetch_add(
                res.hold.is_some() as u64 + res.prp_list.is_some() as u64,
                Ordering::Relaxed,
            );
            core::mem::forget(res);
        }
        slot.timed_out.store(false, Ordering::Relaxed);
        slot.late.store(false, Ordering::Relaxed);
        slot.started.store(0, Ordering::Relaxed);
        slot.deadline_ns.store(u64::MAX, Ordering::Relaxed);
        slot.state.store(FREE, Ordering::Release);
        self.free_tag(tag);
    }

    fn release_resources(&self, res: Option<CmdResources>) {
        if let Some(res) = res {
            if let Some(page) = res.prp_list {
                self.prp_pool.release(page);
            }
            drop(res.hold);
        }
    }

    // ── teardown ──────────────────────────────────────────────────

    /// Quiesce the queue (Linux `nvme_suspend_queue` + `nvme_cancel_request`
    /// for its requests): no more postings, the interrupt unhooked, every
    /// in-flight command marked reset and its owner woken, abandoned
    /// commands' pages freed when the controller was confirmed `stopped`
    /// and leaked otherwise. The SQ/CQ pages are freed only when stopped.
    /// Idempotent.
    pub fn teardown(&self, stopped: bool) {
        {
            let _tail = self.sq.lock();
            self.quiesced.store(true, Ordering::Release);
        }
        if self.torn_down.swap(true, Ordering::AcqRel) {
            return;
        }
        self.stopped.store(stopped, Ordering::Release);
        wheel::del_timer_sync(&self.timer.timer);
        let cookie = self.isr_cookie.swap(0, Ordering::AcqRel);
        if let (Some(v), true) = (self.vector, cookie != 0) {
            narf_interrupts::remove_handler(v, ISR_NAME, cookie);
            narf_interrupts::synchronize_irq(v);
            // SAFETY: `cookie` is the `Arc::into_raw` of `install_isr`,
            // handed out exactly once and no longer reachable by the ISR.
            drop(unsafe { Arc::from_raw(cookie as *const IoQueue) });
        }
        // Everything the device still had is now either stopped (CC.EN=0
        // confirmed) or must be treated as live forever.
        let _g = self.cq.lock();
        for tag in 0..self.slots.len() as u16 {
            let slot = &self.slots[tag as usize];
            match slot.state.load(Ordering::Acquire) {
                INFLIGHT => {
                    self.in_flight.fetch_sub(1, Ordering::AcqRel);
                    slot.state.store(RESET, Ordering::Release);
                    slot.wake();
                }
                ABANDONED => {
                    self.in_flight.fetch_sub(1, Ordering::AcqRel);
                    self.reap(tag, stopped);
                }
                ABANDONED_DONE => self.reap(tag, true),
                _ => {}
            }
        }
    }

    /// Release the queue's own pages when the controller is known to have
    /// stopped using them. Called by the owner after `teardown(true)`;
    /// a queue torn down with `stopped == false` leaks them.
    fn drop_pages(&mut self) {
        // SAFETY: called once, from `Drop`, on a queue whose pages the
        // device no longer owns.
        unsafe {
            ManuallyDrop::drop(&mut self.sq_buf);
            ManuallyDrop::drop(&mut self.cq_buf);
        }
    }
}

impl Drop for IoQueue {
    fn drop(&mut self) {
        wheel::del_timer_sync(&self.timer.timer);
        let torn_down = self.torn_down.load(Ordering::Acquire);
        // A queue that was never torn down (a fake controller in a smoke, or
        // a queue replaced before the controller was ever enabled) frees its
        // pages as the old `Queue` did; one torn down with the controller
        // not confirmed stopped keeps them out of the allocator forever.
        if !torn_down || self.stopped.load(Ordering::Acquire) {
            self.drop_pages();
        }
    }
}

/// The per-queue MSI-X handler: reap the CQ, wake owners.
fn isr(cookie: u64) -> narf_interrupts::IrqStatus {
    // SAFETY: `cookie` is the leaked `Arc<IoQueue>` of `install_isr`, kept
    // alive until `teardown` removed this handler and synchronised.
    let q = unsafe { &*(cookie as *const IoQueue) };
    q.process_cq(true);
    narf_interrupts::IrqStatus::Handled
}

/// The queue timeout timer's callback (`blk_rq_timed_out_timer`).
fn timeout_timer(t: &TimerList) {
    // SAFETY: only `QueueTimer` uses this callback; `timer` is its first
    // field (repr(C)), and the queue it points at deletes the timer
    // synchronously before it is freed.
    let qt = unsafe { &*(t as *const TimerList as *const QueueTimer) };
    let q = qt.queue.load(Ordering::Acquire);
    if q.is_null() {
        return;
    }
    // SAFETY: as above.
    unsafe { &*q }.on_timeout_timer();
}

// ── owner-side futures ────────────────────────────────────────────

/// One posted command, owned by a waiter until its outcome. Dropping it
/// before the outcome abandons the command (see the module docs).
pub struct Cmd {
    queue: Arc<IoQueue>,
    id: CmdId,
    /// The wait armed for the next reason to look at the CQ: the vector
    /// firing or the poll slice elapsing (IRQ queue), or the slice alone
    /// (polled queue).
    wait: Option<CmdWait>,
    done: bool,
}

enum CmdWait {
    Irq(narf_time::Timeout<narf_interrupts::WaitForIrq>),
    Slice(narf_time::SleepUntil),
}

impl core::fmt::Debug for Cmd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cmd")
            .field("qid", &self.queue.qid)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Cmd {
    pub fn new(queue: Arc<IoQueue>, id: CmdId) -> Self {
        Self {
            queue,
            id,
            wait: None,
            done: false,
        }
    }

    pub fn id(&self) -> CmdId {
        self.id
    }

    pub fn queue(&self) -> &Arc<IoQueue> {
        &self.queue
    }

    fn arm(&mut self) {
        let slice = narf_time::Deadline::after_ms(CQ_POLL_SLICE_MS);
        self.wait = Some(match self.queue.vector {
            Some(v) => CmdWait::Irq(narf_interrupts::wait_for_irq_until(v, slice)),
            None => CmdWait::Slice(narf_time::sleep_until(slice)),
        });
    }

    /// Poll for the outcome. Pending while the command is in flight and
    /// its budget has not run out.
    pub fn poll_outcome(&mut self, cx: &mut Context<'_>) -> Poll<CmdOutcome> {
        let tag = self.id.tag;
        // Two rounds at most: one before and one after a fresh CQ look.
        for round in 0..3 {
            if let Some(o) = self.queue.poll_cmd(tag) {
                if o != CmdOutcome::TimedOut {
                    self.done = true;
                }
                return Poll::Ready(o);
            }
            if round == 0 {
                // Register, then re-check: a completion between the check
                // above and the registration is seen by the next round.
                self.queue.register_waker(tag, cx.waker());
                continue;
            }
            // Anything fresh at the head is reaped here, by this waiter
            // (the polled path / lost-interrupt fallback).
            if self.queue.cq_has_fresh() {
                self.queue.process_cq(false);
                continue;
            }
            // Arm BEFORE the final check, so an interrupt landing between
            // the check and the suspension resolves the wait at once.
            if self.wait.is_none() {
                self.arm();
            }
            let fired = match self.wait.as_mut() {
                Some(CmdWait::Irq(w)) => Pin::new(w).poll(cx).is_ready(),
                Some(CmdWait::Slice(s)) => Pin::new(s).poll(cx).is_ready(),
                None => false,
            };
            if fired {
                // The vector fired or the slice ran out: look again with a
                // fresh wait armed.
                self.wait = None;
                if round < 2 {
                    continue;
                }
                // Bounded: yield once and come back.
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }
        Poll::Pending
    }

    /// Synchronous wait for the outcome, for the gate-held paths (sync
    /// wrappers, Flush/DSM under `&mut Controller`). Spins responsively;
    /// never holds a lock. `TimedOut` leaves the command abandoned in the
    /// slot.
    pub fn wait_sync(mut self) -> CmdOutcome {
        let tag = self.id.tag;
        loop {
            if let Some(o) = self.queue.poll_cmd(tag) {
                if o == CmdOutcome::TimedOut {
                    // The slot keeps the command's pages; the controller is
                    // reset by the caller.
                    self.queue.abandon(tag);
                }
                self.done = true;
                return o;
            }
            let q = Arc::clone(&self.queue);
            let v = q.vector;
            let baseline = v.map(narf_interrupts::fire_count);
            let slice = narf_time::Deadline::after_ms(CQ_POLL_SLICE_MS);
            let _ = narf_scheduler::responsive_spin_until(
                || {
                    q.cq_has_fresh()
                        || q.poll_cmd_peek(tag)
                        || v.is_some_and(|v| Some(narf_interrupts::fire_count(v)) != baseline)
                },
                slice,
            );
            if self.queue.cq_has_fresh() {
                self.queue.process_cq(false);
            }
        }
    }
}

impl IoQueue {
    /// Whether command `tag` has left the in-flight state or timed out
    /// (lock-free, for spin waits).
    fn poll_cmd_peek(&self, tag: u16) -> bool {
        let slot = &self.slots[tag as usize];
        let s = slot.state.load(Ordering::Acquire);
        (s != INFLIGHT && !(s == DONE && slot.late.load(Ordering::Relaxed)))
            || self.deadline_passed(tag)
    }
}

impl Drop for Cmd {
    fn drop(&mut self) {
        if !self.done {
            self.queue.abandon(self.id.tag);
        }
    }
}
