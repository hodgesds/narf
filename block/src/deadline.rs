//! Single-queue deadline scheduler.
//!
//! Spec: `block/specification/spec.md` (Stage 3 deliverable). The
//! Stage-3 scope is a single-queue deadline scheduler: two FIFOs
//! (read / write) with write-starvation prevention. `dequeue_next`
//! prefers the read side to minimise request-completion latency —
//! the common case for latency-sensitive consumers — but after
//! `STARVE_BOUND` consecutive reads services a pending write.
//! Per-request deadlines further promote a request whose deadline
//! has passed, even if the write budget hasn't drained.
//!
//! Out of scope here (Stage-4 follow-ups in the block/ spec):
//! - Request merging (coalescing adjacent LBAs before dispatch).
//! - Multi-queue dispatch / per-CPU queues.
//! - CFQ-style fair-share across submitters.
//! - Feedback from device queue depth (back-pressure).

use alloc::collections::VecDeque;

use narf_lib::sync::IrqSafeSpinLock;

use crate::{BlockOp, BlockRequest};

/// Number of consecutive read dispatches allowed before a pending
/// write is serviced. 5 matches the Linux deadline scheduler default
/// — low enough that writes aren't unbounded, high enough that
/// read-heavy workloads don't context-switch per-request.
pub const STARVE_BOUND: u32 = 5;

/// Lane a request lives in. A separate `BlockOp::Trim` lane could be
/// added here in Stage 4; for now TRIM follows the write path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Lane {
    Read,
    Write,
}

impl Lane {
    #[inline]
    pub fn of(op: BlockOp) -> Self {
        match op {
            BlockOp::Read => Lane::Read,
            _ => Lane::Write,
        }
    }
}

/// One entry on a scheduler queue. Adds a deadline-cycles timestamp
/// to the caller's `BlockRequest`; a request whose deadline has passed
/// is promoted to head-of-line on the next `dequeue_next` call even
/// if its lane isn't due.
#[derive(Debug)]
struct Entry {
    req: BlockRequest,
    deadline: u64,
}

/// Single-queue deadline I/O scheduler.
///
/// The public surface is `enqueue` + `dequeue_next` + `len`; callers
/// that want to drain into a device driver await completions on the
/// device side, not here — this crate does not dispatch.
#[derive(Debug)]
pub struct DeadlineScheduler {
    inner: IrqSafeSpinLock<Inner>,
}

#[derive(Debug)]
struct Inner {
    read: VecDeque<Entry>,
    write: VecDeque<Entry>,
    consecutive_reads: u32,
    /// Monotonic tag assigned to each enqueue; exposed by the
    /// scheduler because callers (test harness, the block/ backend)
    /// want to correlate dequeued requests with earlier submissions.
    next_tag: u64,
}

impl DeadlineScheduler {
    pub const fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(Inner {
                read: VecDeque::new(),
                write: VecDeque::new(),
                consecutive_reads: 0,
                next_tag: 1,
            }),
        }
    }

    /// Queue a request with an absolute-cycle deadline. Returns the
    /// kernel-assigned tag; the caller correlates through
    /// `BlockCompletion::tag` once the device drains this entry.
    pub fn enqueue(&self, req: BlockRequest, deadline_cycles: u64) -> u64 {
        let mut g = self.inner.lock();
        let tag = g.next_tag;
        g.next_tag = g.next_tag.saturating_add(1);
        let lane = Lane::of(req.op);
        let entry = Entry {
            req,
            deadline: deadline_cycles,
        };
        match lane {
            Lane::Read => g.read.push_back(entry),
            Lane::Write => g.write.push_back(entry),
        }
        tag
    }

    /// Pick the next request to dispatch. Returns `None` when both
    /// lanes are empty. The ordering rule:
    ///
    /// 1. If a request on either lane has an already-expired
    ///    `deadline` (relative to `now_cycles`), promote it.
    /// 2. Otherwise, prefer the read lane unless the write lane is
    ///    non-empty and `consecutive_reads >= STARVE_BOUND`.
    pub fn dequeue_next(&self, now_cycles: u64) -> Option<BlockRequest> {
        let mut g = self.inner.lock();

        // Deadline-promotion: oldest-past-due first.
        if let Some(lane) = Self::find_expired_lane(&g, now_cycles) {
            let entry = match lane {
                Lane::Read => g.read.pop_front()?,
                Lane::Write => g.write.pop_front()?,
            };
            if lane == Lane::Read {
                g.consecutive_reads = g.consecutive_reads.saturating_add(1);
            } else {
                g.consecutive_reads = 0;
            }
            return Some(entry.req);
        }

        // Write-starvation promotion.
        let write_due = g.consecutive_reads >= STARVE_BOUND && !g.write.is_empty();
        if write_due {
            let entry = g.write.pop_front()?;
            g.consecutive_reads = 0;
            return Some(entry.req);
        }

        // Default: prefer reads.
        if let Some(entry) = g.read.pop_front() {
            g.consecutive_reads = g.consecutive_reads.saturating_add(1);
            return Some(entry.req);
        }
        if let Some(entry) = g.write.pop_front() {
            g.consecutive_reads = 0;
            return Some(entry.req);
        }
        None
    }

    /// Total pending requests across both lanes.
    pub fn len(&self) -> usize {
        let g = self.inner.lock();
        g.read.len() + g.write.len()
    }

    /// `true` iff no requests are pending.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Count of pending reads.
    pub fn reads_pending(&self) -> usize {
        self.inner.lock().read.len()
    }

    /// Count of pending writes.
    pub fn writes_pending(&self) -> usize {
        self.inner.lock().write.len()
    }

    fn find_expired_lane(g: &Inner, now: u64) -> Option<Lane> {
        // Check head-of-line on each lane — deadlines land in FIFO
        // order, so only the front can be expired without the prior
        // entries already being gone.
        let rd_exp = g.read.front().map(|e| e.deadline <= now).unwrap_or(false);
        let wr_exp = g.write.front().map(|e| e.deadline <= now).unwrap_or(false);
        match (rd_exp, wr_exp) {
            (true, true) => {
                // Older head wins.
                let rd = g.read.front().unwrap().deadline;
                let wr = g.write.front().unwrap().deadline;
                if rd <= wr {
                    Some(Lane::Read)
                } else {
                    Some(Lane::Write)
                }
            }
            (true, false) => Some(Lane::Read),
            (false, true) => Some(Lane::Write),
            _ => None,
        }
    }
}

impl Default for DeadlineScheduler {
    fn default() -> Self {
        Self::new()
    }
}
