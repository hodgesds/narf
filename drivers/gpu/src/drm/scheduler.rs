//! GPU command-buffer scheduler.
//!
//! Hardware-agnostic front-end for queuing GPU command buffers across
//! per-context queues with priority + dependency tracking.  Drivers
//! supply a [`JobPayload`] (per-engine pushbuf, NV class, AMD PM4
//! IB, etc.); the scheduler core picks the next runnable job, runs
//! it through the [`JobPayload::execute`] callback, and signals the
//! job's output fence so syncobj waiters wake.
//!
//! The model mirrors Linux's `drm_gpu_scheduler`:
//!
//! - `drm_sched_entity` ≡ [`SchedContext`] — one per-{driver,client}
//!   queue.  Holds an ordered VecDeque of jobs and a priority.
//! - `drm_gpu_scheduler` ≡ [`Sched`] — owns N contexts and the
//!   round-robin selector across them.
//! - `drm_sched_job` ≡ [`Job`] — carries dependency fences in, an
//!   output fence to signal on retire, and a driver-supplied payload.
//! - `drm_sched_fence` ≡ [`JobFence`] — the signalled-bit a job
//!   exposes once `execute()` returns.
//!
//! Selection between contexts is FIFO within a priority class, with
//! higher-priority classes drained first (Linux's
//! `DRM_SCHED_PRIORITY_HIGH > NORMAL > LOW > MIN`).  Linux's
//! credit-flow control is collapsed to "one job runs at a time per
//! `Sched::tick`" — the credit-limit machinery slots in next to
//! `runnable_idx` when hardware backing arrives.
//!
//! ## Deferred
//!
//! - Credit-flow control (Linux: `sched->credit_limit`).
//! - Hardware-specific job submission (AMD CP / NV pushbuf classes;
//!   these implement [`JobPayload::execute`] in their own crates).
//! - TDR (timeout/reset) — Linux's `drm_sched_fault` reset path.
//!
//! ## Linux references
//!
//! - `drivers/gpu/drm/scheduler/sched_main.c::drm_sched_main` — main
//!   run loop selector.
//! - `drivers/gpu/drm/scheduler/sched_entity.c::drm_sched_entity_init`
//!   + `..._push` — per-context queue.
//! - `drivers/gpu/drm/scheduler/sched_fence.c` — output fence model.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::syncobj::DmaFence;

// ── Errors ─────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedError {
    /// Context id not found in scheduler.
    NoContext,
    /// No runnable job (all contexts empty or all blocked on deps).
    NotRunnable,
    /// Job submission failed because the context's queue is full.
    QueueFull,
}

// ── Priority ───────────────────────────────────────────────────────────

/// Per-context priority class.  Lower numeric ⇒ higher scheduling
/// preference.  Matches Linux's `DRM_SCHED_PRIORITY_*` ordering.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Priority {
    /// Kernel-internal high (compositor / display).
    High = 0,
    /// Normal — default for userspace.
    Normal = 1,
    /// Low — background / batch.
    Low = 2,
    /// Min — only runs when nothing else can.
    Min = 3,
}

// ── JobFence ───────────────────────────────────────────────────────────

/// Output fence a job exposes to consumers.
///
/// Set unsignalled at queue-time; signalled once
/// [`JobPayload::execute`] returns.  Wraps an `AtomicBool` so it can
/// be polled / waited from any thread via [`DmaFence`].
///
/// Linux equivalent: `drm_sched_fence::finished`.
#[derive(Debug)]
pub struct JobFence {
    signalled: AtomicBool,
}

impl JobFence {
    /// Construct an unsignalled job fence.
    pub fn pending() -> Arc<Self> {
        Arc::new(JobFence {
            signalled: AtomicBool::new(false),
        })
    }
}

impl DmaFence for JobFence {
    fn is_signalled(&self) -> bool {
        self.signalled.load(Ordering::Acquire)
    }
    fn wait(&self, _timeout_ns: u64) -> bool {
        // Same constraint as BinaryFence — no kernel wait queue in
        // no_std; consumers poll or yield via the sleep pump.
        self.is_signalled()
    }
    fn signal(&self) {
        self.signalled.store(true, Ordering::Release);
    }
}

// ── JobPayload ─────────────────────────────────────────────────────────

/// Driver-supplied command-buffer payload.
///
/// `execute` runs synchronously when the scheduler picks this job.
/// Real drivers will instead enqueue the pushbuf to a ring and return
/// immediately, letting the hardware fence the JobFence on retire;
/// the trait stays sync so the scheduler core works in either model
/// (sync drivers signal in-place; async drivers signal from their
/// completion IRQ).
///
/// Linux equivalent: `struct drm_sched_backend_ops` `run_job` + `cb`.
pub trait JobPayload: Send + core::fmt::Debug {
    /// Run the command buffer.  After this returns, the scheduler
    /// signals the job's output fence.
    fn execute(&mut self);
}

/// No-op payload — useful for the scheduler smokes.
#[derive(Debug)]
pub struct NoopPayload;
impl JobPayload for NoopPayload {
    fn execute(&mut self) {}
}

// ── Job ────────────────────────────────────────────────────────────────

/// One scheduler job.
///
/// Linux equivalent: `struct drm_sched_job`.
#[derive(Debug)]
pub struct Job {
    /// Fences this job is gated on.  All must be signalled before
    /// `execute` runs.  Linux: `job->dependencies` xarray.
    pub deps_in: Vec<Arc<dyn DmaFence>>,
    /// Fence signalled on retire.  Exposed to consumers (syncobj,
    /// other jobs) via `Arc::clone`.
    pub fence_out: Arc<JobFence>,
    /// Driver pushbuf / IB / class payload.
    pub payload: Box<dyn JobPayload>,
}

impl Job {
    /// `true` once every input dependency has signalled — i.e. the
    /// job is eligible for `execute`.  Linux: drm_sched picks ready
    /// jobs based on `drm_sched_entity_is_ready`.
    pub fn is_ready(&self) -> bool {
        self.deps_in.iter().all(|f| f.is_signalled())
    }
}

// ── SchedContext ───────────────────────────────────────────────────────

/// Per-{client, engine} queue.
///
/// Linux equivalent: `struct drm_sched_entity`.
#[derive(Debug)]
pub struct SchedContext {
    /// Context id assigned at register-time.
    pub id: u32,
    /// Scheduling class.
    pub priority: Priority,
    /// FIFO of jobs awaiting execution.
    pub jobs: VecDeque<Job>,
}

impl SchedContext {
    /// New empty context with the given priority.
    pub fn new(id: u32, priority: Priority) -> Self {
        SchedContext {
            id,
            priority,
            jobs: VecDeque::new(),
        }
    }

    /// Front-of-queue job is ready to run?
    pub fn front_is_ready(&self) -> bool {
        self.jobs.front().is_some_and(|j| j.is_ready())
    }

    /// Number of queued jobs.
    pub fn pending(&self) -> usize {
        self.jobs.len()
    }
}

// ── Sched ──────────────────────────────────────────────────────────────

/// Per-engine GPU scheduler.
///
/// Linux equivalent: `struct drm_gpu_scheduler`.
#[derive(Debug, Default)]
pub struct Sched {
    /// Round-robin context list.  Replaces Linux's per-priority
    /// run-queues with a single list scanned in priority order.
    pub contexts: Vec<SchedContext>,
    /// Maximum jobs queued per context — Linux uses an unbounded
    /// xarray; we cap conservatively so misbehaving clients can't
    /// exhaust kernel memory.
    pub queue_cap: usize,
    /// Next context id.
    next_ctx_id: u32,
    /// Round-robin cursor — last context that ran.  Selection skips
    /// past this index modulo `contexts.len()` to provide fairness
    /// within a priority class.
    rr_cursor: usize,
}

impl Sched {
    /// New scheduler.
    pub fn new() -> Self {
        Sched {
            contexts: Vec::new(),
            queue_cap: 1024,
            next_ctx_id: 1,
            rr_cursor: 0,
        }
    }

    /// Register a new context with the given priority.
    ///
    /// Returns the context id.  Linux equivalent:
    /// `drm_sched_entity_init`.
    pub fn add_context(&mut self, priority: Priority) -> u32 {
        let id = self.next_ctx_id;
        self.next_ctx_id = self.next_ctx_id.wrapping_add(1).max(1);
        self.contexts.push(SchedContext::new(id, priority));
        id
    }

    /// Remove a context.  Drops every queued job (Linux:
    /// `drm_sched_entity_fini` waits for drain; we expose drain
    /// separately so this matches a "force-fini").
    pub fn remove_context(&mut self, id: u32) -> Result<(), SchedError> {
        let pos = self
            .contexts
            .iter()
            .position(|c| c.id == id)
            .ok_or(SchedError::NoContext)?;
        self.contexts.remove(pos);
        if self.rr_cursor >= self.contexts.len() && !self.contexts.is_empty() {
            self.rr_cursor %= self.contexts.len();
        }
        Ok(())
    }

    /// Submit a job to a context's queue.
    ///
    /// Linux equivalent: `drm_sched_entity_push_job`.
    pub fn submit(
        &mut self,
        ctx_id: u32,
        deps_in: Vec<Arc<dyn DmaFence>>,
        payload: Box<dyn JobPayload>,
    ) -> Result<Arc<JobFence>, SchedError> {
        let cap = self.queue_cap;
        let ctx = self
            .contexts
            .iter_mut()
            .find(|c| c.id == ctx_id)
            .ok_or(SchedError::NoContext)?;
        if ctx.jobs.len() >= cap {
            return Err(SchedError::QueueFull);
        }
        let fence_out = JobFence::pending();
        let job = Job {
            deps_in,
            fence_out: fence_out.clone(),
            payload,
        };
        ctx.jobs.push_back(job);
        Ok(fence_out)
    }

    /// Pick the next runnable job, run it, signal its fence.
    ///
    /// Strategy mirrors Linux's `drm_sched_select_entity` priority
    /// scan + round-robin within a priority class.  Returns the id of
    /// the context that ran, or `NotRunnable` if no context has a
    /// front-of-queue job whose dependencies are satisfied.
    ///
    /// Linux equivalent: one iteration of `drm_sched_main`.
    pub fn tick(&mut self) -> Result<u32, SchedError> {
        if self.contexts.is_empty() {
            return Err(SchedError::NotRunnable);
        }
        // Find highest-priority class with at least one ready front.
        let mut chosen: Option<usize> = None;
        let mut best_prio = Priority::Min;
        for offset in 0..self.contexts.len() {
            let idx = (self.rr_cursor + offset) % self.contexts.len();
            if self.contexts[idx].front_is_ready() {
                let p = self.contexts[idx].priority;
                if chosen.is_none() || p < best_prio {
                    chosen = Some(idx);
                    best_prio = p;
                    if p == Priority::High {
                        break;
                    } // can't beat High
                }
            }
        }
        let idx = chosen.ok_or(SchedError::NotRunnable)?;
        let mut job = self.contexts[idx]
            .jobs
            .pop_front()
            .expect("front_is_ready guarantees pop_front");
        // Advance the cursor past the chosen context so the next tick
        // is biased away from the same context (fairness).
        self.rr_cursor = (idx + 1) % self.contexts.len();
        let ctx_id = self.contexts[idx].id;
        // Run the payload synchronously, then signal the output
        // fence.  An async driver would instead enqueue to its
        // pushbuf and signal from its retirement IRQ.
        job.payload.execute();
        job.fence_out.signal();
        Ok(ctx_id)
    }

    /// Run `tick` until no contexts have ready jobs.  Returns the
    /// number of jobs actually executed.
    pub fn drain(&mut self) -> usize {
        let mut n = 0usize;
        while self.tick().is_ok() {
            n += 1;
        }
        n
    }

    /// Total queued-but-not-yet-executed jobs across all contexts.
    pub fn pending(&self) -> usize {
        self.contexts.iter().map(|c| c.pending()).sum()
    }
}
