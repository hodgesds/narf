//! narf-scheduler — cooperative async executor.
//!
//! Spec: `scheduler/specification/spec.md`. Stage-1 subset per STAGE1.md
//! #10: single-CPU cooperative executor, intrusive-esque ready queue,
//! `spawn`, `yield_now`, `block_on`, no preemption.
//!
//! Non-goals for Stage 1:
//! - Direct context transfer (Stage 3).
//! - Work stealing / multi-CPU (Stage 2).
//! - PKRS save/restore at yield points (Stage 2; Stage 1 has one domain).
//! - CPU budgets / affinities (Stage 2).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::future::Future;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use narf_lib::sync::IrqSafeSpinLock;

/// A pinned boxed future representing one kernel task.
type Task = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Ready queue of runnable tasks. Stage 1 uses `VecDeque` for FIFO
/// fairness; Wave 2 upgrades to the intrusive doubly-linked structure
/// in `narf_lib::IntrusiveList` so spawn is allocation-free for the
/// queue itself (tasks are still boxed).
static READY: IrqSafeSpinLock<Option<VecDeque<TaskSlot>>> = IrqSafeSpinLock::new(None);

struct TaskSlot {
    task: Task,
    // Per-task "needs-repoll" flag set by the waker. When false we can
    // suspend (future waker machinery) and skip the poll this round.
    awake: AtomicBool,
}

impl core::fmt::Debug for TaskSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TaskSlot")
            .field("awake", &self.awake.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Call once at boot before spawning anything. Wave 2 promotes this to a
/// per-CPU `Executor` struct; Stage 1 is single-CPU so a global works.
pub fn init() {
    let mut q = READY.lock();
    *q = Some(VecDeque::new());
}

/// Queue a new task on the ready queue. Requires `init()` to have run.
pub fn spawn<F: Future<Output = ()> + Send + 'static>(f: F) {
    let slot = TaskSlot {
        task:  Box::pin(f),
        awake: AtomicBool::new(true),
    };
    let mut q = READY.lock();
    q.as_mut().expect("scheduler::spawn before init").push_back(slot);
}

// ── Waker plumbing ──────────────────────────────────────────────────
//
// Stage 1 uses a no-op waker: every Pending task just gets repolled next
// round. A proper wake_by_ref() that flips the per-task `awake` flag
// lands once we have a stable pointer from the poll cycle into the slot.

const NOOP_VTABLE: RawWakerVTable = RawWakerVTable::new(
    |_| RawWaker::new(ptr::null(), &NOOP_VTABLE),   // clone
    |_| {},                                          // wake (by value)
    |_| {},                                          // wake by ref
    |_| {},                                          // drop
);

fn noop_waker() -> Waker {
    // SAFETY: vtable functions are all no-ops over a null data pointer.
    unsafe { Waker::from_raw(RawWaker::new(ptr::null(), &NOOP_VTABLE)) }
}

/// Run the ready queue until it's empty.
///
/// Strategy: round through every task in the queue, polling each once.
/// After a full round where **no** task went `Ready`, halt the CPU via
/// `arch::halt_until_irq` — an external interrupt (timer or otherwise)
/// will wake us, and the next round of polling either makes progress
/// (some task's deadline met, waker fired) or we halt again.
///
/// This replaces the Stage-1 busy-poll that spin-checked `Instant::now`
/// every iteration. Saves massive CPU when all tasks are sleeping.
/// Correctness-preserving because our Futures are self-propelling
/// (they check the clock on poll, so spurious wake-ups are harmless).
pub fn run_until_empty() {
    let waker = noop_waker();
    let mut ctx = Context::from_waker(&waker);
    loop {
        // Snapshot queue length. We'll poll each task at most once per
        // round; spawns during the round land at the back and get
        // polled on the NEXT round.
        let round_len = {
            let q = READY.lock();
            q.as_ref().expect("scheduler::run_until_empty before init").len()
        };
        if round_len == 0 { return; }

        let mut ready_this_round: usize = 0;

        for _ in 0..round_len {
            // Pop; if empty, break (can happen if a task was cancelled).
            let mut slot = {
                let mut q = READY.lock();
                match q.as_mut().unwrap().pop_front() {
                    Some(t) => t,
                    None    => break,
                }
            };

            slot.awake.store(false, Ordering::Relaxed);
            let poll_result = slot.task.as_mut().poll(&mut ctx);

            match poll_result {
                Poll::Ready(()) => { ready_this_round += 1; /* drop slot */ }
                Poll::Pending   => {
                    let mut q = READY.lock();
                    q.as_mut().unwrap().push_back(slot);
                }
            }
        }

        // If we made no progress this round, halt until an IRQ wakes
        // us. With the LAPIC timer live (narf-interrupts), this saves
        // the CPU from spin-polling `Instant::now` tens of thousands
        // of times between tick deadlines.
        if ready_this_round == 0 {
            narf_arch::halt_until_irq();
        }
    }
}

/// Tiny convenience: Future that returns Pending once, then Ready.
/// `block_on`-equivalent `yield` point for cooperative tasks that just
/// want to give the executor a chance to run peers.
#[derive(Debug)]
pub struct YieldNow { yielded: bool }

impl Future for YieldNow {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.yielded { Poll::Ready(()) }
        else {
            this.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

pub fn yield_now() -> YieldNow { YieldNow { yielded: false } }
