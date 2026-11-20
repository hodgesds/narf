//! Kernel CPU statistics shared below the scheduler — Linux
//! `include/linux/kernel_stat.h` (`kstat_softirqs`) and the
//! `rq->nr_iowait` half of `kernel/sched/core.c`.
//!
//! Both families have producers in crates the scheduler depends on (the
//! timer wheel in `time/`, RCU callbacks in `rcu/`, the block adapter in
//! `block/`), so they live here rather than next to the CPU-time accounting
//! that consumes them.
//!
//! # Softirq vectors
//!
//! NARF has no softirq engine. Its deferred-work contexts are mapped onto
//! Linux's vectors so `/proc/softirqs` and the `softirq` line of `/proc/stat`
//! keep their meaning:
//!
//! | Linux vector | NARF context                                               |
//! | ------------ | ---------------------------------------------------------- |
//! | `TIMER`      | timer-wheel expiry (`narf_time::timer::run_timer_softirq`) |
//! | `NET_RX`     | a `WorkKind::SoftIrq` task poll (driver NAPI pollers)      |
//! | `SCHED`      | a policy-requested load-balance migration                  |
//! | `HRTIMER`    | soft hrtimer expiry (`hrtimer_run_softirq`)                |
//! | `RCU`        | an RCU callback batch (`narf_rcu` reclaim)                 |
//! | `HI`, `NET_TX`, `BLOCK`, `IRQ_POLL`, `TASKLET` | no equivalent; stay 0 |
//!
//! A vector is counted once per execution of its handler, as Linux's
//! `handle_softirqs` does, and only when there was work to run.
//!
//! The time spent in a vector's handler is softirq time. The scheduler's
//! CPU-time accounting installs [`set_softirq_time_hooks`]; until it does,
//! [`softirq_enter`] only counts.
//!
//! # I/O wait
//!
//! [`IoWait`] is Linux's `io_schedule()` bracket: a task that blocks while
//! one is armed counts in its CPU's `nr_iowait` until it is woken. Idle time
//! on a CPU with a non-zero `nr_iowait` is iowait (`get_cpu_iowait_time_us`),
//! and the sum is `/proc/stat` `procs_blocked`.

use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};

use crate::percpu::MAX_CPUS;

/// `NR_SOFTIRQS`.
pub const NR_SOFTIRQS: usize = 10;

/// Linux softirq vector numbers (`enum { HI_SOFTIRQ = 0, ... }`).
pub mod vector {
    pub const HI: usize = 0;
    pub const TIMER: usize = 1;
    pub const NET_TX: usize = 2;
    pub const NET_RX: usize = 3;
    pub const BLOCK: usize = 4;
    pub const IRQ_POLL: usize = 5;
    pub const TASKLET: usize = 6;
    pub const SCHED: usize = 7;
    pub const HRTIMER: usize = 8;
    pub const RCU: usize = 9;
}

/// `softirq_to_name[]`, in vector order.
pub const SOFTIRQ_NAMES: [&str; NR_SOFTIRQS] = [
    "HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU",
];

/// One CPU's softirq counters. Cache-line aligned so a CPU incrementing its
/// own counters never shares a line with a neighbour.
#[repr(align(64))]
struct SoftirqCounters([AtomicU64; NR_SOFTIRQS]);

static SOFTIRQS: [SoftirqCounters; MAX_CPUS] =
    [const { SoftirqCounters([const { AtomicU64::new(0) }; NR_SOFTIRQS]) }; MAX_CPUS];

/// `rq->nr_iowait`. Incremented on the CPU a task blocks on and decremented
/// by whichever CPU wakes it, so it is a shared atomic, one line per CPU.
#[repr(align(64))]
struct IoWaitCount(AtomicU64);

static NR_IOWAIT: [IoWaitCount; MAX_CPUS] = [const { IoWaitCount(AtomicU64::new(0)) }; MAX_CPUS];

/// Installed by the scheduler: `enter` returns an opaque token that `exit`
/// consumes. Zero until installed.
static SOFTIRQ_ENTER_HOOK: AtomicUsize = AtomicUsize::new(0);
static SOFTIRQ_EXIT_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the softirq CPU-time hooks (the scheduler's CPU-time accounting).
///
/// Both run with whatever interrupt state the softirq context has and must
/// mask interrupts themselves if they need it; neither may allocate, sleep
/// or take a lock that an interrupt handler takes.
pub fn set_softirq_time_hooks(enter: fn() -> usize, exit: fn(usize)) {
    SOFTIRQ_EXIT_HOOK.store(exit as usize, Ordering::Release);
    SOFTIRQ_ENTER_HOOK.store(enter as usize, Ordering::Release);
}

#[inline]
fn this_cpu() -> usize {
    crate::percpu::current_cpu() % MAX_CPUS
}

/// Count one execution of softirq `vec` on the calling CPU
/// (`kstat_incr_softirqs_this_cpu`). Out-of-range vectors are ignored.
#[inline]
pub fn note_softirq(vec: usize) {
    if let Some(counter) = SOFTIRQS[this_cpu()].0.get(vec) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Executions of softirq `vec` on `cpu` since boot (`kstat_softirqs_cpu`).
pub fn softirq_count(cpu: usize, vec: usize) -> u64 {
    SOFTIRQS
        .get(cpu)
        .and_then(|c| c.0.get(vec))
        .map_or(0, |c| c.load(Ordering::Relaxed))
}

/// A running softirq handler: counted on entry, its CPU time charged to
/// the `softirq` column until it drops. Not `Send`: it must end on the CPU
/// it started on.
#[must_use = "the guard must cover the softirq handler"]
#[derive(Debug)]
pub struct SoftirqGuard {
    token: usize,
    timed: bool,
    _not_send: PhantomData<*mut ()>,
}

/// Begin running softirq `vec`'s handler on this CPU.
#[inline]
pub fn softirq_enter(vec: usize) -> SoftirqGuard {
    note_softirq(vec);
    let enter = SOFTIRQ_ENTER_HOOK.load(Ordering::Acquire);
    if enter == 0 {
        return SoftirqGuard {
            token: 0,
            timed: false,
            _not_send: PhantomData,
        };
    }
    // SAFETY: only `set_softirq_time_hooks` stores this slot, from a
    // `fn() -> usize`, and publishes it with Release.
    let enter: fn() -> usize = unsafe { core::mem::transmute(enter) };
    SoftirqGuard {
        token: enter(),
        timed: true,
        _not_send: PhantomData,
    }
}

impl Drop for SoftirqGuard {
    #[inline]
    fn drop(&mut self) {
        if !self.timed {
            return;
        }
        let exit = SOFTIRQ_EXIT_HOOK.load(Ordering::Acquire);
        if exit != 0 {
            // SAFETY: stored by `set_softirq_time_hooks` from a `fn(usize)`
            // before the enter hook was published.
            let exit: fn(usize) = unsafe { core::mem::transmute(exit) };
            exit(self.token);
        }
    }
}

/// Tasks currently blocked in I/O wait whose wait began on `cpu`
/// (`nr_iowait_cpu`).
pub fn nr_iowait(cpu: usize) -> u64 {
    NR_IOWAIT
        .get(cpu)
        .map_or(0, |c| c.0.load(Ordering::Relaxed))
}

/// Tasks currently blocked in I/O wait, system-wide (`nr_iowait`).
pub fn nr_iowait_total() -> u64 {
    NR_IOWAIT.iter().fold(0u64, |sum, c| {
        sum.saturating_add(c.0.load(Ordering::Relaxed))
    })
}

const NOT_WAITING: usize = usize::MAX;

/// Linux `io_schedule_prepare`/`io_schedule_finish` for one wait.
///
/// [`IoWait::block`] marks the calling CPU as having one more task in I/O
/// wait (idempotent while marked); [`IoWait::wake`] (or drop) removes the
/// mark from the CPU that took it, whichever CPU runs the wake.
#[derive(Debug)]
pub struct IoWait {
    cpu: usize,
}

impl IoWait {
    pub const fn new() -> Self {
        Self { cpu: NOT_WAITING }
    }

    /// The caller is about to block on I/O.
    #[inline]
    pub fn block(&mut self) {
        if self.cpu == NOT_WAITING {
            let cpu = this_cpu();
            NR_IOWAIT[cpu].0.fetch_add(1, Ordering::Relaxed);
            self.cpu = cpu;
        }
    }

    /// The wait is over.
    #[inline]
    pub fn wake(&mut self) {
        if self.cpu != NOT_WAITING {
            NR_IOWAIT[self.cpu].0.fetch_sub(1, Ordering::Relaxed);
            self.cpu = NOT_WAITING;
        }
    }

    /// Whether a block is currently counted.
    pub const fn is_blocked(&self) -> bool {
        self.cpu != NOT_WAITING
    }
}

impl Default for IoWait {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for IoWait {
    fn drop(&mut self) {
        self.wake();
    }
}

/// A future whose `Pending` polls are I/O waits: the polling task counts
/// in `nr_iowait` from its first `Pending` until the inner future completes
/// or is dropped. Wrap the completion of a block request in this, the way
/// Linux brackets `submit_bio_wait` with `io_schedule`.
#[derive(Debug)]
pub struct IoWaitFuture<F> {
    inner: F,
    wait: IoWait,
}

impl<F> IoWaitFuture<F> {
    pub const fn new(inner: F) -> Self {
        Self {
            inner,
            wait: IoWait::new(),
        }
    }
}

impl<F: Future + Unpin> Future for IoWaitFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll(cx) {
            Poll::Ready(value) => {
                this.wait.wake();
                Poll::Ready(value)
            }
            Poll::Pending => {
                this.wait.block();
                Poll::Pending
            }
        }
    }
}

#[cfg(test)]
mod host_tests {
    use super::*;

    #[test]
    fn softirq_names_match_linux_order() {
        assert_eq!(SOFTIRQ_NAMES[vector::HI], "HI");
        assert_eq!(SOFTIRQ_NAMES[vector::TIMER], "TIMER");
        assert_eq!(SOFTIRQ_NAMES[vector::NET_RX], "NET_RX");
        assert_eq!(SOFTIRQ_NAMES[vector::SCHED], "SCHED");
        assert_eq!(SOFTIRQ_NAMES[vector::HRTIMER], "HRTIMER");
        assert_eq!(SOFTIRQ_NAMES[vector::RCU], "RCU");
    }

    #[test]
    fn softirq_enter_counts_without_hooks() {
        let before = softirq_count(0, vector::TASKLET);
        drop(softirq_enter(vector::TASKLET));
        assert_eq!(softirq_count(0, vector::TASKLET), before + 1);
        // Out-of-range vectors are ignored rather than panicking.
        note_softirq(NR_SOFTIRQS);
    }

    #[test]
    fn iowait_is_counted_once_and_released_on_drop() {
        let before = nr_iowait(0);
        let mut wait = IoWait::new();
        wait.block();
        wait.block();
        assert_eq!(nr_iowait(0), before + 1);
        assert!(wait.is_blocked());
        drop(wait);
        assert_eq!(nr_iowait(0), before);
    }
}
