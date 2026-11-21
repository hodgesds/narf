//! Soft- and hard-lockup decisions (Linux `kernel/watchdog.c`,
//! `kernel/watchdog_buddy.c`), kept apart from the state they judge so the
//! timer-tick watchdog that samples that state only has to sample and print.
//!
//! Linux's model, and how NARF's state maps onto it:
//!
//! * **Soft lockup** — a CPU that has not scheduled for
//!   `2 * watchdog_thresh` seconds (`get_softlockup_thresh`). Linux proves a
//!   CPU scheduled by running a stopper thread on it; NARF has the same proof
//!   for free in the executor's per-CPU scheduling-point counter (a dispatch
//!   round started, a polled task returned, a direct task-to-task handoff).
//!   A CPU-bound user task does not stop that counter: every preemption
//!   returns to the executor. A kernel path that never reaches a scheduling
//!   point does.
//! * **Hard lockup** — a CPU whose timer interrupts stopped
//!   (`is_hardlockup`: `hrtimer_interrupts` unchanged). Like Linux's buddy
//!   detector, another CPU does the checking, so the stuck CPU's own
//!   interrupts are not needed. NARF's idle CPUs are tickless and its busy
//!   ones are not, so a CPU counts only while it is awake (not in HLT) and
//!   has neither taken a tick nor scheduled for `watchdog_thresh` seconds.
//! * An idle (halted) CPU is responsive by definition — it sleeps with
//!   interrupts enabled — so halting touches both detectors, as Linux's idle
//!   CPUs are touched by their watchdog hrtimer.
//! * **Executor lockup** — Linux's workqueue watchdog (`wq_watchdog_timer_fn`,
//!   `BUG: workqueue lockup - pool cpus=N ... stuck for Ns!`): work is queued
//!   for a CPU that does not run it. NARF's form is a CPU halted over work
//!   its own idle commit would have refused to halt over (a pending wake or
//!   reschedule request, an undrained wake list, a dispatchable task), with
//!   no scheduling point for `2 * watchdog_thresh`: a wake whose kick never
//!   reached it. The soft and hard detectors cannot see it, since the CPU is
//!   halted.
//!
//! * **Runnable but not dispatched** — Linux's workqueue watchdog again
//!   (`wq_watchdog_timer_fn`, `show_cpu_pool_hog`), at task granularity: a
//!   task that has sat runnable on one CPU (its ready queue, wake inbox or
//!   woken-parked set) for `workqueue.watchdog_thresh` seconds without being
//!   dispatched. The executor-lockup detector judges only halted CPUs and the
//!   run-delay report fires only at dispatch, so a task that never runs on an
//!   awake CPU is seen by neither. [`RunnableWatch`] reports it once per stall.
//!
//! Reports follow Linux: a soft lockup is re-reported every soft threshold
//! while it lasts (`update_report_ts`), a hard lockup once per episode
//! (`watchdog_hardlockup_warned`).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// `watchdog_thresh` default, seconds (`kernel/watchdog.c`).
pub const WATCHDOG_THRESH_SECS: u64 = 10;

/// One CPU as the watchdog sampled it.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuSample {
    /// The CPU is online and its executor has started.
    pub online: bool,
    /// The CPU published that it is halted waiting for an interrupt.
    pub halted: bool,
    /// Scheduling points this CPU's executor has passed (monotonic).
    pub sched_passes: u64,
    /// Timer interrupts this CPU has taken (monotonic).
    pub timer_ticks: u64,
    /// Its executor has work it would not halt over: a pending wake or
    /// reschedule request, an undrained wake list, or a dispatchable task.
    pub runnable: bool,
}

/// A lockup the detector has decided to report.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Lockup {
    /// `BUG: soft lockup - CPU#N stuck for Ss!` — awake, taking interrupts,
    /// not scheduling, for `stuck_ns`.
    Soft {
        /// Time since the CPU last scheduled.
        stuck_ns: u64,
        /// The first report of this episode (later ones repeat it every
        /// soft threshold while the CPU stays stuck).
        first: bool,
    },
    /// `Watchdog detected hard LOCKUP on cpu N` — awake, neither taking
    /// timer interrupts nor scheduling, for `stuck_ns`.
    Hard {
        /// Time since the CPU last took a timer interrupt.
        stuck_ns: u64,
    },
    /// `BUG: executor lockup - CPU#N idle with runnable work for Ns!` —
    /// halted over runnable work, not scheduling, for `stuck_ns` (Linux's
    /// workqueue lockup). Repeated like a soft lockup.
    Stalled {
        /// Time since the CPU last scheduled.
        stuck_ns: u64,
        /// The first report of this episode.
        first: bool,
    },
}

/// Per-CPU detector state: what the last sample saw and since when.
#[derive(Debug)]
pub struct CpuWatch {
    passes: AtomicU64,
    ticks: AtomicU64,
    /// `watchdog_touch_ts`: when the CPU last scheduled (or was touched).
    /// Zero until the first sample.
    pass_ns: AtomicU64,
    /// When the CPU last took a timer interrupt (or was touched).
    tick_ns: AtomicU64,
    /// `watchdog_report_ts`: when this soft-lockup episode was last
    /// reported, zero when not reported.
    soft_report_ns: AtomicU64,
    /// `watchdog_hardlockup_warned`.
    hard_warned: AtomicBool,
}

impl CpuWatch {
    /// Fresh, unsampled state.
    pub const fn new() -> Self {
        Self {
            passes: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            pass_ns: AtomicU64::new(0),
            tick_ns: AtomicU64::new(0),
            soft_report_ns: AtomicU64::new(0),
            hard_warned: AtomicBool::new(false),
        }
    }

    /// `touch_softlockup_watchdog` + `watchdog_hardlockup_touch_cpu`: take
    /// `s` as the new baseline, as of `now_ns`.
    pub fn touch(&self, s: &CpuSample, now_ns: u64) {
        self.passes.store(s.sched_passes, Ordering::Relaxed);
        self.ticks.store(s.timer_ticks, Ordering::Relaxed);
        self.pass_ns.store(now_ns.max(1), Ordering::Relaxed);
        self.tick_ns.store(now_ns.max(1), Ordering::Relaxed);
        self.soft_report_ns.store(0, Ordering::Relaxed);
        self.hard_warned.store(false, Ordering::Relaxed);
    }

    /// Judge one sample taken at `now_ns` against `thresh_ns`
    /// (`watchdog_thresh`; zero disables both detectors, as in Linux).
    /// Callers sample every CPU from one place at a time.
    pub fn observe(&self, s: &CpuSample, now_ns: u64, thresh_ns: u64) -> Option<Lockup> {
        let idle = s.halted && !s.runnable;
        if thresh_ns == 0 || !s.online || idle || self.pass_ns.load(Ordering::Relaxed) == 0 {
            self.touch(s, now_ns);
            return None;
        }
        if s.sched_passes != self.passes.load(Ordering::Relaxed) {
            self.passes.store(s.sched_passes, Ordering::Relaxed);
            self.pass_ns.store(now_ns.max(1), Ordering::Relaxed);
            self.soft_report_ns.store(0, Ordering::Relaxed);
        }
        if s.timer_ticks != self.ticks.load(Ordering::Relaxed) {
            self.ticks.store(s.timer_ticks, Ordering::Relaxed);
            self.tick_ns.store(now_ns.max(1), Ordering::Relaxed);
            self.hard_warned.store(false, Ordering::Relaxed);
        }
        let no_sched = now_ns.saturating_sub(self.pass_ns.load(Ordering::Relaxed));
        if s.halted {
            // Halted over runnable work. A halted CPU is tickless by design,
            // so only the scheduling-point clock judges it.
            self.tick_ns.store(now_ns.max(1), Ordering::Relaxed);
            self.hard_warned.store(false, Ordering::Relaxed);
            return self
                .soft_due(no_sched, now_ns, thresh_ns)
                .map(|(stuck_ns, first)| Lockup::Stalled { stuck_ns, first });
        }
        let no_tick = now_ns.saturating_sub(self.tick_ns.load(Ordering::Relaxed));
        if no_tick >= thresh_ns && no_sched >= thresh_ns {
            if self.hard_warned.swap(true, Ordering::Relaxed) {
                return None;
            }
            return Some(Lockup::Hard { stuck_ns: no_tick });
        }
        self.soft_due(no_sched, now_ns, thresh_ns)
            .map(|(stuck_ns, first)| Lockup::Soft { stuck_ns, first })
    }

    /// The soft-threshold cadence (`2 * thresh`, then every `2 * thresh`
    /// while the episode lasts): `(stuck_ns, first)` when a report is due.
    fn soft_due(&self, no_sched: u64, now_ns: u64, thresh_ns: u64) -> Option<(u64, bool)> {
        let soft_thresh = thresh_ns.saturating_mul(2);
        if no_sched < soft_thresh {
            return None;
        }
        let reported = self.soft_report_ns.load(Ordering::Relaxed);
        if reported != 0 && now_ns.saturating_sub(reported) < soft_thresh {
            return None;
        }
        self.soft_report_ns.store(now_ns.max(1), Ordering::Relaxed);
        Some((no_sched, reported == 0))
    }
}

impl Default for CpuWatch {
    fn default() -> Self {
        Self::new()
    }
}

/// The detector for every CPU plus the checker's own cadence.
#[derive(Debug)]
pub struct LockupWatch<const CPUS: usize> {
    cpus: [CpuWatch; CPUS],
    last_check_ns: AtomicU64,
}

impl<const CPUS: usize> LockupWatch<CPUS> {
    /// Fresh, unsampled state.
    pub const fn new() -> Self {
        Self {
            cpus: [const { CpuWatch::new() }; CPUS],
            last_check_ns: AtomicU64::new(0),
        }
    }

    /// Start a check round at `now_ns`. Returns `false` when the previous
    /// round was more than a soft threshold ago: the system did not run the
    /// checker at all (suspended, or a stopped virtual machine — Linux's
    /// `kvm_check_and_clear_guest_paused`), so elapsed time says nothing
    /// about any CPU. Every CPU is then re-baselined by its next
    /// [`Self::observe`] instead of judged. A soft-locked CPU takes ticks
    /// and runs the checker itself, so a gap that long never hides one.
    pub fn begin_round(&self, now_ns: u64, thresh_ns: u64) -> bool {
        let last = self.last_check_ns.swap(now_ns.max(1), Ordering::Relaxed);
        if last != 0 && now_ns.saturating_sub(last) > thresh_ns.saturating_mul(2) {
            for c in &self.cpus {
                c.pass_ns.store(0, Ordering::Relaxed);
            }
            return false;
        }
        true
    }

    /// [`CpuWatch::observe`] for `cpu` (`None` beyond `CPUS`).
    pub fn observe(
        &self,
        cpu: usize,
        s: &CpuSample,
        now_ns: u64,
        thresh_ns: u64,
    ) -> Option<Lockup> {
        self.cpus.get(cpu)?.observe(s, now_ns, thresh_ns)
    }
}

impl<const CPUS: usize> Default for LockupWatch<CPUS> {
    fn default() -> Self {
        Self::new()
    }
}

// ── runnable-but-not-dispatched (Linux `wq_watchdog_timer_fn`) ──────────

/// Default for `workqueue.watchdog_thresh`, seconds: how long a task may
/// sit runnable on a CPU without being dispatched before it is reported.
/// Linux's workqueue default is 30 s; NARF's executor dispatches every
/// runnable task within a scheduling round, so a third of that is already
/// a stall.
pub const RUNNABLE_THRESH_SECS: u64 = 10;

/// One CPU's oldest runnable-but-not-dispatched task, as sampled.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RunnableSample {
    /// The task's scheduler id.
    pub task: u64,
    /// When it became runnable without running since, on the same clock
    /// as the `now` and `thresh` it is judged against (the caller's choice:
    /// the scheduler stamps cycles). Zero is never a valid stamp.
    pub since: u64,
}

#[derive(Debug)]
struct RunnableCpu {
    task: AtomicU64,
    since: AtomicU64,
    reported: AtomicBool,
}

impl RunnableCpu {
    const fn new() -> Self {
        Self {
            task: AtomicU64::new(0),
            since: AtomicU64::new(0),
            reported: AtomicBool::new(false),
        }
    }

    fn clear(&self) {
        self.task.store(0, Ordering::Relaxed);
        self.since.store(0, Ordering::Relaxed);
        self.reported.store(false, Ordering::Relaxed);
    }
}

/// Per-CPU state of the runnable-task watchdog: which stall each CPU was
/// last seen in and whether it has been reported.
///
/// A stall is one task runnable since one instant. It is reported once,
/// when it has lasted the threshold and was already seen, unchanged, by the
/// previous round: a single sample can catch a wake between setting its
/// task's runnable bit and stamping the time, so one sighting is never
/// enough. The task running (the CPU's oldest runnable task or its stamp
/// changing) ends the stall; a later one is reported again.
#[derive(Debug)]
pub struct RunnableWatch<const CPUS: usize> {
    cpus: [RunnableCpu; CPUS],
}

impl<const CPUS: usize> RunnableWatch<CPUS> {
    /// Fresh state: nothing seen.
    pub const fn new() -> Self {
        Self {
            cpus: [const { RunnableCpu::new() }; CPUS],
        }
    }

    /// Judge `cpu`'s oldest runnable task `sample` (`None`: nothing
    /// runnable is waiting) at `now` against `thresh`
    /// (`workqueue.watchdog_thresh`; zero disables), all on one clock.
    /// Returns how long the task has waited when this stall is due its one
    /// report.
    pub fn observe(
        &self,
        cpu: usize,
        sample: Option<RunnableSample>,
        now: u64,
        thresh: u64,
    ) -> Option<u64> {
        let c = self.cpus.get(cpu)?;
        let Some(s) = sample.filter(|s| thresh != 0 && s.since != 0) else {
            c.clear();
            return None;
        };
        if c.task.load(Ordering::Relaxed) != s.task || c.since.load(Ordering::Relaxed) != s.since {
            c.task.store(s.task, Ordering::Relaxed);
            c.since.store(s.since, Ordering::Relaxed);
            c.reported.store(false, Ordering::Relaxed);
            return None;
        }
        let waited = now.saturating_sub(s.since);
        if waited < thresh || c.reported.swap(true, Ordering::Relaxed) {
            return None;
        }
        Some(waited)
    }
}

impl<const CPUS: usize> Default for RunnableWatch<CPUS> {
    fn default() -> Self {
        Self::new()
    }
}

// ── per-CPU hard-IRQ share ──────────────────────────────────────────────

/// Vectors an [`IrqShare`] keeps, busiest first.
pub const IRQ_TOP_N: usize = 3;

/// One CPU's interrupts over one watchdog window: how many, and the
/// busiest vectors. Built by [`Self::add`]ing each vector's count; no
/// allocation, so the timer interrupt can build it.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IrqShare {
    /// Interrupts of every vector in the window.
    pub total: u64,
    /// `(vector, count)`, busiest first; unused entries have count 0.
    pub top: [(u8, u64); IRQ_TOP_N],
}

impl IrqShare {
    /// Count `count` interrupts of `vector`.
    pub fn add(&mut self, vector: u8, count: u64) {
        if count == 0 {
            return;
        }
        self.total = self.total.saturating_add(count);
        let Some(at) = self.top.iter().position(|&(_, c)| count > c) else {
            return;
        };
        self.top.copy_within(at..IRQ_TOP_N - 1, at + 1);
        self.top[at] = (vector, count);
    }

    /// The busiest vector, if any interrupt was counted.
    pub fn busiest(&self) -> Option<(u8, u64)> {
        Some(self.top[0]).filter(|&(_, c)| c != 0)
    }
}

/// `count` events over `elapsed_ns` as a rate per second (0 for an empty
/// window).
pub fn per_sec(count: u64, elapsed_ns: u64) -> u64 {
    if elapsed_ns == 0 {
        return 0;
    }
    ((count as u128 * 1_000_000_000) / elapsed_ns as u128).min(u64::MAX as u128) as u64
}

/// `part` of `whole` in tenths of a percent, capped at 1000.
pub fn permille(part: u64, whole: u64) -> u64 {
    if whole == 0 {
        return 0;
    }
    ((part as u128 * 1000) / whole as u128).min(1000) as u64
}
