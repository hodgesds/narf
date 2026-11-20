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
