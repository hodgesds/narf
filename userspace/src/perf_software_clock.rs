//! Pinned hrtimer sampling for Linux CPU/task clocks.
//!
//! Timer storage has a stable heap address until synchronous cancellation.
//! Callbacks retain no event pointer or Arc and never take the perf registry
//! lock: only the event ID crosses into the bounded deferred sample queue.

use super::*;
use narf_time::hrtimer::{self, ClockId, HrTimer, HrtimerMode, HrtimerRestart};

const MIN_PERIOD_NS: u64 = 10_000;

pub(super) fn is_clock(attr: &PerfEventAttr) -> bool {
    attr.type_ == PERF_TYPE_SOFTWARE
        && matches!(
            attr.config,
            PERF_COUNT_SW_CPU_CLOCK | PERF_COUNT_SW_TASK_CLOCK
        )
}

pub(super) fn period(attr: &PerfEventAttr) -> u64 {
    let period = if attr.flags & PERF_ATTR_FLAG_FREQ != 0 {
        1_000_000_000 / attr.sample_period_or_freq.max(1)
    } else {
        attr.sample_period_or_freq
    };
    period.max(MIN_PERIOD_NS)
}

#[repr(C)]
struct ClockTimer {
    timer: HrTimer,
    control: IrqSafeSpinLock<()>,
    event_id: u64,
    cpu: usize,
    period: AtomicU64,
    active: AtomicBool,
    task: AtomicU64,
    flags: u64,
    stack_bytes: usize,
}

fn clock_expired(timer: &HrTimer) -> HrtimerRestart {
    // SAFETY: this callback is installed only on the first field of the
    // repr(C) ClockTimer. SoftwareClock::drop cancels before freeing storage.
    let clock = unsafe { &*(timer as *const HrTimer).cast::<ClockTimer>() };
    if !clock.active.load(Ordering::Acquire) {
        return HrtimerRestart::NoRestart;
    }
    let period = clock.period.load(Ordering::Acquire);
    let cpu = narf_lib::percpu::current_cpu();
    let task = clock.task.load(Ordering::Acquire);
    let ip = narf_interrupts::interrupted_ip();
    let user = narf_interrupts::interrupted_user_state().is_some_and(|state| state.user);
    // A broadcast timer or executor-side expiry has no valid interrupted
    // context for a remote CPU. Never attribute its callback IP to the target.
    if cpu == clock.cpu
        && ip != 0
        && (task == u64::MAX || task == current_task_id())
        && if user {
            clock.flags & PERF_ATTR_FLAG_EXCLUDE_USER == 0
        } else {
            clock.flags & PERF_ATTR_FLAG_EXCLUDE_KERNEL == 0
        }
    {
        capture_clock_sample(cpu, clock.event_id, period, clock.stack_bytes);
        queue_sample_drain();
    }
    timer.forward(narf_time::monotonic_ns(), period);
    if clock.active.load(Ordering::Acquire) {
        HrtimerRestart::Restart
    } else {
        HrtimerRestart::NoRestart
    }
}

pub(super) struct SoftwareClock {
    enabled: AtomicBool,
    // Never resized after construction: intrusive hrtimer nodes cannot move.
    timers: Vec<ClockTimer>,
    // Allocated at open/fork, never by a switch or IRQ. A task's remaining
    // interval follows it across CPU migration, independently of descendants.
    remaining: IrqSafeSpinLock<Vec<(u64, u64)>>,
}

impl SoftwareClock {
    pub(super) fn new(id: u64, target: u64, attr: &PerfEventAttr) -> Self {
        let period = period(attr);
        let stack_bytes = if attr.sample_type & PERF_SAMPLE_CALLCHAIN != 0 {
            PERF_MAX_USER_STACK_SAMPLE
        } else {
            attr.sample_stack_user as usize
        };
        let mut timers = Vec::with_capacity(SAMPLE_CPU_SLOTS);
        for cpu in 0..SAMPLE_CPU_SLOTS {
            // Named-CPU starts require an existing base. Prepare it here,
            // where allocation is permitted, including CPUs a task may later
            // migrate to after hotplug; never allocate from a switch or IRQ.
            hrtimer::hrtimers_prepare_cpu(cpu);
            timers.push(ClockTimer {
                timer: HrTimer::new(clock_expired, ClockId::Monotonic, HrtimerMode::REL_HARD),
                control: IrqSafeSpinLock::new(()),
                event_id: id,
                cpu,
                period: AtomicU64::new(period),
                active: AtomicBool::new(false),
                task: AtomicU64::new(u64::MAX),
                flags: attr.flags,
                stack_bytes,
            });
        }
        Self {
            enabled: AtomicBool::new(false),
            timers,
            remaining: IrqSafeSpinLock::new(alloc::vec![(target, period)]),
        }
    }

    pub(super) fn inherit(&self, task: u64) {
        let mut remaining = self.remaining.lock();
        if !remaining.iter().any(|entry| entry.0 == task) {
            remaining.push((task, self.timers[0].period.load(Ordering::Acquire)));
        }
    }

    pub(super) fn retire(&self, task: u64) {
        for (cpu, clock) in self.timers.iter().enumerate() {
            if clock.task.load(Ordering::Acquire) == task {
                self.stop(cpu);
            }
        }
        self.remaining.lock().retain(|entry| entry.0 != task);
    }

    pub(super) fn start(&self, cpu: usize, task: u64) {
        let clock = &self.timers[cpu];
        let _control = clock.control.lock();
        // Disable publishes false before taking any control lock. A switch-in
        // which checked the event before that publication cannot restart a
        // timer after disable has already visited this CPU.
        if !self.enabled.load(Ordering::Acquire) || clock.active.load(Ordering::Acquire) {
            return;
        }
        // A remote disable may have met a running callback. Join it before
        // changing expiry; the callback never takes control or registry locks.
        hrtimer::hrtimer_cancel(&clock.timer);
        let remaining = self.remaining.lock();
        let Some((_, left)) = remaining.iter().find(|entry| entry.0 == task) else {
            return;
        };
        clock.task.store(task, Ordering::Relaxed);
        clock.active.store(true, Ordering::Release);
        // SAFETY: the Vec has its final size and Drop joins all callbacks.
        // This control lock serializes start/stop for the same timer.
        unsafe {
            hrtimer::hrtimer_start_on(
                &clock.timer,
                cpu,
                (*left).max(MIN_PERIOD_NS),
                0,
                HrtimerMode::REL_PINNED.union(HrtimerMode::HARD),
            );
        }
    }

    pub(super) fn stop(&self, cpu: usize) {
        let clock = &self.timers[cpu];
        let _control = clock.control.lock();
        if !clock.active.swap(false, Ordering::AcqRel) {
            return;
        }
        let left = hrtimer::hrtimer_get_remaining(&clock.timer).max(MIN_PERIOD_NS);
        hrtimer::hrtimer_cancel(&clock.timer);
        let task = clock.task.load(Ordering::Acquire);
        if let Some(entry) = self
            .remaining
            .lock()
            .iter_mut()
            .find(|entry| entry.0 == task)
        {
            entry.1 = left;
        }
    }

    pub(super) fn stop_all(&self) {
        for cpu in 0..self.timers.len() {
            self.stop(cpu);
        }
    }

    pub(super) fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    pub(super) fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
        self.stop_all();
    }

    pub(super) fn set_period(&self, period: u64) {
        for clock in &self.timers {
            clock
                .period
                .store(period.max(MIN_PERIOD_NS), Ordering::Release);
        }
        for (_, left) in self.remaining.lock().iter_mut() {
            *left = period.max(MIN_PERIOD_NS);
        }
    }

    #[cfg(feature = "kernel-test")]
    pub(super) fn expire_for_test(&self, cpu: usize) {
        let clock = &self.timers[cpu];
        let _control = clock.control.lock();
        hrtimer::hrtimer_cancel(&clock.timer);
        if clock.active.load(Ordering::Acquire) {
            // SAFETY: same stable storage and control exclusion as start.
            unsafe {
                hrtimer::hrtimer_start_on(
                    &clock.timer,
                    cpu,
                    0,
                    0,
                    HrtimerMode::ABS_PINNED.union(HrtimerMode::HARD),
                );
            }
        }
    }
}

impl Drop for SoftwareClock {
    fn drop(&mut self) {
        self.disable();
        for clock in &self.timers {
            // Also join callbacks which observed active=false during disable.
            hrtimer::hrtimer_cancel(&clock.timer);
        }
    }
}
