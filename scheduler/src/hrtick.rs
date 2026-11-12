//! High-resolution tick (Linux `CONFIG_SCHED_HRTICK`): a per-task one-shot
//! slice timer, so a running task is preempted PRECISELY when its slice is
//! exhausted instead of at the next coarse periodic tick.
//!
//! As in Linux (`rq->hrtick_timer`), each CPU owns one pinned hard-IRQ
//! hrtimer. At each slice start ([`crate::stackful::stamp_slice_start`]) the
//! running task's slice deadline (`tsc_started + slice_cycles`) re-arms it on
//! this CPU's hrtimer base, which programs the local clockevent. Its expiry
//! callback (`hrtick`) reschedules the CPU, and `try_preempt` in that IRQ's
//! tail preempts.
//!
//! Feature-gated (`hrtick`): none of this compiles into the default kernel.
//! Allocation-free: the timers are statics.

use narf_lib::percpu::MAX_CPUS;
use narf_time::hrtimer::{self, ClockId, HrTimer, HrtimerMode, HrtimerRestart};

/// One CPU's slice timer (`rq->hrtick_timer`).
#[repr(C)]
struct HrTick {
    timer: HrTimer,
    cpu: u32,
}

impl HrTick {
    const fn new(cpu: u32) -> Self {
        Self {
            timer: HrTimer::new(hrtick, ClockId::Monotonic, HrtimerMode::ABS_HARD),
            cpu,
        }
    }
}

static HRTICK: [HrTick; MAX_CPUS] = {
    let mut a = [const { HrTick::new(0) }; MAX_CPUS];
    let mut i = 0;
    while i < MAX_CPUS {
        a[i] = HrTick::new(i as u32);
        i += 1;
    }
    a
};

/// A slice at or above this is treated as "infinite" (non-preemptible tasks set
/// `u64::MAX / 2`); arming a timer ~quarter-of-forever out is pointless, so we
/// skip it and disarm any stale entry instead.
const INFINITE_SLICE: u64 = u64::MAX / 4;

/// (Re)arm the running task's one-shot slice timer on `cpu` (the calling
/// CPU). `now` is the freshly stamped `tsc_started`; `slice` is the task's
/// `slice_cycles`, both TSC cycles.
pub(crate) fn arm(cpu: usize, now: u64, slice: u64) {
    if cpu >= MAX_CPUS {
        return;
    }
    if slice >= INFINITE_SLICE {
        disarm(cpu);
        return;
    }
    let deadline = narf_time::deadline_cycles_to_ns(now.saturating_add(slice));
    // SAFETY: the timer is a static, so it never moves or is freed.
    unsafe {
        hrtimer::hrtimer_start_range_ns(&HRTICK[cpu].timer, deadline, 0, HrtimerMode::ABS_PINNED)
    };
}

/// Drop this CPU's armed slice timer, if any (voluntary path / infinite slice).
/// A callback already running is left to finish; it only reschedules.
pub(crate) fn disarm(cpu: usize) {
    if cpu >= MAX_CPUS {
        return;
    }
    let _ = hrtimer::hrtimer_try_to_cancel(&HRTICK[cpu].timer);
}

/// Whether `cpu` currently holds an armed slice timer (test support).
pub(crate) fn is_armed(cpu: usize) -> bool {
    cpu < MAX_CPUS && HRTICK[cpu].timer.is_queued()
}

/// `hrtick()`: the slice expired; reschedule the timer's CPU. The timer is
/// pinned, so this normally runs on that CPU; a broadcast expiry (HPET
/// fallback) may run it elsewhere, which forces a reschedule IPI.
fn hrtick(t: &HrTimer) -> HrtimerRestart {
    // SAFETY: only `HrTick` timers use this callback, and `timer` is the
    // first field of the repr(C) struct (`container_of`).
    let cpu = unsafe { (*(t as *const HrTimer as *const HrTick)).cpu };
    reschedule(cpu);
    HrtimerRestart::NoRestart
}

fn reschedule(cpu: u32) {
    if cpu as usize >= MAX_CPUS {
        return;
    }
    if cpu == narf_lib::percpu::current_cpu() as u32 {
        crate::resched_current();
    } else {
        crate::resched_remote_force(cpu);
    }
}
