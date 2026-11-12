//! Timer migration — Linux `kernel/time/timer_migration.c` (tmigr), one
//! group.
//!
//! An idle CPU (tickless, `tmigr_cpu_deactivate`) stops waking for its own
//! `BASE_GLOBAL` timers: an active CPU of the group expires them remotely
//! from its timer softirq (`tmigr_handle_remote` → `timer_expire_remote`).
//! When the last CPU goes idle it becomes the group's migrator and programs
//! its clockevent for the earliest global timer of every idle CPU, so global
//! timers are still never late; pinned (`BASE_LOCAL`) timers always wake
//! their own CPU. Linux builds a hierarchy of groups of eight; NARF's CPU
//! count fits one group, so the hierarchy is a single level.
//!
//! State is one idle bitmap. A CPU sets its bit before it computes its next
//! event and clears it on idle exit, both with SeqCst, so of two CPUs going
//! idle together at least the later one sees the other idle and covers both
//! (an extra wake at worst, never a lost timer).

use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::percpu::MAX_CPUS;

/// Bit `n` set ⇒ CPU `n` is idle (deactivated).
static IDLE: AtomicU64 = AtomicU64::new(0);

#[inline]
fn this_cpu() -> usize {
    narf_lib::percpu::current_cpu().min(MAX_CPUS - 1)
}

/// `tmigr_cpu_deactivate`: this CPU enters tickless idle.
pub fn tmigr_cpu_deactivate() {
    IDLE.fetch_or(1 << this_cpu(), Ordering::SeqCst);
}

/// `tmigr_cpu_activate`: this CPU leaves idle.
pub fn tmigr_cpu_activate() {
    let bit = 1u64 << this_cpu();
    if IDLE.load(Ordering::Relaxed) & bit != 0 {
        IDLE.fetch_and(!bit, Ordering::SeqCst);
    }
}

/// Whether `cpu` is active (not in tickless idle).
#[inline]
pub fn cpu_active(cpu: usize) -> bool {
    IDLE.load(Ordering::SeqCst) & (1 << cpu.min(MAX_CPUS - 1)) == 0
}

/// Earliest GLOBAL expiry (jiffies) among idle online CPUs other than `me`.
fn idle_global_min(me: usize) -> u64 {
    let mut idle = IDLE.load(Ordering::SeqCst) & narf_lib::smp::online_bitmap() & !(1 << me);
    let mut min = u64::MAX;
    while idle != 0 {
        let cpu = idle.trailing_zeros() as usize;
        idle &= idle - 1;
        min = min.min(crate::timer::global_next(cpu));
    }
    min
}

/// The GLOBAL-timer part of `cpu`'s next event (jiffies; `u64::MAX` none),
/// for `get_next_timer_interrupt`:
/// - active: its own global timers and the idle CPUs' it may have to run;
/// - idle with another CPU active: none (that CPU runs them);
/// - idle and last (the migrator): every idle CPU's, its own included.
pub fn global_next_for(cpu: usize) -> u64 {
    let own = crate::timer::global_next(cpu);
    if !cpu_active(cpu) {
        let active = narf_lib::smp::online_bitmap() & !IDLE.load(Ordering::SeqCst);
        if active & !(1 << cpu) != 0 {
            return u64::MAX;
        }
    }
    own.min(idle_global_min(cpu))
}

/// `tmigr_handle_remote`: run every idle CPU's due GLOBAL timers here.
/// Executor context. Returns callbacks run.
pub(crate) fn handle_remote() -> u64 {
    let me = this_cpu();
    let now = crate::timer::jiffies();
    let mut idle = IDLE.load(Ordering::SeqCst) & !(1 << me);
    let mut ran = 0;
    while idle != 0 {
        let cpu = idle.trailing_zeros() as usize;
        idle &= idle - 1;
        if crate::timer::global_next(cpu) <= now {
            ran += crate::timer::expire_remote_global(cpu);
        }
    }
    ran
}

/// Test-only: the idle bitmap.
#[doc(hidden)]
pub fn __test_idle_mask() -> u64 {
    IDLE.load(Ordering::SeqCst)
}
