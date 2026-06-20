//! Per-CPU software-event counters (the `perf_events` aggregation model).
//!
//! Each CPU increments its OWN cache-line-padded counter set, so the hot
//! path has zero cross-CPU cache-coherency traffic — unlike a single shared
//! `AtomicU64`, whose line ping-pongs between cores on every increment.
//! Callers sum across CPUs only at read time, via [`snapshot`] — exactly how
//! Linux `perf_events` aggregates per-CPU events.
//!
//! This deliberately lives in `narf-lib`, NOT `narf-scheduler`: adding
//! sizable statics to the scheduler crate shifts its binary layout enough to
//! trip a layout-sensitive task-future/waker vtable corruption (the
//! "marginal-buddy" flake), so profiling state must stay out of it.

use crate::percpu::{current_cpu, MAX_CPUS};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Master gate. When `false` (the default — "not attached"), every
/// tracepoint short-circuits to a single read-mostly load + a predictable
/// not-taken branch — effectively free, so the counters cost nothing in
/// production. A profiler "attaches" by calling [`set_enabled(true)`]. (For
/// TRUE zero — eliding even the load — a static-key/jump-label facility
/// would patch the call sites; this gate is ~99% of the way there cheaply.)
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Attach/detach the profiler (enables/disables all tracepoints).
#[inline]
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// Whether tracepoints are currently counting.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Per-CPU single-writer increment. A plain relaxed load+store (NO `lock`
/// prefix) is sound here — only the owning CPU ever writes its own cell, so
/// there are no lost updates, and cross-CPU reads in [`snapshot`] are
/// relaxed-atomic (racy but well-defined, fine for statistics). ~3 cycles
/// vs a `lock xadd`'s ~30. This is the kernel `this_cpu_inc` pattern.
#[inline]
fn bump(c: &AtomicU64) {
    c.store(c.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
}

/// One CPU's counter set, padded to a 64-byte cache line so a CPU's
/// increments never invalidate a neighbouring CPU's line (no false sharing).
#[repr(align(64))]
struct PerCpu {
    /// Context switches into user mode (a user-task `enter_user_mode*`).
    ctx: AtomicU64,
    /// Syscalls dispatched.
    syscalls: AtomicU64,
    /// Page faults taken.
    page_faults: AtomicU64,
    /// Timer ticks that interrupted user mode (CPL=3).
    user_ticks: AtomicU64,
    /// Timer ticks that interrupted the kernel (CPL=0).
    kernel_ticks: AtomicU64,
}

impl PerCpu {
    const fn new() -> Self {
        Self {
            ctx: AtomicU64::new(0),
            syscalls: AtomicU64::new(0),
            page_faults: AtomicU64::new(0),
            user_ticks: AtomicU64::new(0),
            kernel_ticks: AtomicU64::new(0),
        }
    }
}

static COUNTERS: [PerCpu; MAX_CPUS] = [const { PerCpu::new() }; MAX_CPUS];

#[inline]
fn this() -> &'static PerCpu {
    let c = current_cpu();
    &COUNTERS[if c < MAX_CPUS { c } else { 0 }]
}

/// Record a context switch into user mode. Free when not attached (one
/// read-mostly load + not-taken branch); otherwise a per-CPU `bump`.
#[inline]
pub fn ctx_switch() {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    bump(&this().ctx);
}

/// Record a dispatched syscall.
#[inline]
pub fn syscall() {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    bump(&this().syscalls);
}

/// Record a page fault.
#[inline]
pub fn page_fault() {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    bump(&this().page_faults);
}

/// Record a timer tick, tagged by the interrupted privilege level.
#[inline]
pub fn tick(kernel: bool) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let p = this();
    bump(if kernel {
        &p.kernel_ticks
    } else {
        &p.user_ticks
    });
}

/// Counters summed across all CPUs (a `perf_events`-style aggregate read).
#[derive(Copy, Clone, Debug, Default)]
pub struct Snapshot {
    pub ctx: u64,
    pub syscalls: u64,
    pub page_faults: u64,
    pub user_ticks: u64,
    pub kernel_ticks: u64,
}

/// Sum every CPU's counters into one [`Snapshot`].
pub fn snapshot() -> Snapshot {
    let mut s = Snapshot::default();
    for p in COUNTERS.iter() {
        s.ctx += p.ctx.load(Ordering::Relaxed);
        s.syscalls += p.syscalls.load(Ordering::Relaxed);
        s.page_faults += p.page_faults.load(Ordering::Relaxed);
        s.user_ticks += p.user_ticks.load(Ordering::Relaxed);
        s.kernel_ticks += p.kernel_ticks.load(Ordering::Relaxed);
    }
    s
}

/// One CPU's counters, WITHOUT the cross-CPU sum — for per-core
/// profiling (where is the work landing, and in what mode). A
/// concentrated `syscalls`/`user_ticks` on one core with the rest idle
/// is the signature of a serialization bottleneck the aggregate
/// [`snapshot`] hides.
pub fn snapshot_cpu(cpu: usize) -> Snapshot {
    let p = &COUNTERS[if cpu < MAX_CPUS { cpu } else { 0 }];
    Snapshot {
        ctx: p.ctx.load(Ordering::Relaxed),
        syscalls: p.syscalls.load(Ordering::Relaxed),
        page_faults: p.page_faults.load(Ordering::Relaxed),
        user_ticks: p.user_ticks.load(Ordering::Relaxed),
        kernel_ticks: p.kernel_ticks.load(Ordering::Relaxed),
    }
}

/// Total timer ticks across all CPUs — handy as a periodic-dump cadence.
pub fn total_ticks() -> u64 {
    let mut t = 0u64;
    for p in COUNTERS.iter() {
        t += p.user_ticks.load(Ordering::Relaxed) + p.kernel_ticks.load(Ordering::Relaxed);
    }
    t
}
