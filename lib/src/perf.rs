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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

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
    /// Scheduler switches out of a task on this CPU
    /// (`PERF_COUNT_SW_CONTEXT_SWITCHES`).
    ctx_switches: AtomicU64,
    /// Tasks whose switch-in landed on this CPU after last running elsewhere
    /// (`PERF_COUNT_SW_CPU_MIGRATIONS`).
    migrations: AtomicU64,
    /// Faults resolved without I/O (`PERF_COUNT_SW_PAGE_FAULTS_MIN`).
    faults_min: AtomicU64,
    /// Faults resolved with I/O (`PERF_COUNT_SW_PAGE_FAULTS_MAJ`).
    faults_maj: AtomicU64,
    /// Alignment faults (`PERF_COUNT_SW_ALIGNMENT_FAULTS`).
    align_faults: AtomicU64,
    /// Emulated instructions (`PERF_COUNT_SW_EMULATION_FAULTS`). No
    /// instruction-emulation path exists in the tree yet, so this stays zero
    /// until one lands — it is never estimated.
    emul_faults: AtomicU64,
    /// Tasks moved to a different cgroup (`PERF_COUNT_SW_CGROUP_SWITCHES`).
    cgroup_switches: AtomicU64,
}

impl PerCpu {
    const fn new() -> Self {
        Self {
            ctx: AtomicU64::new(0),
            syscalls: AtomicU64::new(0),
            page_faults: AtomicU64::new(0),
            user_ticks: AtomicU64::new(0),
            kernel_ticks: AtomicU64::new(0),
            ctx_switches: AtomicU64::new(0),
            migrations: AtomicU64::new(0),
            faults_min: AtomicU64::new(0),
            faults_maj: AtomicU64::new(0),
            align_faults: AtomicU64::new(0),
            emul_faults: AtomicU64::new(0),
            cgroup_switches: AtomicU64::new(0),
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

/// Linux `PERF_COUNT_SW_*` config values for the software events this module
/// counts (`compat/linux-perf-uapi/src/lib.rs:40-51`, mirroring
/// `include/uapi/linux/perf_event.h`). `narf-lib` does not depend on the uapi
/// crate, so the values are repeated here — keep them in sync with that file.
pub const SW_PAGE_FAULTS: u64 = 2;
pub const SW_CONTEXT_SWITCHES: u64 = 3;
pub const SW_CPU_MIGRATIONS: u64 = 4;
pub const SW_PAGE_FAULTS_MIN: u64 = 5;
pub const SW_PAGE_FAULTS_MAJ: u64 = 6;
pub const SW_ALIGNMENT_FAULTS: u64 = 7;
pub const SW_EMULATION_FAULTS: u64 = 8;
pub const SW_CGROUP_SWITCHES: u64 = 11;

/// Task-attribution hook for software events, mirroring the scheduler's
/// `USER_PERF_SWITCH_HOOK`: the userspace perf registry installs
/// `perf_event::note_task_sw_event` at `install_user_task_hooks()`, and any
/// crate that observes a countable phenomenon calls [`note_sw_event`].
/// A hook that is never installed (unit tests, pre-userspace boot) simply
/// leaves task-bound attribution off; the per-CPU counters still move.
static SW_EVENT_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the task-attribution hook for [`note_sw_event`]. Only the
/// userspace perf registry calls this, once, at boot.
pub fn set_sw_event_hook(hook: fn(u64, usize, u64)) {
    SW_EVENT_HOOK.store(hook as usize, Ordering::Release);
}

/// Count one occurrence of software event `config` for `task` on the current
/// CPU: the per-CPU counter moves (the CPU-wide read), and the installed hook
/// attributes it to the task-bound events tracking `task` (the task-bound
/// read). Free when not attached — the `enabled()` gate is the same one the
/// `page_fault()`/`ctx_switch()` bumps use, so counters only run while a
/// perf event is live and reads subtract their enable-time base.
///
/// `config` must be one of the `SW_*` constants above; anything else is
/// ignored (no counter exists for it). `task` is a scheduler TaskId; a
/// `TaskId::NONE` (0) occurrence still moves the per-CPU counter but
/// attributes to no task.
#[inline]
pub fn note_sw_event(task: u64, config: u64) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let cpu = current_cpu();
    let p = &COUNTERS[if cpu < MAX_CPUS { cpu } else { 0 }];
    let counter = match config {
        SW_PAGE_FAULTS => &p.page_faults,
        SW_CONTEXT_SWITCHES => &p.ctx_switches,
        SW_CPU_MIGRATIONS => &p.migrations,
        SW_PAGE_FAULTS_MIN => &p.faults_min,
        SW_PAGE_FAULTS_MAJ => &p.faults_maj,
        SW_ALIGNMENT_FAULTS => &p.align_faults,
        SW_EMULATION_FAULTS => &p.emul_faults,
        SW_CGROUP_SWITCHES => &p.cgroup_switches,
        _ => return,
    };
    bump(counter);
    let hook = SW_EVENT_HOOK.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only `set_sw_event_hook` writes this slot.
        let hook: fn(u64, usize, u64) = unsafe { core::mem::transmute(hook) };
        hook(task, cpu, config);
    }
}

/// Counters summed across all CPUs (a `perf_events`-style aggregate read).
#[derive(Copy, Clone, Debug, Default)]
pub struct Snapshot {
    pub ctx: u64,
    pub syscalls: u64,
    pub page_faults: u64,
    pub user_ticks: u64,
    pub kernel_ticks: u64,
    pub ctx_switches: u64,
    pub migrations: u64,
    pub faults_min: u64,
    pub faults_maj: u64,
    pub align_faults: u64,
    pub emul_faults: u64,
    pub cgroup_switches: u64,
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
        s.ctx_switches += p.ctx_switches.load(Ordering::Relaxed);
        s.migrations += p.migrations.load(Ordering::Relaxed);
        s.faults_min += p.faults_min.load(Ordering::Relaxed);
        s.faults_maj += p.faults_maj.load(Ordering::Relaxed);
        s.align_faults += p.align_faults.load(Ordering::Relaxed);
        s.emul_faults += p.emul_faults.load(Ordering::Relaxed);
        s.cgroup_switches += p.cgroup_switches.load(Ordering::Relaxed);
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
        ctx_switches: p.ctx_switches.load(Ordering::Relaxed),
        migrations: p.migrations.load(Ordering::Relaxed),
        faults_min: p.faults_min.load(Ordering::Relaxed),
        faults_maj: p.faults_maj.load(Ordering::Relaxed),
        align_faults: p.align_faults.load(Ordering::Relaxed),
        emul_faults: p.emul_faults.load(Ordering::Relaxed),
        cgroup_switches: p.cgroup_switches.load(Ordering::Relaxed),
    }
}

/// One software event's per-CPU value, for a CPU-wide `perf_event` read.
/// Returns 0 for an unknown config (no counter exists for it).
pub fn snapshot_cpu_config(cpu: usize, config: u64) -> u64 {
    let s = snapshot_cpu(cpu);
    match config {
        SW_PAGE_FAULTS => s.page_faults,
        SW_CONTEXT_SWITCHES => s.ctx_switches,
        SW_CPU_MIGRATIONS => s.migrations,
        SW_PAGE_FAULTS_MIN => s.faults_min,
        SW_PAGE_FAULTS_MAJ => s.faults_maj,
        SW_ALIGNMENT_FAULTS => s.align_faults,
        SW_EMULATION_FAULTS => s.emul_faults,
        SW_CGROUP_SWITCHES => s.cgroup_switches,
        _ => 0,
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
