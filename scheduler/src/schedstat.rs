//! Linux `/proc/schedstat` (version 17) counters.
//!
//! Linux keeps these in `struct rq` and `struct sched_domain` under
//! `CONFIG_SCHEDSTATS` (`kernel/sched/stats.c:show_schedstat`). NARF keeps one
//! cache line per CPU, written only by that CPU, and derives the rest from
//! counters the scheduler already maintains:
//!
//! | v17 field      | NARF source                                              |
//! |----------------|----------------------------------------------------------|
//! | `yld_count`    | `sched_yield(2)` calls on this CPU                        |
//! | `sched_count`  | scheduling points (`note_sched_pass`)                     |
//! | `sched_goidle` | executor idle entries (Linux: `__schedule` picked idle)   |
//! | `ttwu_count`   | wakeups this CPU performed (Linux counts on `this_rq()`)  |
//! | `ttwu_local`   | of those, wakees placed on this CPU                       |
//! | `rq_cpu_time`  | non-idle accounted time of this CPU, ns                   |
//! | `run_delay`    | wake-to-dispatch time of tasks dispatched here, ns        |
//! | `pcount`       | dispatches (timeslices) on this CPU                       |
//!
//! A wakeup is a task's false→true runnable transition raised by anything
//! other than the task itself: a task re-arming its own waker to stay
//! runnable is not a Linux `try_to_wake_up`.
//!
//! Domain lines report the wake-side domain counters Linux keeps
//! (`ttwu_wake_remote`, `ttwu_move_affine`, `ttwu_move_balance`). NARF has no
//! periodic load balancer with Linux's per-idle-type accounting, so the
//! `lb_*`, `alb_*`, `sbe_*` and `sbf_*` fields are zero.

use core::sync::atomic::{AtomicU64, Ordering};
use narf_lib::percpu::MAX_CPUS;

#[repr(C, align(64))]
struct CpuCounters {
    yld_count: AtomicU64,
    sched_goidle: AtomicU64,
    ttwu_count: AtomicU64,
    ttwu_local: AtomicU64,
    run_delay_cycles: AtomicU64,
    pcount: AtomicU64,
    /// Wakes moved at wake time to the waker's CPU (wake-affine).
    ttwu_move_affine: AtomicU64,
    /// Wakes moved at wake time to another idle CPU (`select_idle_sibling`)
    /// sharing the source's last-level cache, and to one that does not.
    ttwu_move_balance: AtomicU64,
    ttwu_move_balance_far: AtomicU64,
    /// Remote wakes (`ttwu_count - ttwu_local`) whose target shares this
    /// CPU's last-level cache, and those that do not — Linux charges
    /// `ttwu_wake_remote` to the lowest domain spanning both CPUs.
    ttwu_remote_llc: AtomicU64,
    ttwu_remote_far: AtomicU64,
}

impl CpuCounters {
    const fn new() -> Self {
        Self {
            yld_count: AtomicU64::new(0),
            sched_goidle: AtomicU64::new(0),
            ttwu_count: AtomicU64::new(0),
            ttwu_local: AtomicU64::new(0),
            run_delay_cycles: AtomicU64::new(0),
            pcount: AtomicU64::new(0),
            ttwu_move_affine: AtomicU64::new(0),
            ttwu_move_balance: AtomicU64::new(0),
            ttwu_move_balance_far: AtomicU64::new(0),
            ttwu_remote_llc: AtomicU64::new(0),
            ttwu_remote_far: AtomicU64::new(0),
        }
    }
}

const _: () = assert!(core::mem::size_of::<CpuCounters>() == 128);

static COUNTERS: [CpuCounters; MAX_CPUS] = [const { CpuCounters::new() }; MAX_CPUS];

#[inline]
fn local() -> &'static CpuCounters {
    &COUNTERS[narf_lib::percpu::current_cpu().min(MAX_CPUS - 1)]
}

/// `do_sched_yield`: `schedstat_inc(rq->yld_count)`.
#[inline]
pub(crate) fn note_yield() {
    local().yld_count.fetch_add(1, Ordering::Relaxed);
}

/// `__schedule` picked the idle task: this CPU committed to idle.
#[inline]
pub(crate) fn note_goidle() {
    local().sched_goidle.fetch_add(1, Ordering::Relaxed);
}

/// `ttwu_stat`: this CPU woke a task whose run queue is `target`.
#[inline]
pub(crate) fn note_ttwu(target: u32) {
    let counters = local();
    let me = narf_lib::percpu::current_cpu();
    counters.ttwu_count.fetch_add(1, Ordering::Relaxed);
    if target as usize == me {
        counters.ttwu_local.fetch_add(1, Ordering::Relaxed);
    } else if share_llc(me as u32, target) {
        counters.ttwu_remote_llc.fetch_add(1, Ordering::Relaxed);
    } else {
        counters.ttwu_remote_far.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
fn share_llc(a: u32, b: u32) -> bool {
    use crate::affinity::CpuId;
    match (
        crate::steal::llc_id(CpuId(a)),
        crate::steal::llc_id(CpuId(b)),
    ) {
        (Some(x), Some(y)) => x == y,
        _ => true,
    }
}

/// A wake counted by [`note_ttwu`] for `from` was moved at wake time to `to`.
/// `affine` when `to` is the waker's CPU.
#[inline]
pub(crate) fn note_ttwu_move(from: u32, to: u32, affine: bool) {
    let counters = local();
    let me = narf_lib::percpu::current_cpu();
    if affine {
        counters.ttwu_move_affine.fetch_add(1, Ordering::Relaxed);
    } else if share_llc(from, to) {
        counters.ttwu_move_balance.fetch_add(1, Ordering::Relaxed);
    } else {
        counters
            .ttwu_move_balance_far
            .fetch_add(1, Ordering::Relaxed);
    }
    // Keep `ttwu_local` keyed to where the wakee ended up, as Linux's
    // `ttwu_stat` (which runs after `select_task_rq`) does.
    if to as usize == me && from as usize != me {
        counters.ttwu_local.fetch_add(1, Ordering::Relaxed);
    } else if from as usize == me && to as usize != me {
        counters.ttwu_local.fetch_sub(1, Ordering::Relaxed);
    }
}

/// `sched_info_arrive`: a task woken `waited_cycles` ago starts running here.
#[inline]
pub(crate) fn note_dispatch(waited_cycles: u64) {
    let counters = local();
    counters.pcount.fetch_add(1, Ordering::Relaxed);
    counters
        .run_delay_cycles
        .fetch_add(waited_cycles, Ordering::Relaxed);
}

/// One CPU's `/proc/schedstat` line, plus its wake-side domain counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuSchedstat {
    pub yld_count: u64,
    pub sched_count: u64,
    pub sched_goidle: u64,
    pub ttwu_count: u64,
    pub ttwu_local: u64,
    pub rq_cpu_time_ns: u64,
    pub run_delay_ns: u64,
    pub pcount: u64,
    pub ttwu_move_affine: u64,
    pub ttwu_move_balance: u64,
    pub ttwu_move_balance_far: u64,
    pub ttwu_remote_llc: u64,
    pub ttwu_remote_far: u64,
}

/// Snapshot `cpu`'s counters. Zero for an out-of-range CPU.
pub fn cpu_schedstat(cpu: usize) -> CpuSchedstat {
    let Some(c) = COUNTERS.get(cpu) else {
        return CpuSchedstat::default();
    };
    let times = crate::cputime::cpu_times(cpu);
    CpuSchedstat {
        yld_count: c.yld_count.load(Ordering::Relaxed),
        sched_count: crate::cpu_sched_passes(cpu),
        sched_goidle: c.sched_goidle.load(Ordering::Relaxed),
        ttwu_count: c.ttwu_count.load(Ordering::Relaxed),
        ttwu_local: c.ttwu_local.load(Ordering::Relaxed),
        rq_cpu_time_ns: times
            .total()
            .saturating_sub(times.idle)
            .saturating_sub(times.iowait)
            .saturating_sub(times.steal),
        run_delay_ns: narf_time::cycles_to_ns(c.run_delay_cycles.load(Ordering::Relaxed)),
        pcount: c.pcount.load(Ordering::Relaxed),
        ttwu_move_affine: c.ttwu_move_affine.load(Ordering::Relaxed),
        ttwu_move_balance: c.ttwu_move_balance.load(Ordering::Relaxed),
        ttwu_move_balance_far: c.ttwu_move_balance_far.load(Ordering::Relaxed),
        ttwu_remote_llc: c.ttwu_remote_llc.load(Ordering::Relaxed),
        ttwu_remote_far: c.ttwu_remote_far.load(Ordering::Relaxed),
    }
}

/// One scheduling domain of `cpu` for `/proc/schedstat`: Linux's name and
/// the span of online CPUs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedDomain {
    pub name: &'static str,
    pub span: u64,
}

/// `cpu`'s domains, innermost first, as Linux builds them after degenerating
/// levels whose span equals the level below: `MC` (CPUs sharing its
/// last-level cache) and, when wider, `PKG` (every online CPU). NARF's wake
/// placement and stealing reason about exactly these two levels.
pub fn sched_domains(cpu: usize) -> ([SchedDomain; 2], usize) {
    use crate::affinity::CpuId;
    let online = narf_lib::smp::online_bitmap();
    let llc = crate::steal::llc_id(CpuId(cpu as u32));
    let mut mc = 0u64;
    let mut scan = online;
    while scan != 0 {
        let other = scan.trailing_zeros();
        scan &= scan - 1;
        if other as usize == cpu || (llc.is_some() && crate::steal::llc_id(CpuId(other)) == llc) {
            mc |= 1u64 << other;
        }
    }
    if llc.is_none() {
        mc = online;
    }
    let domains = [
        SchedDomain {
            name: "MC",
            span: mc,
        },
        SchedDomain {
            name: "PKG",
            span: online,
        },
    ];
    let count = if online & !mc == 0 { 1 } else { 2 };
    (domains, count)
}

/// `SCHEDSTAT_VERSION` in `kernel/sched/stats.c`.
pub const SCHEDSTAT_VERSION: u32 = 17;
