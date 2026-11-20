//! `/proc/timer_list` — Linux `kernel/time/timer_list.c`.
//!
//! Every CPU's eight hrtimer clock bases with each queued timer in
//! `print_timer` form:
//!
//! ```text
//!  #0: <ffff8000012345c0>, hrtimer_wakeup, S:01, drivers/net/igc/src/igc.rs:2217:31, narf_igc::spawn_pumps::{{closure}}/41
//!  # expires at 1000000-1050000 nsecs [in 900 to 50900 nsecs]
//! ```
//!
//! The function is resolved through the kernel's own symbol table. A
//! sleeper (`hrtimer_wakeup`, a task's sleep) also names where it was armed
//! and the task that armed it (its spawn origin, or `?` when unknown) with
//! the task id — the `start_site, comm/pid` pair Linux printed until
//! `CONFIG_TIMER_STATS` was removed. Every `hrtimer_wakeup` line is one task
//! asleep, and that pair says which.
//!
//! After the hrtimer bases, a NARF-specific section lists the timer wheel
//! (`timer_list` timers: `msleep`, timeouts, delayed work) per CPU and base
//! in the same shape, in jiffies, which Linux has no file for.
//!
//! Mode 0400, as Linux (`proc_create_seq_private("timer_list", 0400, ..)`):
//! the file prints kernel addresses.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_observability::kallsyms::{self, NameBuf};
use narf_time::hrtimer::{CpuBaseStats, TimerSnapshot, HRTIMER_MAX_CLOCK_BASES};
use narf_time::timer::{WheelBaseStats, WheelTimerSnapshot};

use super::{register_proc, ProcFile};

/// One hrtimer clock base of one CPU, snapshotted.
#[derive(Debug, Default)]
pub struct ClockBaseView {
    /// `base->offset` (ns).
    pub offset: i64,
    pub timers: Vec<TimerSnapshot>,
    /// Timers queued when snapshotted (more than `timers.len()` when the
    /// tail was dropped).
    pub queued: usize,
}

/// One timer-wheel base of one CPU, snapshotted.
#[derive(Debug, Default)]
pub struct WheelBaseView {
    pub stats: WheelBaseStats,
    pub timers: Vec<WheelTimerSnapshot>,
    pub pending: usize,
}

/// Everything `/proc/timer_list` prints for one CPU.
#[derive(Debug, Default)]
pub struct CpuTimerView {
    pub cpu: usize,
    pub stats: CpuBaseStats,
    pub clock_bases: Vec<ClockBaseView>,
    pub wheel: Vec<WheelBaseView>,
}

/// Snapshot `cpu`'s timers (task context; allocates).
pub fn snapshot_cpu(cpu: usize) -> Option<CpuTimerView> {
    let stats = narf_time::hrtimer::cpu_base_stats(cpu)?;
    let mut view = CpuTimerView {
        cpu,
        stats,
        ..CpuTimerView::default()
    };
    for index in 0..HRTIMER_MAX_CLOCK_BASES {
        let mut timers = Vec::new();
        let queued = narf_time::hrtimer::snapshot_base(cpu, index, &mut timers);
        view.clock_bases.push(ClockBaseView {
            offset: narf_time::hrtimer::clock_base_offset(index),
            timers,
            queued,
        });
    }
    for index in 0..narf_time::timer::NR_TIMER_BASES {
        let mut timers = Vec::new();
        if let Some((stats, pending)) = narf_time::timer::snapshot_wheel(cpu, index, &mut timers) {
            view.wheel.push(WheelBaseView {
                stats,
                timers,
                pending,
            });
        }
    }
    Some(view)
}

/// `%ps`: the symbol covering `addr`, or the bare address when the image
/// carries no symbol table.
fn symbol_name(addr: usize) -> String {
    let mut name = NameBuf::new();
    match kallsyms::lookup(addr as u64, &mut name) {
        Some(_) => match name.as_str() {
            Some(s) => String::from(s),
            None => alloc::format!("{:#x}", addr),
        },
        None => alloc::format!("{:#x}", addr),
    }
}

/// The `comm` of a user task, by scheduler task id (userspace installs it).
pub type TaskCommFn = fn(u64) -> Option<String>;
static TASK_COMM_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Install the task-id → `comm` lookup used to name user tasks' timers.
pub fn set_task_comm_hook(f: TaskCommFn) {
    TASK_COMM_HOOK.store(f as usize, core::sync::atomic::Ordering::Release);
}

fn task_comm(task: u64) -> Option<String> {
    let raw = TASK_COMM_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if raw == 0 {
        return None;
    }
    // SAFETY: only `set_task_comm_hook` stores this cell, from a `TaskCommFn`.
    let f: TaskCommFn = unsafe { core::mem::transmute(raw) };
    f(task)
}

/// `comm/pid` for an arming task: a user task's `comm`, a kernel task's
/// spawn origin (the future's type), with the task id. Built once per read.
#[derive(Debug, Default)]
pub struct TaskNames {
    origins: BTreeMap<u64, &'static str>,
    comms: BTreeMap<u64, String>,
}

impl TaskNames {
    /// Snapshot every live task's spawn origin.
    pub fn snapshot() -> Self {
        let mut origins = BTreeMap::new();
        for (id, origin, _site) in narf_scheduler::task_origins() {
            origins.insert(id.raw(), origin);
        }
        Self {
            origins,
            comms: BTreeMap::new(),
        }
    }

    /// For tests: a fixed table.
    pub fn from_pairs(pairs: &[(u64, &'static str)]) -> Self {
        Self {
            origins: pairs.iter().copied().collect(),
            comms: BTreeMap::new(),
        }
    }

    /// Resolve the `comm` of every owner in `cpus` once, outside the
    /// printing loop.
    fn resolve_comms(&mut self, cpus: &[CpuTimerView]) {
        let owners = cpus.iter().flat_map(|c| {
            c.clock_bases
                .iter()
                .flat_map(|b| b.timers.iter().map(|t| t.owner_task))
                .chain(
                    c.wheel
                        .iter()
                        .flat_map(|b| b.timers.iter().map(|t| t.owner_task)),
                )
        });
        for task in owners {
            if task != 0 && !self.comms.contains_key(&task) {
                if let Some(comm) = task_comm(task) {
                    self.comms.insert(task, comm);
                }
            }
        }
    }

    fn name(&self, task: u64) -> &str {
        if task == 0 {
            return "?";
        }
        if let Some(comm) = self.comms.get(&task) {
            return comm;
        }
        self.origins.get(&task).copied().unwrap_or("?")
    }
}

fn write_owner(
    s: &mut String,
    site: Option<&'static core::panic::Location<'static>>,
    task: u64,
    names: &TaskNames,
) {
    if let Some(site) = site {
        let _ = write!(s, ", {}:{}:{}", site.file(), site.line(), site.column());
        let _ = write!(s, ", {}/{}", names.name(task), task);
    }
}

/// Linux `print_timer`, plus the arm site and task of a sleeper.
fn print_timer(
    s: &mut String,
    t: &TimerSnapshot,
    idx: usize,
    now: i128,
    resolve: &dyn Fn(usize) -> String,
    names: &TaskNames,
) {
    let _ = write!(
        s,
        " #{}: <{:016x}>, {}, S:{:02x}",
        idx,
        t.addr,
        resolve(t.function),
        t.state
    );
    write_owner(s, t.site, t.owner_task, names);
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        " # expires at {}-{} nsecs [in {} to {} nsecs]",
        t.softexpires,
        t.expires,
        t.softexpires as i128 - now,
        t.expires as i128 - now
    );
}

/// Render the whole file. `now` is CLOCK_MONOTONIC in ns, `jiffies` the
/// wheel clock; `resolve` names a function address.
pub fn render(
    now: u64,
    jiffies: u64,
    cpus: &[CpuTimerView],
    resolve: &dyn Fn(usize) -> String,
    names: &TaskNames,
) -> String {
    let mut s = String::new();
    // `timer_list_header`.
    let _ = writeln!(s, "Timer List Version: v0.10");
    let _ = writeln!(s, "HRTIMER_MAX_CLOCK_BASES: {}", HRTIMER_MAX_CLOCK_BASES);
    let _ = writeln!(s, "now at {} nsecs", now);
    let _ = writeln!(s);
    for cpu in cpus {
        // `print_cpu`.
        let _ = writeln!(s, "cpu: {}", cpu.cpu);
        for (i, base) in cpu.clock_bases.iter().enumerate() {
            let _ = writeln!(s, " clock {}:", i);
            let _ = writeln!(s, "  .index:      {}", i);
            let _ = writeln!(s, "  .resolution: 1 nsecs");
            let _ = writeln!(s, "  .offset:     {} nsecs", base.offset);
            let _ = writeln!(s, "active timers:");
            let basenow = now as i128 + base.offset as i128;
            for (idx, t) in base.timers.iter().enumerate() {
                print_timer(&mut s, t, idx, basenow, resolve, names);
            }
            if base.queued > base.timers.len() {
                let _ = writeln!(
                    s,
                    " # {} more queued while reading",
                    base.queued - base.timers.len()
                );
            }
        }
        let expires_next = if cpu.stats.expires_next == narf_time::hrtimer::KTIME_MAX {
            i64::MAX as u64
        } else {
            cpu.stats.expires_next
        };
        let _ = writeln!(s, "  .{:<15}: {} nsecs", "expires_next", expires_next);
        let _ = writeln!(s, "  .{:<15}: {}", "hres_active", 1);
        let _ = writeln!(s, "  .{:<15}: {}", "nr_events", cpu.stats.nr_events);
        let _ = writeln!(s, "  .{:<15}: {}", "nr_retries", cpu.stats.nr_retries);
        let _ = writeln!(s, "  .{:<15}: {}", "nr_hangs", cpu.stats.nr_hangs);
        let _ = writeln!(s, "  .{:<15}: {}", "max_hang_time", 0);
        let _ = writeln!(s, "  .{:<15}: {}", "nr_queued", cpu.stats.nr_queued);
        let _ = writeln!(s, "jiffies: {}", jiffies);
        let _ = writeln!(s);
    }
    // NARF: the timer wheel, which Linux does not print.
    let _ = writeln!(
        s,
        "Timer Wheel (timer_list, jiffies at HZ={})",
        narf_time::timer::HZ
    );
    let _ = writeln!(s, "jiffies: {}", jiffies);
    let _ = writeln!(s);
    for cpu in cpus {
        let _ = writeln!(s, "cpu: {}", cpu.cpu);
        for (i, base) in cpu.wheel.iter().enumerate() {
            let name = narf_time::timer::BASE_NAMES.get(i).copied().unwrap_or("?");
            let _ = write!(
                s,
                " base {} {}: .clk {}, .next_expiry ",
                i, name, base.stats.clk
            );
            if base.stats.next_expiry == u64::MAX {
                let _ = write!(s, "none");
            } else {
                let _ = write!(s, "{}", base.stats.next_expiry);
            }
            let _ = writeln!(s, ", .nr_expired {}", base.stats.nr_expired);
            let _ = writeln!(s, "pending timers:");
            for (idx, t) in base.timers.iter().enumerate() {
                let _ = write!(
                    s,
                    " #{}: <{:016x}>, {}, F:{:02x}, L:{}",
                    idx,
                    t.addr,
                    resolve(t.function),
                    t.flags,
                    t.level
                );
                write_owner(&mut s, t.site, t.owner_task, names);
                let _ = writeln!(s);
                let _ = writeln!(
                    s,
                    " # expires at {} (bucket {}) jiffies [in {} jiffies]",
                    t.expires,
                    t.bucket_expiry,
                    t.bucket_expiry as i128 - jiffies as i128
                );
            }
            if base.pending > base.timers.len() {
                let _ = writeln!(
                    s,
                    " # {} more pending while reading",
                    base.pending - base.timers.len()
                );
            }
        }
        let _ = writeln!(s);
    }
    s
}

fn gen_timer_list() -> Vec<u8> {
    let mut names = TaskNames::snapshot();
    let mut cpus = Vec::new();
    for cpu in 0..narf_lib::percpu::MAX_CPUS {
        if !narf_lib::smp::is_online(cpu as u32) {
            continue;
        }
        if let Some(v) = snapshot_cpu(cpu) {
            cpus.push(v);
        }
    }
    names.resolve_comms(&cpus);
    render(
        narf_time::monotonic_ns(),
        narf_time::timer::jiffies(),
        &cpus,
        &symbol_name,
        &names,
    )
    .into_bytes()
}

/// `/proc/timer_list`.
#[derive(Debug)]
struct TimerListFile;

impl ProcFile for TimerListFile {
    fn read(&self) -> Vec<u8> {
        gen_timer_list()
    }

    fn perms(&self) -> u16 {
        0o400
    }
}

/// The scheduler's running-task id, recorded as each timer's arming task.
fn current_task() -> u64 {
    narf_scheduler::current_task_id().raw()
}

/// Register `/proc/timer_list` and start recording timer owners.
pub fn register() {
    narf_time::hrtimer::set_current_task_hook(current_task);
    register_proc("timer_list", Arc::new(TimerListFile));
}

#[path = "timer_list_tests.rs"]
mod tests;
