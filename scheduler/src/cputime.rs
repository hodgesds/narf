//! Per-CPU and per-task CPU time accounting.
//!
//! Linux reference: `kernel/sched/cputime.c` with `VIRT_CPU_ACCOUNTING_GEN`
//! (the `vtime_*` family: time is measured at every user/kernel/idle/guest
//! transition instead of sampled per tick) and `IRQ_TIME_ACCOUNTING`
//! (hard- and soft-interrupt time measured at entry/exit and removed from the
//! interrupted context).
//!
//! # Why transitions, not ticks
//!
//! Linux on the reference host samples user/system per tick
//! (`account_process_tick`) because `nohz_full=` is not set. NARF's tick is
//! 100 Hz and stops on idle CPUs, its one-shot clockevent is re-armed for
//! hrtimer and budget deadlines, and its executor dispatches many short
//! polls per tick: a tick sample would be both coarse and correlated with
//! the work it samples. Every transition the sampler would need to classify
//! already passes a single choke point (trap entry/exit, executor dispatch,
//! the idle halts), so each one stamps the TSC and folds the elapsed span
//! into the context it closes. The cost per transition is one TSC read and a
//! handful of stores to this CPU's own cache line, with interrupts masked; no
//! lock, allocation or I/O.
//!
//! # Model
//!
//! Each CPU is always in one context: user, system, softirq or idle. The span
//! since the last transition belongs to that context, minus the hard-IRQ (and
//! NMI) cycles `accounting` measured inside it and minus KVM steal time. The
//! running task, when there is one, is charged the same span: user spans as
//! utime, system and softirq spans as stime. Idle spans and the softirq work
//! that interrupts a task are charged to no task, as Linux charges irq-exit
//! softirqs to no task under `IRQ_TIME_ACCOUNTING`.
//!
//! The context and current task travel with the code that is executing. A
//! stackful continuation that is switched out keeps its own context word
//! ([`context_swap`]); the executor that resumes has its own. A kernel task
//! preempted inside an idle bracket or a softirq handler therefore takes that
//! context with it instead of leaving it on the CPU for the next task.
//!
//! # Concurrency
//!
//! Only the owning CPU writes its [`CpuCell`], always with interrupts masked,
//! inside a sequence-count write section (Linux `vtime->seqcount`). Remote
//! readers (`/proc/stat`, `/proc/<pid>/stat`, getrusage of another thread)
//! retry on a torn snapshot and add the open span themselves, so a busy CPU
//! that never transitions is still reported correctly.

use core::sync::atomic::{fence, AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use narf_lib::cputime::exclusive_span;
use narf_lib::percpu::MAX_CPUS;

/// Context of the code a CPU is executing (low bits of a context word).
const CTX_USER: usize = 0;
const CTX_SYSTEM: usize = 1;
const CTX_SOFTIRQ: usize = 2;
const CTX_IDLE: usize = 3;
const CTX_MASK: usize = 3;
/// Set in a user-context word whose task has positive nice. Kept in the word
/// so neither a fold nor a remote reader has to reach through the pointer.
const WORD_NICE: usize = 4;
/// Every non-pointer bit of a context word.
const WORD_FLAGS: usize = 7;

/// Accumulator indices (cycles), in `/proc/stat` column order.
const ACC_USER: usize = 0;
const ACC_NICE: usize = 1;
const ACC_SYSTEM: usize = 2;
const ACC_SOFTIRQ: usize = 3;
const ACC_IDLE: usize = 4;
const ACC_IOWAIT: usize = 5;
const NR_ACC: usize = 6;

/// `last_switched` marker for the idle context; never a valid task address.
const IDLE_IDENTITY: usize = 1;

/// How often a fold re-samples the KVM steal clock (≈1 ms). The sample is a
/// versioned read with a full fence, too costly for every transition; steal
/// sampled at this rate is still removed exactly, just from later spans.
const STEAL_SAMPLE_NS: u64 = 1_000_000;

/// A packed context word: a `*const TaskCputime` (8-aligned) with the
/// context and the nice flag in its low bits. A null task means "no task is
/// charged".
pub(crate) type ContextWord = usize;

/// A context word for continuation state that has not run yet: system
/// context, task pointer resolved by the dispatcher.
pub(crate) const FRESH_CONTEXT: ContextWord = CTX_SYSTEM;

/// Per-task CPU time: Linux `task_struct::{utime, stime}` maintained by
/// vtime. Owned by the task's scheduler wake cell; user tasks share it with
/// their `UserControl` so the process layer reads it without a registry
/// walk.
#[derive(Debug)]
#[repr(align(8))]
pub struct TaskCputime {
    utime_ns: AtomicU64,
    stime_ns: AtomicU64,
    /// CPU whose cell last made this task current (`u32::MAX` before its
    /// first run). A reader validates it against that cell's context word.
    cpu: AtomicU32,
    /// `task_nice(p) > 0`: this task's user time is the `nice` column.
    nice: AtomicBool,
    /// Time spent runnable but waiting for a CPU, in TSC cycles (Linux
    /// `sched_info.run_delay`, `/proc/<pid>/schedstat`'s second field).
    run_delay_cycles: AtomicU64,
    /// Dispatches (slice starts) this task has had (Linux
    /// `sched_info.pcount`, `/proc/<pid>/schedstat`'s third field).
    /// Counted by `stamp_slice_start`, the single choke point for every
    /// resume/dispatch path — so a task that has run at all reports >= 1,
    /// on both arches and both execution models.
    dispatches: AtomicU64,
}

const _: () = assert!(core::mem::align_of::<TaskCputime>() > WORD_FLAGS);

/// A task's accumulated CPU time in nanoseconds, including the span it is
/// running right now.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskTimes {
    pub utime_ns: u64,
    pub stime_ns: u64,
}

impl TaskTimes {
    /// `utime + stime`: the task's on-CPU time excluding interrupts.
    pub const fn total_ns(self) -> u64 {
        self.utime_ns.saturating_add(self.stime_ns)
    }
}

impl Default for TaskCputime {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskCputime {
    pub const fn new() -> Self {
        Self {
            utime_ns: AtomicU64::new(0),
            stime_ns: AtomicU64::new(0),
            cpu: AtomicU32::new(u32::MAX),
            nice: AtomicBool::new(false),
            run_delay_cycles: AtomicU64::new(0),
            dispatches: AtomicU64::new(0),
        }
    }

    /// Charge `cycles` of waiting-to-run to this task (`sched_info_arrive`).
    #[inline]
    pub(crate) fn note_run_delay(&self, cycles: u64) {
        if cycles != 0 {
            self.run_delay_cycles.fetch_add(cycles, Ordering::Relaxed);
        }
    }

    /// Total time this task has waited runnable for a CPU, in ns.
    pub fn run_delay_ns(&self) -> u64 {
        narf_time::cycles_to_ns(self.run_delay_cycles.load(Ordering::Relaxed))
    }

    /// Count one dispatch of this task, at slice start.
    #[inline]
    pub(crate) fn note_dispatch(&self) {
        self.dispatches.fetch_add(1, Ordering::Relaxed);
    }

    /// Dispatches so far (slice starts), including the slice running now.
    pub fn dispatches(&self) -> u64 {
        self.dispatches.load(Ordering::Relaxed)
    }

    /// Test hook: count one dispatch directly, as `stamp_slice_start`
    /// would have. Only for a task that is not running.
    #[doc(hidden)]
    pub fn __test_note_dispatch(&self) {
        self.dispatches.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the task's nice value; positive nice moves its user time to
    /// the `nice` column (`account_user_time`) from its next user entry.
    pub fn set_nice(&self, nice: i8) {
        self.nice.store(nice > 0, Ordering::Relaxed);
    }

    /// Current `utime`/`stime`, including the open span when the task is
    /// running on some CPU. Each field is monotonic across calls.
    pub fn sample(&self) -> TaskTimes {
        let me = self as *const Self as usize;
        for _ in 0..READ_RETRIES {
            let cpu = self.cpu.load(Ordering::Acquire) as usize;
            let Some(cell) = CELLS.get(cpu) else {
                return self.folded();
            };
            let Some(snap) = cell.snapshot() else {
                core::hint::spin_loop();
                continue;
            };
            // Read the task fields inside the same section: the fold that
            // closes the open span updates them under this sequence count.
            let folded = self.folded();
            if !cell.seq_unchanged(snap.seq) {
                core::hint::spin_loop();
                continue;
            }
            if snap.cur & !WORD_FLAGS != me {
                return folded;
            }
            let open = narf_time::cycles_to_ns(snap.open_cycles(cpu, narf_time::now_cycles()));
            return match snap.cur & CTX_MASK {
                CTX_USER => TaskTimes {
                    utime_ns: folded.utime_ns.saturating_add(open),
                    ..folded
                },
                CTX_SYSTEM | CTX_SOFTIRQ => TaskTimes {
                    stime_ns: folded.stime_ns.saturating_add(open),
                    ..folded
                },
                _ => folded,
            };
        }
        self.folded()
    }

    fn folded(&self) -> TaskTimes {
        TaskTimes {
            utime_ns: self.utime_ns.load(Ordering::Relaxed),
            stime_ns: self.stime_ns.load(Ordering::Relaxed),
        }
    }

    /// Test hook: charge time directly, as if it had been folded. Only for a
    /// task that is not running.
    #[doc(hidden)]
    pub fn __test_charge(&self, utime_ns: u64, stime_ns: u64) {
        self.utime_ns.fetch_add(utime_ns, Ordering::Relaxed);
        self.stime_ns.fetch_add(stime_ns, Ordering::Relaxed);
    }

    /// Test hook: zero the accumulated time of a task that is not running.
    #[doc(hidden)]
    pub fn __test_reset(&self) {
        self.utime_ns.store(0, Ordering::Relaxed);
        self.stime_ns.store(0, Ordering::Relaxed);
    }
}

/// Bounded seqcount retries. Writers mask interrupts and are short, so a
/// reader only spins through a few iterations; the bound keeps an NMI-time
/// reader that interrupted its own CPU's writer from spinning forever.
const READ_RETRIES: usize = 1024;

/// One CPU's accounting state. Single writer (the owning CPU, interrupts
/// masked); remote readers use the sequence count.
#[repr(C, align(64))]
struct CpuCell {
    seq: AtomicU32,
    /// Packed context word of the code running on this CPU.
    cur: AtomicUsize,
    /// TSC at the last fold; 0 until the CPU's first transition.
    stamp: AtomicU64,
    /// `accounting::interrupt_cycles` at the last fold.
    irq_stamp: AtomicU64,
    /// Steal time sampled so far, and the part already removed from spans
    /// (cycles). The remainder is removed from later spans (Linux carries
    /// unaccounted steal in `rq->prev_steal_time` the same way).
    steal_total: AtomicU64,
    steal_taken: AtomicU64,
    /// TSC of the last steal-clock sample.
    steal_sampled: AtomicU64,
    /// Steal ns already converted into `steal_total`.
    steal_seen_ns: AtomicU64,
    acc: [AtomicU64; NR_ACC],
    /// `rq->nr_switches`.
    nr_switches: AtomicU64,
    /// Identity of the last task (or [`IDLE_IDENTITY`]) switched in.
    last_switched: AtomicUsize,
}

impl CpuCell {
    const fn new() -> Self {
        Self {
            seq: AtomicU32::new(0),
            cur: AtomicUsize::new(CTX_SYSTEM),
            stamp: AtomicU64::new(0),
            irq_stamp: AtomicU64::new(0),
            steal_total: AtomicU64::new(0),
            steal_taken: AtomicU64::new(0),
            steal_sampled: AtomicU64::new(0),
            steal_seen_ns: AtomicU64::new(0),
            acc: [const { AtomicU64::new(0) }; NR_ACC],
            nr_switches: AtomicU64::new(0),
            last_switched: AtomicUsize::new(0),
        }
    }

    /// Start a consistent read, or `None` while a write is in progress.
    #[inline]
    fn snapshot(&self) -> Option<Snapshot> {
        let seq = self.seq.load(Ordering::Acquire);
        if seq & 1 != 0 {
            return None;
        }
        let mut acc = [0u64; NR_ACC];
        for (slot, value) in acc.iter_mut().zip(&self.acc) {
            *slot = value.load(Ordering::Relaxed);
        }
        Some(Snapshot {
            seq,
            cur: self.cur.load(Ordering::Relaxed),
            stamp: self.stamp.load(Ordering::Relaxed),
            irq_stamp: self.irq_stamp.load(Ordering::Relaxed),
            steal_left: self
                .steal_total
                .load(Ordering::Relaxed)
                .saturating_sub(self.steal_taken.load(Ordering::Relaxed)),
            acc,
        })
    }

    /// Finish a read started by [`Self::snapshot`].
    #[inline]
    fn seq_unchanged(&self, seq: u32) -> bool {
        fence(Ordering::Acquire);
        self.seq.load(Ordering::Relaxed) == seq
    }
}

struct Snapshot {
    seq: u32,
    cur: ContextWord,
    stamp: u64,
    irq_stamp: u64,
    steal_left: u64,
    acc: [u64; NR_ACC],
}

impl Snapshot {
    /// Cycles of the still-open span that belong to `cur`'s context.
    fn open_cycles(&self, cpu: usize, now: u64) -> u64 {
        if self.stamp == 0 {
            return 0;
        }
        let irq = crate::accounting::interrupt_cycles(cpu)
            .saturating_add(crate::accounting::interrupt_in_progress_cycles(cpu, now));
        let span = exclusive_span(now, self.stamp, irq, self.irq_stamp);
        span.saturating_sub(span.min(self.steal_left))
    }
}

static CELLS: [CpuCell; MAX_CPUS] = [const { CpuCell::new() }; MAX_CPUS];

#[inline]
fn this_cpu() -> usize {
    narf_lib::percpu::current_cpu().min(MAX_CPUS - 1)
}

#[inline]
fn task_of(word: ContextWord) -> *const TaskCputime {
    (word & !WORD_FLAGS) as *const TaskCputime
}

/// Accumulator a span of `word`'s context lands in. Reads only the word:
/// remote readers call this on another CPU's word and must not reach
/// through its task pointer.
#[inline]
fn acc_index(word: ContextWord, cpu: usize) -> usize {
    match word & CTX_MASK {
        CTX_USER => {
            if word & WORD_NICE != 0 {
                ACC_NICE
            } else {
                ACC_USER
            }
        }
        CTX_SYSTEM => ACC_SYSTEM,
        CTX_SOFTIRQ => ACC_SOFTIRQ,
        _ => {
            if narf_lib::kstat::nr_iowait(cpu) != 0 {
                ACC_IOWAIT
            } else {
                ACC_IDLE
            }
        }
    }
}

/// Close the open span on `cpu` at `now` and charge it to the current
/// context (and task). Caller holds the cell's write section.
#[inline(always)]
fn fold(cell: &CpuCell, cpu: usize, now: u64) -> ContextWord {
    let cur = cell.cur.load(Ordering::Relaxed);
    // Include a hard IRQ still in progress: a transition made from inside a
    // handler (a driver spin-wait that pumps the executor) then charges none
    // of the handler to the interrupted context, and the next fold after the
    // handler returns subtracts exactly its remainder.
    let irq = crate::accounting::interrupt_cycles(cpu)
        .saturating_add(crate::accounting::interrupt_in_progress_cycles(cpu, now));
    let stamp = cell.stamp.load(Ordering::Relaxed);
    if stamp != 0 {
        let mut span = exclusive_span(now, stamp, irq, cell.irq_stamp.load(Ordering::Relaxed));
        let steal_taken = cell.steal_taken.load(Ordering::Relaxed);
        let steal_left = cell
            .steal_total
            .load(Ordering::Relaxed)
            .saturating_sub(steal_taken);
        if steal_left != 0 {
            let take = steal_left.min(span);
            cell.steal_taken
                .store(steal_taken.wrapping_add(take), Ordering::Relaxed);
            span -= take;
        }
        if span != 0 {
            let acc = &cell.acc[acc_index(cur, cpu)];
            acc.store(
                acc.load(Ordering::Relaxed).wrapping_add(span),
                Ordering::Relaxed,
            );
            let task = task_of(cur);
            let ctx = cur & CTX_MASK;
            if !task.is_null() && ctx != CTX_IDLE {
                // SAFETY: see `acc_index`. The running CPU is the task's only
                // accounting writer, so a load/store pair cannot lose a fold.
                let task = unsafe { &*task };
                let field = if ctx == CTX_USER {
                    &task.utime_ns
                } else {
                    &task.stime_ns
                };
                field.store(
                    field
                        .load(Ordering::Relaxed)
                        .wrapping_add(narf_time::cycles_to_ns(span)),
                    Ordering::Relaxed,
                );
            }
        }
    }
    cell.stamp.store(now, Ordering::Relaxed);
    cell.irq_stamp.store(irq, Ordering::Relaxed);
    // Steal sampled now is removed from later spans, so a reader that saw
    // the open span before this fold never reads more than the fold adds.
    if now.saturating_sub(cell.steal_sampled.load(Ordering::Relaxed))
        >= narf_time::ns_to_cycles(STEAL_SAMPLE_NS)
    {
        cell.steal_sampled.store(now, Ordering::Relaxed);
        let steal_ns = crate::cpu_steal_ns(cpu);
        let seen = cell.steal_seen_ns.load(Ordering::Relaxed);
        if steal_ns > seen {
            cell.steal_seen_ns.store(steal_ns, Ordering::Relaxed);
            let total = cell.steal_total.load(Ordering::Relaxed);
            cell.steal_total.store(
                total.wrapping_add(narf_time::ns_to_cycles(steal_ns - seen)),
                Ordering::Relaxed,
            );
        }
    }
    cur
}

/// Fold the open span and install the context `next(previous)` returns.
/// Returns the previous context word.
///
/// # Safety
/// Interrupts must be masked on the calling CPU, and every task pointer the
/// new word names must stay valid until a later transition replaces it.
#[inline(always)]
unsafe fn transition(next: impl FnOnce(ContextWord) -> ContextWord) -> ContextWord {
    let cpu = this_cpu();
    let cell = &CELLS[cpu];
    let now = narf_time::now_cycles();
    let seq = cell.seq.load(Ordering::Relaxed);
    cell.seq.store(seq.wrapping_add(1), Ordering::Relaxed);
    fence(Ordering::Release);
    let old = fold(cell, cpu, now);
    let mut new = next(old) & !WORD_NICE;
    let task = task_of(new);
    // SAFETY: caller contract — `task` is live while installed. The owning
    // CPU refreshes the flag at every user entry, so a nice change takes
    // effect from the task's next return to user mode.
    if new & CTX_MASK == CTX_USER
        && !task.is_null()
        // SAFETY: caller contract — `task` is live while installed.
        && unsafe { (*task).nice.load(Ordering::Relaxed) }
    {
        new |= WORD_NICE;
    }
    if new != old {
        cell.cur.store(new, Ordering::Relaxed);
        if !task.is_null() && task != task_of(old) {
            // SAFETY: caller contract — `task` is live while installed.
            unsafe { (*task).cpu.store(cpu as u32, Ordering::Release) };
        }
        let identity = match new & CTX_MASK {
            CTX_IDLE => IDLE_IDENTITY,
            _ => task as usize,
        };
        if identity != 0 && identity != cell.last_switched.load(Ordering::Relaxed) {
            cell.last_switched.store(identity, Ordering::Relaxed);
            cell.nr_switches.store(
                cell.nr_switches.load(Ordering::Relaxed).wrapping_add(1),
                Ordering::Relaxed,
            );
        }
    }
    cell.seq.store(seq.wrapping_add(2), Ordering::Release);
    old
}

#[inline]
fn masked<R>(f: impl FnOnce() -> R) -> R {
    narf_lib::sync::without_interrupts(f)
}

// ── Trap boundary (frame/) ──────────────────────────────────────────

/// The CPU entered the kernel from user mode (syscall, exception or
/// interrupt taken at CPL3 / EL0): close the user span (Linux
/// `vtime_user_exit`).
///
/// # Safety
/// Interrupts must be masked, and this must run before any hard-IRQ
/// accounting of the same entry begins.
#[inline]
pub unsafe fn user_exit_irqs_off() {
    // SAFETY: caller contract; the task pointer is unchanged.
    unsafe { transition(|old| (old & !CTX_MASK) | CTX_SYSTEM) };
}

/// The CPU is about to return to user mode: close the kernel span (Linux
/// `vtime_user_enter`).
///
/// # Safety
/// Interrupts must be masked and stay masked until the return to user mode.
#[inline]
pub unsafe fn user_enter_irqs_off() {
    // SAFETY: caller contract; the task pointer is unchanged.
    unsafe { transition(|old| (old & !CTX_MASK) | CTX_USER) };
}

/// [`user_enter_irqs_off`] for a caller whose interrupt state is not known.
#[inline]
pub fn user_enter() {
    // SAFETY: masked for the transition; the task pointer is unchanged.
    masked(|| unsafe { user_enter_irqs_off() });
}

// ── Executor dispatch ───────────────────────────────────────────────

/// A task's poll begins on this CPU: charge it until [`dispatch_exit`].
/// A `WorkKind::SoftIrq` task runs in softirq context (a NAPI poller is
/// Linux's `NET_RX` handler); every other task runs in system context.
pub(crate) fn dispatch_enter(task: &TaskCputime, softirq: bool) -> ContextWord {
    let ctx = if softirq {
        narf_lib::kstat::note_softirq(narf_lib::kstat::vector::NET_RX);
        CTX_SOFTIRQ
    } else {
        CTX_SYSTEM
    };
    let word = task as *const TaskCputime as usize | ctx;
    // SAFETY: masked; the dispatching executor pins `task` for the poll.
    masked(|| unsafe { transition(|_| word) })
}

/// The poll [`dispatch_enter`] began has returned: restore the dispatcher's
/// own context.
pub(crate) fn dispatch_exit(previous: ContextWord) {
    context_restore(previous);
}

/// Reinstall a context word exactly (the executor side of a stackful
/// switch-back). Returns the outgoing continuation's word.
pub(crate) fn context_restore(word: ContextWord) -> ContextWord {
    // SAFETY: masked; `word` was live when its owner switched away and that
    // owner (an outer poll or the executor) is still on this stack.
    masked(|| unsafe { transition(|_| word) })
}

/// Switch accounting to another continuation: `next` is the context word it
/// saved when it last stopped (or [`FRESH_CONTEXT`]), `task` the task it
/// runs for. Returns the outgoing continuation's word, to be saved with it.
///
/// A saved word that names a task keeps it (a continuation stopped inside a
/// nested poll resumes charging that poll's task); a fresh one charges
/// `task`, or keeps the dispatcher's task when `task` is null.
pub(crate) fn context_swap(next: ContextWord, task: *const TaskCputime) -> ContextWord {
    // SAFETY: masked; the switch keeps both continuations' tasks pinned.
    masked(|| unsafe {
        transition(|old| {
            let saved = task_of(next);
            let charged = if !saved.is_null() {
                saved
            } else if !task.is_null() {
                task
            } else {
                task_of(old)
            };
            charged as usize | (next & CTX_MASK)
        })
    })
}

// ── Idle ────────────────────────────────────────────────────────────

/// The CPU is about to halt: idle (or iowait) until [`idle_exit`]. The
/// halted interval is charged to no task (Linux switches to the idle task).
pub(crate) fn idle_enter() -> ContextWord {
    // SAFETY: masked; the idle word names no task.
    masked(|| unsafe { transition(|_| CTX_IDLE) })
}

/// The halt [`idle_enter`] began is over.
pub(crate) fn idle_exit(previous: ContextWord) {
    // SAFETY: masked; `previous` belongs to the frame that entered idle.
    masked(|| unsafe { transition(|_| previous) });
}

// ── Softirq (installed into narf_lib::kstat) ────────────────────────

fn softirq_hook_enter() -> usize {
    // SAFETY: masked. Interrupted work is not charged for the handler.
    masked(|| unsafe { transition(|_| CTX_SOFTIRQ) })
}

fn softirq_hook_exit(previous: usize) {
    // SAFETY: masked; `previous` belongs to the frame that ran the handler.
    masked(|| unsafe { transition(|_| previous) });
}

/// Install the softirq time hooks. Idempotent.
pub(crate) fn init() {
    narf_lib::kstat::set_softirq_time_hooks(softirq_hook_enter, softirq_hook_exit);
}

// ── Readers ─────────────────────────────────────────────────────────

/// One CPU's `/proc/stat` columns in nanoseconds (`kernel_cpustat`, with
/// idle and iowait as `get_idle_time`/`get_iowait_time` return them).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTimes {
    /// Sum of every column: the CPU's accounted time.
    pub const fn total(&self) -> u64 {
        self.user
            .saturating_add(self.nice)
            .saturating_add(self.system)
            .saturating_add(self.idle)
            .saturating_add(self.iowait)
            .saturating_add(self.irq)
            .saturating_add(self.softirq)
            .saturating_add(self.steal)
    }
}

/// `cpu`'s accounted time since its first transition, including the open
/// span. Zero for an out-of-range CPU.
pub fn cpu_times(cpu: usize) -> CpuTimes {
    let Some(cell) = CELLS.get(cpu) else {
        return CpuTimes::default();
    };
    let mut acc = [0u64; NR_ACC];
    for _ in 0..READ_RETRIES {
        let Some(snap) = cell.snapshot() else {
            core::hint::spin_loop();
            continue;
        };
        let now = narf_time::now_cycles();
        let open = snap.open_cycles(cpu, now);
        let index = acc_index(snap.cur, cpu);
        if !cell.seq_unchanged(snap.seq) {
            core::hint::spin_loop();
            continue;
        }
        acc = snap.acc;
        acc[index] = acc[index].saturating_add(open);
        break;
    }
    let ns = narf_time::cycles_to_ns;
    let now = narf_time::now_cycles();
    let irq = crate::accounting::interrupt_cycles(cpu)
        .saturating_add(crate::accounting::interrupt_in_progress_cycles(cpu, now));
    CpuTimes {
        user: ns(acc[ACC_USER]),
        nice: ns(acc[ACC_NICE]),
        system: ns(acc[ACC_SYSTEM]),
        idle: ns(acc[ACC_IDLE]),
        iowait: ns(acc[ACC_IOWAIT]),
        irq: ns(irq),
        softirq: ns(acc[ACC_SOFTIRQ]),
        steal: crate::cpu_steal_ns(cpu),
    }
}

/// `nr_context_switches()`: task switches on every CPU since boot. A switch
/// is a change of the task (or idle) a CPU runs, as `__schedule` counts
/// `prev != next`.
pub fn nr_context_switches() -> u64 {
    CELLS.iter().fold(0u64, |sum, cell| {
        sum.wrapping_add(cell.nr_switches.load(Ordering::Relaxed))
    })
}

/// Context switches on `cpu` since boot.
pub fn cpu_context_switches(cpu: usize) -> u64 {
    CELLS
        .get(cpu)
        .map_or(0, |cell| cell.nr_switches.load(Ordering::Relaxed))
}

// ── Conversions ─────────────────────────────────────────────────────
//
// The pure arithmetic lives in `narf_lib::cputime`, where it is host-tested.

pub use narf_lib::cputime::{clock_t_to_ns, cputime_adjust, ns_to_clock_t, USER_HZ};
